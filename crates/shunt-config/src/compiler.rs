use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use http::Method;
use serde::Serialize;
use shunt_engine::{
    ActiveHealthCheckConfig, ActiveProbeKind, CertStore, ClientAuthConfig, ClientAuthMode,
    GatewaySnapshot, OtlpExporterConfig, PathMatch, RedisStoreConfig, RouteMatch, RouteSpec,
    RuntimeRegistry, SnapshotBuilder, TimeoutConfig, TrafficMirrorSpec, UpstreamConfig,
    UpstreamEndpoint, UpstreamTlsConfig, load_certified_key_pem,
};
use shunt_plugin_sdk::{
    DistributedStore, HookMask, HttpPlugin, PluginConfig, PluginRegistry, TelemetrySink,
};

use crate::error::ConfigError;
use crate::ir::{
    ActiveHealthCheckIr, ActiveProbeKindIr, ClientAuthModeIr, GatewayConfig, PluginAttachment,
    RouteIr, ServerTlsConfig, StateBackendKind, StateConfig, TelemetryBackendKind, TelemetryConfig,
    UpstreamIr, redact_secrets,
};
use crate::provider::LoadedConfig;

/// Redacted inspection view of the active compiled snapshot (exposed via `GET /snapshot`
/// and `shunt check`).
#[derive(Debug, Clone, Serialize)]
pub struct SnapshotInspect {
    pub version: u64,
    pub digest: String,
    pub source: String,
    pub state_backend: String,
    pub telemetry_backend: String,
    pub global_plugins: Vec<PluginInspect>,
    pub upstreams: Vec<UpstreamInspect>,
    pub routes: Vec<RouteInspect>,
}

#[derive(Debug, Clone, Serialize)]
pub struct PluginInspect {
    pub name: String,
    pub scope_id: String,
    pub hook_mask: HookMask,
    pub config: serde_json::Value,
}

#[derive(Debug, Clone, Serialize)]
pub struct UpstreamInspect {
    pub name: String,
    pub pool_id: u64,
    pub endpoints: Vec<String>,
    pub weights: Vec<u32>,
    pub http2_only: bool,
    pub active_health_check: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct RoutePluginInspect {
    pub name: String,
    pub scope_id: String,
    pub hook_mask: HookMask,
}

#[derive(Debug, Clone, Serialize)]
pub struct RouteInspect {
    pub id: String,
    pub hosts: Vec<String>,
    pub path: String,
    pub methods: Vec<String>,
    pub upstream: String,
    pub max_attempts: usize,
    pub max_body_bytes: usize,
    pub hook_mask: HookMask,
    pub plugins: Vec<String>,
    pub plugin_details: Vec<RoutePluginInspect>,
}

/// Output of a successful atomic snapshot compilation.
pub struct CompiledBundle {
    pub snapshot: Arc<GatewaySnapshot>,
    pub cert_store: Option<CertStore>,
    pub client_auth: Option<ClientAuthConfig>,
    pub inspect: SnapshotInspect,
    pub config: GatewayConfig,
}

/// Compiles canonical [`GatewayConfig`] IR into an immutable [`GatewaySnapshot`],
/// resolving plugins via [`PluginRegistry`] and preserving warm pools & plugin state
/// via [`RuntimeRegistry`].
pub struct SnapshotCompiler {
    plugin_registry: Arc<PluginRegistry>,
    runtime_registry: Arc<RuntimeRegistry>,
    extra_global_plugins: Vec<Arc<dyn HttpPlugin>>,
    next_version: AtomicU64,
}

impl SnapshotCompiler {
    pub fn new(
        plugin_registry: Arc<PluginRegistry>,
        runtime_registry: Arc<RuntimeRegistry>,
    ) -> Self {
        Self {
            plugin_registry,
            runtime_registry,
            extra_global_plugins: Vec::new(),
            next_version: AtomicU64::new(1),
        }
    }

    /// Adds an extra global plugin (e.g., `DevWaterfallPlugin` in `shunt dev`) to every
    /// compiled snapshot.
    pub fn with_extra_global_plugin(mut self, plugin: Arc<dyn HttpPlugin>) -> Self {
        self.extra_global_plugins.push(plugin);
        self
    }

    pub fn runtime_registry(&self) -> &Arc<RuntimeRegistry> {
        &self.runtime_registry
    }

    /// Parses/validates IR, builds plugin instances, loads TLS certs, compiles
    /// [`GatewaySnapshot`], and only garbage-collects orphaned pools & plugin state
    /// after everything succeeds (atomic fail-safe).
    pub fn compile(&self, loaded: &LoadedConfig) -> Result<CompiledBundle, ConfigError> {
        loaded.config.validate()?;

        // Load TLS certs and optional mTLS client CA upfront so invalid files fail before mutating state.
        let (cert_store, client_auth) = match &loaded.config.server.tls {
            Some(tls_cfg) => (Some(load_cert_store(tls_cfg)?), load_client_auth(tls_cfg)?),
            None => (None, None),
        };

        // Resolve optional distributed state backend upfront so invalid env/URL fails cleanly.
        let (redis_cfg, distributed_store, state_backend): (
            Option<RedisStoreConfig>,
            Option<Arc<dyn DistributedStore>>,
            String,
        ) = match loaded.config.state.backend {
            StateBackendKind::Memory => (None, None, "memory".to_owned()),
            StateBackendKind::Redis => {
                let rcfg = compile_redis_state_config(&loaded.config.state)?;
                let store = self.runtime_registry.get_or_create_redis_store(&rcfg);
                let dyn_store: Arc<dyn DistributedStore> = store;
                (Some(rcfg), Some(dyn_store), "redis".to_owned())
            }
        };

        // Resolve optional telemetry exporter upfront so invalid env/URL fails cleanly.
        let (otlp_cfg, telemetry_sink, telemetry_backend): (
            Option<OtlpExporterConfig>,
            Option<Arc<dyn TelemetrySink>>,
            String,
        ) = if loaded.config.telemetry.enabled {
            match loaded.config.telemetry.backend {
                TelemetryBackendKind::OtlpHttp => {
                    let ocfg = compile_telemetry_config(&loaded.config.telemetry)?;
                    let exporter = self.runtime_registry.get_or_create_otlp_exporter(&ocfg);
                    let dyn_sink: Arc<dyn TelemetrySink> = exporter;
                    (Some(ocfg), Some(dyn_sink), "otlp_http".to_owned())
                }
            }
        } else {
            (None, None, "disabled".to_owned())
        };

        let version = self.next_version.fetch_add(1, Ordering::Relaxed);
        let build_session = self
            .runtime_registry
            .begin_build_session_with_services(distributed_store, telemetry_sink);

        let mut builder = SnapshotBuilder::new(version);
        let mut global_inspect = Vec::new();

        for (idx, att) in loaded.config.plugins.iter().enumerate() {
            let scope_id = format!(
                "global:{}",
                att.id
                    .as_deref()
                    .map(str::to_owned)
                    .unwrap_or_else(|| format!("{}:{idx}", att.name))
            );
            let plugin = self.build_plugin(att, &scope_id, &build_session)?;
            global_inspect.push(PluginInspect {
                name: plugin.name().to_owned(),
                scope_id,
                hook_mask: plugin.hook_mask(),
                config: redact_secrets(&att.config),
            });
            builder = builder.global_plugin(plugin);
        }

        for extra in &self.extra_global_plugins {
            builder = builder.global_plugin(Arc::clone(extra));
        }

        for up_ir in &loaded.config.upstreams {
            let up_cfg = compile_upstream_ir(up_ir)?;
            builder = builder.upstream(up_cfg);
        }

        let mut route_plugin_details: Vec<Vec<RoutePluginInspect>> =
            Vec::with_capacity(loaded.config.routes.len());
        for route_ir in &loaded.config.routes {
            let mut spec = compile_route_ir(route_ir)?;
            let mut details = Vec::with_capacity(route_ir.plugins.len());
            for (idx, att) in route_ir.plugins.iter().enumerate() {
                let scope_id = format!(
                    "route:{}:{}",
                    route_ir.id,
                    att.id
                        .as_deref()
                        .map(str::to_owned)
                        .unwrap_or_else(|| format!("{}:{idx}", att.name))
                );
                let plugin = self.build_plugin(att, &scope_id, &build_session)?;
                details.push(RoutePluginInspect {
                    name: plugin.name().to_owned(),
                    scope_id,
                    hook_mask: plugin.hook_mask(),
                });
                spec = spec.with_plugin(plugin);
            }
            route_plugin_details.push(details);
            builder = builder.route(spec);
        }

        // Transactionally build snapshot: pools are staged and only committed + GC'd
        // after every upstream and route compiles cleanly.
        let snapshot = builder.build(&self.runtime_registry, true)?;

        // Compilation fully succeeded: atomically commit staged plugin state & GC orphans.
        build_session.commit_gc();
        self.runtime_registry.retain_redis_store(redis_cfg.as_ref());
        self.runtime_registry
            .retain_otlp_exporter(otlp_cfg.as_ref());

        let mut upstreams_inspect: Vec<UpstreamInspect> = loaded
            .config
            .upstreams
            .iter()
            .filter_map(|u| {
                snapshot.upstream(&u.name).map(|pool| UpstreamInspect {
                    name: u.name.clone(),
                    pool_id: pool.pool_id(),
                    endpoints: u.endpoints.iter().map(|e| e.url().to_owned()).collect(),
                    weights: u.endpoints.iter().map(|e| e.weight()).collect(),
                    http2_only: u.http2_only,
                    active_health_check: u.health_check.is_some(),
                })
            })
            .collect();
        upstreams_inspect.sort_by(|a, b| a.name.cmp(&b.name));

        let routes_inspect: Vec<RouteInspect> = snapshot
            .routes
            .iter()
            .zip(route_plugin_details)
            .map(|(r, plugin_details)| {
                let path = match &r.matcher.path {
                    PathMatch::Any => "*".to_owned(),
                    PathMatch::Exact(p) => format!("={p}"),
                    PathMatch::Prefix(p) => format!("{p}*"),
                };
                RouteInspect {
                    id: r.id.clone(),
                    hosts: r.matcher.hosts.clone(),
                    path,
                    methods: r.matcher.methods.iter().map(ToString::to_string).collect(),
                    upstream: r.upstream.clone(),
                    max_attempts: r.max_attempts,
                    max_body_bytes: r.max_body_bytes,
                    hook_mask: r.hook_mask,
                    plugins: r.plugins.iter().map(|p| p.name().to_owned()).collect(),
                    plugin_details,
                }
            })
            .collect();

        let inspect = SnapshotInspect {
            version,
            digest: loaded.digest.clone(),
            source: loaded.source_name.clone(),
            state_backend,
            telemetry_backend,
            global_plugins: global_inspect,
            upstreams: upstreams_inspect,
            routes: routes_inspect,
        };

        Ok(CompiledBundle {
            snapshot,
            cert_store,
            client_auth,
            inspect,
            config: loaded.config.clone(),
        })
    }

    fn build_plugin(
        &self,
        att: &PluginAttachment,
        scope_id: &str,
        session: &shunt_engine::BuildSession,
    ) -> Result<Arc<dyn HttpPlugin>, ConfigError> {
        let cfg = PluginConfig::new(att.config.clone());
        let build_ctx = session.context_for(scope_id);
        self.plugin_registry
            .build(&att.name, &cfg, &build_ctx)
            .map_err(|source| ConfigError::PluginBuild {
                scope: scope_id.to_owned(),
                plugin: att.name.clone(),
                source,
            })
    }
}

fn compile_telemetry_config(
    telemetry: &TelemetryConfig,
) -> Result<OtlpExporterConfig, ConfigError> {
    let raw_endpoint = telemetry.endpoint.as_deref().ok_or_else(|| {
        ConfigError::Validation(vec![
            "telemetry.endpoint is required when telemetry is enabled".into(),
        ])
    })?;
    let resolved_endpoint = resolve_env_var(raw_endpoint, "telemetry.endpoint")?;
    let uri: http::Uri = resolved_endpoint.parse().map_err(|e| {
        ConfigError::Validation(vec![format!(
            "telemetry.endpoint: invalid URI `{resolved_endpoint}`: {e}"
        )])
    })?;
    let scheme = uri.scheme_str().unwrap_or("");
    if (scheme != "http" && scheme != "https") || uri.authority().is_none() {
        return Err(ConfigError::Validation(vec![format!(
            "telemetry.endpoint: `{resolved_endpoint}` must be a valid http:// or https:// URL"
        )]));
    }

    let mut headers = std::collections::BTreeMap::new();
    for (k, v) in &telemetry.headers {
        let resolved_val = resolve_env_var(v, &format!("telemetry.headers.{k}"))?;
        if http::header::HeaderValue::from_str(&resolved_val).is_err() {
            return Err(ConfigError::Validation(vec![format!(
                "telemetry.headers.{k}: resolved value is not a valid HTTP header value"
            )]));
        }
        headers.insert(k.clone(), resolved_val);
    }

    Ok(OtlpExporterConfig {
        endpoint: resolved_endpoint,
        service_name: telemetry.service_name.clone(),
        service_version: env!("CARGO_PKG_VERSION").to_owned(),
        resource_attributes: telemetry.resource_attributes.clone(),
        headers,
        queue_capacity: telemetry.queue_capacity.max(1),
        batch_size: telemetry.batch_size.max(1),
        flush_interval: Duration::from_millis(telemetry.flush_interval_ms.max(1)),
        export_timeout: Duration::from_millis(telemetry.export_timeout_ms.max(1)),
        insecure_skip_verify: telemetry.insecure_skip_verify,
    })
}

fn compile_redis_state_config(state: &StateConfig) -> Result<RedisStoreConfig, ConfigError> {
    let raw_url = state
        .url
        .as_deref()
        .ok_or_else(|| ConfigError::Validation(vec!["state.url is required for redis".into()]))?;
    let resolved_url = resolve_env_var(raw_url, "state.url")?;
    let mut cfg = RedisStoreConfig::from_url(&resolved_url)
        .map_err(|e| ConfigError::Validation(vec![format!("state.url: {e}")]))?;

    if let Some(raw_pw) = &state.password {
        let pw = resolve_env_var(raw_pw, "state.password")?;
        if !pw.is_empty() {
            cfg.password = Some(pw);
        }
    }
    if let Some(user) = &state.username
        && !user.is_empty()
    {
        cfg.username = Some(user.clone());
    }
    cfg.key_prefix = state.key_prefix.clone();
    cfg.pool_size = state.pool_size.max(1);
    cfg.connect_timeout = Duration::from_millis(state.connect_timeout_ms.max(1));
    cfg.command_timeout = Duration::from_millis(state.command_timeout_ms.max(1));
    cfg.failure_policy = state.failure_policy;
    cfg.insecure_skip_verify = state.insecure_skip_verify;
    Ok(cfg)
}

fn resolve_env_var(raw: &str, field: &str) -> Result<String, ConfigError> {
    if let Some(var) = raw.strip_prefix("env:") {
        std::env::var(var).map_err(|_| {
            ConfigError::Validation(vec![format!(
                "{field}: environment variable `{var}` is not set"
            )])
        })
    } else {
        Ok(raw.to_owned())
    }
}

fn compile_upstream_ir(ir: &UpstreamIr) -> Result<UpstreamConfig, ConfigError> {
    let extra_ca_pem = match &ir.tls.ca_cert {
        Some(path) => Some(std::fs::read(path).map_err(|source| ConfigError::ReadFile {
            path: path.clone(),
            source,
        })?),
        None => None,
    };

    let alpn_protocols = match &ir.tls.alpn {
        Some(list) => list.iter().map(|s| s.as_bytes().to_vec()).collect(),
        None => vec![b"h2".to_vec(), b"http/1.1".to_vec()],
    };

    let endpoints: Vec<UpstreamEndpoint> = ir
        .endpoints
        .iter()
        .map(|ep| UpstreamEndpoint::with_weight(ep.url().to_owned(), ep.weight()))
        .collect();

    let mut cfg = UpstreamConfig::with_endpoints(ir.name.clone(), endpoints);
    cfg.http2_only = ir.http2_only;
    cfg.connect_timeout = Duration::from_millis(ir.connect_timeout_ms);
    cfg.pool_idle_timeout = Duration::from_millis(ir.pool_idle_timeout_ms);
    cfg.pool_max_idle_per_host = ir.pool_max_idle_per_host;
    cfg.unhealthy_threshold = ir.unhealthy_threshold;
    cfg.unhealthy_cooldown = Duration::from_millis(ir.unhealthy_cooldown_ms);
    cfg.tls = UpstreamTlsConfig {
        extra_ca_pem,
        insecure_skip_verify: ir.tls.insecure_skip_verify,
        alpn_protocols,
    };
    cfg.active_health_check = ir.health_check.as_ref().map(compile_active_health_check_ir);
    Ok(cfg)
}

fn compile_active_health_check_ir(ir: &ActiveHealthCheckIr) -> ActiveHealthCheckConfig {
    let kind = match ir.kind {
        ActiveProbeKindIr::Http => ActiveProbeKind::Http {
            method: ir.method.to_ascii_uppercase(),
            path: ir.path.clone(),
            expected_statuses: ir.expected_statuses.clone(),
            headers: ir
                .headers
                .iter()
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect(),
        },
        ActiveProbeKindIr::Tcp => ActiveProbeKind::Tcp,
    };
    ActiveHealthCheckConfig {
        kind,
        interval: Duration::from_millis(ir.interval_ms),
        timeout: Duration::from_millis(ir.timeout_ms),
        unhealthy_threshold: ir.unhealthy_threshold,
        healthy_threshold: ir.healthy_threshold,
        initial_healthy: ir.initial_healthy,
    }
}

fn compile_route_ir(ir: &RouteIr) -> Result<RouteSpec, ConfigError> {
    let path = if let Some(exact) = &ir.path_exact {
        PathMatch::Exact(exact.clone())
    } else if let Some(prefix) = &ir.path_prefix {
        PathMatch::Prefix(prefix.clone())
    } else {
        PathMatch::Any
    };

    let methods = ir
        .methods
        .iter()
        .map(|m| {
            Method::from_bytes(m.as_bytes())
                .map_err(|e| ConfigError::Validation(vec![format!("invalid method `{m}`: {e}")]))
        })
        .collect::<Result<Vec<_>, _>>()?;

    let mut headers = Vec::with_capacity(ir.headers.len());
    for (k, v) in &ir.headers {
        let name = http::header::HeaderName::from_bytes(k.as_bytes()).map_err(|e| {
            ConfigError::Validation(vec![format!("invalid header matcher `{k}`: {e}")])
        })?;
        headers.push((name, v.clone()));
    }

    let matcher = RouteMatch {
        hosts: ir.hosts.iter().map(|h| h.to_ascii_lowercase()).collect(),
        path,
        methods,
        headers,
    };

    let mut spec = RouteSpec::new(ir.id.clone(), matcher, ir.upstream.clone())
        .with_max_attempts(ir.max_attempts)
        .allow_websockets(ir.allow_websockets)
        .with_timeouts(TimeoutConfig {
            response_headers_timeout: ir.response_headers_timeout_ms.map(Duration::from_millis),
            idle_chunk_timeout: ir.idle_chunk_timeout_ms.map(Duration::from_millis),
        });

    if let Some(max_body) = ir.max_body_bytes {
        spec = spec.with_max_body_bytes(max_body);
    }
    if let Some(strip) = &ir.strip_prefix {
        spec = spec.with_strip_prefix(strip.clone());
    }
    for mirror in &ir.mirrors {
        let mut headers = Vec::with_capacity(mirror.headers.len());
        for (k, v) in &mirror.headers {
            let name = http::header::HeaderName::from_bytes(k.as_bytes()).map_err(|e| {
                ConfigError::Validation(vec![format!("invalid mirror header `{k}`: {e}")])
            })?;
            let val = http::header::HeaderValue::from_str(v).map_err(|e| {
                ConfigError::Validation(vec![format!("invalid mirror header value `{k}`: {e}")])
            })?;
            headers.push((name, val));
        }
        let mut m_spec = TrafficMirrorSpec::new(mirror.upstream.clone(), mirror.sample_rate);
        m_spec.timeout = Duration::from_millis(mirror.timeout_ms.max(1));
        m_spec.max_in_flight = mirror.max_in_flight.max(1);
        m_spec.headers = headers;
        spec = spec.with_mirror(m_spec);
    }

    Ok(spec)
}

fn load_cert_store(tls: &ServerTlsConfig) -> Result<CertStore, ConfigError> {
    let mut store = CertStore::new();

    if let (Some(cert_pem), Some(key_pem)) = (&tls.cert_pem, &tls.key_pem) {
        let ck = load_certified_key_pem(cert_pem.as_bytes(), key_pem.as_bytes())
            .map_err(|e| ConfigError::Tls(e.to_string()))?;
        store = store.with_default(ck);
    } else if let (Some(cert_path), Some(key_path)) = (&tls.cert, &tls.key) {
        let cert_pem = std::fs::read(cert_path).map_err(|source| ConfigError::ReadFile {
            path: cert_path.clone(),
            source,
        })?;
        let key_pem = std::fs::read(key_path).map_err(|source| ConfigError::ReadFile {
            path: key_path.clone(),
            source,
        })?;
        let ck = load_certified_key_pem(&cert_pem, &key_pem)
            .map_err(|e| ConfigError::Tls(e.to_string()))?;
        store = store.with_default(ck);
    }

    for sni in &tls.sni {
        let (cert_pem, key_pem) = match (&sni.cert_pem, &sni.key_pem) {
            (Some(c), Some(k)) => (c.as_bytes().to_vec(), k.as_bytes().to_vec()),
            _ => {
                let cert_path = sni.cert.as_ref().ok_or_else(|| {
                    ConfigError::Tls(format!("SNI `{}` missing cert path/PEM", sni.host))
                })?;
                let key_path = sni.key.as_ref().ok_or_else(|| {
                    ConfigError::Tls(format!("SNI `{}` missing key path/PEM", sni.host))
                })?;
                let c = std::fs::read(cert_path).map_err(|source| ConfigError::ReadFile {
                    path: cert_path.clone(),
                    source,
                })?;
                let k = std::fs::read(key_path).map_err(|source| ConfigError::ReadFile {
                    path: key_path.clone(),
                    source,
                })?;
                (c, k)
            }
        };
        let ck = load_certified_key_pem(&cert_pem, &key_pem)
            .map_err(|e| ConfigError::Tls(format!("SNI `{}`: {e}", sni.host)))?;
        store = store.with_sni(sni.host.clone(), ck);
    }

    Ok(store)
}

fn load_client_auth(tls: &ServerTlsConfig) -> Result<Option<ClientAuthConfig>, ConfigError> {
    let mode = match tls.effective_client_auth() {
        ClientAuthModeIr::None => return Ok(None),
        ClientAuthModeIr::Optional => ClientAuthMode::Optional,
        ClientAuthModeIr::Required => ClientAuthMode::Required,
    };

    let ca_pem = if let Some(inline) = &tls.client_ca_pem {
        inline.as_bytes().to_vec()
    } else if let Some(path) = &tls.client_ca {
        std::fs::read(path).map_err(|source| ConfigError::ReadFile {
            path: path.clone(),
            source,
        })?
    } else {
        return Err(ConfigError::Tls(
            "client_ca is required when client_auth is enabled".to_owned(),
        ));
    };

    // Validate the CA bundle upfront so invalid PEM fails compilation cleanly.
    let dummy_resolver = Arc::new(shunt_engine::DynamicCertResolver::new(CertStore::new()));
    let cfg = ClientAuthConfig { mode, ca_pem };
    shunt_engine::TlsListenerConfig::new(dummy_resolver)
        .with_client_auth(Some(cfg.clone()))
        .build_server_config()
        .map_err(|e| ConfigError::Tls(e.to_string()))?;

    Ok(Some(cfg))
}
