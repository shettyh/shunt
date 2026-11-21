use std::collections::HashSet;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use http::Method;
use serde::Serialize;
use shunt_core::{
    CertStore, GatewaySnapshot, PathMatch, RouteMatch, RouteSpec, RuntimeRegistry, SnapshotBuilder,
    TimeoutConfig, UpstreamConfig, UpstreamPoolKey, UpstreamTlsConfig, load_certified_key_pem,
};
use shunt_plugin_sdk::{HookMask, HttpPlugin, PluginConfig, PluginRegistry};

use crate::error::ConfigError;
use crate::ir::{
    GatewayConfig, PluginAttachment, RouteIr, ServerTlsConfig, UpstreamIr, redact_secrets,
};
use crate::provider::LoadedConfig;

/// Redacted inspection view of the active compiled snapshot (exposed via `GET /snapshot`
/// and `shunt check`).
#[derive(Debug, Clone, Serialize)]
pub struct SnapshotInspect {
    pub version: u64,
    pub digest: String,
    pub source: String,
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
    pub http2_only: bool,
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
}

/// Output of a successful atomic snapshot compilation.
pub struct CompiledBundle {
    pub snapshot: Arc<GatewaySnapshot>,
    pub cert_store: Option<CertStore>,
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

        // Load TLS certs upfront so invalid cert/key files fail before mutating any state.
        let cert_store = match &loaded.config.server.tls {
            Some(tls_cfg) => Some(load_cert_store(tls_cfg)?),
            None => None,
        };

        let version = self.next_version.fetch_add(1, Ordering::Relaxed);
        let build_session = self.runtime_registry.begin_build_session();

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

        let mut active_pool_keys: HashSet<UpstreamPoolKey> = HashSet::new();
        for up_ir in &loaded.config.upstreams {
            let up_cfg = compile_upstream_ir(up_ir)?;
            active_pool_keys.insert(up_cfg.pool_key());
            builder = builder.upstream(up_cfg);
        }

        for route_ir in &loaded.config.routes {
            let mut spec = compile_route_ir(route_ir)?;
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
                spec = spec.with_plugin(plugin);
            }
            builder = builder.route(spec);
        }

        // Compile snapshot without GC first so any error leaves live pools/state intact.
        let snapshot = builder.build(&self.runtime_registry, false)?;

        // Compilation fully succeeded: atomically GC orphaned pools & plugin state scopes.
        self.runtime_registry.gc_unused_pools(&active_pool_keys);
        build_session.commit_gc();

        let mut upstreams_inspect: Vec<UpstreamInspect> = loaded
            .config
            .upstreams
            .iter()
            .filter_map(|u| {
                snapshot.upstream(&u.name).map(|pool| UpstreamInspect {
                    name: u.name.clone(),
                    pool_id: pool.pool_id(),
                    endpoints: u.endpoints.clone(),
                    http2_only: u.http2_only,
                })
            })
            .collect();
        upstreams_inspect.sort_by(|a, b| a.name.cmp(&b.name));

        let routes_inspect: Vec<RouteInspect> = snapshot
            .routes
            .iter()
            .map(|r| {
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
                }
            })
            .collect();

        let inspect = SnapshotInspect {
            version,
            digest: loaded.digest.clone(),
            source: loaded.source_name.clone(),
            global_plugins: global_inspect,
            upstreams: upstreams_inspect,
            routes: routes_inspect,
        };

        Ok(CompiledBundle {
            snapshot,
            cert_store,
            inspect,
            config: loaded.config.clone(),
        })
    }

    fn build_plugin(
        &self,
        att: &PluginAttachment,
        scope_id: &str,
        session: &shunt_core::BuildSession,
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

    let mut cfg = UpstreamConfig::new(ir.name.clone(), ir.endpoints.clone());
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
    Ok(cfg)
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

    let matcher = RouteMatch {
        hosts: ir.hosts.iter().map(|h| h.to_ascii_lowercase()).collect(),
        path,
        methods,
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

    Ok(spec)
}

fn load_cert_store(tls: &ServerTlsConfig) -> Result<CertStore, ConfigError> {
    let mut store = CertStore::new();

    if let (Some(cert_path), Some(key_path)) = (&tls.cert, &tls.key) {
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
        let cert_pem = std::fs::read(&sni.cert).map_err(|source| ConfigError::ReadFile {
            path: sni.cert.clone(),
            source,
        })?;
        let key_pem = std::fs::read(&sni.key).map_err(|source| ConfigError::ReadFile {
            path: sni.key.clone(),
            source,
        })?;
        let ck = load_certified_key_pem(&cert_pem, &key_pem)
            .map_err(|e| ConfigError::Tls(format!("SNI `{}`: {e}", sni.host)))?;
        store = store.with_sni(sni.host.clone(), ck);
    }

    Ok(store)
}
