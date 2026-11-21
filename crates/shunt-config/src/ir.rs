use std::collections::{BTreeMap, HashSet};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use http::Method;
use http::header::{HeaderName, HeaderValue};
use serde::{Deserialize, Serialize};
use shunt_core::RedisStoreConfig;
use shunt_plugin_sdk::FailurePolicy;

use crate::error::ConfigError;
use crate::verify::VerifyPolicy;

/// Canonical configuration IR parsed from `shunt.toml` (or optional YAML).
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(default)]
pub struct GatewayConfig {
    pub server: ServerConfig,
    pub admin: AdminConfig,
    #[serde(default)]
    pub state: StateConfig,
    #[serde(default)]
    pub plugins: Vec<PluginAttachment>,
    #[serde(default)]
    pub upstreams: Vec<UpstreamIr>,
    #[serde(default)]
    pub routes: Vec<RouteIr>,
    #[serde(default)]
    pub verify: VerifyPolicy,
}

/// Backing store mode for stateful plugins across Shunt replicas.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum StateBackendKind {
    /// Zero-dependency in-process `StateStore` (sync zero-allocation fast path).
    #[default]
    Memory,
    /// Shared Redis / Valkey distributed backend for multi-replica coordination.
    Redis,
}

/// Optional gateway-level `[state]` configuration.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
pub struct StateConfig {
    pub backend: StateBackendKind,
    /// Redis / Valkey URL (`redis://...`, `rediss://...`, or `env:VAR_NAME`).
    pub url: Option<String>,
    /// Optional password override (plain or `env:VAR_NAME`).
    pub password: Option<String>,
    /// Optional Redis ACL username override.
    pub username: Option<String>,
    /// Prefix prepended to all keys stored in Redis/Valkey (default: `"shunt:"`).
    pub key_prefix: String,
    /// Max pooled connections to Redis/Valkey (default: `8`).
    pub pool_size: usize,
    /// TCP/TLS connect timeout in ms (default: `1000`).
    pub connect_timeout_ms: u64,
    /// Command round-trip timeout in ms (default: `250`).
    pub command_timeout_ms: u64,
    /// Behavior when Redis/Valkey is unreachable (`fail_open` default or `fail_closed`).
    pub failure_policy: FailurePolicy,
    /// Skip TLS verification for `rediss://` (dev/testing only).
    pub insecure_skip_verify: bool,
}

impl Default for StateConfig {
    fn default() -> Self {
        Self {
            backend: StateBackendKind::Memory,
            url: None,
            password: None,
            username: None,
            key_prefix: "shunt:".to_owned(),
            pool_size: 8,
            connect_timeout_ms: 1_000,
            command_timeout_ms: 250,
            failure_policy: FailurePolicy::FailOpen,
            insecure_skip_verify: false,
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
pub struct ServerConfig {
    pub listen: String,
    pub drain_timeout_ms: u64,
    pub tls: Option<ServerTlsConfig>,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            listen: "0.0.0.0:8080".to_owned(),
            drain_timeout_ms: 30_000,
            tls: None,
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ServerTlsConfig {
    pub cert: Option<PathBuf>,
    pub key: Option<PathBuf>,
    #[serde(default)]
    pub sni: Vec<SniCertConfig>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SniCertConfig {
    pub host: String,
    pub cert: PathBuf,
    pub key: PathBuf,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
pub struct AdminConfig {
    pub enabled: bool,
    pub listen: String,
}

impl Default for AdminConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            listen: "127.0.0.1:9090".to_owned(),
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct PluginAttachment {
    /// Plugin factory name registered in `PluginRegistry`.
    pub name: String,
    /// Optional stable instance ID for `StateStore` scoping across reloads.
    #[serde(default)]
    pub id: Option<String>,
    /// Plugin-specific configuration payload.
    #[serde(default = "default_empty_object")]
    pub config: serde_json::Value,
}

fn default_empty_object() -> serde_json::Value {
    serde_json::Value::Object(serde_json::Map::new())
}

/// Canonical endpoint entry in `upstreams[].endpoints`: accepts either a bare URL string
/// (implicit `weight = 1`) or an explicit `{ url = "...", weight = N }` table.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(untagged)]
pub enum UpstreamEndpointIr {
    Url(String),
    Weighted {
        url: String,
        #[serde(default = "default_endpoint_weight")]
        weight: u32,
    },
}

fn default_endpoint_weight() -> u32 {
    1
}

impl UpstreamEndpointIr {
    pub fn url(&self) -> &str {
        match self {
            UpstreamEndpointIr::Url(u) => u.as_str(),
            UpstreamEndpointIr::Weighted { url, .. } => url.as_str(),
        }
    }

    pub fn weight(&self) -> u32 {
        match self {
            UpstreamEndpointIr::Url(_) => 1,
            UpstreamEndpointIr::Weighted { weight, .. } => *weight,
        }
    }

    pub fn set_url(&mut self, next_url: String) {
        match self {
            UpstreamEndpointIr::Url(u) => *u = next_url,
            UpstreamEndpointIr::Weighted { url, .. } => *url = next_url,
        }
    }
}

/// Active health check probe protocol (`http` or `tcp`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ActiveProbeKindIr {
    #[default]
    Http,
    Tcp,
}

/// Optional `[upstreams.health_check]` background probe configuration.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
pub struct ActiveHealthCheckIr {
    pub kind: ActiveProbeKindIr,
    /// HTTP probe request path (default: `"/health"`).
    pub path: String,
    /// HTTP probe method (default: `"GET"`).
    pub method: String,
    /// HTTP status codes considered healthy (default: `[200]`).
    pub expected_statuses: Vec<u16>,
    /// Optional HTTP headers attached to probe requests.
    pub headers: BTreeMap<String, String>,
    /// Interval between probe cycles in milliseconds (default: `10000`).
    pub interval_ms: u64,
    /// Per-probe timeout in milliseconds (default: `2000`).
    pub timeout_ms: u64,
    /// Consecutive failed probes before ejecting an endpoint (default: `2`).
    pub unhealthy_threshold: usize,
    /// Consecutive successful probes before recovering an endpoint (default: `1`).
    pub healthy_threshold: usize,
    /// Initial active health state before the first probe finishes (default: `true`).
    pub initial_healthy: bool,
}

impl Default for ActiveHealthCheckIr {
    fn default() -> Self {
        Self {
            kind: ActiveProbeKindIr::Http,
            path: "/health".to_owned(),
            method: "GET".to_owned(),
            expected_statuses: vec![200],
            headers: BTreeMap::new(),
            interval_ms: 10_000,
            timeout_ms: 2_000,
            unhealthy_threshold: 2,
            healthy_threshold: 1,
            initial_healthy: true,
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct UpstreamIr {
    pub name: String,
    pub endpoints: Vec<UpstreamEndpointIr>,
    #[serde(default)]
    pub http2_only: bool,
    #[serde(default = "default_connect_timeout_ms")]
    pub connect_timeout_ms: u64,
    #[serde(default = "default_pool_idle_timeout_ms")]
    pub pool_idle_timeout_ms: u64,
    #[serde(default = "default_pool_max_idle_per_host")]
    pub pool_max_idle_per_host: usize,
    #[serde(default = "default_unhealthy_threshold")]
    pub unhealthy_threshold: usize,
    #[serde(default = "default_unhealthy_cooldown_ms")]
    pub unhealthy_cooldown_ms: u64,
    #[serde(default)]
    pub tls: UpstreamTlsIr,
    #[serde(default)]
    pub health_check: Option<ActiveHealthCheckIr>,
}

fn default_connect_timeout_ms() -> u64 {
    5_000
}
fn default_pool_idle_timeout_ms() -> u64 {
    90_000
}
fn default_pool_max_idle_per_host() -> usize {
    64
}
fn default_unhealthy_threshold() -> usize {
    3
}
fn default_unhealthy_cooldown_ms() -> u64 {
    10_000
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(default)]
pub struct UpstreamTlsIr {
    pub ca_cert: Option<PathBuf>,
    pub insecure_skip_verify: bool,
    pub alpn: Option<Vec<String>>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RouteIr {
    pub id: String,
    #[serde(default)]
    pub hosts: Vec<String>,
    pub path_prefix: Option<String>,
    pub path_exact: Option<String>,
    #[serde(default)]
    pub methods: Vec<String>,
    pub upstream: String,
    pub strip_prefix: Option<String>,
    pub max_body_bytes: Option<usize>,
    #[serde(default = "default_max_attempts")]
    pub max_attempts: usize,
    #[serde(default = "default_response_headers_timeout_ms")]
    pub response_headers_timeout_ms: Option<u64>,
    #[serde(default = "default_idle_chunk_timeout_ms")]
    pub idle_chunk_timeout_ms: Option<u64>,
    #[serde(default = "default_allow_websockets")]
    pub allow_websockets: bool,
    #[serde(default)]
    pub plugins: Vec<PluginAttachment>,
}

fn default_max_attempts() -> usize {
    1
}
fn default_response_headers_timeout_ms() -> Option<u64> {
    Some(30_000)
}
fn default_idle_chunk_timeout_ms() -> Option<u64> {
    Some(60_000)
}
fn default_allow_websockets() -> bool {
    true
}

impl GatewayConfig {
    /// Resolves relative TLS file paths against `base_dir`.
    pub fn resolve_relative_paths(&mut self, base_dir: &Path) {
        if let Some(tls) = &mut self.server.tls {
            if let Some(cert) = &mut tls.cert
                && cert.is_relative()
            {
                *cert = base_dir.join(&*cert);
            }
            if let Some(key) = &mut tls.key
                && key.is_relative()
            {
                *key = base_dir.join(&*key);
            }
            for sni in &mut tls.sni {
                if sni.cert.is_relative() {
                    sni.cert = base_dir.join(&sni.cert);
                }
                if sni.key.is_relative() {
                    sni.key = base_dir.join(&sni.key);
                }
            }
        }
        for up in &mut self.upstreams {
            if let Some(ca) = &mut up.tls.ca_cert
                && ca.is_relative()
            {
                *ca = base_dir.join(&*ca);
            }
        }
    }

    /// Collects all external file paths referenced by this config (e.g., TLS certs)
    /// so file watchers can trigger hot reloads on certificate rotation too.
    pub fn referenced_tls_files(&self) -> Vec<PathBuf> {
        let mut paths = Vec::new();
        if let Some(tls) = &self.server.tls {
            if let Some(c) = &tls.cert {
                paths.push(c.clone());
            }
            if let Some(k) = &tls.key {
                paths.push(k.clone());
            }
            for sni in &tls.sni {
                paths.push(sni.cert.clone());
                paths.push(sni.key.clone());
            }
        }
        paths
    }

    /// Performs thorough structural validation, returning all actionable errors together.
    pub fn validate(&self) -> Result<(), ConfigError> {
        let mut errors = Vec::new();

        let server_addr = self.server.listen.parse::<SocketAddr>().ok();
        if server_addr.is_none() {
            errors.push(format!(
                "server.listen: `{}` is not a valid socket address (expected host:port)",
                self.server.listen
            ));
        }

        let admin_addr = if self.admin.enabled {
            let parsed = self.admin.listen.parse::<SocketAddr>().ok();
            if parsed.is_none() {
                errors.push(format!(
                    "admin.listen: `{}` is not a valid socket address",
                    self.admin.listen
                ));
            }
            parsed
        } else {
            None
        };

        if let (Some(sa), Some(aa)) = (server_addr, admin_addr)
            && sa == aa
            && sa.port() != 0
        {
            errors.push(format!(
                "admin.listen (`{}`) must be bound to a separate address/port from server.listen",
                self.admin.listen
            ));
        }

        if let Some(tls) = &self.server.tls {
            if tls.cert.is_some() != tls.key.is_some() {
                errors.push("server.tls: both `cert` and `key` must be specified together".into());
            }
            if tls.cert.is_none() && tls.sni.is_empty() {
                errors.push(
                    "server.tls: specify a default `cert`/`key` pair or at least one `sni` entry"
                        .into(),
                );
            }
        }

        if self.state.backend == StateBackendKind::Redis {
            match self.state.url.as_deref().map(str::trim) {
                None | Some("") => {
                    errors.push("state.url: required when `state.backend = \"redis\"`".into());
                }
                Some(raw_url) if !raw_url.starts_with("env:") => {
                    if let Err(err) = RedisStoreConfig::from_url(raw_url) {
                        errors.push(format!("state.url: {err}"));
                    }
                }
                Some(_) => {}
            }
            if self.state.pool_size == 0 {
                errors.push("state.pool_size: must be >= 1".into());
            }
            if self.state.connect_timeout_ms == 0 {
                errors.push("state.connect_timeout_ms: must be >= 1".into());
            }
            if self.state.command_timeout_ms == 0 {
                errors.push("state.command_timeout_ms: must be >= 1".into());
            }
        }

        let mut upstream_names = HashSet::new();
        for up in &self.upstreams {
            if up.name.trim().is_empty() {
                errors.push("upstreams: upstream name cannot be empty".into());
            } else if !upstream_names.insert(up.name.clone()) {
                errors.push(format!("upstreams: duplicate upstream name `{}`", up.name));
            }
            if up.endpoints.is_empty() {
                errors.push(format!(
                    "upstreams.{}: must define at least one endpoint",
                    up.name
                ));
            }
            for ep in &up.endpoints {
                if ep.weight() == 0 {
                    errors.push(format!(
                        "upstreams.{}: endpoint `{}` weight must be >= 1",
                        up.name,
                        ep.url()
                    ));
                }
                match ep.url().parse::<http::Uri>() {
                    Ok(uri) => {
                        let scheme = uri.scheme_str().unwrap_or("");
                        if scheme != "http" && scheme != "https" {
                            errors.push(format!(
                                "upstreams.{}: endpoint `{}` must use http:// or https://",
                                up.name,
                                ep.url()
                            ));
                        }
                        if uri.authority().is_none() {
                            errors.push(format!(
                                "upstreams.{}: endpoint `{}` is missing host/authority",
                                up.name,
                                ep.url()
                            ));
                        }
                    }
                    Err(e) => {
                        errors.push(format!(
                            "upstreams.{}: invalid endpoint URI `{}`: {e}",
                            up.name,
                            ep.url()
                        ));
                    }
                }
            }
            if let Some(hc) = &up.health_check {
                if hc.interval_ms == 0 {
                    errors.push(format!(
                        "upstreams.{}.health_check.interval_ms: must be >= 1",
                        up.name
                    ));
                }
                if hc.timeout_ms == 0 {
                    errors.push(format!(
                        "upstreams.{}.health_check.timeout_ms: must be >= 1",
                        up.name
                    ));
                }
                if hc.unhealthy_threshold == 0 {
                    errors.push(format!(
                        "upstreams.{}.health_check.unhealthy_threshold: must be >= 1",
                        up.name
                    ));
                }
                if hc.healthy_threshold == 0 {
                    errors.push(format!(
                        "upstreams.{}.health_check.healthy_threshold: must be >= 1",
                        up.name
                    ));
                }
                if hc.kind == ActiveProbeKindIr::Http {
                    if !hc.path.starts_with('/') {
                        errors.push(format!(
                            "upstreams.{}.health_check.path: `{}` must start with `/`",
                            up.name, hc.path
                        ));
                    }
                    if Method::from_bytes(hc.method.as_bytes()).is_err() {
                        errors.push(format!(
                            "upstreams.{}.health_check.method: invalid HTTP method `{}`",
                            up.name, hc.method
                        ));
                    }
                    if hc.expected_statuses.is_empty() {
                        errors.push(format!(
                            "upstreams.{}.health_check.expected_statuses: cannot be empty",
                            up.name
                        ));
                    }
                    for &code in &hc.expected_statuses {
                        if !(100..=599).contains(&code) {
                            errors.push(format!(
                                "upstreams.{}.health_check.expected_statuses: invalid HTTP status `{code}`",
                                up.name
                            ));
                        }
                    }
                    for (k, v) in &hc.headers {
                        if HeaderName::from_bytes(k.as_bytes()).is_err() {
                            errors.push(format!(
                                "upstreams.{}.health_check.headers: invalid header name `{k}`",
                                up.name
                            ));
                        }
                        if HeaderValue::from_str(v).is_err() {
                            errors.push(format!(
                                "upstreams.{}.health_check.headers.{k}: invalid header value",
                                up.name
                            ));
                        }
                    }
                }
            }
        }

        let mut route_ids = HashSet::new();
        for route in &self.routes {
            if route.id.trim().is_empty() {
                errors.push("routes: route id cannot be empty".into());
            } else if !route_ids.insert(route.id.clone()) {
                errors.push(format!("routes: duplicate route id `{}`", route.id));
            }
            if route.path_prefix.is_some() && route.path_exact.is_some() {
                errors.push(format!(
                    "routes.{}: cannot specify both `path_prefix` and `path_exact`",
                    route.id
                ));
            }
            if !upstream_names.contains(&route.upstream) {
                errors.push(format!(
                    "routes.{}: references unknown upstream `{}`",
                    route.id, route.upstream
                ));
            }
            if route.max_attempts == 0 {
                errors.push(format!("routes.{}: `max_attempts` must be >= 1", route.id));
            }
            for m in &route.methods {
                if Method::from_bytes(m.as_bytes()).is_err() {
                    errors.push(format!("routes.{}: invalid HTTP method `{m}`", route.id));
                }
            }
        }

        if errors.is_empty() {
            Ok(())
        } else {
            Err(ConfigError::Validation(errors))
        }
    }
}

/// Recursively redacts secret-looking fields in plugin configuration JSON for `GET /snapshot`.
pub fn redact_secrets(value: &serde_json::Value) -> serde_json::Value {
    match value {
        serde_json::Value::Object(map) => {
            let mut out = serde_json::Map::with_capacity(map.len());
            for (k, v) in map {
                if is_secret_key(k) {
                    out.insert(
                        k.clone(),
                        serde_json::Value::String("[REDACTED]".to_owned()),
                    );
                } else {
                    out.insert(k.clone(), redact_secrets(v));
                }
            }
            serde_json::Value::Object(out)
        }
        serde_json::Value::Array(items) => {
            serde_json::Value::Array(items.iter().map(redact_secrets).collect())
        }
        other => other.clone(),
    }
}

fn is_secret_key(key: &str) -> bool {
    let lower = key.to_ascii_lowercase();
    const PATTERNS: &[&str] = &[
        "token",
        "secret",
        "password",
        "passwd",
        "api_key",
        "apikey",
        "authorization",
        "private_key",
        "credential",
    ];
    PATTERNS.iter().any(|p| lower.contains(p))
}
