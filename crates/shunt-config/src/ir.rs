use std::collections::HashSet;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use http::Method;
use serde::{Deserialize, Serialize};

use crate::error::ConfigError;

/// Canonical configuration IR parsed from `shunt.toml` (or optional YAML).
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(default)]
pub struct GatewayConfig {
    pub server: ServerConfig,
    pub admin: AdminConfig,
    #[serde(default)]
    pub plugins: Vec<PluginAttachment>,
    #[serde(default)]
    pub upstreams: Vec<UpstreamIr>,
    #[serde(default)]
    pub routes: Vec<RouteIr>,
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

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct UpstreamIr {
    pub name: String,
    pub endpoints: Vec<String>,
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
                match ep.parse::<http::Uri>() {
                    Ok(uri) => {
                        let scheme = uri.scheme_str().unwrap_or("");
                        if scheme != "http" && scheme != "https" {
                            errors.push(format!(
                                "upstreams.{}: endpoint `{ep}` must use http:// or https://",
                                up.name
                            ));
                        }
                        if uri.authority().is_none() {
                            errors.push(format!(
                                "upstreams.{}: endpoint `{ep}` is missing host/authority",
                                up.name
                            ));
                        }
                    }
                    Err(e) => {
                        errors.push(format!(
                            "upstreams.{}: invalid endpoint URI `{ep}`: {e}",
                            up.name
                        ));
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
