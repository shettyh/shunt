use std::collections::{HashMap, HashSet};
use std::fmt::Write as _;
use std::sync::Arc;
use std::time::Duration;

use http::{Method, Request};
use shunt_plugin_sdk::{HookMask, HttpPlugin};

use crate::error::CoreError;
use crate::registry::RuntimeRegistry;
use crate::upstream::{EndpointHealthSnapshot, UpstreamConfig, UpstreamPool, UpstreamPoolKey};

/// Default request body buffer limit (1 MiB) when `REQUEST_BODY_BUFFERED` is active
/// and no explicit cap was configured.
pub const DEFAULT_MAX_BODY_BYTES: usize = 1024 * 1024;

/// Split timeout configuration for a route.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TimeoutConfig {
    /// Time-to-first-byte / upstream response headers timeout.
    pub response_headers_timeout: Option<Duration>,
    /// Maximum idle gap between consecutive streaming response chunks.
    pub idle_chunk_timeout: Option<Duration>,
}

impl Default for TimeoutConfig {
    fn default() -> Self {
        Self {
            response_headers_timeout: Some(Duration::from_secs(30)),
            idle_chunk_timeout: Some(Duration::from_secs(60)),
        }
    }
}

/// Path matching rule for a route.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum PathMatch {
    /// Matches any path.
    #[default]
    Any,
    /// Matches an exact path (e.g. `"/v1/chat/completions"`).
    Exact(String),
    /// Matches paths starting with the prefix (e.g. `"/api"` matches `"/api"` and `"/api/foo"`).
    Prefix(String),
}

impl PathMatch {
    pub fn matches(&self, path: &str) -> bool {
        match self {
            PathMatch::Any => true,
            PathMatch::Exact(exact) => path == exact,
            PathMatch::Prefix(prefix) => {
                if prefix == "/" {
                    return true;
                }
                let trimmed = prefix.trim_end_matches('/');
                if path == trimmed {
                    return true;
                }
                path.starts_with(trimmed) && path.as_bytes().get(trimmed.len()) == Some(&b'/')
            }
        }
    }
}

/// Request matcher for a compiled route.
#[derive(Debug, Clone, Default)]
pub struct RouteMatch {
    /// Optional host filters (exact or `*.suffix`). Empty matches any host.
    pub hosts: Vec<String>,
    /// Path match rule.
    pub path: PathMatch,
    /// Optional HTTP method filters. Empty matches any method.
    pub methods: Vec<Method>,
}

impl RouteMatch {
    pub fn any() -> Self {
        Self::default()
    }

    pub fn prefix(prefix: impl Into<String>) -> Self {
        Self {
            path: PathMatch::Prefix(prefix.into()),
            ..Self::default()
        }
    }

    pub fn exact(path: impl Into<String>) -> Self {
        Self {
            path: PathMatch::Exact(path.into()),
            ..Self::default()
        }
    }

    pub fn with_host(mut self, host: impl Into<String>) -> Self {
        self.hosts.push(host.into().to_ascii_lowercase());
        self
    }

    pub fn with_method(mut self, method: Method) -> Self {
        self.methods.push(method);
        self
    }

    pub fn matches<B>(&self, req: &Request<B>) -> bool {
        if !self.methods.is_empty() && !self.methods.contains(req.method()) {
            return false;
        }

        if !self.path.matches(req.uri().path()) {
            return false;
        }

        if !self.hosts.is_empty() {
            let req_host = extract_request_host(req);
            let Some(host) = req_host else {
                return false;
            };
            if !self
                .hosts
                .iter()
                .any(|pattern| host_matches(pattern, &host))
            {
                return false;
            }
        }

        true
    }
}

fn extract_request_host<B>(req: &Request<B>) -> Option<String> {
    if let Some(authority) = req.uri().authority() {
        return Some(authority.host().to_ascii_lowercase());
    }
    req.headers()
        .get(http::header::HOST)
        .and_then(|v| v.to_str().ok())
        .map(|h| {
            // Strip optional `:port` (handling IPv6 bracketed hosts too).
            let without_port = if let Some(rest) = h.strip_prefix('[') {
                rest.split_once(']').map(|(ip, _)| ip).unwrap_or(h)
            } else {
                h.split_once(':').map(|(name, _)| name).unwrap_or(h)
            };
            without_port.to_ascii_lowercase()
        })
}

/// Matches a host against an exact pattern or `*.suffix` wildcard (case-insensitive, zero-alloc).
pub fn host_matches(pattern: &str, host: &str) -> bool {
    if let Some(suffix) = pattern.strip_prefix("*.") {
        host.len() > suffix.len() + 1
            && host.as_bytes()[host.len() - suffix.len() - 1] == b'.'
            && host.as_bytes()[host.len() - suffix.len()..].eq_ignore_ascii_case(suffix.as_bytes())
    } else {
        pattern.eq_ignore_ascii_case(host)
    }
}

/// Uncompiled route specification passed to [`SnapshotBuilder`].
pub struct RouteSpec {
    pub id: String,
    pub matcher: RouteMatch,
    pub upstream: String,
    pub plugins: Vec<Arc<dyn HttpPlugin>>,
    pub max_body_bytes: Option<usize>,
    pub max_attempts: usize,
    pub timeouts: TimeoutConfig,
    pub allow_websockets: bool,
    pub strip_prefix: Option<String>,
}

impl RouteSpec {
    pub fn new(id: impl Into<String>, matcher: RouteMatch, upstream: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            matcher,
            upstream: upstream.into(),
            plugins: Vec::new(),
            max_body_bytes: None,
            max_attempts: 1,
            timeouts: TimeoutConfig::default(),
            allow_websockets: true,
            strip_prefix: None,
        }
    }

    pub fn with_plugin(mut self, plugin: Arc<dyn HttpPlugin>) -> Self {
        self.plugins.push(plugin);
        self
    }

    pub fn with_max_body_bytes(mut self, max_bytes: usize) -> Self {
        self.max_body_bytes = Some(max_bytes);
        self
    }

    pub fn with_max_attempts(mut self, max_attempts: usize) -> Self {
        self.max_attempts = max_attempts.max(1);
        self
    }

    pub fn with_timeouts(mut self, timeouts: TimeoutConfig) -> Self {
        self.timeouts = timeouts;
        self
    }

    pub fn with_strip_prefix(mut self, prefix: impl Into<String>) -> Self {
        self.strip_prefix = Some(prefix.into());
        self
    }

    pub fn allow_websockets(mut self, allow: bool) -> Self {
        self.allow_websockets = allow;
        self
    }
}

/// Immutable compiled route baked into a [`GatewaySnapshot`].
pub struct CompiledRoute {
    pub id: String,
    pub matcher: RouteMatch,
    pub upstream: String,
    pub plugins: Arc<[Arc<dyn HttpPlugin>]>,
    pub hook_mask: HookMask,
    pub max_body_bytes: usize,
    pub max_attempts: usize,
    pub timeouts: TimeoutConfig,
    pub allow_websockets: bool,
    pub strip_prefix: Option<String>,
}

impl std::fmt::Debug for CompiledRoute {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CompiledRoute")
            .field("id", &self.id)
            .field("upstream", &self.upstream)
            .field("hook_mask", &self.hook_mask)
            .field("max_body_bytes", &self.max_body_bytes)
            .field("max_attempts", &self.max_attempts)
            .field("plugin_count", &self.plugins.len())
            .finish()
    }
}

/// Immutable, atomically-swappable gateway configuration snapshot.
#[derive(Debug)]
pub struct GatewaySnapshot {
    pub version: u64,
    pub routes: Vec<Arc<CompiledRoute>>,
    pub upstreams: HashMap<String, Arc<UpstreamPool>>,
}

/// Live health report for a single compiled upstream pool.
#[derive(Debug, Clone)]
pub struct UpstreamHealthReport {
    pub name: String,
    pub pool_id: u64,
    pub active_health_check: bool,
    pub endpoints: Vec<EndpointHealthSnapshot>,
}

impl GatewaySnapshot {
    /// Finds the first matching compiled route for the incoming request.
    pub fn match_route<B>(&self, req: &Request<B>) -> Option<&Arc<CompiledRoute>> {
        self.routes.iter().find(|r| r.matcher.matches(req))
    }

    /// Looks up a compiled upstream pool by name.
    pub fn upstream(&self, name: &str) -> Option<&Arc<UpstreamPool>> {
        self.upstreams.get(name)
    }

    /// Collects live health & weight snapshots across all upstreams, sorted deterministically by name.
    pub fn upstream_health_reports(&self) -> Vec<UpstreamHealthReport> {
        let mut reports: Vec<UpstreamHealthReport> = self
            .upstreams
            .iter()
            .map(|(name, pool)| UpstreamHealthReport {
                name: name.clone(),
                pool_id: pool.pool_id(),
                active_health_check: pool.active_health_check().is_some(),
                endpoints: pool.endpoint_health_snapshots(),
            })
            .collect();
        reports.sort_by(|a, b| a.name.cmp(&b.name));
        reports
    }

    /// Renders live upstream endpoint health gauges and active probe counters in Prometheus
    /// exposition text format (v0.0.4).
    pub fn render_upstream_health_prometheus(&self) -> String {
        let reports = self.upstream_health_reports();
        if reports.is_empty() {
            return String::new();
        }

        let mut out = String::with_capacity(512);
        out.push_str(
            "# HELP shunt_upstream_endpoint_healthy Current effective endpoint health (1=healthy, 0=unhealthy).\n",
        );
        out.push_str("# TYPE shunt_upstream_endpoint_healthy gauge\n");

        let mut has_probes = false;
        for r in &reports {
            for ep in &r.endpoints {
                let val = if ep.healthy { 1 } else { 0 };
                let _ = writeln!(
                    out,
                    "shunt_upstream_endpoint_healthy{{upstream=\"{}\",endpoint=\"{}\"}} {}",
                    escape_prom_label(&r.name),
                    escape_prom_label(&ep.url),
                    val
                );
                if ep.active_probes_ok > 0 || ep.active_probes_err > 0 {
                    has_probes = true;
                }
            }
        }

        if has_probes {
            out.push_str(
                "# HELP shunt_upstream_active_probes_total Total active upstream health probes executed.\n",
            );
            out.push_str("# TYPE shunt_upstream_active_probes_total counter\n");
            for r in &reports {
                for ep in &r.endpoints {
                    if ep.active_probes_ok > 0 {
                        let _ = writeln!(
                            out,
                            "shunt_upstream_active_probes_total{{upstream=\"{}\",endpoint=\"{}\",result=\"success\"}} {}",
                            escape_prom_label(&r.name),
                            escape_prom_label(&ep.url),
                            ep.active_probes_ok
                        );
                    }
                    if ep.active_probes_err > 0 {
                        let _ = writeln!(
                            out,
                            "shunt_upstream_active_probes_total{{upstream=\"{}\",endpoint=\"{}\",result=\"failure\"}} {}",
                            escape_prom_label(&r.name),
                            escape_prom_label(&ep.url),
                            ep.active_probes_err
                        );
                    }
                }
            }
        }

        out
    }
}

fn escape_prom_label(s: &str) -> String {
    s.replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
}

/// Compiles routes, global plugins, and upstreams into an immutable [`GatewaySnapshot`],
/// reusing warm upstream pools from [`RuntimeRegistry`].
pub struct SnapshotBuilder {
    version: u64,
    global_plugins: Vec<Arc<dyn HttpPlugin>>,
    upstreams: Vec<UpstreamConfig>,
    routes: Vec<RouteSpec>,
}

impl SnapshotBuilder {
    pub fn new(version: u64) -> Self {
        Self {
            version,
            global_plugins: Vec::new(),
            upstreams: Vec::new(),
            routes: Vec::new(),
        }
    }

    pub fn global_plugin(mut self, plugin: Arc<dyn HttpPlugin>) -> Self {
        self.global_plugins.push(plugin);
        self
    }

    pub fn upstream(mut self, upstream: UpstreamConfig) -> Self {
        self.upstreams.push(upstream);
        self
    }

    pub fn route(mut self, route: RouteSpec) -> Self {
        self.routes.push(route);
        self
    }

    /// Compiles and validates the snapshot transactionally, reusing existing warm pools in
    /// `registry` and staging newly created pools so a failed build never mutates `registry`.
    /// When compilation succeeds, staged pools are committed and (if `gc_unused_pools` is
    /// true) pools no longer referenced by this snapshot are garbage-collected atomically.
    pub fn build(
        self,
        registry: &RuntimeRegistry,
        gc_unused_pools: bool,
    ) -> Result<Arc<GatewaySnapshot>, CoreError> {
        let mut compiled_upstreams: HashMap<String, Arc<UpstreamPool>> =
            HashMap::with_capacity(self.upstreams.len());
        let mut upstream_keys_by_name: HashMap<String, UpstreamPoolKey> =
            HashMap::with_capacity(self.upstreams.len());
        let mut staged_pools: HashMap<UpstreamPoolKey, Arc<UpstreamPool>> = HashMap::new();
        let mut active_pool_keys: HashSet<UpstreamPoolKey> =
            HashSet::with_capacity(self.upstreams.len());

        for up_cfg in &self.upstreams {
            if compiled_upstreams.contains_key(&up_cfg.name) {
                return Err(CoreError::Config(format!(
                    "duplicate upstream `{}`",
                    up_cfg.name
                )));
            }
            let key = up_cfg.pool_key();
            let pool = if let Some(existing) = registry.get_pool(&key) {
                existing
            } else if let Some(staged) = staged_pools.get(&key) {
                Arc::clone(staged)
            } else {
                let created = registry.create_pool_unstaged(up_cfg)?;
                staged_pools.insert(key.clone(), Arc::clone(&created));
                created
            };
            active_pool_keys.insert(key.clone());
            upstream_keys_by_name.insert(up_cfg.name.clone(), key);
            compiled_upstreams.insert(up_cfg.name.clone(), pool);
        }

        let mut seen_route_ids = HashSet::with_capacity(self.routes.len());
        let mut compiled_routes = Vec::with_capacity(self.routes.len());

        for spec in self.routes {
            if !seen_route_ids.insert(spec.id.clone()) {
                return Err(CoreError::Config(format!(
                    "duplicate route id `{}`",
                    spec.id
                )));
            }
            if !compiled_upstreams.contains_key(&spec.upstream) {
                return Err(CoreError::UnknownUpstream(spec.upstream));
            }

            let mut chain = Vec::with_capacity(self.global_plugins.len() + spec.plugins.len());
            chain.extend(self.global_plugins.iter().cloned());
            chain.extend(spec.plugins);

            let mut hook_mask = HookMask::EMPTY;
            let mut effective_max_body: Option<usize> = spec.max_body_bytes;

            for plugin in &chain {
                hook_mask |= plugin.hook_mask();
                if let Some(cap) = plugin.max_request_body_bytes() {
                    effective_max_body = Some(match effective_max_body {
                        Some(cur) => cur.min(cap),
                        None => cap,
                    });
                }
            }

            compiled_routes.push(Arc::new(CompiledRoute {
                id: spec.id,
                matcher: spec.matcher,
                upstream: spec.upstream,
                plugins: Arc::from(chain),
                hook_mask,
                max_body_bytes: effective_max_body.unwrap_or(DEFAULT_MAX_BODY_BYTES),
                max_attempts: spec.max_attempts.max(1),
                timeouts: spec.timeouts,
                allow_websockets: spec.allow_websockets,
                strip_prefix: spec.strip_prefix,
            }));
        }

        // All validation & route compilation succeeded: atomically commit staged pools (+ GC).
        let canonical_staged =
            registry.commit_pools(staged_pools, gc_unused_pools.then_some(&active_pool_keys));
        if !canonical_staged.is_empty() {
            for (name, key) in upstream_keys_by_name {
                if let Some(canonical) = canonical_staged.get(&key) {
                    compiled_upstreams.insert(name, Arc::clone(canonical));
                }
            }
        }

        Ok(Arc::new(GatewaySnapshot {
            version: self.version,
            routes: compiled_routes,
            upstreams: compiled_upstreams,
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn path_prefix_matching() {
        let p = PathMatch::Prefix("/api".into());
        assert!(p.matches("/api"));
        assert!(p.matches("/api/"));
        assert!(p.matches("/api/v1/users"));
        assert!(!p.matches("/apiv2"));
        assert!(!p.matches("/other"));

        let root = PathMatch::Prefix("/".into());
        assert!(root.matches("/"));
        assert!(root.matches("/anything"));
    }

    #[test]
    fn host_wildcard_matching() {
        assert!(host_matches("example.com", "example.com"));
        assert!(!host_matches("example.com", "api.example.com"));
        assert!(host_matches("*.example.com", "api.example.com"));
        assert!(host_matches("*.example.com", "a.b.example.com"));
        assert!(!host_matches("*.example.com", "example.com"));
    }
}

#[cfg(kani)]
mod kani_proofs {
    use super::{PathMatch, host_matches};

    #[kani::proof]
    #[kani::unwind(16)]
    fn path_prefix_boundary_safety() {
        let c: u8 = kani::any();
        kani::assume(c.is_ascii_lowercase());

        let sibling_bytes = [b'/', b'a', b'p', b'i', c];
        let child_bytes = [b'/', b'a', b'p', b'i', b'/', c];
        let sibling = std::str::from_utf8(&sibling_bytes).unwrap();
        let child = std::str::from_utf8(&child_bytes).unwrap();

        let matcher = PathMatch::Prefix("/api".to_owned());
        assert!(matcher.matches("/api"));
        assert!(matcher.matches(child));
        assert!(!matcher.matches(sibling));
    }

    #[kani::proof]
    #[kani::unwind(24)]
    fn host_wildcard_never_matches_bare_suffix() {
        assert!(!host_matches("*.example.com", "example.com"));
        let c: u8 = kani::any();
        kani::assume(c.is_ascii_alphabetic());

        let valid_bytes = [
            c, b'.', b'e', b'x', b'a', b'm', b'p', b'l', b'e', b'.', b'c', b'o', b'm',
        ];
        let valid = std::str::from_utf8(&valid_bytes).unwrap();
        assert!(host_matches("*.example.com", valid));
        assert!(host_matches("*.EXAMPLE.COM", valid));
    }
}
