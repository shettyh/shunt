use std::collections::{HashMap, HashSet};
use std::fmt::Write as _;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use http::header::{HeaderName, HeaderValue};
use http::{Method, Request, StatusCode};
use regex::{RegexSet, RegexSetBuilder};
use shunt_plugin_sdk::{HookMask, HttpPlugin};
use tokio::sync::Semaphore;

use crate::error::CoreError;
use crate::path_match::{
    CompiledPathRegex, CompiledPathTemplate, DEFAULT_PATH_REGEX_SIZE_LIMIT, PathMatch,
};
use crate::registry::RuntimeRegistry;
use crate::route_index::{ROUTE_INDEX_MIN_ROUTES, RouteIndex};
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

/// Request matcher for a compiled route.
#[derive(Debug, Clone, Default)]
pub struct RouteMatch {
    /// Optional host filters (exact or `*.suffix`). Empty matches any host.
    pub hosts: Vec<String>,
    /// Path match rule.
    pub path: PathMatch,
    /// Optional HTTP method filters. Empty matches any method.
    pub methods: Vec<Method>,
    /// Optional exact HTTP header matchers (all must match). Empty matches any headers.
    pub headers: Vec<(HeaderName, String)>,
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

    pub fn template(template: &str) -> Result<Self, String> {
        Ok(Self {
            path: PathMatch::Template(CompiledPathTemplate::parse(template)?),
            ..Self::default()
        })
    }

    pub fn regex(pattern: &str) -> Result<Self, String> {
        Ok(Self {
            path: PathMatch::Regex(CompiledPathRegex::compile(pattern)?),
            ..Self::default()
        })
    }

    pub fn with_host(mut self, host: impl Into<String>) -> Self {
        self.hosts.push(host.into().to_ascii_lowercase());
        self
    }

    pub fn with_method(mut self, method: Method) -> Self {
        self.methods.push(method);
        self
    }

    pub fn with_header(mut self, name: HeaderName, value: impl Into<String>) -> Self {
        self.headers.push((name, value.into()));
        self
    }

    /// Checks non-path match dimensions (`methods`, `hosts`, `headers`).
    pub fn matches_non_path<B>(&self, req: &Request<B>) -> bool {
        let mut cached_host = None;
        self.matches_non_path_cached(req, &mut cached_host)
    }

    /// Checks non-path match dimensions (`methods`, `hosts`, `headers`) with lazy request-host caching.
    #[inline]
    pub(crate) fn matches_non_path_cached<'a, B>(
        &self,
        req: &'a Request<B>,
        cached_host: &mut Option<Option<&'a str>>,
    ) -> bool {
        if !self.methods.is_empty() && !self.methods.contains(req.method()) {
            return false;
        }

        if !self.hosts.is_empty() {
            let req_host = *cached_host.get_or_insert_with(|| extract_request_host(req));
            let Some(host) = req_host else {
                return false;
            };
            if !self.hosts.iter().any(|pattern| host_matches(pattern, host)) {
                return false;
            }
        }

        if !self.headers.is_empty() {
            for (name, expected) in &self.headers {
                let matched = req
                    .headers()
                    .get_all(name)
                    .iter()
                    .any(|v| v.to_str().map(|s| s == expected).unwrap_or(false));
                if !matched {
                    return false;
                }
            }
        }

        true
    }

    pub fn matches<B>(&self, req: &Request<B>) -> bool {
        if !self.methods.is_empty() && !self.methods.contains(req.method()) {
            return false;
        }

        // For regex routes, check cheap host filters before invoking the regex engine.
        if matches!(self.path, PathMatch::Regex(_)) {
            if !self.hosts.is_empty() {
                let Some(host) = extract_request_host(req) else {
                    return false;
                };
                if !self.hosts.iter().any(|pattern| host_matches(pattern, host)) {
                    return false;
                }
            }
            if !self.path.matches(req.uri().path()) {
                return false;
            }
        } else {
            if !self.path.matches(req.uri().path()) {
                return false;
            }
            if !self.hosts.is_empty() {
                let Some(host) = extract_request_host(req) else {
                    return false;
                };
                if !self.hosts.iter().any(|pattern| host_matches(pattern, host)) {
                    return false;
                }
            }
        }

        if !self.headers.is_empty() {
            for (name, expected) in &self.headers {
                let matched = req
                    .headers()
                    .get_all(name)
                    .iter()
                    .any(|v| v.to_str().map(|s| s == expected).unwrap_or(false));
                if !matched {
                    return false;
                }
            }
        }

        true
    }
}

#[inline]
fn extract_request_host<B>(req: &Request<B>) -> Option<&str> {
    if let Some(authority) = req.uri().authority() {
        return Some(authority.host());
    }
    req.headers()
        .get(http::header::HOST)
        .and_then(|v| v.to_str().ok())
        .map(|h| {
            // Strip optional `:port` (handling IPv6 bracketed hosts too).
            if let Some(rest) = h.strip_prefix('[') {
                rest.split_once(']').map(|(ip, _)| ip).unwrap_or(h)
            } else {
                h.split_once(':').map(|(name, _)| name).unwrap_or(h)
            }
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

/// Uncompiled fire-and-forget HTTP traffic mirroring specification attached to a [`RouteSpec`].
#[derive(Debug, Clone)]
pub struct TrafficMirrorSpec {
    /// Target upstream pool name to receive mirrored copies.
    pub upstream: String,
    /// Fraction of requests to mirror in `[0.0, 1.0]` (default: `1.0`).
    pub sample_rate: f64,
    /// Per-mirror upstream request timeout (default: `5s`).
    pub timeout: Duration,
    /// Maximum concurrent in-flight mirrored requests (excess are dropped silently, default: `128`).
    pub max_in_flight: usize,
    /// Optional extra HTTP headers attached to mirrored requests.
    pub headers: Vec<(HeaderName, HeaderValue)>,
}

impl TrafficMirrorSpec {
    pub fn new(upstream: impl Into<String>, sample_rate: f64) -> Self {
        Self {
            upstream: upstream.into(),
            sample_rate,
            timeout: Duration::from_secs(5),
            max_in_flight: 128,
            headers: Vec::new(),
        }
    }
}

/// Immutable compiled traffic mirror target baked into a [`CompiledRoute`].
#[derive(Debug)]
pub struct CompiledMirror {
    pub upstream: String,
    /// Sampling probability scaled to basis points (`0..=10_000`) for lock-free deterministic sampling.
    pub sample_rate_bps: u32,
    pub timeout: Duration,
    pub headers: Vec<(HeaderName, HeaderValue)>,
    pub semaphore: Arc<Semaphore>,
    sample_cursor: AtomicU64,
    pub sent_total: AtomicU64,
    pub dropped_total: AtomicU64,
    pub errors_total: AtomicU64,
}

impl CompiledMirror {
    fn from_spec(spec: TrafficMirrorSpec) -> Self {
        let clamped = if spec.sample_rate.is_finite() {
            spec.sample_rate.clamp(0.0, 1.0)
        } else {
            0.0
        };
        let sample_rate_bps = (clamped * 10_000.0).round() as u32;
        Self {
            upstream: spec.upstream,
            sample_rate_bps,
            timeout: spec.timeout.max(Duration::from_millis(1)),
            headers: spec.headers,
            semaphore: Arc::new(Semaphore::new(spec.max_in_flight.max(1))),
            sample_cursor: AtomicU64::new(0),
            sent_total: AtomicU64::new(0),
            dropped_total: AtomicU64::new(0),
            errors_total: AtomicU64::new(0),
        }
    }

    /// Deterministically decides whether the next request should be mirrored using
    /// lock-free fixed-point stride sampling (no RNG overhead).
    #[inline]
    pub fn should_sample(&self) -> bool {
        if self.sample_rate_bps == 0 {
            return false;
        }
        if self.sample_rate_bps >= 10_000 {
            return true;
        }
        let n = self.sample_cursor.fetch_add(1, Ordering::Relaxed);
        let rate = self.sample_rate_bps as u64;
        // Bresenham/fixed-point exact stride: triggers exactly `rate` times per 10,000 requests.
        ((n.wrapping_add(1)).wrapping_mul(rate) / 10_000) > (n.wrapping_mul(rate) / 10_000)
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
    pub allow_raw_path: bool,
    pub strip_prefix: Option<String>,
    pub mirrors: Vec<TrafficMirrorSpec>,
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
            allow_websockets: false,
            allow_raw_path: false,
            strip_prefix: None,
            mirrors: Vec::new(),
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

    pub fn allow_raw_path(mut self, allow: bool) -> Self {
        self.allow_raw_path = allow;
        self
    }

    pub fn with_mirror(mut self, mirror: TrafficMirrorSpec) -> Self {
        self.mirrors.push(mirror);
        self
    }
}

/// Maximum combined memory budget for a snapshot's multi-pattern `RegexSet` accelerator (16 MiB).
pub(crate) const MAX_REGEX_SET_SIZE_LIMIT: usize = 16 * 1024 * 1024;

/// Compiled multi-pattern `RegexSet` accelerator baked into small [`GatewaySnapshot`]s when
/// one or more routes use [`PathMatch::Regex`].
struct CompiledRegexTable {
    set: RegexSet,
    min_route_idx: usize,
}

impl std::fmt::Debug for CompiledRegexTable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CompiledRegexTable")
            .field("pattern_count", &self.set.len())
            .field("min_route_idx", &self.min_route_idx)
            .finish()
    }
}

/// Internal route dispatch strategy selected at [`SnapshotBuilder::build`] time.
#[derive(Debug)]
enum RouteDispatch {
    /// Small route tables with no regex routes: tight L1-cache linear scan.
    Linear,
    /// Small route tables with `>= 1` regex route: linear prefix scan + single-pass `RegexSet`.
    LinearWithRegex(CompiledRegexTable),
    /// Medium/large route tables (`>= ROUTE_INDEX_MIN_ROUTES`): Exact hash map + Segment Trie + `RegexSet`.
    Indexed(Box<RouteIndex>),
}

/// Immutable compiled route baked into a [`GatewaySnapshot`].
pub struct CompiledRoute {
    pub id: String,
    pub matcher: RouteMatch,
    pub upstream: String,
    pub plugins: Arc<[Arc<dyn HttpPlugin>]>,
    pub hook_mask: HookMask,
    pub max_body_bytes: usize,
    /// Explicit request body cap set by route config or a plugin (`max_request_body_bytes`).
    /// Enforced on both buffered and unbuffered streaming requests (`None` = unlimited streaming).
    pub explicit_max_body_bytes: Option<usize>,
    /// HTTP 4xx status code returned when `max_body_bytes` is exceeded (default: `413`).
    pub max_body_status: StatusCode,
    pub max_attempts: usize,
    pub timeouts: TimeoutConfig,
    pub allow_websockets: bool,
    pub allow_raw_path: bool,
    pub strip_prefix: Option<String>,
    pub mirrors: Arc<[Arc<CompiledMirror>]>,
    /// Slot index inside [`GatewaySnapshot`]'s compiled [`RegexSet`], if this route uses `PathMatch::Regex`.
    regex_set_slot: Option<usize>,
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
    pub has_raw_path_routes: bool,
    dispatch: RouteDispatch,
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
    /// Returns `true` if this snapshot uses the internal [`RouteIndex`] accelerator.
    #[inline]
    pub fn is_indexed(&self) -> bool {
        matches!(self.dispatch, RouteDispatch::Indexed(_))
    }

    /// Finds the first matching compiled route for the incoming request.
    ///
    /// Preserves strict first-match-wins declaration order while accelerating larger snapshots
    /// with [`RouteIndex`] (Exact hash map + Segment Trie + single-pass `RegexSet`) and small
    /// regex snapshots with a single-pass `RegexSet` scan.
    #[inline]
    pub fn match_route<B>(&self, req: &Request<B>) -> Option<&Arc<CompiledRoute>> {
        match &self.dispatch {
            RouteDispatch::Linear => self.routes.iter().find(|r| r.matcher.matches(req)),
            RouteDispatch::Indexed(index) => index.match_route(&self.routes, req),
            RouteDispatch::LinearWithRegex(rt) => self.match_route_linear_with_regex(rt, req),
        }
    }

    fn match_route_linear_with_regex<B>(
        &self,
        rt: &CompiledRegexTable,
        req: &Request<B>,
    ) -> Option<&Arc<CompiledRoute>> {
        // Fast-path: check all routes strictly preceding the first regex route.
        for route in &self.routes[..rt.min_route_idx] {
            if route.matcher.matches(req) {
                return Some(route);
            }
        }

        // Single linear-time O(path_len) pass across all regex routes in this snapshot.
        let regex_matches = rt.set.matches(req.uri().path());
        let mut cached_host = None;
        for route in &self.routes[rt.min_route_idx..] {
            if let Some(slot) = route.regex_set_slot {
                if regex_matches.matched(slot)
                    && route.matcher.matches_non_path_cached(req, &mut cached_host)
                {
                    return Some(route);
                }
            } else if route.matcher.matches(req) {
                return Some(route);
            }
        }
        None
    }

    /// Reference linear first-match-wins route lookup (used by equivalence property tests).
    pub fn match_route_linear<B>(&self, req: &Request<B>) -> Option<&Arc<CompiledRoute>> {
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

    /// Renders traffic mirror counters in Prometheus exposition text format (v0.0.4).
    pub fn render_mirror_metrics_prometheus(&self) -> String {
        let mut has_mirrors = false;
        for route in &self.routes {
            if !route.mirrors.is_empty() {
                has_mirrors = true;
                break;
            }
        }
        if !has_mirrors {
            return String::new();
        }

        let mut out = String::with_capacity(256);
        out.push_str(
            "# HELP shunt_traffic_mirror_requests_total Total HTTP traffic mirror dispatch outcomes.\n",
        );
        out.push_str("# TYPE shunt_traffic_mirror_requests_total counter\n");
        for route in &self.routes {
            for m in route.mirrors.iter() {
                let sent = m.sent_total.load(Ordering::Relaxed);
                let dropped = m.dropped_total.load(Ordering::Relaxed);
                let errors = m.errors_total.load(Ordering::Relaxed);
                for (result, count) in [("sent", sent), ("dropped", dropped), ("error", errors)] {
                    if count > 0 {
                        let _ = writeln!(
                            out,
                            "shunt_traffic_mirror_requests_total{{route=\"{}\",upstream=\"{}\",result=\"{result}\"}} {count}",
                            escape_prom_label(&route.id),
                            escape_prom_label(&m.upstream),
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
        let will_index =
            self.routes.len() >= ROUTE_INDEX_MIN_ROUTES && self.routes.len() < u32::MAX as usize;
        let mut regex_patterns: Vec<String> = Vec::new();
        let mut min_regex_route_idx: Option<usize> = None;

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
            for m in &spec.mirrors {
                if !compiled_upstreams.contains_key(&m.upstream) {
                    return Err(CoreError::UnknownUpstream(m.upstream.clone()));
                }
            }

            let mut chain = Vec::with_capacity(self.global_plugins.len() + spec.plugins.len());
            chain.extend(self.global_plugins.iter().cloned());
            chain.extend(spec.plugins);

            let mut hook_mask = HookMask::EMPTY;
            let mut effective_max_body: Option<usize> = spec.max_body_bytes;
            let mut max_body_status = StatusCode::PAYLOAD_TOO_LARGE;

            for plugin in &chain {
                hook_mask |= plugin.hook_mask();
                if let Some(cap) = plugin.max_request_body_bytes() {
                    let is_tighter = effective_max_body.is_none_or(|cur| cap <= cur);
                    effective_max_body = Some(match effective_max_body {
                        Some(cur) => cur.min(cap),
                        None => cap,
                    });
                    if is_tighter && let Some(st) = plugin.max_request_body_status_code() {
                        max_body_status = st;
                    }
                }
            }

            let compiled_mirrors: Vec<Arc<CompiledMirror>> = spec
                .mirrors
                .into_iter()
                .map(|m| Arc::new(CompiledMirror::from_spec(m)))
                .collect();

            let route_idx = compiled_routes.len();
            let regex_set_slot = if !will_index && let PathMatch::Regex(re) = &spec.matcher.path {
                let slot = regex_patterns.len();
                regex_patterns.push(re.anchored_pattern().to_owned());
                if min_regex_route_idx.is_none() {
                    min_regex_route_idx = Some(route_idx);
                }
                Some(slot)
            } else {
                None
            };

            compiled_routes.push(Arc::new(CompiledRoute {
                id: spec.id,
                matcher: spec.matcher,
                upstream: spec.upstream,
                plugins: Arc::from(chain),
                hook_mask,
                max_body_bytes: effective_max_body.unwrap_or(DEFAULT_MAX_BODY_BYTES),
                explicit_max_body_bytes: effective_max_body,
                max_body_status,
                max_attempts: spec.max_attempts.max(1),
                timeouts: spec.timeouts,
                allow_websockets: spec.allow_websockets,
                allow_raw_path: spec.allow_raw_path,
                strip_prefix: spec.strip_prefix,
                mirrors: Arc::from(compiled_mirrors),
                regex_set_slot,
            }));
        }

        let dispatch = if compiled_routes.len() >= ROUTE_INDEX_MIN_ROUTES
            && compiled_routes.len() < u32::MAX as usize
        {
            RouteDispatch::Indexed(Box::new(RouteIndex::build(&compiled_routes)))
        } else if let Some(min_route_idx) = min_regex_route_idx {
            let budget = DEFAULT_PATH_REGEX_SIZE_LIMIT
                .saturating_mul(regex_patterns.len().max(1))
                .min(MAX_REGEX_SET_SIZE_LIMIT);
            match RegexSetBuilder::new(&regex_patterns)
                .size_limit(budget)
                .dfa_size_limit(budget)
                .build()
            {
                Ok(set) => {
                    RouteDispatch::LinearWithRegex(CompiledRegexTable { set, min_route_idx })
                }
                Err(_) => RouteDispatch::Linear,
            }
        } else {
            RouteDispatch::Linear
        };

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

        let has_raw_path_routes = compiled_routes.iter().any(|r| r.allow_raw_path);

        Ok(Arc::new(GatewaySnapshot {
            version: self.version,
            routes: compiled_routes,
            upstreams: compiled_upstreams,
            has_raw_path_routes,
            dispatch,
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
