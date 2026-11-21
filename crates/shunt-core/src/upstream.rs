use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicUsize, Ordering};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use http::header::{HeaderName, HeaderValue};
use http::{Method, Uri};
use http_body_util::BodyExt;
use hyper::rt::{Read, ReadBufCursor, Write};
use hyper_util::client::legacy::Client;
use hyper_util::client::legacy::connect::{Connected, Connection};
use hyper_util::rt::{TokioExecutor, TokioIo};
use rustls::pki_types::ServerName;
use shunt_plugin_sdk::{Clock, SystemClock};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tower_service::Service;

use crate::body::ShuntBody;
use crate::error::CoreError;
use crate::tls::UpstreamTlsConfig;

/// Maximum precomputed smooth weighted round-robin schedule length.
/// Larger co-prime weight sums fall back to deterministic cumulative-weight selection.
pub const MAX_SWRR_SCHEDULE_LEN: usize = 4096;

/// Single upstream endpoint with a relative selection weight (`>= 1`).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct UpstreamEndpoint {
    pub url: String,
    pub weight: u32,
}

impl UpstreamEndpoint {
    pub fn new(url: impl Into<String>) -> Self {
        Self {
            url: url.into(),
            weight: 1,
        }
    }

    pub fn with_weight(url: impl Into<String>, weight: u32) -> Self {
        Self {
            url: url.into(),
            weight: weight.max(1),
        }
    }
}

impl From<String> for UpstreamEndpoint {
    fn from(url: String) -> Self {
        Self::new(url)
    }
}

impl From<&str> for UpstreamEndpoint {
    fn from(url: &str) -> Self {
        Self::new(url)
    }
}

/// Active health probe protocol configuration.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ActiveProbeKind {
    Http {
        method: String,
        path: String,
        expected_statuses: Vec<u16>,
        headers: Vec<(String, String)>,
    },
    Tcp,
}

impl Default for ActiveProbeKind {
    fn default() -> Self {
        Self::Http {
            method: "GET".to_owned(),
            path: "/health".to_owned(),
            expected_statuses: vec![200],
            headers: Vec::new(),
        }
    }
}

/// Active background health probe configuration for an upstream cluster.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ActiveHealthCheckConfig {
    pub kind: ActiveProbeKind,
    pub interval: Duration,
    pub timeout: Duration,
    pub unhealthy_threshold: usize,
    pub healthy_threshold: usize,
    pub initial_healthy: bool,
}

impl Default for ActiveHealthCheckConfig {
    fn default() -> Self {
        Self {
            kind: ActiveProbeKind::default(),
            interval: Duration::from_secs(10),
            timeout: Duration::from_secs(2),
            unhealthy_threshold: 2,
            healthy_threshold: 1,
            initial_healthy: true,
        }
    }
}

/// Point-in-time health snapshot of an endpoint (for `GET /upstreams` and Prometheus metrics).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EndpointHealthSnapshot {
    pub url: String,
    pub weight: u32,
    pub healthy: bool,
    pub active_healthy: bool,
    pub passive_healthy: bool,
    pub passive_failures: usize,
    pub active_probes_ok: u64,
    pub active_probes_err: u64,
    pub last_probe_latency_us: u64,
}

/// Configuration for a logical upstream cluster.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct UpstreamConfig {
    pub name: String,
    /// Endpoint definitions (URL + relative weight >= 1).
    pub endpoints: Vec<UpstreamEndpoint>,
    /// Use HTTP/2 prior knowledge (h2c) for cleartext endpoints.
    pub http2_only: bool,
    /// Upstream TLS settings.
    pub tls: UpstreamTlsConfig,
    /// Timeout for TCP connect + TLS handshake.
    pub connect_timeout: Duration,
    /// Idle timeout for pooled keep-alive connections.
    pub pool_idle_timeout: Duration,
    /// Maximum idle connections kept per host.
    pub pool_max_idle_per_host: usize,
    /// Consecutive transport failures before marking an endpoint temporarily unhealthy.
    pub unhealthy_threshold: usize,
    /// Cooldown duration before retrying a passively marked unhealthy endpoint.
    pub unhealthy_cooldown: Duration,
    /// Optional active background health check settings.
    pub active_health_check: Option<ActiveHealthCheckConfig>,
}

impl UpstreamConfig {
    pub fn new(name: impl Into<String>, endpoints: Vec<String>) -> Self {
        Self::with_endpoints(
            name,
            endpoints.into_iter().map(UpstreamEndpoint::new).collect(),
        )
    }

    pub fn with_endpoints(name: impl Into<String>, endpoints: Vec<UpstreamEndpoint>) -> Self {
        Self {
            name: name.into(),
            endpoints,
            http2_only: false,
            tls: UpstreamTlsConfig::default(),
            connect_timeout: Duration::from_secs(5),
            pool_idle_timeout: Duration::from_secs(90),
            pool_max_idle_per_host: 64,
            unhealthy_threshold: 3,
            unhealthy_cooldown: Duration::from_secs(10),
            active_health_check: None,
        }
    }

    pub fn with_active_health_check(mut self, hc: ActiveHealthCheckConfig) -> Self {
        self.active_health_check = Some(hc);
        self
    }

    /// Computes the pool identity key used by [`crate::RuntimeRegistry`] to reuse warm
    /// connection pools and health state across snapshot reloads.
    pub fn pool_key(&self) -> UpstreamPoolKey {
        UpstreamPoolKey {
            endpoints: self.endpoints.clone(),
            http2_only: self.http2_only,
            tls: self.tls.clone(),
            connect_timeout: self.connect_timeout,
            pool_idle_timeout: self.pool_idle_timeout,
            pool_max_idle_per_host: self.pool_max_idle_per_host,
            unhealthy_threshold: self.unhealthy_threshold,
            unhealthy_cooldown: self.unhealthy_cooldown,
            active_health_check: self.active_health_check.clone(),
        }
    }
}

/// Stable pool key determining when an existing warm pool can be reused across reloads.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct UpstreamPoolKey {
    pub endpoints: Vec<UpstreamEndpoint>,
    pub http2_only: bool,
    pub tls: UpstreamTlsConfig,
    pub connect_timeout: Duration,
    pub pool_idle_timeout: Duration,
    pub pool_max_idle_per_host: usize,
    pub unhealthy_threshold: usize,
    pub unhealthy_cooldown: Duration,
    pub active_health_check: Option<ActiveHealthCheckConfig>,
}

const UNHEALTHY_UNTIL_MASK: u64 = (1u64 << 48) - 1;
const FAILURES_SHIFT: u32 = 48;

#[inline]
const fn pack_health(failures: u16, unhealthy_until_ms: u64) -> u64 {
    let clamped_until = if unhealthy_until_ms > UNHEALTHY_UNTIL_MASK {
        UNHEALTHY_UNTIL_MASK
    } else {
        unhealthy_until_ms
    };
    ((failures as u64) << FAILURES_SHIFT) | clamped_until
}

#[inline]
const fn unpack_health(packed: u64) -> (u16, u64) {
    let failures = (packed >> FAILURES_SHIFT) as u16;
    let until = packed & UNHEALTHY_UNTIL_MASK;
    (failures, until)
}

/// Parsed endpoint with single-word atomic passive health tracking and atomic active probe health.
///
/// Passive health packs `(consecutive_failures: u16, unhealthy_until_ms: u48)` into a single
/// `AtomicU64` updated via CAS (`AcqRel`/`Acquire`) so readers never observe split state.
/// Active health composes via `is_active_healthy() && is_passively_healthy(now_ms)`.
#[derive(Debug)]
pub struct EndpointState {
    pub raw_url: String,
    pub base_uri: Uri,
    pub weight: u32,
    health: AtomicU64,
    active_healthy: AtomicBool,
    active_consecutive_failures: AtomicU32,
    active_consecutive_successes: AtomicU32,
    active_probes_ok: AtomicU64,
    active_probes_err: AtomicU64,
    last_probe_latency_us: AtomicU64,
}

impl EndpointState {
    pub fn new(raw_url: String) -> Result<Self, CoreError> {
        Self::new_with_options(raw_url, 1, true)
    }

    pub fn new_with_options(
        raw_url: String,
        weight: u32,
        initial_active_healthy: bool,
    ) -> Result<Self, CoreError> {
        let base_uri: Uri = raw_url.parse().map_err(|e| CoreError::InvalidUri {
            uri: raw_url.clone(),
            message: format!("{e}"),
        })?;

        let scheme = base_uri.scheme_str().unwrap_or("http");
        if scheme != "http" && scheme != "https" {
            return Err(CoreError::InvalidUri {
                uri: raw_url,
                message: format!("unsupported scheme `{scheme}`"),
            });
        }
        if base_uri.authority().is_none() {
            return Err(CoreError::InvalidUri {
                uri: raw_url,
                message: "missing host/authority".to_owned(),
            });
        }

        Ok(Self {
            raw_url,
            base_uri,
            weight: weight.max(1),
            health: AtomicU64::new(0),
            active_healthy: AtomicBool::new(initial_active_healthy),
            active_consecutive_failures: AtomicU32::new(0),
            active_consecutive_successes: AtomicU32::new(0),
            active_probes_ok: AtomicU64::new(0),
            active_probes_err: AtomicU64::new(0),
            last_probe_latency_us: AtomicU64::new(0),
        })
    }

    /// Atomically returns passive `(consecutive_failures, unhealthy_until_ms)`.
    #[inline]
    pub fn health_snapshot(&self) -> (usize, u64) {
        let (failures, until) = unpack_health(self.health.load(Ordering::Acquire));
        (failures as usize, until)
    }

    /// Returns whether this endpoint is currently healthy according to active probes.
    #[inline]
    pub fn is_active_healthy(&self) -> bool {
        self.active_healthy.load(Ordering::Acquire)
    }

    /// Returns whether this endpoint is currently healthy according to passive cooldown state.
    #[inline]
    pub fn is_passively_healthy(&self, now_ms: u64) -> bool {
        let (_, until) = unpack_health(self.health.load(Ordering::Acquire));
        until == 0 || now_ms >= until
    }

    /// Returns effective health combining active probe state and passive cooldown state.
    #[inline]
    pub fn is_healthy(&self, now_ms: u64) -> bool {
        self.is_active_healthy() && self.is_passively_healthy(now_ms)
    }

    #[inline]
    pub fn consecutive_failures(&self) -> usize {
        self.health_snapshot().0
    }

    #[inline]
    pub fn unhealthy_until_ms(&self) -> u64 {
        self.health_snapshot().1
    }

    /// Atomically clears both passive failure counter and cooldown timestamp.
    pub fn record_success(&self) {
        self.health.store(0, Ordering::Release);
    }

    /// Atomically increments consecutive passive failures and activates cooldown once `threshold` is met.
    pub fn record_failure(&self, now_ms: u64, threshold: usize, cooldown: Duration) {
        let threshold_u16 = threshold.clamp(1, u16::MAX as usize) as u16;
        let cooldown_ms = cooldown.as_millis().min(UNHEALTHY_UNTIL_MASK as u128) as u64;

        let mut cur = self.health.load(Ordering::Acquire);
        loop {
            let (cur_failures, cur_until) = unpack_health(cur);
            let next_failures = cur_failures.saturating_add(1);
            let next_until = if next_failures >= threshold_u16 {
                let candidate = now_ms.saturating_add(cooldown_ms).min(UNHEALTHY_UNTIL_MASK);
                cur_until.max(candidate)
            } else {
                cur_until
            };
            let next = pack_health(next_failures, next_until);
            match self
                .health
                .compare_exchange_weak(cur, next, Ordering::AcqRel, Ordering::Acquire)
            {
                Ok(_) => break,
                Err(actual) => cur = actual,
            }
        }
    }

    /// Applies an active probe observation, updating active health thresholds and counters.
    ///
    /// When consecutive successes reach `healthy_threshold`, the endpoint is marked actively
    /// healthy and any passive failure cooldown is cleared immediately so traffic resumes.
    pub fn record_active_probe(
        &self,
        ok: bool,
        latency_us: u64,
        unhealthy_threshold: usize,
        healthy_threshold: usize,
    ) {
        let unhealthy_t = unhealthy_threshold.clamp(1, u32::MAX as usize) as u32;
        let healthy_t = healthy_threshold.clamp(1, u32::MAX as usize) as u32;
        self.last_probe_latency_us
            .store(latency_us, Ordering::Relaxed);

        if ok {
            self.active_probes_ok.fetch_add(1, Ordering::Relaxed);
            self.active_consecutive_failures.store(0, Ordering::Release);
            let succ = self
                .active_consecutive_successes
                .fetch_add(1, Ordering::AcqRel)
                .saturating_add(1);
            if succ >= healthy_t {
                self.active_healthy.store(true, Ordering::Release);
                // Clear passive cooldown immediately upon active recovery.
                self.record_success();
            }
        } else {
            self.active_probes_err.fetch_add(1, Ordering::Relaxed);
            self.active_consecutive_successes
                .store(0, Ordering::Release);
            let fail = self
                .active_consecutive_failures
                .fetch_add(1, Ordering::AcqRel)
                .saturating_add(1);
            if fail >= unhealthy_t {
                self.active_healthy.store(false, Ordering::Release);
            }
        }
    }

    /// Returns a point-in-time diagnostic snapshot of this endpoint's health and probe stats.
    pub fn diagnostic_snapshot(&self, now_ms: u64) -> EndpointHealthSnapshot {
        let (passive_failures, until) = self.health_snapshot();
        let active_healthy = self.is_active_healthy();
        let passive_healthy = until == 0 || now_ms >= until;
        EndpointHealthSnapshot {
            url: self.raw_url.clone(),
            weight: self.weight,
            healthy: active_healthy && passive_healthy,
            active_healthy,
            passive_healthy,
            passive_failures,
            active_probes_ok: self.active_probes_ok.load(Ordering::Relaxed),
            active_probes_err: self.active_probes_err.load(Ordering::Relaxed),
            last_probe_latency_us: self.last_probe_latency_us.load(Ordering::Relaxed),
        }
    }
}

/// Computes the greatest common divisor of two positive integers.
const fn gcd_u32(mut a: u32, mut b: u32) -> u32 {
    while b != 0 {
        let r = a % b;
        a = b;
        b = r;
    }
    a
}

/// Precomputes a Nginx-style Smooth Weighted Round-Robin (SWRR) index schedule for `weights`.
///
/// Returns an empty `Vec` if:
/// - `weights.len() <= 1`
/// - all weights are identical (uniform fast path uses `cursor % len`)
/// - the GCD-reduced total weight exceeds [`MAX_SWRR_SCHEDULE_LEN`] (fallback uses cumulative weights)
pub fn build_swrr_schedule(weights: &[u32]) -> Vec<usize> {
    if weights.len() <= 1 {
        return Vec::new();
    }
    let norm: Vec<u32> = weights.iter().map(|&w| w.max(1)).collect();
    if norm.iter().all(|&w| w == norm[0]) {
        return Vec::new();
    }

    let g = norm.iter().copied().reduce(gcd_u32).unwrap_or(1).max(1);
    let reduced: Vec<u32> = norm.iter().map(|&w| w / g).collect();

    let total: usize = reduced.iter().map(|&w| w as usize).sum();
    if total == 0 || total > MAX_SWRR_SCHEDULE_LEN {
        return Vec::new();
    }

    let mut current = vec![0i64; reduced.len()];
    let total_i64 = total as i64;
    let mut schedule = Vec::with_capacity(total);

    for _ in 0..total {
        let mut best_idx = 0usize;
        let mut best_val = i64::MIN;
        for (i, &w) in reduced.iter().enumerate() {
            current[i] += w as i64;
            if current[i] > best_val {
                best_val = current[i];
                best_idx = i;
            }
        }
        current[best_idx] -= total_i64;
        schedule.push(best_idx);
    }

    schedule
}

/// Pure endpoint index selector implementing Shunt's 3-pass selection policy:
/// 1. Healthy and untried
/// 2. Any untried (even if currently in cooldown)
/// 3. Any healthy, otherwise `start % len`
///
/// Assumes `healthy.len() >= 1`.
pub fn select_endpoint_index(start: usize, tried_indices: &[usize], healthy: &[bool]) -> usize {
    let len = healthy.len();
    debug_assert!(len > 0);
    let start = start % len;

    // Pass 1: healthy & not yet tried in this request
    for offset in 0..len {
        let idx = (start + offset) % len;
        if !tried_indices.contains(&idx) && healthy[idx] {
            return idx;
        }
    }

    // Pass 2: any endpoint not yet tried in this request (even if marked unhealthy)
    for offset in 0..len {
        let idx = (start + offset) % len;
        if !tried_indices.contains(&idx) {
            return idx;
        }
    }

    // Pass 3: wrap around to any healthy endpoint, else start
    for offset in 0..len {
        let idx = (start + offset) % len;
        if healthy[idx] {
            return idx;
        }
    }

    start
}

/// Pure weighted endpoint selector combining smooth weighted distribution with Shunt's
/// 3-pass health & untried priority policy.
///
/// Assumes `healthy.len() == weights.len()` and `healthy.len() >= 1`.
pub fn select_weighted_endpoint_index(
    cursor: usize,
    weights: &[u32],
    schedule: &[usize],
    tried_indices: &[usize],
    healthy: &[bool],
) -> usize {
    let len = healthy.len();
    debug_assert!(len > 0 && len == weights.len());

    if !schedule.is_empty() {
        let slen = schedule.len();
        let pos = cursor % slen;
        let first = schedule[pos];

        // Fast path: scheduled slot is healthy and untried.
        if !tried_indices.contains(&first) && healthy[first] {
            return first;
        }

        // Pass 1: healthy & untried (scanning forward preserves smooth proportional ratios)
        for offset in 1..slen {
            let idx = schedule[(pos + offset) % slen];
            if !tried_indices.contains(&idx) && healthy[idx] {
                return idx;
            }
        }

        // Pass 2: any untried
        for offset in 0..slen {
            let idx = schedule[(pos + offset) % slen];
            if !tried_indices.contains(&idx) {
                return idx;
            }
        }

        // Pass 3: any healthy
        for offset in 0..slen {
            let idx = schedule[(pos + offset) % slen];
            if healthy[idx] {
                return idx;
            }
        }

        return first;
    }

    // Uniform-weight fast path (or single endpoint).
    if len == 1 || weights.iter().all(|&w| w.max(1) == weights[0].max(1)) {
        return select_endpoint_index(cursor, tried_indices, healthy);
    }

    // Cumulative-weight fallback for huge co-prime weight sums (> MAX_SWRR_SCHEDULE_LEN).
    let pick_from = |predicate: &dyn Fn(usize) -> bool| -> Option<usize> {
        let mut total_w = 0u64;
        for (i, &w) in weights.iter().enumerate() {
            if predicate(i) {
                total_w = total_w.saturating_add(w.max(1) as u64);
            }
        }
        if total_w == 0 {
            return None;
        }
        // Golden-ratio stride spreads consecutive cursor values smoothly across total_w.
        let mut target = (cursor as u64).wrapping_mul(2_654_435_761) % total_w;
        for (i, &w) in weights.iter().enumerate() {
            if !predicate(i) {
                continue;
            }
            let w64 = w.max(1) as u64;
            if target < w64 {
                return Some(i);
            }
            target -= w64;
        }
        None
    };

    if let Some(i) = pick_from(&|i| !tried_indices.contains(&i) && healthy[i]) {
        return i;
    }
    if let Some(i) = pick_from(&|i| !tried_indices.contains(&i)) {
        return i;
    }
    if let Some(i) = pick_from(&|i| healthy[i]) {
        return i;
    }
    pick_from(&|_| true).unwrap_or(0)
}

/// Warm HTTP/1.1 + HTTP/2 connection pool and active/passive health manager for an upstream.
pub struct UpstreamPool {
    pool_id: u64,
    key: UpstreamPoolKey,
    endpoints: Vec<EndpointState>,
    weights: Vec<u32>,
    swrr_schedule: Vec<usize>,
    rr_cursor: AtomicUsize,
    clock: Arc<dyn Clock>,
    client: Client<ShuntConnector, ShuntBody>,
    connector_h1_tls: Option<TlsConnector>,
}

impl std::fmt::Debug for UpstreamPool {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UpstreamPool")
            .field("pool_id", &self.pool_id)
            .field("endpoints", &self.key.endpoints)
            .field("http2_only", &self.key.http2_only)
            .field(
                "active_health_check",
                &self.key.active_health_check.is_some(),
            )
            .finish()
    }
}

impl UpstreamPool {
    pub fn new(pool_id: u64, config: &UpstreamConfig) -> Result<Self, CoreError> {
        Self::new_with_clock(pool_id, config, SystemClock::shared())
    }

    pub fn new_with_clock(
        pool_id: u64,
        config: &UpstreamConfig,
        clock: Arc<dyn Clock>,
    ) -> Result<Self, CoreError> {
        if config.endpoints.is_empty() {
            return Err(CoreError::EmptyUpstream(config.name.clone()));
        }

        let initial_active_healthy = config
            .active_health_check
            .as_ref()
            .map(|hc| hc.initial_healthy)
            .unwrap_or(true);

        let mut endpoints = Vec::with_capacity(config.endpoints.len());
        let mut weights = Vec::with_capacity(config.endpoints.len());
        for ep in &config.endpoints {
            let w = ep.weight.max(1);
            endpoints.push(EndpointState::new_with_options(
                ep.url.clone(),
                w,
                initial_active_healthy,
            )?);
            weights.push(w);
        }

        let swrr_schedule = build_swrr_schedule(&weights);

        let tls_cfg = config.tls.build_client_config(None)?;
        let tls_connector = TlsConnector::from(tls_cfg);

        // Separate H1-only ALPN TLS connector for WebSocket upgrade handshakes.
        let h1_tls_cfg = config
            .tls
            .build_client_config(Some(vec![b"http/1.1".to_vec()]))?;
        let connector_h1_tls = Some(TlsConnector::from(h1_tls_cfg));

        let connector = ShuntConnector {
            connect_timeout: config.connect_timeout,
            tls_connector,
        };

        let mut builder = Client::builder(TokioExecutor::new());
        builder
            .pool_idle_timeout(config.pool_idle_timeout)
            .pool_max_idle_per_host(config.pool_max_idle_per_host);
        if config.http2_only {
            builder.http2_only(true);
        }

        let client = builder.build(connector);

        Ok(Self {
            pool_id,
            key: config.pool_key(),
            endpoints,
            weights,
            swrr_schedule,
            rr_cursor: AtomicUsize::new(0),
            clock,
            client,
            connector_h1_tls,
        })
    }

    /// Unique identifier for this pool instance (useful for verifying pool reuse across reloads).
    pub fn pool_id(&self) -> u64 {
        self.pool_id
    }

    pub fn key(&self) -> &UpstreamPoolKey {
        &self.key
    }

    pub fn endpoints(&self) -> &[EndpointState] {
        &self.endpoints
    }

    pub fn active_health_check(&self) -> Option<&ActiveHealthCheckConfig> {
        self.key.active_health_check.as_ref()
    }

    /// Returns point-in-time health snapshots for every endpoint in this pool.
    pub fn endpoint_health_snapshots(&self) -> Vec<EndpointHealthSnapshot> {
        let now = self.now_ms();
        self.endpoints
            .iter()
            .map(|ep| ep.diagnostic_snapshot(now))
            .collect()
    }

    fn now_ms(&self) -> u64 {
        self.clock.now_ms()
    }

    /// Selects the next healthy endpoint (uniform round-robin or smooth weighted round-robin),
    /// preferring endpoints not in `tried_indices`.
    pub fn select_endpoint(&self, tried_indices: &[usize]) -> (usize, &EndpointState) {
        let len = self.endpoints.len();
        let cursor = self.rr_cursor.fetch_add(1, Ordering::Relaxed);
        let now = self.now_ms();

        // Zero-allocation fast path when SWRR schedule is active and slot is healthy & untried.
        if !self.swrr_schedule.is_empty() {
            let slen = self.swrr_schedule.len();
            let pos = cursor % slen;
            let first = self.swrr_schedule[pos];
            if !tried_indices.contains(&first) && self.endpoints[first].is_healthy(now) {
                return (first, &self.endpoints[first]);
            }
            for offset in 1..slen {
                let idx = self.swrr_schedule[(pos + offset) % slen];
                if !tried_indices.contains(&idx) && self.endpoints[idx].is_healthy(now) {
                    return (idx, &self.endpoints[idx]);
                }
            }
            for offset in 0..slen {
                let idx = self.swrr_schedule[(pos + offset) % slen];
                if !tried_indices.contains(&idx) {
                    return (idx, &self.endpoints[idx]);
                }
            }
            for offset in 0..slen {
                let idx = self.swrr_schedule[(pos + offset) % slen];
                if self.endpoints[idx].is_healthy(now) {
                    return (idx, &self.endpoints[idx]);
                }
            }
            return (first, &self.endpoints[first]);
        }

        // Uniform fast path (no heap allocations).
        if len == 1 || self.weights.iter().all(|&w| w == self.weights[0]) {
            let start = cursor % len;

            for offset in 0..len {
                let idx = (start + offset) % len;
                if !tried_indices.contains(&idx) && self.endpoints[idx].is_healthy(now) {
                    return (idx, &self.endpoints[idx]);
                }
            }
            for offset in 0..len {
                let idx = (start + offset) % len;
                if !tried_indices.contains(&idx) {
                    return (idx, &self.endpoints[idx]);
                }
            }
            for offset in 0..len {
                let idx = (start + offset) % len;
                if self.endpoints[idx].is_healthy(now) {
                    return (idx, &self.endpoints[idx]);
                }
            }
            return (start, &self.endpoints[start]);
        }

        // Fallback for huge co-prime weights (> MAX_SWRR_SCHEDULE_LEN).
        let healthy: Vec<bool> = self.endpoints.iter().map(|e| e.is_healthy(now)).collect();
        let idx = select_weighted_endpoint_index(
            cursor,
            &self.weights,
            &self.swrr_schedule,
            tried_indices,
            &healthy,
        );
        (idx, &self.endpoints[idx])
    }

    pub fn record_success(&self, endpoint_idx: usize) {
        if let Some(ep) = self.endpoints.get(endpoint_idx) {
            ep.record_success();
        }
    }

    pub fn record_failure(&self, endpoint_idx: usize) {
        if let Some(ep) = self.endpoints.get(endpoint_idx) {
            ep.record_failure(
                self.now_ms(),
                self.key.unhealthy_threshold,
                self.key.unhealthy_cooldown,
            );
        }
    }

    /// Executes a single active health probe against endpoint `endpoint_idx` using this pool's
    /// configured [`ActiveHealthCheckConfig`], updating its active health state.
    ///
    /// Returns `true` if the probe succeeded, `false` otherwise (or if no active health check
    /// is configured or `endpoint_idx` is out of bounds).
    pub async fn probe_endpoint_once(&self, endpoint_idx: usize) -> bool {
        let Some(hc) = self.key.active_health_check.as_ref() else {
            return false;
        };
        let Some(ep) = self.endpoints.get(endpoint_idx) else {
            return false;
        };

        let started = Instant::now();
        let ok = match &hc.kind {
            ActiveProbeKind::Tcp => probe_tcp(&ep.base_uri, hc.timeout).await,
            ActiveProbeKind::Http {
                method,
                path,
                expected_statuses,
                headers,
            } => {
                self.probe_http(
                    &ep.base_uri,
                    method,
                    path,
                    expected_statuses,
                    headers,
                    hc.timeout,
                )
                .await
            }
        };
        let latency_us = started.elapsed().as_micros().min(u64::MAX as u128) as u64;
        ep.record_active_probe(ok, latency_us, hc.unhealthy_threshold, hc.healthy_threshold);
        ok
    }

    /// Runs one active health probe cycle across every endpoint in this pool.
    pub async fn probe_all_once(&self) {
        if self.key.active_health_check.is_none() {
            return;
        }
        for idx in 0..self.endpoints.len() {
            let _ = self.probe_endpoint_once(idx).await;
        }
    }

    async fn probe_http(
        &self,
        base_uri: &Uri,
        method: &str,
        path: &str,
        expected_statuses: &[u16],
        headers: &[(String, String)],
        timeout: Duration,
    ) -> bool {
        let Ok(probe_method) = Method::from_bytes(method.as_bytes()) else {
            return false;
        };
        let Ok(probe_rel_uri) = path.parse::<Uri>() else {
            return false;
        };
        let Ok(target_uri) = build_target_uri(base_uri, &probe_rel_uri) else {
            return false;
        };

        let mut builder = http::Request::builder()
            .method(probe_method)
            .uri(target_uri)
            .header(http::header::USER_AGENT, "shunt-health-probe");

        for (k, v) in headers {
            if let (Ok(name), Ok(val)) = (
                HeaderName::from_bytes(k.as_bytes()),
                HeaderValue::from_str(v),
            ) {
                builder = builder.header(name, val);
            }
        }

        let Ok(req) = builder.body(ShuntBody::empty()) else {
            return false;
        };

        let deadline = Instant::now() + timeout;
        let Ok(resp) = self.send_request(req, Some(timeout)).await else {
            return false;
        };

        let status = resp.status().as_u16();
        let matched = expected_statuses.contains(&status);

        // Best-effort drain of small probe responses within remaining timeout so keep-alive
        // connections return cleanly to the pool.
        let remaining = deadline.saturating_duration_since(Instant::now());
        if !remaining.is_zero() {
            let mut body = resp.into_body();
            let _ = tokio::time::timeout(remaining, async {
                let mut drained = 0usize;
                while let Some(Ok(frame)) = body.frame().await {
                    if let Some(data) = frame.data_ref() {
                        drained += data.len();
                        if drained >= 64 * 1024 {
                            break;
                        }
                    }
                }
            })
            .await;
        }

        matched
    }

    /// Sends an HTTP request through the warm connection pool, enforcing `response_headers_timeout`.
    pub async fn send_request(
        &self,
        req: http::Request<ShuntBody>,
        response_headers_timeout: Option<Duration>,
    ) -> Result<http::Response<hyper::body::Incoming>, CoreError> {
        let fut = self.client.request(req);
        let res = match response_headers_timeout {
            Some(dur) => tokio::time::timeout(dur, fut)
                .await
                .map_err(|_| CoreError::ResponseHeadersTimeout(dur))?,
            None => fut.await,
        };

        res.map_err(|err| {
            // Preserve connect-timeout diagnostics if the connector timed out.
            if err.is_connect()
                && let Some(source) = std::error::Error::source(&err)
                && let Some(CoreError::ConnectTimeout(d)) = source.downcast_ref::<CoreError>()
            {
                return CoreError::ConnectTimeout(*d);
            }
            CoreError::HyperClient(err)
        })
    }

    /// Opens a dedicated HTTP/1.1 stream (TCP or TLS with ALPN `http/1.1`) for WebSocket upgrades.
    pub async fn connect_for_upgrade(&self, uri: &Uri) -> Result<ShuntStream, CoreError> {
        let tls = self
            .connector_h1_tls
            .clone()
            .expect("h1 tls connector initialized");
        connect_uri(uri, self.key.connect_timeout, tls).await
    }
}

async fn probe_tcp(base_uri: &Uri, timeout: Duration) -> bool {
    let scheme = base_uri.scheme_str().unwrap_or("http");
    let Some(host) = base_uri
        .host()
        .map(|h| h.trim_matches(|c| c == '[' || c == ']').to_owned())
    else {
        return false;
    };
    let port = base_uri
        .port_u16()
        .unwrap_or(if scheme == "https" { 443 } else { 80 });

    let connect_fut = async {
        if let Ok(ip) = host.parse::<std::net::IpAddr>() {
            TcpStream::connect(std::net::SocketAddr::new(ip, port)).await
        } else {
            TcpStream::connect((host.as_str(), port)).await
        }
    };

    tokio::time::timeout(timeout, connect_fut)
        .await
        .ok()
        .and_then(Result::ok)
        .is_some()
}

/// Resolves an endpoint base URI + relative request path/query into a full target URI.
pub fn build_target_uri(base_uri: &Uri, req_uri: &Uri) -> Result<Uri, CoreError> {
    let scheme = base_uri.scheme_str().unwrap_or("http");
    let authority = base_uri
        .authority()
        .ok_or_else(|| CoreError::InvalidUri {
            uri: base_uri.to_string(),
            message: "missing authority".to_owned(),
        })?
        .as_str();

    let base_path = base_uri.path().trim_end_matches('/');
    let req_pq = req_uri
        .path_and_query()
        .map(|pq| pq.as_str())
        .unwrap_or("/");

    let combined_pq = if base_path.is_empty() || base_path == "/" {
        if req_pq.starts_with('/') {
            req_pq.to_owned()
        } else {
            format!("/{req_pq}")
        }
    } else if req_pq.starts_with('/') {
        format!("{base_path}{req_pq}")
    } else {
        format!("{base_path}/{req_pq}")
    };

    Uri::builder()
        .scheme(scheme)
        .authority(authority)
        .path_and_query(combined_pq)
        .build()
        .map_err(|e| CoreError::InvalidUri {
            uri: format!("{scheme}://{authority}"),
            message: e.to_string(),
        })
}

/// TCP or TLS upstream stream.
pub enum MaybeTlsStream {
    Http(TcpStream),
    Https(Box<tokio_rustls::client::TlsStream<TcpStream>>),
}

impl AsyncRead for MaybeTlsStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            MaybeTlsStream::Http(s) => Pin::new(s).poll_read(cx, buf),
            MaybeTlsStream::Https(s) => Pin::new(s.as_mut()).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for MaybeTlsStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        match self.get_mut() {
            MaybeTlsStream::Http(s) => Pin::new(s).poll_write(cx, buf),
            MaybeTlsStream::Https(s) => Pin::new(s.as_mut()).poll_write(cx, buf),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            MaybeTlsStream::Http(s) => Pin::new(s).poll_flush(cx),
            MaybeTlsStream::Https(s) => Pin::new(s.as_mut()).poll_flush(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            MaybeTlsStream::Http(s) => Pin::new(s).poll_shutdown(cx),
            MaybeTlsStream::Https(s) => Pin::new(s.as_mut()).poll_shutdown(cx),
        }
    }
}

/// Hyper-compatible upstream connection stream implementing `Read`, `Write`, and `Connection`.
pub struct ShuntStream {
    io: TokioIo<MaybeTlsStream>,
}

impl ShuntStream {
    pub fn new(stream: MaybeTlsStream) -> Self {
        Self {
            io: TokioIo::new(stream),
        }
    }
}

impl Read for ShuntStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: ReadBufCursor<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.io).poll_read(cx, buf)
    }
}

impl Write for ShuntStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.io).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.io).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.io).poll_shutdown(cx)
    }
}

impl Connection for ShuntStream {
    fn connected(&self) -> Connected {
        let conn = Connected::new();
        match self.io.inner() {
            MaybeTlsStream::Http(_) => conn,
            MaybeTlsStream::Https(tls) => {
                if tls.get_ref().1.alpn_protocol() == Some(b"h2") {
                    conn.negotiated_h2()
                } else {
                    conn
                }
            }
        }
    }
}

#[derive(Clone)]
struct ShuntConnector {
    connect_timeout: Duration,
    tls_connector: TlsConnector,
}

impl Service<Uri> for ShuntConnector {
    type Response = ShuntStream;
    type Error = CoreError;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, uri: Uri) -> Self::Future {
        let timeout = self.connect_timeout;
        let tls = self.tls_connector.clone();
        Box::pin(async move { connect_uri(&uri, timeout, tls).await })
    }
}

async fn connect_uri(
    uri: &Uri,
    connect_timeout: Duration,
    tls_connector: TlsConnector,
) -> Result<ShuntStream, CoreError> {
    let scheme = uri.scheme_str().unwrap_or("http");
    let host = uri
        .host()
        .ok_or_else(|| CoreError::InvalidUri {
            uri: uri.to_string(),
            message: "missing host".to_owned(),
        })?
        .trim_matches(|c| c == '[' || c == ']')
        .to_owned();

    let port = uri
        .port_u16()
        .unwrap_or(if scheme == "https" { 443 } else { 80 });

    let deadline = Instant::now() + connect_timeout;

    let connect_fut = async {
        if let Ok(ip) = host.parse::<std::net::IpAddr>() {
            TcpStream::connect(std::net::SocketAddr::new(ip, port)).await
        } else {
            TcpStream::connect((host.as_str(), port)).await
        }
    };

    let tcp = tokio::time::timeout(connect_timeout, connect_fut)
        .await
        .map_err(|_| CoreError::ConnectTimeout(connect_timeout))??;

    let _ = tcp.set_nodelay(true);

    if scheme == "https" {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(CoreError::ConnectTimeout(connect_timeout));
        }
        let server_name = ServerName::try_from(host.clone())
            .map_err(|e| CoreError::Tls(format!("invalid TLS server name `{host}`: {e}")))?;
        let tls_stream = tokio::time::timeout(remaining, tls_connector.connect(server_name, tcp))
            .await
            .map_err(|_| CoreError::ConnectTimeout(connect_timeout))?
            .map_err(|e| CoreError::Tls(format!("upstream TLS handshake failed: {e}")))?;
        Ok(ShuntStream::new(MaybeTlsStream::Https(Box::new(
            tls_stream,
        ))))
    } else {
        Ok(ShuntStream::new(MaybeTlsStream::Http(tcp)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::convert::Infallible;
    use std::sync::atomic::AtomicU16;

    use hyper::server::conn::http1;
    use hyper::service::service_fn;
    use tokio::net::TcpListener;

    #[test]
    fn swrr_schedule_is_smooth_and_exact() {
        // Uniform -> empty (fast path)
        assert!(build_swrr_schedule(&[1, 1, 1]).is_empty());
        assert!(build_swrr_schedule(&[5, 5]).is_empty());

        // 80/20 -> GCD 20 -> [4, 1] -> [0, 0, 1, 0, 0]
        let s = build_swrr_schedule(&[80, 20]);
        assert_eq!(s, vec![0, 0, 1, 0, 0]);

        // 5/1/1 -> [0, 0, 1, 0, 2, 0, 0]
        let s2 = build_swrr_schedule(&[5, 1, 1]);
        assert_eq!(s2.len(), 7);
        assert_eq!(s2.iter().filter(|&&i| i == 0).count(), 5);
        assert_eq!(s2.iter().filter(|&&i| i == 1).count(), 1);
        assert_eq!(s2.iter().filter(|&&i| i == 2).count(), 1);
    }

    #[test]
    fn active_and_passive_health_compose_cleanly() {
        let ep = EndpointState::new_with_options("http://127.0.0.1:8080".into(), 5, true).unwrap();
        assert!(ep.is_healthy(0));

        // 1 active failure below threshold=2 keeps endpoint healthy
        ep.record_active_probe(false, 100, 2, 2);
        assert!(ep.is_healthy(0));

        // 2nd active failure ejects endpoint
        ep.record_active_probe(false, 200, 2, 2);
        assert!(!ep.is_active_healthy());
        assert!(!ep.is_healthy(0));

        // Passive failure on top while inactive
        ep.record_failure(0, 1, Duration::from_secs(30));
        assert!(!ep.is_passively_healthy(1000));

        // 1 active success below healthy_threshold=2 still unhealthy
        ep.record_active_probe(true, 150, 2, 2);
        assert!(!ep.is_active_healthy());

        // 2nd active success restores active health AND clears passive cooldown
        ep.record_active_probe(true, 120, 2, 2);
        assert!(ep.is_active_healthy());
        assert!(ep.is_passively_healthy(1000));
        assert!(ep.is_healthy(1000));
    }

    #[tokio::test]
    async fn active_http_probe_ejects_and_recovers_endpoint() {
        let status_code = Arc::new(AtomicU16::new(200));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let status_bg = Arc::clone(&status_code);

        let srv = tokio::spawn(async move {
            loop {
                let Ok((tcp, _)) = listener.accept().await else {
                    break;
                };
                let sc = Arc::clone(&status_bg);
                tokio::spawn(async move {
                    let svc = service_fn(move |_req: http::Request<hyper::body::Incoming>| {
                        let code = sc.load(Ordering::Relaxed);
                        async move {
                            Ok::<_, Infallible>(
                                http::Response::builder()
                                    .status(code)
                                    .body(http_body_util::Full::new(bytes::Bytes::from_static(
                                        b"ok",
                                    )))
                                    .unwrap(),
                            )
                        }
                    });
                    let _ = http1::Builder::new()
                        .serve_connection(TokioIo::new(tcp), svc)
                        .await;
                });
            }
        });

        let cfg = UpstreamConfig::new("hc_http", vec![format!("http://{addr}")])
            .with_active_health_check(ActiveHealthCheckConfig {
                kind: ActiveProbeKind::Http {
                    method: "GET".to_owned(),
                    path: "/healthz".to_owned(),
                    expected_statuses: vec![200],
                    headers: vec![("x-probe".to_owned(), "1".to_owned())],
                },
                interval: Duration::from_secs(5),
                timeout: Duration::from_secs(1),
                unhealthy_threshold: 2,
                healthy_threshold: 2,
                initial_healthy: true,
            });
        let pool = UpstreamPool::new(1, &cfg).unwrap();

        assert!(pool.probe_endpoint_once(0).await);
        assert!(pool.endpoints()[0].is_active_healthy());

        // Flip backend to 503 -> 2 probes eject it
        status_code.store(503, Ordering::Relaxed);
        assert!(!pool.probe_endpoint_once(0).await);
        assert!(pool.endpoints()[0].is_active_healthy());
        assert!(!pool.probe_endpoint_once(0).await);
        assert!(!pool.endpoints()[0].is_active_healthy());

        // Flip back to 200 -> 2 probes recover it
        status_code.store(200, Ordering::Relaxed);
        assert!(pool.probe_endpoint_once(0).await);
        assert!(!pool.endpoints()[0].is_active_healthy());
        assert!(pool.probe_endpoint_once(0).await);
        assert!(pool.endpoints()[0].is_active_healthy());

        srv.abort();
    }

    #[tokio::test]
    async fn active_tcp_probe_detects_open_and_refused_ports() {
        let open_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let open_addr = open_listener.local_addr().unwrap();

        let closed_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let closed_addr = closed_listener.local_addr().unwrap();
        drop(closed_listener);

        let cfg = UpstreamConfig::new(
            "hc_tcp",
            vec![
                format!("http://{open_addr}"),
                format!("http://{closed_addr}"),
            ],
        )
        .with_active_health_check(ActiveHealthCheckConfig {
            kind: ActiveProbeKind::Tcp,
            interval: Duration::from_secs(5),
            timeout: Duration::from_millis(250),
            unhealthy_threshold: 1,
            healthy_threshold: 1,
            initial_healthy: true,
        });
        let pool = UpstreamPool::new(1, &cfg).unwrap();

        assert!(pool.probe_endpoint_once(0).await);
        assert!(!pool.probe_endpoint_once(1).await);
        assert!(pool.endpoints()[0].is_active_healthy());
        assert!(!pool.endpoints()[1].is_active_healthy());

        drop(open_listener);
    }
}

#[cfg(kani)]
mod kani_proofs {
    use super::{UNHEALTHY_UNTIL_MASK, pack_health, select_endpoint_index, unpack_health};

    #[kani::proof]
    fn health_word_pack_unpack_roundtrip() {
        let failures: u16 = kani::any();
        let until: u64 = kani::any();
        kani::assume(until <= UNHEALTHY_UNTIL_MASK);

        let packed = pack_health(failures, until);
        let (f2, u2) = unpack_health(packed);
        assert_eq!(f2, failures);
        assert_eq!(u2, until);
    }

    #[kani::proof]
    fn select_endpoint_index_bounds_and_priority() {
        let healthy: [bool; 4] = kani::any();
        let start: usize = kani::any();
        let t0: usize = kani::any();
        let t1: usize = kani::any();
        let tried = [t0 % 4, t1 % 4];

        let chosen = select_endpoint_index(start, &tried, &healthy);
        assert!(chosen < 4);

        let has_healthy_untried = (0..4).any(|i| !tried.contains(&i) && healthy[i]);
        if has_healthy_untried {
            assert!(!tried.contains(&chosen));
            assert!(healthy[chosen]);
        }
    }
}
