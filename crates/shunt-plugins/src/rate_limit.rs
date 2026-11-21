use std::collections::HashMap;
use std::hash::{DefaultHasher, Hash, Hasher};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde::Deserialize;
use shunt_plugin_sdk::{
    BufferedResponse, BuildContext, Clock, Flow, HeaderName, HeaderValue, HookMask, HookResult,
    HttpPlugin, PluginBuildError, PluginConfig, PluginFactory, RequestCtx, RequestHead,
    ResponseHead, StatusCode, header,
};

const DEFAULT_MAX_ENTRIES: usize = 100_000;
const DEFAULT_IDLE_TTL_MS: u64 = 300_000; // 5 minutes
const NUM_SHARDS: usize = 16;

#[derive(Debug, Clone)]
struct RateLimitRemaining(u32);

#[derive(Debug, Deserialize, Default, Clone, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum KeyStrategy {
    Global,
    #[default]
    ClientIp,
    Header,
}

#[derive(Debug, Deserialize)]
#[serde(default)]
struct RateLimitConfig {
    requests_per_second: f64,
    burst: u32,
    key: KeyStrategy,
    header_name: Option<String>,
    /// Maximum number of distinct client/header buckets tracked simultaneously (default: 100,000).
    max_entries: usize,
    /// Evict idle buckets untouched for longer than this duration in milliseconds (default: 300,000).
    /// Set to `0` to disable time-based idle eviction (hard `max_entries` cap still applies).
    idle_ttl_ms: u64,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            requests_per_second: 100.0,
            burst: 100,
            key: KeyStrategy::ClientIp,
            header_name: None,
            max_entries: DEFAULT_MAX_ENTRIES,
            idle_ttl_ms: DEFAULT_IDLE_TTL_MS,
        }
    }
}

/// Monotonic token-bucket rate limiter state for a single key.
#[derive(Debug, Clone)]
pub struct TokenBucket {
    tokens: f64,
    last_refill: Duration,
}

impl TokenBucket {
    pub fn new(burst: u32, now: Duration) -> Self {
        Self {
            tokens: f64::from(burst),
            last_refill: now,
        }
    }

    pub fn tokens(&self) -> f64 {
        self.tokens
    }

    pub fn last_refill(&self) -> Duration {
        self.last_refill
    }

    /// Attempts to consume 1 token. Returns `Ok(remaining)` or `Err(retry_after_secs)`.
    ///
    /// Guarantees `0.0 <= tokens <= burst`, no NaN/Inf, and `retry_after_secs >= 1` on rejection.
    pub fn try_consume(&mut self, rps: f64, burst: f64, now: Duration) -> Result<u32, u64> {
        let safe_burst = if burst.is_finite() && burst >= 1.0 {
            burst
        } else {
            1.0
        };
        let safe_rps = if rps.is_finite() && rps > 0.0 {
            rps
        } else {
            1.0
        };

        let elapsed = now.saturating_sub(self.last_refill).as_secs_f64();
        if elapsed > 0.0 {
            let added = elapsed * safe_rps;
            if added.is_finite() {
                self.tokens = (self.tokens + added).min(safe_burst);
            } else {
                self.tokens = safe_burst;
            }
            self.last_refill = now;
        }
        // Keep tokens within [0.0, burst] even if burst decreased across a hot reload.
        if !self.tokens.is_finite() || self.tokens < 0.0 {
            self.tokens = 0.0;
        } else if self.tokens > safe_burst {
            self.tokens = safe_burst;
        }

        if self.tokens >= 1.0 {
            self.tokens = (self.tokens - 1.0).max(0.0);
            Ok(self.tokens.floor().min(u32::MAX as f64) as u32)
        } else {
            let needed = (1.0 - self.tokens).max(0.0);
            let raw_wait = (needed / safe_rps).ceil();
            let wait_secs = if raw_wait.is_finite() && raw_wait >= 1.0 {
                raw_wait.min(u64::MAX as f64) as u64
            } else {
                1
            };
            Err(wait_secs)
        }
    }
}

/// Sharded, bounded-cardinality token bucket table stored in `StateStore` across reloads.
///
/// Enforces a hard upper bound `max_entries` plus idle TTL eviction without ever holding
/// more than one shard lock at a time (deadlock-free).
#[derive(Debug)]
pub struct BucketTable {
    shards: Box<[Mutex<HashMap<String, TokenBucket>>]>,
    entry_count: AtomicUsize,
}

impl Default for BucketTable {
    fn default() -> Self {
        Self::new()
    }
}

impl BucketTable {
    pub fn new() -> Self {
        let mut shards = Vec::with_capacity(NUM_SHARDS);
        for _ in 0..NUM_SHARDS {
            shards.push(Mutex::new(HashMap::new()));
        }
        Self {
            shards: shards.into_boxed_slice(),
            entry_count: AtomicUsize::new(0),
        }
    }

    /// Total number of tracked bucket entries across all shards.
    pub fn len(&self) -> usize {
        self.entry_count.load(Ordering::Acquire)
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    fn shard_index(key: &str) -> usize {
        let mut hasher = DefaultHasher::new();
        key.hash(&mut hasher);
        (hasher.finish() as usize) % NUM_SHARDS
    }

    /// Shrinks the table to at most `max_entries` (e.g., if `max_entries` was lowered on reload).
    pub fn shrink_to(&self, max_entries: usize) {
        let cap = max_entries.max(1);
        for shard in self.shards.iter() {
            if self.entry_count.load(Ordering::Acquire) <= cap {
                break;
            }
            let mut map = shard.lock().expect("BucketTable shard lock poisoned");
            while self.entry_count.load(Ordering::Acquire) > cap && !map.is_empty() {
                if let Some(oldest_key) = oldest_key_in_map(&map) {
                    if map.remove(&oldest_key).is_some() {
                        self.entry_count.fetch_sub(1, Ordering::AcqRel);
                    }
                } else {
                    break;
                }
            }
        }
    }

    /// Checks and consumes 1 token for `key` under `(rps, burst)` while enforcing
    /// `max_entries` and `idle_ttl`.
    pub fn check_and_consume(
        &self,
        key: String,
        rps: f64,
        burst: u32,
        now: Duration,
        max_entries: usize,
        idle_ttl: Duration,
    ) -> Result<u32, u64> {
        let cap = max_entries.max(1);
        let shard_idx = Self::shard_index(&key);

        // Fast path: key already exists in its shard, or we can reserve a fresh slot immediately.
        {
            let mut map = self.shards[shard_idx]
                .lock()
                .expect("BucketTable shard lock poisoned");
            if let Some(bucket) = map.get_mut(&key) {
                return bucket.try_consume(rps, f64::from(burst), now);
            }

            // Opportunistically evict idle entries in this shard before checking capacity.
            if !idle_ttl.is_zero() {
                let evicted = evict_idle_in_map(&mut map, now, idle_ttl);
                if evicted > 0 {
                    self.entry_count.fetch_sub(evicted, Ordering::AcqRel);
                }
            }

            if self
                .entry_count
                .fetch_update(Ordering::AcqRel, Ordering::Acquire, |c| {
                    (c < cap).then_some(c + 1)
                })
                .is_ok()
            {
                let mut bucket = TokenBucket::new(burst, now);
                let res = bucket.try_consume(rps, f64::from(burst), now);
                map.insert(key, bucket);
                return res;
            }

            // Table is at capacity: evict oldest entry in this shard if non-empty (slot-neutral).
            if let Some(oldest_key) = oldest_key_in_map(&map)
                && map.remove(&oldest_key).is_some()
            {
                let mut bucket = TokenBucket::new(burst, now);
                let res = bucket.try_consume(rps, f64::from(burst), now);
                map.insert(key, bucket);
                return res;
            }
        }

        // Slow path: table is at capacity and our target shard was empty, so free one slot from
        // another shard without ever holding two locks simultaneously.
        for offset in 1..NUM_SHARDS {
            let idx = (shard_idx + offset) % NUM_SHARDS;
            let mut other = self.shards[idx]
                .lock()
                .expect("BucketTable shard lock poisoned");
            if !idle_ttl.is_zero() {
                let evicted = evict_idle_in_map(&mut other, now, idle_ttl);
                if evicted > 0 {
                    self.entry_count.fetch_sub(evicted, Ordering::AcqRel);
                    if self.entry_count.load(Ordering::Acquire) < cap {
                        break;
                    }
                }
            }
            if let Some(oldest_key) = oldest_key_in_map(&other)
                && other.remove(&oldest_key).is_some()
            {
                self.entry_count.fetch_sub(1, Ordering::AcqRel);
                break;
            }
        }

        // Re-acquire target shard and insert if a slot is now available; otherwise evaluate a
        // fresh ephemeral bucket without exceeding `max_entries`.
        let mut map = self.shards[shard_idx]
            .lock()
            .expect("BucketTable shard lock poisoned");
        if let Some(bucket) = map.get_mut(&key) {
            return bucket.try_consume(rps, f64::from(burst), now);
        }

        let mut bucket = TokenBucket::new(burst, now);
        let res = bucket.try_consume(rps, f64::from(burst), now);

        if self
            .entry_count
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |c| {
                (c < cap).then_some(c + 1)
            })
            .is_ok()
        {
            map.insert(key, bucket);
        } else if let Some(oldest_key) = oldest_key_in_map(&map)
            && map.remove(&oldest_key).is_some()
        {
            map.insert(key, bucket);
        }

        res
    }
}

fn evict_idle_in_map(
    map: &mut HashMap<String, TokenBucket>,
    now: Duration,
    idle_ttl: Duration,
) -> usize {
    let before = map.len();
    map.retain(|_, b| now.saturating_sub(b.last_refill) < idle_ttl);
    before - map.len()
}

fn oldest_key_in_map(map: &HashMap<String, TokenBucket>) -> Option<String> {
    map.iter()
        .min_by_key(|(_, b)| b.last_refill)
        .map(|(k, _)| k.clone())
}

pub struct RateLimitFactory;

impl PluginFactory for RateLimitFactory {
    fn name(&self) -> &str {
        "rate-limit"
    }

    fn build(
        &self,
        config: &PluginConfig,
        ctx: &BuildContext,
    ) -> Result<Arc<dyn HttpPlugin>, PluginBuildError> {
        let cfg: RateLimitConfig = config.deserialize(self.name())?;
        if !(cfg.requests_per_second.is_finite() && cfg.requests_per_second > 0.0) {
            return Err(PluginBuildError::BuildFailed {
                plugin: self.name().to_owned(),
                message: "`requests_per_second` must be a positive finite number".to_owned(),
            });
        }
        if cfg.burst == 0 {
            return Err(PluginBuildError::BuildFailed {
                plugin: self.name().to_owned(),
                message: "`burst` must be >= 1".to_owned(),
            });
        }
        if cfg.max_entries == 0 {
            return Err(PluginBuildError::BuildFailed {
                plugin: self.name().to_owned(),
                message: "`max_entries` must be >= 1".to_owned(),
            });
        }

        let header_name = if cfg.key == KeyStrategy::Header {
            let raw = cfg
                .header_name
                .as_deref()
                .ok_or_else(|| PluginBuildError::BuildFailed {
                    plugin: self.name().to_owned(),
                    message: "`header_name` is required when `key = \"header\"`".to_owned(),
                })?;
            Some(HeaderName::from_bytes(raw.as_bytes()).map_err(|e| {
                PluginBuildError::BuildFailed {
                    plugin: self.name().to_owned(),
                    message: format!("invalid header_name `{raw}`: {e}"),
                }
            })?)
        } else {
            None
        };

        // Acquire persistent state from RuntimeRegistry's StateStore so rate-limit
        // buckets survive hot config reloads without resetting!
        let state = ctx
            .state_handle()
            .get_or_init("token_buckets", BucketTable::new);
        state.shrink_to(cfg.max_entries);

        Ok(Arc::new(RateLimitPlugin {
            rps: cfg.requests_per_second,
            burst: cfg.burst,
            key_strategy: cfg.key,
            header_name,
            max_entries: cfg.max_entries,
            idle_ttl: Duration::from_millis(cfg.idle_ttl_ms),
            clock: ctx.clock(),
            state,
        }))
    }
}

pub struct RateLimitPlugin {
    rps: f64,
    burst: u32,
    key_strategy: KeyStrategy,
    header_name: Option<HeaderName>,
    max_entries: usize,
    idle_ttl: Duration,
    clock: Arc<dyn Clock>,
    state: Arc<BucketTable>,
}

impl HttpPlugin for RateLimitPlugin {
    fn name(&self) -> &str {
        "rate-limit"
    }

    fn hook_mask(&self) -> HookMask {
        HookMask::ON_REQUEST_HEADERS | HookMask::ON_RESPONSE_HEADERS
    }

    fn on_request_headers<'a>(
        &'a self,
        ctx: &'a mut RequestCtx,
        req: &'a mut RequestHead,
    ) -> HookResult<'a, Flow> {
        let bucket_key = match self.key_strategy {
            KeyStrategy::Global => "global".to_owned(),
            KeyStrategy::ClientIp => ctx.client_addr.ip().to_string(),
            KeyStrategy::Header => self
                .header_name
                .as_ref()
                .and_then(|name| req.headers.get(name))
                .and_then(|v| v.to_str().ok())
                .map(str::to_owned)
                .unwrap_or_else(|| ctx.client_addr.ip().to_string()),
        };

        let now = self.clock.now();
        let outcome = self.state.check_and_consume(
            bucket_key,
            self.rps,
            self.burst,
            now,
            self.max_entries,
            self.idle_ttl,
        );

        match outcome {
            Ok(remaining) => {
                ctx.insert_ext(RateLimitRemaining(remaining));
                HookResult::Ready(Flow::Continue)
            }
            Err(retry_after) => {
                let mut resp = BufferedResponse::json(
                    StatusCode::TOO_MANY_REQUESTS,
                    r#"{"error":"rate_limit_exceeded"}"#,
                );
                if let Ok(v) = HeaderValue::from_str(&retry_after.to_string()) {
                    resp.headers.insert(header::RETRY_AFTER, v);
                }
                if let Ok(v) = HeaderValue::from_str(&self.burst.to_string()) {
                    resp.headers
                        .insert(HeaderName::from_static("x-ratelimit-limit"), v);
                }
                resp.headers.insert(
                    HeaderName::from_static("x-ratelimit-remaining"),
                    HeaderValue::from_static("0"),
                );
                HookResult::Ready(Flow::Respond(resp))
            }
        }
    }

    fn on_response_headers<'a>(
        &'a self,
        ctx: &'a mut RequestCtx,
        res: &'a mut ResponseHead,
    ) -> HookResult<'a, Flow> {
        if let Some(RateLimitRemaining(rem)) = ctx.get_ext::<RateLimitRemaining>() {
            if let Ok(v) = HeaderValue::from_str(&self.burst.to_string()) {
                res.headers
                    .insert(HeaderName::from_static("x-ratelimit-limit"), v);
            }
            if let Ok(v) = HeaderValue::from_str(&rem.to_string()) {
                res.headers
                    .insert(HeaderName::from_static("x-ratelimit-remaining"), v);
            }
        }
        HookResult::Ready(Flow::Continue)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bucket_table_enforces_max_entries_and_idle_ttl() {
        let table = BucketTable::new();
        let t0 = Duration::from_secs(0);

        for i in 0..50 {
            let res = table.check_and_consume(
                format!("ip-{i}"),
                10.0,
                5,
                t0,
                10,
                Duration::from_secs(60),
            );
            assert!(res.is_ok());
            assert!(
                table.len() <= 10,
                "table.len()={} exceeded cap=10",
                table.len()
            );
        }

        // Advance past idle TTL -> subsequent insert evicts idle buckets in its shard.
        let t1 = Duration::from_secs(120);
        assert!(
            table
                .check_and_consume("fresh".to_owned(), 10.0, 5, t1, 10, Duration::from_secs(60))
                .is_ok()
        );
        assert!(table.len() <= 10);
    }
}

#[cfg(kani)]
mod kani_proofs {
    use std::time::Duration;

    use super::TokenBucket;

    #[kani::proof]
    fn token_bucket_try_consume_invariants() {
        let burst: u32 = kani::any();
        kani::assume(burst >= 1 && burst <= 1_000);
        let rps_int: u32 = kani::any();
        kani::assume(rps_int >= 1 && rps_int <= 1_000);
        let rps = f64::from(rps_int);
        let dt_ms: u64 = kani::any();
        kani::assume(dt_ms <= 60_000);

        let mut bucket = TokenBucket::new(burst, Duration::ZERO);
        let res = bucket.try_consume(rps, f64::from(burst), Duration::from_millis(dt_ms));

        let t = bucket.tokens();
        assert!(t.is_finite());
        assert!(t >= 0.0 && t <= f64::from(burst));

        match res {
            Ok(rem) => assert!(rem < burst),
            Err(retry_after) => assert!(retry_after >= 1),
        }
    }
}
