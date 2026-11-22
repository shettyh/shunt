use std::collections::{BTreeMap, HashMap};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use serde_json::json;
use shunt_plugin_sdk::{
    BuildContext, Bytes, Clock, DistributedStore, FailurePolicy, Flow, HeaderValue, HookMask,
    HookResult, HttpPlugin, PluginBuildError, PluginConfig, PluginFactory, RequestCtx,
    RequestSummary, StatusCode, header,
};
use tracing::warn;

use crate::telemetry::McpMetrics;
use crate::types::{
    MCP_ERR_RATE_LIMITED, McpLoopBreakInfo, McpPrincipal, McpRequestMeta, canonical_json_bytes,
    glob_match, jsonrpc_error_response, sha256_hex,
};

const DEFAULT_WINDOW_SECS: u64 = 60;
const DEFAULT_MAX_BUCKETS: usize = 32_768;

fn default_window_secs() -> u64 {
    DEFAULT_WINDOW_SECS
}

fn default_max_buckets() -> usize {
    DEFAULT_MAX_BUCKETS
}

#[derive(Debug, Clone, Deserialize)]
struct PerToolLimitConfig {
    rpm: u64,
    #[serde(default = "default_window_secs")]
    window_secs: u64,
}

/// Identical tool-call loop breaker configuration.
///
/// Hashes `(scope, tool_name, canonical_arguments)` and rejects stuck agent loops
/// invoking the exact same tool with identical arguments more than `max_repeats`
/// times inside `window_secs`.
#[derive(Debug, Clone, Deserialize)]
struct LoopBreakerConfig {
    /// Maximum identical calls allowed within `window_secs` before tripping.
    max_repeats: u64,
    #[serde(default = "default_window_secs")]
    window_secs: u64,
}

#[derive(Debug, Deserialize)]
#[serde(default)]
struct McpRateLimitConfig {
    /// Default total MCP requests per window per principal/client (0 = unlimited).
    rpm: u64,
    /// Default `tools/call` requests per window per principal/client (0 = unlimited).
    tool_rpm: u64,
    /// Fixed window duration in seconds for `rpm` and `tool_rpm` (default: 60).
    #[serde(default = "default_window_secs")]
    window_secs: u64,
    /// Hard cap on total `tools/call` invocations in a single MCP session (0 = unlimited).
    max_calls_per_session: u64,
    /// TTL in seconds for session call counters (default: 3600).
    #[serde(default = "default_session_counter_ttl")]
    session_window_secs: u64,
    /// Max concurrent in-flight `tools/call` executions per principal (0 = unlimited).
    max_parallel_calls: u64,
    /// Per-tool glob rate limits (`"github__create_issue" = { rpm = 5, window_secs = 60 }`).
    #[serde(default)]
    tool_limits: BTreeMap<String, PerToolLimitConfig>,
    /// Optional stuck-agent loop breaker.
    #[serde(default)]
    loop_breaker: Option<LoopBreakerConfig>,
    /// Maximum bounded entries in local rate-limit tables (default: 32,768).
    #[serde(default = "default_max_buckets")]
    max_buckets: usize,
}

fn default_session_counter_ttl() -> u64 {
    3_600
}

impl Default for McpRateLimitConfig {
    fn default() -> Self {
        Self {
            rpm: 0,
            tool_rpm: 0,
            window_secs: DEFAULT_WINDOW_SECS,
            max_calls_per_session: 0,
            session_window_secs: default_session_counter_ttl(),
            max_parallel_calls: 0,
            tool_limits: BTreeMap::new(),
            loop_breaker: None,
            max_buckets: DEFAULT_MAX_BUCKETS,
        }
    }
}

#[derive(Debug, Clone)]
struct CounterWindow {
    count: u64,
    window_start: Duration,
    window_len: Duration,
}

/// Reload-persistent, bounded local rate-limit / loop-breaker / concurrency table stored in `StateStore`.
#[derive(Debug, Default)]
pub struct McpRateLimitTable {
    windows: Mutex<HashMap<String, CounterWindow>>,
    inflight: Mutex<HashMap<String, u64>>,
    total_rate_limited: AtomicU64,
    total_loop_breaks: AtomicU64,
    total_session_caps: AtomicU64,
}

/// Read-only snapshot for Admin Inspector `/api/status`.
#[derive(Debug, Clone, Serialize)]
pub struct McpRateLimitStatsSnapshot {
    pub active_buckets: usize,
    pub active_inflight: u64,
    pub total_rate_limited: u64,
    pub total_loop_breaks: u64,
    pub total_session_caps: u64,
}

impl McpRateLimitTable {
    /// Atomically checks and increments a fixed-window counter.
    /// Returns `Ok((current, remaining))` when admitted, or `Err(retry_after_secs)` when exceeded.
    pub fn try_consume(
        &self,
        key: &str,
        limit: u64,
        window: Duration,
        now: Duration,
        max_buckets: usize,
    ) -> Result<(u64, u64), u64> {
        let mut guard = self.windows.lock().expect("McpRateLimitTable poisoned");
        guard.retain(|_, w| now < w.window_start.saturating_add(w.window_len));

        if let Some(entry) = guard.get_mut(key) {
            if entry.count >= limit {
                let end = entry.window_start.saturating_add(entry.window_len);
                let retry = end.saturating_sub(now).as_secs().max(1);
                return Err(retry);
            }
            entry.count += 1;
            return Ok((entry.count, limit.saturating_sub(entry.count)));
        }

        if guard.len() >= max_buckets.max(1)
            && let Some(oldest) = guard
                .iter()
                .min_by_key(|(_, w)| w.window_start.saturating_add(w.window_len))
                .map(|(k, _)| k.clone())
        {
            guard.remove(&oldest);
        }

        if limit == 0 {
            return Err(window.as_secs().max(1));
        }

        guard.insert(
            key.to_owned(),
            CounterWindow {
                count: 1,
                window_start: now,
                window_len: window,
            },
        );
        Ok((1, limit.saturating_sub(1)))
    }

    pub fn try_acquire_inflight(&self, key: &str, limit: u64) -> bool {
        let mut guard = self.inflight.lock().expect("McpRateLimitTable poisoned");
        let cur = guard.entry(key.to_owned()).or_insert(0);
        if *cur >= limit {
            return false;
        }
        *cur += 1;
        true
    }

    pub fn release_inflight(&self, key: &str) {
        let mut guard = self.inflight.lock().expect("McpRateLimitTable poisoned");
        if let Some(cur) = guard.get_mut(key) {
            *cur = cur.saturating_sub(1);
            if *cur == 0 {
                guard.remove(key);
            }
        }
    }

    pub fn record_rate_limited(&self) {
        self.total_rate_limited.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_loop_break(&self) {
        self.total_loop_breaks.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_session_cap(&self) {
        self.total_session_caps.fetch_add(1, Ordering::Relaxed);
    }

    pub fn snapshot(&self, now: Duration) -> McpRateLimitStatsSnapshot {
        let active_buckets = {
            let guard = self.windows.lock().expect("McpRateLimitTable poisoned");
            guard
                .values()
                .filter(|w| now < w.window_start.saturating_add(w.window_len))
                .count()
        };
        let active_inflight: u64 = {
            let guard = self.inflight.lock().expect("McpRateLimitTable poisoned");
            guard.values().copied().sum()
        };
        McpRateLimitStatsSnapshot {
            active_buckets,
            active_inflight,
            total_rate_limited: self.total_rate_limited.load(Ordering::Relaxed),
            total_loop_breaks: self.total_loop_breaks.load(Ordering::Relaxed),
            total_session_caps: self.total_session_caps.load(Ordering::Relaxed),
        }
    }
}

/// RAII concurrency guard stored in `RequestCtx::extensions`; guarantees release even on abort/panic.
#[derive(Clone)]
struct InflightCallGuard {
    _inner: Arc<InflightGuardInner>,
}

struct InflightGuardInner {
    table: Arc<McpRateLimitTable>,
    key: String,
}

impl Drop for InflightGuardInner {
    fn drop(&mut self) {
        self.table.release_inflight(&self.key);
    }
}

/// Plugin factory for `mcp-rate-limit`.
pub struct McpRateLimitFactory {
    metrics: Arc<McpMetrics>,
}

impl McpRateLimitFactory {
    pub fn new(metrics: Arc<McpMetrics>) -> Self {
        Self { metrics }
    }
}

impl PluginFactory for McpRateLimitFactory {
    fn name(&self) -> &str {
        "mcp-rate-limit"
    }

    fn build(
        &self,
        config: &PluginConfig,
        ctx: &BuildContext,
    ) -> Result<Arc<dyn HttpPlugin>, PluginBuildError> {
        let cfg: McpRateLimitConfig = config.deserialize(self.name())?;
        let table = ctx
            .state_handle()
            .get_or_init("mcp-rate-limit", McpRateLimitTable::default);

        Ok(Arc::new(McpRateLimitPlugin {
            rpm: cfg.rpm,
            tool_rpm: cfg.tool_rpm,
            window: Duration::from_secs(cfg.window_secs.max(1)),
            max_calls_per_session: cfg.max_calls_per_session,
            session_window: Duration::from_secs(cfg.session_window_secs.max(1)),
            max_parallel_calls: cfg.max_parallel_calls,
            tool_limits: cfg.tool_limits,
            loop_breaker: cfg.loop_breaker,
            max_buckets: cfg.max_buckets.max(1),
            table,
            distributed: ctx.distributed_store(),
            clock: ctx.clock(),
            metrics: Arc::clone(&self.metrics),
        }))
    }
}

/// MCP per-principal/per-tool rate limiter, per-session budget cap, concurrency limiter,
/// and identical-call agent loop breaker.
pub struct McpRateLimitPlugin {
    rpm: u64,
    tool_rpm: u64,
    window: Duration,
    max_calls_per_session: u64,
    session_window: Duration,
    max_parallel_calls: u64,
    tool_limits: BTreeMap<String, PerToolLimitConfig>,
    loop_breaker: Option<LoopBreakerConfig>,
    max_buckets: usize,
    table: Arc<McpRateLimitTable>,
    distributed: Option<Arc<dyn DistributedStore>>,
    clock: Arc<dyn Clock>,
    metrics: Arc<McpMetrics>,
}

impl McpRateLimitPlugin {
    fn find_tool_limit(&self, full: &str, raw: Option<&str>) -> Option<&PerToolLimitConfig> {
        for (pat, cfg) in &self.tool_limits {
            if glob_match(pat, full) || raw.is_some_and(|r| glob_match(pat, r)) {
                return Some(cfg);
            }
        }
        None
    }

    fn rate_limit_response(
        req_id: Option<&serde_json::Value>,
        message: String,
        retry_after: u64,
        reason: &str,
    ) -> Flow {
        let mut resp = jsonrpc_error_response(
            StatusCode::TOO_MANY_REQUESTS,
            req_id,
            MCP_ERR_RATE_LIMITED,
            message,
            Some(json!({ "reason": reason, "retry_after_secs": retry_after })),
        );
        if let Ok(hv) = HeaderValue::from_str(&retry_after.to_string()) {
            resp.headers.insert(header::RETRY_AFTER, hv);
        }
        Flow::Respond(resp)
    }
}

impl HttpPlugin for McpRateLimitPlugin {
    fn name(&self) -> &str {
        "mcp-rate-limit"
    }

    fn hook_mask(&self) -> HookMask {
        HookMask::REQUEST_BODY_BUFFERED | HookMask::ON_COMPLETE
    }

    fn on_request_body_buffered<'a>(
        &'a self,
        ctx: &'a mut RequestCtx,
        _body: &'a mut Bytes,
    ) -> HookResult<'a, Flow> {
        let Some(meta) = ctx.get_ext::<McpRequestMeta>().cloned() else {
            return HookResult::Ready(Flow::Continue);
        };
        if meta.handled_locally {
            return HookResult::Ready(Flow::Continue);
        }

        let principal = ctx.get_ext::<McpPrincipal>().cloned();
        let scope = principal
            .as_ref()
            .map(|p| format!("p:{}", p.id))
            .unwrap_or_else(|| format!("ip:{}", ctx.client_addr.ip()));

        let eff_rpm = principal.as_ref().and_then(|p| p.rpm).unwrap_or(self.rpm);
        let eff_tool_rpm = principal
            .as_ref()
            .and_then(|p| p.tool_rpm)
            .unwrap_or(self.tool_rpm);
        let eff_session_cap = principal
            .as_ref()
            .and_then(|p| p.max_calls_per_session)
            .unwrap_or(self.max_calls_per_session);
        let eff_parallel = principal
            .as_ref()
            .and_then(|p| p.max_parallel_calls)
            .unwrap_or(self.max_parallel_calls);

        let is_tool_call = meta.method == "tools/call";
        let tool_full = meta.tool_name.clone();
        let tool_raw = meta.backend_tool_name.clone();

        // Build list of (bucket_key, limit, window, kind, label) checks to enforce
        let mut checks: Vec<(String, u64, Duration, &'static str, String)> = Vec::new();
        if eff_rpm > 0 {
            checks.push((
                format!("mcp:rpm:{scope}"),
                eff_rpm,
                self.window,
                "rpm",
                format!(
                    "MCP request rate limit ({eff_rpm}/{:?}) exceeded",
                    self.window
                ),
            ));
        }

        if is_tool_call {
            if eff_tool_rpm > 0 {
                checks.push((
                    format!("mcp:tool_rpm:{scope}"),
                    eff_tool_rpm,
                    self.window,
                    "tool_rpm",
                    format!(
                        "MCP tools/call rate limit ({eff_tool_rpm}/{:?}) exceeded",
                        self.window
                    ),
                ));
            }
            if let Some(ref tf) = tool_full {
                if let Some(tl) = self.find_tool_limit(tf, tool_raw.as_deref())
                    && tl.rpm > 0
                {
                    let w = Duration::from_secs(tl.window_secs.max(1));
                    checks.push((
                        format!("mcp:tool:{scope}:{tf}"),
                        tl.rpm,
                        w,
                        "per_tool_rpm",
                        format!("tool `{tf}` rate limit ({}/{:?}) exceeded", tl.rpm, w),
                    ));
                }

                if eff_session_cap > 0 {
                    let sess_key = meta.session_id.as_deref().unwrap_or(scope.as_str());
                    checks.push((
                        format!("mcp:sess:{sess_key}"),
                        eff_session_cap,
                        self.session_window,
                        "session_cap",
                        format!("MCP session tool-call budget ({eff_session_cap} calls) exceeded"),
                    ));
                }

                if let Some(ref lb) = self.loop_breaker
                    && lb.max_repeats > 0
                {
                    let args_canon = meta
                        .arguments
                        .as_ref()
                        .map(canonical_json_bytes)
                        .unwrap_or_default();
                    let args_hash = sha256_hex(&args_canon);
                    let lb_scope = meta.session_id.as_deref().unwrap_or(scope.as_str());
                    let w = Duration::from_secs(lb.window_secs.max(1));
                    checks.push((
                        format!("mcp:loop:{lb_scope}:{tf}:{args_hash}"),
                        lb.max_repeats,
                        w,
                        "loop_breaker",
                        format!(
                            "agent loop breaker triggered: tool `{tf}` invoked with identical arguments more than {} time(s) in {}s",
                            lb.max_repeats,
                            w.as_secs()
                        ),
                    ));
                }
            }
        }

        // Fast sync path when no DistributedStore is configured
        if self.distributed.is_none() {
            let now = self.clock.now();
            let table = self.table.as_ref();
            for (key, limit, win, kind, msg) in checks {
                if let Err(retry_after) = table.try_consume(&key, limit, win, now, self.max_buckets)
                {
                    table.record_rate_limited();
                    if kind == "loop_breaker" {
                        table.record_loop_break();
                        if let Some(ref tf) = tool_full {
                            self.metrics.record_loop_break(tf);
                            ctx.insert_ext(McpLoopBreakInfo {
                                tool: tf.clone(),
                                repeats: limit + 1,
                            });
                        }
                    } else if kind == "session_cap" {
                        table.record_session_cap();
                    }
                    return HookResult::Ready(Self::rate_limit_response(
                        meta.jsonrpc_id.as_ref(),
                        msg,
                        retry_after,
                        kind,
                    ));
                }
            }

            if is_tool_call && eff_parallel > 0 {
                let pkey = format!("mcp:par:{scope}");
                if !table.try_acquire_inflight(&pkey, eff_parallel) {
                    table.record_rate_limited();
                    return HookResult::Ready(Self::rate_limit_response(
                        meta.jsonrpc_id.as_ref(),
                        format!("max_parallel_calls ({eff_parallel}) exceeded"),
                        1,
                        "max_parallel_calls",
                    ));
                }
                ctx.insert_ext(InflightCallGuard {
                    _inner: Arc::new(InflightGuardInner {
                        table: Arc::clone(&self.table),
                        key: pkey,
                    }),
                });
            }

            return HookResult::Ready(Flow::Continue);
        }

        // Distributed Redis/Valkey path
        let store = self.distributed.clone().unwrap();
        let table_handle = Arc::clone(&self.table);
        let metrics = Arc::clone(&self.metrics);
        let req_id = meta.jsonrpc_id.clone();

        HookResult::pending(async move {
            for (key, limit, win, kind, msg) in checks {
                match store.try_consume_quota(&key, 1, limit, win).await {
                    Ok(outcome) if outcome.allowed => {}
                    Ok(outcome) => {
                        table_handle.record_rate_limited();
                        if kind == "loop_breaker" {
                            table_handle.record_loop_break();
                            if let Some(ref tf) = tool_full {
                                metrics.record_loop_break(tf);
                                ctx.insert_ext(McpLoopBreakInfo {
                                    tool: tf.clone(),
                                    repeats: limit + 1,
                                });
                            }
                        } else if kind == "session_cap" {
                            table_handle.record_session_cap();
                        }
                        return Self::rate_limit_response(
                            req_id.as_ref(),
                            msg,
                            outcome.retry_after_secs.max(1),
                            kind,
                        );
                    }
                    Err(err) => {
                        warn!(error = %err, key = %key, "MCP distributed rate-limit store error");
                        if store.failure_policy() == FailurePolicy::FailClosed {
                            return Flow::Respond(jsonrpc_error_response(
                                StatusCode::SERVICE_UNAVAILABLE,
                                req_id.as_ref(),
                                MCP_ERR_RATE_LIMITED,
                                "distributed rate-limit store unavailable",
                                None,
                            ));
                        }
                    }
                }
            }

            if is_tool_call && eff_parallel > 0 {
                let pkey = format!("mcp:par:{scope}");
                if !table_handle.try_acquire_inflight(&pkey, eff_parallel) {
                    table_handle.record_rate_limited();
                    return Self::rate_limit_response(
                        req_id.as_ref(),
                        format!("max_parallel_calls ({eff_parallel}) exceeded"),
                        1,
                        "max_parallel_calls",
                    );
                }
                ctx.insert_ext(InflightCallGuard {
                    _inner: Arc::new(InflightGuardInner {
                        table: table_handle,
                        key: pkey,
                    }),
                });
            }

            Flow::Continue
        })
    }

    fn on_complete<'a>(
        &'a self,
        _ctx: &'a RequestCtx,
        _summary: &'a RequestSummary,
    ) -> HookResult<'a, ()> {
        // `InflightCallGuard` releases deterministically when `RequestCtx` drops.
        HookResult::Ready(())
    }
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;

    proptest! {
        #[test]
        fn bounded_table_never_exceeds_max_buckets_or_limit(
            ops in proptest::collection::vec((0u8..8, 0u64..120), 1..100),
            limit in 1u64..10,
            max_buckets in 1usize..6,
        ) {
            let table = McpRateLimitTable::default();
            for (k, t_secs) in ops {
                let key = format!("k{k}");
                let _ = table.try_consume(
                    &key,
                    limit,
                    Duration::from_secs(30),
                    Duration::from_secs(t_secs),
                    max_buckets,
                );
                let snap = table.snapshot(Duration::from_secs(t_secs));
                prop_assert!(snap.active_buckets <= max_buckets);
            }
        }
    }
}
