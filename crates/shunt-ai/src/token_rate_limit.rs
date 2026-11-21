use std::collections::HashMap;
use std::hash::{DefaultHasher, Hash, Hasher};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde::Deserialize;
use shunt_plugin_sdk::{
    BufferedResponse, BuildContext, Bytes, Clock, DistributedStore, FailurePolicy, Flow,
    HeaderName, HeaderValue, HookMask, HookResult, HttpPlugin, PluginBuildError, PluginConfig,
    PluginFactory, RequestCtx, RequestSummary, ResponseHead, StatusCode, header,
};
use tracing::warn;

use crate::tokens::estimate_request_tokens;
use crate::types::{
    AiEndpointKind, AiKeyPolicy, AiUsage, DetectedEndpoint, endpoint_error_response,
};

const DEFAULT_WINDOW_SECS: u64 = 60;
const DEFAULT_MAX_ENTRIES: usize = 100_000;
const NUM_SHARDS: usize = 16;

fn default_true() -> bool {
    true
}

fn default_window_secs() -> u64 {
    DEFAULT_WINDOW_SECS
}

fn default_max_entries() -> usize {
    DEFAULT_MAX_ENTRIES
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "snake_case")]
enum TokenRateLimitKeyBy {
    /// Scope by authenticated virtual key ID (falls back to client IP when unauthenticated).
    #[default]
    VirtualKey,
    /// Scope by authenticated virtual key's team (falls back to key ID, then client IP).
    Team,
    ClientIp,
    Global,
    Header,
}

#[derive(Debug, Deserialize)]
#[serde(default)]
struct AiTokenRateLimitConfig {
    /// Default requests-per-window limit (typically per minute). Overridden by `AiKeyPolicy::rpm`.
    rpm: Option<u64>,
    /// Default tokens-per-window limit (typically per minute). Overridden by `AiKeyPolicy::tpm`.
    tpm: Option<u64>,
    /// Window size in seconds (default: `60`).
    #[serde(default = "default_window_secs")]
    window_secs: u64,
    /// Subject bucketing strategy (default: `"virtual_key"`).
    key_by: TokenRateLimitKeyBy,
    /// Header name when `key_by = "header"`.
    header_name: Option<String>,
    /// Reconcile pre-flight token estimate against actual `AiUsage` in `on_complete` (default: true).
    #[serde(default = "default_true")]
    reconcile_usage: bool,
    /// Optional cap on client `max_tokens` reserved during pre-flight (default: `0` = input only).
    reserve_output_tokens_cap: u64,
    /// Max tracked subjects in local memory (default: `100_000`).
    #[serde(default = "default_max_entries")]
    max_entries: usize,
    /// Use the gateway's configured distributed store (e.g., Redis/Valkey) when available (default: true).
    #[serde(default = "default_true")]
    distributed: bool,
}

impl Default for AiTokenRateLimitConfig {
    fn default() -> Self {
        Self {
            rpm: None,
            tpm: None,
            window_secs: DEFAULT_WINDOW_SECS,
            key_by: TokenRateLimitKeyBy::VirtualKey,
            header_name: None,
            reconcile_usage: true,
            reserve_output_tokens_cap: 0,
            max_entries: DEFAULT_MAX_ENTRIES,
            distributed: true,
        }
    }
}

/// Per-request reservation stored in `RequestCtx::extensions` for response headers &
/// post-response reconciliation in `on_complete`.
#[derive(Debug, Clone)]
pub struct AiTokenReservation {
    pub subject: String,
    pub window_id: u64,
    pub estimated_tokens: u64,
    pub rpm_limit: Option<u64>,
    pub rpm_remaining: Option<u64>,
    pub tpm_limit: Option<u64>,
    pub tpm_remaining: Option<u64>,
    pub rpm_dist_key: Option<String>,
    pub tpm_dist_key: Option<String>,
}

#[derive(Debug, Clone, Copy)]
struct WindowCounters {
    window_id: u64,
    requests: u64,
    tokens: u64,
    last_seen_ms: u64,
}

#[derive(Debug, Clone, Copy)]
enum LocalReserveError {
    RpmExceeded {
        limit: u64,
        retry_after_secs: u64,
        tpm_limit: Option<u64>,
        tpm_remaining: Option<u64>,
    },
    TpmExceeded {
        limit: u64,
        remaining: u64,
        retry_after_secs: u64,
        rpm_limit: Option<u64>,
        rpm_remaining: Option<u64>,
    },
}

#[derive(Debug, Clone, Copy)]
struct LocalReserveOk {
    rpm_remaining: Option<u64>,
    tpm_remaining: Option<u64>,
}

/// Sharded, bounded-cardinality fixed-window RPM/TPM state table persisted across reloads.
#[derive(Debug)]
pub struct QuotaWindowTable {
    shards: Box<[Mutex<HashMap<String, WindowCounters>>]>,
    entry_count: AtomicUsize,
}

impl Default for QuotaWindowTable {
    fn default() -> Self {
        Self::new()
    }
}

impl QuotaWindowTable {
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

    pub fn len(&self) -> usize {
        self.entry_count.load(Ordering::Acquire)
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    fn shard_index(key: &str) -> usize {
        let mut h = DefaultHasher::new();
        key.hash(&mut h);
        (h.finish() as usize) % NUM_SHARDS
    }

    fn try_reserve_slot(&self, cap: usize) -> bool {
        let mut cur = self.entry_count.load(Ordering::Acquire);
        loop {
            if cur >= cap {
                return false;
            }
            match self.entry_count.compare_exchange_weak(
                cur,
                cur + 1,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => return true,
                Err(actual) => cur = actual,
            }
        }
    }

    /// Atomically checks and reserves `1` request and `estimated_tokens` for `subject`.
    #[allow(clippy::too_many_arguments)]
    fn try_reserve(
        &self,
        subject: &str,
        rpm_limit: Option<u64>,
        tpm_limit: Option<u64>,
        estimated_tokens: u64,
        now_ms: u64,
        window_ms: u64,
        max_entries: usize,
    ) -> Result<LocalReserveOk, LocalReserveError> {
        let cap = max_entries.max(1);
        let window_id = now_ms / window_ms;
        let window_end_ms = (window_id.saturating_add(1)).saturating_mul(window_ms);
        let rem_ms = window_end_ms.saturating_sub(now_ms);
        let retry_after_secs = rem_ms.div_ceil(1000).max(1);

        let shard_idx = Self::shard_index(subject);
        let mut map = self.shards[shard_idx]
            .lock()
            .expect("QuotaWindowTable shard lock poisoned");

        // Opportunistically evict expired windows in this shard.
        let before = map.len();
        map.retain(|_, c| c.window_id == window_id);
        let evicted = before - map.len();
        if evicted > 0 {
            self.entry_count.fetch_sub(evicted, Ordering::AcqRel);
        }

        let current = map
            .get(subject)
            .copied()
            .filter(|c| c.window_id == window_id)
            .unwrap_or(WindowCounters {
                window_id,
                requests: 0,
                tokens: 0,
                last_seen_ms: now_ms,
            });

        if let Some(rpm) = rpm_limit
            && current.requests.saturating_add(1) > rpm
        {
            return Err(LocalReserveError::RpmExceeded {
                limit: rpm,
                retry_after_secs,
                tpm_limit,
                tpm_remaining: tpm_limit.map(|l| l.saturating_sub(current.tokens)),
            });
        }

        if let Some(tpm) = tpm_limit
            && current.tokens.saturating_add(estimated_tokens) > tpm
        {
            return Err(LocalReserveError::TpmExceeded {
                limit: tpm,
                remaining: tpm.saturating_sub(current.tokens),
                retry_after_secs,
                rpm_limit,
                rpm_remaining: rpm_limit.map(|l| l.saturating_sub(current.requests)),
            });
        }

        let updated = WindowCounters {
            window_id,
            requests: current.requests.saturating_add(1),
            tokens: current.tokens.saturating_add(estimated_tokens),
            last_seen_ms: now_ms,
        };

        if let Some(slot) = map.get_mut(subject) {
            *slot = updated;
        } else if self.try_reserve_slot(cap) {
            map.insert(subject.to_owned(), updated);
        } else if let Some(oldest) = map
            .iter()
            .min_by_key(|(_, c)| c.last_seen_ms)
            .map(|(k, _)| k.clone())
            && map.remove(&oldest).is_some()
        {
            map.insert(subject.to_owned(), updated);
        }

        Ok(LocalReserveOk {
            rpm_remaining: rpm_limit.map(|l| l.saturating_sub(updated.requests)),
            tpm_remaining: tpm_limit.map(|l| l.saturating_sub(updated.tokens)),
        })
    }

    /// Reconciles actual tokens/requests against a previously reserved window entry.
    pub fn adjust(&self, subject: &str, window_id: u64, req_delta: i64, tok_delta: i64) {
        let shard_idx = Self::shard_index(subject);
        let mut map = self.shards[shard_idx]
            .lock()
            .expect("QuotaWindowTable shard lock poisoned");
        if let Some(entry) = map.get_mut(subject)
            && entry.window_id == window_id
        {
            entry.requests = apply_signed_delta(entry.requests, req_delta);
            entry.tokens = apply_signed_delta(entry.tokens, tok_delta);
        }
    }

    /// Reads current `(requests, tokens)` in `window_id` for `subject` (testing/diagnostics).
    pub fn current_usage(&self, subject: &str, window_id: u64) -> (u64, u64) {
        let shard_idx = Self::shard_index(subject);
        let map = self.shards[shard_idx]
            .lock()
            .expect("QuotaWindowTable shard lock poisoned");
        map.get(subject)
            .filter(|e| e.window_id == window_id)
            .map(|e| (e.requests, e.tokens))
            .unwrap_or((0, 0))
    }
}

pub(crate) fn apply_signed_delta(base: u64, delta: i64) -> u64 {
    if delta >= 0 {
        base.saturating_add(delta as u64)
    } else {
        base.saturating_sub(delta.unsigned_abs())
    }
}

/// Factory for the `ai-token-rate-limit` plugin.
pub struct AiTokenRateLimitFactory;

impl PluginFactory for AiTokenRateLimitFactory {
    fn name(&self) -> &str {
        "ai-token-rate-limit"
    }

    fn build(
        &self,
        config: &PluginConfig,
        ctx: &BuildContext,
    ) -> Result<Arc<dyn HttpPlugin>, PluginBuildError> {
        let cfg: AiTokenRateLimitConfig = config.deserialize(self.name())?;
        if cfg.window_secs == 0 {
            return Err(PluginBuildError::BuildFailed {
                plugin: self.name().to_owned(),
                message: "`window_secs` must be >= 1".to_owned(),
            });
        }
        if cfg.rpm == Some(0) {
            return Err(PluginBuildError::BuildFailed {
                plugin: self.name().to_owned(),
                message: "`rpm` must be >= 1".to_owned(),
            });
        }
        if cfg.tpm == Some(0) {
            return Err(PluginBuildError::BuildFailed {
                plugin: self.name().to_owned(),
                message: "`tpm` must be >= 1".to_owned(),
            });
        }
        if cfg.max_entries == 0 {
            return Err(PluginBuildError::BuildFailed {
                plugin: self.name().to_owned(),
                message: "`max_entries` must be >= 1".to_owned(),
            });
        }

        let header_name = if cfg.key_by == TokenRateLimitKeyBy::Header {
            let raw = cfg
                .header_name
                .as_deref()
                .ok_or_else(|| PluginBuildError::BuildFailed {
                    plugin: self.name().to_owned(),
                    message: "`header_name` is required when `key_by = \"header\"`".to_owned(),
                })?;
            Some(HeaderName::from_bytes(raw.as_bytes()).map_err(|e| {
                PluginBuildError::BuildFailed {
                    plugin: self.name().to_owned(),
                    message: format!("invalid `header_name` `{raw}`: {e}"),
                }
            })?)
        } else {
            None
        };

        let table = ctx
            .state_handle()
            .get_or_init("ai_token_quotas", QuotaWindowTable::new);
        let distributed = if cfg.distributed {
            ctx.distributed_store()
        } else {
            None
        };

        Ok(Arc::new(AiTokenRateLimitPlugin {
            scope_id: ctx.scope_id().to_owned(),
            default_rpm: cfg.rpm,
            default_tpm: cfg.tpm,
            window_ms: cfg.window_secs.saturating_mul(1_000),
            window: Duration::from_secs(cfg.window_secs),
            key_by: cfg.key_by,
            header_name,
            reconcile_usage: cfg.reconcile_usage,
            reserve_output_tokens_cap: cfg.reserve_output_tokens_cap,
            max_entries: cfg.max_entries,
            clock: ctx.clock(),
            table,
            distributed,
        }))
    }
}

#[derive(Debug, Clone)]
struct CapturedHeaderSubject(String);

/// Token-aware RPM & TPM rate limiter (`ai-token-rate-limit`) with pre-flight estimation,
/// post-response `AiUsage` reconciliation, per-virtual-key overrides, and optional
/// distributed Redis / Valkey coordination.
pub struct AiTokenRateLimitPlugin {
    scope_id: String,
    default_rpm: Option<u64>,
    default_tpm: Option<u64>,
    window_ms: u64,
    window: Duration,
    key_by: TokenRateLimitKeyBy,
    header_name: Option<HeaderName>,
    reconcile_usage: bool,
    reserve_output_tokens_cap: u64,
    max_entries: usize,
    clock: Arc<dyn Clock>,
    table: Arc<QuotaWindowTable>,
    distributed: Option<Arc<dyn DistributedStore>>,
}

impl AiTokenRateLimitPlugin {
    fn resolve_subject(&self, ctx: &RequestCtx) -> String {
        let policy = ctx.get_ext::<AiKeyPolicy>();
        match self.key_by {
            TokenRateLimitKeyBy::VirtualKey => policy
                .map(|p| format!("key:{}", p.key_id))
                .unwrap_or_else(|| format!("ip:{}", ctx.client_addr.ip())),
            TokenRateLimitKeyBy::Team => policy
                .and_then(|p| p.team.as_deref().map(|t| format!("team:{t}")))
                .or_else(|| policy.map(|p| format!("key:{}", p.key_id)))
                .unwrap_or_else(|| format!("ip:{}", ctx.client_addr.ip())),
            TokenRateLimitKeyBy::ClientIp => format!("ip:{}", ctx.client_addr.ip()),
            TokenRateLimitKeyBy::Global => "global".to_owned(),
            TokenRateLimitKeyBy::Header => ctx
                .get_ext::<CapturedHeaderSubject>()
                .map(|h| format!("hdr:{}", h.0))
                .unwrap_or_else(|| format!("ip:{}", ctx.client_addr.ip())),
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn rate_limit_error(
        endpoint: AiEndpointKind,
        code: &str,
        message: &str,
        retry_after_secs: u64,
        rpm_limit: Option<u64>,
        rpm_remaining: Option<u64>,
        tpm_limit: Option<u64>,
        tpm_remaining: Option<u64>,
    ) -> BufferedResponse {
        let mut resp = endpoint_error_response(
            endpoint,
            StatusCode::TOO_MANY_REQUESTS,
            "rate_limit_error",
            Some(code),
            message,
        );
        if let Ok(v) = HeaderValue::from_str(&retry_after_secs.to_string()) {
            resp.headers.insert(header::RETRY_AFTER, v);
        }
        attach_ratelimit_headers(
            &mut resp.headers,
            rpm_limit,
            rpm_remaining,
            tpm_limit,
            tpm_remaining,
        );
        resp
    }
}

fn attach_ratelimit_headers(
    headers: &mut shunt_plugin_sdk::HeaderMap,
    rpm_limit: Option<u64>,
    rpm_remaining: Option<u64>,
    tpm_limit: Option<u64>,
    tpm_remaining: Option<u64>,
) {
    if let Some(lim) = rpm_limit
        && let Ok(v) = HeaderValue::from_str(&lim.to_string())
    {
        headers.insert(HeaderName::from_static("x-ratelimit-limit-requests"), v);
    }
    if let Some(rem) = rpm_remaining
        && let Ok(v) = HeaderValue::from_str(&rem.to_string())
    {
        headers.insert(HeaderName::from_static("x-ratelimit-remaining-requests"), v);
    }
    if let Some(lim) = tpm_limit
        && let Ok(v) = HeaderValue::from_str(&lim.to_string())
    {
        headers.insert(HeaderName::from_static("x-ratelimit-limit-tokens"), v);
    }
    if let Some(rem) = tpm_remaining
        && let Ok(v) = HeaderValue::from_str(&rem.to_string())
    {
        headers.insert(HeaderName::from_static("x-ratelimit-remaining-tokens"), v);
    }
}

impl HttpPlugin for AiTokenRateLimitPlugin {
    fn name(&self) -> &str {
        "ai-token-rate-limit"
    }

    fn hook_mask(&self) -> HookMask {
        let mut mask =
            HookMask::REQUEST_BODY_BUFFERED | HookMask::ON_RESPONSE_HEADERS | HookMask::ON_COMPLETE;
        if self.header_name.is_some() {
            mask |= HookMask::ON_REQUEST_HEADERS;
        }
        mask
    }

    fn on_request_headers<'a>(
        &'a self,
        ctx: &'a mut RequestCtx,
        req: &'a mut shunt_plugin_sdk::RequestHead,
    ) -> HookResult<'a, Flow> {
        if let Some(hdr) = &self.header_name
            && let Some(val) = req
                .headers
                .get(hdr)
                .and_then(|v| v.to_str().ok())
                .map(str::trim)
                .filter(|s| !s.is_empty())
        {
            ctx.insert_ext(CapturedHeaderSubject(val.to_owned()));
        }
        HookResult::Ready(Flow::Continue)
    }

    fn on_request_body_buffered<'a>(
        &'a self,
        ctx: &'a mut RequestCtx,
        body: &'a mut Bytes,
    ) -> HookResult<'a, Flow> {
        let endpoint = ctx
            .get_ext::<DetectedEndpoint>()
            .map(|d| d.0)
            .unwrap_or(AiEndpointKind::ChatCompletions);
        if endpoint.is_models_discovery() {
            return HookResult::Ready(Flow::Continue);
        }

        let policy = ctx.get_ext::<AiKeyPolicy>();
        let rpm_limit = policy.and_then(|p| p.rpm).or(self.default_rpm);
        let tpm_limit = policy.and_then(|p| p.tpm).or(self.default_tpm);
        if rpm_limit.is_none() && tpm_limit.is_none() {
            return HookResult::Ready(Flow::Continue);
        }

        let subject = self.resolve_subject(ctx);
        let est = estimate_request_tokens(endpoint, body);
        let output_reserve = est
            .requested_max_output
            .unwrap_or(0)
            .min(self.reserve_output_tokens_cap);
        let estimated_tokens = est.input_tokens.saturating_add(output_reserve).max(1);
        let now_ms = self.clock.now_ms();
        let window_id = now_ms / self.window_ms;

        if let Some(dist) = &self.distributed {
            let dist = Arc::clone(dist);
            let rpm_key = format!("ai_rpm:{}:{subject}", self.scope_id);
            let tpm_key = format!("ai_tpm:{}:{subject}", self.scope_id);
            let window = self.window;
            return HookResult::pending(async move {
                let mut rpm_remaining = None;
                let mut tpm_remaining = None;
                let mut rpm_consumed = false;

                if let Some(rpm) = rpm_limit {
                    match dist.try_consume_quota(&rpm_key, 1, rpm, window).await {
                        Ok(out) if out.allowed => {
                            rpm_consumed = true;
                            rpm_remaining = Some(out.remaining);
                        }
                        Ok(out) => {
                            return Flow::Respond(Self::rate_limit_error(
                                endpoint,
                                "rpm_limit_exceeded",
                                &format!(
                                    "Request rate limit exceeded ({rpm} requests per {}s)",
                                    window.as_secs()
                                ),
                                out.retry_after_secs,
                                rpm_limit,
                                Some(0),
                                tpm_limit,
                                None,
                            ));
                        }
                        Err(err) => {
                            warn!(
                                plugin = "ai-token-rate-limit",
                                backend = dist.backend_name(),
                                error = %err,
                                "distributed RPM check failed"
                            );
                            if dist.failure_policy() == FailurePolicy::FailClosed {
                                return Flow::Respond(endpoint_error_response(
                                    endpoint,
                                    StatusCode::SERVICE_UNAVAILABLE,
                                    "server_error",
                                    Some("rate_limit_store_unavailable"),
                                    "Distributed rate-limit store unavailable",
                                ));
                            }
                            return Flow::Continue;
                        }
                    }
                }

                if let Some(tpm) = tpm_limit {
                    match dist
                        .try_consume_quota(&tpm_key, estimated_tokens, tpm, window)
                        .await
                    {
                        Ok(out) if out.allowed => {
                            tpm_remaining = Some(out.remaining);
                        }
                        Ok(out) => {
                            if rpm_consumed {
                                let _ = dist.adjust_counter(&rpm_key, -1, window).await;
                            }
                            return Flow::Respond(Self::rate_limit_error(
                                endpoint,
                                "tpm_limit_exceeded",
                                &format!(
                                    "Token rate limit exceeded (estimated {estimated_tokens} tokens, limit {tpm} tokens per {}s)",
                                    window.as_secs()
                                ),
                                out.retry_after_secs,
                                rpm_limit,
                                rpm_remaining.map(|r| r.saturating_add(1)),
                                tpm_limit,
                                Some(out.remaining),
                            ));
                        }
                        Err(err) => {
                            warn!(
                                plugin = "ai-token-rate-limit",
                                backend = dist.backend_name(),
                                error = %err,
                                "distributed TPM check failed"
                            );
                            if dist.failure_policy() == FailurePolicy::FailClosed {
                                return Flow::Respond(endpoint_error_response(
                                    endpoint,
                                    StatusCode::SERVICE_UNAVAILABLE,
                                    "server_error",
                                    Some("rate_limit_store_unavailable"),
                                    "Distributed rate-limit store unavailable",
                                ));
                            }
                            return Flow::Continue;
                        }
                    }
                }

                ctx.insert_ext(AiTokenReservation {
                    subject,
                    window_id,
                    estimated_tokens,
                    rpm_limit,
                    rpm_remaining,
                    tpm_limit,
                    tpm_remaining,
                    rpm_dist_key: rpm_limit.map(|_| rpm_key),
                    tpm_dist_key: tpm_limit.map(|_| tpm_key),
                });
                Flow::Continue
            });
        }

        // Zero-allocation synchronous local fast path.
        match self.table.try_reserve(
            &subject,
            rpm_limit,
            tpm_limit,
            estimated_tokens,
            now_ms,
            self.window_ms,
            self.max_entries,
        ) {
            Ok(ok) => {
                ctx.insert_ext(AiTokenReservation {
                    subject,
                    window_id,
                    estimated_tokens,
                    rpm_limit,
                    rpm_remaining: ok.rpm_remaining,
                    tpm_limit,
                    tpm_remaining: ok.tpm_remaining,
                    rpm_dist_key: None,
                    tpm_dist_key: None,
                });
                HookResult::Ready(Flow::Continue)
            }
            Err(LocalReserveError::RpmExceeded {
                limit,
                retry_after_secs,
                tpm_limit,
                tpm_remaining,
            }) => HookResult::Ready(Flow::Respond(Self::rate_limit_error(
                endpoint,
                "rpm_limit_exceeded",
                &format!(
                    "Request rate limit exceeded ({limit} requests per {}s)",
                    self.window.as_secs()
                ),
                retry_after_secs,
                Some(limit),
                Some(0),
                tpm_limit,
                tpm_remaining,
            ))),
            Err(LocalReserveError::TpmExceeded {
                limit,
                remaining,
                retry_after_secs,
                rpm_limit,
                rpm_remaining,
            }) => HookResult::Ready(Flow::Respond(Self::rate_limit_error(
                endpoint,
                "tpm_limit_exceeded",
                &format!(
                    "Token rate limit exceeded (estimated {estimated_tokens} tokens, limit {limit} tokens per {}s)",
                    self.window.as_secs()
                ),
                retry_after_secs,
                rpm_limit,
                rpm_remaining,
                Some(limit),
                Some(remaining),
            ))),
        }
    }

    fn on_response_headers<'a>(
        &'a self,
        ctx: &'a mut RequestCtx,
        res: &'a mut ResponseHead,
    ) -> HookResult<'a, Flow> {
        if let Some(r) = ctx.get_ext::<AiTokenReservation>() {
            attach_ratelimit_headers(
                &mut res.headers,
                r.rpm_limit,
                r.rpm_remaining,
                r.tpm_limit,
                r.tpm_remaining,
            );
        }
        HookResult::Ready(Flow::Continue)
    }

    fn on_complete<'a>(
        &'a self,
        ctx: &'a RequestCtx,
        summary: &'a RequestSummary,
    ) -> HookResult<'a, ()> {
        if !self.reconcile_usage {
            return HookResult::Ready(());
        }
        let Some(res) = ctx.get_ext::<AiTokenReservation>() else {
            return HookResult::Ready(());
        };

        // If short-circuited before reaching any upstream (e.g., rejected by `ai-budget`),
        // refund the pre-flight reservation completely.
        let (req_delta, tok_delta) = if summary.attempts == 0 {
            (-1i64, -(res.estimated_tokens.min(i64::MAX as u64) as i64))
        } else if let Some(actual) = ctx
            .get_ext::<AiUsage>()
            .and_then(AiUsage::effective_total_tokens)
        {
            let est = res.estimated_tokens.min(i64::MAX as u64) as i64;
            let act = actual.min(i64::MAX as u64) as i64;
            (0i64, act.saturating_sub(est))
        } else {
            (0i64, 0i64)
        };

        if req_delta == 0 && tok_delta == 0 {
            return HookResult::Ready(());
        }

        if let Some(dist) = &self.distributed {
            let dist = Arc::clone(dist);
            let rpm_key = res.rpm_dist_key.clone();
            let tpm_key = res.tpm_dist_key.clone();
            let window = self.window;
            return HookResult::pending(async move {
                if req_delta != 0
                    && let Some(k) = rpm_key
                    && let Err(err) = dist.adjust_counter(&k, req_delta, window).await
                {
                    warn!(plugin = "ai-token-rate-limit", error = %err, "distributed RPM reconcile failed");
                }
                if tok_delta != 0
                    && let Some(k) = tpm_key
                    && let Err(err) = dist.adjust_counter(&k, tok_delta, window).await
                {
                    warn!(plugin = "ai-token-rate-limit", error = %err, "distributed TPM reconcile failed");
                }
            });
        }

        self.table
            .adjust(&res.subject, res.window_id, req_delta, tok_delta);
        HookResult::Ready(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn local_quota_window_reserves_reconciles_and_resets() {
        let table = QuotaWindowTable::new();
        // Window 0: reserve 60 tokens of 100 TPM, 1 of 2 RPM
        let r1 = table
            .try_reserve("key:alice", Some(2), Some(100), 60, 1_000, 60_000, 100)
            .unwrap();
        assert_eq!(r1.rpm_remaining, Some(1));
        assert_eq!(r1.tpm_remaining, Some(40));

        // Second request estimating 50 tokens exceeds 100 TPM -> rejected, counters unchanged!
        let err = table
            .try_reserve("key:alice", Some(2), Some(100), 50, 2_000, 60_000, 100)
            .unwrap_err();
        assert!(matches!(err, LocalReserveError::TpmExceeded { .. }));
        assert_eq!(table.current_usage("key:alice", 0), (1, 60));

        // Reconcile down by -30 tokens (actual usage was 30 instead of 60) -> now 50 fits!
        table.adjust("key:alice", 0, 0, -30);
        assert_eq!(table.current_usage("key:alice", 0), (1, 30));

        let r2 = table
            .try_reserve("key:alice", Some(2), Some(100), 50, 3_000, 60_000, 100)
            .unwrap();
        assert_eq!(r2.rpm_remaining, Some(0));
        assert_eq!(r2.tpm_remaining, Some(20));

        // Next window (t = 61s) resets cleanly
        let r3 = table
            .try_reserve("key:alice", Some(2), Some(100), 80, 61_000, 60_000, 100)
            .unwrap();
        assert_eq!(r3.rpm_remaining, Some(1));
        assert_eq!(r3.tpm_remaining, Some(20));
    }
}
