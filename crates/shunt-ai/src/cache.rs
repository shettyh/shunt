use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use shunt_plugin_sdk::{
    BufferedResponse, BuildContext, Bytes, Clock, DistributedStore, FailurePolicy, Flow,
    HeaderName, HeaderValue, HookMask, HookResult, HttpPlugin, PluginBuildError, PluginConfig,
    PluginFactory, RequestCtx, RequestHead, RequestSummary, ResponseHead, SpanHandle, StatusCode,
    StreamFlow, encode_hex_lower, header,
};
use tracing::warn;

use crate::types::{
    AiEndpointKind, AiKeyPolicy, AiRequestMeta, DetectedEndpoint, endpoint_error_response,
};
use crate::usage_tracker::AiMetrics;

const DEFAULT_TTL_SECS: u64 = 300;
const DEFAULT_MAX_ENTRIES: usize = 1024;
const DEFAULT_MAX_TOTAL_BYTES: usize = 32 * 1024 * 1024; // 32 MiB
const DEFAULT_MAX_ENTRY_BYTES: usize = 512 * 1024; // 512 KiB

fn default_ttl_secs() -> u64 {
    DEFAULT_TTL_SECS
}
fn default_max_entries() -> usize {
    DEFAULT_MAX_ENTRIES
}
fn default_max_total_bytes() -> usize {
    DEFAULT_MAX_TOTAL_BYTES
}
fn default_max_entry_bytes() -> usize {
    DEFAULT_MAX_ENTRY_BYTES
}
fn default_true() -> bool {
    true
}
fn default_endpoints() -> Vec<AiEndpointKind> {
    vec![
        AiEndpointKind::Embeddings,
        AiEndpointKind::ChatCompletions,
        AiEndpointKind::AnthropicMessages,
        AiEndpointKind::OpenAiResponses,
    ]
}

/// Tenant isolation scope for AI cache keys.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CacheScope {
    /// Isolate cached entries per authenticated virtual key (default; safe for multi-tenant setups).
    #[default]
    VirtualKey,
    /// Share cached entries across keys within the same team.
    Team,
    /// Share cached entries globally across all callers on this route.
    Global,
}

#[derive(Debug, Deserialize)]
#[serde(default)]
struct AiCacheConfig {
    /// Time-to-live for cached responses in seconds (default: `300`).
    #[serde(default = "default_ttl_secs")]
    ttl_secs: u64,
    /// Maximum number of entries in the in-memory LRU cache (default: `1024`).
    #[serde(default = "default_max_entries")]
    max_entries: usize,
    /// Maximum aggregate response payload bytes stored in memory (default: `32 MiB`).
    #[serde(default = "default_max_total_bytes")]
    max_total_bytes: usize,
    /// Maximum single response payload bytes eligible for caching (default: `512 KiB`).
    #[serde(default = "default_max_entry_bytes")]
    max_entry_bytes: usize,
    /// Tenant isolation scope (`"virtual_key"` default, `"team"`, `"global"`).
    #[serde(default)]
    scope: CacheScope,
    /// When `true` (default), conversational endpoints (`/v1/chat/completions`, `/v1/messages`,
    /// `/v1/responses`) are cached only when `temperature == 0` is explicitly set; `/v1/embeddings`
    /// is always treated as deterministic.
    #[serde(default = "default_true")]
    require_deterministic: bool,
    /// Endpoints eligible for caching (default: embeddings + chat/messages/responses).
    #[serde(default = "default_endpoints")]
    endpoints: Vec<AiEndpointKind>,
    /// Honor client `Cache-Control: no-store` / `no-cache` and upstream `Cache-Control: no-store` (default: `true`).
    #[serde(default = "default_true")]
    respect_cache_control: bool,
    /// Emit `x-shunt-cache: hit | miss | bypass` response header (default: `true`).
    #[serde(default = "default_true")]
    emit_headers: bool,
    /// Include the resolved primary `(provider, model)` target in the cache key so hot-reloading
    /// a model alias to a different backend automatically invalidates stale entries (default: `true`).
    #[serde(default = "default_true")]
    include_target_in_key: bool,
    /// Use the gateway's configured distributed store (Redis/Valkey) when available (default: `true`).
    #[serde(default = "default_true")]
    distributed: bool,
}

impl Default for AiCacheConfig {
    fn default() -> Self {
        Self {
            ttl_secs: default_ttl_secs(),
            max_entries: default_max_entries(),
            max_total_bytes: default_max_total_bytes(),
            max_entry_bytes: default_max_entry_bytes(),
            scope: CacheScope::VirtualKey,
            require_deterministic: true,
            endpoints: default_endpoints(),
            respect_cache_control: true,
            emit_headers: true,
            include_target_in_key: true,
            distributed: true,
        }
    }
}

/// Cache disposition attached to `RequestCtx::extensions` for downstream observability
/// (`ai-usage-tracker` and `otel-trace`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AiCacheStatus {
    Hit {
        provider: String,
        served_model: String,
    },
    Miss,
    Bypass,
}

impl AiCacheStatus {
    pub const fn as_str(&self) -> &'static str {
        match self {
            AiCacheStatus::Hit { .. } => "hit",
            AiCacheStatus::Miss => "miss",
            AiCacheStatus::Bypass => "bypass",
        }
    }
}

/// Marker placed in `RequestCtx::extensions` when a request missed cache and its response
/// should be captured and stored on completion.
#[derive(Debug, Clone)]
pub struct AiCachePending {
    pub cache_key: String,
    pub dist_key: String,
    pub endpoint: AiEndpointKind,
    pub requested_model: String,
    pub provider: String,
    pub served_model: String,
}

/// Optional translated client-facing non-streaming JSON body attached by `ai-provider-adapter`
/// when `AiCachePending` is active, ensuring translated Anthropic/Gemini/Bedrock responses are
/// cached in the client's ingress schema regardless of plugin ordering.
#[derive(Debug, Clone)]
pub struct AiTranslatedResponseBody(pub Bytes);

#[derive(Debug, Clone, Copy)]
struct RequestCacheDirectives {
    bypass_read: bool,
    bypass_store: bool,
}

#[derive(Debug, Clone)]
struct AiCacheCapture {
    content_type: String,
    buf: Vec<u8>,
    overflowed: bool,
}

#[derive(Debug, Clone)]
struct AiCacheCapturedBody {
    content_type: String,
    body: Bytes,
}

/// Wire-encoded cached response entry shared by in-memory and distributed backends.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CachedAiResponse {
    pub content_type: String,
    pub provider: String,
    pub served_model: String,
    pub body: Vec<u8>,
}

impl CachedAiResponse {
    fn encode(&self) -> Option<Bytes> {
        serde_json::to_vec(self).ok().map(Bytes::from)
    }

    fn decode(raw: &[u8]) -> Option<Self> {
        serde_json::from_slice(raw).ok()
    }
}

#[derive(Debug, Clone)]
struct LruEntry {
    value: CachedAiResponse,
    byte_len: usize,
    expires_at: Duration,
    generation: u64,
}

#[derive(Debug, Default)]
struct LruInner {
    map: HashMap<String, LruEntry>,
    order: VecDeque<(String, u64)>,
    total_bytes: usize,
    next_gen: u64,
}

/// Bounded, reload-persistent in-memory LRU + TTL cache stored in `StateStore`.
#[derive(Debug, Default)]
pub struct AiCacheTable {
    inner: Mutex<LruInner>,
}

impl AiCacheTable {
    pub fn new() -> Self {
        Self::default()
    }

    /// Looks up a non-expired entry and promotes it to most-recently-used.
    pub fn get(&self, key: &str, now: Duration) -> Option<CachedAiResponse> {
        let mut guard = self.inner.lock().expect("AiCacheTable lock poisoned");
        let expired = guard
            .map
            .get(key)
            .map(|e| now >= e.expires_at)
            .unwrap_or(false);
        if expired {
            if let Some(removed) = guard.map.remove(key) {
                guard.total_bytes = guard.total_bytes.saturating_sub(removed.byte_len);
            }
            return None;
        }
        guard.next_gen = guard.next_gen.wrapping_add(1);
        let next_gen = guard.next_gen;
        if let Some(entry) = guard.map.get_mut(key) {
            entry.generation = next_gen;
            let value = entry.value.clone();
            guard.order.push_back((key.to_owned(), next_gen));
            Self::compact_order_if_needed(&mut guard);
            return Some(value);
        }
        None
    }

    /// Inserts or updates a cached response, enforcing `max_entries` and `max_total_bytes`.
    pub fn insert(
        &self,
        key: String,
        value: CachedAiResponse,
        now: Duration,
        ttl: Duration,
        max_entries: usize,
        max_total_bytes: usize,
    ) {
        let byte_len = value.body.len();
        if max_entries == 0 || byte_len > max_total_bytes {
            return;
        }

        let mut guard = self.inner.lock().expect("AiCacheTable lock poisoned");
        if let Some(prev) = guard.map.remove(&key) {
            guard.total_bytes = guard.total_bytes.saturating_sub(prev.byte_len);
        }

        // First evict any expired head entries, then evict LRU entries until within budget.
        Self::evict_to_fit(
            &mut guard,
            now,
            max_entries.saturating_sub(1),
            max_total_bytes.saturating_sub(byte_len),
        );

        guard.next_gen = guard.next_gen.wrapping_add(1);
        let generation = guard.next_gen;
        guard.total_bytes = guard.total_bytes.saturating_add(byte_len);
        guard.map.insert(
            key.clone(),
            LruEntry {
                value,
                byte_len,
                expires_at: now.saturating_add(ttl),
                generation,
            },
        );
        guard.order.push_back((key, generation));
        Self::compact_order_if_needed(&mut guard);
    }

    pub fn len(&self) -> usize {
        self.inner
            .lock()
            .expect("AiCacheTable lock poisoned")
            .map
            .len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn total_bytes(&self) -> usize {
        self.inner
            .lock()
            .expect("AiCacheTable lock poisoned")
            .total_bytes
    }

    fn evict_to_fit(
        guard: &mut LruInner,
        now: Duration,
        target_entries: usize,
        target_bytes: usize,
    ) {
        while guard.map.len() > target_entries || guard.total_bytes > target_bytes {
            let Some((candidate_key, candidate_gen)) = guard.order.pop_front() else {
                // Defensive fallback if queue somehow desynced: clear map.
                guard.map.clear();
                guard.total_bytes = 0;
                break;
            };
            let should_remove = guard
                .map
                .get(&candidate_key)
                .map(|e| e.generation == candidate_gen || now >= e.expires_at)
                .unwrap_or(false);
            if should_remove && let Some(removed) = guard.map.remove(&candidate_key) {
                guard.total_bytes = guard.total_bytes.saturating_sub(removed.byte_len);
            }
        }
    }

    fn compact_order_if_needed(guard: &mut LruInner) {
        if guard.order.len() > guard.map.len().saturating_mul(4).max(64) {
            let mut live: Vec<(u64, String)> = guard
                .map
                .iter()
                .map(|(k, e)| (e.generation, k.clone()))
                .collect();
            live.sort_unstable_by_key(|(g, _)| *g);
            guard.order = live.into_iter().map(|(g, k)| (k, g)).collect();
        }
    }
}

/// Factory for the `ai-cache` plugin.
pub struct AiCacheFactory {
    metrics: Arc<AiMetrics>,
}

impl AiCacheFactory {
    pub fn new(metrics: Arc<AiMetrics>) -> Self {
        Self { metrics }
    }
}

impl PluginFactory for AiCacheFactory {
    fn name(&self) -> &str {
        "ai-cache"
    }

    fn build(
        &self,
        config: &PluginConfig,
        ctx: &BuildContext,
    ) -> Result<Arc<dyn HttpPlugin>, PluginBuildError> {
        let cfg: AiCacheConfig = config.deserialize(self.name())?;
        if cfg.ttl_secs == 0 {
            return Err(PluginBuildError::BuildFailed {
                plugin: self.name().to_owned(),
                message: "`ttl_secs` must be >= 1".to_owned(),
            });
        }
        if cfg.max_entries == 0 {
            return Err(PluginBuildError::BuildFailed {
                plugin: self.name().to_owned(),
                message: "`max_entries` must be >= 1".to_owned(),
            });
        }
        if cfg.max_total_bytes == 0 || cfg.max_entry_bytes == 0 {
            return Err(PluginBuildError::BuildFailed {
                plugin: self.name().to_owned(),
                message: "`max_total_bytes` and `max_entry_bytes` must be >= 1".to_owned(),
            });
        }
        if cfg.endpoints.is_empty() {
            return Err(PluginBuildError::BuildFailed {
                plugin: self.name().to_owned(),
                message: "`endpoints` cannot be empty".to_owned(),
            });
        }

        let state_handle = ctx.state_handle();
        let table = state_handle.get_or_init("ai_cache_table", AiCacheTable::new);
        let distributed = if cfg.distributed {
            ctx.distributed_store()
        } else {
            None
        };

        Ok(Arc::new(AiCachePlugin {
            scope_id: ctx.scope_id().to_owned(),
            ttl: Duration::from_secs(cfg.ttl_secs),
            max_entries: cfg.max_entries,
            max_total_bytes: cfg.max_total_bytes,
            max_entry_bytes: cfg.max_entry_bytes,
            scope: cfg.scope,
            require_deterministic: cfg.require_deterministic,
            endpoints: cfg.endpoints,
            respect_cache_control: cfg.respect_cache_control,
            emit_headers: cfg.emit_headers,
            include_target_in_key: cfg.include_target_in_key,
            clock: ctx.clock(),
            table,
            distributed,
            metrics: Arc::clone(&self.metrics),
        }))
    }
}

/// Exact-match AI response cache plugin (`ai-cache`).
///
/// Caches deterministic non-streaming AI responses (`POST /v1/embeddings` and
/// `temperature == 0` conversational calls on `/v1/chat/completions`, `/v1/messages`,
/// `/v1/responses`) using canonicalized JSON SHA-256 keys.
///
/// Place directly after `ai-model-router` and before `ai-token-rate-limit` / `ai-budget` so
/// cache hits short-circuit with zero upstream latency, zero token quota, and zero spend.
pub struct AiCachePlugin {
    scope_id: String,
    ttl: Duration,
    max_entries: usize,
    max_total_bytes: usize,
    max_entry_bytes: usize,
    scope: CacheScope,
    require_deterministic: bool,
    endpoints: Vec<AiEndpointKind>,
    respect_cache_control: bool,
    emit_headers: bool,
    include_target_in_key: bool,
    clock: Arc<dyn Clock>,
    table: Arc<AiCacheTable>,
    distributed: Option<Arc<dyn DistributedStore>>,
    metrics: Arc<AiMetrics>,
}

impl AiCachePlugin {
    fn resolve_tenant_scope(&self, policy: Option<&AiKeyPolicy>) -> String {
        match self.scope {
            CacheScope::Global => "global".to_owned(),
            CacheScope::Team => policy
                .and_then(|p| p.team.as_deref())
                .map(|t| format!("team:{t}"))
                .unwrap_or_else(|| "team:default".to_owned()),
            CacheScope::VirtualKey => policy
                .map(|p| format!("key:{}", p.key_id))
                .unwrap_or_else(|| "key:anonymous".to_owned()),
        }
    }

    fn build_hit_response(&self, entry: CachedAiResponse) -> BufferedResponse {
        let mut resp = BufferedResponse::new(StatusCode::OK, entry.body);
        if let Ok(ct) = HeaderValue::from_str(&entry.content_type) {
            resp.headers.insert(header::CONTENT_TYPE, ct);
        } else {
            resp.headers.insert(
                header::CONTENT_TYPE,
                HeaderValue::from_static("application/json"),
            );
        }
        if self.emit_headers {
            resp.headers.insert(
                HeaderName::from_static("x-shunt-cache"),
                HeaderValue::from_static("hit"),
            );
        }
        resp
    }
}

impl HttpPlugin for AiCachePlugin {
    fn name(&self) -> &str {
        "ai-cache"
    }

    fn hook_mask(&self) -> HookMask {
        HookMask::ON_REQUEST_HEADERS
            | HookMask::REQUEST_BODY_BUFFERED
            | HookMask::ON_RESPONSE_HEADERS
            | HookMask::RESPONSE_BODY_STREAM
            | HookMask::ON_COMPLETE
    }

    fn on_request_headers<'a>(
        &'a self,
        ctx: &'a mut RequestCtx,
        req: &'a mut RequestHead,
    ) -> HookResult<'a, Flow> {
        let mut bypass_read = false;
        let mut bypass_store = false;

        if self.respect_cache_control
            && let Some(cc) = req
                .headers
                .get(header::CACHE_CONTROL)
                .and_then(|v| v.to_str().ok())
        {
            for token in cc.split(',').map(|t| t.trim().to_ascii_lowercase()) {
                if token == "no-store" {
                    bypass_read = true;
                    bypass_store = true;
                } else if token == "no-cache" || token == "max-age=0" {
                    bypass_read = true;
                }
            }
        }

        if let Some(bypass) = req
            .headers
            .get("x-shunt-cache-bypass")
            .and_then(|v| v.to_str().ok())
            && (bypass.eq_ignore_ascii_case("true") || bypass.trim() == "1")
        {
            bypass_read = true;
            bypass_store = true;
        }

        if bypass_read || bypass_store {
            ctx.insert_ext(RequestCacheDirectives {
                bypass_read,
                bypass_store,
            });
        }

        HookResult::Ready(Flow::Continue)
    }

    fn on_request_body_buffered<'a>(
        &'a self,
        ctx: &'a mut RequestCtx,
        body: &'a mut Bytes,
    ) -> HookResult<'a, Flow> {
        if ctx
            .get_ext::<DetectedEndpoint>()
            .map(|d| d.0.is_models_discovery())
            .unwrap_or(false)
        {
            return HookResult::Ready(Flow::Continue);
        }

        let Some(meta) = ctx.get_ext::<AiRequestMeta>().cloned() else {
            return HookResult::Ready(Flow::Continue);
        };

        let directives =
            ctx.get_ext::<RequestCacheDirectives>()
                .copied()
                .unwrap_or(RequestCacheDirectives {
                    bypass_read: false,
                    bypass_store: false,
                });

        // Streaming responses, unconfigured endpoints, or `no-store` requests bypass caching.
        if meta.stream || !self.endpoints.contains(&meta.endpoint) || directives.bypass_store {
            self.metrics
                .record_cache("bypass", meta.endpoint.as_str(), &meta.requested_model);
            ctx.insert_ext(AiCacheStatus::Bypass);
            return HookResult::Ready(Flow::Continue);
        }

        let Ok(parsed_body) = serde_json::from_slice::<Value>(body) else {
            self.metrics
                .record_cache("bypass", meta.endpoint.as_str(), &meta.requested_model);
            ctx.insert_ext(AiCacheStatus::Bypass);
            return HookResult::Ready(Flow::Continue);
        };

        if self.require_deterministic
            && meta.endpoint.is_conversational()
            && !is_deterministic_request(&parsed_body)
        {
            self.metrics
                .record_cache("bypass", meta.endpoint.as_str(), &meta.requested_model);
            ctx.insert_ext(AiCacheStatus::Bypass);
            return HookResult::Ready(Flow::Continue);
        }

        let tenant_scope = self.resolve_tenant_scope(ctx.get_ext::<AiKeyPolicy>());
        let active_target = meta.active_target();
        let target_tuple = if self.include_target_in_key {
            active_target.map(|t| (t.provider.as_str(), t.model.as_str()))
        } else {
            None
        };

        let cache_key = compute_cache_key(
            &tenant_scope,
            meta.endpoint,
            &meta.requested_model,
            target_tuple,
            &parsed_body,
        );
        let dist_key = format!("ai_cache:{}:{cache_key}", self.scope_id);

        let provider = active_target
            .map(|t| t.provider.clone())
            .unwrap_or_else(|| "unknown".to_owned());
        let served_model = active_target
            .map(|t| t.model.clone())
            .unwrap_or_else(|| meta.requested_model.clone());

        let pending = AiCachePending {
            cache_key: cache_key.clone(),
            dist_key: dist_key.clone(),
            endpoint: meta.endpoint,
            requested_model: meta.requested_model.clone(),
            provider,
            served_model,
        };

        if directives.bypass_read {
            self.metrics
                .record_cache("miss", meta.endpoint.as_str(), &meta.requested_model);
            ctx.insert_ext(AiCacheStatus::Miss);
            ctx.insert_ext(pending);
            return HookResult::Ready(Flow::Continue);
        }

        if let Some(dist) = &self.distributed {
            let dist = Arc::clone(dist);
            let metrics = Arc::clone(&self.metrics);
            let endpoint = meta.endpoint;
            let requested_model = meta.requested_model.clone();
            let emit_headers = self.emit_headers;
            return HookResult::pending(async move {
                match dist.get_bytes(&dist_key).await {
                    Ok(Some(raw)) => {
                        if let Some(entry) = CachedAiResponse::decode(&raw) {
                            metrics.record_cache("hit", endpoint.as_str(), &requested_model);
                            ctx.insert_ext(AiCacheStatus::Hit {
                                provider: entry.provider.clone(),
                                served_model: entry.served_model.clone(),
                            });
                            let mut resp = BufferedResponse::new(StatusCode::OK, entry.body);
                            if let Ok(ct) = HeaderValue::from_str(&entry.content_type) {
                                resp.headers.insert(header::CONTENT_TYPE, ct);
                            } else {
                                resp.headers.insert(
                                    header::CONTENT_TYPE,
                                    HeaderValue::from_static("application/json"),
                                );
                            }
                            if emit_headers {
                                resp.headers.insert(
                                    HeaderName::from_static("x-shunt-cache"),
                                    HeaderValue::from_static("hit"),
                                );
                            }
                            return Flow::Respond(resp);
                        }
                        // Corrupt or incompatible payload: treat as miss and overwrite on completion.
                        metrics.record_cache("miss", endpoint.as_str(), &requested_model);
                        ctx.insert_ext(AiCacheStatus::Miss);
                        ctx.insert_ext(pending);
                        Flow::Continue
                    }
                    Ok(None) => {
                        metrics.record_cache("miss", endpoint.as_str(), &requested_model);
                        ctx.insert_ext(AiCacheStatus::Miss);
                        ctx.insert_ext(pending);
                        Flow::Continue
                    }
                    Err(err) => {
                        warn!(
                            plugin = "ai-cache",
                            backend = dist.backend_name(),
                            error = %err,
                            "distributed cache lookup failed"
                        );
                        match dist.failure_policy() {
                            FailurePolicy::FailOpen => {
                                metrics.record_cache("miss", endpoint.as_str(), &requested_model);
                                ctx.insert_ext(AiCacheStatus::Miss);
                                ctx.insert_ext(pending);
                                Flow::Continue
                            }
                            FailurePolicy::FailClosed => Flow::Respond(endpoint_error_response(
                                endpoint,
                                StatusCode::SERVICE_UNAVAILABLE,
                                "server_error",
                                Some("cache_store_unavailable"),
                                "Distributed AI cache backend is unavailable",
                            )),
                        }
                    }
                }
            });
        }

        // Synchronous zero-allocation in-memory fast path.
        let now = self.clock.now();
        if let Some(entry) = self.table.get(&cache_key, now) {
            self.metrics
                .record_cache("hit", meta.endpoint.as_str(), &meta.requested_model);
            ctx.insert_ext(AiCacheStatus::Hit {
                provider: entry.provider.clone(),
                served_model: entry.served_model.clone(),
            });
            return HookResult::Ready(Flow::Respond(self.build_hit_response(entry)));
        }

        self.metrics
            .record_cache("miss", meta.endpoint.as_str(), &meta.requested_model);
        ctx.insert_ext(AiCacheStatus::Miss);
        ctx.insert_ext(pending);
        HookResult::Ready(Flow::Continue)
    }

    fn on_response_headers<'a>(
        &'a self,
        ctx: &'a mut RequestCtx,
        res: &'a mut ResponseHead,
    ) -> HookResult<'a, Flow> {
        // Clear any stale capture buffer from an earlier failed attempt (e.g. after ai-failover).
        let _ = ctx.remove_ext::<AiCacheCapture>();
        let _ = ctx.remove_ext::<AiCacheCapturedBody>();
        let _ = ctx.remove_ext::<AiTranslatedResponseBody>();

        if self.emit_headers
            && let Some(status) = ctx.get_ext::<AiCacheStatus>()
            && let Ok(val) = HeaderValue::from_str(status.as_str())
        {
            res.headers
                .insert(HeaderName::from_static("x-shunt-cache"), val);
        }

        if ctx.get_ext::<AiCachePending>().is_none() {
            return HookResult::Ready(Flow::Continue);
        }

        if res.status != StatusCode::OK {
            return HookResult::Ready(Flow::Continue);
        }

        let content_type = res
            .headers
            .get(header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("application/json")
            .to_owned();
        if content_type
            .to_ascii_lowercase()
            .contains("text/event-stream")
        {
            return HookResult::Ready(Flow::Continue);
        }

        if self.respect_cache_control
            && let Some(cc) = res
                .headers
                .get(header::CACHE_CONTROL)
                .and_then(|v| v.to_str().ok())
            && cc
                .split(',')
                .any(|tok| tok.trim().eq_ignore_ascii_case("no-store"))
        {
            return HookResult::Ready(Flow::Continue);
        }

        ctx.insert_ext(AiCacheCapture {
            content_type,
            buf: Vec::new(),
            overflowed: false,
        });

        HookResult::Ready(Flow::Continue)
    }

    fn on_response_body_chunk<'a>(
        &'a self,
        ctx: &'a mut RequestCtx,
        chunk: &'a mut Bytes,
        end_of_stream: bool,
    ) -> HookResult<'a, StreamFlow> {
        let Some(mut capture) = ctx.remove_ext::<AiCacheCapture>() else {
            return HookResult::Ready(StreamFlow::Continue);
        };

        if !chunk.is_empty() && !capture.overflowed {
            if capture.buf.len().saturating_add(chunk.len()) <= self.max_entry_bytes {
                capture.buf.extend_from_slice(chunk);
            } else {
                capture.overflowed = true;
                capture.buf.clear();
            }
        }

        if end_of_stream {
            if !capture.overflowed && !capture.buf.is_empty() {
                ctx.insert_ext(AiCacheCapturedBody {
                    content_type: capture.content_type,
                    body: Bytes::from(capture.buf),
                });
            }
        } else {
            ctx.insert_ext(capture);
        }

        HookResult::Ready(StreamFlow::Continue)
    }

    fn on_complete<'a>(
        &'a self,
        ctx: &'a RequestCtx,
        summary: &'a RequestSummary,
    ) -> HookResult<'a, ()> {
        if let Some(span) = ctx.get_ext::<SpanHandle>()
            && let Some(status) = ctx.get_ext::<AiCacheStatus>()
        {
            span.set_str("shunt.ai.cache_status", status.as_str());
        }

        let Some(pending) = ctx.get_ext::<AiCachePending>() else {
            return HookResult::Ready(());
        };

        if summary.aborted_mid_stream
            || summary.error.is_some()
            || summary.status != Some(StatusCode::OK)
        {
            return HookResult::Ready(());
        }

        // Prefer the translated client-facing body from `ai-provider-adapter` when present
        // (covers Anthropic/Gemini/Bedrock non-streaming translation even when `ai-cache`
        // precedes `ai-provider-adapter`).
        let (content_type, body) =
            if let Some(translated) = ctx.get_ext::<AiTranslatedResponseBody>() {
                ("application/json".to_owned(), translated.0.clone())
            } else if let Some(captured) = ctx.get_ext::<AiCacheCapturedBody>() {
                (captured.content_type.clone(), captured.body.clone())
            } else {
                return HookResult::Ready(());
            };

        if body.is_empty() || body.len() > self.max_entry_bytes {
            return HookResult::Ready(());
        }

        // Resolve actual provider/model served (may differ from primary target after failover).
        let (provider, served_model) = ctx
            .get_ext::<AiRequestMeta>()
            .and_then(AiRequestMeta::active_target)
            .map(|t| (t.provider.clone(), t.model.clone()))
            .unwrap_or_else(|| (pending.provider.clone(), pending.served_model.clone()));

        let entry = CachedAiResponse {
            content_type,
            provider,
            served_model,
            body: body.to_vec(),
        };

        if let Some(dist) = &self.distributed {
            let Some(encoded) = entry.encode() else {
                return HookResult::Ready(());
            };
            let dist = Arc::clone(dist);
            let dist_key = pending.dist_key.clone();
            let ttl = self.ttl;
            return HookResult::pending(async move {
                if let Err(err) = dist.set_bytes(&dist_key, encoded, ttl).await {
                    warn!(
                        plugin = "ai-cache",
                        backend = dist.backend_name(),
                        error = %err,
                        "distributed cache write failed"
                    );
                }
            });
        }

        let now = self.clock.now();
        self.table.insert(
            pending.cache_key.clone(),
            entry,
            now,
            self.ttl,
            self.max_entries,
            self.max_total_bytes,
        );
        HookResult::Ready(())
    }
}

/// Returns `true` when the request JSON explicitly sets `temperature` to `0` (`0` or `0.0`).
pub fn is_deterministic_request(body: &Value) -> bool {
    body.get("temperature")
        .and_then(Value::as_f64)
        .map(|t| t == 0.0)
        .unwrap_or(false)
}

/// Computes a deterministic SHA-256 hex cache key invariant to JSON object key ordering.
pub fn compute_cache_key(
    tenant_scope: &str,
    endpoint: AiEndpointKind,
    requested_model: &str,
    target: Option<(&str, &str)>,
    body: &Value,
) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"shunt-ai-cache-v1\0");
    hasher.update(tenant_scope.as_bytes());
    hasher.update(b"\0");
    hasher.update(endpoint.as_str().as_bytes());
    hasher.update(b"\0");
    hasher.update(requested_model.as_bytes());
    hasher.update(b"\0");
    if let Some((provider, model)) = target {
        hasher.update(provider.as_bytes());
        hasher.update(b":");
        hasher.update(model.as_bytes());
    }
    hasher.update(b"\0");
    let canonical = canonical_json_bytes(body);
    hasher.update(&canonical);
    encode_hex_lower(&hasher.finalize())
}

/// Serializes `value` into deterministic canonical JSON bytes with recursively sorted object keys.
pub fn canonical_json_bytes(value: &Value) -> Vec<u8> {
    let mut buf = Vec::with_capacity(256);
    write_canonical_json(value, &mut buf);
    buf
}

fn write_canonical_json(value: &Value, out: &mut Vec<u8>) {
    match value {
        Value::Null => out.extend_from_slice(b"null"),
        Value::Bool(true) => out.extend_from_slice(b"true"),
        Value::Bool(false) => out.extend_from_slice(b"false"),
        Value::Number(n) => {
            // Normalize `0.0` / `-0.0` to `0` so `temperature: 0` and `temperature: 0.0` match.
            if let Some(f) = n.as_f64()
                && f == 0.0
            {
                out.push(b'0');
            } else {
                out.extend_from_slice(n.to_string().as_bytes());
            }
        }
        Value::String(s) => {
            if let Ok(encoded) = serde_json::to_vec(s) {
                out.extend_from_slice(&encoded);
            }
        }
        Value::Array(items) => {
            out.push(b'[');
            for (idx, item) in items.iter().enumerate() {
                if idx > 0 {
                    out.push(b',');
                }
                write_canonical_json(item, out);
            }
            out.push(b']');
        }
        Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort_unstable();
            out.push(b'{');
            for (idx, key) in keys.iter().enumerate() {
                if idx > 0 {
                    out.push(b',');
                }
                if let Ok(encoded_k) = serde_json::to_vec(key) {
                    out.extend_from_slice(&encoded_k);
                }
                out.push(b':');
                write_canonical_json(&map[*key], out);
            }
            out.push(b'}');
        }
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn canonical_cache_key_is_invariant_to_object_key_order_and_zero_float() {
        let a = json!({
            "model": "gpt-4o",
            "temperature": 0,
            "messages": [{"role": "user", "content": "hi"}]
        });
        let b = json!({
            "messages": [{"content": "hi", "role": "user"}],
            "temperature": 0.0,
            "model": "gpt-4o"
        });
        let ka = compute_cache_key(
            "key:k1",
            AiEndpointKind::ChatCompletions,
            "gpt-4o",
            Some(("openai", "gpt-4o")),
            &a,
        );
        let kb = compute_cache_key(
            "key:k1",
            AiEndpointKind::ChatCompletions,
            "gpt-4o",
            Some(("openai", "gpt-4o")),
            &b,
        );
        assert_eq!(ka, kb);

        // Tenant isolation changes key.
        let kc = compute_cache_key(
            "key:k2",
            AiEndpointKind::ChatCompletions,
            "gpt-4o",
            Some(("openai", "gpt-4o")),
            &a,
        );
        assert_ne!(ka, kc);
    }

    #[test]
    fn lru_table_evicts_least_recently_used_and_honors_ttl() {
        let table = AiCacheTable::new();
        let make = |body: &[u8]| CachedAiResponse {
            content_type: "application/json".to_owned(),
            provider: "openai".to_owned(),
            served_model: "gpt-4o".to_owned(),
            body: body.to_vec(),
        };

        let t0 = Duration::from_secs(10);
        let ttl = Duration::from_secs(60);
        table.insert("k1".into(), make(b"aaaa"), t0, ttl, 2, 1024);
        table.insert("k2".into(), make(b"bbbb"), t0, ttl, 2, 1024);
        // Touch k1 so k2 becomes least-recently-used.
        assert_eq!(table.get("k1", t0).unwrap().body, b"aaaa");
        table.insert("k3".into(), make(b"cccc"), t0, ttl, 2, 1024);

        assert!(table.get("k1", t0).is_some());
        assert!(table.get("k2", t0).is_none(), "k2 should be LRU-evicted");
        assert!(table.get("k3", t0).is_some());
        assert_eq!(table.len(), 2);
        assert_eq!(table.total_bytes(), 8);

        // Advance past TTL: both expire cleanly.
        let expired = Duration::from_secs(70);
        assert!(table.get("k1", expired).is_none());
        assert!(table.get("k3", expired).is_none());
        assert_eq!(table.total_bytes(), 0);
    }

    #[test]
    fn lru_table_enforces_byte_budget() {
        let table = AiCacheTable::new();
        let make = |n: usize| CachedAiResponse {
            content_type: "application/json".to_owned(),
            provider: "openai".to_owned(),
            served_model: "gpt-4o".to_owned(),
            body: vec![b'x'; n],
        };
        let t0 = Duration::from_secs(0);
        let ttl = Duration::from_secs(60);

        table.insert("a".into(), make(60), t0, ttl, 10, 100);
        table.insert("b".into(), make(60), t0, ttl, 10, 100);
        assert!(table.get("a", t0).is_none());
        assert!(table.get("b", t0).is_some());
        assert_eq!(table.total_bytes(), 60);

        // Oversized entry > max_total_bytes is ignored without evicting existing entries.
        table.insert("huge".into(), make(200), t0, ttl, 10, 100);
        assert!(table.get("b", t0).is_some());
        assert_eq!(table.total_bytes(), 60);
    }
}
