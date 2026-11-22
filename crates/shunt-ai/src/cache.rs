use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use shunt_plugin_sdk::{
    BoxFuture, BufferedResponse, BuildContext, Bytes, Clock, DistributedStore, FailurePolicy, Flow,
    HeaderMap, HeaderName, HeaderValue, HookMask, HookResult, HttpClient, HttpPlugin, HttpRequest,
    Method, PluginBuildError, PluginConfig, PluginFactory, RequestCtx, RequestHead, RequestSummary,
    ResponseHead, StatusCode, StreamFlow, Uri, encode_hex_lower, header,
};
use tokio::sync::watch;
use tracing::warn;

use crate::cloud_auth::base64_std_decode;
use crate::types::{
    AiEndpointKind, AiKeyPolicy, AiRequestMeta, DetectedEndpoint, endpoint_error_response,
    resolve_env_secret,
};
use crate::usage_tracker::AiMetrics;

const DEFAULT_TTL_SECS: u64 = 300;
const DEFAULT_MAX_ENTRIES: usize = 1024;
const DEFAULT_MAX_TOTAL_BYTES: usize = 32 * 1024 * 1024; // 32 MiB
const DEFAULT_MAX_ENTRY_BYTES: usize = 512 * 1024; // 512 KiB
const DEFAULT_SINGLEFLIGHT_TIMEOUT_MS: u64 = 30_000;
const DEFAULT_SEMANTIC_THRESHOLD: f32 = 0.95;
const DEFAULT_SEMANTIC_MAX_ENTRIES: usize = 512;
const DEFAULT_SEMANTIC_TIMEOUT_MS: u64 = 2_000;

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
fn default_singleflight_timeout_ms() -> u64 {
    DEFAULT_SINGLEFLIGHT_TIMEOUT_MS
}
fn default_semantic_threshold() -> f32 {
    DEFAULT_SEMANTIC_THRESHOLD
}
fn default_semantic_max_entries() -> usize {
    DEFAULT_SEMANTIC_MAX_ENTRIES
}
fn default_semantic_timeout_ms() -> u64 {
    DEFAULT_SEMANTIC_TIMEOUT_MS
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
        AiEndpointKind::Completions,
        AiEndpointKind::Rerank,
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

/// Mode for the opt-in semantic vector cache seam (`[semantic]`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SemanticCacheMode {
    /// Calls an OpenAI/Ollama-compatible `/v1/embeddings` HTTP endpoint via `HttpClient`
    /// and performs pure-Rust cosine similarity search over a bounded `SemanticCacheTable`.
    #[default]
    EmbeddingHttp,
    /// Delegates semantic lookup & store to an external HTTP vector sidecar/webhook via `HttpClient`.
    Webhook,
}

/// Declarative configuration for the opt-in semantic cache seam under `ai-cache`.
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct SemanticCacheConfig {
    /// Semantic backend mode (`"embedding_http"` default or `"webhook"`).
    pub mode: SemanticCacheMode,
    /// Target URL for embedding generation (`POST .../v1/embeddings`) or external vector webhook.
    pub endpoint: String,
    /// Embedding model name sent to the embedding endpoint (required for `embedding_http`).
    pub model: Option<String>,
    /// Optional Bearer API key (`"env:VAR"` supported; named `api_key` so `/snapshot` redacts it).
    pub api_key: Option<String>,
    /// Minimum cosine similarity in `(0.0, 1.0]` required for a semantic cache hit (default: `0.95`).
    #[serde(default = "default_semantic_threshold")]
    pub similarity_threshold: f32,
    /// Maximum number of vector entries stored in memory across all partitions (default: `512`).
    #[serde(default = "default_semantic_max_entries")]
    pub max_entries: usize,
    /// Outbound HTTP timeout in milliseconds for embedding/webhook calls (default: `2000`).
    #[serde(default = "default_semantic_timeout_ms")]
    pub timeout_ms: u64,
    /// Fail closed (`503`) if the semantic backend errors (default: `false`, fail-open to miss).
    #[serde(default)]
    pub fail_closed: bool,
}

impl Default for SemanticCacheConfig {
    fn default() -> Self {
        Self {
            mode: SemanticCacheMode::EmbeddingHttp,
            endpoint: String::new(),
            model: None,
            api_key: None,
            similarity_threshold: default_semantic_threshold(),
            max_entries: default_semantic_max_entries(),
            timeout_ms: default_semantic_timeout_ms(),
            fail_closed: false,
        }
    }
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
    /// When `true` (default), conversational/completions endpoints are cached only when
    /// `temperature == 0` is explicitly set; embeddings and rerank are always deterministic.
    #[serde(default = "default_true")]
    require_deterministic: bool,
    /// Enable lossless capture and instant replay of `stream: true` SSE responses (default: `false`).
    #[serde(default)]
    cache_streaming: bool,
    /// Coalesce concurrent identical cache misses via in-process singleflight (default: `false`).
    #[serde(default)]
    singleflight: bool,
    /// Maximum time (ms) a singleflight follower waits for the leader before falling through
    /// to upstream (default: `30000`).
    #[serde(default = "default_singleflight_timeout_ms")]
    singleflight_timeout_ms: u64,
    /// Optional semantic vector cache configuration (`embedding_http` or `webhook`).
    #[serde(default)]
    semantic: Option<SemanticCacheConfig>,
    /// Endpoints eligible for caching.
    #[serde(default = "default_endpoints")]
    endpoints: Vec<AiEndpointKind>,
    /// Honor client `Cache-Control: no-store` / `no-cache` and upstream `Cache-Control: no-store` (default: `true`).
    #[serde(default = "default_true")]
    respect_cache_control: bool,
    /// Emit `x-shunt-cache` response header (default: `true`).
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
            cache_streaming: false,
            singleflight: false,
            singleflight_timeout_ms: default_singleflight_timeout_ms(),
            semantic: None,
            endpoints: default_endpoints(),
            respect_cache_control: true,
            emit_headers: true,
            include_target_in_key: true,
            distributed: true,
        }
    }
}

/// Cache disposition attached to `RequestCtx::extensions` for downstream observability
/// (`ai-usage-tracker`, `ai-audit`, and `otel-trace`).
#[derive(Debug, Clone, PartialEq)]
pub enum AiCacheStatus {
    Hit {
        provider: String,
        served_model: String,
    },
    /// Served by coalescing onto an in-flight identical request via singleflight.
    Coalesced {
        provider: String,
        served_model: String,
    },
    /// Served via semantic cosine-similarity match.
    SemanticHit {
        provider: String,
        served_model: String,
        similarity: f32,
    },
    Miss,
    Bypass,
}

impl AiCacheStatus {
    pub const fn as_str(&self) -> &'static str {
        match self {
            AiCacheStatus::Hit { .. } => "hit",
            AiCacheStatus::Coalesced { .. } => "coalesced",
            AiCacheStatus::SemanticHit { .. } => "semantic_hit",
            AiCacheStatus::Miss => "miss",
            AiCacheStatus::Bypass => "bypass",
        }
    }

    /// Returns `(provider, served_model)` when this request was satisfied from cache
    /// (exact hit, singleflight coalesced hit, or semantic hit).
    pub fn hit_target(&self) -> Option<(&str, &str)> {
        match self {
            AiCacheStatus::Hit {
                provider,
                served_model,
            }
            | AiCacheStatus::Coalesced {
                provider,
                served_model,
            }
            | AiCacheStatus::SemanticHit {
                provider,
                served_model,
                ..
            } => Some((provider.as_str(), served_model.as_str())),
            AiCacheStatus::Miss | AiCacheStatus::Bypass => None,
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
    pub is_stream: bool,
    pub requested_model: String,
    pub provider: String,
    pub served_model: String,
    /// Optional semantic partition key + prompt text / precomputed embedding for storage on completion.
    pub semantic_partition: Option<String>,
    pub semantic_prompt: Option<String>,
    pub semantic_embedding: Option<Vec<f32>>,
}

/// Optional translated client-facing response body (JSON or wire SSE) attached by
/// `ai-provider-adapter` when `AiCachePending` is active, ensuring translated
/// Anthropic/Gemini/Bedrock responses are cached in the client's ingress schema regardless of
/// plugin ordering.
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

/// Wire-encoded cached response entry shared by in-memory, distributed, singleflight, and
/// semantic cache backends.
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

// ---------------------------------------------------------------------------
// In-Memory LRU + TTL Exact Cache Table
// ---------------------------------------------------------------------------

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

    /// Returns `(entries, total_bytes)` consistently under a single lock for Admin inspection.
    pub fn snapshot_stats(&self) -> (usize, usize) {
        let guard = self.inner.lock().expect("AiCacheTable lock poisoned");
        (guard.map.len(), guard.total_bytes)
    }

    fn evict_to_fit(
        guard: &mut LruInner,
        now: Duration,
        target_entries: usize,
        target_bytes: usize,
    ) {
        while guard.map.len() > target_entries || guard.total_bytes > target_bytes {
            let Some((candidate_key, candidate_gen)) = guard.order.pop_front() else {
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

// ---------------------------------------------------------------------------
// Singleflight Request Coalescing Table (Deadlock-Free RAII Leader Guard)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
enum SingleflightOutcome {
    Cached(CachedAiResponse),
    Failed,
}

/// Reload-persistent table coordinating concurrent identical cache misses so only one leader
/// hits the upstream provider while followers wait for the cached result.
#[derive(Debug, Default)]
pub struct AiSingleflightTable {
    inflight: Mutex<HashMap<String, watch::Sender<Option<SingleflightOutcome>>>>,
}

impl AiSingleflightTable {
    pub fn new() -> Self {
        Self::default()
    }

    fn acquire(self: &Arc<Self>, key: String) -> SingleflightAcquire {
        let mut guard = self
            .inflight
            .lock()
            .expect("AiSingleflightTable lock poisoned");
        if let Some(tx) = guard.get(&key) {
            return SingleflightAcquire::Follower(tx.subscribe());
        }
        let (tx, _rx) = watch::channel(None);
        guard.insert(key.clone(), tx.clone());
        SingleflightAcquire::Leader(SingleflightLeaderSlot(Arc::new(SingleflightLeaderInner {
            table: Arc::clone(self),
            key,
            tx: Mutex::new(Some(tx)),
            finished: AtomicBool::new(false),
        })))
    }

    pub fn inflight_count(&self) -> usize {
        self.inflight
            .lock()
            .expect("AiSingleflightTable lock poisoned")
            .len()
    }
}

enum SingleflightAcquire {
    Leader(SingleflightLeaderSlot),
    Follower(watch::Receiver<Option<SingleflightOutcome>>),
}

struct SingleflightLeaderInner {
    table: Arc<AiSingleflightTable>,
    key: String,
    tx: Mutex<Option<watch::Sender<Option<SingleflightOutcome>>>>,
    finished: AtomicBool,
}

impl SingleflightLeaderInner {
    fn publish(&self, outcome: SingleflightOutcome) {
        if self.finished.swap(true, Ordering::AcqRel) {
            return;
        }
        {
            let mut map = self
                .table
                .inflight
                .lock()
                .expect("AiSingleflightTable lock poisoned");
            map.remove(&self.key);
        }
        if let Some(tx) = self
            .tx
            .lock()
            .expect("SingleflightLeader tx poisoned")
            .take()
        {
            let _ = tx.send(Some(outcome));
        }
    }
}

impl Drop for SingleflightLeaderInner {
    fn drop(&mut self) {
        // Always release followers with `Failed` if the leader never published a cached entry
        // (e.g., upstream 5xx, guardrail block, stream abort, client disconnect, or panic).
        self.publish(SingleflightOutcome::Failed);
    }
}

/// Extension wrapper placed into `RequestCtx::extensions` for the singleflight leader request.
#[derive(Clone)]
struct SingleflightLeaderSlot(Arc<SingleflightLeaderInner>);

impl SingleflightLeaderSlot {
    fn complete_cached(&self, entry: CachedAiResponse) {
        self.0.publish(SingleflightOutcome::Cached(entry));
    }

    fn complete_failed(&self) {
        self.0.publish(SingleflightOutcome::Failed);
    }
}

// ---------------------------------------------------------------------------
// Semantic Vector Cache Seam (`SemanticCacheBackend` + `SemanticCacheTable`)
// ---------------------------------------------------------------------------

/// Result of a semantic cache lookup hit.
#[derive(Debug, Clone)]
pub struct SemanticCacheHit {
    pub response: CachedAiResponse,
    pub similarity: f32,
}

/// Request context passed into [`SemanticCacheBackend::lookup`] and [`SemanticCacheBackend::store`].
#[derive(Debug, Clone)]
pub struct SemanticLookupQuery {
    pub partition: String,
    pub prompt_text: String,
    pub similarity_threshold: f32,
}

/// Outcome of a semantic lookup: either a hit or an optional precomputed embedding vector
/// to reuse on store without paying for a second embedding call.
#[derive(Debug, Clone)]
pub enum SemanticLookupResult {
    Hit(SemanticCacheHit),
    Miss { embedding: Option<Vec<f32>> },
}

/// Extensible async seam for plugging custom semantic vector caches (e.g., Qdrant, pgvector,
/// Redis VSS, or custom embedding stores) into `ai-cache` without bloating `shunt-core`.
pub trait SemanticCacheBackend: Send + Sync + 'static {
    fn lookup<'a>(
        &'a self,
        query: SemanticLookupQuery,
        now: Duration,
    ) -> BoxFuture<'a, Result<SemanticLookupResult, String>>;

    fn store<'a>(
        &'a self,
        partition: String,
        prompt_text: String,
        embedding: Option<Vec<f32>>,
        response: CachedAiResponse,
        now: Duration,
        ttl: Duration,
    ) -> BoxFuture<'a, Result<(), String>>;
}

/// Pure-Rust cosine similarity in `[-1.0, 1.0]`. Returns `0.0` for mismatched lengths, empty
/// slices, zero-norm vectors, or non-finite inputs.
pub fn cosine_similarity(a: &[f32], b: &[f32]) -> f32 {
    if a.is_empty() || a.len() != b.len() {
        return 0.0;
    }
    let mut dot = 0.0f64;
    let mut norm_a = 0.0f64;
    let mut norm_b = 0.0f64;
    for (&x, &y) in a.iter().zip(b.iter()) {
        if !x.is_finite() || !y.is_finite() {
            return 0.0;
        }
        let xf = x as f64;
        let yf = y as f64;
        dot += xf * yf;
        norm_a += xf * xf;
        norm_b += yf * yf;
    }
    let denom = norm_a.sqrt() * norm_b.sqrt();
    if denom <= f64::EPSILON || !denom.is_finite() {
        return 0.0;
    }
    (dot / denom).clamp(-1.0, 1.0) as f32
}

/// Read-only stats snapshot of [`SemanticCacheTable`] for Admin Inspector `/api/status`.
#[derive(Debug, Clone, Serialize)]
pub struct SemanticCacheSnapshot {
    pub entries: usize,
    pub partitions: usize,
}

#[derive(Debug, Clone)]
struct VectorEntry {
    id: u64,
    partition: String,
    embedding: Vec<f32>,
    response: CachedAiResponse,
    expires_at: Duration,
}

#[derive(Debug, Default)]
struct SemanticTableInner {
    entries: VecDeque<VectorEntry>,
    next_id: u64,
}

/// Bounded, reload-persistent in-memory vector cache table stored in `StateStore`.
#[derive(Debug, Default)]
pub struct SemanticCacheTable {
    inner: RwLock<SemanticTableInner>,
}

impl SemanticCacheTable {
    pub fn new() -> Self {
        Self::default()
    }

    /// Finds the highest-similarity non-expired entry in `partition` meeting `threshold`.
    pub fn search(
        &self,
        partition: &str,
        query_vec: &[f32],
        threshold: f32,
        now: Duration,
    ) -> Option<SemanticCacheHit> {
        let guard = self.inner.read().expect("SemanticCacheTable poisoned");
        let mut best: Option<(f32, &CachedAiResponse)> = None;
        for entry in &guard.entries {
            if entry.partition != partition || now >= entry.expires_at {
                continue;
            }
            let sim = cosine_similarity(query_vec, &entry.embedding);
            if sim >= threshold && best.is_none_or(|(b, _)| sim > b) {
                best = Some((sim, &entry.response));
            }
        }
        best.map(|(similarity, resp)| SemanticCacheHit {
            response: resp.clone(),
            similarity,
        })
    }

    /// Inserts a vector entry, pruning expired entries and enforcing `max_entries`.
    pub fn insert(
        &self,
        partition: String,
        embedding: Vec<f32>,
        response: CachedAiResponse,
        now: Duration,
        ttl: Duration,
        max_entries: usize,
    ) {
        if max_entries == 0 || embedding.is_empty() {
            return;
        }
        let mut guard = self.inner.write().expect("SemanticCacheTable poisoned");
        guard.entries.retain(|e| now < e.expires_at);
        while guard.entries.len() >= max_entries {
            guard.entries.pop_front();
        }
        guard.next_id = guard.next_id.wrapping_add(1);
        let id = guard.next_id;
        guard.entries.push_back(VectorEntry {
            id,
            partition,
            embedding,
            response,
            expires_at: now.saturating_add(ttl),
        });
    }

    pub fn snapshot(&self) -> SemanticCacheSnapshot {
        let guard = self.inner.read().expect("SemanticCacheTable poisoned");
        let mut parts = std::collections::HashSet::new();
        for e in &guard.entries {
            parts.insert(e.partition.as_str());
        }
        let _ = guard.entries.front().map(|e| e.id);
        SemanticCacheSnapshot {
            entries: guard.entries.len(),
            partitions: parts.len(),
        }
    }
}

/// Built-in HTTP embedding + in-memory cosine-similarity [`SemanticCacheBackend`].
struct EmbeddingHttpSemanticBackend {
    endpoint: Uri,
    model: String,
    auth_header: Option<HeaderValue>,
    timeout: Duration,
    max_entries: usize,
    http_client: Arc<dyn HttpClient>,
    table: Arc<SemanticCacheTable>,
}

impl EmbeddingHttpSemanticBackend {
    async fn fetch_embedding(&self, prompt: &str) -> Result<Vec<f32>, String> {
        let body = serde_json::to_vec(&json!({
            "model": self.model,
            "input": prompt,
        }))
        .map_err(|e| format!("failed to encode embedding request: {e}"))?;

        let mut headers = HeaderMap::new();
        headers.insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/json"),
        );
        if let Some(auth) = &self.auth_header {
            headers.insert(header::AUTHORIZATION, auth.clone());
        }

        let resp = self
            .http_client
            .send(HttpRequest {
                method: Method::POST,
                uri: self.endpoint.clone(),
                headers,
                body: Bytes::from(body),
                timeout: Some(self.timeout),
                max_response_bytes: Some(2 * 1024 * 1024),
            })
            .await
            .map_err(|e| format!("embedding HTTP request failed: {e}"))?;

        if !resp.status.is_success() {
            return Err(format!("embedding endpoint returned HTTP {}", resp.status));
        }

        parse_embedding_vector(&resp.body)
    }
}

impl SemanticCacheBackend for EmbeddingHttpSemanticBackend {
    fn lookup<'a>(
        &'a self,
        query: SemanticLookupQuery,
        now: Duration,
    ) -> BoxFuture<'a, Result<SemanticLookupResult, String>> {
        Box::pin(async move {
            let embedding = self.fetch_embedding(&query.prompt_text).await?;
            if let Some(hit) = self.table.search(
                &query.partition,
                &embedding,
                query.similarity_threshold,
                now,
            ) {
                return Ok(SemanticLookupResult::Hit(hit));
            }
            Ok(SemanticLookupResult::Miss {
                embedding: Some(embedding),
            })
        })
    }

    fn store<'a>(
        &'a self,
        partition: String,
        _prompt_text: String,
        embedding: Option<Vec<f32>>,
        response: CachedAiResponse,
        now: Duration,
        ttl: Duration,
    ) -> BoxFuture<'a, Result<(), String>> {
        Box::pin(async move {
            if let Some(vec) = embedding {
                self.table
                    .insert(partition, vec, response, now, ttl, self.max_entries);
            }
            Ok(())
        })
    }
}

/// Built-in external HTTP vector webhook [`SemanticCacheBackend`].
struct WebhookSemanticBackend {
    endpoint: Uri,
    auth_header: Option<HeaderValue>,
    timeout: Duration,
    http_client: Arc<dyn HttpClient>,
}

impl SemanticCacheBackend for WebhookSemanticBackend {
    fn lookup<'a>(
        &'a self,
        query: SemanticLookupQuery,
        _now: Duration,
    ) -> BoxFuture<'a, Result<SemanticLookupResult, String>> {
        Box::pin(async move {
            let body = serde_json::to_vec(&json!({
                "action": "lookup",
                "partition": query.partition,
                "prompt": query.prompt_text,
                "threshold": query.similarity_threshold,
            }))
            .map_err(|e| format!("failed to encode semantic webhook lookup: {e}"))?;

            let mut headers = HeaderMap::new();
            headers.insert(
                header::CONTENT_TYPE,
                HeaderValue::from_static("application/json"),
            );
            if let Some(auth) = &self.auth_header {
                headers.insert(header::AUTHORIZATION, auth.clone());
            }

            let resp = self
                .http_client
                .send(HttpRequest {
                    method: Method::POST,
                    uri: self.endpoint.clone(),
                    headers,
                    body: Bytes::from(body),
                    timeout: Some(self.timeout),
                    max_response_bytes: Some(2 * 1024 * 1024),
                })
                .await
                .map_err(|e| format!("semantic webhook lookup failed: {e}"))?;

            if !resp.status.is_success() {
                return Err(format!("semantic webhook returned HTTP {}", resp.status));
            }

            let val: Value = serde_json::from_slice(&resp.body)
                .map_err(|e| format!("invalid semantic webhook JSON: {e}"))?;
            if val.get("hit").and_then(Value::as_bool) != Some(true) {
                return Ok(SemanticLookupResult::Miss { embedding: None });
            }
            let similarity = val.get("similarity").and_then(Value::as_f64).unwrap_or(1.0) as f32;
            let Some(resp_obj) = val.get("response").and_then(Value::as_object) else {
                return Ok(SemanticLookupResult::Miss { embedding: None });
            };
            let content_type = resp_obj
                .get("content_type")
                .and_then(Value::as_str)
                .unwrap_or("application/json")
                .to_owned();
            let provider = resp_obj
                .get("provider")
                .and_then(Value::as_str)
                .unwrap_or("semantic")
                .to_owned();
            let served_model = resp_obj
                .get("served_model")
                .and_then(Value::as_str)
                .unwrap_or("unknown")
                .to_owned();
            let body_bytes = if let Some(b64) = resp_obj.get("body_base64").and_then(Value::as_str)
            {
                base64_std_decode(b64)
                    .map_err(|e| format!("invalid body_base64 from semantic webhook: {e}"))?
            } else if let Some(raw) = resp_obj.get("body").and_then(Value::as_str) {
                raw.as_bytes().to_vec()
            } else {
                return Ok(SemanticLookupResult::Miss { embedding: None });
            };

            Ok(SemanticLookupResult::Hit(SemanticCacheHit {
                response: CachedAiResponse {
                    content_type,
                    provider,
                    served_model,
                    body: body_bytes,
                },
                similarity,
            }))
        })
    }

    fn store<'a>(
        &'a self,
        partition: String,
        prompt_text: String,
        _embedding: Option<Vec<f32>>,
        response: CachedAiResponse,
        _now: Duration,
        ttl: Duration,
    ) -> BoxFuture<'a, Result<(), String>> {
        Box::pin(async move {
            let body = serde_json::to_vec(&json!({
                "action": "store",
                "partition": partition,
                "prompt": prompt_text,
                "ttl_secs": ttl.as_secs(),
                "response": {
                    "content_type": response.content_type,
                    "provider": response.provider,
                    "served_model": response.served_model,
                    "body_base64": base64_std_encode(&response.body),
                }
            }))
            .map_err(|e| format!("failed to encode semantic webhook store: {e}"))?;

            let mut headers = HeaderMap::new();
            headers.insert(
                header::CONTENT_TYPE,
                HeaderValue::from_static("application/json"),
            );
            if let Some(auth) = &self.auth_header {
                headers.insert(header::AUTHORIZATION, auth.clone());
            }

            let resp = self
                .http_client
                .send(HttpRequest {
                    method: Method::POST,
                    uri: self.endpoint.clone(),
                    headers,
                    body: Bytes::from(body),
                    timeout: Some(self.timeout),
                    max_response_bytes: Some(2 * 1024 * 1024),
                })
                .await
                .map_err(|e| format!("semantic webhook store failed: {e}"))?;

            if !resp.status.is_success() {
                return Err(format!(
                    "semantic webhook store returned HTTP {}",
                    resp.status
                ));
            }
            Ok(())
        })
    }
}

/// Parses an OpenAI (`data[0].embedding`) or Ollama (`embedding` / `embeddings[0]`) vector JSON.
pub fn parse_embedding_vector(raw: &[u8]) -> Result<Vec<f32>, String> {
    let val: Value =
        serde_json::from_slice(raw).map_err(|e| format!("invalid embedding JSON: {e}"))?;
    let arr = val
        .get("data")
        .and_then(Value::as_array)
        .and_then(|d| d.first())
        .and_then(|item| item.get("embedding"))
        .and_then(Value::as_array)
        .or_else(|| val.get("embedding").and_then(Value::as_array))
        .or_else(|| {
            val.get("embeddings")
                .and_then(Value::as_array)
                .and_then(|a| a.first())
                .and_then(Value::as_array)
        })
        .ok_or_else(|| "embedding response missing vector array".to_owned())?;

    let mut out = Vec::with_capacity(arr.len());
    for elem in arr {
        let Some(f) = elem.as_f64() else {
            return Err("embedding vector contains non-numeric element".to_owned());
        };
        if !f.is_finite() {
            return Err("embedding vector contains non-finite element".to_owned());
        }
        out.push(f as f32);
    }
    if out.is_empty() {
        return Err("embedding vector is empty".to_owned());
    }
    Ok(out)
}

/// Extracts canonical prompt text from an AI JSON request for semantic vector caching.
pub fn extract_semantic_prompt_text(endpoint: AiEndpointKind, body: &Value) -> Option<String> {
    let mut parts: Vec<String> = Vec::new();
    match endpoint {
        AiEndpointKind::ChatCompletions | AiEndpointKind::AnthropicMessages => {
            if let Some(sys) = body.get("system") {
                push_text_value(sys, &mut parts);
            }
            if let Some(msgs) = body.get("messages").and_then(Value::as_array) {
                for msg in msgs {
                    let role = msg.get("role").and_then(Value::as_str).unwrap_or("user");
                    let mut msg_parts = Vec::new();
                    if let Some(content) = msg.get("content") {
                        push_text_value(content, &mut msg_parts);
                    }
                    if !msg_parts.is_empty() {
                        parts.push(format!("{role}: {}", msg_parts.join(" ")));
                    }
                }
            }
        }
        AiEndpointKind::OpenAiResponses => {
            if let Some(inst) = body.get("instructions").and_then(Value::as_str) {
                parts.push(inst.to_owned());
            }
            if let Some(input) = body.get("input") {
                push_text_value(input, &mut parts);
            }
        }
        AiEndpointKind::Completions => {
            if let Some(prompt) = body.get("prompt") {
                push_text_value(prompt, &mut parts);
            }
        }
        AiEndpointKind::Rerank => {
            if let Some(q) = body.get("query").and_then(Value::as_str) {
                parts.push(q.to_owned());
            }
        }
        _ => return None,
    }
    let joined = parts.join("\n").trim().to_owned();
    if joined.is_empty() {
        None
    } else {
        Some(joined)
    }
}

fn push_text_value(val: &Value, out: &mut Vec<String>) {
    match val {
        Value::String(s) if !s.trim().is_empty() => out.push(s.clone()),
        Value::Array(arr) => {
            for item in arr {
                if let Some(s) = item.as_str() {
                    if !s.trim().is_empty() {
                        out.push(s.to_owned());
                    }
                } else if let Some(t) = item.get("text").and_then(Value::as_str) {
                    if !t.trim().is_empty() {
                        out.push(t.to_owned());
                    }
                } else if let Some(c) = item.get("content") {
                    push_text_value(c, out);
                }
            }
        }
        _ => {}
    }
}

fn base64_std_encode(input: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
    for chunk in input.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = if chunk.len() > 1 { chunk[1] as u32 } else { 0 };
        let b2 = if chunk.len() > 2 { chunk[2] as u32 } else { 0 };
        let n = (b0 << 16) | (b1 << 8) | b2;
        out.push(TABLE[((n >> 18) & 0x3f) as usize] as char);
        out.push(TABLE[((n >> 12) & 0x3f) as usize] as char);
        if chunk.len() > 1 {
            out.push(TABLE[((n >> 6) & 0x3f) as usize] as char);
        } else {
            out.push('=');
        }
        if chunk.len() > 2 {
            out.push(TABLE[(n & 0x3f) as usize] as char);
        } else {
            out.push('=');
        }
    }
    out
}

// ---------------------------------------------------------------------------
// Plugin Factory & Implementation (`ai-cache`)
// ---------------------------------------------------------------------------

/// Factory for the `ai-cache` plugin.
pub struct AiCacheFactory {
    metrics: Arc<AiMetrics>,
    custom_semantic: Option<Arc<dyn SemanticCacheBackend>>,
}

impl AiCacheFactory {
    pub fn new(metrics: Arc<AiMetrics>) -> Self {
        Self {
            metrics,
            custom_semantic: None,
        }
    }

    /// Injects a custom in-process [`SemanticCacheBackend`] (useful for embedders and tests).
    pub fn with_semantic_backend(mut self, backend: Arc<dyn SemanticCacheBackend>) -> Self {
        self.custom_semantic = Some(backend);
        self
    }
}

struct CompiledSemantic {
    backend: Arc<dyn SemanticCacheBackend>,
    threshold: f32,
    fail_closed: bool,
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
        let singleflight_table = if cfg.singleflight {
            Some(state_handle.get_or_init("ai_singleflight_table", AiSingleflightTable::new))
        } else {
            None
        };
        let distributed = if cfg.distributed {
            ctx.distributed_store()
        } else {
            None
        };

        let semantic = if let Some(sem_cfg) = cfg.semantic {
            if !sem_cfg.similarity_threshold.is_finite()
                || sem_cfg.similarity_threshold <= 0.0
                || sem_cfg.similarity_threshold > 1.0
            {
                return Err(PluginBuildError::BuildFailed {
                    plugin: self.name().to_owned(),
                    message: "`semantic.similarity_threshold` must be in (0.0, 1.0]".to_owned(),
                });
            }
            if let Some(custom) = &self.custom_semantic {
                Some(Arc::new(CompiledSemantic {
                    backend: Arc::clone(custom),
                    threshold: sem_cfg.similarity_threshold,
                    fail_closed: sem_cfg.fail_closed,
                }))
            } else {
                if sem_cfg.endpoint.trim().is_empty() {
                    return Err(PluginBuildError::BuildFailed {
                        plugin: self.name().to_owned(),
                        message: "`semantic.endpoint` cannot be empty".to_owned(),
                    });
                }
                let endpoint_uri: Uri =
                    sem_cfg
                        .endpoint
                        .parse()
                        .map_err(|e| PluginBuildError::BuildFailed {
                            plugin: self.name().to_owned(),
                            message: format!(
                                "invalid `semantic.endpoint` `{}`: {e}",
                                sem_cfg.endpoint
                            ),
                        })?;
                let http_client =
                    ctx.http_client()
                        .ok_or_else(|| PluginBuildError::BuildFailed {
                            plugin: self.name().to_owned(),
                            message:
                                "`semantic` caching requires a runtime HttpClient in BuildContext"
                                    .to_owned(),
                        })?;
                let auth_header = match sem_cfg.api_key {
                    Some(raw) => {
                        let secret = resolve_env_secret(&raw).map_err(|msg| {
                            PluginBuildError::BuildFailed {
                                plugin: self.name().to_owned(),
                                message: format!("semantic.api_key: {msg}"),
                            }
                        })?;
                        let hv =
                            HeaderValue::from_str(&format!("Bearer {secret}")).map_err(|e| {
                                PluginBuildError::BuildFailed {
                                    plugin: self.name().to_owned(),
                                    message: format!("invalid semantic.api_key header value: {e}"),
                                }
                            })?;
                        Some(hv)
                    }
                    None => None,
                };
                let timeout = Duration::from_millis(sem_cfg.timeout_ms.max(50));
                let backend: Arc<dyn SemanticCacheBackend> = match sem_cfg.mode {
                    SemanticCacheMode::EmbeddingHttp => {
                        let model = sem_cfg
                            .model
                            .as_deref()
                            .map(str::trim)
                            .filter(|s| !s.is_empty())
                            .ok_or_else(|| PluginBuildError::BuildFailed {
                                plugin: self.name().to_owned(),
                                message:
                                    "`semantic.model` is required when `semantic.mode = \"embedding_http\"`"
                                        .to_owned(),
                            })?
                            .to_owned();
                        let sem_table = state_handle
                            .get_or_init("ai_semantic_cache_table", SemanticCacheTable::new);
                        Arc::new(EmbeddingHttpSemanticBackend {
                            endpoint: endpoint_uri,
                            model,
                            auth_header,
                            timeout,
                            max_entries: sem_cfg.max_entries.max(1),
                            http_client,
                            table: sem_table,
                        })
                    }
                    SemanticCacheMode::Webhook => Arc::new(WebhookSemanticBackend {
                        endpoint: endpoint_uri,
                        auth_header,
                        timeout,
                        http_client,
                    }),
                };
                Some(Arc::new(CompiledSemantic {
                    backend,
                    threshold: sem_cfg.similarity_threshold,
                    fail_closed: sem_cfg.fail_closed,
                }))
            }
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
            cache_streaming: cfg.cache_streaming,
            singleflight_timeout: Duration::from_millis(cfg.singleflight_timeout_ms.max(50)),
            endpoints: cfg.endpoints,
            respect_cache_control: cfg.respect_cache_control,
            emit_headers: cfg.emit_headers,
            include_target_in_key: cfg.include_target_in_key,
            clock: ctx.clock(),
            table,
            singleflight: singleflight_table,
            distributed,
            semantic,
            metrics: Arc::clone(&self.metrics),
        }))
    }
}

/// Exact-match, streaming SSE, singleflight-coalescing, and opt-in semantic AI response cache
/// plugin (`ai-cache`).
pub struct AiCachePlugin {
    scope_id: String,
    ttl: Duration,
    max_entries: usize,
    max_total_bytes: usize,
    max_entry_bytes: usize,
    scope: CacheScope,
    require_deterministic: bool,
    cache_streaming: bool,
    singleflight_timeout: Duration,
    endpoints: Vec<AiEndpointKind>,
    respect_cache_control: bool,
    emit_headers: bool,
    include_target_in_key: bool,
    clock: Arc<dyn Clock>,
    table: Arc<AiCacheTable>,
    singleflight: Option<Arc<AiSingleflightTable>>,
    distributed: Option<Arc<dyn DistributedStore>>,
    semantic: Option<Arc<CompiledSemantic>>,
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

    fn build_hit_response(
        emit_headers: bool,
        cache_header_val: &'static str,
        similarity: Option<f32>,
        entry: CachedAiResponse,
    ) -> BufferedResponse {
        let is_sse = entry
            .content_type
            .to_ascii_lowercase()
            .contains("text/event-stream");
        let mut resp = BufferedResponse::new(StatusCode::OK, entry.body);
        if let Ok(ct) = HeaderValue::from_str(&entry.content_type) {
            resp.headers.insert(header::CONTENT_TYPE, ct);
        } else {
            resp.headers.insert(
                header::CONTENT_TYPE,
                HeaderValue::from_static("application/json"),
            );
        }
        if is_sse {
            resp.headers
                .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-cache"));
        }
        if emit_headers {
            resp.headers.insert(
                HeaderName::from_static("x-shunt-cache"),
                HeaderValue::from_static(cache_header_val),
            );
            if let Some(sim) = similarity
                && let Ok(hv) = HeaderValue::from_str(&format!("{sim:.4}"))
            {
                resp.headers
                    .insert(HeaderName::from_static("x-shunt-cache-similarity"), hv);
            }
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

        // Unconfigured endpoints, `no-store`, or streaming when `cache_streaming = false` bypass.
        let streaming_disallowed =
            meta.stream && (!self.cache_streaming || !meta.endpoint.supports_sse_streaming());
        if streaming_disallowed
            || !self.endpoints.contains(&meta.endpoint)
            || directives.bypass_store
        {
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

        let requires_temp_zero =
            meta.endpoint.is_conversational() || meta.endpoint == AiEndpointKind::Completions;
        if self.require_deterministic
            && requires_temp_zero
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

        let semantic_prompt = self
            .semantic
            .as_ref()
            .and_then(|_| extract_semantic_prompt_text(meta.endpoint, &parsed_body));
        let semantic_partition = semantic_prompt.as_ref().map(|_| {
            format!(
                "{}|{}|{}|{}|{}",
                tenant_scope,
                meta.endpoint.as_str(),
                meta.stream,
                meta.requested_model,
                target_tuple
                    .map(|(p, m)| format!("{p}:{m}"))
                    .unwrap_or_default()
            )
        });

        let mut pending = AiCachePending {
            cache_key: cache_key.clone(),
            dist_key: dist_key.clone(),
            endpoint: meta.endpoint,
            is_stream: meta.stream,
            requested_model: meta.requested_model.clone(),
            provider,
            served_model,
            semantic_partition: semantic_partition.clone(),
            semantic_prompt: semantic_prompt.clone(),
            semantic_embedding: None,
        };

        let hit_metric_label: &'static str = if meta.stream { "stream_hit" } else { "hit" };

        if directives.bypass_read {
            self.metrics
                .record_cache("miss", meta.endpoint.as_str(), &meta.requested_model);
            ctx.insert_ext(AiCacheStatus::Miss);
            ctx.insert_ext(pending);
            return HookResult::Ready(Flow::Continue);
        }

        // Fast synchronous in-memory exact-match path (zero heap/future allocation on hit,
        // or on miss when neither distributed, semantic, nor singleflight follower awaits).
        if self.distributed.is_none() {
            let now = self.clock.now();
            if let Some(entry) = self.table.get(&cache_key, now) {
                self.metrics.record_cache(
                    hit_metric_label,
                    meta.endpoint.as_str(),
                    &meta.requested_model,
                );
                ctx.insert_ext(AiCacheStatus::Hit {
                    provider: entry.provider.clone(),
                    served_model: entry.served_model.clone(),
                });
                return HookResult::Ready(Flow::Respond(Self::build_hit_response(
                    self.emit_headers,
                    "hit",
                    None,
                    entry,
                )));
            }

            // If semantic is disabled, handle singleflight synchronously for leader or async for follower.
            if self.semantic.is_none() {
                if let Some(sf) = &self.singleflight {
                    match sf.acquire(cache_key) {
                        SingleflightAcquire::Leader(leader) => {
                            ctx.insert_ext(leader);
                            self.metrics.record_cache(
                                "miss",
                                meta.endpoint.as_str(),
                                &meta.requested_model,
                            );
                            ctx.insert_ext(AiCacheStatus::Miss);
                            ctx.insert_ext(pending);
                            return HookResult::Ready(Flow::Continue);
                        }
                        SingleflightAcquire::Follower(mut rx) => {
                            let timeout = self.singleflight_timeout;
                            let metrics = Arc::clone(&self.metrics);
                            let emit_headers = self.emit_headers;
                            let endpoint = meta.endpoint;
                            let requested_model = meta.requested_model.clone();
                            return HookResult::pending(async move {
                                let wait_res = tokio::time::timeout(timeout, async {
                                    loop {
                                        if let Some(outcome) = rx.borrow().clone() {
                                            return Some(outcome);
                                        }
                                        if rx.changed().await.is_err() {
                                            return None;
                                        }
                                    }
                                })
                                .await;

                                if let Ok(Some(SingleflightOutcome::Cached(entry))) = wait_res {
                                    metrics.record_cache(
                                        "coalesced",
                                        endpoint.as_str(),
                                        &requested_model,
                                    );
                                    ctx.insert_ext(AiCacheStatus::Coalesced {
                                        provider: entry.provider.clone(),
                                        served_model: entry.served_model.clone(),
                                    });
                                    return Flow::Respond(Self::build_hit_response(
                                        emit_headers,
                                        "coalesced",
                                        None,
                                        entry,
                                    ));
                                }

                                // Leader failed, aborted, or timed out: fall through to upstream.
                                metrics.record_cache("miss", endpoint.as_str(), &requested_model);
                                ctx.insert_ext(AiCacheStatus::Miss);
                                ctx.insert_ext(pending);
                                Flow::Continue
                            });
                        }
                    }
                }

                self.metrics
                    .record_cache("miss", meta.endpoint.as_str(), &meta.requested_model);
                ctx.insert_ext(AiCacheStatus::Miss);
                ctx.insert_ext(pending);
                return HookResult::Ready(Flow::Continue);
            }
        }

        // Async lookup path: distributed Redis exact-match -> semantic vector search -> singleflight.
        let dist_opt = self.distributed.clone();
        let sem_opt = self.semantic.clone();
        let sf_opt = self.singleflight.clone();
        let sf_timeout = self.singleflight_timeout;
        let metrics = Arc::clone(&self.metrics);
        let clock = Arc::clone(&self.clock);
        let endpoint = meta.endpoint;
        let requested_model = meta.requested_model.clone();
        let emit_headers = self.emit_headers;

        HookResult::pending(async move {
            // 1. Distributed exact-match check (if configured).
            if let Some(dist) = &dist_opt {
                match dist.get_bytes(&dist_key).await {
                    Ok(Some(raw)) => {
                        if let Some(entry) = CachedAiResponse::decode(&raw) {
                            metrics.record_cache(
                                hit_metric_label,
                                endpoint.as_str(),
                                &requested_model,
                            );
                            ctx.insert_ext(AiCacheStatus::Hit {
                                provider: entry.provider.clone(),
                                served_model: entry.served_model.clone(),
                            });
                            return Flow::Respond(Self::build_hit_response(
                                emit_headers,
                                "hit",
                                None,
                                entry,
                            ));
                        }
                    }
                    Ok(None) => {}
                    Err(err) => {
                        warn!(
                            plugin = "ai-cache",
                            backend = dist.backend_name(),
                            error = %err,
                            "distributed cache lookup failed"
                        );
                        if dist.failure_policy() == FailurePolicy::FailClosed {
                            return Flow::Respond(endpoint_error_response(
                                endpoint,
                                StatusCode::SERVICE_UNAVAILABLE,
                                "server_error",
                                Some("cache_store_unavailable"),
                                "Distributed AI cache backend is unavailable",
                            ));
                        }
                    }
                }
            }

            // 2. Semantic vector cache lookup (if configured and prompt text extracted).
            if let (Some(sem), Some(partition), Some(prompt_text)) =
                (&sem_opt, semantic_partition, semantic_prompt)
            {
                let query = SemanticLookupQuery {
                    partition,
                    prompt_text,
                    similarity_threshold: sem.threshold,
                };
                match sem.backend.lookup(query, clock.now()).await {
                    Ok(SemanticLookupResult::Hit(hit)) => {
                        metrics.record_cache("semantic_hit", endpoint.as_str(), &requested_model);
                        ctx.insert_ext(AiCacheStatus::SemanticHit {
                            provider: hit.response.provider.clone(),
                            served_model: hit.response.served_model.clone(),
                            similarity: hit.similarity,
                        });
                        return Flow::Respond(Self::build_hit_response(
                            emit_headers,
                            "semantic_hit",
                            Some(hit.similarity),
                            hit.response,
                        ));
                    }
                    Ok(SemanticLookupResult::Miss { embedding }) => {
                        pending.semantic_embedding = embedding;
                    }
                    Err(err) => {
                        warn!(
                            plugin = "ai-cache",
                            error = %err,
                            "semantic cache lookup failed"
                        );
                        if sem.fail_closed {
                            return Flow::Respond(endpoint_error_response(
                                endpoint,
                                StatusCode::SERVICE_UNAVAILABLE,
                                "server_error",
                                Some("semantic_cache_unavailable"),
                                "Semantic AI cache backend is unavailable",
                            ));
                        }
                    }
                }
            }

            // 3. Singleflight coalescing (if configured).
            if let Some(sf) = &sf_opt {
                match sf.acquire(cache_key) {
                    SingleflightAcquire::Leader(leader) => {
                        ctx.insert_ext(leader);
                    }
                    SingleflightAcquire::Follower(mut rx) => {
                        let wait_res = tokio::time::timeout(sf_timeout, async {
                            loop {
                                if let Some(outcome) = rx.borrow().clone() {
                                    return Some(outcome);
                                }
                                if rx.changed().await.is_err() {
                                    return None;
                                }
                            }
                        })
                        .await;
                        if let Ok(Some(SingleflightOutcome::Cached(entry))) = wait_res {
                            metrics.record_cache("coalesced", endpoint.as_str(), &requested_model);
                            ctx.insert_ext(AiCacheStatus::Coalesced {
                                provider: entry.provider.clone(),
                                served_model: entry.served_model.clone(),
                            });
                            return Flow::Respond(Self::build_hit_response(
                                emit_headers,
                                "coalesced",
                                None,
                                entry,
                            ));
                        }
                    }
                }
            }

            metrics.record_cache("miss", endpoint.as_str(), &requested_model);
            ctx.insert_ext(AiCacheStatus::Miss);
            ctx.insert_ext(pending);
            Flow::Continue
        })
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

        let Some(pending) = ctx.get_ext::<AiCachePending>() else {
            return HookResult::Ready(Flow::Continue);
        };

        if res.status != StatusCode::OK {
            return HookResult::Ready(Flow::Continue);
        }

        let content_type = res
            .headers
            .get(header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("application/json")
            .to_owned();
        let is_sse = content_type
            .to_ascii_lowercase()
            .contains("text/event-stream");
        if is_sse && !(self.cache_streaming && pending.is_stream) {
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
        if let Some(status) = ctx.get_ext::<AiCacheStatus>() {
            ctx.annotate_str("shunt.ai.cache_status", status.as_str());
            if let AiCacheStatus::SemanticHit { similarity, .. } = status {
                ctx.annotate_float("shunt.ai.cache_similarity", *similarity as f64);
            }
        }

        let leader = ctx.get_ext::<SingleflightLeaderSlot>();
        let Some(pending) = ctx.get_ext::<AiCachePending>() else {
            if let Some(l) = leader {
                l.complete_failed();
            }
            return HookResult::Ready(());
        };

        if summary.aborted_mid_stream
            || summary.error.is_some()
            || summary.status != Some(StatusCode::OK)
        {
            if let Some(l) = leader {
                l.complete_failed();
            }
            return HookResult::Ready(());
        }

        // Prefer the translated client-facing body from `ai-provider-adapter` when present
        // (covers Anthropic/Gemini/Bedrock non-streaming AND streaming translation regardless of
        // whether `ai-cache` precedes or follows `ai-provider-adapter`).
        let (content_type, body) =
            if let Some(translated) = ctx.get_ext::<AiTranslatedResponseBody>() {
                let ct = if pending.is_stream {
                    "text/event-stream; charset=utf-8".to_owned()
                } else {
                    "application/json".to_owned()
                };
                (ct, translated.0.clone())
            } else if let Some(captured) = ctx.get_ext::<AiCacheCapturedBody>() {
                (captured.content_type.clone(), captured.body.clone())
            } else {
                if let Some(l) = leader {
                    l.complete_failed();
                }
                return HookResult::Ready(());
            };

        if body.is_empty() || body.len() > self.max_entry_bytes {
            if let Some(l) = leader {
                l.complete_failed();
            }
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

        // Wake singleflight followers immediately with the cached entry before any async I/O.
        if let Some(l) = leader {
            l.complete_cached(entry.clone());
        }

        let now = self.clock.now();
        if self.distributed.is_none() {
            self.table.insert(
                pending.cache_key.clone(),
                entry.clone(),
                now,
                self.ttl,
                self.max_entries,
                self.max_total_bytes,
            );
        }

        let needs_dist_write = self.distributed.is_some();
        let needs_sem_write = self.semantic.is_some()
            && pending.semantic_partition.is_some()
            && pending.semantic_prompt.is_some();

        if !needs_dist_write && !needs_sem_write {
            return HookResult::Ready(());
        }

        let dist_opt = self.distributed.clone();
        let sem_opt = self.semantic.clone();
        let dist_key = pending.dist_key.clone();
        let sem_partition = pending.semantic_partition.clone();
        let sem_prompt = pending.semantic_prompt.clone();
        let sem_embedding = pending.semantic_embedding.clone();
        let ttl = self.ttl;

        HookResult::pending(async move {
            if let Some(dist) = dist_opt
                && let Some(encoded) = entry.encode()
                && let Err(err) = dist.set_bytes(&dist_key, encoded, ttl).await
            {
                warn!(
                    plugin = "ai-cache",
                    backend = dist.backend_name(),
                    error = %err,
                    "distributed cache write failed"
                );
            }

            if let (Some(sem), Some(partition), Some(prompt)) = (sem_opt, sem_partition, sem_prompt)
                && let Err(err) = sem
                    .backend
                    .store(partition, prompt, sem_embedding, entry, now, ttl)
                    .await
            {
                warn!(
                    plugin = "ai-cache",
                    error = %err,
                    "semantic cache store failed"
                );
            }
        })
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
        assert_eq!(table.get("k1", t0).unwrap().body, b"aaaa");
        table.insert("k3".into(), make(b"cccc"), t0, ttl, 2, 1024);

        assert!(table.get("k1", t0).is_some());
        assert!(table.get("k2", t0).is_none(), "k2 should be LRU-evicted");
        assert!(table.get("k3", t0).is_some());
        assert_eq!(table.len(), 2);
        assert_eq!(table.total_bytes(), 8);

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

        table.insert("huge".into(), make(200), t0, ttl, 10, 100);
        assert!(table.get("b", t0).is_some());
        assert_eq!(table.total_bytes(), 60);
    }

    #[test]
    fn cosine_similarity_and_semantic_table_partition_isolation() {
        assert!((cosine_similarity(&[1.0, 0.0], &[1.0, 0.0]) - 1.0).abs() < 1e-6);
        assert!((cosine_similarity(&[1.0, 0.0], &[0.0, 1.0])).abs() < 1e-6);
        assert!((cosine_similarity(&[1.0, 0.0], &[-1.0, 0.0]) + 1.0).abs() < 1e-6);
        assert_eq!(cosine_similarity(&[], &[]), 0.0);
        assert_eq!(cosine_similarity(&[0.0, 0.0], &[1.0, 0.0]), 0.0);

        let table = SemanticCacheTable::new();
        let t0 = Duration::from_secs(1);
        let ttl = Duration::from_secs(60);
        let resp = CachedAiResponse {
            content_type: "application/json".to_owned(),
            provider: "openai".to_owned(),
            served_model: "gpt-4o".to_owned(),
            body: br#"{"ok":true}"#.to_vec(),
        };
        table.insert("tenantA|chat".into(), vec![1.0, 0.0], resp, t0, ttl, 16);

        let hit = table
            .search("tenantA|chat", &[0.99, 0.14], 0.95, t0)
            .expect("should match above 0.95");
        assert!(hit.similarity > 0.98);
        assert!(table.search("tenantB|chat", &[1.0, 0.0], 0.5, t0).is_none());
        assert!(
            table
                .search("tenantA|chat", &[1.0, 0.0], 0.5, Duration::from_secs(61))
                .is_none()
        );
    }

    #[tokio::test]
    async fn singleflight_leader_drop_always_releases_follower() {
        let sf = Arc::new(AiSingleflightTable::new());
        let leader = match sf.acquire("key-drop".into()) {
            SingleflightAcquire::Leader(l) => l,
            SingleflightAcquire::Follower(_) => panic!("first caller must be leader"),
        };
        let mut follower_rx = match sf.acquire("key-drop".into()) {
            SingleflightAcquire::Follower(rx) => rx,
            SingleflightAcquire::Leader(_) => panic!("second caller must be follower"),
        };
        assert_eq!(sf.inflight_count(), 1);

        // Drop leader without calling complete_cached -> follower wakes with Failed.
        drop(leader);
        assert_eq!(sf.inflight_count(), 0);
        let outcome = loop {
            if let Some(o) = follower_rx.borrow().clone() {
                break o;
            }
            follower_rx.changed().await.unwrap();
        };
        assert!(matches!(outcome, SingleflightOutcome::Failed));
    }
}
