//! Opt-in redacted prompt & completion audit sink plugin (`ai-audit`).
//!
//! Captures bounded request prompts and response completions (both non-streaming JSON and
//! streaming SSE), scrubs PII/secrets using [`crate::guardrails::LocalRedactor`] BEFORE data
//! leaves Shunt, and emits structured [`AuditRecord`]s off the hot path (`on_complete`) to
//! any combination of:
//! - **JSONL file sink** (bounded async background writer with optional size rotation)
//! - **OTLP GenAI Span Events** (`gen_ai.content.prompt` & `gen_ai.content.completion` via
//!   `RequestCtx::add_span_event`, exported automatically by `OtlpHttpExporter`)
//! - **Async HTTP webhook sink** (bounded batching background worker via `BuildContext::http_client()`
//!   with optional `X-Shunt-Signature-256` HMAC-SHA256 signing)

use std::collections::BTreeMap;
use std::io::Write as _;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use shunt_plugin_sdk::{
    BuildContext, Bytes, Flow, HeaderName, HeaderValue, HookMask, HookResult, HttpClient,
    HttpPlugin, HttpRequest, PluginBuildError, PluginConfig, PluginFactory, RequestCtx,
    RequestHead, RequestSummary, ResponseHead, SpanValue, StreamFlow, TraceContext, Uri, header,
};
use tokio::sync::mpsc;
use tracing::{debug, warn};

use crate::alerts::compute_hmac_sha256_hex;
use crate::cache::AiCacheStatus;
use crate::guardrails::{
    GuardrailSummary, LocalRedactor, RedactionMode, extract_request_text, extract_response_text,
    extract_sse_delta_text,
};
use crate::sse::SseParser;
use crate::types::{
    AiEndpointKind, AiKeyPolicy, AiRequestMeta, AiUsage, DetectedEndpoint, resolve_env_secret,
};
use crate::usage_tracker::AiMetrics;

const DEFAULT_MAX_CAPTURE_BYTES: usize = 64 * 1024; // 64 KiB
const DEFAULT_QUEUE_CAPACITY: usize = 1024;
const DEFAULT_WEBHOOK_BATCH_SIZE: usize = 1;
const DEFAULT_WEBHOOK_FLUSH_MS: u64 = 1_000;
const DEFAULT_WEBHOOK_TIMEOUT_MS: u64 = 5_000;

fn default_true() -> bool {
    true
}

fn default_sample_rate() -> f64 {
    1.0
}

fn default_max_capture_bytes() -> usize {
    DEFAULT_MAX_CAPTURE_BYTES
}

fn default_queue_capacity() -> usize {
    DEFAULT_QUEUE_CAPACITY
}

fn default_webhook_batch_size() -> usize {
    DEFAULT_WEBHOOK_BATCH_SIZE
}

fn default_webhook_flush_ms() -> u64 {
    DEFAULT_WEBHOOK_FLUSH_MS
}

fn default_webhook_timeout_ms() -> u64 {
    DEFAULT_WEBHOOK_TIMEOUT_MS
}

/// Complete redacted audit record emitted per sampled AI request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditRecord {
    pub schema_version: u8,
    pub timestamp_unix_ms: u64,
    pub request_id: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub trace_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub route_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub team: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub endpoint: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub provider: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub requested_model: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub served_model: Option<String>,
    pub stream: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<u16>,
    pub duration_ms: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ttft_ms: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prompt_tokens: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub completion_tokens: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cached_prompt_tokens: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reasoning_tokens: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cache_status: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub guardrail_action: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub guardrail_rules: Vec<String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub headers: BTreeMap<String, String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prompt: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub completion: Option<String>,
    pub redactions_applied: usize,
    pub aborted_mid_stream: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// Point-in-time audit sink counters exposed via `GET /api/status`.
#[derive(Debug, Clone, Default, Serialize)]
pub struct AuditStatsSnapshot {
    pub records_captured: u64,
    pub jsonl_written: u64,
    pub jsonl_dropped: u64,
    pub jsonl_errors: u64,
    pub otlp_events_emitted: u64,
    pub webhook_sent: u64,
    pub webhook_dropped: u64,
    pub webhook_errors: u64,
}

/// Reload-persistent atomic audit counters stored in `StateStore`.
#[derive(Debug, Default)]
pub struct AuditStatsTable {
    records_captured: AtomicU64,
    jsonl_written: AtomicU64,
    jsonl_dropped: AtomicU64,
    jsonl_errors: AtomicU64,
    otlp_events_emitted: AtomicU64,
    webhook_sent: AtomicU64,
    webhook_dropped: AtomicU64,
    webhook_errors: AtomicU64,
}

impl AuditStatsTable {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn snapshot(&self) -> AuditStatsSnapshot {
        AuditStatsSnapshot {
            records_captured: self.records_captured.load(Ordering::Relaxed),
            jsonl_written: self.jsonl_written.load(Ordering::Relaxed),
            jsonl_dropped: self.jsonl_dropped.load(Ordering::Relaxed),
            jsonl_errors: self.jsonl_errors.load(Ordering::Relaxed),
            otlp_events_emitted: self.otlp_events_emitted.load(Ordering::Relaxed),
            webhook_sent: self.webhook_sent.load(Ordering::Relaxed),
            webhook_dropped: self.webhook_dropped.load(Ordering::Relaxed),
            webhook_errors: self.webhook_errors.load(Ordering::Relaxed),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
struct AuditRedactPatternConfig {
    name: String,
    pattern: String,
    #[serde(default)]
    replacement: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
struct JsonlSinkConfig {
    path: String,
    #[serde(default)]
    max_file_bytes: Option<u64>,
    #[serde(default = "default_queue_capacity")]
    queue_capacity: usize,
}

#[derive(Debug, Clone, Deserialize)]
struct OtlpEventsSinkConfig {
    #[serde(default = "default_true")]
    enabled: bool,
}

#[derive(Debug, Clone, Deserialize)]
struct WebhookSinkConfig {
    url: String,
    #[serde(default)]
    headers: BTreeMap<String, String>,
    #[serde(default)]
    signing_secret: Option<String>,
    #[serde(default = "default_webhook_batch_size")]
    batch_size: usize,
    #[serde(default = "default_webhook_flush_ms")]
    flush_interval_ms: u64,
    #[serde(default = "default_webhook_timeout_ms")]
    timeout_ms: u64,
    #[serde(default = "default_queue_capacity")]
    queue_capacity: usize,
}

#[derive(Debug, Deserialize)]
#[serde(default)]
struct AiAuditConfig {
    /// Capture & audit redacted request prompts (default: `true`).
    #[serde(default = "default_true")]
    include_prompt: bool,
    /// Capture & audit redacted response completions (default: `true`).
    #[serde(default = "default_true")]
    include_completion: bool,
    /// Scrub built-in PII entities before writing to any sink (default: `true`).
    #[serde(default = "default_true")]
    redact_pii: bool,
    /// Scrub built-in secrets/API keys before writing to any sink (default: `true`).
    #[serde(default = "default_true")]
    redact_secrets: bool,
    /// Redaction style (`"mask"`, `"hash"`, or `"partial"`).
    redaction_mode: RedactionMode,
    /// Optional additional custom regex redaction patterns.
    redact_patterns: Vec<AuditRedactPatternConfig>,
    /// Maximum UTF-8 bytes captured for prompt and for completion independently (default: `64 KiB`).
    #[serde(default = "default_max_capture_bytes")]
    max_capture_bytes: usize,
    /// Deterministic sampling ratio in `[0.0, 1.0]` (default: `1.0`).
    #[serde(default = "default_sample_rate")]
    sample_rate: f64,
    /// Explicit allowlist of non-sensitive request headers to record (auth headers are always rejected).
    include_headers: Vec<String>,
    /// Emit audit records only when `ai-guardrails` recorded a finding.
    only_on_guardrail_trigger: bool,
    /// Emit audit records only for error responses (`status >= 400` or aborted).
    only_on_error: bool,
    /// Optional JSONL file sink configuration.
    jsonl: Option<JsonlSinkConfig>,
    /// Optional OTLP GenAI span-events sink configuration.
    otlp_events: Option<OtlpEventsSinkConfig>,
    /// Optional async HTTP webhook sink configuration.
    webhook: Option<WebhookSinkConfig>,
}

impl Default for AiAuditConfig {
    fn default() -> Self {
        Self {
            include_prompt: true,
            include_completion: true,
            redact_pii: true,
            redact_secrets: true,
            redaction_mode: RedactionMode::Mask,
            redact_patterns: Vec::new(),
            max_capture_bytes: default_max_capture_bytes(),
            sample_rate: default_sample_rate(),
            include_headers: Vec::new(),
            only_on_guardrail_trigger: false,
            only_on_error: false,
            jsonl: None,
            otlp_events: None,
            webhook: None,
        }
    }
}

#[derive(Debug, Clone)]
struct CompiledJsonlSink {
    path: PathBuf,
    max_file_bytes: Option<u64>,
    tx: mpsc::Sender<String>,
    pending_rx: Arc<Mutex<Option<mpsc::Receiver<String>>>>,
}

#[derive(Debug, Clone)]
struct CompiledWebhookSink {
    uri: Uri,
    headers: Vec<(HeaderName, HeaderValue)>,
    signing_secret: Option<String>,
    batch_size: usize,
    flush_interval: Duration,
    timeout: Duration,
    tx: mpsc::Sender<AuditRecord>,
    pending_rx: Arc<Mutex<Option<mpsc::Receiver<AuditRecord>>>>,
}

#[derive(Debug, Clone, Default)]
struct AuditCaptureState {
    sampled: bool,
    headers: BTreeMap<String, String>,
    prompt_text: Option<String>,
    is_sse: bool,
    sse_parser: Option<SseParser>,
    completion_text: String,
    json_buf: Vec<u8>,
    json_overflowed: bool,
}

/// Safely truncates `s` to at most `max_bytes` on a UTF-8 char boundary.
pub fn truncate_utf8_bytes(s: &str, max_bytes: usize) -> String {
    if s.len() <= max_bytes {
        return s.to_owned();
    }
    let mut end = max_bytes;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    let mut out = s[..end].to_owned();
    out.push_str("...[truncated]");
    out
}

fn is_forbidden_audit_header(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    matches!(
        lower.as_str(),
        "authorization"
            | "proxy-authorization"
            | "cookie"
            | "set-cookie"
            | "x-api-key"
            | "api-key"
            | "x-goog-api-key"
            | "x-amz-security-token"
    ) || lower.contains("token")
        || lower.contains("secret")
        || lower.contains("password")
}

fn should_sample(request_id: u64, rate: f64) -> bool {
    if rate <= 0.0 || !rate.is_finite() {
        return false;
    }
    if rate >= 1.0 {
        return true;
    }
    // Deterministic SplitMix64 mixing on request_id for uniform sampling.
    let mut x = request_id.wrapping_add(0x9e37_79b9_7f4a_7c15);
    x = (x ^ (x >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    x = (x ^ (x >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    x ^= x >> 31;
    let threshold = (rate * (u64::MAX as f64)) as u64;
    x <= threshold
}

/// Factory for the `ai-audit` plugin.
pub struct AiAuditFactory {
    metrics: Arc<AiMetrics>,
}

impl AiAuditFactory {
    pub fn new(metrics: Arc<AiMetrics>) -> Self {
        Self { metrics }
    }
}

impl PluginFactory for AiAuditFactory {
    fn name(&self) -> &str {
        "ai-audit"
    }

    fn build(
        &self,
        config: &PluginConfig,
        ctx: &BuildContext,
    ) -> Result<Arc<dyn HttpPlugin>, PluginBuildError> {
        let cfg: AiAuditConfig = config.deserialize(self.name())?;

        if !cfg.sample_rate.is_finite() || !(0.0..=1.0).contains(&cfg.sample_rate) {
            return Err(PluginBuildError::BuildFailed {
                plugin: self.name().to_owned(),
                message: "`sample_rate` must be within [0.0, 1.0]".to_owned(),
            });
        }

        let otlp_events_enabled = cfg.otlp_events.as_ref().map(|o| o.enabled).unwrap_or(false);

        if cfg.jsonl.is_none() && !otlp_events_enabled && cfg.webhook.is_none() {
            return Err(PluginBuildError::BuildFailed {
                plugin: self.name().to_owned(),
                message: "at least one audit sink (`jsonl`, `otlp_events`, or `webhook`) must be configured".to_owned(),
            });
        }

        let extra_patterns: Vec<(String, String, Option<String>)> = cfg
            .redact_patterns
            .into_iter()
            .map(|p| (p.name, p.pattern, p.replacement))
            .collect();
        let redactor = LocalRedactor::new(
            cfg.redact_pii,
            cfg.redact_secrets,
            &extra_patterns,
            cfg.redaction_mode,
        )
        .map_err(|msg| PluginBuildError::BuildFailed {
            plugin: self.name().to_owned(),
            message: msg,
        })?;

        let include_headers: Vec<String> = cfg
            .include_headers
            .into_iter()
            .filter(|h| !is_forbidden_audit_header(h))
            .map(|h| h.to_ascii_lowercase())
            .collect();

        let jsonl = match cfg.jsonl {
            Some(j) => {
                if j.path.trim().is_empty() {
                    return Err(PluginBuildError::BuildFailed {
                        plugin: self.name().to_owned(),
                        message: "`jsonl.path` cannot be empty".to_owned(),
                    });
                }
                let (tx, rx) = mpsc::channel(j.queue_capacity.max(1));
                Some(CompiledJsonlSink {
                    path: PathBuf::from(j.path),
                    max_file_bytes: j.max_file_bytes,
                    tx,
                    pending_rx: Arc::new(Mutex::new(Some(rx))),
                })
            }
            None => None,
        };

        let webhook = match cfg.webhook {
            Some(w) => {
                let resolved_url =
                    resolve_env_secret(&w.url).map_err(|e| PluginBuildError::BuildFailed {
                        plugin: self.name().to_owned(),
                        message: format!("webhook.url: {e}"),
                    })?;
                let uri: Uri = resolved_url
                    .parse()
                    .map_err(|e| PluginBuildError::BuildFailed {
                        plugin: self.name().to_owned(),
                        message: format!("webhook.url `{resolved_url}` is invalid: {e}"),
                    })?;
                let scheme = uri.scheme_str().unwrap_or("");
                if (scheme != "http" && scheme != "https") || uri.authority().is_none() {
                    return Err(PluginBuildError::BuildFailed {
                        plugin: self.name().to_owned(),
                        message: format!("webhook.url `{resolved_url}` must be http(s)://"),
                    });
                }
                let mut headers = Vec::with_capacity(w.headers.len());
                for (hk, hv) in w.headers {
                    let resolved_v =
                        resolve_env_secret(&hv).map_err(|e| PluginBuildError::BuildFailed {
                            plugin: self.name().to_owned(),
                            message: format!("webhook.headers.{hk}: {e}"),
                        })?;
                    let hname = HeaderName::from_bytes(hk.as_bytes()).map_err(|e| {
                        PluginBuildError::BuildFailed {
                            plugin: self.name().to_owned(),
                            message: format!("webhook.headers: invalid `{hk}`: {e}"),
                        }
                    })?;
                    let hval = HeaderValue::from_str(&resolved_v).map_err(|e| {
                        PluginBuildError::BuildFailed {
                            plugin: self.name().to_owned(),
                            message: format!("webhook.headers.{hk}: invalid value: {e}"),
                        }
                    })?;
                    headers.push((hname, hval));
                }
                let signing_secret = match w.signing_secret {
                    Some(raw) => Some(resolve_env_secret(&raw).map_err(|e| {
                        PluginBuildError::BuildFailed {
                            plugin: self.name().to_owned(),
                            message: format!("webhook.signing_secret: {e}"),
                        }
                    })?),
                    None => None,
                };
                let (tx, rx) = mpsc::channel(w.queue_capacity.max(1));
                Some(CompiledWebhookSink {
                    uri,
                    headers,
                    signing_secret,
                    batch_size: w.batch_size.max(1),
                    flush_interval: Duration::from_millis(w.flush_interval_ms.max(25)),
                    timeout: Duration::from_millis(w.timeout_ms.max(100)),
                    tx,
                    pending_rx: Arc::new(Mutex::new(Some(rx))),
                })
            }
            None => None,
        };

        let stats = ctx
            .state_handle()
            .get_or_init("ai_audit_stats", AuditStatsTable::new);

        Ok(Arc::new(AiAuditPlugin {
            include_prompt: cfg.include_prompt,
            include_completion: cfg.include_completion,
            redactor,
            max_capture_bytes: cfg.max_capture_bytes.max(256),
            sample_rate: cfg.sample_rate,
            include_headers,
            only_on_guardrail_trigger: cfg.only_on_guardrail_trigger,
            only_on_error: cfg.only_on_error,
            jsonl,
            otlp_events_enabled,
            webhook,
            http_client: ctx.http_client(),
            stats,
            metrics: Arc::clone(&self.metrics),
        }))
    }
}

/// Opt-in redacted prompt & completion audit plugin (`ai-audit`).
pub struct AiAuditPlugin {
    include_prompt: bool,
    include_completion: bool,
    redactor: LocalRedactor,
    max_capture_bytes: usize,
    sample_rate: f64,
    include_headers: Vec<String>,
    only_on_guardrail_trigger: bool,
    only_on_error: bool,
    jsonl: Option<CompiledJsonlSink>,
    otlp_events_enabled: bool,
    webhook: Option<CompiledWebhookSink>,
    http_client: Option<Arc<dyn HttpClient>>,
    stats: Arc<AuditStatsTable>,
    metrics: Arc<AiMetrics>,
}

impl AiAuditPlugin {
    fn ensure_workers_started(&self) {
        let Ok(handle) = tokio::runtime::Handle::try_current() else {
            return;
        };

        if let Some(j) = &self.jsonl {
            let rx = j
                .pending_rx
                .lock()
                .expect("jsonl pending_rx poisoned")
                .take();
            if let Some(rx) = rx {
                let path = j.path.clone();
                let max_bytes = j.max_file_bytes;
                let stats = Arc::clone(&self.stats);
                let metrics = Arc::clone(&self.metrics);
                handle.spawn(run_jsonl_worker(path, max_bytes, rx, stats, metrics));
            }
        }

        if let (Some(w), Some(client)) = (&self.webhook, &self.http_client) {
            let rx = w
                .pending_rx
                .lock()
                .expect("webhook pending_rx poisoned")
                .take();
            if let Some(rx) = rx {
                let sink = w.clone();
                let client = Arc::clone(client);
                let stats = Arc::clone(&self.stats);
                let metrics = Arc::clone(&self.metrics);
                handle.spawn(run_webhook_worker(sink, client, rx, stats, metrics));
            }
        }
    }
}

async fn run_jsonl_worker(
    path: PathBuf,
    max_file_bytes: Option<u64>,
    mut rx: mpsc::Receiver<String>,
    stats: Arc<AuditStatsTable>,
    metrics: Arc<AiMetrics>,
) {
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        let parent_buf = parent.to_path_buf();
        if let Ok(Err(err)) =
            tokio::task::spawn_blocking(move || std::fs::create_dir_all(&parent_buf)).await
        {
            warn!(plugin = "ai-audit", path = %path.display(), error = %err, "failed to create audit JSONL parent directory");
        }
    }

    while let Some(line) = rx.recv().await {
        let p = path.clone();
        let res = tokio::task::spawn_blocking(move || -> std::io::Result<()> {
            if let Some(max_bytes) = max_file_bytes
                && let Ok(meta) = std::fs::metadata(&p)
                && meta.len() >= max_bytes
            {
                let rotated = PathBuf::from(format!("{}.1", p.display()));
                let _ = std::fs::rename(&p, &rotated);
            }
            let mut file = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(&p)?;
            writeln!(file, "{line}")?;
            Ok(())
        })
        .await;

        match res {
            Ok(Ok(())) => {
                stats.jsonl_written.fetch_add(1, Ordering::Relaxed);
                metrics.record_audit("jsonl", "written");
            }
            Ok(Err(err)) => {
                warn!(plugin = "ai-audit", path = %path.display(), error = %err, "failed writing JSONL audit record");
                stats.jsonl_errors.fetch_add(1, Ordering::Relaxed);
                metrics.record_audit("jsonl", "error");
            }
            Err(err) => {
                warn!(plugin = "ai-audit", path = %path.display(), error = %err, "audit JSONL task join failed");
                stats.jsonl_errors.fetch_add(1, Ordering::Relaxed);
                metrics.record_audit("jsonl", "error");
            }
        }
    }
}

async fn run_webhook_worker(
    sink: CompiledWebhookSink,
    client: Arc<dyn HttpClient>,
    mut rx: mpsc::Receiver<AuditRecord>,
    stats: Arc<AuditStatsTable>,
    metrics: Arc<AiMetrics>,
) {
    let mut batch: Vec<AuditRecord> = Vec::with_capacity(sink.batch_size.min(256));
    let mut ticker = tokio::time::interval(sink.flush_interval);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    ticker.tick().await;

    loop {
        tokio::select! {
            item = rx.recv() => {
                match item {
                    Some(rec) => {
                        batch.push(rec);
                        if batch.len() >= sink.batch_size {
                            flush_webhook_batch(&sink, client.as_ref(), &mut batch, &stats, &metrics).await;
                        }
                    }
                    None => {
                        if !batch.is_empty() {
                            flush_webhook_batch(&sink, client.as_ref(), &mut batch, &stats, &metrics).await;
                        }
                        break;
                    }
                }
            }
            _ = ticker.tick() => {
                if !batch.is_empty() {
                    flush_webhook_batch(&sink, client.as_ref(), &mut batch, &stats, &metrics).await;
                }
            }
        }
    }
}

async fn flush_webhook_batch(
    sink: &CompiledWebhookSink,
    client: &dyn HttpClient,
    batch: &mut Vec<AuditRecord>,
    stats: &AuditStatsTable,
    metrics: &AiMetrics,
) {
    let records = std::mem::take(batch);
    let count = records.len() as u64;
    let payload_val: Value = if sink.batch_size == 1 && records.len() == 1 {
        serde_json::to_value(&records[0]).unwrap_or_else(|_| json!({}))
    } else {
        json!({ "records": records })
    };
    let body_bytes = match serde_json::to_vec(&payload_val) {
        Ok(b) => b,
        Err(err) => {
            warn!(plugin = "ai-audit", error = %err, "failed to serialize audit webhook payload");
            stats.webhook_errors.fetch_add(count, Ordering::Relaxed);
            metrics.record_audit("webhook", "error");
            return;
        }
    };

    let mut req = HttpRequest::post(sink.uri.clone())
        .with_header(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/json"),
        )
        .with_timeout(sink.timeout)
        .with_max_response_bytes(64 * 1024);

    for (hk, hv) in &sink.headers {
        req.headers.insert(hk.clone(), hv.clone());
    }
    if let Some(secret) = &sink.signing_secret {
        let sig = compute_hmac_sha256_hex(secret.as_bytes(), &body_bytes);
        if let Ok(hv) = HeaderValue::from_str(&format!("sha256={sig}")) {
            req.headers
                .insert(HeaderName::from_static("x-shunt-signature-256"), hv);
        }
    }
    req.body = body_bytes.into();

    match client.send(req).await {
        Ok(resp) if resp.status.is_success() => {
            stats.webhook_sent.fetch_add(count, Ordering::Relaxed);
            for _ in 0..count {
                metrics.record_audit("webhook", "written");
            }
            debug!(
                plugin = "ai-audit",
                count,
                status = resp.status.as_u16(),
                "delivered audit webhook batch"
            );
        }
        Ok(resp) => {
            stats.webhook_errors.fetch_add(count, Ordering::Relaxed);
            metrics.record_audit("webhook", "error");
            warn!(
                plugin = "ai-audit",
                status = resp.status.as_u16(),
                count,
                "audit webhook returned non-2xx status"
            );
        }
        Err(err) => {
            stats.webhook_errors.fetch_add(count, Ordering::Relaxed);
            metrics.record_audit("webhook", "error");
            warn!(plugin = "ai-audit", error = %err, count, "audit webhook delivery failed");
        }
    }
}

impl HttpPlugin for AiAuditPlugin {
    fn name(&self) -> &str {
        "ai-audit"
    }

    fn hook_mask(&self) -> HookMask {
        let mut mask = HookMask::ON_COMPLETE;
        if !self.include_headers.is_empty() {
            mask |= HookMask::ON_REQUEST_HEADERS;
        }
        if self.include_prompt {
            mask |= HookMask::REQUEST_BODY_BUFFERED;
        }
        if self.include_completion {
            mask |= HookMask::ON_RESPONSE_HEADERS | HookMask::RESPONSE_BODY_STREAM;
        }
        mask
    }

    fn on_request_headers<'a>(
        &'a self,
        ctx: &'a mut RequestCtx,
        req: &'a mut RequestHead,
    ) -> HookResult<'a, Flow> {
        let sampled = should_sample(ctx.request_id, self.sample_rate);
        let mut state = AuditCaptureState {
            sampled,
            ..Default::default()
        };
        if sampled {
            for hname in &self.include_headers {
                if let Some(val) = req
                    .headers
                    .get(hname.as_str())
                    .and_then(|v| v.to_str().ok())
                {
                    state.headers.insert(hname.clone(), val.to_owned());
                }
            }
        }
        ctx.insert_ext(state);
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

        let sampled = ctx
            .get_ext::<AuditCaptureState>()
            .map(|s| s.sampled)
            .unwrap_or_else(|| should_sample(ctx.request_id, self.sample_rate));
        if !sampled {
            return HookResult::Ready(Flow::Continue);
        }

        let prompt_text = if self.include_prompt && !body.is_empty() {
            extract_request_text(body, &[]).map(|t| truncate_utf8_bytes(&t, self.max_capture_bytes))
        } else {
            None
        };

        if let Some(state) = ctx.get_ext_mut::<AuditCaptureState>() {
            state.prompt_text = prompt_text;
        } else {
            ctx.insert_ext(AuditCaptureState {
                sampled: true,
                prompt_text,
                ..Default::default()
            });
        }
        HookResult::Ready(Flow::Continue)
    }

    fn on_response_headers<'a>(
        &'a self,
        ctx: &'a mut RequestCtx,
        res: &'a mut ResponseHead,
    ) -> HookResult<'a, Flow> {
        if !self.include_completion {
            return HookResult::Ready(Flow::Continue);
        }
        let sampled = ctx
            .get_ext::<AuditCaptureState>()
            .map(|s| s.sampled)
            .unwrap_or_else(|| should_sample(ctx.request_id, self.sample_rate));
        if !sampled {
            return HookResult::Ready(Flow::Continue);
        }

        let is_sse = res
            .headers
            .get(header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .map(|ct| ct.to_ascii_lowercase().contains("text/event-stream"))
            .unwrap_or(false);

        if let Some(state) = ctx.get_ext_mut::<AuditCaptureState>() {
            state.is_sse = is_sse;
            state.sse_parser = is_sse.then(SseParser::new);
            state.completion_text.clear();
            state.json_buf.clear();
            state.json_overflowed = false;
        } else {
            ctx.insert_ext(AuditCaptureState {
                sampled: true,
                is_sse,
                sse_parser: is_sse.then(SseParser::new),
                ..Default::default()
            });
        }
        HookResult::Ready(Flow::Continue)
    }

    fn on_response_body_chunk<'a>(
        &'a self,
        ctx: &'a mut RequestCtx,
        chunk: &'a mut Bytes,
        end_of_stream: bool,
    ) -> HookResult<'a, StreamFlow> {
        let Some(state) = ctx.get_ext_mut::<AuditCaptureState>() else {
            return HookResult::Ready(StreamFlow::Continue);
        };
        if !state.sampled || !self.include_completion {
            return HookResult::Ready(StreamFlow::Continue);
        }

        if state.is_sse {
            if let Some(parser) = state.sse_parser.as_mut() {
                let mut events = if !chunk.is_empty() {
                    parser.push(chunk)
                } else {
                    Vec::new()
                };
                if end_of_stream {
                    events.extend(parser.finish());
                }
                for ev in events {
                    if ev.data.trim() == "[DONE]" {
                        continue;
                    }
                    if let Ok(val) = serde_json::from_str::<Value>(&ev.data)
                        && let Some(delta) = extract_sse_delta_text(&val)
                        && state.completion_text.len() < self.max_capture_bytes
                    {
                        let rem = self.max_capture_bytes - state.completion_text.len();
                        if delta.len() <= rem {
                            state.completion_text.push_str(&delta);
                        } else {
                            let mut end = rem;
                            while end > 0 && !delta.is_char_boundary(end) {
                                end -= 1;
                            }
                            state.completion_text.push_str(&delta[..end]);
                        }
                    }
                }
            }
        } else {
            if !chunk.is_empty() && !state.json_overflowed {
                if state.json_buf.len().saturating_add(chunk.len())
                    <= self.max_capture_bytes.saturating_mul(4)
                {
                    state.json_buf.extend_from_slice(chunk);
                } else {
                    state.json_overflowed = true;
                }
            }
            if end_of_stream && !state.json_buf.is_empty() {
                if let Some(extracted) = extract_response_text(&state.json_buf) {
                    state.completion_text = truncate_utf8_bytes(&extracted, self.max_capture_bytes);
                } else if let Ok(raw) = std::str::from_utf8(&state.json_buf) {
                    state.completion_text = truncate_utf8_bytes(raw, self.max_capture_bytes);
                }
                state.json_buf.clear();
            }
        }

        HookResult::Ready(StreamFlow::Continue)
    }

    fn on_complete<'a>(
        &'a self,
        ctx: &'a RequestCtx,
        summary: &'a RequestSummary,
    ) -> HookResult<'a, ()> {
        let endpoint = ctx.get_ext::<DetectedEndpoint>().map(|d| d.0);
        if endpoint.is_some_and(AiEndpointKind::is_models_discovery) {
            return HookResult::Ready(());
        }

        let state = ctx.get_ext::<AuditCaptureState>();
        let sampled = state
            .map(|s| s.sampled)
            .unwrap_or_else(|| should_sample(summary.request_id, self.sample_rate));
        if !sampled {
            return HookResult::Ready(());
        }

        let guardrail = ctx.get_ext::<GuardrailSummary>();
        if self.only_on_guardrail_trigger
            && guardrail.map(|g| g.findings.is_empty()).unwrap_or(true)
        {
            return HookResult::Ready(());
        }
        let status_u16 = summary.status.map(|s| s.as_u16());
        let is_error = status_u16.is_some_and(|s| s >= 400)
            || summary.aborted_mid_stream
            || summary.error.is_some();
        if self.only_on_error && !is_error {
            return HookResult::Ready(());
        }

        let mut redactions_applied = 0usize;
        let redacted_prompt = state
            .and_then(|s| s.prompt_text.as_deref())
            .filter(|s| !s.is_empty())
            .map(|raw| {
                let (clean, n) = self.redactor.redact_text(raw);
                redactions_applied += n;
                clean
            });
        let redacted_completion = state
            .map(|s| s.completion_text.as_str())
            .filter(|s| !s.is_empty())
            .map(|raw| {
                let (clean, n) = self.redactor.redact_text(raw);
                redactions_applied += n;
                clean
            });

        let meta = ctx.get_ext::<AiRequestMeta>();
        let active_target = meta.and_then(AiRequestMeta::active_target);
        let usage = ctx.get_ext::<AiUsage>();
        let policy = ctx.get_ext::<AiKeyPolicy>();
        let cache = ctx.get_ext::<AiCacheStatus>();
        let trace_id = ctx
            .get_ext::<TraceContext>()
            .map(TraceContext::trace_id_hex);

        let provider = usage
            .and_then(|u| u.provider.clone())
            .or_else(|| active_target.map(|t| t.provider.clone()));
        let requested_model = meta.map(|m| m.requested_model.clone());
        let served_model = usage
            .and_then(|u| u.served_model.clone())
            .or_else(|| active_target.map(|t| t.model.clone()))
            .or_else(|| requested_model.clone());

        let ttft_ms = usage
            .and_then(|u| u.first_token_at)
            .map(|first| first.saturating_duration_since(ctx.started_at).as_millis() as u64)
            .or_else(|| summary.ttfb.map(|d| d.as_millis() as u64));

        let timestamp_unix_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis().min(u64::MAX as u128) as u64)
            .unwrap_or(0);

        let record = AuditRecord {
            schema_version: 1,
            timestamp_unix_ms,
            request_id: summary.request_id,
            trace_id,
            route_id: summary.route_id.clone(),
            key_id: policy.map(|p| p.key_id.clone()),
            team: policy.and_then(|p| p.team.clone()),
            endpoint: endpoint.map(|e| e.as_str().to_owned()),
            provider,
            requested_model,
            served_model,
            stream: meta.map(|m| m.stream).unwrap_or(false),
            status: status_u16,
            duration_ms: summary.total_duration.as_millis() as u64,
            ttft_ms,
            prompt_tokens: usage.and_then(|u| u.prompt_tokens),
            completion_tokens: usage.and_then(|u| u.completion_tokens),
            cached_prompt_tokens: usage.and_then(|u| u.cached_prompt_tokens),
            reasoning_tokens: usage.and_then(|u| u.reasoning_tokens),
            cache_status: cache.map(|c| c.as_str().to_owned()),
            guardrail_action: guardrail.map(|g| g.effective_action.as_str().to_owned()),
            guardrail_rules: guardrail
                .map(GuardrailSummary::rule_names)
                .unwrap_or_default(),
            headers: state.map(|s| s.headers.clone()).unwrap_or_default(),
            prompt: redacted_prompt.clone(),
            completion: redacted_completion.clone(),
            redactions_applied,
            aborted_mid_stream: summary.aborted_mid_stream,
            error: summary.error.clone(),
        };

        self.stats.records_captured.fetch_add(1, Ordering::Relaxed);
        self.ensure_workers_started();

        // 1. OTLP GenAI Span Events sink (zero extra network hops; rides on active OTLP span!)
        if self.otlp_events_enabled {
            let mut emitted = false;
            if let Some(prompt) = &redacted_prompt {
                let mut attrs = BTreeMap::new();
                attrs.insert(
                    "gen_ai.prompt".to_owned(),
                    SpanValue::String(prompt.clone()),
                );
                if let Some(m) = &record.requested_model {
                    attrs.insert(
                        "gen_ai.request.model".to_owned(),
                        SpanValue::String(m.clone()),
                    );
                }
                attrs.insert(
                    "shunt.audit.redactions".to_owned(),
                    SpanValue::Int(redactions_applied as i64),
                );
                ctx.add_span_event("gen_ai.content.prompt", attrs);
                emitted = true;
            }
            if let Some(completion) = &redacted_completion {
                let mut attrs = BTreeMap::new();
                attrs.insert(
                    "gen_ai.completion".to_owned(),
                    SpanValue::String(completion.clone()),
                );
                if let Some(m) = &record.served_model {
                    attrs.insert(
                        "gen_ai.response.model".to_owned(),
                        SpanValue::String(m.clone()),
                    );
                }
                ctx.add_span_event("gen_ai.content.completion", attrs);
                emitted = true;
            }
            if emitted {
                self.stats
                    .otlp_events_emitted
                    .fetch_add(1, Ordering::Relaxed);
                self.metrics.record_audit("otlp_events", "written");
            }
        }

        // 2. JSONL file sink (bounded non-blocking queue)
        if let Some(j) = &self.jsonl {
            match serde_json::to_string(&record) {
                Ok(line) => {
                    if j.tx.try_send(line).is_err() {
                        self.stats.jsonl_dropped.fetch_add(1, Ordering::Relaxed);
                        self.metrics.record_audit("jsonl", "dropped");
                    }
                }
                Err(err) => {
                    warn!(plugin = "ai-audit", error = %err, "failed to serialize JSONL audit record");
                    self.stats.jsonl_errors.fetch_add(1, Ordering::Relaxed);
                    self.metrics.record_audit("jsonl", "error");
                }
            }
        }

        // 3. Async HTTP webhook sink (bounded non-blocking queue)
        if let Some(w) = &self.webhook
            && w.tx.try_send(record).is_err()
        {
            self.stats.webhook_dropped.fetch_add(1, Ordering::Relaxed);
            self.metrics.record_audit("webhook", "dropped");
        }

        HookResult::Ready(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn truncate_utf8_bytes_preserves_multibyte_boundaries() {
        let s = "hello 🌍 world";
        let t = truncate_utf8_bytes(s, 8);
        assert!(t.starts_with("hello "));
        assert!(t.ends_with("...[truncated]"));
    }

    #[test]
    fn forbidden_audit_headers_are_always_filtered() {
        assert!(is_forbidden_audit_header("Authorization"));
        assert!(is_forbidden_audit_header("x-api-key"));
        assert!(is_forbidden_audit_header("X-Custom-Token"));
        assert!(!is_forbidden_audit_header("x-request-id"));
        assert!(!is_forbidden_audit_header("user-agent"));
    }

    #[test]
    fn sampling_extremes_work_deterministically() {
        assert!(!should_sample(1, 0.0));
        assert!(should_sample(1, 1.0));
        let hits = (1..=1000).filter(|&id| should_sample(id, 0.5)).count();
        assert!(
            (400..=600).contains(&hits),
            "expected ~500 hits, got {hits}"
        );
    }
}
