//! Non-blocking operational alert webhook dispatcher (`ai-alerts`).
//!
//! Delivers structured alerts for budget threshold crossings, failover circuit-breaker trips,
//! exhausted failover chains, and guardrail blocks to **Slack**, **PagerDuty Events API v2**,
//! and generic **HTTP JSON webhooks** (with optional HMAC-SHA256 signing) via
//! [`shunt_plugin_sdk::HttpClient`].
//!
//! Runs strictly in `on_complete` (`HookMask::ON_COMPLETE`) over a bounded non-blocking queue
//! with reload-persistent deduplication (`StateStore` + `Clock`), ensuring zero hot-path overhead.

use std::collections::{BTreeMap, HashMap};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use ring::hmac;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use shunt_plugin_sdk::{
    BuildContext, Clock, HeaderName, HeaderValue, HookMask, HookResult, HttpClient, HttpPlugin,
    HttpRequest, PluginBuildError, PluginConfig, PluginFactory, RequestCtx, RequestSummary, Uri,
    encode_hex_lower, header,
};
use tokio::sync::mpsc;
use tracing::{debug, warn};

use crate::types::resolve_env_secret;
use crate::usage_tracker::AiMetrics;

const DEFAULT_DEDUP_WINDOW_MS: u64 = 60_000;
const DEFAULT_QUEUE_CAPACITY: usize = 256;
const DEFAULT_WEBHOOK_TIMEOUT_MS: u64 = 5_000;
const DEFAULT_PAGERDUTY_URL: &str = "https://events.pagerduty.com/v2/enqueue";

fn default_dedup_window_ms() -> u64 {
    DEFAULT_DEDUP_WINDOW_MS
}

fn default_queue_capacity() -> usize {
    DEFAULT_QUEUE_CAPACITY
}

fn default_webhook_timeout_ms() -> u64 {
    DEFAULT_WEBHOOK_TIMEOUT_MS
}

fn default_alert_kinds() -> Vec<AiAlertKind> {
    vec![
        AiAlertKind::BudgetSoftWarning,
        AiAlertKind::BudgetHardExceeded,
        AiAlertKind::CircuitBreakerOpen,
        AiAlertKind::FailoverExhausted,
        AiAlertKind::GuardrailBlock,
    ]
}

fn default_source() -> String {
    "shunt".to_owned()
}

/// Categories of operational AI gateway alerts emitted to `ai-alerts`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AiAlertKind {
    BudgetSoftWarning,
    BudgetHardExceeded,
    CircuitBreakerOpen,
    FailoverExhausted,
    GuardrailBlock,
}

impl AiAlertKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            AiAlertKind::BudgetSoftWarning => "budget_soft_warning",
            AiAlertKind::BudgetHardExceeded => "budget_hard_exceeded",
            AiAlertKind::CircuitBreakerOpen => "circuit_breaker_open",
            AiAlertKind::FailoverExhausted => "failover_exhausted",
            AiAlertKind::GuardrailBlock => "guardrail_block",
        }
    }
}

/// Severity level attached to an [`AiAlertEvent`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AiAlertSeverity {
    Info,
    Warning,
    Error,
    Critical,
}

impl AiAlertSeverity {
    pub const fn as_str(self) -> &'static str {
        match self {
            AiAlertSeverity::Info => "info",
            AiAlertSeverity::Warning => "warning",
            AiAlertSeverity::Error => "error",
            AiAlertSeverity::Critical => "critical",
        }
    }
}

/// Structured operational alert event emitted by `ai-budget`, `ai-failover`, or `ai-guardrails`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AiAlertEvent {
    pub kind: AiAlertKind,
    pub severity: AiAlertSeverity,
    pub dedup_key: String,
    pub title: String,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subject: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub provider: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub model: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub team: Option<String>,
    #[serde(default)]
    pub details: Value,
}

/// Interior-mutable per-request alert event collector attached to `RequestCtx::extensions`.
///
/// Mirrors `SpanHandle` / `TraceAnnotations` so both pre-response hooks (`&mut RequestCtx`)
/// and post-response `on_complete` hooks (`&RequestCtx`) can record alert events cleanly.
#[derive(Debug, Clone, Default)]
pub struct AiAlertBus {
    events: Arc<Mutex<Vec<AiAlertEvent>>>,
}

impl AiAlertBus {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn push(&self, event: AiAlertEvent) {
        if let Ok(mut guard) = self.events.lock() {
            guard.push(event);
        }
    }

    pub fn snapshot(&self) -> Vec<AiAlertEvent> {
        self.events
            .lock()
            .map(|guard| guard.clone())
            .unwrap_or_default()
    }
}

/// Ensures an [`AiAlertBus`] is attached to `ctx.extensions` and returns a handle to it.
pub fn ensure_alert_bus(ctx: &mut RequestCtx) -> AiAlertBus {
    if let Some(bus) = ctx.get_ext::<AiAlertBus>() {
        return bus.clone();
    }
    let bus = AiAlertBus::new();
    ctx.insert_ext(bus.clone());
    bus
}

/// Pushes an [`AiAlertEvent`] onto `ctx.extensions`, creating the [`AiAlertBus`] lazily.
pub fn push_alert_event(ctx: &mut RequestCtx, event: AiAlertEvent) {
    ensure_alert_bus(ctx).push(event);
}

/// Pushes an [`AiAlertEvent`] from an immutable `&RequestCtx` (e.g., `on_complete`) when an
/// [`AiAlertBus`] was attached earlier in the request lifecycle.
pub fn push_alert_event_ref(ctx: &RequestCtx, event: AiAlertEvent) {
    if let Some(bus) = ctx.get_ext::<AiAlertBus>() {
        bus.push(event);
    }
}

/// Computes lowercase hex HMAC-SHA256 signature (`ring::hmac`) for webhook verification.
pub fn compute_hmac_sha256_hex(secret: &[u8], payload: &[u8]) -> String {
    let key = hmac::Key::new(hmac::HMAC_SHA256, secret);
    let tag = hmac::sign(&key, payload);
    encode_hex_lower(tag.as_ref())
}

/// Reload-persistent deduplication window table stored in `StateStore`.
#[derive(Debug, Default)]
pub struct AlertDedupTable {
    last_sent: RwLock<HashMap<String, Duration>>,
}

impl AlertDedupTable {
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns `true` if `key` is outside its `window` (recording `now` as the new send time),
    /// or `false` if this alert should be suppressed as a duplicate.
    pub fn should_send(&self, key: &str, now: Duration, window: Duration) -> bool {
        if window.is_zero() {
            return true;
        }
        {
            let guard = self.last_sent.read().expect("AlertDedupTable poisoned");
            if let Some(&prev) = guard.get(key)
                && now.saturating_sub(prev) < window
            {
                return false;
            }
        }
        let mut guard = self.last_sent.write().expect("AlertDedupTable poisoned");
        if let Some(&prev) = guard.get(key)
            && now.saturating_sub(prev) < window
        {
            return false;
        }
        guard.insert(key.to_owned(), now);
        true
    }
}

/// Point-in-time alert dispatcher statistics exposed via `GET /api/status`.
#[derive(Debug, Clone, Default, Serialize)]
pub struct AlertStatsSnapshot {
    pub enqueued: u64,
    pub sent: u64,
    pub deduplicated: u64,
    pub dropped: u64,
    pub errors: u64,
}

/// Reload-persistent atomic counters for `ai-alerts` stored in `StateStore`.
#[derive(Debug, Default)]
pub struct AlertStatsTable {
    enqueued: AtomicU64,
    sent: AtomicU64,
    deduplicated: AtomicU64,
    dropped: AtomicU64,
    errors: AtomicU64,
}

impl AlertStatsTable {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn snapshot(&self) -> AlertStatsSnapshot {
        AlertStatsSnapshot {
            enqueued: self.enqueued.load(Ordering::Relaxed),
            sent: self.sent.load(Ordering::Relaxed),
            deduplicated: self.deduplicated.load(Ordering::Relaxed),
            dropped: self.dropped.load(Ordering::Relaxed),
            errors: self.errors.load(Ordering::Relaxed),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum AlertTargetConfig {
    Slack {
        name: Option<String>,
        url: String,
        #[serde(default)]
        channel: Option<String>,
        #[serde(default)]
        username: Option<String>,
        #[serde(default)]
        events: Vec<AiAlertKind>,
        #[serde(default)]
        timeout_ms: Option<u64>,
    },
    Pagerduty {
        name: Option<String>,
        #[serde(default)]
        url: Option<String>,
        routing_key: String,
        #[serde(default)]
        events: Vec<AiAlertKind>,
        #[serde(default)]
        timeout_ms: Option<u64>,
    },
    Http {
        name: Option<String>,
        url: String,
        #[serde(default)]
        headers: BTreeMap<String, String>,
        #[serde(default)]
        signing_secret: Option<String>,
        #[serde(default)]
        events: Vec<AiAlertKind>,
        #[serde(default)]
        timeout_ms: Option<u64>,
    },
}

#[derive(Debug, Deserialize)]
#[serde(default)]
struct AiAlertsConfig {
    /// Default alert kinds enabled for targets that do not override `events`.
    #[serde(default = "default_alert_kinds")]
    events: Vec<AiAlertKind>,
    /// Deduplication cooldown per `(target, dedup_key)` in milliseconds (`0` disables dedup).
    #[serde(default = "default_dedup_window_ms")]
    dedup_window_ms: u64,
    /// Bounded non-blocking outbound dispatch queue capacity (default: `256`).
    #[serde(default = "default_queue_capacity")]
    queue_capacity: usize,
    /// Default outbound webhook HTTP timeout in milliseconds (default: `5000`).
    #[serde(default = "default_webhook_timeout_ms")]
    timeout_ms: u64,
    /// Logical source identifier included in alert payloads (default: `"shunt"`).
    #[serde(default = "default_source")]
    source: String,
    /// Configured outbound alert targets (`slack`, `pagerduty`, `http`).
    #[serde(default)]
    targets: Vec<AlertTargetConfig>,
}

impl Default for AiAlertsConfig {
    fn default() -> Self {
        Self {
            events: default_alert_kinds(),
            dedup_window_ms: default_dedup_window_ms(),
            queue_capacity: default_queue_capacity(),
            timeout_ms: default_webhook_timeout_ms(),
            source: default_source(),
            targets: Vec::new(),
        }
    }
}

#[derive(Debug, Clone)]
enum CompiledTargetKind {
    Slack {
        channel: Option<String>,
        username: Option<String>,
    },
    PagerDuty {
        routing_key: String,
    },
    Http {
        headers: Vec<(HeaderName, HeaderValue)>,
        signing_secret: Option<String>,
    },
}

#[derive(Debug, Clone)]
struct CompiledAlertTarget {
    name: String,
    uri: Uri,
    kind: CompiledTargetKind,
    events: Vec<AiAlertKind>,
    timeout: Duration,
}

impl CompiledAlertTarget {
    fn accepts(&self, kind: AiAlertKind) -> bool {
        self.events.contains(&kind)
    }
}

#[derive(Debug, Clone)]
struct QueuedAlert {
    target: CompiledAlertTarget,
    source: String,
    event: AiAlertEvent,
    request_id: u64,
    route_id: Option<String>,
    timestamp_unix_ms: u64,
}

/// Formats a Slack Incoming Webhook payload for `event`.
pub fn format_slack_alert_payload(
    source: &str,
    event: &AiAlertEvent,
    request_id: u64,
    route_id: Option<&str>,
    channel: Option<&str>,
    username: Option<&str>,
) -> Value {
    let icon = match event.severity {
        AiAlertSeverity::Critical => ":rotating_light:",
        AiAlertSeverity::Error => ":x:",
        AiAlertSeverity::Warning => ":warning:",
        AiAlertSeverity::Info => ":information_source:",
    };
    let headline = format!("{icon} [{source}] {}", event.title);
    let mut fields = vec![
        json!({ "type": "mrkdwn", "text": format!("*Event:*\n`{}`", event.kind.as_str()) }),
        json!({ "type": "mrkdwn", "text": format!("*Severity:*\n`{}`", event.severity.as_str()) }),
    ];
    if let Some(subj) = &event.subject {
        fields.push(json!({ "type": "mrkdwn", "text": format!("*Subject:*\n`{subj}`") }));
    }
    if let Some(provider) = &event.provider {
        fields.push(json!({ "type": "mrkdwn", "text": format!("*Provider:*\n`{provider}`") }));
    }
    if let Some(model) = &event.model {
        fields.push(json!({ "type": "mrkdwn", "text": format!("*Model:*\n`{model}`") }));
    }
    if let Some(route) = route_id {
        fields.push(json!({ "type": "mrkdwn", "text": format!("*Route:*\n`{route}`") }));
    }

    let mut payload = json!({
        "text": format!("{headline}: {}", event.message),
        "blocks": [
            {
                "type": "header",
                "text": { "type": "plain_text", "text": event.title }
            },
            {
                "type": "section",
                "text": { "type": "mrkdwn", "text": event.message }
            },
            {
                "type": "section",
                "fields": fields
            },
            {
                "type": "context",
                "elements": [
                    { "type": "mrkdwn", "text": format!("source=`{source}` request_id=`{request_id}`") }
                ]
            }
        ]
    });
    if let Some(obj) = payload.as_object_mut() {
        if let Some(ch) = channel {
            obj.insert("channel".to_owned(), Value::String(ch.to_owned()));
        }
        if let Some(user) = username {
            obj.insert("username".to_owned(), Value::String(user.to_owned()));
        }
    }
    payload
}

/// Formats a PagerDuty Events API v2 payload for `event`.
pub fn format_pagerduty_alert_payload(
    source: &str,
    routing_key: &str,
    event: &AiAlertEvent,
    request_id: u64,
    route_id: Option<&str>,
) -> Value {
    let pd_severity = match event.severity {
        AiAlertSeverity::Critical => "critical",
        AiAlertSeverity::Error => "error",
        AiAlertSeverity::Warning => "warning",
        AiAlertSeverity::Info => "info",
    };
    json!({
        "routing_key": routing_key,
        "event_action": "trigger",
        "dedup_key": format!("{}:{}", event.kind.as_str(), event.dedup_key),
        "payload": {
            "summary": format!("[{source}] {}: {}", event.title, event.message),
            "source": source,
            "severity": pd_severity,
            "component": route_id.unwrap_or("shunt-ai"),
            "group": event.team.as_deref().unwrap_or("default"),
            "class": event.kind.as_str(),
            "custom_details": {
                "request_id": request_id,
                "subject": event.subject,
                "provider": event.provider,
                "model": event.model,
                "key_id": event.key_id,
                "team": event.team,
                "details": event.details,
            }
        }
    })
}

/// Formats a canonical generic HTTP webhook JSON payload for `event`.
pub fn format_http_alert_payload(
    source: &str,
    event: &AiAlertEvent,
    request_id: u64,
    route_id: Option<&str>,
    timestamp_unix_ms: u64,
) -> Value {
    json!({
        "schema_version": 1,
        "source": source,
        "timestamp_unix_ms": timestamp_unix_ms,
        "request_id": request_id,
        "route_id": route_id,
        "event": event.kind.as_str(),
        "severity": event.severity.as_str(),
        "dedup_key": event.dedup_key,
        "title": event.title,
        "message": event.message,
        "subject": event.subject,
        "provider": event.provider,
        "model": event.model,
        "key_id": event.key_id,
        "team": event.team,
        "details": event.details,
    })
}

/// Factory for the `ai-alerts` plugin.
pub struct AiAlertsFactory {
    metrics: Arc<AiMetrics>,
}

impl AiAlertsFactory {
    pub fn new(metrics: Arc<AiMetrics>) -> Self {
        Self { metrics }
    }
}

impl PluginFactory for AiAlertsFactory {
    fn name(&self) -> &str {
        "ai-alerts"
    }

    fn build(
        &self,
        config: &PluginConfig,
        ctx: &BuildContext,
    ) -> Result<Arc<dyn HttpPlugin>, PluginBuildError> {
        let cfg: AiAlertsConfig = config.deserialize(self.name())?;
        if cfg.targets.is_empty() {
            return Err(PluginBuildError::BuildFailed {
                plugin: self.name().to_owned(),
                message: "`targets` must contain at least one alert destination".to_owned(),
            });
        }
        let default_timeout = Duration::from_millis(cfg.timeout_ms.max(100));
        let mut compiled_targets = Vec::with_capacity(cfg.targets.len());

        for (idx, raw) in cfg.targets.into_iter().enumerate() {
            match raw {
                AlertTargetConfig::Slack {
                    name,
                    url,
                    channel,
                    username,
                    events,
                    timeout_ms,
                } => {
                    let resolved_url =
                        resolve_env_secret(&url).map_err(|e| PluginBuildError::BuildFailed {
                            plugin: self.name().to_owned(),
                            message: format!("targets[{idx}].url: {e}"),
                        })?;
                    let uri = parse_http_uri(&resolved_url, self.name(), idx)?;
                    compiled_targets.push(CompiledAlertTarget {
                        name: name.unwrap_or_else(|| format!("slack-{idx}")),
                        uri,
                        kind: CompiledTargetKind::Slack { channel, username },
                        events: if events.is_empty() {
                            cfg.events.clone()
                        } else {
                            events
                        },
                        timeout: timeout_ms
                            .map(|ms| Duration::from_millis(ms.max(100)))
                            .unwrap_or(default_timeout),
                    });
                }
                AlertTargetConfig::Pagerduty {
                    name,
                    url,
                    routing_key,
                    events,
                    timeout_ms,
                } => {
                    let raw_url = url.as_deref().unwrap_or(DEFAULT_PAGERDUTY_URL);
                    let resolved_url =
                        resolve_env_secret(raw_url).map_err(|e| PluginBuildError::BuildFailed {
                            plugin: self.name().to_owned(),
                            message: format!("targets[{idx}].url: {e}"),
                        })?;
                    let uri = parse_http_uri(&resolved_url, self.name(), idx)?;
                    let resolved_key = resolve_env_secret(&routing_key).map_err(|e| {
                        PluginBuildError::BuildFailed {
                            plugin: self.name().to_owned(),
                            message: format!("targets[{idx}].routing_key: {e}"),
                        }
                    })?;
                    if resolved_key.trim().is_empty() {
                        return Err(PluginBuildError::BuildFailed {
                            plugin: self.name().to_owned(),
                            message: format!("targets[{idx}].routing_key cannot be empty"),
                        });
                    }
                    compiled_targets.push(CompiledAlertTarget {
                        name: name.unwrap_or_else(|| format!("pagerduty-{idx}")),
                        uri,
                        kind: CompiledTargetKind::PagerDuty {
                            routing_key: resolved_key,
                        },
                        events: if events.is_empty() {
                            cfg.events.clone()
                        } else {
                            events
                        },
                        timeout: timeout_ms
                            .map(|ms| Duration::from_millis(ms.max(100)))
                            .unwrap_or(default_timeout),
                    });
                }
                AlertTargetConfig::Http {
                    name,
                    url,
                    headers,
                    signing_secret,
                    events,
                    timeout_ms,
                } => {
                    let resolved_url =
                        resolve_env_secret(&url).map_err(|e| PluginBuildError::BuildFailed {
                            plugin: self.name().to_owned(),
                            message: format!("targets[{idx}].url: {e}"),
                        })?;
                    let uri = parse_http_uri(&resolved_url, self.name(), idx)?;
                    let mut parsed_headers = Vec::with_capacity(headers.len());
                    for (hk, hv) in headers {
                        let resolved_v =
                            resolve_env_secret(&hv).map_err(|e| PluginBuildError::BuildFailed {
                                plugin: self.name().to_owned(),
                                message: format!("targets[{idx}].headers.{hk}: {e}"),
                            })?;
                        let hname = HeaderName::from_bytes(hk.as_bytes()).map_err(|e| {
                            PluginBuildError::BuildFailed {
                                plugin: self.name().to_owned(),
                                message: format!("targets[{idx}].headers: invalid `{hk}`: {e}"),
                            }
                        })?;
                        let hval = HeaderValue::from_str(&resolved_v).map_err(|e| {
                            PluginBuildError::BuildFailed {
                                plugin: self.name().to_owned(),
                                message: format!("targets[{idx}].headers.{hk}: invalid value: {e}"),
                            }
                        })?;
                        parsed_headers.push((hname, hval));
                    }
                    let resolved_secret = match signing_secret {
                        Some(raw) => Some(resolve_env_secret(&raw).map_err(|e| {
                            PluginBuildError::BuildFailed {
                                plugin: self.name().to_owned(),
                                message: format!("targets[{idx}].signing_secret: {e}"),
                            }
                        })?),
                        None => None,
                    };
                    compiled_targets.push(CompiledAlertTarget {
                        name: name.unwrap_or_else(|| format!("http-{idx}")),
                        uri,
                        kind: CompiledTargetKind::Http {
                            headers: parsed_headers,
                            signing_secret: resolved_secret,
                        },
                        events: if events.is_empty() {
                            cfg.events.clone()
                        } else {
                            events
                        },
                        timeout: timeout_ms
                            .map(|ms| Duration::from_millis(ms.max(100)))
                            .unwrap_or(default_timeout),
                    });
                }
            }
        }

        let state = ctx.state_handle();
        let dedup = state.get_or_init("ai_alerts_dedup", AlertDedupTable::new);
        let stats = state.get_or_init("ai_alerts_stats", AlertStatsTable::new);
        let (tx, rx) = mpsc::channel(cfg.queue_capacity.max(1));

        Ok(Arc::new(AiAlertsPlugin {
            targets: compiled_targets,
            dedup_window: Duration::from_millis(cfg.dedup_window_ms),
            source: cfg.source,
            clock: ctx.clock(),
            http_client: ctx.http_client(),
            dedup,
            stats,
            metrics: Arc::clone(&self.metrics),
            tx,
            pending_rx: Mutex::new(Some(rx)),
        }))
    }
}

fn parse_http_uri(raw: &str, plugin: &str, idx: usize) -> Result<Uri, PluginBuildError> {
    let uri: Uri = raw.parse().map_err(|e| PluginBuildError::BuildFailed {
        plugin: plugin.to_owned(),
        message: format!("targets[{idx}].url `{raw}` is not a valid URI: {e}"),
    })?;
    let scheme = uri.scheme_str().unwrap_or("");
    if (scheme != "http" && scheme != "https") || uri.authority().is_none() {
        return Err(PluginBuildError::BuildFailed {
            plugin: plugin.to_owned(),
            message: format!("targets[{idx}].url `{raw}` must be an absolute http(s):// URI"),
        });
    }
    Ok(uri)
}

/// Non-blocking alert dispatcher plugin (`ai-alerts`).
pub struct AiAlertsPlugin {
    targets: Vec<CompiledAlertTarget>,
    dedup_window: Duration,
    source: String,
    clock: Arc<dyn Clock>,
    http_client: Option<Arc<dyn HttpClient>>,
    dedup: Arc<AlertDedupTable>,
    stats: Arc<AlertStatsTable>,
    metrics: Arc<AiMetrics>,
    tx: mpsc::Sender<QueuedAlert>,
    pending_rx: Mutex<Option<mpsc::Receiver<QueuedAlert>>>,
}

impl AiAlertsPlugin {
    fn ensure_worker_started(&self) {
        let Some(client) = self.http_client.as_ref().map(Arc::clone) else {
            return;
        };
        let Ok(handle) = tokio::runtime::Handle::try_current() else {
            return;
        };
        let rx = {
            let mut guard = self
                .pending_rx
                .lock()
                .expect("AiAlertsPlugin pending_rx poisoned");
            guard.take()
        };
        if let Some(rx) = rx {
            let stats = Arc::clone(&self.stats);
            let metrics = Arc::clone(&self.metrics);
            handle.spawn(run_alert_worker(client, rx, stats, metrics));
        }
    }
}

async fn run_alert_worker(
    client: Arc<dyn HttpClient>,
    mut rx: mpsc::Receiver<QueuedAlert>,
    stats: Arc<AlertStatsTable>,
    metrics: Arc<AiMetrics>,
) {
    while let Some(item) = rx.recv().await {
        let payload = match &item.target.kind {
            CompiledTargetKind::Slack { channel, username } => format_slack_alert_payload(
                &item.source,
                &item.event,
                item.request_id,
                item.route_id.as_deref(),
                channel.as_deref(),
                username.as_deref(),
            ),
            CompiledTargetKind::PagerDuty { routing_key } => format_pagerduty_alert_payload(
                &item.source,
                routing_key,
                &item.event,
                item.request_id,
                item.route_id.as_deref(),
            ),
            CompiledTargetKind::Http { .. } => format_http_alert_payload(
                &item.source,
                &item.event,
                item.request_id,
                item.route_id.as_deref(),
                item.timestamp_unix_ms,
            ),
        };

        let body_bytes = match serde_json::to_vec(&payload) {
            Ok(b) => b,
            Err(err) => {
                warn!(plugin = "ai-alerts", target = %item.target.name, error = %err, "failed to serialize alert payload");
                stats.errors.fetch_add(1, Ordering::Relaxed);
                metrics.record_alert(item.event.kind.as_str(), &item.target.name, "error");
                continue;
            }
        };

        let mut req = HttpRequest::post(item.target.uri.clone())
            .with_header(
                header::CONTENT_TYPE,
                HeaderValue::from_static("application/json"),
            )
            .with_timeout(item.target.timeout)
            .with_max_response_bytes(64 * 1024);

        if let CompiledTargetKind::Http {
            headers,
            signing_secret,
        } = &item.target.kind
        {
            for (k, v) in headers {
                req.headers.insert(k.clone(), v.clone());
            }
            if let Some(secret) = signing_secret {
                let sig = compute_hmac_sha256_hex(secret.as_bytes(), &body_bytes);
                if let Ok(hv) = HeaderValue::from_str(&format!("sha256={sig}")) {
                    req.headers
                        .insert(HeaderName::from_static("x-shunt-signature-256"), hv);
                }
            }
        }
        req.body = body_bytes.into();

        match client.send(req).await {
            Ok(resp) if resp.status.is_success() => {
                stats.sent.fetch_add(1, Ordering::Relaxed);
                metrics.record_alert(item.event.kind.as_str(), &item.target.name, "sent");
                debug!(
                    plugin = "ai-alerts",
                    target = %item.target.name,
                    event = item.event.kind.as_str(),
                    status = resp.status.as_u16(),
                    "dispatched AI alert webhook"
                );
            }
            Ok(resp) => {
                stats.errors.fetch_add(1, Ordering::Relaxed);
                metrics.record_alert(item.event.kind.as_str(), &item.target.name, "error");
                warn!(
                    plugin = "ai-alerts",
                    target = %item.target.name,
                    event = item.event.kind.as_str(),
                    status = resp.status.as_u16(),
                    "alert webhook returned non-2xx status"
                );
            }
            Err(err) => {
                stats.errors.fetch_add(1, Ordering::Relaxed);
                metrics.record_alert(item.event.kind.as_str(), &item.target.name, "error");
                warn!(
                    plugin = "ai-alerts",
                    target = %item.target.name,
                    event = item.event.kind.as_str(),
                    error = %err,
                    "alert webhook delivery failed"
                );
            }
        }
    }
}

impl HttpPlugin for AiAlertsPlugin {
    fn name(&self) -> &str {
        "ai-alerts"
    }

    fn hook_mask(&self) -> HookMask {
        HookMask::ON_COMPLETE
    }

    fn on_complete<'a>(
        &'a self,
        ctx: &'a RequestCtx,
        summary: &'a RequestSummary,
    ) -> HookResult<'a, ()> {
        let Some(bus) = ctx.get_ext::<AiAlertBus>() else {
            return HookResult::Ready(());
        };
        let events = bus.snapshot();
        if events.is_empty() {
            return HookResult::Ready(());
        }

        self.ensure_worker_started();
        let now = self.clock.now();
        let timestamp_unix_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis().min(u64::MAX as u128) as u64)
            .unwrap_or(0);

        for event in events {
            for target in &self.targets {
                if !target.accepts(event.kind) {
                    continue;
                }
                let dedup_id = format!(
                    "{}::{}::{}",
                    target.name,
                    event.kind.as_str(),
                    event.dedup_key
                );
                if !self.dedup.should_send(&dedup_id, now, self.dedup_window) {
                    self.stats.deduplicated.fetch_add(1, Ordering::Relaxed);
                    self.metrics
                        .record_alert(event.kind.as_str(), &target.name, "deduplicated");
                    continue;
                }
                let queued = QueuedAlert {
                    target: target.clone(),
                    source: self.source.clone(),
                    event: event.clone(),
                    request_id: summary.request_id,
                    route_id: summary.route_id.clone(),
                    timestamp_unix_ms,
                };
                match self.tx.try_send(queued) {
                    Ok(()) => {
                        self.stats.enqueued.fetch_add(1, Ordering::Relaxed);
                    }
                    Err(_) => {
                        self.stats.dropped.fetch_add(1, Ordering::Relaxed);
                        self.metrics
                            .record_alert(event.kind.as_str(), &target.name, "dropped");
                    }
                }
            }
        }

        HookResult::Ready(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dedup_table_suppresses_within_window_and_allows_after() {
        let dedup = AlertDedupTable::new();
        let win = Duration::from_secs(60);
        assert!(dedup.should_send("t1::k1", Duration::from_secs(10), win));
        assert!(!dedup.should_send("t1::k1", Duration::from_secs(40), win));
        assert!(dedup.should_send("t1::k1", Duration::from_secs(70), win));
        // Zero window disables deduplication.
        assert!(dedup.should_send("t1::k1", Duration::from_secs(70), Duration::ZERO));
    }

    #[test]
    fn hmac_sha256_produces_expected_digest() {
        // RFC 4231 test vector #2: key = "Jefe", data = "what do ya want for nothing?"
        let sig = compute_hmac_sha256_hex(b"Jefe", b"what do ya want for nothing?");
        assert_eq!(
            sig,
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
        );
    }

    #[test]
    fn formats_slack_pagerduty_and_http_payloads() {
        let ev = AiAlertEvent {
            kind: AiAlertKind::CircuitBreakerOpen,
            severity: AiAlertSeverity::Error,
            dedup_key: "openai::gpt-4o".to_owned(),
            title: "Provider circuit breaker opened".to_owned(),
            message: "Target openai::gpt-4o entered cooldown for 30000ms".to_owned(),
            subject: Some("openai::gpt-4o".to_owned()),
            provider: Some("openai".to_owned()),
            model: Some("gpt-4o".to_owned()),
            key_id: None,
            team: Some("platform".to_owned()),
            details: json!({ "status": 429, "cooldown_ms": 30000 }),
        };

        let slack = format_slack_alert_payload(
            "shunt",
            &ev,
            42,
            Some("ai"),
            Some("#ai-ops"),
            Some("shunt-bot"),
        );
        assert_eq!(slack["channel"], "#ai-ops");
        assert_eq!(slack["username"], "shunt-bot");
        assert!(slack["text"].as_str().unwrap().contains("30000ms"));

        let pd = format_pagerduty_alert_payload("shunt", "rk_test_123", &ev, 42, Some("ai"));
        assert_eq!(pd["routing_key"], "rk_test_123");
        assert_eq!(pd["event_action"], "trigger");
        assert_eq!(pd["payload"]["severity"], "error");
        assert_eq!(pd["dedup_key"], "circuit_breaker_open:openai::gpt-4o");

        let http = format_http_alert_payload("shunt", &ev, 42, Some("ai"), 1_700_000_000_000);
        assert_eq!(http["event"], "circuit_breaker_open");
        assert_eq!(http["severity"], "error");
        assert_eq!(http["request_id"], 42);
    }
}
