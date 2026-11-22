use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::sync::{Arc, RwLock};
use std::time::Instant;

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use shunt_plugin_sdk::{
    BufferedResponse, BuildContext, Bytes, Clock, Flow, HeaderName, HeaderValue, HookMask,
    HookResult, HttpPlugin, Method, PluginBuildError, PluginConfig, PluginFactory, RequestCtx,
    RequestHead, RequestSummary, ResponseHead, SpanHandle, StatusCode, StreamFlow, header,
};
use tracing::info;

use crate::cache::AiCacheStatus;
use crate::generation::{AiGenerationRecord, AiGenerationStore, AiRecordedCost};
use crate::multimodal::extract_query_param;
use crate::pricing::{PricingCatalog, nano_usd_to_usd};
use crate::sse::SseParser;
use crate::types::{
    AiEndpointKind, AiFailoverHistory, AiKeyPolicy, AiRequestMeta, AiUsage, AiUsageReport,
    DetectedEndpoint, openai_error_response,
};

const DEFAULT_MAX_JSON_INSPECT_BYTES: usize = 4 * 1024 * 1024; // 4 MiB
const DEFAULT_GENERATION_STORE_CAPACITY: usize = 4096;

const AI_LATENCY_BUCKETS: &[f64] = &[0.05, 0.1, 0.25, 0.5, 1.0, 2.0, 5.0, 10.0, 30.0, 60.0];

/// Optional callback invoked with every completed [`AiUsageReport`] (useful for tests
/// or custom telemetry pipelines).
pub type UsageSink = Arc<dyn Fn(&AiUsageReport) + Send + Sync>;

#[derive(Debug, Clone)]
struct HistogramState {
    buckets: Vec<u64>,
    sum: f64,
    count: u64,
}

impl Default for HistogramState {
    fn default() -> Self {
        Self {
            buckets: vec![0; AI_LATENCY_BUCKETS.len() + 1],
            sum: 0.0,
            count: 0,
        }
    }
}

impl HistogramState {
    fn observe(&mut self, value_secs: f64) {
        self.sum += value_secs;
        self.count += 1;
        for (idx, &bound) in AI_LATENCY_BUCKETS.iter().enumerate() {
            if value_secs <= bound {
                self.buckets[idx] += 1;
            }
        }
        *self.buckets.last_mut().unwrap() += 1;
    }
}

#[derive(Debug, Default)]
struct AiMetricsData {
    /// (provider, model, stream, status) -> count
    requests_total: BTreeMap<(String, String, bool, u16), u64>,
    /// (provider, model, kind="prompt"|"completion") -> tokens
    tokens_total: BTreeMap<(String, String, &'static str), u64>,
    /// (provider, model, key_id, team) -> nano-USD spend
    cost_nano_usd_total: BTreeMap<(String, String, String, String), u64>,
    /// (from_provider, to_provider, model) -> count
    failovers_total: BTreeMap<(String, String, String), u64>,
    /// (provider, model, stream) -> TTFT histogram
    ttft_seconds: BTreeMap<(String, String, bool), HistogramState>,
    /// (provider, model, stream) -> total duration histogram
    duration_seconds: BTreeMap<(String, String, bool), HistogramState>,
    /// (status="hit"|"miss"|"bypass", endpoint, model) -> count
    cache_requests_total: BTreeMap<(&'static str, String, String), u64>,
    /// (stage, action, rule) -> count
    guardrail_evaluations_total: BTreeMap<(String, String, String), u64>,
    /// (guardrail, fail_open) -> count
    guardrail_errors_total: BTreeMap<(String, bool), u64>,
    /// (sink, result="written"|"dropped"|"error") -> count
    audit_events_total: BTreeMap<(String, &'static str), u64>,
    /// (event, target, result="sent"|"deduplicated"|"dropped"|"error") -> count
    alerts_total: BTreeMap<(String, String, &'static str), u64>,
}

/// Point-in-time aggregate counters from [`AiMetrics`] (useful for programmatic checks/tests).
#[derive(Debug, Clone, Default, Serialize)]
pub struct AiMetricsSnapshot {
    pub total_requests: u64,
    pub total_prompt_tokens: u64,
    pub total_completion_tokens: u64,
    pub total_failovers: u64,
    pub total_cost_usd: f64,
    pub total_cache_hits: u64,
    pub total_cache_misses: u64,
}

/// Per-(provider, model) rollup rendered for read-only Admin Inspector dashboards.
#[derive(Debug, Clone, Default, Serialize)]
pub struct AiModelBreakdown {
    pub provider: String,
    pub model: String,
    pub requests: u64,
    pub error_requests: u64,
    pub prompt_tokens: u64,
    pub completion_tokens: u64,
    pub cost_usd: f64,
    pub avg_ttft_ms: Option<f64>,
    pub avg_duration_ms: Option<f64>,
}

/// Detailed point-in-time AI usage summary for read-only inspection APIs.
#[derive(Debug, Clone, Default, Serialize)]
pub struct AiDetailedMetricsSnapshot {
    pub totals: AiMetricsSnapshot,
    pub models: Vec<AiModelBreakdown>,
}

/// Thread-safe Prometheus-compatible AI metrics store updated by [`AiUsageTrackerPlugin`]
/// and exposed via the Admin API (`GET /metrics`).
#[derive(Debug, Default)]
pub struct AiMetrics {
    inner: RwLock<AiMetricsData>,
}

impl AiMetrics {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn record(&self, report: &AiUsageReport) {
        let mut data = self.inner.write().expect("AiMetrics lock poisoned");
        let status = report.status.unwrap_or(0);

        *data
            .requests_total
            .entry((
                report.provider.clone(),
                report.served_model.clone(),
                report.stream,
                status,
            ))
            .or_insert(0) += 1;

        if let Some(prompt) = report.prompt_tokens {
            *data
                .tokens_total
                .entry((
                    report.provider.clone(),
                    report.served_model.clone(),
                    "prompt",
                ))
                .or_insert(0) += prompt;
        }
        if let Some(completion) = report.completion_tokens {
            *data
                .tokens_total
                .entry((
                    report.provider.clone(),
                    report.served_model.clone(),
                    "completion",
                ))
                .or_insert(0) += completion;
        }
        if let Some(cached_read) = report.cached_prompt_tokens
            && cached_read > 0
        {
            *data
                .tokens_total
                .entry((
                    report.provider.clone(),
                    report.served_model.clone(),
                    "cache_read",
                ))
                .or_insert(0) += cached_read;
        }
        if let Some(cache_write) = report.cache_creation_prompt_tokens
            && cache_write > 0
        {
            *data
                .tokens_total
                .entry((
                    report.provider.clone(),
                    report.served_model.clone(),
                    "cache_write",
                ))
                .or_insert(0) += cache_write;
        }
        if let Some(reasoning) = report.reasoning_tokens
            && reasoning > 0
        {
            *data
                .tokens_total
                .entry((
                    report.provider.clone(),
                    report.served_model.clone(),
                    "reasoning",
                ))
                .or_insert(0) += reasoning;
        }

        for ev in &report.failover_events {
            *data
                .failovers_total
                .entry((
                    ev.provider.clone(),
                    report.provider.clone(),
                    report.requested_model.clone(),
                ))
                .or_insert(0) += 1;
        }

        if let Some(ttft) = report.ttft {
            data.ttft_seconds
                .entry((
                    report.provider.clone(),
                    report.served_model.clone(),
                    report.stream,
                ))
                .or_default()
                .observe(ttft.as_secs_f64());
        }

        data.duration_seconds
            .entry((
                report.provider.clone(),
                report.served_model.clone(),
                report.stream,
            ))
            .or_default()
            .observe(report.total_duration.as_secs_f64());
    }

    /// Records attributed LLM spend (in exact integer nano-USD) for Prometheus `shunt_ai_cost_usd_total`.
    pub fn record_cost(
        &self,
        provider: &str,
        model: &str,
        key_id: &str,
        team: &str,
        cost_nano_usd: u64,
    ) {
        if cost_nano_usd == 0 {
            return;
        }
        let mut data = self.inner.write().expect("AiMetrics lock poisoned");
        let entry = data
            .cost_nano_usd_total
            .entry((
                provider.to_owned(),
                model.to_owned(),
                key_id.to_owned(),
                team.to_owned(),
            ))
            .or_insert(0);
        *entry = entry.saturating_add(cost_nano_usd);
    }

    /// Records an AI response cache lookup disposition (`"hit"`, `"miss"`, or `"bypass"`).
    pub fn record_cache(&self, status: &'static str, endpoint: &str, model: &str) {
        let mut data = self.inner.write().expect("AiMetrics lock poisoned");
        *data
            .cache_requests_total
            .entry((status, endpoint.to_owned(), model.to_owned()))
            .or_insert(0) += 1;
    }

    /// Records a guardrail evaluation outcome (`stage`, `action`, `rule`).
    pub fn record_guardrail(&self, stage: &str, action: &str, rule: &str) {
        let mut data = self.inner.write().expect("AiMetrics lock poisoned");
        *data
            .guardrail_evaluations_total
            .entry((stage.to_owned(), action.to_owned(), rule.to_owned()))
            .or_insert(0) += 1;
    }

    /// Records an external guardrail callout error (`guardrail` name and whether `fail_open` applied).
    pub fn record_guardrail_error(&self, guardrail: &str, fail_open: bool) {
        let mut data = self.inner.write().expect("AiMetrics lock poisoned");
        *data
            .guardrail_errors_total
            .entry((guardrail.to_owned(), fail_open))
            .or_insert(0) += 1;
    }

    /// Records an audit sink delivery result (`"written"`, `"dropped"`, or `"error"`).
    pub fn record_audit(&self, sink: &str, result: &'static str) {
        let mut data = self.inner.write().expect("AiMetrics lock poisoned");
        *data
            .audit_events_total
            .entry((sink.to_owned(), result))
            .or_insert(0) += 1;
    }

    /// Records an alert webhook dispatch outcome (`"sent"`, `"deduplicated"`, `"dropped"`, or `"error"`).
    pub fn record_alert(&self, event: &str, target: &str, result: &'static str) {
        let mut data = self.inner.write().expect("AiMetrics lock poisoned");
        *data
            .alerts_total
            .entry((event.to_owned(), target.to_owned(), result))
            .or_insert(0) += 1;
    }

    pub fn snapshot(&self) -> AiMetricsSnapshot {
        let data = self.inner.read().expect("AiMetrics lock poisoned");
        let total_requests = data.requests_total.values().copied().sum();
        let total_prompt_tokens = data
            .tokens_total
            .iter()
            .filter(|((_, _, k), _)| *k == "prompt")
            .map(|(_, &v)| v)
            .sum();
        let total_completion_tokens = data
            .tokens_total
            .iter()
            .filter(|((_, _, k), _)| *k == "completion")
            .map(|(_, &v)| v)
            .sum();
        let total_failovers = data.failovers_total.values().copied().sum();
        let total_cost_nano: u64 = data
            .cost_nano_usd_total
            .values()
            .copied()
            .fold(0u64, u64::saturating_add);
        let total_cache_hits = data
            .cache_requests_total
            .iter()
            .filter(|((status, _, _), _)| {
                matches!(*status, "hit" | "stream_hit" | "coalesced" | "semantic_hit")
            })
            .map(|(_, &v)| v)
            .sum();
        let total_cache_misses = data
            .cache_requests_total
            .iter()
            .filter(|((status, _, _), _)| *status == "miss")
            .map(|(_, &v)| v)
            .sum();
        AiMetricsSnapshot {
            total_requests,
            total_prompt_tokens,
            total_completion_tokens,
            total_failovers,
            total_cost_usd: nano_usd_to_usd(total_cost_nano),
            total_cache_hits,
            total_cache_misses,
        }
    }

    /// Returns aggregate totals plus per-(provider, model) breakdowns for Admin Inspector APIs.
    pub fn detailed_snapshot(&self) -> AiDetailedMetricsSnapshot {
        let data = self.inner.read().expect("AiMetrics lock poisoned");

        let total_requests = data.requests_total.values().copied().sum();
        let total_prompt_tokens = data
            .tokens_total
            .iter()
            .filter(|((_, _, k), _)| *k == "prompt")
            .map(|(_, &v)| v)
            .sum();
        let total_completion_tokens = data
            .tokens_total
            .iter()
            .filter(|((_, _, k), _)| *k == "completion")
            .map(|(_, &v)| v)
            .sum();
        let total_failovers = data.failovers_total.values().copied().sum();
        let total_cost_nano: u64 = data
            .cost_nano_usd_total
            .values()
            .copied()
            .fold(0u64, u64::saturating_add);
        let total_cache_hits = data
            .cache_requests_total
            .iter()
            .filter(|((status, _, _), _)| {
                matches!(*status, "hit" | "stream_hit" | "coalesced" | "semantic_hit")
            })
            .map(|(_, &v)| v)
            .sum();
        let total_cache_misses = data
            .cache_requests_total
            .iter()
            .filter(|((status, _, _), _)| *status == "miss")
            .map(|(_, &v)| v)
            .sum();

        #[derive(Default)]
        struct Accum {
            requests: u64,
            error_requests: u64,
            prompt_tokens: u64,
            completion_tokens: u64,
            cost_nano: u64,
            ttft_sum_secs: f64,
            ttft_count: u64,
            dur_sum_secs: f64,
            dur_count: u64,
        }

        let mut by_model: BTreeMap<(String, String), Accum> = BTreeMap::new();
        for ((provider, model, _stream, status), &count) in &data.requests_total {
            let entry = by_model
                .entry((provider.clone(), model.clone()))
                .or_default();
            entry.requests += count;
            if *status == 0 || *status >= 400 {
                entry.error_requests += count;
            }
        }
        for ((provider, model, kind), &count) in &data.tokens_total {
            let entry = by_model
                .entry((provider.clone(), model.clone()))
                .or_default();
            if *kind == "prompt" {
                entry.prompt_tokens += count;
            } else if *kind == "completion" {
                entry.completion_tokens += count;
            }
        }
        for ((provider, model, _key, _team), &nano) in &data.cost_nano_usd_total {
            let entry = by_model
                .entry((provider.clone(), model.clone()))
                .or_default();
            entry.cost_nano = entry.cost_nano.saturating_add(nano);
        }
        for ((provider, model, _stream), hist) in &data.ttft_seconds {
            let entry = by_model
                .entry((provider.clone(), model.clone()))
                .or_default();
            entry.ttft_sum_secs += hist.sum;
            entry.ttft_count += hist.count;
        }
        for ((provider, model, _stream), hist) in &data.duration_seconds {
            let entry = by_model
                .entry((provider.clone(), model.clone()))
                .or_default();
            entry.dur_sum_secs += hist.sum;
            entry.dur_count += hist.count;
        }

        let mut models: Vec<AiModelBreakdown> = by_model
            .into_iter()
            .map(|((provider, model), a)| AiModelBreakdown {
                provider,
                model,
                requests: a.requests,
                error_requests: a.error_requests,
                prompt_tokens: a.prompt_tokens,
                completion_tokens: a.completion_tokens,
                cost_usd: nano_usd_to_usd(a.cost_nano),
                avg_ttft_ms: (a.ttft_count > 0)
                    .then(|| (a.ttft_sum_secs / a.ttft_count as f64) * 1000.0),
                avg_duration_ms: (a.dur_count > 0)
                    .then(|| (a.dur_sum_secs / a.dur_count as f64) * 1000.0),
            })
            .collect();
        models.sort_by(|a, b| {
            b.requests
                .cmp(&a.requests)
                .then_with(|| a.provider.cmp(&b.provider))
                .then_with(|| a.model.cmp(&b.model))
        });

        AiDetailedMetricsSnapshot {
            totals: AiMetricsSnapshot {
                total_requests,
                total_prompt_tokens,
                total_completion_tokens,
                total_failovers,
                total_cost_usd: nano_usd_to_usd(total_cost_nano),
                total_cache_hits,
                total_cache_misses,
            },
            models,
        }
    }

    /// Renders collected AI metrics in Prometheus exposition text format (v0.0.4).
    /// Returns an empty string if no AI requests, cache events, or costs have been observed yet.
    pub fn render_prometheus(&self) -> String {
        let data = self.inner.read().expect("AiMetrics lock poisoned");
        if data.requests_total.is_empty()
            && data.cost_nano_usd_total.is_empty()
            && data.cache_requests_total.is_empty()
            && data.guardrail_evaluations_total.is_empty()
            && data.guardrail_errors_total.is_empty()
            && data.audit_events_total.is_empty()
            && data.alerts_total.is_empty()
        {
            return String::new();
        }

        let mut out = String::with_capacity(2048);

        if !data.requests_total.is_empty() {
            out.push_str("# HELP shunt_ai_requests_total Total AI gateway requests handled.\n");
            out.push_str("# TYPE shunt_ai_requests_total counter\n");
            for ((provider, model, stream, status), count) in &data.requests_total {
                let _ = writeln!(
                    out,
                    "shunt_ai_requests_total{{provider=\"{}\",model=\"{}\",stream=\"{}\",status=\"{}\"}} {}",
                    escape_label(provider),
                    escape_label(model),
                    stream,
                    status,
                    count
                );
            }
        }

        if !data.tokens_total.is_empty() {
            out.push_str("# HELP shunt_ai_tokens_total Total LLM input/output tokens accounted.\n");
            out.push_str("# TYPE shunt_ai_tokens_total counter\n");
            for ((provider, model, kind), count) in &data.tokens_total {
                let _ = writeln!(
                    out,
                    "shunt_ai_tokens_total{{provider=\"{}\",model=\"{}\",kind=\"{}\"}} {}",
                    escape_label(provider),
                    escape_label(model),
                    kind,
                    count
                );
            }
        }

        if !data.cost_nano_usd_total.is_empty() {
            out.push_str("# HELP shunt_ai_cost_usd_total Total attributed LLM spend in USD.\n");
            out.push_str("# TYPE shunt_ai_cost_usd_total counter\n");
            for ((provider, model, key_id, team), nano) in &data.cost_nano_usd_total {
                let _ = writeln!(
                    out,
                    "shunt_ai_cost_usd_total{{provider=\"{}\",model=\"{}\",key=\"{}\",team=\"{}\"}} {:.9}",
                    escape_label(provider),
                    escape_label(model),
                    escape_label(key_id),
                    escape_label(team),
                    nano_usd_to_usd(*nano)
                );
            }
        }

        if !data.failovers_total.is_empty() {
            out.push_str("# HELP shunt_ai_failovers_total Total provider failover events.\n");
            out.push_str("# TYPE shunt_ai_failovers_total counter\n");
            for ((from_p, to_p, model), count) in &data.failovers_total {
                let _ = writeln!(
                    out,
                    "shunt_ai_failovers_total{{from_provider=\"{}\",to_provider=\"{}\",model=\"{}\"}} {}",
                    escape_label(from_p),
                    escape_label(to_p),
                    escape_label(model),
                    count
                );
            }
        }

        if !data.ttft_seconds.is_empty() {
            out.push_str("# HELP shunt_ai_ttft_seconds Time to first token (TTFT) in seconds.\n");
            out.push_str("# TYPE shunt_ai_ttft_seconds histogram\n");
            for ((provider, model, stream), hist) in &data.ttft_seconds {
                render_ai_histogram(
                    &mut out,
                    "shunt_ai_ttft_seconds",
                    provider,
                    model,
                    *stream,
                    hist,
                );
            }
        }

        if !data.duration_seconds.is_empty() {
            out.push_str(
                "# HELP shunt_ai_request_duration_seconds Total AI request duration in seconds.\n",
            );
            out.push_str("# TYPE shunt_ai_request_duration_seconds histogram\n");
            for ((provider, model, stream), hist) in &data.duration_seconds {
                render_ai_histogram(
                    &mut out,
                    "shunt_ai_request_duration_seconds",
                    provider,
                    model,
                    *stream,
                    hist,
                );
            }
        }

        if !data.cache_requests_total.is_empty() {
            out.push_str(
                "# HELP shunt_ai_cache_requests_total Total AI response cache lookups by status.\n",
            );
            out.push_str("# TYPE shunt_ai_cache_requests_total counter\n");
            for ((status, endpoint, model), count) in &data.cache_requests_total {
                let _ = writeln!(
                    out,
                    "shunt_ai_cache_requests_total{{status=\"{}\",endpoint=\"{}\",model=\"{}\"}} {}",
                    status,
                    escape_label(endpoint),
                    escape_label(model),
                    count
                );
            }
        }

        if !data.guardrail_evaluations_total.is_empty() {
            out.push_str(
                "# HELP shunt_ai_guardrail_evaluations_total Total AI guardrail evaluations by stage, action, and rule.\n",
            );
            out.push_str("# TYPE shunt_ai_guardrail_evaluations_total counter\n");
            for ((stage, action, rule), count) in &data.guardrail_evaluations_total {
                let _ = writeln!(
                    out,
                    "shunt_ai_guardrail_evaluations_total{{stage=\"{}\",action=\"{}\",rule=\"{}\"}} {}",
                    escape_label(stage),
                    escape_label(action),
                    escape_label(rule),
                    count
                );
            }
        }

        if !data.guardrail_errors_total.is_empty() {
            out.push_str(
                "# HELP shunt_ai_guardrail_errors_total Total external AI guardrail callout errors.\n",
            );
            out.push_str("# TYPE shunt_ai_guardrail_errors_total counter\n");
            for ((guardrail, fail_open), count) in &data.guardrail_errors_total {
                let _ = writeln!(
                    out,
                    "shunt_ai_guardrail_errors_total{{guardrail=\"{}\",fail_open=\"{}\"}} {}",
                    escape_label(guardrail),
                    fail_open,
                    count
                );
            }
        }

        if !data.audit_events_total.is_empty() {
            out.push_str(
                "# HELP shunt_ai_audit_events_total Total AI prompt/completion audit events processed by sink.\n",
            );
            out.push_str("# TYPE shunt_ai_audit_events_total counter\n");
            for ((sink, result), count) in &data.audit_events_total {
                let _ = writeln!(
                    out,
                    "shunt_ai_audit_events_total{{sink=\"{}\",result=\"{}\"}} {}",
                    escape_label(sink),
                    result,
                    count
                );
            }
        }

        if !data.alerts_total.is_empty() {
            out.push_str(
                "# HELP shunt_ai_alerts_total Total AI operational alert webhook events by kind, target, and result.\n",
            );
            out.push_str("# TYPE shunt_ai_alerts_total counter\n");
            for ((event, target, result), count) in &data.alerts_total {
                let _ = writeln!(
                    out,
                    "shunt_ai_alerts_total{{event=\"{}\",target=\"{}\",result=\"{}\"}} {}",
                    escape_label(event),
                    escape_label(target),
                    result,
                    count
                );
            }
        }

        out
    }
}

fn render_ai_histogram(
    out: &mut String,
    metric: &str,
    provider: &str,
    model: &str,
    stream: bool,
    hist: &HistogramState,
) {
    let p = escape_label(provider);
    let m = escape_label(model);
    for (idx, &bound) in AI_LATENCY_BUCKETS.iter().enumerate() {
        let _ = writeln!(
            out,
            "{metric}_bucket{{provider=\"{p}\",model=\"{m}\",stream=\"{stream}\",le=\"{bound}\"}} {}",
            hist.buckets[idx]
        );
    }
    let _ = writeln!(
        out,
        "{metric}_bucket{{provider=\"{p}\",model=\"{m}\",stream=\"{stream}\",le=\"+Inf\"}} {}",
        hist.buckets[AI_LATENCY_BUCKETS.len()]
    );
    let _ = writeln!(
        out,
        "{metric}_sum{{provider=\"{p}\",model=\"{m}\",stream=\"{stream}\"}} {:.6}",
        hist.sum
    );
    let _ = writeln!(
        out,
        "{metric}_count{{provider=\"{p}\",model=\"{m}\",stream=\"{stream}\"}} {}",
        hist.count
    );
}

fn escape_label(s: &str) -> String {
    s.replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
}

#[derive(Debug, Deserialize)]
#[serde(default)]
struct AiUsageTrackerConfig {
    /// Emit a structured `tracing::info!` log line per completed AI request (default: true).
    log_usage: bool,
    /// Safety cap (bytes) for inspecting non-streaming JSON response bodies (default: 4 MiB).
    max_json_inspect_bytes: usize,
    /// Bounded capacity of the reload-persistent `AiGenerationStore` backing `GET /v1/generation?id=...`
    /// (default: `4096`; set to `0` to disable generation storage).
    generation_store_capacity: usize,
    /// Serve `GET /v1/generation?id=...` directly from `on_request_headers` (default: true).
    serve_generation_endpoint: bool,
    /// Attach `x-shunt-generation-id: gen-<request_id>` on upstream AI responses (default: true).
    emit_generation_id_header: bool,
}

impl Default for AiUsageTrackerConfig {
    fn default() -> Self {
        Self {
            log_usage: true,
            max_json_inspect_bytes: DEFAULT_MAX_JSON_INSPECT_BYTES,
            generation_store_capacity: DEFAULT_GENERATION_STORE_CAPACITY,
            serve_generation_endpoint: true,
            emit_generation_id_header: true,
        }
    }
}

#[derive(Debug, Clone)]
enum UsageCollectorState {
    Sse(SseParser),
    Json { buf: Vec<u8>, overflowed: bool },
}

/// Factory for the `ai-usage-tracker` plugin.
pub struct AiUsageTrackerFactory {
    metrics: Arc<AiMetrics>,
    sink: Option<UsageSink>,
}

impl AiUsageTrackerFactory {
    pub fn new(metrics: Arc<AiMetrics>) -> Self {
        Self {
            metrics,
            sink: None,
        }
    }

    pub fn with_sink(mut self, sink: UsageSink) -> Self {
        self.sink = Some(sink);
        self
    }
}

impl PluginFactory for AiUsageTrackerFactory {
    fn name(&self) -> &str {
        "ai-usage-tracker"
    }

    fn build(
        &self,
        config: &PluginConfig,
        ctx: &BuildContext,
    ) -> Result<Arc<dyn HttpPlugin>, PluginBuildError> {
        let cfg: AiUsageTrackerConfig = config.deserialize(self.name())?;
        let generation_store = if cfg.generation_store_capacity > 0 {
            Some(
                ctx.state_handle()
                    .get_or_init("ai_generation_store", AiGenerationStore::new),
            )
        } else {
            None
        };
        let pricing_catalog = PricingCatalog::new(std::collections::HashMap::new(), true, None)
            .expect("built-in pricing catalog is valid");

        Ok(Arc::new(AiUsageTrackerPlugin {
            metrics: Arc::clone(&self.metrics),
            sink: self.sink.clone(),
            log_usage: cfg.log_usage,
            max_json_inspect_bytes: cfg.max_json_inspect_bytes.max(1024),
            generation_store,
            generation_store_capacity: cfg.generation_store_capacity,
            serve_generation_endpoint: cfg.serve_generation_endpoint,
            emit_generation_id_header: cfg.emit_generation_id_header,
            clock: ctx.clock(),
            pricing_catalog,
        }))
    }
}

/// Inspects non-streaming JSON and streaming SSE responses (both OpenAI and Anthropic
/// formats) to record token usage, TTFT, and duration into `ctx.extensions`, [`AiMetrics`],
/// [`AiGenerationStore`] (`GET /v1/generation?id=...`), and structured completion logs.
pub struct AiUsageTrackerPlugin {
    metrics: Arc<AiMetrics>,
    sink: Option<UsageSink>,
    log_usage: bool,
    max_json_inspect_bytes: usize,
    generation_store: Option<Arc<AiGenerationStore>>,
    generation_store_capacity: usize,
    serve_generation_endpoint: bool,
    emit_generation_id_header: bool,
    clock: Arc<dyn Clock>,
    pricing_catalog: PricingCatalog,
}

impl HttpPlugin for AiUsageTrackerPlugin {
    fn name(&self) -> &str {
        "ai-usage-tracker"
    }

    fn hook_mask(&self) -> HookMask {
        let mut mask =
            HookMask::ON_RESPONSE_HEADERS | HookMask::RESPONSE_BODY_STREAM | HookMask::ON_COMPLETE;
        if self.serve_generation_endpoint && self.generation_store.is_some() {
            mask |= HookMask::ON_REQUEST_HEADERS;
        }
        mask
    }

    fn on_request_headers<'a>(
        &'a self,
        ctx: &'a mut RequestCtx,
        req: &'a mut RequestHead,
    ) -> HookResult<'a, Flow> {
        if !self.serve_generation_endpoint || req.method != Method::GET {
            return HookResult::Ready(Flow::Continue);
        }
        let Some(store) = &self.generation_store else {
            return HookResult::Ready(Flow::Continue);
        };
        let raw_path = req.uri.path();
        let path = if raw_path.len() > 1 {
            raw_path.trim_end_matches('/')
        } else {
            raw_path
        };
        if path != "/v1/generation" && path != "/generation" {
            return HookResult::Ready(Flow::Continue);
        }

        ctx.insert_ext(DetectedEndpoint(AiEndpointKind::GenerationRetrieve));

        let Some(gen_id) = extract_query_param(req.uri.query(), "id") else {
            return HookResult::Ready(Flow::Respond(openai_error_response(
                StatusCode::BAD_REQUEST,
                "invalid_request_error",
                Some("missing_generation_id"),
                "Query parameter `id` is required (e.g., `GET /v1/generation?id=gen-1`)",
            )));
        };

        let Some(record) = store.get(&gen_id) else {
            return HookResult::Ready(Flow::Respond(openai_error_response(
                StatusCode::NOT_FOUND,
                "invalid_request_error",
                Some("generation_not_found"),
                &format!("Generation `{gen_id}` was not found"),
            )));
        };

        // Strict virtual-key tenant isolation: callers with an authenticated key may only
        // inspect generations belonging to that key.
        if let Some(policy) = ctx.get_ext::<AiKeyPolicy>()
            && record.key_id.as_deref() != Some(policy.key_id.as_str())
        {
            return HookResult::Ready(Flow::Respond(openai_error_response(
                StatusCode::FORBIDDEN,
                "permission_error",
                Some("generation_not_allowed"),
                &format!(
                    "Virtual key `{}` is not allowed to inspect generation `{gen_id}`",
                    policy.key_id
                ),
            )));
        }

        let payload = json!({ "data": *record });
        let bytes = serde_json::to_vec(&payload).unwrap_or_default();
        HookResult::Ready(Flow::Respond(BufferedResponse::json(StatusCode::OK, bytes)))
    }

    fn on_response_headers<'a>(
        &'a self,
        ctx: &'a mut RequestCtx,
        res: &'a mut ResponseHead,
    ) -> HookResult<'a, Flow> {
        if self.emit_generation_id_header
            && self.generation_store.is_some()
            && ctx.get_ext::<AiRequestMeta>().is_some()
            && let Ok(hv) = HeaderValue::from_str(&format!("gen-{}", ctx.request_id))
        {
            res.headers
                .insert(HeaderName::from_static("x-shunt-generation-id"), hv);
        }

        let ct_lower = res
            .headers
            .get(header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .map(str::to_ascii_lowercase)
            .unwrap_or_default();
        let is_sse = ct_lower.contains("text/event-stream");
        let is_binary_media = ct_lower.starts_with("audio/")
            || ct_lower.starts_with("image/")
            || ct_lower.starts_with("video/")
            || ct_lower.contains("application/octet-stream");

        let provider = ctx
            .get_ext::<AiRequestMeta>()
            .and_then(AiRequestMeta::active_target)
            .map(|t| t.provider.clone());

        if !is_binary_media {
            let collector = if is_sse {
                UsageCollectorState::Sse(SseParser::new())
            } else {
                UsageCollectorState::Json {
                    buf: Vec::new(),
                    overflowed: false,
                }
            };
            ctx.insert_ext(collector);
        }

        ctx.insert_ext(AiUsage {
            provider,
            ..AiUsage::default()
        });

        HookResult::Ready(Flow::Continue)
    }

    fn on_response_body_chunk<'a>(
        &'a self,
        ctx: &'a mut RequestCtx,
        chunk: &'a mut Bytes,
        end_of_stream: bool,
    ) -> HookResult<'a, StreamFlow> {
        let Some(mut collector) = ctx.remove_ext::<UsageCollectorState>() else {
            return HookResult::Ready(StreamFlow::Continue);
        };

        let mut usage = ctx.remove_ext::<AiUsage>().unwrap_or_default();

        match &mut collector {
            UsageCollectorState::Sse(parser) => {
                if !chunk.is_empty() {
                    usage.chunk_count += 1;
                    let events = parser.push(chunk);
                    for ev in events {
                        inspect_sse_event_data(&ev.data, &mut usage);
                    }
                }
                if end_of_stream {
                    let events = parser.finish();
                    for ev in events {
                        inspect_sse_event_data(&ev.data, &mut usage);
                    }
                }
            }
            UsageCollectorState::Json { buf, overflowed } => {
                if !chunk.is_empty() && !*overflowed {
                    if buf.len().saturating_add(chunk.len()) <= self.max_json_inspect_bytes {
                        buf.extend_from_slice(chunk);
                    } else {
                        *overflowed = true;
                        buf.clear();
                    }
                }
                if end_of_stream && !*overflowed && !buf.is_empty() {
                    if let Ok(val) = serde_json::from_slice::<Value>(buf) {
                        extract_usage_from_json(&val, &mut usage);
                    }
                    buf.clear();
                }
            }
        }

        ctx.insert_ext(usage);
        if !end_of_stream {
            ctx.insert_ext(collector);
        }

        HookResult::Ready(StreamFlow::Continue)
    }

    fn on_complete<'a>(
        &'a self,
        ctx: &'a RequestCtx,
        summary: &'a RequestSummary,
    ) -> HookResult<'a, ()> {
        // Synthetic model discovery responses (`GET /v1/models`, `GET /v1/models/{id}`)
        // do not represent LLM inference invocations.
        if ctx
            .get_ext::<DetectedEndpoint>()
            .map(|d| d.0.is_models_discovery())
            .unwrap_or(false)
        {
            return HookResult::Ready(());
        }

        let meta = ctx.get_ext::<AiRequestMeta>();
        let cache_status = ctx.get_ext::<AiCacheStatus>();

        // On any AI cache hit (exact, streaming, coalesced, or semantic), annotate OTel &
        // optionally store a zero-cost generation record without double-counting upstream inference.
        if let Some(cs) = cache_status
            && let Some((provider, served_model)) = cs.hit_target()
        {
            if ctx.has_trace_collectors() {
                let op = meta
                    .map(|m| genai_operation_name(m.endpoint))
                    .unwrap_or("chat");
                let requested_model = meta
                    .map(|m| m.requested_model.as_str())
                    .unwrap_or(served_model);
                if let Some(span) = ctx.get_ext::<SpanHandle>() {
                    span.set_name(format!("{op} {requested_model}"));
                }
                ctx.annotate_str("gen_ai.operation.name", op);
                ctx.annotate_str("gen_ai.provider.name", provider);
                ctx.annotate_str("gen_ai.request.model", requested_model);
                ctx.annotate_str("gen_ai.response.model", served_model);
                ctx.annotate_str("shunt.ai.cache_status", cs.as_str());
                if let Some(policy) = ctx.get_ext::<AiKeyPolicy>() {
                    ctx.annotate_str("shunt.ai.key_id", policy.key_id.as_str());
                    if let Some(team) = &policy.team {
                        ctx.annotate_str("shunt.ai.team", team.as_str());
                    }
                }
            }
            if let Some(store) = &self.generation_store {
                let gw_id = format!("gen-{}", summary.request_id);
                let policy = ctx.get_ext::<AiKeyPolicy>();
                store.insert(
                    AiGenerationRecord {
                        id: gw_id.clone(),
                        gateway_id: Some(gw_id),
                        created_at_ms: self.clock.now_ms(),
                        endpoint: meta
                            .map(|m| m.endpoint.as_str().to_owned())
                            .unwrap_or_else(|| "chat_completions".to_owned()),
                        model: meta
                            .map(|m| m.requested_model.clone())
                            .unwrap_or_else(|| served_model.to_owned()),
                        served_model: served_model.to_owned(),
                        provider_name: provider.to_owned(),
                        streamed: meta.map(|m| m.stream).unwrap_or(false),
                        status: summary.status.map(|s| s.as_u16()).unwrap_or(200),
                        tokens_prompt: 0,
                        tokens_completion: 0,
                        tokens_cached_read: 0,
                        tokens_cache_write: 0,
                        tokens_reasoning: 0,
                        total_cost: 0.0,
                        latency_ms: summary.total_duration.as_secs_f64() * 1000.0,
                        generation_time_ms: summary.total_duration.as_secs_f64() * 1000.0,
                        finish_reason: None,
                        cache_status: Some(cs.as_str().to_owned()),
                        key_id: policy.map(|p| p.key_id.clone()),
                        team: policy.and_then(|p| p.team.clone()),
                    },
                    self.generation_store_capacity,
                );
            }
            return HookResult::Ready(());
        }

        let usage = ctx.get_ext::<AiUsage>();
        let failover_events = ctx
            .get_ext::<AiFailoverHistory>()
            .map(|h| h.events.clone())
            .unwrap_or_default();

        let active_target = meta.and_then(AiRequestMeta::active_target);
        let provider = usage
            .and_then(|u| u.provider.clone())
            .or_else(|| active_target.map(|t| t.provider.clone()))
            .unwrap_or_else(|| "unknown".to_owned());

        let requested_model = meta
            .map(|m| m.requested_model.clone())
            .unwrap_or_else(|| "unknown".to_owned());
        let served_model = usage
            .and_then(|u| u.served_model.clone())
            .or_else(|| active_target.map(|t| t.model.clone()))
            .unwrap_or_else(|| requested_model.clone());
        let stream = meta.map(|m| m.stream).unwrap_or(false);

        let prompt_tokens = usage.and_then(|u| u.prompt_tokens);
        let cached_prompt_tokens = usage.and_then(|u| u.cached_prompt_tokens);
        let cache_creation_prompt_tokens = usage.and_then(|u| u.cache_creation_prompt_tokens);
        let completion_tokens = usage.and_then(|u| u.completion_tokens);
        let reasoning_tokens = usage.and_then(|u| u.reasoning_tokens);
        let total_tokens = usage.and_then(AiUsage::effective_total_tokens);
        let key_policy = ctx.get_ext::<AiKeyPolicy>();
        let key_id = key_policy.map(|p| p.key_id.clone());
        let team = key_policy.and_then(|p| p.team.clone());

        // True TTFT for streams (first non-empty content/tool token chunk); falls back to TTFB.
        let ttft = usage
            .and_then(|u| u.first_token_at)
            .map(|t| t.saturating_duration_since(ctx.started_at))
            .or(summary.ttfb);

        let report = AiUsageReport {
            request_id: summary.request_id,
            route_id: summary.route_id.clone(),
            key_id,
            team,
            provider,
            upstream: summary.upstream.clone(),
            requested_model,
            served_model,
            stream,
            status: summary.status.map(|s| s.as_u16()),
            attempts: summary.attempts,
            failover_events,
            prompt_tokens,
            cached_prompt_tokens,
            cache_creation_prompt_tokens,
            completion_tokens,
            reasoning_tokens,
            total_tokens,
            ttft,
            total_duration: summary.total_duration,
            aborted_mid_stream: summary.aborted_mid_stream,
            error: summary.error.clone(),
        };

        self.metrics.record(&report);

        if let Some(store) = &self.generation_store
            && summary.attempts > 0
        {
            let gw_id = format!("gen-{}", summary.request_id);
            let canonical_id = usage
                .and_then(|u| u.response_id.clone())
                .filter(|id| !id.trim().is_empty())
                .unwrap_or_else(|| gw_id.clone());
            let budget_nano = ctx
                .get_ext::<AiRecordedCost>()
                .map(AiRecordedCost::nano_usd)
                .unwrap_or(0);
            let cost_nano = if budget_nano > 0 {
                budget_nano
            } else {
                self.pricing_catalog
                    .lookup(&report.served_model, &report.requested_model)
                    .map(|p| {
                        p.cost_nano_usd_detailed(
                            report.prompt_tokens.unwrap_or(0),
                            report.cached_prompt_tokens.unwrap_or(0),
                            report.cache_creation_prompt_tokens.unwrap_or(0),
                            report.completion_tokens.unwrap_or(0),
                        )
                    })
                    .unwrap_or(0)
            };

            store.insert(
                AiGenerationRecord {
                    id: canonical_id,
                    gateway_id: Some(gw_id),
                    created_at_ms: self.clock.now_ms(),
                    endpoint: meta
                        .map(|m| m.endpoint.as_str().to_owned())
                        .unwrap_or_else(|| "chat_completions".to_owned()),
                    model: report.requested_model.clone(),
                    served_model: report.served_model.clone(),
                    provider_name: report.provider.clone(),
                    streamed: report.stream,
                    status: report.status.unwrap_or(0),
                    tokens_prompt: report.prompt_tokens.unwrap_or(0),
                    tokens_completion: report.completion_tokens.unwrap_or(0),
                    tokens_cached_read: report.cached_prompt_tokens.unwrap_or(0),
                    tokens_cache_write: report.cache_creation_prompt_tokens.unwrap_or(0),
                    tokens_reasoning: report.reasoning_tokens.unwrap_or(0),
                    total_cost: nano_usd_to_usd(cost_nano),
                    latency_ms: report.ttft.unwrap_or(report.total_duration).as_secs_f64() * 1000.0,
                    generation_time_ms: report.total_duration.as_secs_f64() * 1000.0,
                    finish_reason: usage.and_then(|u| u.finish_reason.clone()),
                    cache_status: cache_status.map(|cs| cs.as_str().to_owned()),
                    key_id: report.key_id.clone(),
                    team: report.team.clone(),
                },
                self.generation_store_capacity,
            );
        }

        if ctx.has_trace_collectors() {
            let op = meta
                .map(|m| genai_operation_name(m.endpoint))
                .unwrap_or("chat");
            if let Some(span) = ctx.get_ext::<SpanHandle>() {
                span.set_name(format!("{op} {}", report.requested_model));
            }
            ctx.annotate_str("gen_ai.operation.name", op);
            ctx.annotate_str("gen_ai.provider.name", report.provider.as_str());
            ctx.annotate_str("gen_ai.request.model", report.requested_model.as_str());
            ctx.annotate_str("gen_ai.response.model", report.served_model.as_str());
            if let Some(p) = report.prompt_tokens {
                ctx.annotate_int("gen_ai.usage.input_tokens", p.min(i64::MAX as u64) as i64);
            }
            if let Some(c) = report.completion_tokens {
                ctx.annotate_int("gen_ai.usage.output_tokens", c.min(i64::MAX as u64) as i64);
            }
            if let Some(cached) = report.cached_prompt_tokens {
                ctx.annotate_int(
                    "gen_ai.usage.cache_read.input_tokens",
                    cached.min(i64::MAX as u64) as i64,
                );
            }
            if let Some(cache_write) = report.cache_creation_prompt_tokens {
                ctx.annotate_int(
                    "gen_ai.usage.cache_creation.input_tokens",
                    cache_write.min(i64::MAX as u64) as i64,
                );
            }
            if let Some(reasoning) = report.reasoning_tokens {
                ctx.annotate_int(
                    "gen_ai.usage.reasoning_tokens",
                    reasoning.min(i64::MAX as u64) as i64,
                );
            }
            ctx.annotate_bool("shunt.ai.stream", report.stream);
            if let Some(ttft) = report.ttft {
                ctx.annotate_float("shunt.ai.ttft_ms", ttft.as_secs_f64() * 1000.0);
            }
            ctx.annotate_int("shunt.ai.failovers", report.failover_events.len() as i64);
            if let Some(m) = meta {
                ctx.annotate_str("shunt.ai.routing_strategy", m.routing_strategy.as_str());
            }
            if let Some(cs) = cache_status {
                ctx.annotate_str("shunt.ai.cache_status", cs.as_str());
            }
            if let Some(k) = &report.key_id {
                ctx.annotate_str("shunt.ai.key_id", k.as_str());
            }
            if let Some(t) = &report.team {
                ctx.annotate_str("shunt.ai.team", t.as_str());
            }
        }

        if let Some(sink) = &self.sink {
            sink(&report);
        }

        if self.log_usage {
            info!(
                request_id = report.request_id,
                provider = %report.provider,
                requested_model = %report.requested_model,
                served_model = %report.served_model,
                stream = report.stream,
                status = report.status.unwrap_or(0),
                attempts = report.attempts,
                failovers = report.failover_events.len(),
                prompt_tokens = report.prompt_tokens,
                completion_tokens = report.completion_tokens,
                total_tokens = report.total_tokens,
                ttft_ms = report.ttft.map(|d| d.as_secs_f64() * 1000.0),
                duration_ms = report.total_duration.as_secs_f64() * 1000.0,
                "ai_usage"
            );
        }

        HookResult::Ready(())
    }
}

const fn genai_operation_name(endpoint: AiEndpointKind) -> &'static str {
    match endpoint {
        AiEndpointKind::Embeddings => "embeddings",
        AiEndpointKind::Completions => "text_completion",
        AiEndpointKind::Rerank => "rerank",
        AiEndpointKind::Moderations => "moderations",
        AiEndpointKind::ImagesGenerations
        | AiEndpointKind::ImagesEdits
        | AiEndpointKind::ImagesVariations => "images",
        AiEndpointKind::AudioSpeech
        | AiEndpointKind::AudioTranscriptions
        | AiEndpointKind::AudioTranslations => "audio",
        AiEndpointKind::Realtime => "realtime",
        AiEndpointKind::Files => "files",
        AiEndpointKind::Batches => "batches",
        AiEndpointKind::GenerationRetrieve => "generation",
        AiEndpointKind::ChatCompletions
        | AiEndpointKind::AnthropicMessages
        | AiEndpointKind::OpenAiResponses
        | AiEndpointKind::ModelsList
        | AiEndpointKind::ModelRetrieve
        | AiEndpointKind::AnthropicCountTokens => "chat",
    }
}

fn inspect_sse_event_data(data: &str, usage: &mut AiUsage) {
    let trimmed = data.trim();
    if trimmed.is_empty() || trimmed == "[DONE]" {
        return;
    }
    let Ok(val) = serde_json::from_str::<Value>(trimmed) else {
        return;
    };

    if usage.first_token_at.is_none() && contains_first_token(&val) {
        usage.first_token_at = Some(Instant::now());
    }

    extract_usage_from_json(&val, usage);
}

fn contains_first_token(val: &Value) -> bool {
    // OpenAI streaming chunk: choices[0].delta.content / reasoning_content (non-empty) or tool_calls
    if let Some(choices) = val.get("choices").and_then(Value::as_array) {
        for ch in choices {
            if let Some(delta) = ch.get("delta") {
                if delta
                    .get("content")
                    .and_then(Value::as_str)
                    .map(|s| !s.is_empty())
                    .unwrap_or(false)
                {
                    return true;
                }
                if delta
                    .get("reasoning_content")
                    .or_else(|| delta.get("reasoning"))
                    .and_then(Value::as_str)
                    .map(|s| !s.is_empty())
                    .unwrap_or(false)
                {
                    return true;
                }
                if delta
                    .get("tool_calls")
                    .and_then(Value::as_array)
                    .map(|a| !a.is_empty())
                    .unwrap_or(false)
                {
                    return true;
                }
            }
            // Legacy `/v1/completions` streaming chunk: choices[0].text
            if ch
                .get("text")
                .and_then(Value::as_str)
                .map(|s| !s.is_empty())
                .unwrap_or(false)
            {
                return true;
            }
        }
    }

    // Gemini streaming chunk (in case ai-usage-tracker runs before ai-provider-adapter)
    if let Some(candidates) = val.get("candidates").and_then(Value::as_array) {
        for cand in candidates {
            if let Some(parts) = cand
                .get("content")
                .and_then(|c| c.get("parts"))
                .and_then(Value::as_array)
            {
                for part in parts {
                    if part
                        .get("text")
                        .and_then(Value::as_str)
                        .map(|s| !s.is_empty())
                        .unwrap_or(false)
                        || part.get("functionCall").is_some()
                    {
                        return true;
                    }
                }
            }
        }
    }

    // Anthropic / OpenAI Responses streaming chunks
    matches!(
        val.get("type").and_then(Value::as_str),
        Some(
            "content_block_delta"
                | "response.output_text.delta"
                | "response.reasoning_summary_text.delta"
                | "response.function_call_arguments.delta"
        )
    )
}

fn extract_usage_from_json(val: &Value, usage: &mut AiUsage) {
    // Capture upstream response/generation ID (OpenAI `id`, Anthropic `message.id`, Responses `response.id`).
    if usage.response_id.is_none() {
        if let Some(id) = val
            .get("id")
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
        {
            usage.response_id = Some(id.to_owned());
        } else if let Some(id) = val
            .get("message")
            .and_then(|m| m.get("id"))
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
        {
            usage.response_id = Some(id.to_owned());
        } else if let Some(id) = val
            .get("response")
            .and_then(|r| r.get("id"))
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
        {
            usage.response_id = Some(id.to_owned());
        }
    }

    // Capture finish/stop reason when present.
    if let Some(fr) = val
        .get("choices")
        .and_then(Value::as_array)
        .and_then(|arr| arr.first())
        .and_then(|c| c.get("finish_reason"))
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .or_else(|| {
            val.get("stop_reason")
                .and_then(Value::as_str)
                .filter(|s| !s.is_empty())
        })
        .or_else(|| {
            val.get("delta")
                .and_then(|d| d.get("stop_reason"))
                .and_then(Value::as_str)
                .filter(|s| !s.is_empty())
        })
    {
        usage.finish_reason = Some(fr.to_owned());
    }

    // Model name (OpenAI top-level, Gemini modelVersion, Anthropic message_start.message.model,
    // or OpenAI Responses SSE response.completed / response.created)
    if let Some(m) = val.get("model").and_then(Value::as_str) {
        usage.served_model = Some(m.to_owned());
    } else if let Some(m) = val.get("modelVersion").and_then(Value::as_str) {
        usage.served_model = Some(m.to_owned());
    } else if let Some(m) = val
        .get("message")
        .and_then(|msg| msg.get("model"))
        .and_then(Value::as_str)
    {
        usage.served_model = Some(m.to_owned());
    } else if let Some(m) = val
        .get("response")
        .and_then(|resp| resp.get("model"))
        .and_then(Value::as_str)
    {
        usage.served_model = Some(m.to_owned());
    }

    // Top-level `usage` (OpenAI chat/responses/embeddings, Anthropic non-stream/message_delta, Bedrock Converse)
    if let Some(u) = val.get("usage").and_then(Value::as_object) {
        let mut cache_read_opt: Option<u64> = None;
        let mut cache_write_opt: Option<u64> = None;

        // Cached prompt read tokens
        if let Some(cached) = u
            .get("prompt_tokens_details")
            .and_then(|d| d.get("cached_tokens"))
            .and_then(Value::as_u64)
            .or_else(|| {
                u.get("input_tokens_details")
                    .and_then(|d| d.get("cached_tokens"))
                    .and_then(Value::as_u64)
            })
            .or_else(|| u.get("cache_read_input_tokens").and_then(Value::as_u64))
            .or_else(|| u.get("cacheReadInputTokens").and_then(Value::as_u64))
        {
            usage.cached_prompt_tokens = Some(cached);
            cache_read_opt = Some(cached);
        }

        // Cached prompt write (creation) tokens
        if let Some(written) = u
            .get("prompt_tokens_details")
            .and_then(|d| d.get("cache_creation_tokens"))
            .and_then(Value::as_u64)
            .or_else(|| u.get("cache_creation_input_tokens").and_then(Value::as_u64))
            .or_else(|| u.get("cacheWriteInputTokens").and_then(Value::as_u64))
        {
            usage.cache_creation_prompt_tokens = Some(written);
            cache_write_opt = Some(written);
        }

        // Reasoning tokens
        if let Some(reasoning) = u
            .get("completion_tokens_details")
            .and_then(|d| d.get("reasoning_tokens"))
            .and_then(Value::as_u64)
            .or_else(|| {
                u.get("output_tokens_details")
                    .and_then(|d| d.get("reasoning_tokens"))
                    .and_then(Value::as_u64)
            })
        {
            usage.reasoning_tokens = Some(reasoning);
        }

        if let Some(p) = u.get("prompt_tokens").and_then(Value::as_u64) {
            usage.prompt_tokens = Some(p);
        }
        if let Some(c) = u.get("completion_tokens").and_then(Value::as_u64) {
            usage.completion_tokens = Some(c);
        }
        if let Some(t) = u.get("total_tokens").and_then(Value::as_u64) {
            usage.total_tokens = Some(t);
        }
        if let Some(i) = u.get("input_tokens").and_then(Value::as_u64) {
            // Native Anthropic Messages reports `input_tokens` excluding cache read/write tokens,
            // whereas OpenAI Responses reports `input_tokens` inclusively (with `input_tokens_details`).
            let is_anthropic_additive = u.contains_key("cache_read_input_tokens")
                || u.contains_key("cache_creation_input_tokens");
            let total_in = if is_anthropic_additive {
                i.saturating_add(cache_read_opt.unwrap_or(0))
                    .saturating_add(cache_write_opt.unwrap_or(0))
            } else {
                i
            };
            usage.prompt_tokens = Some(total_in);
        }
        if let Some(o) = u.get("output_tokens").and_then(Value::as_u64) {
            usage.completion_tokens = Some(o);
        }
        // Bedrock Converse camelCase usage keys
        if let Some(i) = u.get("inputTokens").and_then(Value::as_u64) {
            let total_in = i
                .saturating_add(cache_read_opt.unwrap_or(0))
                .saturating_add(cache_write_opt.unwrap_or(0));
            usage.prompt_tokens = Some(total_in);
        }
        if let Some(o) = u.get("outputTokens").and_then(Value::as_u64) {
            usage.completion_tokens = Some(o);
        }
        if let Some(t) = u.get("totalTokens").and_then(Value::as_u64) {
            usage.total_tokens = Some(t);
        }
    }

    // OpenAI Responses SSE (`response.completed` / `response.incomplete`): response.usage
    if let Some(u) = val
        .get("response")
        .and_then(|r| r.get("usage"))
        .and_then(Value::as_object)
    {
        if let Some(i) = u.get("input_tokens").and_then(Value::as_u64) {
            usage.prompt_tokens = Some(i);
        }
        if let Some(o) = u.get("output_tokens").and_then(Value::as_u64) {
            usage.completion_tokens = Some(o);
        }
        if let Some(t) = u.get("total_tokens").and_then(Value::as_u64) {
            usage.total_tokens = Some(t);
        }
        if let Some(cached) = u
            .get("input_tokens_details")
            .and_then(|d| d.get("cached_tokens"))
            .and_then(Value::as_u64)
        {
            usage.cached_prompt_tokens = Some(cached);
        }
        if let Some(reasoning) = u
            .get("output_tokens_details")
            .and_then(|d| d.get("reasoning_tokens"))
            .and_then(Value::as_u64)
        {
            usage.reasoning_tokens = Some(reasoning);
        }
    }

    // Anthropic `message_start`: message.usage.{input_tokens, output_tokens, cache_read_input_tokens, cache_creation_input_tokens}
    if let Some(u) = val
        .get("message")
        .and_then(|m| m.get("usage"))
        .and_then(Value::as_object)
    {
        let cached = u.get("cache_read_input_tokens").and_then(Value::as_u64);
        let written = u.get("cache_creation_input_tokens").and_then(Value::as_u64);
        if let Some(c) = cached {
            usage.cached_prompt_tokens = Some(c);
        }
        if let Some(w) = written {
            usage.cache_creation_prompt_tokens = Some(w);
        }
        if let Some(i) = u.get("input_tokens").and_then(Value::as_u64) {
            usage.prompt_tokens = Some(
                i.saturating_add(cached.unwrap_or(0))
                    .saturating_add(written.unwrap_or(0)),
            );
        }
        if let Some(o) = u.get("output_tokens").and_then(Value::as_u64) {
            usage.completion_tokens = Some(o);
        }
    }

    // Google Gemini `usageMetadata.{promptTokenCount, candidatesTokenCount, thoughtsTokenCount, totalTokenCount, cachedContentTokenCount}`
    if let Some(u) = val.get("usageMetadata").and_then(Value::as_object) {
        if let Some(p) = u.get("promptTokenCount").and_then(Value::as_u64) {
            usage.prompt_tokens = Some(p);
        }
        let thoughts = u.get("thoughtsTokenCount").and_then(Value::as_u64);
        if let Some(r) = thoughts {
            usage.reasoning_tokens = Some(r);
        }
        if let Some(c) = u.get("candidatesTokenCount").and_then(Value::as_u64) {
            usage.completion_tokens = Some(c.saturating_add(thoughts.unwrap_or(0)));
        }
        if let Some(t) = u.get("totalTokenCount").and_then(Value::as_u64) {
            usage.total_tokens = Some(t);
        }
        if let Some(cached) = u.get("cachedContentTokenCount").and_then(Value::as_u64) {
            usage.cached_prompt_tokens = Some(cached);
        }
    }
}
