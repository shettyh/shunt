use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::sync::{Arc, RwLock};
use std::time::Instant;

use serde::Deserialize;
use serde_json::Value;
use shunt_plugin_sdk::{
    BuildContext, Bytes, Flow, HookMask, HookResult, HttpPlugin, PluginBuildError, PluginConfig,
    PluginFactory, RequestCtx, RequestSummary, ResponseHead, StreamFlow, header,
};
use tracing::info;

use crate::sse::SseParser;
use crate::types::{AiFailoverHistory, AiRequestMeta, AiUsage, AiUsageReport};

const DEFAULT_MAX_JSON_INSPECT_BYTES: usize = 4 * 1024 * 1024; // 4 MiB

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
    /// (from_provider, to_provider, model) -> count
    failovers_total: BTreeMap<(String, String, String), u64>,
    /// (provider, model, stream) -> TTFT histogram
    ttft_seconds: BTreeMap<(String, String, bool), HistogramState>,
    /// (provider, model, stream) -> total duration histogram
    duration_seconds: BTreeMap<(String, String, bool), HistogramState>,
}

/// Point-in-time aggregate counters from [`AiMetrics`] (useful for programmatic checks/tests).
#[derive(Debug, Clone, Default)]
pub struct AiMetricsSnapshot {
    pub total_requests: u64,
    pub total_prompt_tokens: u64,
    pub total_completion_tokens: u64,
    pub total_failovers: u64,
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

        for ev in &report.failover_events {
            *data
                .failovers_total
                .entry((
                    ev.provider.as_str().to_owned(),
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
        AiMetricsSnapshot {
            total_requests,
            total_prompt_tokens,
            total_completion_tokens,
            total_failovers,
        }
    }

    /// Renders collected AI metrics in Prometheus exposition text format (v0.0.4).
    /// Returns an empty string if no AI requests have been observed yet.
    pub fn render_prometheus(&self) -> String {
        let data = self.inner.read().expect("AiMetrics lock poisoned");
        if data.requests_total.is_empty() {
            return String::new();
        }

        let mut out = String::with_capacity(2048);

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
}

impl Default for AiUsageTrackerConfig {
    fn default() -> Self {
        Self {
            log_usage: true,
            max_json_inspect_bytes: DEFAULT_MAX_JSON_INSPECT_BYTES,
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
        _ctx: &BuildContext,
    ) -> Result<Arc<dyn HttpPlugin>, PluginBuildError> {
        let cfg: AiUsageTrackerConfig = config.deserialize(self.name())?;
        Ok(Arc::new(AiUsageTrackerPlugin {
            metrics: Arc::clone(&self.metrics),
            sink: self.sink.clone(),
            log_usage: cfg.log_usage,
            max_json_inspect_bytes: cfg.max_json_inspect_bytes.max(1024),
        }))
    }
}

/// Inspects non-streaming JSON and streaming SSE responses (both OpenAI and Anthropic
/// formats) to record token usage, TTFT, and duration into `ctx.extensions`, [`AiMetrics`],
/// and structured completion logs.
pub struct AiUsageTrackerPlugin {
    metrics: Arc<AiMetrics>,
    sink: Option<UsageSink>,
    log_usage: bool,
    max_json_inspect_bytes: usize,
}

impl HttpPlugin for AiUsageTrackerPlugin {
    fn name(&self) -> &str {
        "ai-usage-tracker"
    }

    fn hook_mask(&self) -> HookMask {
        HookMask::ON_RESPONSE_HEADERS | HookMask::RESPONSE_BODY_STREAM | HookMask::ON_COMPLETE
    }

    fn on_response_headers<'a>(
        &'a self,
        ctx: &'a mut RequestCtx,
        res: &'a mut ResponseHead,
    ) -> HookResult<'a, Flow> {
        let is_sse = res
            .headers
            .get(header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .map(|ct| ct.to_ascii_lowercase().contains("text/event-stream"))
            .unwrap_or(false);

        let provider = ctx
            .get_ext::<AiRequestMeta>()
            .and_then(AiRequestMeta::active_target)
            .map(|t| t.provider);

        let collector = if is_sse {
            UsageCollectorState::Sse(SseParser::new())
        } else {
            UsageCollectorState::Json {
                buf: Vec::new(),
                overflowed: false,
            }
        };

        ctx.insert_ext(collector);
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
        let meta = ctx.get_ext::<AiRequestMeta>();
        let usage = ctx.get_ext::<AiUsage>();
        let failover_events = ctx
            .get_ext::<AiFailoverHistory>()
            .map(|h| h.events.clone())
            .unwrap_or_default();

        let active_target = meta.and_then(AiRequestMeta::active_target);
        let provider = usage
            .and_then(|u| u.provider)
            .or_else(|| active_target.map(|t| t.provider))
            .map(|p| p.as_str().to_owned())
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
        let completion_tokens = usage.and_then(|u| u.completion_tokens);
        let total_tokens = usage.and_then(AiUsage::effective_total_tokens);

        // True TTFT for streams (first non-empty content/tool token chunk); falls back to TTFB.
        let ttft = usage
            .and_then(|u| u.first_token_at)
            .map(|t| t.saturating_duration_since(ctx.started_at))
            .or(summary.ttfb);

        let report = AiUsageReport {
            request_id: summary.request_id,
            route_id: summary.route_id.clone(),
            provider,
            upstream: summary.upstream.clone(),
            requested_model,
            served_model,
            stream,
            status: summary.status.map(|s| s.as_u16()),
            attempts: summary.attempts,
            failover_events,
            prompt_tokens,
            completion_tokens,
            total_tokens,
            ttft,
            total_duration: summary.total_duration,
            aborted_mid_stream: summary.aborted_mid_stream,
            error: summary.error.clone(),
        };

        self.metrics.record(&report);

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
    // OpenAI streaming chunk: choices[0].delta.content (non-empty) or tool_calls
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
                    .get("tool_calls")
                    .and_then(Value::as_array)
                    .map(|a| !a.is_empty())
                    .unwrap_or(false)
                {
                    return true;
                }
            }
        }
    }

    // Anthropic streaming chunk (in case ai-usage-tracker runs before ai-provider-adapter)
    if val.get("type").and_then(Value::as_str) == Some("content_block_delta") {
        return true;
    }

    false
}

fn extract_usage_from_json(val: &Value, usage: &mut AiUsage) {
    // Model name (OpenAI top-level or Anthropic message_start.message.model)
    if let Some(m) = val.get("model").and_then(Value::as_str) {
        usage.served_model = Some(m.to_owned());
    } else if let Some(m) = val
        .get("message")
        .and_then(|msg| msg.get("model"))
        .and_then(Value::as_str)
    {
        usage.served_model = Some(m.to_owned());
    }

    // Top-level `usage` (OpenAI non-stream/stream, Anthropic non-stream, Anthropic message_delta)
    if let Some(u) = val.get("usage").and_then(Value::as_object) {
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
            usage.prompt_tokens = Some(i);
        }
        if let Some(o) = u.get("output_tokens").and_then(Value::as_u64) {
            usage.completion_tokens = Some(o);
        }
    }

    // Anthropic `message_start`: message.usage.{input_tokens, output_tokens}
    if let Some(u) = val
        .get("message")
        .and_then(|m| m.get("usage"))
        .and_then(Value::as_object)
    {
        if let Some(i) = u.get("input_tokens").and_then(Value::as_u64) {
            usage.prompt_tokens = Some(i);
        }
        if let Some(o) = u.get("output_tokens").and_then(Value::as_u64) {
            usage.completion_tokens = Some(o);
        }
    }
}
