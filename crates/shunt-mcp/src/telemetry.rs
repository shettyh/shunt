use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::sync::{Arc, RwLock};

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use shunt_plugin_sdk::{
    BuildContext, Bytes, Clock, Flow, HookMask, HookResult, HttpPlugin, PluginBuildError,
    PluginConfig, PluginFactory, RequestCtx, RequestSummary, ResponseHead, StateStore, StreamFlow,
};
use tracing::info;

use crate::auth::McpSessionBindingTable;
use crate::guardrails::McpGuardrailStatsTable;
use crate::rate_limit::McpRateLimitTable;
use crate::router::{McpCatalogTable, McpSessionTable};
use crate::types::{
    McpGuardrailSummary, McpLoopBreakInfo, McpPrincipal, McpRequestMeta, canonical_json_bytes,
    extract_mcp_response_payloads, is_sse_content_type, sha256_hex,
};

const MCP_LATENCY_BUCKETS: &[f64] = &[
    0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 15.0,
];

#[derive(Debug, Clone)]
struct HistogramState {
    buckets: Vec<u64>,
    sum: f64,
    count: u64,
}

impl Default for HistogramState {
    fn default() -> Self {
        Self {
            buckets: vec![0; MCP_LATENCY_BUCKETS.len() + 1],
            sum: 0.0,
            count: 0,
        }
    }
}

impl HistogramState {
    fn observe(&mut self, value_secs: f64) {
        self.sum += value_secs;
        self.count += 1;
        for (idx, &bound) in MCP_LATENCY_BUCKETS.iter().enumerate() {
            if value_secs <= bound {
                self.buckets[idx] += 1;
            }
        }
        *self.buckets.last_mut().unwrap() += 1;
    }
}

#[derive(Debug, Default)]
struct McpMetricsData {
    /// (server, method, tool, status) -> count
    requests_total: BTreeMap<(String, String, String, u16), u64>,
    /// (server, tool, outcome) -> count
    tool_calls_total: BTreeMap<(String, String, String), u64>,
    /// (direction, detector, action) -> count
    guardrail_triggers_total: BTreeMap<(String, String, String), u64>,
    /// tool -> loop break count
    loop_breaks_total: BTreeMap<String, u64>,
    /// (server, method) -> duration histogram
    duration_seconds: BTreeMap<(String, String), HistogramState>,
}

/// Thread-safe Prometheus & Inspector metrics collector for `shunt-mcp`.
#[derive(Debug, Default)]
pub struct McpMetrics {
    data: RwLock<McpMetricsData>,
}

/// Point-in-time aggregate counters from [`McpMetrics`].
#[derive(Debug, Clone, Default, Serialize)]
pub struct McpMetricsSnapshot {
    pub total_requests: u64,
    pub total_tool_calls: u64,
    pub total_tool_errors: u64,
    pub total_guardrail_triggers: u64,
    pub total_loop_breaks: u64,
}

impl McpMetrics {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn record_request(
        &self,
        server: &str,
        method: &str,
        tool: &str,
        status: u16,
        duration_secs: f64,
    ) {
        let mut guard = self.data.write().expect("McpMetrics poisoned");
        *guard
            .requests_total
            .entry((
                server.to_owned(),
                method.to_owned(),
                tool.to_owned(),
                status,
            ))
            .or_insert(0) += 1;
        guard
            .duration_seconds
            .entry((server.to_owned(), method.to_owned()))
            .or_default()
            .observe(duration_secs);
    }

    pub fn record_tool_call(&self, server: &str, tool: &str, outcome: &str) {
        let mut guard = self.data.write().expect("McpMetrics poisoned");
        *guard
            .tool_calls_total
            .entry((server.to_owned(), tool.to_owned(), outcome.to_owned()))
            .or_insert(0) += 1;
    }

    pub fn record_guardrail_trigger(&self, direction: &str, detector: &str, action: &str) {
        let mut guard = self.data.write().expect("McpMetrics poisoned");
        *guard
            .guardrail_triggers_total
            .entry((direction.to_owned(), detector.to_owned(), action.to_owned()))
            .or_insert(0) += 1;
    }

    pub fn record_loop_break(&self, tool: &str) {
        let mut guard = self.data.write().expect("McpMetrics poisoned");
        *guard.loop_breaks_total.entry(tool.to_owned()).or_insert(0) += 1;
    }

    pub fn snapshot(&self) -> McpMetricsSnapshot {
        let guard = self.data.read().expect("McpMetrics poisoned");
        let total_requests: u64 = guard.requests_total.values().copied().sum();
        let mut total_tool_calls = 0u64;
        let mut total_tool_errors = 0u64;
        for ((_, _, outcome), &count) in &guard.tool_calls_total {
            total_tool_calls += count;
            if outcome != "ok" {
                total_tool_errors += count;
            }
        }
        let total_guardrail_triggers: u64 = guard.guardrail_triggers_total.values().copied().sum();
        let total_loop_breaks: u64 = guard.loop_breaks_total.values().copied().sum();

        McpMetricsSnapshot {
            total_requests,
            total_tool_calls,
            total_tool_errors,
            total_guardrail_triggers,
            total_loop_breaks,
        }
    }

    /// Renders all collected MCP counters & histograms in Prometheus exposition format.
    pub fn render_prometheus(&self) -> String {
        let guard = self.data.read().expect("McpMetrics poisoned");
        let mut out = String::new();

        if !guard.requests_total.is_empty() {
            out.push_str(
                "# HELP shunt_mcp_requests_total Total MCP JSON-RPC requests processed.\n",
            );
            out.push_str("# TYPE shunt_mcp_requests_total counter\n");
            for ((server, method, tool, status), count) in &guard.requests_total {
                let _ = writeln!(
                    out,
                    "shunt_mcp_requests_total{{server=\"{}\",method=\"{}\",tool=\"{}\",status=\"{status}\"}} {count}",
                    escape_prom(server),
                    escape_prom(method),
                    escape_prom(tool),
                );
            }
        }

        if !guard.tool_calls_total.is_empty() {
            out.push_str(
                "# HELP shunt_mcp_tool_calls_total Total MCP tools/call invocations by outcome.\n",
            );
            out.push_str("# TYPE shunt_mcp_tool_calls_total counter\n");
            for ((server, tool, outcome), count) in &guard.tool_calls_total {
                let _ = writeln!(
                    out,
                    "shunt_mcp_tool_calls_total{{server=\"{}\",tool=\"{}\",outcome=\"{}\"}} {count}",
                    escape_prom(server),
                    escape_prom(tool),
                    escape_prom(outcome),
                );
            }
        }

        if !guard.guardrail_triggers_total.is_empty() {
            out.push_str(
                "# HELP shunt_mcp_guardrail_triggers_total Total MCP guardrail detections by direction, detector, and action.\n",
            );
            out.push_str("# TYPE shunt_mcp_guardrail_triggers_total counter\n");
            for ((direction, detector, action), count) in &guard.guardrail_triggers_total {
                let _ = writeln!(
                    out,
                    "shunt_mcp_guardrail_triggers_total{{direction=\"{}\",detector=\"{}\",action=\"{}\"}} {count}",
                    escape_prom(direction),
                    escape_prom(detector),
                    escape_prom(action),
                );
            }
        }

        if !guard.loop_breaks_total.is_empty() {
            out.push_str(
                "# HELP shunt_mcp_loop_breaks_total Total MCP agent loop-breaker trips.\n",
            );
            out.push_str("# TYPE shunt_mcp_loop_breaks_total counter\n");
            for (tool, count) in &guard.loop_breaks_total {
                let _ = writeln!(
                    out,
                    "shunt_mcp_loop_breaks_total{{tool=\"{}\"}} {count}",
                    escape_prom(tool),
                );
            }
        }

        if !guard.duration_seconds.is_empty() {
            out.push_str(
                "# HELP shunt_mcp_duration_seconds End-to-end MCP request duration in seconds.\n",
            );
            out.push_str("# TYPE shunt_mcp_duration_seconds histogram\n");
            for ((server, method), hist) in &guard.duration_seconds {
                let s_esc = escape_prom(server);
                let m_esc = escape_prom(method);
                for (idx, bound) in MCP_LATENCY_BUCKETS.iter().enumerate() {
                    let _ = writeln!(
                        out,
                        "shunt_mcp_duration_seconds_bucket{{server=\"{s_esc}\",method=\"{m_esc}\",le=\"{bound}\"}} {}",
                        hist.buckets[idx],
                    );
                }
                let _ = writeln!(
                    out,
                    "shunt_mcp_duration_seconds_bucket{{server=\"{s_esc}\",method=\"{m_esc}\",le=\"+Inf\"}} {}",
                    hist.buckets[MCP_LATENCY_BUCKETS.len()],
                );
                let _ = writeln!(
                    out,
                    "shunt_mcp_duration_seconds_sum{{server=\"{s_esc}\",method=\"{m_esc}\"}} {:.6}",
                    hist.sum,
                );
                let _ = writeln!(
                    out,
                    "shunt_mcp_duration_seconds_count{{server=\"{s_esc}\",method=\"{m_esc}\"}} {}",
                    hist.count,
                );
            }
        }

        out
    }
}

fn escape_prom(s: &str) -> String {
    s.replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
}

#[derive(Debug, Deserialize)]
#[serde(default)]
struct McpTelemetryConfig {
    /// Emit structured audit logs on `on_complete` (default: true).
    log_calls: bool,
    /// Inspect response body chunks to detect JSON-RPC `error` or MCP `result.isError: true` (default: true).
    inspect_tool_errors: bool,
    /// Maximum response bytes buffered for error inspection (default: 512 KiB).
    max_inspect_bytes: usize,
}

impl Default for McpTelemetryConfig {
    fn default() -> Self {
        Self {
            log_calls: true,
            inspect_tool_errors: true,
            max_inspect_bytes: 512 * 1024,
        }
    }
}

#[derive(Debug, Clone)]
struct ResponseInspectBuf {
    is_sse: bool,
    buf: Vec<u8>,
    truncated: bool,
}

/// Plugin factory for `mcp-telemetry`.
pub struct McpTelemetryFactory {
    metrics: Arc<McpMetrics>,
}

impl McpTelemetryFactory {
    pub fn new(metrics: Arc<McpMetrics>) -> Self {
        Self { metrics }
    }
}

impl PluginFactory for McpTelemetryFactory {
    fn name(&self) -> &str {
        "mcp-telemetry"
    }

    fn build(
        &self,
        config: &PluginConfig,
        _ctx: &BuildContext,
    ) -> Result<Arc<dyn HttpPlugin>, PluginBuildError> {
        let cfg: McpTelemetryConfig = config.deserialize(self.name())?;
        Ok(Arc::new(McpTelemetryPlugin {
            log_calls: cfg.log_calls,
            inspect_tool_errors: cfg.inspect_tool_errors,
            max_inspect_bytes: cfg.max_inspect_bytes.max(1024),
            metrics: Arc::clone(&self.metrics),
        }))
    }
}

/// MCP Prometheus metrics, OTLP span enrichment, and structured audit logger.
pub struct McpTelemetryPlugin {
    log_calls: bool,
    inspect_tool_errors: bool,
    max_inspect_bytes: usize,
    metrics: Arc<McpMetrics>,
}

impl HttpPlugin for McpTelemetryPlugin {
    fn name(&self) -> &str {
        "mcp-telemetry"
    }

    fn hook_mask(&self) -> HookMask {
        let mut mask = HookMask::ON_COMPLETE;
        if self.inspect_tool_errors {
            mask |= HookMask::ON_RESPONSE_HEADERS | HookMask::RESPONSE_BODY_STREAM;
        }
        mask
    }

    fn on_response_headers<'a>(
        &'a self,
        ctx: &'a mut RequestCtx,
        res: &'a mut ResponseHead,
    ) -> HookResult<'a, Flow> {
        if self.inspect_tool_errors && ctx.get_ext::<McpRequestMeta>().is_some() {
            ctx.insert_ext(ResponseInspectBuf {
                is_sse: is_sse_content_type(&res.headers),
                buf: Vec::new(),
                truncated: false,
            });
        }
        HookResult::Ready(Flow::Continue)
    }

    fn on_response_body_chunk<'a>(
        &'a self,
        ctx: &'a mut RequestCtx,
        chunk: &'a mut Bytes,
        _end_of_stream: bool,
    ) -> HookResult<'a, StreamFlow> {
        if !chunk.is_empty()
            && let Some(state) = ctx.get_ext_mut::<ResponseInspectBuf>()
            && !state.truncated
        {
            if state.buf.len().saturating_add(chunk.len()) <= self.max_inspect_bytes {
                state.buf.extend_from_slice(chunk);
            } else {
                state.truncated = true;
            }
        }
        HookResult::Ready(StreamFlow::Continue)
    }

    fn on_complete<'a>(
        &'a self,
        ctx: &'a RequestCtx,
        summary: &'a RequestSummary,
    ) -> HookResult<'a, ()> {
        let Some(meta) = ctx.get_ext::<McpRequestMeta>() else {
            return HookResult::Ready(());
        };

        let status_code = summary.status.map(|s| s.as_u16()).unwrap_or(0);
        let tool_label = meta.tool_name.as_deref().unwrap_or("-");
        let duration_secs = summary.total_duration.as_secs_f64();

        self.metrics.record_request(
            &meta.server,
            &meta.method,
            tool_label,
            status_code,
            duration_secs,
        );

        let guardrail = ctx.get_ext::<McpGuardrailSummary>();
        let loop_break = ctx.get_ext::<McpLoopBreakInfo>();
        let principal = ctx.get_ext::<McpPrincipal>();

        let mut outcome = "ok";
        if loop_break.is_some() {
            outcome = "loop_broken";
        } else if guardrail.is_some_and(|g| g.blocked) {
            outcome = "blocked";
        } else if status_code == 429 {
            outcome = "rate_limited";
        } else if status_code == 401 || status_code == 403 {
            outcome = "denied";
        } else if status_code >= 500 || summary.error.is_some() {
            outcome = "upstream_error";
        } else if let Some(resp_buf) = ctx.get_ext::<ResponseInspectBuf>()
            && !resp_buf.buf.is_empty()
        {
            let ct = if resp_buf.is_sse {
                Some("text/event-stream")
            } else {
                Some("application/json")
            };
            let payloads = extract_mcp_response_payloads(ct, &resp_buf.buf);
            for p in payloads {
                if p.get("error").is_some() {
                    outcome = "jsonrpc_error";
                    break;
                }
                if p.get("result")
                    .and_then(|r| r.get("isError"))
                    .and_then(Value::as_bool)
                    == Some(true)
                {
                    outcome = "tool_error";
                    break;
                }
            }
        }

        if meta.method == "tools/call" {
            self.metrics
                .record_tool_call(&meta.server, tool_label, outcome);
        }

        // Enrich active OTLP span and Admin Inspector TraceAnnotations
        if ctx.has_trace_collectors() {
            ctx.annotate_str("mcp.method", &meta.method);
            ctx.annotate_str("mcp.server", &meta.server);
            ctx.annotate_str("mcp.outcome", outcome);
            if let Some(ref tool) = meta.tool_name {
                ctx.annotate_str("mcp.tool", tool);
            }
            if let Some(ref sid) = meta.session_id {
                ctx.annotate_str("mcp.session_id", sid);
            }
            if let Some(ref ver) = meta.protocol_version {
                ctx.annotate_str("mcp.protocol_version", ver);
            }
            if let Some(p) = principal {
                ctx.annotate_str("mcp.principal", &p.id);
            }
            if let Some(g) = guardrail {
                ctx.annotate_bool("mcp.guardrail.blocked", g.blocked);
                ctx.annotate_bool("mcp.guardrail.redacted", g.redacted);
            }
        }

        if self.log_calls {
            let args_sha256 = meta
                .arguments
                .as_ref()
                .map(|a| sha256_hex(&canonical_json_bytes(a)));
            info!(
                request_id = summary.request_id,
                mcp_method = %meta.method,
                mcp_server = %meta.server,
                mcp_tool = %tool_label,
                mcp_principal = %principal.map(|p| p.id.as_str()).unwrap_or("-"),
                mcp_session = %meta.session_id.as_deref().unwrap_or("-"),
                mcp_outcome = %outcome,
                args_sha256 = %args_sha256.as_deref().unwrap_or("-"),
                status = status_code,
                duration_ms = summary.total_duration.as_millis() as u64,
                "mcp_audit"
            );
        }

        HookResult::Ready(())
    }
}

/// Builds a read-only JSON status snapshot of live `shunt-mcp` runtime state
/// for the Admin API (`GET /api/status` under `"mcp"`).
pub fn inspect_mcp_runtime(metrics: &McpMetrics, state: &StateStore, clock: &dyn Clock) -> Value {
    let now = clock.now();
    let metrics_snap = metrics.snapshot();

    let mut active_sessions = 0usize;
    let mut upstream_session_links = 0usize;
    for (_, _, table) in state.collect_by_type::<McpSessionTable>() {
        let s = table.snapshot(now);
        active_sessions += s.active_sessions;
        upstream_session_links += s.upstream_session_links;
    }

    let mut active_session_bindings = 0usize;
    for (_, _, table) in state.collect_by_type::<McpSessionBindingTable>() {
        active_session_bindings += table.active_count(now);
    }

    let mut cached_catalogs = 0usize;
    let mut cached_items = 0usize;
    for (_, _, table) in state.collect_by_type::<McpCatalogTable>() {
        let c = table.snapshot(now);
        cached_catalogs += c.cached_catalogs;
        cached_items += c.cached_items;
    }

    let mut guardrails = Vec::new();
    for (scope, _, table) in state.collect_by_type::<McpGuardrailStatsTable>() {
        guardrails.push(json!({
            "scope": scope,
            "stats": table.snapshot(),
        }));
    }

    let mut rate_limits = Vec::new();
    for (scope, _, table) in state.collect_by_type::<McpRateLimitTable>() {
        rate_limits.push(json!({
            "scope": scope,
            "stats": table.snapshot(now),
        }));
    }

    json!({
        "metrics": metrics_snap,
        "sessions": {
            "active_sessions": active_sessions,
            "upstream_session_links": upstream_session_links,
            "active_session_bindings": active_session_bindings,
        },
        "catalogs": {
            "cached_catalogs": cached_catalogs,
            "cached_items": cached_items,
        },
        "guardrails": guardrails,
        "rate_limits": rate_limits,
    })
}
