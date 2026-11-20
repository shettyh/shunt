use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::sync::{Arc, RwLock};

use shunt_plugin_sdk::{
    BuildContext, HookMask, HookResult, HttpPlugin, PluginBuildError, PluginConfig, PluginFactory,
    RequestCtx, RequestSummary,
};

const LATENCY_BUCKETS: &[f64] = &[
    0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0,
];

#[derive(Debug, Clone)]
struct HistogramState {
    /// Cumulative per-bucket counts (length = LATENCY_BUCKETS.len() + 1 for +Inf).
    buckets: Vec<u64>,
    sum: f64,
    count: u64,
}

impl Default for HistogramState {
    fn default() -> Self {
        Self::new()
    }
}

impl HistogramState {
    fn new() -> Self {
        Self {
            buckets: vec![0; LATENCY_BUCKETS.len() + 1],
            sum: 0.0,
            count: 0,
        }
    }

    fn observe(&mut self, value_secs: f64) {
        self.sum += value_secs;
        self.count += 1;
        for (idx, &bound) in LATENCY_BUCKETS.iter().enumerate() {
            if value_secs <= bound {
                self.buckets[idx] += 1;
            }
        }
        *self.buckets.last_mut().unwrap() += 1;
    }
}

#[derive(Debug, Default)]
struct MetricsData {
    /// (route, upstream, status) -> count
    requests_total: BTreeMap<(String, String, u16), u64>,
    /// (route, upstream) -> histogram
    request_duration: BTreeMap<(String, String), HistogramState>,
    /// (route, upstream) -> histogram
    upstream_ttfb: BTreeMap<(String, String), HistogramState>,
    /// route -> bytes
    request_bytes: BTreeMap<String, u64>,
    /// route -> bytes
    response_bytes: BTreeMap<String, u64>,
    /// route -> count
    stream_aborts: BTreeMap<String, u64>,
}

/// Shared, thread-safe Prometheus metrics registry updated by [`MetricsPlugin`]
/// and exposed via the read-only Admin API (`GET /metrics`).
#[derive(Debug, Default)]
pub struct PrometheusMetrics {
    inner: RwLock<MetricsData>,
}

impl PrometheusMetrics {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn record(&self, summary: &RequestSummary) {
        let route = summary
            .route_id
            .clone()
            .unwrap_or_else(|| "unmatched".to_owned());
        let upstream = summary
            .upstream
            .clone()
            .unwrap_or_else(|| "none".to_owned());
        let status = summary.status.map(|s| s.as_u16()).unwrap_or(0);

        let mut data = self.inner.write().expect("PrometheusMetrics lock poisoned");

        *data
            .requests_total
            .entry((route.clone(), upstream.clone(), status))
            .or_insert(0) += 1;

        data.request_duration
            .entry((route.clone(), upstream.clone()))
            .or_default()
            .observe(summary.total_duration.as_secs_f64());

        if let Some(ttfb) = summary.ttfb {
            data.upstream_ttfb
                .entry((route.clone(), upstream))
                .or_default()
                .observe(ttfb.as_secs_f64());
        }

        *data.request_bytes.entry(route.clone()).or_insert(0) += summary.request_bytes;
        *data.response_bytes.entry(route.clone()).or_insert(0) += summary.response_bytes;

        if summary.aborted_mid_stream {
            *data.stream_aborts.entry(route).or_insert(0) += 1;
        }
    }

    /// Renders all collected metrics in standard Prometheus text exposition format (v0.0.4).
    pub fn render_prometheus(&self) -> String {
        let data = self.inner.read().expect("PrometheusMetrics lock poisoned");
        let mut out = String::with_capacity(2048);

        out.push_str("# HELP shunt_requests_total Total HTTP requests handled by Shunt.\n");
        out.push_str("# TYPE shunt_requests_total counter\n");
        for ((route, upstream, status), count) in &data.requests_total {
            let _ = writeln!(
                out,
                "shunt_requests_total{{route=\"{}\",upstream=\"{}\",status=\"{}\"}} {}",
                escape_label(route),
                escape_label(upstream),
                status,
                count
            );
        }

        out.push_str(
            "# HELP shunt_request_duration_seconds End-to-end HTTP request duration in seconds.\n",
        );
        out.push_str("# TYPE shunt_request_duration_seconds histogram\n");
        for ((route, upstream), hist) in &data.request_duration {
            render_histogram(&mut out, "shunt_request_duration_seconds", route, upstream, hist);
        }

        out.push_str(
            "# HELP shunt_upstream_ttfb_seconds Time to upstream response headers (TTFB) in seconds.\n",
        );
        out.push_str("# TYPE shunt_upstream_ttfb_seconds histogram\n");
        for ((route, upstream), hist) in &data.upstream_ttfb {
            render_histogram(&mut out, "shunt_upstream_ttfb_seconds", route, upstream, hist);
        }

        out.push_str("# HELP shunt_request_bytes_total Total incoming request body bytes.\n");
        out.push_str("# TYPE shunt_request_bytes_total counter\n");
        for (route, bytes) in &data.request_bytes {
            let _ = writeln!(
                out,
                "shunt_request_bytes_total{{route=\"{}\"}} {}",
                escape_label(route),
                bytes
            );
        }

        out.push_str("# HELP shunt_response_bytes_total Total outgoing response body bytes.\n");
        out.push_str("# TYPE shunt_response_bytes_total counter\n");
        for (route, bytes) in &data.response_bytes {
            let _ = writeln!(
                out,
                "shunt_response_bytes_total{{route=\"{}\"}} {}",
                escape_label(route),
                bytes
            );
        }

        out.push_str("# HELP shunt_stream_aborts_total Total responses aborted mid-stream.\n");
        out.push_str("# TYPE shunt_stream_aborts_total counter\n");
        for (route, count) in &data.stream_aborts {
            let _ = writeln!(
                out,
                "shunt_stream_aborts_total{{route=\"{}\"}} {}",
                escape_label(route),
                count
            );
        }

        out
    }
}

fn render_histogram(
    out: &mut String,
    metric: &str,
    route: &str,
    upstream: &str,
    hist: &HistogramState,
) {
    let r = escape_label(route);
    let u = escape_label(upstream);
    for (idx, &bound) in LATENCY_BUCKETS.iter().enumerate() {
        let _ = writeln!(
            out,
            "{metric}_bucket{{route=\"{r}\",upstream=\"{u}\",le=\"{bound}\"}} {}",
            hist.buckets[idx]
        );
    }
    let _ = writeln!(
        out,
        "{metric}_bucket{{route=\"{r}\",upstream=\"{u}\",le=\"+Inf\"}} {}",
        hist.buckets[LATENCY_BUCKETS.len()]
    );
    let _ = writeln!(
        out,
        "{metric}_sum{{route=\"{r}\",upstream=\"{u}\"}} {:.6}",
        hist.sum
    );
    let _ = writeln!(
        out,
        "{metric}_count{{route=\"{r}\",upstream=\"{u}\"}} {}",
        hist.count
    );
}

fn escape_label(s: &str) -> String {
    s.replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
}

pub struct MetricsFactory {
    store: Arc<PrometheusMetrics>,
}

impl MetricsFactory {
    pub fn new(store: Arc<PrometheusMetrics>) -> Self {
        Self { store }
    }
}

impl PluginFactory for MetricsFactory {
    fn name(&self) -> &str {
        "metrics"
    }

    fn build(
        &self,
        _config: &PluginConfig,
        _ctx: &BuildContext,
    ) -> Result<Arc<dyn HttpPlugin>, PluginBuildError> {
        Ok(Arc::new(MetricsPlugin {
            store: Arc::clone(&self.store),
        }))
    }
}

pub struct MetricsPlugin {
    store: Arc<PrometheusMetrics>,
}

impl HttpPlugin for MetricsPlugin {
    fn name(&self) -> &str {
        "metrics"
    }

    fn hook_mask(&self) -> HookMask {
        HookMask::ON_COMPLETE
    }

    fn on_complete<'a>(
        &'a self,
        _ctx: &'a RequestCtx,
        summary: &'a RequestSummary,
    ) -> HookResult<'a, ()> {
        self.store.record(summary);
        HookResult::Ready(())
    }
}
