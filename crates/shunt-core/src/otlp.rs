use std::collections::BTreeMap;
use std::fmt;
use std::fmt::Write as _;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::Bytes;
use http::header::{self, HeaderName, HeaderValue};
use http::{Method, Request, Uri};
use http_body_util::{BodyExt, Full};
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;
use serde_json::{Value, json};
use shunt_plugin_sdk::{SpanRecord, SpanValue, TelemetrySink};
use tokio::sync::{mpsc, oneshot};
use tracing::warn;

use crate::tls::UpstreamTlsConfig;
use crate::upstream::ShuntConnector;

/// Configuration for the zero-dependency OTLP/HTTP JSON trace exporter (`POST /v1/traces`).
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct OtlpExporterConfig {
    pub endpoint: String,
    pub service_name: String,
    pub service_version: String,
    pub resource_attributes: BTreeMap<String, String>,
    pub headers: BTreeMap<String, String>,
    pub queue_capacity: usize,
    pub batch_size: usize,
    pub flush_interval: Duration,
    pub export_timeout: Duration,
    pub insecure_skip_verify: bool,
}

impl fmt::Debug for OtlpExporterConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let redacted_headers: Vec<&str> = self.headers.keys().map(String::as_str).collect();
        f.debug_struct("OtlpExporterConfig")
            .field("endpoint", &self.endpoint)
            .field("service_name", &self.service_name)
            .field("service_version", &self.service_version)
            .field("resource_attributes", &self.resource_attributes)
            .field("header_keys", &redacted_headers)
            .field("queue_capacity", &self.queue_capacity)
            .field("batch_size", &self.batch_size)
            .field("flush_interval", &self.flush_interval)
            .field("export_timeout", &self.export_timeout)
            .field("insecure_skip_verify", &self.insecure_skip_verify)
            .finish()
    }
}

impl Default for OtlpExporterConfig {
    fn default() -> Self {
        Self {
            endpoint: "http://127.0.0.1:4318/v1/traces".to_owned(),
            service_name: "shunt".to_owned(),
            service_version: env!("CARGO_PKG_VERSION").to_owned(),
            resource_attributes: BTreeMap::new(),
            headers: BTreeMap::new(),
            queue_capacity: 4096,
            batch_size: 128,
            flush_interval: Duration::from_millis(1000),
            export_timeout: Duration::from_millis(5000),
            insecure_skip_verify: false,
        }
    }
}

/// Snapshot of telemetry export counters.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct OtlpExporterStats {
    pub spans_enqueued: u64,
    pub spans_exported: u64,
    pub spans_dropped: u64,
    pub spans_failed: u64,
    pub export_errors: u64,
    pub batches_exported: u64,
}

#[derive(Debug, Default)]
struct AtomicOtlpStats {
    spans_enqueued: AtomicU64,
    spans_exported: AtomicU64,
    spans_dropped: AtomicU64,
    spans_failed: AtomicU64,
    export_errors: AtomicU64,
    batches_exported: AtomicU64,
}

impl AtomicOtlpStats {
    fn snapshot(&self) -> OtlpExporterStats {
        OtlpExporterStats {
            spans_enqueued: self.spans_enqueued.load(Ordering::Relaxed),
            spans_exported: self.spans_exported.load(Ordering::Relaxed),
            spans_dropped: self.spans_dropped.load(Ordering::Relaxed),
            spans_failed: self.spans_failed.load(Ordering::Relaxed),
            export_errors: self.export_errors.load(Ordering::Relaxed),
            batches_exported: self.batches_exported.load(Ordering::Relaxed),
        }
    }
}

enum ExporterCommand {
    Span(Box<SpanRecord>),
    Flush(oneshot::Sender<()>),
}

/// Non-blocking, bounded async OTLP/HTTP JSON trace exporter built on Shunt's `hyper` + `rustls` stack.
///
/// Spans are submitted via non-blocking `try_send` so telemetry never blocks the request hot path.
/// When the bounded queue is full, excess spans are dropped and counted under `spans_dropped`.
pub struct OtlpHttpExporter {
    config: Arc<OtlpExporterConfig>,
    tx: mpsc::Sender<ExporterCommand>,
    pending_rx: Mutex<Option<mpsc::Receiver<ExporterCommand>>>,
    stats: Arc<AtomicOtlpStats>,
}

impl fmt::Debug for OtlpHttpExporter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OtlpHttpExporter")
            .field("config", &self.config)
            .field("stats", &self.stats.snapshot())
            .finish()
    }
}

impl OtlpHttpExporter {
    pub fn new(config: OtlpExporterConfig) -> Self {
        let cap = config.queue_capacity.max(1);
        let (tx, rx) = mpsc::channel(cap);
        Self {
            config: Arc::new(config),
            tx,
            pending_rx: Mutex::new(Some(rx)),
            stats: Arc::new(AtomicOtlpStats::default()),
        }
    }

    pub fn config(&self) -> &OtlpExporterConfig {
        &self.config
    }

    pub fn stats(&self) -> OtlpExporterStats {
        self.stats.snapshot()
    }

    /// Lazily spawns the background batching worker on the active Tokio runtime.
    ///
    /// Returns `false` if called outside a Tokio runtime (e.g., synchronous `shunt check`),
    /// leaving the receiver intact until a runtime is active.
    fn ensure_worker_started(&self) -> bool {
        let Ok(handle) = tokio::runtime::Handle::try_current() else {
            return false;
        };
        let rx = {
            let mut guard = self
                .pending_rx
                .lock()
                .expect("OtlpHttpExporter pending_rx poisoned");
            guard.take()
        };
        if let Some(rx) = rx {
            let cfg = Arc::clone(&self.config);
            let stats = Arc::clone(&self.stats);
            handle.spawn(run_exporter_loop(cfg, rx, stats));
        }
        true
    }

    /// Flushes all currently queued spans to the OTLP collector up to `timeout`.
    pub async fn flush(&self, timeout: Duration) {
        if !self.ensure_worker_started() {
            return;
        }
        let (done_tx, done_rx) = oneshot::channel();
        if self.tx.send(ExporterCommand::Flush(done_tx)).await.is_err() {
            return;
        }
        let _ = tokio::time::timeout(timeout, done_rx).await;
    }

    /// Renders telemetry export counters in Prometheus text exposition format (v0.0.4).
    pub fn render_prometheus(&self) -> String {
        let s = self.stats.snapshot();
        if s.spans_enqueued == 0 && s.spans_dropped == 0 && s.export_errors == 0 {
            return String::new();
        }
        let mut out = String::with_capacity(256);
        out.push_str(
            "# HELP shunt_telemetry_spans_total Total telemetry spans processed by the OTLP exporter.\n",
        );
        out.push_str("# TYPE shunt_telemetry_spans_total counter\n");
        let _ = writeln!(
            out,
            "shunt_telemetry_spans_total{{backend=\"otlp_http\",result=\"exported\"}} {}",
            s.spans_exported
        );
        let _ = writeln!(
            out,
            "shunt_telemetry_spans_total{{backend=\"otlp_http\",result=\"dropped\"}} {}",
            s.spans_dropped
        );
        let _ = writeln!(
            out,
            "shunt_telemetry_spans_total{{backend=\"otlp_http\",result=\"failed\"}} {}",
            s.spans_failed
        );
        out.push_str(
            "# HELP shunt_telemetry_export_errors_total Total OTLP HTTP batch export failures.\n",
        );
        out.push_str("# TYPE shunt_telemetry_export_errors_total counter\n");
        let _ = writeln!(
            out,
            "shunt_telemetry_export_errors_total{{backend=\"otlp_http\"}} {}",
            s.export_errors
        );
        out
    }
}

impl TelemetrySink for OtlpHttpExporter {
    fn backend_name(&self) -> &str {
        "otlp_http"
    }

    fn emit_span(&self, span: SpanRecord) -> bool {
        let _ = self.ensure_worker_started();
        match self.tx.try_send(ExporterCommand::Span(Box::new(span))) {
            Ok(()) => {
                self.stats.spans_enqueued.fetch_add(1, Ordering::Relaxed);
                true
            }
            Err(_) => {
                self.stats.spans_dropped.fetch_add(1, Ordering::Relaxed);
                false
            }
        }
    }
}

async fn run_exporter_loop(
    config: Arc<OtlpExporterConfig>,
    mut rx: mpsc::Receiver<ExporterCommand>,
    stats: Arc<AtomicOtlpStats>,
) {
    let batch_limit = config.batch_size.max(1);
    let flush_interval = config.flush_interval.max(Duration::from_millis(10));

    let tls_cfg = UpstreamTlsConfig {
        extra_ca_pem: None,
        insecure_skip_verify: config.insecure_skip_verify,
        alpn_protocols: vec![b"h2".to_vec(), b"http/1.1".to_vec()],
    };
    let connector = match ShuntConnector::new(Duration::from_secs(5), &tls_cfg) {
        Ok(c) => c,
        Err(err) => {
            warn!(error = %err, "failed to initialize OTLP HTTP TLS connector; disabling export");
            return;
        }
    };
    let client: Client<ShuntConnector, Full<Bytes>> =
        Client::builder(TokioExecutor::new()).build(connector);

    let mut batch: Vec<SpanRecord> = Vec::with_capacity(batch_limit.min(512));
    let mut ticker = tokio::time::interval(flush_interval);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    // Consume the immediate first tick so we wait a full interval before idle flushing.
    ticker.tick().await;

    loop {
        tokio::select! {
            cmd = rx.recv() => {
                match cmd {
                    Some(ExporterCommand::Span(span)) => {
                        batch.push(*span);
                        if batch.len() >= batch_limit {
                            export_batch(&client, &config, &mut batch, &stats).await;
                        }
                    }
                    Some(ExporterCommand::Flush(done)) => {
                        while let Ok(next) = rx.try_recv() {
                            if let ExporterCommand::Span(span) = next {
                                batch.push(*span);
                            }
                        }
                        if !batch.is_empty() {
                            export_batch(&client, &config, &mut batch, &stats).await;
                        }
                        let _ = done.send(());
                    }
                    None => {
                        if !batch.is_empty() {
                            export_batch(&client, &config, &mut batch, &stats).await;
                        }
                        break;
                    }
                }
            }
            _ = ticker.tick() => {
                if !batch.is_empty() {
                    export_batch(&client, &config, &mut batch, &stats).await;
                }
            }
        }
    }
}

async fn export_batch(
    client: &Client<ShuntConnector, Full<Bytes>>,
    config: &OtlpExporterConfig,
    batch: &mut Vec<SpanRecord>,
    stats: &AtomicOtlpStats,
) {
    let spans = std::mem::take(batch);
    let count = spans.len() as u64;
    let payload = encode_otlp_traces_json(config, &spans);

    let uri: Uri = match config.endpoint.parse() {
        Ok(u) => u,
        Err(err) => {
            warn!(endpoint = %config.endpoint, error = %err, "invalid OTLP endpoint URI");
            stats.export_errors.fetch_add(1, Ordering::Relaxed);
            stats.spans_failed.fetch_add(count, Ordering::Relaxed);
            return;
        }
    };

    let mut req_builder = Request::builder()
        .method(Method::POST)
        .uri(uri)
        .header(header::CONTENT_TYPE, "application/json");

    for (k, v) in &config.headers {
        if let (Ok(name), Ok(val)) = (
            HeaderName::from_bytes(k.as_bytes()),
            HeaderValue::from_str(v),
        ) {
            req_builder = req_builder.header(name, val);
        }
    }

    let req = match req_builder.body(Full::new(Bytes::from(payload))) {
        Ok(r) => r,
        Err(err) => {
            warn!(error = %err, "failed to construct OTLP HTTP request");
            stats.export_errors.fetch_add(1, Ordering::Relaxed);
            stats.spans_failed.fetch_add(count, Ordering::Relaxed);
            return;
        }
    };

    let send_fut = async {
        let resp = client.request(req).await.map_err(|e| e.to_string())?;
        let status = resp.status();
        // Drain body so keep-alive connections can be reused cleanly.
        let _ = resp.into_body().collect().await;
        if status.is_success() {
            Ok(())
        } else {
            Err(format!("collector returned HTTP {status}"))
        }
    };

    match tokio::time::timeout(config.export_timeout, send_fut).await {
        Ok(Ok(())) => {
            stats.spans_exported.fetch_add(count, Ordering::Relaxed);
            stats.batches_exported.fetch_add(1, Ordering::Relaxed);
        }
        Ok(Err(err)) => {
            warn!(endpoint = %config.endpoint, error = %err, spans = count, "OTLP trace export failed");
            stats.export_errors.fetch_add(1, Ordering::Relaxed);
            stats.spans_failed.fetch_add(count, Ordering::Relaxed);
        }
        Err(_) => {
            warn!(endpoint = %config.endpoint, spans = count, "OTLP trace export timed out");
            stats.export_errors.fetch_add(1, Ordering::Relaxed);
            stats.spans_failed.fetch_add(count, Ordering::Relaxed);
        }
    }
}

/// Encodes a batch of [`SpanRecord`]s into standard OTLP/HTTP JSON (`ExportTraceServiceRequest`).
///
/// Follows the OpenTelemetry Protobuf-JSON specification:
/// - `traceId` / `spanId` / `parentSpanId`: lowercase hex strings
/// - `startTimeUnixNano` / `endTimeUnixNano` / `intValue`: base-10 strings (64-bit Proto3 JSON)
pub fn encode_otlp_traces_json(config: &OtlpExporterConfig, spans: &[SpanRecord]) -> Vec<u8> {
    let mut resource_attrs = Vec::with_capacity(config.resource_attributes.len() + 2);
    resource_attrs.push(json!({
        "key": "service.name",
        "value": { "stringValue": config.service_name }
    }));
    resource_attrs.push(json!({
        "key": "service.version",
        "value": { "stringValue": config.service_version }
    }));
    for (k, v) in &config.resource_attributes {
        if k == "service.name" || k == "service.version" {
            continue;
        }
        resource_attrs.push(json!({
            "key": k,
            "value": { "stringValue": v }
        }));
    }

    let otlp_spans: Vec<Value> = spans.iter().map(encode_single_span).collect();

    let payload = json!({
        "resourceSpans": [
            {
                "resource": {
                    "attributes": resource_attrs
                },
                "scopeSpans": [
                    {
                        "scope": {
                            "name": "shunt",
                            "version": config.service_version
                        },
                        "spans": otlp_spans
                    }
                ]
            }
        ]
    });

    serde_json::to_vec(&payload).unwrap_or_else(|_| b"{}".to_vec())
}

fn encode_attributes(attributes: &BTreeMap<String, SpanValue>) -> Vec<Value> {
    attributes
        .iter()
        .map(|(k, v)| {
            let val_json = match v {
                SpanValue::String(s) => json!({ "stringValue": s }),
                SpanValue::Int(i) => json!({ "intValue": i.to_string() }),
                SpanValue::Float(f) => json!({ "doubleValue": f }),
                SpanValue::Bool(b) => json!({ "boolValue": b }),
            };
            json!({ "key": k, "value": val_json })
        })
        .collect()
}

fn encode_single_span(span: &SpanRecord) -> Value {
    let attrs = encode_attributes(&span.attributes);

    let mut status_obj = serde_json::Map::new();
    status_obj.insert("code".to_owned(), json!(span.status as u8));
    if let Some(msg) = &span.status_message {
        status_obj.insert("message".to_owned(), json!(msg));
    }

    let mut obj = serde_json::Map::new();
    obj.insert("traceId".to_owned(), json!(span.trace_id_hex()));
    obj.insert("spanId".to_owned(), json!(span.span_id_hex()));
    if let Some(parent) = span.parent_span_id_hex() {
        obj.insert("parentSpanId".to_owned(), json!(parent));
    }
    obj.insert("flags".to_owned(), json!(span.trace_flags as u32));
    obj.insert("name".to_owned(), json!(span.name));
    obj.insert("kind".to_owned(), json!(span.kind as u8));
    obj.insert(
        "startTimeUnixNano".to_owned(),
        json!(span.start_time_unix_nanos.to_string()),
    );
    obj.insert(
        "endTimeUnixNano".to_owned(),
        json!(span.end_time_unix_nanos.to_string()),
    );
    obj.insert("attributes".to_owned(), Value::Array(attrs));
    if !span.events.is_empty() {
        let events: Vec<Value> = span
            .events
            .iter()
            .map(|ev| {
                json!({
                    "timeUnixNano": ev.time_unix_nanos.to_string(),
                    "name": ev.name,
                    "attributes": encode_attributes(&ev.attributes),
                })
            })
            .collect();
        obj.insert("events".to_owned(), Value::Array(events));
    }
    obj.insert("status".to_owned(), Value::Object(status_obj));

    Value::Object(obj)
}

#[cfg(test)]
mod tests {
    use std::convert::Infallible;
    use std::sync::Mutex as StdMutex;

    use hyper::server::conn::http1;
    use hyper::service::service_fn;
    use hyper_util::rt::TokioIo;
    use shunt_plugin_sdk::{SpanKind, SpanStatusCode, TraceContext};
    use tokio::net::TcpListener;

    use super::*;

    fn sample_span(name: &str) -> SpanRecord {
        let tc = TraceContext::new_root(true);
        let mut attributes = BTreeMap::new();
        attributes.insert(
            "http.request.method".to_owned(),
            SpanValue::String("POST".to_owned()),
        );
        attributes.insert("http.response.status_code".to_owned(), SpanValue::Int(200));
        attributes.insert("shunt.ai.cost_usd".to_owned(), SpanValue::Float(0.00125));
        attributes.insert("shunt.ai.stream".to_owned(), SpanValue::Bool(false));
        SpanRecord {
            trace_id: tc.trace_id,
            span_id: tc.span_id,
            parent_span_id: None,
            trace_flags: tc.trace_flags,
            name: name.to_owned(),
            kind: SpanKind::Server,
            start_time_unix_nanos: 1_700_000_000_000_000_000,
            end_time_unix_nanos: 1_700_000_000_050_000_000,
            status: SpanStatusCode::Ok,
            status_message: None,
            attributes,
            events: Vec::new(),
        }
    }

    #[test]
    fn encodes_valid_otlp_http_json_payload() {
        let cfg = OtlpExporterConfig {
            service_name: "shunt-edge".to_owned(),
            resource_attributes: BTreeMap::from([(
                "deployment.environment".to_owned(),
                "prod".to_owned(),
            )]),
            ..Default::default()
        };
        let mut span = sample_span("chat gpt-4o");
        span.events.push(shunt_plugin_sdk::SpanEvent {
            name: "gen_ai.content.prompt".to_owned(),
            time_unix_nanos: 1_700_000_000_010_000_000,
            attributes: BTreeMap::from([(
                "gen_ai.prompt".to_owned(),
                SpanValue::String("Hello [REDACTED:EMAIL]".to_owned()),
            )]),
        });
        let bytes = encode_otlp_traces_json(&cfg, std::slice::from_ref(&span));
        let v: Value = serde_json::from_slice(&bytes).expect("valid JSON");

        let rs = &v["resourceSpans"][0];
        assert_eq!(rs["resource"]["attributes"][0]["key"], "service.name");
        assert_eq!(
            rs["resource"]["attributes"][0]["value"]["stringValue"],
            "shunt-edge"
        );
        let s = &rs["scopeSpans"][0]["spans"][0];
        assert_eq!(s["traceId"], span.trace_id_hex());
        assert_eq!(s["spanId"], span.span_id_hex());
        assert_eq!(s["name"], "chat gpt-4o");
        assert_eq!(s["kind"], 2);
        assert_eq!(s["startTimeUnixNano"], "1700000000000000000");
        assert_eq!(s["status"]["code"], 1);
        assert_eq!(s["events"][0]["name"], "gen_ai.content.prompt");
        assert_eq!(s["events"][0]["timeUnixNano"], "1700000000010000000");
        assert_eq!(
            s["events"][0]["attributes"][0]["value"]["stringValue"],
            "Hello [REDACTED:EMAIL]"
        );
    }

    #[tokio::test]
    async fn exports_batched_spans_to_mock_collector_and_counts_drops() {
        type CapturedOtlpBatch = (Option<String>, Value);
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let received: Arc<StdMutex<Vec<CapturedOtlpBatch>>> = Arc::new(StdMutex::new(Vec::new()));
        let rec_srv = Arc::clone(&received);

        let srv = tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                let rec_conn = Arc::clone(&rec_srv);
                tokio::spawn(async move {
                    let svc = service_fn(move |req: Request<hyper::body::Incoming>| {
                        let rec = Arc::clone(&rec_conn);
                        async move {
                            let auth = req
                                .headers()
                                .get(header::AUTHORIZATION)
                                .and_then(|v| v.to_str().ok())
                                .map(str::to_owned);
                            let body = req.into_body().collect().await.unwrap().to_bytes();
                            let json: Value = serde_json::from_slice(&body).unwrap();
                            rec.lock().unwrap().push((auth, json));
                            Ok::<_, Infallible>(
                                http::Response::builder()
                                    .status(http::StatusCode::OK)
                                    .body(Full::new(Bytes::from_static(b"{}")))
                                    .unwrap(),
                            )
                        }
                    });
                    let _ = http1::Builder::new()
                        .serve_connection(TokioIo::new(stream), svc)
                        .await;
                });
            }
        });

        let exporter = OtlpHttpExporter::new(OtlpExporterConfig {
            endpoint: format!("http://{addr}/v1/traces"),
            service_name: "shunt-test".to_owned(),
            headers: BTreeMap::from([(
                "Authorization".to_owned(),
                "Bearer secret-otlp".to_owned(),
            )]),
            queue_capacity: 16,
            batch_size: 2,
            flush_interval: Duration::from_secs(10),
            export_timeout: Duration::from_secs(2),
            ..Default::default()
        });

        assert!(exporter.emit_span(sample_span("span-1")));
        assert!(exporter.emit_span(sample_span("span-2")));
        exporter.flush(Duration::from_secs(2)).await;

        let stats = exporter.stats();
        assert_eq!(stats.spans_enqueued, 2);
        assert_eq!(stats.spans_exported, 2);
        assert_eq!(stats.spans_dropped, 0);
        assert_eq!(stats.export_errors, 0);

        let captured = received.lock().unwrap();
        assert_eq!(captured.len(), 1);
        assert_eq!(captured[0].0.as_deref(), Some("Bearer secret-otlp"));
        assert_eq!(
            captured[0].1["resourceSpans"][0]["scopeSpans"][0]["spans"]
                .as_array()
                .unwrap()
                .len(),
            2
        );

        let prom = exporter.render_prometheus();
        assert!(
            prom.contains(
                "shunt_telemetry_spans_total{backend=\"otlp_http\",result=\"exported\"} 2"
            )
        );

        srv.abort();
    }

    #[test]
    fn bounded_queue_drops_without_blocking_when_full() {
        // Without a Tokio runtime, the worker is not started, so filling capacity=2 drops #3 cleanly.
        let exporter = OtlpHttpExporter::new(OtlpExporterConfig {
            queue_capacity: 2,
            ..Default::default()
        });
        assert!(exporter.emit_span(sample_span("s1")));
        assert!(exporter.emit_span(sample_span("s2")));
        assert!(!exporter.emit_span(sample_span("s3")));
        let stats = exporter.stats();
        assert_eq!(stats.spans_enqueued, 2);
        assert_eq!(stats.spans_dropped, 1);
    }
}
