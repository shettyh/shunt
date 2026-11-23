use std::collections::BTreeMap;
use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use http::{Method, Request, Response, StatusCode, header};
use http_body::Frame;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use serde::Serialize;
use shunt_engine::{CoreError, ShuntBody};
use tokio::net::TcpListener;
use tokio::sync::{broadcast, mpsc, watch};
use tracing::{debug, info, warn};

use crate::compiler::SnapshotInspect;
use crate::error::ConfigError;
use crate::inspector::{
    InspectorTrace, TraceRingBuffer, TraceRingSummary, format_sse_lagged_event,
    format_sse_trace_event,
};
use crate::reloader::ReloadController;

/// Callback rendering Prometheus text exposition metrics for `GET /metrics`.
pub type MetricsRenderer = Arc<dyn Fn() -> String + Send + Sync>;

/// Pluggable read-only JSON status provider rendered under `GET /api/status` (`extensions.<name>`).
///
/// Allows domain plugin packs (e.g., `shunt-ai`) to expose live usage, cooldowns, latency tables,
/// and cache stats on the Admin Inspector without coupling `shunt-config` to AI types.
pub type StatusProvider = Arc<dyn Fn() -> serde_json::Value + Send + Sync>;

/// Whether this build includes the embedded Admin Inspector Web UI assets (`admin-ui` Cargo feature).
pub const fn ui_feature_compiled() -> bool {
    cfg!(feature = "admin-ui")
}

/// Dedicated Admin API server (`127.0.0.1:9090` by default).
///
/// Always bound to a separate listener from the public proxy data plane.
/// Exposes:
/// - `GET /health`
/// - `GET /metrics`
/// - `GET /snapshot`
/// - `GET /upstreams`
/// - `GET /api/status`
/// - `POST /reload`
///
/// And when opt-in Inspector UI / trace capture is enabled (`--ui` or `[admin] ui = true`):
/// - `GET /` and `GET /ui` (embedded read-only Inspector Web UI)
/// - `GET /api/traces` (bounded in-memory trace ring buffer + rolling latency/status summary)
/// - `GET /api/traces/stream` (live SSE stream of completed traces with `Last-Event-ID` replay)
pub struct AdminServer {
    controller: Arc<ReloadController>,
    metrics_renderer: MetricsRenderer,
    ui_enabled: bool,
    trace_store: Option<Arc<TraceRingBuffer>>,
    status_providers: BTreeMap<String, StatusProvider>,
}

struct AdminState {
    controller: Arc<ReloadController>,
    metrics_renderer: MetricsRenderer,
    ui_enabled: bool,
    trace_store: Option<Arc<TraceRingBuffer>>,
    status_providers: BTreeMap<String, StatusProvider>,
    shutdown_rx: watch::Receiver<bool>,
}

impl AdminServer {
    pub fn new(controller: Arc<ReloadController>, metrics_renderer: MetricsRenderer) -> Self {
        Self {
            controller,
            metrics_renderer,
            ui_enabled: false,
            trace_store: None,
            status_providers: BTreeMap::new(),
        }
    }

    /// Enables or disables serving the embedded read-only Admin Inspector Web UI on `/` and `/ui`.
    pub fn with_ui_enabled(mut self, enabled: bool) -> Self {
        self.ui_enabled = enabled;
        self
    }

    /// Attaches a bounded in-memory [`TraceRingBuffer`] backing `GET /api/traces` and
    /// `GET /api/traces/stream`.
    pub fn with_trace_store(mut self, store: Arc<TraceRingBuffer>) -> Self {
        self.trace_store = Some(store);
        self
    }

    /// Registers a named read-only JSON status provider exposed under `GET /api/status`.
    pub fn with_status_provider(
        mut self,
        name: impl Into<String>,
        provider: StatusProvider,
    ) -> Self {
        self.status_providers.insert(name.into(), provider);
        self
    }

    pub async fn bind(self, addr: SocketAddr) -> Result<AdminHandle, ConfigError> {
        let listener = TcpListener::bind(addr).await.map_err(|e| {
            ConfigError::Admin(format!("failed to bind admin listener {addr}: {e}"))
        })?;
        let local_addr = listener
            .local_addr()
            .map_err(|e| ConfigError::Admin(e.to_string()))?;

        let (shutdown_tx, mut shutdown_rx) = watch::channel(false);
        let state = Arc::new(AdminState {
            controller: self.controller,
            metrics_renderer: self.metrics_renderer,
            ui_enabled: self.ui_enabled && ui_feature_compiled(),
            trace_store: self.trace_store,
            status_providers: self.status_providers,
            shutdown_rx: shutdown_rx.clone(),
        });

        info!(%local_addr, ui = state.ui_enabled, "shunt admin listener started");

        let task = tokio::spawn(async move {
            loop {
                tokio::select! {
                    biased;
                    _ = shutdown_rx.changed() => {
                        if *shutdown_rx.borrow() {
                            break;
                        }
                    }
                    res = listener.accept() => {
                        let (tcp, peer) = match res {
                            Ok(pair) => pair,
                            Err(e) => {
                                warn!(error = %e, "admin accept error");
                                continue;
                            }
                        };
                        let st = Arc::clone(&state);
                        tokio::spawn(async move {
                            let svc = service_fn(move |req: Request<hyper::body::Incoming>| {
                                let st = Arc::clone(&st);
                                async move {
                                    Ok::<_, Infallible>(handle_admin_request(req, &st))
                                }
                            });
                            if let Err(e) = http1::Builder::new()
                                .serve_connection(TokioIo::new(tcp), svc)
                                .await
                            {
                                debug!(%peer, error = %e, "admin connection closed");
                            }
                        });
                    }
                }
            }
        });

        Ok(AdminHandle {
            local_addr,
            shutdown_tx,
            task: Some(task),
        })
    }
}

pub struct AdminHandle {
    local_addr: SocketAddr,
    shutdown_tx: watch::Sender<bool>,
    task: Option<tokio::task::JoinHandle<()>>,
}

impl AdminHandle {
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    pub async fn shutdown(mut self) {
        let _ = self.shutdown_tx.send(true);
        if let Some(task) = self.task.take() {
            let _ = task.await;
        }
    }
}

#[derive(Serialize)]
struct HealthBody<'a> {
    status: &'static str,
    version: u64,
    digest: &'a str,
    routes: usize,
    upstreams: usize,
}

#[derive(Serialize)]
struct EndpointHealthBody {
    url: String,
    weight: u32,
    healthy: bool,
    active_healthy: bool,
    passive_healthy: bool,
    passive_failures: usize,
    active_probes_ok: u64,
    active_probes_err: u64,
    last_probe_latency_us: u64,
}

#[derive(Serialize)]
struct UpstreamHealthBody {
    name: String,
    pool_id: u64,
    active_health_check: bool,
    endpoints: Vec<EndpointHealthBody>,
}

#[derive(Serialize)]
struct UpstreamsResponseBody {
    version: u64,
    upstreams: Vec<UpstreamHealthBody>,
}

#[derive(Serialize)]
struct ReloadOkBody {
    reloaded: bool,
    snapshot: SnapshotInspect,
}

#[derive(Serialize)]
struct ReloadErrBody {
    reloaded: bool,
    error: String,
}

#[derive(Serialize)]
struct TracesResponseBody {
    summary: TraceRingSummary,
    traces: Vec<InspectorTrace>,
}

#[derive(Serialize)]
struct StatusResponseBody<'a> {
    version: u64,
    digest: &'a str,
    state_backend: &'a str,
    telemetry_backend: &'a str,
    ui_enabled: bool,
    ui_compiled: bool,
    trace_capture_enabled: bool,
    extensions: BTreeMap<String, serde_json::Value>,
}

fn handle_admin_request(
    req: Request<hyper::body::Incoming>,
    state: &AdminState,
) -> Response<ShuntBody> {
    match (req.method(), req.uri().path()) {
        (&Method::GET, "/" | "/ui") => {
            if !state.ui_enabled {
                return text_response(StatusCode::NOT_FOUND, "not found");
            }
            serve_inspector_ui()
        }
        (&Method::GET, "/health") => {
            let snap = state.controller.current_inspect();
            let body = HealthBody {
                status: "ok",
                version: snap.version,
                digest: &snap.digest,
                routes: snap.routes.len(),
                upstreams: snap.upstreams.len(),
            };
            json_response(StatusCode::OK, &body)
        }
        (&Method::GET, "/snapshot") => {
            let snap = state.controller.current_inspect();
            json_response(StatusCode::OK, &*snap)
        }
        (&Method::GET, "/upstreams") => {
            let snapshot = state.controller.current_snapshot();
            let reports = snapshot.upstream_health_reports();
            let body = UpstreamsResponseBody {
                version: snapshot.version,
                upstreams: reports
                    .into_iter()
                    .map(|r| UpstreamHealthBody {
                        name: r.name,
                        pool_id: r.pool_id,
                        active_health_check: r.active_health_check,
                        endpoints: r
                            .endpoints
                            .into_iter()
                            .map(|ep| EndpointHealthBody {
                                url: ep.url,
                                weight: ep.weight,
                                healthy: ep.healthy,
                                active_healthy: ep.active_healthy,
                                passive_healthy: ep.passive_healthy,
                                passive_failures: ep.passive_failures,
                                active_probes_ok: ep.active_probes_ok,
                                active_probes_err: ep.active_probes_err,
                                last_probe_latency_us: ep.last_probe_latency_us,
                            })
                            .collect(),
                    })
                    .collect(),
            };
            json_response(StatusCode::OK, &body)
        }
        (&Method::GET, "/metrics") => {
            let rendered = (state.metrics_renderer)();
            Response::builder()
                .status(StatusCode::OK)
                .header(
                    header::CONTENT_TYPE,
                    "text/plain; version=0.0.4; charset=utf-8",
                )
                .header(header::CACHE_CONTROL, "no-store")
                .body(ShuntBody::full(Bytes::from(rendered)))
                .unwrap()
        }
        (&Method::GET, "/api/status") => {
            let snap = state.controller.current_inspect();
            let mut extensions = BTreeMap::new();
            for (name, provider) in &state.status_providers {
                extensions.insert(name.clone(), provider());
            }
            let body = StatusResponseBody {
                version: snap.version,
                digest: &snap.digest,
                state_backend: &snap.state_backend,
                telemetry_backend: &snap.telemetry_backend,
                ui_enabled: state.ui_enabled,
                ui_compiled: ui_feature_compiled(),
                trace_capture_enabled: state.trace_store.is_some(),
                extensions,
            };
            json_response(StatusCode::OK, &body)
        }
        (&Method::GET, "/api/traces") => {
            let Some(store) = &state.trace_store else {
                return text_response(StatusCode::NOT_FOUND, "trace inspector disabled");
            };
            let after_seq = parse_query_u64(req.uri().query(), "after");
            let limit = parse_query_u64(req.uri().query(), "limit").map(|v| v as usize);
            let body = TracesResponseBody {
                summary: store.summary(),
                traces: store.recent(after_seq, limit),
            };
            json_response(StatusCode::OK, &body)
        }
        (&Method::GET, "/api/traces/stream") => {
            let Some(store) = &state.trace_store else {
                return text_response(StatusCode::NOT_FOUND, "trace inspector disabled");
            };
            let after_seq = req
                .headers()
                .get("last-event-id")
                .and_then(|v| v.to_str().ok())
                .and_then(|s| s.trim().parse::<u64>().ok())
                .or_else(|| parse_query_u64(req.uri().query(), "after"));
            serve_trace_sse(Arc::clone(store), after_seq, state.shutdown_rx.clone())
        }
        (&Method::POST, "/reload") => match state.controller.reload() {
            Ok(snapshot) => json_response(
                StatusCode::OK,
                &ReloadOkBody {
                    reloaded: true,
                    snapshot,
                },
            ),
            Err(err) => json_response(
                StatusCode::UNPROCESSABLE_ENTITY,
                &ReloadErrBody {
                    reloaded: false,
                    error: err.to_string(),
                },
            ),
        },
        (_, "/health" | "/snapshot" | "/upstreams" | "/metrics" | "/reload" | "/api/status") => {
            text_response(StatusCode::METHOD_NOT_ALLOWED, "method not allowed")
        }
        (_, "/" | "/ui") if state.ui_enabled => {
            text_response(StatusCode::METHOD_NOT_ALLOWED, "method not allowed")
        }
        (_, "/api/traces" | "/api/traces/stream") if state.trace_store.is_some() => {
            text_response(StatusCode::METHOD_NOT_ALLOWED, "method not allowed")
        }
        _ => text_response(StatusCode::NOT_FOUND, "not found"),
    }
}

fn serve_inspector_ui() -> Response<ShuntBody> {
    #[cfg(feature = "admin-ui")]
    {
        Response::builder()
            .status(StatusCode::OK)
            .header(header::CONTENT_TYPE, "text/html; charset=utf-8")
            .header(header::CACHE_CONTROL, "no-store")
            .header("x-content-type-options", "nosniff")
            .header("x-frame-options", "DENY")
            .header("referrer-policy", "no-referrer")
            .header(
                "content-security-policy",
                "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self'; img-src 'self' data:; frame-ancestors 'none'; base-uri 'none'",
            )
            .body(ShuntBody::full(Bytes::from_static(
                crate::ui::INSPECTOR_HTML.as_bytes(),
            )))
            .unwrap()
    }
    #[cfg(not(feature = "admin-ui"))]
    {
        text_response(StatusCode::NOT_FOUND, "not found")
    }
}

fn serve_trace_sse(
    store: Arc<TraceRingBuffer>,
    after_seq: Option<u64>,
    mut shutdown_rx: watch::Receiver<bool>,
) -> Response<ShuntBody> {
    // Subscribe BEFORE reading the ring-buffer snapshot so no events between replay and live
    // subscription can ever be lost; duplicate seqs are filtered cleanly via `last_sent_seq`.
    let mut rx = store.subscribe();
    let replay = store.recent(after_seq, None);
    let (tx, body_rx) = mpsc::channel::<Result<Frame<Bytes>, CoreError>>(64);

    tokio::spawn(async move {
        let mut last_sent_seq = after_seq.unwrap_or(0);

        if tx
            .send(Ok(Frame::data(Bytes::from_static(b": connected\n\n"))))
            .await
            .is_err()
        {
            return;
        }

        for trace in replay {
            if trace.seq <= last_sent_seq {
                continue;
            }
            last_sent_seq = trace.seq;
            if tx
                .send(Ok(Frame::data(format_sse_trace_event(&trace))))
                .await
                .is_err()
            {
                return;
            }
        }

        let mut keepalive = tokio::time::interval(Duration::from_secs(15));
        keepalive.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        keepalive.tick().await;

        loop {
            tokio::select! {
                biased;
                _ = shutdown_rx.changed() => {
                    if *shutdown_rx.borrow() {
                        break;
                    }
                }
                _ = tx.closed() => {
                    break;
                }
                recv = rx.recv() => {
                    match recv {
                        Ok(trace) => {
                            if trace.seq <= last_sent_seq {
                                continue;
                            }
                            last_sent_seq = trace.seq;
                            if tx.send(Ok(Frame::data(format_sse_trace_event(&trace)))).await.is_err() {
                                break;
                            }
                        }
                        Err(broadcast::error::RecvError::Lagged(skipped)) => {
                            if tx.send(Ok(Frame::data(format_sse_lagged_event(skipped)))).await.is_err() {
                                break;
                            }
                        }
                        Err(broadcast::error::RecvError::Closed) => {
                            break;
                        }
                    }
                }
                _ = keepalive.tick() => {
                    if tx.send(Ok(Frame::data(Bytes::from_static(b": keep-alive\n\n")))).await.is_err() {
                        break;
                    }
                }
            }
        }
    });

    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "text/event-stream; charset=utf-8")
        .header(header::CACHE_CONTROL, "no-cache, no-store")
        .header("x-accel-buffering", "no")
        .body(ShuntBody::channel(body_rx))
        .unwrap()
}

fn parse_query_u64(query: Option<&str>, key: &str) -> Option<u64> {
    let q = query?;
    for pair in q.split('&') {
        if let Some((k, v)) = pair.split_once('=')
            && k == key
        {
            return v.parse::<u64>().ok();
        }
    }
    None
}

fn json_response<T: Serialize>(status: StatusCode, payload: &T) -> Response<ShuntBody> {
    let body = serde_json::to_vec_pretty(payload).unwrap_or_else(|_| b"{}".to_vec());
    Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::CACHE_CONTROL, "no-store")
        .body(ShuntBody::full(Bytes::from(body)))
        .unwrap()
}

fn text_response(status: StatusCode, body: &'static str) -> Response<ShuntBody> {
    Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, "text/plain; charset=utf-8")
        .body(ShuntBody::full(Bytes::from_static(body.as_bytes())))
        .unwrap()
}
