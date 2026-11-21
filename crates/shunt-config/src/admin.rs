use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;

use bytes::Bytes;
use http::{Method, Request, Response, StatusCode, header};
use http_body_util::Full;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use serde::Serialize;
use tokio::net::TcpListener;
use tokio::sync::watch;
use tracing::{debug, info, warn};

use crate::compiler::SnapshotInspect;
use crate::error::ConfigError;
use crate::reloader::ReloadController;

/// Callback rendering Prometheus text exposition metrics for `GET /metrics`.
pub type MetricsRenderer = Arc<dyn Fn() -> String + Send + Sync>;

/// Dedicated read-only Admin API server (`127.0.0.1:9090` by default).
///
/// Always bound to a separate listener from the public proxy data plane.
/// Exposes:
/// - `GET /health`
/// - `GET /metrics`
/// - `GET /snapshot`
/// - `POST /reload`
pub struct AdminServer {
    controller: Arc<ReloadController>,
    metrics_renderer: MetricsRenderer,
}

impl AdminServer {
    pub fn new(controller: Arc<ReloadController>, metrics_renderer: MetricsRenderer) -> Self {
        Self {
            controller,
            metrics_renderer,
        }
    }

    pub async fn bind(self, addr: SocketAddr) -> Result<AdminHandle, ConfigError> {
        let listener = TcpListener::bind(addr).await.map_err(|e| {
            ConfigError::Admin(format!("failed to bind admin listener {addr}: {e}"))
        })?;
        let local_addr = listener
            .local_addr()
            .map_err(|e| ConfigError::Admin(e.to_string()))?;

        let (shutdown_tx, mut shutdown_rx) = watch::channel(false);
        let controller = self.controller;
        let metrics = self.metrics_renderer;

        info!(%local_addr, "shunt admin listener started");

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
                        let ctrl = Arc::clone(&controller);
                        let met = Arc::clone(&metrics);
                        tokio::spawn(async move {
                            let svc = service_fn(move |req: Request<hyper::body::Incoming>| {
                                let ctrl = Arc::clone(&ctrl);
                                let met = Arc::clone(&met);
                                async move {
                                    Ok::<_, Infallible>(handle_admin_request(req, &ctrl, &met))
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

fn handle_admin_request(
    req: Request<hyper::body::Incoming>,
    controller: &ReloadController,
    metrics_renderer: &MetricsRenderer,
) -> Response<Full<Bytes>> {
    match (req.method(), req.uri().path()) {
        (&Method::GET, "/health") => {
            let snap = controller.current_inspect();
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
            let snap = controller.current_inspect();
            json_response(StatusCode::OK, &*snap)
        }
        (&Method::GET, "/upstreams") => {
            let snapshot = controller.current_snapshot();
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
            let rendered = metrics_renderer();
            Response::builder()
                .status(StatusCode::OK)
                .header(
                    header::CONTENT_TYPE,
                    "text/plain; version=0.0.4; charset=utf-8",
                )
                .body(Full::new(Bytes::from(rendered)))
                .unwrap()
        }
        (&Method::POST, "/reload") => match controller.reload() {
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
        (_, "/health" | "/snapshot" | "/upstreams" | "/metrics" | "/reload") => {
            text_response(StatusCode::METHOD_NOT_ALLOWED, "method not allowed")
        }
        _ => text_response(StatusCode::NOT_FOUND, "not found"),
    }
}

fn json_response<T: Serialize>(status: StatusCode, payload: &T) -> Response<Full<Bytes>> {
    let body = serde_json::to_vec_pretty(payload).unwrap_or_else(|_| b"{}".to_vec());
    Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Full::new(Bytes::from(body)))
        .unwrap()
}

fn text_response(status: StatusCode, body: &'static str) -> Response<Full<Bytes>> {
    Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, "text/plain; charset=utf-8")
        .body(Full::new(Bytes::from_static(body.as_bytes())))
        .unwrap()
}
