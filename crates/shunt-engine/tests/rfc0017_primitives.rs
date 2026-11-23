//! Core engine integration tests for RFC 0017 AI-free primitives:
//! - Per-attempt `UpstreamSelection::response_headers_timeout_override`
//! - Pre-flush `Flow::InspectResponseBody` + `on_response_body_inspected` (retry & verbatim passthrough)
//! - Route-level fire-and-forget HTTP traffic mirroring (`TrafficMirrorSpec`)

use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::Bytes;
use http::{HeaderName, HeaderValue, Method, Request, Response, StatusCode};
use http_body_util::{BodyExt, Full};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::client::legacy::Client;
use hyper_util::rt::{TokioExecutor, TokioIo};
use shunt_engine::{
    GatewayServer, RouteMatch, RouteSpec, RuntimeRegistry, SnapshotBuilder, TimeoutConfig,
    TrafficMirrorSpec, UpstreamConfig,
};
use shunt_plugin_sdk::{
    Flow, HookMask, HookResult, HttpPlugin, RequestCtx, ResponseHead, UpstreamSelection,
};
use tokio::net::TcpListener;

async fn spawn_backend<F, Fut>(handler: F) -> SocketAddr
where
    F: Fn(Request<Bytes>) -> Fut + Send + Sync + 'static,
    Fut: std::future::Future<Output = Response<Full<Bytes>>> + Send + 'static,
{
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handler = Arc::new(handler);
    tokio::spawn(async move {
        loop {
            let Ok((tcp, _)) = listener.accept().await else {
                break;
            };
            let h = Arc::clone(&handler);
            tokio::spawn(async move {
                let svc = service_fn(move |req: Request<hyper::body::Incoming>| {
                    let h = Arc::clone(&h);
                    async move {
                        let (parts, body) = req.into_parts();
                        let bytes = body
                            .collect()
                            .await
                            .map(|c| c.to_bytes())
                            .unwrap_or_default();
                        let full_req = Request::from_parts(parts, bytes);
                        Ok::<_, Infallible>(h(full_req).await)
                    }
                });
                let _ = http1::Builder::new()
                    .serve_connection(TokioIo::new(tcp), svc)
                    .await;
            });
        }
    });
    addr
}

struct PerAttemptTimeoutRouterPlugin {
    primary_timeout: Duration,
    fallback_upstream: String,
}

impl HttpPlugin for PerAttemptTimeoutRouterPlugin {
    fn name(&self) -> &str {
        "per-attempt-timeout-router"
    }

    fn hook_mask(&self) -> HookMask {
        HookMask::REQUEST_BODY_BUFFERED | HookMask::ON_UPSTREAM_SELECT
    }

    fn on_upstream_select<'a>(
        &'a self,
        ctx: &'a mut RequestCtx,
        selection: &'a mut UpstreamSelection,
    ) -> HookResult<'a, Flow> {
        if ctx.attempt == 1 {
            selection.response_headers_timeout_override = Some(self.primary_timeout);
        } else {
            selection.upstream = self.fallback_upstream.clone();
            selection.response_headers_timeout_override = Some(Duration::from_secs(5));
        }
        HookResult::Ready(Flow::Continue)
    }
}

#[tokio::test]
async fn per_attempt_response_headers_timeout_override_triggers_failover() {
    let slow_hits = Arc::new(AtomicUsize::new(0));
    let slow_hits_bg = Arc::clone(&slow_hits);
    let slow_addr = spawn_backend(move |_req| {
        let hits = Arc::clone(&slow_hits_bg);
        async move {
            hits.fetch_add(1, Ordering::Relaxed);
            tokio::time::sleep(Duration::from_millis(300)).await;
            Response::builder()
                .status(StatusCode::OK)
                .body(Full::new(Bytes::from_static(b"slow")))
                .unwrap()
        }
    })
    .await;

    let fast_addr = spawn_backend(move |_req| async move {
        Response::builder()
            .status(StatusCode::OK)
            .body(Full::new(Bytes::from_static(b"fast-fallback")))
            .unwrap()
    })
    .await;

    let registry = Arc::new(RuntimeRegistry::new());
    let snap = SnapshotBuilder::new(1)
        .upstream(UpstreamConfig::new(
            "slow",
            vec![format!("http://{slow_addr}")],
        ))
        .upstream(UpstreamConfig::new(
            "fast",
            vec![format!("http://{fast_addr}")],
        ))
        .route(
            RouteSpec::new("test", RouteMatch::prefix("/"), "slow")
                .with_max_attempts(2)
                .with_timeouts(TimeoutConfig {
                    response_headers_timeout: Some(Duration::from_secs(10)),
                    idle_chunk_timeout: Some(Duration::from_secs(10)),
                })
                .with_plugin(Arc::new(PerAttemptTimeoutRouterPlugin {
                    primary_timeout: Duration::from_millis(60),
                    fallback_upstream: "fast".to_owned(),
                })),
        )
        .build(&registry, false)
        .unwrap();

    let server = GatewayServer::new(snap)
        .bind("127.0.0.1:0".parse().unwrap())
        .await
        .unwrap();
    let gw_addr = server.local_addr();

    let client = Client::builder(TokioExecutor::new()).build_http::<Full<Bytes>>();
    let req = Request::builder()
        .method(Method::POST)
        .uri(format!("http://{gw_addr}/echo"))
        .body(Full::new(Bytes::from_static(b"hello")))
        .unwrap();
    let res = client.request(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let body = res.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(body.as_ref(), b"fast-fallback");
    assert_eq!(slow_hits.load(Ordering::Relaxed), 1);

    server.shutdown().await;
}

struct InspectBodyRetryPlugin {
    fallback_upstream: String,
}

impl HttpPlugin for InspectBodyRetryPlugin {
    fn name(&self) -> &str {
        "inspect-body-retry"
    }

    fn hook_mask(&self) -> HookMask {
        HookMask::REQUEST_BODY_BUFFERED
            | HookMask::ON_UPSTREAM_SELECT
            | HookMask::ON_RESPONSE_HEADERS
            | HookMask::ON_RESPONSE_BODY_INSPECTED
    }

    fn on_upstream_select<'a>(
        &'a self,
        ctx: &'a mut RequestCtx,
        selection: &'a mut UpstreamSelection,
    ) -> HookResult<'a, Flow> {
        if ctx.attempt >= 2 {
            selection.upstream = self.fallback_upstream.clone();
        }
        HookResult::Ready(Flow::Continue)
    }

    fn on_response_headers<'a>(
        &'a self,
        ctx: &'a mut RequestCtx,
        res: &'a mut ResponseHead,
    ) -> HookResult<'a, Flow> {
        if res.status == StatusCode::BAD_REQUEST && ctx.attempt == 1 {
            return HookResult::Ready(Flow::InspectResponseBody { max_bytes: 16_384 });
        }
        HookResult::Ready(Flow::Continue)
    }

    fn on_response_body_inspected<'a>(
        &'a self,
        _ctx: &'a mut RequestCtx,
        _res: &'a mut ResponseHead,
        body: &'a Bytes,
    ) -> HookResult<'a, Flow> {
        if std::str::from_utf8(body)
            .unwrap_or("")
            .contains("retryable_error")
        {
            HookResult::Ready(Flow::RetryUpstream)
        } else {
            HookResult::Ready(Flow::Continue)
        }
    }
}

#[tokio::test]
async fn inspect_response_body_retries_matching_400_and_forwards_non_matching_verbatim() {
    let primary_addr = spawn_backend(move |req| async move {
        if req.uri().path() == "/retry" {
            Response::builder()
                .status(StatusCode::BAD_REQUEST)
                .header("content-type", "application/json")
                .body(Full::new(Bytes::from_static(
                    br#"{"error":"retryable_error"}"#,
                )))
                .unwrap()
        } else {
            Response::builder()
                .status(StatusCode::BAD_REQUEST)
                .header("content-type", "application/json")
                .body(Full::new(Bytes::from_static(
                    br#"{"error":"fatal_bad_req"}"#,
                )))
                .unwrap()
        }
    })
    .await;

    let fallback_addr = spawn_backend(move |_req| async move {
        Response::builder()
            .status(StatusCode::OK)
            .body(Full::new(Bytes::from_static(b"recovered")))
            .unwrap()
    })
    .await;

    let registry = Arc::new(RuntimeRegistry::new());
    let snap = SnapshotBuilder::new(1)
        .upstream(UpstreamConfig::new(
            "primary",
            vec![format!("http://{primary_addr}")],
        ))
        .upstream(UpstreamConfig::new(
            "fallback",
            vec![format!("http://{fallback_addr}")],
        ))
        .route(
            RouteSpec::new("inspect", RouteMatch::prefix("/"), "primary")
                .with_max_attempts(2)
                .with_plugin(Arc::new(InspectBodyRetryPlugin {
                    fallback_upstream: "fallback".to_owned(),
                })),
        )
        .build(&registry, false)
        .unwrap();

    let server = GatewayServer::new(snap)
        .bind("127.0.0.1:0".parse().unwrap())
        .await
        .unwrap();
    let gw_addr = server.local_addr();
    let client = Client::builder(TokioExecutor::new()).build_http::<Full<Bytes>>();

    // 1. Retryable 400 body fails over to fallback
    let res1 = client
        .request(
            Request::builder()
                .method(Method::POST)
                .uri(format!("http://{gw_addr}/retry"))
                .body(Full::new(Bytes::from_static(b"payload")))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res1.status(), StatusCode::OK);
    let b1 = res1.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(b1.as_ref(), b"recovered");

    // 2. Non-retryable 400 body is forwarded verbatim downstream
    let res2 = client
        .request(
            Request::builder()
                .method(Method::POST)
                .uri(format!("http://{gw_addr}/fatal"))
                .body(Full::new(Bytes::from_static(b"payload")))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res2.status(), StatusCode::BAD_REQUEST);
    let b2 = res2.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(b2.as_ref(), br#"{"error":"fatal_bad_req"}"#);

    server.shutdown().await;
}

#[tokio::test]
async fn route_traffic_mirror_dispatches_body_and_headers_without_blocking_primary() {
    let primary_addr = spawn_backend(move |_req| async move {
        Response::builder()
            .status(StatusCode::OK)
            .body(Full::new(Bytes::from_static(b"primary-ok")))
            .unwrap()
    })
    .await;

    #[derive(Clone)]
    struct MirroredReq {
        path: String,
        body: Vec<u8>,
        tag: Option<String>,
    }
    let mirrored: Arc<Mutex<Vec<MirroredReq>>> = Arc::new(Mutex::new(Vec::new()));
    let mirrored_bg = Arc::clone(&mirrored);
    let shadow_addr = spawn_backend(move |req| {
        let mirrored_bg = Arc::clone(&mirrored_bg);
        async move {
            let path = req.uri().path().to_owned();
            let tag = req
                .headers()
                .get("x-mirror-tag")
                .and_then(|v| v.to_str().ok())
                .map(str::to_owned);
            let body = req.into_body().to_vec();
            mirrored_bg
                .lock()
                .unwrap()
                .push(MirroredReq { path, body, tag });
            Response::builder()
                .status(StatusCode::ACCEPTED)
                .body(Full::new(Bytes::new()))
                .unwrap()
        }
    })
    .await;

    let mut mirror_spec = TrafficMirrorSpec::new("shadow", 1.0);
    mirror_spec.headers.push((
        HeaderName::from_static("x-mirror-tag"),
        HeaderValue::from_static("canary-v2"),
    ));

    let registry = Arc::new(RuntimeRegistry::new());
    let snap = SnapshotBuilder::new(1)
        .upstream(UpstreamConfig::new(
            "primary",
            vec![format!("http://{primary_addr}")],
        ))
        .upstream(UpstreamConfig::new(
            "shadow",
            vec![format!("http://{shadow_addr}")],
        ))
        .route(
            RouteSpec::new("orders", RouteMatch::prefix("/orders"), "primary")
                .with_mirror(mirror_spec),
        )
        .build(&registry, false)
        .unwrap();
    let snap_ref = Arc::clone(&snap);

    let server = GatewayServer::new(snap)
        .bind("127.0.0.1:0".parse().unwrap())
        .await
        .unwrap();
    let gw_addr = server.local_addr();
    let client = Client::builder(TokioExecutor::new()).build_http::<Full<Bytes>>();

    let res = client
        .request(
            Request::builder()
                .method(Method::POST)
                .uri(format!("http://{gw_addr}/orders/42"))
                .body(Full::new(Bytes::from_static(br#"{"item":"widget"}"#)))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let body = res.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(body.as_ref(), b"primary-ok");

    // Wait briefly for detached mirror task to deliver and record its response metric.
    for _ in 0..40 {
        if !mirrored.lock().unwrap().is_empty()
            && snap_ref
                .render_mirror_metrics_prometheus()
                .contains(r#"result="sent"} 1"#)
        {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }

    let caps = mirrored.lock().unwrap().clone();
    assert_eq!(caps.len(), 1);
    assert_eq!(caps[0].path, "/orders/42");
    assert_eq!(caps[0].body, br#"{"item":"widget"}"#);
    assert_eq!(caps[0].tag.as_deref(), Some("canary-v2"));

    let prom = snap_ref.render_mirror_metrics_prometheus();
    assert!(prom.contains(
        r#"shunt_traffic_mirror_requests_total{route="orders",upstream="shadow",result="sent"} 1"#
    ));

    server.shutdown().await;
}
