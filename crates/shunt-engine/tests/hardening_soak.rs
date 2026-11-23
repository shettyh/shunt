use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Duration;

use bytes::Bytes;
use http::{Request, Response, StatusCode, header};
use http_body::Frame;
use http_body_util::{BodyExt, Full};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::client::legacy::Client;
use hyper_util::rt::{TokioExecutor, TokioIo};
use shunt_engine::{
    GatewayServer, RouteMatch, RouteSpec, RuntimeRegistry, ShuntBody, SnapshotBuilder,
    TimeoutConfig, UpstreamConfig,
};
use shunt_plugin_sdk::{
    Flow, HookMask, HookResult, HttpPlugin, RequestCtx, RequestHead, RequestSummary, ResponseHead,
    RouteDecision, StreamFlow, UpstreamRequest, UpstreamSelection,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::mpsc;

// =============================================================================
// Shared Test Helpers
// =============================================================================

async fn spawn_http_and_sse_upstream() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            let _ = stream.set_nodelay(true);
            tokio::spawn(async move {
                let svc = service_fn(move |req: Request<hyper::body::Incoming>| async move {
                    let path = req.uri().path().to_owned();
                    let _ = req.into_body().collect().await;

                    if path == "/sse" {
                        let (tx, rx) = mpsc::channel(8);
                        tokio::spawn(async move {
                            for i in 0..8 {
                                tokio::time::sleep(Duration::from_millis(8)).await;
                                let frame = Bytes::from(format!("data: chunk-{i}\n\n"));
                                if tx.send(Ok(Frame::data(frame))).await.is_err() {
                                    break;
                                }
                            }
                            let _ = tx
                                .send(Ok(Frame::data(Bytes::from_static(b"data: [DONE]\n\n"))))
                                .await;
                        });
                        let resp = Response::builder()
                            .status(StatusCode::OK)
                            .header(header::CONTENT_TYPE, "text/event-stream")
                            .body(ShuntBody::channel(rx))
                            .unwrap();
                        Ok::<_, Infallible>(resp)
                    } else {
                        let resp = Response::builder()
                            .status(StatusCode::OK)
                            .header(header::CONTENT_TYPE, "text/plain")
                            .body(ShuntBody::full(Bytes::from_static(b"ok")))
                            .unwrap();
                        Ok::<_, Infallible>(resp)
                    }
                });
                let _ = http1::Builder::new()
                    .keep_alive(true)
                    .serve_connection(TokioIo::new(stream), svc)
                    .await;
            });
        }
    });

    addr
}

struct VersionHeaderPlugin {
    version: u64,
}

impl HttpPlugin for VersionHeaderPlugin {
    fn name(&self) -> &str {
        "version-header"
    }

    fn hook_mask(&self) -> HookMask {
        HookMask::ON_RESPONSE_HEADERS
    }

    fn on_response_headers<'a>(
        &'a self,
        _ctx: &'a mut RequestCtx,
        res: &'a mut ResponseHead,
    ) -> HookResult<'a, Flow> {
        res.headers.insert(
            http::HeaderName::from_static("x-snapshot-version"),
            http::HeaderValue::from_str(&self.version.to_string()).unwrap(),
        );
        HookResult::Ready(Flow::Continue)
    }
}

// =============================================================================
// 1. Reload-under-load soak test (zero dropped HTTP + SSE requests, pool reuse, GC)
// =============================================================================

#[tokio::test]
async fn reload_under_load_zero_dropped_requests_and_pool_gc() {
    let stable_upstream = spawn_http_and_sse_upstream().await;
    let temp_upstream = spawn_http_and_sse_upstream().await;
    let registry = Arc::new(RuntimeRegistry::new());

    let build_snap = |version: u64, include_temp: bool| {
        let mut builder = SnapshotBuilder::new(version)
            .upstream(UpstreamConfig::new(
                "stable",
                vec![format!("http://{stable_upstream}")],
            ))
            .route(
                RouteSpec::new("http_ok", RouteMatch::exact("/ping"), "stable")
                    .with_plugin(Arc::new(VersionHeaderPlugin { version })),
            )
            .route(
                RouteSpec::new("sse_ok", RouteMatch::exact("/sse"), "stable")
                    .with_plugin(Arc::new(VersionHeaderPlugin { version })),
            );

        if include_temp {
            builder = builder
                .upstream(UpstreamConfig::new(
                    "ephemeral",
                    vec![format!("http://{temp_upstream}")],
                ))
                .route(RouteSpec::new(
                    "temp_route",
                    RouteMatch::exact("/temp"),
                    "ephemeral",
                ));
        }

        builder.build(&registry, true).unwrap()
    };

    let initial = build_snap(1, true);
    let initial_stable_pool_id = initial.upstream("stable").unwrap().pool_id();
    let gw = GatewayServer::new(initial)
        .bind("127.0.0.1:0".parse().unwrap())
        .await
        .unwrap();
    let gw_addr = gw.local_addr();
    let reloader = gw.reloader();

    let stop = Arc::new(AtomicBool::new(false));
    let http_ok = Arc::new(AtomicUsize::new(0));
    let http_err = Arc::new(AtomicUsize::new(0));
    let sse_ok = Arc::new(AtomicUsize::new(0));
    let sse_err = Arc::new(AtomicUsize::new(0));

    let client = Arc::new(
        Client::builder(TokioExecutor::new())
            .pool_max_idle_per_host(64)
            .build_http::<Full<Bytes>>(),
    );

    // 8 concurrent HTTP keep-alive workers
    let mut workers = Vec::new();
    for _ in 0..8 {
        let client = Arc::clone(&client);
        let stop = Arc::clone(&stop);
        let http_ok = Arc::clone(&http_ok);
        let http_err = Arc::clone(&http_err);
        workers.push(tokio::spawn(async move {
            while !stop.load(Ordering::Relaxed) {
                let req = Request::builder()
                    .uri(format!("http://{gw_addr}/ping"))
                    .body(Full::new(Bytes::new()))
                    .unwrap();
                match client.request(req).await {
                    Ok(res) if res.status() == StatusCode::OK => {
                        let body = res.into_body().collect().await.unwrap().to_bytes();
                        if body.as_ref() == b"ok" {
                            http_ok.fetch_add(1, Ordering::Relaxed);
                        } else {
                            http_err.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                    _ => {
                        http_err.fetch_add(1, Ordering::Relaxed);
                    }
                }
            }
        }));
    }

    // 6 concurrent multi-chunk SSE streaming workers running across reload boundaries
    for _ in 0..6 {
        let client = Arc::clone(&client);
        let stop = Arc::clone(&stop);
        let sse_ok = Arc::clone(&sse_ok);
        let sse_err = Arc::clone(&sse_err);
        workers.push(tokio::spawn(async move {
            while !stop.load(Ordering::Relaxed) {
                let req = Request::builder()
                    .uri(format!("http://{gw_addr}/sse"))
                    .body(Full::new(Bytes::new()))
                    .unwrap();
                match client.request(req).await {
                    Ok(res) if res.status() == StatusCode::OK => {
                        match res.into_body().collect().await {
                            Ok(collected) => {
                                let text =
                                    String::from_utf8_lossy(&collected.to_bytes()).into_owned();
                                if text.contains("chunk-0")
                                    && text.contains("chunk-7")
                                    && text.contains("data: [DONE]")
                                {
                                    sse_ok.fetch_add(1, Ordering::Relaxed);
                                } else {
                                    sse_err.fetch_add(1, Ordering::Relaxed);
                                }
                            }
                            Err(_) => {
                                sse_err.fetch_add(1, Ordering::Relaxed);
                            }
                        }
                    }
                    _ => {
                        sse_err.fetch_add(1, Ordering::Relaxed);
                    }
                }
            }
        }));
    }

    // Rapidly fire 25 live reloads while traffic is flowing!
    for v in 2..=26u64 {
        tokio::time::sleep(Duration::from_millis(15)).await;
        let include_temp = v % 2 == 0;
        let next = build_snap(v, include_temp);
        assert_eq!(
            next.upstream("stable").unwrap().pool_id(),
            initial_stable_pool_id,
            "warm stable upstream pool must be reused across every reload"
        );
        reloader.swap_snapshot(next);
    }

    // Final reload without temp upstream -> verify orphaned pool was GC'd cleanly.
    let final_snap = build_snap(27, false);
    reloader.swap_snapshot(final_snap);
    assert_eq!(
        registry.pool_count(),
        1,
        "ephemeral upstream pool should be GC'd"
    );

    stop.store(true, Ordering::Release);
    for w in workers {
        w.await.unwrap();
    }

    assert_eq!(
        http_err.load(Ordering::Relaxed),
        0,
        "zero HTTP errors during reload soak"
    );
    assert_eq!(
        sse_err.load(Ordering::Relaxed),
        0,
        "zero SSE errors/truncations during reload soak"
    );
    assert!(
        http_ok.load(Ordering::Relaxed) > 50,
        "expected substantial HTTP traffic"
    );
    assert!(
        sse_ok.load(Ordering::Relaxed) >= 6,
        "expected completed SSE streams across reloads"
    );

    assert!(
        gw.shutdown().await,
        "graceful shutdown should drain cleanly"
    );
}

// =============================================================================
// 2. Async hook panic isolation across every lifecycle stage
// =============================================================================

#[derive(Clone, Copy)]
enum PanicStage {
    RequestHeaders,
    RequestBodyBuffered,
    Route,
    UpstreamSelect,
    UpstreamRequest,
    ResponseHeaders,
    ResponseChunk,
    ResponseEof,
    Complete,
}

struct AsyncPanicPlugin {
    stage: PanicStage,
}

impl HttpPlugin for AsyncPanicPlugin {
    fn name(&self) -> &str {
        "async-panicker"
    }

    fn hook_mask(&self) -> HookMask {
        match self.stage {
            PanicStage::RequestHeaders => HookMask::ON_REQUEST_HEADERS,
            PanicStage::RequestBodyBuffered => HookMask::REQUEST_BODY_BUFFERED,
            PanicStage::Route => HookMask::ON_ROUTE,
            PanicStage::UpstreamSelect => HookMask::ON_UPSTREAM_SELECT,
            PanicStage::UpstreamRequest => HookMask::ON_UPSTREAM_REQUEST,
            PanicStage::ResponseHeaders => HookMask::ON_RESPONSE_HEADERS,
            PanicStage::ResponseChunk | PanicStage::ResponseEof => HookMask::RESPONSE_BODY_STREAM,
            PanicStage::Complete => HookMask::ON_COMPLETE,
        }
    }

    fn on_request_headers<'a>(
        &'a self,
        _ctx: &'a mut RequestCtx,
        _req: &'a mut RequestHead,
    ) -> HookResult<'a, Flow> {
        HookResult::pending(async {
            tokio::task::yield_now().await;
            panic!("async panic in on_request_headers");
        })
    }

    fn on_request_body_buffered<'a>(
        &'a self,
        _ctx: &'a mut RequestCtx,
        _body: &'a mut Bytes,
    ) -> HookResult<'a, Flow> {
        HookResult::pending(async {
            tokio::task::yield_now().await;
            panic!("async panic in on_request_body_buffered");
        })
    }

    fn on_route<'a>(
        &'a self,
        _ctx: &'a mut RequestCtx,
        _decision: &'a mut RouteDecision,
    ) -> HookResult<'a, Flow> {
        HookResult::pending(async {
            tokio::task::yield_now().await;
            panic!("async panic in on_route");
        })
    }

    fn on_upstream_select<'a>(
        &'a self,
        _ctx: &'a mut RequestCtx,
        _selection: &'a mut UpstreamSelection,
    ) -> HookResult<'a, Flow> {
        HookResult::pending(async {
            tokio::task::yield_now().await;
            panic!("async panic in on_upstream_select");
        })
    }

    fn on_upstream_request<'a>(
        &'a self,
        _ctx: &'a mut RequestCtx,
        _req: &'a mut UpstreamRequest,
    ) -> HookResult<'a, Flow> {
        HookResult::pending(async {
            tokio::task::yield_now().await;
            panic!("async panic in on_upstream_request");
        })
    }

    fn on_response_headers<'a>(
        &'a self,
        _ctx: &'a mut RequestCtx,
        _res: &'a mut ResponseHead,
    ) -> HookResult<'a, Flow> {
        HookResult::pending(async {
            tokio::task::yield_now().await;
            panic!("async panic in on_response_headers");
        })
    }

    fn on_response_body_chunk<'a>(
        &'a self,
        _ctx: &'a mut RequestCtx,
        _chunk: &'a mut Bytes,
        end_of_stream: bool,
    ) -> HookResult<'a, StreamFlow> {
        let should_panic = match self.stage {
            PanicStage::ResponseChunk => !end_of_stream,
            PanicStage::ResponseEof => end_of_stream,
            _ => false,
        };
        if should_panic {
            HookResult::pending(async {
                tokio::task::yield_now().await;
                panic!("async panic in on_response_body_chunk");
            })
        } else {
            HookResult::Ready(StreamFlow::Continue)
        }
    }

    fn on_complete<'a>(
        &'a self,
        _ctx: &'a RequestCtx,
        _summary: &'a RequestSummary,
    ) -> HookResult<'a, ()> {
        HookResult::pending(async {
            tokio::task::yield_now().await;
            panic!("async panic in on_complete");
        })
    }
}

struct CompleteObserver {
    total: Arc<AtomicUsize>,
    aborted: Arc<AtomicUsize>,
}

impl HttpPlugin for CompleteObserver {
    fn name(&self) -> &str {
        "complete-observer"
    }

    fn hook_mask(&self) -> HookMask {
        HookMask::ON_COMPLETE
    }

    fn on_complete<'a>(
        &'a self,
        _ctx: &'a RequestCtx,
        summary: &'a RequestSummary,
    ) -> HookResult<'a, ()> {
        self.total.fetch_add(1, Ordering::SeqCst);
        if summary.aborted_mid_stream {
            self.aborted.fetch_add(1, Ordering::SeqCst);
        }
        HookResult::Ready(())
    }
}

#[tokio::test]
async fn async_hook_panics_isolated_across_every_stage() {
    let upstream = spawn_http_and_sse_upstream().await;
    let registry = RuntimeRegistry::new();

    let total_complete = Arc::new(AtomicUsize::new(0));
    let aborted_complete = Arc::new(AtomicUsize::new(0));
    let observer: Arc<dyn HttpPlugin> = Arc::new(CompleteObserver {
        total: Arc::clone(&total_complete),
        aborted: Arc::clone(&aborted_complete),
    });

    let snap = SnapshotBuilder::new(1)
        .upstream(UpstreamConfig::new(
            "up",
            vec![format!("http://{upstream}")],
        ))
        .route(RouteSpec::new(
            "healthy",
            RouteMatch::exact("/healthy"),
            "up",
        ))
        .route(
            RouteSpec::new("p_req_h", RouteMatch::exact("/p_req_h"), "up")
                .with_plugin(Arc::new(AsyncPanicPlugin {
                    stage: PanicStage::RequestHeaders,
                }))
                .with_plugin(Arc::clone(&observer)),
        )
        .route(
            RouteSpec::new("p_req_b", RouteMatch::exact("/p_req_b"), "up")
                .with_plugin(Arc::new(AsyncPanicPlugin {
                    stage: PanicStage::RequestBodyBuffered,
                }))
                .with_plugin(Arc::clone(&observer)),
        )
        .route(
            RouteSpec::new("p_route", RouteMatch::exact("/p_route"), "up")
                .with_plugin(Arc::new(AsyncPanicPlugin {
                    stage: PanicStage::Route,
                }))
                .with_plugin(Arc::clone(&observer)),
        )
        .route(
            RouteSpec::new("p_sel", RouteMatch::exact("/p_sel"), "up")
                .with_plugin(Arc::new(AsyncPanicPlugin {
                    stage: PanicStage::UpstreamSelect,
                }))
                .with_plugin(Arc::clone(&observer)),
        )
        .route(
            RouteSpec::new("p_up_req", RouteMatch::exact("/p_up_req"), "up")
                .with_plugin(Arc::new(AsyncPanicPlugin {
                    stage: PanicStage::UpstreamRequest,
                }))
                .with_plugin(Arc::clone(&observer)),
        )
        .route(
            RouteSpec::new("p_res_h", RouteMatch::exact("/p_res_h"), "up")
                .with_plugin(Arc::new(AsyncPanicPlugin {
                    stage: PanicStage::ResponseHeaders,
                }))
                .with_plugin(Arc::clone(&observer)),
        )
        .route(
            RouteSpec::new("p_chunk", RouteMatch::exact("/p_chunk"), "up")
                .with_plugin(Arc::new(AsyncPanicPlugin {
                    stage: PanicStage::ResponseChunk,
                }))
                .with_plugin(Arc::clone(&observer)),
        )
        .route(
            RouteSpec::new("p_eof", RouteMatch::exact("/p_eof"), "up")
                .with_plugin(Arc::new(AsyncPanicPlugin {
                    stage: PanicStage::ResponseEof,
                }))
                .with_plugin(Arc::clone(&observer)),
        )
        .route(
            RouteSpec::new("p_complete", RouteMatch::exact("/p_complete"), "up")
                .with_plugin(Arc::new(AsyncPanicPlugin {
                    stage: PanicStage::Complete,
                }))
                .with_plugin(Arc::clone(&observer)),
        )
        .build(&registry, false)
        .unwrap();

    let gw = GatewayServer::new(snap)
        .bind("127.0.0.1:0".parse().unwrap())
        .await
        .unwrap();
    let addr = gw.local_addr();
    let client = Client::builder(TokioExecutor::new()).build_http::<Full<Bytes>>();

    // All 6 pre-flush async panics must return clean 500 without crashing the server.
    for path in [
        "/p_req_h",
        "/p_req_b",
        "/p_route",
        "/p_sel",
        "/p_up_req",
        "/p_res_h",
    ] {
        let req = Request::builder()
            .method("POST")
            .uri(format!("http://{addr}{path}"))
            .body(Full::new(Bytes::from_static(b"payload")))
            .unwrap();
        let res = client.request(req).await.unwrap();
        assert_eq!(
            res.status(),
            StatusCode::INTERNAL_SERVER_ERROR,
            "expected 500 on async panic at {path}"
        );
    }

    // Mid-stream and EOF async panics must cleanly abort the body stream.
    for path in ["/p_chunk", "/p_eof"] {
        let req = Request::builder()
            .uri(format!("http://{addr}{path}"))
            .body(Full::new(Bytes::new()))
            .unwrap();
        let res = client.request(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        let collect_res = res.into_body().collect().await;
        assert!(
            collect_res.is_err(),
            "expected stream error on async panic at {path}"
        );
    }

    // Panic in on_complete still lets response succeed AND still runs the subsequent observer plugin.
    let req = Request::builder()
        .uri(format!("http://{addr}/p_complete"))
        .body(Full::new(Bytes::new()))
        .unwrap();
    let res = client.request(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let _ = res.into_body().collect().await.unwrap();

    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_eq!(total_complete.load(Ordering::SeqCst), 9);
    assert_eq!(aborted_complete.load(Ordering::SeqCst), 2);

    // Server must remain completely healthy after all 9 async panics.
    let healthy = client
        .request(
            Request::builder()
                .uri(format!("http://{addr}/healthy"))
                .body(Full::new(Bytes::new()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(healthy.status(), StatusCode::OK);

    gw.shutdown().await;
}

// =============================================================================
// 3. Mid-stream upstream TCP reset & abrupt client disconnect hardening
// =============================================================================

struct NoopStreamInspector;

impl HttpPlugin for NoopStreamInspector {
    fn name(&self) -> &str {
        "noop-stream-inspector"
    }

    fn hook_mask(&self) -> HookMask {
        HookMask::RESPONSE_BODY_STREAM
    }

    fn on_response_body_chunk<'a>(
        &'a self,
        _ctx: &'a mut RequestCtx,
        _chunk: &'a mut Bytes,
        _end_of_stream: bool,
    ) -> HookResult<'a, StreamFlow> {
        HookResult::Ready(StreamFlow::Continue)
    }
}

#[tokio::test]
async fn mid_stream_upstream_truncation_detected_in_passthrough_and_hooked_modes() {
    // Raw TCP upstream that sends headers + one chunk, then abruptly drops the socket without 0\r\n\r\n.
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let bad_up_addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut sock, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut buf = [0u8; 1024];
                let _ = sock.read(&mut buf).await;
                let partial =
                    b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n";
                let _ = sock.write_all(partial).await;
                let _ = sock.flush().await;
                // Abrupt close without terminating chunk!
                drop(sock);
            });
        }
    });

    let registry = RuntimeRegistry::new();
    let aborted = Arc::new(AtomicUsize::new(0));
    let total = Arc::new(AtomicUsize::new(0));
    let observer: Arc<dyn HttpPlugin> = Arc::new(CompleteObserver {
        total: Arc::clone(&total),
        aborted: Arc::clone(&aborted),
    });

    let snap = SnapshotBuilder::new(1)
        .upstream(UpstreamConfig::new(
            "flaky",
            vec![format!("http://{bad_up_addr}")],
        ))
        .route(
            RouteSpec::new("passthrough", RouteMatch::exact("/pass"), "flaky")
                .with_plugin(Arc::clone(&observer)),
        )
        .route(
            RouteSpec::new("hooked", RouteMatch::exact("/hooked"), "flaky")
                .with_plugin(Arc::new(NoopStreamInspector))
                .with_plugin(Arc::clone(&observer)),
        )
        .build(&registry, false)
        .unwrap();

    let gw = GatewayServer::new(snap)
        .bind("127.0.0.1:0".parse().unwrap())
        .await
        .unwrap();
    let addr = gw.local_addr();
    let client = Client::builder(TokioExecutor::new()).build_http::<Full<Bytes>>();

    for path in ["/pass", "/hooked"] {
        let req = Request::builder()
            .uri(format!("http://{addr}{path}"))
            .body(Full::new(Bytes::new()))
            .unwrap();
        let res = client.request(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        let body_res = res.into_body().collect().await;
        assert!(
            body_res.is_err(),
            "truncated upstream chunked body must surface as a stream error on {path}"
        );
    }

    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_eq!(total.load(Ordering::SeqCst), 2);
    assert_eq!(
        aborted.load(Ordering::SeqCst),
        2,
        "both passthrough and hooked routes must report aborted_mid_stream=true"
    );

    gw.shutdown().await;
}

// =============================================================================
// 4. High-concurrency SSE streaming (200 concurrent streams w/ live chunk rewrite)
// =============================================================================

struct UppercaseChunkPlugin;

impl HttpPlugin for UppercaseChunkPlugin {
    fn name(&self) -> &str {
        "uppercase-chunk"
    }

    fn hook_mask(&self) -> HookMask {
        HookMask::RESPONSE_BODY_STREAM
    }

    fn on_response_body_chunk<'a>(
        &'a self,
        _ctx: &'a mut RequestCtx,
        chunk: &'a mut Bytes,
        _end_of_stream: bool,
    ) -> HookResult<'a, StreamFlow> {
        if !chunk.is_empty() {
            let upper: Vec<u8> = chunk.iter().map(|b| b.to_ascii_uppercase()).collect();
            *chunk = Bytes::from(upper);
        }
        HookResult::Ready(StreamFlow::Continue)
    }
}

#[tokio::test]
async fn high_concurrency_sse_streaming_with_chunk_rewrite() {
    let upstream = spawn_http_and_sse_upstream().await;
    let registry = RuntimeRegistry::new();

    let completed = Arc::new(AtomicUsize::new(0));
    let aborted = Arc::new(AtomicUsize::new(0));
    let observer = Arc::new(CompleteObserver {
        total: Arc::clone(&completed),
        aborted: Arc::clone(&aborted),
    });

    let mut up_cfg = UpstreamConfig::new("sse_up", vec![format!("http://{upstream}")]);
    up_cfg.pool_max_idle_per_host = 64;

    let snap = SnapshotBuilder::new(1)
        .upstream(up_cfg)
        .route(
            RouteSpec::new("sse_rewrite", RouteMatch::exact("/sse"), "sse_up")
                .with_timeouts(TimeoutConfig {
                    response_headers_timeout: Some(Duration::from_secs(10)),
                    idle_chunk_timeout: Some(Duration::from_secs(10)),
                })
                .with_plugin(Arc::new(UppercaseChunkPlugin))
                .with_plugin(observer),
        )
        .build(&registry, false)
        .unwrap();

    let gw = GatewayServer::new(snap)
        .bind("127.0.0.1:0".parse().unwrap())
        .await
        .unwrap();
    let addr = gw.local_addr();
    let client = Arc::new(
        Client::builder(TokioExecutor::new())
            .pool_max_idle_per_host(64)
            .build_http::<Full<Bytes>>(),
    );

    // 24 concurrent streams x 5 waves = 120 rewritten SSE streams (stays well under macOS's default 256 FD soft limit even when tests run in parallel).
    const CONCURRENCY: usize = 24;
    const WAVES: usize = 5;
    for _ in 0..WAVES {
        let mut handles = Vec::with_capacity(CONCURRENCY);
        for _ in 0..CONCURRENCY {
            let client = Arc::clone(&client);
            handles.push(tokio::spawn(async move {
                let req = Request::builder()
                    .uri(format!("http://{addr}/sse"))
                    .body(Full::new(Bytes::new()))
                    .unwrap();
                let res = client.request(req).await.unwrap();
                assert_eq!(res.status(), StatusCode::OK);
                let bytes = res.into_body().collect().await.unwrap().to_bytes();
                let text = String::from_utf8(bytes.to_vec()).unwrap();
                assert!(text.contains("DATA: CHUNK-0"));
                assert!(text.contains("DATA: CHUNK-7"));
                assert!(text.contains("DATA: [DONE]"));
            }));
        }

        for h in handles {
            h.await.unwrap();
        }
    }

    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_eq!(completed.load(Ordering::SeqCst), CONCURRENCY * WAVES);
    assert_eq!(aborted.load(Ordering::SeqCst), 0);

    assert!(gw.shutdown().await);
}
