use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::Bytes;
use http::{HeaderName, HeaderValue, Method, Request, Response, StatusCode, Version, header};
use http_body::Frame;
use http_body_util::{BodyExt, Full};
use hyper::server::conn::{http1, http2};
use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo};
use rustls::pki_types::ServerName;
use shunt_engine::{
    CertStore, DynamicCertResolver, GatewayServer, RouteMatch, RouteSpec, RuntimeRegistry,
    ShuntBody, SnapshotBuilder, TimeoutConfig, TlsListenerConfig, UpstreamConfig,
    load_certified_key_pem,
};
use shunt_plugin_sdk::{
    BufferedResponse, Flow, HookMask, HookResult, HttpPlugin, RequestCtx, RequestHead,
    RequestSummary, ResponseHead, RouteDecision, StreamFlow, UpstreamRequest, UpstreamSelection,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Notify, mpsc};
use tokio_rustls::TlsConnector;

// -----------------------------------------------------------------------------
// Test upstream helpers
// -----------------------------------------------------------------------------

async fn spawn_http1_upstream<F, Fut>(handler: F) -> SocketAddr
where
    F: Fn(Request<hyper::body::Incoming>) -> Fut + Send + Sync + 'static,
    Fut: std::future::Future<Output = Response<ShuntBody>> + Send + 'static,
{
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handler = Arc::new(handler);

    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            let h = Arc::clone(&handler);
            tokio::spawn(async move {
                let svc = service_fn(move |req| {
                    let h = Arc::clone(&h);
                    async move { Ok::<_, Infallible>(h(req).await) }
                });
                let _ = http1::Builder::new()
                    .serve_connection(TokioIo::new(stream), svc)
                    .with_upgrades()
                    .await;
            });
        }
    });

    addr
}

async fn spawn_h2_upstream<F, Fut>(handler: F) -> SocketAddr
where
    F: Fn(Request<hyper::body::Incoming>) -> Fut + Send + Sync + 'static,
    Fut: std::future::Future<Output = Response<Full<Bytes>>> + Send + 'static,
{
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handler = Arc::new(handler);

    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            let h = Arc::clone(&handler);
            tokio::spawn(async move {
                let svc = service_fn(move |req| {
                    let h = Arc::clone(&h);
                    async move { Ok::<_, Infallible>(h(req).await) }
                });
                let _ = http2::Builder::new(TokioExecutor::new())
                    .serve_connection(TokioIo::new(stream), svc)
                    .await;
            });
        }
    });

    addr
}

async fn send_h1(
    addr: SocketAddr,
    req: Request<Full<Bytes>>,
) -> (StatusCode, http::HeaderMap, Bytes) {
    let stream = TcpStream::connect(addr).await.unwrap();
    let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(stream))
        .await
        .unwrap();
    tokio::spawn(async move {
        let _ = conn.await;
    });
    let res = sender.send_request(req).await.unwrap();
    let status = res.status();
    let headers = res.headers().clone();
    let body = res.into_body().collect().await.unwrap().to_bytes();
    (status, headers, body)
}

fn self_signed_cert_pem(domains: Vec<String>) -> (Vec<u8>, Vec<u8>) {
    let ck = rcgen::generate_simple_self_signed(domains).unwrap();
    (
        ck.cert.pem().into_bytes(),
        ck.signing_key.serialize_pem().into_bytes(),
    )
}

// -----------------------------------------------------------------------------
// 1. HTTP/1.1 zero-plugin passthrough + strip_prefix + XFF + hop-by-hop
// -----------------------------------------------------------------------------

#[tokio::test]
async fn h1_zero_plugin_passthrough() {
    let upstream = spawn_http1_upstream(|req| async move {
        let path = req
            .uri()
            .path_and_query()
            .map(|p| p.as_str())
            .unwrap_or("")
            .to_owned();
        let xff = req
            .headers()
            .get("x-forwarded-for")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_owned();
        let has_hop = req.headers().contains_key("x-custom-hop");
        let body = req.into_body().collect().await.unwrap().to_bytes();

        let payload = format!(
            "path={path}|xff={xff}|hop={has_hop}|body={}",
            String::from_utf8_lossy(&body)
        );
        Response::builder()
            .status(StatusCode::OK)
            .header("x-upstream", "echo")
            .body(ShuntBody::full(Bytes::from(payload)))
            .unwrap()
    })
    .await;

    let registry = RuntimeRegistry::new();
    let snapshot = SnapshotBuilder::new(1)
        .upstream(UpstreamConfig::new(
            "echo",
            vec![format!("http://{upstream}")],
        ))
        .route(RouteSpec::new("r1", RouteMatch::prefix("/api"), "echo").with_strip_prefix("/api"))
        .build(&registry, true)
        .unwrap();

    assert_eq!(snapshot.routes[0].hook_mask, HookMask::EMPTY);

    let handle = GatewayServer::new(snapshot)
        .bind("127.0.0.1:0".parse().unwrap())
        .await
        .unwrap();

    let req = Request::builder()
        .method(Method::POST)
        .uri("/api/v1/items?limit=5")
        .header(header::HOST, "gateway.local")
        .header(header::CONNECTION, "x-custom-hop")
        .header("x-custom-hop", "should-be-stripped")
        .body(Full::new(Bytes::from_static(b"hello-shunt")))
        .unwrap();

    let (status, headers, body) = send_h1(handle.local_addr(), req).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(headers.get("x-upstream").unwrap(), "echo");
    let text = String::from_utf8(body.to_vec()).unwrap();
    assert!(text.contains("path=/v1/items?limit=5"), "got: {text}");
    assert!(text.contains("xff=127.0.0.1"), "got: {text}");
    assert!(text.contains("hop=false"), "got: {text}");
    assert!(text.contains("body=hello-shunt"), "got: {text}");

    assert!(handle.shutdown().await);
}

// -----------------------------------------------------------------------------
// 2. HTTP/2 (h2c) downstream & upstream multiplexed passthrough
// -----------------------------------------------------------------------------

#[tokio::test]
async fn h2_downstream_and_upstream_passthrough() {
    let upstream = spawn_h2_upstream(|req| async move {
        let ver = format!("{:?}", req.version());
        let path = req.uri().path().to_owned();
        Response::builder()
            .status(StatusCode::OK)
            .body(Full::new(Bytes::from(format!("{ver}:{path}"))))
            .unwrap()
    })
    .await;

    let mut up_cfg = UpstreamConfig::new("h2-up", vec![format!("http://{upstream}")]);
    up_cfg.http2_only = true;

    let registry = RuntimeRegistry::new();
    let snapshot = SnapshotBuilder::new(1)
        .upstream(up_cfg)
        .route(RouteSpec::new("h2", RouteMatch::any(), "h2-up"))
        .build(&registry, true)
        .unwrap();

    let handle = GatewayServer::new(snapshot)
        .bind("127.0.0.1:0".parse().unwrap())
        .await
        .unwrap();

    let stream = TcpStream::connect(handle.local_addr()).await.unwrap();
    let (mut sender, conn) =
        hyper::client::conn::http2::handshake(TokioExecutor::new(), TokioIo::new(stream))
            .await
            .unwrap();
    tokio::spawn(async move {
        let _ = conn.await;
    });

    // Fire 8 concurrent multiplexed HTTP/2 streams on a single TCP connection.
    let mut futs = Vec::new();
    for i in 0..8 {
        let req = Request::builder()
            .method(Method::GET)
            .uri(format!("http://localhost/stream/{i}"))
            .version(Version::HTTP_2)
            .body(Full::new(Bytes::new()))
            .unwrap();
        let resp_fut = sender.send_request(req);
        futs.push(async move {
            let res = resp_fut.await.unwrap();
            assert_eq!(res.version(), Version::HTTP_2);
            assert_eq!(res.status(), StatusCode::OK);
            let body = res.into_body().collect().await.unwrap().to_bytes();
            (i, String::from_utf8(body.to_vec()).unwrap())
        });
    }

    for (idx, fut) in futs.into_iter().enumerate() {
        let (i, text) = fut.await;
        assert_eq!(i, idx);
        assert_eq!(text, format!("HTTP/2.0:/stream/{i}"));
    }

    assert!(handle.shutdown().await);
}

// -----------------------------------------------------------------------------
// 3. TLS termination with SNI + hot-reloadable certificates
// -----------------------------------------------------------------------------

struct SniEchoPlugin;

impl HttpPlugin for SniEchoPlugin {
    fn name(&self) -> &str {
        "sni-echo"
    }

    fn hook_mask(&self) -> HookMask {
        HookMask::ON_RESPONSE_HEADERS
    }

    fn on_response_headers<'a>(
        &'a self,
        ctx: &'a mut RequestCtx,
        res: &'a mut ResponseHead,
    ) -> HookResult<'a, Flow> {
        if let Some(sni) = &ctx.tls_sni {
            res.headers.insert(
                HeaderName::from_static("x-tls-sni"),
                HeaderValue::from_str(sni).unwrap(),
            );
        }
        HookResult::Ready(Flow::Continue)
    }
}

#[tokio::test]
async fn tls_sni_and_hot_cert_reload() {
    shunt_engine::ensure_crypto_provider();

    let upstream = spawn_http1_upstream(|_req| async move {
        Response::builder()
            .status(StatusCode::OK)
            .body(ShuntBody::full(Bytes::from_static(b"tls-ok")))
            .unwrap()
    })
    .await;

    let (alpha_cert1, alpha_key1) = self_signed_cert_pem(vec!["alpha.test".into()]);
    let (beta_cert, beta_key) = self_signed_cert_pem(vec!["beta.test".into()]);
    let (alpha_cert2, alpha_key2) = self_signed_cert_pem(vec!["alpha.test".into()]);

    let store1 = CertStore::new()
        .with_sni(
            "alpha.test",
            load_certified_key_pem(&alpha_cert1, &alpha_key1).unwrap(),
        )
        .with_sni(
            "beta.test",
            load_certified_key_pem(&beta_cert, &beta_key).unwrap(),
        );

    let resolver = Arc::new(DynamicCertResolver::new(store1));
    let tls_cfg = TlsListenerConfig::new(resolver);

    let registry = RuntimeRegistry::new();
    let snapshot = SnapshotBuilder::new(1)
        .upstream(UpstreamConfig::new(
            "up",
            vec![format!("http://{upstream}")],
        ))
        .route(
            RouteSpec::new("tls-route", RouteMatch::any(), "up")
                .with_plugin(Arc::new(SniEchoPlugin)),
        )
        .build(&registry, true)
        .unwrap();

    let handle = GatewayServer::new(snapshot)
        .with_tls(tls_cfg)
        .bind("127.0.0.1:0".parse().unwrap())
        .await
        .unwrap();

    async fn tls_get_with_ca(addr: SocketAddr, sni: &str, ca_pem: &[u8]) -> Result<String, String> {
        let up_tls = shunt_engine::UpstreamTlsConfig {
            extra_ca_pem: Some(ca_pem.to_vec()),
            alpn_protocols: vec![b"http/1.1".to_vec()],
            ..Default::default()
        };
        let client_cfg = up_tls.build_client_config(None).unwrap();
        let connector = TlsConnector::from(client_cfg);

        let tcp = TcpStream::connect(addr).await.map_err(|e| e.to_string())?;
        let server_name = ServerName::try_from(sni.to_owned()).unwrap();
        let tls = connector
            .connect(server_name, tcp)
            .await
            .map_err(|e| e.to_string())?;

        let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(tls))
            .await
            .map_err(|e| e.to_string())?;
        tokio::spawn(async move {
            let _ = conn.await;
        });

        let req = Request::builder()
            .method(Method::GET)
            .uri("/")
            .header(header::HOST, sni)
            .body(Full::new(Bytes::new()))
            .unwrap();
        let res = sender.send_request(req).await.map_err(|e| e.to_string())?;
        let sni_hdr = res
            .headers()
            .get("x-tls-sni")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_owned();
        let body = res.into_body().collect().await.unwrap().to_bytes();
        Ok(format!("{sni_hdr}:{}", String::from_utf8_lossy(&body)))
    }

    // Both alpha.test (cert1) and beta.test verify strictly against their respective CAs.
    assert_eq!(
        tls_get_with_ca(handle.local_addr(), "alpha.test", &alpha_cert1)
            .await
            .unwrap(),
        "alpha.test:tls-ok"
    );
    assert_eq!(
        tls_get_with_ca(handle.local_addr(), "beta.test", &beta_cert)
            .await
            .unwrap(),
        "beta.test:tls-ok"
    );
    // alpha_cert2 is NOT yet active.
    assert!(
        tls_get_with_ca(handle.local_addr(), "alpha.test", &alpha_cert2)
            .await
            .is_err()
    );

    // Hot-reload alpha.test to cert2 without restarting the listener.
    let store2 = CertStore::new()
        .with_sni(
            "alpha.test",
            load_certified_key_pem(&alpha_cert2, &alpha_key2).unwrap(),
        )
        .with_sni(
            "beta.test",
            load_certified_key_pem(&beta_cert, &beta_key).unwrap(),
        );
    handle.reload_tls(store2);

    // Now alpha.test verifies against alpha_cert2!
    assert_eq!(
        tls_get_with_ca(handle.local_addr(), "alpha.test", &alpha_cert2)
            .await
            .unwrap(),
        "alpha.test:tls-ok"
    );

    assert!(handle.shutdown().await);
}

// -----------------------------------------------------------------------------
// 4. Hybrid sync + async plugins, Flow::Respond short-circuit, hook timings
// -----------------------------------------------------------------------------

struct AsyncAuthPlugin {
    expected_token: String,
    summaries: Arc<Mutex<Vec<RequestSummary>>>,
    done_notify: Arc<Notify>,
}

impl HttpPlugin for AsyncAuthPlugin {
    fn name(&self) -> &str {
        "async-auth"
    }

    fn hook_mask(&self) -> HookMask {
        HookMask::ON_REQUEST_HEADERS | HookMask::ON_RESPONSE_HEADERS | HookMask::ON_COMPLETE
    }

    fn on_request_headers<'a>(
        &'a self,
        ctx: &'a mut RequestCtx,
        req: &'a mut RequestHead,
    ) -> HookResult<'a, Flow> {
        let auth = req
            .headers
            .get(header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned);
        let expected = self.expected_token.clone();

        // Simulate async I/O auth lookup.
        HookResult::pending(async move {
            tokio::time::sleep(Duration::from_millis(5)).await;
            if auth.as_deref() == Some(expected.as_str()) {
                ctx.insert_ext("authed-user".to_owned());
                Flow::Continue
            } else {
                Flow::Respond(BufferedResponse::text(StatusCode::UNAUTHORIZED, "denied"))
            }
        })
    }

    fn on_response_headers<'a>(
        &'a self,
        ctx: &'a mut RequestCtx,
        res: &'a mut ResponseHead,
    ) -> HookResult<'a, Flow> {
        // Sync fast-path (zero heap allocation).
        if let Some(user) = ctx.get_ext::<String>() {
            res.headers.insert(
                HeaderName::from_static("x-authed-user"),
                HeaderValue::from_str(user).unwrap(),
            );
        }
        HookResult::Ready(Flow::Continue)
    }

    fn on_complete<'a>(
        &'a self,
        _ctx: &'a RequestCtx,
        summary: &'a RequestSummary,
    ) -> HookResult<'a, ()> {
        self.summaries.lock().unwrap().push(summary.clone());
        self.done_notify.notify_one();
        HookResult::Ready(())
    }
}

#[tokio::test]
async fn sync_and_async_plugins_short_circuit_and_timings() {
    let upstream_hits = Arc::new(AtomicUsize::new(0));
    let hits_clone = Arc::clone(&upstream_hits);
    let upstream = spawn_http1_upstream(move |_req| {
        let hits = Arc::clone(&hits_clone);
        async move {
            hits.fetch_add(1, Ordering::SeqCst);
            Response::builder()
                .status(StatusCode::OK)
                .body(ShuntBody::full(Bytes::from_static(b"secret-data")))
                .unwrap()
        }
    })
    .await;

    let summaries = Arc::new(Mutex::new(Vec::new()));
    let notify = Arc::new(Notify::new());
    let plugin = Arc::new(AsyncAuthPlugin {
        expected_token: "Bearer ok".into(),
        summaries: Arc::clone(&summaries),
        done_notify: Arc::clone(&notify),
    });

    let registry = RuntimeRegistry::new();
    let snapshot = SnapshotBuilder::new(1)
        .upstream(UpstreamConfig::new(
            "up",
            vec![format!("http://{upstream}")],
        ))
        .route(RouteSpec::new("auth-route", RouteMatch::any(), "up").with_plugin(plugin))
        .build(&registry, true)
        .unwrap();

    let handle = GatewayServer::new(snapshot)
        .with_trace_enabled(true)
        .bind("127.0.0.1:0".parse().unwrap())
        .await
        .unwrap();

    // 1. Unauthorized -> short-circuit 401 without hitting upstream.
    let req_unauth = Request::builder()
        .uri("/")
        .body(Full::new(Bytes::new()))
        .unwrap();
    let (status, _, body) = send_h1(handle.local_addr(), req_unauth).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(body, Bytes::from_static(b"denied"));
    assert_eq!(upstream_hits.load(Ordering::SeqCst), 0);
    notify.notified().await;

    // 2. Authorized -> reaches upstream and sets response header.
    let req_auth = Request::builder()
        .uri("/")
        .header(header::AUTHORIZATION, "Bearer ok")
        .body(Full::new(Bytes::new()))
        .unwrap();
    let (status, headers, body) = send_h1(handle.local_addr(), req_auth).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(headers.get("x-authed-user").unwrap(), "authed-user");
    assert_eq!(body, Bytes::from_static(b"secret-data"));
    assert_eq!(upstream_hits.load(Ordering::SeqCst), 1);
    notify.notified().await;

    {
        let recorded = summaries.lock().unwrap();
        assert_eq!(recorded.len(), 2);
        assert_eq!(recorded[0].status, Some(StatusCode::UNAUTHORIZED));
        assert_eq!(recorded[1].status, Some(StatusCode::OK));
        assert!(
            recorded[1]
                .hook_timings
                .iter()
                .any(|t| t.plugin == "async-auth" && t.hook == "on_request_headers")
        );
        assert!(
            recorded[1]
                .hook_timings
                .iter()
                .any(|t| t.plugin == "async-auth" && t.hook == "on_response_headers")
        );
    }

    assert!(handle.shutdown().await);
}

// -----------------------------------------------------------------------------
// 5. Request body buffering (JSON-driven dynamic routing) + 413 cap
// -----------------------------------------------------------------------------

struct JsonModelRouterPlugin {
    cap: usize,
}

#[derive(Clone)]
struct TargetModel(String);

impl HttpPlugin for JsonModelRouterPlugin {
    fn name(&self) -> &str {
        "json-router"
    }

    fn hook_mask(&self) -> HookMask {
        HookMask::REQUEST_BODY_BUFFERED | HookMask::ON_ROUTE
    }

    fn max_request_body_bytes(&self) -> Option<usize> {
        Some(self.cap)
    }

    fn on_request_body_buffered<'a>(
        &'a self,
        ctx: &'a mut RequestCtx,
        body: &'a mut Bytes,
    ) -> HookResult<'a, Flow> {
        if let Ok(v) = serde_json::from_slice::<serde_json::Value>(body)
            && let Some(model) = v.get("model").and_then(|m| m.as_str())
        {
            ctx.insert_ext(TargetModel(model.to_owned()));
        }
        HookResult::Ready(Flow::Continue)
    }

    fn on_route<'a>(
        &'a self,
        ctx: &'a mut RequestCtx,
        decision: &'a mut RouteDecision,
    ) -> HookResult<'a, Flow> {
        if let Some(TargetModel(model)) = ctx.get_ext::<TargetModel>()
            && model.starts_with("claude")
        {
            decision.upstream = "anthropic".to_owned();
        }
        HookResult::Ready(Flow::Continue)
    }
}

#[tokio::test]
async fn request_body_buffering_dynamic_route_and_413_cap() {
    let openai_up = spawn_http1_upstream(|req| async move {
        let body = req.into_body().collect().await.unwrap().to_bytes();
        Response::builder()
            .status(StatusCode::OK)
            .body(ShuntBody::full(Bytes::from(format!(
                "openai:{}",
                String::from_utf8_lossy(&body)
            ))))
            .unwrap()
    })
    .await;

    let anthropic_up = spawn_http1_upstream(|req| async move {
        let body = req.into_body().collect().await.unwrap().to_bytes();
        Response::builder()
            .status(StatusCode::OK)
            .body(ShuntBody::full(Bytes::from(format!(
                "anthropic:{}",
                String::from_utf8_lossy(&body)
            ))))
            .unwrap()
    })
    .await;

    let registry = RuntimeRegistry::new();
    let snapshot = SnapshotBuilder::new(1)
        .upstream(UpstreamConfig::new(
            "openai",
            vec![format!("http://{openai_up}")],
        ))
        .upstream(UpstreamConfig::new(
            "anthropic",
            vec![format!("http://{anthropic_up}")],
        ))
        .route(
            RouteSpec::new("chat", RouteMatch::exact("/v1/chat"), "openai")
                .with_plugin(Arc::new(JsonModelRouterPlugin { cap: 64 })),
        )
        .build(&registry, true)
        .unwrap();

    let handle = GatewayServer::new(snapshot)
        .bind("127.0.0.1:0".parse().unwrap())
        .await
        .unwrap();

    // Small payload routed dynamically to anthropic based on buffered JSON body.
    let req = Request::builder()
        .method(Method::POST)
        .uri("/v1/chat")
        .body(Full::new(Bytes::from_static(br#"{"model":"claude-3"}"#)))
        .unwrap();
    let (status, _, body) = send_h1(handle.local_addr(), req).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        body,
        Bytes::from_static(br#"anthropic:{"model":"claude-3"}"#)
    );

    // Oversized payload (> 64 bytes) rejected with 413 Payload Too Large.
    let big = vec![b'a'; 128];
    let req_big = Request::builder()
        .method(Method::POST)
        .uri("/v1/chat")
        .body(Full::new(Bytes::from(big)))
        .unwrap();
    let (status, _, _) = send_h1(handle.local_addr(), req_big).await;
    assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);

    assert!(handle.shutdown().await);
}

// -----------------------------------------------------------------------------
// 6. Per-attempt failover & retry with O(1) cloned buffered body
// -----------------------------------------------------------------------------

struct FailoverAdapterPlugin;

impl HttpPlugin for FailoverAdapterPlugin {
    fn name(&self) -> &str {
        "failover-adapter"
    }

    fn hook_mask(&self) -> HookMask {
        HookMask::REQUEST_BODY_BUFFERED
            | HookMask::ON_UPSTREAM_SELECT
            | HookMask::ON_UPSTREAM_REQUEST
            | HookMask::ON_RESPONSE_HEADERS
    }

    fn on_upstream_select<'a>(
        &'a self,
        _ctx: &'a mut RequestCtx,
        selection: &'a mut UpstreamSelection,
    ) -> HookResult<'a, Flow> {
        if selection.attempt == 2 {
            selection.upstream = "backup".to_owned();
        }
        HookResult::Ready(Flow::Continue)
    }

    fn on_upstream_request<'a>(
        &'a self,
        ctx: &'a mut RequestCtx,
        req: &'a mut UpstreamRequest,
    ) -> HookResult<'a, Flow> {
        req.headers.insert(
            HeaderName::from_static("x-attempt"),
            HeaderValue::from_str(&ctx.attempt.to_string()).unwrap(),
        );
        // Translate body differently on attempt 2 to prove canonical body wasn't mutated by attempt 1.
        if let Some(body) = &mut req.body {
            let suffix = format!("|attempt={}", ctx.attempt);
            let mut merged = body.to_vec();
            merged.extend_from_slice(suffix.as_bytes());
            *body = Bytes::from(merged);
        }
        HookResult::Ready(Flow::Continue)
    }

    fn on_response_headers<'a>(
        &'a self,
        _ctx: &'a mut RequestCtx,
        res: &'a mut ResponseHead,
    ) -> HookResult<'a, Flow> {
        if res.status == StatusCode::TOO_MANY_REQUESTS || res.status.is_server_error() {
            HookResult::Ready(Flow::RetryUpstream)
        } else {
            HookResult::Ready(Flow::Continue)
        }
    }
}

#[tokio::test]
async fn per_attempt_failover_replays_canonical_buffered_body() {
    let primary_hits = Arc::new(AtomicUsize::new(0));
    let p_hits = Arc::clone(&primary_hits);
    let primary_up = spawn_http1_upstream(move |_req| {
        let hits = Arc::clone(&p_hits);
        async move {
            hits.fetch_add(1, Ordering::SeqCst);
            Response::builder()
                .status(StatusCode::TOO_MANY_REQUESTS)
                .body(ShuntBody::full(Bytes::from_static(b"rate-limited")))
                .unwrap()
        }
    })
    .await;

    let backup_up = spawn_http1_upstream(|req| async move {
        let attempt = req
            .headers()
            .get("x-attempt")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_owned();
        let body = req.into_body().collect().await.unwrap().to_bytes();
        Response::builder()
            .status(StatusCode::OK)
            .body(ShuntBody::full(Bytes::from(format!(
                "backup({attempt}):{}",
                String::from_utf8_lossy(&body)
            ))))
            .unwrap()
    })
    .await;

    let registry = RuntimeRegistry::new();
    let snapshot = SnapshotBuilder::new(1)
        .upstream(UpstreamConfig::new(
            "primary",
            vec![format!("http://{primary_up}")],
        ))
        .upstream(UpstreamConfig::new(
            "backup",
            vec![format!("http://{backup_up}")],
        ))
        .route(
            RouteSpec::new("ai", RouteMatch::any(), "primary")
                .with_max_attempts(2)
                .with_plugin(Arc::new(FailoverAdapterPlugin)),
        )
        .build(&registry, true)
        .unwrap();

    let handle = GatewayServer::new(snapshot)
        .bind("127.0.0.1:0".parse().unwrap())
        .await
        .unwrap();

    let req = Request::builder()
        .method(Method::POST)
        .uri("/v1/chat/completions")
        .body(Full::new(Bytes::from_static(b"prompt-payload")))
        .unwrap();

    let (status, _, body) = send_h1(handle.local_addr(), req).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(primary_hits.load(Ordering::SeqCst), 1);
    // Crucially, attempt 2 receives the clean canonical body + "|attempt=2" (NOT attempt 1's mutation).
    assert_eq!(
        body,
        Bytes::from_static(b"backup(2):prompt-payload|attempt=2")
    );

    assert!(handle.shutdown().await);
}

// -----------------------------------------------------------------------------
// 7. Streaming SSE response chunk rewriting + end_of_stream flush
// -----------------------------------------------------------------------------

#[derive(Clone, Default)]
struct SseLineBuf(String);

struct SseUpperPlugin {
    summaries: Arc<Mutex<Vec<RequestSummary>>>,
    done: Arc<Notify>,
}

impl HttpPlugin for SseUpperPlugin {
    fn name(&self) -> &str {
        "sse-upper"
    }

    fn hook_mask(&self) -> HookMask {
        HookMask::RESPONSE_BODY_STREAM | HookMask::ON_COMPLETE
    }

    fn on_response_body_chunk<'a>(
        &'a self,
        ctx: &'a mut RequestCtx,
        chunk: &'a mut Bytes,
        end_of_stream: bool,
    ) -> HookResult<'a, StreamFlow> {
        let mut buf = ctx.remove_ext::<SseLineBuf>().unwrap_or_default();
        buf.0.push_str(&String::from_utf8_lossy(chunk));

        let mut emitted = String::new();
        while let Some(pos) = buf.0.find('\n') {
            let line = buf.0[..=pos].to_ascii_uppercase();
            emitted.push_str(&line);
            buf.0.drain(..=pos);
        }
        if end_of_stream && !buf.0.is_empty() {
            emitted.push_str(&buf.0.to_ascii_uppercase());
            emitted.push_str("[EOF]");
            buf.0.clear();
        }
        ctx.insert_ext(buf);
        *chunk = Bytes::from(emitted);
        HookResult::Ready(StreamFlow::Continue)
    }

    fn on_complete<'a>(
        &'a self,
        _ctx: &'a RequestCtx,
        summary: &'a RequestSummary,
    ) -> HookResult<'a, ()> {
        self.summaries.lock().unwrap().push(summary.clone());
        self.done.notify_one();
        HookResult::Ready(())
    }
}

#[tokio::test]
async fn streaming_sse_chunk_rewrite_and_eof_flush() {
    let upstream = spawn_http1_upstream(|_req| async move {
        let (tx, rx) = mpsc::channel(8);
        tokio::spawn(async move {
            let _ = tx
                .send(Ok(Frame::data(Bytes::from_static(b"data: hel"))))
                .await;
            tokio::time::sleep(Duration::from_millis(10)).await;
            let _ = tx
                .send(Ok(Frame::data(Bytes::from_static(b"lo\ndata: wor"))))
                .await;
            tokio::time::sleep(Duration::from_millis(10)).await;
            let _ = tx.send(Ok(Frame::data(Bytes::from_static(b"ld")))).await;
        });

        Response::builder()
            .status(StatusCode::OK)
            .header(header::CONTENT_TYPE, "text/event-stream")
            .body(ShuntBody::channel(rx))
            .unwrap()
    })
    .await;

    let summaries = Arc::new(Mutex::new(Vec::new()));
    let done = Arc::new(Notify::new());
    let registry = RuntimeRegistry::new();
    let snapshot = SnapshotBuilder::new(1)
        .upstream(UpstreamConfig::new(
            "sse",
            vec![format!("http://{upstream}")],
        ))
        .route(
            RouteSpec::new("sse", RouteMatch::any(), "sse").with_plugin(Arc::new(SseUpperPlugin {
                summaries: Arc::clone(&summaries),
                done: Arc::clone(&done),
            })),
        )
        .build(&registry, true)
        .unwrap();

    let handle = GatewayServer::new(snapshot)
        .bind("127.0.0.1:0".parse().unwrap())
        .await
        .unwrap();

    let req = Request::builder()
        .uri("/events")
        .body(Full::new(Bytes::new()))
        .unwrap();
    let (status, _, body) = send_h1(handle.local_addr(), req).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, Bytes::from_static(b"DATA: HELLO\nDATA: WORLD[EOF]"));

    done.notified().await;
    {
        let s = summaries.lock().unwrap();
        assert_eq!(s.len(), 1);
        assert!(!s[0].aborted_mid_stream);
        assert_eq!(
            s[0].response_bytes,
            b"DATA: HELLO\nDATA: WORLD[EOF]".len() as u64
        );
    }

    assert!(handle.shutdown().await);
}

// -----------------------------------------------------------------------------
// 8. Split timeouts: response_headers_timeout (TTFB) vs idle_chunk_timeout
// -----------------------------------------------------------------------------

#[tokio::test]
async fn split_timeouts_ttfb_and_idle_chunk() {
    let upstream = spawn_http1_upstream(|req| async move {
        match req.uri().path() {
            "/slow-headers" => {
                tokio::time::sleep(Duration::from_millis(250)).await;
                Response::builder()
                    .status(StatusCode::OK)
                    .body(ShuntBody::full(Bytes::from_static(b"late")))
                    .unwrap()
            }
            "/steady-stream" => {
                // Emits 4 chunks spaced 35ms apart (total 140ms > 80ms idle timeout, but
                // each gap 35ms < 80ms idle timeout -> MUST SUCCEED!).
                let (tx, rx) = mpsc::channel(8);
                tokio::spawn(async move {
                    for i in 0..4 {
                        let _ = tx.send(Ok(Frame::data(Bytes::from(format!("c{i}"))))).await;
                        tokio::time::sleep(Duration::from_millis(35)).await;
                    }
                });
                Response::builder()
                    .status(StatusCode::OK)
                    .body(ShuntBody::channel(rx))
                    .unwrap()
            }
            "/stalled-stream" => {
                // Sends chunk 1 immediately, then stalls 250ms (> 80ms idle timeout -> MUST ABORT!).
                let (tx, rx) = mpsc::channel(8);
                tokio::spawn(async move {
                    let _ = tx.send(Ok(Frame::data(Bytes::from_static(b"first")))).await;
                    tokio::time::sleep(Duration::from_millis(250)).await;
                    let _ = tx.send(Ok(Frame::data(Bytes::from_static(b"never")))).await;
                });
                Response::builder()
                    .status(StatusCode::OK)
                    .body(ShuntBody::channel(rx))
                    .unwrap()
            }
            _ => Response::builder()
                .status(StatusCode::NOT_FOUND)
                .body(ShuntBody::empty())
                .unwrap(),
        }
    })
    .await;

    let registry = RuntimeRegistry::new();
    let snapshot = SnapshotBuilder::new(1)
        .upstream(UpstreamConfig::new("t", vec![format!("http://{upstream}")]))
        .route(
            RouteSpec::new("timeout-route", RouteMatch::any(), "t").with_timeouts(TimeoutConfig {
                response_headers_timeout: Some(Duration::from_millis(80)),
                idle_chunk_timeout: Some(Duration::from_millis(80)),
            }),
        )
        .build(&registry, true)
        .unwrap();

    let handle = GatewayServer::new(snapshot)
        .bind("127.0.0.1:0".parse().unwrap())
        .await
        .unwrap();

    // 1. TTFB timeout -> 504 Gateway Timeout
    let (status, _, _) = send_h1(
        handle.local_addr(),
        Request::builder()
            .uri("/slow-headers")
            .body(Full::new(Bytes::new()))
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::GATEWAY_TIMEOUT);

    // 2. Steady stream longer than idle timeout -> succeeds completely!
    let (status, _, body) = send_h1(
        handle.local_addr(),
        Request::builder()
            .uri("/steady-stream")
            .body(Full::new(Bytes::new()))
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, Bytes::from_static(b"c0c1c2c3"));

    // 3. Stalled stream exceeding idle_chunk_timeout -> body reading fails mid-stream!
    let stream = TcpStream::connect(handle.local_addr()).await.unwrap();
    let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(stream))
        .await
        .unwrap();
    tokio::spawn(async move {
        let _ = conn.await;
    });
    let res = sender
        .send_request(
            Request::builder()
                .uri("/stalled-stream")
                .body(Full::new(Bytes::new()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let body_res = res.into_body().collect().await;
    assert!(
        body_res.is_err(),
        "expected mid-stream abort on idle chunk timeout"
    );

    assert!(handle.shutdown().await);
}

// -----------------------------------------------------------------------------
// 9. Fault isolation: plugin panics pre-flush (sync & async) and mid-stream
// -----------------------------------------------------------------------------

struct PanickingPlugin {
    summaries: Arc<Mutex<Vec<RequestSummary>>>,
    done: Arc<Notify>,
}

impl HttpPlugin for PanickingPlugin {
    fn name(&self) -> &str {
        "panicker"
    }

    fn hook_mask(&self) -> HookMask {
        HookMask::ON_REQUEST_HEADERS | HookMask::RESPONSE_BODY_STREAM | HookMask::ON_COMPLETE
    }

    fn on_request_headers<'a>(
        &'a self,
        ctx: &'a mut RequestCtx,
        req: &'a mut RequestHead,
    ) -> HookResult<'a, Flow> {
        match req.uri.path() {
            "/panic-sync" => panic!("boom sync"),
            "/panic-async" => HookResult::pending(async move {
                tokio::task::yield_now().await;
                panic!("boom async");
            }),
            "/panic-stream" => {
                ctx.insert_ext(true);
                HookResult::Ready(Flow::Continue)
            }
            _ => HookResult::Ready(Flow::Continue),
        }
    }

    fn on_response_body_chunk<'a>(
        &'a self,
        ctx: &'a mut RequestCtx,
        _chunk: &'a mut Bytes,
        _end_of_stream: bool,
    ) -> HookResult<'a, StreamFlow> {
        if ctx.get_ext::<bool>().copied().unwrap_or(false) {
            panic!("boom mid-stream");
        }
        HookResult::Ready(StreamFlow::Continue)
    }

    fn on_complete<'a>(
        &'a self,
        _ctx: &'a RequestCtx,
        summary: &'a RequestSummary,
    ) -> HookResult<'a, ()> {
        self.summaries.lock().unwrap().push(summary.clone());
        self.done.notify_one();
        HookResult::Ready(())
    }
}

#[tokio::test]
async fn panic_isolation_pre_flush_and_mid_stream() {
    let upstream = spawn_http1_upstream(|_req| async move {
        Response::builder()
            .status(StatusCode::OK)
            .body(ShuntBody::full(Bytes::from_static(b"stream-chunk")))
            .unwrap()
    })
    .await;

    let summaries = Arc::new(Mutex::new(Vec::new()));
    let done = Arc::new(Notify::new());

    let registry = RuntimeRegistry::new();
    let snapshot = SnapshotBuilder::new(1)
        .upstream(UpstreamConfig::new(
            "up",
            vec![format!("http://{upstream}")],
        ))
        .route(
            RouteSpec::new("p", RouteMatch::any(), "up").with_plugin(Arc::new(PanickingPlugin {
                summaries: Arc::clone(&summaries),
                done: Arc::clone(&done),
            })),
        )
        .build(&registry, true)
        .unwrap();

    let handle = GatewayServer::new(snapshot)
        .bind("127.0.0.1:0".parse().unwrap())
        .await
        .unwrap();

    // Sync pre-flush panic -> 500
    let (st, _, _) = send_h1(
        handle.local_addr(),
        Request::builder()
            .uri("/panic-sync")
            .body(Full::new(Bytes::new()))
            .unwrap(),
    )
    .await;
    assert_eq!(st, StatusCode::INTERNAL_SERVER_ERROR);
    done.notified().await;

    // Async pre-flush panic -> 500
    let (st, _, _) = send_h1(
        handle.local_addr(),
        Request::builder()
            .uri("/panic-async")
            .body(Full::new(Bytes::new()))
            .unwrap(),
    )
    .await;
    assert_eq!(st, StatusCode::INTERNAL_SERVER_ERROR);
    done.notified().await;

    // Mid-stream panic -> stream aborted cleanly, on_complete sees aborted_mid_stream = true
    let stream = TcpStream::connect(handle.local_addr()).await.unwrap();
    let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(stream))
        .await
        .unwrap();
    tokio::spawn(async move {
        let _ = conn.await;
    });
    let res = sender
        .send_request(
            Request::builder()
                .uri("/panic-stream")
                .body(Full::new(Bytes::new()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    assert!(res.into_body().collect().await.is_err());
    done.notified().await;

    // Gateway is completely healthy for normal traffic after panics!
    let (st, _, body) = send_h1(
        handle.local_addr(),
        Request::builder()
            .uri("/ok")
            .body(Full::new(Bytes::new()))
            .unwrap(),
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(body, Bytes::from_static(b"stream-chunk"));
    done.notified().await;

    {
        let recorded = summaries.lock().unwrap();
        assert_eq!(recorded.len(), 4);
        assert!(recorded[0].error.as_deref().unwrap().contains("boom sync"));
        assert!(recorded[1].error.as_deref().unwrap().contains("boom async"));
        assert!(recorded[2].aborted_mid_stream);
        assert!(
            recorded[2]
                .error
                .as_deref()
                .unwrap()
                .contains("boom mid-stream")
        );
        assert!(!recorded[3].aborted_mid_stream);
    }

    assert!(handle.shutdown().await);
}

// -----------------------------------------------------------------------------
// 10. Hot reload: ArcSwap snapshot swap + RuntimeRegistry pool & StateStore reuse
// -----------------------------------------------------------------------------

#[tokio::test]
async fn hot_reload_preserves_warm_pools_and_plugin_state_and_drains_inflight() {
    let gate = Arc::new(Notify::new());
    let gate_up = Arc::clone(&gate);
    let entered = Arc::new(Notify::new());
    let entered_up = Arc::clone(&entered);

    let v1_up = spawn_http1_upstream(move |_req| {
        let g = Arc::clone(&gate_up);
        let e = Arc::clone(&entered_up);
        async move {
            e.notify_one();
            g.notified().await;
            Response::builder()
                .status(StatusCode::OK)
                .body(ShuntBody::full(Bytes::from_static(b"from-v1")))
                .unwrap()
        }
    })
    .await;

    let v2_up = spawn_http1_upstream(|_req| async move {
        Response::builder()
            .status(StatusCode::OK)
            .body(ShuntBody::full(Bytes::from_static(b"from-v2")))
            .unwrap()
    })
    .await;

    let stable_up = spawn_http1_upstream(|_req| async move {
        Response::builder()
            .status(StatusCode::OK)
            .body(ShuntBody::full(Bytes::from_static(b"stable")))
            .unwrap()
    })
    .await;

    let registry = RuntimeRegistry::new();

    // Build session 1: initialize stateful plugin counters.
    let session1 = registry.begin_build_session();
    let stable_counter = session1
        .context_for("route:stable:limiter")
        .state_handle()
        .get_or_init("count", || AtomicUsize::new(0));
    stable_counter.fetch_add(42, Ordering::SeqCst);
    let _ephemeral_counter = session1
        .context_for("route:v1:limiter")
        .state_handle()
        .get_or_init("count", || AtomicUsize::new(7));
    session1.commit_gc();
    assert_eq!(registry.state_store().len(), 2);

    let snap1 = SnapshotBuilder::new(1)
        .upstream(UpstreamConfig::new(
            "stable",
            vec![format!("http://{stable_up}")],
        ))
        .upstream(UpstreamConfig::new(
            "ephemeral",
            vec![format!("http://{v1_up}")],
        ))
        .route(RouteSpec::new(
            "r-main",
            RouteMatch::prefix("/main"),
            "ephemeral",
        ))
        .route(RouteSpec::new(
            "r-stable",
            RouteMatch::prefix("/stable"),
            "stable",
        ))
        .build(&registry, true)
        .unwrap();

    let stable_pool_id_v1 = snap1.upstream("stable").unwrap().pool_id();
    assert_eq!(registry.pool_count(), 2);

    let handle = GatewayServer::new(snap1)
        .bind("127.0.0.1:0".parse().unwrap())
        .await
        .unwrap();
    let gw_addr = handle.local_addr();

    // Start in-flight request against snapshot v1.
    let inflight = tokio::spawn(async move {
        send_h1(
            gw_addr,
            Request::builder()
                .uri("/main")
                .body(Full::new(Bytes::new()))
                .unwrap(),
        )
        .await
    });

    // Wait until the in-flight request is actively inside v1 upstream.
    entered.notified().await;

    // Compile snapshot v2: `stable` unchanged, `ephemeral` removed, `new_up` added.
    let session2 = registry.begin_build_session();
    let stable_counter_after = session2
        .context_for("route:stable:limiter")
        .state_handle()
        .get_or_init("count", || AtomicUsize::new(0));
    let removed_state = session2.commit_gc();
    assert_eq!(removed_state, 1);
    assert_eq!(registry.state_store().len(), 1);
    assert_eq!(stable_counter_after.load(Ordering::SeqCst), 42);

    let snap2 = SnapshotBuilder::new(2)
        .upstream(UpstreamConfig::new(
            "stable",
            vec![format!("http://{stable_up}")],
        ))
        .upstream(UpstreamConfig::new(
            "new_up",
            vec![format!("http://{v2_up}")],
        ))
        .route(RouteSpec::new(
            "r-main",
            RouteMatch::prefix("/main"),
            "new_up",
        ))
        .route(RouteSpec::new(
            "r-stable",
            RouteMatch::prefix("/stable"),
            "stable",
        ))
        .build(&registry, true)
        .unwrap();

    // Verify warm pool reuse & orphan pool GC.
    assert_eq!(
        snap2.upstream("stable").unwrap().pool_id(),
        stable_pool_id_v1
    );
    assert_eq!(registry.pool_count(), 2);

    // Atomic hot swap while v1 request is still in-flight!
    handle.swap_snapshot(snap2);

    // New request immediately hits v2.
    let (st2, _, body2) = send_h1(
        gw_addr,
        Request::builder()
            .uri("/main")
            .body(Full::new(Bytes::new()))
            .unwrap(),
    )
    .await;
    assert_eq!(st2, StatusCode::OK);
    assert_eq!(body2, Bytes::from_static(b"from-v2"));

    // Release in-flight v1 request -> finishes cleanly on its original snapshot v1!
    gate.notify_one();
    let (st1, _, body1) = inflight.await.unwrap();
    assert_eq!(st1, StatusCode::OK);
    assert_eq!(body1, Bytes::from_static(b"from-v1"));

    assert!(handle.shutdown().await);
}

// -----------------------------------------------------------------------------
// 11. WebSocket upgrade bidirectional tunnel
// -----------------------------------------------------------------------------

#[tokio::test]
async fn websocket_upgrade_bidirectional_tunnel() {
    let upstream = spawn_http1_upstream(|mut req| async move {
        let on_upgrade = hyper::upgrade::on(&mut req);
        tokio::spawn(async move {
            if let Ok(upgraded) = on_upgrade.await {
                let mut io = TokioIo::new(upgraded);
                let mut buf = [0u8; 64];
                if let Ok(n) = io.read(&mut buf).await {
                    let mut reply = b"echo:".to_vec();
                    reply.extend_from_slice(&buf[..n]);
                    let _ = io.write_all(&reply).await;
                    let _ = io.shutdown().await;
                }
            }
        });

        Response::builder()
            .status(StatusCode::SWITCHING_PROTOCOLS)
            .header(header::CONNECTION, "Upgrade")
            .header(header::UPGRADE, "websocket")
            .header("sec-websocket-accept", "test-accept-token")
            .body(ShuntBody::empty())
            .unwrap()
    })
    .await;

    let registry = RuntimeRegistry::new();
    let snapshot = SnapshotBuilder::new(1)
        .upstream(UpstreamConfig::new(
            "ws",
            vec![format!("http://{upstream}")],
        ))
        .route(RouteSpec::new("ws", RouteMatch::prefix("/ws"), "ws"))
        .build(&registry, true)
        .unwrap();

    let handle = GatewayServer::new(snapshot)
        .bind("127.0.0.1:0".parse().unwrap())
        .await
        .unwrap();

    let mut tcp = TcpStream::connect(handle.local_addr()).await.unwrap();
    let upgrade_req = concat!(
        "GET /ws/chat HTTP/1.1\r\n",
        "Host: localhost\r\n",
        "Connection: Upgrade\r\n",
        "Upgrade: websocket\r\n",
        "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n",
        "Sec-WebSocket-Version: 13\r\n\r\n"
    );
    tcp.write_all(upgrade_req.as_bytes()).await.unwrap();

    // Read HTTP 101 response headers.
    let mut header_buf = Vec::new();
    let mut tmp = [0u8; 256];
    loop {
        let n = tcp.read(&mut tmp).await.unwrap();
        assert!(n > 0);
        header_buf.extend_from_slice(&tmp[..n]);
        if header_buf.windows(4).any(|w| w == b"\r\n\r\n") {
            break;
        }
    }
    let header_str = String::from_utf8_lossy(&header_buf);
    assert!(header_str.starts_with("HTTP/1.1 101"), "got: {header_str}");
    assert!(
        header_str
            .to_ascii_lowercase()
            .contains("sec-websocket-accept: test-accept-token")
    );

    // Send bytes over the upgraded bidirectional tunnel and verify echo.
    tcp.write_all(b"ping-over-ws").await.unwrap();
    let mut echoed = vec![0u8; 64];
    let n = tcp.read(&mut echoed).await.unwrap();
    assert_eq!(&echoed[..n], b"echo:ping-over-ws");
    drop(tcp);

    assert!(handle.shutdown().await);
}

// -----------------------------------------------------------------------------
// 12. Graceful shutdown drains in-flight requests cleanly
// -----------------------------------------------------------------------------

#[tokio::test]
async fn graceful_shutdown_drains_inflight_requests() {
    let entered = Arc::new(Notify::new());
    let entered_up = Arc::clone(&entered);

    let upstream = spawn_http1_upstream(move |_req| {
        let e = Arc::clone(&entered_up);
        async move {
            e.notify_one();
            tokio::time::sleep(Duration::from_millis(120)).await;
            Response::builder()
                .status(StatusCode::OK)
                .body(ShuntBody::full(Bytes::from_static(b"drained-ok")))
                .unwrap()
        }
    })
    .await;

    let registry = RuntimeRegistry::new();
    let snapshot = SnapshotBuilder::new(1)
        .upstream(UpstreamConfig::new(
            "up",
            vec![format!("http://{upstream}")],
        ))
        .route(RouteSpec::new("r", RouteMatch::any(), "up"))
        .build(&registry, true)
        .unwrap();

    let handle = GatewayServer::new(snapshot)
        .with_drain_timeout(Duration::from_secs(5))
        .bind("127.0.0.1:0".parse().unwrap())
        .await
        .unwrap();
    let addr = handle.local_addr();

    let inflight = tokio::spawn(async move {
        send_h1(
            addr,
            Request::builder()
                .uri("/slow")
                .body(Full::new(Bytes::new()))
                .unwrap(),
        )
        .await
    });

    // Wait until the request is actively in-flight, then initiate graceful shutdown.
    entered.notified().await;
    let drained_cleanly = handle.shutdown().await;
    assert!(drained_cleanly);

    // In-flight request finished cleanly with 200 OK!
    let (status, _, body) = inflight.await.unwrap();
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, Bytes::from_static(b"drained-ok"));

    // Listener is now closed (new connections are refused).
    assert!(TcpStream::connect(addr).await.is_err());
}
