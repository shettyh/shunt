//! Adversarial security regression tests for Wave 1 `shunt-engine` hardening:
//! - §2 H-1: `Connection:` hop-by-hop stripping order & protected framing/gateway headers
//! - §2 H-2: `Flow::InspectResponseBody` fail-closed on `StreamFlow::Abort` and panic
//! - §2 H-3: Strict request path validation, `allow_raw_path` opt-in, `strip_uri_prefix` & `build_target_uri`
//! - §2 H-4: Hyper timers, Slowloris header/TLS/body timeouts, `InspectResponseBody` idle timeout, `max_connections`
//! - §2 H-5: WebSockets disabled by default
//! - §3 H-8: Strict `Content-Length` validation & chunked early-response `body-limit` enforcement
//! - §3 H-6 / E-M8: X.509 DN RFC 4514 escaping

use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Duration;

use bytes::Bytes;
use http::{HeaderName, HeaderValue, Request, Response, StatusCode, Uri, header};
use http_body_util::{BodyExt, Full};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::client::legacy::Client;
use hyper_util::rt::{TokioExecutor, TokioIo};
use shunt_engine::pipeline::strip_uri_prefix;
use shunt_engine::upstream::build_target_uri;
use shunt_engine::{
    CertStore, DynamicCertResolver, GatewayServer, RouteMatch, RouteSpec, RuntimeRegistry,
    ServerLimits, ShuntBody, SnapshotBuilder, TimeoutConfig, TlsListenerConfig, UpstreamConfig,
    load_certified_key_pem, parse_client_cert_info, validate_request_path,
};
use shunt_plugin_sdk::{
    Flow, HookMask, HookResult, HttpPlugin, RequestCtx, RequestHead, RequestSummary, ResponseHead,
    StreamFlow,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

async fn spawn_http1_upstream<F, Fut>(handler: F) -> SocketAddr
where
    F: Fn(Request<hyper::body::Incoming>) -> Fut + Send + Sync + 'static,
    Fut: std::future::Future<Output = Response<ShuntBody>> + Send + 'static,
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
                let svc = service_fn(move |req| {
                    let h = Arc::clone(&h);
                    async move { Ok::<_, Infallible>(h(req).await) }
                });
                let _ = http1::Builder::new()
                    .keep_alive(true)
                    .serve_connection(TokioIo::new(tcp), svc)
                    .await;
            });
        }
    });
    addr
}

async fn send_raw_http(addr: SocketAddr, raw_req: &str) -> String {
    let mut tcp = TcpStream::connect(addr).await.unwrap();
    tcp.write_all(raw_req.as_bytes()).await.unwrap();
    let mut buf = Vec::new();
    tokio::time::timeout(Duration::from_secs(3), tcp.read_to_end(&mut buf))
        .await
        .expect("timed out reading raw HTTP response")
        .unwrap();
    String::from_utf8_lossy(&buf).into_owned()
}

// -----------------------------------------------------------------------------
// §2 H-1: Connection: header cannot strip X-Forwarded-For or plugin identity headers
// -----------------------------------------------------------------------------

struct InjectIdentityPlugin;

impl HttpPlugin for InjectIdentityPlugin {
    fn name(&self) -> &str {
        "inject-identity"
    }

    fn hook_mask(&self) -> HookMask {
        HookMask::ON_REQUEST_HEADERS
    }

    fn on_request_headers<'a>(
        &'a self,
        _ctx: &'a mut RequestCtx,
        req: &'a mut RequestHead,
    ) -> HookResult<'a, Flow> {
        req.headers.insert(
            HeaderName::from_static("x-jwt-sub"),
            HeaderValue::from_static("alice"),
        );
        req.headers.insert(
            HeaderName::from_static("x-client-cn"),
            HeaderValue::from_static("svc-payments"),
        );
        HookResult::Ready(Flow::Continue)
    }
}

#[tokio::test]
async fn connection_header_cannot_strip_xff_or_plugin_injected_identity_headers() {
    let upstream = spawn_http1_upstream(|req| async move {
        let jwt = req
            .headers()
            .get("x-jwt-sub")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("MISSING");
        let cn = req
            .headers()
            .get("x-client-cn")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("MISSING");
        let xff = req
            .headers()
            .get("x-forwarded-for")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("MISSING");
        let cl = req
            .headers()
            .get(header::CONTENT_LENGTH)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("MISSING");
        let hop = req
            .headers()
            .get("x-client-hop")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("STRIPPED");
        let te_vals: Vec<&str> = req
            .headers()
            .get_all(header::TE)
            .iter()
            .filter_map(|v| v.to_str().ok())
            .collect();
        let body = format!(
            "jwt={jwt};cn={cn};xff={xff};cl={cl};hop={hop};te={}",
            te_vals.join("|")
        );
        Response::builder()
            .status(StatusCode::OK)
            .body(ShuntBody::full(Bytes::from(body)))
            .unwrap()
    })
    .await;

    let registry = RuntimeRegistry::new();
    let snap = SnapshotBuilder::new(1)
        .upstream(UpstreamConfig::new(
            "be",
            vec![format!("http://{upstream}")],
        ))
        .route(
            RouteSpec::new("api", RouteMatch::prefix("/api"), "be")
                .with_plugin(Arc::new(InjectIdentityPlugin)),
        )
        .build(&registry, true)
        .unwrap();

    let gw = GatewayServer::new(snap)
        .bind("127.0.0.1:0".parse().unwrap())
        .await
        .unwrap();

    let raw = concat!(
        "POST /api/data HTTP/1.1\r\n",
        "Host: localhost\r\n",
        "Connection: close, x-forwarded-for, x-jwt-sub, x-client-cn, content-length, x-client-hop\r\n",
        "X-Client-Hop: should-be-stripped\r\n",
        "TE: trailers\r\n",
        "TE: gzip\r\n",
        "Content-Length: 4\r\n\r\n",
        "ping"
    );
    let resp = send_raw_http(gw.local_addr(), raw).await;
    assert!(resp.starts_with("HTTP/1.1 200"), "resp: {resp}");
    assert!(resp.contains("jwt=alice;"), "resp: {resp}");
    assert!(resp.contains("cn=svc-payments;"), "resp: {resp}");
    assert!(resp.contains("xff=127.0.0.1;"), "resp: {resp}");
    assert!(resp.contains("cl=4;"), "resp: {resp}");
    assert!(resp.contains("hop=STRIPPED;"), "resp: {resp}");
    assert!(resp.contains("te=trailers"), "resp: {resp}");
    assert!(!resp.contains("gzip"), "resp: {resp}");

    assert!(gw.shutdown().await);
}

// -----------------------------------------------------------------------------
// §2 H-2: Flow::InspectResponseBody fails closed on StreamFlow::Abort and panic
// -----------------------------------------------------------------------------

struct InspectTriggerPlugin;

impl HttpPlugin for InspectTriggerPlugin {
    fn name(&self) -> &str {
        "inspect-trigger"
    }

    fn hook_mask(&self) -> HookMask {
        HookMask::ON_RESPONSE_HEADERS
    }

    fn on_response_headers<'a>(
        &'a self,
        _ctx: &'a mut RequestCtx,
        _res: &'a mut ResponseHead,
    ) -> HookResult<'a, Flow> {
        HookResult::Ready(Flow::InspectResponseBody { max_bytes: 4096 })
    }
}

struct StreamFailPlugin {
    panic_instead: bool,
    saw_aborted: Arc<AtomicBool>,
}

impl HttpPlugin for StreamFailPlugin {
    fn name(&self) -> &str {
        "stream-fail"
    }

    fn hook_mask(&self) -> HookMask {
        HookMask::RESPONSE_BODY_STREAM | HookMask::ON_COMPLETE
    }

    fn on_response_body_chunk<'a>(
        &'a self,
        _ctx: &'a mut RequestCtx,
        _chunk: &'a mut Bytes,
        _end_of_stream: bool,
    ) -> HookResult<'a, StreamFlow> {
        if self.panic_instead {
            panic!("simulated guardrail panic");
        }
        HookResult::Ready(StreamFlow::Abort("dlp_secret_detected".to_owned()))
    }

    fn on_complete<'a>(
        &'a self,
        _ctx: &'a RequestCtx,
        summary: &'a RequestSummary,
    ) -> HookResult<'a, ()> {
        if summary.aborted_mid_stream {
            self.saw_aborted.store(true, Ordering::SeqCst);
        }
        HookResult::Ready(())
    }
}

#[tokio::test]
async fn inspect_response_body_fails_closed_on_stream_abort_and_panic() {
    let upstream = spawn_http1_upstream(|_req| async move {
        Response::builder()
            .status(StatusCode::OK)
            .body(ShuntBody::full(Bytes::from_static(b"TOP-SECRET-PII-LEAK")))
            .unwrap()
    })
    .await;

    for (panic_instead, expected_status) in [
        (false, StatusCode::BAD_GATEWAY),
        (true, StatusCode::INTERNAL_SERVER_ERROR),
    ] {
        let saw_aborted = Arc::new(AtomicBool::new(false));
        let registry = RuntimeRegistry::new();
        let snap = SnapshotBuilder::new(1)
            .upstream(UpstreamConfig::new(
                "be",
                vec![format!("http://{upstream}")],
            ))
            .route(
                RouteSpec::new("r", RouteMatch::prefix("/"), "be")
                    .with_plugin(Arc::new(InspectTriggerPlugin))
                    .with_plugin(Arc::new(StreamFailPlugin {
                        panic_instead,
                        saw_aborted: Arc::clone(&saw_aborted),
                    })),
            )
            .build(&registry, true)
            .unwrap();

        let gw = GatewayServer::new(snap)
            .bind("127.0.0.1:0".parse().unwrap())
            .await
            .unwrap();

        let client = Client::builder(TokioExecutor::new()).build_http::<Full<Bytes>>();
        let req = Request::builder()
            .uri(format!("http://{}/secret", gw.local_addr()))
            .body(Full::new(Bytes::new()))
            .unwrap();
        let resp = client.request(req).await.unwrap();
        assert_eq!(resp.status(), expected_status);
        let body = resp.into_body().collect().await.unwrap().to_bytes();
        assert!(
            !String::from_utf8_lossy(&body).contains("TOP-SECRET-PII-LEAK"),
            "blocked content leaked!"
        );

        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(
            saw_aborted.load(Ordering::SeqCst),
            "on_complete must observe aborted_mid_stream = true"
        );
        assert!(gw.shutdown().await);
    }
}

// -----------------------------------------------------------------------------
// §2 H-3: Strict path validation, allow_raw_path opt-in, strip_prefix & target URI
// -----------------------------------------------------------------------------

#[tokio::test]
async fn strict_path_validation_rejects_traversal_and_supports_raw_opt_in() {
    let hits = Arc::new(AtomicUsize::new(0));
    let hits_cb = Arc::clone(&hits);
    let upstream = spawn_http1_upstream(move |req| {
        hits_cb.fetch_add(1, Ordering::SeqCst);
        let path = req.uri().path().to_owned();
        async move {
            Response::builder()
                .status(StatusCode::OK)
                .body(ShuntBody::full(Bytes::from(path)))
                .unwrap()
        }
    })
    .await;

    let registry = RuntimeRegistry::new();
    let snap = SnapshotBuilder::new(1)
        .upstream(UpstreamConfig::new(
            "be",
            vec![format!("http://{upstream}")],
        ))
        .route(RouteSpec::new("strict", RouteMatch::prefix("/api"), "be"))
        .route(RouteSpec::new("raw", RouteMatch::prefix("/objects"), "be").allow_raw_path(true))
        .build(&registry, true)
        .unwrap();

    let gw = GatewayServer::new(snap)
        .bind("127.0.0.1:0".parse().unwrap())
        .await
        .unwrap();

    // Hostile paths on strict route must return 400 and never touch upstream.
    let hostile_paths = [
        "/api/../admin",
        "/api/..",
        "/api/./v1",
        "//api/v1",
        "/api//v1",
        "/api/%2e%2e/admin",
        "/api/%2E/admin",
        "/api/foo%2fbar",
        "/api/foo%2Fbar",
        "/api/foo%5cbar",
        "/api/foo%00bar",
        "/api/%61dmin",
        "/api/%2",
    ];
    for p in hostile_paths {
        let raw = format!("GET {p} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n");
        let resp = send_raw_http(gw.local_addr(), &raw).await;
        assert!(
            resp.starts_with("HTTP/1.1 400"),
            "expected 400 for `{p}`, got: {resp}"
        );
    }
    assert_eq!(hits.load(Ordering::SeqCst), 0);

    // Valid normal paths succeed on strict route.
    for p in [
        "/api/v1/hello%20world",
        "/api/v1/file.txt",
        "/api/v1/..hidden",
        "/api/v1/",
    ] {
        let raw = format!("GET {p} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n");
        let resp = send_raw_http(gw.local_addr(), &raw).await;
        assert!(
            resp.starts_with("HTTP/1.1 200"),
            "expected 200 for `{p}`, got: {resp}"
        );
    }

    // Opt-in `allow_raw_path` route allows encoded slashes (`%2F`), but still blocks traversal,
    // double slashes, backslashes, encoded control bytes, malformed `%`, and encoded unreserved chars.
    let raw_ok = send_raw_http(
        gw.local_addr(),
        "GET /objects/group%2Frepo HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert!(raw_ok.starts_with("HTTP/1.1 200"), "got: {raw_ok}");

    for raw_bad in [
        "/objects/bad%00id",
        "/objects/bad%01id",
        "/objects/x/../admin",
        "/objects//admin",
        "/objects/%2e%2e/admin",
        "/objects/foo%5cbar",
        "/objects/%61dmin",
        "/objects/%2",
    ] {
        let req_str =
            format!("GET {raw_bad} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n");
        let resp = send_raw_http(gw.local_addr(), &req_str).await;
        assert!(
            resp.starts_with("HTTP/1.1 400"),
            "expected 400 on allow_raw_path for `{raw_bad}`, got: {resp}"
        );
    }

    assert!(gw.shutdown().await);
}

#[test]
fn strip_uri_prefix_and_target_uri_fail_closed_on_double_slash_escape() {
    let evil: Uri = "/api//evil.example/admin".parse().unwrap();
    assert!(strip_uri_prefix(&evil, "/api").is_err());

    let base: Uri = "http://backend.internal:8080".parse().unwrap();
    let bad_req: Uri = "//evil.example/steal".parse().unwrap();
    assert!(build_target_uri(&base, &bad_req).is_err());

    assert!(validate_request_path("/api/v1").is_ok());
    assert!(validate_request_path("*").is_ok());
    assert!(validate_request_path("/a\\b").is_err());
    assert!(validate_request_path("/a/%2e%2e/b").is_err());
}

// -----------------------------------------------------------------------------
// §2 H-4: Slowloris header timeout, body timeout, TLS timeout, max_connections,
//         and InspectResponseBody idle timeout
// -----------------------------------------------------------------------------

struct BufferRequestBodyPlugin;

impl HttpPlugin for BufferRequestBodyPlugin {
    fn name(&self) -> &str {
        "buffer-body"
    }

    fn hook_mask(&self) -> HookMask {
        HookMask::REQUEST_BODY_BUFFERED
    }
}

#[tokio::test]
async fn slowloris_header_body_tls_inspect_timeouts_and_max_connections() {
    let upstream = spawn_http1_upstream(|req| async move {
        if req.uri().path() == "/stall-response" {
            // Emit headers immediately, then stall body chunks beyond idle_chunk_timeout.
            let (tx, rx) = tokio::sync::mpsc::channel(2);
            tokio::spawn(async move {
                let _ = tx
                    .send(Ok(http_body::Frame::data(Bytes::from_static(b"part1"))))
                    .await;
                tokio::time::sleep(Duration::from_secs(5)).await;
                drop(tx);
            });
            return Response::builder()
                .status(StatusCode::OK)
                .body(ShuntBody::channel(rx))
                .unwrap();
        }
        Response::builder()
            .status(StatusCode::OK)
            .body(ShuntBody::full(Bytes::from_static(b"ok")))
            .unwrap()
    })
    .await;

    let registry = RuntimeRegistry::new();
    let snap = SnapshotBuilder::new(1)
        .upstream(UpstreamConfig::new(
            "be",
            vec![format!("http://{upstream}")],
        ))
        .route(
            RouteSpec::new("buf", RouteMatch::prefix("/buf"), "be")
                .with_plugin(Arc::new(BufferRequestBodyPlugin)),
        )
        .route(
            RouteSpec::new("stall", RouteMatch::exact("/stall-response"), "be")
                .with_plugin(Arc::new(InspectTriggerPlugin))
                .with_timeouts(TimeoutConfig {
                    response_headers_timeout: Some(Duration::from_secs(2)),
                    idle_chunk_timeout: Some(Duration::from_millis(150)),
                }),
        )
        .route(RouteSpec::new("ok", RouteMatch::prefix("/"), "be"))
        .build(&registry, true)
        .unwrap();

    let limits = ServerLimits {
        max_connections: 2,
        header_read_timeout: Duration::from_millis(150),
        request_body_timeout: Some(Duration::from_millis(150)),
        tls_handshake_timeout: Duration::from_millis(150),
        ..ServerLimits::default()
    };

    let gw = GatewayServer::new(Arc::clone(&snap))
        .with_limits(limits)
        .with_drain_timeout(Duration::from_secs(2))
        .bind("127.0.0.1:0".parse().unwrap())
        .await
        .unwrap();

    // 1) Slowloris partial HTTP/1.1 headers -> closed promptly by Hyper TokioTimer.
    {
        let mut slow = TcpStream::connect(gw.local_addr()).await.unwrap();
        slow.write_all(b"GET /ok HTTP/1.1\r\nHost: loc")
            .await
            .unwrap();
        let mut buf = [0u8; 64];
        let res = tokio::time::timeout(Duration::from_secs(2), slow.read(&mut buf))
            .await
            .expect("header_read_timeout did not fire");
        assert!(
            matches!(res, Ok(0) | Err(_)),
            "expected EOF/reset, got {res:?}"
        );
    }

    // 1b) 0-byte idle connection (AutoServerBuilder::ReadVersion) -> closed promptly.
    {
        let mut zero_bytes = TcpStream::connect(gw.local_addr()).await.unwrap();
        let mut buf = [0u8; 64];
        let res = tokio::time::timeout(Duration::from_secs(2), zero_bytes.read(&mut buf))
            .await
            .expect("0-byte initial protocol detection timeout did not fire");
        assert!(
            matches!(res, Ok(0) | Err(_)),
            "expected EOF/reset on 0-byte conn, got {res:?}"
        );
    }

    // 1c) Partial HTTP/2 preface (`PRI * `) -> closed promptly instead of stalling ReadVersion.
    {
        let mut partial_h2 = TcpStream::connect(gw.local_addr()).await.unwrap();
        partial_h2.write_all(b"PRI * ").await.unwrap();
        let mut buf = [0u8; 64];
        let res = tokio::time::timeout(Duration::from_secs(2), partial_h2.read(&mut buf))
            .await
            .expect("partial H2 preface initial protocol detection timeout did not fire");
        assert!(
            matches!(res, Ok(0) | Err(_)),
            "expected EOF/reset on partial H2 preface, got {res:?}"
        );
    }

    // 2) Slow-POST buffered body -> 408 Request Timeout.
    {
        let mut slow_post = TcpStream::connect(gw.local_addr()).await.unwrap();
        slow_post
            .write_all(
                b"POST /buf HTTP/1.1\r\nHost: localhost\r\nContent-Length: 100\r\nConnection: close\r\n\r\n12345",
            )
            .await
            .unwrap();
        let mut resp_buf = Vec::new();
        tokio::time::timeout(Duration::from_secs(2), slow_post.read_to_end(&mut resp_buf))
            .await
            .expect("request_body_timeout did not fire")
            .unwrap();
        let resp_str = String::from_utf8_lossy(&resp_buf);
        assert!(resp_str.starts_with("HTTP/1.1 408"), "got: {resp_str}");
    }

    // 3) InspectResponseBody idle chunk timeout -> 504 Gateway Timeout.
    {
        let resp = send_raw_http(
            gw.local_addr(),
            "GET /stall-response HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
        )
        .await;
        assert!(resp.starts_with("HTTP/1.1 504"), "got: {resp}");
    }

    // 4) max_connections = 2 rejects 3rd concurrent connection immediately.
    {
        let c1 = TcpStream::connect(gw.local_addr()).await.unwrap();
        let c2 = TcpStream::connect(gw.local_addr()).await.unwrap();
        // Wait briefly for both connections to be accepted.
        tokio::time::sleep(Duration::from_millis(50)).await;
        let mut c3 = TcpStream::connect(gw.local_addr()).await.unwrap();
        let mut buf = [0u8; 16];
        let r = tokio::time::timeout(Duration::from_millis(500), c3.read(&mut buf))
            .await
            .expect("3rd connection should be rejected promptly");
        assert!(
            matches!(r, Ok(0) | Err(_)),
            "expected close on 3rd conn, got {r:?}"
        );
        drop(c1);
        drop(c2);
    }

    assert!(gw.shutdown().await);

    // 5) TLS handshake timeout closes stalled TLS TCP connection cleanly.
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()]).unwrap();
    let ck = load_certified_key_pem(
        cert.cert.pem().as_bytes(),
        cert.signing_key.serialize_pem().as_bytes(),
    )
    .unwrap();
    let resolver = Arc::new(DynamicCertResolver::new(CertStore::new().with_default(ck)));
    let tls_gw = GatewayServer::new(snap)
        .with_tls(TlsListenerConfig::new(resolver))
        .with_limits(limits)
        .with_drain_timeout(Duration::from_secs(1))
        .bind("127.0.0.1:0".parse().unwrap())
        .await
        .unwrap();

    let mut stalled_tls = TcpStream::connect(tls_gw.local_addr()).await.unwrap();
    let mut buf = [0u8; 16];
    let r = tokio::time::timeout(Duration::from_secs(2), stalled_tls.read(&mut buf))
        .await
        .expect("tls_handshake_timeout did not fire");
    assert!(
        matches!(r, Ok(0) | Err(_)),
        "expected close on stalled TLS, got {r:?}"
    );
    drop(stalled_tls);
    assert!(tls_gw.shutdown().await);
}

// -----------------------------------------------------------------------------
// §2 H-5: WebSockets disabled by default
// -----------------------------------------------------------------------------

#[test]
fn websockets_disabled_by_default_on_route_spec() {
    let spec = RouteSpec::new("r", RouteMatch::prefix("/ws"), "be");
    assert!(!spec.allow_websockets);
    assert!(!spec.allow_raw_path);
}

// -----------------------------------------------------------------------------
// §3 H-8: Malformed/conflicting Content-Length & chunked early-response body limit
// -----------------------------------------------------------------------------

struct CustomBodyLimitPlugin;

impl HttpPlugin for CustomBodyLimitPlugin {
    fn name(&self) -> &str {
        "custom-body-limit"
    }

    fn hook_mask(&self) -> HookMask {
        HookMask::EMPTY
    }

    fn max_request_body_bytes(&self) -> Option<usize> {
        Some(16)
    }

    fn max_request_body_status_code(&self) -> Option<StatusCode> {
        Some(StatusCode::UNPROCESSABLE_ENTITY)
    }
}

#[tokio::test]
async fn content_length_validation_and_chunked_early_response_limit() {
    // Upstream replies 200 OK immediately without reading request body.
    let upstream = spawn_http1_upstream(|_req| async move {
        Response::builder()
            .status(StatusCode::OK)
            .body(ShuntBody::full(Bytes::from_static(b"early-ok")))
            .unwrap()
    })
    .await;

    let registry = RuntimeRegistry::new();
    let snap = SnapshotBuilder::new(1)
        .upstream(UpstreamConfig::new(
            "be",
            vec![format!("http://{upstream}")],
        ))
        .route(
            RouteSpec::new("upload", RouteMatch::prefix("/upload"), "be")
                .with_plugin(Arc::new(CustomBodyLimitPlugin)),
        )
        .build(&registry, true)
        .unwrap();

    let gw = GatewayServer::new(snap)
        .bind("127.0.0.1:0".parse().unwrap())
        .await
        .unwrap();

    // Conflicting Content-Length headers -> 400 Bad Request.
    let resp_conflict = send_raw_http(
        gw.local_addr(),
        "POST /upload HTTP/1.1\r\nHost: localhost\r\nContent-Length: 4\r\nContent-Length: 8\r\nConnection: close\r\n\r\n1234",
    )
    .await;
    assert!(
        resp_conflict.starts_with("HTTP/1.1 400"),
        "expected 400 for conflicting Content-Length, got: {resp_conflict}"
    );

    // Oversized Content-Length honors plugin custom 422 status.
    let resp_cl = send_raw_http(
        gw.local_addr(),
        "POST /upload HTTP/1.1\r\nHost: localhost\r\nContent-Length: 32\r\nConnection: close\r\n\r\n0123456789abcdef0123456789abcdef",
    )
    .await;
    assert!(
        resp_cl.starts_with("HTTP/1.1 422"),
        "expected custom 422 for oversized Content-Length, got: {resp_cl}"
    );

    // Oversized chunked body rejected with 422 even though upstream tries to reply 200 immediately.
    let resp_chunked = send_raw_http(
        gw.local_addr(),
        "POST /upload HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n20\r\n0123456789abcdef0123456789abcdef\r\n0\r\n\r\n",
    )
    .await;
    assert!(
        resp_chunked.starts_with("HTTP/1.1 422"),
        "expected 422 on chunked overflow even with early upstream response, got: {resp_chunked}"
    );

    assert!(gw.shutdown().await);
}

// -----------------------------------------------------------------------------
// §3 H-6 / E-M8: X.509 DN RFC 4514 escaping prevents CN attribute spoofing
// -----------------------------------------------------------------------------

#[test]
fn x509_dn_escapes_commas_per_rfc4514() {
    let mut params = rcgen::CertificateParams::new(vec!["svc.internal".to_owned()]).unwrap();
    let mut dn = rcgen::DistinguishedName::new();
    dn.push(rcgen::DnType::OrganizationName, "Evil,CN=admin");
    dn.push(rcgen::DnType::CommonName, "regular-user");
    params.distinguished_name = dn;
    let kp = rcgen::KeyPair::generate().unwrap();
    let cert = params.self_signed(&kp).unwrap();

    let info = parse_client_cert_info(cert.der().as_ref()).expect("parse cert");
    assert_eq!(info.subject_cn.as_deref(), Some("regular-user"));
    assert!(
        info.subject_dn.contains(r"O=Evil\,CN=admin"),
        "expected RFC 4514 escaped comma in subject_dn, got: {}",
        info.subject_dn
    );
}

#[test]
fn strip_hop_by_hop_preserves_te_trailers_with_connection_te() {
    let mut headers = http::HeaderMap::new();
    headers.insert(
        http::header::CONNECTION,
        http::HeaderValue::from_static("TE, keep-alive"),
    );
    headers.insert(http::header::TE, http::HeaderValue::from_static("trailers"));
    shunt_engine::pipeline::strip_hop_by_hop_headers(&mut headers);
    assert!(!headers.contains_key(http::header::CONNECTION));
    assert_eq!(headers.get(http::header::TE).unwrap(), "trailers");
}

struct TighterDefaultStatusBodyLimitPlugin;

impl HttpPlugin for TighterDefaultStatusBodyLimitPlugin {
    fn name(&self) -> &str {
        "tighter-default-status"
    }

    fn hook_mask(&self) -> HookMask {
        HookMask::EMPTY
    }

    fn max_request_body_bytes(&self) -> Option<usize> {
        Some(8)
    }
}

#[test]
fn snapshot_builder_tighter_body_limit_resets_default_413_status() {
    let registry = RuntimeRegistry::new();
    let snap = SnapshotBuilder::new(1)
        .upstream(UpstreamConfig::new(
            "be",
            vec!["http://127.0.0.1:9999".to_owned()],
        ))
        .route(
            RouteSpec::new("r", RouteMatch::prefix("/"), "be")
                .with_plugin(Arc::new(CustomBodyLimitPlugin))
                .with_plugin(Arc::new(TighterDefaultStatusBodyLimitPlugin)),
        )
        .build(&registry, true)
        .unwrap();
    assert_eq!(snap.routes[0].max_body_bytes, 8);
    assert_eq!(
        snap.routes[0].max_body_status,
        StatusCode::PAYLOAD_TOO_LARGE
    );
}
