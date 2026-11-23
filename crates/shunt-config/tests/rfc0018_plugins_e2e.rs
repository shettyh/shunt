use std::convert::Infallible;
use std::io::Read as _;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use bytes::Bytes;
use http::{HeaderValue, Method, Request, Response, StatusCode, header};
use http_body_util::{BodyExt, Full};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::client::legacy::Client;
use hyper_util::rt::{TokioExecutor, TokioIo};
use ring::hmac;
use ring::rand::SystemRandom;
use ring::signature::{ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair, Ed25519KeyPair, KeyPair};
use serde_json::{Value, json};
use shunt_config::{ConfigProvider, InlineConfigProvider, SnapshotCompiler};
use shunt_engine::{GatewayServer, RuntimeRegistry};
use shunt_plugin_sdk::{ManualClock, PluginRegistry};
use shunt_plugins::{PrometheusMetrics, base64url_encode, register_builtin_plugins};
use tokio::net::TcpListener;

async fn spawn_http_mock<F, Fut>(handler: F) -> (SocketAddr, tokio::task::JoinHandle<()>)
where
    F: Fn(Request<hyper::body::Incoming>) -> Fut + Send + Sync + 'static,
    Fut: std::future::Future<Output = Response<Full<Bytes>>> + Send + 'static,
{
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handler = Arc::new(handler);
    let task = tokio::spawn(async move {
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
                    .serve_connection(TokioIo::new(tcp), svc)
                    .await;
            });
        }
    });
    (addr, task)
}

fn sign_hs256(header_json: &Value, claims_json: &Value, secret: &[u8]) -> String {
    let h = base64url_encode(&serde_json::to_vec(header_json).unwrap());
    let p = base64url_encode(&serde_json::to_vec(claims_json).unwrap());
    let signing_input = format!("{h}.{p}");
    let key = hmac::Key::new(hmac::HMAC_SHA256, secret);
    let tag = hmac::sign(&key, signing_input.as_bytes());
    format!("{signing_input}.{}", base64url_encode(tag.as_ref()))
}

fn sign_ed25519(header_json: &Value, claims_json: &Value, kp: &Ed25519KeyPair) -> String {
    let h = base64url_encode(&serde_json::to_vec(header_json).unwrap());
    let p = base64url_encode(&serde_json::to_vec(claims_json).unwrap());
    let signing_input = format!("{h}.{p}");
    let sig = kp.sign(signing_input.as_bytes());
    format!("{signing_input}.{}", base64url_encode(sig.as_ref()))
}

fn sign_es256(header_json: &Value, claims_json: &Value, kp: &EcdsaKeyPair) -> String {
    let h = base64url_encode(&serde_json::to_vec(header_json).unwrap());
    let p = base64url_encode(&serde_json::to_vec(claims_json).unwrap());
    let signing_input = format!("{h}.{p}");
    let rng = SystemRandom::new();
    let sig = kp.sign(&rng, signing_input.as_bytes()).unwrap();
    format!("{signing_input}.{}", base64url_encode(sig.as_ref()))
}

async fn start_gateway_from_toml(
    toml_src: &str,
    clock: Arc<ManualClock>,
) -> shunt_engine::ServerHandle {
    let mut reg = PluginRegistry::new();
    let metrics = Arc::new(PrometheusMetrics::new());
    register_builtin_plugins(&mut reg, metrics);
    let runtime = Arc::new(RuntimeRegistry::with_clock(clock));
    let compiler = SnapshotCompiler::new(Arc::new(reg), runtime);
    let provider = InlineConfigProvider::from_toml("test.toml", toml_src);
    let loaded = provider.load().expect("config parse");
    let bundle = compiler.compile(&loaded).expect("config compile");
    GatewayServer::new(bundle.snapshot)
        .with_drain_timeout(Duration::from_secs(2))
        .bind("127.0.0.1:0".parse().unwrap())
        .await
        .expect("bind gateway")
}

#[tokio::test]
async fn jwt_auth_oidc_discovery_jwks_rotation_claims_and_antidos() {
    let rng = SystemRandom::new();

    // Generate Ed25519 key (kid = "ed-1") and EC P-256 key (kid = "ec-2")
    let ed_pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
    let ed_kp = Ed25519KeyPair::from_pkcs8(ed_pkcs8.as_ref()).unwrap();
    let ed_pub_b64 = base64url_encode(ed_kp.public_key().as_ref());

    let ec_pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng).unwrap();
    let ec_kp = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, ec_pkcs8.as_ref(), &rng)
        .unwrap();
    let ec_pub = ec_kp.public_key().as_ref(); // 0x04 || x(32) || y(32)
    assert_eq!(ec_pub.len(), 65);
    let ec_x = base64url_encode(&ec_pub[1..33]);
    let ec_y = base64url_encode(&ec_pub[33..65]);

    let jwks_version = Arc::new(AtomicUsize::new(1));
    let jwks_hits = Arc::new(AtomicUsize::new(0));
    let disc_hits = Arc::new(AtomicUsize::new(0));

    let jwks_ver_clone = Arc::clone(&jwks_version);
    let jwks_hits_clone = Arc::clone(&jwks_hits);
    let disc_hits_clone = Arc::clone(&disc_hits);

    let (idp_addr, idp_task) = spawn_http_mock(move |req| {
        let ver = jwks_ver_clone.load(Ordering::SeqCst);
        let j_hits = Arc::clone(&jwks_hits_clone);
        let d_hits = Arc::clone(&disc_hits_clone);
        let ed_x = ed_pub_b64.clone();
        let ex = ec_x.clone();
        let ey = ec_y.clone();
        async move {
            let path = req.uri().path();
            let host = req
                .headers()
                .get(header::HOST)
                .and_then(|v| v.to_str().ok())
                .unwrap_or("127.0.0.1");
            if path == "/.well-known/openid-configuration" {
                d_hits.fetch_add(1, Ordering::SeqCst);
                let body = json!({
                    "issuer": format!("http://{host}"),
                    "jwks_uri": format!("http://{host}/jwks.json")
                });
                Response::builder()
                    .status(StatusCode::OK)
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Full::new(Bytes::from(body.to_string())))
                    .unwrap()
            } else if path == "/jwks.json" {
                j_hits.fetch_add(1, Ordering::SeqCst);
                let keys = if ver == 1 {
                    json!([{
                        "kty": "OKP", "crv": "Ed25519", "kid": "ed-1", "use": "sig", "x": ed_x
                    }])
                } else {
                    json!([
                        {"kty": "OKP", "crv": "Ed25519", "kid": "ed-1", "use": "sig", "x": ed_x},
                        {"kty": "EC", "crv": "P-256", "kid": "ec-2", "use": "sig", "x": ex, "y": ey}
                    ])
                };
                Response::builder()
                    .status(StatusCode::OK)
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Full::new(Bytes::from(json!({"keys": keys}).to_string())))
                    .unwrap()
            } else {
                Response::builder()
                    .status(StatusCode::NOT_FOUND)
                    .body(Full::new(Bytes::new()))
                    .unwrap()
            }
        }
    })
    .await;

    let (backend_addr, backend_task) = spawn_http_mock(|req| async move {
        let user = req
            .headers()
            .get("x-user-id")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_owned();
        let org = req
            .headers()
            .get("x-org-id")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_owned();
        let auth_present = req.headers().contains_key(header::AUTHORIZATION);
        Response::builder()
            .status(StatusCode::OK)
            .header(header::CONTENT_TYPE, "application/json")
            .body(Full::new(Bytes::from(
                json!({"user": user, "org": org, "auth_present": auth_present}).to_string(),
            )))
            .unwrap()
    })
    .await;

    let clock = ManualClock::shared();
    clock.set_unix_timestamp_secs(1_700_000_000);

    let toml = format!(
        r#"
[server]
listen = "127.0.0.1:0"

[admin]
enabled = false

[[upstreams]]
name = "api"
endpoints = ["http://{backend_addr}"]

[[routes]]
id = "protected"
path_prefix = "/api"
upstream = "api"

[[routes.plugins]]
name = "jwt-auth"
[routes.plugins.config]
oidc_discovery_url = "http://{idp_addr}/.well-known/openid-configuration"
algorithms = ["EdDSA", "ES256"]
issuer = "http://{idp_addr}"
audience = "shunt-api"
required_scopes = ["read:items"]
required_claims = {{ "org.tier" = "pro" }}
forward_claims = {{ "sub" = "x-user-id", "org.id" = "x-org-id" }}
strip_header = true
clock_skew_secs = 30
jwks_cache_ttl_secs = 300
jwks_min_refresh_secs = 10
"#
    );

    let gw = start_gateway_from_toml(&toml, Arc::clone(&clock)).await;
    let client = Client::builder(TokioExecutor::new()).build_http::<Full<Bytes>>();

    // 1. Missing token -> 401
    let r = client
        .request(
            Request::builder()
                .uri(format!("http://{}/api/items", gw.local_addr()))
                .header("x-user-id", "spoofed-attacker")
                .body(Full::new(Bytes::new()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::UNAUTHORIZED);

    // 2. Valid Ed25519 JWT -> OIDC discovery + JWKS fetch + forwarded claims + stripped Authorization
    let valid_ed = sign_ed25519(
        &json!({"alg": "EdDSA", "kid": "ed-1", "typ": "JWT"}),
        &json!({
            "sub": "user-42",
            "iss": format!("http://{idp_addr}"),
            "aud": ["other", "shunt-api"],
            "exp": 1_700_000_600u64,
            "scope": "read:items write:items",
            "org": {"id": "org-9", "tier": "pro"}
        }),
        &ed_kp,
    );
    let r = client
        .request(
            Request::builder()
                .uri(format!("http://{}/api/items", gw.local_addr()))
                .header(header::AUTHORIZATION, format!("Bearer {valid_ed}"))
                .header("x-user-id", "spoofed")
                .body(Full::new(Bytes::new()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK);
    let body: Value =
        serde_json::from_slice(&r.into_body().collect().await.unwrap().to_bytes()).unwrap();
    assert_eq!(body["user"], "user-42");
    assert_eq!(body["org"], "org-9");
    assert_eq!(body["auth_present"], false);
    assert_eq!(disc_hits.load(Ordering::SeqCst), 1);
    assert_eq!(jwks_hits.load(Ordering::SeqCst), 1);

    // 3. Second request hits warm cache synchronously (ZERO additional JWKS calls!)
    let r = client
        .request(
            Request::builder()
                .uri(format!("http://{}/api/items", gw.local_addr()))
                .header(header::AUTHORIZATION, format!("Bearer {valid_ed}"))
                .body(Full::new(Bytes::new()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK);
    assert_eq!(jwks_hits.load(Ordering::SeqCst), 1);

    // 4. Random unknown kid within anti-DoS min_refresh_secs does NOT trigger JWKS fetch
    let bad_kid = sign_ed25519(
        &json!({"alg": "EdDSA", "kid": "attacker-random-kid"}),
        &json!({
            "sub": "u", "iss": format!("http://{idp_addr}"), "aud": "shunt-api",
            "exp": 1_700_000_600u64, "scope": "read:items", "org": {"id": "o", "tier": "pro"}
        }),
        &ed_kp,
    );
    let r = client
        .request(
            Request::builder()
                .uri(format!("http://{}/api/items", gw.local_addr()))
                .header(header::AUTHORIZATION, format!("Bearer {bad_kid}"))
                .body(Full::new(Bytes::new()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(jwks_hits.load(Ordering::SeqCst), 1);

    // 5. Key rotation: IdP publishes ES256 key `ec-2`; advance clock past 10s cooldown -> auto-refresh!
    jwks_version.store(2, Ordering::SeqCst);
    clock.advance(Duration::from_secs(12));
    let valid_ec = sign_es256(
        &json!({"alg": "ES256", "kid": "ec-2"}),
        &json!({
            "sub": "user-ec",
            "iss": format!("http://{idp_addr}"),
            "aud": "shunt-api",
            "exp": 1_700_000_600u64,
            "scp": ["read:items"],
            "org": {"id": "org-ec", "tier": "pro"}
        }),
        &ec_kp,
    );
    let r = client
        .request(
            Request::builder()
                .uri(format!("http://{}/api/items", gw.local_addr()))
                .header(header::AUTHORIZATION, format!("Bearer {valid_ec}"))
                .body(Full::new(Bytes::new()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK);
    let body: Value =
        serde_json::from_slice(&r.into_body().collect().await.unwrap().to_bytes()).unwrap();
    assert_eq!(body["user"], "user-ec");
    assert_eq!(jwks_hits.load(Ordering::SeqCst), 2);

    // 6. Insufficient scope -> 403 Forbidden
    let no_scope = sign_es256(
        &json!({"alg": "ES256", "kid": "ec-2"}),
        &json!({
            "sub": "user-ec",
            "iss": format!("http://{idp_addr}"),
            "aud": "shunt-api",
            "exp": 1_700_000_600u64,
            "scope": "other:scope",
            "org": {"id": "org-ec", "tier": "pro"}
        }),
        &ec_kp,
    );
    let r = client
        .request(
            Request::builder()
                .uri(format!("http://{}/api/items", gw.local_addr()))
                .header(header::AUTHORIZATION, format!("Bearer {no_scope}"))
                .body(Full::new(Bytes::new()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::FORBIDDEN);

    // 7. Token expiration enforced deterministically via ManualClock (+ 30s skew)
    clock.advance(Duration::from_secs(700));
    let r = client
        .request(
            Request::builder()
                .uri(format!("http://{}/api/items", gw.local_addr()))
                .header(header::AUTHORIZATION, format!("Bearer {valid_ec}"))
                .body(Full::new(Bytes::new()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::UNAUTHORIZED);

    gw.shutdown().await;
    idp_task.abort();
    backend_task.abort();
}

#[tokio::test]
async fn jwt_hs256_ip_filter_compression_body_limit_and_redirect_e2e() {
    let payload_big = "the quick brown fox jumps over the lazy dog. ".repeat(80);
    let payload_big_clone = payload_big.clone();

    let (backend_addr, backend_task) = spawn_http_mock(move |req| {
        let big = payload_big_clone.clone();
        async move {
            match req.uri().path() {
                "/json" => Response::builder()
                    .status(StatusCode::OK)
                    .header(header::CONTENT_TYPE, "application/json")
                    .header(header::ETAG, "\"v1\"")
                    .header(header::CONTENT_LENGTH, big.len().to_string())
                    .body(Full::new(Bytes::from(big)))
                    .unwrap(),
                "/sse" => Response::builder()
                    .status(StatusCode::OK)
                    .header(header::CONTENT_TYPE, "text/event-stream")
                    .body(Full::new(Bytes::from(format!("data: {big}\n\n"))))
                    .unwrap(),
                "/tiny" => Response::builder()
                    .status(StatusCode::OK)
                    .header(header::CONTENT_TYPE, "text/plain")
                    .header(header::CONTENT_LENGTH, "2")
                    .body(Full::new(Bytes::from_static(b"ok")))
                    .unwrap(),
                "/notransform" => Response::builder()
                    .status(StatusCode::OK)
                    .header(header::CONTENT_TYPE, "text/plain")
                    .header(header::CACHE_CONTROL, "public, no-transform")
                    .body(Full::new(Bytes::from(big)))
                    .unwrap(),
                _ => Response::builder()
                    .status(StatusCode::OK)
                    .header(header::CONTENT_TYPE, "text/plain")
                    .body(Full::new(Bytes::from_static(b"ok")))
                    .unwrap(),
            }
        }
    })
    .await;

    let clock = ManualClock::shared();
    clock.set_unix_timestamp_secs(1_700_000_000);

    let toml = format!(
        r#"
[server]
listen = "127.0.0.1:0"

[admin]
enabled = false

[[upstreams]]
name = "api"
endpoints = ["http://{backend_addr}"]

[[routes]]
id = "redirect_old"
path_prefix = "/old"
upstream = "api"

[[routes.plugins]]
name = "redirect"
[routes.plugins.config]
status_code = 301
scheme = "https"
hostname = "api.example.com"
path_match_prefix = "/old"
path_replace_prefix = "/v2"

[[routes]]
id = "secure_api"
path_prefix = "/"
upstream = "api"

[[routes.plugins]]
name = "ip-filter"
[routes.plugins.config]
allow = ["127.0.0.0/8", "10.0.0.0/8"]
deny = ["10.99.0.0/16"]
trusted_proxies = ["127.0.0.1/32"]
use_forwarded_for = true

[[routes.plugins]]
name = "jwt-auth"
[routes.plugins.config]
algorithms = ["HS256"]
keys = [{{ kid = "hs1", secret = "super-secret-hmac-key" }}]

[[routes.plugins]]
name = "body-limit"
[routes.plugins.config]
max_bytes = 32

[[routes.plugins]]
name = "compression"
[routes.plugins.config]
encodings = ["zstd", "br", "gzip"]
min_size_bytes = 64
level = 3
"#
    );

    let gw = start_gateway_from_toml(&toml, Arc::clone(&clock)).await;
    let client = Client::builder(TokioExecutor::new()).build_http::<Full<Bytes>>();

    // 1. Redirect route
    let r = client
        .request(
            Request::builder()
                .uri(format!("http://{}/old/users?page=2", gw.local_addr()))
                .body(Full::new(Bytes::new()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::MOVED_PERMANENTLY);
    assert_eq!(
        r.headers().get(header::LOCATION).unwrap(),
        "https://api.example.com/v2/users?page=2"
    );

    // 2. IP filter rejects denied XFF IP via trusted proxy 127.0.0.1
    let r = client
        .request(
            Request::builder()
                .uri(format!("http://{}/tiny", gw.local_addr()))
                .header("x-forwarded-for", "10.99.5.4")
                .body(Full::new(Bytes::new()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::FORBIDDEN);

    let valid_hs = sign_hs256(
        &json!({"alg": "HS256", "kid": "hs1"}),
        &json!({"sub": "alice", "exp": 1_700_000_999u64}),
        b"super-secret-hmac-key",
    );

    // 3. Body limit rejects > 32 bytes synchronously with 413
    let r = client
        .request(
            Request::builder()
                .method(Method::POST)
                .uri(format!("http://{}/tiny", gw.local_addr()))
                .header(header::AUTHORIZATION, format!("Bearer {valid_hs}"))
                .body(Full::new(Bytes::from(vec![b'a'; 64])))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::PAYLOAD_TOO_LARGE);

    // 4. Compression: gzip, brotli, zstd round-trips + ETag weakening + Vary
    for (accept, expected_enc) in [
        ("gzip", "gzip"),
        ("br, gzip", "br"),
        ("zstd, br, gzip", "zstd"),
    ] {
        let r = client
            .request(
                Request::builder()
                    .uri(format!("http://{}/json", gw.local_addr()))
                    .header(header::AUTHORIZATION, format!("Bearer {valid_hs}"))
                    .header(header::ACCEPT_ENCODING, accept)
                    .body(Full::new(Bytes::new()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(r.status(), StatusCode::OK);
        assert_eq!(
            r.headers().get(header::CONTENT_ENCODING).unwrap(),
            expected_enc
        );
        assert_eq!(r.headers().get(header::ETAG).unwrap(), "W/\"v1\"");
        assert!(
            r.headers()
                .get(header::VARY)
                .and_then(|v| v.to_str().ok())
                .unwrap_or("")
                .to_ascii_lowercase()
                .contains("accept-encoding")
        );
        let compressed = r.into_body().collect().await.unwrap().to_bytes();
        let mut decoded = Vec::new();
        match expected_enc {
            "gzip" => flate2::read::GzDecoder::new(&compressed[..])
                .read_to_end(&mut decoded)
                .unwrap(),
            "br" => brotli::Decompressor::new(&compressed[..], 4096)
                .read_to_end(&mut decoded)
                .unwrap(),
            "zstd" => zstd::stream::read::Decoder::new(&compressed[..])
                .unwrap()
                .read_to_end(&mut decoded)
                .unwrap(),
            _ => unreachable!(),
        };
        assert_eq!(decoded, payload_big.as_bytes());
    }

    // 5. SSE (`text/event-stream`), tiny payloads (< min_size_bytes), and `no-transform` are NEVER compressed!
    for path in ["/sse", "/tiny", "/notransform"] {
        let r = client
            .request(
                Request::builder()
                    .uri(format!("http://{}{path}", gw.local_addr()))
                    .header(header::AUTHORIZATION, format!("Bearer {valid_hs}"))
                    .header(
                        header::ACCEPT_ENCODING,
                        HeaderValue::from_static("zstd, br, gzip"),
                    )
                    .body(Full::new(Bytes::new()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(r.status(), StatusCode::OK);
        assert!(
            r.headers().get(header::CONTENT_ENCODING).is_none(),
            "{path} should never be compressed"
        );
    }

    gw.shutdown().await;
    backend_task.abort();
}
