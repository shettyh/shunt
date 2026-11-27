//! Adversarial security regression tests for Wave 1 `shunt-plugins` hardening:
//! - §3 H-1: `redirect` open redirects, bad `Host`, scheme fallback, `allowed_hosts`, prefix boundaries
//! - §3 H-2: `header-rewrite` `{param}` traversal & fail-closed rewritten URIs
//! - §3 H-5: `bearer-auth` default `strip_header = true`, duplicate `Authorization`, `jwt-auth` duplicate creds & cookie/query stripping
//! - §3 H-6: `mtls-auth` single-label DNS, segment-bounded SPIFFE `*`/`**`, matched SAN forwarding, `denied_fingerprints`
//! - §3 H-8: `body-limit` malformed/conflicting `Content-Length` & custom status code
//! - §3 P-M9: `#[serde(deny_unknown_fields)]` across all core HTTP plugins

use std::collections::HashSet;
use std::net::SocketAddr;
use std::sync::{Arc, RwLock};

use ring::hmac;
use serde_json::json;
use shunt_plugin_sdk::{
    BuildContext, ClientCertInfo, Flow, HeaderMap, HeaderValue, Method, PathParams, PluginConfig,
    PluginFactory, RequestCtx, RequestHead, StateStore, StatusCode, UpstreamRequest, Uri, Version,
    header,
};
use shunt_plugins::{
    AccessLogFactory, AuthSubject, BearerAuthFactory, BodyLimitFactory, CorsFactory,
    HeaderRewriteFactory, JwtAuthFactory, MtlsAuthFactory, OtelTraceFactory, RateLimitFactory,
    RedirectFactory, RequestIdFactory,
};

fn build_ctx() -> BuildContext {
    BuildContext::new(
        "test-scope",
        Arc::new(StateStore::new()),
        Arc::new(RwLock::new(HashSet::new())),
    )
}

fn req_head(method: Method, uri: &str) -> RequestHead {
    RequestHead {
        method,
        uri: uri.parse().unwrap(),
        version: Version::HTTP_11,
        headers: HeaderMap::new(),
    }
}

fn rctx() -> RequestCtx {
    let addr: SocketAddr = "127.0.0.1:42000".parse().unwrap();
    RequestCtx::new(1, addr, None)
}

fn b64url_encode(data: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = if chunk.len() > 1 { chunk[1] as u32 } else { 0 };
        let b2 = if chunk.len() > 2 { chunk[2] as u32 } else { 0 };
        let n = (b0 << 16) | (b1 << 8) | b2;
        out.push(TABLE[((n >> 18) & 0x3F) as usize] as char);
        out.push(TABLE[((n >> 12) & 0x3F) as usize] as char);
        if chunk.len() > 1 {
            out.push(TABLE[((n >> 6) & 0x3F) as usize] as char);
        }
        if chunk.len() > 2 {
            out.push(TABLE[(n & 0x3F) as usize] as char);
        }
    }
    out
}

fn sign_hs256_jwt(secret: &[u8], payload: serde_json::Value) -> String {
    let hdr = b64url_encode(br#"{"alg":"HS256","typ":"JWT"}"#);
    let body = b64url_encode(&serde_json::to_vec(&payload).unwrap());
    let input = format!("{hdr}.{body}");
    let key = hmac::Key::new(hmac::HMAC_SHA256, secret);
    let sig = b64url_encode(hmac::sign(&key, input.as_bytes()).as_ref());
    format!("{input}.{sig}")
}

// -----------------------------------------------------------------------------
// §3 H-1: Redirect open redirects & Host/prefix hardening
// -----------------------------------------------------------------------------

#[tokio::test]
async fn redirect_blocks_open_redirects_malformed_host_and_prefix_boundary_bugs() {
    // 1) Relative redirect must never emit `//evil.example` or `/\evil.example`.
    let rel = RedirectFactory
        .build(
            &PluginConfig::new(json!({
                "path_match_prefix": "/old",
                "path_replace_prefix": "/"
            })),
            &build_ctx(),
        )
        .unwrap();

    for bad_uri in ["/old//evil.example/x", "//evil.example/x"] {
        let mut ctx = rctx();
        let mut req = req_head(Method::GET, bad_uri);
        let flow = rel.on_request_headers(&mut ctx, &mut req).resolve().await;
        assert!(
            matches!(flow, Flow::Respond(r) if r.status == StatusCode::BAD_REQUEST),
            "expected 400 for open redirect URI `{bad_uri}`"
        );
    }

    // 2) Prefix replacement respects segment boundary (`/old-admin` must NOT match `/old`).
    let pfx = RedirectFactory
        .build(
            &PluginConfig::new(json!({
                "path_match_prefix": "/old",
                "path_replace_prefix": "/new"
            })),
            &build_ctx(),
        )
        .unwrap();
    let mut ctx = rctx();
    let mut req = req_head(Method::GET, "/old-admin");
    let flow = pfx.on_request_headers(&mut ctx, &mut req).resolve().await;
    match flow {
        Flow::Respond(r) => {
            assert_eq!(r.status, StatusCode::FOUND);
            assert_eq!(r.headers.get(header::LOCATION).unwrap(), "/old-admin");
        }
        _ => panic!("expected redirect response"),
    }

    // 3) Host reflection rejects `@`, `/`, duplicate Host, and enforces `allowed_hosts`.
    let abs = RedirectFactory
        .build(
            &PluginConfig::new(json!({
                "scheme": "https",
                "allowed_hosts": ["app.example.com"]
            })),
            &build_ctx(),
        )
        .unwrap();

    for bad_host in [
        "app.example.com@evil.example",
        "evil.example/foo",
        "evil.example",
    ] {
        let mut ctx = rctx();
        let mut req = req_head(Method::GET, "/login");
        req.headers
            .insert(header::HOST, HeaderValue::from_str(bad_host).unwrap());
        let flow = abs.on_request_headers(&mut ctx, &mut req).resolve().await;
        assert!(
            matches!(flow, Flow::Respond(r) if r.status == StatusCode::BAD_REQUEST),
            "expected 400 for hostile Host `{bad_host}`"
        );
    }

    // Valid allowed Host succeeds.
    let mut ctx = rctx();
    let mut req = req_head(Method::GET, "/login");
    req.headers.insert(
        header::HOST,
        HeaderValue::from_static("app.example.com:8080"),
    );
    let flow = abs.on_request_headers(&mut ctx, &mut req).resolve().await;
    match flow {
        Flow::Respond(r) => {
            assert_eq!(r.status, StatusCode::FOUND);
            assert_eq!(
                r.headers.get(header::LOCATION).unwrap(),
                "https://app.example.com/login"
            );
        }
        _ => panic!("expected redirect response"),
    }

    // 4) Host vs URI :authority disagreement -> 400 Bad Request (prevents host-route open redirect).
    let no_allowlist = RedirectFactory
        .build(
            &PluginConfig::new(json!({ "scheme": "https" })),
            &build_ctx(),
        )
        .unwrap();
    let mut ctx = rctx();
    let mut req = req_head(Method::GET, "https://trusted.example.com/login");
    req.headers
        .insert(header::HOST, HeaderValue::from_static("evil.example.com"));
    let flow = no_allowlist
        .on_request_headers(&mut ctx, &mut req)
        .resolve()
        .await;
    assert!(matches!(flow, Flow::Respond(r) if r.status == StatusCode::BAD_REQUEST));

    // 5) Build-time validation rejects blank/port allowed_hosts and port-bearing hostname.
    assert!(
        RedirectFactory
            .build(
                &PluginConfig::new(json!({ "scheme": "https", "allowed_hosts": ["   "] })),
                &build_ctx(),
            )
            .is_err()
    );
    assert!(
        RedirectFactory
            .build(
                &PluginConfig::new(
                    json!({ "scheme": "https", "allowed_hosts": ["app.example.com:8080"] })
                ),
                &build_ctx(),
            )
            .is_err()
    );
    assert!(
        RedirectFactory
            .build(
                &PluginConfig::new(
                    json!({ "scheme": "https", "hostname": "app.example.com:8080", "port": 8443 })
                ),
                &build_ctx(),
            )
            .is_err()
    );

    // 6) Mixed-case URI scheme normalizes cleanly when suppressing default port 443.
    let port_443 = RedirectFactory
        .build(&PluginConfig::new(json!({ "port": 443 })), &build_ctx())
        .unwrap();
    let mut ctx = rctx();
    let mut req = req_head(Method::GET, "HTTPS://app.example.com/login");
    let flow = port_443
        .on_request_headers(&mut ctx, &mut req)
        .resolve()
        .await;
    match flow {
        Flow::Respond(r) => {
            assert_eq!(r.status, StatusCode::FOUND);
            assert_eq!(
                r.headers.get(header::LOCATION).unwrap(),
                "https://app.example.com/login"
            );
        }
        _ => panic!("expected redirect response"),
    }
}

// -----------------------------------------------------------------------------
// §3 H-2: header-rewrite rejects {param} traversal and fails closed
// -----------------------------------------------------------------------------

#[tokio::test]
async fn header_rewrite_blocks_path_param_traversal_and_fails_closed() {
    let plugin = HeaderRewriteFactory
        .build(
            &PluginConfig::new(json!({
                "path_replace_full": "/internal/orders/{order_id}/state"
            })),
            &build_ctx(),
        )
        .unwrap();

    for evil_param in [
        "../../admin",
        "..",
        ".",
        "%2e%2e",
        "foo%2fbar",
        "foo%5cbar",
        "foo?x=1",
        "foo#frag",
        "foo\\bar",
    ] {
        let mut ctx = rctx();
        ctx.path_params =
            PathParams::from_pairs(vec![(Arc::from("order_id"), evil_param.to_owned())]);
        let mut up_req = UpstreamRequest {
            method: Method::GET,
            uri: Uri::from_static("/orders/x/status"),
            headers: HeaderMap::new(),
            body: None,
            endpoint_uri: None,
        };
        let flow = plugin
            .on_upstream_request(&mut ctx, &mut up_req)
            .resolve()
            .await;
        assert!(
            matches!(flow, Flow::Respond(r) if r.status == StatusCode::BAD_REQUEST),
            "expected 400 for evil param `{evil_param}`"
        );
    }
}

// -----------------------------------------------------------------------------
// §3 H-5: bearer-auth & jwt-auth duplicate credentials & stripping
// -----------------------------------------------------------------------------

#[tokio::test]
async fn bearer_auth_strips_header_by_default_and_rejects_duplicate_authorization() {
    let plugin = BearerAuthFactory
        .build(
            &PluginConfig::new(json!({
                "tokens": [{ "token": "secret-123", "subject": "alice" }]
            })),
            &build_ctx(),
        )
        .unwrap();

    // Case-insensitive "BEARER " succeeds and strips Authorization by default.
    let mut ctx = rctx();
    let mut req = req_head(Method::GET, "/api");
    req.headers.insert(
        header::AUTHORIZATION,
        HeaderValue::from_static("BEARER secret-123"),
    );
    let flow = plugin
        .on_request_headers(&mut ctx, &mut req)
        .resolve()
        .await;
    assert!(matches!(flow, Flow::Continue));
    assert!(!req.headers.contains_key(header::AUTHORIZATION));
    assert_eq!(ctx.get_ext::<AuthSubject>().unwrap().0, "alice");

    // Duplicate Authorization headers -> 400 Bad Request.
    let mut ctx2 = rctx();
    let mut req2 = req_head(Method::GET, "/api");
    req2.headers.append(
        header::AUTHORIZATION,
        HeaderValue::from_static("Bearer secret-123"),
    );
    req2.headers.append(
        header::AUTHORIZATION,
        HeaderValue::from_static("Bearer evil-other"),
    );
    let flow2 = plugin
        .on_request_headers(&mut ctx2, &mut req2)
        .resolve()
        .await;
    assert!(matches!(flow2, Flow::Respond(r) if r.status == StatusCode::BAD_REQUEST));
}

#[tokio::test]
async fn jwt_auth_rejects_duplicate_credentials_and_strips_cookie_and_query() {
    let secret = b"super-secret-hs256-key-at-least-32-bytes!";
    let plugin = JwtAuthFactory
        .build(
            &PluginConfig::new(json!({
                "keys": [{ "kid": "k1", "alg": "HS256", "secret": String::from_utf8_lossy(secret) }],
                "algorithms": ["HS256"],
                "require_exp": false,
                "cookie_name": "session_jwt",
                "query_param": "access_token",
                "strip_header": true
            })),
            &build_ctx(),
        )
        .unwrap();

    let tok = sign_hs256_jwt(secret, json!({ "sub": "bob" }));

    // 1) Duplicate Authorization headers -> 400.
    let mut ctx = rctx();
    let mut req = req_head(Method::GET, "/api");
    req.headers.append(
        header::AUTHORIZATION,
        HeaderValue::from_str(&format!("Bearer {tok}")).unwrap(),
    );
    req.headers.append(
        header::AUTHORIZATION,
        HeaderValue::from_static("Bearer second-token"),
    );
    let flow = plugin
        .on_request_headers(&mut ctx, &mut req)
        .resolve()
        .await;
    assert!(matches!(flow, Flow::Respond(r) if r.status == StatusCode::BAD_REQUEST));

    // 2) Duplicate matching Cookie -> 400.
    let mut ctx = rctx();
    let mut req = req_head(Method::GET, "/api");
    req.headers.insert(
        header::COOKIE,
        HeaderValue::from_str(&format!("session_jwt={tok}; session_jwt=other")).unwrap(),
    );
    let flow = plugin
        .on_request_headers(&mut ctx, &mut req)
        .resolve()
        .await;
    assert!(matches!(flow, Flow::Respond(r) if r.status == StatusCode::BAD_REQUEST));

    // 3) Single Cookie -> passes and strips ONLY `session_jwt`, keeping `theme=dark`.
    let mut ctx = rctx();
    let mut req = req_head(Method::GET, "/api");
    req.headers.insert(
        header::COOKIE,
        HeaderValue::from_str(&format!("theme=dark; session_jwt={tok}")).unwrap(),
    );
    let flow = plugin
        .on_request_headers(&mut ctx, &mut req)
        .resolve()
        .await;
    assert!(matches!(flow, Flow::Continue));
    assert_eq!(req.headers.get(header::COOKIE).unwrap(), "theme=dark");

    // 4) Duplicate matching query param -> 400.
    let mut ctx = rctx();
    let mut req = req_head(
        Method::GET,
        &format!("/api?access_token={tok}&access_token=other"),
    );
    let flow = plugin
        .on_request_headers(&mut ctx, &mut req)
        .resolve()
        .await;
    assert!(matches!(flow, Flow::Respond(r) if r.status == StatusCode::BAD_REQUEST));

    // 5) Single query param -> passes and strips ONLY `access_token`, keeping `foo=1`.
    let mut ctx = rctx();
    let mut req = req_head(Method::GET, &format!("/api?foo=1&access_token={tok}&bar=2"));
    let flow = plugin
        .on_request_headers(&mut ctx, &mut req)
        .resolve()
        .await;
    assert!(matches!(flow, Flow::Continue));
    assert_eq!(req.uri.to_string(), "/api?foo=1&bar=2");

    // 6) Cross-source credential smuggling (Header + Cookie, or Header + Query) -> 400.
    let mut ctx = rctx();
    let mut req = req_head(Method::GET, "/api");
    req.headers.insert(
        header::AUTHORIZATION,
        HeaderValue::from_str(&format!("Bearer {tok}")).unwrap(),
    );
    req.headers.insert(
        header::COOKIE,
        HeaderValue::from_static("session_jwt=smuggled-token"),
    );
    let flow = plugin
        .on_request_headers(&mut ctx, &mut req)
        .resolve()
        .await;
    assert!(matches!(flow, Flow::Respond(r) if r.status == StatusCode::BAD_REQUEST));

    let mut ctx = rctx();
    let mut req = req_head(Method::GET, "/api?access_token=smuggled-token");
    req.headers.insert(
        header::AUTHORIZATION,
        HeaderValue::from_str(&format!("Bearer {tok}")).unwrap(),
    );
    let flow = plugin
        .on_request_headers(&mut ctx, &mut req)
        .resolve()
        .await;
    assert!(matches!(flow, Flow::Respond(r) if r.status == StatusCode::BAD_REQUEST));

    // 7) Empty duplicate cookie or query param -> 400.
    let mut ctx = rctx();
    let mut req = req_head(Method::GET, "/api");
    req.headers.insert(
        header::COOKIE,
        HeaderValue::from_str(&format!("session_jwt=; session_jwt={tok}")).unwrap(),
    );
    let flow = plugin
        .on_request_headers(&mut ctx, &mut req)
        .resolve()
        .await;
    assert!(matches!(flow, Flow::Respond(r) if r.status == StatusCode::BAD_REQUEST));

    let mut ctx = rctx();
    let mut req = req_head(
        Method::GET,
        &format!("/api?access_token=&access_token={tok}"),
    );
    let flow = plugin
        .on_request_headers(&mut ctx, &mut req)
        .resolve()
        .await;
    assert!(matches!(flow, Flow::Respond(r) if r.status == StatusCode::BAD_REQUEST));

    // 8) HTTP/2 / absolute-form URI preserves scheme and :authority when stripping query param.
    let mut ctx = rctx();
    let mut req = req_head(
        Method::GET,
        &format!("https://api.example.com/v1?foo=1&access_token={tok}&bar=2"),
    );
    let flow = plugin
        .on_request_headers(&mut ctx, &mut req)
        .resolve()
        .await;
    assert!(matches!(flow, Flow::Continue));
    assert_eq!(req.uri.scheme_str(), Some("https"));
    assert_eq!(req.uri.host(), Some("api.example.com"));
    assert_eq!(
        req.uri.to_string(),
        "https://api.example.com/v1?foo=1&bar=2"
    );
}

// -----------------------------------------------------------------------------
// §3 H-6: mTLS single-label DNS, SPIFFE segment bounds, matched SAN, denied_fingerprints
// -----------------------------------------------------------------------------

#[tokio::test]
async fn mtls_auth_hardened_wildcards_matched_san_and_revocation() {
    // 1) DNS wildcard is single-label only (`*.svc.internal` rejects `a.b.svc.internal`).
    let dns_plugin = MtlsAuthFactory
        .build(
            &PluginConfig::new(json!({
                "allowed_san_dns": ["*.svc.internal"]
            })),
            &build_ctx(),
        )
        .unwrap();

    let multi_label_cert = Arc::new(ClientCertInfo {
        subject_cn: Some("svc".to_owned()),
        subject_dn: "CN=svc".to_owned(),
        issuer_dn: "CN=CA".to_owned(),
        san_dns: vec!["evil.other.svc.internal".to_owned()],
        san_uris: vec![],
        san_emails: vec![],
        serial_hex: "01".to_owned(),
        sha256_fingerprint: "1".repeat(64),
    });
    let mut ctx = rctx().with_client_cert(Some(multi_label_cert));
    let mut req = req_head(Method::GET, "/");
    let flow = dns_plugin
        .on_request_headers(&mut ctx, &mut req)
        .resolve()
        .await;
    assert!(matches!(flow, Flow::Respond(r) if r.status == StatusCode::FORBIDDEN));

    // 2) SPIFFE single `*` does NOT cross `/`, and multi-SAN cert forwards the MATCHED SAN!
    let spiffe_plugin = MtlsAuthFactory
        .build(
            &PluginConfig::new(json!({
                "allowed_san_uris": ["spiffe://prod/ns/*/sa/frontend"],
                "san_uri_header": "x-spiffe-id",
                "denied_fingerprints": ["d".repeat(64)]
            })),
            &build_ctx(),
        )
        .unwrap();

    // Slash-crossing escape attempt -> 403.
    let slash_escape_cert = Arc::new(ClientCertInfo {
        subject_cn: None,
        subject_dn: "O=Evil".to_owned(),
        issuer_dn: "CN=CA".to_owned(),
        san_dns: vec![],
        san_uris: vec!["spiffe://prod/ns/other/sa/admin/sa/frontend".to_owned()],
        san_emails: vec![],
        serial_hex: "02".to_owned(),
        sha256_fingerprint: "2".repeat(64),
    });
    let mut ctx = rctx().with_client_cert(Some(slash_escape_cert));
    let mut req = req_head(Method::GET, "/");
    let flow = spiffe_plugin
        .on_request_headers(&mut ctx, &mut req)
        .resolve()
        .await;
    assert!(matches!(flow, Flow::Respond(r) if r.status == StatusCode::FORBIDDEN));

    // Multi-SAN cert: SAN #1 is privileged admin, SAN #2 matches allowlist -> MUST forward SAN #2!
    let multi_san_cert = Arc::new(ClientCertInfo {
        subject_cn: None,
        subject_dn: "O=Acme".to_owned(),
        issuer_dn: "CN=CA".to_owned(),
        san_dns: vec![],
        san_uris: vec![
            "spiffe://prod/ns/admin/sa/root".to_owned(),
            "spiffe://prod/ns/payments/sa/frontend".to_owned(),
        ],
        san_emails: vec![],
        serial_hex: "03".to_owned(),
        sha256_fingerprint: "3".repeat(64),
    });
    let mut ctx = rctx().with_client_cert(Some(multi_san_cert));
    let mut req = req_head(Method::GET, "/");
    let flow = spiffe_plugin
        .on_request_headers(&mut ctx, &mut req)
        .resolve()
        .await;
    assert!(matches!(flow, Flow::Continue));
    assert_eq!(
        req.headers.get("x-spiffe-id").unwrap(),
        "spiffe://prod/ns/payments/sa/frontend"
    );
    assert_eq!(
        ctx.get_ext::<AuthSubject>().unwrap().0,
        "spiffe://prod/ns/payments/sa/frontend"
    );

    // Denied fingerprint -> 403 even with matching SPIFFE URI.
    let revoked_cert = Arc::new(ClientCertInfo {
        subject_cn: Some("frontend".to_owned()),
        subject_dn: "CN=frontend".to_owned(),
        issuer_dn: "CN=CA".to_owned(),
        san_dns: vec![],
        san_uris: vec!["spiffe://prod/ns/payments/sa/frontend".to_owned()],
        san_emails: vec![],
        serial_hex: "04".to_owned(),
        sha256_fingerprint: "d".repeat(64),
    });
    let mut ctx = rctx().with_client_cert(Some(revoked_cert));
    let mut req = req_head(Method::GET, "/");
    let flow = spiffe_plugin
        .on_request_headers(&mut ctx, &mut req)
        .resolve()
        .await;
    assert!(matches!(flow, Flow::Respond(r) if r.status == StatusCode::FORBIDDEN));

    // 3) `**` followed by `*` backtracks properly across repeated segments.
    let combo_plugin = MtlsAuthFactory
        .build(
            &PluginConfig::new(json!({
                "allowed_san_uris": ["spiffe://prod/**/sa/*"]
            })),
            &build_ctx(),
        )
        .unwrap();
    let nested_sa_cert = Arc::new(ClientCertInfo {
        subject_cn: None,
        subject_dn: "O=Acme".to_owned(),
        issuer_dn: "CN=CA".to_owned(),
        san_dns: vec![],
        san_uris: vec!["spiffe://prod/ns/sa/foo/sa/web".to_owned()],
        san_emails: vec![],
        serial_hex: "05".to_owned(),
        sha256_fingerprint: "5".repeat(64),
    });
    let mut ctx = rctx().with_client_cert(Some(nested_sa_cert));
    let mut req = req_head(Method::GET, "/");
    let flow = combo_plugin
        .on_request_headers(&mut ctx, &mut req)
        .resolve()
        .await;
    assert!(matches!(flow, Flow::Continue));

    let extra_seg_cert = Arc::new(ClientCertInfo {
        subject_cn: None,
        subject_dn: "O=Acme".to_owned(),
        issuer_dn: "CN=CA".to_owned(),
        san_dns: vec![],
        san_uris: vec!["spiffe://prod/ns/sa/foo/sa/web/extra".to_owned()],
        san_emails: vec![],
        serial_hex: "06".to_owned(),
        sha256_fingerprint: "6".repeat(64),
    });
    let mut ctx = rctx().with_client_cert(Some(extra_seg_cert));
    let mut req = req_head(Method::GET, "/");
    let flow = combo_plugin
        .on_request_headers(&mut ctx, &mut req)
        .resolve()
        .await;
    assert!(matches!(flow, Flow::Respond(r) if r.status == StatusCode::FORBIDDEN));

    // 4) CN wildcard `*.svc.internal` rejects empty leading label `.svc.internal`.
    let cn_plugin = MtlsAuthFactory
        .build(
            &PluginConfig::new(json!({
                "allowed_cns": ["*.svc.internal"]
            })),
            &build_ctx(),
        )
        .unwrap();
    let empty_label_cn_cert = Arc::new(ClientCertInfo {
        subject_cn: Some(".svc.internal".to_owned()),
        subject_dn: "CN=.svc.internal".to_owned(),
        issuer_dn: "CN=CA".to_owned(),
        san_dns: vec![],
        san_uris: vec![],
        san_emails: vec![],
        serial_hex: "07".to_owned(),
        sha256_fingerprint: "7".repeat(64),
    });
    let mut ctx = rctx().with_client_cert(Some(empty_label_cn_cert));
    let mut req = req_head(Method::GET, "/");
    let flow = cn_plugin
        .on_request_headers(&mut ctx, &mut req)
        .resolve()
        .await;
    assert!(matches!(flow, Flow::Respond(r) if r.status == StatusCode::FORBIDDEN));
}

// -----------------------------------------------------------------------------
// §3 H-8: body-limit rejects malformed/conflicting Content-Length & exposes status
// -----------------------------------------------------------------------------

#[tokio::test]
async fn body_limit_rejects_malformed_and_conflicting_content_length() {
    let plugin = BodyLimitFactory
        .build(
            &PluginConfig::new(json!({ "max_bytes": 100, "status_code": 422 })),
            &build_ctx(),
        )
        .unwrap();
    assert_eq!(
        plugin.max_request_body_status_code(),
        Some(StatusCode::UNPROCESSABLE_ENTITY)
    );

    for bad_cl in ["-5", "abc", "999999999999999999999999999999", "10, 20"] {
        let mut ctx = rctx();
        let mut req = req_head(Method::POST, "/upload");
        req.headers.insert(
            header::CONTENT_LENGTH,
            HeaderValue::from_str(bad_cl).unwrap(),
        );
        let flow = plugin
            .on_request_headers(&mut ctx, &mut req)
            .resolve()
            .await;
        assert!(
            matches!(flow, Flow::Respond(r) if r.status == StatusCode::BAD_REQUEST),
            "expected 400 for bad Content-Length `{bad_cl}`"
        );
    }
}

// -----------------------------------------------------------------------------
// §3 P-M9: deny_unknown_fields across all 7 hardened core plugin configs
// -----------------------------------------------------------------------------

#[test]
fn core_plugins_reject_unknown_config_fields() {
    let ctx = build_ctx();
    assert!(
        CorsFactory
            .build(
                &PluginConfig::new(json!({ "allow_origin": ["https://a.example"] })),
                &ctx
            )
            .is_err()
    );
    assert!(
        BearerAuthFactory
            .build(
                &PluginConfig::new(json!({ "tokens": ["t1"], "strip_headers": true })),
                &ctx
            )
            .is_err()
    );
    assert!(
        RateLimitFactory
            .build(&PluginConfig::new(json!({ "rps": 10.0 })), &ctx)
            .is_err()
    );
    assert!(
        HeaderRewriteFactory
            .build(
                &PluginConfig::new(json!({ "add_response_headers": { "x": "1" } })),
                &ctx
            )
            .is_err()
    );
    assert!(
        OtelTraceFactory
            .build(&PluginConfig::new(json!({ "sample": 0.5 })), &ctx)
            .is_err()
    );
    assert!(
        RequestIdFactory
            .build(&PluginConfig::new(json!({ "trust_header": false })), &ctx)
            .is_err()
    );
    assert!(
        AccessLogFactory
            .build(&PluginConfig::new(json!({ "timings": true })), &ctx)
            .is_err()
    );
}
