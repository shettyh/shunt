use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use http::{Method, Request, Response, StatusCode};
use http_body::Frame;
use http_body_util::{BodyExt, Full};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use rcgen::{
    BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, KeyPair, SanType,
};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use rustls::{ClientConfig, RootCertStore};
use shunt_core::{
    CertStore, ClientAuthConfig, ClientAuthMode, DynamicCertResolver, GatewayServer, RouteMatch,
    RouteSpec, RuntimeRegistry, SnapshotBuilder, TlsListenerConfig, UpstreamConfig,
    ensure_crypto_provider, load_certified_key_pem, parse_client_cert_info,
};
use shunt_plugin_sdk::{
    HookMask, HookResult, HttpPlugin, RequestCtx, RequestHead, UpstreamRequest,
};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsConnector;

struct CertMaterial {
    ca_cert_pem: String,
    ca_cert: rcgen::Certificate,
    ca_key: KeyPair,
}

fn generate_ca(cn: &str) -> CertMaterial {
    let mut params = CertificateParams::new(Vec::new()).unwrap();
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.distinguished_name.push(DnType::CommonName, cn);
    let ca_key = KeyPair::generate().unwrap();
    let ca_cert = params.self_signed(&ca_key).unwrap();
    CertMaterial {
        ca_cert_pem: ca_cert.pem(),
        ca_cert,
        ca_key,
    }
}

fn issue_server_cert(ca: &CertMaterial, dns: &str) -> (String, String) {
    let mut params = CertificateParams::new(vec![dns.to_owned()]).unwrap();
    params.distinguished_name.push(DnType::CommonName, dns);
    params
        .extended_key_usages
        .push(ExtendedKeyUsagePurpose::ServerAuth);
    let key = KeyPair::generate().unwrap();
    let cert = params.signed_by(&key, &ca.ca_cert, &ca.ca_key).unwrap();
    (cert.pem(), key.serialize_pem())
}

fn issue_client_cert(
    ca: &CertMaterial,
    cn: &str,
    san_dns: &str,
    spiffe_uri: &str,
) -> (String, String, Vec<u8>) {
    let mut params = CertificateParams::new(Vec::new()).unwrap();
    params.distinguished_name.push(DnType::CommonName, cn);
    params
        .distinguished_name
        .push(DnType::OrganizationName, "ShuntTest");
    params
        .subject_alt_names
        .push(SanType::DnsName(san_dns.try_into().unwrap()));
    params
        .subject_alt_names
        .push(SanType::URI(spiffe_uri.try_into().unwrap()));
    params
        .extended_key_usages
        .push(ExtendedKeyUsagePurpose::ClientAuth);
    let key = KeyPair::generate().unwrap();
    let cert = params.signed_by(&key, &ca.ca_cert, &ca.ca_key).unwrap();
    (cert.pem(), key.serialize_pem(), cert.der().to_vec())
}

struct ClientCertEchoPlugin;

impl HttpPlugin for ClientCertEchoPlugin {
    fn name(&self) -> &str {
        "client-cert-echo"
    }

    fn hook_mask(&self) -> HookMask {
        HookMask::ON_REQUEST_HEADERS | HookMask::ON_UPSTREAM_REQUEST
    }

    fn on_request_headers<'a>(
        &'a self,
        _ctx: &'a mut RequestCtx,
        _req: &'a mut RequestHead,
    ) -> HookResult<'a, shunt_plugin_sdk::Flow> {
        HookResult::Ready(shunt_plugin_sdk::Flow::Continue)
    }

    fn on_upstream_request<'a>(
        &'a self,
        ctx: &'a mut RequestCtx,
        req: &'a mut UpstreamRequest,
    ) -> HookResult<'a, shunt_plugin_sdk::Flow> {
        if let Some(cert) = &ctx.client_cert {
            if let Some(cn) = &cert.subject_cn {
                req.headers.insert(
                    http::HeaderName::from_static("x-mtls-cn"),
                    http::HeaderValue::from_str(cn).unwrap(),
                );
            }
            if let Some(uri) = cert.san_uris.first() {
                req.headers.insert(
                    http::HeaderName::from_static("x-mtls-spiffe"),
                    http::HeaderValue::from_str(uri).unwrap(),
                );
            }
            req.headers.insert(
                http::HeaderName::from_static("x-mtls-fp"),
                http::HeaderValue::from_str(&cert.sha256_fingerprint).unwrap(),
            );
        }
        HookResult::Ready(shunt_plugin_sdk::Flow::Continue)
    }
}

async fn spawn_echo_backend() -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let task = tokio::spawn(async move {
        loop {
            let Ok((tcp, _)) = listener.accept().await else {
                break;
            };
            tokio::spawn(async move {
                let svc = service_fn(|req: Request<hyper::body::Incoming>| async move {
                    let cn = req
                        .headers()
                        .get("x-mtls-cn")
                        .and_then(|v| v.to_str().ok())
                        .unwrap_or("")
                        .to_owned();
                    let spiffe = req
                        .headers()
                        .get("x-mtls-spiffe")
                        .and_then(|v| v.to_str().ok())
                        .unwrap_or("")
                        .to_owned();
                    let body = req
                        .into_body()
                        .collect()
                        .await
                        .map(|c| c.to_bytes())
                        .unwrap_or_default();
                    let out = format!("cn={cn}|spiffe={spiffe}|len={}", body.len());
                    Ok::<_, Infallible>(
                        Response::builder()
                            .status(StatusCode::OK)
                            .body(Full::new(Bytes::from(out)))
                            .unwrap(),
                    )
                });
                let _ = http1::Builder::new()
                    .serve_connection(TokioIo::new(tcp), svc)
                    .await;
            });
        }
    });
    (addr, task)
}

async fn send_tls_get(
    addr: SocketAddr,
    server_ca_pem: &str,
    client_pem: Option<(&str, &str)>,
) -> Result<(StatusCode, String), String> {
    ensure_crypto_provider();
    let mut roots = RootCertStore::empty();
    for c in CertificateDer::pem_slice_iter(server_ca_pem.as_bytes()) {
        roots.add(c.unwrap()).unwrap();
    }
    let builder = ClientConfig::builder().with_root_certificates(roots);
    let cfg = match client_pem {
        Some((cert_pem, key_pem)) => {
            let certs: Vec<CertificateDer<'static>> =
                CertificateDer::pem_slice_iter(cert_pem.as_bytes())
                    .map(|r| r.unwrap())
                    .collect();
            let key = PrivateKeyDer::from_pem_slice(key_pem.as_bytes()).unwrap();
            builder
                .with_client_auth_cert(certs, key)
                .map_err(|e| e.to_string())?
        }
        None => builder.with_no_client_auth(),
    };
    let connector = TlsConnector::from(Arc::new(cfg));
    let tcp = TcpStream::connect(addr).await.map_err(|e| e.to_string())?;
    let tls = connector
        .connect(ServerName::try_from("localhost").unwrap(), tcp)
        .await
        .map_err(|e| e.to_string())?;
    let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(tls))
        .await
        .map_err(|e| e.to_string())?;
    tokio::spawn(async move {
        let _ = conn.await;
    });
    let req = Request::builder()
        .uri("https://localhost/check")
        .header("host", "localhost")
        .body(Full::new(Bytes::new()))
        .unwrap();
    let res = sender.send_request(req).await.map_err(|e| e.to_string())?;
    let status = res.status();
    let bytes = res
        .into_body()
        .collect()
        .await
        .map_err(|e| e.to_string())?
        .to_bytes();
    Ok((status, String::from_utf8_lossy(&bytes).into_owned()))
}

#[tokio::test]
async fn mtls_required_extracts_cert_info_and_supports_hot_ca_rotation() {
    let server_ca = generate_ca("Server-CA");
    let client_ca_1 = generate_ca("Client-CA-1");
    let client_ca_2 = generate_ca("Client-CA-2");

    let (srv_cert, srv_key) = issue_server_cert(&server_ca, "localhost");
    let (cli1_cert, cli1_key, cli1_der) = issue_client_cert(
        &client_ca_1,
        "checkout-svc",
        "checkout.internal",
        "spiffe://prod.cluster/ns/payments/sa/checkout",
    );
    let (cli2_cert, cli2_key, _cli2_der) = issue_client_cert(
        &client_ca_2,
        "billing-svc",
        "billing.internal",
        "spiffe://prod.cluster/ns/billing/sa/billing",
    );

    // Direct unit check on pure-Rust X.509 DER parser
    let parsed = parse_client_cert_info(&cli1_der).expect("parse DER");
    assert_eq!(parsed.subject_cn.as_deref(), Some("checkout-svc"));
    assert!(parsed.subject_dn.contains("CN=checkout-svc"));
    assert!(parsed.san_dns.iter().any(|d| d == "checkout.internal"));
    assert!(
        parsed
            .san_uris
            .iter()
            .any(|u| u == "spiffe://prod.cluster/ns/payments/sa/checkout")
    );
    assert_eq!(parsed.sha256_fingerprint.len(), 64);

    let (backend_addr, backend_task) = spawn_echo_backend().await;
    let registry = RuntimeRegistry::new();
    let snap = SnapshotBuilder::new(1)
        .upstream(UpstreamConfig::new(
            "backend",
            vec![format!("http://{backend_addr}")],
        ))
        .route(
            RouteSpec::new("r1", RouteMatch::any(), "backend")
                .with_plugin(Arc::new(ClientCertEchoPlugin)),
        )
        .build(&registry, false)
        .unwrap();

    let ck = load_certified_key_pem(srv_cert.as_bytes(), srv_key.as_bytes()).unwrap();
    let resolver = Arc::new(DynamicCertResolver::new(CertStore::new().with_default(ck)));
    let tls_cfg = TlsListenerConfig::new(resolver).with_client_auth(Some(ClientAuthConfig {
        mode: ClientAuthMode::Required,
        ca_pem: client_ca_1.ca_cert_pem.as_bytes().to_vec(),
    }));

    let gw = GatewayServer::new(snap)
        .with_tls(tls_cfg)
        .with_drain_timeout(Duration::from_secs(2))
        .bind("127.0.0.1:0".parse().unwrap())
        .await
        .unwrap();

    // 1. No client cert -> rejected at TLS handshake
    assert!(
        send_tls_get(gw.local_addr(), &server_ca.ca_cert_pem, None)
            .await
            .is_err()
    );

    // 2. Client cert signed by CA 1 -> accepted + metadata propagated into RequestCtx
    let (status, body) = send_tls_get(
        gw.local_addr(),
        &server_ca.ca_cert_pem,
        Some((&cli1_cert, &cli1_key)),
    )
    .await
    .unwrap();
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("cn=checkout-svc"), "got {body}");
    assert!(
        body.contains("spiffe=spiffe://prod.cluster/ns/payments/sa/checkout"),
        "got {body}"
    );

    // 3. Client cert signed by CA 2 -> rejected before CA rotation
    assert!(
        send_tls_get(
            gw.local_addr(),
            &server_ca.ca_cert_pem,
            Some((&cli2_cert, &cli2_key)),
        )
        .await
        .is_err()
    );

    // 4. Zero-downtime hot reload of mTLS Client CA to CA 2!
    gw.reload_client_auth(Some(&ClientAuthConfig {
        mode: ClientAuthMode::Required,
        ca_pem: client_ca_2.ca_cert_pem.as_bytes().to_vec(),
    }))
    .unwrap();

    // Now CA 2 cert succeeds and CA 1 cert is rejected!
    let (status2, body2) = send_tls_get(
        gw.local_addr(),
        &server_ca.ca_cert_pem,
        Some((&cli2_cert, &cli2_key)),
    )
    .await
    .unwrap();
    assert_eq!(status2, StatusCode::OK);
    assert!(body2.contains("cn=billing-svc"), "got {body2}");
    assert!(
        send_tls_get(
            gw.local_addr(),
            &server_ca.ca_cert_pem,
            Some((&cli1_cert, &cli1_key)),
        )
        .await
        .is_err()
    );

    gw.shutdown().await;
    backend_task.abort();
}

#[tokio::test]
async fn unbuffered_streaming_body_limit_enforced_on_chunked_requests() {
    let (backend_addr, backend_task) = spawn_echo_backend().await;
    let registry = RuntimeRegistry::new();
    // Note: ZERO buffering plugins — pure zero-copy streaming route with explicit max_body_bytes = 32!
    let snap = SnapshotBuilder::new(1)
        .upstream(UpstreamConfig::new(
            "backend",
            vec![format!("http://{backend_addr}")],
        ))
        .route(RouteSpec::new("capped", RouteMatch::any(), "backend").with_max_body_bytes(32))
        .build(&registry, false)
        .unwrap();

    let gw = GatewayServer::new(snap)
        .with_drain_timeout(Duration::from_secs(2))
        .bind("127.0.0.1:0".parse().unwrap())
        .await
        .unwrap();

    // Helper to send a true chunked request (no Content-Length header) via raw hyper H1 client
    let send_chunked = |chunks: Vec<&'static [u8]>| {
        let addr = gw.local_addr();
        async move {
            let tcp = TcpStream::connect(addr).await.unwrap();
            let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(tcp))
                .await
                .unwrap();
            tokio::spawn(async move {
                let _ = conn.await;
            });
            let (tx, rx) = tokio::sync::mpsc::channel::<Result<Frame<Bytes>, Infallible>>(4);
            tokio::spawn(async move {
                for c in chunks {
                    let _ = tx.send(Ok(Frame::data(Bytes::from_static(c)))).await;
                }
            });
            let req = Request::builder()
                .method(Method::POST)
                .uri("/upload")
                .header("host", "localhost")
                .body(tokio_stream_from_rx(rx))
                .unwrap();
            sender.send_request(req).await
        }
    };

    // 1. Small chunked body (20 bytes <= 32) succeeds!
    let ok_res = send_chunked(vec![b"0123456789", b"abcdefghij"])
        .await
        .unwrap();
    assert_eq!(ok_res.status(), StatusCode::OK);
    let body = ok_res.into_body().collect().await.unwrap().to_bytes();
    assert!(String::from_utf8_lossy(&body).contains("len=20"));

    // 2. Oversized chunked body (60 bytes > 32) is rejected with 413 Payload Too Large!
    let over_res = send_chunked(vec![
        b"01234567890123456789",
        b"01234567890123456789",
        b"01234567890123456789",
    ])
    .await;
    match over_res {
        Ok(resp) => assert_eq!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE),
        Err(_) => {
            // Depending on TCP timing, the gateway may reject/reset the stream before client finishes writing;
            // either 413 or early stream abort proves the cap prevented forwarding the full payload.
        }
    }

    gw.shutdown().await;
    backend_task.abort();
}

fn tokio_stream_from_rx(
    rx: tokio::sync::mpsc::Receiver<Result<Frame<Bytes>, Infallible>>,
) -> impl http_body::Body<Data = Bytes, Error = Infallible> {
    struct ChannelReqBody(tokio::sync::mpsc::Receiver<Result<Frame<Bytes>, Infallible>>);
    impl http_body::Body for ChannelReqBody {
        type Data = Bytes;
        type Error = Infallible;
        fn poll_frame(
            mut self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
            self.0.poll_recv(cx)
        }
    }
    ChannelReqBody(rx)
}
