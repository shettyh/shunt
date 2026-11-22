//! End-to-end integration tests for RFC 0014 dynamic cloud IAM flows requiring
//! ephemeral RSA PKCS#8 keys (GCP Service Account RS256 JWT) or rotating projected
//! OIDC token files on disk (AWS EKS IRSA, Azure AKS Workload Identity).

use std::convert::Infallible;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::Bytes;
use http::{Request, Response, StatusCode, header};
use http_body_util::{BodyExt, Full};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::client::legacy::Client;
use hyper_util::rt::{TokioExecutor, TokioIo};
use ring::signature::{KeyPair, RSA_PKCS1_2048_8192_SHA256, RsaKeyPair, UnparsedPublicKey};
use serde_json::{Value, json};
use shunt_ai::{
    AiMetrics, base64_std_decode, decode_pem_pkcs8_private_key, inspect_ai_runtime,
    register_ai_plugins,
};
use shunt_config::{GatewayConfig, LoadedConfig, SnapshotCompiler};
use shunt_core::{GatewayServer, RuntimeRegistry};
use shunt_plugin_sdk::{ManualClock, PluginRegistry};
use tokio::net::TcpListener;

#[derive(Debug, Clone)]
struct Captured {
    path: String,
    auth: Option<String>,
    amz_token: Option<String>,
    body: String,
}

async fn spawn_scripted_http<F>(
    handler: F,
) -> (
    std::net::SocketAddr,
    Arc<Mutex<Vec<Captured>>>,
    tokio::task::JoinHandle<()>,
)
where
    F: Fn(usize, &Captured) -> (StatusCode, &'static str, String) + Send + Sync + 'static,
{
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let captures = Arc::new(Mutex::new(Vec::new()));
    let handler = Arc::new(handler);

    let captures_bg = Arc::clone(&captures);
    let handle = tokio::spawn(async move {
        loop {
            let Ok((tcp, _)) = listener.accept().await else {
                break;
            };
            let caps = Arc::clone(&captures_bg);
            let h = Arc::clone(&handler);
            tokio::spawn(async move {
                let svc = service_fn(move |req: Request<hyper::body::Incoming>| {
                    let caps = Arc::clone(&caps);
                    let h = Arc::clone(&h);
                    async move {
                        let path = req
                            .uri()
                            .path_and_query()
                            .map(|pq| pq.as_str().to_owned())
                            .unwrap_or_else(|| "/".to_owned());
                        let auth = req
                            .headers()
                            .get(header::AUTHORIZATION)
                            .and_then(|v| v.to_str().ok())
                            .map(str::to_owned);
                        let amz_token = req
                            .headers()
                            .get("x-amz-security-token")
                            .and_then(|v| v.to_str().ok())
                            .map(str::to_owned);
                        let body_bytes = req
                            .into_body()
                            .collect()
                            .await
                            .map(|c| c.to_bytes())
                            .unwrap_or_default();
                        let cap = Captured {
                            path,
                            auth,
                            amz_token,
                            body: String::from_utf8_lossy(&body_bytes).into_owned(),
                        };
                        let idx = {
                            let mut g = caps.lock().unwrap();
                            let i = g.len();
                            g.push(cap.clone());
                            i
                        };
                        let (status, ct, resp_body) = h(idx, &cap);
                        Ok::<_, Infallible>(
                            Response::builder()
                                .status(status)
                                .header(header::CONTENT_TYPE, ct)
                                .body(Full::new(Bytes::from(resp_body)))
                                .unwrap(),
                        )
                    }
                });
                let _ = http1::Builder::new()
                    .serve_connection(TokioIo::new(tcp), svc)
                    .await;
            });
        }
    });
    (addr, captures, handle)
}

async fn post_chat(gw_addr: std::net::SocketAddr, model: &str) -> (StatusCode, Value) {
    let client: Client<_, Full<Bytes>> = Client::builder(TokioExecutor::new()).build_http();
    let req = Request::builder()
        .method("POST")
        .uri(format!("http://{gw_addr}/v1/chat/completions"))
        .header(header::CONTENT_TYPE, "application/json")
        .body(Full::new(Bytes::from(
            serde_json::to_vec(&json!({
                "model": model,
                "messages": [{"role": "user", "content": "hi"}]
            }))
            .unwrap(),
        )))
        .unwrap();
    let resp = client.request(req).await.unwrap();
    let status = resp.status();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let json = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    (status, json)
}

/// Test-only 2048-bit RSA PKCS#8 keypair used exclusively for RS256 e2e tests.
const TEST_RSA_PKCS8_PEM: &str = concat!(
    "-----BEGIN ",
    "PRIVATE KEY-----\n",
    "MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQCiGQ0gptn4R29n\n",
    "bZuYy6fxh7+hFbzvsVu6c91zJY4vAbcd4REiEJdicBfq8lzgewEW/bbi6BspYdNx\n",
    "5OrDmEI6M/y8kFN593vofdAtSXXqaklWBFuEz8A+/pp5TW5NJ6G49KP9ziF506QG\n",
    "a520qWgj4/YBdJfH+UTc/Me8446ToxKyxc3upYYp1mENU2wMLxMCEArigfxsYRkI\n",
    "BCRApQGjJ0HIOg7mQS95h3CJGkMh5li+fQiJu74a89qI8P1rhQVvYD9O6uw4dqIz\n",
    "1sXUlXphrd9Py4aNEWxWQNseU+hm9KoydTvyO2R1gIjvyUyqXLd3FsCLjCubZOhR\n",
    "2cXR2uIRAgMBAAECggEAIS2LeFFub9j/PmY64M1edJtaZ7gxUcY1hjZM71KShaCO\n",
    "QHlermBC/A0BeD9fLzs9/9yyYEMtvAyf4MIAI0S42XzmkBniXCaBoBaQU5Sjo/VZ\n",
    "SVfe+5IiQUKPj6B/oR8phNfd8QcN5wegnQfN4bqC7EWuhqG8p1un8qtynoDdH+5/\n",
    "GGNG+qW5QeDUOqZoKaDw5WP+EBGsqBWtg6dps5SLhHE7f5A6JD7gEpSoPN6DjDhS\n",
    "6rBfMUfZTnZDBbisNuPGio5R5n5OGYQ4Q4S3fn5d4SyvEIrAU5WRAcYAffGYDM/U\n",
    "7VYWcLS3dhqoKqWQ6Zi5GWCMKSq/pYwyOTwoXt5G2QKBgQDfZK6+F8rAWKViR2ko\n",
    "DDv0Yp6d+TINCvyB1senohYSybdTQpmDsfsIJPdbHRmpHy8fPLu2zmUDq2TNP9ou\n",
    "YXR9Cb1s1qxp5iuWdkLFj5vT7mV2lYstF/Du7ItXac5Es2LuYQ+lcoKrZk5GUh6f\n",
    "Jwhalcu5KK9qaL7TT4uZVNW2hwKBgQC5wgChauYmIBXRGDvRQ0wLJnfi7dI6/3ud\n",
    "PF0r/MFBz2JrxxejDQROT7OQt5ASOqyNw80dozv15bNIwNTQza5pNOCvfcZXbD31\n",
    "Q5IwEnrr9wggt58HxPDEa4WbcoarjniflrYqxUge9IOOIKsHm6ZzgyzFA/6r5NMz\n",
    "yL03FGywpwKBgDrMo3oBhSpvqshdh341CirfMmTeTKBGPgRm5hJnhWvYkFpn80RI\n",
    "uoyAPmNLG4/6V0rfj4Ekfk4i9NtZbTI8EI9A2w0kzCjrnplx801Q6XE1FJvL7OAn\n",
    "pxEcTejqPpKyrN2Vyqp/o4k92miEAO9fNMGzH/ZSkSlu/JteGp53R/FNAoGANp2w\n",
    "28T3eDw0ze6nH8b+o8SiuSkdh9U4PinSZy2AkN3t3SyDaaBZJMFQVXtzM7jmpSPt\n",
    "ugoVhh4MUZbIu7/NyQcQDOkZGPktWmCMqe+1Do3qaNw0OO+Rrt7CQMsyh1xzYNDK\n",
    "LNcmdluEFpTKVIlSLmJiFmcvSNEVvAMIhxpNPr8CgYAq7COYeivC94c3ET28FqMb\n",
    "cSEy8lwf8AREvpaMBmEm9OnX5UTuq0wPQNFZ1m/MyTWzPefHSgMrvMKagJUGWs5R\n",
    "bcaHkdIR9r7eY3UGwQtSqGINwQL1AMf+Byt90PwJZfokJa0xkZUguWR+NVFKvIef\n",
    "XBf5WPxWUrKOGfs1mV/Jsw==\n",
    "-----END ",
    "PRIVATE KEY-----\n"
);

#[tokio::test]
async fn gcp_service_account_rs256_jwt_end_to_end_and_signature_verification() {
    let pem = TEST_RSA_PKCS8_PEM.to_owned();
    let der = decode_pem_pkcs8_private_key(&pem).unwrap();
    let ring_kp = RsaKeyPair::from_pkcs8(&der).unwrap();
    let pub_key_der = ring_kp.public_key().as_ref().to_vec();

    // Mock Google OAuth2 token server that cryptographically verifies the RS256 JWT assertion.
    let (oauth_addr, oauth_caps, oauth_task) = spawn_scripted_http(move |idx, cap| {
        let mut assertion = None;
        for part in cap.body.split('&') {
            if let Some((k, v)) = part.split_once('=')
                && k == "assertion"
            {
                assertion = Some(v.to_owned());
            }
        }
        let jwt = assertion.expect("assertion param must be present");
        let segs: Vec<&str> = jwt.split('.').collect();
        assert_eq!(segs.len(), 3, "JWT must have 3 segments");

        // Verify RS256 signature with the SA public key.
        let signing_input = format!("{}.{}", segs[0], segs[1]);
        let mut sig_b64 = segs[2].replace('-', "+").replace('_', "/");
        while !sig_b64.len().is_multiple_of(4) {
            sig_b64.push('=');
        }
        let sig_bytes = base64_std_decode(&sig_b64).unwrap();
        let verifier = UnparsedPublicKey::new(&RSA_PKCS1_2048_8192_SHA256, &pub_key_der);
        verifier
            .verify(signing_input.as_bytes(), &sig_bytes)
            .expect("GCP JWT RS256 signature must verify");

        (
            StatusCode::OK,
            "application/json",
            format!(
                r#"{{"access_token":"gcp-sa-token-{}","expires_in":60,"token_type":"Bearer"}}"#,
                idx + 1
            ),
        )
    })
    .await;

    // Mock Vertex AI Claude-on-Vertex upstream.
    let (vertex_addr, vertex_caps, vertex_task) = spawn_scripted_http(|_, _| {
        (
            StatusCode::OK,
            "application/json",
            json!({
                "id": "msg_vtx_1",
                "type": "message",
                "role": "assistant",
                "model": "claude-sonnet-4-5",
                "content": [{"type": "text", "text": "hello from vertex sa"}],
                "stop_reason": "end_turn",
                "usage": {"input_tokens": 5, "output_tokens": 4}
            })
            .to_string(),
        )
    })
    .await;

    let sa_json = json!({
        "type": "service_account",
        "client_email": "shunt-e2e@my-proj.iam.gserviceaccount.com",
        "private_key_id": "key-01",
        "private_key": pem,
        "token_uri": format!("http://{oauth_addr}/token"),
    })
    .to_string();

    let gw_cfg: GatewayConfig = serde_json::from_value(json!({
        "server": { "listen": "127.0.0.1:0" },
        "upstreams": [
            { "name": "vertex", "endpoints": [format!("http://{vertex_addr}")] }
        ],
        "routes": [
            {
                "id": "ai",
                "path_prefix": "/v1/",
                "upstream": "vertex",
                "plugins": [
                    {
                        "name": "ai-model-router",
                        "config": {
                            "models": {
                                "vertex-claude": [
                                    { "provider": "vertex_claude", "upstream": "vertex", "model": "claude-sonnet-4-5" }
                                ]
                            }
                        }
                    },
                    {
                        "name": "ai-provider-adapter",
                        "config": {
                            "providers": {
                                "vertex_claude": {
                                    "dialect": "anthropic",
                                    "vertex_project": "my-proj",
                                    "vertex_location": "us-east5",
                                    "auth": {
                                        "type": "gcp_iam",
                                        "mode": "service_account",
                                        "credentials_json": sa_json,
                                        "refresh_margin_secs": 15
                                    }
                                }
                            }
                        }
                    }
                ]
            }
        ]
    }))
    .unwrap();

    let clock = ManualClock::shared();
    let ai_metrics = Arc::new(AiMetrics::new());
    let mut plugins = PluginRegistry::new();
    register_ai_plugins(&mut plugins, Arc::clone(&ai_metrics));
    let runtime = Arc::new(RuntimeRegistry::with_clock(clock.clone()));
    let compiler = SnapshotCompiler::new(Arc::new(plugins), Arc::clone(&runtime));
    let bundle = compiler
        .compile(&LoadedConfig {
            source_name: "e2e".into(),
            config: gw_cfg,
            digest: "d1".into(),
        })
        .unwrap();

    // Verify `credentials_json` is absent from snapshot inspection and redacted by `redact_secrets`.
    let inspect_str = serde_json::to_string(&bundle.inspect).unwrap();
    assert!(!inspect_str.contains("BEGIN PRIVATE KEY"));
    let redacted_cfg = shunt_config::redact_secrets(&bundle.config.routes[0].plugins[1].config);
    let redacted_str = serde_json::to_string(&redacted_cfg).unwrap();
    assert!(!redacted_str.contains("BEGIN PRIVATE KEY"));
    assert!(redacted_str.contains("[REDACTED]"));

    let server = GatewayServer::new(bundle.snapshot)
        .bind("127.0.0.1:0".parse().unwrap())
        .await
        .unwrap();

    // Request 1: cold miss -> RS256 JWT exchanged -> token 1 used.
    let (st1, j1) = post_chat(server.local_addr(), "vertex-claude").await;
    assert_eq!(st1, StatusCode::OK);
    assert_eq!(
        j1["choices"][0]["message"]["content"],
        "hello from vertex sa"
    );
    assert_eq!(oauth_caps.lock().unwrap().len(), 1);
    assert_eq!(
        vertex_caps.lock().unwrap()[0].auth.as_deref(),
        Some("Bearer gcp-sa-token-1")
    );

    // Request 2 at +20s: warm cache hit (zero extra OAuth calls!).
    clock.advance(Duration::from_secs(20));
    let (st2, _) = post_chat(server.local_addr(), "vertex-claude").await;
    assert_eq!(st2, StatusCode::OK);
    assert_eq!(oauth_caps.lock().unwrap().len(), 1);
    assert_eq!(
        vertex_caps.lock().unwrap()[1].auth.as_deref(),
        Some("Bearer gcp-sa-token-1")
    );

    // Inspector reports cached cloud token metadata without exposing token value.
    let inspect_rt = inspect_ai_runtime(&ai_metrics, runtime.state_store(), clock.as_ref());
    let cloud_tokens = inspect_rt["cloud_tokens"].as_array().unwrap();
    assert_eq!(cloud_tokens.len(), 1);
    assert_eq!(cloud_tokens[0]["provider"], "vertex_claude");
    assert_eq!(cloud_tokens[0]["auth_kind"], "gcp_iam");
    assert_eq!(cloud_tokens[0]["cached"], true);
    assert_eq!(cloud_tokens[0]["refresh_count"], 1);
    assert!(!inspect_rt.to_string().contains("gcp-sa-token-1"));

    // Request 3 at +50s (past 45s refresh margin): exchanges fresh RS256 JWT -> token 2!
    clock.advance(Duration::from_secs(30));
    let (st3, _) = post_chat(server.local_addr(), "vertex-claude").await;
    assert_eq!(st3, StatusCode::OK);
    assert_eq!(oauth_caps.lock().unwrap().len(), 2);
    assert_eq!(
        vertex_caps.lock().unwrap()[2].auth.as_deref(),
        Some("Bearer gcp-sa-token-2")
    );

    server.shutdown().await;
    oauth_task.abort();
    vertex_task.abort();
}

#[tokio::test]
async fn aws_irsa_and_azure_workload_identity_reread_rotated_token_files() {
    let tmp_dir = std::env::temp_dir().join(format!("shunt-rfc0014-e2e-{}", std::process::id()));
    let _ = std::fs::create_dir_all(&tmp_dir);
    let aws_tok_path = tmp_dir.join("aws-oidc-token");
    let az_tok_path = tmp_dir.join("azure-oidc-token");
    std::fs::write(&aws_tok_path, "k8s-aws-oidc-v1\n").unwrap();
    std::fs::write(&az_tok_path, "k8s-azure-oidc-v1\n").unwrap();

    // Mock AWS STS AssumeRoleWithWebIdentity endpoint.
    let (sts_addr, sts_caps, sts_task) = spawn_scripted_http(|idx, cap| {
        assert!(cap.body.contains("Action=AssumeRoleWithWebIdentity"));
        let expected_tok = if idx == 0 {
            "WebIdentityToken=k8s-aws-oidc-v1"
        } else {
            "WebIdentityToken=k8s-aws-oidc-v2"
        };
        assert!(
            cap.body.contains(expected_tok),
            "expected {expected_tok} in {}",
            cap.body
        );
        let n = idx + 1;
        (
            StatusCode::OK,
            "text/xml",
            format!(
                "<AssumeRoleWithWebIdentityResponse><AssumeRoleWithWebIdentityResult><Credentials>\
                 <AccessKeyId>ASIAIRSA{n}</AccessKeyId>\
                 <SecretAccessKey>SECRET{n}</SecretAccessKey>\
                 <SessionToken>SESS_IRSA_{n}</SessionToken>\
                 <Expiration>2099-01-01T00:00:00Z</Expiration>\
                 </Credentials></AssumeRoleWithWebIdentityResult></AssumeRoleWithWebIdentityResponse>"
            ),
        )
    })
    .await;

    // Mock Bedrock Converse upstream.
    let (bedrock_addr, bedrock_caps, bedrock_task) = spawn_scripted_http(|_, _| {
        (
            StatusCode::OK,
            "application/json",
            json!({
                "output": {"message": {"role": "assistant", "content": [{"text": "bedrock irsa ok"}]}},
                "stopReason": "end_turn",
                "usage": {"inputTokens": 3, "outputTokens": 3}
            })
            .to_string(),
        )
    })
    .await;

    // Mock Azure Entra ID token endpoint (Workload Identity).
    let (entra_addr, entra_caps, entra_task) = spawn_scripted_http(|idx, cap| {
        assert!(cap.path.contains("/tenant-abc/oauth2/v2.0/token"));
        assert!(cap.body.contains(
            "client_assertion_type=urn%3Aietf%3Aparams%3Aoauth%3Aclient-assertion-type%3Ajwt-bearer"
        ));
        let expected = if idx == 0 {
            "client_assertion=k8s-azure-oidc-v1"
        } else {
            "client_assertion=k8s-azure-oidc-v2"
        };
        assert!(
            cap.body.contains(expected),
            "expected {expected} in {}",
            cap.body
        );
        (
            StatusCode::OK,
            "application/json",
            format!(
                r#"{{"access_token":"az-wi-tok-{}","expires_in":60}}"#,
                idx + 1
            ),
        )
    })
    .await;

    // Mock Azure OpenAI upstream.
    let (azure_addr, azure_caps, azure_task) = spawn_scripted_http(|_, _| {
        (
            StatusCode::OK,
            "application/json",
            json!({
                "id": "chatcmpl_az_1",
                "object": "chat.completion",
                "model": "gpt-4o",
                "choices": [{"index": 0, "message": {"role": "assistant", "content": "azure wi ok"}, "finish_reason": "stop"}],
                "usage": {"prompt_tokens": 3, "completion_tokens": 3, "total_tokens": 6}
            })
            .to_string(),
        )
    })
    .await;

    let gw_cfg: GatewayConfig = serde_json::from_value(json!({
        "server": { "listen": "127.0.0.1:0" },
        "upstreams": [
            { "name": "bedrock", "endpoints": [format!("http://{bedrock_addr}")] },
            { "name": "azure", "endpoints": [format!("http://{azure_addr}")] }
        ],
        "routes": [
            {
                "id": "ai",
                "path_prefix": "/v1/",
                "upstream": "bedrock",
                "plugins": [
                    {
                        "name": "ai-model-router",
                        "config": {
                            "models": {
                                "bedrock-irsa": [
                                    { "provider": "bedrock", "upstream": "bedrock", "model": "anthropic.claude-3-5-sonnet" }
                                ],
                                "azure-wi": [
                                    { "provider": "azure", "upstream": "azure", "model": "gpt-4o" }
                                ]
                            }
                        }
                    },
                    {
                        "name": "ai-provider-adapter",
                        "config": {
                            "providers": {
                                "bedrock": {
                                    "dialect": "bedrock",
                                    "region": "us-east-1",
                                    "auth": {
                                        "type": "aws_iam",
                                        "mode": "web_identity",
                                        "role_arn": "arn:aws:iam::123456789012:role/shunt-bedrock",
                                        "web_identity_token_file": aws_tok_path.display().to_string(),
                                        "sts_endpoint": format!("http://{sts_addr}"),
                                        "refresh_margin_secs": 10,
                                        "max_cache_ttl_secs": 60
                                    }
                                },
                                "azure": {
                                    "dialect": "azure_openai",
                                    "auth": {
                                        "type": "azure_ad",
                                        "mode": "workload_identity",
                                        "tenant_id": "tenant-abc",
                                        "client_id": "client-xyz",
                                        "federated_token_file": az_tok_path.display().to_string(),
                                        "authority_host": format!("http://{entra_addr}"),
                                        "refresh_margin_secs": 10
                                    }
                                }
                            }
                        }
                    }
                ]
            }
        ]
    }))
    .unwrap();

    let clock = ManualClock::shared();
    let ai_metrics = Arc::new(AiMetrics::new());
    let mut plugins = PluginRegistry::new();
    register_ai_plugins(&mut plugins, Arc::clone(&ai_metrics));
    let runtime = Arc::new(RuntimeRegistry::with_clock(clock.clone()));
    let compiler = SnapshotCompiler::new(Arc::new(plugins), Arc::clone(&runtime));
    let bundle = compiler
        .compile(&LoadedConfig {
            source_name: "e2e-wi".into(),
            config: gw_cfg,
            digest: "d2".into(),
        })
        .unwrap();
    let server = GatewayServer::new(bundle.snapshot)
        .bind("127.0.0.1:0".parse().unwrap())
        .await
        .unwrap();

    // First requests read v1 projected tokens from disk.
    let (s1, j1) = post_chat(server.local_addr(), "bedrock-irsa").await;
    assert_eq!(s1, StatusCode::OK);
    assert_eq!(j1["choices"][0]["message"]["content"], "bedrock irsa ok");
    assert_eq!(
        bedrock_caps.lock().unwrap()[0].amz_token.as_deref(),
        Some("SESS_IRSA_1")
    );

    let (s2, j2) = post_chat(server.local_addr(), "azure-wi").await;
    assert_eq!(s2, StatusCode::OK);
    assert_eq!(j2["choices"][0]["message"]["content"], "azure wi ok");
    assert_eq!(
        azure_caps.lock().unwrap()[0].auth.as_deref(),
        Some("Bearer az-wi-tok-1")
    );

    // Rotate both projected OIDC token files on disk & advance clock past TTL.
    std::fs::write(&aws_tok_path, "k8s-aws-oidc-v2\n").unwrap();
    std::fs::write(&az_tok_path, "k8s-azure-oidc-v2\n").unwrap();
    clock.advance(Duration::from_secs(65));

    let (s3, _) = post_chat(server.local_addr(), "bedrock-irsa").await;
    assert_eq!(s3, StatusCode::OK);
    assert_eq!(sts_caps.lock().unwrap().len(), 2);
    assert_eq!(
        bedrock_caps.lock().unwrap()[1].amz_token.as_deref(),
        Some("SESS_IRSA_2")
    );

    let (s4, _) = post_chat(server.local_addr(), "azure-wi").await;
    assert_eq!(s4, StatusCode::OK);
    assert_eq!(entra_caps.lock().unwrap().len(), 2);
    assert_eq!(
        azure_caps.lock().unwrap()[1].auth.as_deref(),
        Some("Bearer az-wi-tok-2")
    );

    server.shutdown().await;
    sts_task.abort();
    bedrock_task.abort();
    entra_task.abort();
    azure_task.abort();
    let _ = std::fs::remove_dir_all(&tmp_dir);
}
