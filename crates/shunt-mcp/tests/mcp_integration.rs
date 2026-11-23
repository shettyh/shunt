use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use bytes::Bytes;
use http::{Method, Request, Response, StatusCode, header};
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::client::legacy::Client;
use hyper_util::rt::{TokioExecutor, TokioIo};
use serde_json::{Value, json};
use shunt_config::{
    FileConfigProvider, GatewayConfig, LoadedConfig, SnapshotCompiler, verify_bundle,
};
use shunt_engine::{GatewayServer, RuntimeRegistry};
use shunt_mcp::{McpMetrics, register_mcp_plugins};
use shunt_plugin_sdk::{ManualClock, PluginRegistry};
use shunt_plugins::{PrometheusMetrics, register_builtin_plugins};
use tokio::net::TcpListener;

async fn spawn_test_server<F, Fut>(handler: F) -> SocketAddr
where
    F: Fn(Request<Incoming>) -> Fut + Send + Sync + 'static,
    Fut: std::future::Future<Output = Response<Full<Bytes>>> + Send + 'static,
{
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handler = Arc::new(handler);
    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                break;
            };
            let h = Arc::clone(&handler);
            tokio::spawn(async move {
                let io = TokioIo::new(stream);
                let svc = service_fn(move |req| {
                    let h = Arc::clone(&h);
                    async move { Ok::<_, std::convert::Infallible>(h(req).await) }
                });
                let _ = http1::Builder::new().serve_connection(io, svc).await;
            });
        }
    });
    addr
}

async fn send_post(
    addr: SocketAddr,
    path: &str,
    headers: &[(&str, &str)],
    body: Value,
) -> (StatusCode, http::HeaderMap, Value) {
    let client = Client::builder(TokioExecutor::new()).build_http::<Full<Bytes>>();
    let mut builder = Request::builder()
        .method(Method::POST)
        .uri(format!("http://{addr}{path}"))
        .header(header::CONTENT_TYPE, "application/json");
    for (k, v) in headers {
        builder = builder.header(*k, *v);
    }
    let req = builder
        .body(Full::new(Bytes::from(serde_json::to_vec(&body).unwrap())))
        .unwrap();
    let resp = client.request(req).await.unwrap();
    let status = resp.status();
    let resp_headers = resp.headers().clone();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let json = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    (status, resp_headers, json)
}

#[tokio::test]
async fn stateful_upstream_handshake_and_opa_webhook_and_distributed_rate_limit() {
    let init_calls = Arc::new(AtomicUsize::new(0));
    let init_calls_c = Arc::clone(&init_calls);

    // Stateful MCP upstream that requires `initialize` -> returns `Mcp-Session-Id: up-sess-99`
    // and enforces `Mcp-Session-Id == up-sess-99` on `tools/call`.
    let stateful_addr = spawn_test_server(move |req: Request<Incoming>| {
        let init_calls = Arc::clone(&init_calls_c);
        async move {
            let sid_hdr = req
                .headers()
                .get("mcp-session-id")
                .and_then(|v| v.to_str().ok())
                .map(str::to_owned);
            let bytes = req.into_body().collect().await.unwrap().to_bytes();
            let doc: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
            let method = doc.get("method").and_then(Value::as_str).unwrap_or("");

            if method == "initialize" {
                init_calls.fetch_add(1, Ordering::SeqCst);
                return Response::builder()
                    .status(StatusCode::OK)
                    .header(header::CONTENT_TYPE, "application/json")
                    .header("mcp-session-id", "up-sess-99")
                    .body(Full::new(Bytes::from(
                        serde_json::to_vec(&json!({
                            "jsonrpc": "2.0",
                            "id": doc.get("id").cloned().unwrap_or(Value::Null),
                            "result": { "protocolVersion": "2025-06-18", "capabilities": {} }
                        }))
                        .unwrap(),
                    )))
                    .unwrap();
            }
            if method == "notifications/initialized" {
                return Response::builder()
                    .status(StatusCode::ACCEPTED)
                    .body(Full::new(Bytes::new()))
                    .unwrap();
            }
            if sid_hdr.as_deref() != Some("up-sess-99") {
                return Response::builder()
                    .status(StatusCode::BAD_REQUEST)
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Full::new(Bytes::from(
                        b"{\"jsonrpc\":\"2.0\",\"id\":1,\"error\":{\"code\":-32000,\"message\":\"missing upstream session\"}}".to_vec(),
                    )))
                    .unwrap();
            }
            Response::builder()
                .status(StatusCode::OK)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Full::new(Bytes::from(
                    serde_json::to_vec(&json!({
                        "jsonrpc": "2.0",
                        "id": doc.get("id").cloned().unwrap_or(Value::Null),
                        "result": {
                            "content": [{ "type": "text", "text": format!("ok:{}", doc["params"]["name"].as_str().unwrap_or("")) }],
                            "isError": false
                        }
                    }))
                    .unwrap(),
                )))
                .unwrap()
        }
    })
    .await;

    // External OPA-style policy webhook: denies when arguments.env == "prod"
    let opa_addr = spawn_test_server(|req: Request<Incoming>| async move {
        let bytes = req.into_body().collect().await.unwrap().to_bytes();
        let doc: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
        let env = doc["arguments"]["env"].as_str().unwrap_or("");
        let resp_body = if env == "prod" {
            json!({ "result": { "allow": false, "reason": "OPA policy forbids prod mutations" } })
        } else {
            json!({ "result": { "allow": true } })
        };
        Response::builder()
            .status(StatusCode::OK)
            .header(header::CONTENT_TYPE, "application/json")
            .body(Full::new(Bytes::from(
                serde_json::to_vec(&resp_body).unwrap(),
            )))
            .unwrap()
    })
    .await;

    let toml_cfg = format!(
        r#"
[server]
listen = "127.0.0.1:0"

[[upstreams]]
name = "deploy_mcp"
endpoints = ["http://{stateful_addr}"]

[[routes]]
id = "mcp_stateful_opa"
path_prefix = "/mcp"
methods = ["POST", "DELETE"]
upstream = "deploy_mcp"

[[routes.plugins]]
name = "mcp-auth"
[routes.plugins.config]
identity_header = "x-trusted-sub"
[[routes.plugins.config.keys]]
id = "svc-deployer"
max_calls_per_session = 2

[[routes.plugins]]
name = "mcp-router"
[routes.plugins.config]
[routes.plugins.config.servers.deploy]
upstream = "deploy_mcp"
endpoint = "http://{stateful_addr}/mcp"
path = "/mcp"
stateful = true

[[routes.plugins]]
name = "mcp-guardrails"
[routes.plugins.config]
[routes.plugins.config.policy_webhook]
url = "http://{opa_addr}/v1/data/mcp/allow"
timeout_ms = 2000
fail_open = false

[[routes.plugins]]
name = "mcp-rate-limit"
[routes.plugins.config]
max_calls_per_session = 10

[[routes.plugins]]
name = "mcp-telemetry"
"#
    );

    let config: GatewayConfig = toml::from_str(&toml_cfg).unwrap();
    let loaded = LoadedConfig {
        source_name: "inline".to_owned(),
        config,
        digest: "test".to_owned(),
    };

    let clock = ManualClock::shared();
    let metrics = Arc::new(PrometheusMetrics::new());
    let mcp_metrics = Arc::new(McpMetrics::new());
    let mut reg = PluginRegistry::new();
    register_builtin_plugins(&mut reg, Arc::clone(&metrics));
    register_mcp_plugins(&mut reg, Arc::clone(&mcp_metrics));
    let runtime = Arc::new(RuntimeRegistry::with_clock(clock.clone()));
    let compiler = SnapshotCompiler::new(Arc::new(reg), runtime);
    let bundle = compiler.compile(&loaded).unwrap();

    // Also verify `shunt verify` reports 0 errors on valid MCP config
    let report = verify_bundle(&bundle, None, false);
    assert!(
        report.passed,
        "expected verify pass: {:?}",
        report.diagnostics
    );

    let gw = GatewayServer::new(bundle.snapshot)
        .bind("127.0.0.1:0".parse().unwrap())
        .await
        .unwrap();
    let gw_addr = gw.local_addr();

    // 1. Initialize virtual session as `svc-deployer` via trusted identity_header
    let (status, hdrs, _) = send_post(
        gw_addr,
        "/mcp",
        &[("x-trusted-sub", "svc-deployer")],
        json!({ "jsonrpc": "2.0", "id": 1, "method": "initialize", "params": { "protocolVersion": "2025-06-18" } }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let gw_sid = hdrs
        .get("mcp-session-id")
        .unwrap()
        .to_str()
        .unwrap()
        .to_owned();

    // 2. OPA webhook denies `env = "prod"`
    let (status, _, body) = send_post(
        gw_addr,
        "/mcp",
        &[("x-trusted-sub", "svc-deployer"), ("mcp-session-id", &gw_sid)],
        json!({ "jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": { "name": "deploy__rollout", "arguments": { "env": "prod" } } }),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(body["error"]["code"], -32030);
    assert!(body["error"]["message"].as_str().unwrap().contains("OPA"));

    // 3. First allowed call lazily initializes stateful backend session (init_calls == 1)
    let (status, _, body) = send_post(
        gw_addr,
        "/mcp",
        &[("x-trusted-sub", "svc-deployer"), ("mcp-session-id", &gw_sid)],
        json!({ "jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": { "name": "deploy__rollout", "arguments": { "env": "staging" } } }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["result"]["content"][0]["text"], "ok:rollout");
    assert_eq!(init_calls.load(Ordering::SeqCst), 1);

    // 4. Second allowed call reuses cached upstream session (init_calls still == 1)
    let (status, _, _) = send_post(
        gw_addr,
        "/mcp",
        &[("x-trusted-sub", "svc-deployer"), ("mcp-session-id", &gw_sid)],
        json!({ "jsonrpc": "2.0", "id": 4, "method": "tools/call", "params": { "name": "deploy__rollout", "arguments": { "env": "dev" } } }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(init_calls.load(Ordering::SeqCst), 1);

    // 5. Third call exceeds principal `max_calls_per_session = 2` via DistributedStore
    let (status, _, body) = send_post(
        gw_addr,
        "/mcp",
        &[("x-trusted-sub", "svc-deployer"), ("mcp-session-id", &gw_sid)],
        json!({ "jsonrpc": "2.0", "id": 5, "method": "tools/call", "params": { "name": "deploy__rollout", "arguments": { "env": "qa" } } }),
    )
    .await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(body["error"]["code"], -32029);
    assert_eq!(body["error"]["data"]["reason"], "session_cap");

    gw.shutdown().await;
}

#[test]
fn verify_detects_mcp_plugin_order_and_unknown_upstream() {
    let bad_toml = r#"
[server]
listen = "127.0.0.1:0"

[[upstreams]]
name = "known_up"
endpoints = ["http://127.0.0.1:9999"]

[[routes]]
id = "bad_mcp"
path_prefix = "/mcp"
upstream = "known_up"

[[routes.plugins]]
name = "mcp-guardrails"

[[routes.plugins]]
name = "mcp-router"
[routes.plugins.config.servers.ghost]
upstream = "missing_up"

[[routes.plugins]]
name = "mcp-auth"
[routes.plugins.config]
identity_header = "x-sub"
allow_unlisted_identities = true
"#;
    let config: GatewayConfig = toml::from_str(bad_toml).unwrap();
    let loaded = LoadedConfig {
        source_name: "bad.toml".to_owned(),
        config,
        digest: "bad".to_owned(),
    };
    let mcp_metrics = Arc::new(McpMetrics::new());
    let mut reg = PluginRegistry::new();
    register_mcp_plugins(&mut reg, mcp_metrics);
    let compiler = SnapshotCompiler::new(Arc::new(reg), Arc::new(RuntimeRegistry::new()));
    let bundle = compiler.compile(&loaded).unwrap();
    let report = verify_bundle(&bundle, None, false);
    assert!(!report.passed);
    let rules: Vec<&str> = report.diagnostics.iter().map(|d| d.rule.as_str()).collect();
    assert!(rules.contains(&"mcp.plugin_order"), "got {rules:?}");
    assert!(rules.contains(&"mcp.unknown_upstream"), "got {rules:?}");

    // Ensure example config verifies cleanly with env vars set
    let _ = FileConfigProvider::new("examples/shunt-mcp-gateway.toml");
}
