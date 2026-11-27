use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use http::{Request, StatusCode, header};
use http_body_util::{BodyExt, Full};
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;
use serde_json::Value;
use shunt_config::{
    AdminServer, ConfigProvider, InlineConfigProvider, InspectorCapturePlugin, ReloadController,
    SnapshotCompiler, TraceRingBuffer, verify_bundle,
};
use shunt_engine::{GatewayServer, RuntimeRegistry};
use shunt_plugin_sdk::{PluginRegistry, RequestCtx};
use shunt_plugins::{PrometheusMetrics, register_builtin_plugins};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

async fn spawn_echo_upstream() -> (std::net::SocketAddr, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move {
        while let Ok((mut sock, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut buf = [0u8; 2048];
                let _ = sock.read(&mut buf).await;
                let resp = "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: 11\r\nconnection: close\r\n\r\n{\"ok\":true}";
                let _ = sock.write_all(resp.as_bytes()).await;
            });
        }
    });
    (addr, handle)
}

fn make_toml(upstream_addr: std::net::SocketAddr, ui: bool) -> String {
    format!(
        r#"
[server]
listen = "127.0.0.1:0"

[admin]
enabled = true
listen = "127.0.0.1:0"
ui = {ui}
ui_trace_capacity = 32

[[plugins]]
name = "request-id"

[[upstreams]]
name = "backend"
endpoints = ["http://{upstream_addr}"]

[[routes]]
id = "api"
path_prefix = "/api"
upstream = "backend"
[[routes.plugins]]
name = "header-rewrite"
[routes.plugins.config]
response_add = {{ "x-demo" = "yes" }}
"#
    )
}

#[tokio::test]
async fn admin_ui_disabled_returns_404_for_ui_and_traces() {
    let (up_addr, up_task) = spawn_echo_upstream().await;

    let metrics = Arc::new(PrometheusMetrics::new());
    let mut reg = PluginRegistry::new();
    register_builtin_plugins(&mut reg, Arc::clone(&metrics));
    let runtime = Arc::new(RuntimeRegistry::new());
    let compiler = Arc::new(SnapshotCompiler::new(Arc::new(reg), runtime));
    let provider = Arc::new(InlineConfigProvider::from_toml(
        "ui-off.toml",
        make_toml(up_addr, false),
    ));

    let loaded = provider.load().unwrap();
    let bundle = compiler.compile(&loaded).unwrap();
    let gw = GatewayServer::new(bundle.snapshot)
        .bind("127.0.0.1:0".parse().unwrap())
        .await
        .unwrap();
    let controller = Arc::new(ReloadController::new(
        provider,
        compiler,
        gw.reloader(),
        bundle.inspect,
    ));
    let admin = AdminServer::new(controller, Arc::new(String::new))
        .bind("127.0.0.1:0".parse().unwrap())
        .await
        .unwrap();

    let client = Client::builder(TokioExecutor::new()).build_http::<Full<Bytes>>();
    for path in ["/", "/ui", "/api/traces", "/api/traces/stream"] {
        let req = Request::builder()
            .uri(format!("http://{}{path}", admin.local_addr()))
            .body(Full::new(Bytes::new()))
            .unwrap();
        let resp = client.request(req).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::NOT_FOUND,
            "expected 404 for {path} when UI is disabled"
        );
    }

    // /api/status still works and reports ui_enabled = false
    let req = Request::builder()
        .uri(format!("http://{}/api/status", admin.local_addr()))
        .body(Full::new(Bytes::new()))
        .unwrap();
    let resp = client.request(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let json: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["ui_enabled"], false);
    assert_eq!(json["trace_capture_enabled"], false);

    admin.shutdown().await;
    gw.shutdown().await;
    up_task.abort();
}

#[tokio::test]
async fn admin_ui_enabled_serves_html_captures_traces_and_streams_sse() {
    let (up_addr, up_task) = spawn_echo_upstream().await;

    let metrics = Arc::new(PrometheusMetrics::new());
    let mut reg = PluginRegistry::new();
    register_builtin_plugins(&mut reg, Arc::clone(&metrics));
    let runtime = Arc::new(RuntimeRegistry::new());
    let trace_store = Arc::new(TraceRingBuffer::new(32));
    let compiler = Arc::new(
        SnapshotCompiler::new(Arc::new(reg), runtime).with_extra_global_plugin(Arc::new(
            InspectorCapturePlugin::new(Arc::clone(&trace_store)),
        )),
    );
    let provider = Arc::new(InlineConfigProvider::from_toml(
        "ui-on.toml",
        make_toml(up_addr, true),
    ));

    let loaded = provider.load().unwrap();
    let bundle = compiler.compile(&loaded).unwrap();
    let gw = GatewayServer::new(bundle.snapshot)
        .with_trace_enabled(true)
        .bind("127.0.0.1:0".parse().unwrap())
        .await
        .unwrap();
    let controller = Arc::new(ReloadController::new(
        provider,
        compiler,
        gw.reloader(),
        bundle.inspect,
    ));
    let admin = AdminServer::new(controller, Arc::new(String::new))
        .with_ui_enabled(true)
        .with_trace_store(Arc::clone(&trace_store))
        .with_status_provider("custom", Arc::new(|| serde_json::json!({ "ready": true })))
        .bind("127.0.0.1:0".parse().unwrap())
        .await
        .unwrap();

    let client = Client::builder(TokioExecutor::new()).build_http::<Full<Bytes>>();

    // 1. Embedded HTML served at / and /ui with strict security headers
    for path in ["/", "/ui"] {
        let req = Request::builder()
            .uri(format!("http://{}{path}", admin.local_addr()))
            .body(Full::new(Bytes::new()))
            .unwrap();
        let resp = client.request(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert!(
            resp.headers()
                .get(header::CONTENT_TYPE)
                .unwrap()
                .to_str()
                .unwrap()
                .contains("text/html")
        );
        assert_eq!(resp.headers().get("x-frame-options").unwrap(), "DENY");
        assert_eq!(
            resp.headers().get("x-content-type-options").unwrap(),
            "nosniff"
        );
        assert!(resp.headers().contains_key("content-security-policy"));
        let html = String::from_utf8(
            resp.into_body()
                .collect()
                .await
                .unwrap()
                .to_bytes()
                .to_vec(),
        )
        .unwrap();
        assert!(html.contains("Shunt Admin Inspector"));
    }

    // 2. Snapshot exposes per-route plugin_details with HookMask flags
    let snap_resp = client
        .request(
            Request::builder()
                .uri(format!("http://{}/snapshot", admin.local_addr()))
                .body(Full::new(Bytes::new()))
                .unwrap(),
        )
        .await
        .unwrap();
    let snap_json: Value =
        serde_json::from_slice(&snap_resp.into_body().collect().await.unwrap().to_bytes()).unwrap();
    let details = snap_json["routes"][0]["plugin_details"].as_array().unwrap();
    assert_eq!(details.len(), 1);
    assert_eq!(details[0]["name"], "header-rewrite");
    assert!(details[0]["hook_mask"].is_array());

    // 3. Status exposes pluggable extension
    let st_resp = client
        .request(
            Request::builder()
                .uri(format!("http://{}/api/status", admin.local_addr()))
                .body(Full::new(Bytes::new()))
                .unwrap(),
        )
        .await
        .unwrap();
    let st_json: Value =
        serde_json::from_slice(&st_resp.into_body().collect().await.unwrap().to_bytes()).unwrap();
    assert_eq!(st_json["ui_enabled"], true);
    assert_eq!(st_json["trace_capture_enabled"], true);
    assert_eq!(st_json["extensions"]["custom"]["ready"], true);

    // 4. Send two gateway requests; verify ring buffer captures per-hook timings
    for i in 1..=2 {
        let req = Request::builder()
            .uri(format!("http://{}/api/hello-{i}", gw.local_addr()))
            .body(Full::new(Bytes::new()))
            .unwrap();
        let resp = client.request(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let _ = resp.into_body().collect().await.unwrap();
    }
    tokio::time::sleep(Duration::from_millis(40)).await;

    let tr_resp = client
        .request(
            Request::builder()
                .uri(format!("http://{}/api/traces", admin.local_addr()))
                .body(Full::new(Bytes::new()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(tr_resp.status(), StatusCode::OK);
    let tr_json: Value =
        serde_json::from_slice(&tr_resp.into_body().collect().await.unwrap().to_bytes()).unwrap();
    assert_eq!(tr_json["summary"]["total_recorded"], 2);
    let traces = tr_json["traces"].as_array().unwrap();
    assert_eq!(traces.len(), 2);
    assert_eq!(traces[0]["path"], "/api/hello-1");
    assert_eq!(traces[1]["path"], "/api/hello-2");
    assert!(!traces[0]["hooks"].as_array().unwrap().is_empty());

    // 5. Connect to live SSE stream with `Last-Event-ID: 1`: must replay #2 and stream live #3
    let sse_req = Request::builder()
        .uri(format!("http://{}/api/traces/stream", admin.local_addr()))
        .header("last-event-id", "1")
        .body(Full::new(Bytes::new()))
        .unwrap();
    let sse_resp = client.request(sse_req).await.unwrap();
    assert_eq!(sse_resp.status(), StatusCode::OK);
    assert!(
        sse_resp
            .headers()
            .get(header::CONTENT_TYPE)
            .unwrap()
            .to_str()
            .unwrap()
            .contains("text/event-stream")
    );

    let mut sse_body = sse_resp.into_body();

    // Trigger live request #3 while SSE stream is open
    let req3 = Request::builder()
        .uri(format!("http://{}/api/live-3", gw.local_addr()))
        .body(Full::new(Bytes::new()))
        .unwrap();
    let resp3 = client.request(req3).await.unwrap();
    assert_eq!(resp3.status(), StatusCode::OK);
    let _ = resp3.into_body().collect().await.unwrap();

    let mut received = String::new();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(3);
    while tokio::time::Instant::now() < deadline {
        match tokio::time::timeout(Duration::from_millis(500), sse_body.frame()).await {
            Ok(Some(Ok(frame))) => {
                if let Ok(data) = frame.into_data() {
                    received.push_str(&String::from_utf8_lossy(&data));
                    if received.contains("/api/live-3") {
                        break;
                    }
                }
            }
            _ => break,
        }
    }
    assert!(
        !received.contains("/api/hello-1"),
        "Last-Event-ID: 1 must skip seq 1: {received}"
    );
    assert!(
        received.contains("/api/hello-2"),
        "expected replay of seq 2: {received}"
    );
    assert!(
        received.contains("/api/live-3"),
        "expected live streamed seq 3: {received}"
    );

    // 6. Admin shutdown must complete promptly even while an SSE stream is open
    let shutdown_res = tokio::time::timeout(Duration::from_secs(2), admin.shutdown()).await;
    assert!(
        shutdown_res.is_ok(),
        "admin.shutdown() must not hang with active SSE clients"
    );
    gw.shutdown().await;
    up_task.abort();
}

#[test]
fn validates_admin_ui_constraints_and_warns_on_non_loopback() {
    let invalid = InlineConfigProvider::from_toml(
        "bad-ui.toml",
        r#"
[server]
listen = "127.0.0.1:0"
[admin]
enabled = false
ui = true
ui_trace_capacity = 0
[[upstreams]]
name = "u1"
endpoints = ["http://127.0.0.1:8080"]
[[routes]]
id = "r1"
path_prefix = "/"
upstream = "u1"
"#,
    )
    .load()
    .unwrap();
    let err = invalid.config.validate().unwrap_err().to_string();
    assert!(err.contains("admin.ui"), "got: {err}");
    assert!(err.contains("ui_trace_capacity"), "got: {err}");

    let non_loopback = InlineConfigProvider::from_toml(
        "public-ui.toml",
        r#"
[server]
listen = "127.0.0.1:8080"
[admin]
enabled = true
listen = "0.0.0.0:9090"
ui = true
[[upstreams]]
name = "u1"
endpoints = ["http://127.0.0.1:8081"]
[[routes]]
id = "r1"
path_prefix = "/"
upstream = "u1"
"#,
    )
    .load()
    .unwrap();
    let compiler = SnapshotCompiler::new(
        Arc::new(PluginRegistry::new()),
        Arc::new(RuntimeRegistry::new()),
    );
    let bundle = compiler.compile(&non_loopback).unwrap();
    let report = verify_bundle(&bundle, None, false);
    assert!(
        report
            .diagnostics
            .iter()
            .any(|d| d.rule == "admin.ui_non_loopback"),
        "expected admin.ui_non_loopback warning: {:?}",
        report.diagnostics
    );

    // Quick sanity check that RequestCtx::annotate_* is a no-op when no collectors attached
    let ctx = RequestCtx::new(1, "127.0.0.1:1234".parse().unwrap(), None);
    assert!(!ctx.has_trace_collectors());
    ctx.annotate_str("k", "v");
}
