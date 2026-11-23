use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::Bytes;
use http::{Method, Request, Response, StatusCode, header};
use http_body_util::{BodyExt, Full};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use shunt_config::{
    AdminServer, ConfigProvider, FileConfigProvider, InlineConfigProvider, ReloadController,
    SnapshotCompiler, start_file_watcher,
};
use shunt_engine::{GatewayServer, RuntimeRegistry, ShuntBody};
use shunt_plugin_sdk::PluginRegistry;
use shunt_plugins::{DevWaterfallPlugin, PrometheusMetrics, register_builtin_plugins};
use tokio::net::{TcpListener, TcpStream};

async fn spawn_upstream(label: &'static str) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                let svc = service_fn(move |req: Request<hyper::body::Incoming>| async move {
                    let req_id = req
                        .headers()
                        .get("x-request-id")
                        .and_then(|v| v.to_str().ok())
                        .unwrap_or("")
                        .to_owned();
                    let injected = req
                        .headers()
                        .get("x-injected")
                        .and_then(|v| v.to_str().ok())
                        .unwrap_or("")
                        .to_owned();
                    let payload = format!("{label}|req_id={req_id}|injected={injected}");
                    Ok::<_, Infallible>(
                        Response::builder()
                            .status(StatusCode::OK)
                            .body(ShuntBody::full(Bytes::from(payload)))
                            .unwrap(),
                    )
                });
                let _ = http1::Builder::new()
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

fn setup_compiler() -> (Arc<SnapshotCompiler>, Arc<PrometheusMetrics>) {
    let metrics = Arc::new(PrometheusMetrics::new());
    let mut plugins = PluginRegistry::new();
    register_builtin_plugins(&mut plugins, Arc::clone(&metrics));
    let runtime = Arc::new(RuntimeRegistry::new());
    let compiler = Arc::new(SnapshotCompiler::new(Arc::new(plugins), runtime));
    (compiler, metrics)
}

// -----------------------------------------------------------------------------
// 1. Full built-in plugin chain + Prometheus metrics via Admin API
// -----------------------------------------------------------------------------

#[tokio::test]
async fn builtin_plugins_full_chain_and_prometheus_metrics() {
    let up = spawn_upstream("v1").await;

    let toml_cfg = format!(
        r#"
[server]
listen = "127.0.0.1:0"

[admin]
enabled = true
listen = "127.0.0.1:0"

[[plugins]]
name = "request-id"

[[plugins]]
name = "metrics"

[[plugins]]
name = "access-log"

[[upstreams]]
name = "api"
endpoints = ["http://{up}"]

[[routes]]
id = "main"
path_prefix = "/api"
upstream = "api"

[[routes.plugins]]
name = "cors"
[routes.plugins.config]
allow_origins = ["https://app.example.com"]
allow_credentials = true

[[routes.plugins]]
name = "bearer-auth"
[routes.plugins.config]
tokens = [{{ token = "secret-token-xyz", subject = "alice" }}]
strip_header = true

[[routes.plugins]]
name = "rate-limit"
id = "main-rl"
[routes.plugins.config]
requests_per_second = 0.01
burst = 2
key = "global"

[[routes.plugins]]
name = "header-rewrite"
[routes.plugins.config]
request_set = {{ "x-injected" = "yes" }}
response_set = {{ "x-gateway" = "shunt" }}
"#
    );

    let (compiler, metrics) = setup_compiler();
    let provider = Arc::new(InlineConfigProvider::from_toml("inline.toml", toml_cfg));
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
    let metrics_ref = Arc::clone(&metrics);
    let admin = AdminServer::new(
        controller,
        Arc::new(move || metrics_ref.render_prometheus()),
    )
    .bind("127.0.0.1:0".parse().unwrap())
    .await
    .unwrap();

    // 1. CORS preflight short-circuits with 204 (before bearer-auth!).
    let preflight = Request::builder()
        .method(Method::OPTIONS)
        .uri("/api/items")
        .header(header::ORIGIN, "https://app.example.com")
        .header(header::ACCESS_CONTROL_REQUEST_METHOD, "GET")
        .body(Full::new(Bytes::new()))
        .unwrap();
    let (st, hdrs, _) = send_h1(gw.local_addr(), preflight).await;
    assert_eq!(st, StatusCode::NO_CONTENT);
    assert_eq!(
        hdrs.get(header::ACCESS_CONTROL_ALLOW_ORIGIN).unwrap(),
        "https://app.example.com"
    );
    assert_eq!(
        hdrs.get(header::ACCESS_CONTROL_ALLOW_CREDENTIALS).unwrap(),
        "true"
    );

    // 2. Missing bearer token -> 401 Unauthorized.
    let unauth = Request::builder()
        .uri("/api/items")
        .body(Full::new(Bytes::new()))
        .unwrap();
    let (st, hdrs, _) = send_h1(gw.local_addr(), unauth).await;
    assert_eq!(st, StatusCode::UNAUTHORIZED);
    assert!(hdrs.contains_key(header::WWW_AUTHENTICATE));

    // 3. Two authorized requests succeed (burst = 2), receiving request-id, header-rewrite, CORS & rate-limit headers.
    for expected_rem in ["1", "0"] {
        let req = Request::builder()
            .uri("/api/items")
            .header(header::ORIGIN, "https://app.example.com")
            .header(header::AUTHORIZATION, "Bearer secret-token-xyz")
            .body(Full::new(Bytes::new()))
            .unwrap();
        let (st, hdrs, body) = send_h1(gw.local_addr(), req).await;
        assert_eq!(st, StatusCode::OK);
        assert_eq!(hdrs.get("x-gateway").unwrap(), "shunt");
        assert_eq!(hdrs.get("x-ratelimit-remaining").unwrap(), expected_rem);
        assert!(hdrs.contains_key("x-request-id"));
        assert_eq!(
            hdrs.get(header::ACCESS_CONTROL_ALLOW_ORIGIN).unwrap(),
            "https://app.example.com"
        );
        let text = String::from_utf8(body.to_vec()).unwrap();
        assert!(text.starts_with("v1|req_id=req-"), "got: {text}");
        assert!(text.contains("injected=yes"), "got: {text}");
    }

    // 4. Third request exceeds burst -> 429 Too Many Requests with Retry-After.
    let req3 = Request::builder()
        .uri("/api/items")
        .header(header::AUTHORIZATION, "Bearer secret-token-xyz")
        .body(Full::new(Bytes::new()))
        .unwrap();
    let (st, hdrs, _) = send_h1(gw.local_addr(), req3).await;
    assert_eq!(st, StatusCode::TOO_MANY_REQUESTS);
    assert!(hdrs.contains_key(header::RETRY_AFTER));

    // Give off-hot-path on_complete tasks a brief moment to record metrics.
    tokio::time::sleep(Duration::from_millis(30)).await;

    // 5. Scrape GET /metrics on Admin API.
    let (st, hdrs, body) = send_h1(
        admin.local_addr(),
        Request::builder()
            .uri("/metrics")
            .body(Full::new(Bytes::new()))
            .unwrap(),
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    assert!(
        hdrs.get(header::CONTENT_TYPE)
            .unwrap()
            .to_str()
            .unwrap()
            .starts_with("text/plain")
    );
    let prom = String::from_utf8(body.to_vec()).unwrap();
    assert!(
        prom.contains(r#"shunt_requests_total{route="main",upstream="api",status="200"} 2"#),
        "got:\n{prom}"
    );
    assert!(
        prom.contains(r#"shunt_requests_total{route="main",upstream="none",status="429"} 1"#),
        "got:\n{prom}"
    );
    assert!(prom.contains("shunt_request_duration_seconds_bucket"));
    assert!(prom.contains("shunt_upstream_ttfb_seconds_bucket"));

    admin.shutdown().await;
    assert!(gw.shutdown().await);
}

// -----------------------------------------------------------------------------
// 2. Admin API (/health, /snapshot secret redaction, POST /reload fail-safe + StateStore survival)
// -----------------------------------------------------------------------------

#[tokio::test]
async fn admin_api_snapshot_redaction_and_atomic_reload_preserves_rate_limit_state() {
    let up1 = spawn_upstream("backend-v1").await;
    let up2 = spawn_upstream("backend-v2").await;

    let tmp_dir = std::env::temp_dir().join(format!(
        "shunt-test-admin-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&tmp_dir).unwrap();
    let cfg_path = tmp_dir.join("shunt.toml");

    let cfg_v1 = format!(
        r#"
[server]
listen = "127.0.0.1:0"

[admin]
enabled = true
listen = "127.0.0.1:0"

[[plugins]]
name = "bearer-auth"
[plugins.config]
tokens = ["super-secret-token-123"]

[[upstreams]]
name = "svc"
endpoints = ["http://{up1}"]

[[routes]]
id = "api"
path_prefix = "/"
upstream = "svc"

[[routes.plugins]]
name = "rate-limit"
id = "stable-bucket"
[routes.plugins.config]
requests_per_second = 0.001
burst = 2
key = "global"
"#
    );
    std::fs::write(&cfg_path, &cfg_v1).unwrap();

    let (compiler, metrics) = setup_compiler();
    let provider = Arc::new(FileConfigProvider::new(&cfg_path));
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
    let admin = AdminServer::new(controller, Arc::new(move || metrics.render_prometheus()))
        .bind("127.0.0.1:0".parse().unwrap())
        .await
        .unwrap();

    // Check GET /health
    let (st, _, body) = send_h1(
        admin.local_addr(),
        Request::builder()
            .uri("/health")
            .body(Full::new(Bytes::new()))
            .unwrap(),
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    let health: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(health["status"], "ok");
    assert_eq!(health["version"], 1);

    // Check GET /snapshot redacts secrets
    let (st, _, body) = send_h1(
        admin.local_addr(),
        Request::builder()
            .uri("/snapshot")
            .body(Full::new(Bytes::new()))
            .unwrap(),
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    let snap_str = String::from_utf8(body.to_vec()).unwrap();
    assert!(
        !snap_str.contains("super-secret-token-123"),
        "secret leaked in /snapshot: {snap_str}"
    );
    assert!(
        snap_str.contains("[REDACTED]"),
        "expected redaction marker: {snap_str}"
    );

    // Consume 1 of 2 rate-limit tokens on v1.
    let (st, hdrs, body) = send_h1(
        gw.local_addr(),
        Request::builder()
            .uri("/hello")
            .header(header::AUTHORIZATION, "Bearer super-secret-token-123")
            .body(Full::new(Bytes::new()))
            .unwrap(),
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(hdrs.get("x-ratelimit-remaining").unwrap(), "1");
    assert!(String::from_utf8_lossy(&body).starts_with("backend-v1"));

    // Write INVALID config -> POST /reload fails atomically with 422, v1 stays active!
    std::fs::write(
        &cfg_path,
        r#"
[server]
listen = "127.0.0.1:0"
[[routes]]
id = "broken"
upstream = "does-not-exist"
"#,
    )
    .unwrap();

    let (st, _, body) = send_h1(
        admin.local_addr(),
        Request::builder()
            .method(Method::POST)
            .uri("/reload")
            .body(Full::new(Bytes::new()))
            .unwrap(),
    )
    .await;
    assert_eq!(st, StatusCode::UNPROCESSABLE_ENTITY);
    let err_json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(err_json["reloaded"], false);
    assert!(
        err_json["error"]
            .as_str()
            .unwrap()
            .contains("does-not-exist")
    );

    // Write VALID v2 config pointing to backend-v2 -> POST /reload succeeds!
    let cfg_v2 = cfg_v1.replace(&format!("http://{up1}"), &format!("http://{up2}"));
    std::fs::write(&cfg_path, &cfg_v2).unwrap();

    let (st, _, body) = send_h1(
        admin.local_addr(),
        Request::builder()
            .method(Method::POST)
            .uri("/reload")
            .body(Full::new(Bytes::new()))
            .unwrap(),
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    let ok_json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(ok_json["reloaded"], true);
    assert_eq!(ok_json["snapshot"]["version"], 2);

    // Traffic now hits backend-v2 AND rate-limit state survived reload (remaining drops from 1 -> 0, then 429)!
    let (st, hdrs, body) = send_h1(
        gw.local_addr(),
        Request::builder()
            .uri("/hello")
            .header(header::AUTHORIZATION, "Bearer super-secret-token-123")
            .body(Full::new(Bytes::new()))
            .unwrap(),
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(hdrs.get("x-ratelimit-remaining").unwrap(), "0");
    assert!(String::from_utf8_lossy(&body).starts_with("backend-v2"));

    let (st, _, _) = send_h1(
        gw.local_addr(),
        Request::builder()
            .uri("/hello")
            .header(header::AUTHORIZATION, "Bearer super-secret-token-123")
            .body(Full::new(Bytes::new()))
            .unwrap(),
    )
    .await;
    assert_eq!(st, StatusCode::TOO_MANY_REQUESTS);

    admin.shutdown().await;
    assert!(gw.shutdown().await);
    let _ = std::fs::remove_dir_all(&tmp_dir);
}

// -----------------------------------------------------------------------------
// 3. File watcher auto-reloads on disk modification
// -----------------------------------------------------------------------------

#[tokio::test]
async fn file_watcher_auto_reloads_on_disk_edit() {
    let up1 = spawn_upstream("watch-v1").await;
    let up2 = spawn_upstream("watch-v2").await;

    let tmp_dir = std::env::temp_dir().join(format!(
        "shunt-test-watch-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&tmp_dir).unwrap();
    let cfg_path = tmp_dir.join("shunt.toml");

    let make_cfg = |up: SocketAddr| {
        format!(
            r#"
[server]
listen = "127.0.0.1:0"
[admin]
enabled = false
[[upstreams]]
name = "app"
endpoints = ["http://{up}"]
[[routes]]
id = "root"
path_prefix = "/"
upstream = "app"
"#
        )
    };
    std::fs::write(&cfg_path, make_cfg(up1)).unwrap();

    let (compiler, _) = setup_compiler();
    let provider = Arc::new(FileConfigProvider::new(&cfg_path));
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
    let watcher = start_file_watcher(
        vec![cfg_path.clone()],
        controller,
        Duration::from_millis(50),
    )
    .unwrap();

    let (_, _, body) = send_h1(
        gw.local_addr(),
        Request::builder()
            .uri("/")
            .body(Full::new(Bytes::new()))
            .unwrap(),
    )
    .await;
    assert!(String::from_utf8_lossy(&body).starts_with("watch-v1"));

    // Modify shunt.toml on disk and wait for watcher to swap snapshot automatically.
    std::fs::write(&cfg_path, make_cfg(up2)).unwrap();

    let mut swapped = false;
    for _ in 0..40 {
        tokio::time::sleep(Duration::from_millis(50)).await;
        let (_, _, body) = send_h1(
            gw.local_addr(),
            Request::builder()
                .uri("/")
                .body(Full::new(Bytes::new()))
                .unwrap(),
        )
        .await;
        if String::from_utf8_lossy(&body).starts_with("watch-v2") {
            swapped = true;
            break;
        }
    }
    assert!(
        swapped,
        "file watcher did not hot-reload shunt.toml in time"
    );

    watcher.stop();
    assert!(gw.shutdown().await);
    let _ = std::fs::remove_dir_all(&tmp_dir);
}

// -----------------------------------------------------------------------------
// 4. YAML config + `shunt dev` waterfall microsecond trace output
// -----------------------------------------------------------------------------

#[tokio::test]
async fn yaml_config_and_dev_waterfall_trace() {
    let up = spawn_upstream("yaml-ok").await;

    let tmp_dir = std::env::temp_dir().join(format!(
        "shunt-test-yaml-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&tmp_dir).unwrap();
    let yaml_path = tmp_dir.join("shunt.yaml");

    let yaml = format!(
        r#"
server:
  listen: "127.0.0.1:0"
admin:
  enabled: false
upstreams:
  - name: backend
    endpoints:
      - "http://{up}"
routes:
  - id: demo
    path_prefix: "/demo"
    upstream: backend
    plugins:
      - name: request-id
      - name: header-rewrite
        config:
          response_set:
            x-mode: dev
"#
    );
    std::fs::write(&yaml_path, yaml).unwrap();

    let lines = Arc::new(Mutex::new(Vec::<String>::new()));
    let lines_sink = Arc::clone(&lines);
    let waterfall = Arc::new(DevWaterfallPlugin::with_sink(Arc::new(move |line| {
        lines_sink.lock().unwrap().push(line);
    })));

    let metrics = Arc::new(PrometheusMetrics::new());
    let mut plugins = PluginRegistry::new();
    register_builtin_plugins(&mut plugins, metrics);
    let runtime = Arc::new(RuntimeRegistry::new());
    let compiler =
        SnapshotCompiler::new(Arc::new(plugins), runtime).with_extra_global_plugin(waterfall);

    let loaded = FileConfigProvider::new(&yaml_path).load().unwrap();
    let bundle = compiler.compile(&loaded).unwrap();

    let gw = GatewayServer::new(bundle.snapshot)
        .with_trace_enabled(true)
        .bind("127.0.0.1:0".parse().unwrap())
        .await
        .unwrap();

    let (st, hdrs, _) = send_h1(
        gw.local_addr(),
        Request::builder()
            .uri("/demo/hello")
            .body(Full::new(Bytes::new()))
            .unwrap(),
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(hdrs.get("x-mode").unwrap(), "dev");

    tokio::time::sleep(Duration::from_millis(30)).await;
    {
        let captured = lines.lock().unwrap();
        assert_eq!(captured.len(), 1);
        let line = &captured[0];
        assert!(line.contains("200 GET /demo/hello"), "got: {line}");
        assert!(line.contains("request-id:"), "got: {line}");
        assert!(line.contains("header-rewrite:"), "got: {line}");
        assert!(line.contains("upstream TTFB:"), "got: {line}");
        assert!(line.contains("total:"), "got: {line}");
    }

    assert!(gw.shutdown().await);
    let _ = std::fs::remove_dir_all(&tmp_dir);
}
