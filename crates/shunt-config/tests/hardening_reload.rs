use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Duration;

use bytes::Bytes;
use http::{Method, Request, Response, StatusCode};
use http_body_util::{BodyExt, Full};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::client::legacy::Client;
use hyper_util::rt::{TokioExecutor, TokioIo};
use shunt_config::{
    AdminServer, ConfigProvider, FileConfigProvider, ReloadController, SnapshotCompiler,
};
use shunt_engine::{GatewayServer, RuntimeRegistry};
use shunt_plugin_sdk::PluginRegistry;
use shunt_plugins::{PrometheusMetrics, register_builtin_plugins};
use tokio::net::TcpListener;

async fn spawn_ok_upstream() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                let svc = service_fn(|_req: Request<hyper::body::Incoming>| async move {
                    Ok::<_, Infallible>(
                        Response::builder()
                            .status(StatusCode::OK)
                            .body(Full::new(Bytes::from_static(b"ok")))
                            .unwrap(),
                    )
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

#[tokio::test]
async fn rapid_corrupt_and_valid_reloads_preserve_lkg_and_rate_limit_state() {
    let upstream = spawn_ok_upstream().await;

    let tmp_dir = std::env::temp_dir().join(format!("shunt-hardening-{}", std::process::id()));
    let _ = std::fs::create_dir_all(&tmp_dir);
    let cfg_path = tmp_dir.join("shunt.toml");

    let make_valid_toml = |header_val: &str| {
        format!(
            r#"
[server]
listen = "127.0.0.1:0"

[admin]
enabled = true
listen = "127.0.0.1:0"

[[upstreams]]
name = "backend"
endpoints = ["http://{upstream}"]

[[routes]]
id = "api"
path_prefix = "/api"
upstream = "backend"

[[routes.plugins]]
name = "header-rewrite"
[routes.plugins.config]
response_set = {{ "x-config-gen" = "{header_val}" }}

[[routes.plugins]]
name = "rate-limit"
id = "sticky-rl"
[routes.plugins.config]
requests_per_second = 0.01
burst = 5
key = "global"
"#
        )
    };

    std::fs::write(&cfg_path, make_valid_toml("gen-1")).unwrap();

    let metrics = Arc::new(PrometheusMetrics::new());
    let mut reg = PluginRegistry::new();
    register_builtin_plugins(&mut reg, Arc::clone(&metrics));
    let runtime = Arc::new(RuntimeRegistry::new());
    let compiler = Arc::new(SnapshotCompiler::new(Arc::new(reg), Arc::clone(&runtime)));
    let provider = Arc::new(FileConfigProvider::new(&cfg_path));

    let initial_loaded = provider.load().unwrap();
    let initial_bundle = compiler.compile(&initial_loaded).unwrap();

    let gw = GatewayServer::new(initial_bundle.snapshot)
        .bind("127.0.0.1:0".parse().unwrap())
        .await
        .unwrap();
    let gw_addr = gw.local_addr();

    let controller = Arc::new(ReloadController::new(
        provider.clone(),
        Arc::clone(&compiler),
        gw.reloader(),
        initial_bundle.inspect,
    ));

    let metrics_clone = Arc::clone(&metrics);
    let admin = AdminServer::new(
        Arc::clone(&controller),
        Arc::new(move || metrics_clone.render_prometheus()),
    )
    .bind("127.0.0.1:0".parse().unwrap())
    .await
    .unwrap();
    let admin_addr = admin.local_addr();

    let client = Arc::new(Client::builder(TokioExecutor::new()).build_http::<Full<Bytes>>());

    // Consume 3 of the 5 burst tokens on gen-1.
    for _ in 0..3 {
        let res = client
            .request(
                Request::builder()
                    .uri(format!("http://{gw_addr}/api/test"))
                    .body(Full::new(Bytes::new()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        assert_eq!(res.headers().get("x-config-gen").unwrap(), "gen-1");
    }

    // Drive concurrent probes to /health while bombarding POST /reload with corrupt configs.
    let stop = Arc::new(AtomicBool::new(false));
    let health_err = Arc::new(AtomicUsize::new(0));
    let health_client = Arc::clone(&client);
    let stop_c = Arc::clone(&stop);
    let err_c = Arc::clone(&health_err);
    let health_task = tokio::spawn(async move {
        while !stop_c.load(Ordering::Relaxed) {
            let res = health_client
                .request(
                    Request::builder()
                        .uri(format!("http://{admin_addr}/health"))
                        .body(Full::new(Bytes::new()))
                        .unwrap(),
                )
                .await;
            if !matches!(res, Ok(r) if r.status() == StatusCode::OK) {
                err_c.fetch_add(1, Ordering::Relaxed);
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    });

    let corrupt_configs = [
        "this is [[[ not valid toml",
        "[server]\nlisten = \"not-a-socket\"\n",
        r#"
[server]
listen = "127.0.0.1:0"
[[upstreams]]
name = "backend"
endpoints = ["http://127.0.0.1:9999"]
[[routes]]
id = "bad"
path_prefix = "/"
upstream = "missing_upstream"
"#,
        r#"
[server]
listen = "127.0.0.1:0"
[[upstreams]]
name = "backend"
endpoints = ["http://127.0.0.1:9999"]
[[routes]]
id = "bad_plugin"
path_prefix = "/"
upstream = "backend"
[[routes.plugins]]
name = "does-not-exist"
"#,
    ];

    for bad in corrupt_configs {
        std::fs::write(&cfg_path, bad).unwrap();
        let res = client
            .request(
                Request::builder()
                    .method(Method::POST)
                    .uri(format!("http://{admin_addr}/reload"))
                    .body(Full::new(Bytes::new()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::UNPROCESSABLE_ENTITY);
        let body = res.into_body().collect().await.unwrap().to_bytes();
        assert!(String::from_utf8_lossy(&body).contains(r#""reloaded": false"#));
    }

    // Now write valid gen-2 and reload -> must succeed and preserve remaining 2 burst tokens!
    std::fs::write(&cfg_path, make_valid_toml("gen-2")).unwrap();
    let ok_reload = client
        .request(
            Request::builder()
                .method(Method::POST)
                .uri(format!("http://{admin_addr}/reload"))
                .body(Full::new(Bytes::new()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(ok_reload.status(), StatusCode::OK);

    // Remaining 2 tokens succeed on gen-2, and the 6th total request must hit 429!
    for _ in 0..2 {
        let res = client
            .request(
                Request::builder()
                    .uri(format!("http://{gw_addr}/api/test"))
                    .body(Full::new(Bytes::new()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        assert_eq!(res.headers().get("x-config-gen").unwrap(), "gen-2");
    }

    let rate_limited = client
        .request(
            Request::builder()
                .uri(format!("http://{gw_addr}/api/test"))
                .body(Full::new(Bytes::new()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        rate_limited.status(),
        StatusCode::TOO_MANY_REQUESTS,
        "rate-limit state must survive both failed corrupt reloads and valid reloads"
    );

    stop.store(true, Ordering::Release);
    health_task.await.unwrap();
    assert_eq!(health_err.load(Ordering::Relaxed), 0);

    admin.shutdown().await;
    assert!(gw.shutdown().await);
    let _ = std::fs::remove_dir_all(&tmp_dir);
}
