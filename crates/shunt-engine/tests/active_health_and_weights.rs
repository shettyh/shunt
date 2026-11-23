use std::convert::Infallible;
use std::sync::Arc;
use std::sync::atomic::{AtomicU16, Ordering};
use std::time::Duration;

use bytes::Bytes;
use http::{Request, Response, StatusCode};
use http_body_util::{BodyExt, Full};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::client::legacy::Client;
use hyper_util::rt::{TokioExecutor, TokioIo};
use shunt_engine::{
    ActiveHealthCheckConfig, ActiveProbeKind, GatewayServer, RouteMatch, RouteSpec,
    RuntimeRegistry, SnapshotBuilder, UpstreamConfig, UpstreamEndpoint,
};
use tokio::net::TcpListener;

async fn spawn_toggle_backend(
    health_status: Arc<AtomicU16>,
    label: &'static str,
) -> (std::net::SocketAddr, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let task = tokio::spawn(async move {
        loop {
            let Ok((tcp, _)) = listener.accept().await else {
                break;
            };
            let hs = Arc::clone(&health_status);
            tokio::spawn(async move {
                let svc = service_fn(move |req: Request<hyper::body::Incoming>| {
                    let hs = Arc::clone(&hs);
                    async move {
                        let status = if req.uri().path() == "/healthz" {
                            StatusCode::from_u16(hs.load(Ordering::Relaxed))
                                .unwrap_or(StatusCode::INTERNAL_SERVER_ERROR)
                        } else {
                            StatusCode::OK
                        };
                        Ok::<_, Infallible>(
                            Response::builder()
                                .status(status)
                                .body(Full::new(Bytes::from_static(label.as_bytes())))
                                .unwrap(),
                        )
                    }
                });
                let _ = http1::Builder::new()
                    .keep_alive(true)
                    .serve_connection(TokioIo::new(tcp), svc)
                    .await;
            });
        }
    });
    (addr, task)
}

#[tokio::test]
async fn probe_supervisor_ejects_recovers_and_cleans_up_on_reload_and_shutdown() {
    let status_a = Arc::new(AtomicU16::new(200));
    let status_b = Arc::new(AtomicU16::new(503));
    let (addr_a, task_a) = spawn_toggle_backend(Arc::clone(&status_a), "node-a").await;
    let (addr_b, task_b) = spawn_toggle_backend(Arc::clone(&status_b), "node-b").await;

    let registry = RuntimeRegistry::new();
    let hc = ActiveHealthCheckConfig {
        kind: ActiveProbeKind::Http {
            method: "GET".to_owned(),
            path: "/healthz".to_owned(),
            expected_statuses: vec![200],
            headers: Vec::new(),
        },
        interval: Duration::from_millis(30),
        timeout: Duration::from_millis(200),
        unhealthy_threshold: 2,
        healthy_threshold: 2,
        initial_healthy: true,
    };

    let up_cfg = UpstreamConfig::with_endpoints(
        "cluster",
        vec![
            UpstreamEndpoint::with_weight(format!("http://{addr_a}"), 1),
            UpstreamEndpoint::with_weight(format!("http://{addr_b}"), 1),
        ],
    )
    .with_active_health_check(hc);

    let snap1 = SnapshotBuilder::new(1)
        .upstream(up_cfg.clone())
        .route(RouteSpec::new("r1", RouteMatch::prefix("/"), "cluster"))
        .build(&registry, true)
        .unwrap();

    let server = GatewayServer::new(Arc::clone(&snap1))
        .bind("127.0.0.1:0".parse().unwrap())
        .await
        .unwrap();
    assert_eq!(server.active_probe_tasks(), 1);

    // Wait for node-b to be ejected by >=2 failing active probes.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
    loop {
        let reports = server.current_snapshot().upstream_health_reports();
        if !reports[0].endpoints[1].active_healthy && reports[0].endpoints[0].active_healthy {
            break;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "timed out waiting for active probe ejection: {reports:?}"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }

    // Verify Prometheus output reflects healthy=1 for node-a and healthy=0 for node-b.
    let prom = server
        .current_snapshot()
        .render_upstream_health_prometheus();
    assert!(prom.contains(&format!(
        "shunt_upstream_endpoint_healthy{{upstream=\"cluster\",endpoint=\"http://{addr_a}\"}} 1"
    )));
    assert!(prom.contains(&format!(
        "shunt_upstream_endpoint_healthy{{upstream=\"cluster\",endpoint=\"http://{addr_b}\"}} 0"
    )));
    assert!(prom.contains("shunt_upstream_active_probes_total"));

    // All HTTP requests should hit node-a while node-b is actively unhealthy.
    let client = Client::builder(TokioExecutor::new()).build_http::<Full<Bytes>>();
    for _ in 0..4 {
        let req = Request::builder()
            .uri(format!("http://{}/work", server.local_addr()))
            .body(Full::new(Bytes::new()))
            .unwrap();
        let resp = client.request(req).await.unwrap();
        let body = resp.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(body.as_ref(), b"node-a");
    }

    // Now flip node-b back to 200 -> active probes should recover it!
    status_b.store(200, Ordering::Relaxed);
    let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
    loop {
        let reports = server.current_snapshot().upstream_health_reports();
        if reports[0].endpoints[1].active_healthy {
            break;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "timed out waiting for active probe recovery: {reports:?}"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }

    // Reloading with identical upstream reuses pool & keeps exactly 1 probe task.
    let snap2 = SnapshotBuilder::new(2)
        .upstream(up_cfg)
        .route(RouteSpec::new("r1", RouteMatch::prefix("/"), "cluster"))
        .build(&registry, true)
        .unwrap();
    assert_eq!(
        snap1.upstream("cluster").unwrap().pool_id(),
        snap2.upstream("cluster").unwrap().pool_id()
    );
    server.swap_snapshot(snap2);
    assert_eq!(server.active_probe_tasks(), 1);

    // Reloading without active health check immediately stops the obsolete probe task.
    let snap3 = SnapshotBuilder::new(3)
        .upstream(UpstreamConfig::new(
            "cluster",
            vec![format!("http://{addr_a}")],
        ))
        .route(RouteSpec::new("r1", RouteMatch::prefix("/"), "cluster"))
        .build(&registry, true)
        .unwrap();
    server.swap_snapshot(snap3);
    assert_eq!(server.active_probe_tasks(), 0);

    assert!(server.shutdown().await);
    task_a.abort();
    task_b.abort();
}
