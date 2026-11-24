use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use http::{Method, Request, StatusCode};
use http_body_util::{BodyExt, Full};
use hyper::body::Bytes;
use hyper::service::service_fn;
use hyper_util::client::legacy::Client;
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto::Builder as AutoServerBuilder;
use shunt_engine::{
    DEFAULT_LISTEN_BACKLOG, GatewayServer, ListenerConfig, MAX_REUSEPORT_SHARDS, PathMatch,
    RouteMatch, RouteSpec, RuntimeRegistry, SnapshotBuilder, UpstreamConfig,
};
use tokio::net::TcpListener;
use tokio::sync::Barrier;

async fn spawn_echo_upstream(
    tag: &'static str,
    delay: Duration,
) -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                break;
            };
            tokio::spawn(async move {
                let svc = service_fn(move |req: Request<hyper::body::Incoming>| async move {
                    if !delay.is_zero() {
                        tokio::time::sleep(delay).await;
                    }
                    let path = req.uri().path().to_owned();
                    let body = format!("{tag}:{path}");
                    Ok::<_, std::convert::Infallible>(
                        http::Response::builder()
                            .status(StatusCode::OK)
                            .body(Full::new(Bytes::from(body)))
                            .unwrap(),
                    )
                });
                let _ = AutoServerBuilder::new(TokioExecutor::new())
                    .serve_connection(TokioIo::new(stream), svc)
                    .await;
            });
        }
    });
    (addr, handle)
}

fn build_passthrough_snapshot(upstream_addr: SocketAddr) -> Arc<shunt_engine::GatewaySnapshot> {
    let registry = RuntimeRegistry::new();
    SnapshotBuilder::new(1)
        .upstream(UpstreamConfig::new(
            "echo",
            vec![format!("http://{upstream_addr}")],
        ))
        .route(RouteSpec {
            id: "all".to_owned(),
            matcher: RouteMatch {
                hosts: vec![],
                path: PathMatch::Any,
                methods: vec![],
                headers: vec![],
            },
            upstream: "echo".to_owned(),
            strip_prefix: None,
            plugins: vec![],
            max_body_bytes: None,
            max_attempts: 1,
            timeouts: Default::default(),
            allow_websockets: false,
            mirrors: vec![],
        })
        .build(&registry, true)
        .unwrap()
}

async fn send_get(addr: SocketAddr, path: &str) -> (StatusCode, String) {
    let client = Client::builder(TokioExecutor::new()).build_http::<Full<Bytes>>();
    let uri: http::Uri = format!("http://{addr}{path}").parse().unwrap();
    let req = Request::builder()
        .method(Method::GET)
        .uri(uri)
        .body(Full::new(Bytes::new()))
        .unwrap();
    let resp = client.request(req).await.unwrap();
    let status = resp.status();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    (status, String::from_utf8_lossy(&bytes).into_owned())
}

#[tokio::test]
async fn default_single_listener_info_and_traffic() {
    let (up_addr, up_task) = spawn_echo_upstream("single", Duration::ZERO).await;
    let snap = build_passthrough_snapshot(up_addr);

    let handle = GatewayServer::new(snap)
        .with_drain_timeout(Duration::from_secs(2))
        .bind("127.0.0.1:0".parse().unwrap())
        .await
        .unwrap();

    let info = handle.listener_info();
    assert!(!info.reuseport);
    assert_eq!(info.accept_shards, 1);
    assert_eq!(info.backlog, DEFAULT_LISTEN_BACKLOG);

    let (status, body) = send_get(handle.local_addr(), "/hello").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, "single:/hello");

    assert!(handle.shutdown().await);
    up_task.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn reuseport_multi_shard_serves_concurrent_burst_and_drains() {
    let (up_addr, up_task) = spawn_echo_upstream("sharded", Duration::ZERO).await;
    let snap = build_passthrough_snapshot(up_addr);

    let cfg = ListenerConfig {
        reuseport: true,
        accept_shards: Some(4),
        backlog: 1024,
    };

    let handle = GatewayServer::new(snap)
        .with_drain_timeout(Duration::from_secs(2))
        .with_listener_config(cfg)
        .bind("127.0.0.1:0".parse().unwrap())
        .await
        .unwrap();

    let info = handle.listener_info();
    assert_eq!(info.backlog, 1024);
    #[cfg(unix)]
    {
        assert!(info.reuseport);
        assert_eq!(info.accept_shards, 4);
    }
    #[cfg(not(unix))]
    {
        assert!(!info.reuseport);
        assert_eq!(info.accept_shards, 1);
    }

    let addr = handle.local_addr();
    let mut joins = Vec::new();
    for worker in 0..16 {
        joins.push(tokio::spawn(async move {
            for iter in 0..4 {
                let path = format!("/req/{worker}/{iter}");
                let (status, body) = send_get(addr, &path).await;
                assert_eq!(status, StatusCode::OK, "unexpected status body={body}");
                assert_eq!(body, format!("sharded:{path}"));
            }
        }));
    }
    for j in joins {
        j.await.unwrap();
    }

    assert!(handle.shutdown().await);
    up_task.abort();
}

#[tokio::test]
async fn reuseport_per_core_auto_shards_works() {
    let (up_addr, up_task) = spawn_echo_upstream("percore", Duration::ZERO).await;
    let snap = build_passthrough_snapshot(up_addr);

    let handle = GatewayServer::new(snap)
        .with_drain_timeout(Duration::from_secs(2))
        .with_reuseport(true)
        .bind("127.0.0.1:0".parse().unwrap())
        .await
        .unwrap();

    let info = handle.listener_info();
    #[cfg(unix)]
    {
        let expected = std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(1)
            .clamp(1, MAX_REUSEPORT_SHARDS);
        assert!(info.reuseport);
        assert_eq!(info.accept_shards, expected);
    }

    let (status, body) = send_get(handle.local_addr(), "/ping").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, "percore:/ping");

    assert!(handle.shutdown().await);
    up_task.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn reuseport_sharded_graceful_drain_completes_slow_in_flight_requests() {
    let (up_addr, up_task) = spawn_echo_upstream("slow", Duration::from_millis(120)).await;
    let snap = build_passthrough_snapshot(up_addr);

    let cfg = ListenerConfig {
        reuseport: true,
        accept_shards: Some(4),
        backlog: 512,
    };

    let handle = GatewayServer::new(snap)
        .with_drain_timeout(Duration::from_secs(5))
        .with_listener_config(cfg)
        .bind("127.0.0.1:0".parse().unwrap())
        .await
        .unwrap();
    let addr = handle.local_addr();

    let inflight = 12usize;
    let barrier = Arc::new(Barrier::new(inflight + 1));
    let mut joins = Vec::with_capacity(inflight);
    for i in 0..inflight {
        let b = Arc::clone(&barrier);
        joins.push(tokio::spawn(async move {
            b.wait().await;
            let path = format!("/drain/{i}");
            let (status, body) = send_get(addr, &path).await;
            assert_eq!(status, StatusCode::OK);
            assert_eq!(body, format!("slow:{path}"));
        }));
    }

    // Release all slow requests simultaneously, wait briefly until connections are accepted,
    // then trigger graceful shutdown while all requests are mid-flight.
    barrier.wait().await;
    tokio::time::sleep(Duration::from_millis(35)).await;

    let clean = handle.shutdown().await;
    assert!(clean, "multi-shard graceful drain should complete cleanly");
    for j in joins {
        j.await.unwrap();
    }

    up_task.abort();
}

#[cfg(unix)]
#[tokio::test]
async fn reuseport_overlapping_servers_rolling_restart_with_in_flight_drain() {
    let (up_a_addr, up_a_task) = spawn_echo_upstream("genA", Duration::from_millis(100)).await;
    let (up_b_addr, up_b_task) = spawn_echo_upstream("genB", Duration::ZERO).await;

    let cfg = ListenerConfig {
        reuseport: true,
        accept_shards: Some(2),
        backlog: 512,
    };

    // Generation A binds ephemeral port with SO_REUSEPORT.
    let srv_a = GatewayServer::new(build_passthrough_snapshot(up_a_addr))
        .with_drain_timeout(Duration::from_secs(3))
        .with_listener_config(cfg.clone())
        .bind("127.0.0.1:0".parse().unwrap())
        .await
        .unwrap();
    let shared_addr = srv_a.local_addr();

    // Start an in-flight slow request on Generation A before Generation B binds.
    let inflight_a = tokio::spawn(async move { send_get(shared_addr, "/slow-gen-a").await });
    tokio::time::sleep(Duration::from_millis(25)).await;

    // Generation B binds the exact same port while Generation A is still serving.
    let srv_b = GatewayServer::new(build_passthrough_snapshot(up_b_addr))
        .with_drain_timeout(Duration::from_secs(2))
        .with_listener_config(cfg)
        .bind(shared_addr)
        .await
        .unwrap();
    assert_eq!(srv_b.local_addr(), shared_addr);

    // Gracefully drain Generation A; its in-flight request completes with 200 OK.
    assert!(srv_a.shutdown().await);
    let (status_a, body_a) = inflight_a.await.unwrap();
    assert_eq!(status_a, StatusCode::OK);
    assert_eq!(body_a, "genA:/slow-gen-a");

    // Subsequent traffic is served cleanly by Generation B on the same port.
    for i in 0..8 {
        let path = format!("/after/{i}");
        let (status, body) = send_get(shared_addr, &path).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body, format!("genB:{path}"));
    }

    assert!(srv_b.shutdown().await);
    up_a_task.abort();
    up_b_task.abort();
}
