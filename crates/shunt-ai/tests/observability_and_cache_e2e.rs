use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use bytes::Bytes;
use http::{Method, Request, Response, StatusCode, header};
use http_body_util::{BodyExt, Full};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::client::legacy::Client;
use hyper_util::rt::{TokioExecutor, TokioIo};
use serde_json::{Value, json};
use shunt_ai::{AiMetrics, register_ai_plugins};
use shunt_config::{
    ConfigProvider, InlineConfigProvider, Severity, SnapshotCompiler, verify_bundle,
};
use shunt_core::{
    GatewayServer, RouteMatch, RouteSpec, RuntimeRegistry, SnapshotBuilder, UpstreamConfig,
};
use shunt_plugin_sdk::{
    DistributedStore, FailurePolicy, InMemoryDistributedStore, InMemoryTelemetrySink, ManualClock,
    PluginConfig, PluginRegistry, SpanValue, TelemetrySink,
};
use shunt_plugins::{PrometheusMetrics, register_builtin_plugins};
use tokio::net::TcpListener;

async fn spawn_chat_mock(
    hits: Arc<AtomicUsize>,
    content: &'static str,
) -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let task = tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            let hits = Arc::clone(&hits);
            tokio::spawn(async move {
                let svc = service_fn(move |req: Request<hyper::body::Incoming>| {
                    let hits = Arc::clone(&hits);
                    async move {
                        let _ = req.into_body().collect().await;
                        hits.fetch_add(1, Ordering::SeqCst);
                        let body = json!({
                            "id": "chatcmpl-dist-1",
                            "object": "chat.completion",
                            "model": "gpt-4o-mini",
                            "choices": [{
                                "index": 0,
                                "message": { "role": "assistant", "content": content },
                                "finish_reason": "stop"
                            }],
                            "usage": {
                                "prompt_tokens": 100,
                                "completion_tokens": 50,
                                "total_tokens": 150
                            }
                        });
                        Ok::<_, Infallible>(
                            Response::builder()
                                .status(StatusCode::OK)
                                .header(header::CONTENT_TYPE, "application/json")
                                .body(Full::new(Bytes::from(serde_json::to_vec(&body).unwrap())))
                                .unwrap(),
                        )
                    }
                });
                let _ = http1::Builder::new()
                    .serve_connection(TokioIo::new(stream), svc)
                    .await;
            });
        }
    });
    (addr, task)
}

async fn build_replica_server(
    upstream_addr: SocketAddr,
    clock: Arc<ManualClock>,
    dist: Arc<dyn DistributedStore>,
    sink: Arc<dyn TelemetrySink>,
) -> (SocketAddr, shunt_core::ServerHandle, Arc<AiMetrics>) {
    let metrics = Arc::new(PrometheusMetrics::new());
    let ai_metrics = Arc::new(AiMetrics::new());
    let mut reg = PluginRegistry::new();
    register_builtin_plugins(&mut reg, metrics);
    register_ai_plugins(&mut reg, Arc::clone(&ai_metrics));

    let runtime = RuntimeRegistry::with_clock(clock);
    let session = runtime.begin_build_session_with_services(Some(dist), Some(sink));

    let otel = reg
        .build(
            "otel-trace",
            &PluginConfig::new(json!({ "sample_rate": 1.0, "emit_response_header": true })),
            &session.context_for("global:otel"),
        )
        .unwrap();
    let router = reg
        .build(
            "ai-model-router",
            &PluginConfig::new(json!({
                "models": {
                    "gpt-mini": [{ "provider": "openai", "upstream": "openai_up", "model": "gpt-4o-mini" }]
                }
            })),
            &session.context_for("route:ai:router"),
        )
        .unwrap();
    let cache = reg
        .build(
            "ai-cache",
            &PluginConfig::new(json!({
                "ttl_secs": 120,
                "scope": "global",
                "distributed": true
            })),
            &session.context_for("route:ai:cache"),
        )
        .unwrap();
    let budget = reg
        .build(
            "ai-budget",
            &PluginConfig::new(json!({
                "scope": "global",
                "default_limit_usd": 5.0
            })),
            &session.context_for("route:ai:budget"),
        )
        .unwrap();
    let adapter = reg
        .build(
            "ai-provider-adapter",
            &PluginConfig::new(json!({
                "providers": {
                    "openai": { "dialect": "openai_compatible" }
                }
            })),
            &session.context_for("route:ai:adapter"),
        )
        .unwrap();
    let tracker = reg
        .build(
            "ai-usage-tracker",
            &PluginConfig::new(json!({ "log_usage": false })),
            &session.context_for("route:ai:tracker"),
        )
        .unwrap();

    let snapshot = SnapshotBuilder::new(1)
        .global_plugin(otel)
        .upstream(UpstreamConfig::new(
            "openai_up",
            vec![format!("http://{upstream_addr}")],
        ))
        .route(
            RouteSpec::new("ai", RouteMatch::prefix("/v1"), "openai_up")
                .with_plugin(router)
                .with_plugin(cache)
                .with_plugin(budget)
                .with_plugin(adapter)
                .with_plugin(tracker),
        )
        .build(&runtime, true)
        .unwrap();
    session.commit_gc();

    let handle = GatewayServer::new(snapshot)
        .bind("127.0.0.1:0".parse().unwrap())
        .await
        .unwrap();
    (handle.local_addr(), handle, ai_metrics)
}

#[tokio::test]
async fn distributed_ai_cache_shares_entries_across_replicas_and_enriches_otel_spans() {
    let upstream_hits = Arc::new(AtomicUsize::new(0));
    let (up_addr, up_task) =
        spawn_chat_mock(Arc::clone(&upstream_hits), "shared-across-replicas").await;

    let clock = ManualClock::shared();
    let shared_dist: Arc<dyn DistributedStore> = Arc::new(InMemoryDistributedStore::new(
        clock.clone(),
        FailurePolicy::FailOpen,
    ));
    let sink = Arc::new(InMemoryTelemetrySink::new(64));

    let (addr_a, srv_a, metrics_a) = build_replica_server(
        up_addr,
        clock.clone(),
        Arc::clone(&shared_dist),
        Arc::clone(&sink) as Arc<dyn TelemetrySink>,
    )
    .await;
    let (addr_b, srv_b, metrics_b) = build_replica_server(
        up_addr,
        clock.clone(),
        Arc::clone(&shared_dist),
        Arc::clone(&sink) as Arc<dyn TelemetrySink>,
    )
    .await;

    let client = Client::builder(TokioExecutor::new()).build_http::<Full<Bytes>>();
    let payload = serde_json::to_vec(&json!({
        "model": "gpt-mini",
        "temperature": 0,
        "messages": [{ "role": "user", "content": "shared prompt" }]
    }))
    .unwrap();

    // 1. Replica A misses, calls upstream, and writes to shared DistributedStore in on_complete.
    let req_a = Request::builder()
        .method(Method::POST)
        .uri(format!("http://{addr_a}/v1/chat/completions"))
        .header(header::CONTENT_TYPE, "application/json")
        .body(Full::new(Bytes::from(payload.clone())))
        .unwrap();
    let res_a = client.request(req_a).await.unwrap();
    assert_eq!(res_a.status(), StatusCode::OK);
    assert_eq!(res_a.headers().get("x-shunt-cache").unwrap(), "miss");
    let body_a: Value =
        serde_json::from_slice(&res_a.into_body().collect().await.unwrap().to_bytes()).unwrap();
    assert_eq!(
        body_a["choices"][0]["message"]["content"],
        "shared-across-replicas"
    );
    assert_eq!(upstream_hits.load(Ordering::SeqCst), 1);

    // Allow off-hot-path on_complete (distributed write + span drop) to finish.
    tokio::time::sleep(Duration::from_millis(50)).await;

    // 2. Replica B immediately hits the distributed cache with ZERO upstream call!
    let req_b = Request::builder()
        .method(Method::POST)
        .uri(format!("http://{addr_b}/v1/chat/completions"))
        .header(header::CONTENT_TYPE, "application/json")
        .body(Full::new(Bytes::from(payload)))
        .unwrap();
    let res_b = client.request(req_b).await.unwrap();
    assert_eq!(res_b.status(), StatusCode::OK);
    assert_eq!(res_b.headers().get("x-shunt-cache").unwrap(), "hit");
    let body_b: Value =
        serde_json::from_slice(&res_b.into_body().collect().await.unwrap().to_bytes()).unwrap();
    assert_eq!(
        body_b["choices"][0]["message"]["content"],
        "shared-across-replicas"
    );
    assert_eq!(
        upstream_hits.load(Ordering::SeqCst),
        1,
        "replica B must not call upstream on cache hit"
    );

    tokio::time::sleep(Duration::from_millis(50)).await;

    // Verify metrics & OTel GenAI spans for both miss (with cost) and hit (no upstream spend).
    assert_eq!(metrics_a.snapshot().total_cache_misses, 1);
    assert_eq!(metrics_b.snapshot().total_cache_hits, 1);
    assert_eq!(metrics_b.snapshot().total_requests, 0);

    let spans = sink.spans();
    assert_eq!(spans.len(), 2);
    let miss_span = spans
        .iter()
        .find(|s| {
            s.attributes.get("shunt.ai.cache_status") == Some(&SpanValue::String("miss".into()))
        })
        .expect("miss span present");
    assert_eq!(miss_span.name, "chat gpt-mini");
    assert_eq!(
        miss_span.attributes.get("gen_ai.provider.name"),
        Some(&SpanValue::String("openai".into()))
    );
    assert_eq!(
        miss_span.attributes.get("gen_ai.usage.input_tokens"),
        Some(&SpanValue::Int(100))
    );
    assert_eq!(
        miss_span.attributes.get("gen_ai.usage.output_tokens"),
        Some(&SpanValue::Int(50))
    );
    assert!(
        miss_span.attributes.contains_key("shunt.ai.cost_usd"),
        "miss span must include attributed cost from ai-budget"
    );

    let hit_span = spans
        .iter()
        .find(|s| {
            s.attributes.get("shunt.ai.cache_status") == Some(&SpanValue::String("hit".into()))
        })
        .expect("hit span present");
    assert_eq!(hit_span.name, "chat gpt-mini");
    assert!(!hit_span.attributes.contains_key("shunt.ai.cost_usd"));

    srv_a.shutdown().await;
    srv_b.shutdown().await;
    up_task.abort();
}

#[test]
fn verify_checks_ai_cache_order_and_reuses_otlp_exporter_across_reload() {
    let metrics = Arc::new(PrometheusMetrics::new());
    let ai_metrics = Arc::new(AiMetrics::new());
    let mut reg = PluginRegistry::new();
    register_builtin_plugins(&mut reg, metrics);
    register_ai_plugins(&mut reg, ai_metrics);
    let runtime = Arc::new(RuntimeRegistry::new());
    let compiler = SnapshotCompiler::new(Arc::new(reg), Arc::clone(&runtime));

    // Bad ordering: ai-cache after ai-budget triggers warning, ai-cache before ai-model-router triggers error.
    let bad_toml = r#"
[server]
listen = "127.0.0.1:0"
[admin]
enabled = false

[telemetry]
enabled = true
endpoint = "http://127.0.0.1:4318/v1/traces"

[[plugins]]
name = "otel-trace"

[[upstreams]]
name = "openai"
endpoints = ["http://127.0.0.1:8081"]

[[routes]]
id = "bad_order"
path_prefix = "/v1"
upstream = "openai"

[[routes.plugins]]
name = "ai-cache"

[[routes.plugins]]
name = "ai-model-router"
[routes.plugins.config.models]
"gpt-4o" = [{ provider = "openai", upstream = "openai", model = "gpt-4o" }]
"#;
    let loaded = InlineConfigProvider::from_toml("bad.toml", bad_toml)
        .load()
        .unwrap();
    let bundle = compiler.compile(&loaded).unwrap();
    assert_eq!(bundle.inspect.telemetry_backend, "otlp_http");
    let report = verify_bundle(&bundle, None, false);
    assert!(!report.passed);
    assert!(
        report
            .diagnostics
            .iter()
            .any(|d| d.rule == "ai.plugin_order" && d.severity == Severity::Error)
    );

    // Warning case: ai-cache after ai-budget.
    let warn_toml = r#"
[server]
listen = "127.0.0.1:0"
[admin]
enabled = false

[[upstreams]]
name = "openai"
endpoints = ["http://127.0.0.1:8081"]

[[routes]]
id = "warn_order"
path_prefix = "/v1"
upstream = "openai"

[[routes.plugins]]
name = "ai-model-router"
[routes.plugins.config.models]
"gpt-4o" = [{ provider = "openai", upstream = "openai", model = "gpt-4o" }]

[[routes.plugins]]
name = "ai-budget"
[routes.plugins.config]
default_limit_usd = 5.0

[[routes.plugins]]
name = "ai-cache"
"#;
    let loaded2 = InlineConfigProvider::from_toml("warn.toml", warn_toml)
        .load()
        .unwrap();
    let bundle2 = compiler.compile(&loaded2).unwrap();
    assert_eq!(bundle2.inspect.telemetry_backend, "disabled");
    assert!(
        !runtime.has_active_telemetry(),
        "disabled telemetry should GC exporter"
    );
    let report2 = verify_bundle(&bundle2, None, false);
    assert!(report2.passed);
    assert!(
        report2
            .diagnostics
            .iter()
            .any(|d| d.rule == "ai.cache_order" && d.severity == Severity::Warning)
    );
}

#[test]
fn otlp_exporter_config_debug_redacts_headers() {
    let mut headers = std::collections::BTreeMap::new();
    headers.insert(
        "Authorization".to_owned(),
        "Bearer top-secret-key".to_owned(),
    );
    let cfg = shunt_core::OtlpExporterConfig {
        headers,
        ..Default::default()
    };
    let rendered = format!("{cfg:?}");
    assert!(!rendered.contains("top-secret-key"));
    assert!(rendered.contains("Authorization"));
}
