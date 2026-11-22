//! End-to-end integration tests for RFC 0017:
//! - OpenRouter-style per-request `models[]` & `provider: { order, only, ignore, sort,
//!   allow_fallbacks, data_collection, zdr, regions, tags }` + virtual-key ACL intersection
//!   + stripping of `models`/`provider` before forwarding upstream
//! - Context-window capability guards (`400 context_length_exceeded` + automatic large-context selection)
//! - `RoutingStrategy::Throughput` (EWMA tokens/sec) & `RoutingStrategy::Headroom` (header feedback)
//! - TTFT-timeout failover (`ttft_timeout_ms` -> `504` -> automatic fallback)
//! - Context-overflow `400` error-body failover (`failover_on_context_overflow = true`)
//! - AI off-path traffic shadowing (`shadow_targets`)
//! - Virtual key `expires_at` (deterministic `ManualClock`), `org`, `max_parallel_requests`,
//!   per-model `model_limits` (RPM & budget), end-user budgets, and `preflight_reserve = true`
//! - External JSON pricing catalog (`pricing_file` LiteLLM schema) & enriched `GET /v1/models`

use std::convert::Infallible;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::Bytes;
use http::{Method, Request, Response, StatusCode, header};
use http_body_util::{BodyExt, Full};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::client::legacy::Client;
use hyper_util::rt::{TokioExecutor, TokioIo};
use serde_json::{Value, json};
use shunt_ai::{AiMetrics, inspect_ai_runtime, register_ai_plugins};
use shunt_config::{ConfigProvider, InlineConfigProvider, SnapshotCompiler};
use shunt_core::{GatewayServer, RuntimeRegistry};
use shunt_plugin_sdk::{ManualClock, PluginRegistry};
use shunt_plugins::{PrometheusMetrics, register_builtin_plugins};
use tokio::net::TcpListener;

#[derive(Debug, Clone)]
struct CapturedReq {
    headers: std::collections::BTreeMap<String, String>,
    body: Vec<u8>,
}

async fn spawn_mock_http<F, Fut>(
    handler: F,
) -> (
    std::net::SocketAddr,
    Arc<Mutex<Vec<CapturedReq>>>,
    tokio::task::JoinHandle<()>,
)
where
    F: Fn(usize, CapturedReq) -> Fut + Send + Sync + 'static,
    Fut:
        std::future::Future<Output = (StatusCode, Vec<(String, String)>, Vec<u8>)> + Send + 'static,
{
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let captures = Arc::new(Mutex::new(Vec::new()));
    let handler = Arc::new(handler);

    let caps_bg = Arc::clone(&captures);
    let handle = tokio::spawn(async move {
        loop {
            let Ok((tcp, _)) = listener.accept().await else {
                break;
            };
            let caps = Arc::clone(&caps_bg);
            let h = Arc::clone(&handler);
            tokio::spawn(async move {
                let svc = service_fn(move |req: Request<hyper::body::Incoming>| {
                    let caps = Arc::clone(&caps);
                    let h = Arc::clone(&h);
                    async move {
                        let mut headers = std::collections::BTreeMap::new();
                        for (k, v) in req.headers() {
                            if let Ok(s) = v.to_str() {
                                headers.insert(k.as_str().to_ascii_lowercase(), s.to_owned());
                            }
                        }
                        let body = req
                            .into_body()
                            .collect()
                            .await
                            .map(|c| c.to_bytes().to_vec())
                            .unwrap_or_default();
                        let cap = CapturedReq { headers, body };
                        let idx = {
                            let mut g = caps.lock().unwrap();
                            let i = g.len();
                            g.push(cap.clone());
                            i
                        };
                        let (status, extra_hdrs, resp_body) = h(idx, cap).await;
                        let mut builder = Response::builder()
                            .status(status)
                            .header(header::CONTENT_TYPE, "application/json");
                        for (k, v) in extra_hdrs {
                            builder = builder.header(k, v);
                        }
                        Ok::<_, Infallible>(
                            builder.body(Full::new(Bytes::from(resp_body))).unwrap(),
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

async fn boot_gateway(
    toml_cfg: &str,
    clock: Option<Arc<ManualClock>>,
) -> (
    std::net::SocketAddr,
    shunt_core::ServerHandle,
    Arc<RuntimeRegistry>,
    Arc<AiMetrics>,
) {
    let prom = Arc::new(PrometheusMetrics::new());
    let ai_metrics = Arc::new(AiMetrics::new());
    let mut plugins = PluginRegistry::new();
    register_builtin_plugins(&mut plugins, prom);
    register_ai_plugins(&mut plugins, Arc::clone(&ai_metrics));

    let runtime = match clock {
        Some(c) => Arc::new(RuntimeRegistry::with_clock(c)),
        None => Arc::new(RuntimeRegistry::new()),
    };
    let compiler = SnapshotCompiler::new(Arc::new(plugins), Arc::clone(&runtime));
    let provider = InlineConfigProvider::from_toml("rfc0017.toml", toml_cfg);
    let loaded = provider.load().unwrap();
    let bundle = compiler.compile(&loaded).unwrap();

    let server = GatewayServer::new(bundle.snapshot)
        .bind("127.0.0.1:0".parse().unwrap())
        .await
        .unwrap();
    let addr = server.local_addr();
    (addr, server, runtime, ai_metrics)
}

async fn send_json(
    addr: std::net::SocketAddr,
    method: Method,
    path: &str,
    auth: Option<&str>,
    body: Option<Value>,
) -> (StatusCode, http::HeaderMap, Value) {
    let client = Client::builder(TokioExecutor::new()).build_http::<Full<Bytes>>();
    let mut req = Request::builder()
        .method(method)
        .uri(format!("http://{addr}{path}"))
        .header(header::CONTENT_TYPE, "application/json");
    if let Some(a) = auth {
        req = req.header(header::AUTHORIZATION, format!("Bearer {a}"));
    }
    let payload = match body {
        Some(v) => Bytes::from(serde_json::to_vec(&v).unwrap()),
        None => Bytes::new(),
    };
    let res = client
        .request(req.body(Full::new(payload)).unwrap())
        .await
        .unwrap();
    let status = res.status();
    let headers = res.headers().clone();
    let bytes = res.into_body().collect().await.unwrap().to_bytes();
    let json_val = serde_json::from_slice(&bytes)
        .unwrap_or_else(|_| json!({ "raw": String::from_utf8_lossy(&bytes) }));
    (status, headers, json_val)
}

fn chat_ok_response(
    model: &str,
    content: &str,
    prompt_tokens: u64,
    completion_tokens: u64,
) -> Vec<u8> {
    serde_json::to_vec(&json!({
        "id": "chatcmpl-test",
        "object": "chat.completion",
        "created": 1,
        "model": model,
        "choices": [{
            "index": 0,
            "message": { "role": "assistant", "content": content },
            "finish_reason": "stop"
        }],
        "usage": {
            "prompt_tokens": prompt_tokens,
            "completion_tokens": completion_tokens,
            "total_tokens": prompt_tokens + completion_tokens
        }
    }))
    .unwrap()
}

#[tokio::test]
async fn openrouter_overrides_zdr_regions_acl_intersection_and_context_guard() {
    let (us_addr, us_caps, _h1) = spawn_mock_http(|_, _| async {
        (
            StatusCode::OK,
            vec![],
            chat_ok_response("gpt-4o-us", "from-us", 10, 5),
        )
    })
    .await;
    let (eu_addr, eu_caps, _h2) = spawn_mock_http(|_, _| async {
        (
            StatusCode::OK,
            vec![],
            chat_ok_response("gpt-4o-eu", "from-eu-zdr", 10, 5),
        )
    })
    .await;
    let (big_addr, _big_caps, _h3) = spawn_mock_http(|_, _| async {
        (
            StatusCode::OK,
            vec![],
            chat_ok_response("gemini-big", "from-big-context", 10, 5),
        )
    })
    .await;
    let (shadow_addr, shadow_caps, _h4) = spawn_mock_http(|_, _| async {
        (
            StatusCode::OK,
            vec![],
            chat_ok_response("shadow-v2", "shadow-ok", 5, 5),
        )
    })
    .await;

    let cfg = format!(
        r#"
[server]
listen = "127.0.0.1:0"

[[upstreams]]
name = "us_up"
endpoints = ["http://{us_addr}"]

[[upstreams]]
name = "eu_up"
endpoints = ["http://{eu_addr}"]

[[upstreams]]
name = "big_up"
endpoints = ["http://{big_addr}"]

[[routes]]
id = "ai"
path_prefix = "/v1/"
upstream = "us_up"

[[routes.plugins]]
name = "ai-virtual-keys"
[routes.plugins.config]
[[routes.plugins.config.keys]]
id = "full"
api_key = "vk-full"
[[routes.plugins.config.keys]]
id = "us-only"
api_key = "vk-us-only"
allowed_providers = ["openai_us"]

[[routes.plugins]]
name = "ai-model-router"
[routes.plugins.config]
allow_request_routing_overrides = true
include_routing_headers = true

[[routes.plugins.config.shadow_targets]]
name = "eval-v2"
url = "http://{shadow_addr}/v1/chat/completions"
model = "shadow-v2"
sample_rate = 1.0

[routes.plugins.config.models]
smart = [
  {{ provider = "openai_us", upstream = "us_up", model = "gpt-4o-us", context_window = 50, zdr = false, regions = ["us"], tags = ["standard"] }},
  {{ provider = "openai_eu", upstream = "eu_up", model = "gpt-4o-eu", context_window = 50, zdr = true, regions = ["eu"], tags = ["hipaa", "soc2"] }},
  {{ provider = "gemini_big", upstream = "big_up", model = "gemini-big", context_window = 100000, zdr = true, regions = ["us", "eu"], tags = ["soc2"] }}
]
backup = [
  {{ provider = "openai_eu", upstream = "eu_up", model = "gpt-4o-eu", context_window = 100000, zdr = true, regions = ["eu"] }}
]

[[routes.plugins]]
name = "ai-provider-adapter"
[routes.plugins.config.providers.openai_us]
preset = "openai"
api_key = "sk-us"
[routes.plugins.config.providers.openai_eu]
preset = "openai"
api_key = "sk-eu"
[routes.plugins.config.providers.gemini_big]
preset = "openai"
api_key = "sk-big"
"#
    );

    let (addr, server, runtime, ai_metrics) = boot_gateway(&cfg, None).await;

    // 1. ZDR + region=eu + tags=["hipaa"] selects openai_eu AND strips `provider`/`models` upstream
    let (st, hdrs, body) = send_json(
        addr,
        Method::POST,
        "/v1/chat/completions",
        Some("vk-full"),
        Some(json!({
            "model": "smart",
            "provider": { "data_collection": "deny", "regions": ["eu"], "tags": ["hipaa"] },
            "messages": [{ "role": "user", "content": "hi" }]
        })),
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(hdrs.get("x-shunt-selected-provider").unwrap(), "openai_eu");
    assert_eq!(body["choices"][0]["message"]["content"], "from-eu-zdr");

    let eu_body: Value = serde_json::from_slice(&eu_caps.lock().unwrap()[0].body).unwrap();
    assert!(eu_body.get("provider").is_none());
    assert!(eu_body.get("models").is_none());

    // 2. Virtual-key ACL intersection: `us-only` key requesting `provider.only = ["openai_eu"]` MUST fail!
    let (st, _, err_body) = send_json(
        addr,
        Method::POST,
        "/v1/chat/completions",
        Some("vk-us-only"),
        Some(json!({
            "model": "smart",
            "provider": { "only": ["openai_eu"] },
            "messages": [{ "role": "user", "content": "hi" }]
        })),
    )
    .await;
    assert_eq!(st, StatusCode::BAD_REQUEST);
    assert_eq!(err_body["error"]["code"], "no_matching_provider");

    // 3. Context-window capability guard skips 50-token targets and routes long prompt to gemini_big
    let long_prompt = "word ".repeat(200);
    let (st, hdrs, body) = send_json(
        addr,
        Method::POST,
        "/v1/chat/completions",
        Some("vk-full"),
        Some(json!({
            "model": "smart",
            "messages": [{ "role": "user", "content": long_prompt }]
        })),
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(hdrs.get("x-shunt-selected-provider").unwrap(), "gemini_big");
    assert_eq!(body["choices"][0]["message"]["content"], "from-big-context");

    // 4. OpenRouter `models[]` without `model` + `provider.order`
    let (st, hdrs, _) = send_json(
        addr,
        Method::POST,
        "/v1/chat/completions",
        Some("vk-full"),
        Some(json!({
            "models": ["backup"],
            "messages": [{ "role": "user", "content": "hello" }]
        })),
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(hdrs.get("x-shunt-selected-provider").unwrap(), "openai_eu");
    assert_eq!(us_caps.lock().unwrap().len(), 0);

    // 5. Verify AI shadow target received shadowed copies with rewritten model & header
    for _ in 0..40 {
        if !shadow_caps.lock().unwrap().is_empty() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let shadows = shadow_caps.lock().unwrap().clone();
    assert!(!shadows.is_empty());
    assert_eq!(
        shadows[0].headers.get("x-shunt-shadow").map(String::as_str),
        Some("true")
    );
    let shadow_json: Value = serde_json::from_slice(&shadows[0].body).unwrap();
    assert_eq!(shadow_json["model"], "shadow-v2");

    let insp = inspect_ai_runtime(&ai_metrics, runtime.state_store(), runtime.clock().as_ref());
    assert!(insp["shadow_stats"][0]["sent"].as_u64().unwrap_or(0) >= 1);

    server.shutdown().await;
}

#[tokio::test]
async fn ttft_timeout_failover_and_context_overflow_400_failover() {
    let (slow_addr, _, _h1) = spawn_mock_http(|_, _| async {
        tokio::time::sleep(Duration::from_millis(300)).await;
        (
            StatusCode::OK,
            vec![],
            chat_ok_response("slow-m", "too-slow", 10, 5),
        )
    })
    .await;

    let (overflow_addr, _, _h2) = spawn_mock_http(|_, req| async move {
        let parsed: Value = serde_json::from_slice(&req.body).unwrap_or_default();
        let prompt = parsed["messages"][0]["content"].as_str().unwrap_or("");
        if prompt.contains("TRIGGER_OVERFLOW") {
            (
                StatusCode::BAD_REQUEST,
                vec![],
                serde_json::to_vec(&json!({
                    "error": {
                        "message": "This model's maximum context length is 8192 tokens.",
                        "type": "invalid_request_error",
                        "code": "context_length_exceeded"
                    }
                }))
                .unwrap(),
            )
        } else {
            (
                StatusCode::BAD_REQUEST,
                vec![],
                serde_json::to_vec(&json!({
                    "error": {
                        "message": "Invalid temperature parameter",
                        "type": "invalid_request_error",
                        "code": "invalid_parameter"
                    }
                }))
                .unwrap(),
            )
        }
    })
    .await;

    let (big_addr, _, _h3) = spawn_mock_http(|_, _| async {
        (
            StatusCode::OK,
            vec![],
            chat_ok_response("large-ctx-model", "recovered-large", 10, 5),
        )
    })
    .await;

    let cfg = format!(
        r#"
[server]
listen = "127.0.0.1:0"

[[upstreams]]
name = "slow_up"
endpoints = ["http://{slow_addr}"]

[[upstreams]]
name = "overflow_up"
endpoints = ["http://{overflow_addr}"]

[[upstreams]]
name = "big_up"
endpoints = ["http://{big_addr}"]

[[routes]]
id = "ai"
path_prefix = "/v1/"
upstream = "slow_up"
response_headers_timeout_ms = 5000

[[routes.plugins]]
name = "ai-model-router"
[routes.plugins.config]
include_routing_headers = true
enforce_context_window = false
[routes.plugins.config.models]
ttft-test = [
  {{ provider = "slow", upstream = "slow_up", model = "slow-m", ttft_timeout_ms = 70 }},
  {{ provider = "big", upstream = "big_up", model = "large-ctx-model" }}
]
overflow-test = [
  {{ provider = "small", upstream = "overflow_up", model = "small-m", context_window = 8192 }},
  {{ provider = "big", upstream = "big_up", model = "large-ctx-model", context_window = 200000 }}
]

[[routes.plugins]]
name = "ai-provider-adapter"
[routes.plugins.config.providers.slow]
preset = "openai"
api_key = "sk-1"
[routes.plugins.config.providers.small]
preset = "openai"
api_key = "sk-2"
[routes.plugins.config.providers.big]
preset = "openai"
api_key = "sk-3"

[[routes.plugins]]
name = "ai-failover"
[routes.plugins.config]
cooldown_ms = 5000
failover_on_context_overflow = true
"#
    );

    let (addr, server, _, _) = boot_gateway(&cfg, None).await;

    // 1. TTFT-timeout failover (70ms timeout on primary triggers automatic failover to big_up)
    let (st, hdrs, body) = send_json(
        addr,
        Method::POST,
        "/v1/chat/completions",
        None,
        Some(json!({
            "model": "ttft-test",
            "messages": [{ "role": "user", "content": "ping" }]
        })),
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(hdrs.get("x-shunt-selected-provider").unwrap(), "big");
    assert_eq!(body["choices"][0]["message"]["content"], "recovered-large");

    // 2. Context-overflow 400 body triggers failover to larger-context fallback
    let (st, hdrs, body) = send_json(
        addr,
        Method::POST,
        "/v1/chat/completions",
        None,
        Some(json!({
            "model": "overflow-test",
            "messages": [{ "role": "user", "content": "TRIGGER_OVERFLOW" }]
        })),
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(hdrs.get("x-shunt-selected-provider").unwrap(), "big");
    assert_eq!(body["choices"][0]["message"]["content"], "recovered-large");

    // 3. Ordinary non-overflow 400 passes through verbatim (no wasted failover)
    let (st, _, body) = send_json(
        addr,
        Method::POST,
        "/v1/chat/completions",
        None,
        Some(json!({
            "model": "overflow-test",
            "messages": [{ "role": "user", "content": "regular bad param" }]
        })),
    )
    .await;
    assert_eq!(st, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"]["code"], "invalid_parameter");

    server.shutdown().await;
}

#[tokio::test]
async fn throughput_and_headroom_routing_strategies_rank_dynamically() {
    let (p1_addr, _, _h1) = spawn_mock_http(|_, _| async {
        // Slow throughput (~100ms for 10 tokens -> ~100 tps) & low remaining headroom (1/100)
        tokio::time::sleep(Duration::from_millis(80)).await;
        (
            StatusCode::OK,
            vec![
                ("x-ratelimit-limit-requests".to_owned(), "100".to_owned()),
                ("x-ratelimit-remaining-requests".to_owned(), "1".to_owned()),
            ],
            chat_ok_response("m1", "from-p1", 10, 10),
        )
    })
    .await;

    let (p2_addr, _, _h2) = spawn_mock_http(|_, _| async {
        // High throughput (fast, 500 completion tokens) & abundant headroom (95/100)
        (
            StatusCode::OK,
            vec![
                ("x-ratelimit-limit-requests".to_owned(), "100".to_owned()),
                ("x-ratelimit-remaining-requests".to_owned(), "95".to_owned()),
            ],
            chat_ok_response("m2", "from-p2", 10, 500),
        )
    })
    .await;

    let cfg = format!(
        r#"
[server]
listen = "127.0.0.1:0"

[[upstreams]]
name = "u1"
endpoints = ["http://{p1_addr}"]

[[upstreams]]
name = "u2"
endpoints = ["http://{p2_addr}"]

[[routes]]
id = "ai"
path_prefix = "/v1/"
upstream = "u1"

[[routes.plugins]]
name = "ai-model-router"
[routes.plugins.config]
include_routing_headers = true

[routes.plugins.config.models.fast-tps]
strategy = "throughput"
targets = [
  {{ provider = "p1", upstream = "u1", model = "m1" }},
  {{ provider = "p2", upstream = "u2", model = "m2" }}
]

[routes.plugins.config.models.headroom-pool]
strategy = "headroom"
targets = [
  {{ provider = "p1", upstream = "u1", model = "m1", upstream_rpm = 100 }},
  {{ provider = "p2", upstream = "u2", model = "m2", upstream_rpm = 100 }}
]

[[routes.plugins]]
name = "ai-provider-adapter"
[routes.plugins.config.providers.p1]
preset = "openai"
api_key = "sk-1"
[routes.plugins.config.providers.p2]
preset = "openai"
api_key = "sk-2"

[[routes.plugins]]
name = "ai-usage-tracker"
[routes.plugins.config]
log_usage = false
"#
    );

    let (addr, server, _, _) = boot_gateway(&cfg, None).await;

    // Warm up both cold-start targets for throughput routing
    let _ = send_json(
        addr,
        Method::POST,
        "/v1/chat/completions",
        None,
        Some(json!({"model":"fast-tps","messages":[{"role":"user","content":"1"}]})),
    )
    .await;
    let _ = send_json(
        addr,
        Method::POST,
        "/v1/chat/completions",
        None,
        Some(json!({"model":"fast-tps","messages":[{"role":"user","content":"2"}]})),
    )
    .await;
    tokio::time::sleep(Duration::from_millis(30)).await;

    // 3rd request must pick higher-throughput p2
    let (st, hdrs, _) = send_json(
        addr,
        Method::POST,
        "/v1/chat/completions",
        None,
        Some(json!({"model":"fast-tps","messages":[{"role":"user","content":"3"}]})),
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(hdrs.get("x-shunt-routing-strategy").unwrap(), "throughput");
    assert_eq!(hdrs.get("x-shunt-selected-provider").unwrap(), "p2");

    // Headroom: p1 already reported 1/100 remaining; p2 reported 95/100 -> must pick p2!
    let (st, hdrs, _) = send_json(
        addr,
        Method::POST,
        "/v1/chat/completions",
        None,
        Some(json!({"model":"headroom-pool","messages":[{"role":"user","content":"h"}]})),
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(hdrs.get("x-shunt-routing-strategy").unwrap(), "headroom");
    assert_eq!(hdrs.get("x-shunt-selected-provider").unwrap(), "p2");

    server.shutdown().await;
}

#[tokio::test]
async fn key_expiry_concurrency_limits_per_model_quotas_preflight_holds_and_external_pricing() {
    let in_flight_gate = Arc::new(AtomicUsize::new(0));
    let gate_bg = Arc::clone(&in_flight_gate);
    let (up_addr, _, _h) = spawn_mock_http(move |_, req| {
        let gate = Arc::clone(&gate_bg);
        async move {
            let parsed: Value = serde_json::from_slice(&req.body).unwrap_or_default();
            let content = parsed["messages"][0]["content"].as_str().unwrap_or("");
            if content.contains("HOLD_CONCURRENT") {
                gate.fetch_add(1, Ordering::SeqCst);
                tokio::time::sleep(Duration::from_millis(180)).await;
            }
            (
                StatusCode::OK,
                vec![],
                chat_ok_response(
                    parsed["model"].as_str().unwrap_or("custom-litellm"),
                    "ok",
                    100,
                    50,
                ),
            )
        }
    })
    .await;

    // Write temporary LiteLLM-format external pricing JSON file
    let tmp_pricing =
        std::env::temp_dir().join(format!("shunt_rfc0017_prices_{}.json", std::process::id()));
    std::fs::write(
        &tmp_pricing,
        r#"{
            "custom-litellm": {
                "input_cost_per_token": 0.001,
                "output_cost_per_token": 0.002,
                "max_input_tokens": 32768,
                "max_output_tokens": 4096
            },
            "cheap-model": {
                "input_cost_per_token": 0.000001,
                "output_cost_per_token": 0.000001,
                "max_input_tokens": 16384,
                "max_output_tokens": 2048
            }
        }"#,
    )
    .unwrap();

    let clock = ManualClock::shared();
    clock.set_unix_timestamp_secs(1_700_000_000); // 2023-11-14T22:13:20Z

    let pricing_path_str = tmp_pricing.to_string_lossy().replace('\\', "/");
    let cfg = format!(
        r#"
[server]
listen = "127.0.0.1:0"

[[upstreams]]
name = "up"
endpoints = ["http://{up_addr}"]

[[routes]]
id = "ai"
path_prefix = "/v1/"
upstream = "up"

[[routes.plugins]]
name = "ai-virtual-keys"
[routes.plugins.config]
[[routes.plugins.config.keys]]
id = "expiring"
api_key = "vk-expiring"
expires_at = 1700000060

[[routes.plugins.config.keys]]
id = "alice"
api_key = "vk-alice"
org = "acme"
team = "eng"
max_parallel_requests = 1
budget_usd = 10.0
[routes.plugins.config.keys.model_limits.expensive]
rpm = 1

[[routes.plugins.config.keys]]
id = "burst-key"
api_key = "vk-burst"
org = "tight-org"
budget_usd = 0.50

[[routes.plugins]]
name = "ai-model-router"
[routes.plugins.config]
pricing_file = "{pricing_path_str}"
[routes.plugins.config.models]
expensive = [{{ provider = "p", upstream = "up", model = "custom-litellm", capabilities = ["chat"], zdr = true, regions = ["eu"] }}]
cheap = [{{ provider = "p", upstream = "up", model = "cheap-model", capabilities = ["chat"] }}]

[[routes.plugins]]
name = "ai-token-rate-limit"
[routes.plugins.config]
window_secs = 60

[[routes.plugins]]
name = "ai-budget"
[routes.plugins.config]
pricing_file = "{pricing_path_str}"
preflight_reserve = true
reserve_output_tokens_cap = 100
end_user_budget_usd = 0.30
[routes.plugins.config.org_budgets.tight-org]
limit_usd = 0.25

[[routes.plugins]]
name = "ai-provider-adapter"
[routes.plugins.config.providers.p]
preset = "openai"
api_key = "sk-test"

[[routes.plugins]]
name = "ai-usage-tracker"
[routes.plugins.config]
log_usage = false
"#
    );

    let (addr, server, _, _) = boot_gateway(&cfg, Some(Arc::clone(&clock))).await;

    // 1. Enriched `GET /v1/models` exposes context_length, max_output_tokens, pricing, capabilities, zdr, regions
    let (st, _, models_body) =
        send_json(addr, Method::GET, "/v1/models", Some("vk-alice"), None).await;
    assert_eq!(st, StatusCode::OK);
    let expensive_meta = models_body["data"]
        .as_array()
        .unwrap()
        .iter()
        .find(|m| m["id"] == "expensive")
        .unwrap();
    assert_eq!(expensive_meta["context_length"], 32_768);
    assert_eq!(expensive_meta["max_output_tokens"], 4_096);
    assert_eq!(expensive_meta["zdr"], true);
    assert_eq!(expensive_meta["regions"], json!(["eu"]));
    assert_eq!(expensive_meta["pricing"]["input_per_million_usd"], 1000.0);

    // 2. Virtual key `expires_at` works before expiry and rejects with 401 `api_key_expired` after advancing clock
    let (st, _, _) = send_json(
        addr,
        Method::POST,
        "/v1/chat/completions",
        Some("vk-expiring"),
        Some(json!({"model":"cheap","messages":[{"role":"user","content":"hi"}]})),
    )
    .await;
    assert_eq!(st, StatusCode::OK);

    clock.advance(Duration::from_secs(61));
    let (st, _, exp_body) = send_json(
        addr,
        Method::POST,
        "/v1/chat/completions",
        Some("vk-expiring"),
        Some(json!({"model":"cheap","messages":[{"role":"user","content":"hi"}]})),
    )
    .await;
    assert_eq!(st, StatusCode::UNAUTHORIZED);
    assert_eq!(exp_body["error"]["code"], "api_key_expired");

    // 3. `max_parallel_requests = 1`: concurrent 2nd request rejected with 429 `concurrency_limit_exceeded`,
    //    then succeeds cleanly after 1st completes (zero leak!).
    let f1 = tokio::spawn(send_json(
        addr,
        Method::POST,
        "/v1/chat/completions",
        Some("vk-alice"),
        Some(json!({"model":"cheap","messages":[{"role":"user","content":"HOLD_CONCURRENT"}]})),
    ));
    for _ in 0..40 {
        if in_flight_gate.load(Ordering::SeqCst) > 0 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    let (st2, hdrs2, body2) = send_json(
        addr,
        Method::POST,
        "/v1/chat/completions",
        Some("vk-alice"),
        Some(json!({"model":"cheap","messages":[{"role":"user","content":"second"}]})),
    )
    .await;
    assert_eq!(st2, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(body2["error"]["code"], "concurrency_limit_exceeded");
    assert_eq!(hdrs2.get("x-ratelimit-limit-concurrent").unwrap(), "1");
    assert_eq!(hdrs2.get("x-ratelimit-remaining-concurrent").unwrap(), "0");

    let (st1, _, _) = f1.await.unwrap();
    assert_eq!(st1, StatusCode::OK);
    tokio::time::sleep(Duration::from_millis(25)).await;

    // Slot is released cleanly -> next request succeeds
    let (st3, _, _) = send_json(
        addr,
        Method::POST,
        "/v1/chat/completions",
        Some("vk-alice"),
        Some(json!({"model":"cheap","messages":[{"role":"user","content":"after"}]})),
    )
    .await;
    assert_eq!(st3, StatusCode::OK);

    // 4. Per-model `model_limits`: alice has rpm=1 on `expensive` -> 1st succeeds, 2nd fails with 429,
    //    while `cheap` still succeeds!
    let (st, _, _) = send_json(
        addr,
        Method::POST,
        "/v1/chat/completions",
        Some("vk-alice"),
        Some(json!({"model":"expensive","max_tokens":10,"messages":[{"role":"user","content":"one"}]})),
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    let (st, _, body) = send_json(
        addr,
        Method::POST,
        "/v1/chat/completions",
        Some("vk-alice"),
        Some(json!({"model":"expensive","max_tokens":10,"messages":[{"role":"user","content":"two"}]})),
    )
    .await;
    assert_eq!(st, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(body["error"]["code"], "model_rpm_limit_exceeded");

    // 5. Pre-flight budget hold + org budget: `custom-litellm` costs $0.001/in + $0.002/out.
    //    With `max_tokens = 100`, preflight reserves ~$0.20+ against `tight-org` ($0.25 limit).
    //    First slow request holds ~$0.20; concurrent 2nd request must be rejected IMMEDIATELY
    //    by the pre-flight hold before 1st finishes!
    in_flight_gate.store(0, Ordering::SeqCst);
    let b1 = tokio::spawn(send_json(
        addr,
        Method::POST,
        "/v1/chat/completions",
        Some("vk-burst"),
        Some(json!({
            "model": "expensive",
            "user": "enduser-1",
            "max_tokens": 100,
            "messages": [{"role": "user", "content": "HOLD_CONCURRENT"}]
        })),
    ));
    for _ in 0..40 {
        if in_flight_gate.load(Ordering::SeqCst) > 0 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    let (bst2, _, bbody2) = send_json(
        addr,
        Method::POST,
        "/v1/chat/completions",
        Some("vk-burst"),
        Some(json!({
            "model": "expensive",
            "user": "enduser-1",
            "max_tokens": 100,
            "messages": [{"role": "user", "content": "burst-2"}]
        })),
    )
    .await;
    assert_eq!(bst2, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(bbody2["error"]["code"], "budget_exceeded");

    let (bst1, _, _) = b1.await.unwrap();
    assert_eq!(bst1, StatusCode::OK);

    let _ = std::fs::remove_file(&tmp_pricing);
    server.shutdown().await;
}
