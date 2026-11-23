use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use bytes::Bytes;
use http::{Request, Response, StatusCode, header};
use http_body_util::{BodyExt, Full};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::client::legacy::Client;
use hyper_util::rt::{TokioExecutor, TokioIo};
use serde_json::{Value, json};
use shunt_ai::{AiMetrics, register_ai_plugins};
use shunt_config::{ConfigProvider, InlineConfigProvider, SnapshotCompiler};
use shunt_engine::{
    GatewayServer, RespValue, RuntimeRegistry, decode_resp_frame, encode_resp_value,
};
use shunt_plugin_sdk::PluginRegistry;
use shunt_plugins::{PrometheusMetrics, register_builtin_plugins};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

// ---------------------------------------------------------------------------
// In-process mock Redis / Valkey RESP2 TCP server for multi-replica E2E tests
// ---------------------------------------------------------------------------

#[derive(Default)]
struct SharedRedisState {
    entries: HashMap<String, (String, Option<Instant>)>,
}

impl SharedRedisState {
    fn prune(&mut self) {
        let now = Instant::now();
        self.entries
            .retain(|_, (_, exp)| exp.map(|t| now < t).unwrap_or(true));
    }
}

async fn spawn_mock_redis_tcp() -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let state = Arc::new(Mutex::new(SharedRedisState::default()));

    let handle = tokio::spawn(async move {
        loop {
            let Ok((mut socket, _)) = listener.accept().await else {
                break;
            };
            let st = Arc::clone(&state);
            tokio::spawn(async move {
                let mut buf = Vec::new();
                let mut tmp = [0u8; 4096];
                while let Ok(n) = socket.read(&mut tmp).await {
                    if n == 0 {
                        break;
                    }
                    buf.extend_from_slice(&tmp[..n]);
                    while let Ok(Some((val, consumed))) = decode_resp_frame(&buf) {
                        buf.drain(..consumed);
                        let reply = dispatch_redis(val, &st);
                        let mut out = Vec::new();
                        encode_resp_value(&reply, &mut out);
                        if socket.write_all(&out).await.is_err() {
                            return;
                        }
                    }
                }
            });
        }
    });

    (addr, handle)
}

fn dispatch_redis(val: RespValue, state: &Arc<Mutex<SharedRedisState>>) -> RespValue {
    let RespValue::Array(Some(items)) = val else {
        return RespValue::Error("ERR expected array".to_owned());
    };
    let args: Vec<String> = items
        .into_iter()
        .filter_map(|v| match v {
            RespValue::BulkString(Some(b)) => Some(String::from_utf8_lossy(&b).into_owned()),
            RespValue::SimpleString(s) => Some(s),
            _ => None,
        })
        .collect();
    if args.is_empty() {
        return RespValue::Error("ERR empty command".to_owned());
    }

    let mut guard = state.lock().unwrap();
    guard.prune();

    match args[0].to_ascii_uppercase().as_str() {
        "PING" => RespValue::SimpleString("PONG".to_owned()),
        "AUTH" | "SELECT" => RespValue::SimpleString("OK".to_owned()),
        "GET" => match guard.entries.get(&args[1]) {
            Some((v, _)) => RespValue::BulkString(Some(v.as_bytes().to_vec())),
            None => RespValue::BulkString(None),
        },
        "SET" => {
            let key = args[1].clone();
            let val = args[2].clone();
            let mut exp = None;
            if args.len() >= 5
                && args[3].eq_ignore_ascii_case("PX")
                && let Ok(ms) = args[4].parse::<u64>()
            {
                exp = Some(Instant::now() + Duration::from_millis(ms));
            }
            guard.entries.insert(key, (val, exp));
            RespValue::SimpleString("OK".to_owned())
        }
        "EXISTS" => RespValue::Integer(i64::from(guard.entries.contains_key(&args[1]))),
        "DEL" => RespValue::Integer(i64::from(guard.entries.remove(&args[1]).is_some())),
        "EVAL" => {
            let script = &args[1];
            let key = args[3].clone();
            if script.contains("INCRBY") {
                let amt: i64 = args[4].parse().unwrap_or(0);
                let lim: i64 = args[5].parse().unwrap_or(0);
                let win: u64 = args[6].parse().unwrap_or(1000);
                let (cur, existing_exp) = guard
                    .entries
                    .get(&key)
                    .map(|(v, e)| (v.parse::<i64>().unwrap_or(0), *e))
                    .unwrap_or((0, None));
                if cur + amt <= lim {
                    let nxt = cur + amt;
                    let exp =
                        existing_exp.unwrap_or_else(|| Instant::now() + Duration::from_millis(win));
                    guard.entries.insert(key, (nxt.to_string(), Some(exp)));
                    RespValue::Array(Some(vec![
                        RespValue::Integer(1),
                        RespValue::Integer(nxt),
                        RespValue::Integer((lim - nxt).max(0)),
                        RespValue::Integer(0),
                    ]))
                } else {
                    let pttl = existing_exp
                        .map(|t| t.saturating_duration_since(Instant::now()).as_millis() as u64)
                        .unwrap_or(win);
                    let retry = pttl.div_ceil(1000).max(1) as i64;
                    RespValue::Array(Some(vec![
                        RespValue::Integer(0),
                        RespValue::Integer(cur),
                        RespValue::Integer((lim - cur).max(0)),
                        RespValue::Integer(retry),
                    ]))
                }
            } else {
                let delta: i64 = args[4].parse().unwrap_or(0);
                let ttl: u64 = args[5].parse().unwrap_or(1000);
                let (cur, existing_exp) = guard
                    .entries
                    .get(&key)
                    .map(|(v, e)| (v.parse::<i64>().unwrap_or(0), *e))
                    .unwrap_or((0, None));
                let nxt = (cur + delta).max(0);
                let exp =
                    existing_exp.unwrap_or_else(|| Instant::now() + Duration::from_millis(ttl));
                guard.entries.insert(key, (nxt.to_string(), Some(exp)));
                RespValue::Integer(nxt)
            }
        }
        other => RespValue::Error(format!("ERR unknown command {other}")),
    }
}

// ---------------------------------------------------------------------------
// Mock HTTP upstream server
// ---------------------------------------------------------------------------

async fn spawn_mock_http(
    status: StatusCode,
    body_json: Value,
) -> (SocketAddr, Arc<AtomicUsize>, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let hits = Arc::new(AtomicUsize::new(0));
    let hits_clone = Arc::clone(&hits);
    let body_bytes = Bytes::from(serde_json::to_vec(&body_json).unwrap());

    let handle = tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                break;
            };
            let h = Arc::clone(&hits_clone);
            let b = body_bytes.clone();
            tokio::spawn(async move {
                let io = TokioIo::new(stream);
                let svc = service_fn(move |_req: Request<hyper::body::Incoming>| {
                    h.fetch_add(1, Ordering::SeqCst);
                    let body = b.clone();
                    async move {
                        Ok::<_, hyper::Error>(
                            Response::builder()
                                .status(status)
                                .header(header::CONTENT_TYPE, "application/json")
                                .body(Full::new(body))
                                .unwrap(),
                        )
                    }
                });
                let _ = http1::Builder::new().serve_connection(io, svc).await;
            });
        }
    });

    (addr, hits, handle)
}

async fn start_replica(toml_src: &str) -> (SocketAddr, shunt_engine::ServerHandle, Arc<AiMetrics>) {
    let metrics = Arc::new(PrometheusMetrics::new());
    let ai_metrics = Arc::new(AiMetrics::new());
    let mut reg = PluginRegistry::new();
    register_builtin_plugins(&mut reg, metrics);
    register_ai_plugins(&mut reg, Arc::clone(&ai_metrics));
    let runtime = Arc::new(RuntimeRegistry::new());
    let compiler = SnapshotCompiler::new(Arc::new(reg), runtime);
    let loaded = InlineConfigProvider::from_toml("replica.toml", toml_src)
        .load()
        .unwrap();
    let bundle = compiler.compile(&loaded).unwrap();
    assert_eq!(bundle.inspect.state_backend, "redis");
    let handle = GatewayServer::new(bundle.snapshot)
        .with_drain_timeout(Duration::from_secs(2))
        .bind("127.0.0.1:0".parse().unwrap())
        .await
        .unwrap();
    let addr = handle.local_addr();
    (addr, handle, ai_metrics)
}

async fn post_chat(addr: SocketAddr, key: &str, model: &str, content: &str) -> (StatusCode, Value) {
    let client = Client::builder(TokioExecutor::new()).build_http::<Full<Bytes>>();
    let body = serde_json::to_vec(&json!({
        "model": model,
        "messages": [{ "role": "user", "content": content }]
    }))
    .unwrap();
    let req = Request::builder()
        .method("POST")
        .uri(format!("http://{addr}/v1/chat/completions"))
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::AUTHORIZATION, format!("Bearer {key}"))
        .body(Full::new(Bytes::from(body)))
        .unwrap();
    let res = client.request(req).await.unwrap();
    let status = res.status();
    let bytes = res.into_body().collect().await.unwrap().to_bytes();
    let val = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    (status, val)
}

#[tokio::test]
async fn multi_replica_shared_rpm_budget_and_failover_cooldown_via_redis() {
    let (redis_addr, redis_handle) = spawn_mock_redis_tcp().await;

    // Primary upstream returns 503 so we can verify distributed failover cooldowns,
    // and backup upstream returns 200 with usage costing $0.006 per call.
    let (primary_addr, primary_hits, primary_handle) = spawn_mock_http(
        StatusCode::SERVICE_UNAVAILABLE,
        json!({"error": {"message": "overloaded"}}),
    )
    .await;
    let (backup_addr, backup_hits, backup_handle) = spawn_mock_http(
        StatusCode::OK,
        json!({
            "id": "chatcmpl-dist-1",
            "object": "chat.completion",
            "model": "gpt-4o",
            "choices": [{"index": 0, "message": {"role": "assistant", "content": "from backup"}, "finish_reason": "stop"}],
            "usage": {"prompt_tokens": 400, "completion_tokens": 500, "total_tokens": 900}
        }),
    )
    .await;

    // gpt-4o @ $2.50/1M in, $10/1M out: 400 in ($0.001) + 500 out ($0.005) = $0.006 per request
    // Alice budget = $0.010 -> 1st call on Replica A ($0.006), 2nd call on Replica B ($0.012), 3rd call rejected 402 on Replica A!
    let cfg_toml = format!(
        r#"
[server]
listen = "127.0.0.1:0"
[admin]
enabled = false

[state]
backend = "redis"
url = "redis://{redis_addr}/0"
key_prefix = "shunt_test:"
pool_size = 4
connect_timeout_ms = 1000
command_timeout_ms = 500
failure_policy = "fail_closed"

[[upstreams]]
name = "primary"
endpoints = ["http://{primary_addr}"]

[[upstreams]]
name = "backup"
endpoints = ["http://{backup_addr}"]

[[routes]]
id = "api_rl"
path_prefix = "/api"
upstream = "backup"
[[routes.plugins]]
name = "rate-limit"
id = "http_rl"
[routes.plugins.config]
requests_per_second = 2.0
burst = 2
key = "global"

[[routes]]
id = "ai_dist"
path_prefix = "/v1"
upstream = "primary"
max_attempts = 2

[[routes.plugins]]
name = "ai-virtual-keys"
id = "vkeys"
[routes.plugins.config]
[[routes.plugins.config.keys]]
id = "alice"
api_key = "sk-alice-dist"
team = "platform"
rpm = 10
tpm = 100000
budget_usd = 0.010
budget_window = "daily"

[[routes.plugins]]
name = "ai-model-router"
id = "router"
[routes.plugins.config.models]
smart = [
  {{ provider = "primary", upstream = "primary", model = "gpt-4o" }},
  {{ provider = "backup", upstream = "backup", model = "gpt-4o" }},
]

[[routes.plugins]]
name = "ai-token-rate-limit"
id = "token_rl"
[routes.plugins.config]
rpm = 100
tpm = 100000
window_secs = 60

[[routes.plugins]]
name = "ai-budget"
id = "budget"
[routes.plugins.config]
scope = "virtual_key"
reject_status = 402
use_builtin_pricing = false
[routes.plugins.config.pricing."gpt-4o"]
input_per_million_usd = 2.50
output_per_million_usd = 10.00

[[routes.plugins]]
name = "ai-provider-adapter"
id = "adapter"
[routes.plugins.config.providers.primary]
dialect = "openai_compatible"
auth = {{ type = "none" }}
[routes.plugins.config.providers.backup]
dialect = "openai_compatible"
auth = {{ type = "none" }}

[[routes.plugins]]
name = "ai-failover"
id = "failover"
[routes.plugins.config]
retry_statuses = [503]
cooldown_ms = 30000

[[routes.plugins]]
name = "ai-usage-tracker"
id = "usage"
[routes.plugins.config]
log_usage = false
"#
    );

    // Boot TWO completely independent gateway replicas sharing only Redis!
    let (addr_a, gw_a, metrics_a) = start_replica(&cfg_toml).await;
    let (addr_b, gw_b, metrics_b) = start_replica(&cfg_toml).await;

    // 1. Path B: Shared HTTP `rate-limit` (burst = 2 across Replica A + Replica B)
    let client = Client::builder(TokioExecutor::new()).build_http::<Full<Bytes>>();
    let r1 = client
        .request(
            Request::builder()
                .uri(format!("http://{addr_a}/api/ping"))
                .body(Full::new(Bytes::new()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(r1.status(), StatusCode::OK);
    let r2 = client
        .request(
            Request::builder()
                .uri(format!("http://{addr_b}/api/ping"))
                .body(Full::new(Bytes::new()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(r2.status(), StatusCode::OK);
    // 3rd request hits Replica A and MUST be rejected 429 because Redis counter is at 2!
    let r3 = client
        .request(
            Request::builder()
                .uri(format!("http://{addr_a}/api/ping"))
                .body(Full::new(Bytes::new()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(r3.status(), StatusCode::TOO_MANY_REQUESTS);

    // 2. Path A: Distributed failover cooldown + shared spend budget across Replica A & B
    // Call 1 on Replica A: hits primary (503) -> sets distributed cooldown in Redis -> fails over to backup (200), charges $0.006
    let (st1, _) = post_chat(addr_a, "sk-alice-dist", "smart", "hello from replica A").await;
    assert_eq!(st1, StatusCode::OK);
    assert_eq!(primary_hits.load(Ordering::SeqCst), 1);
    assert_eq!(backup_hits.load(Ordering::SeqCst), 3); // 2 from /api/ping + 1 from chat

    // Allow async on_complete budget charge to finish
    tokio::time::sleep(Duration::from_millis(50)).await;

    // Call 2 on Replica B: MUST skip primary completely because Replica A stored the cooldown in Redis!
    let (st2, _) = post_chat(addr_b, "sk-alice-dist", "smart", "hello from replica B").await;
    assert_eq!(st2, StatusCode::OK);
    assert_eq!(
        primary_hits.load(Ordering::SeqCst),
        1,
        "Replica B should skip primary due to distributed cooldown in Redis"
    );
    assert_eq!(backup_hits.load(Ordering::SeqCst), 4);

    // Allow async on_complete budget charge on Replica B to push shared spend to $0.012 (> $0.010 limit)
    tokio::time::sleep(Duration::from_millis(50)).await;

    // Call 3 on Replica A: MUST be rejected with 402 budget_exceeded from shared Redis spend!
    let (st3, body3) = post_chat(addr_a, "sk-alice-dist", "smart", "should be rejected").await;
    assert_eq!(st3, StatusCode::PAYMENT_REQUIRED);
    assert_eq!(body3["error"]["code"], "budget_exceeded");

    // Verify per-replica Prometheus cost metrics were recorded accurately
    assert!((metrics_a.snapshot().total_cost_usd - 0.006).abs() < 1e-6);
    assert!((metrics_b.snapshot().total_cost_usd - 0.006).abs() < 1e-6);

    gw_a.shutdown().await;
    gw_b.shutdown().await;
    primary_handle.abort();
    backup_handle.abort();
    redis_handle.abort();
}

#[tokio::test]
async fn distributed_store_fail_open_and_fail_closed_when_redis_unreachable() {
    let (up_addr, _hits, up_handle) = spawn_mock_http(
        StatusCode::OK,
        json!({
            "id": "chatcmpl-fallback",
            "object": "chat.completion",
            "model": "gpt-4o",
            "choices": [{"index": 0, "message": {"role": "assistant", "content": "ok"}, "finish_reason": "stop"}],
            "usage": {"prompt_tokens": 5, "completion_tokens": 5, "total_tokens": 10}
        }),
    )
    .await;

    // Allocate an unused closed port so Redis connections fail immediately with ConnectionRefused.
    let closed_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let closed_port = closed_listener.local_addr().unwrap().port();
    drop(closed_listener);

    let make_cfg = |policy: &str| {
        format!(
            r#"
[server]
listen = "127.0.0.1:0"
[admin]
enabled = false

[state]
backend = "redis"
url = "redis://127.0.0.1:{closed_port}/0"
connect_timeout_ms = 200
command_timeout_ms = 200
failure_policy = "{policy}"

[[upstreams]]
name = "up"
endpoints = ["http://{up_addr}"]

[[routes]]
id = "r"
path_prefix = "/v1"
upstream = "up"
[[routes.plugins]]
name = "ai-model-router"
[routes.plugins.config.models]
smart = [{{ provider = "up", upstream = "up", model = "gpt-4o" }}]
[[routes.plugins]]
name = "ai-token-rate-limit"
[routes.plugins.config]
rpm = 10
tpm = 1000
[[routes.plugins]]
name = "ai-provider-adapter"
[routes.plugins.config.providers.up]
dialect = "openai_compatible"
auth = {{ type = "none" }}
"#
        )
    };

    let (open_addr, gw_open, _) = start_replica(&make_cfg("fail_open")).await;
    let (st_open, _) = post_chat(open_addr, "any", "smart", "hi").await;
    assert_eq!(st_open, StatusCode::OK);
    gw_open.shutdown().await;

    let (closed_addr, gw_closed, _) = start_replica(&make_cfg("fail_closed")).await;
    let (st_closed, _) = post_chat(closed_addr, "any", "smart", "hi").await;
    assert_eq!(st_closed, StatusCode::SERVICE_UNAVAILABLE);
    gw_closed.shutdown().await;

    up_handle.abort();
}
