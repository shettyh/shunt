use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use bytes::Bytes;
use http::{Request, Response, StatusCode, header};
use http_body::Frame;
use http_body_util::{BodyExt, Full};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::client::legacy::Client;
use hyper_util::rt::{TokioExecutor, TokioIo};
use serde_json::{Value, json};
use shunt_ai::{
    AiFailoverFactory, AiMetrics, AiModelRouterFactory, AiProviderAdapterFactory, AiUsageReport,
    AiUsageTrackerFactory, SseParser, register_ai_plugins,
};
use shunt_config::{ConfigProvider, InlineConfigProvider, SnapshotCompiler};
use shunt_core::{GatewayServer, RuntimeRegistry};
use shunt_plugin_sdk::PluginRegistry;
use shunt_plugins::{PrometheusMetrics, register_builtin_plugins};
use tokio::net::TcpListener;
use tokio::sync::Mutex;

type BoxBody = http_body_util::combinators::BoxBody<Bytes, Infallible>;

fn full_json(status: StatusCode, body: Value) -> Response<BoxBody> {
    let bytes = Bytes::from(serde_json::to_vec(&body).unwrap());
    Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Full::new(bytes).boxed())
        .unwrap()
}

struct ReceiverStream {
    rx: tokio::sync::mpsc::Receiver<Result<Frame<Bytes>, Infallible>>,
}

impl http_body::Body for ReceiverStream {
    type Data = Bytes;
    type Error = Infallible;

    fn poll_frame(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        self.rx.poll_recv(cx)
    }
}

fn sse_response_direct(chunks: Vec<Bytes>, chunk_delay: Duration) -> Response<BoxBody> {
    let (tx, rx) = tokio::sync::mpsc::channel::<Result<Frame<Bytes>, Infallible>>(32);
    tokio::spawn(async move {
        for chunk in chunks {
            if !chunk_delay.is_zero() {
                tokio::time::sleep(chunk_delay).await;
            }
            if tx.send(Ok(Frame::data(chunk))).await.is_err() {
                break;
            }
        }
    });

    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "text/event-stream")
        .header(header::CACHE_CONTROL, "no-cache")
        .body(ReceiverStream { rx }.boxed())
        .unwrap()
}

#[derive(Debug, Clone)]
struct CapturedReq {
    path: String,
    auth: Option<String>,
    x_api_key: Option<String>,
    anthropic_version: Option<String>,
    accept_encoding: Option<String>,
    body: Value,
}

async fn spawn_mock_server<F, Fut>(handler: F) -> SocketAddr
where
    F: Fn(CapturedReq) -> Fut + Send + Sync + 'static,
    Fut: std::future::Future<Output = Response<BoxBody>> + Send + 'static,
{
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handler = Arc::new(handler);

    tokio::spawn(async move {
        loop {
            let Ok((tcp, _)) = listener.accept().await else {
                break;
            };
            let h = Arc::clone(&handler);
            tokio::spawn(async move {
                let svc = service_fn(move |req: Request<hyper::body::Incoming>| {
                    let h = Arc::clone(&h);
                    async move {
                        let path = req.uri().path().to_owned();
                        let auth = req
                            .headers()
                            .get(header::AUTHORIZATION)
                            .and_then(|v| v.to_str().ok())
                            .map(str::to_owned);
                        let x_api_key = req
                            .headers()
                            .get("x-api-key")
                            .and_then(|v| v.to_str().ok())
                            .map(str::to_owned);
                        let anthropic_version = req
                            .headers()
                            .get("anthropic-version")
                            .and_then(|v| v.to_str().ok())
                            .map(str::to_owned);
                        let accept_encoding = req
                            .headers()
                            .get(header::ACCEPT_ENCODING)
                            .and_then(|v| v.to_str().ok())
                            .map(str::to_owned);
                        let bytes = req.into_body().collect().await.unwrap().to_bytes();
                        let body: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);

                        let captured = CapturedReq {
                            path,
                            auth,
                            x_api_key,
                            anthropic_version,
                            accept_encoding,
                            body,
                        };
                        Ok::<_, Infallible>(h(captured).await)
                    }
                });
                let _ = http1::Builder::new()
                    .serve_connection(TokioIo::new(tcp), svc)
                    .await;
            });
        }
    });

    addr
}

async fn post_chat(
    addr: SocketAddr,
    body: Value,
    extra_headers: &[(&str, &str)],
) -> (StatusCode, http::HeaderMap, Bytes) {
    let client: Client<_, Full<Bytes>> = Client::builder(TokioExecutor::new()).build_http();
    let payload = Bytes::from(serde_json::to_vec(&body).unwrap());
    let mut builder = Request::builder()
        .method("POST")
        .uri(format!("http://{addr}/v1/chat/completions"))
        .header(header::CONTENT_TYPE, "application/json");
    for &(k, v) in extra_headers {
        builder = builder.header(k, v);
    }
    let req = builder.body(Full::new(payload)).unwrap();
    let res = client.request(req).await.unwrap();
    let status = res.status();
    let headers = res.headers().clone();
    let bytes = res.into_body().collect().await.unwrap().to_bytes();
    (status, headers, bytes)
}

fn compile_toml(
    toml_str: &str,
    plugins: Arc<PluginRegistry>,
    runtime: Arc<RuntimeRegistry>,
) -> shunt_config::CompiledBundle {
    let loaded = InlineConfigProvider::from_toml("test.toml", toml_str)
        .load()
        .unwrap();
    let compiler = SnapshotCompiler::new(plugins, runtime);
    compiler.compile(&loaded).unwrap()
}

#[tokio::test]
async fn openai_non_stream_and_stream_with_usage_and_metrics() {
    let captured_reqs: Arc<Mutex<Vec<CapturedReq>>> = Arc::new(Mutex::new(Vec::new()));
    let cap_clone = Arc::clone(&captured_reqs);

    let openai_addr = spawn_mock_server(move |req| {
        let cap = Arc::clone(&cap_clone);
        async move {
            let is_stream = req
                .body
                .get("stream")
                .and_then(Value::as_bool)
                .unwrap_or(false);
            cap.lock().await.push(req);

            if is_stream {
                let chunks = vec![
                    Bytes::from_static(
                        b"data: {\"id\":\"chatcmpl-1\",\"object\":\"chat.completion.chunk\",\"created\":1,\"model\":\"gpt-4o-2024-08-06\",\"choices\":[{\"index\":0,\"delta\":{\"role\":\"assistant\",\"content\":\"\"},\"finish_reason\":null}]}\n\n",
                    ),
                    Bytes::from_static(
                        b"data: {\"id\":\"chatcmpl-1\",\"object\":\"chat.completion.chunk\",\"created\":1,\"model\":\"gpt-4o-2024-08-06\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"Hi \"},\"finish_reason\":null}]}\n\n",
                    ),
                    Bytes::from_static(
                        b"data: {\"id\":\"chatcmpl-1\",\"object\":\"chat.completion.chunk\",\"created\":1,\"model\":\"gpt-4o-2024-08-06\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"there!\"},\"finish_reason\":null}]}\n\n",
                    ),
                    Bytes::from_static(
                        b"data: {\"id\":\"chatcmpl-1\",\"object\":\"chat.completion.chunk\",\"created\":1,\"model\":\"gpt-4o-2024-08-06\",\"choices\":[{\"index\":0,\"delta\":{},\"finish_reason\":\"stop\"}]}\n\n",
                    ),
                    Bytes::from_static(
                        b"data: {\"id\":\"chatcmpl-1\",\"object\":\"chat.completion.chunk\",\"created\":1,\"model\":\"gpt-4o-2024-08-06\",\"choices\":[],\"usage\":{\"prompt_tokens\":14,\"completion_tokens\":6,\"total_tokens\":20}}\n\n",
                    ),
                    Bytes::from_static(b"data: [DONE]\n\n"),
                ];
                sse_response_direct(chunks, Duration::from_millis(2))
            } else {
                full_json(
                    StatusCode::OK,
                    json!({
                        "id": "chatcmpl-nonstream",
                        "object": "chat.completion",
                        "created": 1700000000,
                        "model": "gpt-4o-2024-08-06",
                        "choices": [{
                            "index": 0,
                            "message": {"role": "assistant", "content": "Hello from OpenAI!"},
                            "finish_reason": "stop"
                        }],
                        "usage": {
                            "prompt_tokens": 10,
                            "completion_tokens": 5,
                            "total_tokens": 15
                        }
                    }),
                )
            }
        }
    })
    .await;

    let ai_metrics = Arc::new(AiMetrics::new());
    let reports: Arc<std::sync::Mutex<Vec<AiUsageReport>>> =
        Arc::new(std::sync::Mutex::new(Vec::new()));
    let reports_sink = Arc::clone(&reports);

    let mut reg = PluginRegistry::new();
    let prom = Arc::new(PrometheusMetrics::new());
    register_builtin_plugins(&mut reg, prom);
    reg.register(AiModelRouterFactory)
        .register(AiProviderAdapterFactory)
        .register(AiFailoverFactory)
        .register(
            AiUsageTrackerFactory::new(Arc::clone(&ai_metrics)).with_sink(Arc::new(move |r| {
                reports_sink.lock().unwrap().push(r.clone());
            })),
        );

    let toml_cfg = format!(
        r#"
[server]
listen = "127.0.0.1:0"

[admin]
enabled = false

[[upstreams]]
name = "openai"
endpoints = ["http://{openai_addr}"]

[[routes]]
id = "ai_chat"
path_exact = "/v1/chat/completions"
methods = ["POST"]
upstream = "openai"

[[routes.plugins]]
name = "ai-model-router"
[routes.plugins.config.models]
default-gpt = [{{ provider = "openai", upstream = "openai", model = "gpt-4o-2024-08-06" }}]

[[routes.plugins]]
name = "ai-provider-adapter"
[routes.plugins.config.providers.openai]
dialect = "openai_compatible"
auth = {{ type = "bearer", api_key = "sk-test-openai-secret" }}
include_stream_usage = true

[[routes.plugins]]
name = "ai-usage-tracker"
[routes.plugins.config]
log_usage = false
"#
    );

    let runtime = Arc::new(RuntimeRegistry::new());
    let bundle = compile_toml(&toml_cfg, Arc::new(reg), runtime);
    let gw = GatewayServer::new(bundle.snapshot)
        .bind("127.0.0.1:0".parse().unwrap())
        .await
        .unwrap();
    let gw_addr = gw.local_addr();

    // 1. Non-streaming OpenAI request
    let (status, headers, body) = post_chat(
        gw_addr,
        json!({
            "model": "default-gpt",
            "messages": [{"role": "user", "content": "Say hi"}]
        }),
        &[
            ("authorization", "Bearer client-gateway-key"),
            ("accept-encoding", "gzip"),
        ],
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(headers.get("x-shunt-provider").unwrap(), "openai");
    assert_eq!(headers.get("x-shunt-model").unwrap(), "gpt-4o-2024-08-06");
    let json_body: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(
        json_body["choices"][0]["message"]["content"],
        "Hello from OpenAI!"
    );

    // 2. Streaming OpenAI request
    let (status2, headers2, body2) = post_chat(
        gw_addr,
        json!({
            "model": "default-gpt",
            "stream": true,
            "messages": [{"role": "user", "content": "Stream hi"}]
        }),
        &[],
    )
    .await;
    assert_eq!(status2, StatusCode::OK);
    assert!(
        headers2
            .get(header::CONTENT_TYPE)
            .unwrap()
            .to_str()
            .unwrap()
            .contains("text/event-stream")
    );
    let stream_text = String::from_utf8(body2.to_vec()).unwrap();
    assert!(stream_text.contains("Hi "));
    assert!(stream_text.contains("there!"));
    assert!(stream_text.contains("data: [DONE]"));

    // Allow spawned on_complete hooks to flush.
    tokio::time::sleep(Duration::from_millis(50)).await;

    // Verify upstream saw provider key (not client key), rewritten model, identity accept-encoding, and stream_options.
    let reqs = captured_reqs.lock().await;
    assert_eq!(reqs.len(), 2);
    assert_eq!(reqs[0].path, "/v1/chat/completions");
    assert_eq!(
        reqs[0].auth.as_deref(),
        Some("Bearer sk-test-openai-secret")
    );
    assert_eq!(reqs[0].accept_encoding.as_deref(), Some("identity"));
    assert_eq!(reqs[0].body["model"], "gpt-4o-2024-08-06");
    assert_eq!(reqs[1].body["stream_options"]["include_usage"], true);

    // Verify usage reports & Prometheus metrics.
    {
        let reps = reports.lock().unwrap();
        assert_eq!(reps.len(), 2);
        assert_eq!(reps[0].prompt_tokens, Some(10));
        assert_eq!(reps[0].completion_tokens, Some(5));
        assert_eq!(reps[0].total_tokens, Some(15));
        assert!(reps[0].ttft.is_some());

        assert_eq!(reps[1].prompt_tokens, Some(14));
        assert_eq!(reps[1].completion_tokens, Some(6));
        assert_eq!(reps[1].total_tokens, Some(20));
        assert!(reps[1].stream);
        assert!(reps[1].ttft.is_some());
    }

    let snap = ai_metrics.snapshot();
    assert_eq!(snap.total_requests, 2);
    assert_eq!(snap.total_prompt_tokens, 24);
    assert_eq!(snap.total_completion_tokens, 11);

    let prom_text = ai_metrics.render_prometheus();
    assert!(prom_text.contains("shunt_ai_requests_total"));
    assert!(prom_text.contains("shunt_ai_tokens_total"));
    assert!(prom_text.contains("shunt_ai_ttft_seconds"));

    gw.shutdown().await;
}

#[tokio::test]
async fn anthropic_translation_non_stream_and_live_sse_with_weird_chunk_splits() {
    let captured_reqs: Arc<Mutex<Vec<CapturedReq>>> = Arc::new(Mutex::new(Vec::new()));
    let cap_clone = Arc::clone(&captured_reqs);

    let anthropic_addr = spawn_mock_server(move |req| {
        let cap = Arc::clone(&cap_clone);
        async move {
            let is_stream = req
                .body
                .get("stream")
                .and_then(Value::as_bool)
                .unwrap_or(false);
            cap.lock().await.push(req);

            if is_stream {
                let raw_sse = concat!(
                    "event: message_start\n",
                    "data: {\"type\":\"message_start\",\"message\":{\"id\":\"msg_stream_99\",\"type\":\"message\",\"role\":\"assistant\",\"content\":[],\"model\":\"claude-3-5-sonnet-20241022\",\"usage\":{\"input_tokens\":31,\"output_tokens\":1}}}\n\n",
                    "event: content_block_start\n",
                    "data: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"text\",\"text\":\"\"}}\n\n",
                    "event: ping\n",
                    "data: {\"type\":\"ping\"}\n\n",
                    "event: content_block_delta\n",
                    "data: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"Rust \"}}\n\n",
                    "event: content_block_delta\n",
                    "data: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"rocks!\"}}\n\n",
                    "event: content_block_stop\n",
                    "data: {\"type\":\"content_block_stop\",\"index\":0}\n\n",
                    "event: message_delta\n",
                    "data: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"end_turn\",\"stop_sequence\":null},\"usage\":{\"output_tokens\":9}}\n\n",
                    "event: message_stop\n",
                    "data: {\"type\":\"message_stop\"}\n\n"
                );
                // Split into tiny 17-byte chunks to stress incremental SSE framing!
                let chunks: Vec<Bytes> = raw_sse
                    .as_bytes()
                    .chunks(17)
                    .map(Bytes::copy_from_slice)
                    .collect();
                sse_response_direct(chunks, Duration::from_millis(1))
            } else {
                full_json(
                    StatusCode::OK,
                    json!({
                        "id": "msg_json_42",
                        "type": "message",
                        "role": "assistant",
                        "model": "claude-3-5-sonnet-20241022",
                        "content": [
                            {"type": "text", "text": "Translated from Anthropic!"}
                        ],
                        "stop_reason": "end_turn",
                        "usage": {
                            "input_tokens": 19,
                            "output_tokens": 8
                        }
                    }),
                )
            }
        }
    })
    .await;

    let ai_metrics = Arc::new(AiMetrics::new());
    let mut reg = PluginRegistry::new();
    register_ai_plugins(&mut reg, Arc::clone(&ai_metrics));

    let toml_cfg = format!(
        r#"
[server]
listen = "127.0.0.1:0"

[admin]
enabled = false

[[upstreams]]
name = "anthropic"
endpoints = ["http://{anthropic_addr}"]

[[routes]]
id = "ai_chat"
path_exact = "/v1/chat/completions"
methods = ["POST"]
upstream = "anthropic"

[[routes.plugins]]
name = "ai-model-router"
[[routes.plugins.config.rules]]
pattern = "claude-*"
targets = [{{ provider = "anthropic", upstream = "anthropic" }}]

[[routes.plugins]]
name = "ai-provider-adapter"
[routes.plugins.config.providers.anthropic]
dialect = "anthropic"
auth = {{ type = "header", header = "x-api-key", api_key = "sk-ant-test-key" }}
anthropic_version = "2023-06-01"
default_max_tokens = 2048

[[routes.plugins]]
name = "ai-usage-tracker"
[routes.plugins.config]
log_usage = false
"#
    );

    let runtime = Arc::new(RuntimeRegistry::new());
    let bundle = compile_toml(&toml_cfg, Arc::new(reg), runtime);
    let gw = GatewayServer::new(bundle.snapshot)
        .bind("127.0.0.1:0".parse().unwrap())
        .await
        .unwrap();
    let gw_addr = gw.local_addr();

    // 1. Non-streaming OpenAI request -> Anthropic Messages -> translated OpenAI JSON
    let (status, headers, body) = post_chat(
        gw_addr,
        json!({
            "model": "claude-3-5-sonnet-20241022",
            "messages": [
                {"role": "system", "content": "Be brief."},
                {"role": "user", "content": "Hello Claude"}
            ]
        }),
        &[("authorization", "Bearer client-token-must-be-stripped")],
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(headers.get("x-shunt-provider").unwrap(), "anthropic");
    let resp: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(resp["id"], "chatcmpl-msg_json_42");
    assert_eq!(resp["object"], "chat.completion");
    assert_eq!(
        resp["choices"][0]["message"]["content"],
        "Translated from Anthropic!"
    );
    assert_eq!(resp["choices"][0]["finish_reason"], "stop");
    assert_eq!(resp["usage"]["prompt_tokens"], 19);
    assert_eq!(resp["usage"]["completion_tokens"], 8);
    assert_eq!(resp["usage"]["total_tokens"], 27);

    // 2. Streaming OpenAI request -> Anthropic SSE -> live translated OpenAI SSE
    let (status2, headers2, body2) = post_chat(
        gw_addr,
        json!({
            "model": "claude-3-5-sonnet-20241022",
            "stream": true,
            "messages": [{"role": "user", "content": "Stream Rust"}]
        }),
        &[],
    )
    .await;

    assert_eq!(status2, StatusCode::OK);
    assert!(
        headers2
            .get(header::CONTENT_TYPE)
            .unwrap()
            .to_str()
            .unwrap()
            .contains("text/event-stream")
    );

    let mut parser = SseParser::new();
    let mut events = parser.push(&body2);
    events.extend(parser.finish());
    assert_eq!(events.last().unwrap().data, "[DONE]");

    let mut collected_text = String::new();
    let mut saw_finish = false;
    let mut saw_usage = None;
    for ev in &events[..events.len() - 1] {
        let chunk: Value = serde_json::from_str(&ev.data).unwrap();
        assert_eq!(chunk["object"], "chat.completion.chunk");
        assert_eq!(chunk["id"], "chatcmpl-msg_stream_99");
        if let Some(c) = chunk["choices"]
            .get(0)
            .and_then(|ch| ch.get("delta"))
            .and_then(|d| d.get("content"))
            .and_then(Value::as_str)
        {
            collected_text.push_str(c);
        }
        if chunk["choices"]
            .get(0)
            .and_then(|ch| ch.get("finish_reason"))
            .and_then(Value::as_str)
            == Some("stop")
        {
            saw_finish = true;
        }
        if let Some(u) = chunk.get("usage").filter(|v| !v.is_null()) {
            saw_usage = Some(u.clone());
        }
    }
    assert_eq!(collected_text, "Rust rocks!");
    assert!(saw_finish);
    let usage = saw_usage.expect("translated SSE should include OpenAI usage chunk");
    assert_eq!(usage["prompt_tokens"], 31);
    assert_eq!(usage["completion_tokens"], 9);
    assert_eq!(usage["total_tokens"], 40);

    tokio::time::sleep(Duration::from_millis(50)).await;

    // Verify Anthropic received translated request headers & body
    let reqs = captured_reqs.lock().await;
    assert_eq!(reqs.len(), 2);
    assert_eq!(reqs[0].path, "/v1/messages");
    assert_eq!(
        reqs[0].auth, None,
        "downstream Authorization must be stripped"
    );
    assert_eq!(reqs[0].x_api_key.as_deref(), Some("sk-ant-test-key"));
    assert_eq!(reqs[0].anthropic_version.as_deref(), Some("2023-06-01"));
    assert_eq!(reqs[0].body["system"], "Be brief.");
    assert_eq!(reqs[0].body["max_tokens"], 2048);
    assert_eq!(reqs[0].body["messages"][0]["role"], "user");
    assert_eq!(reqs[0].body["messages"][0]["content"], "Hello Claude");

    let snap = ai_metrics.snapshot();
    assert_eq!(snap.total_requests, 2);
    assert_eq!(snap.total_prompt_tokens, 50);
    assert_eq!(snap.total_completion_tokens, 17);

    gw.shutdown().await;
}

#[tokio::test]
async fn automatic_failover_from_openai_429_and_503_to_anthropic() {
    let openai_calls = Arc::new(AtomicUsize::new(0));
    let openai_calls_srv = Arc::clone(&openai_calls);

    let openai_addr = spawn_mock_server(move |_req| {
        let count = openai_calls_srv.fetch_add(1, Ordering::SeqCst);
        async move {
            let status = if count == 0 {
                StatusCode::TOO_MANY_REQUESTS
            } else {
                StatusCode::SERVICE_UNAVAILABLE
            };
            full_json(
                status,
                json!({"error": {"message": "overloaded", "type": "rate_limit_error"}}),
            )
        }
    })
    .await;

    let anthropic_calls = Arc::new(AtomicUsize::new(0));
    let anthropic_calls_srv = Arc::clone(&anthropic_calls);

    let anthropic_addr = spawn_mock_server(move |req| {
        anthropic_calls_srv.fetch_add(1, Ordering::SeqCst);
        let is_stream = req
            .body
            .get("stream")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        async move {
            assert_eq!(req.path, "/v1/messages");
            assert_eq!(req.x_api_key.as_deref(), Some("sk-ant-fallback"));
            if is_stream {
                let raw = concat!(
                    "event: message_start\n",
                    "data: {\"type\":\"message_start\",\"message\":{\"id\":\"msg_fb\",\"model\":\"claude-3-5-sonnet-20241022\",\"usage\":{\"input_tokens\":11,\"output_tokens\":1}}}\n\n",
                    "event: content_block_delta\n",
                    "data: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"Recovered!\"}}\n\n",
                    "event: message_delta\n",
                    "data: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"end_turn\"},\"usage\":{\"output_tokens\":4}}\n\n",
                    "event: message_stop\n",
                    "data: {\"type\":\"message_stop\"}\n\n"
                );
                sse_response_direct(vec![Bytes::from(raw)], Duration::ZERO)
            } else {
                full_json(
                    StatusCode::OK,
                    json!({
                        "id": "msg_fallback_json",
                        "type": "message",
                        "role": "assistant",
                        "model": "claude-3-5-sonnet-20241022",
                        "content": [{"type": "text", "text": "Served by Anthropic fallback"}],
                        "stop_reason": "end_turn",
                        "usage": {"input_tokens": 15, "output_tokens": 6}
                    }),
                )
            }
        }
    })
    .await;

    let ai_metrics = Arc::new(AiMetrics::new());
    let mut reg = PluginRegistry::new();
    register_ai_plugins(&mut reg, Arc::clone(&ai_metrics));

    // Notice: route sets default max_attempts = 1, and ai-model-router's auto_max_attempts
    // automatically raises max_attempts to 2 to cover the 2-provider fallback chain!
    let toml_cfg = format!(
        r#"
[server]
listen = "127.0.0.1:0"

[admin]
enabled = false

[[upstreams]]
name = "openai"
endpoints = ["http://{openai_addr}"]

[[upstreams]]
name = "anthropic"
endpoints = ["http://{anthropic_addr}"]

[[routes]]
id = "ai_smart"
path_exact = "/v1/chat/completions"
methods = ["POST"]
upstream = "openai"

[[routes.plugins]]
name = "ai-model-router"
[routes.plugins.config.models]
smart = [
    {{ provider = "openai", upstream = "openai", model = "gpt-4o" }},
    {{ provider = "anthropic", upstream = "anthropic", model = "claude-3-5-sonnet-20241022" }},
]

[[routes.plugins]]
name = "ai-provider-adapter"
[routes.plugins.config.providers.openai]
dialect = "openai_compatible"
auth = {{ type = "bearer", api_key = "sk-openai-primary" }}
[routes.plugins.config.providers.anthropic]
dialect = "anthropic"
auth = {{ type = "header", header = "x-api-key", api_key = "sk-ant-fallback" }}

[[routes.plugins]]
name = "ai-failover"
[routes.plugins.config]
retry_statuses = [429, 500, 502, 503, 504, 529]

[[routes.plugins]]
name = "ai-usage-tracker"
[routes.plugins.config]
log_usage = false
"#
    );

    let runtime = Arc::new(RuntimeRegistry::new());
    let bundle = compile_toml(&toml_cfg, Arc::new(reg), runtime);
    let gw = GatewayServer::new(bundle.snapshot)
        .bind("127.0.0.1:0".parse().unwrap())
        .await
        .unwrap();
    let gw_addr = gw.local_addr();

    // 1. Non-streaming failover (OpenAI 429 -> Anthropic 200)
    let (status1, headers1, body1) = post_chat(
        gw_addr,
        json!({
            "model": "smart",
            "messages": [{"role": "user", "content": "Help"}]
        }),
        &[],
    )
    .await;
    assert_eq!(status1, StatusCode::OK);
    assert_eq!(headers1.get("x-shunt-provider").unwrap(), "anthropic");
    assert_eq!(headers1.get("x-shunt-attempt").unwrap(), "2");
    let j1: Value = serde_json::from_slice(&body1).unwrap();
    assert_eq!(
        j1["choices"][0]["message"]["content"],
        "Served by Anthropic fallback"
    );

    // 2. Streaming failover (OpenAI 503 -> Anthropic 200 SSE translated live to OpenAI SSE)
    let (status2, headers2, body2) = post_chat(
        gw_addr,
        json!({
            "model": "smart",
            "stream": true,
            "messages": [{"role": "user", "content": "Stream help"}]
        }),
        &[],
    )
    .await;
    assert_eq!(status2, StatusCode::OK);
    assert_eq!(headers2.get("x-shunt-provider").unwrap(), "anthropic");
    assert_eq!(headers2.get("x-shunt-attempt").unwrap(), "2");
    let s2 = String::from_utf8(body2.to_vec()).unwrap();
    assert!(s2.contains("Recovered!"));
    assert!(s2.contains("data: [DONE]"));

    tokio::time::sleep(Duration::from_millis(50)).await;

    assert_eq!(openai_calls.load(Ordering::SeqCst), 2);
    assert_eq!(anthropic_calls.load(Ordering::SeqCst), 2);

    let snap = ai_metrics.snapshot();
    assert_eq!(snap.total_requests, 2);
    assert_eq!(snap.total_failovers, 2);
    assert_eq!(snap.total_prompt_tokens, 26);
    assert_eq!(snap.total_completion_tokens, 10);

    let prom = ai_metrics.render_prometheus();
    assert!(prom.contains(
        r#"shunt_ai_failovers_total{from_provider="openai",to_provider="anthropic",model="smart"} 2"#
    ));

    gw.shutdown().await;
}

#[tokio::test]
async fn cooldown_circuit_breaker_persists_across_hot_reload_and_redacts_secrets() {
    let openai_calls = Arc::new(AtomicUsize::new(0));
    let openai_calls_srv = Arc::clone(&openai_calls);
    let openai_addr = spawn_mock_server(move |_req| {
        openai_calls_srv.fetch_add(1, Ordering::SeqCst);
        async move {
            full_json(
                StatusCode::TOO_MANY_REQUESTS,
                json!({"error": {"message": "rate limited", "type": "rate_limit_error"}}),
            )
        }
    })
    .await;

    let anthropic_calls = Arc::new(AtomicUsize::new(0));
    let anthropic_calls_srv = Arc::clone(&anthropic_calls);
    let anthropic_addr = spawn_mock_server(move |_req| {
        anthropic_calls_srv.fetch_add(1, Ordering::SeqCst);
        async move {
            full_json(
                StatusCode::OK,
                json!({
                    "id": "msg_cb",
                    "type": "message",
                    "role": "assistant",
                    "model": "claude-3-5-sonnet-20241022",
                    "content": [{"type": "text", "text": "OK from Anthropic"}],
                    "stop_reason": "end_turn",
                    "usage": {"input_tokens": 5, "output_tokens": 3}
                }),
            )
        }
    })
    .await;

    let ai_metrics = Arc::new(AiMetrics::new());
    let mut reg = PluginRegistry::new();
    register_ai_plugins(&mut reg, Arc::clone(&ai_metrics));
    let plugins = Arc::new(reg);
    let runtime = Arc::new(RuntimeRegistry::new());

    let toml_cfg = format!(
        r#"
[server]
listen = "127.0.0.1:0"

[admin]
enabled = false

[[upstreams]]
name = "openai"
endpoints = ["http://{openai_addr}"]

[[upstreams]]
name = "anthropic"
endpoints = ["http://{anthropic_addr}"]

[[routes]]
id = "ai_cb"
path_exact = "/v1/chat/completions"
methods = ["POST"]
upstream = "openai"

[[routes.plugins]]
name = "ai-model-router"
[routes.plugins.config.models]
smart = [
    {{ provider = "openai", upstream = "openai", model = "gpt-4o" }},
    {{ provider = "anthropic", upstream = "anthropic", model = "claude-3-5-sonnet-20241022" }},
]

[[routes.plugins]]
name = "ai-failover"
id = "cb-failover"
[routes.plugins.config]
retry_statuses = [429, 503]
cooldown_ms = 10000
failure_threshold = 1

[[routes.plugins]]
name = "ai-provider-adapter"
[routes.plugins.config.providers.openai]
dialect = "openai_compatible"
auth = {{ type = "bearer", api_key = "super-secret-openai-key" }}
[routes.plugins.config.providers.anthropic]
dialect = "anthropic"
auth = {{ type = "header", header = "x-api-key", api_key = "super-secret-anthropic-key" }}

[[routes.plugins]]
name = "ai-usage-tracker"
[routes.plugins.config]
log_usage = false
"#
    );

    let compiler = SnapshotCompiler::new(Arc::clone(&plugins), Arc::clone(&runtime));
    let loaded1 = InlineConfigProvider::from_toml("v1.toml", &toml_cfg)
        .load()
        .unwrap();
    let bundle1 = compiler.compile(&loaded1).unwrap();

    // Verify SnapshotInspect JSON never leaks API keys
    let inspect_json = serde_json::to_string(&bundle1.inspect).unwrap();
    assert!(!inspect_json.contains("super-secret-openai-key"));
    assert!(!inspect_json.contains("super-secret-anthropic-key"));

    let gw = GatewayServer::new(bundle1.snapshot)
        .bind("127.0.0.1:0".parse().unwrap())
        .await
        .unwrap();
    let gw_addr = gw.local_addr();

    // Request 1: hits OpenAI (429), trips cooldown, fails over to Anthropic.
    let (st1, h1, _) = post_chat(
        gw_addr,
        json!({"model": "smart", "messages": [{"role": "user", "content": "1"}]}),
        &[],
    )
    .await;
    assert_eq!(st1, StatusCode::OK);
    assert_eq!(h1.get("x-shunt-provider").unwrap(), "anthropic");
    assert_eq!(h1.get("x-shunt-attempt").unwrap(), "2");
    assert_eq!(openai_calls.load(Ordering::SeqCst), 1);
    assert_eq!(anthropic_calls.load(Ordering::SeqCst), 1);

    // Hot-reload a new snapshot (same stable plugin id = "cb-failover")!
    let loaded2 = InlineConfigProvider::from_toml("v2.toml", &toml_cfg)
        .load()
        .unwrap();
    let bundle2 = compiler.compile(&loaded2).unwrap();
    gw.reloader().swap_snapshot(bundle2.snapshot);

    // Request 2 on the new snapshot: cooldown survived hot reload -> skips OpenAI directly on attempt 1!
    let (st2, h2, _) = post_chat(
        gw_addr,
        json!({"model": "smart", "messages": [{"role": "user", "content": "2"}]}),
        &[],
    )
    .await;
    assert_eq!(st2, StatusCode::OK);
    assert_eq!(h2.get("x-shunt-provider").unwrap(), "anthropic");
    assert_eq!(h2.get("x-shunt-attempt").unwrap(), "1");
    assert_eq!(
        openai_calls.load(Ordering::SeqCst),
        1,
        "cooled-down OpenAI target should be skipped across hot reload"
    );
    assert_eq!(anthropic_calls.load(Ordering::SeqCst), 2);

    gw.shutdown().await;
}

#[tokio::test]
async fn validation_errors_413_body_cap_and_reverse_plugin_ordering() {
    let anthropic_addr = spawn_mock_server(move |_req| async move {
        full_json(
            StatusCode::OK,
            json!({
                "id": "msg_order",
                "type": "message",
                "role": "assistant",
                "model": "claude-3-5-sonnet-20241022",
                "content": [{"type": "text", "text": "Works in reverse order too!"}],
                "stop_reason": "end_turn",
                "usage": {"input_tokens": 7, "output_tokens": 4}
            }),
        )
    })
    .await;

    let ai_metrics = Arc::new(AiMetrics::new());
    let mut reg = PluginRegistry::new();
    register_ai_plugins(&mut reg, Arc::clone(&ai_metrics));

    // Deliberately place `ai-usage-tracker` BEFORE `ai-provider-adapter` and set tiny `max_body_bytes`
    let toml_cfg = format!(
        r#"
[server]
listen = "127.0.0.1:0"

[admin]
enabled = false

[[upstreams]]
name = "anthropic"
endpoints = ["http://{anthropic_addr}"]

[[routes]]
id = "ai_order"
path_exact = "/v1/chat/completions"
methods = ["POST"]
upstream = "anthropic"

[[routes.plugins]]
name = "ai-model-router"
[routes.plugins.config]
max_body_bytes = 256
[routes.plugins.config.models]
claude = [{{ provider = "anthropic", upstream = "anthropic", model = "claude-3-5-sonnet-20241022" }}]

[[routes.plugins]]
name = "ai-usage-tracker"
[routes.plugins.config]
log_usage = false

[[routes.plugins]]
name = "ai-provider-adapter"
[routes.plugins.config.providers.anthropic]
dialect = "anthropic"
auth = {{ type = "header", header = "x-api-key", api_key = "sk-ant-test" }}
"#
    );

    let runtime = Arc::new(RuntimeRegistry::new());
    let bundle = compile_toml(&toml_cfg, Arc::new(reg), runtime);
    let gw = GatewayServer::new(bundle.snapshot)
        .bind("127.0.0.1:0".parse().unwrap())
        .await
        .unwrap();
    let gw_addr = gw.local_addr();

    // Missing `model` -> 400 OpenAI error JSON
    let (st_missing, _, body_missing) = post_chat(
        gw_addr,
        json!({"messages": [{"role": "user", "content": "hi"}]}),
        &[],
    )
    .await;
    assert_eq!(st_missing, StatusCode::BAD_REQUEST);
    let err_missing: Value = serde_json::from_slice(&body_missing).unwrap();
    assert_eq!(err_missing["error"]["code"], "missing_model");

    // Unknown `model` -> 404 OpenAI error JSON
    let (st_unknown, _, body_unknown) = post_chat(
        gw_addr,
        json!({"model": "nonexistent", "messages": [{"role": "user", "content": "hi"}]}),
        &[],
    )
    .await;
    assert_eq!(st_unknown, StatusCode::NOT_FOUND);
    let err_unknown: Value = serde_json::from_slice(&body_unknown).unwrap();
    assert_eq!(err_unknown["error"]["code"], "model_not_found");

    // Oversized body (> 256 bytes) -> 413 Payload Too Large
    let big_text = "x".repeat(400);
    let (st_big, _, _) = post_chat(
        gw_addr,
        json!({"model": "claude", "messages": [{"role": "user", "content": big_text}]}),
        &[],
    )
    .await;
    assert_eq!(st_big, StatusCode::PAYLOAD_TOO_LARGE);

    // Valid Anthropic request with ai-usage-tracker BEFORE ai-provider-adapter
    let (st_ok, _, body_ok) = post_chat(
        gw_addr,
        json!({"model": "claude", "messages": [{"role": "user", "content": "hi"}]}),
        &[],
    )
    .await;
    assert_eq!(st_ok, StatusCode::OK);
    let ok_json: Value = serde_json::from_slice(&body_ok).unwrap();
    assert_eq!(
        ok_json["choices"][0]["message"]["content"],
        "Works in reverse order too!"
    );

    tokio::time::sleep(Duration::from_millis(50)).await;
    let snap = ai_metrics.snapshot();
    // All 4 requests (400, 404, 413, 200) are accounted for in requests_total, while tokens come from the 200.
    assert_eq!(snap.total_requests, 4);
    assert_eq!(snap.total_prompt_tokens, 7);
    assert_eq!(snap.total_completion_tokens, 4);
    let prom = ai_metrics.render_prometheus();
    assert!(prom.contains(r#"status="400""#));
    assert!(prom.contains(r#"status="404""#));
    assert!(prom.contains(r#"status="413""#));
    assert!(prom.contains(r#"status="200""#));

    gw.shutdown().await;
}

#[test]
fn example_shunt_ai_toml_compiles_cleanly() {
    // Provide dummy env vars referenced in examples/shunt-ai.toml (unsafe in Rust 2024).
    unsafe {
        std::env::set_var("OPENAI_API_KEY", "sk-example-openai");
        std::env::set_var("ANTHROPIC_API_KEY", "sk-example-anthropic");
    }

    let path =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../examples/shunt-ai.toml");
    let provider = shunt_config::FileConfigProvider::new(&path);
    let loaded = provider
        .load()
        .expect("examples/shunt-ai.toml should parse");

    let mut reg = PluginRegistry::new();
    let prom = Arc::new(PrometheusMetrics::new());
    let ai_metrics = Arc::new(AiMetrics::new());
    register_builtin_plugins(&mut reg, prom);
    register_ai_plugins(&mut reg, ai_metrics);

    let compiler = SnapshotCompiler::new(Arc::new(reg), Arc::new(RuntimeRegistry::new()));
    let bundle = compiler
        .compile(&loaded)
        .expect("examples/shunt-ai.toml should compile into a valid GatewaySnapshot");
    assert_eq!(bundle.inspect.routes.len(), 1);
    assert_eq!(bundle.inspect.routes[0].id, "ai_chat_completions");
}

#[test]
fn example_shunt_ai_multi_provider_toml_compiles_and_verifies_cleanly() {
    unsafe {
        std::env::set_var("OPENAI_API_KEY", "sk-example-openai");
        std::env::set_var("ANTHROPIC_API_KEY", "sk-example-anthropic");
        std::env::set_var("GROQ_API_KEY", "gsk-example-groq");
        std::env::set_var("AZURE_OPENAI_API_KEY", "az-example-key");
        std::env::set_var("GEMINI_API_KEY", "AIza-example-gemini");
        std::env::set_var("VERTEX_ACCESS_TOKEN", "ya29.example-vertex");
        std::env::set_var("AWS_ACCESS_KEY_ID", "AKIAIOSFODNN7EXAMPLE");
        std::env::set_var(
            "AWS_SECRET_ACCESS_KEY",
            "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        );
    }

    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../examples/shunt-ai-multi-provider.toml");
    let provider = shunt_config::FileConfigProvider::new(&path);
    let loaded = provider
        .load()
        .expect("examples/shunt-ai-multi-provider.toml should parse");

    let mut reg = PluginRegistry::new();
    let prom = Arc::new(PrometheusMetrics::new());
    let ai_metrics = Arc::new(AiMetrics::new());
    register_builtin_plugins(&mut reg, prom);
    register_ai_plugins(&mut reg, ai_metrics);

    let compiler = SnapshotCompiler::new(Arc::new(reg), Arc::new(RuntimeRegistry::new()));
    let bundle = compiler
        .compile(&loaded)
        .expect("examples/shunt-ai-multi-provider.toml should compile cleanly");

    // Verify all provider secrets are redacted from SnapshotInspect.
    let inspect_json = serde_json::to_string(&bundle.inspect).unwrap();
    for secret in [
        "sk-example-openai",
        "sk-example-anthropic",
        "gsk-example-groq",
        "az-example-key",
        "AIza-example-gemini",
        "ya29.example-vertex",
        "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
    ] {
        assert!(
            !inspect_json.contains(secret),
            "secret `{secret}` leaked into SnapshotInspect"
        );
    }

    // Static verification passes with zero errors or warnings.
    let report = shunt_config::verify_bundle(&bundle, None, true);
    assert!(
        report.passed,
        "multi-provider example failed verify: {:?}",
        report.diagnostics
    );
}

#[test]
fn example_shunt_ai_governance_toml_compiles_and_verifies_cleanly() {
    unsafe {
        std::env::set_var("OPENAI_API_KEY", "sk-example-openai");
        std::env::set_var("ANTHROPIC_API_KEY", "sk-example-anthropic");
        std::env::set_var("ALICE_VIRTUAL_KEY", "sk-shunt-alice-secret");
        std::env::set_var("BOB_VIRTUAL_KEY", "sk-shunt-bob-secret");
    }

    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../examples/shunt-ai-governance.toml");
    let provider = shunt_config::FileConfigProvider::new(&path);
    let loaded = provider
        .load()
        .expect("examples/shunt-ai-governance.toml should parse");

    let mut reg = PluginRegistry::new();
    let prom = Arc::new(PrometheusMetrics::new());
    let ai_metrics = Arc::new(AiMetrics::new());
    register_builtin_plugins(&mut reg, prom);
    register_ai_plugins(&mut reg, ai_metrics);

    let compiler = SnapshotCompiler::new(Arc::new(reg), Arc::new(RuntimeRegistry::new()));
    let bundle = compiler
        .compile(&loaded)
        .expect("examples/shunt-ai-governance.toml should compile cleanly");

    let inspect_json = serde_json::to_string(&bundle.inspect).unwrap();
    for secret in [
        "sk-example-openai",
        "sk-example-anthropic",
        "sk-shunt-alice-secret",
        "sk-shunt-bob-secret",
    ] {
        assert!(
            !inspect_json.contains(secret),
            "secret `{secret}` leaked into SnapshotInspect"
        );
    }

    let report = shunt_config::verify_bundle(&bundle, None, true);
    assert!(
        report.passed,
        "governance example failed verify: {:?}",
        report.diagnostics
    );
}

#[test]
fn example_shunt_ai_smart_routing_toml_compiles_and_verifies_cleanly() {
    unsafe {
        std::env::set_var("OPENAI_API_KEY", "sk-example-openai");
        std::env::set_var("ANTHROPIC_API_KEY", "sk-example-anthropic");
        std::env::set_var("GEMINI_API_KEY", "AIza-example-gemini");
    }

    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../examples/shunt-ai-smart-routing.toml");
    let provider = shunt_config::FileConfigProvider::new(&path);
    let loaded = provider
        .load()
        .expect("examples/shunt-ai-smart-routing.toml should parse");

    let mut reg = PluginRegistry::new();
    let prom = Arc::new(PrometheusMetrics::new());
    let ai_metrics = Arc::new(AiMetrics::new());
    register_builtin_plugins(&mut reg, prom);
    register_ai_plugins(&mut reg, ai_metrics);

    let compiler = SnapshotCompiler::new(Arc::new(reg), Arc::new(RuntimeRegistry::new()));
    let bundle = compiler
        .compile(&loaded)
        .expect("examples/shunt-ai-smart-routing.toml should compile cleanly");

    let inspect_json = serde_json::to_string(&bundle.inspect).unwrap();
    for secret in [
        "sk-example-openai",
        "sk-example-anthropic",
        "AIza-example-gemini",
    ] {
        assert!(
            !inspect_json.contains(secret),
            "secret `{secret}` leaked into SnapshotInspect"
        );
    }

    let report = shunt_config::verify_bundle(&bundle, None, true);
    assert!(
        report.passed,
        "smart-routing example failed verify: {:?}",
        report.diagnostics
    );
}

#[test]
fn example_shunt_ai_observability_cache_toml_compiles_and_verifies_cleanly() {
    unsafe {
        std::env::set_var("OPENAI_API_KEY", "sk-example-openai");
        std::env::set_var("ANTHROPIC_API_KEY", "sk-example-anthropic");
    }

    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../examples/shunt-ai-observability-cache.toml");
    let provider = shunt_config::FileConfigProvider::new(&path);
    let loaded = provider
        .load()
        .expect("examples/shunt-ai-observability-cache.toml should parse");

    let mut reg = PluginRegistry::new();
    let prom = Arc::new(PrometheusMetrics::new());
    let ai_metrics = Arc::new(AiMetrics::new());
    register_builtin_plugins(&mut reg, prom);
    register_ai_plugins(&mut reg, ai_metrics);

    let compiler = SnapshotCompiler::new(Arc::new(reg), Arc::new(RuntimeRegistry::new()));
    let bundle = compiler
        .compile(&loaded)
        .expect("examples/shunt-ai-observability-cache.toml should compile cleanly");
    assert_eq!(bundle.inspect.telemetry_backend, "otlp_http");

    let inspect_json = serde_json::to_string(&bundle.inspect).unwrap();
    for secret in ["sk-example-openai", "sk-example-anthropic", "sk-shunt-dev"] {
        assert!(
            !inspect_json.contains(secret),
            "secret `{secret}` leaked into SnapshotInspect"
        );
    }

    let report = shunt_config::verify_bundle(&bundle, None, true);
    assert!(
        report.passed,
        "observability-cache example failed verify: {:?}",
        report.diagnostics
    );
}
