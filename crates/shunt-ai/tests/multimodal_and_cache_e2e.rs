//! End-to-end integration tests for RFC 0016:
//! - Multimodal & expanded AI endpoints:
//!   - `POST /v1/rerank` (Cohere `/v2/rerank`, Voyage normalization, AWS Bedrock `/rerank` + SigV4)
//!   - `POST /v1/completions` (JSON + SSE streaming + token usage)
//!   - `POST /v1/moderations`
//!   - `POST /v1/images/generations` (OpenAI + Gemini Imagen `:predict`) & `POST /v1/images/edits` (multipart)
//!   - `POST /v1/audio/speech` (binary MP3 passthrough) & `POST /v1/audio/transcriptions` (multipart Groq)
//!   - `GET /v1/realtime` (live WebSocket upgrade tunnel, `Sec-WebSocket-Protocol` virtual key auth & stripping, `?model=` rewrite)
//!   - `/v1/files` & `/v1/batches` CRUD lifecycle + `x-shunt-provider` routing
//!   - `GET /v1/generation?id=...` (lookup by upstream ID and `x-shunt-generation-id`, cost & token fields, tenant isolation)
//! - Enhanced `ai-cache`:
//!   - Streaming SSE capture & instant replay (including translated Anthropic -> OpenAI SSE)
//!   - Singleflight request coalescing (concurrent identical misses + leader failure release)
//!   - Opt-in semantic vector caching (`embedding_http` + `webhook`)

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
use shunt_plugin_sdk::PluginRegistry;
use shunt_plugins::{PrometheusMetrics, register_builtin_plugins};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

#[derive(Debug, Clone)]
struct CapturedReq {
    method: String,
    path: String,
    headers: std::collections::BTreeMap<String, String>,
    body: Vec<u8>,
}

async fn spawn_mock_http<F>(
    handler: F,
) -> (
    std::net::SocketAddr,
    Arc<Mutex<Vec<CapturedReq>>>,
    tokio::task::JoinHandle<()>,
)
where
    F: Fn(usize, &CapturedReq) -> (StatusCode, &'static str, Vec<u8>) + Send + Sync + 'static,
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
                        let method = req.method().as_str().to_owned();
                        let path = req
                            .uri()
                            .path_and_query()
                            .map(|pq| pq.as_str().to_owned())
                            .unwrap_or_else(|| "/".to_owned());
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
                        let cap = CapturedReq {
                            method,
                            path,
                            headers,
                            body,
                        };
                        let idx = {
                            let mut g = caps.lock().unwrap();
                            let i = g.len();
                            g.push(cap.clone());
                            i
                        };
                        let (status, ct, resp_body) = h(idx, &cap);
                        Ok::<_, Infallible>(
                            Response::builder()
                                .status(status)
                                .header(header::CONTENT_TYPE, ct)
                                .body(Full::new(Bytes::from(resp_body)))
                                .unwrap(),
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

async fn start_gateway(
    toml_cfg: &str,
) -> (
    std::net::SocketAddr,
    Arc<AiMetrics>,
    Arc<RuntimeRegistry>,
    shunt_core::ServerHandle,
) {
    let loaded = InlineConfigProvider::from_toml("rfc0016-test", toml_cfg)
        .load()
        .expect("valid gateway TOML");

    let mut plugins = PluginRegistry::new();
    let http_metrics = Arc::new(PrometheusMetrics::new());
    let ai_metrics = Arc::new(AiMetrics::new());
    register_builtin_plugins(&mut plugins, Arc::clone(&http_metrics));
    register_ai_plugins(&mut plugins, Arc::clone(&ai_metrics));

    let runtime = Arc::new(RuntimeRegistry::new());
    let compiler = SnapshotCompiler::new(Arc::new(plugins), Arc::clone(&runtime));
    let compiled = compiler.compile(&loaded).expect("compile snapshot");

    let server = GatewayServer::new(compiled.snapshot)
        .bind("127.0.0.1:0".parse().unwrap())
        .await
        .expect("bind gateway");
    let addr = server.local_addr();
    (addr, ai_metrics, runtime, server)
}

async fn send_req(
    addr: std::net::SocketAddr,
    method: Method,
    path: &str,
    content_type: Option<&str>,
    body: Vec<u8>,
    extra_headers: &[(&str, &str)],
) -> (StatusCode, http::HeaderMap, Vec<u8>) {
    let client = Client::builder(TokioExecutor::new()).build_http::<Full<Bytes>>();
    let mut builder = Request::builder()
        .method(method)
        .uri(format!("http://{addr}{path}"));
    if let Some(ct) = content_type {
        builder = builder.header(header::CONTENT_TYPE, ct);
    }
    for &(k, v) in extra_headers {
        builder = builder.header(k, v);
    }
    let req = builder.body(Full::new(Bytes::from(body))).unwrap();
    let res = client.request(req).await.expect("HTTP request failed");
    let status = res.status();
    let headers = res.headers().clone();
    let bytes = res.into_body().collect().await.unwrap().to_bytes().to_vec();
    (status, headers, bytes)
}

#[tokio::test]
async fn e2e_rerank_completions_moderations_images_audio_files_batches_and_generation() {
    let (mock_addr, mock_caps, mock_handle) = spawn_mock_http(|_idx, req| {
        if req.path == "/v2/rerank" {
            // Cohere v2 rerank
            return (
                StatusCode::OK,
                "application/json",
                serde_json::to_vec(&json!({
                    "id": "rerank-cohere-1",
                    "results": [
                        { "index": 1, "relevance_score": 0.96 },
                        { "index": 0, "relevance_score": 0.21 }
                    ],
                    "meta": { "tokens": { "input_tokens": 18 } }
                }))
                .unwrap(),
            );
        }
        if req.path == "/v1/rerank" && req.headers.get("authorization").map(String::as_str) == Some("Bearer sk-voyage") {
            // Voyage rerank returns `data[]` -> normalized to `results[]`
            return (
                StatusCode::OK,
                "application/json",
                serde_json::to_vec(&json!({
                    "model": "rerank-2",
                    "data": [{ "index": 0, "relevance_score": 0.91, "document": "rust" }],
                    "usage": { "total_tokens": 20 }
                }))
                .unwrap(),
            );
        }
        if req.path == "/rerank" {
            // AWS Bedrock Agent Runtime rerank
            return (
                StatusCode::OK,
                "application/json",
                serde_json::to_vec(&json!({
                    "results": [{ "index": 0, "relevanceScore": 0.94 }]
                }))
                .unwrap(),
            );
        }
        if req.path == "/v1/completions" {
            return (
                StatusCode::OK,
                "application/json",
                serde_json::to_vec(&json!({
                    "id": "cmpl-777",
                    "object": "text_completion",
                    "model": "gpt-3.5-turbo-instruct",
                    "choices": [{ "text": " world!", "index": 0, "finish_reason": "stop" }],
                    "usage": { "prompt_tokens": 5, "completion_tokens": 2, "total_tokens": 7 }
                }))
                .unwrap(),
            );
        }
        if req.path == "/v1/moderations" {
            return (
                StatusCode::OK,
                "application/json",
                serde_json::to_vec(&json!({
                    "id": "modr-1",
                    "model": "omni-moderation-latest",
                    "results": [{ "flagged": false }]
                }))
                .unwrap(),
            );
        }
        if req.path.contains(":predict") {
            // Gemini Imagen
            return (
                StatusCode::OK,
                "application/json",
                serde_json::to_vec(&json!({
                    "predictions": [{ "bytesBase64Encoded": "iVBORw0KGgo=", "mimeType": "image/png" }]
                }))
                .unwrap(),
            );
        }
        if req.path == "/v1/images/edits" {
            return (
                StatusCode::OK,
                "application/json",
                serde_json::to_vec(&json!({ "created": 1, "data": [{ "b64_json": "EDITED" }] }))
                    .unwrap(),
            );
        }
        if req.path == "/v1/audio/speech" {
            return (StatusCode::OK, "audio/mpeg", vec![0xFF, 0xFB, 0x90, 0x64, 0x00, 0x42]);
        }
        if req.path == "/openai/v1/audio/transcriptions" {
            return (
                StatusCode::OK,
                "application/json",
                serde_json::to_vec(&json!({ "text": "hello from groq whisper" })).unwrap(),
            );
        }
        if req.path.starts_with("/v1/files") {
            if req.method == "POST" {
                return (
                    StatusCode::OK,
                    "application/json",
                    serde_json::to_vec(&json!({ "id": "file-abc", "object": "file", "purpose": "batch" }))
                        .unwrap(),
                );
            }
            if req.path == "/v1/files/file-abc/content" {
                return (
                    StatusCode::OK,
                    "application/octet-stream",
                    b"{\"custom_id\":\"1\"}\n".to_vec(),
                );
            }
            return (
                StatusCode::OK,
                "application/json",
                serde_json::to_vec(&json!({ "id": "file-abc", "deleted": true })).unwrap(),
            );
        }
        if req.path.starts_with("/v1/batches") {
            return (
                StatusCode::OK,
                "application/json",
                serde_json::to_vec(&json!({
                    "id": "batch_123",
                    "object": "batch",
                    "status": if req.path.ends_with("/cancel") { "cancelling" } else { "in_progress" }
                }))
                .unwrap(),
            );
        }
        (StatusCode::NOT_FOUND, "text/plain", format!("unexpected {}", req.path).into_bytes())
    })
    .await;

    let toml_cfg = format!(
        r#"
[server]
listen = "127.0.0.1:0"

[[upstreams]]
name = "mock"
endpoints = ["http://{mock_addr}"]

[[routes]]
id = "ai"
path_prefix = "/v1/"
upstream = "mock"
max_body_bytes = 4194304

[[routes.plugins]]
name = "ai-virtual-keys"
[routes.plugins.config]
[[routes.plugins.config.keys]]
id = "key-alice"
api_key = "vk-alice"
team = "ml"
[[routes.plugins.config.keys]]
id = "key-bob"
api_key = "vk-bob"
team = "ops"

[[routes.plugins]]
name = "ai-model-router"
[routes.plugins.config]
max_body_bytes = 4194304
files_targets = [{{ provider = "openai", upstream = "mock", capabilities = ["files"] }}]
batches_targets = [{{ provider = "openai", upstream = "mock", capabilities = ["batches"] }}]

[routes.plugins.config.models]
cohere-rerank = [{{ provider = "cohere", upstream = "mock", model = "rerank-v3.5", capabilities = ["rerank"] }}]
voyage-rerank = [{{ provider = "voyage", upstream = "mock", model = "rerank-2", capabilities = ["rerank"] }}]
bedrock-rerank = [{{ provider = "bedrock", upstream = "mock", model = "amazon.rerank-v1:0", capabilities = ["rerank"] }}]
fim-model = [{{ provider = "openai", upstream = "mock", model = "gpt-3.5-turbo-instruct", capabilities = ["completions", "streaming"] }}]
mod-model = [{{ provider = "openai", upstream = "mock", model = "omni-moderation-latest", capabilities = ["moderations"] }}]
imagen-alias = [{{ provider = "gemini", upstream = "mock", model = "imagen-3.0-generate-002", capabilities = ["images"] }}]
img-edit = [{{ provider = "openai", upstream = "mock", model = "gpt-image-1", capabilities = ["images"] }}]
tts-alias = [{{ provider = "openai", upstream = "mock", model = "tts-1", capabilities = ["audio"] }}]
stt-alias = [{{ provider = "groq", upstream = "mock", model = "whisper-large-v3", capabilities = ["audio"] }}]

[[routes.plugins]]
name = "ai-provider-adapter"
[routes.plugins.config.providers.openai]
preset = "openai"
api_key = "sk-openai"

[routes.plugins.config.providers.cohere]
preset = "cohere"
api_key = "sk-cohere"

[routes.plugins.config.providers.voyage]
preset = "voyage"
api_key = "sk-voyage"

[routes.plugins.config.providers.bedrock]
preset = "bedrock"
region = "us-east-1"
[routes.plugins.config.providers.bedrock.auth]
type = "aws_sigv4"
access_key_id = "AKIAEXAMPLE"
secret_access_key = "secret-key"

[routes.plugins.config.providers.gemini]
preset = "gemini"
api_key = "gem-key"

[routes.plugins.config.providers.groq]
preset = "groq"
api_key = "sk-groq"

[[routes.plugins]]
name = "ai-usage-tracker"
[routes.plugins.config]
log_usage = false
generation_store_capacity = 64
"#
    );

    let (gw_addr, metrics, runtime, gw_handle) = start_gateway(&toml_cfg).await;
    let alice = &[("authorization", "Bearer vk-alice")];
    let bob = &[("authorization", "Bearer vk-bob")];

    // 1. Cohere rerank -> /v2/rerank
    let (st, _, body) = send_req(
        gw_addr,
        Method::POST,
        "/v1/rerank",
        Some("application/json"),
        serde_json::to_vec(&json!({
            "model": "cohere-rerank",
            "query": "rust gateway",
            "documents": ["python proxy", "rust http gateway"]
        }))
        .unwrap(),
        alice,
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    let v: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(v["results"][0]["index"], 1);

    // 2. Voyage rerank -> normalizes data[] into results[]
    let (st, _, body) = send_req(
        gw_addr,
        Method::POST,
        "/v1/rerank",
        Some("application/json"),
        serde_json::to_vec(&json!({
            "model": "voyage-rerank",
            "query": "rust",
            "documents": ["rust"]
        }))
        .unwrap(),
        alice,
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    let v: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(v["results"][0]["relevance_score"], 0.91);
    assert_eq!(v["results"][0]["document"]["text"], "rust");

    // 3. Bedrock rerank -> translates request, signs SigV4, re-attaches return_documents
    let (st, _, body) = send_req(
        gw_addr,
        Method::POST,
        "/v1/rerank",
        Some("application/json"),
        serde_json::to_vec(&json!({
            "model": "bedrock-rerank",
            "query": "shunt",
            "documents": ["Shunt is fast"],
            "return_documents": true
        }))
        .unwrap(),
        alice,
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    let v: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(v["results"][0]["relevance_score"], 0.94);
    assert_eq!(v["results"][0]["document"]["text"], "Shunt is fast");
    {
        let caps = mock_caps.lock().unwrap();
        let br_cap = caps.iter().find(|c| c.path == "/rerank").unwrap();
        assert!(
            br_cap
                .headers
                .get("authorization")
                .is_some_and(|a| a.starts_with("AWS4-HMAC-SHA256")),
            "Bedrock rerank must be AWS SigV4 signed"
        );
    }

    // 4. Legacy /v1/completions + GET /v1/generation?id=... (by upstream ID & gateway alias + tenant isolation)
    let (st, hdrs, body) = send_req(
        gw_addr,
        Method::POST,
        "/v1/completions",
        Some("application/json"),
        serde_json::to_vec(&json!({ "model": "fim-model", "prompt": "Hello" })).unwrap(),
        alice,
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    let gw_gen_id = hdrs
        .get("x-shunt-generation-id")
        .expect("x-shunt-generation-id header")
        .to_str()
        .unwrap()
        .to_owned();
    let v: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(v["id"], "cmpl-777");

    // Allow off-hot-path on_complete task to commit generation record.
    tokio::time::sleep(Duration::from_millis(40)).await;

    // Lookup by upstream ID (`cmpl-777`) as Alice -> 200 OK
    let (st, _, body) = send_req(
        gw_addr,
        Method::GET,
        "/v1/generation?id=cmpl-777",
        None,
        Vec::new(),
        alice,
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    let gen_v: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(gen_v["data"]["id"], "cmpl-777");
    assert_eq!(gen_v["data"]["tokens_prompt"], 5);
    assert_eq!(gen_v["data"]["tokens_completion"], 2);
    assert_eq!(gen_v["data"]["finish_reason"], "stop");
    assert_eq!(gen_v["data"]["key_id"], "key-alice");

    // Lookup by gateway alias (`gen-<id>`) as Alice -> 200 OK
    let (st, _, body) = send_req(
        gw_addr,
        Method::GET,
        &format!("/v1/generation?id={gw_gen_id}"),
        None,
        Vec::new(),
        alice,
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    let gen_alias: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(gen_alias["data"]["id"], "cmpl-777");

    // Lookup by Bob (different virtual key) -> 403 Forbidden (tenant isolation)
    let (st, _, _) = send_req(
        gw_addr,
        Method::GET,
        "/v1/generation?id=cmpl-777",
        None,
        Vec::new(),
        bob,
    )
    .await;
    assert_eq!(st, StatusCode::FORBIDDEN);

    // 5. Moderations
    let (st, _, body) = send_req(
        gw_addr,
        Method::POST,
        "/v1/moderations",
        Some("application/json"),
        serde_json::to_vec(&json!({ "model": "mod-model", "input": "hello" })).unwrap(),
        alice,
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    let v: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(v["results"][0]["flagged"], false);

    // 6. Gemini Imagen translation on POST /v1/images/generations
    let (st, _, body) = send_req(
        gw_addr,
        Method::POST,
        "/v1/images/generations",
        Some("application/json"),
        serde_json::to_vec(&json!({ "model": "imagen-alias", "prompt": "cat on moon", "n": 1 }))
            .unwrap(),
        alice,
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    let v: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(v["data"][0]["b64_json"], "iVBORw0KGgo=");

    // 7. Multipart image edits + binary preservation & model alias rewrite
    let bnd = "ImgBoundary99";
    let png_bytes: Vec<u8> = vec![0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A, 0x00, 0xFF];
    let mut mp_img = Vec::new();
    mp_img.extend_from_slice(
        format!("--{bnd}\r\nContent-Disposition: form-data; name=\"image\"; filename=\"a.png\"\r\nContent-Type: image/png\r\n\r\n").as_bytes(),
    );
    mp_img.extend_from_slice(&png_bytes);
    mp_img.extend_from_slice(
        format!("\r\n--{bnd}\r\nContent-Disposition: form-data; name=\"model\"\r\n\r\nimg-edit\r\n--{bnd}--\r\n").as_bytes(),
    );
    let (st, _, body) = send_req(
        gw_addr,
        Method::POST,
        "/v1/images/edits",
        Some(&format!("multipart/form-data; boundary={bnd}")),
        mp_img,
        alice,
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    assert!(String::from_utf8_lossy(&body).contains("EDITED"));
    {
        let caps = mock_caps.lock().unwrap();
        let edit_cap = caps.iter().find(|c| c.path == "/v1/images/edits").unwrap();
        assert!(
            edit_cap
                .body
                .windows(png_bytes.len())
                .any(|w| w == png_bytes.as_slice()),
            "binary PNG bytes must survive multipart model rewrite"
        );
        assert_eq!(
            shunt_ai::extract_multipart_text_field(&edit_cap.body, bnd, "model").as_deref(),
            Some("gpt-image-1")
        );
    }

    // 8. Audio TTS (binary passthrough) + Multipart STT on Groq preset
    let (st, hdrs, audio_out) = send_req(
        gw_addr,
        Method::POST,
        "/v1/audio/speech",
        Some("application/json"),
        serde_json::to_vec(&json!({ "model": "tts-alias", "input": "hello", "voice": "alloy" }))
            .unwrap(),
        alice,
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(hdrs.get(header::CONTENT_TYPE).unwrap(), "audio/mpeg");
    assert_eq!(audio_out, vec![0xFF, 0xFB, 0x90, 0x64, 0x00, 0x42]);

    let stt_bnd = "AudioBound7";
    let wav_bytes = vec![b'R', b'I', b'F', b'F', 0x00, 0x01, 0xFE, 0xFF];
    let mut mp_stt = Vec::new();
    mp_stt.extend_from_slice(
        format!("--{stt_bnd}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"a.wav\"\r\nContent-Type: audio/wav\r\n\r\n").as_bytes(),
    );
    mp_stt.extend_from_slice(&wav_bytes);
    mp_stt.extend_from_slice(
        format!("\r\n--{stt_bnd}\r\nContent-Disposition: form-data; name=\"model\"\r\n\r\nstt-alias\r\n--{stt_bnd}--\r\n").as_bytes(),
    );
    let (st, _, body) = send_req(
        gw_addr,
        Method::POST,
        "/v1/audio/transcriptions",
        Some(&format!("multipart/form-data; boundary={stt_bnd}")),
        mp_stt,
        alice,
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    assert!(String::from_utf8_lossy(&body).contains("hello from groq whisper"));
    {
        let caps = mock_caps.lock().unwrap();
        let stt_cap = caps
            .iter()
            .find(|c| c.path == "/openai/v1/audio/transcriptions")
            .expect("Groq audio preset path");
        assert!(
            stt_cap
                .body
                .windows(wav_bytes.len())
                .any(|w| w == wav_bytes.as_slice())
        );
        assert_eq!(
            shunt_ai::extract_multipart_text_field(&stt_cap.body, stt_bnd, "model").as_deref(),
            Some("whisper-large-v3")
        );
    }

    // 9. Files & Batches CRUD lifecycle
    let (st, _, body) = send_req(
        gw_addr,
        Method::POST,
        "/v1/files",
        Some("multipart/form-data; boundary=filebnd"),
        b"--filebnd\r\nContent-Disposition: form-data; name=\"purpose\"\r\n\r\nbatch\r\n--filebnd--\r\n"
            .to_vec(),
        alice,
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    assert!(String::from_utf8_lossy(&body).contains("file-abc"));

    let (st, _, body) = send_req(
        gw_addr,
        Method::GET,
        "/v1/files/file-abc/content",
        None,
        Vec::new(),
        alice,
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(body, b"{\"custom_id\":\"1\"}\n");

    let (st, _, body) = send_req(
        gw_addr,
        Method::POST,
        "/v1/batches",
        Some("application/json"),
        serde_json::to_vec(&json!({
            "input_file_id": "file-abc",
            "endpoint": "/v1/chat/completions",
            "completion_window": "24h"
        }))
        .unwrap(),
        alice,
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    assert!(String::from_utf8_lossy(&body).contains("in_progress"));

    let (st, _, body) = send_req(
        gw_addr,
        Method::POST,
        "/v1/batches/batch_123/cancel",
        None,
        Vec::new(),
        alice,
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    assert!(String::from_utf8_lossy(&body).contains("cancelling"));

    // Verify Admin Inspector exposes generation store stats
    let inspect = inspect_ai_runtime(&metrics, runtime.state_store(), runtime.clock().as_ref());
    assert!(
        inspect["generation_stores"][0]["stored_records"]
            .as_u64()
            .unwrap_or(0)
            >= 1
    );

    drop(gw_handle);
    mock_handle.abort();
}

#[tokio::test]
async fn e2e_realtime_websocket_proxy_auth_and_uri_rewrite() {
    // Raw HTTP/1.1 WebSocket echo upstream that captures the upgraded request head & echoes bytes.
    let ws_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let ws_addr = ws_listener.local_addr().unwrap();
    let captured_head = Arc::new(Mutex::new(String::new()));
    let cap_bg = Arc::clone(&captured_head);

    let ws_handle = tokio::spawn(async move {
        if let Ok((mut stream, _)) = ws_listener.accept().await {
            let mut buf = vec![0u8; 4096];
            let mut total = 0usize;
            while total < buf.len() {
                let n = stream.read(&mut buf[total..]).await.unwrap_or(0);
                if n == 0 {
                    break;
                }
                total += n;
                if buf[..total].windows(4).any(|w| w == b"\r\n\r\n") {
                    break;
                }
            }
            let head_str = String::from_utf8_lossy(&buf[..total]).into_owned();
            *cap_bg.lock().unwrap() = head_str;

            let resp = concat!(
                "HTTP/1.1 101 Switching Protocols\r\n",
                "Upgrade: websocket\r\n",
                "Connection: Upgrade\r\n",
                "Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n",
                "Sec-WebSocket-Protocol: realtime\r\n\r\n"
            );
            stream.write_all(resp.as_bytes()).await.unwrap();

            // Echo payload back across the tunneled WebSocket stream.
            let mut msg = [0u8; 64];
            if let Ok(n) = stream.read(&mut msg).await
                && n > 0
            {
                let _ = stream.write_all(&msg[..n]).await;
            }
        }
    });

    let toml_cfg = format!(
        r#"
[server]
listen = "127.0.0.1:0"

[[upstreams]]
name = "openai_ws"
endpoints = ["http://{ws_addr}"]

[[routes]]
id = "ai_rt"
path_prefix = "/v1/"
upstream = "openai_ws"
allow_websockets = true

[[routes.plugins]]
name = "ai-virtual-keys"
[routes.plugins.config]
[[routes.plugins.config.keys]]
id = "voice-user"
api_key = "vk-voice-secret"

[[routes.plugins]]
name = "ai-model-router"
[routes.plugins.config.models]
voice-fast = [{{ provider = "openai", upstream = "openai_ws", model = "gpt-4o-realtime-preview", capabilities = ["realtime"] }}]

[[routes.plugins]]
name = "ai-provider-adapter"
[routes.plugins.config.providers.openai]
preset = "openai"
api_key = "sk-real-openai-key"
"#
    );

    let (gw_addr, _metrics, _runtime, gw_handle) = start_gateway(&toml_cfg).await;

    // Connect as a WebSocket client presenting virtual key in `Sec-WebSocket-Protocol`!
    let mut client = TcpStream::connect(gw_addr).await.unwrap();
    let req_bytes = concat!(
        "GET /v1/realtime?model=voice-fast&intent=transcription HTTP/1.1\r\n",
        "Host: localhost\r\n",
        "Upgrade: websocket\r\n",
        "Connection: Upgrade\r\n",
        "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n",
        "Sec-WebSocket-Version: 13\r\n",
        "Sec-WebSocket-Protocol: realtime, openai-insecure-api-key.vk-voice-secret, openai-beta.realtime-v1\r\n\r\n"
    );
    client.write_all(req_bytes.as_bytes()).await.unwrap();

    let mut resp_buf = vec![0u8; 2048];
    let n = client.read(&mut resp_buf).await.unwrap();
    let resp_str = String::from_utf8_lossy(&resp_buf[..n]);
    assert!(
        resp_str.starts_with("HTTP/1.1 101"),
        "expected 101 Switching Protocols, got: {resp_str}"
    );

    // Verify bidirectional tunnel carries frames intact.
    client.write_all(b"ping-realtime-frame").await.unwrap();
    let mut echo = [0u8; 64];
    let en = client.read(&mut echo).await.unwrap();
    assert_eq!(&echo[..en], b"ping-realtime-frame");

    // Verify upstream received rewritten model query, upstream Bearer key, and NO virtual key leakage!
    let upstream_head = captured_head.lock().unwrap().clone();
    assert!(
        upstream_head.starts_with(
            "GET /v1/realtime?model=gpt-4o-realtime-preview&intent=transcription HTTP/1.1"
        ),
        "unexpected upstream realtime URI: {upstream_head}"
    );
    let lower = upstream_head.to_ascii_lowercase();
    assert!(lower.contains("authorization: bearer sk-real-openai-key"));
    assert!(lower.contains("openai-beta: realtime=v1"));
    assert!(
        !upstream_head.contains("vk-voice-secret"),
        "virtual key must be stripped from Sec-WebSocket-Protocol: {upstream_head}"
    );
    assert!(lower.contains("sec-websocket-protocol: realtime, openai-beta.realtime-v1"));

    drop(gw_handle);
    ws_handle.abort();
}

#[tokio::test]
async fn e2e_streaming_sse_cache_singleflight_and_semantic_cache() {
    let upstream_calls = Arc::new(AtomicUsize::new(0));
    let calls_bg = Arc::clone(&upstream_calls);

    // Upstream with configurable delay on `/slow` and Anthropic SSE on `/v1/messages` + OpenAI JSON on `/v1/chat/completions`.
    let up_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let up_addr = up_listener.local_addr().unwrap();
    let up_handle = tokio::spawn(async move {
        loop {
            let Ok((tcp, _)) = up_listener.accept().await else {
                break;
            };
            let calls = Arc::clone(&calls_bg);
            tokio::spawn(async move {
                let svc = service_fn(move |req: Request<hyper::body::Incoming>| {
                    let calls = Arc::clone(&calls);
                    async move {
                        let path = req.uri().path().to_owned();
                        let body = req
                            .into_body()
                            .collect()
                            .await
                            .map(|c| c.to_bytes())
                            .unwrap_or_default();
                        let body_str = String::from_utf8_lossy(&body).into_owned();
                        let call_num = calls.fetch_add(1, Ordering::SeqCst) + 1;

                        if body_str.contains("coalesce-me") {
                            tokio::time::sleep(Duration::from_millis(120)).await;
                        }
                        if body_str.contains("fail-leader") {
                            tokio::time::sleep(Duration::from_millis(60)).await;
                            if call_num == 1 {
                                return Ok::<_, Infallible>(
                                    Response::builder()
                                        .status(StatusCode::INTERNAL_SERVER_ERROR)
                                        .header(header::CONTENT_TYPE, "application/json")
                                        .body(Full::new(Bytes::from(
                                            r#"{"error":{"message":"boom"}}"#,
                                        )))
                                        .unwrap(),
                                );
                            }
                        }

                        if path == "/v1/messages" {
                            // Anthropic SSE response -> translated live by ai-provider-adapter to OpenAI SSE!
                            let sse = concat!(
                                "event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"id\":\"msg_1\",\"model\":\"claude-3-5-sonnet\",\"usage\":{\"input_tokens\":10,\"output_tokens\":0}}}\n\n",
                                "event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"Cached SSE!\"}}\n\n",
                                "event: message_delta\ndata: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"end_turn\"},\"usage\":{\"output_tokens\":4}}\n\n",
                                "event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n"
                            );
                            return Ok(Response::builder()
                                .status(StatusCode::OK)
                                .header(header::CONTENT_TYPE, "text/event-stream")
                                .body(Full::new(Bytes::from(sse)))
                                .unwrap());
                        }

                        let resp_json = json!({
                            "id": format!("chatcmpl-{call_num}"),
                            "object": "chat.completion",
                            "model": "gpt-4o",
                            "choices": [{
                                "index": 0,
                                "message": { "role": "assistant", "content": format!("reply #{call_num}") },
                                "finish_reason": "stop"
                            }],
                            "usage": { "prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15 }
                        });
                        Ok(Response::builder()
                            .status(StatusCode::OK)
                            .header(header::CONTENT_TYPE, "application/json")
                            .body(Full::new(Bytes::from(
                                serde_json::to_vec(&resp_json).unwrap(),
                            )))
                            .unwrap())
                    }
                });
                let _ = http1::Builder::new()
                    .serve_connection(TokioIo::new(tcp), svc)
                    .await;
            });
        }
    });

    // Mock embedding endpoint returning nearly identical vectors for paraphrased weather prompts.
    let (emb_addr, _emb_caps, emb_handle) = spawn_mock_http(|_idx, req| {
        let s = String::from_utf8_lossy(&req.body);
        let vec = if s.contains("capital of France") || s.contains("French capital") {
            vec![0.99f32, 0.14, 0.0]
        } else if s.contains("coalesce-me") {
            vec![0.0, 1.0, 0.0]
        } else {
            vec![0.0, 0.0, 1.0]
        };
        (
            StatusCode::OK,
            "application/json",
            serde_json::to_vec(&json!({ "data": [{ "embedding": vec }] })).unwrap(),
        )
    })
    .await;

    let toml_cfg = format!(
        r#"
[server]
listen = "127.0.0.1:0"

[[upstreams]]
name = "mock_up"
endpoints = ["http://{up_addr}"]

[[routes]]
id = "ai_cache_e2e"
path_prefix = "/v1/"
upstream = "mock_up"

[[routes.plugins]]
name = "ai-model-router"
[routes.plugins.config.models]
gpt = [{{ provider = "openai", upstream = "mock_up", model = "gpt-4o" }}]
claude = [{{ provider = "anthropic", upstream = "mock_up", model = "claude-3-5-sonnet" }}]

[[routes.plugins]]
name = "ai-provider-adapter"
[routes.plugins.config.providers.openai]
preset = "openai"
api_key = "sk-oai"
[routes.plugins.config.providers.anthropic]
preset = "anthropic"
api_key = "sk-ant"

[[routes.plugins]]
name = "ai-cache"
[routes.plugins.config]
ttl_secs = 300
cache_streaming = true
singleflight = true
singleflight_timeout_ms = 5000
require_deterministic = true
[routes.plugins.config.semantic]
mode = "embedding_http"
endpoint = "http://{emb_addr}/v1/embeddings"
model = "text-embedding-3-small"
similarity_threshold = 0.95
max_entries = 64

[[routes.plugins]]
name = "ai-usage-tracker"
[routes.plugins.config]
log_usage = false
"#
    );

    let (gw_addr, metrics, runtime, gw_handle) = start_gateway(&toml_cfg).await;

    // 1. Streaming SSE capture & instant replay (with live Anthropic -> OpenAI SSE translation!)
    let sse_req = serde_json::to_vec(&json!({
        "model": "claude",
        "stream": true,
        "temperature": 0,
        "messages": [{ "role": "user", "content": "Say hi" }]
    }))
    .unwrap();
    let (st1, h1, b1) = send_req(
        gw_addr,
        Method::POST,
        "/v1/chat/completions",
        Some("application/json"),
        sse_req.clone(),
        &[],
    )
    .await;
    assert_eq!(st1, StatusCode::OK);
    assert_eq!(h1.get("x-shunt-cache").unwrap(), "miss");
    let sse_body1 = String::from_utf8_lossy(&b1);
    assert!(sse_body1.contains("Cached SSE!"), "got: {sse_body1}");
    assert!(sse_body1.contains("data: [DONE]"));

    tokio::time::sleep(Duration::from_millis(40)).await;
    let calls_after_miss = upstream_calls.load(Ordering::SeqCst);

    let (st2, h2, b2) = send_req(
        gw_addr,
        Method::POST,
        "/v1/chat/completions",
        Some("application/json"),
        sse_req,
        &[],
    )
    .await;
    assert_eq!(st2, StatusCode::OK);
    assert_eq!(h2.get("x-shunt-cache").unwrap(), "hit");
    assert!(
        h2.get(header::CONTENT_TYPE)
            .unwrap()
            .to_str()
            .unwrap()
            .contains("text/event-stream")
    );
    assert_eq!(b2, b1, "replayed SSE stream must match captured wire bytes");
    assert_eq!(
        upstream_calls.load(Ordering::SeqCst),
        calls_after_miss,
        "streaming cache hit must not call upstream"
    );

    // 2. Semantic vector cache hit on paraphrased prompt!
    let sem_q1 = serde_json::to_vec(&json!({
        "model": "gpt",
        "temperature": 0,
        "messages": [{ "role": "user", "content": "What is the capital of France?" }]
    }))
    .unwrap();
    let (st, h, b_orig) = send_req(
        gw_addr,
        Method::POST,
        "/v1/chat/completions",
        Some("application/json"),
        sem_q1,
        &[],
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(h.get("x-shunt-cache").unwrap(), "miss");
    tokio::time::sleep(Duration::from_millis(40)).await;
    let calls_before_sem = upstream_calls.load(Ordering::SeqCst);

    let sem_q2 = serde_json::to_vec(&json!({
        "model": "gpt",
        "temperature": 0,
        "messages": [{ "role": "user", "content": "Tell me the French capital city" }]
    }))
    .unwrap();
    let (st, h, b_sem) = send_req(
        gw_addr,
        Method::POST,
        "/v1/chat/completions",
        Some("application/json"),
        sem_q2,
        &[],
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(h.get("x-shunt-cache").unwrap(), "semantic_hit");
    assert!(h.get("x-shunt-cache-similarity").is_some());
    assert_eq!(b_sem, b_orig);
    assert_eq!(
        upstream_calls.load(Ordering::SeqCst),
        calls_before_sem,
        "semantic hit must not call upstream"
    );

    // 3. Singleflight request coalescing: 5 concurrent identical misses fire ONLY 1 upstream call!
    let calls_before_sf = upstream_calls.load(Ordering::SeqCst);
    let sf_body = serde_json::to_vec(&json!({
        "model": "gpt",
        "temperature": 0,
        "messages": [{ "role": "user", "content": "coalesce-me" }]
    }))
    .unwrap();
    let mut futs = Vec::new();
    for _ in 0..5 {
        let body_clone = sf_body.clone();
        futs.push(tokio::spawn(async move {
            send_req(
                gw_addr,
                Method::POST,
                "/v1/chat/completions",
                Some("application/json"),
                body_clone,
                &[],
            )
            .await
        }));
    }
    let mut statuses = Vec::new();
    let mut cache_hdrs = Vec::new();
    for f in futs {
        let (st, h, _) = f.await.unwrap();
        statuses.push(st);
        cache_hdrs.push(
            h.get("x-shunt-cache")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("")
                .to_owned(),
        );
    }
    assert!(statuses.iter().all(|&s| s == StatusCode::OK));
    assert_eq!(
        upstream_calls.load(Ordering::SeqCst) - calls_before_sf,
        1,
        "singleflight must coalesce 5 concurrent misses into 1 upstream call (headers: {cache_hdrs:?})"
    );
    assert!(
        cache_hdrs.iter().any(|h| h == "coalesced"),
        "expected at least one coalesced follower: {cache_hdrs:?}"
    );

    // Verify Admin Inspector shows semantic cache entries & Prometheus renders stream_hit/coalesced/semantic_hit
    let inspect = inspect_ai_runtime(&metrics, runtime.state_store(), runtime.clock().as_ref());
    assert!(
        inspect["semantic_caches"][0]["entries"]
            .as_u64()
            .unwrap_or(0)
            >= 1
    );
    let prom = metrics.render_prometheus();
    assert!(prom.contains("status=\"stream_hit\""));
    assert!(prom.contains("status=\"semantic_hit\""));
    assert!(prom.contains("status=\"coalesced\""));

    drop(gw_handle);
    up_handle.abort();
    emb_handle.abort();
}
