//! Multimodal, rerank, legacy completions, and WebSocket Realtime endpoint translators & helpers.
//!
//! Keeps all protocol adaptation strictly inside `shunt-ai` while preserving zero-AI `shunt-core`.

use serde_json::{Map, Value, json};
use shunt_plugin_sdk::{HeaderMap, HeaderName, HeaderValue, StatusCode, Uri};

use crate::dialects::unix_timestamp_secs;
use crate::types::{percent_decode, percent_encode_path_segment};

// ---------------------------------------------------------------------------
// Legacy Text / FIM Completions (`POST /v1/completions`)
// ---------------------------------------------------------------------------

/// Rewrites `"model"` in an OpenAI `/v1/completions` JSON request body and optionally injects
/// `stream_options.include_usage = true` when streaming.
pub fn rewrite_openai_completions_request(
    body: &[u8],
    target_model: &str,
    include_stream_usage: bool,
) -> Result<Option<Vec<u8>>, String> {
    let mut val: Value =
        serde_json::from_slice(body).map_err(|e| format!("invalid JSON request body: {e}"))?;
    let obj = val
        .as_object_mut()
        .ok_or_else(|| "request body must be a JSON object".to_owned())?;

    let mut modified = false;
    if obj.get("model").and_then(Value::as_str) != Some(target_model) {
        obj.insert("model".to_owned(), Value::String(target_model.to_owned()));
        modified = true;
    }

    let is_stream = obj.get("stream").and_then(Value::as_bool).unwrap_or(false);
    if is_stream && include_stream_usage {
        let needs_usage = match obj.get("stream_options").and_then(Value::as_object) {
            Some(opts) => !opts.contains_key("include_usage"),
            None => true,
        };
        if needs_usage {
            let opts = obj
                .entry("stream_options".to_owned())
                .or_insert_with(|| Value::Object(Map::new()));
            if let Some(opts_obj) = opts.as_object_mut() {
                opts_obj.insert("include_usage".to_owned(), Value::Bool(true));
                modified = true;
            }
        }
    }

    if !modified {
        return Ok(None);
    }
    serde_json::to_vec(&val)
        .map(Some)
        .map_err(|e| format!("failed to serialize completions request: {e}"))
}

// ---------------------------------------------------------------------------
// Rerank (`POST /v1/rerank`): Cohere / Jina / vLLM / Voyage / AWS Bedrock
// ---------------------------------------------------------------------------

/// Captures original document texts for Bedrock Rerank responses (Bedrock returns indices &
/// scores only, so `return_documents: true` re-attaches the original documents cleanly).
#[derive(Debug, Clone)]
pub struct RerankRequestContext {
    pub documents: Vec<String>,
    pub return_documents: bool,
}

/// Rewrites `"model"` in a canonical `/v1/rerank` JSON request for OpenAI-compatible, Cohere,
/// Jina, Voyage, or vLLM rerankers.
pub fn rewrite_rerank_request(body: &[u8], target_model: &str) -> Result<Option<Vec<u8>>, String> {
    let mut val: Value =
        serde_json::from_slice(body).map_err(|e| format!("invalid JSON request body: {e}"))?;
    let obj = val
        .as_object_mut()
        .ok_or_else(|| "request body must be a JSON object".to_owned())?;

    if obj.get("model").and_then(Value::as_str) == Some(target_model) {
        return Ok(None);
    }
    obj.insert("model".to_owned(), Value::String(target_model.to_owned()));
    serde_json::to_vec(&val)
        .map(Some)
        .map_err(|e| format!("failed to serialize rerank request: {e}"))
}

/// Extracts document strings from a canonical `/v1/rerank` request (`documents` array of strings
/// or `{ "text": "..." }` objects) along with `return_documents`.
pub fn extract_rerank_context(body: &[u8]) -> Option<RerankRequestContext> {
    let val: Value = serde_json::from_slice(body).ok()?;
    let docs_arr = val.get("documents")?.as_array()?;
    let mut documents = Vec::with_capacity(docs_arr.len());
    for doc in docs_arr {
        if let Some(s) = doc.as_str() {
            documents.push(s.to_owned());
        } else if let Some(s) = doc.get("text").and_then(Value::as_str) {
            documents.push(s.to_owned());
        } else {
            documents.push(doc.to_string());
        }
    }
    let return_documents = val
        .get("return_documents")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    Some(RerankRequestContext {
        documents,
        return_documents,
    })
}

/// Translates a canonical `/v1/rerank` JSON request into an AWS Bedrock Agent Runtime `/rerank`
/// JSON request body.
///
/// Accepts either a full foundation model ARN (`arn:aws:bedrock:...`) or a bare Bedrock model ID
/// (e.g. `amazon.rerank-v1:0` or `cohere.rerank-v3-5:0`), expanding bare IDs using `region`.
pub fn openai_to_bedrock_rerank_request(
    body: &[u8],
    model_or_arn: &str,
    region: &str,
) -> Result<Vec<u8>, String> {
    let val: Value =
        serde_json::from_slice(body).map_err(|e| format!("invalid JSON request body: {e}"))?;
    let obj = val
        .as_object()
        .ok_or_else(|| "request body must be a JSON object".to_owned())?;

    let query = obj
        .get("query")
        .and_then(Value::as_str)
        .filter(|q| !q.trim().is_empty())
        .ok_or_else(|| "rerank request must include a non-empty `query` string".to_owned())?;

    let docs = obj
        .get("documents")
        .and_then(Value::as_array)
        .filter(|d| !d.is_empty())
        .ok_or_else(|| "rerank request must include a non-empty `documents` array".to_owned())?;

    let mut sources = Vec::with_capacity(docs.len());
    for doc in docs {
        let text = if let Some(s) = doc.as_str() {
            s.to_owned()
        } else if let Some(s) = doc.get("text").and_then(Value::as_str) {
            s.to_owned()
        } else {
            doc.to_string()
        };
        sources.push(json!({
            "type": "INLINE",
            "inlineDocumentSource": {
                "type": "TEXT",
                "textDocument": {
                    "text": text,
                }
            }
        }));
    }

    let model_arn = if model_or_arn.starts_with("arn:") {
        model_or_arn.to_owned()
    } else {
        format!("arn:aws:bedrock:{region}::foundation-model/{model_or_arn}")
    };

    let mut bedrock_cfg = Map::new();
    bedrock_cfg.insert(
        "modelConfiguration".to_owned(),
        json!({ "modelArn": model_arn }),
    );
    if let Some(top_n) = obj.get("top_n").and_then(Value::as_u64) {
        bedrock_cfg.insert("numberOfResults".to_owned(), json!(top_n));
    }

    let payload = json!({
        "queries": [
            {
                "type": "TEXT",
                "textQuery": { "text": query }
            }
        ],
        "sources": sources,
        "rerankingConfiguration": {
            "type": "BEDROCK_RERANKING_MODEL",
            "bedrockRerankingConfiguration": bedrock_cfg,
        }
    });

    serde_json::to_vec(&payload)
        .map_err(|e| format!("failed to serialize Bedrock rerank request: {e}"))
}

/// Translates an AWS Bedrock Agent Runtime `/rerank` JSON response into canonical Cohere/OpenAI
/// `/v1/rerank` JSON response format.
pub fn bedrock_to_openai_rerank_response(
    body: &[u8],
    status: StatusCode,
    fallback_model: &str,
    ctx: Option<&RerankRequestContext>,
) -> Result<Vec<u8>, String> {
    let val: Value =
        serde_json::from_slice(body).map_err(|e| format!("invalid Bedrock rerank JSON: {e}"))?;

    if !status.is_success() {
        let msg = val
            .get("message")
            .or_else(|| val.get("Message"))
            .and_then(Value::as_str)
            .unwrap_or("Bedrock rerank request failed");
        let err = json!({
            "error": {
                "message": msg,
                "type": "api_error",
                "code": status.as_u16().to_string(),
            }
        });
        return serde_json::to_vec(&err)
            .map_err(|e| format!("failed to serialize rerank error: {e}"));
    }

    let raw_results = val
        .get("results")
        .and_then(Value::as_array)
        .ok_or_else(|| "Bedrock rerank response missing `results` array".to_owned())?;

    let mut results = Vec::with_capacity(raw_results.len());
    for item in raw_results {
        let index = item.get("index").and_then(Value::as_u64).unwrap_or(0) as usize;
        let score = item
            .get("relevanceScore")
            .or_else(|| item.get("relevance_score"))
            .and_then(Value::as_f64)
            .unwrap_or(0.0);
        let mut entry = Map::new();
        entry.insert("index".to_owned(), json!(index));
        entry.insert("relevance_score".to_owned(), json!(score));
        if let Some(rctx) = ctx
            && rctx.return_documents
            && let Some(text) = rctx.documents.get(index)
        {
            entry.insert("document".to_owned(), json!({ "text": text }));
        }
        results.push(Value::Object(entry));
    }

    let out = json!({
        "id": format!("rerank-{}", unix_timestamp_secs()),
        "model": fallback_model,
        "results": results,
    });
    serde_json::to_vec(&out).map_err(|e| format!("failed to serialize rerank response: {e}"))
}

/// Normalizes a Voyage AI rerank response (`{ "data": [{ "index", "relevance_score", "document" }] }`)
/// into the canonical `{ "results": [...] }` schema when `results` is absent.
pub fn normalize_voyage_rerank_response(
    body: &[u8],
    status: StatusCode,
    fallback_model: &str,
) -> Result<Vec<u8>, String> {
    if !status.is_success() {
        return Ok(body.to_vec());
    }
    let val: Value =
        serde_json::from_slice(body).map_err(|e| format!("invalid rerank JSON response: {e}"))?;
    if val.get("results").is_some() {
        return Ok(body.to_vec());
    }
    let Some(data) = val.get("data").and_then(Value::as_array) else {
        return Ok(body.to_vec());
    };

    let mut results = Vec::with_capacity(data.len());
    for item in data {
        let index = item.get("index").and_then(Value::as_u64).unwrap_or(0);
        let score = item
            .get("relevance_score")
            .and_then(Value::as_f64)
            .unwrap_or(0.0);
        let mut entry = Map::new();
        entry.insert("index".to_owned(), json!(index));
        entry.insert("relevance_score".to_owned(), json!(score));
        if let Some(doc) = item.get("document") {
            if let Some(s) = doc.as_str() {
                entry.insert("document".to_owned(), json!({ "text": s }));
            } else {
                entry.insert("document".to_owned(), doc.clone());
            }
        }
        results.push(Value::Object(entry));
    }

    let mut out = Map::new();
    out.insert(
        "id".to_owned(),
        val.get("id")
            .cloned()
            .unwrap_or_else(|| json!(format!("rerank-{}", unix_timestamp_secs()))),
    );
    out.insert(
        "model".to_owned(),
        val.get("model")
            .cloned()
            .unwrap_or_else(|| json!(fallback_model)),
    );
    out.insert("results".to_owned(), Value::Array(results));
    if let Some(usage) = val.get("usage") {
        out.insert("usage".to_owned(), usage.clone());
    }
    serde_json::to_vec(&Value::Object(out))
        .map_err(|e| format!("failed to serialize normalized rerank response: {e}"))
}

// ---------------------------------------------------------------------------
// Images (`POST /v1/images/generations`) — Gemini / Vertex AI Imagen
// ---------------------------------------------------------------------------

/// Builds the upstream URI path for a Google Gemini / Vertex AI Imagen `:predict` request.
pub fn gemini_imagen_path(model: &str, vertex: Option<(&str, &str)>) -> String {
    let clean = model.strip_prefix("models/").unwrap_or(model);
    let encoded_model = percent_encode_path_segment(clean);
    match vertex {
        Some((project, location)) => format!(
            "/v1/projects/{}/locations/{}/publishers/google/models/{}:predict",
            percent_encode_path_segment(project),
            percent_encode_path_segment(location),
            encoded_model
        ),
        None => format!("/v1beta/models/{encoded_model}:predict"),
    }
}

/// Translates an OpenAI `POST /v1/images/generations` JSON request into Google Imagen `:predict`
/// format (`instances: [{ prompt }]`, `parameters: { sampleCount, aspectRatio }`).
pub fn openai_to_gemini_imagen_request(body: &[u8]) -> Result<Vec<u8>, String> {
    let val: Value =
        serde_json::from_slice(body).map_err(|e| format!("invalid JSON request body: {e}"))?;
    let obj = val
        .as_object()
        .ok_or_else(|| "request body must be a JSON object".to_owned())?;

    let prompt = obj
        .get("prompt")
        .and_then(Value::as_str)
        .filter(|p| !p.trim().is_empty())
        .ok_or_else(|| "image generation request must include a non-empty `prompt`".to_owned())?;

    let mut params = Map::new();
    let sample_count = obj
        .get("n")
        .and_then(Value::as_u64)
        .unwrap_or(1)
        .clamp(1, 8);
    params.insert("sampleCount".to_owned(), json!(sample_count));

    if let Some(size) = obj.get("size").and_then(Value::as_str) {
        let aspect = match size {
            "1024x1024" | "512x512" | "256x256" => Some("1:1"),
            "1792x1024" | "1536x1024" => Some("16:9"),
            "1024x1792" | "1024x1536" => Some("9:16"),
            "1280x960" => Some("4:3"),
            "960x1280" => Some("3:4"),
            _ => None,
        };
        if let Some(ar) = aspect {
            params.insert("aspectRatio".to_owned(), json!(ar));
        }
    }

    let payload = json!({
        "instances": [{ "prompt": prompt }],
        "parameters": params,
    });
    serde_json::to_vec(&payload)
        .map_err(|e| format!("failed to serialize Gemini Imagen request: {e}"))
}

/// Translates a Google Imagen `:predict` response into OpenAI `/v1/images/generations` JSON.
pub fn gemini_imagen_to_openai_response(
    body: &[u8],
    status: StatusCode,
) -> Result<Vec<u8>, String> {
    let val: Value =
        serde_json::from_slice(body).map_err(|e| format!("invalid Gemini Imagen JSON: {e}"))?;

    if !status.is_success() {
        let msg = val
            .get("error")
            .and_then(|e| e.get("message"))
            .and_then(Value::as_str)
            .unwrap_or("Gemini Imagen request failed");
        let err = json!({
            "error": {
                "message": msg,
                "type": "api_error",
                "code": status.as_u16().to_string(),
            }
        });
        return serde_json::to_vec(&err)
            .map_err(|e| format!("failed to serialize Imagen error: {e}"));
    }

    let preds = val
        .get("predictions")
        .and_then(Value::as_array)
        .ok_or_else(|| "Gemini Imagen response missing `predictions` array".to_owned())?;

    let mut data = Vec::with_capacity(preds.len());
    for pred in preds {
        if let Some(b64) = pred.get("bytesBase64Encoded").and_then(Value::as_str) {
            let mut item = Map::new();
            item.insert("b64_json".to_owned(), Value::String(b64.to_owned()));
            if let Some(revised) = pred.get("prompt").and_then(Value::as_str) {
                item.insert(
                    "revised_prompt".to_owned(),
                    Value::String(revised.to_owned()),
                );
            }
            data.push(Value::Object(item));
        }
    }

    let out = json!({
        "created": unix_timestamp_secs(),
        "data": data,
    });
    serde_json::to_vec(&out).map_err(|e| format!("failed to serialize OpenAI image response: {e}"))
}

/// Rewrites `"model"` in a generic OpenAI JSON request (used for `/v1/images/generations`,
/// `/v1/audio/speech`, and `/v1/moderations`).
pub fn rewrite_json_model_field(
    body: &[u8],
    target_model: &str,
) -> Result<Option<Vec<u8>>, String> {
    let mut val: Value =
        serde_json::from_slice(body).map_err(|e| format!("invalid JSON request body: {e}"))?;
    let obj = val
        .as_object_mut()
        .ok_or_else(|| "request body must be a JSON object".to_owned())?;
    if obj.get("model").and_then(Value::as_str) == Some(target_model) {
        return Ok(None);
    }
    obj.insert("model".to_owned(), Value::String(target_model.to_owned()));
    serde_json::to_vec(&val)
        .map(Some)
        .map_err(|e| format!("failed to serialize JSON request: {e}"))
}

// ---------------------------------------------------------------------------
// Query Parameter & WebSocket Realtime Helpers (`GET /v1/realtime`, `GET /v1/generation`)
// ---------------------------------------------------------------------------

/// Extracts and percent-decodes the first query parameter matching `key` from a URI query string.
pub fn extract_query_param(query: Option<&str>, key: &str) -> Option<String> {
    let q = query?;
    for pair in q.split('&') {
        if pair.is_empty() {
            continue;
        }
        let (k, v) = match pair.split_once('=') {
            Some((k, v)) => (k, v),
            None => (pair, ""),
        };
        if k == key {
            let decoded = percent_decode(v);
            if !decoded.trim().is_empty() {
                return Some(decoded);
            }
        }
    }
    None
}

/// Extracts an OpenAI Realtime browser-style API key from `Sec-WebSocket-Protocol`:
/// `realtime, openai-insecure-api-key.<KEY>, openai-beta.realtime-v1`.
pub fn extract_realtime_ws_subprotocol_key(headers: &HeaderMap) -> Option<String> {
    for val in headers.get_all("sec-websocket-protocol") {
        let Ok(s) = val.to_str() else {
            continue;
        };
        for tok in s.split(',') {
            let tok = tok.trim();
            if let Some(key) = tok.strip_prefix("openai-insecure-api-key.") {
                let key = key.trim();
                if !key.is_empty() {
                    return Some(key.to_owned());
                }
            }
        }
    }
    None
}

/// Removes `openai-insecure-api-key.*` tokens from `Sec-WebSocket-Protocol` while keeping all
/// remaining WebSocket subprotocols (`realtime`, `openai-beta.realtime-v1`, etc.) intact.
pub fn strip_realtime_ws_key_subprotocol(headers: &mut HeaderMap) {
    let proto_name = HeaderName::from_static("sec-websocket-protocol");
    let mut kept = Vec::new();
    let mut saw_key_token = false;

    for val in headers.get_all(&proto_name) {
        let Ok(s) = val.to_str() else {
            continue;
        };
        for tok in s.split(',') {
            let tok = tok.trim();
            if tok.is_empty() {
                continue;
            }
            if tok.starts_with("openai-insecure-api-key.") {
                saw_key_token = true;
            } else {
                kept.push(tok.to_owned());
            }
        }
    }

    if !saw_key_token {
        return;
    }

    headers.remove(&proto_name);
    if !kept.is_empty()
        && let Ok(joined) = HeaderValue::from_str(&kept.join(", "))
    {
        headers.insert(proto_name, joined);
    }
}

/// Rewrites an incoming `/v1/realtime?...` URI for either OpenAI-compatible (`/v1/realtime?model=...`)
/// or Azure OpenAI (`/openai/realtime?api-version=...&deployment=...`) while preserving non-model
/// query parameters (such as `intent=transcription`).
pub fn rewrite_realtime_uri(
    orig_uri: &Uri,
    base_path: &str,
    target_model: &str,
    azure_api_version: Option<&str>,
) -> Result<Uri, String> {
    let mut params: Vec<String> = Vec::new();

    if let Some(api_ver) = azure_api_version {
        params.push(format!(
            "api-version={}",
            percent_encode_path_segment(api_ver)
        ));
        params.push(format!(
            "deployment={}",
            percent_encode_path_segment(target_model)
        ));
    } else {
        params.push(format!(
            "model={}",
            percent_encode_path_segment(target_model)
        ));
    }

    if let Some(q) = orig_uri.query() {
        for pair in q.split('&') {
            if pair.is_empty() {
                continue;
            }
            let k = pair.split_once('=').map(|(k, _)| k).unwrap_or(pair);
            if k == "model"
                || (azure_api_version.is_some() && matches!(k, "deployment" | "api-version"))
            {
                continue;
            }
            params.push(pair.to_owned());
        }
    }

    let full = format!("{base_path}?{}", params.join("&"));
    full.parse::<Uri>()
        .map_err(|e| format!("invalid realtime URI `{full}`: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bedrock_rerank_request_and_response_roundtrip() {
        let req = serde_json::to_vec(&json!({
            "model": "rerank-fast",
            "query": "What is Rust?",
            "documents": ["Rust is a systems language", {"text": "Bananas are yellow"}],
            "top_n": 1,
            "return_documents": true
        }))
        .unwrap();

        let rctx = extract_rerank_context(&req).unwrap();
        assert!(rctx.return_documents);
        assert_eq!(rctx.documents.len(), 2);

        let br_bytes =
            openai_to_bedrock_rerank_request(&req, "amazon.rerank-v1:0", "us-east-1").unwrap();
        let br: Value = serde_json::from_slice(&br_bytes).unwrap();
        assert_eq!(
            br["rerankingConfiguration"]["bedrockRerankingConfiguration"]["modelConfiguration"]["modelArn"],
            "arn:aws:bedrock:us-east-1::foundation-model/amazon.rerank-v1:0"
        );
        assert_eq!(
            br["rerankingConfiguration"]["bedrockRerankingConfiguration"]["numberOfResults"],
            1
        );
        assert_eq!(
            br["sources"][0]["inlineDocumentSource"]["textDocument"]["text"],
            "Rust is a systems language"
        );

        let br_resp = serde_json::to_vec(&json!({
            "results": [{ "index": 0, "relevanceScore": 0.97 }]
        }))
        .unwrap();
        let canonical_bytes = bedrock_to_openai_rerank_response(
            &br_resp,
            StatusCode::OK,
            "amazon.rerank-v1:0",
            Some(&rctx),
        )
        .unwrap();
        let canonical: Value = serde_json::from_slice(&canonical_bytes).unwrap();
        assert_eq!(canonical["results"][0]["index"], 0);
        assert_eq!(canonical["results"][0]["relevance_score"], 0.97);
        assert_eq!(
            canonical["results"][0]["document"]["text"],
            "Rust is a systems language"
        );
    }

    #[test]
    fn voyage_rerank_response_normalizes_data_to_results() {
        let raw = serde_json::to_vec(&json!({
            "model": "rerank-2",
            "data": [{ "index": 1, "relevance_score": 0.88, "document": "hello" }],
            "usage": { "total_tokens": 12 }
        }))
        .unwrap();
        let norm_bytes =
            normalize_voyage_rerank_response(&raw, StatusCode::OK, "rerank-2").unwrap();
        let norm: Value = serde_json::from_slice(&norm_bytes).unwrap();
        assert_eq!(norm["results"][0]["index"], 1);
        assert_eq!(norm["results"][0]["document"]["text"], "hello");
        assert_eq!(norm["usage"]["total_tokens"], 12);
    }

    #[test]
    fn gemini_imagen_request_and_response_translate() {
        let req = serde_json::to_vec(&json!({
            "model": "imagen-3.0-generate-002",
            "prompt": "A serene alpine lake",
            "n": 2,
            "size": "1792x1024"
        }))
        .unwrap();
        let gem_bytes = openai_to_gemini_imagen_request(&req).unwrap();
        let gem: Value = serde_json::from_slice(&gem_bytes).unwrap();
        assert_eq!(gem["instances"][0]["prompt"], "A serene alpine lake");
        assert_eq!(gem["parameters"]["sampleCount"], 2);
        assert_eq!(gem["parameters"]["aspectRatio"], "16:9");

        let gem_resp = serde_json::to_vec(&json!({
            "predictions": [{ "bytesBase64Encoded": "AAAA", "mimeType": "image/png" }]
        }))
        .unwrap();
        let oai_bytes = gemini_imagen_to_openai_response(&gem_resp, StatusCode::OK).unwrap();
        let oai: Value = serde_json::from_slice(&oai_bytes).unwrap();
        assert_eq!(oai["data"][0]["b64_json"], "AAAA");
    }

    #[test]
    fn realtime_subprotocol_extraction_stripping_and_uri_rewrite() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "sec-websocket-protocol",
            HeaderValue::from_static(
                "realtime, openai-insecure-api-key.vk-secret, openai-beta.realtime-v1",
            ),
        );
        assert_eq!(
            extract_realtime_ws_subprotocol_key(&headers).as_deref(),
            Some("vk-secret")
        );
        strip_realtime_ws_key_subprotocol(&mut headers);
        assert_eq!(
            headers
                .get("sec-websocket-protocol")
                .and_then(|v| v.to_str().ok()),
            Some("realtime, openai-beta.realtime-v1")
        );

        let uri: Uri = "/v1/realtime?model=voice-alias&intent=transcription"
            .parse()
            .unwrap();
        let oai =
            rewrite_realtime_uri(&uri, "/v1/realtime", "gpt-4o-realtime-preview", None).unwrap();
        assert_eq!(
            oai.to_string(),
            "/v1/realtime?model=gpt-4o-realtime-preview&intent=transcription"
        );
        let az = rewrite_realtime_uri(
            &uri,
            "/openai/realtime",
            "my-rt-deploy",
            Some("2024-10-01-preview"),
        )
        .unwrap();
        assert_eq!(
            az.to_string(),
            "/openai/realtime?api-version=2024-10-01-preview&deployment=my-rt-deploy&intent=transcription"
        );
    }
}
