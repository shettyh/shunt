//! Google Gemini dialect translator supporting both AI Studio (`generativelanguage.googleapis.com`)
//! and Vertex AI (`*-aiplatform.googleapis.com`) chat completions, SSE streaming, and embeddings.

use std::collections::HashMap;

use serde_json::{Map, Value, json};
use shunt_plugin_sdk::{Bytes, StatusCode};

use crate::dialects::{
    emit_openai_chunk, extract_text_content, format_chatcmpl_id, unix_timestamp_secs,
    write_sse_json,
};
use crate::sse::{SseEvent, SseParser};
use crate::translate::resolve_thinking_budget;
use crate::types::percent_encode_path_segment;

/// Builds the upstream URI path (and query) for a Gemini chat request.
pub fn gemini_chat_path(model: &str, stream: bool, vertex: Option<(&str, &str)>) -> String {
    let clean = model.strip_prefix("models/").unwrap_or(model);
    let encoded_model = percent_encode_path_segment(clean);
    let action = if stream {
        "streamGenerateContent?alt=sse"
    } else {
        "generateContent"
    };

    match vertex {
        Some((project, location)) => format!(
            "/v1/projects/{}/locations/{}/publishers/google/models/{}:{}",
            percent_encode_path_segment(project),
            percent_encode_path_segment(location),
            encoded_model,
            action
        ),
        None => format!("/v1beta/models/{encoded_model}:{action}"),
    }
}

/// Builds the upstream URI path for a Gemini embeddings request.
pub fn gemini_embeddings_path(model: &str, is_batch: bool, vertex: Option<(&str, &str)>) -> String {
    let clean = model.strip_prefix("models/").unwrap_or(model);
    let encoded_model = percent_encode_path_segment(clean);

    match vertex {
        Some((project, location)) => format!(
            "/v1/projects/{}/locations/{}/publishers/google/models/{}:predict",
            percent_encode_path_segment(project),
            percent_encode_path_segment(location),
            encoded_model
        ),
        None => {
            let action = if is_batch {
                "batchEmbedContents"
            } else {
                "embedContent"
            };
            format!("/v1beta/models/{encoded_model}:{action}")
        }
    }
}

/// Translates an OpenAI `/v1/chat/completions` JSON request into a Gemini `generateContent` JSON request.
pub fn openai_to_gemini_request(body: &[u8]) -> Result<Vec<u8>, String> {
    let val: Value =
        serde_json::from_slice(body).map_err(|e| format!("invalid JSON request body: {e}"))?;
    let obj = val
        .as_object()
        .ok_or_else(|| "request body must be a JSON object".to_owned())?;

    let messages_val = obj
        .get("messages")
        .and_then(Value::as_array)
        .ok_or_else(|| "missing or invalid `messages` array".to_owned())?;

    let mut system_parts: Vec<Value> = Vec::new();
    let mut contents: Vec<(String, Vec<Value>)> = Vec::new();
    let mut tool_id_to_name: HashMap<String, String> = HashMap::new();

    for msg in messages_val {
        let Some(msg_obj) = msg.as_object() else {
            continue;
        };
        let role = msg_obj
            .get("role")
            .and_then(Value::as_str)
            .unwrap_or("user");

        match role {
            "system" | "developer" => {
                let text = extract_text_content(msg_obj.get("content"));
                if !text.is_empty() {
                    system_parts.push(json!({ "text": text }));
                }
            }
            "assistant" => {
                let mut parts = convert_content_to_gemini_parts(msg_obj.get("content"));
                if let Some(tool_calls) = msg_obj.get("tool_calls").and_then(Value::as_array) {
                    for tc in tool_calls {
                        let id = tc.get("id").and_then(Value::as_str).unwrap_or("");
                        let func = tc.get("function");
                        let name = func
                            .and_then(|f| f.get("name"))
                            .and_then(Value::as_str)
                            .unwrap_or("");
                        if !id.is_empty() && !name.is_empty() {
                            tool_id_to_name.insert(id.to_owned(), name.to_owned());
                        }
                        let raw_args = func
                            .and_then(|f| f.get("arguments"))
                            .and_then(Value::as_str)
                            .unwrap_or("{}");
                        let args: Value = serde_json::from_str(raw_args)
                            .unwrap_or_else(|_| Value::Object(Map::new()));
                        parts.push(json!({
                            "functionCall": {
                                "name": name,
                                "args": args,
                            }
                        }));
                    }
                }
                if !parts.is_empty() {
                    push_gemini_content(&mut contents, "model", parts);
                }
            }
            "tool" => {
                let tool_call_id = msg_obj
                    .get("tool_call_id")
                    .and_then(Value::as_str)
                    .unwrap_or("");
                let name = msg_obj
                    .get("name")
                    .and_then(Value::as_str)
                    .map(str::to_owned)
                    .or_else(|| tool_id_to_name.get(tool_call_id).cloned())
                    .unwrap_or_else(|| tool_call_id.to_owned());
                let raw_text = extract_text_content(msg_obj.get("content"));
                let response_obj = match serde_json::from_str::<Value>(&raw_text) {
                    Ok(Value::Object(map)) => Value::Object(map),
                    Ok(other) => json!({ "result": other }),
                    Err(_) => json!({ "result": raw_text }),
                };
                let part = json!({
                    "functionResponse": {
                        "name": name,
                        "response": response_obj,
                    }
                });
                push_gemini_content(&mut contents, "user", vec![part]);
            }
            _ => {
                let parts = convert_content_to_gemini_parts(msg_obj.get("content"));
                if !parts.is_empty() {
                    push_gemini_content(&mut contents, "user", parts);
                }
            }
        }
    }

    let formatted_contents: Vec<Value> = contents
        .into_iter()
        .map(|(role, parts)| json!({ "role": role, "parts": parts }))
        .collect();

    let mut out = Map::new();
    out.insert("contents".to_owned(), Value::Array(formatted_contents));

    if !system_parts.is_empty() {
        out.insert(
            "systemInstruction".to_owned(),
            json!({ "parts": system_parts }),
        );
    }

    // Generation parameters
    let mut gen_cfg = Map::new();
    if let Some(temp) = obj.get("temperature").filter(|v| !v.is_null()) {
        gen_cfg.insert("temperature".to_owned(), temp.clone());
    }
    if let Some(top_p) = obj.get("top_p").filter(|v| !v.is_null()) {
        gen_cfg.insert("topP".to_owned(), top_p.clone());
    }
    if let Some(max_tok) = obj
        .get("max_tokens")
        .and_then(Value::as_u64)
        .filter(|&n| n > 0)
        .or_else(|| {
            obj.get("max_completion_tokens")
                .and_then(Value::as_u64)
                .filter(|&n| n > 0)
        })
    {
        gen_cfg.insert("maxOutputTokens".to_owned(), Value::Number(max_tok.into()));
    }
    if let Some(stop) = obj.get("stop") {
        match stop {
            Value::String(s) => {
                gen_cfg.insert(
                    "stopSequences".to_owned(),
                    Value::Array(vec![Value::String(s.clone())]),
                );
            }
            Value::Array(arr) => {
                let seqs: Vec<Value> = arr
                    .iter()
                    .filter_map(|v| v.as_str().map(|s| Value::String(s.to_owned())))
                    .collect();
                if !seqs.is_empty() {
                    gen_cfg.insert("stopSequences".to_owned(), Value::Array(seqs));
                }
            }
            _ => {}
        }
    }
    if let Some(rf) = obj.get("response_format").and_then(Value::as_object) {
        match rf.get("type").and_then(Value::as_str) {
            Some("json_object") => {
                gen_cfg.insert(
                    "responseMimeType".to_owned(),
                    Value::String("application/json".to_owned()),
                );
            }
            Some("json_schema") => {
                gen_cfg.insert(
                    "responseMimeType".to_owned(),
                    Value::String("application/json".to_owned()),
                );
                if let Some(schema) = rf.get("json_schema").and_then(|js| js.get("schema")) {
                    gen_cfg.insert("responseSchema".to_owned(), clean_gemini_schema(schema));
                }
            }
            _ => {}
        }
    }
    if let Some(thinking_intent) = resolve_thinking_budget(obj) {
        match thinking_intent {
            Some(budget) => {
                gen_cfg.insert(
                    "thinkingConfig".to_owned(),
                    json!({
                        "thinkingBudget": budget,
                        "includeThoughts": true,
                    }),
                );
            }
            None => {
                gen_cfg.insert("thinkingConfig".to_owned(), json!({ "thinkingBudget": 0 }));
            }
        }
    }
    if !gen_cfg.is_empty() {
        out.insert("generationConfig".to_owned(), Value::Object(gen_cfg));
    }

    // Tools
    if let Some(tools) = obj.get("tools").and_then(Value::as_array) {
        let decls: Vec<Value> = tools
            .iter()
            .filter_map(|t| {
                let func = t.get("function")?;
                let name = func.get("name")?.as_str()?;
                let mut decl = Map::new();
                decl.insert("name".to_owned(), Value::String(name.to_owned()));
                if let Some(desc) = func.get("description").and_then(Value::as_str) {
                    decl.insert("description".to_owned(), Value::String(desc.to_owned()));
                }
                if let Some(params) = func.get("parameters") {
                    decl.insert("parameters".to_owned(), clean_gemini_schema(params));
                }
                Some(Value::Object(decl))
            })
            .collect();
        if !decls.is_empty() {
            out.insert(
                "tools".to_owned(),
                json!([{ "functionDeclarations": decls }]),
            );
        }
    }

    if let Some(tc) = obj.get("tool_choice") {
        match tc {
            Value::String(s) if s == "none" => {
                out.insert(
                    "toolConfig".to_owned(),
                    json!({ "functionCallingConfig": { "mode": "NONE" } }),
                );
            }
            Value::String(s) if s == "auto" => {
                out.insert(
                    "toolConfig".to_owned(),
                    json!({ "functionCallingConfig": { "mode": "AUTO" } }),
                );
            }
            Value::String(s) if s == "required" => {
                out.insert(
                    "toolConfig".to_owned(),
                    json!({ "functionCallingConfig": { "mode": "ANY" } }),
                );
            }
            Value::Object(tc_obj) => {
                if let Some(name) = tc_obj
                    .get("function")
                    .and_then(|f| f.get("name"))
                    .and_then(Value::as_str)
                {
                    out.insert(
                        "toolConfig".to_owned(),
                        json!({
                            "functionCallingConfig": {
                                "mode": "ANY",
                                "allowedFunctionNames": [name],
                            }
                        }),
                    );
                }
            }
            _ => {}
        }
    }

    serde_json::to_vec(&Value::Object(out))
        .map_err(|e| format!("failed to serialize Gemini request: {e}"))
}

fn push_gemini_content(
    contents: &mut Vec<(String, Vec<Value>)>,
    role: &str,
    mut parts: Vec<Value>,
) {
    if let Some((last_role, last_parts)) = contents.last_mut()
        && last_role == role
    {
        last_parts.append(&mut parts);
        return;
    }
    contents.push((role.to_owned(), parts));
}

fn convert_content_to_gemini_parts(content: Option<&Value>) -> Vec<Value> {
    match content {
        Some(Value::String(s)) => {
            if s.is_empty() {
                Vec::new()
            } else {
                vec![json!({ "text": s })]
            }
        }
        Some(Value::Array(parts)) => {
            let mut out = Vec::new();
            for part in parts {
                match part.get("type").and_then(Value::as_str) {
                    Some("text") => {
                        if let Some(t) = part.get("text").and_then(Value::as_str) {
                            out.push(json!({ "text": t }));
                        }
                    }
                    Some("image_url") => {
                        if let Some(url) = part
                            .get("image_url")
                            .and_then(|u| u.get("url"))
                            .and_then(Value::as_str)
                        {
                            if let Some(rest) = url.strip_prefix("data:")
                                && let Some((meta, data)) = rest.split_once(',')
                                && let Some(mime_type) = meta.strip_suffix(";base64")
                            {
                                out.push(json!({
                                    "inlineData": {
                                        "mimeType": mime_type,
                                        "data": data,
                                    }
                                }));
                            } else {
                                out.push(json!({
                                    "fileData": {
                                        "mimeType": infer_mime_type(url),
                                        "fileUri": url,
                                    }
                                }));
                            }
                        }
                    }
                    _ => {}
                }
            }
            out
        }
        _ => Vec::new(),
    }
}

fn infer_mime_type(url: &str) -> &'static str {
    let lower = url.to_ascii_lowercase();
    if lower.ends_with(".png") {
        "image/png"
    } else if lower.ends_with(".webp") {
        "image/webp"
    } else if lower.ends_with(".gif") {
        "image/gif"
    } else {
        "image/jpeg"
    }
}

/// Recursively strips JSON Schema keywords rejected by Gemini (`$schema`, `additionalProperties`).
pub fn clean_gemini_schema(schema: &Value) -> Value {
    match schema {
        Value::Object(map) => {
            let mut out = Map::with_capacity(map.len());
            for (k, v) in map {
                if matches!(k.as_str(), "$schema" | "additionalProperties" | "$id") {
                    continue;
                }
                out.insert(k.clone(), clean_gemini_schema(v));
            }
            Value::Object(out)
        }
        Value::Array(items) => Value::Array(items.iter().map(clean_gemini_schema).collect()),
        other => other.clone(),
    }
}

/// Maps Gemini `finishReason` to OpenAI `finish_reason`.
pub fn map_gemini_finish_reason(
    finish_reason: Option<&str>,
    has_tool_calls: bool,
) -> Option<&'static str> {
    if has_tool_calls {
        return Some("tool_calls");
    }
    match finish_reason {
        Some("STOP") => Some("stop"),
        Some("MAX_TOKENS") => Some("length"),
        Some("SAFETY")
        | Some("RECITATION")
        | Some("BLOCKLIST")
        | Some("PROHIBITED_CONTENT")
        | Some("SPII") => Some("content_filter"),
        Some(_) => Some("stop"),
        None => None,
    }
}

/// Translates a non-streaming Gemini `generateContent` JSON response (or error JSON)
/// into an OpenAI `/v1/chat/completions` JSON response.
pub fn gemini_to_openai_response(
    gemini_body: &[u8],
    status: StatusCode,
    fallback_model: &str,
) -> Result<Vec<u8>, String> {
    let val: Value = serde_json::from_slice(gemini_body)
        .map_err(|e| format!("invalid Gemini JSON response: {e}"))?;

    if !status.is_success() || val.get("error").is_some() {
        return serialize_gemini_error(&val);
    }

    let raw_id = val
        .get("responseId")
        .and_then(Value::as_str)
        .unwrap_or("gemini");
    let id = format_chatcmpl_id(raw_id);
    let model = val
        .get("modelVersion")
        .and_then(Value::as_str)
        .unwrap_or(fallback_model);

    let candidate = val
        .get("candidates")
        .and_then(Value::as_array)
        .and_then(|c| c.first());

    let mut text_parts: Vec<&str> = Vec::new();
    let mut thought_parts: Vec<&str> = Vec::new();
    let mut tool_calls: Vec<Value> = Vec::new();

    if let Some(parts) = candidate
        .and_then(|c| c.get("content"))
        .and_then(|c| c.get("parts"))
        .and_then(Value::as_array)
    {
        for (idx, part) in parts.iter().enumerate() {
            let is_thought = part
                .get("thought")
                .and_then(Value::as_bool)
                .unwrap_or(false);
            if let Some(t) = part.get("text").and_then(Value::as_str) {
                if is_thought {
                    if !t.is_empty() {
                        thought_parts.push(t);
                    }
                } else {
                    text_parts.push(t);
                }
            }
            if let Some(fc) = part.get("functionCall").and_then(Value::as_object) {
                let name = fc.get("name").and_then(Value::as_str).unwrap_or("");
                let call_id = fc
                    .get("id")
                    .and_then(Value::as_str)
                    .map(str::to_owned)
                    .unwrap_or_else(|| format!("call_gemini_{idx}"));
                let args_str = fc
                    .get("args")
                    .map(|a| serde_json::to_string(a).unwrap_or_else(|_| "{}".to_owned()))
                    .unwrap_or_else(|| "{}".to_owned());
                tool_calls.push(json!({
                    "id": call_id,
                    "type": "function",
                    "function": {
                        "name": name,
                        "arguments": args_str,
                    }
                }));
            }
        }
    }

    let finish_reason = map_gemini_finish_reason(
        candidate
            .and_then(|c| c.get("finishReason"))
            .and_then(Value::as_str),
        !tool_calls.is_empty(),
    )
    .unwrap_or("stop");

    let mut message = Map::new();
    message.insert("role".to_owned(), Value::String("assistant".to_owned()));
    if text_parts.is_empty() && !tool_calls.is_empty() {
        message.insert("content".to_owned(), Value::Null);
    } else {
        message.insert("content".to_owned(), Value::String(text_parts.join("")));
    }
    if !thought_parts.is_empty() {
        message.insert(
            "reasoning_content".to_owned(),
            Value::String(thought_parts.join("")),
        );
    }
    if !tool_calls.is_empty() {
        message.insert("tool_calls".to_owned(), Value::Array(tool_calls));
    }

    let usage_meta = val.get("usageMetadata");
    let prompt_tokens = usage_meta
        .and_then(|u| u.get("promptTokenCount"))
        .and_then(Value::as_u64)
        .unwrap_or(0);
    let cached_tokens = usage_meta
        .and_then(|u| u.get("cachedContentTokenCount"))
        .and_then(Value::as_u64)
        .unwrap_or(0);
    let thoughts_tokens = usage_meta
        .and_then(|u| u.get("thoughtsTokenCount"))
        .and_then(Value::as_u64)
        .unwrap_or(0);
    let completion_tokens = usage_meta
        .and_then(|u| u.get("candidatesTokenCount"))
        .and_then(Value::as_u64)
        .unwrap_or(0)
        .saturating_add(thoughts_tokens);
    let total_tokens = usage_meta
        .and_then(|u| u.get("totalTokenCount"))
        .and_then(Value::as_u64)
        .unwrap_or_else(|| prompt_tokens.saturating_add(completion_tokens));

    let mut usage_obj = Map::new();
    usage_obj.insert(
        "prompt_tokens".to_owned(),
        Value::Number(prompt_tokens.into()),
    );
    usage_obj.insert(
        "completion_tokens".to_owned(),
        Value::Number(completion_tokens.into()),
    );
    usage_obj.insert(
        "total_tokens".to_owned(),
        Value::Number(total_tokens.into()),
    );
    if cached_tokens > 0 {
        usage_obj.insert(
            "prompt_tokens_details".to_owned(),
            json!({ "cached_tokens": cached_tokens }),
        );
    }
    if thoughts_tokens > 0 {
        usage_obj.insert(
            "completion_tokens_details".to_owned(),
            json!({ "reasoning_tokens": thoughts_tokens }),
        );
    }

    let openai_resp = json!({
        "id": id,
        "object": "chat.completion",
        "created": unix_timestamp_secs(),
        "model": model,
        "choices": [{
            "index": 0,
            "message": Value::Object(message),
            "finish_reason": finish_reason,
        }],
        "usage": Value::Object(usage_obj),
    });

    serde_json::to_vec(&openai_resp)
        .map_err(|e| format!("failed to serialize OpenAI response: {e}"))
}

fn serialize_gemini_error(val: &Value) -> Result<Vec<u8>, String> {
    let err_obj = val.get("error").or_else(|| {
        val.as_array()
            .and_then(|a| a.first())
            .and_then(|v| v.get("error"))
    });
    let err_status = err_obj
        .and_then(|e| e.get("status"))
        .and_then(Value::as_str)
        .unwrap_or("api_error");
    let err_msg = err_obj
        .and_then(|e| e.get("message"))
        .and_then(Value::as_str)
        .unwrap_or("upstream Gemini provider error");
    let openai_err = json!({
        "error": {
            "message": err_msg,
            "type": err_status.to_ascii_lowercase(),
            "param": Value::Null,
            "code": err_status,
        }
    });
    serde_json::to_vec(&openai_err).map_err(|e| format!("failed to serialize OpenAI error: {e}"))
}

/// Stateful per-request streaming translator converting Gemini `?alt=sse` SSE frames into
/// OpenAI `chat.completion.chunk` SSE frames live in `on_response_body_chunk`.
#[derive(Debug, Clone)]
pub struct GeminiSseTranslator {
    parser: SseParser,
    id: String,
    model: String,
    created: u64,
    started: bool,
    saw_tool_call: bool,
    next_tool_call_index: usize,
    final_finish_reason: Option<&'static str>,
    prompt_tokens: Option<u64>,
    cached_tokens: Option<u64>,
    completion_tokens: Option<u64>,
    reasoning_tokens: Option<u64>,
    total_tokens: Option<u64>,
    done_emitted: bool,
}

impl GeminiSseTranslator {
    pub fn new(fallback_model: impl Into<String>) -> Self {
        Self {
            parser: SseParser::new(),
            id: "chatcmpl-gemini".to_owned(),
            model: fallback_model.into(),
            created: unix_timestamp_secs(),
            started: false,
            saw_tool_call: false,
            next_tool_call_index: 0,
            final_finish_reason: None,
            prompt_tokens: None,
            cached_tokens: None,
            completion_tokens: None,
            reasoning_tokens: None,
            total_tokens: None,
            done_emitted: false,
        }
    }

    pub fn push_chunk(&mut self, chunk: &[u8]) -> Bytes {
        let events = self.parser.push(chunk);
        if events.is_empty() {
            return Bytes::new();
        }
        let mut out = Vec::with_capacity(events.len() * 192);
        for ev in events {
            self.translate_event(&ev, &mut out);
        }
        Bytes::from(out)
    }

    pub fn finish(&mut self) -> Bytes {
        let events = self.parser.finish();
        let mut out = Vec::new();
        for ev in events {
            self.translate_event(&ev, &mut out);
        }

        if self.started && !self.done_emitted {
            let finish_reason = if self.saw_tool_call {
                "tool_calls"
            } else {
                self.final_finish_reason.unwrap_or("stop")
            };
            emit_openai_chunk(
                &mut out,
                &self.id,
                self.created,
                &self.model,
                json!([{
                    "index": 0,
                    "delta": {},
                    "finish_reason": finish_reason,
                }]),
                None,
            );

            if self.prompt_tokens.is_some()
                || self.completion_tokens.is_some()
                || self.reasoning_tokens.is_some()
                || self.total_tokens.is_some()
            {
                let p = self.prompt_tokens.unwrap_or(0);
                let r = self.reasoning_tokens.unwrap_or(0);
                let c = self.completion_tokens.unwrap_or(0).saturating_add(r);
                let t = self.total_tokens.unwrap_or_else(|| p.saturating_add(c));
                let mut usage_obj = Map::new();
                usage_obj.insert("prompt_tokens".to_owned(), Value::Number(p.into()));
                usage_obj.insert("completion_tokens".to_owned(), Value::Number(c.into()));
                usage_obj.insert("total_tokens".to_owned(), Value::Number(t.into()));
                if let Some(cached) = self.cached_tokens
                    && cached > 0
                {
                    usage_obj.insert(
                        "prompt_tokens_details".to_owned(),
                        json!({ "cached_tokens": cached }),
                    );
                }
                if r > 0 {
                    usage_obj.insert(
                        "completion_tokens_details".to_owned(),
                        json!({ "reasoning_tokens": r }),
                    );
                }
                emit_openai_chunk(
                    &mut out,
                    &self.id,
                    self.created,
                    &self.model,
                    json!([]),
                    Some(Value::Object(usage_obj)),
                );
            }

            out.extend_from_slice(b"data: [DONE]\n\n");
            self.done_emitted = true;
        }

        Bytes::from(out)
    }

    fn translate_event(&mut self, ev: &SseEvent, out: &mut Vec<u8>) {
        let trimmed = ev.data.trim();
        if trimmed.is_empty() || trimmed == "[DONE]" {
            return;
        }
        let Ok(payload) = serde_json::from_str::<Value>(trimmed) else {
            return;
        };

        if payload.get("error").is_some() {
            if let Ok(err_bytes) = serialize_gemini_error(&payload)
                && let Ok(err_val) = serde_json::from_slice::<Value>(&err_bytes)
            {
                write_sse_json(out, &err_val);
            }
            return;
        }

        if let Some(raw_id) = payload.get("responseId").and_then(Value::as_str) {
            self.id = format_chatcmpl_id(raw_id);
        }
        if let Some(m) = payload.get("modelVersion").and_then(Value::as_str) {
            self.model = m.to_owned();
        }
        if let Some(u) = payload.get("usageMetadata") {
            if let Some(p) = u.get("promptTokenCount").and_then(Value::as_u64) {
                self.prompt_tokens = Some(p);
            }
            if let Some(cached) = u.get("cachedContentTokenCount").and_then(Value::as_u64) {
                self.cached_tokens = Some(cached);
            }
            if let Some(c) = u.get("candidatesTokenCount").and_then(Value::as_u64) {
                self.completion_tokens = Some(c);
            }
            if let Some(r) = u.get("thoughtsTokenCount").and_then(Value::as_u64) {
                self.reasoning_tokens = Some(r);
            }
            if let Some(t) = u.get("totalTokenCount").and_then(Value::as_u64) {
                self.total_tokens = Some(t);
            }
        }

        if !self.started {
            self.started = true;
            emit_openai_chunk(
                out,
                &self.id,
                self.created,
                &self.model,
                json!([{
                    "index": 0,
                    "delta": { "role": "assistant", "content": "" },
                    "finish_reason": Value::Null,
                }]),
                None,
            );
        }

        let Some(candidate) = payload
            .get("candidates")
            .and_then(Value::as_array)
            .and_then(|c| c.first())
        else {
            return;
        };

        if let Some(parts) = candidate
            .get("content")
            .and_then(|c| c.get("parts"))
            .and_then(Value::as_array)
        {
            for part in parts {
                let is_thought = part
                    .get("thought")
                    .and_then(Value::as_bool)
                    .unwrap_or(false);
                if let Some(text) = part.get("text").and_then(Value::as_str)
                    && !text.is_empty()
                {
                    let delta = if is_thought {
                        json!({ "reasoning_content": text })
                    } else {
                        json!({ "content": text })
                    };
                    emit_openai_chunk(
                        out,
                        &self.id,
                        self.created,
                        &self.model,
                        json!([{
                            "index": 0,
                            "delta": delta,
                            "finish_reason": Value::Null,
                        }]),
                        None,
                    );
                }
                if let Some(fc) = part.get("functionCall").and_then(Value::as_object) {
                    self.saw_tool_call = true;
                    let tool_idx = self.next_tool_call_index;
                    self.next_tool_call_index += 1;
                    let name = fc.get("name").and_then(Value::as_str).unwrap_or("");
                    let call_id = fc
                        .get("id")
                        .and_then(Value::as_str)
                        .map(str::to_owned)
                        .unwrap_or_else(|| format!("call_gemini_{tool_idx}"));
                    let args_str = fc
                        .get("args")
                        .map(|a| serde_json::to_string(a).unwrap_or_else(|_| "{}".to_owned()))
                        .unwrap_or_else(|| "{}".to_owned());

                    emit_openai_chunk(
                        out,
                        &self.id,
                        self.created,
                        &self.model,
                        json!([{
                            "index": 0,
                            "delta": {
                                "tool_calls": [{
                                    "index": tool_idx,
                                    "id": call_id,
                                    "type": "function",
                                    "function": {
                                        "name": name,
                                        "arguments": args_str,
                                    }
                                }]
                            },
                            "finish_reason": Value::Null,
                        }]),
                        None,
                    );
                }
            }
        }

        if let Some(fr) = candidate.get("finishReason").and_then(Value::as_str) {
            self.final_finish_reason = map_gemini_finish_reason(Some(fr), self.saw_tool_call);
        }
    }
}

/// Translates an OpenAI `/v1/embeddings` JSON request into Gemini AI Studio (`embedContent` or
/// `batchEmbedContents`) or Vertex AI (`predict`) JSON.
///
/// Returns `(translated_json_bytes, is_batch)`.
pub fn openai_to_gemini_embeddings_request(
    body: &[u8],
    target_model: &str,
    is_vertex: bool,
) -> Result<(Vec<u8>, bool), String> {
    let val: Value =
        serde_json::from_slice(body).map_err(|e| format!("invalid JSON request body: {e}"))?;
    let obj = val
        .as_object()
        .ok_or_else(|| "request body must be a JSON object".to_owned())?;

    let inputs = extract_embedding_inputs(obj.get("input"))?;
    let output_dim = obj.get("dimensions").and_then(Value::as_u64);

    if is_vertex {
        let instances: Vec<Value> = inputs
            .into_iter()
            .map(|text| json!({ "content": text }))
            .collect();
        let mut out = Map::new();
        out.insert("instances".to_owned(), Value::Array(instances));
        if let Some(dim) = output_dim {
            out.insert(
                "parameters".to_owned(),
                json!({ "outputDimensionality": dim }),
            );
        }
        let encoded = serde_json::to_vec(&Value::Object(out))
            .map_err(|e| format!("failed to serialize Vertex embeddings request: {e}"))?;
        return Ok((encoded, false));
    }

    let clean_model = target_model.strip_prefix("models/").unwrap_or(target_model);
    let model_resource = format!("models/{clean_model}");

    if inputs.len() == 1 {
        let mut out = Map::new();
        out.insert("model".to_owned(), Value::String(model_resource));
        out.insert(
            "content".to_owned(),
            json!({ "parts": [{ "text": inputs[0] }] }),
        );
        if let Some(dim) = output_dim {
            out.insert("outputDimensionality".to_owned(), Value::Number(dim.into()));
        }
        let encoded = serde_json::to_vec(&Value::Object(out))
            .map_err(|e| format!("failed to serialize Gemini embedContent request: {e}"))?;
        Ok((encoded, false))
    } else {
        let requests: Vec<Value> = inputs
            .into_iter()
            .map(|text| {
                let mut item = Map::new();
                item.insert("model".to_owned(), Value::String(model_resource.clone()));
                item.insert("content".to_owned(), json!({ "parts": [{ "text": text }] }));
                if let Some(dim) = output_dim {
                    item.insert("outputDimensionality".to_owned(), Value::Number(dim.into()));
                }
                Value::Object(item)
            })
            .collect();
        let encoded = serde_json::to_vec(&json!({ "requests": requests }))
            .map_err(|e| format!("failed to serialize Gemini batchEmbedContents request: {e}"))?;
        Ok((encoded, true))
    }
}

fn extract_embedding_inputs(input: Option<&Value>) -> Result<Vec<String>, String> {
    match input {
        Some(Value::String(s)) => Ok(vec![s.clone()]),
        Some(Value::Array(arr)) if !arr.is_empty() => {
            let mut out = Vec::with_capacity(arr.len());
            for item in arr {
                match item {
                    Value::String(s) => out.push(s.clone()),
                    other => out.push(other.to_string()),
                }
            }
            Ok(out)
        }
        _ => Err("embeddings request must include a non-empty `input` string or array".to_owned()),
    }
}

/// Translates a Gemini AI Studio (`embedContent` / `batchEmbedContents`) or Vertex AI (`predict`)
/// embeddings response into OpenAI `/v1/embeddings` JSON format.
pub fn gemini_to_openai_embeddings_response(
    gemini_body: &[u8],
    status: StatusCode,
    model: &str,
) -> Result<Vec<u8>, String> {
    let val: Value = serde_json::from_slice(gemini_body)
        .map_err(|e| format!("invalid Gemini embeddings JSON response: {e}"))?;

    if !status.is_success() || val.get("error").is_some() {
        return serialize_gemini_error(&val);
    }

    let mut data = Vec::new();
    let mut prompt_tokens = 0u64;

    if let Some(values) = val
        .get("embedding")
        .and_then(|e| e.get("values"))
        .and_then(Value::as_array)
    {
        data.push(json!({
            "object": "embedding",
            "index": 0,
            "embedding": values,
        }));
    } else if let Some(embeddings) = val.get("embeddings").and_then(Value::as_array) {
        for (idx, emb) in embeddings.iter().enumerate() {
            if let Some(values) = emb.get("values").and_then(Value::as_array) {
                data.push(json!({
                    "object": "embedding",
                    "index": idx,
                    "embedding": values,
                }));
            }
        }
    } else if let Some(predictions) = val.get("predictions").and_then(Value::as_array) {
        for (idx, pred) in predictions.iter().enumerate() {
            if let Some(emb) = pred.get("embeddings") {
                if let Some(values) = emb.get("values").and_then(Value::as_array) {
                    data.push(json!({
                        "object": "embedding",
                        "index": idx,
                        "embedding": values,
                    }));
                }
                if let Some(tc) = emb
                    .get("statistics")
                    .and_then(|s| s.get("token_count"))
                    .and_then(Value::as_u64)
                {
                    prompt_tokens = prompt_tokens.saturating_add(tc);
                }
            }
        }
    }

    if let Some(u) = val
        .get("usageMetadata")
        .and_then(|u| u.get("promptTokenCount"))
        .and_then(Value::as_u64)
    {
        prompt_tokens = u;
    }

    let resp = json!({
        "object": "list",
        "data": data,
        "model": model,
        "usage": {
            "prompt_tokens": prompt_tokens,
            "total_tokens": prompt_tokens,
        }
    });

    serde_json::to_vec(&resp)
        .map_err(|e| format!("failed to serialize OpenAI embeddings response: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn translates_openai_chat_with_tools_and_system_to_gemini() {
        let req = json!({
            "model": "gemini-2.5-flash",
            "temperature": 0.2,
            "max_completion_tokens": 512,
            "response_format": { "type": "json_object" },
            "messages": [
                { "role": "system", "content": "You are helpful." },
                { "role": "user", "content": "Weather in NYC?" },
                {
                    "role": "assistant",
                    "content": "",
                    "tool_calls": [{
                        "id": "call_1",
                        "type": "function",
                        "function": { "name": "get_weather", "arguments": "{\"city\":\"NYC\"}" }
                    }]
                },
                { "role": "tool", "tool_call_id": "call_1", "content": "{\"temp\":72}" }
            ],
            "tools": [{
                "type": "function",
                "function": {
                    "name": "get_weather",
                    "description": "Get weather",
                    "parameters": {
                        "$schema": "http://json-schema.org/draft-07/schema#",
                        "type": "object",
                        "additionalProperties": false,
                        "properties": { "city": { "type": "string" } }
                    }
                }
            }]
        });

        let out_bytes = openai_to_gemini_request(&serde_json::to_vec(&req).unwrap()).unwrap();
        let out: Value = serde_json::from_slice(&out_bytes).unwrap();

        assert_eq!(
            out["systemInstruction"]["parts"][0]["text"],
            "You are helpful."
        );
        assert_eq!(out["contents"][0]["role"], "user");
        assert_eq!(out["contents"][1]["role"], "model");
        assert_eq!(
            out["contents"][1]["parts"][0]["functionCall"]["name"],
            "get_weather"
        );
        assert_eq!(out["contents"][2]["role"], "user");
        assert_eq!(
            out["contents"][2]["parts"][0]["functionResponse"]["name"],
            "get_weather"
        );
        assert_eq!(
            out["contents"][2]["parts"][0]["functionResponse"]["response"]["temp"],
            72
        );
        assert_eq!(out["generationConfig"]["maxOutputTokens"], 512);
        assert_eq!(
            out["generationConfig"]["responseMimeType"],
            "application/json"
        );
        let params = &out["tools"][0]["functionDeclarations"][0]["parameters"];
        assert!(params.get("$schema").is_none());
        assert!(params.get("additionalProperties").is_none());
    }

    #[test]
    fn translates_gemini_sse_stream_incrementally() {
        let raw = concat!(
            "data: {\"responseId\":\"resp_1\",\"modelVersion\":\"gemini-2.5-flash\",\"candidates\":[{\"content\":{\"role\":\"model\",\"parts\":[{\"text\":\"Hello \"}]}}]}\n\n",
            "data: {\"responseId\":\"resp_1\",\"modelVersion\":\"gemini-2.5-flash\",\"candidates\":[{\"content\":{\"role\":\"model\",\"parts\":[{\"text\":\"Gemini!\"}]},\"finishReason\":\"STOP\"}],\"usageMetadata\":{\"promptTokenCount\":9,\"candidatesTokenCount\":4,\"totalTokenCount\":13}}\n\n"
        );

        let mut tr = GeminiSseTranslator::new("gemini-2.5-flash");
        let mut out = Vec::new();
        for chunk in raw.as_bytes().chunks(13) {
            out.extend_from_slice(&tr.push_chunk(chunk));
        }
        out.extend_from_slice(&tr.finish());

        let text = String::from_utf8(out).unwrap();
        assert!(text.contains("Hello "));
        assert!(text.contains("Gemini!"));
        assert!(text.contains("\"finish_reason\":\"stop\""));
        assert!(text.contains("\"prompt_tokens\":9"));
        assert!(text.ends_with("data: [DONE]\n\n"));
    }

    #[test]
    fn translates_gemini_single_and_batch_embeddings() {
        let single_req = json!({ "model": "text-embedding-004", "input": "hello world" });
        let (bytes, is_batch) = openai_to_gemini_embeddings_request(
            &serde_json::to_vec(&single_req).unwrap(),
            "text-embedding-004",
            false,
        )
        .unwrap();
        assert!(!is_batch);
        let v: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(v["content"]["parts"][0]["text"], "hello world");

        let batch_req = json!({ "model": "text-embedding-004", "input": ["a", "b"] });
        let (b_bytes, is_batch2) = openai_to_gemini_embeddings_request(
            &serde_json::to_vec(&batch_req).unwrap(),
            "text-embedding-004",
            false,
        )
        .unwrap();
        assert!(is_batch2);
        let bv: Value = serde_json::from_slice(&b_bytes).unwrap();
        assert_eq!(bv["requests"].as_array().unwrap().len(), 2);

        let resp_bytes = gemini_to_openai_embeddings_response(
            br#"{"embeddings":[{"values":[0.1,0.2]},{"values":[0.3,0.4]}]}"#,
            StatusCode::OK,
            "text-embedding-004",
        )
        .unwrap();
        let resp: Value = serde_json::from_slice(&resp_bytes).unwrap();
        assert_eq!(resp["object"], "list");
        assert_eq!(resp["data"][0]["index"], 0);
        assert_eq!(resp["data"][1]["embedding"][1], 0.4);
    }

    #[test]
    fn translates_gemini_reasoning_request_and_thought_parts() {
        let req = json!({
            "model": "gemini-2.5-pro",
            "reasoning_effort": "medium",
            "messages": [{ "role": "user", "content": "Prove it." }]
        });
        let out_bytes = openai_to_gemini_request(&serde_json::to_vec(&req).unwrap()).unwrap();
        let out: Value = serde_json::from_slice(&out_bytes).unwrap();
        assert_eq!(
            out["generationConfig"]["thinkingConfig"]["thinkingBudget"],
            4096
        );
        assert_eq!(
            out["generationConfig"]["thinkingConfig"]["includeThoughts"],
            true
        );

        let gem_resp = json!({
            "responseId": "gem_t1",
            "modelVersion": "gemini-2.5-pro",
            "candidates": [{
                "content": {
                    "role": "model",
                    "parts": [
                        { "text": "Let me think...", "thought": true },
                        { "text": "QED." }
                    ]
                },
                "finishReason": "STOP"
            }],
            "usageMetadata": {
                "promptTokenCount": 50,
                "cachedContentTokenCount": 20,
                "candidatesTokenCount": 10,
                "thoughtsTokenCount": 30,
                "totalTokenCount": 90
            }
        });
        let oa_bytes = gemini_to_openai_response(
            &serde_json::to_vec(&gem_resp).unwrap(),
            StatusCode::OK,
            "gemini-2.5-pro",
        )
        .unwrap();
        let oa: Value = serde_json::from_slice(&oa_bytes).unwrap();
        assert_eq!(
            oa["choices"][0]["message"]["reasoning_content"],
            "Let me think..."
        );
        assert_eq!(oa["choices"][0]["message"]["content"], "QED.");
        assert_eq!(oa["usage"]["completion_tokens"], 40);
        assert_eq!(
            oa["usage"]["completion_tokens_details"]["reasoning_tokens"],
            30
        );
        assert_eq!(oa["usage"]["prompt_tokens_details"]["cached_tokens"], 20);
    }
}
