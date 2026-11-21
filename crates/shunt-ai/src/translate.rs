use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::{Map, Value, json};
use shunt_plugin_sdk::{Bytes, StatusCode};

use crate::sse::{SseEvent, SseParser};

fn unix_timestamp_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Rewrites an OpenAI `/v1/chat/completions` JSON request body for an OpenAI upstream:
/// - Updates `"model"` if it differs from `target_model`
/// - Optionally injects `"stream_options": {"include_usage": true}` when `stream == true`
///
/// Returns `Ok(None)` when no mutation is needed (allowing zero-copy reuse of the input `Bytes`).
pub fn rewrite_openai_request(
    body: &[u8],
    target_model: &str,
    inject_stream_usage: bool,
) -> Result<Option<Vec<u8>>, String> {
    let mut val: Value =
        serde_json::from_slice(body).map_err(|e| format!("invalid JSON request body: {e}"))?;
    let obj = val
        .as_object_mut()
        .ok_or_else(|| "request body must be a JSON object".to_owned())?;

    let mut changed = false;

    let current_model = obj.get("model").and_then(Value::as_str);
    if current_model != Some(target_model) {
        obj.insert("model".to_owned(), Value::String(target_model.to_owned()));
        changed = true;
    }

    let is_stream = obj.get("stream").and_then(Value::as_bool).unwrap_or(false);
    if is_stream && inject_stream_usage {
        match obj.get_mut("stream_options") {
            Some(Value::Object(so)) if !so.contains_key("include_usage") => {
                so.insert("include_usage".to_owned(), Value::Bool(true));
                changed = true;
            }
            None => {
                obj.insert(
                    "stream_options".to_owned(),
                    json!({ "include_usage": true }),
                );
                changed = true;
            }
            _ => {}
        }
    }

    if !changed {
        return Ok(None);
    }

    serde_json::to_vec(&val)
        .map(Some)
        .map_err(|e| format!("failed to serialize OpenAI request: {e}"))
}

/// Rewrites an OpenAI `/v1/embeddings` JSON request body by updating `"model"` when it differs
/// from `target_model`. Returns `Ok(None)` when no mutation is needed (zero-copy passthrough).
pub fn rewrite_openai_embeddings_request(
    body: &[u8],
    target_model: &str,
) -> Result<Option<Vec<u8>>, String> {
    let mut val: Value =
        serde_json::from_slice(body).map_err(|e| format!("invalid JSON request body: {e}"))?;
    let obj = val
        .as_object_mut()
        .ok_or_else(|| "request body must be a JSON object".to_owned())?;

    let current_model = obj.get("model").and_then(Value::as_str);
    if current_model == Some(target_model) {
        return Ok(None);
    }

    obj.insert("model".to_owned(), Value::String(target_model.to_owned()));
    serde_json::to_vec(&val)
        .map(Some)
        .map_err(|e| format!("failed to serialize OpenAI embeddings request: {e}"))
}

/// Translates an OpenAI `/v1/chat/completions` JSON request into an Anthropic `/v1/messages` JSON request.
pub fn openai_to_anthropic_request(
    body: &[u8],
    target_model: &str,
    default_max_tokens: u64,
) -> Result<Vec<u8>, String> {
    let val: Value =
        serde_json::from_slice(body).map_err(|e| format!("invalid JSON request body: {e}"))?;
    let obj = val
        .as_object()
        .ok_or_else(|| "request body must be a JSON object".to_owned())?;

    let messages_val = obj
        .get("messages")
        .and_then(Value::as_array)
        .ok_or_else(|| "missing or invalid `messages` array".to_owned())?;

    let mut system_parts: Vec<String> = Vec::new();
    let mut anthropic_messages: Vec<(String, Vec<Value>)> = Vec::new();

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
                    system_parts.push(text);
                }
            }
            "tool" => {
                let tool_use_id = msg_obj
                    .get("tool_call_id")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_owned();
                let content_str = extract_text_content(msg_obj.get("content"));
                let block = json!({
                    "type": "tool_result",
                    "tool_use_id": tool_use_id,
                    "content": content_str,
                });
                push_anthropic_message(&mut anthropic_messages, "user", vec![block]);
            }
            "assistant" => {
                let mut blocks = convert_content_to_blocks(msg_obj.get("content"));
                if let Some(tool_calls) = msg_obj.get("tool_calls").and_then(Value::as_array) {
                    for tc in tool_calls {
                        let id = tc.get("id").and_then(Value::as_str).unwrap_or("");
                        let func = tc.get("function");
                        let name = func
                            .and_then(|f| f.get("name"))
                            .and_then(Value::as_str)
                            .unwrap_or("");
                        let raw_args = func
                            .and_then(|f| f.get("arguments"))
                            .and_then(Value::as_str)
                            .unwrap_or("{}");
                        let input: Value = serde_json::from_str(raw_args)
                            .unwrap_or_else(|_| Value::Object(Map::new()));
                        blocks.push(json!({
                            "type": "tool_use",
                            "id": id,
                            "name": name,
                            "input": input,
                        }));
                    }
                }
                if !blocks.is_empty() {
                    push_anthropic_message(&mut anthropic_messages, "assistant", blocks);
                }
            }
            _ => {
                // Default to "user"
                let blocks = convert_content_to_blocks(msg_obj.get("content"));
                if !blocks.is_empty() {
                    push_anthropic_message(&mut anthropic_messages, "user", blocks);
                }
            }
        }
    }

    let formatted_messages: Vec<Value> = anthropic_messages
        .into_iter()
        .map(|(role, blocks)| {
            // Keep simple single-text messages compact when there's just one text block.
            if blocks.len() == 1
                && blocks[0].get("type").and_then(Value::as_str) == Some("text")
                && let Some(text) = blocks[0].get("text").and_then(Value::as_str)
            {
                json!({ "role": role, "content": text })
            } else {
                json!({ "role": role, "content": blocks })
            }
        })
        .collect();

    let max_tokens = obj
        .get("max_tokens")
        .and_then(Value::as_u64)
        .filter(|&n| n > 0)
        .or_else(|| {
            obj.get("max_completion_tokens")
                .and_then(Value::as_u64)
                .filter(|&n| n > 0)
        })
        .unwrap_or_else(|| default_max_tokens.max(1));

    let mut out = Map::new();
    out.insert("model".to_owned(), Value::String(target_model.to_owned()));
    out.insert("max_tokens".to_owned(), Value::Number(max_tokens.into()));
    out.insert("messages".to_owned(), Value::Array(formatted_messages));

    if !system_parts.is_empty() {
        out.insert(
            "system".to_owned(),
            Value::String(system_parts.join("\n\n")),
        );
    }

    if let Some(stream) = obj.get("stream").and_then(Value::as_bool)
        && stream
    {
        out.insert("stream".to_owned(), Value::Bool(true));
    }

    if let Some(temp) = obj.get("temperature").filter(|v| !v.is_null()) {
        out.insert("temperature".to_owned(), temp.clone());
    }
    if let Some(top_p) = obj.get("top_p").filter(|v| !v.is_null()) {
        out.insert("top_p".to_owned(), top_p.clone());
    }

    if let Some(stop) = obj.get("stop") {
        match stop {
            Value::String(s) => {
                out.insert(
                    "stop_sequences".to_owned(),
                    Value::Array(vec![Value::String(s.clone())]),
                );
            }
            Value::Array(arr) => {
                let seqs: Vec<Value> = arr
                    .iter()
                    .filter_map(|v| v.as_str().map(|s| Value::String(s.to_owned())))
                    .collect();
                if !seqs.is_empty() {
                    out.insert("stop_sequences".to_owned(), Value::Array(seqs));
                }
            }
            _ => {}
        }
    }

    if let Some(tools) = obj.get("tools").and_then(Value::as_array) {
        let converted_tools: Vec<Value> = tools
            .iter()
            .filter_map(|t| {
                let func = t.get("function")?;
                let name = func.get("name")?.as_str()?;
                let mut tool = Map::new();
                tool.insert("name".to_owned(), Value::String(name.to_owned()));
                if let Some(desc) = func.get("description").and_then(Value::as_str) {
                    tool.insert("description".to_owned(), Value::String(desc.to_owned()));
                }
                let schema = func
                    .get("parameters")
                    .cloned()
                    .unwrap_or_else(|| json!({ "type": "object", "properties": {} }));
                tool.insert("input_schema".to_owned(), schema);
                Some(Value::Object(tool))
            })
            .collect();
        if !converted_tools.is_empty() {
            out.insert("tools".to_owned(), Value::Array(converted_tools));
        }
    }

    if let Some(tc) = obj.get("tool_choice") {
        match tc {
            Value::String(s) if s == "auto" => {
                out.insert("tool_choice".to_owned(), json!({ "type": "auto" }));
            }
            Value::String(s) if s == "required" => {
                out.insert("tool_choice".to_owned(), json!({ "type": "any" }));
            }
            Value::Object(tc_obj) => {
                if let Some(name) = tc_obj
                    .get("function")
                    .and_then(|f| f.get("name"))
                    .and_then(Value::as_str)
                {
                    out.insert(
                        "tool_choice".to_owned(),
                        json!({ "type": "tool", "name": name }),
                    );
                }
            }
            _ => {}
        }
    }

    if let Some(user) = obj.get("user").and_then(Value::as_str) {
        out.insert("metadata".to_owned(), json!({ "user_id": user }));
    }

    serde_json::to_vec(&Value::Object(out))
        .map_err(|e| format!("failed to serialize Anthropic request: {e}"))
}

fn push_anthropic_message(
    messages: &mut Vec<(String, Vec<Value>)>,
    role: &str,
    mut blocks: Vec<Value>,
) {
    if let Some((last_role, last_blocks)) = messages.last_mut()
        && last_role == role
    {
        last_blocks.append(&mut blocks);
        return;
    }
    messages.push((role.to_owned(), blocks));
}

fn extract_text_content(content: Option<&Value>) -> String {
    match content {
        Some(Value::String(s)) => s.clone(),
        Some(Value::Array(parts)) => parts
            .iter()
            .filter_map(|p| {
                if p.get("type").and_then(Value::as_str) == Some("text") {
                    p.get("text").and_then(Value::as_str)
                } else {
                    None
                }
            })
            .collect::<Vec<_>>()
            .join("\n"),
        _ => String::new(),
    }
}

fn convert_content_to_blocks(content: Option<&Value>) -> Vec<Value> {
    match content {
        Some(Value::String(s)) => {
            if s.is_empty() {
                Vec::new()
            } else {
                vec![json!({ "type": "text", "text": s })]
            }
        }
        Some(Value::Array(parts)) => {
            let mut out = Vec::new();
            for part in parts {
                match part.get("type").and_then(Value::as_str) {
                    Some("text") => {
                        if let Some(t) = part.get("text").and_then(Value::as_str) {
                            out.push(json!({ "type": "text", "text": t }));
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
                                && let Some(media_type) = meta.strip_suffix(";base64")
                            {
                                out.push(json!({
                                    "type": "image",
                                    "source": {
                                        "type": "base64",
                                        "media_type": media_type,
                                        "data": data,
                                    }
                                }));
                            } else {
                                out.push(json!({
                                    "type": "image",
                                    "source": {
                                        "type": "url",
                                        "url": url,
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

/// Maps Anthropic `stop_reason` to OpenAI `finish_reason`.
pub fn map_anthropic_stop_reason(stop_reason: Option<&str>) -> Option<&'static str> {
    match stop_reason {
        Some("end_turn") | Some("stop_sequence") => Some("stop"),
        Some("max_tokens") => Some("length"),
        Some("tool_use") => Some("tool_calls"),
        Some(_) => Some("stop"),
        None => None,
    }
}

/// Translates a non-streaming Anthropic Messages JSON response (or Anthropic error JSON)
/// into an OpenAI-compatible `/v1/chat/completions` JSON response.
pub fn anthropic_to_openai_response(
    anthropic_body: &[u8],
    status: StatusCode,
    fallback_model: &str,
) -> Result<Vec<u8>, String> {
    let val: Value = serde_json::from_slice(anthropic_body)
        .map_err(|e| format!("invalid Anthropic JSON response: {e}"))?;

    if !status.is_success() || val.get("type").and_then(Value::as_str) == Some("error") {
        let err_obj = val.get("error");
        let err_type = err_obj
            .and_then(|e| e.get("type"))
            .and_then(Value::as_str)
            .unwrap_or("api_error");
        let err_msg = err_obj
            .and_then(|e| e.get("message"))
            .and_then(Value::as_str)
            .unwrap_or("upstream provider error");
        let openai_err = json!({
            "error": {
                "message": err_msg,
                "type": err_type,
                "param": Value::Null,
                "code": err_type,
            }
        });
        return serde_json::to_vec(&openai_err)
            .map_err(|e| format!("failed to serialize OpenAI error: {e}"));
    }

    let raw_id = val.get("id").and_then(Value::as_str).unwrap_or("anthropic");
    let id = format_chatcmpl_id(raw_id);
    let model = val
        .get("model")
        .and_then(Value::as_str)
        .unwrap_or(fallback_model);

    let mut text_parts: Vec<&str> = Vec::new();
    let mut tool_calls: Vec<Value> = Vec::new();

    if let Some(content) = val.get("content").and_then(Value::as_array) {
        for block in content {
            match block.get("type").and_then(Value::as_str) {
                Some("text") => {
                    if let Some(t) = block.get("text").and_then(Value::as_str) {
                        text_parts.push(t);
                    }
                }
                Some("tool_use") => {
                    let call_id = block.get("id").and_then(Value::as_str).unwrap_or("");
                    let name = block.get("name").and_then(Value::as_str).unwrap_or("");
                    let args_str = block
                        .get("input")
                        .map(|v| serde_json::to_string(v).unwrap_or_else(|_| "{}".to_owned()))
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
                _ => {}
            }
        }
    }

    let finish_reason =
        map_anthropic_stop_reason(val.get("stop_reason").and_then(Value::as_str)).unwrap_or("stop");

    let mut message = Map::new();
    message.insert("role".to_owned(), Value::String("assistant".to_owned()));
    if text_parts.is_empty() && !tool_calls.is_empty() {
        message.insert("content".to_owned(), Value::Null);
    } else {
        message.insert("content".to_owned(), Value::String(text_parts.join("")));
    }
    if !tool_calls.is_empty() {
        message.insert("tool_calls".to_owned(), Value::Array(tool_calls));
    }

    let input_tokens = val
        .get("usage")
        .and_then(|u| u.get("input_tokens"))
        .and_then(Value::as_u64)
        .unwrap_or(0);
    let output_tokens = val
        .get("usage")
        .and_then(|u| u.get("output_tokens"))
        .and_then(Value::as_u64)
        .unwrap_or(0);

    let openai_resp = json!({
        "id": id,
        "object": "chat.completion",
        "created": unix_timestamp_secs(),
        "model": model,
        "choices": [
            {
                "index": 0,
                "message": Value::Object(message),
                "finish_reason": finish_reason,
            }
        ],
        "usage": {
            "prompt_tokens": input_tokens,
            "completion_tokens": output_tokens,
            "total_tokens": input_tokens.saturating_add(output_tokens),
        }
    });

    serde_json::to_vec(&openai_resp)
        .map_err(|e| format!("failed to serialize OpenAI response: {e}"))
}

fn format_chatcmpl_id(raw_id: &str) -> String {
    if raw_id.starts_with("chatcmpl-") {
        raw_id.to_owned()
    } else {
        format!("chatcmpl-{raw_id}")
    }
}

/// Stateful per-request streaming translator that converts Anthropic Messages SSE frames
/// into OpenAI `chat.completion.chunk` SSE frames live in `on_response_body_chunk`.
#[derive(Debug, Clone)]
pub struct AnthropicSseTranslator {
    parser: SseParser,
    id: String,
    model: String,
    created: u64,
    input_tokens: u64,
    output_tokens: u64,
    next_tool_call_index: usize,
    /// Maps Anthropic `content_block` index -> OpenAI `tool_calls` array index.
    block_to_tool_index: HashMap<usize, usize>,
    started: bool,
    done_emitted: bool,
}

impl AnthropicSseTranslator {
    pub fn new(fallback_model: impl Into<String>) -> Self {
        Self {
            parser: SseParser::new(),
            id: "chatcmpl-anthropic".to_owned(),
            model: fallback_model.into(),
            created: unix_timestamp_secs(),
            input_tokens: 0,
            output_tokens: 0,
            next_tool_call_index: 0,
            block_to_tool_index: HashMap::new(),
            started: false,
            done_emitted: false,
        }
    }

    /// Consumes a raw chunk of Anthropic SSE bytes and emits translated OpenAI SSE bytes.
    pub fn push_chunk(&mut self, chunk: &[u8]) -> Bytes {
        let events = self.parser.push(chunk);
        self.translate_events(events)
    }

    /// Flushes any trailing buffered SSE frame and ensures `data: [DONE]\n\n` is emitted.
    pub fn finish(&mut self) -> Bytes {
        let events = self.parser.finish();
        let mut out = Vec::new();
        for ev in events {
            self.translate_event(&ev, &mut out);
        }
        if self.started && !self.done_emitted {
            out.extend_from_slice(b"data: [DONE]\n\n");
            self.done_emitted = true;
        }
        Bytes::from(out)
    }

    fn translate_events(&mut self, events: Vec<SseEvent>) -> Bytes {
        if events.is_empty() {
            return Bytes::new();
        }
        let mut out = Vec::with_capacity(events.len() * 192);
        for ev in events {
            self.translate_event(&ev, &mut out);
        }
        Bytes::from(out)
    }

    fn translate_event(&mut self, ev: &SseEvent, out: &mut Vec<u8>) {
        if ev.data.is_empty() {
            return;
        }
        let Ok(payload) = serde_json::from_str::<Value>(&ev.data) else {
            return;
        };

        let event_type = ev
            .event
            .as_deref()
            .or_else(|| payload.get("type").and_then(Value::as_str))
            .unwrap_or("");

        match event_type {
            "message_start" => {
                if let Some(msg) = payload.get("message") {
                    if let Some(raw_id) = msg.get("id").and_then(Value::as_str) {
                        self.id = format_chatcmpl_id(raw_id);
                    }
                    if let Some(m) = msg.get("model").and_then(Value::as_str) {
                        self.model = m.to_owned();
                    }
                    if let Some(u) = msg.get("usage") {
                        if let Some(inp) = u.get("input_tokens").and_then(Value::as_u64) {
                            self.input_tokens = inp;
                        }
                        if let Some(out_tok) = u.get("output_tokens").and_then(Value::as_u64) {
                            self.output_tokens = out_tok;
                        }
                    }
                }
                self.started = true;
                self.emit_chunk(
                    out,
                    json!([{
                        "index": 0,
                        "delta": { "role": "assistant", "content": "" },
                        "finish_reason": Value::Null,
                    }]),
                    None,
                );
            }
            "content_block_start" => {
                let block_idx = payload.get("index").and_then(Value::as_u64).unwrap_or(0) as usize;
                let Some(cb) = payload.get("content_block") else {
                    return;
                };
                match cb.get("type").and_then(Value::as_str) {
                    Some("text") => {
                        if let Some(text) = cb.get("text").and_then(Value::as_str)
                            && !text.is_empty()
                        {
                            self.emit_chunk(
                                out,
                                json!([{
                                    "index": 0,
                                    "delta": { "content": text },
                                    "finish_reason": Value::Null,
                                }]),
                                None,
                            );
                        }
                    }
                    Some("tool_use") => {
                        let tool_idx = self.next_tool_call_index;
                        self.next_tool_call_index += 1;
                        self.block_to_tool_index.insert(block_idx, tool_idx);

                        let call_id = cb.get("id").and_then(Value::as_str).unwrap_or("");
                        let name = cb.get("name").and_then(Value::as_str).unwrap_or("");
                        self.emit_chunk(
                            out,
                            json!([{
                                "index": 0,
                                "delta": {
                                    "tool_calls": [{
                                        "index": tool_idx,
                                        "id": call_id,
                                        "type": "function",
                                        "function": {
                                            "name": name,
                                            "arguments": "",
                                        }
                                    }]
                                },
                                "finish_reason": Value::Null,
                            }]),
                            None,
                        );
                    }
                    _ => {}
                }
            }
            "content_block_delta" => {
                let block_idx = payload.get("index").and_then(Value::as_u64).unwrap_or(0) as usize;
                let Some(delta) = payload.get("delta") else {
                    return;
                };
                match delta.get("type").and_then(Value::as_str) {
                    Some("text_delta") => {
                        if let Some(text) = delta.get("text").and_then(Value::as_str) {
                            self.emit_chunk(
                                out,
                                json!([{
                                    "index": 0,
                                    "delta": { "content": text },
                                    "finish_reason": Value::Null,
                                }]),
                                None,
                            );
                        }
                    }
                    Some("input_json_delta") => {
                        if let Some(partial) = delta.get("partial_json").and_then(Value::as_str) {
                            let tool_idx = *self.block_to_tool_index.get(&block_idx).unwrap_or(&0);
                            self.emit_chunk(
                                out,
                                json!([{
                                    "index": 0,
                                    "delta": {
                                        "tool_calls": [{
                                            "index": tool_idx,
                                            "function": {
                                                "arguments": partial,
                                            }
                                        }]
                                    },
                                    "finish_reason": Value::Null,
                                }]),
                                None,
                            );
                        }
                    }
                    _ => {}
                }
            }
            "message_delta" => {
                if let Some(u) = payload.get("usage")
                    && let Some(out_tok) = u.get("output_tokens").and_then(Value::as_u64)
                {
                    self.output_tokens = out_tok;
                }
                let stop_reason = payload
                    .get("delta")
                    .and_then(|d| d.get("stop_reason"))
                    .and_then(Value::as_str);
                let finish_reason = map_anthropic_stop_reason(stop_reason).unwrap_or("stop");

                self.emit_chunk(
                    out,
                    json!([{
                        "index": 0,
                        "delta": {},
                        "finish_reason": finish_reason,
                    }]),
                    None,
                );

                // Emit standard OpenAI final usage chunk (matching stream_options.include_usage).
                let usage = json!({
                    "prompt_tokens": self.input_tokens,
                    "completion_tokens": self.output_tokens,
                    "total_tokens": self.input_tokens.saturating_add(self.output_tokens),
                });
                self.emit_chunk(out, json!([]), Some(usage));
            }
            "message_stop" => {
                if !self.done_emitted {
                    out.extend_from_slice(b"data: [DONE]\n\n");
                    self.done_emitted = true;
                }
            }
            "error" => {
                let err_obj = payload.get("error");
                let err_type = err_obj
                    .and_then(|e| e.get("type"))
                    .and_then(Value::as_str)
                    .unwrap_or("api_error");
                let err_msg = err_obj
                    .and_then(|e| e.get("message"))
                    .and_then(Value::as_str)
                    .unwrap_or("upstream stream error");
                let err_frame = json!({
                    "error": {
                        "message": err_msg,
                        "type": err_type,
                        "param": Value::Null,
                        "code": err_type,
                    }
                });
                write_sse_json(out, &err_frame);
            }
            // Heartbeats and block-stop markers carry no OpenAI equivalent.
            "ping" | "content_block_stop" => {}
            _ => {}
        }
    }

    fn emit_chunk(&self, out: &mut Vec<u8>, choices: Value, usage: Option<Value>) {
        let mut obj = Map::new();
        obj.insert("id".to_owned(), Value::String(self.id.clone()));
        obj.insert(
            "object".to_owned(),
            Value::String("chat.completion.chunk".to_owned()),
        );
        obj.insert("created".to_owned(), Value::Number(self.created.into()));
        obj.insert("model".to_owned(), Value::String(self.model.clone()));
        obj.insert("choices".to_owned(), choices);
        if let Some(u) = usage {
            obj.insert("usage".to_owned(), u);
        }
        write_sse_json(out, &Value::Object(obj));
    }
}

fn write_sse_json(out: &mut Vec<u8>, val: &Value) {
    out.extend_from_slice(b"data: ");
    if let Ok(encoded) = serde_json::to_vec(val) {
        out.extend_from_slice(&encoded);
    }
    out.extend_from_slice(b"\n\n");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn translates_openai_request_to_anthropic_with_system_and_tools() {
        let req = json!({
            "model": "gpt-4o",
            "messages": [
                {"role": "system", "content": "Be concise."},
                {"role": "user", "content": "What's the weather in NYC?"},
                {
                    "role": "assistant",
                    "content": null,
                    "tool_calls": [{
                        "id": "call_1",
                        "type": "function",
                        "function": {"name": "get_weather", "arguments": "{\"city\":\"NYC\"}"}
                    }]
                },
                {"role": "tool", "tool_call_id": "call_1", "content": "72F sunny"}
            ],
            "stream": true,
            "temperature": 0.2,
            "stop": "END",
            "tools": [{
                "type": "function",
                "function": {
                    "name": "get_weather",
                    "description": "Fetch weather",
                    "parameters": {"type": "object", "properties": {"city": {"type": "string"}}}
                }
            }],
            "tool_choice": "auto"
        });

        let out_bytes = openai_to_anthropic_request(
            &serde_json::to_vec(&req).unwrap(),
            "claude-3-5-sonnet-20241022",
            4096,
        )
        .unwrap();
        let out: Value = serde_json::from_slice(&out_bytes).unwrap();

        assert_eq!(out["model"], "claude-3-5-sonnet-20241022");
        assert_eq!(out["max_tokens"], 4096);
        assert_eq!(out["system"], "Be concise.");
        assert_eq!(out["stream"], true);
        assert_eq!(out["stop_sequences"], json!(["END"]));
        assert_eq!(out["tools"][0]["name"], "get_weather");
        assert_eq!(out["tool_choice"]["type"], "auto");

        let msgs = out["messages"].as_array().unwrap();
        assert_eq!(msgs.len(), 3);
        assert_eq!(msgs[0]["role"], "user");
        assert_eq!(msgs[1]["role"], "assistant");
        assert_eq!(msgs[1]["content"][0]["type"], "tool_use");
        assert_eq!(msgs[1]["content"][0]["input"]["city"], "NYC");
        assert_eq!(msgs[2]["role"], "user");
        assert_eq!(msgs[2]["content"][0]["type"], "tool_result");
        assert_eq!(msgs[2]["content"][0]["tool_use_id"], "call_1");
    }

    #[test]
    fn translates_anthropic_non_stream_response_to_openai() {
        let anthropic = json!({
            "id": "msg_123",
            "type": "message",
            "role": "assistant",
            "model": "claude-3-5-sonnet-20241022",
            "content": [{"type": "text", "text": "Hello from Claude!"}],
            "stop_reason": "end_turn",
            "usage": {"input_tokens": 12, "output_tokens": 6}
        });

        let out_bytes = anthropic_to_openai_response(
            &serde_json::to_vec(&anthropic).unwrap(),
            StatusCode::OK,
            "fallback",
        )
        .unwrap();
        let out: Value = serde_json::from_slice(&out_bytes).unwrap();

        assert_eq!(out["id"], "chatcmpl-msg_123");
        assert_eq!(out["object"], "chat.completion");
        assert_eq!(out["model"], "claude-3-5-sonnet-20241022");
        assert_eq!(out["choices"][0]["message"]["role"], "assistant");
        assert_eq!(
            out["choices"][0]["message"]["content"],
            "Hello from Claude!"
        );
        assert_eq!(out["choices"][0]["finish_reason"], "stop");
        assert_eq!(out["usage"]["prompt_tokens"], 12);
        assert_eq!(out["usage"]["completion_tokens"], 6);
        assert_eq!(out["usage"]["total_tokens"], 18);
    }

    #[test]
    fn translates_anthropic_sse_stream_to_openai_sse() {
        let raw_sse = concat!(
            "event: message_start\n",
            "data: {\"type\":\"message_start\",\"message\":{\"id\":\"msg_abc\",\"model\":\"claude-3-5-sonnet\",\"usage\":{\"input_tokens\":20,\"output_tokens\":1}}}\n\n",
            "event: content_block_start\n",
            "data: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"text\",\"text\":\"\"}}\n\n",
            "event: ping\n",
            "data: {\"type\":\"ping\"}\n\n",
            "event: content_block_delta\n",
            "data: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"Hello \"}}\n\n",
            "event: content_block_delta\n",
            "data: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"world!\"}}\n\n",
            "event: message_delta\n",
            "data: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"end_turn\"},\"usage\":{\"output_tokens\":7}}\n\n",
            "event: message_stop\n",
            "data: {\"type\":\"message_stop\"}\n\n"
        );

        let mut translator = AnthropicSseTranslator::new("claude-3-5-sonnet");
        let mut combined = Vec::new();
        // Split across odd chunk boundaries to verify incremental buffering.
        for chunk in raw_sse.as_bytes().chunks(13) {
            combined.extend_from_slice(&translator.push_chunk(chunk));
        }
        combined.extend_from_slice(&translator.finish());

        let text = String::from_utf8(combined).unwrap();
        let mut parser = SseParser::new();
        let mut frames = parser.push(text.as_bytes());
        frames.extend(parser.finish());

        assert_eq!(frames.len(), 6);
        let f0: Value = serde_json::from_str(&frames[0].data).unwrap();
        assert_eq!(f0["id"], "chatcmpl-msg_abc");
        assert_eq!(f0["choices"][0]["delta"]["role"], "assistant");

        let f1: Value = serde_json::from_str(&frames[1].data).unwrap();
        assert_eq!(f1["choices"][0]["delta"]["content"], "Hello ");

        let f2: Value = serde_json::from_str(&frames[2].data).unwrap();
        assert_eq!(f2["choices"][0]["delta"]["content"], "world!");

        let f3: Value = serde_json::from_str(&frames[3].data).unwrap();
        assert_eq!(f3["choices"][0]["finish_reason"], "stop");

        let f4: Value = serde_json::from_str(&frames[4].data).unwrap();
        assert_eq!(f4["usage"]["prompt_tokens"], 20);
        assert_eq!(f4["usage"]["completion_tokens"], 7);
        assert_eq!(f4["usage"]["total_tokens"], 27);

        assert_eq!(frames[5].data, "[DONE]");
    }
}
