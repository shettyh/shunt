//! Anthropic Messages API (`POST /v1/messages`) ingress translator.
//!
//! - Native fast path: [`rewrite_anthropic_request`] rewrites `"model"` only (zero-copy when
//!   unchanged) for direct `anthropic` upstream passthrough.
//! - Cross-provider path: [`anthropic_to_openai_request`] converts an Anthropic Messages request
//!   into canonical OpenAI Chat Completions JSON so it can be dispatched to OpenAI-compatible,
//!   Azure OpenAI, Gemini, or AWS Bedrock backends, while [`openai_to_anthropic_response`] and
//!   [`OpenAiToAnthropicSseTranslator`] translate responses back into spec-compliant Anthropic
//!   Messages JSON and SSE streams.

use std::collections::HashMap;

use serde_json::{Map, Value, json};
use shunt_plugin_sdk::{Bytes, StatusCode};

use crate::ingress::write_named_sse_json;
use crate::sse::{SseEvent, SseParser};
use crate::types::map_status_to_anthropic_error_type;

/// Rewrites `"model"` in an Anthropic `/v1/messages` JSON request body for native passthrough
/// to an Anthropic upstream.
///
/// Returns `Ok(None)` when `"model"` already equals `target_model` (zero-copy passthrough).
pub fn rewrite_anthropic_request(
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
        .map_err(|e| format!("failed to serialize Anthropic request: {e}"))
}

/// Translates an Anthropic `POST /v1/messages` JSON request into a canonical OpenAI
/// `/v1/chat/completions` JSON request targeted at `target_model`.
pub fn anthropic_to_openai_request(body: &[u8], target_model: &str) -> Result<Vec<u8>, String> {
    let val: Value =
        serde_json::from_slice(body).map_err(|e| format!("invalid JSON request body: {e}"))?;
    let obj = val
        .as_object()
        .ok_or_else(|| "request body must be a JSON object".to_owned())?;

    let raw_messages = obj
        .get("messages")
        .and_then(Value::as_array)
        .ok_or_else(|| "missing or invalid `messages` array".to_owned())?;

    let mut openai_messages: Vec<Value> = Vec::with_capacity(raw_messages.len() + 1);

    // 1. Optional top-level `system` (string or array of content blocks).
    if let Some(sys) = obj.get("system") {
        let sys_text = extract_anthropic_system_text(sys);
        if !sys_text.is_empty() {
            openai_messages.push(json!({
                "role": "system",
                "content": sys_text,
            }));
        }
    }

    // 2. Convert `messages[]` preserving tool_use / tool_result and image blocks.
    for msg in raw_messages {
        let Some(msg_obj) = msg.as_object() else {
            continue;
        };
        let role = msg_obj
            .get("role")
            .and_then(Value::as_str)
            .unwrap_or("user");
        let content = msg_obj.get("content");

        match role {
            "assistant" => convert_anthropic_assistant_message(content, &mut openai_messages),
            "system" => {
                let text = extract_anthropic_text(content);
                if !text.is_empty() {
                    openai_messages.push(json!({ "role": "system", "content": text }));
                }
            }
            _ => convert_anthropic_user_message(content, &mut openai_messages),
        }
    }

    let mut out = Map::new();
    out.insert("model".to_owned(), Value::String(target_model.to_owned()));
    out.insert("messages".to_owned(), Value::Array(openai_messages));

    if let Some(max_tokens) = obj.get("max_tokens").and_then(Value::as_u64) {
        out.insert("max_tokens".to_owned(), Value::Number(max_tokens.into()));
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

    if let Some(stops) = obj.get("stop_sequences").and_then(Value::as_array) {
        let seqs: Vec<Value> = stops
            .iter()
            .filter_map(|v| v.as_str().map(|s| Value::String(s.to_owned())))
            .collect();
        if !seqs.is_empty() {
            out.insert("stop".to_owned(), Value::Array(seqs));
        }
    }

    if let Some(tools) = obj.get("tools").and_then(Value::as_array) {
        let converted: Vec<Value> = tools
            .iter()
            .filter_map(|t| {
                let name = t.get("name")?.as_str()?;
                let mut func = Map::new();
                func.insert("name".to_owned(), Value::String(name.to_owned()));
                if let Some(desc) = t.get("description").and_then(Value::as_str) {
                    func.insert("description".to_owned(), Value::String(desc.to_owned()));
                }
                let params = t
                    .get("input_schema")
                    .cloned()
                    .unwrap_or_else(|| json!({ "type": "object", "properties": {} }));
                func.insert("parameters".to_owned(), params);
                Some(json!({
                    "type": "function",
                    "function": Value::Object(func),
                }))
            })
            .collect();
        if !converted.is_empty() {
            out.insert("tools".to_owned(), Value::Array(converted));
        }
    }

    if let Some(tc) = obj.get("tool_choice").and_then(Value::as_object)
        && let Some(tc_type) = tc.get("type").and_then(Value::as_str)
    {
        match tc_type {
            "auto" => {
                out.insert("tool_choice".to_owned(), Value::String("auto".to_owned()));
            }
            "any" => {
                out.insert(
                    "tool_choice".to_owned(),
                    Value::String("required".to_owned()),
                );
            }
            "none" => {
                out.insert("tool_choice".to_owned(), Value::String("none".to_owned()));
            }
            "tool" => {
                if let Some(name) = tc.get("name").and_then(Value::as_str) {
                    out.insert(
                        "tool_choice".to_owned(),
                        json!({
                            "type": "function",
                            "function": { "name": name },
                        }),
                    );
                }
            }
            _ => {}
        }
    }

    if let Some(user_id) = obj
        .get("metadata")
        .and_then(|m| m.get("user_id"))
        .and_then(Value::as_str)
    {
        out.insert("user".to_owned(), Value::String(user_id.to_owned()));
    }

    serde_json::to_vec(&Value::Object(out))
        .map_err(|e| format!("failed to serialize canonical OpenAI request: {e}"))
}

fn extract_anthropic_system_text(sys: &Value) -> String {
    match sys {
        Value::String(s) => s.clone(),
        Value::Array(blocks) => blocks
            .iter()
            .filter_map(|b| {
                if b.get("type").and_then(Value::as_str) == Some("text") {
                    b.get("text").and_then(Value::as_str)
                } else {
                    None
                }
            })
            .collect::<Vec<_>>()
            .join("\n\n"),
        _ => String::new(),
    }
}

fn extract_anthropic_text(content: Option<&Value>) -> String {
    match content {
        Some(Value::String(s)) => s.clone(),
        Some(Value::Array(blocks)) => blocks
            .iter()
            .filter_map(|b| {
                if b.get("type").and_then(Value::as_str) == Some("text") {
                    b.get("text").and_then(Value::as_str)
                } else {
                    None
                }
            })
            .collect::<Vec<_>>()
            .join("\n"),
        Some(other) if !other.is_null() => serde_json::to_string(other).unwrap_or_default(),
        _ => String::new(),
    }
}

fn convert_anthropic_user_message(content: Option<&Value>, out: &mut Vec<Value>) {
    match content {
        Some(Value::String(s)) => {
            out.push(json!({ "role": "user", "content": s }));
        }
        Some(Value::Array(blocks)) => {
            let mut user_parts: Vec<Value> = Vec::new();

            for block in blocks {
                match block.get("type").and_then(Value::as_str) {
                    Some("tool_result") => {
                        // Flush any accumulated user parts first to preserve turn order.
                        flush_user_parts(&mut user_parts, out);
                        let call_id = block
                            .get("tool_use_id")
                            .and_then(Value::as_str)
                            .unwrap_or("");
                        let result_text = extract_anthropic_text(block.get("content"));
                        out.push(json!({
                            "role": "tool",
                            "tool_call_id": call_id,
                            "content": result_text,
                        }));
                    }
                    Some("text") => {
                        if let Some(t) = block.get("text").and_then(Value::as_str) {
                            user_parts.push(json!({ "type": "text", "text": t }));
                        }
                    }
                    Some("image") => {
                        if let Some(src) = block.get("source") {
                            match src.get("type").and_then(Value::as_str) {
                                Some("base64") => {
                                    let media_type = src
                                        .get("media_type")
                                        .and_then(Value::as_str)
                                        .unwrap_or("image/png");
                                    if let Some(data) = src.get("data").and_then(Value::as_str) {
                                        let url = format!("data:{media_type};base64,{data}");
                                        user_parts.push(json!({
                                            "type": "image_url",
                                            "image_url": { "url": url },
                                        }));
                                    }
                                }
                                Some("url") => {
                                    if let Some(url) = src.get("url").and_then(Value::as_str) {
                                        user_parts.push(json!({
                                            "type": "image_url",
                                            "image_url": { "url": url },
                                        }));
                                    }
                                }
                                _ => {}
                            }
                        }
                    }
                    _ => {}
                }
            }

            flush_user_parts(&mut user_parts, out);
        }
        _ => {}
    }
}

fn flush_user_parts(parts: &mut Vec<Value>, out: &mut Vec<Value>) {
    if parts.is_empty() {
        return;
    }
    if parts.len() == 1
        && parts[0].get("type").and_then(Value::as_str) == Some("text")
        && let Some(text) = parts[0].get("text").and_then(Value::as_str)
    {
        out.push(json!({ "role": "user", "content": text }));
        parts.clear();
        return;
    }
    out.push(json!({
        "role": "user",
        "content": std::mem::take(parts),
    }));
}

fn convert_anthropic_assistant_message(content: Option<&Value>, out: &mut Vec<Value>) {
    match content {
        Some(Value::String(s)) => {
            out.push(json!({ "role": "assistant", "content": s }));
        }
        Some(Value::Array(blocks)) => {
            let mut texts: Vec<&str> = Vec::new();
            let mut tool_calls: Vec<Value> = Vec::new();

            for block in blocks {
                match block.get("type").and_then(Value::as_str) {
                    Some("text") => {
                        if let Some(t) = block.get("text").and_then(Value::as_str) {
                            texts.push(t);
                        }
                    }
                    Some("tool_use") => {
                        let id = block.get("id").and_then(Value::as_str).unwrap_or("");
                        let name = block.get("name").and_then(Value::as_str).unwrap_or("");
                        let args_str = block
                            .get("input")
                            .map(|v| serde_json::to_string(v).unwrap_or_else(|_| "{}".to_owned()))
                            .unwrap_or_else(|| "{}".to_owned());
                        tool_calls.push(json!({
                            "id": id,
                            "type": "function",
                            "function": {
                                "name": name,
                                "arguments": args_str,
                            }
                        }));
                    }
                    // Thinking blocks and other Anthropic-specific blocks have no OpenAI input equivalent.
                    _ => {}
                }
            }

            if texts.is_empty() && tool_calls.is_empty() {
                return;
            }

            let mut msg = Map::new();
            msg.insert("role".to_owned(), Value::String("assistant".to_owned()));
            if texts.is_empty() {
                msg.insert("content".to_owned(), Value::Null);
            } else {
                msg.insert("content".to_owned(), Value::String(texts.join("")));
            }
            if !tool_calls.is_empty() {
                msg.insert("tool_calls".to_owned(), Value::Array(tool_calls));
            }
            out.push(Value::Object(msg));
        }
        _ => {}
    }
}

/// Maps an OpenAI `finish_reason` string to an Anthropic Messages `stop_reason` string.
pub fn map_openai_finish_to_anthropic_stop(finish_reason: Option<&str>) -> Option<&'static str> {
    match finish_reason {
        Some("stop") => Some("end_turn"),
        Some("length") => Some("max_tokens"),
        Some("tool_calls") | Some("function_call") => Some("tool_use"),
        Some("content_filter") => Some("end_turn"),
        Some(_) => Some("end_turn"),
        None => None,
    }
}

pub(crate) fn format_anthropic_msg_id(raw_id: &str) -> String {
    if raw_id.starts_with("msg_") {
        raw_id.to_owned()
    } else if let Some(stripped) = raw_id.strip_prefix("chatcmpl-") {
        format!("msg_{stripped}")
    } else {
        format!("msg_{raw_id}")
    }
}

/// Translates a canonical OpenAI Chat Completions JSON response (or error JSON) into an
/// Anthropic Messages API JSON response.
pub fn openai_to_anthropic_response(
    openai_body: &[u8],
    status: StatusCode,
    fallback_model: &str,
) -> Result<Vec<u8>, String> {
    let val: Value = serde_json::from_slice(openai_body)
        .map_err(|e| format!("invalid OpenAI JSON response: {e}"))?;

    if !status.is_success() || val.get("error").is_some() {
        let err_obj = val.get("error");
        let raw_type = err_obj.and_then(|e| e.get("type")).and_then(Value::as_str);
        let anth_type = map_status_to_anthropic_error_type(status, raw_type);
        let message = err_obj
            .and_then(|e| e.get("message"))
            .and_then(Value::as_str)
            .unwrap_or("upstream provider error");
        let anth_err = json!({
            "type": "error",
            "error": {
                "type": anth_type,
                "message": message,
            }
        });
        return serde_json::to_vec(&anth_err)
            .map_err(|e| format!("failed to serialize Anthropic error: {e}"));
    }

    let raw_id = val.get("id").and_then(Value::as_str).unwrap_or("shunt");
    let id = format_anthropic_msg_id(raw_id);
    let model = val
        .get("model")
        .and_then(Value::as_str)
        .unwrap_or(fallback_model);

    let choice = val
        .get("choices")
        .and_then(Value::as_array)
        .and_then(|arr| arr.first());
    let message = choice.and_then(|c| c.get("message"));

    let mut content_blocks: Vec<Value> = Vec::new();
    let mut has_tool_calls = false;

    if let Some(msg) = message {
        if let Some(text) = msg.get("content").and_then(Value::as_str)
            && !text.is_empty()
        {
            content_blocks.push(json!({
                "type": "text",
                "text": text,
            }));
        }

        if let Some(tool_calls) = msg.get("tool_calls").and_then(Value::as_array) {
            for (idx, tc) in tool_calls.iter().enumerate() {
                has_tool_calls = true;
                let call_id = tc
                    .get("id")
                    .and_then(Value::as_str)
                    .filter(|s| !s.is_empty())
                    .map(str::to_owned)
                    .unwrap_or_else(|| format!("toolu_{idx}"));
                let func = tc.get("function");
                let name = func
                    .and_then(|f| f.get("name"))
                    .and_then(Value::as_str)
                    .unwrap_or("");
                let raw_args = func
                    .and_then(|f| f.get("arguments"))
                    .and_then(Value::as_str)
                    .unwrap_or("{}");
                let input: Value = serde_json::from_str::<Value>(raw_args)
                    .ok()
                    .filter(Value::is_object)
                    .unwrap_or_else(|| Value::Object(Map::new()));
                content_blocks.push(json!({
                    "type": "tool_use",
                    "id": call_id,
                    "name": name,
                    "input": input,
                }));
            }
        }
    }

    if content_blocks.is_empty() {
        content_blocks.push(json!({
            "type": "text",
            "text": "",
        }));
    }

    let raw_finish = choice
        .and_then(|c| c.get("finish_reason"))
        .and_then(Value::as_str);
    let stop_reason =
        map_openai_finish_to_anthropic_stop(raw_finish).unwrap_or(if has_tool_calls {
            "tool_use"
        } else {
            "end_turn"
        });

    let input_tokens = val
        .get("usage")
        .and_then(|u| u.get("prompt_tokens").or_else(|| u.get("input_tokens")))
        .and_then(Value::as_u64)
        .unwrap_or(0);
    let output_tokens = val
        .get("usage")
        .and_then(|u| {
            u.get("completion_tokens")
                .or_else(|| u.get("output_tokens"))
        })
        .and_then(Value::as_u64)
        .unwrap_or(0);

    let anth_resp = json!({
        "id": id,
        "type": "message",
        "role": "assistant",
        "model": model,
        "content": content_blocks,
        "stop_reason": stop_reason,
        "stop_sequence": Value::Null,
        "usage": {
            "input_tokens": input_tokens,
            "output_tokens": output_tokens,
        }
    });

    serde_json::to_vec(&anth_resp)
        .map_err(|e| format!("failed to serialize Anthropic response: {e}"))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ActiveBlock {
    Text {
        block_index: usize,
    },
    Tool {
        tool_index: usize,
        block_index: usize,
    },
}

/// Stateful per-request streaming translator that converts canonical OpenAI
/// `chat.completion.chunk` SSE frames into spec-compliant Anthropic Messages SSE frames
/// (`message_start`, `content_block_start`, `content_block_delta`, `content_block_stop`,
/// `message_delta`, `message_stop`).
#[derive(Debug, Clone)]
pub struct OpenAiToAnthropicSseTranslator {
    parser: SseParser,
    id: String,
    model: String,
    started: bool,
    finished: bool,
    next_block_index: usize,
    active_block: Option<ActiveBlock>,
    tool_index_to_block: HashMap<usize, usize>,
    has_tool_calls: bool,
    stop_reason: Option<&'static str>,
    input_tokens: u64,
    output_tokens: u64,
}

impl OpenAiToAnthropicSseTranslator {
    pub fn new(fallback_model: impl Into<String>) -> Self {
        Self {
            parser: SseParser::new(),
            id: "msg_shunt".to_owned(),
            model: fallback_model.into(),
            started: false,
            finished: false,
            next_block_index: 0,
            active_block: None,
            tool_index_to_block: HashMap::new(),
            has_tool_calls: false,
            stop_reason: None,
            input_tokens: 0,
            output_tokens: 0,
        }
    }

    /// Consumes a raw chunk of canonical OpenAI SSE bytes and emits Anthropic SSE bytes.
    pub fn push_chunk(&mut self, chunk: &[u8]) -> Bytes {
        let events = self.parser.push(chunk);
        self.translate_events(events)
    }

    /// Flushes any trailing buffered SSE frame and ensures `message_delta` + `message_stop`
    /// are emitted exactly once if the stream started.
    pub fn finish(&mut self) -> Bytes {
        let events = self.parser.finish();
        let mut out = Vec::new();
        for ev in events {
            self.translate_event(&ev, &mut out);
        }
        if self.started && !self.finished {
            self.finalize(&mut out);
        }
        Bytes::from(out)
    }

    fn translate_events(&mut self, events: Vec<SseEvent>) -> Bytes {
        if events.is_empty() {
            return Bytes::new();
        }
        let mut out = Vec::with_capacity(events.len() * 256);
        for ev in events {
            self.translate_event(&ev, &mut out);
        }
        Bytes::from(out)
    }

    fn translate_event(&mut self, ev: &SseEvent, out: &mut Vec<u8>) {
        if self.finished {
            return;
        }
        let trimmed = ev.data.trim();
        if trimmed.is_empty() {
            return;
        }
        if trimmed == "[DONE]" {
            if self.started {
                self.finalize(out);
            }
            return;
        }

        let Ok(payload) = serde_json::from_str::<Value>(trimmed) else {
            return;
        };

        // Upstream SSE error frame.
        if let Some(err_obj) = payload.get("error") {
            let raw_type = err_obj.get("type").and_then(Value::as_str);
            let anth_type =
                map_status_to_anthropic_error_type(StatusCode::INTERNAL_SERVER_ERROR, raw_type);
            let msg = err_obj
                .get("message")
                .and_then(Value::as_str)
                .unwrap_or("upstream stream error");
            write_named_sse_json(
                out,
                "error",
                &json!({
                    "type": "error",
                    "error": {
                        "type": anth_type,
                        "message": msg,
                    }
                }),
            );
            return;
        }

        if let Some(raw_id) = payload.get("id").and_then(Value::as_str)
            && !raw_id.is_empty()
        {
            self.id = format_anthropic_msg_id(raw_id);
        }
        if let Some(m) = payload.get("model").and_then(Value::as_str)
            && !m.is_empty()
        {
            self.model = m.to_owned();
        }

        if let Some(u) = payload.get("usage").and_then(Value::as_object) {
            if let Some(p) = u
                .get("prompt_tokens")
                .or_else(|| u.get("input_tokens"))
                .and_then(Value::as_u64)
            {
                self.input_tokens = p;
            }
            if let Some(c) = u
                .get("completion_tokens")
                .or_else(|| u.get("output_tokens"))
                .and_then(Value::as_u64)
            {
                self.output_tokens = c;
            }
        }

        self.ensure_started(out);

        if let Some(choices) = payload.get("choices").and_then(Value::as_array)
            && let Some(choice) = choices.first()
        {
            if let Some(delta) = choice.get("delta") {
                if let Some(text) = delta.get("content").and_then(Value::as_str)
                    && !text.is_empty()
                {
                    let block_idx = self.ensure_text_block(out);
                    write_named_sse_json(
                        out,
                        "content_block_delta",
                        &json!({
                            "type": "content_block_delta",
                            "index": block_idx,
                            "delta": {
                                "type": "text_delta",
                                "text": text,
                            }
                        }),
                    );
                }

                if let Some(tool_calls) = delta.get("tool_calls").and_then(Value::as_array) {
                    for tc in tool_calls {
                        self.has_tool_calls = true;
                        let tc_index =
                            tc.get("index").and_then(Value::as_u64).unwrap_or(0) as usize;
                        let block_idx =
                            if let Some(&existing) = self.tool_index_to_block.get(&tc_index) {
                                existing
                            } else {
                                self.close_active_block(out);
                                let idx = self.next_block_index;
                                self.next_block_index += 1;
                                self.tool_index_to_block.insert(tc_index, idx);
                                self.active_block = Some(ActiveBlock::Tool {
                                    tool_index: tc_index,
                                    block_index: idx,
                                });

                                let call_id = tc
                                    .get("id")
                                    .and_then(Value::as_str)
                                    .filter(|s| !s.is_empty())
                                    .map(str::to_owned)
                                    .unwrap_or_else(|| format!("toolu_{tc_index}"));
                                let name = tc
                                    .get("function")
                                    .and_then(|f| f.get("name"))
                                    .and_then(Value::as_str)
                                    .unwrap_or("");
                                write_named_sse_json(
                                    out,
                                    "content_block_start",
                                    &json!({
                                        "type": "content_block_start",
                                        "index": idx,
                                        "content_block": {
                                            "type": "tool_use",
                                            "id": call_id,
                                            "name": name,
                                            "input": {},
                                        }
                                    }),
                                );
                                idx
                            };

                        if let Some(partial) = tc
                            .get("function")
                            .and_then(|f| f.get("arguments"))
                            .and_then(Value::as_str)
                            && !partial.is_empty()
                        {
                            write_named_sse_json(
                                out,
                                "content_block_delta",
                                &json!({
                                    "type": "content_block_delta",
                                    "index": block_idx,
                                    "delta": {
                                        "type": "input_json_delta",
                                        "partial_json": partial,
                                    }
                                }),
                            );
                        }
                    }
                }
            }

            if let Some(fr) = choice.get("finish_reason").and_then(Value::as_str)
                && let Some(mapped) = map_openai_finish_to_anthropic_stop(Some(fr))
            {
                self.stop_reason = Some(mapped);
            }
        }
    }

    fn ensure_started(&mut self, out: &mut Vec<u8>) {
        if self.started {
            return;
        }
        self.started = true;
        write_named_sse_json(
            out,
            "message_start",
            &json!({
                "type": "message_start",
                "message": {
                    "id": self.id,
                    "type": "message",
                    "role": "assistant",
                    "content": [],
                    "model": self.model,
                    "stop_reason": Value::Null,
                    "stop_sequence": Value::Null,
                    "usage": {
                        "input_tokens": self.input_tokens,
                        "output_tokens": 0,
                    }
                }
            }),
        );
    }

    fn ensure_text_block(&mut self, out: &mut Vec<u8>) -> usize {
        if let Some(ActiveBlock::Text { block_index }) = self.active_block {
            return block_index;
        }
        self.close_active_block(out);
        let idx = self.next_block_index;
        self.next_block_index += 1;
        self.active_block = Some(ActiveBlock::Text { block_index: idx });
        write_named_sse_json(
            out,
            "content_block_start",
            &json!({
                "type": "content_block_start",
                "index": idx,
                "content_block": {
                    "type": "text",
                    "text": "",
                }
            }),
        );
        idx
    }

    fn close_active_block(&mut self, out: &mut Vec<u8>) {
        if let Some(active) = self.active_block.take() {
            let idx = match active {
                ActiveBlock::Text { block_index } | ActiveBlock::Tool { block_index, .. } => {
                    block_index
                }
            };
            write_named_sse_json(
                out,
                "content_block_stop",
                &json!({
                    "type": "content_block_stop",
                    "index": idx,
                }),
            );
        }
    }

    fn finalize(&mut self, out: &mut Vec<u8>) {
        if self.finished {
            return;
        }
        self.finished = true;
        self.close_active_block(out);

        let stop_reason = self.stop_reason.unwrap_or(if self.has_tool_calls {
            "tool_use"
        } else {
            "end_turn"
        });

        write_named_sse_json(
            out,
            "message_delta",
            &json!({
                "type": "message_delta",
                "delta": {
                    "stop_reason": stop_reason,
                    "stop_sequence": Value::Null,
                },
                "usage": {
                    "input_tokens": self.input_tokens,
                    "output_tokens": self.output_tokens,
                }
            }),
        );
        write_named_sse_json(out, "message_stop", &json!({ "type": "message_stop" }));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rewrite_anthropic_request_is_zero_copy_when_unchanged() {
        let body = br#"{"model":"claude-3-5-sonnet-20241022","max_tokens":128,"messages":[{"role":"user","content":"hi"}]}"#;
        assert!(
            rewrite_anthropic_request(body, "claude-3-5-sonnet-20241022")
                .unwrap()
                .is_none()
        );

        let rewritten = rewrite_anthropic_request(body, "claude-sonnet-4-5")
            .unwrap()
            .unwrap();
        let v: Value = serde_json::from_slice(&rewritten).unwrap();
        assert_eq!(v["model"], "claude-sonnet-4-5");
        assert_eq!(v["max_tokens"], 128);
    }

    #[test]
    fn anthropic_request_translates_system_blocks_tools_and_images() {
        let req = json!({
            "model": "smart",
            "max_tokens": 512,
            "stream": true,
            "temperature": 0.2,
            "stop_sequences": ["END"],
            "system": [
                { "type": "text", "text": "System part 1", "cache_control": { "type": "ephemeral" } },
                { "type": "text", "text": "System part 2" }
            ],
            "tools": [{
                "name": "get_weather",
                "description": "Lookup weather",
                "input_schema": { "type": "object", "properties": { "city": { "type": "string" } } }
            }],
            "tool_choice": { "type": "tool", "name": "get_weather" },
            "metadata": { "user_id": "u-42" },
            "messages": [
                {
                    "role": "user",
                    "content": [
                        { "type": "text", "text": "Describe this" },
                        { "type": "image", "source": { "type": "base64", "media_type": "image/png", "data": "AA==" } }
                    ]
                },
                {
                    "role": "assistant",
                    "content": [
                        { "type": "thinking", "thinking": "hmm" },
                        { "type": "text", "text": "Checking weather" },
                        { "type": "tool_use", "id": "toolu_1", "name": "get_weather", "input": { "city": "NYC" } }
                    ]
                },
                {
                    "role": "user",
                    "content": [
                        { "type": "tool_result", "tool_use_id": "toolu_1", "content": [{ "type": "text", "text": "72F" }] },
                        { "type": "text", "text": "Thanks!" }
                    ]
                }
            ]
        });

        let out_bytes =
            anthropic_to_openai_request(&serde_json::to_vec(&req).unwrap(), "gpt-4o").unwrap();
        let out: Value = serde_json::from_slice(&out_bytes).unwrap();

        assert_eq!(out["model"], "gpt-4o");
        assert_eq!(out["max_tokens"], 512);
        assert_eq!(out["stream"], true);
        assert_eq!(out["stop"][0], "END");
        assert_eq!(out["user"], "u-42");
        assert_eq!(out["tools"][0]["function"]["name"], "get_weather");
        assert_eq!(out["tool_choice"]["function"]["name"], "get_weather");

        let msgs = out["messages"].as_array().unwrap();
        assert_eq!(msgs.len(), 5);
        assert_eq!(msgs[0]["role"], "system");
        assert_eq!(msgs[0]["content"], "System part 1\n\nSystem part 2");
        assert_eq!(msgs[1]["role"], "user");
        assert_eq!(msgs[1]["content"][1]["type"], "image_url");
        assert_eq!(
            msgs[1]["content"][1]["image_url"]["url"],
            "data:image/png;base64,AA=="
        );
        assert_eq!(msgs[2]["role"], "assistant");
        assert_eq!(msgs[2]["content"], "Checking weather");
        assert_eq!(msgs[2]["tool_calls"][0]["id"], "toolu_1");
        assert_eq!(msgs[3]["role"], "tool");
        assert_eq!(msgs[3]["tool_call_id"], "toolu_1");
        assert_eq!(msgs[3]["content"], "72F");
        assert_eq!(msgs[4]["role"], "user");
        assert_eq!(msgs[4]["content"], "Thanks!");
    }

    #[test]
    fn openai_json_translates_to_anthropic_message_and_errors() {
        let resp = json!({
            "id": "chatcmpl-abc",
            "object": "chat.completion",
            "model": "gpt-4o",
            "choices": [{
                "index": 0,
                "message": {
                    "role": "assistant",
                    "content": "Calling tool",
                    "tool_calls": [{
                        "id": "call_1",
                        "type": "function",
                        "function": { "name": "search", "arguments": "{\"q\":\"rust\"}" }
                    }]
                },
                "finish_reason": "tool_calls"
            }],
            "usage": { "prompt_tokens": 12, "completion_tokens": 8, "total_tokens": 20 }
        });

        let out_bytes =
            openai_to_anthropic_response(&serde_json::to_vec(&resp).unwrap(), StatusCode::OK, "x")
                .unwrap();
        let out: Value = serde_json::from_slice(&out_bytes).unwrap();
        assert_eq!(out["id"], "msg_abc");
        assert_eq!(out["type"], "message");
        assert_eq!(out["stop_reason"], "tool_use");
        assert_eq!(out["content"][0]["text"], "Calling tool");
        assert_eq!(out["content"][1]["type"], "tool_use");
        assert_eq!(out["content"][1]["input"]["q"], "rust");
        assert_eq!(out["usage"]["input_tokens"], 12);
        assert_eq!(out["usage"]["output_tokens"], 8);

        let err_body = json!({
            "error": { "message": "quota exceeded", "type": "rate_limit_error" }
        });
        let err_bytes = openai_to_anthropic_response(
            &serde_json::to_vec(&err_body).unwrap(),
            StatusCode::TOO_MANY_REQUESTS,
            "x",
        )
        .unwrap();
        let err: Value = serde_json::from_slice(&err_bytes).unwrap();
        assert_eq!(err["type"], "error");
        assert_eq!(err["error"]["type"], "rate_limit_error");
        assert_eq!(err["error"]["message"], "quota exceeded");
    }

    #[test]
    fn openai_sse_translates_to_anthropic_sse_with_tools_and_usage() {
        let stream = concat!(
            "data: {\"id\":\"chatcmpl-s1\",\"object\":\"chat.completion.chunk\",\"model\":\"gpt-4o\",\"choices\":[{\"index\":0,\"delta\":{\"role\":\"assistant\",\"content\":\"Hi \"},\"finish_reason\":null}]}\n\n",
            "data: {\"id\":\"chatcmpl-s1\",\"object\":\"chat.completion.chunk\",\"model\":\"gpt-4o\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"there\"},\"finish_reason\":null}]}\n\n",
            "data: {\"id\":\"chatcmpl-s1\",\"object\":\"chat.completion.chunk\",\"model\":\"gpt-4o\",\"choices\":[{\"index\":0,\"delta\":{\"tool_calls\":[{\"index\":0,\"id\":\"call_9\",\"type\":\"function\",\"function\":{\"name\":\"calc\",\"arguments\":\"{\\\"x\\\":\"}}]},\"finish_reason\":null}]}\n\n",
            "data: {\"id\":\"chatcmpl-s1\",\"object\":\"chat.completion.chunk\",\"model\":\"gpt-4o\",\"choices\":[{\"index\":0,\"delta\":{\"tool_calls\":[{\"index\":0,\"function\":{\"arguments\":\"42}\"}}]},\"finish_reason\":null}]}\n\n",
            "data: {\"id\":\"chatcmpl-s1\",\"object\":\"chat.completion.chunk\",\"model\":\"gpt-4o\",\"choices\":[{\"index\":0,\"delta\":{},\"finish_reason\":\"tool_calls\"}]}\n\n",
            "data: {\"id\":\"chatcmpl-s1\",\"object\":\"chat.completion.chunk\",\"model\":\"gpt-4o\",\"choices\":[],\"usage\":{\"prompt_tokens\":10,\"completion_tokens\":6,\"total_tokens\":16}}\n\n",
            "data: [DONE]\n\n"
        );

        let mut tr = OpenAiToAnthropicSseTranslator::new("fallback");
        let mut out = Vec::new();
        for chunk in stream.as_bytes().chunks(13) {
            out.extend_from_slice(&tr.push_chunk(chunk));
        }
        out.extend_from_slice(&tr.finish());

        let mut parser = SseParser::new();
        let mut events = parser.push(&out);
        events.extend(parser.finish());

        let event_names: Vec<&str> = events.iter().filter_map(|e| e.event.as_deref()).collect();
        assert_eq!(
            event_names,
            vec![
                "message_start",
                "content_block_start",
                "content_block_delta",
                "content_block_delta",
                "content_block_stop",
                "content_block_start",
                "content_block_delta",
                "content_block_delta",
                "content_block_stop",
                "message_delta",
                "message_stop",
            ]
        );

        let delta_ev: Value = serde_json::from_str(&events[9].data).unwrap();
        assert_eq!(delta_ev["delta"]["stop_reason"], "tool_use");
        assert_eq!(delta_ev["usage"]["input_tokens"], 10);
        assert_eq!(delta_ev["usage"]["output_tokens"], 6);
    }
}
