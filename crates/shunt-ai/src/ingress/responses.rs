//! OpenAI Responses API (`POST /v1/responses`) ingress translator.
//!
//! - Native fast path: [`rewrite_openai_responses_request`] rewrites `"model"` only (zero-copy
//!   when unchanged) when targeting a provider with `responses_path` configured.
//! - Cross-provider path: [`responses_to_chat_request`] converts an OpenAI Responses request into
//!   canonical OpenAI Chat Completions JSON so it can be dispatched to any provider dialect
//!   (`openai_compatible`, `azure_openai`, `anthropic`, `gemini`, `bedrock`), while
//!   [`chat_to_responses_response`] and [`ChatToResponsesSseTranslator`] translate responses back
//!   into spec-compliant OpenAI Responses JSON and streaming SSE events.

use std::collections::{BTreeMap, HashMap};

use serde_json::{Map, Value, json};
use shunt_plugin_sdk::{Bytes, StatusCode};

use crate::dialects::unix_timestamp_secs;
use crate::ingress::write_named_sse_json;
use crate::sse::{SseEvent, SseParser};

/// Rewrites `"model"` in an OpenAI `POST /v1/responses` JSON request body for native passthrough.
///
/// Returns `Ok(None)` when `"model"` already equals `target_model` (zero-copy passthrough).
pub fn rewrite_openai_responses_request(
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
        .map_err(|e| format!("failed to serialize OpenAI Responses request: {e}"))
}

/// Translates an OpenAI `POST /v1/responses` JSON request into a canonical OpenAI
/// `/v1/chat/completions` JSON request targeted at `target_model`.
pub fn responses_to_chat_request(body: &[u8], target_model: &str) -> Result<Vec<u8>, String> {
    let val: Value =
        serde_json::from_slice(body).map_err(|e| format!("invalid JSON request body: {e}"))?;
    let obj = val
        .as_object()
        .ok_or_else(|| "request body must be a JSON object".to_owned())?;

    let mut messages: Vec<Value> = Vec::new();

    if let Some(instructions) = obj
        .get("instructions")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
    {
        messages.push(json!({
            "role": "system",
            "content": instructions,
        }));
    }

    match obj.get("input") {
        Some(Value::String(s)) => {
            messages.push(json!({
                "role": "user",
                "content": s,
            }));
        }
        Some(Value::Array(items)) => {
            for item in items {
                convert_responses_input_item(item, &mut messages);
            }
        }
        None => {
            return Err("missing required `input` field in `/v1/responses` request".to_owned());
        }
        _ => {
            return Err("`input` must be a string or an array of input items".to_owned());
        }
    }

    let mut out = Map::new();
    out.insert("model".to_owned(), Value::String(target_model.to_owned()));
    out.insert("messages".to_owned(), Value::Array(messages));

    if let Some(max_out) = obj.get("max_output_tokens").and_then(Value::as_u64) {
        out.insert("max_tokens".to_owned(), Value::Number(max_out.into()));
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
    if let Some(user) = obj.get("user").and_then(Value::as_str) {
        out.insert("user".to_owned(), Value::String(user.to_owned()));
    }
    if let Some(ptc) = obj.get("parallel_tool_calls").and_then(Value::as_bool) {
        out.insert("parallel_tool_calls".to_owned(), Value::Bool(ptc));
    }

    // Tools: Responses API uses flat function definitions `{type: "function", name, description, parameters}`.
    if let Some(tools) = obj.get("tools").and_then(Value::as_array) {
        let converted: Vec<Value> = tools
            .iter()
            .filter_map(|t| {
                if t.get("type").and_then(Value::as_str) != Some("function") {
                    return None;
                }
                if let Some(nested) = t.get("function").and_then(Value::as_object) {
                    return Some(json!({
                        "type": "function",
                        "function": Value::Object(nested.clone()),
                    }));
                }
                let name = t.get("name")?.as_str()?;
                let mut func = Map::new();
                func.insert("name".to_owned(), Value::String(name.to_owned()));
                if let Some(desc) = t.get("description").and_then(Value::as_str) {
                    func.insert("description".to_owned(), Value::String(desc.to_owned()));
                }
                if let Some(params) = t.get("parameters") {
                    func.insert("parameters".to_owned(), params.clone());
                }
                if let Some(strict) = t.get("strict").and_then(Value::as_bool) {
                    func.insert("strict".to_owned(), Value::Bool(strict));
                }
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

    if let Some(tc) = obj.get("tool_choice") {
        match tc {
            Value::String(s) => {
                out.insert("tool_choice".to_owned(), Value::String(s.clone()));
            }
            Value::Object(tc_obj)
                if tc_obj.get("type").and_then(Value::as_str) == Some("function") =>
            {
                if let Some(name) = tc_obj.get("name").and_then(Value::as_str).or_else(|| {
                    tc_obj
                        .get("function")
                        .and_then(|f| f.get("name"))
                        .and_then(Value::as_str)
                }) {
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

    // Structured outputs: `text.format` -> Chat Completions `response_format`.
    if let Some(fmt) = obj.get("text").and_then(|t| t.get("format"))
        && let Some(fmt_type) = fmt.get("type").and_then(Value::as_str)
    {
        match fmt_type {
            "json_object" => {
                out.insert(
                    "response_format".to_owned(),
                    json!({ "type": "json_object" }),
                );
            }
            "json_schema" => {
                let mut js = Map::new();
                if let Some(name) = fmt.get("name").and_then(Value::as_str) {
                    js.insert("name".to_owned(), Value::String(name.to_owned()));
                }
                if let Some(schema) = fmt.get("schema") {
                    js.insert("schema".to_owned(), schema.clone());
                }
                if let Some(strict) = fmt.get("strict").and_then(Value::as_bool) {
                    js.insert("strict".to_owned(), Value::Bool(strict));
                }
                out.insert(
                    "response_format".to_owned(),
                    json!({
                        "type": "json_schema",
                        "json_schema": Value::Object(js),
                    }),
                );
            }
            _ => {}
        }
    }

    serde_json::to_vec(&Value::Object(out))
        .map_err(|e| format!("failed to serialize canonical Chat Completions request: {e}"))
}

fn convert_responses_input_item(item: &Value, messages: &mut Vec<Value>) {
    let Some(obj) = item.as_object() else {
        if let Some(s) = item.as_str() {
            messages.push(json!({ "role": "user", "content": s }));
        }
        return;
    };

    let item_type = obj.get("type").and_then(Value::as_str);

    match item_type {
        Some("function_call") => {
            let call_id = obj
                .get("call_id")
                .or_else(|| obj.get("id"))
                .and_then(Value::as_str)
                .unwrap_or("");
            let name = obj.get("name").and_then(Value::as_str).unwrap_or("");
            let arguments = match obj.get("arguments") {
                Some(Value::String(s)) => s.clone(),
                Some(other) => serde_json::to_string(other).unwrap_or_else(|_| "{}".to_owned()),
                None => "{}".to_owned(),
            };
            let tc = json!({
                "id": call_id,
                "type": "function",
                "function": {
                    "name": name,
                    "arguments": arguments,
                }
            });

            // Merge consecutive assistant tool_calls into the preceding assistant message if possible.
            if let Some(Value::Object(last)) = messages.last_mut()
                && last.get("role").and_then(Value::as_str) == Some("assistant")
            {
                match last.get_mut("tool_calls") {
                    Some(Value::Array(arr)) => arr.push(tc),
                    _ => {
                        last.insert("tool_calls".to_owned(), Value::Array(vec![tc]));
                    }
                }
                return;
            }

            messages.push(json!({
                "role": "assistant",
                "content": Value::Null,
                "tool_calls": [tc],
            }));
        }
        Some("function_call_output") => {
            let call_id = obj.get("call_id").and_then(Value::as_str).unwrap_or("");
            let output_str = match obj.get("output") {
                Some(Value::String(s)) => s.clone(),
                Some(other) => serde_json::to_string(other).unwrap_or_default(),
                None => String::new(),
            };
            messages.push(json!({
                "role": "tool",
                "tool_call_id": call_id,
                "content": output_str,
            }));
        }
        Some("message") | None => {
            let role = obj.get("role").and_then(Value::as_str).unwrap_or("user");
            let content = convert_responses_message_content(obj.get("content"));
            messages.push(json!({
                "role": role,
                "content": content,
            }));
        }
        _ => {}
    }
}

fn convert_responses_message_content(content: Option<&Value>) -> Value {
    match content {
        Some(Value::String(s)) => Value::String(s.clone()),
        Some(Value::Array(parts)) => {
            let mut out_parts: Vec<Value> = Vec::with_capacity(parts.len());
            for part in parts {
                let ptype = part.get("type").and_then(Value::as_str);
                match ptype {
                    Some("input_text") | Some("output_text") | Some("text") => {
                        if let Some(t) = part.get("text").and_then(Value::as_str) {
                            out_parts.push(json!({ "type": "text", "text": t }));
                        }
                    }
                    Some("refusal") => {
                        if let Some(r) = part.get("refusal").and_then(Value::as_str) {
                            out_parts.push(json!({ "type": "text", "text": r }));
                        }
                    }
                    Some("input_image") | Some("image_url") => {
                        let url_opt = part.get("image_url").and_then(|u| match u {
                            Value::String(s) => Some(s.as_str()),
                            Value::Object(o) => o.get("url").and_then(Value::as_str),
                            _ => None,
                        });
                        if let Some(url) = url_opt {
                            out_parts.push(json!({
                                "type": "image_url",
                                "image_url": { "url": url },
                            }));
                        }
                    }
                    _ => {}
                }
            }

            if out_parts.len() == 1
                && out_parts[0].get("type").and_then(Value::as_str) == Some("text")
                && let Some(t) = out_parts[0].get("text").and_then(Value::as_str)
            {
                return Value::String(t.to_owned());
            }
            Value::Array(out_parts)
        }
        _ => Value::String(String::new()),
    }
}

pub(crate) fn format_response_id(raw_id: &str) -> String {
    if raw_id.starts_with("resp_") {
        raw_id.to_owned()
    } else if let Some(stripped) = raw_id.strip_prefix("chatcmpl-") {
        format!("resp_{stripped}")
    } else {
        format!("resp_{raw_id}")
    }
}

fn id_suffix(resp_id: &str) -> &str {
    resp_id.strip_prefix("resp_").unwrap_or(resp_id)
}

/// Translates a canonical OpenAI Chat Completions JSON response (or error JSON) into an
/// OpenAI Responses API (`object: "response"`) JSON response.
pub fn chat_to_responses_response(
    chat_body: &[u8],
    status: StatusCode,
    fallback_model: &str,
) -> Result<Vec<u8>, String> {
    let val: Value = serde_json::from_slice(chat_body)
        .map_err(|e| format!("invalid Chat Completions JSON response: {e}"))?;

    // Error payloads already follow OpenAI `{"error": ...}` format.
    if !status.is_success() || val.get("error").is_some() {
        return Ok(chat_body.to_vec());
    }

    let raw_id = val.get("id").and_then(Value::as_str).unwrap_or("shunt");
    let resp_id = format_response_id(raw_id);
    let suffix = id_suffix(&resp_id);
    let created_at = val
        .get("created")
        .and_then(Value::as_u64)
        .unwrap_or_else(unix_timestamp_secs);
    let model = val
        .get("model")
        .and_then(Value::as_str)
        .unwrap_or(fallback_model);

    let choice = val
        .get("choices")
        .and_then(Value::as_array)
        .and_then(|arr| arr.first());
    let message = choice.and_then(|c| c.get("message"));
    let finish_reason = choice
        .and_then(|c| c.get("finish_reason"))
        .and_then(Value::as_str);

    let (resp_status, incomplete_details) = if finish_reason == Some("length") {
        ("incomplete", json!({ "reason": "max_output_tokens" }))
    } else {
        ("completed", Value::Null)
    };

    let mut output_items: Vec<Value> = Vec::new();
    if let Some(msg) = message {
        let text = msg.get("content").and_then(Value::as_str).unwrap_or("");
        let tool_calls = msg.get("tool_calls").and_then(Value::as_array);

        if !text.is_empty() || tool_calls.map(|a| a.is_empty()).unwrap_or(true) {
            output_items.push(json!({
                "id": format!("msg_{suffix}"),
                "type": "message",
                "status": "completed",
                "role": "assistant",
                "content": [{
                    "type": "output_text",
                    "text": text,
                    "annotations": [],
                }],
            }));
        }

        if let Some(tcs) = tool_calls {
            for (idx, tc) in tcs.iter().enumerate() {
                let call_id = tc
                    .get("id")
                    .and_then(Value::as_str)
                    .filter(|s| !s.is_empty())
                    .map(str::to_owned)
                    .unwrap_or_else(|| format!("call_{idx}"));
                let func = tc.get("function");
                let name = func
                    .and_then(|f| f.get("name"))
                    .and_then(Value::as_str)
                    .unwrap_or("");
                let arguments = func
                    .and_then(|f| f.get("arguments"))
                    .and_then(Value::as_str)
                    .unwrap_or("{}");
                output_items.push(json!({
                    "id": format!("fc_{idx}_{suffix}"),
                    "type": "function_call",
                    "status": "completed",
                    "call_id": call_id,
                    "name": name,
                    "arguments": arguments,
                }));
            }
        }
    }

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
    let total_tokens = val
        .get("usage")
        .and_then(|u| u.get("total_tokens"))
        .and_then(Value::as_u64)
        .unwrap_or_else(|| input_tokens.saturating_add(output_tokens));

    let resp_obj = json!({
        "id": resp_id,
        "object": "response",
        "created_at": created_at,
        "status": resp_status,
        "error": Value::Null,
        "incomplete_details": incomplete_details,
        "model": model,
        "output": output_items,
        "usage": {
            "input_tokens": input_tokens,
            "output_tokens": output_tokens,
            "total_tokens": total_tokens,
        }
    });

    serde_json::to_vec(&resp_obj)
        .map_err(|e| format!("failed to serialize OpenAI Responses response: {e}"))
}

#[derive(Debug, Clone)]
struct OpenToolState {
    output_index: usize,
    item_id: String,
    call_id: String,
    name: String,
    arguments: String,
}

/// Stateful per-request streaming translator that converts canonical OpenAI
/// `chat.completion.chunk` SSE frames into spec-compliant OpenAI Responses SSE frames
/// (`response.created`, `response.in_progress`, `response.output_item.added`,
/// `response.content_part.added`, `response.output_text.delta`, `response.output_text.done`,
/// `response.content_part.done`, `response.function_call_arguments.delta`,
/// `response.function_call_arguments.done`, `response.output_item.done`,
/// `response.completed` / `response.incomplete`).
#[derive(Debug, Clone)]
pub struct ChatToResponsesSseTranslator {
    parser: SseParser,
    response_id: String,
    model: String,
    created_at: u64,
    sequence_number: u64,
    started: bool,
    finished: bool,
    next_output_index: usize,
    message_output_index: Option<usize>,
    message_item_id: Option<String>,
    message_text: String,
    message_closed: bool,
    /// Maps Chat Completions `tool_calls[].index` -> tracked tool state.
    tools_by_tc_index: HashMap<usize, OpenToolState>,
    completed_items: BTreeMap<usize, Value>,
    finish_reason: Option<String>,
    input_tokens: u64,
    output_tokens: u64,
    total_tokens: Option<u64>,
}

impl ChatToResponsesSseTranslator {
    pub fn new(fallback_model: impl Into<String>) -> Self {
        Self {
            parser: SseParser::new(),
            response_id: "resp_shunt".to_owned(),
            model: fallback_model.into(),
            created_at: unix_timestamp_secs(),
            sequence_number: 0,
            started: false,
            finished: false,
            next_output_index: 0,
            message_output_index: None,
            message_item_id: None,
            message_text: String::new(),
            message_closed: false,
            tools_by_tc_index: HashMap::new(),
            completed_items: BTreeMap::new(),
            finish_reason: None,
            input_tokens: 0,
            output_tokens: 0,
            total_tokens: None,
        }
    }

    /// Consumes a raw chunk of canonical OpenAI Chat SSE bytes and emits OpenAI Responses SSE bytes.
    pub fn push_chunk(&mut self, chunk: &[u8]) -> Bytes {
        let events = self.parser.push(chunk);
        self.translate_events(events)
    }

    /// Flushes any trailing buffered SSE frame and emits terminal `response.completed` /
    /// `response.incomplete` event once if the stream started.
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

    fn next_seq(&mut self) -> u64 {
        let s = self.sequence_number;
        self.sequence_number += 1;
        s
    }

    fn translate_events(&mut self, events: Vec<SseEvent>) -> Bytes {
        if events.is_empty() {
            return Bytes::new();
        }
        let mut out = Vec::with_capacity(events.len() * 320);
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

        if let Some(err_obj) = payload.get("error") {
            let seq = self.next_seq();
            let code = err_obj.get("code").cloned().unwrap_or(Value::Null);
            let msg = err_obj
                .get("message")
                .and_then(Value::as_str)
                .unwrap_or("upstream stream error");
            write_named_sse_json(
                out,
                "error",
                &json!({
                    "type": "error",
                    "sequence_number": seq,
                    "code": code,
                    "message": msg,
                    "param": Value::Null,
                }),
            );
            return;
        }

        if let Some(raw_id) = payload.get("id").and_then(Value::as_str)
            && !raw_id.is_empty()
        {
            self.response_id = format_response_id(raw_id);
        }
        if let Some(m) = payload.get("model").and_then(Value::as_str)
            && !m.is_empty()
        {
            self.model = m.to_owned();
        }
        if let Some(c) = payload.get("created").and_then(Value::as_u64) {
            self.created_at = c;
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
            if let Some(t) = u.get("total_tokens").and_then(Value::as_u64) {
                self.total_tokens = Some(t);
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
                    let (output_index, item_id) = self.ensure_message_item(out);
                    self.message_text.push_str(text);
                    let seq = self.next_seq();
                    write_named_sse_json(
                        out,
                        "response.output_text.delta",
                        &json!({
                            "type": "response.output_text.delta",
                            "sequence_number": seq,
                            "item_id": item_id,
                            "output_index": output_index,
                            "content_index": 0,
                            "delta": text,
                        }),
                    );
                }

                if let Some(tool_calls) = delta.get("tool_calls").and_then(Value::as_array) {
                    // Close open message text item before emitting tool items.
                    self.close_message_item(out);

                    for tc in tool_calls {
                        let tc_index =
                            tc.get("index").and_then(Value::as_u64).unwrap_or(0) as usize;

                        if !self.tools_by_tc_index.contains_key(&tc_index) {
                            let output_index = self.next_output_index;
                            self.next_output_index += 1;
                            let suffix = id_suffix(&self.response_id).to_owned();
                            let item_id = format!("fc_{output_index}_{suffix}");
                            let call_id = tc
                                .get("id")
                                .and_then(Value::as_str)
                                .filter(|s| !s.is_empty())
                                .map(str::to_owned)
                                .unwrap_or_else(|| format!("call_{tc_index}"));
                            let name = tc
                                .get("function")
                                .and_then(|f| f.get("name"))
                                .and_then(Value::as_str)
                                .unwrap_or("")
                                .to_owned();

                            let seq = self.next_seq();
                            write_named_sse_json(
                                out,
                                "response.output_item.added",
                                &json!({
                                    "type": "response.output_item.added",
                                    "sequence_number": seq,
                                    "output_index": output_index,
                                    "item": {
                                        "id": item_id,
                                        "type": "function_call",
                                        "status": "in_progress",
                                        "call_id": call_id,
                                        "name": name,
                                        "arguments": "",
                                    }
                                }),
                            );

                            self.tools_by_tc_index.insert(
                                tc_index,
                                OpenToolState {
                                    output_index,
                                    item_id,
                                    call_id,
                                    name,
                                    arguments: String::new(),
                                },
                            );
                        }

                        if let Some(partial) = tc
                            .get("function")
                            .and_then(|f| f.get("arguments"))
                            .and_then(Value::as_str)
                            && !partial.is_empty()
                        {
                            let (item_id, output_index) = {
                                let st = self.tools_by_tc_index.get_mut(&tc_index).unwrap();
                                st.arguments.push_str(partial);
                                (st.item_id.clone(), st.output_index)
                            };
                            let seq = self.next_seq();
                            write_named_sse_json(
                                out,
                                "response.function_call_arguments.delta",
                                &json!({
                                    "type": "response.function_call_arguments.delta",
                                    "sequence_number": seq,
                                    "item_id": item_id,
                                    "output_index": output_index,
                                    "delta": partial,
                                }),
                            );
                        }
                    }
                }
            }

            if let Some(fr) = choice.get("finish_reason").and_then(Value::as_str) {
                self.finish_reason = Some(fr.to_owned());
            }
        }
    }

    fn ensure_started(&mut self, out: &mut Vec<u8>) {
        if self.started {
            return;
        }
        self.started = true;
        let base_resp = json!({
            "id": self.response_id,
            "object": "response",
            "created_at": self.created_at,
            "status": "in_progress",
            "error": Value::Null,
            "incomplete_details": Value::Null,
            "model": self.model,
            "output": [],
            "usage": Value::Null,
        });

        let seq0 = self.next_seq();
        write_named_sse_json(
            out,
            "response.created",
            &json!({
                "type": "response.created",
                "sequence_number": seq0,
                "response": base_resp,
            }),
        );
        let seq1 = self.next_seq();
        write_named_sse_json(
            out,
            "response.in_progress",
            &json!({
                "type": "response.in_progress",
                "sequence_number": seq1,
                "response": base_resp,
            }),
        );
    }

    fn ensure_message_item(&mut self, out: &mut Vec<u8>) -> (usize, String) {
        if let (Some(idx), Some(id)) = (self.message_output_index, &self.message_item_id) {
            return (idx, id.clone());
        }
        let idx = self.next_output_index;
        self.next_output_index += 1;
        let id = format!("msg_{}", id_suffix(&self.response_id));
        self.message_output_index = Some(idx);
        self.message_item_id = Some(id.clone());

        let seq_item = self.next_seq();
        write_named_sse_json(
            out,
            "response.output_item.added",
            &json!({
                "type": "response.output_item.added",
                "sequence_number": seq_item,
                "output_index": idx,
                "item": {
                    "id": id,
                    "type": "message",
                    "status": "in_progress",
                    "role": "assistant",
                    "content": [],
                }
            }),
        );

        let seq_part = self.next_seq();
        write_named_sse_json(
            out,
            "response.content_part.added",
            &json!({
                "type": "response.content_part.added",
                "sequence_number": seq_part,
                "item_id": id,
                "output_index": idx,
                "content_index": 0,
                "part": {
                    "type": "output_text",
                    "text": "",
                    "annotations": [],
                }
            }),
        );

        (idx, id)
    }

    fn close_message_item(&mut self, out: &mut Vec<u8>) {
        if self.message_closed {
            return;
        }
        let (Some(output_index), Some(item_id)) =
            (self.message_output_index, self.message_item_id.clone())
        else {
            return;
        };
        self.message_closed = true;

        let seq_txt = self.next_seq();
        write_named_sse_json(
            out,
            "response.output_text.done",
            &json!({
                "type": "response.output_text.done",
                "sequence_number": seq_txt,
                "item_id": item_id,
                "output_index": output_index,
                "content_index": 0,
                "text": self.message_text,
            }),
        );

        let part = json!({
            "type": "output_text",
            "text": self.message_text,
            "annotations": [],
        });

        let seq_part = self.next_seq();
        write_named_sse_json(
            out,
            "response.content_part.done",
            &json!({
                "type": "response.content_part.done",
                "sequence_number": seq_part,
                "item_id": item_id,
                "output_index": output_index,
                "content_index": 0,
                "part": part,
            }),
        );

        let completed_item = json!({
            "id": item_id,
            "type": "message",
            "status": "completed",
            "role": "assistant",
            "content": [part],
        });

        let seq_done = self.next_seq();
        write_named_sse_json(
            out,
            "response.output_item.done",
            &json!({
                "type": "response.output_item.done",
                "sequence_number": seq_done,
                "output_index": output_index,
                "item": completed_item,
            }),
        );

        self.completed_items.insert(output_index, completed_item);
    }

    fn finalize(&mut self, out: &mut Vec<u8>) {
        if self.finished {
            return;
        }
        self.finished = true;

        self.close_message_item(out);

        // Close all function call items in deterministic output_index order.
        let mut tools: Vec<OpenToolState> =
            self.tools_by_tc_index.drain().map(|(_, v)| v).collect();
        tools.sort_by_key(|t| t.output_index);
        for tool in tools {
            let seq_args = self.next_seq();
            write_named_sse_json(
                out,
                "response.function_call_arguments.done",
                &json!({
                    "type": "response.function_call_arguments.done",
                    "sequence_number": seq_args,
                    "item_id": tool.item_id,
                    "output_index": tool.output_index,
                    "arguments": tool.arguments,
                }),
            );

            let completed_item = json!({
                "id": tool.item_id,
                "type": "function_call",
                "status": "completed",
                "call_id": tool.call_id,
                "name": tool.name,
                "arguments": tool.arguments,
            });

            let seq_done = self.next_seq();
            write_named_sse_json(
                out,
                "response.output_item.done",
                &json!({
                    "type": "response.output_item.done",
                    "sequence_number": seq_done,
                    "output_index": tool.output_index,
                    "item": completed_item,
                }),
            );

            self.completed_items
                .insert(tool.output_index, completed_item);
        }

        let output_items: Vec<Value> = self.completed_items.values().cloned().collect();
        let total = self
            .total_tokens
            .unwrap_or_else(|| self.input_tokens.saturating_add(self.output_tokens));

        let is_incomplete = self.finish_reason.as_deref() == Some("length");
        let (event_name, status_str, incomplete_details) = if is_incomplete {
            (
                "response.incomplete",
                "incomplete",
                json!({ "reason": "max_output_tokens" }),
            )
        } else {
            ("response.completed", "completed", Value::Null)
        };

        let seq_final = self.next_seq();
        write_named_sse_json(
            out,
            event_name,
            &json!({
                "type": event_name,
                "sequence_number": seq_final,
                "response": {
                    "id": self.response_id,
                    "object": "response",
                    "created_at": self.created_at,
                    "status": status_str,
                    "error": Value::Null,
                    "incomplete_details": incomplete_details,
                    "model": self.model,
                    "output": output_items,
                    "usage": {
                        "input_tokens": self.input_tokens,
                        "output_tokens": self.output_tokens,
                        "total_tokens": total,
                    }
                }
            }),
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rewrite_responses_request_is_zero_copy_when_unchanged() {
        let body = br#"{"model":"gpt-4o","input":"hello"}"#;
        assert!(
            rewrite_openai_responses_request(body, "gpt-4o")
                .unwrap()
                .is_none()
        );

        let rewritten = rewrite_openai_responses_request(body, "gpt-4o-mini")
            .unwrap()
            .unwrap();
        let v: Value = serde_json::from_slice(&rewritten).unwrap();
        assert_eq!(v["model"], "gpt-4o-mini");
        assert_eq!(v["input"], "hello");
    }

    #[test]
    fn responses_request_translates_instructions_items_tools_and_structured_format() {
        let req = json!({
            "model": "smart",
            "instructions": "Be brief",
            "max_output_tokens": 256,
            "stream": true,
            "temperature": 0.1,
            "tools": [{
                "type": "function",
                "name": "lookup",
                "description": "Lookup record",
                "parameters": { "type": "object", "properties": { "id": { "type": "string" } } }
            }],
            "tool_choice": { "type": "function", "name": "lookup" },
            "text": {
                "format": {
                    "type": "json_schema",
                    "name": "answer",
                    "strict": true,
                    "schema": { "type": "object" }
                }
            },
            "input": [
                {
                    "type": "message",
                    "role": "user",
                    "content": [
                        { "type": "input_text", "text": "Check this" },
                        { "type": "input_image", "image_url": "https://example.com/a.png" }
                    ]
                },
                {
                    "type": "function_call",
                    "call_id": "call_1",
                    "name": "lookup",
                    "arguments": "{\"id\":\"7\"}"
                },
                {
                    "type": "function_call_output",
                    "call_id": "call_1",
                    "output": "{\"ok\":true}"
                }
            ]
        });

        let out_bytes =
            responses_to_chat_request(&serde_json::to_vec(&req).unwrap(), "claude-sonnet").unwrap();
        let out: Value = serde_json::from_slice(&out_bytes).unwrap();

        assert_eq!(out["model"], "claude-sonnet");
        assert_eq!(out["max_tokens"], 256);
        assert_eq!(out["stream"], true);
        assert_eq!(out["tools"][0]["function"]["name"], "lookup");
        assert_eq!(out["tool_choice"]["function"]["name"], "lookup");
        assert_eq!(out["response_format"]["type"], "json_schema");
        assert_eq!(out["response_format"]["json_schema"]["name"], "answer");

        let msgs = out["messages"].as_array().unwrap();
        assert_eq!(msgs.len(), 4);
        assert_eq!(msgs[0]["role"], "system");
        assert_eq!(msgs[0]["content"], "Be brief");
        assert_eq!(msgs[1]["role"], "user");
        assert_eq!(
            msgs[1]["content"][1]["image_url"]["url"],
            "https://example.com/a.png"
        );
        assert_eq!(msgs[2]["role"], "assistant");
        assert_eq!(msgs[2]["tool_calls"][0]["id"], "call_1");
        assert_eq!(msgs[3]["role"], "tool");
        assert_eq!(msgs[3]["tool_call_id"], "call_1");
        assert_eq!(msgs[3]["content"], "{\"ok\":true}");
    }

    #[test]
    fn chat_json_translates_to_responses_json() {
        let chat = json!({
            "id": "chatcmpl-xyz",
            "object": "chat.completion",
            "created": 1700000000,
            "model": "claude-3-5-sonnet-20241022",
            "choices": [{
                "index": 0,
                "message": {
                    "role": "assistant",
                    "content": "Done!",
                    "tool_calls": [{
                        "id": "call_77",
                        "type": "function",
                        "function": { "name": "ping", "arguments": "{}" }
                    }]
                },
                "finish_reason": "tool_calls"
            }],
            "usage": { "prompt_tokens": 15, "completion_tokens": 9, "total_tokens": 24 }
        });

        let out_bytes =
            chat_to_responses_response(&serde_json::to_vec(&chat).unwrap(), StatusCode::OK, "m")
                .unwrap();
        let out: Value = serde_json::from_slice(&out_bytes).unwrap();
        assert_eq!(out["id"], "resp_xyz");
        assert_eq!(out["object"], "response");
        assert_eq!(out["status"], "completed");
        assert_eq!(out["output"][0]["type"], "message");
        assert_eq!(out["output"][0]["content"][0]["text"], "Done!");
        assert_eq!(out["output"][1]["type"], "function_call");
        assert_eq!(out["output"][1]["call_id"], "call_77");
        assert_eq!(out["usage"]["input_tokens"], 15);
        assert_eq!(out["usage"]["output_tokens"], 9);
        assert_eq!(out["usage"]["total_tokens"], 24);
    }

    #[test]
    fn chat_sse_translates_to_responses_sse_with_monotonic_sequence() {
        let stream = concat!(
            "data: {\"id\":\"chatcmpl-r1\",\"object\":\"chat.completion.chunk\",\"created\":1700000001,\"model\":\"gemini-2.5-flash\",\"choices\":[{\"index\":0,\"delta\":{\"role\":\"assistant\",\"content\":\"Hello \"},\"finish_reason\":null}]}\n\n",
            "data: {\"id\":\"chatcmpl-r1\",\"object\":\"chat.completion.chunk\",\"created\":1700000001,\"model\":\"gemini-2.5-flash\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"world\"},\"finish_reason\":null}]}\n\n",
            "data: {\"id\":\"chatcmpl-r1\",\"object\":\"chat.completion.chunk\",\"created\":1700000001,\"model\":\"gemini-2.5-flash\",\"choices\":[{\"index\":0,\"delta\":{},\"finish_reason\":\"stop\"}]}\n\n",
            "data: {\"id\":\"chatcmpl-r1\",\"object\":\"chat.completion.chunk\",\"created\":1700000001,\"model\":\"gemini-2.5-flash\",\"choices\":[],\"usage\":{\"prompt_tokens\":7,\"completion_tokens\":3,\"total_tokens\":10}}\n\n",
            "data: [DONE]\n\n"
        );

        let mut tr = ChatToResponsesSseTranslator::new("fallback");
        let mut out = Vec::new();
        for chunk in stream.as_bytes().chunks(11) {
            out.extend_from_slice(&tr.push_chunk(chunk));
        }
        out.extend_from_slice(&tr.finish());

        let mut parser = SseParser::new();
        let mut events = parser.push(&out);
        events.extend(parser.finish());

        let names: Vec<&str> = events.iter().filter_map(|e| e.event.as_deref()).collect();
        assert_eq!(
            names,
            vec![
                "response.created",
                "response.in_progress",
                "response.output_item.added",
                "response.content_part.added",
                "response.output_text.delta",
                "response.output_text.delta",
                "response.output_text.done",
                "response.content_part.done",
                "response.output_item.done",
                "response.completed",
            ]
        );

        // Verify strictly monotonic sequence_number starting at 0.
        for (idx, ev) in events.iter().enumerate() {
            let v: Value = serde_json::from_str(&ev.data).unwrap();
            assert_eq!(v["sequence_number"].as_u64(), Some(idx as u64));
        }

        let completed: Value = serde_json::from_str(&events.last().unwrap().data).unwrap();
        assert_eq!(
            completed["response"]["output"][0]["content"][0]["text"],
            "Hello world"
        );
        assert_eq!(completed["response"]["usage"]["total_tokens"], 10);
    }
}
