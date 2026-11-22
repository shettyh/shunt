//! AWS Bedrock Converse & ConverseStream dialect translator.
//!
//! Translates OpenAI `/v1/chat/completions` JSON requests into Bedrock Converse JSON,
//! non-streaming Converse JSON back to OpenAI JSON, and binary `application/vnd.amazon.eventstream`
//! `ConverseStream` frames live into OpenAI `chat.completion.chunk` SSE frames.

use std::collections::HashMap;

use serde_json::{Map, Value, json};
use shunt_plugin_sdk::{Bytes, StatusCode};

use crate::aws_eventstream::{AwsEventStreamDecoder, EventStreamMessage};
use crate::dialects::{
    emit_openai_chunk, extract_text_content, unix_timestamp_secs, write_sse_json,
};
use crate::translate::resolve_thinking_budget;
use crate::types::percent_encode_path_segment;

/// Builds the upstream URI path for a Bedrock Converse or ConverseStream request.
pub fn bedrock_converse_path(model: &str, stream: bool) -> String {
    let encoded = percent_encode_path_segment(model);
    if stream {
        format!("/model/{encoded}/converse-stream")
    } else {
        format!("/model/{encoded}/converse")
    }
}

/// Builds the upstream URI path for a Bedrock InvokeModel request (used for embeddings).
pub fn bedrock_invoke_path(model: &str) -> String {
    let encoded = percent_encode_path_segment(model);
    format!("/model/{encoded}/invoke")
}

/// Translates an OpenAI `/v1/chat/completions` JSON request into a Bedrock Converse JSON body.
pub fn openai_to_bedrock_converse_request(body: &[u8]) -> Result<Vec<u8>, String> {
    openai_to_bedrock_converse_request_for_model(body, "")
}

/// Translates an OpenAI `/v1/chat/completions` JSON request into a Bedrock Converse JSON body,
/// adapting model-family specifics (`claude` thinking vs `nova` / generic `reasoning_effort`).
pub fn openai_to_bedrock_converse_request_for_model(
    body: &[u8],
    target_model: &str,
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

    let mut system_blocks: Vec<Value> = Vec::new();
    let mut bedrock_messages: Vec<(String, Vec<Value>)> = Vec::new();

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
                let msg_cached = msg_obj.get("cache_control").is_some_and(|v| !v.is_null());
                match msg_obj.get("content") {
                    Some(Value::Array(parts)) => {
                        for part in parts {
                            if part.get("type").and_then(Value::as_str) == Some("text")
                                && let Some(text) = part.get("text").and_then(Value::as_str)
                                && !text.is_empty()
                            {
                                system_blocks.push(json!({ "text": text }));
                                if part.get("cache_control").is_some_and(|v| !v.is_null())
                                    || msg_cached
                                {
                                    system_blocks
                                        .push(json!({ "cachePoint": { "type": "default" } }));
                                }
                            }
                        }
                    }
                    other => {
                        let text = extract_text_content(other);
                        if !text.is_empty() {
                            system_blocks.push(json!({ "text": text }));
                            if msg_cached {
                                system_blocks.push(json!({ "cachePoint": { "type": "default" } }));
                            }
                        }
                    }
                }
            }
            "assistant" => {
                let mut content = convert_content_to_bedrock_blocks(msg_obj.get("content"));
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
                        content.push(json!({
                            "toolUse": {
                                "toolUseId": id,
                                "name": name,
                                "input": input,
                            }
                        }));
                    }
                }
                if !content.is_empty() {
                    push_bedrock_message(&mut bedrock_messages, "assistant", content);
                }
            }
            "tool" => {
                let tool_use_id = msg_obj
                    .get("tool_call_id")
                    .and_then(Value::as_str)
                    .unwrap_or("");
                let content_str = extract_text_content(msg_obj.get("content"));
                let block = json!({
                    "toolResult": {
                        "toolUseId": tool_use_id,
                        "content": [{ "text": content_str }],
                    }
                });
                push_bedrock_message(&mut bedrock_messages, "user", vec![block]);
            }
            _ => {
                let content = convert_content_to_bedrock_blocks(msg_obj.get("content"));
                if !content.is_empty() {
                    push_bedrock_message(&mut bedrock_messages, "user", content);
                }
            }
        }
    }

    // Structured outputs (`response_format`).
    let mut output_config: Option<Value> = None;
    if let Some(rf) = obj.get("response_format").and_then(Value::as_object) {
        match rf.get("type").and_then(Value::as_str) {
            Some("json_schema") => {
                if let Some(js) = rf.get("json_schema").and_then(Value::as_object)
                    && let Some(schema) = js.get("schema")
                {
                    let name = js
                        .get("name")
                        .and_then(Value::as_str)
                        .filter(|s| !s.is_empty())
                        .unwrap_or("response_schema");
                    let schema_str = serde_json::to_string(schema)
                        .map_err(|e| format!("failed to serialize json_schema: {e}"))?;
                    let mut json_schema_obj = Map::new();
                    json_schema_obj.insert("schema".to_owned(), Value::String(schema_str));
                    json_schema_obj.insert("name".to_owned(), Value::String(name.to_owned()));
                    if let Some(desc) = js.get("description").and_then(Value::as_str) {
                        json_schema_obj
                            .insert("description".to_owned(), Value::String(desc.to_owned()));
                    }
                    output_config = Some(json!({
                        "textFormat": {
                            "type": "json_schema",
                            "structure": {
                                "jsonSchema": Value::Object(json_schema_obj),
                            }
                        }
                    }));
                }
            }
            Some("json_object") => {
                system_blocks.push(json!({ "text": "Respond with a valid JSON object only." }));
            }
            _ => {}
        }
    }

    let formatted_messages: Vec<Value> = bedrock_messages
        .into_iter()
        .map(|(role, content)| json!({ "role": role, "content": content }))
        .collect();

    let mut out = Map::new();
    out.insert("messages".to_owned(), Value::Array(formatted_messages));

    if !system_blocks.is_empty() {
        out.insert("system".to_owned(), Value::Array(system_blocks));
    }

    // Reasoning / extended thinking -> additionalModelRequestFields
    let thinking_intent = resolve_thinking_budget(obj);
    let model_lower = target_model.to_ascii_lowercase();
    let is_claude_model = model_lower.is_empty() || model_lower.contains("claude");
    let claude_thinking_enabled = is_claude_model && matches!(thinking_intent, Some(Some(_)));
    let mut additional_fields = Map::new();

    if let Some(intent) = thinking_intent {
        if is_claude_model {
            match intent {
                Some(budget) => {
                    additional_fields.insert(
                        "thinking".to_owned(),
                        json!({ "type": "enabled", "budget_tokens": budget }),
                    );
                }
                None => {
                    additional_fields.insert("thinking".to_owned(), json!({ "type": "disabled" }));
                }
            }
        } else if model_lower.contains("nova") {
            match intent {
                Some(budget) => {
                    let effort = crate::translate::budget_to_reasoning_effort(budget);
                    additional_fields.insert(
                        "reasoningConfig".to_owned(),
                        json!({ "type": "enabled", "maxReasoningEffort": effort }),
                    );
                }
                None => {
                    additional_fields
                        .insert("reasoningConfig".to_owned(), json!({ "type": "disabled" }));
                }
            }
        } else if let Some(effort) =
            obj.get("reasoning_effort")
                .and_then(Value::as_str)
                .or_else(|| {
                    obj.get("reasoning")
                        .and_then(|r| r.get("effort"))
                        .and_then(Value::as_str)
                })
        {
            additional_fields.insert(
                "reasoning_effort".to_owned(),
                Value::String(effort.to_owned()),
            );
        }
    }

    // inferenceConfig
    let mut inf_cfg = Map::new();
    let mut max_tok_opt = obj
        .get("max_tokens")
        .and_then(Value::as_u64)
        .filter(|&n| n > 0)
        .or_else(|| {
            obj.get("max_completion_tokens")
                .and_then(Value::as_u64)
                .filter(|&n| n > 0)
        });
    if claude_thinking_enabled && let Some(Some(budget)) = thinking_intent {
        let min_required = budget.saturating_add(1_024);
        max_tok_opt = Some(max_tok_opt.unwrap_or(0).max(min_required));
    }
    if let Some(max_tok) = max_tok_opt {
        inf_cfg.insert("maxTokens".to_owned(), Value::Number(max_tok.into()));
    }
    if !claude_thinking_enabled {
        if let Some(temp) = obj.get("temperature").filter(|v| !v.is_null()) {
            inf_cfg.insert("temperature".to_owned(), temp.clone());
        }
        if let Some(top_p) = obj.get("top_p").filter(|v| !v.is_null()) {
            inf_cfg.insert("topP".to_owned(), top_p.clone());
        }
    }
    if let Some(stop) = obj.get("stop") {
        match stop {
            Value::String(s) => {
                inf_cfg.insert(
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
                    inf_cfg.insert("stopSequences".to_owned(), Value::Array(seqs));
                }
            }
            _ => {}
        }
    }
    if !inf_cfg.is_empty() {
        out.insert("inferenceConfig".to_owned(), Value::Object(inf_cfg));
    }
    if !additional_fields.is_empty() {
        out.insert(
            "additionalModelRequestFields".to_owned(),
            Value::Object(additional_fields),
        );
    }
    if let Some(oc) = output_config {
        out.insert("outputConfig".to_owned(), oc);
    }

    // toolConfig
    if let Some(tools) = obj.get("tools").and_then(Value::as_array) {
        let mut converted: Vec<Value> = Vec::new();
        for t in tools {
            let Some(func) = t.get("function") else {
                continue;
            };
            let Some(name) = func.get("name").and_then(Value::as_str) else {
                continue;
            };
            let mut spec = Map::new();
            spec.insert("name".to_owned(), Value::String(name.to_owned()));
            if let Some(desc) = func.get("description").and_then(Value::as_str) {
                spec.insert("description".to_owned(), Value::String(desc.to_owned()));
            }
            let schema = func
                .get("parameters")
                .cloned()
                .unwrap_or_else(|| json!({ "type": "object", "properties": {} }));
            spec.insert("inputSchema".to_owned(), json!({ "json": schema }));
            converted.push(json!({ "toolSpec": Value::Object(spec) }));
            if t.get("cache_control").is_some_and(|v| !v.is_null())
                || func.get("cache_control").is_some_and(|v| !v.is_null())
            {
                converted.push(json!({ "cachePoint": { "type": "default" } }));
            }
        }

        if !converted.is_empty() {
            let mut tool_cfg = Map::new();
            tool_cfg.insert("tools".to_owned(), Value::Array(converted));
            if let Some(tc) = obj.get("tool_choice") {
                match tc {
                    Value::String(s) if s == "auto" => {
                        tool_cfg.insert("toolChoice".to_owned(), json!({ "auto": {} }));
                    }
                    Value::String(s) if s == "required" => {
                        tool_cfg.insert("toolChoice".to_owned(), json!({ "any": {} }));
                    }
                    Value::Object(tc_obj) => {
                        if let Some(name) = tc_obj
                            .get("function")
                            .and_then(|f| f.get("name"))
                            .and_then(Value::as_str)
                        {
                            tool_cfg.insert(
                                "toolChoice".to_owned(),
                                json!({ "tool": { "name": name } }),
                            );
                        }
                    }
                    _ => {}
                }
            }
            out.insert("toolConfig".to_owned(), Value::Object(tool_cfg));
        }
    }

    serde_json::to_vec(&Value::Object(out))
        .map_err(|e| format!("failed to serialize Bedrock Converse request: {e}"))
}

fn push_bedrock_message(
    messages: &mut Vec<(String, Vec<Value>)>,
    role: &str,
    mut content: Vec<Value>,
) {
    if let Some((last_role, last_content)) = messages.last_mut()
        && last_role == role
    {
        last_content.append(&mut content);
        return;
    }
    messages.push((role.to_owned(), content));
}

fn convert_content_to_bedrock_blocks(content: Option<&Value>) -> Vec<Value> {
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
                            if part.get("cache_control").is_some_and(|v| !v.is_null()) {
                                out.push(json!({ "cachePoint": { "type": "default" } }));
                            }
                        }
                    }
                    Some("image_url") => {
                        if let Some(url) = part
                            .get("image_url")
                            .and_then(|u| u.get("url"))
                            .and_then(Value::as_str)
                            && let Some(rest) = url.strip_prefix("data:")
                            && let Some((meta, data)) = rest.split_once(',')
                            && let Some(media_type) = meta.strip_suffix(";base64")
                        {
                            let raw_fmt = media_type
                                .strip_prefix("image/")
                                .unwrap_or("png")
                                .to_ascii_lowercase();
                            let format = match raw_fmt.as_str() {
                                "jpg" => "jpeg",
                                other => other,
                            };
                            out.push(json!({
                                "image": {
                                    "format": format,
                                    "source": { "bytes": data },
                                }
                            }));
                            if part.get("cache_control").is_some_and(|v| !v.is_null()) {
                                out.push(json!({ "cachePoint": { "type": "default" } }));
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

/// Maps Bedrock Converse `stopReason` to OpenAI `finish_reason`.
pub fn map_bedrock_stop_reason(stop_reason: Option<&str>) -> Option<&'static str> {
    match stop_reason {
        Some("end_turn") | Some("stop_sequence") => Some("stop"),
        Some("max_tokens") => Some("length"),
        Some("tool_use") => Some("tool_calls"),
        Some("content_filtered") | Some("guardrail_intervened") => Some("content_filter"),
        Some(_) => Some("stop"),
        None => None,
    }
}

/// Translates a non-streaming Bedrock Converse JSON response (or error JSON) into an
/// OpenAI `/v1/chat/completions` JSON response.
pub fn bedrock_converse_to_openai_response(
    bedrock_body: &[u8],
    status: StatusCode,
    model: &str,
) -> Result<Vec<u8>, String> {
    let val: Value = serde_json::from_slice(bedrock_body)
        .map_err(|e| format!("invalid Bedrock JSON response: {e}"))?;

    if !status.is_success() || (val.get("output").is_none() && val.get("message").is_some()) {
        let msg = val
            .get("message")
            .or_else(|| val.get("Message"))
            .and_then(Value::as_str)
            .unwrap_or("upstream Bedrock provider error");
        let err_type = val
            .get("__type")
            .and_then(Value::as_str)
            .unwrap_or("api_error");
        let openai_err = json!({
            "error": {
                "message": msg,
                "type": err_type,
                "param": Value::Null,
                "code": err_type,
            }
        });
        return serde_json::to_vec(&openai_err)
            .map_err(|e| format!("failed to serialize OpenAI error: {e}"));
    }

    let mut text_parts: Vec<&str> = Vec::new();
    let mut reasoning_parts: Vec<&str> = Vec::new();
    let mut tool_calls: Vec<Value> = Vec::new();

    if let Some(content) = val
        .get("output")
        .and_then(|o| o.get("message"))
        .and_then(|m| m.get("content"))
        .and_then(Value::as_array)
    {
        for block in content {
            if let Some(t) = block.get("text").and_then(Value::as_str) {
                text_parts.push(t);
            }
            if let Some(r) = block
                .get("reasoningContent")
                .and_then(|rc| rc.get("reasoningText"))
                .and_then(|rt| rt.get("text"))
                .and_then(Value::as_str)
                && !r.is_empty()
            {
                reasoning_parts.push(r);
            }
            if let Some(tu) = block.get("toolUse").and_then(Value::as_object) {
                let id = tu.get("toolUseId").and_then(Value::as_str).unwrap_or("");
                let name = tu.get("name").and_then(Value::as_str).unwrap_or("");
                let args_str = tu
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
        }
    }

    let finish_reason =
        map_bedrock_stop_reason(val.get("stopReason").and_then(Value::as_str)).unwrap_or("stop");

    let mut message = Map::new();
    message.insert("role".to_owned(), Value::String("assistant".to_owned()));
    if text_parts.is_empty() && !tool_calls.is_empty() {
        message.insert("content".to_owned(), Value::Null);
    } else {
        message.insert("content".to_owned(), Value::String(text_parts.join("")));
    }
    if !reasoning_parts.is_empty() {
        message.insert(
            "reasoning_content".to_owned(),
            Value::String(reasoning_parts.join("")),
        );
    }
    if !tool_calls.is_empty() {
        message.insert("tool_calls".to_owned(), Value::Array(tool_calls));
    }

    let usage = val.get("usage");
    let raw_input_tokens = usage
        .and_then(|u| u.get("inputTokens"))
        .and_then(Value::as_u64)
        .unwrap_or(0);
    let cache_read_tokens = usage
        .and_then(|u| u.get("cacheReadInputTokens"))
        .and_then(Value::as_u64)
        .unwrap_or(0);
    let cache_write_tokens = usage
        .and_then(|u| u.get("cacheWriteInputTokens"))
        .and_then(Value::as_u64)
        .unwrap_or(0);
    let prompt_tokens = raw_input_tokens
        .saturating_add(cache_read_tokens)
        .saturating_add(cache_write_tokens);
    let output_tokens = usage
        .and_then(|u| u.get("outputTokens"))
        .and_then(Value::as_u64)
        .unwrap_or(0);
    let total_tokens = usage
        .and_then(|u| u.get("totalTokens"))
        .and_then(Value::as_u64)
        .map(|t| t.max(prompt_tokens.saturating_add(output_tokens)))
        .unwrap_or_else(|| prompt_tokens.saturating_add(output_tokens));

    let mut usage_obj = Map::new();
    usage_obj.insert(
        "prompt_tokens".to_owned(),
        Value::Number(prompt_tokens.into()),
    );
    usage_obj.insert(
        "completion_tokens".to_owned(),
        Value::Number(output_tokens.into()),
    );
    usage_obj.insert(
        "total_tokens".to_owned(),
        Value::Number(total_tokens.into()),
    );
    if cache_read_tokens > 0 || cache_write_tokens > 0 {
        let mut details = Map::new();
        if cache_read_tokens > 0 {
            details.insert(
                "cached_tokens".to_owned(),
                Value::Number(cache_read_tokens.into()),
            );
        }
        if cache_write_tokens > 0 {
            details.insert(
                "cache_creation_tokens".to_owned(),
                Value::Number(cache_write_tokens.into()),
            );
        }
        usage_obj.insert("prompt_tokens_details".to_owned(), Value::Object(details));
    }

    let openai_resp = json!({
        "id": format!("chatcmpl-bedrock-{}", unix_timestamp_secs()),
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

/// Stateful per-request streaming translator converting binary Bedrock `ConverseStream`
/// AWS EventStream frames into live OpenAI `chat.completion.chunk` SSE frames.
#[derive(Debug, Clone)]
pub struct BedrockStreamTranslator {
    decoder: AwsEventStreamDecoder,
    id: String,
    model: String,
    created: u64,
    started: bool,
    done_emitted: bool,
    next_tool_call_index: usize,
    block_to_tool_index: HashMap<usize, usize>,
}

impl BedrockStreamTranslator {
    pub fn new(model: impl Into<String>) -> Self {
        let created = unix_timestamp_secs();
        Self {
            decoder: AwsEventStreamDecoder::new(),
            id: format!("chatcmpl-bedrock-{created}"),
            model: model.into(),
            created,
            started: false,
            done_emitted: false,
            next_tool_call_index: 0,
            block_to_tool_index: HashMap::new(),
        }
    }

    /// Consumes arbitrary binary AWS EventStream chunks and emits translated OpenAI SSE bytes.
    pub fn push_chunk(&mut self, chunk: &[u8]) -> Bytes {
        let messages = match self.decoder.push(chunk) {
            Ok(m) => m,
            Err(err) => {
                let mut out = Vec::new();
                write_sse_json(
                    &mut out,
                    &json!({
                        "error": {
                            "message": format!("Bedrock EventStream decode error: {err}"),
                            "type": "stream_decode_error",
                            "param": Value::Null,
                            "code": "eventstream_decode_error",
                        }
                    }),
                );
                return Bytes::from(out);
            }
        };

        if messages.is_empty() {
            return Bytes::new();
        }

        let mut out = Vec::with_capacity(messages.len() * 192);
        for msg in messages {
            self.translate_message(&msg, &mut out);
        }
        Bytes::from(out)
    }

    /// Finalizes the stream and emits `data: [DONE]\n\n` if not already emitted.
    pub fn finish(&mut self) -> Bytes {
        let mut out = Vec::new();
        if self.started && !self.done_emitted {
            out.extend_from_slice(b"data: [DONE]\n\n");
            self.done_emitted = true;
        }
        Bytes::from(out)
    }

    fn ensure_started(&mut self, out: &mut Vec<u8>) {
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
    }

    fn translate_message(&mut self, msg: &EventStreamMessage, out: &mut Vec<u8>) {
        let payload: Value = serde_json::from_slice(&msg.payload).unwrap_or(Value::Null);

        if msg.message_type() == Some("exception") {
            let exc_type = msg.exception_type().unwrap_or("bedrock_exception");
            let err_msg = payload
                .get("message")
                .and_then(Value::as_str)
                .unwrap_or("upstream Bedrock stream exception");
            write_sse_json(
                out,
                &json!({
                    "error": {
                        "message": err_msg,
                        "type": exc_type,
                        "param": Value::Null,
                        "code": exc_type,
                    }
                }),
            );
            return;
        }

        let event_type = msg.event_type().unwrap_or("");
        match event_type {
            "messageStart" => {
                self.ensure_started(out);
            }
            "contentBlockStart" => {
                self.ensure_started(out);
                let block_idx = payload
                    .get("contentBlockIndex")
                    .and_then(Value::as_u64)
                    .unwrap_or(0) as usize;
                if let Some(tu) = payload.get("start").and_then(|s| s.get("toolUse")) {
                    let tool_idx = self.next_tool_call_index;
                    self.next_tool_call_index += 1;
                    self.block_to_tool_index.insert(block_idx, tool_idx);

                    let call_id = tu.get("toolUseId").and_then(Value::as_str).unwrap_or("");
                    let name = tu.get("name").and_then(Value::as_str).unwrap_or("");
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
                                        "arguments": "",
                                    }
                                }]
                            },
                            "finish_reason": Value::Null,
                        }]),
                        None,
                    );
                }
            }
            "contentBlockDelta" => {
                self.ensure_started(out);
                let block_idx = payload
                    .get("contentBlockIndex")
                    .and_then(Value::as_u64)
                    .unwrap_or(0) as usize;
                let Some(delta) = payload.get("delta") else {
                    return;
                };
                if let Some(text) = delta.get("text").and_then(Value::as_str) {
                    emit_openai_chunk(
                        out,
                        &self.id,
                        self.created,
                        &self.model,
                        json!([{
                            "index": 0,
                            "delta": { "content": text },
                            "finish_reason": Value::Null,
                        }]),
                        None,
                    );
                }
                if let Some(reasoning) = delta
                    .get("reasoningContent")
                    .and_then(|rc| rc.get("text"))
                    .and_then(Value::as_str)
                    && !reasoning.is_empty()
                {
                    emit_openai_chunk(
                        out,
                        &self.id,
                        self.created,
                        &self.model,
                        json!([{
                            "index": 0,
                            "delta": { "reasoning_content": reasoning },
                            "finish_reason": Value::Null,
                        }]),
                        None,
                    );
                }
                if let Some(partial) = delta
                    .get("toolUse")
                    .and_then(|tu| tu.get("input"))
                    .and_then(Value::as_str)
                {
                    let tool_idx = *self.block_to_tool_index.get(&block_idx).unwrap_or(&0);
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
            "messageStop" => {
                self.ensure_started(out);
                let stop_reason = payload.get("stopReason").and_then(Value::as_str);
                let finish_reason = map_bedrock_stop_reason(stop_reason).unwrap_or("stop");
                emit_openai_chunk(
                    out,
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
            }
            "metadata" => {
                if let Some(u) = payload.get("usage") {
                    let raw_inp = u.get("inputTokens").and_then(Value::as_u64).unwrap_or(0);
                    let cache_read = u
                        .get("cacheReadInputTokens")
                        .and_then(Value::as_u64)
                        .unwrap_or(0);
                    let cache_write = u
                        .get("cacheWriteInputTokens")
                        .and_then(Value::as_u64)
                        .unwrap_or(0);
                    let inp = raw_inp
                        .saturating_add(cache_read)
                        .saturating_add(cache_write);
                    let out_tok = u.get("outputTokens").and_then(Value::as_u64).unwrap_or(0);
                    let total = u
                        .get("totalTokens")
                        .and_then(Value::as_u64)
                        .map(|t| t.max(inp.saturating_add(out_tok)))
                        .unwrap_or_else(|| inp.saturating_add(out_tok));
                    let mut usage_obj = Map::new();
                    usage_obj.insert("prompt_tokens".to_owned(), Value::Number(inp.into()));
                    usage_obj.insert(
                        "completion_tokens".to_owned(),
                        Value::Number(out_tok.into()),
                    );
                    usage_obj.insert("total_tokens".to_owned(), Value::Number(total.into()));
                    if cache_read > 0 || cache_write > 0 {
                        let mut details = Map::new();
                        if cache_read > 0 {
                            details.insert(
                                "cached_tokens".to_owned(),
                                Value::Number(cache_read.into()),
                            );
                        }
                        if cache_write > 0 {
                            details.insert(
                                "cache_creation_tokens".to_owned(),
                                Value::Number(cache_write.into()),
                            );
                        }
                        usage_obj
                            .insert("prompt_tokens_details".to_owned(), Value::Object(details));
                    }
                    emit_openai_chunk(
                        out,
                        &self.id,
                        self.created,
                        &self.model,
                        json!([]),
                        Some(Value::Object(usage_obj)),
                    );
                }
            }
            "contentBlockStop" => {}
            _ => {}
        }
    }
}

/// Translates an OpenAI `/v1/embeddings` JSON request into an AWS Bedrock InvokeModel
/// embeddings payload (supporting `cohere.embed-*` batch requests and `amazon.titan-embed-*`
/// single-input requests).
pub fn openai_to_bedrock_embeddings_request(
    body: &[u8],
    target_model: &str,
) -> Result<Vec<u8>, String> {
    let val: Value =
        serde_json::from_slice(body).map_err(|e| format!("invalid JSON request body: {e}"))?;
    let obj = val
        .as_object()
        .ok_or_else(|| "request body must be a JSON object".to_owned())?;

    let inputs: Vec<String> = match obj.get("input") {
        Some(Value::String(s)) => vec![s.clone()],
        Some(Value::Array(arr)) if !arr.is_empty() => arr
            .iter()
            .map(|item| match item {
                Value::String(s) => s.clone(),
                other => other.to_string(),
            })
            .collect(),
        _ => {
            return Err(
                "embeddings request must include a non-empty `input` string or array".to_owned(),
            );
        }
    };

    let model_lower = target_model.to_ascii_lowercase();
    if model_lower.contains("cohere.embed") {
        let mut out = Map::new();
        out.insert(
            "texts".to_owned(),
            Value::Array(inputs.into_iter().map(Value::String).collect()),
        );
        let input_type = obj
            .get("input_type")
            .and_then(Value::as_str)
            .unwrap_or("search_document");
        out.insert(
            "input_type".to_owned(),
            Value::String(input_type.to_owned()),
        );
        return serde_json::to_vec(&Value::Object(out))
            .map_err(|e| format!("failed to serialize Bedrock Cohere embeddings request: {e}"));
    }

    // Amazon Titan Embed (v1 / v2) accepts a single `inputText` per InvokeModel call.
    if inputs.len() > 1 {
        return Err(
            "Bedrock Titan Embed models accept a single input per request; use a `cohere.embed-*` model for batch embeddings"
                .to_owned(),
        );
    }
    let mut out = Map::new();
    out.insert(
        "inputText".to_owned(),
        Value::String(inputs.into_iter().next().unwrap_or_default()),
    );
    if let Some(dim) = obj.get("dimensions").and_then(Value::as_u64) {
        out.insert("dimensions".to_owned(), Value::Number(dim.into()));
    }
    if let Some(norm) = obj.get("normalize").and_then(Value::as_bool) {
        out.insert("normalize".to_owned(), Value::Bool(norm));
    }

    serde_json::to_vec(&Value::Object(out))
        .map_err(|e| format!("failed to serialize Bedrock Titan embeddings request: {e}"))
}

/// Translates an AWS Bedrock InvokeModel embeddings JSON response (Amazon Titan Embed or
/// Cohere Embed v3/v4) into an OpenAI `/v1/embeddings` JSON response.
pub fn bedrock_embeddings_to_openai_response(
    bedrock_body: &[u8],
    status: StatusCode,
    model: &str,
) -> Result<Vec<u8>, String> {
    let val: Value = serde_json::from_slice(bedrock_body)
        .map_err(|e| format!("invalid Bedrock embeddings JSON response: {e}"))?;

    if !status.is_success()
        || (val.get("embedding").is_none()
            && val.get("embeddings").is_none()
            && (val.get("message").is_some() || val.get("Message").is_some()))
    {
        let msg = val
            .get("message")
            .or_else(|| val.get("Message"))
            .and_then(Value::as_str)
            .unwrap_or("upstream Bedrock embeddings error");
        let err_type = val
            .get("__type")
            .and_then(Value::as_str)
            .unwrap_or("api_error");
        let openai_err = json!({
            "error": {
                "message": msg,
                "type": err_type,
                "param": Value::Null,
                "code": err_type,
            }
        });
        return serde_json::to_vec(&openai_err)
            .map_err(|e| format!("failed to serialize OpenAI error: {e}"));
    }

    let mut data: Vec<Value> = Vec::new();
    if let Some(vec_vals) = val.get("embedding").and_then(Value::as_array) {
        data.push(json!({
            "object": "embedding",
            "index": 0,
            "embedding": vec_vals,
        }));
    } else if let Some(embs) = val.get("embeddings") {
        let rows_opt = embs
            .as_array()
            .or_else(|| embs.get("float").and_then(Value::as_array));
        if let Some(rows) = rows_opt {
            for (idx, row) in rows.iter().enumerate() {
                data.push(json!({
                    "object": "embedding",
                    "index": idx,
                    "embedding": row,
                }));
            }
        }
    }

    let prompt_tokens = val
        .get("inputTextTokenCount")
        .and_then(Value::as_u64)
        .unwrap_or(0);

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
    use crate::aws_eventstream::encode_eventstream_frame;

    use super::*;

    #[test]
    fn translates_openai_chat_to_bedrock_converse() {
        let req = json!({
            "model": "anthropic.claude-3-5-sonnet-20241022-v2:0",
            "temperature": 0.4,
            "max_tokens": 256,
            "messages": [
                { "role": "system", "content": "Be terse." },
                { "role": "user", "content": "Call tool" },
                {
                    "role": "assistant",
                    "content": "",
                    "tool_calls": [{
                        "id": "tu_1",
                        "type": "function",
                        "function": { "name": "lookup", "arguments": "{\"q\":\"rust\"}" }
                    }]
                },
                { "role": "tool", "tool_call_id": "tu_1", "content": "found" }
            ],
            "tools": [{
                "type": "function",
                "function": {
                    "name": "lookup",
                    "description": "Search",
                    "parameters": { "type": "object", "properties": { "q": { "type": "string" } } }
                }
            }]
        });

        let bytes = openai_to_bedrock_converse_request(&serde_json::to_vec(&req).unwrap()).unwrap();
        let out: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(out["system"][0]["text"], "Be terse.");
        assert_eq!(out["inferenceConfig"]["maxTokens"], 256);
        assert_eq!(
            out["messages"][1]["content"][0]["toolUse"]["toolUseId"],
            "tu_1"
        );
        assert_eq!(
            out["messages"][2]["content"][0]["toolResult"]["toolUseId"],
            "tu_1"
        );
        assert_eq!(out["toolConfig"]["tools"][0]["toolSpec"]["name"], "lookup");
    }

    #[test]
    fn translates_binary_converse_stream_to_openai_sse() {
        let mut wire = Vec::new();
        wire.extend_from_slice(&encode_eventstream_frame(
            &[(":message-type", "event"), (":event-type", "messageStart")],
            br#"{"role":"assistant"}"#,
        ));
        wire.extend_from_slice(&encode_eventstream_frame(
            &[
                (":message-type", "event"),
                (":event-type", "contentBlockDelta"),
            ],
            br#"{"contentBlockIndex":0,"delta":{"text":"Bedrock "}}"#,
        ));
        wire.extend_from_slice(&encode_eventstream_frame(
            &[
                (":message-type", "event"),
                (":event-type", "contentBlockDelta"),
            ],
            br#"{"contentBlockIndex":0,"delta":{"text":"live!"}}"#,
        ));
        wire.extend_from_slice(&encode_eventstream_frame(
            &[(":message-type", "event"), (":event-type", "messageStop")],
            br#"{"stopReason":"end_turn"}"#,
        ));
        wire.extend_from_slice(&encode_eventstream_frame(
            &[(":message-type", "event"), (":event-type", "metadata")],
            br#"{"usage":{"inputTokens":12,"outputTokens":5,"totalTokens":17}}"#,
        ));

        let mut tr = BedrockStreamTranslator::new("anthropic.claude-3-5-sonnet-20241022-v2:0");
        let mut out = Vec::new();
        for chunk in wire.chunks(7) {
            out.extend_from_slice(&tr.push_chunk(chunk));
        }
        out.extend_from_slice(&tr.finish());

        let text = String::from_utf8(out).unwrap();
        assert!(text.contains("Bedrock "));
        assert!(text.contains("live!"));
        assert!(text.contains("\"finish_reason\":\"stop\""));
        assert!(text.contains("\"prompt_tokens\":12"));
        assert!(text.contains("\"completion_tokens\":5"));
        assert!(text.ends_with("data: [DONE]\n\n"));
    }

    #[test]
    fn translates_bedrock_reasoning_cache_points_json_schema_and_embeddings() {
        let req = json!({
            "model": "anthropic.claude-sonnet-4-20250514-v1:0",
            "reasoning_effort": "medium",
            "temperature": 0.5,
            "response_format": {
                "type": "json_schema",
                "json_schema": {
                    "name": "result",
                    "schema": { "type": "object", "properties": { "x": { "type": "number" } } }
                }
            },
            "messages": [
                { "role": "system", "content": "Sys", "cache_control": { "type": "ephemeral" } },
                { "role": "user", "content": [{ "type": "text", "text": "Compute", "cache_control": { "type": "ephemeral" } }] }
            ],
            "tools": [{
                "type": "function",
                "cache_control": { "type": "ephemeral" },
                "function": { "name": "f", "parameters": { "type": "object" } }
            }]
        });

        let out_bytes = openai_to_bedrock_converse_request_for_model(
            &serde_json::to_vec(&req).unwrap(),
            "anthropic.claude-sonnet-4-20250514-v1:0",
        )
        .unwrap();
        let out: Value = serde_json::from_slice(&out_bytes).unwrap();
        assert_eq!(out["system"][1]["cachePoint"]["type"], "default");
        assert_eq!(
            out["messages"][0]["content"][1]["cachePoint"]["type"],
            "default"
        );
        assert_eq!(
            out["toolConfig"]["tools"][1]["cachePoint"]["type"],
            "default"
        );
        assert_eq!(
            out["additionalModelRequestFields"]["thinking"]["type"],
            "enabled"
        );
        assert_eq!(
            out["additionalModelRequestFields"]["thinking"]["budget_tokens"],
            4096
        );
        assert!(out["inferenceConfig"].get("temperature").is_none());
        assert!(out["inferenceConfig"]["maxTokens"].as_u64().unwrap() > 4096);
        assert_eq!(out["outputConfig"]["textFormat"]["type"], "json_schema");
        assert_eq!(
            out["outputConfig"]["textFormat"]["structure"]["jsonSchema"]["name"],
            "result"
        );

        // Bedrock Converse response with reasoningContent & cacheRead/cacheWrite tokens
        let bedrock_resp = json!({
            "output": {
                "message": {
                    "role": "assistant",
                    "content": [
                        { "reasoningContent": { "reasoningText": { "text": "thinking hard" } } },
                        { "text": "{\"x\":42}" }
                    ]
                }
            },
            "stopReason": "end_turn",
            "usage": {
                "inputTokens": 50,
                "cacheReadInputTokens": 200,
                "cacheWriteInputTokens": 100,
                "outputTokens": 20
            }
        });
        let oa_bytes = bedrock_converse_to_openai_response(
            &serde_json::to_vec(&bedrock_resp).unwrap(),
            StatusCode::OK,
            "anthropic.claude-sonnet-4",
        )
        .unwrap();
        let oa: Value = serde_json::from_slice(&oa_bytes).unwrap();
        assert_eq!(
            oa["choices"][0]["message"]["reasoning_content"],
            "thinking hard"
        );
        assert_eq!(oa["usage"]["prompt_tokens"], 350);
        assert_eq!(oa["usage"]["prompt_tokens_details"]["cached_tokens"], 200);
        assert_eq!(
            oa["usage"]["prompt_tokens_details"]["cache_creation_tokens"],
            100
        );

        // Titan Embed single input + response
        let titan_req = openai_to_bedrock_embeddings_request(
            br#"{"model":"amazon.titan-embed-text-v2:0","input":"hello","dimensions":256}"#,
            "amazon.titan-embed-text-v2:0",
        )
        .unwrap();
        let tv: Value = serde_json::from_slice(&titan_req).unwrap();
        assert_eq!(tv["inputText"], "hello");
        assert_eq!(tv["dimensions"], 256);

        let titan_resp = bedrock_embeddings_to_openai_response(
            br#"{"embedding":[0.25,0.75],"inputTextTokenCount":3}"#,
            StatusCode::OK,
            "amazon.titan-embed-text-v2:0",
        )
        .unwrap();
        let trv: Value = serde_json::from_slice(&titan_resp).unwrap();
        assert_eq!(trv["data"][0]["embedding"], json!([0.25, 0.75]));
        assert_eq!(trv["usage"]["prompt_tokens"], 3);

        // Cohere Embed batch input + response
        let cohere_req = openai_to_bedrock_embeddings_request(
            br#"{"model":"cohere.embed-english-v3","input":["a","b"]}"#,
            "cohere.embed-english-v3",
        )
        .unwrap();
        let cv: Value = serde_json::from_slice(&cohere_req).unwrap();
        assert_eq!(cv["texts"], json!(["a", "b"]));

        let cohere_resp = bedrock_embeddings_to_openai_response(
            br#"{"embeddings":{"float":[[0.1,0.2],[0.3,0.4]]}}"#,
            StatusCode::OK,
            "cohere.embed-english-v3",
        )
        .unwrap();
        let crv: Value = serde_json::from_slice(&cohere_resp).unwrap();
        assert_eq!(crv["data"][1]["embedding"], json!([0.3, 0.4]));
    }
}
