use serde_json::Value;

use crate::types::AiEndpointKind;

/// Result of fast local pre-flight token estimation on an incoming AI JSON request body.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TokenEstimate {
    /// Estimated prompt/input tokens (>= 1 for any non-empty request).
    pub input_tokens: u64,
    /// Optional client-requested output cap (`max_tokens` / `max_completion_tokens` / `max_output_tokens`).
    pub requested_max_output: Option<u64>,
}

const IMAGE_PART_TOKENS: u64 = 85;
const PER_MESSAGE_OVERHEAD: u64 = 4;
const REPLY_PRIMING_TOKENS: u64 = 3;

/// Fast, deterministic, zero-dependency token estimator calibrated to modern BPE tokenizers.
///
/// - ASCII characters: ~4 bytes per token (`ceil(ascii_bytes / 4)`).
/// - Non-ASCII Unicode characters (e.g., CJK, emoji, accented scripts): ~1 token per char.
/// - Always monotonic and panic-free on arbitrary input.
pub fn estimate_text_tokens(text: &str) -> u64 {
    if text.is_empty() {
        return 0;
    }
    let mut ascii_bytes = 0u64;
    let mut non_ascii_chars = 0u64;
    for ch in text.chars() {
        if ch.is_ascii() {
            ascii_bytes += 1;
        } else {
            non_ascii_chars += 1;
        }
    }
    let ascii_toks = ascii_bytes.div_ceil(4);
    ascii_toks.saturating_add(non_ascii_chars).max(1)
}

/// Estimates prompt tokens (and extracts any requested max output tokens) from an incoming
/// AI request body across OpenAI Chat Completions, Anthropic Messages, OpenAI Responses,
/// and OpenAI Embeddings payloads.
///
/// Never panics on malformed or arbitrary bytes; falls back to raw byte estimation if JSON
/// parsing fails.
pub fn estimate_request_tokens(endpoint: AiEndpointKind, body: &[u8]) -> TokenEstimate {
    if body.is_empty() {
        return TokenEstimate {
            input_tokens: 1,
            requested_max_output: None,
        };
    }

    let Ok(val) = serde_json::from_slice::<Value>(body) else {
        return TokenEstimate {
            input_tokens: (body.len() as u64).div_ceil(4).max(1),
            requested_max_output: None,
        };
    };

    let requested_max_output = val
        .get("max_completion_tokens")
        .or_else(|| val.get("max_output_tokens"))
        .or_else(|| val.get("max_tokens"))
        .and_then(Value::as_u64);

    let input_tokens = match endpoint {
        AiEndpointKind::Embeddings => estimate_embeddings_input(&val),
        AiEndpointKind::OpenAiResponses => estimate_responses_input(&val),
        AiEndpointKind::AnthropicMessages | AiEndpointKind::AnthropicCountTokens => {
            estimate_anthropic_input(&val)
        }
        AiEndpointKind::ChatCompletions
        | AiEndpointKind::ModelsList
        | AiEndpointKind::ModelRetrieve => estimate_chat_input(&val),
    };

    TokenEstimate {
        input_tokens: input_tokens.max(1),
        requested_max_output,
    }
}

fn estimate_chat_input(val: &Value) -> u64 {
    let mut total = REPLY_PRIMING_TOKENS;

    if let Some(messages) = val.get("messages").and_then(Value::as_array) {
        for msg in messages {
            total = total.saturating_add(PER_MESSAGE_OVERHEAD);
            if let Some(role) = msg.get("role").and_then(Value::as_str) {
                total = total.saturating_add(estimate_text_tokens(role));
            }
            if let Some(name) = msg.get("name").and_then(Value::as_str) {
                total = total.saturating_add(estimate_text_tokens(name));
            }
            if let Some(content) = msg.get("content") {
                total = total.saturating_add(estimate_content_value(content));
            }
            if let Some(tool_calls) = msg.get("tool_calls").and_then(Value::as_array) {
                for tc in tool_calls {
                    total = total.saturating_add(estimate_json_compact(tc));
                }
            }
        }
    }

    if let Some(tools) = val.get("tools").and_then(Value::as_array) {
        for tool in tools {
            total = total.saturating_add(estimate_json_compact(tool));
        }
    }

    total
}

fn estimate_anthropic_input(val: &Value) -> u64 {
    let mut total = REPLY_PRIMING_TOKENS;

    if let Some(system) = val.get("system") {
        total = total
            .saturating_add(PER_MESSAGE_OVERHEAD)
            .saturating_add(estimate_content_value(system));
    }

    if let Some(messages) = val.get("messages").and_then(Value::as_array) {
        for msg in messages {
            total = total.saturating_add(PER_MESSAGE_OVERHEAD);
            if let Some(content) = msg.get("content") {
                total = total.saturating_add(estimate_content_value(content));
            }
        }
    }

    if let Some(tools) = val.get("tools").and_then(Value::as_array) {
        for tool in tools {
            total = total.saturating_add(estimate_json_compact(tool));
        }
    }

    total
}

fn estimate_responses_input(val: &Value) -> u64 {
    let mut total = REPLY_PRIMING_TOKENS;

    if let Some(instructions) = val.get("instructions").and_then(Value::as_str) {
        total = total
            .saturating_add(PER_MESSAGE_OVERHEAD)
            .saturating_add(estimate_text_tokens(instructions));
    }

    if let Some(input) = val.get("input") {
        match input {
            Value::String(s) => {
                total = total
                    .saturating_add(PER_MESSAGE_OVERHEAD)
                    .saturating_add(estimate_text_tokens(s));
            }
            Value::Array(items) => {
                for item in items {
                    total = total.saturating_add(PER_MESSAGE_OVERHEAD);
                    if let Some(content) = item.get("content") {
                        total = total.saturating_add(estimate_content_value(content));
                    } else if let Some(output) = item.get("output") {
                        total = total.saturating_add(estimate_content_value(output));
                    } else if let Some(args) = item.get("arguments").and_then(Value::as_str) {
                        total = total.saturating_add(estimate_text_tokens(args));
                        if let Some(name) = item.get("name").and_then(Value::as_str) {
                            total = total.saturating_add(estimate_text_tokens(name));
                        }
                    } else {
                        total = total.saturating_add(estimate_content_value(item));
                    }
                }
            }
            other => {
                total = total.saturating_add(estimate_content_value(other));
            }
        }
    }

    if let Some(tools) = val.get("tools").and_then(Value::as_array) {
        for tool in tools {
            total = total.saturating_add(estimate_json_compact(tool));
        }
    }

    total
}

fn estimate_embeddings_input(val: &Value) -> u64 {
    let Some(input) = val.get("input") else {
        return 1;
    };
    match input {
        Value::String(s) => estimate_text_tokens(s).max(1),
        Value::Array(items) => {
            if items.is_empty() {
                return 1;
            }
            // Integer token ID array: e.g. [1234, 5678, ...]
            if items.iter().all(Value::is_u64) {
                return (items.len() as u64).max(1);
            }
            let mut sum = 0u64;
            for item in items {
                match item {
                    Value::String(s) => sum = sum.saturating_add(estimate_text_tokens(s)),
                    Value::Array(inner) if inner.iter().all(Value::is_u64) => {
                        sum = sum.saturating_add(inner.len() as u64);
                    }
                    other => sum = sum.saturating_add(estimate_json_compact(other)),
                }
            }
            sum.max(1)
        }
        other => estimate_json_compact(other).max(1),
    }
}

fn estimate_content_value(val: &Value) -> u64 {
    match val {
        Value::String(s) => estimate_text_tokens(s),
        Value::Array(parts) => {
            let mut sum = 0u64;
            for part in parts {
                sum = sum.saturating_add(estimate_content_part(part));
            }
            sum
        }
        Value::Null => 0,
        other => estimate_json_compact(other),
    }
}

fn estimate_content_part(part: &Value) -> u64 {
    match part {
        Value::String(s) => estimate_text_tokens(s),
        Value::Object(obj) => {
            let ty = obj.get("type").and_then(Value::as_str).unwrap_or("");
            match ty {
                "text" | "input_text" | "output_text" => obj
                    .get("text")
                    .and_then(Value::as_str)
                    .map(estimate_text_tokens)
                    .unwrap_or(0),
                "refusal" => obj
                    .get("refusal")
                    .and_then(Value::as_str)
                    .map(estimate_text_tokens)
                    .unwrap_or(0),
                "image" | "image_url" | "input_image" => IMAGE_PART_TOKENS,
                "tool_use" => {
                    let name = obj
                        .get("name")
                        .and_then(Value::as_str)
                        .map(estimate_text_tokens)
                        .unwrap_or(0);
                    let input = obj.get("input").map(estimate_json_compact).unwrap_or(0);
                    name.saturating_add(input).saturating_add(4)
                }
                "tool_result" => obj
                    .get("content")
                    .map(estimate_content_value)
                    .unwrap_or(0)
                    .saturating_add(4),
                _ => estimate_json_compact(part),
            }
        }
        other => estimate_json_compact(other),
    }
}

fn estimate_json_compact(val: &Value) -> u64 {
    serde_json::to_string(val)
        .map(|s| estimate_text_tokens(&s))
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn estimates_text_and_cjk_monotonically() {
        assert_eq!(estimate_text_tokens(""), 0);
        assert_eq!(estimate_text_tokens("hi"), 1);
        assert!(estimate_text_tokens("hello world, how are you today?") >= 6);
        assert!(estimate_text_tokens("你好世界") >= 4);
    }

    #[test]
    fn estimates_all_endpoints_and_max_output() {
        let chat = br#"{"model":"gpt-4o","max_tokens":512,"messages":[{"role":"user","content":"Hello world from Shunt gateway!"}]}"#;
        let est = estimate_request_tokens(AiEndpointKind::ChatCompletions, chat);
        assert!(est.input_tokens >= 10);
        assert_eq!(est.requested_max_output, Some(512));

        let anth = br#"{"model":"claude-sonnet","max_tokens":256,"system":"Be brief.","messages":[{"role":"user","content":[{"type":"text","text":"Describe this image"},{"type":"image","source":{"type":"base64","data":"AAAA"}}]}]}"#;
        let anth_est = estimate_request_tokens(AiEndpointKind::AnthropicMessages, anth);
        assert!(anth_est.input_tokens >= IMAGE_PART_TOKENS);
        assert_eq!(anth_est.requested_max_output, Some(256));

        let resp = br#"{"model":"gpt-4.1","max_output_tokens":128,"instructions":"Answer cleanly.","input":"What is 2+2?"}"#;
        let resp_est = estimate_request_tokens(AiEndpointKind::OpenAiResponses, resp);
        assert!(resp_est.input_tokens >= 10);
        assert_eq!(resp_est.requested_max_output, Some(128));

        let emb = br#"{"model":"text-embedding-3-small","input":[101, 202, 303, 404]}"#;
        let emb_est = estimate_request_tokens(AiEndpointKind::Embeddings, emb);
        assert_eq!(emb_est.input_tokens, 4);
    }

    #[test]
    fn handles_malformed_json_without_panicking() {
        let est = estimate_request_tokens(AiEndpointKind::ChatCompletions, b"{not valid json");
        assert!(est.input_tokens >= 1);
        assert_eq!(est.requested_max_output, None);
    }
}
