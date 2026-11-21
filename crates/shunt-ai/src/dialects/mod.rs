//! Upstream protocol dialect translators (`gemini`, `bedrock`).

pub mod bedrock;
pub mod gemini;

use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::{Map, Value};

pub(crate) fn unix_timestamp_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

pub(crate) fn format_chatcmpl_id(raw_id: &str) -> String {
    if raw_id.starts_with("chatcmpl-") {
        raw_id.to_owned()
    } else {
        format!("chatcmpl-{raw_id}")
    }
}

pub(crate) fn write_sse_json(out: &mut Vec<u8>, val: &Value) {
    out.extend_from_slice(b"data: ");
    if let Ok(encoded) = serde_json::to_vec(val) {
        out.extend_from_slice(&encoded);
    }
    out.extend_from_slice(b"\n\n");
}

pub(crate) fn emit_openai_chunk(
    out: &mut Vec<u8>,
    id: &str,
    created: u64,
    model: &str,
    choices: Value,
    usage: Option<Value>,
) {
    let mut obj = Map::new();
    obj.insert("id".to_owned(), Value::String(id.to_owned()));
    obj.insert(
        "object".to_owned(),
        Value::String("chat.completion.chunk".to_owned()),
    );
    obj.insert("created".to_owned(), Value::Number(created.into()));
    obj.insert("model".to_owned(), Value::String(model.to_owned()));
    obj.insert("choices".to_owned(), choices);
    if let Some(u) = usage {
        obj.insert("usage".to_owned(), u);
    }
    write_sse_json(out, &Value::Object(obj));
}

pub(crate) fn extract_text_content(content: Option<&Value>) -> String {
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
