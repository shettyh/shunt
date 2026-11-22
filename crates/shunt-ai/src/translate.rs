use std::collections::{BTreeMap, HashMap};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use shunt_plugin_sdk::{Bytes, StatusCode};

use crate::sse::{SseEvent, SseParser};
use crate::types::{ProviderDialect, percent_encode_path_segment};

/// Parameter-dropping policy for `ai-provider-adapter` (LiteLLM-style `drop_params`).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(untagged)]
pub enum DropParamsConfig {
    /// When `true`, strips known unsupported cross-dialect parameters automatically.
    Bool(bool),
    /// Explicit list of top-level JSON parameter names to strip before forwarding/translation.
    List(Vec<String>),
}

impl Default for DropParamsConfig {
    fn default() -> Self {
        Self::Bool(false)
    }
}

impl DropParamsConfig {
    pub fn is_disabled(&self) -> bool {
        match self {
            DropParamsConfig::Bool(b) => !*b,
            DropParamsConfig::List(keys) => keys.is_empty(),
        }
    }
}

/// Maps OpenAI-style `reasoning_effort` strings to canonical thinking token budgets.
pub fn reasoning_effort_to_budget(effort: &str) -> Option<u64> {
    match effort.trim().to_ascii_lowercase().as_str() {
        "none" | "disabled" | "off" => None,
        "minimal" | "low" => Some(1_024),
        "medium" => Some(4_096),
        "high" => Some(16_384),
        "xhigh" | "max" => Some(32_768),
        _ => Some(4_096),
    }
}

/// Maps an explicit thinking token budget to an OpenAI-style `reasoning_effort` tier.
pub const fn budget_to_reasoning_effort(budget: u64) -> &'static str {
    if budget == 0 {
        "none"
    } else if budget <= 2_048 {
        "low"
    } else if budget <= 10_000 {
        "medium"
    } else {
        "high"
    }
}

/// Extracts unified thinking/reasoning intent from a canonical Chat Completions JSON object.
///
/// - `None`: caller did not specify reasoning/thinking.
/// - `Some(None)`: caller explicitly disabled reasoning (`reasoning_effort = "none"` or `thinking.type = "disabled"`).
/// - `Some(Some(budget_tokens))`: caller enabled reasoning with resolved token budget.
pub(crate) fn resolve_thinking_budget(obj: &Map<String, Value>) -> Option<Option<u64>> {
    if let Some(thinking) = obj.get("thinking").and_then(Value::as_object) {
        match thinking.get("type").and_then(Value::as_str) {
            Some("disabled") => return Some(None),
            Some("enabled") => {
                let budget = thinking
                    .get("budget_tokens")
                    .and_then(Value::as_u64)
                    .filter(|&b| b > 0)
                    .unwrap_or(4_096);
                return Some(Some(budget));
            }
            _ => {}
        }
    }

    if let Some(effort) = obj
        .get("reasoning_effort")
        .and_then(Value::as_str)
        .or_else(|| {
            obj.get("reasoning")
                .and_then(|r| r.get("effort"))
                .and_then(Value::as_str)
        })
    {
        return Some(reasoning_effort_to_budget(effort));
    }

    None
}

fn is_openai_reasoning_model(model: &str) -> bool {
    let lower = model.to_ascii_lowercase();
    lower == "o1"
        || lower.starts_with("o1-")
        || lower == "o3"
        || lower.starts_with("o3-")
        || lower.starts_with("o4-")
        || lower.starts_with("gpt-5")
}

/// Recursively strips Anthropic-style `cache_control` keys from `messages[]` and `tools[]`
/// so OpenAI-compatible upstreams do not reject cross-provider requests with `400`.
pub(crate) fn strip_cache_control_from_openai_obj(obj: &mut Map<String, Value>) -> bool {
    let mut changed = false;
    if let Some(Value::Array(messages)) = obj.get_mut("messages") {
        for msg in messages {
            if let Some(m) = msg.as_object_mut() {
                if m.remove("cache_control").is_some() {
                    changed = true;
                }
                if let Some(Value::Array(parts)) = m.get_mut("content") {
                    for part in parts {
                        if let Some(p) = part.as_object_mut()
                            && p.remove("cache_control").is_some()
                        {
                            changed = true;
                        }
                    }
                }
            }
        }
    }
    if let Some(Value::Array(tools)) = obj.get_mut("tools") {
        for tool in tools {
            if let Some(t) = tool.as_object_mut() {
                if t.remove("cache_control").is_some() {
                    changed = true;
                }
                if let Some(f) = t.get_mut("function").and_then(Value::as_object_mut)
                    && f.remove("cache_control").is_some()
                {
                    changed = true;
                }
            }
        }
    }
    changed
}

/// Applies provider/target `default_params`, `override_params`, and `drop_params` to a JSON
/// request body before dialect translation or forwarding.
///
/// Precedence: client body < provider defaults < target defaults < provider overrides < target overrides < drop_params.
/// Returns `Ok(None)` when no transforms are configured or no fields changed (preserving zero-copy).
#[allow(clippy::too_many_arguments)]
pub fn apply_request_param_transforms(
    body: &[u8],
    provider_defaults: &BTreeMap<String, Value>,
    target_defaults: &BTreeMap<String, Value>,
    provider_overrides: &BTreeMap<String, Value>,
    target_overrides: &BTreeMap<String, Value>,
    drop_params: &DropParamsConfig,
    dialect: ProviderDialect,
    target_model: &str,
) -> Result<Option<Vec<u8>>, String> {
    if provider_defaults.is_empty()
        && target_defaults.is_empty()
        && provider_overrides.is_empty()
        && target_overrides.is_empty()
        && drop_params.is_disabled()
    {
        return Ok(None);
    }

    let mut val: Value =
        serde_json::from_slice(body).map_err(|e| format!("invalid JSON request body: {e}"))?;
    let obj = val
        .as_object_mut()
        .ok_or_else(|| "request body must be a JSON object".to_owned())?;

    let mut changed = false;

    // Defaults: target defaults take precedence over provider defaults when client omits key.
    for (k, v) in target_defaults {
        let missing = obj.get(k).is_none_or(Value::is_null);
        if missing {
            obj.insert(k.clone(), v.clone());
            changed = true;
        }
    }
    for (k, v) in provider_defaults {
        let missing = obj.get(k).is_none_or(Value::is_null);
        if missing {
            obj.insert(k.clone(), v.clone());
            changed = true;
        }
    }

    // Overrides: provider overrides first, then target overrides win.
    for (k, v) in provider_overrides {
        if obj.get(k) != Some(v) {
            obj.insert(k.clone(), v.clone());
            changed = true;
        }
    }
    for (k, v) in target_overrides {
        if obj.get(k) != Some(v) {
            obj.insert(k.clone(), v.clone());
            changed = true;
        }
    }

    // Drop unsupported or explicitly stripped parameters.
    match drop_params {
        DropParamsConfig::Bool(false) => {}
        DropParamsConfig::List(keys) => {
            for k in keys {
                if obj.remove(k).is_some() {
                    changed = true;
                }
            }
        }
        DropParamsConfig::Bool(true) => {
            let strip_keys: &[&str] = match dialect {
                ProviderDialect::OpenAiCompatible | ProviderDialect::AzureOpenAi => &[
                    "thinking",
                    "anthropic_version",
                    "top_k",
                    "output_config",
                    "safety_settings",
                    "additionalModelRequestFields",
                ],
                ProviderDialect::Anthropic => &[
                    "frequency_penalty",
                    "presence_penalty",
                    "logprobs",
                    "top_logprobs",
                    "n",
                    "seed",
                    "logit_bias",
                    "parallel_tool_calls",
                    "stream_options",
                    "prediction",
                    "service_tier",
                    "store",
                    "audio",
                    "modalities",
                    "web_search_options",
                ],
                ProviderDialect::Gemini | ProviderDialect::Bedrock => &[
                    "frequency_penalty",
                    "presence_penalty",
                    "logprobs",
                    "top_logprobs",
                    "n",
                    "seed",
                    "logit_bias",
                    "service_tier",
                    "store",
                    "stream_options",
                ],
            };
            for &k in strip_keys {
                if obj.remove(k).is_some() {
                    changed = true;
                }
            }
            if matches!(
                dialect,
                ProviderDialect::OpenAiCompatible | ProviderDialect::AzureOpenAi
            ) {
                if strip_cache_control_from_openai_obj(obj) {
                    changed = true;
                }
                if is_openai_reasoning_model(target_model) {
                    if let Some(mt) = obj.remove("max_tokens") {
                        if !obj.contains_key("max_completion_tokens") {
                            obj.insert("max_completion_tokens".to_owned(), mt);
                        }
                        changed = true;
                    }
                    if obj.remove("temperature").is_some() {
                        changed = true;
                    }
                    if obj.remove("top_p").is_some() {
                        changed = true;
                    }
                }
            }
        }
    }

    if !changed {
        return Ok(None);
    }

    serde_json::to_vec(&val)
        .map(Some)
        .map_err(|e| format!("failed to serialize normalized AI request: {e}"))
}

/// Builds the upstream URI path for Claude on Google Cloud Vertex AI (`rawPredict` / `streamRawPredict`).
pub fn vertex_anthropic_path(project: &str, location: &str, model: &str, stream: bool) -> String {
    let action = if stream {
        "streamRawPredict"
    } else {
        "rawPredict"
    };
    format!(
        "/v1/projects/{}/locations/{}/publishers/anthropic/models/{}:{}",
        percent_encode_path_segment(project),
        percent_encode_path_segment(location),
        percent_encode_path_segment(model),
        action
    )
}

/// Adapts an Anthropic Messages JSON body for Google Cloud Vertex AI:
/// removes `"model"` (encoded in the Vertex URL path) and injects `"anthropic_version"`
/// (defaulting to `"vertex-2023-10-16"`).
pub fn adapt_anthropic_body_for_vertex(
    body: &[u8],
    anthropic_version: Option<&str>,
) -> Result<Vec<u8>, String> {
    let mut val: Value =
        serde_json::from_slice(body).map_err(|e| format!("invalid JSON request body: {e}"))?;
    let obj = val
        .as_object_mut()
        .ok_or_else(|| "request body must be a JSON object".to_owned())?;

    obj.remove("model");
    let ver = match anthropic_version {
        Some(v) if !v.trim().is_empty() && v != "2023-06-01" => v,
        _ => "vertex-2023-10-16",
    };
    obj.insert(
        "anthropic_version".to_owned(),
        Value::String(ver.to_owned()),
    );

    serde_json::to_vec(&val)
        .map_err(|e| format!("failed to serialize Vertex Anthropic request: {e}"))
}

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

    // Strip Anthropic-specific cross-dialect annotations (e.g., `cache_control`, `thinking`)
    // that would trigger 400 errors on OpenAI-compatible upstreams.
    if strip_cache_control_from_openai_obj(obj) {
        changed = true;
    }
    if obj.remove("thinking").is_some() {
        changed = true;
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

    let mut system_blocks: Vec<Value> = Vec::new();
    let mut system_has_cache_control = false;
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
                let msg_cc = msg_obj.get("cache_control").filter(|v| !v.is_null());
                match msg_obj.get("content") {
                    Some(Value::Array(parts)) => {
                        for part in parts {
                            if part.get("type").and_then(Value::as_str) == Some("text")
                                && let Some(text) = part.get("text").and_then(Value::as_str)
                                && !text.is_empty()
                            {
                                let mut blk = Map::new();
                                blk.insert("type".to_owned(), Value::String("text".to_owned()));
                                blk.insert("text".to_owned(), Value::String(text.to_owned()));
                                if let Some(cc) = part
                                    .get("cache_control")
                                    .filter(|v| !v.is_null())
                                    .or(msg_cc)
                                {
                                    blk.insert("cache_control".to_owned(), cc.clone());
                                    system_has_cache_control = true;
                                }
                                system_blocks.push(Value::Object(blk));
                            }
                        }
                    }
                    other => {
                        let text = extract_text_content(other);
                        if !text.is_empty() {
                            let mut blk = Map::new();
                            blk.insert("type".to_owned(), Value::String("text".to_owned()));
                            blk.insert("text".to_owned(), Value::String(text));
                            if let Some(cc) = msg_cc {
                                blk.insert("cache_control".to_owned(), cc.clone());
                                system_has_cache_control = true;
                            }
                            system_blocks.push(Value::Object(blk));
                        }
                    }
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
            // Keep simple single-text messages compact when there's just one text block without cache_control.
            if blocks.len() == 1
                && blocks[0].get("type").and_then(Value::as_str) == Some("text")
                && blocks[0].get("cache_control").is_none()
                && let Some(text) = blocks[0].get("text").and_then(Value::as_str)
            {
                json!({ "role": role, "content": text })
            } else {
                json!({ "role": role, "content": blocks })
            }
        })
        .collect();

    let mut max_tokens = obj
        .get("max_tokens")
        .and_then(Value::as_u64)
        .filter(|&n| n > 0)
        .or_else(|| {
            obj.get("max_completion_tokens")
                .and_then(Value::as_u64)
                .filter(|&n| n > 0)
        })
        .unwrap_or_else(|| default_max_tokens.max(1));

    // Reasoning / extended thinking translation.
    let thinking_intent = resolve_thinking_budget(obj);
    let thinking_enabled = matches!(thinking_intent, Some(Some(_)));
    if let Some(Some(budget)) = thinking_intent
        && max_tokens <= budget
    {
        max_tokens = budget.saturating_add(1_024);
    }

    // Structured outputs (`response_format`).
    let mut output_config: Option<Value> = None;
    if let Some(rf) = obj.get("response_format").and_then(Value::as_object) {
        match rf.get("type").and_then(Value::as_str) {
            Some("json_schema") => {
                if let Some(schema) = rf
                    .get("json_schema")
                    .and_then(|js| js.get("schema"))
                    .or_else(|| rf.get("schema"))
                {
                    output_config = Some(json!({
                        "format": {
                            "type": "json_schema",
                            "schema": schema,
                        }
                    }));
                }
            }
            Some("json_object") => {
                system_blocks.push(json!({
                    "type": "text",
                    "text": "Respond with a valid JSON object only."
                }));
            }
            _ => {}
        }
    } else if let Some(oc) = obj.get("output_config").filter(|v| v.is_object()) {
        output_config = Some(oc.clone());
    }

    let mut out = Map::new();
    out.insert("model".to_owned(), Value::String(target_model.to_owned()));
    out.insert("max_tokens".to_owned(), Value::Number(max_tokens.into()));
    out.insert("messages".to_owned(), Value::Array(formatted_messages));

    if !system_blocks.is_empty() {
        if system_has_cache_control {
            out.insert("system".to_owned(), Value::Array(system_blocks));
        } else {
            let joined = system_blocks
                .iter()
                .filter_map(|b| b.get("text").and_then(Value::as_str))
                .collect::<Vec<_>>()
                .join("\n\n");
            if !joined.is_empty() {
                out.insert("system".to_owned(), Value::String(joined));
            }
        }
    }

    if let Some(intent) = thinking_intent {
        match intent {
            Some(budget) => {
                out.insert(
                    "thinking".to_owned(),
                    json!({ "type": "enabled", "budget_tokens": budget }),
                );
            }
            None => {
                out.insert("thinking".to_owned(), json!({ "type": "disabled" }));
            }
        }
    }

    if let Some(oc) = output_config {
        out.insert("output_config".to_owned(), oc);
    }

    if let Some(stream) = obj.get("stream").and_then(Value::as_bool)
        && stream
    {
        out.insert("stream".to_owned(), Value::Bool(true));
    }

    // Anthropic rejects non-default temperature/top_p when extended thinking is enabled.
    if !thinking_enabled {
        if let Some(temp) = obj.get("temperature").filter(|v| !v.is_null()) {
            out.insert("temperature".to_owned(), temp.clone());
        }
        if let Some(top_p) = obj.get("top_p").filter(|v| !v.is_null()) {
            out.insert("top_p".to_owned(), top_p.clone());
        }
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
                if let Some(cc) = t
                    .get("cache_control")
                    .or_else(|| func.get("cache_control"))
                    .filter(|v| !v.is_null())
                {
                    tool.insert("cache_control".to_owned(), cc.clone());
                }
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
                            let mut blk = Map::new();
                            blk.insert("type".to_owned(), Value::String("text".to_owned()));
                            blk.insert("text".to_owned(), Value::String(t.to_owned()));
                            if let Some(cc) = part.get("cache_control").filter(|v| !v.is_null()) {
                                blk.insert("cache_control".to_owned(), cc.clone());
                            }
                            out.push(Value::Object(blk));
                        }
                    }
                    Some("image_url") => {
                        if let Some(url) = part
                            .get("image_url")
                            .and_then(|u| u.get("url"))
                            .and_then(Value::as_str)
                        {
                            let mut blk = Map::new();
                            blk.insert("type".to_owned(), Value::String("image".to_owned()));
                            if let Some(rest) = url.strip_prefix("data:")
                                && let Some((meta, data)) = rest.split_once(',')
                                && let Some(media_type) = meta.strip_suffix(";base64")
                            {
                                blk.insert(
                                    "source".to_owned(),
                                    json!({
                                        "type": "base64",
                                        "media_type": media_type,
                                        "data": data,
                                    }),
                                );
                            } else {
                                blk.insert(
                                    "source".to_owned(),
                                    json!({
                                        "type": "url",
                                        "url": url,
                                    }),
                                );
                            }
                            if let Some(cc) = part.get("cache_control").filter(|v| !v.is_null()) {
                                blk.insert("cache_control".to_owned(), cc.clone());
                            }
                            out.push(Value::Object(blk));
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
    let mut thinking_parts: Vec<&str> = Vec::new();
    let mut tool_calls: Vec<Value> = Vec::new();

    if let Some(content) = val.get("content").and_then(Value::as_array) {
        for block in content {
            match block.get("type").and_then(Value::as_str) {
                Some("text") => {
                    if let Some(t) = block.get("text").and_then(Value::as_str) {
                        text_parts.push(t);
                    }
                }
                Some("thinking") => {
                    if let Some(t) = block.get("thinking").and_then(Value::as_str)
                        && !t.is_empty()
                    {
                        thinking_parts.push(t);
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
    if !thinking_parts.is_empty() {
        message.insert(
            "reasoning_content".to_owned(),
            Value::String(thinking_parts.join("")),
        );
    }
    if !tool_calls.is_empty() {
        message.insert("tool_calls".to_owned(), Value::Array(tool_calls));
    }

    let usage_in = val.get("usage");
    let raw_input_tokens = usage_in
        .and_then(|u| u.get("input_tokens"))
        .and_then(Value::as_u64)
        .unwrap_or(0);
    let cache_read_tokens = usage_in
        .and_then(|u| u.get("cache_read_input_tokens"))
        .and_then(Value::as_u64)
        .unwrap_or(0);
    let cache_creation_tokens = usage_in
        .and_then(|u| u.get("cache_creation_input_tokens"))
        .and_then(Value::as_u64)
        .unwrap_or(0);
    let prompt_tokens = raw_input_tokens
        .saturating_add(cache_read_tokens)
        .saturating_add(cache_creation_tokens);
    let output_tokens = usage_in
        .and_then(|u| u.get("output_tokens"))
        .and_then(Value::as_u64)
        .unwrap_or(0);

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
        Value::Number(prompt_tokens.saturating_add(output_tokens).into()),
    );
    if cache_read_tokens > 0 || cache_creation_tokens > 0 {
        let mut details = Map::new();
        if cache_read_tokens > 0 {
            details.insert(
                "cached_tokens".to_owned(),
                Value::Number(cache_read_tokens.into()),
            );
        }
        if cache_creation_tokens > 0 {
            details.insert(
                "cache_creation_tokens".to_owned(),
                Value::Number(cache_creation_tokens.into()),
            );
        }
        usage_obj.insert("prompt_tokens_details".to_owned(), Value::Object(details));
    }

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
        "usage": Value::Object(usage_obj),
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
    cache_read_tokens: u64,
    cache_creation_tokens: u64,
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
            cache_read_tokens: 0,
            cache_creation_tokens: 0,
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
                        if let Some(cr) = u.get("cache_read_input_tokens").and_then(Value::as_u64) {
                            self.cache_read_tokens = cr;
                        }
                        if let Some(cw) =
                            u.get("cache_creation_input_tokens").and_then(Value::as_u64)
                        {
                            self.cache_creation_tokens = cw;
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
                    Some("thinking") => {
                        if let Some(thinking) = cb.get("thinking").and_then(Value::as_str)
                            && !thinking.is_empty()
                        {
                            self.emit_chunk(
                                out,
                                json!([{
                                    "index": 0,
                                    "delta": { "reasoning_content": thinking },
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
                    Some("thinking_delta") => {
                        if let Some(thinking) = delta.get("thinking").and_then(Value::as_str)
                            && !thinking.is_empty()
                        {
                            self.emit_chunk(
                                out,
                                json!([{
                                    "index": 0,
                                    "delta": { "reasoning_content": thinking },
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
                if let Some(u) = payload.get("usage") {
                    if let Some(out_tok) = u.get("output_tokens").and_then(Value::as_u64) {
                        self.output_tokens = out_tok;
                    }
                    if let Some(cr) = u.get("cache_read_input_tokens").and_then(Value::as_u64) {
                        self.cache_read_tokens = cr;
                    }
                    if let Some(cw) = u.get("cache_creation_input_tokens").and_then(Value::as_u64) {
                        self.cache_creation_tokens = cw;
                    }
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
                let total_prompt = self
                    .input_tokens
                    .saturating_add(self.cache_read_tokens)
                    .saturating_add(self.cache_creation_tokens);
                let mut usage_obj = Map::new();
                usage_obj.insert(
                    "prompt_tokens".to_owned(),
                    Value::Number(total_prompt.into()),
                );
                usage_obj.insert(
                    "completion_tokens".to_owned(),
                    Value::Number(self.output_tokens.into()),
                );
                usage_obj.insert(
                    "total_tokens".to_owned(),
                    Value::Number(total_prompt.saturating_add(self.output_tokens).into()),
                );
                if self.cache_read_tokens > 0 || self.cache_creation_tokens > 0 {
                    let mut details = Map::new();
                    if self.cache_read_tokens > 0 {
                        details.insert(
                            "cached_tokens".to_owned(),
                            Value::Number(self.cache_read_tokens.into()),
                        );
                    }
                    if self.cache_creation_tokens > 0 {
                        details.insert(
                            "cache_creation_tokens".to_owned(),
                            Value::Number(self.cache_creation_tokens.into()),
                        );
                    }
                    usage_obj.insert("prompt_tokens_details".to_owned(), Value::Object(details));
                }
                self.emit_chunk(out, json!([]), Some(Value::Object(usage_obj)));
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

    #[test]
    fn translates_reasoning_json_schema_cache_control_and_vertex_anthropic() {
        let req = json!({
            "model": "smart",
            "reasoning_effort": "high",
            "temperature": 0.7,
            "max_tokens": 1000,
            "response_format": {
                "type": "json_schema",
                "json_schema": {
                    "name": "answer",
                    "schema": { "type": "object", "properties": { "ok": { "type": "boolean" } } }
                }
            },
            "messages": [
                { "role": "system", "content": "Cached sys", "cache_control": { "type": "ephemeral" } },
                { "role": "user", "content": [{ "type": "text", "text": "Solve", "cache_control": { "type": "ephemeral" } }] }
            ]
        });

        let anth_bytes = openai_to_anthropic_request(
            &serde_json::to_vec(&req).unwrap(),
            "claude-sonnet-4-20250514",
            4096,
        )
        .unwrap();
        let anth: Value = serde_json::from_slice(&anth_bytes).unwrap();
        assert_eq!(anth["thinking"]["type"], "enabled");
        assert_eq!(anth["thinking"]["budget_tokens"], 16384);
        assert!(anth["max_tokens"].as_u64().unwrap() > 16384);
        assert!(anth.get("temperature").is_none());
        assert_eq!(anth["system"][0]["cache_control"]["type"], "ephemeral");
        assert_eq!(
            anth["messages"][0]["content"][0]["cache_control"]["type"],
            "ephemeral"
        );
        assert_eq!(anth["output_config"]["format"]["type"], "json_schema");
        assert_eq!(
            anth["output_config"]["format"]["schema"]["properties"]["ok"]["type"],
            "boolean"
        );

        // Claude-on-Vertex body adaptation removes `model` and adds vertex anthropic_version
        let vertex_bytes =
            adapt_anthropic_body_for_vertex(&anth_bytes, Some("2023-06-01")).unwrap();
        let vertex: Value = serde_json::from_slice(&vertex_bytes).unwrap();
        assert!(vertex.get("model").is_none());
        assert_eq!(vertex["anthropic_version"], "vertex-2023-10-16");
        assert_eq!(
            vertex_anthropic_path("my-proj", "us-east5", "claude-sonnet-4@20250514", true),
            "/v1/projects/my-proj/locations/us-east5/publishers/anthropic/models/claude-sonnet-4%4020250514:streamRawPredict"
        );

        // Anthropic thinking + cache write/read response -> OpenAI reasoning_content + prompt_tokens_details
        let anth_resp = json!({
            "id": "msg_think",
            "type": "message",
            "role": "assistant",
            "model": "claude-sonnet-4-20250514",
            "content": [
                { "type": "thinking", "thinking": "Step 1..." },
                { "type": "text", "text": "{\"ok\":true}" }
            ],
            "stop_reason": "end_turn",
            "usage": {
                "input_tokens": 100,
                "cache_read_input_tokens": 400,
                "cache_creation_input_tokens": 200,
                "output_tokens": 50
            }
        });
        let oa_bytes = anthropic_to_openai_response(
            &serde_json::to_vec(&anth_resp).unwrap(),
            StatusCode::OK,
            "fallback",
        )
        .unwrap();
        let oa: Value = serde_json::from_slice(&oa_bytes).unwrap();
        assert_eq!(
            oa["choices"][0]["message"]["reasoning_content"],
            "Step 1..."
        );
        assert_eq!(oa["choices"][0]["message"]["content"], "{\"ok\":true}");
        assert_eq!(oa["usage"]["prompt_tokens"], 700);
        assert_eq!(oa["usage"]["prompt_tokens_details"]["cached_tokens"], 400);
        assert_eq!(
            oa["usage"]["prompt_tokens_details"]["cache_creation_tokens"],
            200
        );
    }

    #[test]
    fn applies_param_defaults_overrides_and_drop_params() {
        let mut p_def = BTreeMap::new();
        p_def.insert("temperature".to_owned(), json!(0.3));
        p_def.insert("seed".to_owned(), json!(7));
        let mut t_def = BTreeMap::new();
        t_def.insert("temperature".to_owned(), json!(0.1));
        let mut t_over = BTreeMap::new();
        t_over.insert("max_tokens".to_owned(), json!(512));

        let body = br#"{"model":"o3-mini","top_k":40,"messages":[{"role":"user","content":"hi"}]}"#;
        let out = apply_request_param_transforms(
            body,
            &p_def,
            &t_def,
            &BTreeMap::new(),
            &t_over,
            &DropParamsConfig::Bool(true),
            ProviderDialect::OpenAiCompatible,
            "o3-mini",
        )
        .unwrap()
        .unwrap();
        let v: Value = serde_json::from_slice(&out).unwrap();
        assert!(v.get("top_k").is_none());
        assert!(v.get("temperature").is_none(), "o3-mini drops temperature");
        assert!(v.get("max_tokens").is_none());
        assert_eq!(v["max_completion_tokens"], 512);
        assert_eq!(v["seed"], 7);
    }
}
