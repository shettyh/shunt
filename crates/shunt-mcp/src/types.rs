use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use shunt_plugin_sdk::{
    BufferedResponse, Bytes, HeaderMap, HeaderName, HeaderValue, StatusCode, header,
};

/// Standard MCP Streamable HTTP session identifier header.
pub const MCP_SESSION_HEADER: &str = "mcp-session-id";
/// Standard MCP protocol version negotiation header.
pub const MCP_PROTOCOL_VERSION_HEADER: &str = "mcp-protocol-version";
/// Optional transport header mirroring the invoked tool/resource/prompt name.
pub const MCP_NAME_HEADER: &str = "mcp-name";
/// Default MCP protocol version advertised by the virtual gateway multiplexer.
pub const DEFAULT_PROTOCOL_VERSION: &str = "2025-06-18";
/// Protocol versions accepted by the gateway multiplexer during `initialize`.
pub const SUPPORTED_PROTOCOL_VERSIONS: &[&str] =
    &["2025-11-25", "2025-06-18", "2025-03-26", "2024-11-05"];

// Standard JSON-RPC 2.0 error codes
pub const JSONRPC_PARSE_ERROR: i64 = -32700;
pub const JSONRPC_INVALID_REQUEST: i64 = -32600;
pub const JSONRPC_METHOD_NOT_FOUND: i64 = -32601;
pub const JSONRPC_INVALID_PARAMS: i64 = -32602;
pub const JSONRPC_INTERNAL_ERROR: i64 = -32603;

// Shunt MCP gateway application error codes (reserved server error range -32000..-32099)
pub const MCP_ERR_UNAUTHORIZED: i64 = -32001;
pub const MCP_ERR_FORBIDDEN: i64 = -32003;
pub const MCP_ERR_RATE_LIMITED: i64 = -32029;
pub const MCP_ERR_GUARDRAIL_BLOCKED: i64 = -32030;
pub const MCP_ERR_APPROVAL_REQUIRED: i64 = -32031;
pub const MCP_ERR_UPSTREAM_ERROR: i64 = -32050;

/// Parsed JSON-RPC 2.0 MCP request envelope extracted from an HTTP `POST` body.
#[derive(Debug, Clone, PartialEq)]
pub struct McpParsedRequest {
    /// JSON-RPC request `id` (`None` for notifications).
    pub id: Option<Value>,
    /// JSON-RPC `method` (e.g., `"initialize"`, `"tools/list"`, `"tools/call"`).
    pub method: String,
    /// Optional `params` JSON value.
    pub params: Option<Value>,
    /// True if the message is a JSON-RPC notification (no `id` field).
    pub is_notification: bool,
    /// Extracted tool name for `tools/call` (raw or namespaced).
    pub tool_name: Option<String>,
    /// Extracted resource URI for `resources/read` or `resources/subscribe`.
    pub resource_uri: Option<String>,
    /// Extracted prompt name for `prompts/get`.
    pub prompt_name: Option<String>,
    /// Extracted `params.arguments` object for `tools/call` or `prompts/get`.
    pub arguments: Option<Value>,
    /// Whether `params._meta.approved == true`.
    pub meta_approved: bool,
}

/// Errors produced when parsing an untrusted MCP JSON-RPC 2.0 request payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct McpParseError {
    pub code: i64,
    pub message: String,
}

/// Parses an untrusted MCP JSON-RPC 2.0 HTTP `POST` payload without panicking.
///
/// Rejects malformed JSON, non-object envelopes, unsupported `jsonrpc` versions,
/// empty/non-string `method`, null request IDs, and JSON-RPC batch arrays when
/// `allow_batch` is `false`.
pub fn parse_mcp_jsonrpc_request(
    body: &[u8],
    allow_batch: bool,
) -> Result<Vec<McpParsedRequest>, McpParseError> {
    if body.is_empty() {
        return Err(McpParseError {
            code: JSONRPC_PARSE_ERROR,
            message: "empty JSON-RPC request body".to_owned(),
        });
    }

    let value: Value = serde_json::from_slice(body).map_err(|err| McpParseError {
        code: JSONRPC_PARSE_ERROR,
        message: format!("invalid JSON-RPC payload: {err}"),
    })?;

    match value {
        Value::Object(obj) => Ok(vec![parse_single_object(obj)?]),
        Value::Array(items) => {
            if !allow_batch {
                return Err(McpParseError {
                    code: JSONRPC_INVALID_REQUEST,
                    message: "JSON-RPC batch requests are disabled on this route".to_owned(),
                });
            }
            if items.is_empty() {
                return Err(McpParseError {
                    code: JSONRPC_INVALID_REQUEST,
                    message: "JSON-RPC batch array must not be empty".to_owned(),
                });
            }
            let mut parsed = Vec::with_capacity(items.len());
            for item in items {
                match item {
                    Value::Object(obj) => parsed.push(parse_single_object(obj)?),
                    _ => {
                        return Err(McpParseError {
                            code: JSONRPC_INVALID_REQUEST,
                            message: "every JSON-RPC batch entry must be an object".to_owned(),
                        });
                    }
                }
            }
            Ok(parsed)
        }
        _ => Err(McpParseError {
            code: JSONRPC_INVALID_REQUEST,
            message: "JSON-RPC payload must be a JSON object".to_owned(),
        }),
    }
}

fn parse_single_object(obj: Map<String, Value>) -> Result<McpParsedRequest, McpParseError> {
    match obj.get("jsonrpc").and_then(Value::as_str) {
        Some("2.0") => {}
        _ => {
            return Err(McpParseError {
                code: JSONRPC_INVALID_REQUEST,
                message: "JSON-RPC envelope must specify `jsonrpc: \"2.0\"`".to_owned(),
            });
        }
    }

    let method = match obj.get("method").and_then(Value::as_str) {
        Some(m) if !m.is_empty() => m.to_owned(),
        _ => {
            return Err(McpParseError {
                code: JSONRPC_INVALID_REQUEST,
                message: "JSON-RPC envelope must include a non-empty string `method`".to_owned(),
            });
        }
    };

    let (id, is_notification) = match obj.get("id") {
        None => (None, true),
        Some(Value::String(s)) => (Some(Value::String(s.clone())), false),
        Some(Value::Number(n)) => (Some(Value::Number(n.clone())), false),
        Some(_) => {
            return Err(McpParseError {
                code: JSONRPC_INVALID_REQUEST,
                message: "MCP JSON-RPC `id` must be a string or number (never null)".to_owned(),
            });
        }
    };

    let params = obj.get("params").cloned();
    if let Some(ref p) = params
        && !p.is_object()
        && !p.is_array()
    {
        return Err(McpParseError {
            code: JSONRPC_INVALID_PARAMS,
            message: "JSON-RPC `params` must be an object or array".to_owned(),
        });
    }

    let params_obj = params.as_ref().and_then(Value::as_object);
    let tool_name = if method == "tools/call" {
        params_obj
            .and_then(|p| p.get("name"))
            .and_then(Value::as_str)
            .map(str::to_owned)
    } else {
        None
    };

    let resource_uri = if matches!(
        method.as_str(),
        "resources/read" | "resources/subscribe" | "resources/unsubscribe"
    ) {
        params_obj
            .and_then(|p| p.get("uri"))
            .and_then(Value::as_str)
            .map(str::to_owned)
    } else {
        None
    };

    let prompt_name = if method == "prompts/get" {
        params_obj
            .and_then(|p| p.get("name"))
            .and_then(Value::as_str)
            .map(str::to_owned)
    } else {
        None
    };

    let arguments = params_obj.and_then(|p| p.get("arguments")).cloned();
    let meta_approved = params_obj
        .and_then(|p| p.get("_meta"))
        .and_then(Value::as_object)
        .and_then(|m| m.get("approved"))
        .and_then(Value::as_bool)
        .unwrap_or(false);

    Ok(McpParsedRequest {
        id,
        method,
        params,
        is_notification,
        tool_name,
        resource_uri,
        prompt_name,
        arguments,
        meta_approved,
    })
}

/// Authenticated agent / client identity and ACL policy attached by `mcp-auth`.
#[derive(Debug, Clone)]
pub struct McpPrincipal {
    /// Stable principal identifier (virtual key ID, JWT `sub`, mTLS `CN`, etc.).
    pub id: String,
    /// Optional team / project attribution.
    pub team: Option<String>,
    /// Optional agent identifier (e.g., `"claude-code"`, `"ci-triage-bot"`).
    pub agent_id: Option<String>,
    /// Allowed backend MCP server names (empty = all servers allowed).
    pub allowed_servers: Vec<String>,
    /// Allowed tool globs (matches namespaced or raw tool name; empty = all allowed).
    pub allowed_tools: Vec<String>,
    /// Denied tool globs (always takes precedence over `allowed_tools`).
    pub denied_tools: Vec<String>,
    /// Allowed resource URI globs (empty = all allowed).
    pub allowed_resources: Vec<String>,
    /// Allowed prompt globs (empty = all allowed).
    pub allowed_prompts: Vec<String>,
    /// Allowed JSON-RPC method globs (empty = all allowed).
    pub allowed_methods: Vec<String>,
    /// Optional per-principal total MCP requests-per-minute limit.
    pub rpm: Option<u64>,
    /// Optional per-principal `tools/call` requests-per-minute limit.
    pub tool_rpm: Option<u64>,
    /// Optional per-principal hard cap on `tools/call` per MCP session.
    pub max_calls_per_session: Option<u64>,
    /// Optional per-principal max concurrent in-flight MCP calls.
    pub max_parallel_calls: Option<u64>,
    /// Arbitrary principal metadata tags.
    pub metadata: BTreeMap<String, String>,
}

impl McpPrincipal {
    pub fn allows_server(&self, server: &str) -> bool {
        self.allowed_servers.is_empty()
            || self
                .allowed_servers
                .iter()
                .any(|pat| glob_match(pat, server))
    }

    pub fn allows_method(&self, method: &str) -> bool {
        self.allowed_methods.is_empty()
            || self
                .allowed_methods
                .iter()
                .any(|pat| glob_match(pat, method))
    }

    /// Checks whether a tool is permitted, evaluating both the namespaced name
    /// (e.g., `"github__create_issue"`) and the raw tool name (`"create_issue"`).
    /// `denied_tools` always overrides `allowed_tools`.
    pub fn allows_tool(&self, namespaced: &str, raw: Option<&str>) -> bool {
        let is_denied = self
            .denied_tools
            .iter()
            .any(|pat| glob_match(pat, namespaced) || raw.is_some_and(|r| glob_match(pat, r)));
        if is_denied {
            return false;
        }
        if self.allowed_tools.is_empty() {
            return true;
        }
        self.allowed_tools
            .iter()
            .any(|pat| glob_match(pat, namespaced) || raw.is_some_and(|r| glob_match(pat, r)))
    }

    pub fn allows_resource(&self, uri: &str) -> bool {
        self.allowed_resources.is_empty()
            || self
                .allowed_resources
                .iter()
                .any(|pat| glob_match(pat, uri))
    }

    pub fn allows_prompt(&self, namespaced: &str, raw: Option<&str>) -> bool {
        self.allowed_prompts.is_empty()
            || self
                .allowed_prompts
                .iter()
                .any(|pat| glob_match(pat, namespaced) || raw.is_some_and(|r| glob_match(pat, r)))
    }
}

/// Shared per-request MCP metadata populated by `mcp-router` and read by
/// `mcp-guardrails`, `mcp-rate-limit`, and `mcp-telemetry`.
#[derive(Debug, Clone)]
pub struct McpRequestMeta {
    /// JSON-RPC request `id` (if not a notification).
    pub jsonrpc_id: Option<Value>,
    /// JSON-RPC method (or `"_sse_stream"` for `GET` / `"_session_delete"` for `DELETE`).
    pub method: String,
    /// True if JSON-RPC notification.
    pub is_notification: bool,
    /// Selected logical backend MCP server name (e.g., `"github"`, `"default"`).
    pub server: String,
    /// Selected Shunt upstream name for the backend server.
    pub upstream: Option<String>,
    /// Full (possibly namespaced) tool name as sent by client.
    pub tool_name: Option<String>,
    /// Unprefixed backend tool name (sent to the upstream MCP server).
    pub backend_tool_name: Option<String>,
    /// Resource URI for `resources/read` / `resources/subscribe`.
    pub resource_uri: Option<String>,
    /// Full prompt name for `prompts/get`.
    pub prompt_name: Option<String>,
    /// Unprefixed backend prompt name.
    pub backend_prompt_name: Option<String>,
    /// Serialized arguments JSON value (for guardrails, loop detection, and audit).
    pub arguments: Option<Value>,
    /// Incoming `Mcp-Session-Id` header (or newly minted session ID).
    pub session_id: Option<String>,
    /// Negotiated or client-sent `MCP-Protocol-Version`.
    pub protocol_version: Option<String>,
    /// Whether client explicitly supplied approval (`x-shunt-approved: true` or `_meta.approved`).
    pub approved: bool,
    /// Whether the request was handled locally by the multiplexer (e.g., `initialize`, `tools/list`).
    pub handled_locally: bool,
}

/// Guardrail finding recorded during MCP request/response evaluation.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct McpGuardrailFinding {
    pub direction: String,
    pub detector: String,
    pub action: String,
    pub detail: String,
}

/// Aggregate guardrail verdict attached to `RequestCtx` by `mcp-guardrails`.
#[derive(Debug, Clone, Default, Serialize)]
pub struct McpGuardrailSummary {
    pub blocked: bool,
    pub redacted: bool,
    pub findings: Vec<McpGuardrailFinding>,
}

/// Outcome recorded by `mcp-rate-limit` when the loop breaker trips.
#[derive(Debug, Clone)]
pub struct McpLoopBreakInfo {
    pub tool: String,
    pub repeats: u64,
}

/// Upstream server authentication strategy for backend MCP servers.
#[derive(Debug, Clone, Deserialize, Default)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum McpUpstreamAuth {
    #[default]
    None,
    Bearer {
        /// Plaintext or `"env:VAR_NAME"`. Named `api_key` so `GET /snapshot` redacts it.
        api_key: String,
    },
    Header {
        header: String,
        /// Plaintext or `"env:VAR_NAME"`. Named `api_key` so `GET /snapshot` redacts it.
        api_key: String,
    },
}

/// Resolved upstream authentication header pair (compiled once at snapshot build time).
#[derive(Debug, Clone)]
pub enum ResolvedUpstreamAuth {
    None,
    Header {
        name: HeaderName,
        value: HeaderValue,
    },
}

impl McpUpstreamAuth {
    pub fn resolve(&self, plugin_name: &str) -> Result<ResolvedUpstreamAuth, String> {
        match self {
            McpUpstreamAuth::None => Ok(ResolvedUpstreamAuth::None),
            McpUpstreamAuth::Bearer { api_key } => {
                let secret = resolve_env_secret(api_key)
                    .map_err(|e| format!("{plugin_name}: bearer auth: {e}"))?;
                let val = HeaderValue::from_str(&format!("Bearer {secret}"))
                    .map_err(|e| format!("{plugin_name}: invalid bearer header value: {e}"))?;
                Ok(ResolvedUpstreamAuth::Header {
                    name: header::AUTHORIZATION,
                    value: val,
                })
            }
            McpUpstreamAuth::Header {
                header: name,
                api_key,
            } => {
                let secret = resolve_env_secret(api_key)
                    .map_err(|e| format!("{plugin_name}: header auth `{name}`: {e}"))?;
                let hname = HeaderName::from_bytes(name.as_bytes()).map_err(|e| {
                    format!("{plugin_name}: invalid auth header name `{name}`: {e}")
                })?;
                let hval = HeaderValue::from_str(&secret)
                    .map_err(|e| format!("{plugin_name}: invalid auth header value: {e}"))?;
                Ok(ResolvedUpstreamAuth::Header {
                    name: hname,
                    value: hval,
                })
            }
        }
    }
}

/// Resolves a secret string that may be prefixed with `"env:VAR_NAME"`.
pub fn resolve_env_secret(raw: &str) -> Result<String, String> {
    if let Some(var_name) = raw.strip_prefix("env:") {
        let trimmed = var_name.trim();
        if trimmed.is_empty() {
            return Err("empty environment variable name after `env:`".to_owned());
        }
        std::env::var(trimmed).map_err(|_| format!("environment variable `{trimmed}` is not set"))
    } else {
        Ok(raw.to_owned())
    }
}

/// Builds a JSON-RPC 2.0 error HTTP response.
pub fn jsonrpc_error_response(
    status: StatusCode,
    id: Option<&Value>,
    code: i64,
    message: impl Into<String>,
    data: Option<Value>,
) -> BufferedResponse {
    let mut err_obj = Map::new();
    err_obj.insert("code".to_owned(), json!(code));
    err_obj.insert("message".to_owned(), json!(message.into()));
    if let Some(d) = data {
        err_obj.insert("data".to_owned(), d);
    }

    let payload = json!({
        "jsonrpc": "2.0",
        "id": id.cloned().unwrap_or(Value::Null),
        "error": Value::Object(err_obj),
    });

    let bytes = serde_json::to_vec(&payload).unwrap_or_else(|_| {
        b"{\"jsonrpc\":\"2.0\",\"id\":null,\"error\":{\"code\":-32603,\"message\":\"internal error\"}}"
            .to_vec()
    });
    BufferedResponse::json(status, bytes)
}

/// Builds a JSON-RPC 2.0 success HTTP response.
pub fn jsonrpc_result_response(
    status: StatusCode,
    id: Option<&Value>,
    result: Value,
) -> BufferedResponse {
    let payload = json!({
        "jsonrpc": "2.0",
        "id": id.cloned().unwrap_or(Value::Null),
        "result": result,
    });
    let bytes = serde_json::to_vec(&payload)
        .unwrap_or_else(|_| b"{\"jsonrpc\":\"2.0\",\"id\":null,\"result\":{}}".to_vec());
    BufferedResponse::json(status, bytes)
}

/// Joins a server namespace and backend item name using `separator`.
pub fn join_namespaced(server: &str, separator: &str, name: &str) -> String {
    if separator.is_empty() {
        name.to_owned()
    } else {
        format!("{server}{separator}{name}")
    }
}

/// Splits a namespaced item name (`"<server><sep><name>"`) into `(server, raw_name)`.
pub fn split_namespaced<'a>(full: &'a str, separator: &str) -> Option<(&'a str, &'a str)> {
    if separator.is_empty() {
        return None;
    }
    let (server, raw) = full.split_once(separator)?;
    if server.is_empty() || raw.is_empty() {
        return None;
    }
    Some((server, raw))
}

/// Simple wildcard glob matching (`*` matches any sequence of chars, `?` matches one char).
/// Iterative two-pointer algorithm: O(N*M) worst-case, zero recursion, panic-free.
pub fn glob_match(pattern: &str, text: &str) -> bool {
    let p: Vec<char> = pattern.chars().collect();
    let t: Vec<char> = text.chars().collect();
    let (mut pi, mut ti) = (0usize, 0usize);
    let (mut star_idx, mut match_idx) = (None, 0usize);

    while ti < t.len() {
        if pi < p.len() && (p[pi] == '?' || p[pi] == t[ti]) {
            pi += 1;
            ti += 1;
        } else if pi < p.len() && p[pi] == '*' {
            star_idx = Some(pi);
            match_idx = ti;
            pi += 1;
        } else if let Some(s_idx) = star_idx {
            pi = s_idx + 1;
            match_idx += 1;
            ti = match_idx;
        } else {
            return false;
        }
    }

    while pi < p.len() && p[pi] == '*' {
        pi += 1;
    }
    pi == p.len()
}

/// Produces deterministic canonical JSON bytes with sorted object keys (used for loop-breaker
/// argument hashing and audit fingerprints).
pub fn canonical_json_bytes(value: &Value) -> Vec<u8> {
    let normalized = sort_json_value(value);
    serde_json::to_vec(&normalized).unwrap_or_default()
}

fn sort_json_value(value: &Value) -> Value {
    match value {
        Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            let mut sorted = Map::with_capacity(map.len());
            for k in keys {
                if let Some(v) = map.get(k) {
                    sorted.insert(k.clone(), sort_json_value(v));
                }
            }
            Value::Object(sorted)
        }
        Value::Array(items) => Value::Array(items.iter().map(sort_json_value).collect()),
        other => other.clone(),
    }
}

/// Lowercase hex SHA-256 digest helper.
pub fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut out = String::with_capacity(64);
    for b in digest {
        use std::fmt::Write as _;
        let _ = write!(&mut out, "{b:02x}");
    }
    out
}

/// Extracts JSON-RPC JSON payloads from an MCP Streamable HTTP response body,
/// supporting both `application/json` and `text/event-stream` (SSE `data:` frames).
pub fn extract_mcp_response_payloads(content_type: Option<&str>, body: &[u8]) -> Vec<Value> {
    let is_sse = content_type
        .map(|ct| ct.to_ascii_lowercase().contains("text/event-stream"))
        .unwrap_or(false);

    if !is_sse {
        return match serde_json::from_slice::<Value>(body) {
            Ok(Value::Array(arr)) => arr,
            Ok(v) => vec![v],
            Err(_) => Vec::new(),
        };
    }

    extract_sse_json_events(body)
}

/// Extracts all valid JSON payloads carried in SSE `data:` frames.
pub fn extract_sse_json_events(body: &[u8]) -> Vec<Value> {
    let text = String::from_utf8_lossy(body);
    let mut out = Vec::new();
    let mut current_data = String::new();

    for raw_line in text.lines() {
        let line = raw_line.trim_end_matches('\r');
        if line.is_empty() {
            if !current_data.is_empty() {
                if let Ok(v) = serde_json::from_str::<Value>(&current_data) {
                    out.push(v);
                }
                current_data.clear();
            }
            continue;
        }
        if let Some(rest) = line.strip_prefix("data:") {
            let trimmed = rest.strip_prefix(' ').unwrap_or(rest);
            if !current_data.is_empty() {
                current_data.push('\n');
            }
            current_data.push_str(trimmed);
        }
    }

    if !current_data.is_empty()
        && let Ok(v) = serde_json::from_str::<Value>(&current_data)
    {
        out.push(v);
    }

    out
}

/// Extracts a trimmed string header value case-insensitively.
pub fn get_header_str<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers
        .get(name)
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
        .filter(|s| !s.is_empty())
}

/// Returns `true` if a `Content-Type` header denotes Server-Sent Events.
pub fn is_sse_content_type(headers: &HeaderMap) -> bool {
    headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(|ct| ct.to_ascii_lowercase().contains("text/event-stream"))
        .unwrap_or(false)
}

/// Extracts the `Bytes` body of a JSON-RPC object after mutating a `Value`.
pub fn serialize_json_bytes(value: &Value) -> Result<Bytes, String> {
    serde_json::to_vec(value)
        .map(Bytes::from)
        .map_err(|e| format!("failed to serialize JSON-RPC payload: {e}"))
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;

    #[test]
    fn parses_valid_tools_call_and_notification() {
        let call = br#"{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"github__create_issue","arguments":{"title":"hi"},"_meta":{"approved":true}}}"#;
        let parsed = parse_mcp_jsonrpc_request(call, false).unwrap();
        assert_eq!(parsed.len(), 1);
        let req = &parsed[0];
        assert_eq!(req.method, "tools/call");
        assert_eq!(req.tool_name.as_deref(), Some("github__create_issue"));
        assert!(!req.is_notification);
        assert!(req.meta_approved);

        let notif = br#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#;
        let parsed = parse_mcp_jsonrpc_request(notif, false).unwrap();
        assert!(parsed[0].is_notification);
        assert!(parsed[0].id.is_none());
    }

    #[test]
    fn rejects_null_id_and_disallowed_batch() {
        let null_id = br#"{"jsonrpc":"2.0","id":null,"method":"ping"}"#;
        let err = parse_mcp_jsonrpc_request(null_id, false).unwrap_err();
        assert_eq!(err.code, JSONRPC_INVALID_REQUEST);

        let batch = br#"[{"jsonrpc":"2.0","id":1,"method":"ping"}]"#;
        assert!(parse_mcp_jsonrpc_request(batch, false).is_err());
        assert_eq!(parse_mcp_jsonrpc_request(batch, true).unwrap().len(), 1);
    }

    #[test]
    fn extracts_sse_jsonrpc_events() {
        let sse = b"event: message\ndata: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"tools\":[]}}\n\nevent: ping\ndata: not-json\n\n";
        let events = extract_mcp_response_payloads(Some("text/event-stream; charset=utf-8"), sse);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0]["id"], 1);
    }

    #[test]
    fn principal_denied_tools_override_allowed() {
        let p = McpPrincipal {
            id: "agent-1".to_owned(),
            team: None,
            agent_id: None,
            allowed_servers: vec!["github".to_owned()],
            allowed_tools: vec!["github__*".to_owned()],
            denied_tools: vec!["*delete*".to_owned()],
            allowed_resources: vec![],
            allowed_prompts: vec![],
            allowed_methods: vec![],
            rpm: None,
            tool_rpm: None,
            max_calls_per_session: None,
            max_parallel_calls: None,
            metadata: BTreeMap::new(),
        };
        assert!(p.allows_tool("github__list_issues", Some("list_issues")));
        assert!(!p.allows_tool("github__delete_repo", Some("delete_repo")));
        assert!(!p.allows_tool("postgres__query", Some("query")));
    }

    proptest! {
        #[test]
        fn jsonrpc_parser_never_panics_on_arbitrary_bytes(data in proptest::collection::vec(any::<u8>(), 0..512)) {
            let _ = parse_mcp_jsonrpc_request(&data, false);
            let _ = parse_mcp_jsonrpc_request(&data, true);
            let _ = extract_sse_json_events(&data);
        }

        #[test]
        fn namespace_roundtrip_holds_for_clean_names(
            server in "[a-z][a-z0-9-]{0,12}",
            tool in "[a-z][a-z0-9-]{0,20}"
        ) {
            let joined = join_namespaced(&server, "__", &tool);
            let (s, t) = split_namespaced(&joined, "__").unwrap();
            prop_assert_eq!(s, server.as_str());
            prop_assert_eq!(t, tool.as_str());
        }

        #[test]
        fn glob_match_never_panics(
            pat in "[a-z*?_-]{0,24}",
            text in "[a-z_-]{0,32}"
        ) {
            let _ = glob_match(&pat, &text);
        }
    }
}
