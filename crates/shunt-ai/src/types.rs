use std::fmt;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use shunt_plugin_sdk::{BufferedResponse, StatusCode};

/// Wire protocol dialect spoken by an upstream AI provider instance.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderDialect {
    #[serde(rename = "openai_compatible", alias = "openai")]
    OpenAiCompatible,
    Anthropic,
    #[serde(rename = "azure_openai", alias = "azure")]
    AzureOpenAi,
    Gemini,
    Bedrock,
}

impl ProviderDialect {
    pub const fn as_str(self) -> &'static str {
        match self {
            ProviderDialect::OpenAiCompatible => "openai_compatible",
            ProviderDialect::Anthropic => "anthropic",
            ProviderDialect::AzureOpenAi => "azure_openai",
            ProviderDialect::Gemini => "gemini",
            ProviderDialect::Bedrock => "bedrock",
        }
    }

    /// Returns whether this dialect implements `POST /v1/embeddings`.
    pub const fn supports_embeddings(self) -> bool {
        matches!(
            self,
            ProviderDialect::OpenAiCompatible
                | ProviderDialect::AzureOpenAi
                | ProviderDialect::Gemini
        )
    }
}

impl fmt::Display for ProviderDialect {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Logical AI API operation parsed from the incoming request path and HTTP method.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AiEndpointKind {
    ChatCompletions,
    Embeddings,
    ModelsList,
    ModelRetrieve,
}

impl AiEndpointKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            AiEndpointKind::ChatCompletions => "chat_completions",
            AiEndpointKind::Embeddings => "embeddings",
            AiEndpointKind::ModelsList => "models_list",
            AiEndpointKind::ModelRetrieve => "model_retrieve",
        }
    }

    pub const fn is_models_discovery(self) -> bool {
        matches!(
            self,
            AiEndpointKind::ModelsList | AiEndpointKind::ModelRetrieve
        )
    }
}

impl fmt::Display for AiEndpointKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Optional capability flags declared per target so incompatible targets are filtered out
/// cleanly (e.g., skipping chat-only backends on `/v1/embeddings`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AiCapability {
    Chat,
    Streaming,
    Tools,
    Vision,
    Embeddings,
}

/// Endpoint classification stored in `RequestCtx::extensions` during `on_request_headers`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DetectedEndpoint(pub AiEndpointKind);

/// A single resolved named-provider/upstream/model candidate in a request's fallback chain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AiTarget {
    /// Named provider ID matching an entry in `ai-provider-adapter`'s `providers` map.
    pub provider: String,
    pub upstream: String,
    pub model: String,
    pub endpoint_override: Option<String>,
    /// Optional capability override; when empty, defaults apply per endpoint/dialect.
    pub capabilities: Vec<AiCapability>,
}

impl AiTarget {
    /// Returns `true` if this target supports `capability` (or declares no capability filter).
    pub fn supports(&self, capability: AiCapability) -> bool {
        self.capabilities.is_empty() || self.capabilities.contains(&capability)
    }
}

/// Typed per-request AI routing metadata stored in [`shunt_plugin_sdk::RequestCtx::extensions`]
/// by `ai-model-router` and consumed by `ai-provider-adapter`, `ai-failover`, and `ai-usage-tracker`.
#[derive(Debug, Clone)]
pub struct AiRequestMeta {
    pub endpoint: AiEndpointKind,
    pub requested_model: String,
    pub stream: bool,
    pub targets: Vec<AiTarget>,
    pub active_target_index: usize,
    pub max_attempts: usize,
}

impl AiRequestMeta {
    pub fn new(
        endpoint: AiEndpointKind,
        requested_model: String,
        stream: bool,
        targets: Vec<AiTarget>,
    ) -> Self {
        let max_attempts = targets.len().max(1);
        Self {
            endpoint,
            requested_model,
            stream,
            targets,
            active_target_index: 0,
            max_attempts,
        }
    }

    /// Returns the currently active target for the ongoing upstream attempt.
    pub fn active_target(&self) -> Option<&AiTarget> {
        self.targets.get(self.active_target_index)
    }

    /// Selects and activates the candidate target for a 1-indexed `attempt`.
    pub fn select_for_attempt(&mut self, attempt: usize) -> Option<&AiTarget> {
        if self.targets.is_empty() {
            return None;
        }
        let idx = attempt.saturating_sub(1) % self.targets.len();
        self.active_target_index = idx;
        self.targets.get(idx)
    }
}

/// Record of a single failed upstream attempt that triggered failover.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FailoverEvent {
    pub attempt: usize,
    pub provider: String,
    pub upstream: String,
    pub model: String,
    pub status: u16,
}

/// Per-request history of failover events stored in `RequestCtx::extensions`.
#[derive(Debug, Clone, Default)]
pub struct AiFailoverHistory {
    pub events: Vec<FailoverEvent>,
}

/// Per-request token & timing accounting state stored in `RequestCtx::extensions`
/// by `ai-usage-tracker`.
#[derive(Debug, Clone, Default)]
pub struct AiUsage {
    pub provider: Option<String>,
    pub served_model: Option<String>,
    pub prompt_tokens: Option<u64>,
    pub completion_tokens: Option<u64>,
    pub total_tokens: Option<u64>,
    pub first_token_at: Option<Instant>,
    pub chunk_count: u64,
}

impl AiUsage {
    /// Computes total tokens, falling back to `prompt_tokens + completion_tokens` if not explicit.
    pub fn effective_total_tokens(&self) -> Option<u64> {
        if let Some(t) = self.total_tokens {
            return Some(t);
        }
        match (self.prompt_tokens, self.completion_tokens) {
            (Some(p), Some(c)) => Some(p.saturating_add(c)),
            (Some(p), None) => Some(p),
            (None, Some(c)) => Some(c),
            (None, None) => None,
        }
    }
}

/// Complete AI usage report emitted by `ai-usage-tracker` in `on_complete`.
#[derive(Debug, Clone)]
pub struct AiUsageReport {
    pub request_id: u64,
    pub route_id: Option<String>,
    pub provider: String,
    pub upstream: Option<String>,
    pub requested_model: String,
    pub served_model: String,
    pub stream: bool,
    pub status: Option<u16>,
    pub attempts: usize,
    pub failover_events: Vec<FailoverEvent>,
    pub prompt_tokens: Option<u64>,
    pub completion_tokens: Option<u64>,
    pub total_tokens: Option<u64>,
    pub ttft: Option<Duration>,
    pub total_duration: Duration,
    pub aborted_mid_stream: bool,
    pub error: Option<String>,
}

/// Builds a standard OpenAI-compatible JSON error response.
pub fn openai_error_response(
    status: StatusCode,
    error_type: &str,
    code: Option<&str>,
    message: &str,
) -> BufferedResponse {
    let payload = serde_json::json!({
        "error": {
            "message": message,
            "type": error_type,
            "param": serde_json::Value::Null,
            "code": code,
        }
    });
    let bytes = serde_json::to_vec(&payload).unwrap_or_else(|_| {
        br#"{"error":{"message":"internal error","type":"server_error"}}"#.to_vec()
    });
    BufferedResponse::json(status, bytes)
}

/// Resolves a secret string, supporting `env:VAR_NAME` indirection.
pub fn resolve_env_secret(raw: &str) -> Result<String, String> {
    if let Some(var_name) = raw.strip_prefix("env:") {
        std::env::var(var_name).map_err(|_| format!("environment variable `{var_name}` is not set"))
    } else {
        Ok(raw.to_owned())
    }
}

/// Percent-encodes a single URI path segment per RFC 3986 unreserved characters
/// (`A-Z`, `a-z`, `0-9`, `-`, `_`, `.`, `~`).
pub fn percent_encode_path_segment(input: &str) -> String {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut out = String::with_capacity(input.len());
    for &b in input.as_bytes() {
        if is_rfc3986_unreserved(b) {
            out.push(b as char);
        } else {
            out.push('%');
            out.push(HEX[(b >> 4) as usize] as char);
            out.push(HEX[(b & 0x0F) as usize] as char);
        }
    }
    out
}

/// Decodes `%XX` percent-encoded sequences in a URI component (best-effort UTF-8).
pub fn percent_decode(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%'
            && i + 2 < bytes.len()
            && let (Some(hi), Some(lo)) = (hex_nibble(bytes[i + 1]), hex_nibble(bytes[i + 2]))
        {
            out.push((hi << 4) | lo);
            i += 3;
            continue;
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

#[inline]
pub(crate) const fn is_rfc3986_unreserved(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~')
}

#[inline]
const fn hex_nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}
