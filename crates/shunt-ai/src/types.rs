use std::collections::{BTreeMap, HashMap};
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
    AnthropicMessages,
    AnthropicCountTokens,
    OpenAiResponses,
    Embeddings,
    ModelsList,
    ModelRetrieve,
}

impl AiEndpointKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            AiEndpointKind::ChatCompletions => "chat_completions",
            AiEndpointKind::AnthropicMessages => "anthropic_messages",
            AiEndpointKind::AnthropicCountTokens => "anthropic_count_tokens",
            AiEndpointKind::OpenAiResponses => "openai_responses",
            AiEndpointKind::Embeddings => "embeddings",
            AiEndpointKind::ModelsList => "models_list",
            AiEndpointKind::ModelRetrieve => "model_retrieve",
        }
    }

    pub const fn is_models_discovery(self) -> bool {
        matches!(
            self,
            AiEndpointKind::ModelsList
                | AiEndpointKind::ModelRetrieve
                | AiEndpointKind::AnthropicCountTokens
        )
    }

    /// Returns `true` for conversational generation endpoints (`/v1/chat/completions`,
    /// `/v1/messages`, `/v1/responses`).
    pub const fn is_conversational(self) -> bool {
        matches!(
            self,
            AiEndpointKind::ChatCompletions
                | AiEndpointKind::AnthropicMessages
                | AiEndpointKind::OpenAiResponses
        )
    }

    /// Returns `true` when gateway errors should be formatted using Anthropic's error envelope.
    pub const fn uses_anthropic_errors(self) -> bool {
        matches!(
            self,
            AiEndpointKind::AnthropicMessages | AiEndpointKind::AnthropicCountTokens
        )
    }
}

/// Budget accumulation window used by `ai-virtual-keys` and `ai-budget`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Deserialize, Serialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum BudgetWindow {
    Hourly,
    #[default]
    Daily,
    Monthly,
    /// Explicit window duration in seconds (e.g., `{ seconds = 300 }`).
    #[serde(untagged)]
    Custom {
        seconds: u64,
    },
}

impl BudgetWindow {
    pub const fn as_duration(self) -> Duration {
        match self {
            BudgetWindow::Hourly => Duration::from_secs(3_600),
            BudgetWindow::Daily => Duration::from_secs(86_400),
            BudgetWindow::Monthly => Duration::from_secs(30 * 86_400),
            BudgetWindow::Custom { seconds } => {
                Duration::from_secs(if seconds == 0 { 1 } else { seconds })
            }
        }
    }

    pub const fn label(self) -> &'static str {
        match self {
            BudgetWindow::Hourly => "hourly",
            BudgetWindow::Daily => "daily",
            BudgetWindow::Monthly => "monthly",
            BudgetWindow::Custom { .. } => "custom",
        }
    }
}

/// Authenticated virtual API key identity & multi-tenant policy attached to
/// `RequestCtx::extensions` by `ai-virtual-keys` and enforced downstream by
/// `ai-model-router`, `ai-token-rate-limit`, `ai-budget`, and `ai-usage-tracker`.
#[derive(Debug, Clone)]
pub struct AiKeyPolicy {
    pub key_id: String,
    pub team: Option<String>,
    /// Glob patterns of permitted model aliases/names (empty = all models permitted).
    pub allowed_models: Vec<String>,
    /// Named provider IDs permitted for this key (empty = all providers permitted).
    pub allowed_providers: Vec<String>,
    /// Per-model target override chains (exact model name or glob pattern -> targets).
    pub provider_overrides: HashMap<String, Vec<AiTarget>>,
    /// Optional per-key RPM override for `ai-token-rate-limit`.
    pub rpm: Option<u64>,
    /// Optional per-key TPM override for `ai-token-rate-limit`.
    pub tpm: Option<u64>,
    /// Optional per-key hard spend budget (USD) for `ai-budget`.
    pub budget_usd: Option<f64>,
    /// Optional per-key soft warning spend threshold (USD) for `ai-budget`.
    pub budget_soft_limit_usd: Option<f64>,
    /// Optional per-key budget window override for `ai-budget`.
    pub budget_window: Option<BudgetWindow>,
    /// Arbitrary key metadata tags.
    pub metadata: BTreeMap<String, String>,
}

impl AiKeyPolicy {
    /// Returns `true` if `model` is permitted by `allowed_models` (empty list allows all).
    pub fn allows_model(&self, model: &str) -> bool {
        if self.allowed_models.is_empty() {
            return true;
        }
        self.allowed_models
            .iter()
            .any(|pat| wildcard_match(pat, model))
    }

    /// Returns `true` if `provider` is permitted by `allowed_providers` (empty list allows all).
    pub fn allows_provider(&self, provider: &str) -> bool {
        if self.allowed_providers.is_empty() {
            return true;
        }
        self.allowed_providers
            .iter()
            .any(|pat| wildcard_match(pat, provider))
    }

    /// Resolves any per-key target override for `requested_model` (exact match first, then glob).
    pub fn override_targets(&self, requested_model: &str) -> Option<Vec<AiTarget>> {
        if let Some(targets) = self.provider_overrides.get(requested_model) {
            return Some(targets.clone());
        }
        // Deterministic scan over sorted patterns if a wildcard override exists.
        let mut patterns: Vec<&String> = self
            .provider_overrides
            .keys()
            .filter(|k| k.contains('*'))
            .collect();
        patterns.sort();
        for pat in patterns {
            if wildcard_match(pat, requested_model) {
                return self.provider_overrides.get(pat).cloned();
            }
        }
        None
    }
}

/// Simple wildcard glob matching supporting `*` (zero or more bytes).
pub fn wildcard_match(pattern: &str, text: &str) -> bool {
    let p = pattern.as_bytes();
    let t = text.as_bytes();
    let (mut pi, mut ti) = (0usize, 0usize);
    let mut star_idx: Option<usize> = None;
    let mut match_idx = 0usize;

    while ti < t.len() {
        if pi < p.len() && p[pi] == t[ti] {
            pi += 1;
            ti += 1;
        } else if pi < p.len() && p[pi] == b'*' {
            star_idx = Some(pi);
            match_idx = ti;
            pi += 1;
        } else if let Some(si) = star_idx {
            pi = si + 1;
            match_idx += 1;
            ti = match_idx;
        } else {
            return false;
        }
    }

    while pi < p.len() && p[pi] == b'*' {
        pi += 1;
    }

    pi == p.len()
}

impl fmt::Display for AiEndpointKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Smart routing strategy selecting and ordering candidate targets for an AI request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RoutingStrategy {
    /// Static configured failover order (default, zero extra state/hooks).
    #[default]
    Priority,
    /// Smooth weighted round-robin canary/A-B split across eligible targets.
    Weighted,
    /// Dynamic EWMA TTFT/latency & error-rate-aware ranking with cold-start exploration.
    Latency,
    /// Cheapest-first estimated nano-USD ranking via [`crate::PricingCatalog`].
    Cost,
}

impl RoutingStrategy {
    pub const fn as_str(self) -> &'static str {
        match self {
            RoutingStrategy::Priority => "priority",
            RoutingStrategy::Weighted => "weighted",
            RoutingStrategy::Latency => "latency",
            RoutingStrategy::Cost => "cost",
        }
    }
}

impl fmt::Display for RoutingStrategy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Optional capability flags declared per target so incompatible targets are filtered out
/// cleanly (e.g., skipping text-only backends on vision requests or chat-only on embeddings).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AiCapability {
    Chat,
    Streaming,
    Tools,
    Vision,
    JsonSchema,
    Reasoning,
    Embeddings,
}

impl AiCapability {
    pub const fn as_str(self) -> &'static str {
        match self {
            AiCapability::Chat => "chat",
            AiCapability::Streaming => "streaming",
            AiCapability::Tools => "tools",
            AiCapability::Vision => "vision",
            AiCapability::JsonSchema => "json_schema",
            AiCapability::Reasoning => "reasoning",
            AiCapability::Embeddings => "embeddings",
        }
    }
}

impl fmt::Display for AiCapability {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
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
    /// Optional capability override; when empty, target is treated as unrestricted.
    pub capabilities: Vec<AiCapability>,
    /// Relative traffic weight used by [`RoutingStrategy::Weighted`] (`>= 1`).
    pub weight: u32,
}

impl AiTarget {
    /// Returns `true` if this target supports `capability` (or declares no capability filter).
    pub fn supports(&self, capability: AiCapability) -> bool {
        self.capabilities.is_empty() || self.capabilities.contains(&capability)
    }

    /// Returns `true` if this target supports every required capability.
    pub fn supports_all(&self, required: &[AiCapability]) -> bool {
        self.capabilities.is_empty() || required.iter().all(|c| self.capabilities.contains(c))
    }
}

/// Typed per-request AI routing metadata stored in [`shunt_plugin_sdk::RequestCtx::extensions`]
/// by `ai-model-router` and consumed by `ai-provider-adapter`, `ai-failover`, and `ai-usage-tracker`.
#[derive(Debug, Clone)]
pub struct AiRequestMeta {
    pub endpoint: AiEndpointKind,
    pub requested_model: String,
    pub stream: bool,
    pub routing_strategy: RoutingStrategy,
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
        Self::with_strategy(
            endpoint,
            requested_model,
            stream,
            RoutingStrategy::Priority,
            targets,
        )
    }

    pub fn with_strategy(
        endpoint: AiEndpointKind,
        requested_model: String,
        stream: bool,
        routing_strategy: RoutingStrategy,
        targets: Vec<AiTarget>,
    ) -> Self {
        let max_attempts = targets.len().max(1);
        Self {
            endpoint,
            requested_model,
            stream,
            routing_strategy,
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
    pub cached_prompt_tokens: Option<u64>,
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
    pub key_id: Option<String>,
    pub team: Option<String>,
    pub provider: String,
    pub upstream: Option<String>,
    pub requested_model: String,
    pub served_model: String,
    pub stream: bool,
    pub status: Option<u16>,
    pub attempts: usize,
    pub failover_events: Vec<FailoverEvent>,
    pub prompt_tokens: Option<u64>,
    pub cached_prompt_tokens: Option<u64>,
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

/// Builds a standard Anthropic Messages API JSON error response.
pub fn anthropic_error_response(
    status: StatusCode,
    error_type: &str,
    message: &str,
) -> BufferedResponse {
    let payload = serde_json::json!({
        "type": "error",
        "error": {
            "type": error_type,
            "message": message,
        }
    });
    let bytes = serde_json::to_vec(&payload).unwrap_or_else(|_| {
        br#"{"type":"error","error":{"type":"api_error","message":"internal error"}}"#.to_vec()
    });
    BufferedResponse::json(status, bytes)
}

/// Maps an HTTP status / OpenAI-style error type to a canonical Anthropic error `type` string.
pub fn map_status_to_anthropic_error_type(
    status: StatusCode,
    raw_type: Option<&str>,
) -> &'static str {
    match status.as_u16() {
        401 => return "authentication_error",
        403 => return "permission_error",
        404 => return "not_found_error",
        413 => return "request_too_large",
        429 => return "rate_limit_error",
        529 => return "overloaded_error",
        _ => {}
    }
    if let Some(t) = raw_type {
        match t {
            "invalid_request_error" => return "invalid_request_error",
            "authentication_error" => return "authentication_error",
            "permission_error" => return "permission_error",
            "not_found_error" => return "not_found_error",
            "rate_limit_error" | "rate_limit_exceeded" => return "rate_limit_error",
            "overloaded_error" => return "overloaded_error",
            "request_too_large" => return "request_too_large",
            "api_error" => return "api_error",
            _ => {}
        }
    }
    match status.as_u16() {
        400 => "invalid_request_error",
        _ => "api_error",
    }
}

/// Builds a gateway error response formatted in the native schema of `endpoint`.
pub fn endpoint_error_response(
    endpoint: AiEndpointKind,
    status: StatusCode,
    error_type: &str,
    code: Option<&str>,
    message: &str,
) -> BufferedResponse {
    if endpoint.uses_anthropic_errors() {
        let anth_type = map_status_to_anthropic_error_type(status, Some(error_type));
        anthropic_error_response(status, anth_type, message)
    } else {
        openai_error_response(status, error_type, code, message)
    }
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
