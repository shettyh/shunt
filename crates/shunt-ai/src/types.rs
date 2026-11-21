use std::fmt;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use shunt_plugin_sdk::{BufferedResponse, StatusCode};

/// Supported upstream AI backend providers in `shunt-ai`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum AiProvider {
    #[serde(alias = "open_ai")]
    OpenAi,
    Anthropic,
}

impl AiProvider {
    pub const fn as_str(self) -> &'static str {
        match self {
            AiProvider::OpenAi => "openai",
            AiProvider::Anthropic => "anthropic",
        }
    }
}

impl fmt::Display for AiProvider {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A single resolved provider/upstream/model candidate in a request's fallback chain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AiTarget {
    pub provider: AiProvider,
    pub upstream: String,
    pub model: String,
    pub endpoint_override: Option<String>,
}

/// Typed per-request AI routing metadata stored in [`shunt_plugin_sdk::RequestCtx::extensions`]
/// by `ai-model-router` and consumed by `ai-provider-adapter`, `ai-failover`, and `ai-usage-tracker`.
#[derive(Debug, Clone)]
pub struct AiRequestMeta {
    pub requested_model: String,
    pub stream: bool,
    pub targets: Vec<AiTarget>,
    pub active_target_index: usize,
    pub max_attempts: usize,
}

impl AiRequestMeta {
    pub fn new(requested_model: String, stream: bool, targets: Vec<AiTarget>) -> Self {
        let max_attempts = targets.len().max(1);
        Self {
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
    pub provider: AiProvider,
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
    pub provider: Option<AiProvider>,
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
        std::env::var(var_name)
            .map_err(|_| format!("environment variable `{var_name}` is not set"))
    } else {
        Ok(raw.to_owned())
    }
}
