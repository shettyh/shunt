//! Showcase multi-provider AI router & gateway plugin pack (`shunt-ai`).
//!
//! Implemented **100% through `shunt-plugin-sdk`** with zero dependencies on `shunt-core`,
//! validating Shunt's request buffering, dynamic routing, per-attempt upstream mutation,
//! automatic failover, live SSE chunk translation, and token accounting primitives.
//!
//! ## Included Plugins
//! - `ai-model-router`: Buffers OpenAI chat requests, parses `model` / `stream`, stores
//!   [`AiRequestMeta`] in `ctx.extensions`, and steers `on_route` / `on_upstream_select`
//!   across ordered provider/model fallback chains.
//! - `ai-provider-adapter`: Adapts OpenAI `/v1/chat/completions` requests & responses across
//!   OpenAI and Anthropic (including live Anthropic SSE -> OpenAI `chat.completion.chunk` SSE
//!   and non-streaming JSON translation).
//! - `ai-failover`: Triggers automatic `Flow::RetryUpstream` on `429` / `5xx` / `529` responses,
//!   with optional `StateStore`-backed provider cooldowns that persist across hot reloads.
//! - `ai-usage-tracker`: Extracts input/output token counts and TTFT from JSON or SSE streams,
//!   records Prometheus metrics in [`AiMetrics`], and emits structured usage logs in `on_complete`.

pub mod failover;
pub mod model_router;
pub mod provider_adapter;
pub mod sse;
pub mod translate;
pub mod usage_tracker;
pub mod types;

use std::sync::Arc;

use shunt_plugin_sdk::PluginRegistry;

pub use failover::{AiFailoverFactory, AiFailoverPlugin};
pub use model_router::{AiModelRouterFactory, AiModelRouterPlugin, ModelRule, TargetSpec};
pub use provider_adapter::{AiProviderAdapterFactory, AiProviderAdapterPlugin};
pub use sse::{SseEvent, SseParser};
pub use translate::{
    AnthropicSseTranslator, anthropic_to_openai_response, map_anthropic_stop_reason,
    openai_to_anthropic_request, rewrite_openai_request,
};
pub use types::{
    AiFailoverHistory, AiProvider, AiRequestMeta, AiTarget, AiUsage, AiUsageReport, FailoverEvent,
};
pub use usage_tracker::{
    AiMetrics, AiMetricsSnapshot, AiUsageTrackerFactory, AiUsageTrackerPlugin, UsageSink,
};

/// Registers all `shunt-ai` plugins (`ai-model-router`, `ai-provider-adapter`,
/// `ai-failover`, `ai-usage-tracker`) into `registry`.
pub fn register_ai_plugins(registry: &mut PluginRegistry, ai_metrics: Arc<AiMetrics>) {
    registry
        .register(AiModelRouterFactory)
        .register(AiProviderAdapterFactory)
        .register(AiFailoverFactory)
        .register(AiUsageTrackerFactory::new(ai_metrics));
}
