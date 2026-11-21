//! Showcase multi-provider AI router & gateway plugin pack (`shunt-ai`).
//!
//! Implemented **100% through `shunt-plugin-sdk`** with zero dependencies on `shunt-core`,
//! validating Shunt's request buffering, dynamic routing, per-attempt upstream mutation,
//! automatic failover, live SSE / binary EventStream translation, and token accounting primitives.
//!
//! ## Included Plugins
//! - `ai-model-router`: Serves synthesized `GET /v1/models` & `GET /v1/models/{id}`, buffers
//!   `/v1/chat/completions` & `/v1/embeddings` requests, stores [`AiRequestMeta`] in
//!   `ctx.extensions`, and steers `on_route` / `on_upstream_select` across named-provider chains.
//! - `ai-provider-adapter`: Adapts OpenAI requests & responses across named provider instances
//!   speaking `openai_compatible`, `anthropic`, `azure_openai`, `gemini` (AI Studio & Vertex AI),
//!   and `bedrock` (Converse & ConverseStream with pure-Rust AWS SigV4 & EventStream framing).
//! - `ai-failover`: Triggers automatic `Flow::RetryUpstream` on `429` / `5xx` / `529` responses,
//!   with optional `StateStore`-backed provider cooldowns that persist across hot reloads.
//! - `ai-usage-tracker`: Extracts input/output token counts and TTFT from JSON or SSE streams
//!   across OpenAI, Anthropic, Gemini, Bedrock, and Embeddings formats, records Prometheus metrics
//!   in [`AiMetrics`], and emits structured usage logs in `on_complete`.

pub mod aws_eventstream;
pub mod aws_sigv4;
pub mod budget;
pub mod cache;
pub mod dialects;
pub mod failover;
pub mod ingress;
pub mod model_router;
pub mod pricing;
pub mod provider_adapter;
pub mod routing;
pub mod sse;
pub mod token_rate_limit;
pub mod tokens;
pub mod translate;
pub mod types;
pub mod usage_tracker;
pub mod virtual_keys;

use std::sync::Arc;

use shunt_plugin_sdk::PluginRegistry;

pub use aws_eventstream::{
    AwsEventStreamDecoder, EventStreamError, EventStreamHeaderValue, EventStreamMessage,
    crc32_ieee, encode_eventstream_frame,
};
pub use aws_sigv4::{AwsSigV4Credentials, SigV4Output, sign_canonical, sign_upstream_request};
pub use budget::{AiBudgetFactory, AiBudgetPlugin, AiBudgetState, SpendLedgerTable};
pub use cache::{
    AiCacheFactory, AiCachePending, AiCachePlugin, AiCacheStatus, AiCacheTable,
    AiTranslatedResponseBody, CacheScope, CachedAiResponse, canonical_json_bytes,
    compute_cache_key, is_deterministic_request,
};
pub use dialects::bedrock::{
    BedrockStreamTranslator, bedrock_converse_path, bedrock_converse_to_openai_response,
    map_bedrock_stop_reason, openai_to_bedrock_converse_request,
};
pub use dialects::gemini::{
    GeminiSseTranslator, clean_gemini_schema, gemini_chat_path, gemini_embeddings_path,
    gemini_to_openai_embeddings_response, gemini_to_openai_response, map_gemini_finish_reason,
    openai_to_gemini_embeddings_request, openai_to_gemini_request,
};
pub use failover::{AiFailoverFactory, AiFailoverPlugin};
pub use ingress::anthropic::{
    OpenAiToAnthropicSseTranslator, anthropic_to_openai_request,
    map_openai_finish_to_anthropic_stop, openai_to_anthropic_response, rewrite_anthropic_request,
};
pub use ingress::responses::{
    ChatToResponsesSseTranslator, chat_to_responses_response, responses_to_chat_request,
    rewrite_openai_responses_request,
};
pub use model_router::{
    AiModelRouterFactory, AiModelRouterPlugin, ModelEntryConfig, ModelRule, TargetSpec,
};
pub use pricing::{
    ModelPricing, NANO_USD_PER_USD, PricingCatalog, nano_usd_to_usd, usd_to_nano_usd,
};
pub use provider_adapter::{
    AiProviderAdapterFactory, AiProviderAdapterPlugin, ProviderAuthConfig, ProviderInstanceConfig,
};
pub use routing::{
    LatencyRoutingConfig, RoutingCursorTable, TargetLatencyStats, TargetLatencyTable,
    UnknownCostPolicy, detect_required_capabilities, order_cost_targets, order_weighted_targets,
    pick_weighted_primary,
};
pub use sse::{SseEvent, SseParser};
pub use token_rate_limit::{
    AiTokenRateLimitFactory, AiTokenRateLimitPlugin, AiTokenReservation, QuotaWindowTable,
};
pub use tokens::{TokenEstimate, estimate_request_tokens, estimate_text_tokens};
pub use translate::{
    AnthropicSseTranslator, anthropic_to_openai_response, map_anthropic_stop_reason,
    openai_to_anthropic_request, rewrite_openai_embeddings_request, rewrite_openai_request,
};
pub use types::{
    AiCapability, AiEndpointKind, AiFailoverHistory, AiKeyPolicy, AiRequestMeta, AiTarget, AiUsage,
    AiUsageReport, BudgetWindow, DetectedEndpoint, FailoverEvent, ProviderDialect, RoutingStrategy,
    anthropic_error_response, endpoint_error_response, openai_error_response, wildcard_match,
};
pub use usage_tracker::{
    AiMetrics, AiMetricsSnapshot, AiUsageTrackerFactory, AiUsageTrackerPlugin, UsageSink,
};
pub use virtual_keys::{AiVirtualKeysFactory, AiVirtualKeysPlugin};

/// Registers all `shunt-ai` plugins (`ai-virtual-keys`, `ai-model-router`, `ai-cache`,
/// `ai-token-rate-limit`, `ai-budget`, `ai-provider-adapter`, `ai-failover`,
/// `ai-usage-tracker`) into `registry`.
pub fn register_ai_plugins(registry: &mut PluginRegistry, ai_metrics: Arc<AiMetrics>) {
    registry
        .register(AiVirtualKeysFactory)
        .register(AiModelRouterFactory)
        .register(AiCacheFactory::new(Arc::clone(&ai_metrics)))
        .register(AiTokenRateLimitFactory)
        .register(AiBudgetFactory::new(Arc::clone(&ai_metrics)))
        .register(AiProviderAdapterFactory)
        .register(AiFailoverFactory)
        .register(AiUsageTrackerFactory::new(ai_metrics));
}
