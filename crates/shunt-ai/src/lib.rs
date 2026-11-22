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

pub mod alerts;
pub mod audit;
pub mod aws_eventstream;
pub mod aws_sigv4;
pub mod budget;
pub mod cache;
pub mod cloud_auth;
pub mod dialects;
pub mod failover;
pub mod generation;
pub mod guardrails;
pub mod ingress;
pub mod inspector;
pub mod model_router;
pub mod multimodal;
pub mod multipart;
pub mod presets;
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

pub use alerts::{
    AiAlertBus, AiAlertEvent, AiAlertKind, AiAlertSeverity, AiAlertsFactory, AiAlertsPlugin,
    AlertDedupTable, AlertStatsSnapshot, AlertStatsTable, compute_hmac_sha256_hex,
    ensure_alert_bus, format_http_alert_payload, format_pagerduty_alert_payload,
    format_slack_alert_payload, push_alert_event, push_alert_event_ref,
};
pub use audit::{AiAuditFactory, AiAuditPlugin, AuditRecord, AuditStatsSnapshot, AuditStatsTable};
pub use aws_eventstream::{
    AwsEventStreamDecoder, EventStreamError, EventStreamHeaderValue, EventStreamMessage,
    crc32_ieee, encode_eventstream_frame,
};
pub use aws_sigv4::{AwsSigV4Credentials, SigV4Output, sign_canonical, sign_upstream_request};
pub use budget::{AiBudgetFactory, AiBudgetPlugin, AiBudgetState, SpendLedgerTable};
pub use cache::{
    AiCacheFactory, AiCachePending, AiCachePlugin, AiCacheStatus, AiCacheTable,
    AiSingleflightTable, AiTranslatedResponseBody, CacheScope, CachedAiResponse,
    SemanticCacheBackend, SemanticCacheConfig, SemanticCacheHit, SemanticCacheMode,
    SemanticCacheSnapshot, SemanticCacheTable, SemanticLookupQuery, SemanticLookupResult,
    canonical_json_bytes, compute_cache_key, cosine_similarity, extract_semantic_prompt_text,
    is_deterministic_request, parse_embedding_vector,
};
pub use cloud_auth::{
    AwsIamAuthConfig, AwsIamMode, AwsStsCredentials, AzureAdAuthConfig, AzureAdMode, CacheLookup,
    CloudTokenCache, CloudTokenSnapshot, CompiledCloudAuth, GcpIamAuthConfig, GcpIamMode,
    GcpServiceAccountKey, ResolvedCloudCredential, base64_std_decode, base64url_encode,
    compute_token_deadlines, decode_pem_pkcs8_private_key, parse_aws_json_credentials,
    parse_aws_sts_xml_credentials, parse_expires_in_value, parse_oauth_bearer_response,
    parse_rfc3339_utc_secs, sign_gcp_service_account_jwt,
};
pub use dialects::bedrock::{
    BedrockStreamTranslator, bedrock_converse_path, bedrock_converse_to_openai_response,
    bedrock_embeddings_to_openai_response, bedrock_invoke_path, map_bedrock_stop_reason,
    openai_to_bedrock_converse_request, openai_to_bedrock_converse_request_for_model,
    openai_to_bedrock_embeddings_request,
};
pub use dialects::gemini::{
    GeminiSseTranslator, clean_gemini_schema, gemini_chat_path, gemini_embeddings_path,
    gemini_to_openai_embeddings_response, gemini_to_openai_response, map_gemini_finish_reason,
    openai_to_gemini_embeddings_request, openai_to_gemini_request,
};
pub use failover::{AiFailoverFactory, AiFailoverPlugin, CooldownSnapshot, FailoverCircuitState};
pub use generation::{
    AiGenerationRecord, AiGenerationStore, AiRecordedCost, GenerationStoreSnapshot,
};
pub use guardrails::{
    AiGuardrailsFactory, AiGuardrailsPlugin, BuiltinDetector, ExternalGuardrailKind,
    ExternalGuardrailVerdict, GuardrailAction, GuardrailDirection, GuardrailFinding,
    GuardrailStage, GuardrailStatsSnapshot, GuardrailStatsTable, GuardrailSummary, LocalRedactor,
    RedactionMode, StreamViolationMode, TextSpanMatch, apply_char_span_redactions,
    apply_span_redactions, extract_request_text, extract_response_text, extract_sse_delta_text,
    format_redaction, is_valid_ipv4, is_valid_luhn, is_valid_ssn, parse_bedrock_guardrail_response,
    parse_lakera_guardrail_response, parse_llama_guard_response, parse_opa_guardrail_response,
    parse_presidio_analyze_response, parse_webhook_guardrail_response, scan_builtin_detector,
    visit_request_text_fields, visit_response_text_fields,
};
pub use ingress::anthropic::{
    OpenAiToAnthropicSseTranslator, anthropic_to_openai_request,
    map_openai_finish_to_anthropic_stop, openai_to_anthropic_response, rewrite_anthropic_request,
};
pub use ingress::responses::{
    ChatToResponsesSseTranslator, chat_to_responses_response, responses_to_chat_request,
    rewrite_openai_responses_request,
};
pub use inspector::{
    AiRuntimeInspect, ScopedAlertSnapshot, ScopedAuditSnapshot, ScopedCacheSnapshot,
    ScopedCloudTokenSnapshot, ScopedCooldownSnapshot, ScopedGenerationStoreSnapshot,
    ScopedGuardrailSnapshot, ScopedKeyPoolSnapshot, ScopedLatencySnapshot,
    ScopedSemanticCacheSnapshot, inspect_ai_runtime,
};
pub use model_router::{
    AiModelRouterFactory, AiModelRouterPlugin, ModelEntryConfig, ModelRule, MultipartBoundary,
    TargetSpec, classify_ai_endpoint,
};
pub use multimodal::{
    RerankRequestContext, bedrock_to_openai_rerank_response, extract_query_param,
    extract_realtime_ws_subprotocol_key, extract_rerank_context, gemini_imagen_path,
    gemini_imagen_to_openai_response, normalize_voyage_rerank_response,
    openai_to_bedrock_rerank_request, openai_to_gemini_imagen_request, rewrite_json_model_field,
    rewrite_openai_completions_request, rewrite_realtime_uri, rewrite_rerank_request,
    strip_realtime_ws_key_subprotocol,
};
pub use multipart::{
    extract_multipart_text_field, parse_multipart_boundary, rewrite_multipart_text_field,
};
pub use presets::{
    DefaultAuthShape, KeyPoolSnapshot, KeyPoolTable, PresetDefaults, ProviderPreset,
    default_auth_shape_for_dialect,
};
pub use pricing::{
    ModelPricing, NANO_USD_PER_USD, PricingCatalog, nano_usd_to_usd, usd_to_nano_usd,
};
pub use provider_adapter::{
    AiProviderAdapterFactory, AiProviderAdapterPlugin, ProviderAuthConfig, ProviderInstanceConfig,
};
pub use routing::{
    LatencyEntrySnapshot, LatencyRoutingConfig, RoutingCursorTable, TargetLatencyStats,
    TargetLatencyTable, UnknownCostPolicy, detect_required_capabilities, order_cost_targets,
    order_weighted_targets, pick_weighted_primary,
};
pub use sse::{SseEvent, SseParser};
pub use token_rate_limit::{
    AiTokenRateLimitFactory, AiTokenRateLimitPlugin, AiTokenReservation, QuotaWindowTable,
};
pub use tokens::{TokenEstimate, estimate_request_tokens, estimate_text_tokens};
pub use translate::{
    AnthropicSseTranslator, DropParamsConfig, adapt_anthropic_body_for_vertex,
    anthropic_to_openai_response, apply_request_param_transforms, budget_to_reasoning_effort,
    map_anthropic_stop_reason, openai_to_anthropic_request, reasoning_effort_to_budget,
    rewrite_openai_embeddings_request, rewrite_openai_request, vertex_anthropic_path,
};
pub use types::{
    AiCapability, AiEndpointKind, AiFailoverHistory, AiKeyPolicy, AiRequestMeta, AiTarget, AiUsage,
    AiUsageReport, BudgetWindow, DetectedEndpoint, FailoverEvent, IntraProviderKeyRetry,
    ProviderDialect, RoutingStrategy, anthropic_error_response, endpoint_error_response,
    openai_error_response, wildcard_match,
};
pub use usage_tracker::{
    AiDetailedMetricsSnapshot, AiMetrics, AiMetricsSnapshot, AiModelBreakdown,
    AiUsageTrackerFactory, AiUsageTrackerPlugin, UsageSink,
};
pub use virtual_keys::{AiVirtualKeysFactory, AiVirtualKeysPlugin};

/// Registers all `shunt-ai` plugins (`ai-virtual-keys`, `ai-model-router`, `ai-guardrails`,
/// `ai-cache`, `ai-token-rate-limit`, `ai-budget`, `ai-provider-adapter`, `ai-failover`,
/// `ai-usage-tracker`, `ai-audit`, `ai-alerts`) into `registry`.
pub fn register_ai_plugins(registry: &mut PluginRegistry, ai_metrics: Arc<AiMetrics>) {
    registry
        .register(AiVirtualKeysFactory)
        .register(AiModelRouterFactory)
        .register(AiGuardrailsFactory::new(Arc::clone(&ai_metrics)))
        .register(AiCacheFactory::new(Arc::clone(&ai_metrics)))
        .register(AiTokenRateLimitFactory)
        .register(AiBudgetFactory::new(Arc::clone(&ai_metrics)))
        .register(AiProviderAdapterFactory)
        .register(AiFailoverFactory)
        .register(AiUsageTrackerFactory::new(Arc::clone(&ai_metrics)))
        .register(AiAuditFactory::new(Arc::clone(&ai_metrics)))
        .register(AiAlertsFactory::new(ai_metrics));
}
