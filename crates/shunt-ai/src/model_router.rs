use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use shunt_plugin_sdk::{
    BufferedResponse, BuildContext, Bytes, Clock, Flow, HeaderMap, HeaderName, HeaderValue,
    HookMask, HookResult, HttpClient, HttpPlugin, HttpRequest, Method, PluginBuildError,
    PluginConfig, PluginFactory, RequestCtx, RequestHead, RequestSummary, ResponseHead,
    RouteDecision, StatusCode, UpstreamSelection, Uri, header,
};
use tokio::sync::Semaphore;

use crate::multimodal::extract_query_param;
use crate::multipart::{extract_multipart_text_field, parse_multipart_boundary};
use crate::pricing::{ModelPricing, PricingCatalog};
use crate::routing::{
    LatencyRoutingConfig, ProviderRoutingPreferences, RoutingCursorTable, TargetHeadroomTable,
    TargetLatencyTable, TargetThroughputTable, ThroughputRoutingConfig, UnknownCostPolicy,
    apply_provider_preferences, detect_required_capabilities, extract_end_user_from_body,
    filter_targets_by_context_window, order_cost_targets, order_weighted_targets,
};
use crate::tokens::estimate_request_tokens;
use crate::types::{
    AiCapability, AiEndUser, AiEndpointKind, AiFailoverHistory, AiKeyPolicy, AiRequestMeta,
    AiTarget, AiUsage, ContextOverflowFloor, DetectedEndpoint, IntraProviderKeyRetry,
    RoutingStrategy, endpoint_error_response, openai_error_response, percent_decode,
    resolve_env_secret, wildcard_match,
};

const DEFAULT_MAX_BODY_BYTES: usize = 1024 * 1024; // 1 MiB
const DEFAULT_COST_OUTPUT_TOKENS: u64 = 256;
const DEFAULT_SHADOW_TIMEOUT_MS: u64 = 5_000;
const DEFAULT_SHADOW_MAX_IN_FLIGHT: usize = 64;

fn default_weight() -> u32 {
    1
}

fn default_true() -> bool {
    true
}

fn default_cost_output_tokens() -> u64 {
    DEFAULT_COST_OUTPUT_TOKENS
}

fn default_shadow_sample_rate() -> f64 {
    1.0
}

fn default_shadow_timeout_ms() -> u64 {
    DEFAULT_SHADOW_TIMEOUT_MS
}

fn default_shadow_max_in_flight() -> usize {
    DEFAULT_SHADOW_MAX_IN_FLIGHT
}

#[derive(Debug, Clone, Deserialize)]
pub struct TargetSpec {
    /// Named provider ID matching an entry in `ai-provider-adapter`'s `providers` map.
    pub provider: String,
    pub upstream: String,
    /// Target model name sent to the provider. If omitted, forwards the client's requested model.
    #[serde(default)]
    pub model: Option<String>,
    /// Optional explicit endpoint override passed to `UpstreamSelection::endpoint_override`.
    #[serde(default)]
    pub endpoint_override: Option<String>,
    /// Optional capability tags (`chat`, `streaming`, `tools`, `vision`, `json_schema`, `reasoning`, `embeddings`, ...).
    #[serde(default)]
    pub capabilities: Vec<AiCapability>,
    /// Relative traffic weight used by `strategy = "weighted"` (default: `1`, must be `>= 1`).
    #[serde(default = "default_weight")]
    pub weight: u32,
    /// Optional per-target default JSON parameters applied when absent/null in the client body.
    #[serde(default)]
    pub default_params: BTreeMap<String, Value>,
    /// Optional per-target JSON parameter overrides injected unconditionally before translation.
    #[serde(default)]
    pub override_params: BTreeMap<String, Value>,
    /// Optional explicit input context window length in tokens.
    #[serde(default)]
    pub context_window: Option<u64>,
    /// Optional explicit maximum output tokens advertised in `GET /v1/models`.
    #[serde(default)]
    pub max_output_tokens: Option<u64>,
    /// Zero Data Retention compliance flag (`provider.data_collection = "deny"` / `zdr = true`).
    #[serde(default)]
    pub zdr: bool,
    /// Compliance / geographic region tags (e.g., `["eu", "us-east"]`).
    #[serde(default)]
    pub regions: Vec<String>,
    /// Arbitrary compliance / deployment tags (e.g., `["hipaa", "soc2"]`).
    #[serde(default)]
    pub tags: Vec<String>,
    /// Optional declared upstream provider RPM limit for `strategy = "headroom"`.
    #[serde(default)]
    pub upstream_rpm: Option<u64>,
    /// Optional declared upstream provider TPM limit for `strategy = "headroom"`.
    #[serde(default)]
    pub upstream_tpm: Option<u64>,
    /// Optional per-target TTFT / response-headers timeout override in milliseconds.
    #[serde(default)]
    pub ttft_timeout_ms: Option<u64>,
}

impl TargetSpec {
    pub fn resolve(&self, requested_model: &str) -> AiTarget {
        AiTarget {
            provider: self.provider.clone(),
            upstream: self.upstream.clone(),
            model: self
                .model
                .clone()
                .unwrap_or_else(|| requested_model.to_owned()),
            endpoint_override: self.endpoint_override.clone(),
            capabilities: self.capabilities.clone(),
            weight: self.weight.max(1),
            default_params: self.default_params.clone(),
            override_params: self.override_params.clone(),
            context_window: self.context_window,
            max_output_tokens: self.max_output_tokens,
            zdr: self.zdr,
            regions: self.regions.clone(),
            tags: self.tags.clone(),
            upstream_rpm: self.upstream_rpm,
            upstream_tpm: self.upstream_tpm,
            ttft_timeout_ms: self.ttft_timeout_ms,
        }
    }
}

/// Optional off-path AI traffic shadow target dispatched via [`HttpClient`] without blocking
/// or altering the primary response.
#[derive(Debug, Clone, Deserialize)]
pub struct ShadowTargetSpec {
    /// Human-readable shadow target name for diagnostics/metrics.
    pub name: String,
    /// Full HTTP/HTTPS URL to receive shadowed AI JSON requests.
    pub url: String,
    /// Optional model name to substitute into the shadowed JSON request's `"model"` field.
    #[serde(default)]
    pub model: Option<String>,
    /// Fraction of matching requests to shadow in `[0.0, 1.0]` (default: `1.0`).
    #[serde(default = "default_shadow_sample_rate")]
    pub sample_rate: f64,
    /// Per-shadow request timeout in milliseconds (default: `5000`).
    #[serde(default = "default_shadow_timeout_ms")]
    pub timeout_ms: u64,
    /// Maximum concurrent in-flight shadow requests (default: `64`).
    #[serde(default = "default_shadow_max_in_flight")]
    pub max_in_flight: usize,
    /// Optional extra HTTP headers (values support `env:VAR_NAME`).
    #[serde(default)]
    pub headers: BTreeMap<String, String>,
    /// Optional model glob filters limiting which requested models are shadowed (empty = all).
    #[serde(default)]
    pub models: Vec<String>,
}

struct CompiledShadowTarget {
    name: String,
    uri: Uri,
    model: Option<String>,
    sample_rate_bps: u32,
    timeout: Duration,
    headers: Vec<(HeaderName, HeaderValue)>,
    models: Vec<String>,
    semaphore: Arc<Semaphore>,
    cursor: AtomicU64,
}

impl CompiledShadowTarget {
    fn should_sample(&self) -> bool {
        if self.sample_rate_bps == 0 {
            return false;
        }
        if self.sample_rate_bps >= 10_000 {
            return true;
        }
        let n = self.cursor.fetch_add(1, Ordering::Relaxed);
        let rate = self.sample_rate_bps as u64;
        ((n.wrapping_add(1)).wrapping_mul(rate) / 10_000) > (n.wrapping_mul(rate) / 10_000)
    }

    fn matches_model(&self, model: &str) -> bool {
        self.models.is_empty() || self.models.iter().any(|p| wildcard_match(p, model))
    }
}

/// Read-only snapshot of AI shadow traffic counters for Admin Inspector APIs.
#[derive(Debug, Clone, Default, Serialize)]
pub struct AiShadowStatsSnapshot {
    pub sent: u64,
    pub dropped: u64,
    pub errors: u64,
}

/// `StateStore`-backed AI shadow traffic counter table.
#[derive(Debug, Default)]
pub struct AiShadowStatsTable {
    sent: AtomicU64,
    dropped: AtomicU64,
    errors: AtomicU64,
}

impl AiShadowStatsTable {
    pub fn record_sent(&self) {
        self.sent.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_dropped(&self) {
        self.dropped.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_error(&self) {
        self.errors.fetch_add(1, Ordering::Relaxed);
    }

    pub fn snapshot(&self) -> AiShadowStatsSnapshot {
        AiShadowStatsSnapshot {
            sent: self.sent.load(Ordering::Relaxed),
            dropped: self.dropped.load(Ordering::Relaxed),
            errors: self.errors.load(Ordering::Relaxed),
        }
    }
}

/// Entry under `models.<alias>`: accepts either a compact target array (inheriting router `strategy`)
/// or a structured `{ strategy = "...", targets = [...] }` table.
#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
pub enum ModelEntryConfig {
    Targets(Vec<TargetSpec>),
    Detailed {
        #[serde(default)]
        strategy: Option<RoutingStrategy>,
        targets: Vec<TargetSpec>,
    },
}

impl ModelEntryConfig {
    fn targets(&self) -> &[TargetSpec] {
        match self {
            ModelEntryConfig::Targets(t) => t,
            ModelEntryConfig::Detailed { targets, .. } => targets,
        }
    }

    fn strategy(&self, fallback: RoutingStrategy) -> RoutingStrategy {
        match self {
            ModelEntryConfig::Targets(_) => fallback,
            ModelEntryConfig::Detailed { strategy, .. } => strategy.unwrap_or(fallback),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct ModelRule {
    /// Glob-style pattern supporting `*` wildcards (e.g. `"claude-*"`, `"gpt-4*"`, `"*"`).
    pub pattern: String,
    /// Optional per-rule routing strategy override (defaults to router-level `strategy`).
    #[serde(default)]
    pub strategy: Option<RoutingStrategy>,
    pub targets: Vec<TargetSpec>,
}

#[derive(Debug, Deserialize)]
#[serde(default)]
struct AiModelRouterConfig {
    /// Maximum buffered JSON request body size in bytes (default: 1 MiB).
    max_body_bytes: usize,
    /// Automatically raise `decision.max_attempts` to at least the length of the selected
    /// target fallback chain (default: true).
    #[serde(default = "default_true")]
    auto_max_attempts: bool,
    /// Synthesize and serve `GET /v1/models` and `GET /v1/models/{id}` directly without
    /// buffering bodies or hopping to an upstream (default: true).
    #[serde(default = "default_true")]
    serve_models_endpoint: bool,
    /// Serve `POST /v1/messages/count_tokens` locally using Shunt's fast deterministic
    /// token estimator without calling upstream providers (default: true).
    #[serde(default = "default_true")]
    serve_count_tokens_endpoint: bool,
    /// Default smart routing strategy across models/rules/defaults (`priority`, `weighted`, `latency`, `cost`).
    #[serde(default)]
    strategy: RoutingStrategy,
    /// Optional explicit strategy override for `default_targets`.
    #[serde(default)]
    default_strategy: Option<RoutingStrategy>,
    /// Emit `x-shunt-routing-strategy`, `x-shunt-selected-provider`, and `x-shunt-selected-model`
    /// response headers (default: false; enables `ON_RESPONSE_HEADERS` only when true).
    #[serde(default)]
    include_routing_headers: bool,
    /// Tuning parameters for `strategy = "latency"`.
    #[serde(default)]
    latency: LatencyRoutingConfig,
    /// Tuning parameters for `strategy = "throughput"`.
    #[serde(default)]
    throughput: ThroughputRoutingConfig,
    /// Custom per-model pricing overrides for `strategy = "cost"`.
    #[serde(default)]
    pricing: HashMap<String, ModelPricing>,
    /// Optional path to an external JSON pricing catalog (Shunt or LiteLLM format).
    #[serde(default)]
    pricing_file: Option<PathBuf>,
    /// Include Shunt's built-in reference model pricing catalog for `strategy = "cost"` (default: true).
    #[serde(default = "default_true")]
    use_builtin_pricing: bool,
    /// Optional fallback pricing for models not found in `pricing` or built-ins.
    #[serde(default)]
    default_pricing: Option<ModelPricing>,
    /// How `strategy = "cost"` ranks targets whose model has no pricing entry (`last` or `free`).
    #[serde(default)]
    unknown_cost_policy: UnknownCostPolicy,
    /// Estimated output tokens used when ranking targets by `strategy = "cost"` (default: 256).
    #[serde(default = "default_cost_output_tokens")]
    cost_estimated_output_tokens: u64,
    /// Enable OpenRouter-style per-request `models[]` and `provider: { ... }` routing overrides
    /// (default: false). Overrides are strictly bounded by virtual-key ACLs and stripped before
    /// forwarding upstream.
    #[serde(default)]
    allow_request_routing_overrides: bool,
    /// Filter out targets whose declared or catalog `context_window` cannot fit the estimated
    /// input token count (default: true).
    #[serde(default = "default_true")]
    enforce_context_window: bool,
    /// Extra safety buffer tokens added to estimated input tokens during context-window checks (default: 0).
    #[serde(default)]
    context_window_safety_margin_tokens: u64,
    /// Optional incoming HTTP header to extract an end-user identifier (`AiEndUser`) from,
    /// taking precedence over JSON `user` / `metadata.user_id`.
    #[serde(default)]
    end_user_header: Option<String>,
    /// Optional off-path AI shadow targets dispatched asynchronously via `HttpClient`.
    #[serde(default)]
    shadow_targets: Vec<ShadowTargetSpec>,
    /// Additional concrete model IDs to advertise on `GET /v1/models` (useful for
    /// wildcard-routed models like `"claude-3-5-sonnet-20241022"` or `"gemini-2.5-flash"`).
    exposed_models: Vec<String>,
    /// Exact model name -> target list or `{ strategy, targets }` table.
    models: HashMap<String, ModelEntryConfig>,
    /// Ordered wildcard pattern rules checked when no exact match exists in `models`.
    rules: Vec<ModelRule>,
    /// Catch-all fallback targets when neither `models` nor `rules` match.
    default_targets: Vec<TargetSpec>,
    /// Optional dedicated targets for `/v1/files*` resource endpoints (falls back to `default_targets`).
    #[serde(default)]
    files_targets: Vec<TargetSpec>,
    /// Optional dedicated targets for `/v1/batches*` resource endpoints (falls back to `default_targets`).
    #[serde(default)]
    batches_targets: Vec<TargetSpec>,
}

impl Default for AiModelRouterConfig {
    fn default() -> Self {
        Self {
            max_body_bytes: DEFAULT_MAX_BODY_BYTES,
            auto_max_attempts: true,
            serve_models_endpoint: true,
            serve_count_tokens_endpoint: true,
            strategy: RoutingStrategy::Priority,
            default_strategy: None,
            include_routing_headers: false,
            latency: LatencyRoutingConfig::default(),
            throughput: ThroughputRoutingConfig::default(),
            pricing: HashMap::new(),
            pricing_file: None,
            use_builtin_pricing: true,
            default_pricing: None,
            unknown_cost_policy: UnknownCostPolicy::Last,
            cost_estimated_output_tokens: DEFAULT_COST_OUTPUT_TOKENS,
            allow_request_routing_overrides: false,
            enforce_context_window: true,
            context_window_safety_margin_tokens: 0,
            end_user_header: None,
            shadow_targets: Vec::new(),
            exposed_models: Vec::new(),
            models: HashMap::new(),
            rules: Vec::new(),
            default_targets: Vec::new(),
            files_targets: Vec::new(),
            batches_targets: Vec::new(),
        }
    }
}

/// Multipart boundary captured from the incoming `Content-Type` header so `ai-provider-adapter`
/// can rewrite aliased `model` fields in multipart audio/image requests without re-parsing headers.
#[derive(Debug, Clone)]
pub struct MultipartBoundary(pub String);

/// Optional explicit provider selector header (`x-shunt-provider`) captured for resource endpoints
/// (`/v1/files*`, `/v1/batches*`).
#[derive(Debug, Clone)]
struct RequestedProviderHeader(String);

/// Factory for the `ai-model-router` plugin.
pub struct AiModelRouterFactory;

impl PluginFactory for AiModelRouterFactory {
    fn name(&self) -> &str {
        "ai-model-router"
    }

    fn build(
        &self,
        config: &PluginConfig,
        ctx: &BuildContext,
    ) -> Result<Arc<dyn HttpPlugin>, PluginBuildError> {
        let cfg: AiModelRouterConfig = config.deserialize(self.name())?;

        if cfg.max_body_bytes == 0 {
            return Err(PluginBuildError::BuildFailed {
                plugin: self.name().to_owned(),
                message: "`max_body_bytes` must be > 0".to_owned(),
            });
        }

        if let Err(msg) = cfg.latency.validate() {
            return Err(PluginBuildError::BuildFailed {
                plugin: self.name().to_owned(),
                message: msg,
            });
        }
        if let Err(msg) = cfg.throughput.validate() {
            return Err(PluginBuildError::BuildFailed {
                plugin: self.name().to_owned(),
                message: msg,
            });
        }

        let end_user_header = match &cfg.end_user_header {
            Some(raw) => Some(HeaderName::from_bytes(raw.as_bytes()).map_err(|e| {
                PluginBuildError::BuildFailed {
                    plugin: self.name().to_owned(),
                    message: format!("invalid `end_user_header` `{raw}`: {e}"),
                }
            })?),
            None => None,
        };

        let mut compiled_shadows = Vec::with_capacity(cfg.shadow_targets.len());
        for (idx, s) in cfg.shadow_targets.into_iter().enumerate() {
            if s.name.trim().is_empty() {
                return Err(PluginBuildError::BuildFailed {
                    plugin: self.name().to_owned(),
                    message: format!("`shadow_targets[{idx}].name` cannot be empty"),
                });
            }
            if !s.url.starts_with("http://") && !s.url.starts_with("https://") {
                return Err(PluginBuildError::BuildFailed {
                    plugin: self.name().to_owned(),
                    message: format!(
                        "`shadow_targets[{idx}].url` (`{}`) must use http:// or https://",
                        s.url
                    ),
                });
            }
            if !s.sample_rate.is_finite() || s.sample_rate < 0.0 || s.sample_rate > 1.0 {
                return Err(PluginBuildError::BuildFailed {
                    plugin: self.name().to_owned(),
                    message: format!("`shadow_targets[{idx}].sample_rate` must be in [0.0, 1.0]"),
                });
            }
            if s.timeout_ms == 0 {
                return Err(PluginBuildError::BuildFailed {
                    plugin: self.name().to_owned(),
                    message: format!("`shadow_targets[{idx}].timeout_ms` must be >= 1"),
                });
            }
            if s.max_in_flight == 0 {
                return Err(PluginBuildError::BuildFailed {
                    plugin: self.name().to_owned(),
                    message: format!("`shadow_targets[{idx}].max_in_flight` must be >= 1"),
                });
            }
            let mut headers = Vec::with_capacity(s.headers.len());
            for (k, v) in s.headers {
                let resolved =
                    resolve_env_secret(&v).map_err(|msg| PluginBuildError::BuildFailed {
                        plugin: self.name().to_owned(),
                        message: format!("`shadow_targets[{idx}].headers.{k}`: {msg}"),
                    })?;
                let name = HeaderName::from_bytes(k.as_bytes()).map_err(|e| {
                    PluginBuildError::BuildFailed {
                        plugin: self.name().to_owned(),
                        message: format!(
                            "`shadow_targets[{idx}].headers`: invalid name `{k}`: {e}"
                        ),
                    }
                })?;
                let val = HeaderValue::from_str(&resolved).map_err(|e| {
                    PluginBuildError::BuildFailed {
                        plugin: self.name().to_owned(),
                        message: format!(
                            "`shadow_targets[{idx}].headers.{k}`: invalid header value: {e}"
                        ),
                    }
                })?;
                headers.push((name, val));
            }
            let parsed_uri: Uri = s.url.parse().map_err(|e| PluginBuildError::BuildFailed {
                plugin: self.name().to_owned(),
                message: format!(
                    "`shadow_targets[{idx}].url` (`{}`): invalid URI: {e}",
                    s.url
                ),
            })?;
            compiled_shadows.push(Arc::new(CompiledShadowTarget {
                name: s.name,
                uri: parsed_uri,
                model: s.model,
                sample_rate_bps: (s.sample_rate.clamp(0.0, 1.0) * 10_000.0).round() as u32,
                timeout: Duration::from_millis(s.timeout_ms),
                headers,
                models: s.models,
                semaphore: Arc::new(Semaphore::new(s.max_in_flight.max(1))),
                cursor: AtomicU64::new(0),
            }));
        }

        if cfg.models.is_empty()
            && cfg.rules.is_empty()
            && cfg.default_targets.is_empty()
            && cfg.files_targets.is_empty()
            && cfg.batches_targets.is_empty()
        {
            return Err(PluginBuildError::BuildFailed {
                plugin: self.name().to_owned(),
                message: "configure at least one entry in `models`, `rules`, `default_targets`, `files_targets`, or `batches_targets`"
                    .to_owned(),
            });
        }

        for (model, entry) in &cfg.models {
            validate_targets(self.name(), &format!("models.{model}"), entry.targets())?;
        }
        for rule in &cfg.rules {
            if rule.pattern.trim().is_empty() {
                return Err(PluginBuildError::BuildFailed {
                    plugin: self.name().to_owned(),
                    message: "rule `pattern` cannot be empty".to_owned(),
                });
            }
            validate_targets(
                self.name(),
                &format!("rules[{}]", rule.pattern),
                &rule.targets,
            )?;
        }
        if !cfg.default_targets.is_empty() {
            validate_targets(self.name(), "default_targets", &cfg.default_targets)?;
        }
        if !cfg.files_targets.is_empty() {
            validate_targets(self.name(), "files_targets", &cfg.files_targets)?;
        }
        if !cfg.batches_targets.is_empty() {
            validate_targets(self.name(), "batches_targets", &cfg.batches_targets)?;
        }

        let pricing_catalog = PricingCatalog::new_with_file(
            cfg.pricing,
            cfg.use_builtin_pricing,
            cfg.default_pricing,
            cfg.pricing_file.as_deref(),
        )
        .map_err(|message| PluginBuildError::BuildFailed {
            plugin: self.name().to_owned(),
            message,
        })?;

        let uses_strategy = |target: RoutingStrategy| -> bool {
            cfg.strategy == target
                || cfg.default_strategy == Some(target)
                || cfg
                    .models
                    .values()
                    .any(|e| e.strategy(cfg.strategy) == target)
                || cfg
                    .rules
                    .iter()
                    .any(|r| r.strategy.unwrap_or(cfg.strategy) == target)
        };

        let uses_latency =
            uses_strategy(RoutingStrategy::Latency) || cfg.allow_request_routing_overrides;
        let uses_throughput =
            uses_strategy(RoutingStrategy::Throughput) || cfg.allow_request_routing_overrides;
        let uses_headroom =
            uses_strategy(RoutingStrategy::Headroom) || cfg.allow_request_routing_overrides;
        let uses_cursors =
            uses_latency || uses_throughput || uses_strategy(RoutingStrategy::Weighted);

        let cursors = if uses_cursors {
            Some(
                ctx.state_handle()
                    .get_or_init("routing_cursors", RoutingCursorTable::default),
            )
        } else {
            None
        };

        let latency_table = if uses_latency {
            Some(
                ctx.state_handle()
                    .get_or_init("routing_latency", TargetLatencyTable::default),
            )
        } else {
            None
        };

        let throughput_table = if uses_throughput {
            Some(
                ctx.state_handle()
                    .get_or_init("routing_throughput", TargetThroughputTable::default),
            )
        } else {
            None
        };

        let headroom_table = if uses_headroom {
            Some(
                ctx.state_handle()
                    .get_or_init("routing_headroom", TargetHeadroomTable::default),
            )
        } else {
            None
        };

        let shadow_stats = if !compiled_shadows.is_empty() {
            Some(
                ctx.state_handle()
                    .get_or_init("ai_shadow_stats", AiShadowStatsTable::default),
            )
        } else {
            None
        };

        let (models_list_json, models_by_id, catalog_entries) = compile_models_catalog(
            &cfg.models,
            &cfg.rules,
            &cfg.default_targets,
            &cfg.exposed_models,
            &pricing_catalog,
        );

        Ok(Arc::new(AiModelRouterPlugin {
            max_body_bytes: cfg.max_body_bytes,
            auto_max_attempts: cfg.auto_max_attempts,
            serve_models_endpoint: cfg.serve_models_endpoint,
            serve_count_tokens_endpoint: cfg.serve_count_tokens_endpoint,
            default_router_strategy: cfg.strategy,
            default_targets_strategy: cfg.default_strategy.unwrap_or(cfg.strategy),
            include_routing_headers: cfg.include_routing_headers,
            allow_request_routing_overrides: cfg.allow_request_routing_overrides,
            enforce_context_window: cfg.enforce_context_window,
            context_window_safety_margin_tokens: cfg.context_window_safety_margin_tokens,
            end_user_header,
            latency_cfg: cfg.latency,
            throughput_cfg: cfg.throughput,
            pricing_catalog,
            unknown_cost_policy: cfg.unknown_cost_policy,
            cost_estimated_output_tokens: cfg.cost_estimated_output_tokens,
            clock: ctx.clock(),
            http_client: ctx.http_client(),
            cursors,
            latency_table,
            throughput_table,
            headroom_table,
            shadow_targets: compiled_shadows,
            shadow_stats,
            models: cfg.models,
            rules: cfg.rules,
            default_targets: cfg.default_targets,
            files_targets: cfg.files_targets,
            batches_targets: cfg.batches_targets,
            models_list_json,
            models_by_id,
            catalog_entries,
        }))
    }
}

fn validate_targets(
    plugin: &str,
    label: &str,
    targets: &[TargetSpec],
) -> Result<(), PluginBuildError> {
    if targets.is_empty() {
        return Err(PluginBuildError::BuildFailed {
            plugin: plugin.to_owned(),
            message: format!("`{label}` must define at least one target"),
        });
    }
    for (idx, t) in targets.iter().enumerate() {
        if t.provider.trim().is_empty() {
            return Err(PluginBuildError::BuildFailed {
                plugin: plugin.to_owned(),
                message: format!("`{label}[{idx}].provider` cannot be empty"),
            });
        }
        if t.upstream.trim().is_empty() {
            return Err(PluginBuildError::BuildFailed {
                plugin: plugin.to_owned(),
                message: format!("`{label}[{idx}].upstream` cannot be empty"),
            });
        }
        if t.weight == 0 {
            return Err(PluginBuildError::BuildFailed {
                plugin: plugin.to_owned(),
                message: format!("`{label}[{idx}].weight` must be >= 1"),
            });
        }
    }
    Ok(())
}

/// Pre-serializes deterministic, enriched OpenAI `GET /v1/models` and `GET /v1/models/{id}`
/// payloads once at snapshot compilation time (zero per-request sorting or serialization).
fn compile_models_catalog(
    models: &HashMap<String, ModelEntryConfig>,
    rules: &[ModelRule],
    default_targets: &[TargetSpec],
    exposed_models: &[String],
    pricing_catalog: &PricingCatalog,
) -> (Bytes, HashMap<String, Bytes>, Vec<(String, Value)>) {
    // BTreeMap guarantees deterministic alphabetical ordering by model `id`.
    let mut catalog: BTreeMap<String, (String, Vec<TargetSpec>)> = BTreeMap::new();

    // 1. Explicit model aliases in `models`.
    for (alias, entry) in models {
        let targets = entry.targets().to_vec();
        let owner = targets
            .first()
            .map(|t| t.provider.clone())
            .unwrap_or_else(|| "shunt".to_owned());
        catalog.insert(alias.clone(), (owner, targets));
    }

    // 2. Concrete `model` names referenced inside `rules` targets.
    for rule in rules {
        for t in &rule.targets {
            if let Some(m) = t.model.as_deref().map(str::trim).filter(|m| !m.is_empty()) {
                catalog
                    .entry(m.to_owned())
                    .or_insert_with(|| (t.provider.clone(), vec![t.clone()]));
            }
        }
    }

    // 3. Explicit `exposed_models` advertised for wildcard rules.
    for raw in exposed_models {
        let id = raw.trim();
        if id.is_empty() {
            continue;
        }
        let (owner, resolved_specs) =
            resolve_owner_and_targets_for_exposed(id, models, rules, default_targets);
        catalog
            .entry(id.to_owned())
            .or_insert((owner, resolved_specs));
    }

    let mut data_entries = Vec::with_capacity(catalog.len());
    let mut models_by_id = HashMap::with_capacity(catalog.len());
    let mut ordered_entries = Vec::with_capacity(catalog.len());

    for (id, (owned_by, specs)) in catalog {
        let entry = build_enriched_model_entry(&id, &owned_by, &specs, pricing_catalog);
        let single_bytes = Bytes::from(serde_json::to_vec(&entry).unwrap_or_default());
        ordered_entries.push((id.clone(), entry.clone()));
        models_by_id.insert(id, single_bytes);
        data_entries.push(entry);
    }

    let list_payload = json!({
        "object": "list",
        "data": data_entries,
    });
    let list_bytes = Bytes::from(serde_json::to_vec(&list_payload).unwrap_or_default());

    (list_bytes, models_by_id, ordered_entries)
}

fn build_enriched_model_entry(
    id: &str,
    owned_by: &str,
    specs: &[TargetSpec],
    pricing_catalog: &PricingCatalog,
) -> Value {
    let mut obj = serde_json::Map::new();
    obj.insert("id".to_owned(), Value::String(id.to_owned()));
    obj.insert("object".to_owned(), Value::String("model".to_owned()));
    obj.insert("created".to_owned(), json!(0));
    obj.insert("owned_by".to_owned(), Value::String(owned_by.to_owned()));

    let primary_concrete_model = specs.first().and_then(|s| s.model.as_deref()).unwrap_or(id);
    let pricing = pricing_catalog.lookup(primary_concrete_model, id);

    let context_length = specs
        .iter()
        .filter_map(|s| {
            let concrete = s.model.as_deref().unwrap_or(id);
            s.context_window.or_else(|| {
                pricing_catalog
                    .lookup(concrete, id)
                    .and_then(|p| p.max_input_tokens)
            })
        })
        .max()
        .or_else(|| pricing.and_then(|p| p.max_input_tokens));
    if let Some(ctx_len) = context_length {
        obj.insert("context_length".to_owned(), json!(ctx_len));
    }

    let max_output = specs
        .iter()
        .filter_map(|s| {
            let concrete = s.model.as_deref().unwrap_or(id);
            s.max_output_tokens.or_else(|| {
                pricing_catalog
                    .lookup(concrete, id)
                    .and_then(|p| p.max_output_tokens)
            })
        })
        .max()
        .or_else(|| pricing.and_then(|p| p.max_output_tokens));
    if let Some(max_out) = max_output {
        obj.insert("max_output_tokens".to_owned(), json!(max_out));
    }

    if let Some(p) = pricing {
        let mut p_obj = serde_json::Map::new();
        p_obj.insert(
            "prompt".to_owned(),
            Value::String(format!("{:.10}", p.input_per_million_usd / 1_000_000.0)),
        );
        p_obj.insert(
            "completion".to_owned(),
            Value::String(format!("{:.10}", p.output_per_million_usd / 1_000_000.0)),
        );
        p_obj.insert(
            "input_per_million_usd".to_owned(),
            json!(p.input_per_million_usd),
        );
        p_obj.insert(
            "output_per_million_usd".to_owned(),
            json!(p.output_per_million_usd),
        );
        if let Some(cr) = p.cached_input_per_million_usd {
            p_obj.insert(
                "cache_read".to_owned(),
                Value::String(format!("{:.10}", cr / 1_000_000.0)),
            );
            p_obj.insert("cached_input_per_million_usd".to_owned(), json!(cr));
        }
        if let Some(cw) = p.cache_write_per_million_usd {
            p_obj.insert(
                "cache_write".to_owned(),
                Value::String(format!("{:.10}", cw / 1_000_000.0)),
            );
            p_obj.insert("cache_write_per_million_usd".to_owned(), json!(cw));
        }
        obj.insert("pricing".to_owned(), Value::Object(p_obj));
    }

    if !specs.is_empty() {
        let mut providers = Vec::new();
        let mut seen_providers = HashSet::new();
        let mut caps = BTreeSet::new();
        let mut regions = BTreeSet::new();
        let mut any_zdr = false;
        for s in specs {
            if seen_providers.insert(s.provider.as_str()) {
                providers.push(Value::String(s.provider.clone()));
            }
            for c in &s.capabilities {
                caps.insert(c.as_str());
            }
            for r in &s.regions {
                regions.insert(r.clone());
            }
            if s.zdr {
                any_zdr = true;
            }
        }
        obj.insert("providers".to_owned(), Value::Array(providers));
        if !caps.is_empty() {
            obj.insert(
                "capabilities".to_owned(),
                Value::Array(
                    caps.into_iter()
                        .map(|c| Value::String(c.to_owned()))
                        .collect(),
                ),
            );
        }
        if any_zdr {
            obj.insert("zdr".to_owned(), Value::Bool(true));
        }
        if !regions.is_empty() {
            obj.insert(
                "regions".to_owned(),
                Value::Array(regions.into_iter().map(Value::String).collect()),
            );
        }
    }

    Value::Object(obj)
}

fn resolve_owner_and_targets_for_exposed(
    model_id: &str,
    models: &HashMap<String, ModelEntryConfig>,
    rules: &[ModelRule],
    default_targets: &[TargetSpec],
) -> (String, Vec<TargetSpec>) {
    if let Some(entry) = models.get(model_id)
        && let Some(first) = entry.targets().first()
    {
        return (first.provider.clone(), entry.targets().to_vec());
    }
    for rule in rules {
        if wildcard_match(&rule.pattern, model_id)
            && let Some(first) = rule.targets.first()
        {
            return (first.provider.clone(), rule.targets.clone());
        }
    }
    if let Some(first) = default_targets.first() {
        return (first.provider.clone(), default_targets.to_vec());
    }
    ("shunt".to_owned(), Vec::new())
}

/// Parses incoming AI requests (`/v1/chat/completions`, `/v1/messages`, `/v1/responses`,
/// `/v1/embeddings`, `GET /v1/models`, `POST /v1/messages/count_tokens`), enforces capability
/// and context-window guards, applies per-request routing overrides and smart routing strategies
/// (`priority`, `weighted`, `latency`, `cost`, `throughput`, `headroom`), optionally dispatches
/// sampled AI shadow requests, and stores typed [`AiRequestMeta`] in `ctx.extensions`.
pub struct AiModelRouterPlugin {
    max_body_bytes: usize,
    auto_max_attempts: bool,
    serve_models_endpoint: bool,
    serve_count_tokens_endpoint: bool,
    default_router_strategy: RoutingStrategy,
    default_targets_strategy: RoutingStrategy,
    include_routing_headers: bool,
    allow_request_routing_overrides: bool,
    enforce_context_window: bool,
    context_window_safety_margin_tokens: u64,
    end_user_header: Option<HeaderName>,
    latency_cfg: LatencyRoutingConfig,
    throughput_cfg: ThroughputRoutingConfig,
    pricing_catalog: PricingCatalog,
    unknown_cost_policy: UnknownCostPolicy,
    cost_estimated_output_tokens: u64,
    clock: Arc<dyn Clock>,
    http_client: Option<Arc<dyn HttpClient>>,
    cursors: Option<Arc<RoutingCursorTable>>,
    latency_table: Option<Arc<TargetLatencyTable>>,
    throughput_table: Option<Arc<TargetThroughputTable>>,
    headroom_table: Option<Arc<TargetHeadroomTable>>,
    shadow_targets: Vec<Arc<CompiledShadowTarget>>,
    shadow_stats: Option<Arc<AiShadowStatsTable>>,
    models: HashMap<String, ModelEntryConfig>,
    rules: Vec<ModelRule>,
    default_targets: Vec<TargetSpec>,
    files_targets: Vec<TargetSpec>,
    batches_targets: Vec<TargetSpec>,
    models_list_json: Bytes,
    models_by_id: HashMap<String, Bytes>,
    catalog_entries: Vec<(String, Value)>,
}

impl AiModelRouterPlugin {
    fn resolve_targets_with_strategy(
        &self,
        requested_model: &str,
    ) -> Option<(String, RoutingStrategy, Vec<AiTarget>)> {
        if let Some(entry) = self.models.get(requested_model) {
            let strategy = entry.strategy(self.default_router_strategy);
            let targets = entry
                .targets()
                .iter()
                .map(|s| s.resolve(requested_model))
                .collect();
            return Some((format!("model:{requested_model}"), strategy, targets));
        }
        for rule in &self.rules {
            if wildcard_match(&rule.pattern, requested_model) {
                let strategy = rule.strategy.unwrap_or(self.default_router_strategy);
                let targets = rule
                    .targets
                    .iter()
                    .map(|s| s.resolve(requested_model))
                    .collect();
                return Some((format!("rule:{}", rule.pattern), strategy, targets));
            }
        }
        if !self.default_targets.is_empty() {
            let targets = self
                .default_targets
                .iter()
                .map(|s| s.resolve(requested_model))
                .collect();
            return Some(("default".to_owned(), self.default_targets_strategy, targets));
        }
        None
    }

    fn apply_strategy(
        &self,
        group_key: &str,
        strategy: RoutingStrategy,
        targets: Vec<AiTarget>,
        endpoint: AiEndpointKind,
        requested_model: &str,
        raw_body: &[u8],
    ) -> Vec<AiTarget> {
        if targets.len() <= 1 {
            return targets;
        }
        match strategy {
            RoutingStrategy::Priority => targets,
            RoutingStrategy::Weighted => {
                let cursor = self
                    .cursors
                    .as_ref()
                    .map(|c| c.next(group_key))
                    .unwrap_or(0);
                order_weighted_targets(targets, cursor)
            }
            RoutingStrategy::Latency => {
                let Some(table) = &self.latency_table else {
                    return targets;
                };
                let cursor = self
                    .cursors
                    .as_ref()
                    .map(|c| c.next(group_key))
                    .unwrap_or(0);
                let now_ms = self.clock.now_ms();
                table.order_targets(targets, &self.latency_cfg, now_ms, cursor)
            }
            RoutingStrategy::Cost => order_cost_targets(
                targets,
                &self.pricing_catalog,
                endpoint,
                requested_model,
                raw_body,
                self.cost_estimated_output_tokens,
                self.unknown_cost_policy,
            ),
            RoutingStrategy::Throughput => {
                let Some(table) = &self.throughput_table else {
                    return targets;
                };
                let cursor = self
                    .cursors
                    .as_ref()
                    .map(|c| c.next(group_key))
                    .unwrap_or(0);
                let now_ms = self.clock.now_ms();
                table.order_targets(targets, &self.throughput_cfg, now_ms, cursor)
            }
            RoutingStrategy::Headroom => {
                let Some(table) = &self.headroom_table else {
                    return targets;
                };
                let now_ms = self.clock.now_ms();
                table.order_targets(targets, now_ms)
            }
        }
    }

    fn dispatch_ai_shadows(&self, requested_model: &str, raw_body: &Bytes) {
        if self.shadow_targets.is_empty() {
            return;
        }
        let Some(client) = &self.http_client else {
            return;
        };

        for shadow in &self.shadow_targets {
            if !shadow.matches_model(requested_model) || !shadow.should_sample() {
                continue;
            }
            let Ok(permit) = shadow.semaphore.clone().try_acquire_owned() else {
                if let Some(stats) = &self.shadow_stats {
                    stats.record_dropped();
                }
                continue;
            };

            let shadow_body = if let Some(override_model) = &shadow.model {
                match serde_json::from_slice::<Value>(raw_body) {
                    Ok(mut v) => {
                        if let Some(obj) = v.as_object_mut() {
                            obj.insert("model".to_owned(), Value::String(override_model.clone()));
                        }
                        Bytes::from(serde_json::to_vec(&v).unwrap_or_else(|_| raw_body.to_vec()))
                    }
                    Err(_) => raw_body.clone(),
                }
            } else {
                raw_body.clone()
            };

            let mut headers = HeaderMap::new();
            headers.insert(
                header::CONTENT_TYPE,
                HeaderValue::from_static("application/json"),
            );
            headers.insert(
                HeaderName::from_static("x-shunt-shadow"),
                HeaderValue::from_static("true"),
            );
            if let Ok(v) = HeaderValue::from_str(&shadow.name) {
                headers.insert(HeaderName::from_static("x-shunt-shadow-target"), v);
            }
            for (k, v) in &shadow.headers {
                headers.insert(k.clone(), v.clone());
            }

            let req = HttpRequest {
                method: Method::POST,
                uri: shadow.uri.clone(),
                headers,
                body: shadow_body,
                timeout: Some(shadow.timeout),
                max_response_bytes: Some(1024 * 1024),
            };
            let client = Arc::clone(client);
            let stats = self.shadow_stats.clone();
            tokio::spawn(async move {
                let _permit = permit;
                match client.send(req).await {
                    Ok(resp) if resp.status.is_success() => {
                        if let Some(s) = stats {
                            s.record_sent();
                        }
                    }
                    Ok(_) | Err(_) => {
                        if let Some(s) = stats {
                            s.record_error();
                        }
                    }
                }
            });
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn finish_model_routing<'a>(
        &'a self,
        ctx: &'a mut RequestCtx,
        endpoint: AiEndpointKind,
        model: String,
        extra_models: Vec<String>,
        provider_prefs: Option<ProviderRoutingPreferences>,
        probe_stream: bool,
        parsed: &Value,
        raw_body: &Bytes,
    ) -> HookResult<'a, Flow> {
        let mut all_requested_models = Vec::with_capacity(1 + extra_models.len());
        all_requested_models.push(model.clone());
        for m in extra_models {
            if !all_requested_models.contains(&m) {
                all_requested_models.push(m);
            }
        }

        // Enforce virtual key model ACL across EVERY requested model before routing or count_tokens.
        if let Some(policy) = ctx.get_ext::<AiKeyPolicy>() {
            for req_model in &all_requested_models {
                if !policy.allows_model(req_model) {
                    let resp = endpoint_error_response(
                        endpoint,
                        StatusCode::FORBIDDEN,
                        "permission_error",
                        Some("model_not_allowed"),
                        &format!(
                            "Virtual key `{}` is not allowed to access model `{req_model}`",
                            policy.key_id
                        ),
                    );
                    return HookResult::Ready(Flow::Respond(resp));
                }
            }
        }

        // Local Anthropic `POST /v1/messages/count_tokens` estimation fast path.
        if endpoint == AiEndpointKind::AnthropicCountTokens && self.serve_count_tokens_endpoint {
            let est = estimate_request_tokens(endpoint, raw_body);
            let payload = json!({ "input_tokens": est.input_tokens });
            let bytes = serde_json::to_vec(&payload).unwrap_or_default();
            return HookResult::Ready(Flow::Respond(BufferedResponse::json(StatusCode::OK, bytes)));
        }

        // Resolve targets across primary model and any per-request fallback `models[]`.
        let mut combined_targets: Vec<AiTarget> = Vec::new();
        let mut seen_targets: HashSet<(String, String, String)> = HashSet::new();
        let mut primary_group_key: Option<String> = None;
        let mut primary_strategy: Option<RoutingStrategy> = None;

        for req_model in &all_requested_models {
            let override_targets = ctx
                .get_ext::<AiKeyPolicy>()
                .and_then(|p| p.override_targets(req_model));
            let resolved = override_targets
                .map(|t| {
                    (
                        format!("override:{req_model}"),
                        RoutingStrategy::Priority,
                        t,
                    )
                })
                .or_else(|| self.resolve_targets_with_strategy(req_model));

            if let Some((gkey, strat, targets)) = resolved {
                if primary_group_key.is_none() {
                    primary_group_key = Some(gkey);
                    primary_strategy = Some(strat);
                }
                for t in targets {
                    let dedup_key = (t.provider.clone(), t.upstream.clone(), t.model.clone());
                    if seen_targets.insert(dedup_key) {
                        combined_targets.push(t);
                    }
                }
            }
        }

        if combined_targets.is_empty() {
            let resp = endpoint_error_response(
                endpoint,
                StatusCode::NOT_FOUND,
                "invalid_request_error",
                Some("model_not_found"),
                &format!("The model `{model}` is not configured on this gateway"),
            );
            return HookResult::Ready(Flow::Respond(resp));
        }

        let group_key = primary_group_key.unwrap_or_else(|| format!("model:{model}"));
        let mut strategy = primary_strategy.unwrap_or(self.default_router_strategy);

        // Filter targets by virtual key `allowed_providers` if configured (strictly before client prefs).
        let allowed_targets: Vec<AiTarget> = match ctx.get_ext::<AiKeyPolicy>() {
            Some(policy) if !policy.allowed_providers.is_empty() => combined_targets
                .into_iter()
                .filter(|t| policy.allows_provider(&t.provider))
                .collect(),
            _ => combined_targets,
        };

        if allowed_targets.is_empty() {
            let key_id = ctx
                .get_ext::<AiKeyPolicy>()
                .map(|p| p.key_id.as_str())
                .unwrap_or("unknown");
            let resp = endpoint_error_response(
                endpoint,
                StatusCode::FORBIDDEN,
                "permission_error",
                Some("provider_not_allowed"),
                &format!("Virtual key `{key_id}` has no permitted providers for model `{model}`"),
            );
            return HookResult::Ready(Flow::Respond(resp));
        }

        // Apply per-request OpenRouter-style `provider: { ... }` preferences (strictly narrows ACLs).
        let allow_fallbacks = provider_prefs
            .as_ref()
            .and_then(|p| p.allow_fallbacks)
            .unwrap_or(true);
        let has_explicit_order = provider_prefs.as_ref().is_some_and(|p| !p.order.is_empty());
        let sort_override = provider_prefs
            .as_ref()
            .and_then(ProviderRoutingPreferences::sort_strategy);

        let pref_targets = match &provider_prefs {
            Some(prefs) => {
                let filtered = apply_provider_preferences(allowed_targets, prefs);
                if filtered.is_empty() {
                    let resp = endpoint_error_response(
                        endpoint,
                        StatusCode::BAD_REQUEST,
                        "invalid_request_error",
                        Some("no_matching_provider"),
                        &format!(
                            "No permitted targets for model `{model}` satisfied the requested `provider` constraints"
                        ),
                    );
                    return HookResult::Ready(Flow::Respond(resp));
                }
                filtered
            }
            None => allowed_targets,
        };

        // Enforce multi-protocol capability guards before ordering/failover.
        let required_caps = detect_required_capabilities(endpoint, parsed);
        let capable_targets: Vec<AiTarget> = if required_caps.is_empty() {
            pref_targets
        } else {
            pref_targets
                .into_iter()
                .filter(|t| t.supports_all(&required_caps))
                .collect()
        };

        if capable_targets.is_empty() {
            let (code, msg) = if required_caps.len() == 1
                && matches!(
                    required_caps[0],
                    AiCapability::Embeddings
                        | AiCapability::Chat
                        | AiCapability::Rerank
                        | AiCapability::Completions
                        | AiCapability::Moderations
                        | AiCapability::Images
                        | AiCapability::Audio
                        | AiCapability::Realtime
                ) {
                (
                    "unsupported_endpoint",
                    format!("No configured targets for model `{model}` support `{endpoint}`"),
                )
            } else {
                let cap_names: Vec<&str> = required_caps.iter().map(|c| c.as_str()).collect();
                (
                    "unsupported_capability",
                    format!(
                        "No configured targets for model `{model}` support required capabilities: [{}]",
                        cap_names.join(", ")
                    ),
                )
            };
            let resp = endpoint_error_response(
                endpoint,
                StatusCode::BAD_REQUEST,
                "invalid_request_error",
                Some(code),
                &msg,
            );
            return HookResult::Ready(Flow::Respond(resp));
        }

        // Enforce context-window capability guards when enabled.
        let context_eligible_targets = if self.enforce_context_window && !raw_body.is_empty() {
            let est = estimate_request_tokens(endpoint, raw_body);
            let filtered = filter_targets_by_context_window(
                capable_targets,
                &self.pricing_catalog,
                &model,
                est.input_tokens,
                self.context_window_safety_margin_tokens,
            );
            if filtered.is_empty() {
                let resp = endpoint_error_response(
                    endpoint,
                    StatusCode::BAD_REQUEST,
                    "invalid_request_error",
                    Some("context_length_exceeded"),
                    &format!(
                        "Estimated request input (~{} tokens) exceeds the context window of all eligible targets for model `{model}`",
                        est.input_tokens
                    ),
                );
                return HookResult::Ready(Flow::Respond(resp));
            }
            filtered
        } else {
            capable_targets
        };

        // Rank/order eligible targets according to per-request sort override, explicit order,
        // or the active smart routing strategy.
        if let Some(s) = sort_override {
            strategy = s;
        } else if has_explicit_order {
            strategy = RoutingStrategy::Priority;
        }

        let mut targets = self.apply_strategy(
            &group_key,
            strategy,
            context_eligible_targets,
            endpoint,
            &model,
            raw_body,
        );

        if !allow_fallbacks && targets.len() > 1 {
            targets.truncate(1);
        }

        // Dispatch sampled off-path AI shadow requests without delaying the primary request.
        self.dispatch_ai_shadows(&model, raw_body);

        let effective_stream = if endpoint.supports_sse_streaming() {
            probe_stream
        } else {
            false
        };

        ctx.insert_ext(AiRequestMeta::with_strategy(
            endpoint,
            model,
            effective_stream,
            strategy,
            targets,
        ));
        HookResult::Ready(Flow::Continue)
    }
}

/// Classifies an incoming AI gateway request path and HTTP method into an [`AiEndpointKind`].
pub fn classify_ai_endpoint(method: &Method, path: &str) -> AiEndpointKind {
    if *method == Method::GET && (path == "/v1/generation" || path == "/generation") {
        return AiEndpointKind::GenerationRetrieve;
    }
    if path == "/v1/realtime" || path == "/realtime" || path.ends_with("/realtime") {
        return AiEndpointKind::Realtime;
    }
    if path.ends_with("/embeddings") {
        return AiEndpointKind::Embeddings;
    }
    if path.ends_with("/rerank") {
        return AiEndpointKind::Rerank;
    }
    if path.ends_with("/moderations") {
        return AiEndpointKind::Moderations;
    }
    if path.ends_with("/images/generations") {
        return AiEndpointKind::ImagesGenerations;
    }
    if path.ends_with("/images/edits") {
        return AiEndpointKind::ImagesEdits;
    }
    if path.ends_with("/images/variations") {
        return AiEndpointKind::ImagesVariations;
    }
    if path.ends_with("/audio/speech") {
        return AiEndpointKind::AudioSpeech;
    }
    if path.ends_with("/audio/transcriptions") {
        return AiEndpointKind::AudioTranscriptions;
    }
    if path.ends_with("/audio/translations") {
        return AiEndpointKind::AudioTranslations;
    }
    if path == "/v1/files"
        || path == "/files"
        || path.starts_with("/v1/files/")
        || path.starts_with("/files/")
    {
        return AiEndpointKind::Files;
    }
    if path == "/v1/batches"
        || path == "/batches"
        || path.starts_with("/v1/batches/")
        || path.starts_with("/batches/")
    {
        return AiEndpointKind::Batches;
    }
    if path.ends_with("/messages/count_tokens") {
        return AiEndpointKind::AnthropicCountTokens;
    }
    if path.ends_with("/messages") {
        return AiEndpointKind::AnthropicMessages;
    }
    if path.ends_with("/responses") {
        return AiEndpointKind::OpenAiResponses;
    }
    if path.ends_with("/chat/completions") {
        return AiEndpointKind::ChatCompletions;
    }
    if path.ends_with("/completions") {
        return AiEndpointKind::Completions;
    }
    AiEndpointKind::ChatCompletions
}

impl HttpPlugin for AiModelRouterPlugin {
    fn name(&self) -> &str {
        "ai-model-router"
    }

    fn hook_mask(&self) -> HookMask {
        let mut mask = HookMask::ON_REQUEST_HEADERS
            | HookMask::REQUEST_BODY_BUFFERED
            | HookMask::ON_ROUTE
            | HookMask::ON_UPSTREAM_SELECT;
        if self.include_routing_headers || self.headroom_table.is_some() {
            mask |= HookMask::ON_RESPONSE_HEADERS;
        }
        if self.latency_table.is_some()
            || self.throughput_table.is_some()
            || self.headroom_table.is_some()
        {
            mask |= HookMask::ON_COMPLETE;
        }
        mask
    }

    fn max_request_body_bytes(&self) -> Option<usize> {
        Some(self.max_body_bytes)
    }

    fn on_request_headers<'a>(
        &'a self,
        ctx: &'a mut RequestCtx,
        req: &'a mut RequestHead,
    ) -> HookResult<'a, Flow> {
        let raw_path = req.uri.path();
        let path = if raw_path.len() > 1 {
            raw_path.trim_end_matches('/')
        } else {
            raw_path
        };

        if self.serve_models_endpoint && req.method == Method::GET {
            if path == "/v1/models" || path == "/models" {
                ctx.insert_ext(DetectedEndpoint(AiEndpointKind::ModelsList));
                let payload = match ctx.get_ext::<AiKeyPolicy>() {
                    Some(policy) if !policy.allowed_models.is_empty() => {
                        let filtered: Vec<Value> = self
                            .catalog_entries
                            .iter()
                            .filter(|(id, _)| policy.allows_model(id))
                            .map(|(_, entry)| entry.clone())
                            .collect();
                        let list = json!({ "object": "list", "data": filtered });
                        Bytes::from(serde_json::to_vec(&list).unwrap_or_default())
                    }
                    _ => self.models_list_json.clone(),
                };
                return HookResult::Ready(Flow::Respond(BufferedResponse::json(
                    StatusCode::OK,
                    payload,
                )));
            }

            if let Some(raw_id) = path
                .strip_prefix("/v1/models/")
                .or_else(|| path.strip_prefix("/models/"))
                && !raw_id.is_empty()
            {
                ctx.insert_ext(DetectedEndpoint(AiEndpointKind::ModelRetrieve));
                let decoded_id = percent_decode(raw_id);
                if let Some(policy) = ctx.get_ext::<AiKeyPolicy>()
                    && !policy.allows_model(&decoded_id)
                {
                    let resp = openai_error_response(
                        StatusCode::FORBIDDEN,
                        "permission_error",
                        Some("model_not_allowed"),
                        &format!(
                            "Virtual key `{}` is not allowed to access model `{decoded_id}`",
                            policy.key_id
                        ),
                    );
                    return HookResult::Ready(Flow::Respond(resp));
                }
                if let Some(model_bytes) = self.models_by_id.get(&decoded_id) {
                    return HookResult::Ready(Flow::Respond(BufferedResponse::json(
                        StatusCode::OK,
                        model_bytes.clone(),
                    )));
                }
                let resp = openai_error_response(
                    StatusCode::NOT_FOUND,
                    "invalid_request_error",
                    Some("model_not_found"),
                    &format!("The model `{decoded_id}` does not exist"),
                );
                return HookResult::Ready(Flow::Respond(resp));
            }
        }

        if let Some(ct) = req
            .headers
            .get(header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            && let Some(boundary) = parse_multipart_boundary(ct)
        {
            ctx.insert_ext(MultipartBoundary(boundary));
        }

        if let Some(prov) = req
            .headers
            .get("x-shunt-provider")
            .and_then(|v| v.to_str().ok())
            .map(str::trim)
            .filter(|s| !s.is_empty())
        {
            ctx.insert_ext(RequestedProviderHeader(prov.to_owned()));
        }

        if let Some(hdr) = &self.end_user_header
            && let Some(val) = req
                .headers
                .get(hdr)
                .and_then(|v| v.to_str().ok())
                .map(str::trim)
                .filter(|s| !s.is_empty())
        {
            ctx.insert_ext(AiEndUser(val.to_owned()));
        }

        let endpoint = classify_ai_endpoint(&req.method, path);
        ctx.insert_ext(DetectedEndpoint(endpoint));

        // WebSocket upgrades (`GET /v1/realtime?model=...`) skip `on_request_body_buffered`,
        // so resolve the target chain and enforce virtual-key ACLs directly in `on_request_headers`.
        if endpoint == AiEndpointKind::Realtime {
            let Some(model) = extract_query_param(req.uri.query(), "model") else {
                let resp = endpoint_error_response(
                    endpoint,
                    StatusCode::BAD_REQUEST,
                    "invalid_request_error",
                    Some("missing_model"),
                    "Realtime WebSocket request must include a non-empty `?model=` query parameter",
                );
                return HookResult::Ready(Flow::Respond(resp));
            };

            if let Some(policy) = ctx.get_ext::<AiKeyPolicy>()
                && !policy.allows_model(&model)
            {
                let resp = endpoint_error_response(
                    endpoint,
                    StatusCode::FORBIDDEN,
                    "permission_error",
                    Some("model_not_allowed"),
                    &format!(
                        "Virtual key `{}` is not allowed to access model `{model}`",
                        policy.key_id
                    ),
                );
                return HookResult::Ready(Flow::Respond(resp));
            }

            let override_targets = ctx
                .get_ext::<AiKeyPolicy>()
                .and_then(|p| p.override_targets(&model));
            let Some((group_key, strategy, all_targets)) = override_targets
                .map(|t| (format!("override:{model}"), RoutingStrategy::Priority, t))
                .or_else(|| self.resolve_targets_with_strategy(&model))
            else {
                let resp = endpoint_error_response(
                    endpoint,
                    StatusCode::NOT_FOUND,
                    "invalid_request_error",
                    Some("model_not_found"),
                    &format!("The model `{model}` is not configured on this gateway"),
                );
                return HookResult::Ready(Flow::Respond(resp));
            };

            let allowed_targets: Vec<AiTarget> = match ctx.get_ext::<AiKeyPolicy>() {
                Some(policy) if !policy.allowed_providers.is_empty() => all_targets
                    .into_iter()
                    .filter(|t| policy.allows_provider(&t.provider))
                    .collect(),
                _ => all_targets,
            };
            if allowed_targets.is_empty() {
                let key_id = ctx
                    .get_ext::<AiKeyPolicy>()
                    .map(|p| p.key_id.as_str())
                    .unwrap_or("unknown");
                let resp = endpoint_error_response(
                    endpoint,
                    StatusCode::FORBIDDEN,
                    "permission_error",
                    Some("provider_not_allowed"),
                    &format!(
                        "Virtual key `{key_id}` has no permitted providers for model `{model}`"
                    ),
                );
                return HookResult::Ready(Flow::Respond(resp));
            }

            let required_caps = [AiCapability::Realtime];
            let capable_targets: Vec<AiTarget> = allowed_targets
                .into_iter()
                .filter(|t| t.supports_all(&required_caps))
                .collect();
            if capable_targets.is_empty() {
                let resp = endpoint_error_response(
                    endpoint,
                    StatusCode::BAD_REQUEST,
                    "invalid_request_error",
                    Some("unsupported_endpoint"),
                    &format!("No configured targets for model `{model}` support `{endpoint}`"),
                );
                return HookResult::Ready(Flow::Respond(resp));
            }

            let targets =
                self.apply_strategy(&group_key, strategy, capable_targets, endpoint, &model, &[]);
            ctx.insert_ext(AiRequestMeta::with_strategy(
                endpoint, model, true, strategy, targets,
            ));
        }

        HookResult::Ready(Flow::Continue)
    }

    fn on_request_body_buffered<'a>(
        &'a self,
        ctx: &'a mut RequestCtx,
        body: &'a mut Bytes,
    ) -> HookResult<'a, Flow> {
        let endpoint = ctx
            .get_ext::<DetectedEndpoint>()
            .map(|d| d.0)
            .unwrap_or(AiEndpointKind::ChatCompletions);

        // Discovery, generation lookup, and WebSocket Realtime do not route from a JSON body
        // (`POST /v1/messages/count_tokens` DOES parse JSON to enforce model ACL and estimate tokens).
        if matches!(
            endpoint,
            AiEndpointKind::ModelsList
                | AiEndpointKind::ModelRetrieve
                | AiEndpointKind::GenerationRetrieve
                | AiEndpointKind::Realtime
        ) {
            return HookResult::Ready(Flow::Continue);
        }

        // Resource CRUD endpoints (`/v1/files*`, `/v1/batches*`) have no `model` body field.
        if endpoint.is_resource_endpoint() {
            let specs: &[TargetSpec] = match endpoint {
                AiEndpointKind::Files if !self.files_targets.is_empty() => &self.files_targets,
                AiEndpointKind::Batches if !self.batches_targets.is_empty() => {
                    &self.batches_targets
                }
                _ => &self.default_targets,
            };
            let requested_label = endpoint.as_str().to_owned();
            let mut candidates: Vec<AiTarget> =
                specs.iter().map(|s| s.resolve(&requested_label)).collect();

            if let Some(req_prov) = ctx.get_ext::<RequestedProviderHeader>() {
                candidates.retain(|t| t.provider == req_prov.0);
            }

            if let Some(policy) = ctx.get_ext::<AiKeyPolicy>()
                && !policy.allowed_providers.is_empty()
            {
                candidates.retain(|t| policy.allows_provider(&t.provider));
            }

            let req_cap = if endpoint == AiEndpointKind::Files {
                AiCapability::Files
            } else {
                AiCapability::Batches
            };
            candidates.retain(|t| t.supports(req_cap));

            if candidates.is_empty() {
                let resp = endpoint_error_response(
                    endpoint,
                    StatusCode::BAD_REQUEST,
                    "invalid_request_error",
                    Some("no_provider_configured"),
                    &format!(
                        "No eligible provider target configured for `{endpoint}` (configure `files_targets`, `batches_targets`, or `default_targets`)"
                    ),
                );
                return HookResult::Ready(Flow::Respond(resp));
            }

            let targets = self.apply_strategy(
                endpoint.as_str(),
                self.default_targets_strategy,
                candidates,
                endpoint,
                &requested_label,
                body,
            );
            ctx.insert_ext(AiRequestMeta::with_strategy(
                endpoint,
                requested_label,
                false,
                self.default_targets_strategy,
                targets,
            ));
            return HookResult::Ready(Flow::Continue);
        }

        // Multipart form-data endpoints (`/v1/audio/transcriptions`, `/v1/audio/translations`,
        // `/v1/images/edits`, `/v1/images/variations`) carry `model` as a multipart text field.
        if endpoint.is_multipart_model_endpoint() {
            let Some(boundary) = ctx.get_ext::<MultipartBoundary>().map(|b| b.0.clone()) else {
                let resp = endpoint_error_response(
                    endpoint,
                    StatusCode::BAD_REQUEST,
                    "invalid_request_error",
                    Some("invalid_multipart"),
                    "Request must use `Content-Type: multipart/form-data; boundary=...`",
                );
                return HookResult::Ready(Flow::Respond(resp));
            };

            let model = extract_multipart_text_field(body, &boundary, "model").or_else(|| {
                if endpoint == AiEndpointKind::ImagesVariations {
                    Some("dall-e-2".to_owned())
                } else {
                    None
                }
            });
            let Some(model) = model else {
                let resp = endpoint_error_response(
                    endpoint,
                    StatusCode::BAD_REQUEST,
                    "invalid_request_error",
                    Some("missing_model"),
                    "Multipart request must include a non-empty `model` form field",
                );
                return HookResult::Ready(Flow::Respond(resp));
            };

            return self.finish_model_routing(
                ctx,
                endpoint,
                model,
                Vec::new(),
                None,
                false,
                &Value::Null,
                body,
            );
        }

        let mut parsed: Value = match serde_json::from_slice(body) {
            Ok(v) => v,
            Err(err) => {
                let resp = endpoint_error_response(
                    endpoint,
                    StatusCode::BAD_REQUEST,
                    "invalid_request_error",
                    Some("invalid_json"),
                    &format!("Invalid JSON in request body: {err}"),
                );
                return HookResult::Ready(Flow::Respond(resp));
            }
        };

        // Extract end-user identifier (`user` or `metadata.user_id`) if not already set from header.
        if ctx.get_ext::<AiEndUser>().is_none()
            && let Some(end_user) = extract_end_user_from_body(&parsed)
        {
            ctx.insert_ext(AiEndUser(end_user));
        }

        let mut extra_models: Vec<String> = Vec::new();
        let mut provider_prefs: Option<ProviderRoutingPreferences> = None;
        let mut needs_body_rewrite = false;

        if self.allow_request_routing_overrides
            && let Some(obj) = parsed.as_object_mut()
        {
            if let Some(raw_models) = obj.remove("models") {
                needs_body_rewrite = true;
                match raw_models {
                    Value::Array(arr) => {
                        for item in arr {
                            if let Some(m) = item.as_str().map(str::trim).filter(|s| !s.is_empty())
                            {
                                extra_models.push(m.to_owned());
                            }
                        }
                    }
                    Value::Null => {}
                    _ => {
                        let resp = endpoint_error_response(
                            endpoint,
                            StatusCode::BAD_REQUEST,
                            "invalid_request_error",
                            Some("invalid_models_override"),
                            "`models` routing override must be an array of model strings",
                        );
                        return HookResult::Ready(Flow::Respond(resp));
                    }
                }
            }
            if let Some(raw_provider) = obj.remove("provider") {
                needs_body_rewrite = true;
                if !raw_provider.is_null() {
                    match serde_json::from_value::<ProviderRoutingPreferences>(raw_provider) {
                        Ok(p) => provider_prefs = Some(p),
                        Err(err) => {
                            let resp = endpoint_error_response(
                                endpoint,
                                StatusCode::BAD_REQUEST,
                                "invalid_request_error",
                                Some("invalid_provider_override"),
                                &format!("Invalid `provider` routing override: {err}"),
                            );
                            return HookResult::Ready(Flow::Respond(resp));
                        }
                    }
                }
            }
        }

        let primary_model = parsed
            .get("model")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|m| !m.is_empty())
            .map(str::to_owned)
            .or_else(|| {
                if !extra_models.is_empty() {
                    let first = extra_models.remove(0);
                    if let Some(obj) = parsed.as_object_mut() {
                        obj.insert("model".to_owned(), Value::String(first.clone()));
                        needs_body_rewrite = true;
                    }
                    Some(first)
                } else {
                    None
                }
            });

        let Some(model) = primary_model else {
            let resp = endpoint_error_response(
                endpoint,
                StatusCode::BAD_REQUEST,
                "invalid_request_error",
                Some("missing_model"),
                "Request body must include a non-empty `model` field",
            );
            return HookResult::Ready(Flow::Respond(resp));
        };

        if needs_body_rewrite && let Ok(stripped) = serde_json::to_vec(&parsed) {
            *body = Bytes::from(stripped);
        }

        let probe_stream = parsed
            .get("stream")
            .and_then(Value::as_bool)
            .unwrap_or(false);

        self.finish_model_routing(
            ctx,
            endpoint,
            model,
            extra_models,
            provider_prefs,
            probe_stream,
            &parsed,
            body,
        )
    }

    fn on_route<'a>(
        &'a self,
        ctx: &'a mut RequestCtx,
        decision: &'a mut RouteDecision,
    ) -> HookResult<'a, Flow> {
        if let Some(meta) = ctx.get_ext::<AiRequestMeta>()
            && let Some(primary) = meta.targets.first()
        {
            decision.upstream = primary.upstream.clone();
            if self.auto_max_attempts {
                decision.max_attempts = decision.max_attempts.max(meta.targets.len());
            }
        }
        HookResult::Ready(Flow::Continue)
    }

    fn on_upstream_select<'a>(
        &'a self,
        ctx: &'a mut RequestCtx,
        selection: &'a mut UpstreamSelection,
    ) -> HookResult<'a, Flow> {
        let keep_current = ctx.remove_ext::<IntraProviderKeyRetry>().is_some();
        let overflow_floor = ctx.get_ext::<ContextOverflowFloor>().map(|f| f.0);
        if let Some(meta) = ctx.get_ext_mut::<AiRequestMeta>() {
            meta.max_attempts = selection.max_attempts;
            if let Some(target) = meta.select_next_target(keep_current) {
                let mut chosen = target.clone();
                // If an earlier attempt failed with context-window overflow, skip targets whose
                // known context window is <= the failed floor when a larger target exists.
                if let Some(floor) = overflow_floor
                    && !keep_current
                    && chosen.context_window.is_some_and(|w| w <= floor)
                {
                    let len = meta.targets.len();
                    let start = meta.active_target_index;
                    for offset in 1..len {
                        let idx = (start + offset) % len;
                        let cand = &meta.targets[idx];
                        if cand.context_window.is_none_or(|w| w > floor) {
                            meta.active_target_index = idx;
                            chosen = cand.clone();
                            break;
                        }
                    }
                }
                selection.upstream = chosen.upstream;
                selection.endpoint_override = chosen.endpoint_override;
                selection.response_headers_timeout_override =
                    chosen.ttft_timeout_ms.map(Duration::from_millis);
            }
        }
        HookResult::Ready(Flow::Continue)
    }

    fn on_response_headers<'a>(
        &'a self,
        ctx: &'a mut RequestCtx,
        res: &'a mut ResponseHead,
    ) -> HookResult<'a, Flow> {
        if let Some(headroom) = &self.headroom_table
            && let Some(target) = ctx
                .get_ext::<AiRequestMeta>()
                .and_then(AiRequestMeta::active_target)
        {
            let parse_hdr = |names: &[&str]| -> Option<u64> {
                for n in names {
                    if let Some(v) = res
                        .headers
                        .get(*n)
                        .and_then(|h| h.to_str().ok())
                        .and_then(|s| s.trim().parse::<u64>().ok())
                    {
                        return Some(v);
                    }
                }
                None
            };
            let rpm_lim = parse_hdr(&[
                "x-ratelimit-limit-requests",
                "anthropic-ratelimit-requests-limit",
            ]);
            let rpm_rem = parse_hdr(&[
                "x-ratelimit-remaining-requests",
                "anthropic-ratelimit-requests-remaining",
            ]);
            let tpm_lim = parse_hdr(&[
                "x-ratelimit-limit-tokens",
                "anthropic-ratelimit-tokens-limit",
            ]);
            let tpm_rem = parse_hdr(&[
                "x-ratelimit-remaining-tokens",
                "anthropic-ratelimit-tokens-remaining",
            ]);
            let key =
                TargetHeadroomTable::target_key(&target.provider, &target.upstream, &target.model);
            headroom.record_upstream_headers(
                &key,
                rpm_lim,
                rpm_rem,
                tpm_lim,
                tpm_rem,
                self.clock.now_ms(),
            );
        }

        if self.include_routing_headers
            && let Some(meta) = ctx.get_ext::<AiRequestMeta>()
        {
            if let Ok(val) = HeaderValue::from_str(meta.routing_strategy.as_str()) {
                res.headers
                    .insert(HeaderName::from_static("x-shunt-routing-strategy"), val);
            }
            if let Some(target) = meta.active_target() {
                if let Ok(val) = HeaderValue::from_str(&target.provider) {
                    res.headers
                        .insert(HeaderName::from_static("x-shunt-selected-provider"), val);
                }
                if let Ok(val) = HeaderValue::from_str(&target.model) {
                    res.headers
                        .insert(HeaderName::from_static("x-shunt-selected-model"), val);
                }
            }
        }
        HookResult::Ready(Flow::Continue)
    }

    fn on_complete<'a>(
        &'a self,
        ctx: &'a RequestCtx,
        summary: &'a RequestSummary,
    ) -> HookResult<'a, ()> {
        if self.latency_table.is_none()
            && self.throughput_table.is_none()
            && self.headroom_table.is_none()
        {
            return HookResult::Ready(());
        }
        if summary.attempts == 0 {
            return HookResult::Ready(());
        }
        let Some(meta) = ctx.get_ext::<AiRequestMeta>() else {
            return HookResult::Ready(());
        };

        let now_ms = self.clock.now_ms();

        // Penalize every target that failed during failover attempts.
        if let Some(history) = ctx.get_ext::<AiFailoverHistory>() {
            for ev in &history.events {
                if let Some(table) = &self.latency_table {
                    let key = TargetLatencyTable::target_key(&ev.provider, &ev.upstream, &ev.model);
                    table.record_error(&key, self.latency_cfg.ewma_alpha, now_ms);
                }
                if let Some(table) = &self.throughput_table {
                    let key =
                        TargetThroughputTable::target_key(&ev.provider, &ev.upstream, &ev.model);
                    table.record_error(&key, self.throughput_cfg.ewma_alpha, now_ms);
                }
                if let Some(table) = &self.headroom_table {
                    let key =
                        TargetHeadroomTable::target_key(&ev.provider, &ev.upstream, &ev.model);
                    table.record_usage(&key, 1, 0, now_ms);
                }
            }
        }

        // Record final attempt outcome across active routing tables.
        if let Some(target) = meta.active_target() {
            let status_code = summary.status.map(|s| s.as_u16());
            let is_error = summary.error.is_some()
                || summary.aborted_mid_stream
                || matches!(status_code, None | Some(429 | 500..=599));

            if let Some(table) = &self.headroom_table {
                let key = TargetHeadroomTable::target_key(
                    &target.provider,
                    &target.upstream,
                    &target.model,
                );
                let tokens = ctx
                    .get_ext::<AiUsage>()
                    .and_then(AiUsage::effective_total_tokens)
                    .unwrap_or(0);
                table.record_usage(&key, 1, tokens, now_ms);
            }

            if let Some(table) = &self.latency_table {
                let key = TargetLatencyTable::target_key(
                    &target.provider,
                    &target.upstream,
                    &target.model,
                );
                if is_error {
                    table.record_error(&key, self.latency_cfg.ewma_alpha, now_ms);
                } else {
                    let ttft = ctx
                        .get_ext::<AiUsage>()
                        .and_then(|u| u.first_token_at)
                        .map(|t| t.saturating_duration_since(ctx.started_at))
                        .or(summary.ttfb)
                        .unwrap_or(summary.total_duration);
                    let latency_ms = ttft.as_secs_f64() * 1_000.0;
                    table.record_success(&key, latency_ms, self.latency_cfg.ewma_alpha, now_ms);
                }
            }

            if let Some(table) = &self.throughput_table {
                let key = TargetThroughputTable::target_key(
                    &target.provider,
                    &target.upstream,
                    &target.model,
                );
                if is_error {
                    table.record_error(&key, self.throughput_cfg.ewma_alpha, now_ms);
                } else if let Some(completion_tokens) =
                    ctx.get_ext::<AiUsage>().and_then(|u| u.completion_tokens)
                    && completion_tokens > 0
                {
                    let gen_dur = ctx
                        .get_ext::<AiUsage>()
                        .and_then(|u| u.first_token_at)
                        .map(|ft| {
                            let ttft = ft.saturating_duration_since(ctx.started_at);
                            summary.total_duration.saturating_sub(ttft)
                        })
                        .filter(|d| !d.is_zero())
                        .unwrap_or(summary.total_duration)
                        .max(Duration::from_millis(1));
                    let tps = (completion_tokens as f64) / gen_dur.as_secs_f64();
                    table.record_success(&key, tps, self.throughput_cfg.ewma_alpha, now_ms);
                }
            }
        }

        HookResult::Ready(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wildcard_matching_cases() {
        assert!(wildcard_match("*", "gpt-4o"));
        assert!(wildcard_match("claude-*", "claude-3-5-sonnet-20241022"));
        assert!(!wildcard_match("claude-*", "gpt-4o"));
        assert!(wildcard_match("*-mini", "gpt-4o-mini"));
        assert!(wildcard_match("gpt-*-turbo", "gpt-4-turbo"));
        assert!(wildcard_match("exact", "exact"));
        assert!(!wildcard_match("exact", "exact2"));
    }

    #[test]
    fn models_catalog_is_sorted_and_deduplicated() {
        let mk_spec =
            |provider: &str, upstream: &str, model: Option<&str>, weight: u32| TargetSpec {
                provider: provider.to_owned(),
                upstream: upstream.to_owned(),
                model: model.map(str::to_owned),
                endpoint_override: None,
                capabilities: Vec::new(),
                weight,
                default_params: BTreeMap::new(),
                override_params: BTreeMap::new(),
                context_window: None,
                max_output_tokens: None,
                zdr: false,
                regions: Vec::new(),
                tags: Vec::new(),
                upstream_rpm: None,
                upstream_tpm: None,
                ttft_timeout_ms: None,
            };
        let mut models = HashMap::new();
        models.insert(
            "smart".to_owned(),
            ModelEntryConfig::Targets(vec![mk_spec("openai", "openai", Some("gpt-4o"), 1)]),
        );
        models.insert(
            "fast".to_owned(),
            ModelEntryConfig::Detailed {
                strategy: Some(RoutingStrategy::Weighted),
                targets: vec![mk_spec("groq", "groq", Some("llama-3.3-70b"), 5)],
            },
        );
        let rules = vec![ModelRule {
            pattern: "claude-*".to_owned(),
            strategy: None,
            targets: vec![mk_spec("anthropic", "anthropic", None, 1)],
        }];
        let exposed = vec!["claude-3-5-sonnet-20241022".to_owned(), "smart".to_owned()];
        let pricing = PricingCatalog::new(HashMap::new(), true, None).unwrap();

        let (list_bytes, by_id, entries) =
            compile_models_catalog(&models, &rules, &[], &exposed, &pricing);
        assert_eq!(entries.len(), 3);
        let list: Value = serde_json::from_slice(&list_bytes).unwrap();
        let data = list["data"].as_array().unwrap();
        let ids: Vec<&str> = data.iter().map(|d| d["id"].as_str().unwrap()).collect();
        assert_eq!(ids, vec!["claude-3-5-sonnet-20241022", "fast", "smart"]);
        assert_eq!(data[0]["owned_by"], "anthropic");
        assert_eq!(data[1]["owned_by"], "groq");
        assert_eq!(data[2]["owned_by"], "openai");
        assert_eq!(data[2]["context_length"], 128_000);
        assert_eq!(data[2]["pricing"]["input_per_million_usd"], 2.5);
        assert!(by_id.contains_key("claude-3-5-sonnet-20241022"));
        assert!(by_id.contains_key("fast"));
        assert!(by_id.contains_key("smart"));
    }

    #[test]
    fn hook_mask_stays_minimal_when_priority_only() {
        let state = Arc::new(shunt_plugin_sdk::StateStore::new());
        let touched = Arc::new(std::sync::RwLock::new(std::collections::HashSet::new()));
        let ctx = BuildContext::new("route:ai:router", state, touched);

        let priority_cfg = PluginConfig::new(json!({
            "models": {
                "m": [{ "provider": "openai", "upstream": "openai", "model": "gpt-4o" }]
            }
        }));
        let p1 = AiModelRouterFactory.build(&priority_cfg, &ctx).unwrap();
        assert!(!p1.hook_mask().contains(HookMask::ON_COMPLETE));
        assert!(!p1.hook_mask().contains(HookMask::ON_RESPONSE_HEADERS));

        let latency_cfg = PluginConfig::new(json!({
            "include_routing_headers": true,
            "models": {
                "m": {
                    "strategy": "latency",
                    "targets": [{ "provider": "openai", "upstream": "openai", "model": "gpt-4o" }]
                }
            }
        }));
        let p2 = AiModelRouterFactory.build(&latency_cfg, &ctx).unwrap();
        assert!(p2.hook_mask().contains(HookMask::ON_COMPLETE));
        assert!(p2.hook_mask().contains(HookMask::ON_RESPONSE_HEADERS));
    }
}
