use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;

use serde::Deserialize;
use serde_json::{Value, json};
use shunt_plugin_sdk::{
    BufferedResponse, BuildContext, Bytes, Clock, Flow, HeaderName, HeaderValue, HookMask,
    HookResult, HttpPlugin, Method, PluginBuildError, PluginConfig, PluginFactory, RequestCtx,
    RequestHead, RequestSummary, ResponseHead, RouteDecision, StatusCode, UpstreamSelection,
    header,
};

use crate::multimodal::extract_query_param;
use crate::multipart::{extract_multipart_text_field, parse_multipart_boundary};
use crate::pricing::{ModelPricing, PricingCatalog};
use crate::routing::{
    LatencyRoutingConfig, RoutingCursorTable, TargetLatencyTable, UnknownCostPolicy,
    detect_required_capabilities, order_cost_targets, order_weighted_targets,
};
use crate::tokens::estimate_request_tokens;
use crate::types::{
    AiCapability, AiEndpointKind, AiFailoverHistory, AiKeyPolicy, AiRequestMeta, AiTarget, AiUsage,
    DetectedEndpoint, IntraProviderKeyRetry, RoutingStrategy, endpoint_error_response,
    openai_error_response, percent_decode, wildcard_match,
};

const DEFAULT_MAX_BODY_BYTES: usize = 1024 * 1024; // 1 MiB
const DEFAULT_COST_OUTPUT_TOKENS: u64 = 256;

fn default_weight() -> u32 {
    1
}

fn default_true() -> bool {
    true
}

fn default_cost_output_tokens() -> u64 {
    DEFAULT_COST_OUTPUT_TOKENS
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
    /// Optional capability tags (`chat`, `streaming`, `tools`, `vision`, `json_schema`, `reasoning`, `embeddings`).
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
}

impl TargetSpec {
    fn resolve(&self, requested_model: &str) -> AiTarget {
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
    /// Custom per-model pricing overrides for `strategy = "cost"`.
    #[serde(default)]
    pricing: HashMap<String, ModelPricing>,
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
            pricing: HashMap::new(),
            use_builtin_pricing: true,
            default_pricing: None,
            unknown_cost_policy: UnknownCostPolicy::Last,
            cost_estimated_output_tokens: DEFAULT_COST_OUTPUT_TOKENS,
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

        let pricing_catalog =
            PricingCatalog::new(cfg.pricing, cfg.use_builtin_pricing, cfg.default_pricing)
                .map_err(|message| PluginBuildError::BuildFailed {
                    plugin: self.name().to_owned(),
                    message,
                })?;

        let uses_latency = cfg.strategy == RoutingStrategy::Latency
            || cfg.default_strategy == Some(RoutingStrategy::Latency)
            || cfg
                .models
                .values()
                .any(|e| e.strategy(cfg.strategy) == RoutingStrategy::Latency)
            || cfg
                .rules
                .iter()
                .any(|r| r.strategy.unwrap_or(cfg.strategy) == RoutingStrategy::Latency);

        let uses_cursors = uses_latency
            || cfg.strategy == RoutingStrategy::Weighted
            || cfg.default_strategy == Some(RoutingStrategy::Weighted)
            || cfg
                .models
                .values()
                .any(|e| e.strategy(cfg.strategy) == RoutingStrategy::Weighted)
            || cfg
                .rules
                .iter()
                .any(|r| r.strategy.unwrap_or(cfg.strategy) == RoutingStrategy::Weighted);

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

        let (models_list_json, models_by_id, catalog_entries) = compile_models_catalog(
            &cfg.models,
            &cfg.rules,
            &cfg.default_targets,
            &cfg.exposed_models,
        );

        Ok(Arc::new(AiModelRouterPlugin {
            max_body_bytes: cfg.max_body_bytes,
            auto_max_attempts: cfg.auto_max_attempts,
            serve_models_endpoint: cfg.serve_models_endpoint,
            serve_count_tokens_endpoint: cfg.serve_count_tokens_endpoint,
            default_router_strategy: cfg.strategy,
            default_targets_strategy: cfg.default_strategy.unwrap_or(cfg.strategy),
            include_routing_headers: cfg.include_routing_headers,
            latency_cfg: cfg.latency,
            pricing_catalog,
            unknown_cost_policy: cfg.unknown_cost_policy,
            cost_estimated_output_tokens: cfg.cost_estimated_output_tokens,
            clock: ctx.clock(),
            cursors,
            latency_table,
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

/// Pre-serializes deterministic OpenAI `GET /v1/models` and `GET /v1/models/{id}` payloads
/// once at snapshot compilation time (zero per-request sorting or serialization).
fn compile_models_catalog(
    models: &HashMap<String, ModelEntryConfig>,
    rules: &[ModelRule],
    default_targets: &[TargetSpec],
    exposed_models: &[String],
) -> (Bytes, HashMap<String, Bytes>, Vec<(String, String)>) {
    // BTreeMap guarantees deterministic alphabetical ordering by model `id`.
    let mut catalog: BTreeMap<String, String> = BTreeMap::new();

    // 1. Explicit model aliases in `models`.
    for (alias, entry) in models {
        let owner = entry
            .targets()
            .first()
            .map(|t| t.provider.clone())
            .unwrap_or_else(|| "shunt".to_owned());
        catalog.insert(alias.clone(), owner);
    }

    // 2. Concrete `model` names referenced inside `rules` targets.
    for rule in rules {
        for t in &rule.targets {
            if let Some(m) = t.model.as_deref().map(str::trim).filter(|m| !m.is_empty()) {
                catalog
                    .entry(m.to_owned())
                    .or_insert_with(|| t.provider.clone());
            }
        }
    }

    // 3. Explicit `exposed_models` advertised for wildcard rules.
    for raw in exposed_models {
        let id = raw.trim();
        if id.is_empty() {
            continue;
        }
        let owner = resolve_owner_for_exposed(id, models, rules, default_targets);
        catalog.entry(id.to_owned()).or_insert(owner);
    }

    let mut data_entries = Vec::with_capacity(catalog.len());
    let mut models_by_id = HashMap::with_capacity(catalog.len());
    let mut ordered_entries = Vec::with_capacity(catalog.len());

    for (id, owned_by) in catalog {
        let entry = json!({
            "id": id,
            "object": "model",
            "created": 0,
            "owned_by": owned_by,
        });
        let single_bytes = Bytes::from(serde_json::to_vec(&entry).unwrap_or_default());
        ordered_entries.push((id.clone(), owned_by));
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

fn resolve_owner_for_exposed(
    model_id: &str,
    models: &HashMap<String, ModelEntryConfig>,
    rules: &[ModelRule],
    default_targets: &[TargetSpec],
) -> String {
    if let Some(entry) = models.get(model_id)
        && let Some(first) = entry.targets().first()
    {
        return first.provider.clone();
    }
    for rule in rules {
        if wildcard_match(&rule.pattern, model_id)
            && let Some(first) = rule.targets.first()
        {
            return first.provider.clone();
        }
    }
    if let Some(first) = default_targets.first() {
        return first.provider.clone();
    }
    "shunt".to_owned()
}

/// Parses incoming AI requests (`/v1/chat/completions`, `/v1/messages`, `/v1/responses`,
/// `/v1/embeddings`, `GET /v1/models`, `POST /v1/messages/count_tokens`), enforces capability
/// guards, applies smart routing strategies (`priority`, `weighted`, `latency`, `cost`),
/// and stores typed [`AiRequestMeta`] in `ctx.extensions`.
pub struct AiModelRouterPlugin {
    max_body_bytes: usize,
    auto_max_attempts: bool,
    serve_models_endpoint: bool,
    serve_count_tokens_endpoint: bool,
    default_router_strategy: RoutingStrategy,
    default_targets_strategy: RoutingStrategy,
    include_routing_headers: bool,
    latency_cfg: LatencyRoutingConfig,
    pricing_catalog: PricingCatalog,
    unknown_cost_policy: UnknownCostPolicy,
    cost_estimated_output_tokens: u64,
    clock: Arc<dyn Clock>,
    cursors: Option<Arc<RoutingCursorTable>>,
    latency_table: Option<Arc<TargetLatencyTable>>,
    models: HashMap<String, ModelEntryConfig>,
    rules: Vec<ModelRule>,
    default_targets: Vec<TargetSpec>,
    files_targets: Vec<TargetSpec>,
    batches_targets: Vec<TargetSpec>,
    models_list_json: Bytes,
    models_by_id: HashMap<String, Bytes>,
    catalog_entries: Vec<(String, String)>,
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
        }
    }

    fn finish_model_routing<'a>(
        &'a self,
        ctx: &'a mut RequestCtx,
        endpoint: AiEndpointKind,
        model: String,
        probe_stream: bool,
        parsed: &Value,
        raw_body: &[u8],
    ) -> HookResult<'a, Flow> {
        // Enforce virtual key model ACL before routing or local count_tokens.
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

        // Local Anthropic `POST /v1/messages/count_tokens` estimation fast path.
        if endpoint == AiEndpointKind::AnthropicCountTokens && self.serve_count_tokens_endpoint {
            let est = estimate_request_tokens(endpoint, raw_body);
            let payload = json!({ "input_tokens": est.input_tokens });
            let bytes = serde_json::to_vec(&payload).unwrap_or_default();
            return HookResult::Ready(Flow::Respond(BufferedResponse::json(StatusCode::OK, bytes)));
        }

        // Apply per-key provider overrides if present, else resolve from route rules.
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

        // Filter targets by virtual key `allowed_providers` if configured.
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
                &format!("Virtual key `{key_id}` has no permitted providers for model `{model}`"),
            );
            return HookResult::Ready(Flow::Respond(resp));
        }

        // Enforce multi-protocol capability guards before ordering/failover.
        let required_caps = detect_required_capabilities(endpoint, parsed);
        let capable_targets: Vec<AiTarget> = if required_caps.is_empty() {
            allowed_targets
        } else {
            allowed_targets
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

        // Rank/order eligible targets according to the active smart routing strategy.
        let targets = self.apply_strategy(
            &group_key,
            strategy,
            capable_targets,
            endpoint,
            &model,
            raw_body,
        );

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
        if self.include_routing_headers {
            mask |= HookMask::ON_RESPONSE_HEADERS;
        }
        if self.latency_table.is_some() {
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
                            .map(|(id, owned_by)| {
                                json!({
                                    "id": id,
                                    "object": "model",
                                    "created": 0,
                                    "owned_by": owned_by,
                                })
                            })
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

            return self.finish_model_routing(ctx, endpoint, model, false, &Value::Null, body);
        }

        let parsed: Value = match serde_json::from_slice(body) {
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

        let Some(model) = parsed
            .get("model")
            .and_then(Value::as_str)
            .filter(|m| !m.trim().is_empty())
            .map(str::to_owned)
        else {
            let resp = endpoint_error_response(
                endpoint,
                StatusCode::BAD_REQUEST,
                "invalid_request_error",
                Some("missing_model"),
                "Request body must include a non-empty `model` field",
            );
            return HookResult::Ready(Flow::Respond(resp));
        };

        let probe_stream = parsed
            .get("stream")
            .and_then(Value::as_bool)
            .unwrap_or(false);

        self.finish_model_routing(ctx, endpoint, model, probe_stream, &parsed, body)
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
        if let Some(meta) = ctx.get_ext_mut::<AiRequestMeta>() {
            meta.max_attempts = selection.max_attempts;
            if let Some(target) = meta.select_next_target(keep_current) {
                selection.upstream = target.upstream.clone();
                selection.endpoint_override = target.endpoint_override.clone();
            }
        }
        HookResult::Ready(Flow::Continue)
    }

    fn on_response_headers<'a>(
        &'a self,
        ctx: &'a mut RequestCtx,
        res: &'a mut ResponseHead,
    ) -> HookResult<'a, Flow> {
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
        let Some(table) = &self.latency_table else {
            return HookResult::Ready(());
        };
        if summary.attempts == 0 {
            return HookResult::Ready(());
        }
        let Some(meta) = ctx.get_ext::<AiRequestMeta>() else {
            return HookResult::Ready(());
        };

        let now_ms = self.clock.now_ms();
        let alpha = self.latency_cfg.ewma_alpha;

        // Penalize every target that failed during failover attempts.
        if let Some(history) = ctx.get_ext::<AiFailoverHistory>() {
            for ev in &history.events {
                let key = TargetLatencyTable::target_key(&ev.provider, &ev.upstream, &ev.model);
                table.record_error(&key, alpha, now_ms);
            }
        }

        // Record final attempt outcome and latency (prefer true TTFT -> TTFB -> total_duration).
        if let Some(target) = meta.active_target() {
            let key =
                TargetLatencyTable::target_key(&target.provider, &target.upstream, &target.model);
            let status_code = summary.status.map(|s| s.as_u16());
            let is_error = summary.error.is_some()
                || summary.aborted_mid_stream
                || matches!(status_code, None | Some(429 | 500..=599));

            if is_error {
                table.record_error(&key, alpha, now_ms);
            } else {
                let ttft = ctx
                    .get_ext::<AiUsage>()
                    .and_then(|u| u.first_token_at)
                    .map(|t| t.saturating_duration_since(ctx.started_at))
                    .or(summary.ttfb)
                    .unwrap_or(summary.total_duration);
                let latency_ms = ttft.as_secs_f64() * 1_000.0;
                table.record_success(&key, latency_ms, alpha, now_ms);
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
        let mut models = HashMap::new();
        models.insert(
            "smart".to_owned(),
            ModelEntryConfig::Targets(vec![TargetSpec {
                provider: "openai".to_owned(),
                upstream: "openai".to_owned(),
                model: Some("gpt-4o".to_owned()),
                endpoint_override: None,
                capabilities: Vec::new(),
                weight: 1,
                default_params: BTreeMap::new(),
                override_params: BTreeMap::new(),
            }]),
        );
        models.insert(
            "fast".to_owned(),
            ModelEntryConfig::Detailed {
                strategy: Some(RoutingStrategy::Weighted),
                targets: vec![TargetSpec {
                    provider: "groq".to_owned(),
                    upstream: "groq".to_owned(),
                    model: Some("llama-3.3-70b".to_owned()),
                    endpoint_override: None,
                    capabilities: Vec::new(),
                    weight: 5,
                    default_params: BTreeMap::new(),
                    override_params: BTreeMap::new(),
                }],
            },
        );
        let rules = vec![ModelRule {
            pattern: "claude-*".to_owned(),
            strategy: None,
            targets: vec![TargetSpec {
                provider: "anthropic".to_owned(),
                upstream: "anthropic".to_owned(),
                model: None,
                endpoint_override: None,
                capabilities: Vec::new(),
                weight: 1,
                default_params: BTreeMap::new(),
                override_params: BTreeMap::new(),
            }],
        }];
        let exposed = vec!["claude-3-5-sonnet-20241022".to_owned(), "smart".to_owned()];

        let (list_bytes, by_id, entries) = compile_models_catalog(&models, &rules, &[], &exposed);
        assert_eq!(entries.len(), 3);
        let list: Value = serde_json::from_slice(&list_bytes).unwrap();
        let data = list["data"].as_array().unwrap();
        let ids: Vec<&str> = data.iter().map(|d| d["id"].as_str().unwrap()).collect();
        assert_eq!(ids, vec!["claude-3-5-sonnet-20241022", "fast", "smart"]);
        assert_eq!(data[0]["owned_by"], "anthropic");
        assert_eq!(data[1]["owned_by"], "groq");
        assert_eq!(data[2]["owned_by"], "openai");
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
