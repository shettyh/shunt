use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;

use serde::Deserialize;
use serde_json::json;
use shunt_plugin_sdk::{
    BufferedResponse, BuildContext, Bytes, Flow, HookMask, HookResult, HttpPlugin, Method,
    PluginBuildError, PluginConfig, PluginFactory, RequestCtx, RequestHead, RouteDecision,
    StatusCode, UpstreamSelection,
};

use crate::types::{
    AiCapability, AiEndpointKind, AiRequestMeta, AiTarget, DetectedEndpoint,
    endpoint_error_response, openai_error_response, percent_decode,
};

const DEFAULT_MAX_BODY_BYTES: usize = 1024 * 1024; // 1 MiB

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
    /// Optional capability tags (`chat`, `streaming`, `tools`, `vision`, `embeddings`).
    #[serde(default)]
    pub capabilities: Vec<AiCapability>,
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
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct ModelRule {
    /// Glob-style pattern supporting `*` wildcards (e.g. `"claude-*"`, `"gpt-4*"`, `"*"`).
    pub pattern: String,
    pub targets: Vec<TargetSpec>,
}

fn default_true() -> bool {
    true
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
    /// Additional concrete model IDs to advertise on `GET /v1/models` (useful for
    /// wildcard-routed models like `"claude-3-5-sonnet-20241022"` or `"gemini-2.5-flash"`).
    exposed_models: Vec<String>,
    /// Exact model name -> ordered provider/upstream fallback targets.
    models: HashMap<String, Vec<TargetSpec>>,
    /// Ordered wildcard pattern rules checked when no exact match exists in `models`.
    rules: Vec<ModelRule>,
    /// Catch-all fallback targets when neither `models` nor `rules` match.
    default_targets: Vec<TargetSpec>,
}

impl Default for AiModelRouterConfig {
    fn default() -> Self {
        Self {
            max_body_bytes: DEFAULT_MAX_BODY_BYTES,
            auto_max_attempts: true,
            serve_models_endpoint: true,
            exposed_models: Vec::new(),
            models: HashMap::new(),
            rules: Vec::new(),
            default_targets: Vec::new(),
        }
    }
}

#[derive(Debug, Deserialize)]
struct ModelRequestProbe {
    model: Option<String>,
    #[serde(default)]
    stream: bool,
}

/// Factory for the `ai-model-router` plugin.
pub struct AiModelRouterFactory;

impl PluginFactory for AiModelRouterFactory {
    fn name(&self) -> &str {
        "ai-model-router"
    }

    fn build(
        &self,
        config: &PluginConfig,
        _ctx: &BuildContext,
    ) -> Result<Arc<dyn HttpPlugin>, PluginBuildError> {
        let cfg: AiModelRouterConfig = config.deserialize(self.name())?;

        if cfg.max_body_bytes == 0 {
            return Err(PluginBuildError::BuildFailed {
                plugin: self.name().to_owned(),
                message: "`max_body_bytes` must be > 0".to_owned(),
            });
        }

        if cfg.models.is_empty() && cfg.rules.is_empty() && cfg.default_targets.is_empty() {
            return Err(PluginBuildError::BuildFailed {
                plugin: self.name().to_owned(),
                message: "configure at least one entry in `models`, `rules`, or `default_targets`"
                    .to_owned(),
            });
        }

        for (model, targets) in &cfg.models {
            validate_targets(self.name(), &format!("models.{model}"), targets)?;
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

        let (models_list_json, models_by_id) = compile_models_catalog(
            &cfg.models,
            &cfg.rules,
            &cfg.default_targets,
            &cfg.exposed_models,
        );

        Ok(Arc::new(AiModelRouterPlugin {
            max_body_bytes: cfg.max_body_bytes,
            auto_max_attempts: cfg.auto_max_attempts,
            serve_models_endpoint: cfg.serve_models_endpoint,
            models: cfg.models,
            rules: cfg.rules,
            default_targets: cfg.default_targets,
            models_list_json,
            models_by_id,
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
    }
    Ok(())
}

/// Pre-serializes deterministic OpenAI `GET /v1/models` and `GET /v1/models/{id}` payloads
/// once at snapshot compilation time (zero per-request sorting or serialization).
fn compile_models_catalog(
    models: &HashMap<String, Vec<TargetSpec>>,
    rules: &[ModelRule],
    default_targets: &[TargetSpec],
    exposed_models: &[String],
) -> (Bytes, HashMap<String, Bytes>) {
    // BTreeMap guarantees deterministic alphabetical ordering by model `id`.
    let mut catalog: BTreeMap<String, String> = BTreeMap::new();

    // 1. Explicit model aliases in `models`.
    for (alias, targets) in models {
        let owner = targets
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

    for (id, owned_by) in catalog {
        let entry = json!({
            "id": id,
            "object": "model",
            "created": 0,
            "owned_by": owned_by,
        });
        let single_bytes = Bytes::from(serde_json::to_vec(&entry).unwrap_or_default());
        models_by_id.insert(id, single_bytes);
        data_entries.push(entry);
    }

    let list_payload = json!({
        "object": "list",
        "data": data_entries,
    });
    let list_bytes = Bytes::from(serde_json::to_vec(&list_payload).unwrap_or_default());

    (list_bytes, models_by_id)
}

fn resolve_owner_for_exposed(
    model_id: &str,
    models: &HashMap<String, Vec<TargetSpec>>,
    rules: &[ModelRule],
    default_targets: &[TargetSpec],
) -> String {
    if let Some(specs) = models.get(model_id)
        && let Some(first) = specs.first()
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

/// Parses incoming OpenAI-compatible AI requests (`/v1/chat/completions`, `/v1/embeddings`,
/// `GET /v1/models`, `GET /v1/models/{id}`), stores typed [`AiRequestMeta`] in `ctx.extensions`,
/// and steers `on_route` / `on_upstream_select` across an ordered named-provider fallback chain.
pub struct AiModelRouterPlugin {
    max_body_bytes: usize,
    auto_max_attempts: bool,
    serve_models_endpoint: bool,
    models: HashMap<String, Vec<TargetSpec>>,
    rules: Vec<ModelRule>,
    default_targets: Vec<TargetSpec>,
    models_list_json: Bytes,
    models_by_id: HashMap<String, Bytes>,
}

impl AiModelRouterPlugin {
    fn resolve_targets(&self, requested_model: &str) -> Option<Vec<AiTarget>> {
        if let Some(specs) = self.models.get(requested_model) {
            return Some(specs.iter().map(|s| s.resolve(requested_model)).collect());
        }
        for rule in &self.rules {
            if wildcard_match(&rule.pattern, requested_model) {
                return Some(
                    rule.targets
                        .iter()
                        .map(|s| s.resolve(requested_model))
                        .collect(),
                );
            }
        }
        if !self.default_targets.is_empty() {
            return Some(
                self.default_targets
                    .iter()
                    .map(|s| s.resolve(requested_model))
                    .collect(),
            );
        }
        None
    }
}

impl HttpPlugin for AiModelRouterPlugin {
    fn name(&self) -> &str {
        "ai-model-router"
    }

    fn hook_mask(&self) -> HookMask {
        HookMask::ON_REQUEST_HEADERS
            | HookMask::REQUEST_BODY_BUFFERED
            | HookMask::ON_ROUTE
            | HookMask::ON_UPSTREAM_SELECT
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
                return HookResult::Ready(Flow::Respond(BufferedResponse::json(
                    StatusCode::OK,
                    self.models_list_json.clone(),
                )));
            }

            if let Some(raw_id) = path
                .strip_prefix("/v1/models/")
                .or_else(|| path.strip_prefix("/models/"))
                && !raw_id.is_empty()
            {
                ctx.insert_ext(DetectedEndpoint(AiEndpointKind::ModelRetrieve));
                let decoded_id = percent_decode(raw_id);
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

        let endpoint = if path.ends_with("/embeddings") {
            AiEndpointKind::Embeddings
        } else if path.ends_with("/messages") {
            AiEndpointKind::AnthropicMessages
        } else if path.ends_with("/responses") {
            AiEndpointKind::OpenAiResponses
        } else {
            AiEndpointKind::ChatCompletions
        };
        ctx.insert_ext(DetectedEndpoint(endpoint));

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

        let probe: ModelRequestProbe = match serde_json::from_slice(body) {
            Ok(p) => p,
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

        let Some(model) = probe.model.filter(|m| !m.trim().is_empty()) else {
            let resp = endpoint_error_response(
                endpoint,
                StatusCode::BAD_REQUEST,
                "invalid_request_error",
                Some("missing_model"),
                "Request body must include a non-empty `model` field",
            );
            return HookResult::Ready(Flow::Respond(resp));
        };

        let Some(all_targets) = self.resolve_targets(&model) else {
            let resp = endpoint_error_response(
                endpoint,
                StatusCode::NOT_FOUND,
                "invalid_request_error",
                Some("model_not_found"),
                &format!("The model `{model}` is not configured on this gateway"),
            );
            return HookResult::Ready(Flow::Respond(resp));
        };

        let required_cap = match endpoint {
            AiEndpointKind::Embeddings => Some(AiCapability::Embeddings),
            AiEndpointKind::ChatCompletions
            | AiEndpointKind::AnthropicMessages
            | AiEndpointKind::OpenAiResponses => Some(AiCapability::Chat),
            AiEndpointKind::ModelsList | AiEndpointKind::ModelRetrieve => None,
        };

        let targets: Vec<AiTarget> = match required_cap {
            Some(cap) => all_targets
                .into_iter()
                .filter(|t| t.supports(cap))
                .collect(),
            None => all_targets,
        };

        if targets.is_empty() {
            let resp = endpoint_error_response(
                endpoint,
                StatusCode::BAD_REQUEST,
                "invalid_request_error",
                Some("unsupported_endpoint"),
                &format!("No configured targets for model `{model}` support `{endpoint}`"),
            );
            return HookResult::Ready(Flow::Respond(resp));
        }

        let effective_stream = match endpoint {
            AiEndpointKind::Embeddings => false,
            _ => probe.stream,
        };

        ctx.insert_ext(AiRequestMeta::new(
            endpoint,
            model,
            effective_stream,
            targets,
        ));
        HookResult::Ready(Flow::Continue)
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
        if let Some(meta) = ctx.get_ext_mut::<AiRequestMeta>() {
            meta.max_attempts = selection.max_attempts;
            if let Some(target) = meta.select_for_attempt(selection.attempt) {
                selection.upstream = target.upstream.clone();
                selection.endpoint_override = target.endpoint_override.clone();
            }
        }
        HookResult::Ready(Flow::Continue)
    }
}

/// Simple wildcard glob matching supporting `*` (zero or more characters).
fn wildcard_match(pattern: &str, text: &str) -> bool {
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
            vec![TargetSpec {
                provider: "openai".to_owned(),
                upstream: "openai".to_owned(),
                model: Some("gpt-4o".to_owned()),
                endpoint_override: None,
                capabilities: Vec::new(),
            }],
        );
        models.insert(
            "fast".to_owned(),
            vec![TargetSpec {
                provider: "groq".to_owned(),
                upstream: "groq".to_owned(),
                model: Some("llama-3.3-70b".to_owned()),
                endpoint_override: None,
                capabilities: Vec::new(),
            }],
        );
        let rules = vec![ModelRule {
            pattern: "claude-*".to_owned(),
            targets: vec![TargetSpec {
                provider: "anthropic".to_owned(),
                upstream: "anthropic".to_owned(),
                model: None,
                endpoint_override: None,
                capabilities: Vec::new(),
            }],
        }];
        let exposed = vec!["claude-3-5-sonnet-20241022".to_owned(), "smart".to_owned()];

        let (list_bytes, by_id) = compile_models_catalog(&models, &rules, &[], &exposed);
        let list: serde_json::Value = serde_json::from_slice(&list_bytes).unwrap();
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
}
