use std::collections::HashMap;
use std::sync::Arc;

use serde::Deserialize;
use shunt_plugin_sdk::{
    BuildContext, Bytes, Flow, HookMask, HookResult, HttpPlugin, PluginBuildError, PluginConfig,
    PluginFactory, RequestCtx, RouteDecision, StatusCode, UpstreamSelection,
};

use crate::types::{AiProvider, AiRequestMeta, AiTarget, openai_error_response};

const DEFAULT_MAX_BODY_BYTES: usize = 1024 * 1024; // 1 MiB

#[derive(Debug, Clone, Deserialize)]
pub struct TargetSpec {
    pub provider: AiProvider,
    pub upstream: String,
    /// Target model name sent to the provider. If omitted, forwards the client's requested model.
    #[serde(default)]
    pub model: Option<String>,
    /// Optional explicit endpoint override passed to `UpstreamSelection::endpoint_override`.
    #[serde(default)]
    pub endpoint_override: Option<String>,
}

impl TargetSpec {
    fn resolve(&self, requested_model: &str) -> AiTarget {
        AiTarget {
            provider: self.provider,
            upstream: self.upstream.clone(),
            model: self
                .model
                .clone()
                .unwrap_or_else(|| requested_model.to_owned()),
            endpoint_override: self.endpoint_override.clone(),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct ModelRule {
    /// Glob-style pattern supporting `*` wildcards (e.g. `"claude-*"`, `"gpt-4*"`, `"*"`).
    pub pattern: String,
    pub targets: Vec<TargetSpec>,
}

#[derive(Debug, Deserialize)]
#[serde(default)]
struct AiModelRouterConfig {
    /// Maximum buffered JSON request body size in bytes (default: 1 MiB).
    max_body_bytes: usize,
    /// Automatically raise `decision.max_attempts` to at least the length of the selected
    /// target fallback chain (default: true).
    auto_max_attempts: bool,
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
            models: HashMap::new(),
            rules: Vec::new(),
            default_targets: Vec::new(),
        }
    }
}

#[derive(Debug, Deserialize)]
struct ChatRequestProbe {
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

        Ok(Arc::new(AiModelRouterPlugin {
            max_body_bytes: cfg.max_body_bytes,
            auto_max_attempts: cfg.auto_max_attempts,
            models: cfg.models,
            rules: cfg.rules,
            default_targets: cfg.default_targets,
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
        if t.upstream.trim().is_empty() {
            return Err(PluginBuildError::BuildFailed {
                plugin: plugin.to_owned(),
                message: format!("`{label}[{idx}].upstream` cannot be empty"),
            });
        }
    }
    Ok(())
}

/// Parses OpenAI-compatible chat request bodies, extracts `"model"` and `"stream"`,
/// stores typed [`AiRequestMeta`] in `ctx.extensions`, and steers `on_route` /
/// `on_upstream_select` across an ordered provider/model fallback chain.
pub struct AiModelRouterPlugin {
    max_body_bytes: usize,
    auto_max_attempts: bool,
    models: HashMap<String, Vec<TargetSpec>>,
    rules: Vec<ModelRule>,
    default_targets: Vec<TargetSpec>,
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
        HookMask::REQUEST_BODY_BUFFERED | HookMask::ON_ROUTE | HookMask::ON_UPSTREAM_SELECT
    }

    fn max_request_body_bytes(&self) -> Option<usize> {
        Some(self.max_body_bytes)
    }

    fn on_request_body_buffered<'a>(
        &'a self,
        ctx: &'a mut RequestCtx,
        body: &'a mut Bytes,
    ) -> HookResult<'a, Flow> {
        let probe: ChatRequestProbe = match serde_json::from_slice(body) {
            Ok(p) => p,
            Err(err) => {
                let resp = openai_error_response(
                    StatusCode::BAD_REQUEST,
                    "invalid_request_error",
                    Some("invalid_json"),
                    &format!("Invalid JSON in request body: {err}"),
                );
                return HookResult::Ready(Flow::Respond(resp));
            }
        };

        let Some(model) = probe.model.filter(|m| !m.trim().is_empty()) else {
            let resp = openai_error_response(
                StatusCode::BAD_REQUEST,
                "invalid_request_error",
                Some("missing_model"),
                "Request body must include a non-empty `model` field",
            );
            return HookResult::Ready(Flow::Respond(resp));
        };

        let Some(targets) = self.resolve_targets(&model) else {
            let resp = openai_error_response(
                StatusCode::NOT_FOUND,
                "invalid_request_error",
                Some("model_not_found"),
                &format!("The model `{model}` is not configured on this gateway"),
            );
            return HookResult::Ready(Flow::Respond(resp));
        };

        ctx.insert_ext(AiRequestMeta::new(model, probe.stream, targets));
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
}
