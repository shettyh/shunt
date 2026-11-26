use std::collections::BTreeMap;
use std::sync::Arc;

use serde_json::Value;
use shunt_ai::{AiMetrics, register_ai_plugins};
use shunt_config::{
    AdminConfig, GatewayConfig, LoadedConfig, PluginAttachment, RouteGroupIr, RouteIr,
    ServerConfig, Severity, SnapshotCompiler, StateConfig, TelemetryConfig, UpstreamIr,
    VerifyReport, verify_bundle,
};
use shunt_engine::RuntimeRegistry;
use shunt_mcp::{McpMetrics, register_mcp_plugins};
use shunt_plugin_sdk::PluginRegistry;
use shunt_plugins::{PrometheusMetrics, register_builtin_plugins};

use crate::crypto::sha256_prefixed;
use crate::error::{ConsoleError, DiagnosticItem};
use crate::models::{TopologyResource, TopologyResourceKind, ValidateDraftResult};

/// Output of compiling relational cluster draft resources into canonical `GatewayConfig` IR.
pub struct CompiledTopology {
    pub config: GatewayConfig,
    /// Redacted canonical TOML (safe for storage, UI preview, diffs, and `export.toml`).
    pub redacted_toml: String,
    pub digest: String,
    pub verify_report: VerifyReport,
    pub diagnostics: Vec<DiagnosticItem>,
    pub route_count: usize,
    pub upstream_count: usize,
}

/// Compiles normalized `topology_resources` into canonical Shunt `GatewayConfig` IR and runs
/// Shunt's exact `GatewayConfig::validate()`, `SnapshotCompiler::compile()`, and `verify_bundle()`.
pub struct ConsoleCompiler;

impl ConsoleCompiler {
    /// Builds a `GatewayConfig` from relational cluster resources.
    pub fn assemble_gateway_config(
        resources: &[TopologyResource],
    ) -> Result<GatewayConfig, ConsoleError> {
        let mut cfg = GatewayConfig::default();

        let mut sorted: Vec<&TopologyResource> = resources
            .iter()
            .filter(|r| r.draft_state != "deleted")
            .collect();
        sorted.sort_by(|a, b| a.sort_order.cmp(&b.sort_order).then(a.slug.cmp(&b.slug)));

        for res in sorted {
            match res.kind {
                TopologyResourceKind::Server => {
                    cfg.server =
                        serde_json::from_value::<ServerConfig>(res.spec.clone()).map_err(|e| {
                            ConsoleError::BadRequest(format!(
                                "invalid server resource `{}`: {e}",
                                res.slug
                            ))
                        })?;
                }
                TopologyResourceKind::Admin => {
                    cfg.admin =
                        serde_json::from_value::<AdminConfig>(res.spec.clone()).map_err(|e| {
                            ConsoleError::BadRequest(format!(
                                "invalid admin resource `{}`: {e}",
                                res.slug
                            ))
                        })?;
                }
                TopologyResourceKind::State => {
                    cfg.state =
                        serde_json::from_value::<StateConfig>(res.spec.clone()).map_err(|e| {
                            ConsoleError::BadRequest(format!(
                                "invalid state resource `{}`: {e}",
                                res.slug
                            ))
                        })?;
                }
                TopologyResourceKind::Telemetry => {
                    cfg.telemetry = serde_json::from_value::<TelemetryConfig>(res.spec.clone())
                        .map_err(|e| {
                            ConsoleError::BadRequest(format!(
                                "invalid telemetry resource `{}`: {e}",
                                res.slug
                            ))
                        })?;
                }
                TopologyResourceKind::GlobalPlugin => {
                    let plugin = serde_json::from_value::<PluginAttachment>(res.spec.clone())
                        .map_err(|e| {
                            ConsoleError::BadRequest(format!(
                                "invalid global_plugin `{}`: {e}",
                                res.slug
                            ))
                        })?;
                    cfg.plugins.push(plugin);
                }
                TopologyResourceKind::Upstream => {
                    let mut up =
                        serde_json::from_value::<UpstreamIr>(res.spec.clone()).map_err(|e| {
                            ConsoleError::BadRequest(format!(
                                "invalid upstream `{}`: {e}",
                                res.slug
                            ))
                        })?;
                    if up.name.is_empty() {
                        up.name = res.slug.clone();
                    }
                    cfg.upstreams.push(up);
                }
                TopologyResourceKind::RouteGroup => {
                    let mut rg =
                        serde_json::from_value::<RouteGroupIr>(res.spec.clone()).map_err(|e| {
                            ConsoleError::BadRequest(format!(
                                "invalid route_group `{}`: {e}",
                                res.slug
                            ))
                        })?;
                    if rg.id.is_empty() {
                        rg.id = res.slug.clone();
                    }
                    cfg.route_groups.push(rg);
                }
                TopologyResourceKind::Route => {
                    let mut r =
                        serde_json::from_value::<RouteIr>(res.spec.clone()).map_err(|e| {
                            ConsoleError::BadRequest(format!("invalid route `{}`: {e}", res.slug))
                        })?;
                    if r.id.is_empty() {
                        r.id = res.slug.clone();
                    }
                    cfg.routes.push(r);
                }
            }
        }

        Ok(cfg)
    }

    /// Validates, dry-run compiles against all registered Shunt plugins (`shunt-plugins`,
    /// `shunt-ai`, `shunt-mcp`), and runs `shunt verify` on the assembled draft.
    pub fn compile_and_verify(
        cluster_slug: &str,
        resources: &[TopologyResource],
        strict: bool,
    ) -> Result<CompiledTopology, ConsoleError> {
        let cfg = Self::assemble_gateway_config(resources)?;
        let redacted_toml = toml::to_string_pretty(&cfg).map_err(|e| {
            ConsoleError::Internal(format!("failed to serialize canonical shunt.toml: {e}"))
        })?;
        let digest = sha256_prefixed(redacted_toml.as_bytes());

        // 1. Validate canonical IR.
        if let Err(err) = cfg.validate() {
            let diagnostics = vec![DiagnosticItem {
                severity: "error".to_owned(),
                rule: "ir.validate".to_owned(),
                subject: None,
                message: err.to_string(),
            }];
            return Err(ConsoleError::Validation {
                message: err.to_string(),
                diagnostics,
            });
        }

        // 2. Dry-run compile through SnapshotCompiler with full plugin packs.
        // Substitute placeholder strings for `secret:<slug>` refs only during dry-run validation
        // so vault-backed plugins validate without decrypting secrets during preview.
        let mut dry_run_val = serde_json::to_value(&cfg)
            .map_err(|e| ConsoleError::Internal(format!("serialize config for dry-run: {e}")))?;
        replace_secret_refs_for_dry_run(&mut dry_run_val);
        let dry_run_cfg: GatewayConfig = serde_json::from_value(dry_run_val).map_err(|e| {
            ConsoleError::Internal(format!("deserialize dry-run config failed: {e}"))
        })?;

        let compiler = build_validation_compiler();
        let loaded = LoadedConfig {
            source_name: format!("console:{cluster_slug}:draft"),
            config: dry_run_cfg,
            digest: digest.clone(),
        };

        let bundle = compiler
            .compile(&loaded)
            .map_err(|err| ConsoleError::Validation {
                message: err.to_string(),
                diagnostics: vec![DiagnosticItem {
                    severity: "error".to_owned(),
                    rule: "snapshot.compile".to_owned(),
                    subject: None,
                    message: err.to_string(),
                }],
            })?;

        let verify_report = verify_bundle(&bundle, None, strict);
        let diagnostics: Vec<DiagnosticItem> = verify_report
            .diagnostics
            .iter()
            .map(|d| DiagnosticItem {
                severity: match d.severity {
                    Severity::Error => "error".to_owned(),
                    Severity::Warning => "warning".to_owned(),
                    Severity::Info => "info".to_owned(),
                },
                rule: d.rule.clone(),
                subject: d.subject.clone(),
                message: d.message.clone(),
            })
            .collect();

        Ok(CompiledTopology {
            route_count: bundle.inspect.routes.len(),
            upstream_count: bundle.inspect.upstreams.len(),
            config: cfg,
            redacted_toml,
            digest,
            verify_report,
            diagnostics,
        })
    }

    /// Runs validation and returns a structured report without failing on verify errors
    /// (for interactive UI live validation).
    pub fn validate_preview(
        cluster_slug: &str,
        resources: &[TopologyResource],
    ) -> Result<ValidateDraftResult, ConsoleError> {
        match Self::compile_and_verify(cluster_slug, resources, false) {
            Ok(compiled) => Ok(ValidateDraftResult {
                valid: compiled.verify_report.passed,
                errors: compiled.verify_report.errors,
                warnings: compiled.verify_report.warnings,
                infos: compiled.verify_report.infos,
                digest: compiled.digest,
                compiled_toml: compiled.redacted_toml,
                diagnostics: compiled.diagnostics,
                route_count: compiled.route_count,
                upstream_count: compiled.upstream_count,
            }),
            Err(ConsoleError::Validation { diagnostics, .. }) => {
                let cfg = Self::assemble_gateway_config(resources).unwrap_or_default();
                let compiled_toml = toml::to_string_pretty(&cfg).unwrap_or_default();
                let digest = sha256_prefixed(compiled_toml.as_bytes());
                Ok(ValidateDraftResult {
                    valid: false,
                    errors: diagnostics.len(),
                    warnings: 0,
                    infos: 0,
                    digest,
                    compiled_toml,
                    diagnostics,
                    route_count: cfg.routes.len(),
                    upstream_count: cfg.upstreams.len(),
                })
            }
            Err(other) => Err(other),
        }
    }

    /// Resolves `secret:<slug>` references inside a compiled TOML string for delivery over an
    /// authenticated Channel 1 node bundle connection.
    pub fn resolve_secrets_for_delivery<F>(
        compiled_toml: &str,
        mut resolver: F,
    ) -> Result<String, ConsoleError>
    where
        F: FnMut(&str) -> Result<String, ConsoleError>,
    {
        let cfg: GatewayConfig = toml::from_str(compiled_toml).map_err(|e| {
            ConsoleError::Internal(format!("re-parse stored revision TOML failed: {e}"))
        })?;
        let mut val = serde_json::to_value(&cfg)
            .map_err(|e| ConsoleError::Internal(format!("serialize revision config: {e}")))?;
        let mut changed = false;
        resolve_json_secrets(&mut val, &mut resolver, &mut changed)?;
        if !changed {
            return Ok(compiled_toml.to_owned());
        }
        let resolved_cfg: GatewayConfig = serde_json::from_value(val).map_err(|e| {
            ConsoleError::Internal(format!("deserialize resolved revision config: {e}"))
        })?;
        toml::to_string_pretty(&resolved_cfg)
            .map_err(|e| ConsoleError::Internal(format!("serialize resolved delivery TOML: {e}")))
    }

    /// Decomposes a raw `shunt.toml` into relational `(kind, slug, sort_order, spec_json)` entries
    /// for lossless import into a cluster draft.
    pub fn decompose_toml(
        toml_src: &str,
    ) -> Result<Vec<(TopologyResourceKind, String, i64, Value)>, ConsoleError> {
        let cfg: GatewayConfig = toml::from_str(toml_src)
            .map_err(|e| ConsoleError::BadRequest(format!("invalid shunt.toml: {e}")))?;

        let mut items = vec![
            (
                TopologyResourceKind::Server,
                "default".to_owned(),
                0,
                serde_json::to_value(&cfg.server)
                    .map_err(|e| ConsoleError::Internal(e.to_string()))?,
            ),
            (
                TopologyResourceKind::Admin,
                "default".to_owned(),
                0,
                serde_json::to_value(&cfg.admin)
                    .map_err(|e| ConsoleError::Internal(e.to_string()))?,
            ),
            (
                TopologyResourceKind::State,
                "default".to_owned(),
                0,
                serde_json::to_value(&cfg.state)
                    .map_err(|e| ConsoleError::Internal(e.to_string()))?,
            ),
            (
                TopologyResourceKind::Telemetry,
                "default".to_owned(),
                0,
                serde_json::to_value(&cfg.telemetry)
                    .map_err(|e| ConsoleError::Internal(e.to_string()))?,
            ),
        ];

        for (idx, p) in cfg.plugins.iter().enumerate() {
            let slug =
                p.id.clone()
                    .unwrap_or_else(|| sanitize_slug(&format!("{}-{}", p.name, idx + 1)));
            items.push((
                TopologyResourceKind::GlobalPlugin,
                slug,
                idx as i64,
                serde_json::to_value(p).map_err(|e| ConsoleError::Internal(e.to_string()))?,
            ));
        }
        for (idx, u) in cfg.upstreams.iter().enumerate() {
            items.push((
                TopologyResourceKind::Upstream,
                sanitize_slug(&u.name),
                idx as i64,
                serde_json::to_value(u).map_err(|e| ConsoleError::Internal(e.to_string()))?,
            ));
        }
        for (idx, rg) in cfg.route_groups.iter().enumerate() {
            items.push((
                TopologyResourceKind::RouteGroup,
                sanitize_slug(&rg.id),
                idx as i64,
                serde_json::to_value(rg).map_err(|e| ConsoleError::Internal(e.to_string()))?,
            ));
        }
        for (idx, r) in cfg.routes.iter().enumerate() {
            items.push((
                TopologyResourceKind::Route,
                sanitize_slug(&r.id),
                idx as i64,
                serde_json::to_value(r).map_err(|e| ConsoleError::Internal(e.to_string()))?,
            ));
        }
        Ok(items)
    }

    /// Returns the clean, neutral starter `shunt.toml` skeleton for a newly created cluster.
    ///
    /// Every Shunt cluster is unified by default and can serve HTTP APIs, AI models, and MCP
    /// servers simultaneously without locking the cluster into a single gateway mode.
    pub fn default_cluster_toml() -> &'static str {
        r#"[server]
listen = "0.0.0.0:8080"
drain_timeout_ms = 30000

[admin]
enabled = true
listen = "127.0.0.1:9090"
ui = false

[[plugins]]
name = "request-id"

[[plugins]]
name = "metrics"
"#
    }
}

/// Resolves which topology revision a node should run based on `ring_assignments` and `node_labels`.
///
/// Exact `key=value` selectors take precedence over the wildcard `"*"` default ring.
pub fn resolve_target_revision(
    ring_assignments: &BTreeMap<String, u64>,
    node_labels: &BTreeMap<String, String>,
) -> Option<u64> {
    for (selector, rev) in ring_assignments {
        if selector == "*" {
            continue;
        }
        if selector_matches_labels(selector, node_labels) {
            return Some(*rev);
        }
    }
    ring_assignments.get("*").copied()
}

/// Checks whether a selector like `"*"` or `"ring=canary,region=us-east-1"` matches `labels`.
pub fn selector_matches_labels(selector: &str, labels: &BTreeMap<String, String>) -> bool {
    let trimmed = selector.trim();
    if trimmed == "*" || trimmed.is_empty() {
        return true;
    }
    trimmed.split(',').all(|part| {
        let Some((k, v)) = part.trim().split_once('=') else {
            return false;
        };
        labels.get(k.trim()).map(String::as_str) == Some(v.trim())
    })
}

fn build_validation_compiler() -> SnapshotCompiler {
    let metrics = Arc::new(PrometheusMetrics::new());
    let ai_metrics = Arc::new(AiMetrics::new());
    let mcp_metrics = Arc::new(McpMetrics::new());
    let mut registry = PluginRegistry::new();
    register_builtin_plugins(&mut registry, metrics);
    register_ai_plugins(&mut registry, ai_metrics);
    register_mcp_plugins(&mut registry, mcp_metrics);
    SnapshotCompiler::new(Arc::new(registry), Arc::new(RuntimeRegistry::new()))
}

fn replace_secret_refs_for_dry_run(val: &mut Value) {
    match val {
        Value::String(s) => {
            if let Some(slug) = s.strip_prefix("secret:") {
                *s = format!("__console_dry_run_secret_{slug}__");
            }
        }
        Value::Array(arr) => {
            for item in arr {
                replace_secret_refs_for_dry_run(item);
            }
        }
        Value::Object(map) => {
            for (_, v) in map.iter_mut() {
                replace_secret_refs_for_dry_run(v);
            }
        }
        _ => {}
    }
}

fn resolve_json_secrets<F>(
    val: &mut Value,
    resolver: &mut F,
    changed: &mut bool,
) -> Result<(), ConsoleError>
where
    F: FnMut(&str) -> Result<String, ConsoleError>,
{
    match val {
        Value::String(s) => {
            if let Some(slug) = s.strip_prefix("secret:") {
                *s = resolver(slug.trim())?;
                *changed = true;
            }
        }
        Value::Array(arr) => {
            for item in arr {
                resolve_json_secrets(item, resolver, changed)?;
            }
        }
        Value::Object(map) => {
            for (_, v) in map.iter_mut() {
                resolve_json_secrets(v, resolver, changed)?;
            }
        }
        _ => {}
    }
    Ok(())
}

fn sanitize_slug(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    for c in raw.chars() {
        if c.is_ascii_alphanumeric() {
            out.push(c.to_ascii_lowercase());
        } else if c == '-' || c == '_' {
            out.push(c);
        } else {
            out.push('-');
        }
    }
    let trimmed = out.trim_matches('-').to_owned();
    if trimmed.is_empty() {
        "default".to_owned()
    } else {
        trimmed.chars().take(64).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_cluster_skeleton_compiles_and_verifies_cleanly() {
        let toml_src = ConsoleCompiler::default_cluster_toml();
        let items = ConsoleCompiler::decompose_toml(toml_src).unwrap();
        let resources: Vec<TopologyResource> = items
            .into_iter()
            .map(|(kind, slug, sort_order, spec)| TopologyResource {
                id: format!("r_{slug}"),
                cluster_id: "cls_1".to_owned(),
                kind,
                slug,
                sort_order,
                version: 1,
                etag: "\"1\"".to_owned(),
                spec,
                draft_state: "active".to_owned(),
                updated_by: "test".to_owned(),
                created_at: String::new(),
                updated_at: String::new(),
            })
            .collect();
        let compiled = ConsoleCompiler::compile_and_verify("test", &resources, false).unwrap();
        assert!(
            compiled.verify_report.passed,
            "default cluster skeleton failed verify: {:?}",
            compiled.diagnostics
        );
    }

    #[test]
    fn ring_selector_prefers_canary_over_wildcard() {
        let mut rings = BTreeMap::new();
        rings.insert("*".to_owned(), 1);
        rings.insert("ring=canary".to_owned(), 2);

        let mut canary = BTreeMap::new();
        canary.insert("ring".to_owned(), "canary".to_owned());
        let mut stable = BTreeMap::new();
        stable.insert("ring".to_owned(), "stable".to_owned());

        assert_eq!(resolve_target_revision(&rings, &canary), Some(2));
        assert_eq!(resolve_target_revision(&rings, &stable), Some(1));
    }
}
