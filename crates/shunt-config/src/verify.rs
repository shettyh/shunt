use std::collections::{HashMap, HashSet};
use std::fmt;
use std::net::SocketAddr;
use std::path::Path;

use serde::{Deserialize, Serialize};
use serde_json::Value;
use shunt_core::{PathMatch, RouteMatch, host_matches};
use shunt_plugin_sdk::HookMask;

use crate::compiler::CompiledBundle;
use crate::error::ConfigError;

/// Severity level for a static verification diagnostic.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info,
    Warning,
    Error,
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Severity::Info => f.write_str("info"),
            Severity::Warning => f.write_str("warning"),
            Severity::Error => f.write_str("error"),
        }
    }
}

/// A single structured diagnostic emitted by [`verify_bundle`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct VerifyDiagnostic {
    pub rule: String,
    pub severity: Severity,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subject: Option<String>,
    pub message: String,
}

/// Complete verification report returned by [`verify_bundle`].
#[derive(Debug, Clone, Serialize)]
pub struct VerifyReport {
    pub passed: bool,
    pub errors: usize,
    pub warnings: usize,
    pub infos: usize,
    pub diagnostics: Vec<VerifyDiagnostic>,
}

impl VerifyReport {
    pub fn from_diagnostics(diagnostics: Vec<VerifyDiagnostic>, strict: bool) -> Self {
        let mut errors = 0;
        let mut warnings = 0;
        let mut infos = 0;
        for d in &diagnostics {
            match d.severity {
                Severity::Error => errors += 1,
                Severity::Warning => warnings += 1,
                Severity::Info => infos += 1,
            }
        }
        let passed = errors == 0 && (!strict || warnings == 0);
        Self {
            passed,
            errors,
            warnings,
            infos,
            diagnostics,
        }
    }
}

/// Optional verification policy loaded from `[verify]` in `shunt.toml` or a separate `--policy` file.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(default)]
pub struct VerifyPolicy {
    /// Treat shadowed routes as errors (default: `true`). Set to `false` to downgrade to warning.
    pub forbid_shadowed_routes: Option<bool>,
    /// Escalate non-loopback `admin.listen` from warning to error.
    pub require_loopback_admin: bool,
    /// Escalate buffered routes missing explicit `max_body_bytes` from info to error.
    pub require_explicit_body_cap: bool,
    /// Per-route declarative policy assertions.
    #[serde(default)]
    pub route_policies: Vec<RoutePolicy>,
}

impl VerifyPolicy {
    /// Merges an external override policy (e.g. from `--policy policy.toml`) on top of `self`.
    pub fn merge(&self, overlay: &VerifyPolicy) -> VerifyPolicy {
        let mut route_policies = self.route_policies.clone();
        route_policies.extend(overlay.route_policies.clone());
        VerifyPolicy {
            forbid_shadowed_routes: overlay
                .forbid_shadowed_routes
                .or(self.forbid_shadowed_routes),
            require_loopback_admin: self.require_loopback_admin || overlay.require_loopback_admin,
            require_explicit_body_cap: self.require_explicit_body_cap
                || overlay.require_explicit_body_cap,
            route_policies,
        }
    }
}

/// Wrapper accepting either `[verify]` section or top-level policy fields in a `--policy` TOML file.
#[derive(Debug, Deserialize)]
struct PolicyFileWrapper {
    verify: Option<VerifyPolicy>,
    #[serde(flatten)]
    inline: VerifyPolicy,
}

/// Loads a [`VerifyPolicy`] from a TOML file.
pub fn load_policy_file(path: &Path) -> Result<VerifyPolicy, ConfigError> {
    let raw = std::fs::read_to_string(path).map_err(|source| ConfigError::ReadFile {
        path: path.to_path_buf(),
        source,
    })?;
    let wrapper: PolicyFileWrapper =
        toml::from_str(&raw).map_err(|source| ConfigError::TomlParse {
            source_name: path.display().to_string(),
            source,
        })?;
    Ok(match wrapper.verify {
        Some(v) => v,
        None => wrapper.inline,
    })
}

/// Per-route policy constraints checked during `shunt verify`.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(default)]
pub struct RoutePolicy {
    /// Glob pattern matching route IDs (supports `*`, e.g., `"public_*"`, `"*"`).
    pub match_route: String,
    /// Plugin names required on every matching route (global or route-scoped).
    #[serde(default)]
    pub require_plugins: Vec<String>,
    /// HookMask flags forbidden on every matching route (e.g., `"REQUEST_BODY_BUFFERED"`).
    #[serde(default)]
    pub forbid_hooks: Vec<String>,
    /// HookMask flags required on every matching route.
    #[serde(default)]
    pub require_hooks: Vec<String>,
}

/// Runs Shunt's full static IR & compiled-snapshot verifier against `bundle`.
pub fn verify_bundle(
    bundle: &CompiledBundle,
    policy: Option<&VerifyPolicy>,
    strict: bool,
) -> VerifyReport {
    let effective_policy = match policy {
        Some(p) => bundle.config.verify.merge(p),
        None => bundle.config.verify.clone(),
    };

    let mut diags = Vec::new();
    let compiled_routes = &bundle.snapshot.routes;
    let route_irs = &bundle.config.routes;

    // 1. route.shadowed: check all pairs i < j
    let shadow_sev = if effective_policy.forbid_shadowed_routes.unwrap_or(true) {
        Severity::Error
    } else {
        Severity::Warning
    };
    for j in 1..compiled_routes.len() {
        for i in 0..j {
            if route_subsumes(&compiled_routes[i].matcher, &compiled_routes[j].matcher) {
                diags.push(VerifyDiagnostic {
                    rule: "route.shadowed".to_owned(),
                    severity: shadow_sev,
                    subject: Some(compiled_routes[j].id.clone()),
                    message: format!(
                        "route `{}` is completely shadowed by earlier route `{}`",
                        compiled_routes[j].id, compiled_routes[i].id
                    ),
                });
                break;
            }
        }
    }

    // Build upstream lookup map for timeout & AI upstream reference checks.
    let upstreams_by_name: HashMap<&str, &crate::ir::UpstreamIr> = bundle
        .config
        .upstreams
        .iter()
        .map(|u| (u.name.as_str(), u))
        .collect();
    let upstream_names: HashSet<&str> = upstreams_by_name.keys().copied().collect();

    // 1b. Per-upstream static checks (active health check timeout vs interval)
    for up_ir in &bundle.config.upstreams {
        if let Some(hc) = &up_ir.health_check
            && hc.timeout_ms >= hc.interval_ms
        {
            diags.push(VerifyDiagnostic {
                rule: "upstream.health_check_timeout".to_owned(),
                severity: Severity::Warning,
                subject: Some(up_ir.name.clone()),
                message: format!(
                    "upstream `{}` health_check.timeout_ms ({}) >= interval_ms ({})",
                    up_ir.name, hc.timeout_ms, hc.interval_ms
                ),
            });
        }
    }

    // 2. Per-route static checks (timeouts, body cap, AI plugin ordering & targets)
    for (route_ir, compiled) in route_irs.iter().zip(compiled_routes.iter()) {
        // route.timeout_order
        if let Some(resp_timeout) = route_ir.response_headers_timeout_ms
            && let Some(up_ir) = upstreams_by_name.get(route_ir.upstream.as_str())
            && up_ir.connect_timeout_ms >= resp_timeout
        {
            diags.push(VerifyDiagnostic {
                rule: "route.timeout_order".to_owned(),
                severity: Severity::Warning,
                subject: Some(route_ir.id.clone()),
                message: format!(
                    "upstream `{}` connect_timeout_ms ({}) >= route `{}` response_headers_timeout_ms ({})",
                    up_ir.name, up_ir.connect_timeout_ms, route_ir.id, resp_timeout
                ),
            });
        }

        // route.body_cap_missing
        if compiled.hook_mask.contains(HookMask::REQUEST_BODY_BUFFERED)
            && route_ir.max_body_bytes.is_none()
            && compiled
                .plugins
                .iter()
                .all(|p| p.max_request_body_bytes().is_none())
        {
            diags.push(VerifyDiagnostic {
                rule: "route.body_cap_missing".to_owned(),
                severity: if effective_policy.require_explicit_body_cap {
                    Severity::Error
                } else {
                    Severity::Info
                },
                subject: Some(route_ir.id.clone()),
                message: format!(
                    "route `{}` enables REQUEST_BODY_BUFFERED without an explicit `max_body_bytes` (using default {} bytes)",
                    route_ir.id, compiled.max_body_bytes
                ),
            });
        }

        // ai.plugin_order
        let router_pos = route_ir
            .plugins
            .iter()
            .position(|p| p.name == "ai-model-router");
        if let Some(r_idx) = router_pos {
            let cache_pos = route_ir.plugins.iter().position(|p| p.name == "ai-cache");
            for (idx, att) in route_ir.plugins.iter().enumerate() {
                if idx < r_idx
                    && matches!(
                        att.name.as_str(),
                        "ai-cache"
                            | "ai-provider-adapter"
                            | "ai-failover"
                            | "ai-token-rate-limit"
                            | "ai-budget"
                    )
                {
                    diags.push(VerifyDiagnostic {
                        rule: "ai.plugin_order".to_owned(),
                        severity: Severity::Error,
                        subject: Some(route_ir.id.clone()),
                        message: format!(
                            "plugin `{}` (index {idx}) appears before `ai-model-router` (index {r_idx}) on route `{}`",
                            att.name, route_ir.id
                        ),
                    });
                }
                if idx > r_idx && att.name == "ai-virtual-keys" {
                    diags.push(VerifyDiagnostic {
                        rule: "ai.plugin_order".to_owned(),
                        severity: Severity::Error,
                        subject: Some(route_ir.id.clone()),
                        message: format!(
                            "plugin `ai-virtual-keys` (index {idx}) appears after `ai-model-router` (index {r_idx}) on route `{}`; place `ai-virtual-keys` first so authentication and model ACLs run before routing",
                            route_ir.id
                        ),
                    });
                }
                if let Some(c_idx) = cache_pos
                    && c_idx > idx
                    && matches!(att.name.as_str(), "ai-token-rate-limit" | "ai-budget")
                {
                    diags.push(VerifyDiagnostic {
                        rule: "ai.cache_order".to_owned(),
                        severity: Severity::Warning,
                        subject: Some(route_ir.id.clone()),
                        message: format!(
                            "plugin `ai-cache` (index {c_idx}) appears after `{}` (index {idx}) on route `{}`; place `ai-cache` directly after `ai-model-router` so cache hits skip quota and budget checks",
                            att.name, route_ir.id
                        ),
                    });
                }
            }

            let guardrails_pos = route_ir
                .plugins
                .iter()
                .position(|p| p.name == "ai-guardrails");
            let adapter_pos = route_ir
                .plugins
                .iter()
                .position(|p| p.name == "ai-provider-adapter");
            let audit_pos = route_ir.plugins.iter().position(|p| p.name == "ai-audit");
            let usage_pos = route_ir
                .plugins
                .iter()
                .position(|p| p.name == "ai-usage-tracker");
            let alerts_pos = route_ir.plugins.iter().position(|p| p.name == "ai-alerts");

            if let (Some(g_idx), Some(c_idx)) = (guardrails_pos, cache_pos)
                && g_idx > c_idx
            {
                diags.push(VerifyDiagnostic {
                    rule: "ai.guardrails_order".to_owned(),
                    severity: Severity::Warning,
                    subject: Some(route_ir.id.clone()),
                    message: format!(
                        "plugin `ai-guardrails` (index {g_idx}) appears after `ai-cache` (index {c_idx}) on route `{}`; place `ai-guardrails` before `ai-cache` so blocked prompts do not hit cache and redacted prompts are cached safely",
                        route_ir.id
                    ),
                });
            }
            if let (Some(a_idx), Some(g_idx)) = (audit_pos, guardrails_pos)
                && a_idx < g_idx
            {
                diags.push(VerifyDiagnostic {
                    rule: "ai.audit_order".to_owned(),
                    severity: Severity::Warning,
                    subject: Some(route_ir.id.clone()),
                    message: format!(
                        "plugin `ai-audit` (index {a_idx}) appears before `ai-guardrails` (index {g_idx}) on route `{}`; place `ai-audit` after `ai-guardrails` so audit records capture guardrail verdicts and redacted payloads",
                        route_ir.id
                    ),
                });
            }
            if let (Some(a_idx), Some(u_idx)) = (audit_pos, usage_pos)
                && a_idx < u_idx
            {
                diags.push(VerifyDiagnostic {
                    rule: "ai.audit_order".to_owned(),
                    severity: Severity::Warning,
                    subject: Some(route_ir.id.clone()),
                    message: format!(
                        "plugin `ai-audit` (index {a_idx}) appears before `ai-usage-tracker` (index {u_idx}) on route `{}`; place `ai-audit` after `ai-usage-tracker` so audit records include final token counts",
                        route_ir.id
                    ),
                });
            }
            if let Some(al_idx) = alerts_pos {
                for producer in ["ai-budget", "ai-failover", "ai-guardrails"] {
                    if let Some(p_idx) = route_ir.plugins.iter().position(|p| p.name == producer)
                        && al_idx < p_idx
                    {
                        diags.push(VerifyDiagnostic {
                            rule: "ai.alerts_order".to_owned(),
                            severity: Severity::Warning,
                            subject: Some(route_ir.id.clone()),
                            message: format!(
                                "plugin `ai-alerts` (index {al_idx}) appears before `{producer}` (index {p_idx}) on route `{}`; place `ai-alerts` after `{producer}` so `on_complete` observes all emitted alert events",
                                route_ir.id
                            ),
                        });
                    }
                }
            }
            let _ = adapter_pos;
        }

        // ai.unknown_upstream, ai.unknown_provider & ai.attempts_insufficient
        let adapter_providers: Option<HashSet<&str>> = route_ir
            .plugins
            .iter()
            .find(|p| p.name == "ai-provider-adapter")
            .and_then(|p| p.config.get("providers"))
            .and_then(Value::as_object)
            .map(|map| map.keys().map(String::as_str).collect());

        for att in &route_ir.plugins {
            if att.name != "ai-model-router" {
                continue;
            }
            let auto_max = att
                .config
                .get("auto_max_attempts")
                .and_then(Value::as_bool)
                .unwrap_or(true);

            let chains = extract_ai_target_chains(&att.config);
            for (label, targets) in chains {
                for target in &targets {
                    if !upstream_names.contains(target.upstream.as_str()) {
                        diags.push(VerifyDiagnostic {
                            rule: "ai.unknown_upstream".to_owned(),
                            severity: Severity::Error,
                            subject: Some(route_ir.id.clone()),
                            message: format!(
                                "ai-model-router `{label}` on route `{}` references undeclared upstream `{}`",
                                route_ir.id, target.upstream
                            ),
                        });
                    }
                    if let (Some(known_provs), Some(prov)) = (&adapter_providers, &target.provider)
                        && !known_provs.contains(prov.as_str())
                    {
                        diags.push(VerifyDiagnostic {
                            rule: "ai.unknown_provider".to_owned(),
                            severity: Severity::Error,
                            subject: Some(route_ir.id.clone()),
                            message: format!(
                                "ai-model-router `{label}` on route `{}` references provider `{prov}` not declared in `ai-provider-adapter.providers`",
                                route_ir.id
                            ),
                        });
                    }
                }
                if !auto_max && targets.len() > route_ir.max_attempts {
                    diags.push(VerifyDiagnostic {
                        rule: "ai.attempts_insufficient".to_owned(),
                        severity: Severity::Error,
                        subject: Some(route_ir.id.clone()),
                        message: format!(
                            "ai-model-router `{label}` on route `{}` defines {} fallback targets with auto_max_attempts=false, but route max_attempts={}",
                            route_ir.id,
                            targets.len(),
                            route_ir.max_attempts
                        ),
                    });
                }
            }
        }
    }

    // 3. admin.non_loopback & admin.ui_non_loopback
    if bundle.config.admin.enabled
        && let Ok(addr) = bundle.config.admin.listen.parse::<SocketAddr>()
        && !addr.ip().is_loopback()
    {
        let sev = if effective_policy.require_loopback_admin {
            Severity::Error
        } else {
            Severity::Warning
        };
        diags.push(VerifyDiagnostic {
            rule: "admin.non_loopback".to_owned(),
            severity: sev,
            subject: Some("admin.listen".to_owned()),
            message: format!(
                "admin listener `{}` binds to a non-loopback address; bind to 127.0.0.1 or [::1]",
                bundle.config.admin.listen
            ),
        });
        if bundle.config.admin.ui {
            diags.push(VerifyDiagnostic {
                rule: "admin.ui_non_loopback".to_owned(),
                severity: sev,
                subject: Some("admin.ui".to_owned()),
                message: format!(
                    "admin Inspector UI is enabled on non-loopback listener `{}`; restrict `admin.listen` to 127.0.0.1 or [::1] so live request traces are not publicly exposed",
                    bundle.config.admin.listen
                ),
            });
        }
    }

    // 3b. telemetry.no_trace_plugin
    if bundle.config.telemetry.enabled {
        let has_trace_plugin = bundle.config.plugins.iter().any(|p| p.name == "otel-trace")
            || bundle
                .config
                .routes
                .iter()
                .any(|r| r.plugins.iter().any(|p| p.name == "otel-trace"));
        if !has_trace_plugin {
            diags.push(VerifyDiagnostic {
                rule: "telemetry.no_trace_plugin".to_owned(),
                severity: Severity::Warning,
                subject: Some("telemetry".to_owned()),
                message: "`[telemetry]` is enabled, but no `otel-trace` plugin is attached globally or on any route".to_owned(),
            });
        }
    }

    // 4. Policy rules (policy.require_plugin, policy.assert_hook_mask)
    for rp in &effective_policy.route_policies {
        for compiled in compiled_routes {
            if !glob_match(&rp.match_route, &compiled.id) {
                continue;
            }
            let active_plugins: HashSet<&str> = compiled.plugins.iter().map(|p| p.name()).collect();
            for req_plugin in &rp.require_plugins {
                if !active_plugins.contains(req_plugin.as_str()) {
                    diags.push(VerifyDiagnostic {
                        rule: "policy.require_plugin".to_owned(),
                        severity: Severity::Error,
                        subject: Some(compiled.id.clone()),
                        message: format!(
                            "route `{}` (matched `{}`) is missing required plugin `{req_plugin}`",
                            compiled.id, rp.match_route
                        ),
                    });
                }
            }

            for forbid in &rp.forbid_hooks {
                match parse_hook_flag(forbid) {
                    Some(flag) => {
                        if compiled.hook_mask.contains(flag) {
                            diags.push(VerifyDiagnostic {
                                rule: "policy.assert_hook_mask".to_owned(),
                                severity: Severity::Error,
                                subject: Some(compiled.id.clone()),
                                message: format!(
                                    "route `{}` (matched `{}`) enables forbidden hook `{forbid}` (compiled HookMask: {})",
                                    compiled.id, rp.match_route, compiled.hook_mask
                                ),
                            });
                        }
                    }
                    None => {
                        diags.push(VerifyDiagnostic {
                            rule: "policy.assert_hook_mask".to_owned(),
                            severity: Severity::Error,
                            subject: Some(compiled.id.clone()),
                            message: format!("unknown HookMask flag `{forbid}` in policy"),
                        });
                    }
                }
            }

            for req_hook in &rp.require_hooks {
                match parse_hook_flag(req_hook) {
                    Some(flag) => {
                        if !compiled.hook_mask.contains(flag) {
                            diags.push(VerifyDiagnostic {
                                rule: "policy.assert_hook_mask".to_owned(),
                                severity: Severity::Error,
                                subject: Some(compiled.id.clone()),
                                message: format!(
                                    "route `{}` (matched `{}`) is missing required hook `{req_hook}` (compiled HookMask: {})",
                                    compiled.id, rp.match_route, compiled.hook_mask
                                ),
                            });
                        }
                    }
                    None => {
                        diags.push(VerifyDiagnostic {
                            rule: "policy.assert_hook_mask".to_owned(),
                            severity: Severity::Error,
                            subject: Some(compiled.id.clone()),
                            message: format!("unknown HookMask flag `{req_hook}` in policy"),
                        });
                    }
                }
            }
        }
    }

    VerifyReport::from_diagnostics(diags, strict)
}

/// Returns `true` if every HTTP request matched by `later` is guaranteed to also be matched
/// by `earlier` (i.e., `later` is completely shadowed by `earlier`).
pub fn route_subsumes(earlier: &RouteMatch, later: &RouteMatch) -> bool {
    methods_subsume(&earlier.methods, &later.methods)
        && hosts_subsume(&earlier.hosts, &later.hosts)
        && path_subsumes(&earlier.path, &later.path)
}

fn methods_subsume(earlier: &[http::Method], later: &[http::Method]) -> bool {
    if earlier.is_empty() {
        return true;
    }
    if later.is_empty() {
        return false;
    }
    later.iter().all(|m| earlier.contains(m))
}

fn hosts_subsume(earlier: &[String], later: &[String]) -> bool {
    if earlier.is_empty() {
        return true;
    }
    if later.is_empty() {
        return false;
    }
    later
        .iter()
        .all(|l| earlier.iter().any(|e| host_pattern_subsumes(e, l)))
}

fn host_pattern_subsumes(earlier: &str, later: &str) -> bool {
    let e = earlier.to_ascii_lowercase();
    let l = later.to_ascii_lowercase();
    if e == l {
        return true;
    }
    if let Some(e_suffix) = e.strip_prefix("*.") {
        if let Some(l_suffix) = l.strip_prefix("*.") {
            l_suffix == e_suffix
                || (l_suffix.len() > e_suffix.len()
                    && l_suffix.ends_with(e_suffix)
                    && l_suffix.as_bytes()[l_suffix.len() - e_suffix.len() - 1] == b'.')
        } else {
            host_matches(&e, &l)
        }
    } else {
        false
    }
}

fn path_subsumes(earlier: &PathMatch, later: &PathMatch) -> bool {
    match earlier {
        PathMatch::Any => true,
        PathMatch::Prefix(ep) => {
            if ep == "/" || ep.trim_end_matches('/').is_empty() {
                return true;
            }
            let e_trim = ep.trim_end_matches('/');
            match later {
                PathMatch::Any => false,
                PathMatch::Exact(lp) => earlier.matches(lp),
                PathMatch::Prefix(lp) => {
                    if lp == "/" || lp.trim_end_matches('/').is_empty() {
                        return false;
                    }
                    let l_trim = lp.trim_end_matches('/');
                    l_trim == e_trim
                        || (l_trim.starts_with(e_trim)
                            && l_trim.as_bytes().get(e_trim.len()) == Some(&b'/'))
                }
            }
        }
        PathMatch::Exact(ep) => match later {
            PathMatch::Exact(lp) => ep == lp,
            PathMatch::Any | PathMatch::Prefix(_) => false,
        },
    }
}

struct AiTargetRef {
    upstream: String,
    provider: Option<String>,
}

fn extract_ai_target_chains(cfg: &Value) -> Vec<(String, Vec<AiTargetRef>)> {
    let mut chains = Vec::new();

    if let Some(models) = cfg.get("models").and_then(Value::as_object) {
        let mut keys: Vec<&String> = models.keys().collect();
        keys.sort();
        for model_name in keys {
            let val = &models[model_name];
            let arr_opt = val
                .as_array()
                .or_else(|| val.get("targets").and_then(Value::as_array));
            if let Some(arr) = arr_opt {
                let targets = extract_targets_info(arr);
                chains.push((format!("models.{model_name}"), targets));
            }
        }
    }

    if let Some(rules) = cfg.get("rules").and_then(Value::as_array) {
        for rule in rules {
            let pat = rule.get("pattern").and_then(Value::as_str).unwrap_or("?");
            if let Some(arr) = rule.get("targets").and_then(Value::as_array) {
                let targets = extract_targets_info(arr);
                chains.push((format!("rules[{pat}]"), targets));
            }
        }
    }

    if let Some(defaults) = cfg.get("default_targets").and_then(Value::as_array)
        && !defaults.is_empty()
    {
        let targets = extract_targets_info(defaults);
        chains.push(("default_targets".to_owned(), targets));
    }

    chains
}

fn extract_targets_info(arr: &[Value]) -> Vec<AiTargetRef> {
    arr.iter()
        .filter_map(|t| {
            let upstream = t.get("upstream").and_then(Value::as_str)?.to_owned();
            let provider = t.get("provider").and_then(Value::as_str).map(str::to_owned);
            Some(AiTargetRef { upstream, provider })
        })
        .collect()
}

/// Parses a human-readable HookMask flag name (case-insensitive, e.g., `"REQUEST_BODY_BUFFERED"`).
pub fn parse_hook_flag(name: &str) -> Option<HookMask> {
    match name.trim().to_ascii_lowercase().as_str() {
        "on_request_headers" => Some(HookMask::ON_REQUEST_HEADERS),
        "request_body_buffered" => Some(HookMask::REQUEST_BODY_BUFFERED),
        "request_body_stream" => Some(HookMask::REQUEST_BODY_STREAM),
        "on_route" => Some(HookMask::ON_ROUTE),
        "on_upstream_select" => Some(HookMask::ON_UPSTREAM_SELECT),
        "on_upstream_request" => Some(HookMask::ON_UPSTREAM_REQUEST),
        "on_response_headers" => Some(HookMask::ON_RESPONSE_HEADERS),
        "response_body_stream" => Some(HookMask::RESPONSE_BODY_STREAM),
        "on_complete" => Some(HookMask::ON_COMPLETE),
        _ => None,
    }
}

/// Simple `*` glob matching used for `route_policies.match_route`.
pub fn glob_match(pattern: &str, text: &str) -> bool {
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
    use std::sync::Arc;

    use http::Method;
    use shunt_core::RuntimeRegistry;
    use shunt_plugin_sdk::PluginRegistry;
    use shunt_plugins::{PrometheusMetrics, register_builtin_plugins};

    use super::*;
    use crate::compiler::SnapshotCompiler;
    use crate::provider::{ConfigProvider, InlineConfigProvider};

    fn compile_inline(toml_src: &str) -> CompiledBundle {
        let metrics = Arc::new(PrometheusMetrics::new());
        let mut reg = PluginRegistry::new();
        register_builtin_plugins(&mut reg, metrics);
        let runtime = Arc::new(RuntimeRegistry::new());
        let compiler = SnapshotCompiler::new(Arc::new(reg), runtime);
        let loaded = InlineConfigProvider::from_toml("test.toml", toml_src)
            .load()
            .unwrap();
        compiler.compile(&loaded).unwrap()
    }

    #[test]
    fn detects_shadowed_route_timeout_order_and_non_loopback_admin() {
        let bundle = compile_inline(
            r#"
[server]
listen = "127.0.0.1:0"

[admin]
enabled = true
listen = "0.0.0.0:9090"

[[upstreams]]
name = "be"
endpoints = ["http://127.0.0.1:8081"]
connect_timeout_ms = 5000

[[routes]]
id = "broad"
path_prefix = "/api"
upstream = "be"
response_headers_timeout_ms = 3000

[[routes]]
id = "narrow"
path_exact = "/api/users"
methods = ["GET"]
upstream = "be"
"#,
        );

        let report = verify_bundle(&bundle, None, false);
        assert!(!report.passed);
        assert!(
            report
                .diagnostics
                .iter()
                .any(|d| d.rule == "route.shadowed" && d.subject.as_deref() == Some("narrow"))
        );
        assert!(
            report
                .diagnostics
                .iter()
                .any(|d| d.rule == "route.timeout_order" && d.subject.as_deref() == Some("broad"))
        );
        assert!(
            report
                .diagnostics
                .iter()
                .any(|d| d.rule == "admin.non_loopback")
        );
    }

    #[test]
    fn enforces_route_plugin_and_hook_mask_policies() {
        let bundle = compile_inline(
            r#"
[server]
listen = "127.0.0.1:0"
[admin]
enabled = false

[[upstreams]]
name = "be"
endpoints = ["http://127.0.0.1:8081"]

[[routes]]
id = "public_api"
path_prefix = "/api"
upstream = "be"

[[routes.plugins]]
name = "request-id"
"#,
        );

        let policy = VerifyPolicy {
            route_policies: vec![RoutePolicy {
                match_route: "public_*".to_owned(),
                require_plugins: vec!["request-id".to_owned(), "bearer-auth".to_owned()],
                forbid_hooks: vec!["ON_REQUEST_HEADERS".to_owned()],
                require_hooks: vec![],
            }],
            ..Default::default()
        };

        let report = verify_bundle(&bundle, Some(&policy), false);
        assert!(!report.passed);
        assert!(
            report
                .diagnostics
                .iter()
                .any(|d| d.rule == "policy.require_plugin")
        );
        assert!(
            report
                .diagnostics
                .iter()
                .any(|d| d.rule == "policy.assert_hook_mask")
        );
    }

    #[test]
    fn route_subsumption_edge_cases() {
        let prefix_api = RouteMatch::prefix("/api");
        let prefix_api_v1 = RouteMatch::prefix("/api/v1").with_method(Method::GET);
        let prefix_apiv2 = RouteMatch::prefix("/apiv2");

        assert!(route_subsumes(&prefix_api, &prefix_api_v1));
        assert!(!route_subsumes(&prefix_api, &prefix_apiv2));
        assert!(!route_subsumes(&prefix_api_v1, &prefix_api));

        let wild = RouteMatch::any().with_host("*.example.com");
        let sub_wild = RouteMatch::any().with_host("*.api.example.com");
        let exact = RouteMatch::any().with_host("foo.example.com");
        let bare = RouteMatch::any().with_host("example.com");

        assert!(route_subsumes(&wild, &sub_wild));
        assert!(route_subsumes(&wild, &exact));
        assert!(!route_subsumes(&wild, &bare));
    }

    #[test]
    fn detects_ai_cache_ordering_and_missing_otel_trace_plugin() {
        let bundle = compile_inline(
            r#"
[server]
listen = "127.0.0.1:0"
[admin]
enabled = false

[telemetry]
enabled = true
endpoint = "http://127.0.0.1:4318/v1/traces"

[[upstreams]]
name = "be"
endpoints = ["http://127.0.0.1:8081"]

[[routes]]
id = "api"
path_prefix = "/api"
upstream = "be"
"#,
        );

        let report = verify_bundle(&bundle, None, false);
        assert!(report.passed);
        assert!(
            report
                .diagnostics
                .iter()
                .any(|d| d.rule == "telemetry.no_trace_plugin" && d.severity == Severity::Warning)
        );
    }
}
