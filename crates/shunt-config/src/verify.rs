use std::collections::{HashMap, HashSet};
use std::fmt;
use std::net::SocketAddr;
use std::path::Path;

use serde::{Deserialize, Serialize};
use serde_json::Value;
use shunt_engine::{CompiledPathTemplate, PathMatch, RouteMatch, TemplateSegment};
use shunt_plugin_sdk::HookMask;

use crate::compiler::CompiledBundle;
use crate::error::ConfigError;
use crate::ir::host_pattern_subsumes;

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
    /// May be omitted when `match_group` is set.
    pub match_route: String,
    /// Optional glob pattern matching route group IDs (supports `*`, e.g., `"api_*"`).
    pub match_group: Option<String>,
    /// Plugin names required on every matching route (global, group, or route-scoped).
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

    // 1c. Unused route groups
    let used_groups: HashSet<&str> = route_irs
        .iter()
        .filter_map(|r| r.group.as_deref())
        .collect();
    for group in &bundle.config.route_groups {
        if !used_groups.contains(group.id.as_str()) {
            diags.push(VerifyDiagnostic {
                rule: "route_group.unused".to_owned(),
                severity: Severity::Warning,
                subject: Some(group.id.clone()),
                message: format!(
                    "route group `{}` is declared but not referenced by any route",
                    group.id
                ),
            });
        }
    }

    // 2. Per-route static checks (timeouts, body cap, AI/MCP plugin ordering & targets)
    // Evaluated against the effective lowered route (group + route defaults and merged plugins).
    for (route_ir, compiled) in route_irs.iter().zip(compiled_routes.iter()) {
        let Some(resolved) = bundle.config.resolve_route(route_ir) else {
            continue;
        };
        let effective_plugins = &resolved.effective_plugins;

        // route.timeout_order
        if let Some(resp_timeout) = resolved.response_headers_timeout_ms
            && let Some(up_ir) = upstreams_by_name.get(resolved.upstream.as_str())
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
            && resolved.max_body_bytes.is_none()
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
        let router_pos = effective_plugins
            .iter()
            .position(|p| p.name == "ai-model-router");
        if let Some(r_idx) = router_pos {
            let cache_pos = effective_plugins.iter().position(|p| p.name == "ai-cache");
            for (idx, att) in effective_plugins.iter().enumerate() {
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

            let guardrails_pos = effective_plugins
                .iter()
                .position(|p| p.name == "ai-guardrails");
            let adapter_pos = effective_plugins
                .iter()
                .position(|p| p.name == "ai-provider-adapter");
            let audit_pos = effective_plugins.iter().position(|p| p.name == "ai-audit");
            let usage_pos = effective_plugins
                .iter()
                .position(|p| p.name == "ai-usage-tracker");
            let alerts_pos = effective_plugins.iter().position(|p| p.name == "ai-alerts");

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
                    if let Some(p_idx) = effective_plugins.iter().position(|p| p.name == producer)
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
        let adapter_providers: Option<HashSet<&str>> = effective_plugins
            .iter()
            .find(|p| p.name == "ai-provider-adapter")
            .and_then(|p| p.config.get("providers"))
            .and_then(Value::as_object)
            .map(|map| map.keys().map(String::as_str).collect());

        for att in effective_plugins {
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
                    if target.has_realtime_cap && !resolved.allow_websockets {
                        diags.push(VerifyDiagnostic {
                            rule: "ai.realtime_websockets".to_owned(),
                            severity: Severity::Warning,
                            subject: Some(route_ir.id.clone()),
                            message: format!(
                                "ai-model-router `{label}` on route `{}` declares `realtime` capability, but `allow_websockets = false`; enable `allow_websockets = true` on the route to proxy WebSocket `/v1/realtime`",
                                route_ir.id
                            ),
                        });
                    }
                }
                if !auto_max && targets.len() > resolved.max_attempts {
                    diags.push(VerifyDiagnostic {
                        rule: "ai.attempts_insufficient".to_owned(),
                        severity: Severity::Error,
                        subject: Some(route_ir.id.clone()),
                        message: format!(
                            "ai-model-router `{label}` on route `{}` defines {} fallback targets with auto_max_attempts=false, but route max_attempts={}",
                            route_ir.id,
                            targets.len(),
                            resolved.max_attempts
                        ),
                    });
                }
            }
        }

        // mcp.plugin_order, mcp.unknown_upstream & mcp.auth_recommended
        let mcp_router_pos = effective_plugins
            .iter()
            .position(|p| p.name == "mcp-router");
        if let Some(mr_idx) = mcp_router_pos {
            for (idx, att) in effective_plugins.iter().enumerate() {
                if idx < mr_idx && matches!(att.name.as_str(), "mcp-guardrails" | "mcp-rate-limit")
                {
                    diags.push(VerifyDiagnostic {
                        rule: "mcp.plugin_order".to_owned(),
                        severity: Severity::Error,
                        subject: Some(route_ir.id.clone()),
                        message: format!(
                            "plugin `{}` (index {idx}) appears before `mcp-router` (index {mr_idx}) on route `{}`; place `mcp-router` before guardrails and rate limits so parsed MCP metadata is available",
                            att.name, route_ir.id
                        ),
                    });
                }
                if idx > mr_idx && att.name == "mcp-auth" {
                    diags.push(VerifyDiagnostic {
                        rule: "mcp.plugin_order".to_owned(),
                        severity: Severity::Error,
                        subject: Some(route_ir.id.clone()),
                        message: format!(
                            "plugin `mcp-auth` (index {idx}) appears after `mcp-router` (index {mr_idx}) on route `{}`; place `mcp-auth` first so authentication, session binding, and tool ACLs run before routing",
                            route_ir.id
                        ),
                    });
                }
            }

            if let Some(router_att) = effective_plugins.get(mr_idx)
                && let Some(servers) = router_att.config.get("servers").and_then(Value::as_object)
            {
                for (srv_name, srv_cfg) in servers {
                    if let Some(up) = srv_cfg.get("upstream").and_then(Value::as_str)
                        && !upstream_names.contains(up)
                    {
                        diags.push(VerifyDiagnostic {
                            rule: "mcp.unknown_upstream".to_owned(),
                            severity: Severity::Error,
                            subject: Some(route_ir.id.clone()),
                            message: format!(
                                "mcp-router server `{srv_name}` on route `{}` references undeclared upstream `{up}`",
                                route_ir.id
                            ),
                        });
                    }
                }
            }

            let has_auth = effective_plugins.iter().any(|p| {
                matches!(
                    p.name.as_str(),
                    "mcp-auth" | "jwt-auth" | "mtls-auth" | "bearer-auth"
                )
            }) || bundle.config.plugins.iter().any(|p| {
                matches!(
                    p.name.as_str(),
                    "mcp-auth" | "jwt-auth" | "mtls-auth" | "bearer-auth"
                )
            });
            if !has_auth {
                diags.push(VerifyDiagnostic {
                    rule: "mcp.auth_recommended".to_owned(),
                    severity: Severity::Info,
                    subject: Some(route_ir.id.clone()),
                    message: format!(
                        "MCP route `{}` has `mcp-router` without an authentication plugin (`mcp-auth`, `jwt-auth`, `mtls-auth`, or `bearer-auth`)",
                        route_ir.id
                    ),
                });
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
                .route_groups
                .iter()
                .any(|g| g.plugins.iter().any(|p| p.name == "otel-trace"))
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
                message: "`[telemetry]` is enabled, but no `otel-trace` plugin is attached globally, on a route group, or on any route".to_owned(),
            });
        }
    }

    // 4. Policy rules (policy.require_plugin, policy.assert_hook_mask)
    for rp in &effective_policy.route_policies {
        for (route_ir, compiled) in route_irs.iter().zip(compiled_routes.iter()) {
            let route_matches = if rp.match_route.is_empty() {
                rp.match_group.is_some()
            } else {
                glob_match(&rp.match_route, &compiled.id)
            };
            let group_matches = match &rp.match_group {
                Some(gpat) => route_ir
                    .group
                    .as_deref()
                    .is_some_and(|gid| glob_match(gpat, gid)),
                None => true,
            };
            if !route_matches || !group_matches {
                continue;
            }
            let selector_label = match (rp.match_route.is_empty(), &rp.match_group) {
                (false, Some(g)) => format!("route={}, group={g}", rp.match_route),
                (false, None) => rp.match_route.clone(),
                (true, Some(g)) => format!("group={g}"),
                (true, None) => "*".to_owned(),
            };
            let active_plugins: HashSet<&str> = compiled.plugins.iter().map(|p| p.name()).collect();
            for req_plugin in &rp.require_plugins {
                if !active_plugins.contains(req_plugin.as_str()) {
                    diags.push(VerifyDiagnostic {
                        rule: "policy.require_plugin".to_owned(),
                        severity: Severity::Error,
                        subject: Some(compiled.id.clone()),
                        message: format!(
                            "route `{}` (matched `{selector_label}`) is missing required plugin `{req_plugin}`",
                            compiled.id
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
                                    "route `{}` (matched `{selector_label}`) enables forbidden hook `{forbid}` (compiled HookMask: {})",
                                    compiled.id, compiled.hook_mask
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
                                    "route `{}` (matched `{selector_label}`) is missing required hook `{req_hook}` (compiled HookMask: {})",
                                    compiled.id, compiled.hook_mask
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
        && headers_subsume(&earlier.headers, &later.headers)
}

fn headers_subsume(
    earlier: &[(http::header::HeaderName, String)],
    later: &[(http::header::HeaderName, String)],
) -> bool {
    earlier
        .iter()
        .all(|(ek, ev)| later.iter().any(|(lk, lv)| lk == ek && lv == ev))
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

fn path_subsumes(earlier: &PathMatch, later: &PathMatch) -> bool {
    match earlier {
        PathMatch::Any => true,
        PathMatch::Prefix(ep) => {
            if ep == "/" || ep.trim_end_matches('/').is_empty() {
                return true;
            }
            let e_trim = ep.trim_end_matches('/');
            match later {
                PathMatch::Any | PathMatch::Regex(_) => false,
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
                PathMatch::Template(lt) => {
                    let e_segs: Vec<&str> = e_trim
                        .trim_start_matches('/')
                        .split('/')
                        .filter(|s| !s.is_empty())
                        .collect();
                    let l_segs = lt.segments();
                    l_segs.len() >= e_segs.len()
                        && e_segs.iter().zip(l_segs.iter()).all(|(es, ls)| {
                            matches!(ls, TemplateSegment::Literal(lit) if lit.as_ref() == *es)
                        })
                }
            }
        }
        PathMatch::Exact(ep) => match later {
            PathMatch::Exact(lp) => ep == lp,
            PathMatch::Template(lt) => !lt.has_params() && ep == lt.raw(),
            PathMatch::Any | PathMatch::Prefix(_) | PathMatch::Regex(_) => false,
        },
        PathMatch::Template(et) => match later {
            PathMatch::Exact(lp) => et.matches(lp),
            PathMatch::Template(lt) => template_subsumes(et, lt),
            PathMatch::Prefix(lp) => template_subsumes_prefix(et, lp),
            PathMatch::Any | PathMatch::Regex(_) => false,
        },
        PathMatch::Regex(er) => match later {
            PathMatch::Exact(lp) => er.matches(lp),
            PathMatch::Regex(lr) => er.raw() == lr.raw(),
            PathMatch::Any | PathMatch::Prefix(_) | PathMatch::Template(_) => false,
        },
    }
}

fn template_subsumes(earlier: &CompiledPathTemplate, later: &CompiledPathTemplate) -> bool {
    let e_segs = earlier.segments();
    let l_segs = later.segments();

    for (i, es) in e_segs.iter().enumerate() {
        match es {
            TemplateSegment::Wildcard(_) => {
                // Wildcard is guaranteed final; `later` guarantees a non-empty remainder iff it
                // has at least one segment starting at `i`.
                return l_segs.len() > i;
            }
            TemplateSegment::Literal(elit) => {
                let Some(ls) = l_segs.get(i) else {
                    return false;
                };
                match ls {
                    TemplateSegment::Literal(llit) if elit == llit => {}
                    _ => return false,
                }
            }
            TemplateSegment::Param(_) => {
                let Some(ls) = l_segs.get(i) else {
                    return false;
                };
                match ls {
                    TemplateSegment::Literal(_) | TemplateSegment::Param(_) => {}
                    TemplateSegment::Wildcard(_) => return false,
                }
            }
        }
    }

    e_segs.len() == l_segs.len()
}

fn template_subsumes_prefix(earlier: &CompiledPathTemplate, later_prefix: &str) -> bool {
    if !earlier.has_wildcard() {
        return false;
    }
    let l_trim = later_prefix.trim_end_matches('/');
    if l_trim.is_empty() {
        // Root prefix `"/"` matches `"/"`, which no `{*wildcard}` template matches.
        return false;
    }
    let l_segs: Vec<&str> = l_trim
        .trim_start_matches('/')
        .split('/')
        .filter(|s| !s.is_empty())
        .collect();
    let e_segs = earlier.segments();
    let wildcard_idx = e_segs.len() - 1;
    // `Prefix(lp)` matches `lp` itself (having `l_segs.len()` segments), so the wildcard must
    // start strictly before `l_segs.len()` to guarantee a non-empty tail on `lp` as well.
    if l_segs.len() <= wildcard_idx {
        return false;
    }
    for (es, ls) in e_segs[..wildcard_idx].iter().zip(l_segs.iter()) {
        match es {
            TemplateSegment::Literal(lit) if lit.as_ref() == *ls => {}
            TemplateSegment::Param(_) => {}
            _ => return false,
        }
    }
    true
}

struct AiTargetRef {
    upstream: String,
    provider: Option<String>,
    has_realtime_cap: bool,
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

    for key in ["default_targets", "files_targets", "batches_targets"] {
        if let Some(arr) = cfg.get(key).and_then(Value::as_array)
            && !arr.is_empty()
        {
            let targets = extract_targets_info(arr);
            chains.push((key.to_owned(), targets));
        }
    }

    chains
}

fn extract_targets_info(arr: &[Value]) -> Vec<AiTargetRef> {
    arr.iter()
        .filter_map(|t| {
            let upstream = t.get("upstream").and_then(Value::as_str)?.to_owned();
            let provider = t.get("provider").and_then(Value::as_str).map(str::to_owned);
            let has_realtime_cap = t
                .get("capabilities")
                .and_then(Value::as_array)
                .is_some_and(|caps| caps.iter().any(|c| c.as_str() == Some("realtime")));
            Some(AiTargetRef {
                upstream,
                provider,
                has_realtime_cap,
            })
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
    use shunt_engine::RuntimeRegistry;
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
                match_group: None,
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

    #[test]
    fn template_and_regex_route_shadowing_and_validation() {
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
id = "orders_any_action"
path_template = "/orders/{order_id}/{action}"
upstream = "be"

[[routes]]
id = "orders_status_shadowed"
path_template = "/orders/{order_id}/status"
upstream = "be"

[[routes]]
id = "invoices_re_1"
path_regex = "/invoices/[0-9]{4}/[0-9]+\\.pdf"
upstream = "be"

[[routes]]
id = "invoices_re_dup"
path_regex = "/invoices/[0-9]{4}/[0-9]+\\.pdf"
upstream = "be"

[[routes]]
id = "invoices_exact_shadowed"
path_exact = "/invoices/2026/42.pdf"
upstream = "be"
"#,
        );

        assert_eq!(
            bundle.inspect.routes[0].path,
            "tpl:/orders/{order_id}/{action}"
        );
        assert_eq!(
            bundle.inspect.routes[2].path,
            r"~/invoices/[0-9]{4}/[0-9]+\.pdf"
        );

        let report = verify_bundle(&bundle, None, false);
        assert!(!report.passed);
        let shadowed: Vec<&str> = report
            .diagnostics
            .iter()
            .filter(|d| d.rule == "route.shadowed")
            .filter_map(|d| d.subject.as_deref())
            .collect();
        assert!(shadowed.contains(&"orders_status_shadowed"));
        assert!(shadowed.contains(&"invoices_re_dup"));
        assert!(shadowed.contains(&"invoices_exact_shadowed"));

        // Non-shadowed ordering: specific template before broader template and wildcard.
        let ok_bundle = compile_inline(
            r#"
[server]
listen = "127.0.0.1:0"
[admin]
enabled = false

[[upstreams]]
name = "be"
endpoints = ["http://127.0.0.1:8081"]

[[route_groups]]
id = "api_v2"
path_prefix = "/v2"
upstream = "be"

[[routes]]
id = "orders_status"
group = "api_v2"
path_template = "/orders/{order_id}/status"

[[routes]]
id = "orders_any"
group = "api_v2"
path_template = "/orders/{order_id}/{action}"

[[routes]]
id = "orders_prefix"
group = "api_v2"
path_prefix = "/orders"
"#,
        );
        assert_eq!(
            ok_bundle.inspect.routes[0].path,
            "tpl:/v2/orders/{order_id}/status"
        );
        let ok_report = verify_bundle(&ok_bundle, None, false);
        assert!(ok_report.passed, "diagnostics: {:?}", ok_report.diagnostics);

        // Combining group.path_prefix with route.path_regex is rejected upfront.
        let bad_loaded = InlineConfigProvider::from_toml(
            "bad-group-regex.toml",
            r#"
[server]
listen = "127.0.0.1:0"
[admin]
enabled = false
[[upstreams]]
name = "be"
endpoints = ["http://127.0.0.1:8081"]
[[route_groups]]
id = "api_v2"
path_prefix = "/v2"
upstream = "be"
[[routes]]
id = "bad_re"
group = "api_v2"
path_regex = "/orders/[0-9]+"
"#,
        )
        .load()
        .unwrap();
        let err = bad_loaded.config.validate().unwrap_err().to_string();
        assert!(err.contains("cannot combine `path_regex` with route group"));
    }
}
