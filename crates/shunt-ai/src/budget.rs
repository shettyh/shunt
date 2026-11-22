use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::Duration;

use serde::Deserialize;
use shunt_plugin_sdk::{
    BufferedResponse, BuildContext, Bytes, Clock, DistributedStore, FailurePolicy, Flow,
    HeaderName, HeaderValue, HookMask, HookResult, HttpPlugin, PluginBuildError, PluginConfig,
    PluginFactory, RequestCtx, RequestSummary, ResponseHead, StatusCode,
};
use tracing::{info, warn};

use crate::alerts::{
    AiAlertEvent, AiAlertKind, AiAlertSeverity, ensure_alert_bus, push_alert_event,
    push_alert_event_ref,
};
use crate::pricing::{ModelPricing, PricingCatalog, nano_usd_to_usd, usd_to_nano_usd};
use crate::types::{
    AiEndpointKind, AiKeyPolicy, AiRequestMeta, AiUsage, BudgetWindow, DetectedEndpoint,
    endpoint_error_response,
};
use crate::usage_tracker::AiMetrics;

fn default_true() -> bool {
    true
}

fn default_soft_warning_ratio() -> f64 {
    0.8
}

fn default_reject_status() -> u16 {
    429
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "snake_case")]
enum BudgetScope {
    #[default]
    VirtualKey,
    Team,
    Global,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "snake_case")]
enum BudgetMode {
    /// Reject requests when spend >= hard limit (`429` or `402`).
    #[default]
    Hard,
    /// Never reject; emit `x-shunt-budget-warning` header and log warnings.
    Soft,
}

#[derive(Debug, Clone, Deserialize)]
struct TeamBudgetConfig {
    limit_usd: f64,
    #[serde(default)]
    soft_limit_usd: Option<f64>,
    #[serde(default)]
    window: Option<BudgetWindow>,
}

#[derive(Debug, Deserialize)]
#[serde(default)]
struct AiBudgetConfig {
    /// Primary spend tracking scope (`"virtual_key"` default, `"team"`, or `"global"`).
    scope: BudgetScope,
    /// Default hard budget limit in USD per window (overridden by `AiKeyPolicy::budget_usd`).
    default_limit_usd: Option<f64>,
    /// Default soft warning threshold as a fraction of hard limit in `(0.0, 1.0]` (default: `0.8`).
    #[serde(default = "default_soft_warning_ratio")]
    soft_warning_ratio: f64,
    /// Default budget accumulation window (default: `"daily"`).
    window: BudgetWindow,
    /// Enforcement mode (`"hard"` default or `"soft"`).
    mode: BudgetMode,
    /// HTTP status returned on hard budget rejection (`429` default or `402`).
    #[serde(default = "default_reject_status")]
    reject_status: u16,
    /// Include bundled frontier/open model pricing table (default: true).
    #[serde(default = "default_true")]
    use_builtin_pricing: bool,
    /// User-supplied exact or wildcard model pricing overrides (USD per 1M tokens).
    #[serde(default)]
    pricing: HashMap<String, ModelPricing>,
    /// Optional fallback pricing when a model is not found in `pricing` or built-ins.
    #[serde(default)]
    default_pricing: Option<ModelPricing>,
    /// Optional per-team aggregate budgets enforced in addition to per-key budgets.
    #[serde(default)]
    team_budgets: HashMap<String, TeamBudgetConfig>,
    /// Use the gateway's configured distributed store (e.g., Redis/Valkey) when available (default: true).
    #[serde(default = "default_true")]
    distributed: bool,
}

impl Default for AiBudgetConfig {
    fn default() -> Self {
        Self {
            scope: BudgetScope::VirtualKey,
            default_limit_usd: None,
            soft_warning_ratio: default_soft_warning_ratio(),
            window: BudgetWindow::Daily,
            mode: BudgetMode::Hard,
            reject_status: default_reject_status(),
            use_builtin_pricing: true,
            pricing: HashMap::new(),
            default_pricing: None,
            team_budgets: HashMap::new(),
            distributed: true,
        }
    }
}

#[derive(Debug, Clone)]
struct BudgetTarget {
    label: String,
    local_key: String,
    dist_key: String,
    window: Duration,
    window_id: u64,
    hard_limit_nano: u64,
    soft_limit_nano: u64,
}

/// Per-request budget inspection result attached to `RequestCtx::extensions`.
#[derive(Debug, Clone)]
pub struct AiBudgetState {
    targets: Vec<BudgetTarget>,
    primary_limit_nano: Option<u64>,
    primary_spent_nano: u64,
    warning_reason: Option<&'static str>,
}

#[derive(Debug, Clone, Copy)]
struct LedgerEntry {
    window_id: u64,
    spent_nano_usd: u64,
}

/// Persistent in-memory spend ledger stored in `StateStore` across hot reloads.
#[derive(Debug, Default)]
pub struct SpendLedgerTable {
    entries: RwLock<HashMap<String, LedgerEntry>>,
}

impl SpendLedgerTable {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn current_spend(&self, key: &str, window_id: u64) -> u64 {
        self.entries
            .read()
            .expect("SpendLedgerTable poisoned")
            .get(key)
            .filter(|e| e.window_id == window_id)
            .map(|e| e.spent_nano_usd)
            .unwrap_or(0)
    }

    pub fn add_spend(&self, key: &str, window_id: u64, delta_nano: u64) -> u64 {
        let mut guard = self.entries.write().expect("SpendLedgerTable poisoned");
        let entry = guard.entry(key.to_owned()).or_insert(LedgerEntry {
            window_id,
            spent_nano_usd: 0,
        });
        if entry.window_id != window_id {
            entry.window_id = window_id;
            entry.spent_nano_usd = 0;
        }
        entry.spent_nano_usd = entry.spent_nano_usd.saturating_add(delta_nano);
        entry.spent_nano_usd
    }
}

#[derive(Debug, Clone)]
struct CompiledTeamBudget {
    hard_limit_nano: u64,
    soft_limit_nano: u64,
    window: BudgetWindow,
}

/// Factory for the `ai-budget` plugin.
pub struct AiBudgetFactory {
    metrics: Arc<AiMetrics>,
}

impl AiBudgetFactory {
    pub fn new(metrics: Arc<AiMetrics>) -> Self {
        Self { metrics }
    }
}

impl PluginFactory for AiBudgetFactory {
    fn name(&self) -> &str {
        "ai-budget"
    }

    fn build(
        &self,
        config: &PluginConfig,
        ctx: &BuildContext,
    ) -> Result<Arc<dyn HttpPlugin>, PluginBuildError> {
        let cfg: AiBudgetConfig = config.deserialize(self.name())?;

        if let Some(lim) = cfg.default_limit_usd
            && (!lim.is_finite() || lim < 0.0)
        {
            return Err(PluginBuildError::BuildFailed {
                plugin: self.name().to_owned(),
                message: "`default_limit_usd` must be a non-negative finite number".to_owned(),
            });
        }
        if !cfg.soft_warning_ratio.is_finite()
            || cfg.soft_warning_ratio <= 0.0
            || cfg.soft_warning_ratio > 1.0
        {
            return Err(PluginBuildError::BuildFailed {
                plugin: self.name().to_owned(),
                message: "`soft_warning_ratio` must be in (0.0, 1.0]".to_owned(),
            });
        }
        let reject_status = match cfg.reject_status {
            402 => StatusCode::PAYMENT_REQUIRED,
            429 => StatusCode::TOO_MANY_REQUESTS,
            other => {
                return Err(PluginBuildError::BuildFailed {
                    plugin: self.name().to_owned(),
                    message: format!("`reject_status` must be 429 or 402, got {other}"),
                });
            }
        };

        let catalog =
            PricingCatalog::new(cfg.pricing, cfg.use_builtin_pricing, cfg.default_pricing)
                .map_err(|msg| PluginBuildError::BuildFailed {
                    plugin: self.name().to_owned(),
                    message: msg,
                })?;

        let mut team_budgets = HashMap::with_capacity(cfg.team_budgets.len());
        for (team, tb) in cfg.team_budgets {
            if !tb.limit_usd.is_finite() || tb.limit_usd < 0.0 {
                return Err(PluginBuildError::BuildFailed {
                    plugin: self.name().to_owned(),
                    message: format!("team_budgets.{team}.limit_usd must be non-negative finite"),
                });
            }
            let hard_limit_nano = usd_to_nano_usd(tb.limit_usd);
            let soft_limit_nano = match tb.soft_limit_usd {
                Some(s) if s.is_finite() && s >= 0.0 => usd_to_nano_usd(s).min(hard_limit_nano),
                Some(_) => {
                    return Err(PluginBuildError::BuildFailed {
                        plugin: self.name().to_owned(),
                        message: format!(
                            "team_budgets.{team}.soft_limit_usd must be non-negative finite"
                        ),
                    });
                }
                None => usd_to_nano_usd(tb.limit_usd * cfg.soft_warning_ratio),
            };
            team_budgets.insert(
                team,
                CompiledTeamBudget {
                    hard_limit_nano,
                    soft_limit_nano,
                    window: tb.window.unwrap_or(cfg.window),
                },
            );
        }

        let ledger = ctx
            .state_handle()
            .get_or_init("ai_budget_ledger", SpendLedgerTable::new);
        let distributed = if cfg.distributed {
            ctx.distributed_store()
        } else {
            None
        };

        Ok(Arc::new(AiBudgetPlugin {
            scope_id: ctx.scope_id().to_owned(),
            scope: cfg.scope,
            default_limit_usd: cfg.default_limit_usd,
            soft_warning_ratio: cfg.soft_warning_ratio,
            default_window: cfg.window,
            mode: cfg.mode,
            reject_status,
            catalog,
            team_budgets,
            clock: ctx.clock(),
            ledger,
            distributed,
            metrics: Arc::clone(&self.metrics),
        }))
    }
}

/// Cost attribution & spend budget enforcement plugin (`ai-budget`).
///
/// Tracks exact integer nano-USD spend per virtual key / team / global window, emits
/// `shunt_ai_cost_usd_total` Prometheus metrics, adds `x-shunt-budget-*` headers, and
/// enforces soft warnings or hard `429`/`402` rejections locally or across Redis replicas.
pub struct AiBudgetPlugin {
    scope_id: String,
    scope: BudgetScope,
    default_limit_usd: Option<f64>,
    soft_warning_ratio: f64,
    default_window: BudgetWindow,
    mode: BudgetMode,
    reject_status: StatusCode,
    catalog: PricingCatalog,
    team_budgets: HashMap<String, CompiledTeamBudget>,
    clock: Arc<dyn Clock>,
    ledger: Arc<SpendLedgerTable>,
    distributed: Option<Arc<dyn DistributedStore>>,
    metrics: Arc<AiMetrics>,
}

impl AiBudgetPlugin {
    fn resolve_targets(&self, ctx: &RequestCtx) -> Vec<BudgetTarget> {
        let now_ms = self.clock.now_ms();
        let policy = ctx.get_ext::<AiKeyPolicy>();
        let mut targets = Vec::with_capacity(2);

        // 1. Primary budget target (key, team, or global)
        let primary_limit_usd = policy.and_then(|p| p.budget_usd).or(self.default_limit_usd);
        let primary_window = policy
            .and_then(|p| p.budget_window)
            .unwrap_or(self.default_window);

        if let Some(limit_usd) = primary_limit_usd {
            let hard_limit_nano = usd_to_nano_usd(limit_usd);
            let soft_limit_nano = policy
                .and_then(|p| p.budget_soft_limit_usd)
                .map(|s| usd_to_nano_usd(s).min(hard_limit_nano))
                .unwrap_or_else(|| usd_to_nano_usd(limit_usd * self.soft_warning_ratio));

            let subject = match self.scope {
                BudgetScope::VirtualKey => policy
                    .map(|p| format!("key:{}", p.key_id))
                    .unwrap_or_else(|| format!("ip:{}", ctx.client_addr.ip())),
                BudgetScope::Team => policy
                    .and_then(|p| p.team.as_deref().map(|t| format!("team:{t}")))
                    .or_else(|| policy.map(|p| format!("key:{}", p.key_id)))
                    .unwrap_or_else(|| "global".to_owned()),
                BudgetScope::Global => "global".to_owned(),
            };
            let dur = primary_window.as_duration();
            let win_ms = dur.as_millis().max(1) as u64;
            let window_id = now_ms / win_ms;
            let local_key = format!("primary:{subject}");
            let dist_key = format!(
                "ai_budget:{}:{subject}:{}",
                self.scope_id,
                primary_window.label()
            );
            targets.push(BudgetTarget {
                label: subject,
                local_key,
                dist_key,
                window: dur,
                window_id,
                hard_limit_nano,
                soft_limit_nano,
            });
        }

        // 2. Additional per-team aggregate budget (if configured and not already identical)
        if let Some(team) = policy.and_then(|p| p.team.as_deref())
            && let Some(tb) = self.team_budgets.get(team)
        {
            let subject = format!("team:{team}");
            let already_present = targets.iter().any(|t| t.label == subject);
            if !already_present {
                let dur = tb.window.as_duration();
                let win_ms = dur.as_millis().max(1) as u64;
                let window_id = now_ms / win_ms;
                targets.push(BudgetTarget {
                    label: subject.clone(),
                    local_key: format!("team_agg:{team}"),
                    dist_key: format!(
                        "ai_budget:{}:team_agg:{team}:{}",
                        self.scope_id,
                        tb.window.label()
                    ),
                    window: dur,
                    window_id,
                    hard_limit_nano: tb.hard_limit_nano,
                    soft_limit_nano: tb.soft_limit_nano,
                });
            }
        }

        targets
    }

    #[allow(clippy::result_large_err)]
    fn evaluate_spends(
        &self,
        endpoint: AiEndpointKind,
        targets: Vec<BudgetTarget>,
        spends: &[u64],
        key_id: Option<&str>,
        team: Option<&str>,
    ) -> Result<(AiBudgetState, Vec<AiAlertEvent>), (BufferedResponse, Vec<AiAlertEvent>)> {
        let mut warning_reason: Option<&'static str> = None;
        let mut alerts = Vec::new();

        for (target, &spent) in targets.iter().zip(spends.iter()) {
            if spent >= target.hard_limit_nano {
                let limit_usd = nano_usd_to_usd(target.hard_limit_nano);
                let spent_usd = nano_usd_to_usd(spent);
                match self.mode {
                    BudgetMode::Hard => {
                        alerts.push(AiAlertEvent {
                            kind: AiAlertKind::BudgetHardExceeded,
                            severity: AiAlertSeverity::Critical,
                            dedup_key: format!("hard::{}::{}", target.label, target.window_id),
                            title: format!("AI spend budget exceeded for {}", target.label),
                            message: format!(
                                "Hard spend budget exceeded for `{}` (${spent_usd:.6} / ${limit_usd:.6} USD)",
                                target.label
                            ),
                            subject: Some(target.label.clone()),
                            provider: None,
                            model: None,
                            key_id: key_id.map(str::to_owned),
                            team: team.map(str::to_owned),
                            details: serde_json::json!({
                                "spent_usd": spent_usd,
                                "limit_usd": limit_usd,
                                "mode": "hard",
                            }),
                        });
                        let mut resp = endpoint_error_response(
                            endpoint,
                            self.reject_status,
                            "budget_exceeded",
                            Some("budget_exceeded"),
                            &format!(
                                "Spend budget exceeded for `{}` (${spent_usd:.6} / ${limit_usd:.6} USD)",
                                target.label
                            ),
                        );
                        attach_budget_headers(
                            &mut resp.headers,
                            target.hard_limit_nano,
                            spent,
                            Some("hard_limit_exceeded"),
                        );
                        return Err((resp, alerts));
                    }
                    BudgetMode::Soft => {
                        warn!(
                            plugin = "ai-budget",
                            subject = %target.label,
                            spent_usd,
                            limit_usd,
                            "budget hard limit exceeded in soft mode"
                        );
                        alerts.push(AiAlertEvent {
                            kind: AiAlertKind::BudgetHardExceeded,
                            severity: AiAlertSeverity::Warning,
                            dedup_key: format!("hard_soft::{}::{}", target.label, target.window_id),
                            title: format!("AI spend budget exceeded (soft mode) for {}", target.label),
                            message: format!(
                                "Spend budget exceeded in soft mode for `{}` (${spent_usd:.6} / ${limit_usd:.6} USD)",
                                target.label
                            ),
                            subject: Some(target.label.clone()),
                            provider: None,
                            model: None,
                            key_id: key_id.map(str::to_owned),
                            team: team.map(str::to_owned),
                            details: serde_json::json!({
                                "spent_usd": spent_usd,
                                "limit_usd": limit_usd,
                                "mode": "soft",
                            }),
                        });
                        warning_reason = Some("hard_limit_exceeded_soft_mode");
                    }
                }
            } else if spent >= target.soft_limit_nano {
                let soft_usd = nano_usd_to_usd(target.soft_limit_nano);
                let limit_usd = nano_usd_to_usd(target.hard_limit_nano);
                let spent_usd = nano_usd_to_usd(spent);
                warn!(
                    plugin = "ai-budget",
                    subject = %target.label,
                    spent_usd,
                    soft_limit_usd = soft_usd,
                    limit_usd,
                    "budget soft warning threshold reached"
                );
                alerts.push(AiAlertEvent {
                    kind: AiAlertKind::BudgetSoftWarning,
                    severity: AiAlertSeverity::Warning,
                    dedup_key: format!("soft::{}::{}", target.label, target.window_id),
                    title: format!("AI spend budget soft limit reached for {}", target.label),
                    message: format!(
                        "Spend soft warning threshold reached for `{}` (${spent_usd:.6} / ${limit_usd:.6} USD, soft limit ${soft_usd:.6})",
                        target.label
                    ),
                    subject: Some(target.label.clone()),
                    provider: None,
                    model: None,
                    key_id: key_id.map(str::to_owned),
                    team: team.map(str::to_owned),
                    details: serde_json::json!({
                        "spent_usd": spent_usd,
                        "soft_limit_usd": soft_usd,
                        "limit_usd": limit_usd,
                    }),
                });
                if warning_reason.is_none() {
                    warning_reason = Some("soft_limit_reached");
                }
            }
        }

        let primary_limit_nano = targets.first().map(|t| t.hard_limit_nano);
        let primary_spent_nano = spends.first().copied().unwrap_or(0);
        Ok((
            AiBudgetState {
                targets,
                primary_limit_nano,
                primary_spent_nano,
                warning_reason,
            },
            alerts,
        ))
    }
}

fn attach_budget_headers(
    headers: &mut shunt_plugin_sdk::HeaderMap,
    limit_nano: u64,
    spent_nano: u64,
    warning: Option<&'static str>,
) {
    let rem_nano = limit_nano.saturating_sub(spent_nano);
    if let Ok(v) = HeaderValue::from_str(&format!("{:.6}", nano_usd_to_usd(limit_nano))) {
        headers.insert(HeaderName::from_static("x-shunt-budget-limit-usd"), v);
    }
    if let Ok(v) = HeaderValue::from_str(&format!("{:.6}", nano_usd_to_usd(spent_nano))) {
        headers.insert(HeaderName::from_static("x-shunt-budget-spent-usd"), v);
    }
    if let Ok(v) = HeaderValue::from_str(&format!("{:.6}", nano_usd_to_usd(rem_nano))) {
        headers.insert(HeaderName::from_static("x-shunt-budget-remaining-usd"), v);
    }
    if let Some(w) = warning {
        headers.insert(
            HeaderName::from_static("x-shunt-budget-warning"),
            HeaderValue::from_static(w),
        );
    }
}

impl HttpPlugin for AiBudgetPlugin {
    fn name(&self) -> &str {
        "ai-budget"
    }

    fn hook_mask(&self) -> HookMask {
        HookMask::REQUEST_BODY_BUFFERED | HookMask::ON_RESPONSE_HEADERS | HookMask::ON_COMPLETE
    }

    fn on_request_body_buffered<'a>(
        &'a self,
        ctx: &'a mut RequestCtx,
        _body: &'a mut Bytes,
    ) -> HookResult<'a, Flow> {
        let endpoint = ctx
            .get_ext::<DetectedEndpoint>()
            .map(|d| d.0)
            .unwrap_or(AiEndpointKind::ChatCompletions);
        if endpoint.is_models_discovery() {
            return HookResult::Ready(Flow::Continue);
        }

        let targets = self.resolve_targets(ctx);
        if targets.is_empty() {
            return HookResult::Ready(Flow::Continue);
        }

        // Pre-attach the per-request alert bus so post-response `on_complete` charges
        // crossing soft/hard thresholds can also emit alerts without `&mut RequestCtx`.
        let _ = ensure_alert_bus(ctx);
        let (key_id, team) = ctx
            .get_ext::<AiKeyPolicy>()
            .map(|p| (Some(p.key_id.clone()), p.team.clone()))
            .unwrap_or((None, None));

        if let Some(dist) = &self.distributed {
            let dist = Arc::clone(dist);
            return HookResult::pending(async move {
                let mut spends = Vec::with_capacity(targets.len());
                for t in &targets {
                    match dist.get_counter(&t.dist_key).await {
                        Ok(val) => spends.push(val.max(0) as u64),
                        Err(err) => {
                            warn!(
                                plugin = "ai-budget",
                                backend = dist.backend_name(),
                                error = %err,
                                "distributed budget lookup failed"
                            );
                            if dist.failure_policy() == FailurePolicy::FailClosed {
                                return Flow::Respond(endpoint_error_response(
                                    endpoint,
                                    StatusCode::SERVICE_UNAVAILABLE,
                                    "server_error",
                                    Some("budget_store_unavailable"),
                                    "Distributed budget store unavailable",
                                ));
                            }
                            return Flow::Continue;
                        }
                    }
                }
                match self.evaluate_spends(
                    endpoint,
                    targets,
                    &spends,
                    key_id.as_deref(),
                    team.as_deref(),
                ) {
                    Ok((state, alerts)) => {
                        for ev in alerts {
                            push_alert_event(ctx, ev);
                        }
                        ctx.insert_ext(state);
                        Flow::Continue
                    }
                    Err((resp, alerts)) => {
                        for ev in alerts {
                            push_alert_event(ctx, ev);
                        }
                        Flow::Respond(resp)
                    }
                }
            });
        }

        // Zero-allocation synchronous local fast path.
        let spends: Vec<u64> = targets
            .iter()
            .map(|t| self.ledger.current_spend(&t.local_key, t.window_id))
            .collect();
        match self.evaluate_spends(
            endpoint,
            targets,
            &spends,
            key_id.as_deref(),
            team.as_deref(),
        ) {
            Ok((state, alerts)) => {
                for ev in alerts {
                    push_alert_event(ctx, ev);
                }
                ctx.insert_ext(state);
                HookResult::Ready(Flow::Continue)
            }
            Err((resp, alerts)) => {
                for ev in alerts {
                    push_alert_event(ctx, ev);
                }
                HookResult::Ready(Flow::Respond(resp))
            }
        }
    }

    fn on_response_headers<'a>(
        &'a self,
        ctx: &'a mut RequestCtx,
        res: &'a mut ResponseHead,
    ) -> HookResult<'a, Flow> {
        if let Some(state) = ctx.get_ext::<AiBudgetState>()
            && let Some(lim) = state.primary_limit_nano
        {
            attach_budget_headers(
                &mut res.headers,
                lim,
                state.primary_spent_nano,
                state.warning_reason,
            );
        }
        HookResult::Ready(Flow::Continue)
    }

    fn on_complete<'a>(
        &'a self,
        ctx: &'a RequestCtx,
        summary: &'a RequestSummary,
    ) -> HookResult<'a, ()> {
        if ctx
            .get_ext::<DetectedEndpoint>()
            .map(|d| d.0.is_models_discovery())
            .unwrap_or(false)
        {
            return HookResult::Ready(());
        }
        if summary.attempts == 0 {
            return HookResult::Ready(());
        }

        let Some(usage) = ctx.get_ext::<AiUsage>() else {
            return HookResult::Ready(());
        };
        let prompt = usage.prompt_tokens.unwrap_or(0);
        let cached = usage.cached_prompt_tokens.unwrap_or(0);
        let cache_write = usage.cache_creation_prompt_tokens.unwrap_or(0);
        let completion = usage.completion_tokens.unwrap_or(0);
        if prompt == 0 && completion == 0 {
            return HookResult::Ready(());
        }

        let meta = ctx.get_ext::<AiRequestMeta>();
        let active_target = meta.and_then(AiRequestMeta::active_target);
        let provider = usage
            .provider
            .clone()
            .or_else(|| active_target.map(|t| t.provider.clone()))
            .unwrap_or_else(|| "unknown".to_owned());
        let requested_model = meta
            .map(|m| m.requested_model.as_str())
            .unwrap_or("unknown");
        let served_model = usage
            .served_model
            .as_deref()
            .or_else(|| active_target.map(|t| t.model.as_str()))
            .unwrap_or(requested_model);

        let Some(pricing) = self.catalog.lookup(served_model, requested_model) else {
            return HookResult::Ready(());
        };
        let cost_nano = pricing.cost_nano_usd_detailed(prompt, cached, cache_write, completion);
        if cost_nano == 0 {
            return HookResult::Ready(());
        }

        let policy = ctx.get_ext::<AiKeyPolicy>();
        let key_label = policy.map(|p| p.key_id.as_str()).unwrap_or("anonymous");
        let team_label = policy.and_then(|p| p.team.as_deref()).unwrap_or("default");

        self.metrics
            .record_cost(&provider, served_model, key_label, team_label, cost_nano);

        ctx.annotate_float("shunt.ai.cost_usd", nano_usd_to_usd(cost_nano));

        info!(
            request_id = summary.request_id,
            provider = %provider,
            model = %served_model,
            key_id = %key_label,
            team = %team_label,
            prompt_tokens = prompt,
            cached_prompt_tokens = cached,
            cache_creation_prompt_tokens = cache_write,
            completion_tokens = completion,
            cost_usd = nano_usd_to_usd(cost_nano),
            "ai_cost"
        );

        let targets = ctx
            .get_ext::<AiBudgetState>()
            .map(|s| s.targets.clone())
            .unwrap_or_default();
        if targets.is_empty() {
            return HookResult::Ready(());
        }

        if let Some(dist) = &self.distributed {
            let dist = Arc::clone(dist);
            let delta = cost_nano.min(i64::MAX as u64) as i64;
            return HookResult::pending(async move {
                for t in targets {
                    if let Err(err) = dist.adjust_counter(&t.dist_key, delta, t.window).await {
                        warn!(
                            plugin = "ai-budget",
                            subject = %t.label,
                            error = %err,
                            "distributed budget charge failed"
                        );
                    }
                }
            });
        }

        for t in &targets {
            let prev = self.ledger.current_spend(&t.local_key, t.window_id);
            let after = self.ledger.add_spend(&t.local_key, t.window_id, cost_nano);
            if prev < t.hard_limit_nano && after >= t.hard_limit_nano {
                let limit_usd = nano_usd_to_usd(t.hard_limit_nano);
                let spent_usd = nano_usd_to_usd(after);
                push_alert_event_ref(
                    ctx,
                    AiAlertEvent {
                        kind: AiAlertKind::BudgetHardExceeded,
                        severity: AiAlertSeverity::Critical,
                        dedup_key: format!("hard::{}::{}", t.label, t.window_id),
                        title: format!("AI spend budget reached hard limit for {}", t.label),
                        message: format!(
                            "Spend for `{}` reached hard budget limit (${spent_usd:.6} / ${limit_usd:.6} USD)",
                            t.label
                        ),
                        subject: Some(t.label.clone()),
                        provider: Some(provider.clone()),
                        model: Some(served_model.to_owned()),
                        key_id: policy.map(|p| p.key_id.clone()),
                        team: policy.and_then(|p| p.team.clone()),
                        details: serde_json::json!({
                            "spent_usd": spent_usd,
                            "limit_usd": limit_usd,
                            "request_cost_usd": nano_usd_to_usd(cost_nano),
                        }),
                    },
                );
            } else if prev < t.soft_limit_nano && after >= t.soft_limit_nano {
                let soft_usd = nano_usd_to_usd(t.soft_limit_nano);
                let limit_usd = nano_usd_to_usd(t.hard_limit_nano);
                let spent_usd = nano_usd_to_usd(after);
                push_alert_event_ref(
                    ctx,
                    AiAlertEvent {
                        kind: AiAlertKind::BudgetSoftWarning,
                        severity: AiAlertSeverity::Warning,
                        dedup_key: format!("soft::{}::{}", t.label, t.window_id),
                        title: format!("AI spend budget soft limit crossed for {}", t.label),
                        message: format!(
                            "Spend for `{}` crossed soft limit (${spent_usd:.6} / ${limit_usd:.6} USD, soft limit ${soft_usd:.6})",
                            t.label
                        ),
                        subject: Some(t.label.clone()),
                        provider: Some(provider.clone()),
                        model: Some(served_model.to_owned()),
                        key_id: policy.map(|p| p.key_id.clone()),
                        team: policy.and_then(|p| p.team.clone()),
                        details: serde_json::json!({
                            "spent_usd": spent_usd,
                            "soft_limit_usd": soft_usd,
                            "limit_usd": limit_usd,
                            "request_cost_usd": nano_usd_to_usd(cost_nano),
                        }),
                    },
                );
            }
        }
        HookResult::Ready(())
    }
}
