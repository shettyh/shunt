use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
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
use crate::generation::AiRecordedCost;
use crate::pricing::{ModelPricing, PricingCatalog, nano_usd_to_usd, usd_to_nano_usd};
use crate::token_rate_limit::apply_signed_delta;
use crate::tokens::estimate_request_tokens;
use crate::types::{
    AiEndUser, AiEndpointKind, AiKeyPolicy, AiRequestMeta, AiUsage, BudgetWindow, DetectedEndpoint,
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

fn default_reserve_output_tokens_cap() -> u64 {
    1024
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "snake_case")]
enum BudgetScope {
    #[default]
    VirtualKey,
    Team,
    Org,
    EndUser,
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
    /// Primary spend tracking scope (`"virtual_key"` default, `"team"`, `"org"`, `"end_user"`, or `"global"`).
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
    /// Optional path to an external JSON pricing catalog (Shunt or LiteLLM format).
    #[serde(default)]
    pricing_file: Option<PathBuf>,
    /// Optional fallback pricing when a model is not found in `pricing` or built-ins.
    #[serde(default)]
    default_pricing: Option<ModelPricing>,
    /// Optional per-team aggregate budgets enforced in addition to per-key budgets.
    #[serde(default)]
    team_budgets: HashMap<String, TeamBudgetConfig>,
    /// Optional per-organization aggregate budgets enforced in addition to team/key budgets.
    #[serde(default)]
    org_budgets: HashMap<String, TeamBudgetConfig>,
    /// Optional per-end-user rolling spend budget (USD) enforced when `AiEndUser` is present.
    #[serde(default)]
    end_user_budget_usd: Option<f64>,
    /// Optional budget window for `end_user_budget_usd` (defaults to `window`).
    #[serde(default)]
    end_user_budget_window: Option<BudgetWindow>,
    /// Atomically reserve estimated request cost pre-flight and reconcile against actual usage
    /// in `on_complete` (default: false) to prevent concurrent bursts from overshooting hard limits.
    #[serde(default)]
    preflight_reserve: bool,
    /// Cap on estimated output tokens reserved during `preflight_reserve` (default: `1024`).
    #[serde(default = "default_reserve_output_tokens_cap")]
    reserve_output_tokens_cap: u64,
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
            pricing_file: None,
            default_pricing: None,
            team_budgets: HashMap::new(),
            org_budgets: HashMap::new(),
            end_user_budget_usd: None,
            end_user_budget_window: None,
            preflight_reserve: false,
            reserve_output_tokens_cap: default_reserve_output_tokens_cap(),
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

/// Default maximum number of budget keys retained in [`SpendLedgerTable`].
pub const DEFAULT_MAX_LEDGER_ENTRIES: usize = 65_536;

/// Persistent, bounded-cardinality in-memory spend ledger stored in `StateStore` across hot reloads.
#[derive(Debug)]
pub struct SpendLedgerTable {
    entries: RwLock<HashMap<String, LedgerEntry>>,
    max_entries: usize,
}

impl Default for SpendLedgerTable {
    fn default() -> Self {
        Self::new()
    }
}

impl SpendLedgerTable {
    pub fn new() -> Self {
        Self::with_max_entries(DEFAULT_MAX_LEDGER_ENTRIES)
    }

    pub fn with_max_entries(max_entries: usize) -> Self {
        Self {
            entries: RwLock::new(HashMap::new()),
            max_entries: max_entries.max(1),
        }
    }

    pub fn len(&self) -> usize {
        self.entries
            .read()
            .expect("SpendLedgerTable poisoned")
            .len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    fn ensure_capacity(guard: &mut HashMap<String, LedgerEntry>, key: &str, max_entries: usize) {
        if guard.contains_key(key) || guard.len() < max_entries {
            return;
        }
        // First reclaim zero-spend entries (e.g., fully refunded pre-flight holds).
        guard.retain(|_, e| e.spent_nano_usd > 0);
        while guard.len() >= max_entries {
            let Some(evict_key) = guard
                .iter()
                .min_by_key(|(_, e)| (e.window_id, e.spent_nano_usd))
                .map(|(k, _)| k.clone())
            else {
                break;
            };
            guard.remove(&evict_key);
        }
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
        Self::ensure_capacity(&mut guard, key, self.max_entries);
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

    /// Atomically adjusts spend for `key` in `window_id` by a signed nano-USD delta (clamped at 0).
    pub fn adjust_spend(&self, key: &str, window_id: u64, delta_nano: i64) -> u64 {
        let mut guard = self.entries.write().expect("SpendLedgerTable poisoned");
        Self::ensure_capacity(&mut guard, key, self.max_entries);
        let entry = guard.entry(key.to_owned()).or_insert(LedgerEntry {
            window_id,
            spent_nano_usd: 0,
        });
        if entry.window_id != window_id {
            entry.window_id = window_id;
            entry.spent_nano_usd = 0;
        }
        entry.spent_nano_usd = apply_signed_delta(entry.spent_nano_usd, delta_nano);
        entry.spent_nano_usd
    }

    /// Atomically checks and reserves `reserve_nano` for `key` in `window_id`.
    /// When `enforce_hard` is `true`, rejects with `Err(current_spent)` if `current + reserve_nano > hard_limit_nano`
    /// (or if `current >= hard_limit_nano` when `reserve_nano == 0`).
    pub fn try_reserve_spend(
        &self,
        key: &str,
        window_id: u64,
        reserve_nano: u64,
        hard_limit_nano: u64,
        enforce_hard: bool,
    ) -> Result<u64, u64> {
        let mut guard = self.entries.write().expect("SpendLedgerTable poisoned");
        Self::ensure_capacity(&mut guard, key, self.max_entries);
        let entry = guard.entry(key.to_owned()).or_insert(LedgerEntry {
            window_id,
            spent_nano_usd: 0,
        });
        if entry.window_id != window_id {
            entry.window_id = window_id;
            entry.spent_nano_usd = 0;
        }
        let cur = entry.spent_nano_usd;
        if enforce_hard
            && ((reserve_nano == 0 && cur >= hard_limit_nano)
                || (reserve_nano > 0 && cur.saturating_add(reserve_nano) > hard_limit_nano))
        {
            return Err(cur);
        }
        entry.spent_nano_usd = cur.saturating_add(reserve_nano);
        Ok(entry.spent_nano_usd)
    }
}

#[derive(Debug)]
struct BudgetHoldInner {
    ledger: Arc<SpendLedgerTable>,
    distributed: Option<Arc<dyn DistributedStore>>,
    targets: Vec<BudgetTarget>,
    reserved_nano: u64,
    reconciled: AtomicBool,
}

impl Drop for BudgetHoldInner {
    fn drop(&mut self) {
        if self.reserved_nano == 0 || self.reconciled.swap(true, Ordering::AcqRel) {
            return;
        }
        let refund = -(self.reserved_nano.min(i64::MAX as u64) as i64);
        if let Some(dist) = &self.distributed {
            if let Ok(handle) = tokio::runtime::Handle::try_current() {
                let dist = Arc::clone(dist);
                let targets = self.targets.clone();
                handle.spawn(async move {
                    for t in targets {
                        let _ = dist.adjust_counter(&t.dist_key, refund, t.window).await;
                    }
                });
            }
        } else {
            for t in &self.targets {
                self.ledger.adjust_spend(&t.local_key, t.window_id, refund);
            }
        }
    }
}

/// Leak-free RAII pre-flight budget hold stored in `RequestCtx::extensions`.
///
/// Reconciled explicitly in `on_complete` with `(actual_cost - reserved_cost)`; if dropped early
/// (e.g., short-circuit, stream abort, or panic), automatically refunds the reserved amount.
#[derive(Debug, Clone)]
pub struct BudgetHoldGuard(Arc<BudgetHoldInner>);

impl BudgetHoldGuard {
    fn new(
        ledger: Arc<SpendLedgerTable>,
        distributed: Option<Arc<dyn DistributedStore>>,
        targets: Vec<BudgetTarget>,
        reserved_nano: u64,
    ) -> Self {
        Self(Arc::new(BudgetHoldInner {
            ledger,
            distributed,
            targets,
            reserved_nano,
            reconciled: AtomicBool::new(false),
        }))
    }

    fn take_for_reconcile(&self) -> Option<(Vec<BudgetTarget>, u64)> {
        if self.0.reconciled.swap(true, Ordering::AcqRel) {
            return None;
        }
        Some((self.0.targets.clone(), self.0.reserved_nano))
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

        let catalog = PricingCatalog::new_with_file(
            cfg.pricing,
            cfg.use_builtin_pricing,
            cfg.default_pricing,
            cfg.pricing_file.as_deref(),
        )
        .map_err(|msg| PluginBuildError::BuildFailed {
            plugin: self.name().to_owned(),
            message: msg,
        })?;

        let compile_group_budgets = |map: HashMap<String, TeamBudgetConfig>,
                                     prefix: &str|
         -> Result<
            HashMap<String, CompiledTeamBudget>,
            PluginBuildError,
        > {
            let mut out = HashMap::with_capacity(map.len());
            for (name, tb) in map {
                if !tb.limit_usd.is_finite() || tb.limit_usd < 0.0 {
                    return Err(PluginBuildError::BuildFailed {
                        plugin: self.name().to_owned(),
                        message: format!("{prefix}.{name}.limit_usd must be non-negative finite"),
                    });
                }
                let hard_limit_nano = usd_to_nano_usd(tb.limit_usd);
                let soft_limit_nano = match tb.soft_limit_usd {
                    Some(s) if s.is_finite() && s >= 0.0 => usd_to_nano_usd(s).min(hard_limit_nano),
                    Some(_) => {
                        return Err(PluginBuildError::BuildFailed {
                            plugin: self.name().to_owned(),
                            message: format!(
                                "{prefix}.{name}.soft_limit_usd must be non-negative finite"
                            ),
                        });
                    }
                    None => usd_to_nano_usd(tb.limit_usd * cfg.soft_warning_ratio),
                };
                out.insert(
                    name,
                    CompiledTeamBudget {
                        hard_limit_nano,
                        soft_limit_nano,
                        window: tb.window.unwrap_or(cfg.window),
                    },
                );
            }
            Ok(out)
        };

        let team_budgets = compile_group_budgets(cfg.team_budgets, "team_budgets")?;
        let org_budgets = compile_group_budgets(cfg.org_budgets, "org_budgets")?;

        if let Some(eu) = cfg.end_user_budget_usd
            && (!eu.is_finite() || eu < 0.0)
        {
            return Err(PluginBuildError::BuildFailed {
                plugin: self.name().to_owned(),
                message: "`end_user_budget_usd` must be a non-negative finite number".to_owned(),
            });
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
            org_budgets,
            end_user_budget_usd: cfg.end_user_budget_usd,
            end_user_budget_window: cfg.end_user_budget_window.unwrap_or(cfg.window),
            preflight_reserve: cfg.preflight_reserve,
            reserve_output_tokens_cap: cfg.reserve_output_tokens_cap,
            clock: ctx.clock(),
            ledger,
            distributed,
            metrics: Arc::clone(&self.metrics),
        }))
    }
}

/// Cost attribution & spend budget enforcement plugin (`ai-budget`).
///
/// Tracks exact integer nano-USD spend per virtual key / per-model / team / org / end-user / global
/// window, emits `shunt_ai_cost_usd_total` Prometheus metrics, adds `x-shunt-budget-*` headers,
/// supports opt-in atomic pre-flight budget holds with reconciliation, and enforces soft warnings
/// or hard `429`/`402` rejections locally or across Redis replicas.
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
    org_budgets: HashMap<String, CompiledTeamBudget>,
    end_user_budget_usd: Option<f64>,
    end_user_budget_window: BudgetWindow,
    preflight_reserve: bool,
    reserve_output_tokens_cap: u64,
    clock: Arc<dyn Clock>,
    ledger: Arc<SpendLedgerTable>,
    distributed: Option<Arc<dyn DistributedStore>>,
    metrics: Arc<AiMetrics>,
}

impl AiBudgetPlugin {
    fn estimate_preflight_cost_nano(
        &self,
        ctx: &RequestCtx,
        endpoint: AiEndpointKind,
        body: &[u8],
    ) -> u64 {
        let meta = ctx.get_ext::<AiRequestMeta>();
        let requested_model = meta.map(|m| m.requested_model.as_str()).unwrap_or("");
        let target_model = meta
            .and_then(|m| m.targets.first())
            .map(|t| t.model.as_str())
            .unwrap_or(requested_model);
        let Some(pricing) = self.catalog.lookup(target_model, requested_model) else {
            return 0;
        };
        let est = estimate_request_tokens(endpoint, body);
        let est_out = match endpoint {
            AiEndpointKind::Embeddings | AiEndpointKind::Rerank | AiEndpointKind::Moderations => 0,
            _ => match est.requested_max_output {
                Some(m) if self.reserve_output_tokens_cap > 0 => {
                    m.min(self.reserve_output_tokens_cap)
                }
                Some(m) => m,
                None => self.reserve_output_tokens_cap,
            },
        };
        pricing.cost_nano_usd(est.input_tokens, 0, est_out)
    }

    fn resolve_targets(&self, ctx: &RequestCtx) -> Vec<BudgetTarget> {
        let now_ms = self.clock.now_ms();
        let policy = ctx.get_ext::<AiKeyPolicy>();
        let end_user = ctx.get_ext::<AiEndUser>().map(|u| u.0.as_str());
        let requested_model = ctx
            .get_ext::<AiRequestMeta>()
            .map(|m| m.requested_model.as_str());
        let mut targets = Vec::with_capacity(4);

        // 1. Primary budget target (key, team, org, end_user, or global)
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
                BudgetScope::Org => policy
                    .and_then(|p| p.org.as_deref().map(|o| format!("org:{o}")))
                    .or_else(|| policy.and_then(|p| p.team.as_deref().map(|t| format!("team:{t}"))))
                    .or_else(|| policy.map(|p| format!("key:{}", p.key_id)))
                    .unwrap_or_else(|| "global".to_owned()),
                BudgetScope::EndUser => end_user
                    .map(|u| format!("user:{u}"))
                    .or_else(|| policy.map(|p| format!("key:{}", p.key_id)))
                    .unwrap_or_else(|| format!("ip:{}", ctx.client_addr.ip())),
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

        // 2. Per-key per-model budget override (`model_limits.<pat>.budget_usd`)
        if let Some(p) = policy
            && let Some(model) = requested_model
            && let Some((pat, ml)) = p.limit_for_model(model)
            && let Some(m_limit_usd) = ml.budget_usd
        {
            let m_window = ml.budget_window.unwrap_or(primary_window);
            let hard_limit_nano = usd_to_nano_usd(m_limit_usd);
            let soft_limit_nano = ml
                .budget_soft_limit_usd
                .map(|s| usd_to_nano_usd(s).min(hard_limit_nano))
                .unwrap_or_else(|| usd_to_nano_usd(m_limit_usd * self.soft_warning_ratio));
            let subject = format!("key:{}:model:{pat}", p.key_id);
            let dur = m_window.as_duration();
            let win_ms = dur.as_millis().max(1) as u64;
            let window_id = now_ms / win_ms;
            targets.push(BudgetTarget {
                label: subject.clone(),
                local_key: format!("key_model:{subject}"),
                dist_key: format!("ai_budget:{}:{subject}:{}", self.scope_id, m_window.label()),
                window: dur,
                window_id,
                hard_limit_nano,
                soft_limit_nano,
            });
        }

        // 3. Additional per-team aggregate budget
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
                    label: subject,
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

        // 4. Additional per-organization aggregate budget
        if let Some(org) = policy.and_then(|p| p.org.as_deref())
            && let Some(ob) = self.org_budgets.get(org)
        {
            let subject = format!("org:{org}");
            let already_present = targets.iter().any(|t| t.label == subject);
            if !already_present {
                let dur = ob.window.as_duration();
                let win_ms = dur.as_millis().max(1) as u64;
                let window_id = now_ms / win_ms;
                targets.push(BudgetTarget {
                    label: subject,
                    local_key: format!("org_agg:{org}"),
                    dist_key: format!(
                        "ai_budget:{}:org_agg:{org}:{}",
                        self.scope_id,
                        ob.window.label()
                    ),
                    window: dur,
                    window_id,
                    hard_limit_nano: ob.hard_limit_nano,
                    soft_limit_nano: ob.soft_limit_nano,
                });
            }
        }

        // 5. Additional per-end-user rolling budget
        if let (Some(eu), Some(eu_limit)) = (end_user, self.end_user_budget_usd) {
            let subject = format!("user:{eu}");
            let already_present = targets.iter().any(|t| t.label == subject);
            if !already_present {
                let hard_limit_nano = usd_to_nano_usd(eu_limit);
                let soft_limit_nano = usd_to_nano_usd(eu_limit * self.soft_warning_ratio);
                let dur = self.end_user_budget_window.as_duration();
                let win_ms = dur.as_millis().max(1) as u64;
                let window_id = now_ms / win_ms;
                targets.push(BudgetTarget {
                    label: subject,
                    local_key: format!("user_agg:{eu}"),
                    dist_key: format!(
                        "ai_budget:{}:user_agg:{eu}:{}",
                        self.scope_id,
                        self.end_user_budget_window.label()
                    ),
                    window: dur,
                    window_id,
                    hard_limit_nano,
                    soft_limit_nano,
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
        body: &'a mut Bytes,
    ) -> HookResult<'a, Flow> {
        let endpoint = ctx
            .get_ext::<DetectedEndpoint>()
            .map(|d| d.0)
            .unwrap_or(AiEndpointKind::ChatCompletions);
        if endpoint.is_models_discovery() {
            return HookResult::Ready(Flow::Continue);
        }

        // Pre-attach the interior-mutable cost slot so `ai-usage-tracker` can record attributed
        // spend into `GET /v1/generation?id=...` records in `on_complete`.
        if ctx.get_ext::<AiRecordedCost>().is_none() {
            ctx.insert_ext(AiRecordedCost::default());
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
        let reserve_nano = if self.preflight_reserve {
            self.estimate_preflight_cost_nano(ctx, endpoint, body)
        } else {
            0
        };
        let enforce_hard = self.mode == BudgetMode::Hard;

        if let Some(dist) = &self.distributed {
            let dist = Arc::clone(dist);
            let ledger = Arc::clone(&self.ledger);
            return HookResult::pending(async move {
                if self.preflight_reserve && reserve_nano > 0 && enforce_hard {
                    let mut reserved_targets: Vec<BudgetTarget> = Vec::with_capacity(targets.len());
                    let mut spends = Vec::with_capacity(targets.len());
                    for t in &targets {
                        match dist
                            .try_consume_quota(
                                &t.dist_key,
                                reserve_nano,
                                t.hard_limit_nano,
                                t.window,
                            )
                            .await
                        {
                            Ok(out) if out.allowed => {
                                reserved_targets.push(t.clone());
                                spends.push(out.current);
                            }
                            Ok(out) => {
                                let refund = -(reserve_nano.min(i64::MAX as u64) as i64);
                                for prev in reserved_targets {
                                    let _ = dist
                                        .adjust_counter(&prev.dist_key, refund, prev.window)
                                        .await;
                                }
                                let limit_usd = nano_usd_to_usd(t.hard_limit_nano);
                                let spent_usd = nano_usd_to_usd(out.current);
                                let mut resp = endpoint_error_response(
                                    endpoint,
                                    self.reject_status,
                                    "budget_exceeded",
                                    Some("budget_exceeded"),
                                    &format!(
                                        "Spend budget exceeded for `{}` (${spent_usd:.6} + reserved ${:.6} > ${limit_usd:.6} USD)",
                                        t.label,
                                        nano_usd_to_usd(reserve_nano)
                                    ),
                                );
                                attach_budget_headers(
                                    &mut resp.headers,
                                    t.hard_limit_nano,
                                    out.current,
                                    Some("hard_limit_exceeded"),
                                );
                                return Flow::Respond(resp);
                            }
                            Err(err) => {
                                warn!(
                                    plugin = "ai-budget",
                                    backend = dist.backend_name(),
                                    error = %err,
                                    "distributed pre-flight budget hold failed"
                                );
                                let refund = -(reserve_nano.min(i64::MAX as u64) as i64);
                                for prev in reserved_targets {
                                    let _ = dist
                                        .adjust_counter(&prev.dist_key, refund, prev.window)
                                        .await;
                                }
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
                    let primary_limit_nano = targets.first().map(|t| t.hard_limit_nano);
                    let primary_spent_nano = spends.first().copied().unwrap_or(0);
                    let warning_reason = targets
                        .iter()
                        .zip(spends.iter())
                        .any(|(t, &s)| s >= t.soft_limit_nano)
                        .then_some("soft_limit_reached");
                    ctx.insert_ext(BudgetHoldGuard::new(
                        ledger,
                        Some(dist),
                        reserved_targets,
                        reserve_nano,
                    ));
                    ctx.insert_ext(AiBudgetState {
                        targets,
                        primary_limit_nano,
                        primary_spent_nano,
                        warning_reason,
                    });
                    return Flow::Continue;
                }

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

        // Synchronous local fast path with optional atomic pre-flight budget holds.
        if self.preflight_reserve && reserve_nano > 0 {
            let mut reserved_targets: Vec<BudgetTarget> = Vec::with_capacity(targets.len());
            let mut spends_after = Vec::with_capacity(targets.len());
            for t in &targets {
                match self.ledger.try_reserve_spend(
                    &t.local_key,
                    t.window_id,
                    reserve_nano,
                    t.hard_limit_nano,
                    enforce_hard,
                ) {
                    Ok(after) => {
                        reserved_targets.push(t.clone());
                        spends_after.push(after);
                    }
                    Err(cur) => {
                        let refund = -(reserve_nano.min(i64::MAX as u64) as i64);
                        for prev in &reserved_targets {
                            self.ledger
                                .adjust_spend(&prev.local_key, prev.window_id, refund);
                        }
                        let limit_usd = nano_usd_to_usd(t.hard_limit_nano);
                        let spent_usd = nano_usd_to_usd(cur);
                        push_alert_event(
                            ctx,
                            AiAlertEvent {
                                kind: AiAlertKind::BudgetHardExceeded,
                                severity: AiAlertSeverity::Critical,
                                dedup_key: format!("hard::{}::{}", t.label, t.window_id),
                                title: format!("AI spend budget exceeded for {}", t.label),
                                message: format!(
                                    "Pre-flight budget hold rejected for `{}` (${spent_usd:.6} + reserved ${:.6} > ${limit_usd:.6} USD)",
                                    t.label,
                                    nano_usd_to_usd(reserve_nano)
                                ),
                                subject: Some(t.label.clone()),
                                provider: None,
                                model: None,
                                key_id,
                                team,
                                details: serde_json::json!({
                                    "spent_usd": spent_usd,
                                    "reserved_usd": nano_usd_to_usd(reserve_nano),
                                    "limit_usd": limit_usd,
                                    "mode": "hard_preflight",
                                }),
                            },
                        );
                        let mut resp = endpoint_error_response(
                            endpoint,
                            self.reject_status,
                            "budget_exceeded",
                            Some("budget_exceeded"),
                            &format!(
                                "Spend budget exceeded for `{}` (${spent_usd:.6} + reserved ${:.6} > ${limit_usd:.6} USD)",
                                t.label,
                                nano_usd_to_usd(reserve_nano)
                            ),
                        );
                        attach_budget_headers(
                            &mut resp.headers,
                            t.hard_limit_nano,
                            cur,
                            Some("hard_limit_exceeded"),
                        );
                        return HookResult::Ready(Flow::Respond(resp));
                    }
                }
            }
            let primary_limit_nano = targets.first().map(|t| t.hard_limit_nano);
            let primary_spent_nano = spends_after.first().copied().unwrap_or(0);
            let warning_reason = targets
                .iter()
                .zip(spends_after.iter())
                .any(|(t, &s)| s >= t.soft_limit_nano)
                .then_some("soft_limit_reached");
            ctx.insert_ext(BudgetHoldGuard::new(
                Arc::clone(&self.ledger),
                None,
                reserved_targets,
                reserve_nano,
            ));
            ctx.insert_ext(AiBudgetState {
                targets,
                primary_limit_nano,
                primary_spent_nano,
                warning_reason,
            });
            return HookResult::Ready(Flow::Continue);
        }

        // Standard non-reserving synchronous local fast path.
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
        // Always claim any pre-flight hold so short-circuits/errors refund deterministically.
        let preflight_hold = ctx
            .get_ext::<BudgetHoldGuard>()
            .and_then(BudgetHoldGuard::take_for_reconcile);

        if ctx
            .get_ext::<DetectedEndpoint>()
            .map(|d| d.0.is_models_discovery())
            .unwrap_or(false)
        {
            return HookResult::Ready(());
        }

        let meta = ctx.get_ext::<AiRequestMeta>();
        let active_target = meta.and_then(AiRequestMeta::active_target);
        let usage = ctx.get_ext::<AiUsage>();

        let (cost_nano, provider, served_model) = if summary.attempts > 0
            && let Some(u) = usage
        {
            let prompt = u.prompt_tokens.unwrap_or(0);
            let cached = u.cached_prompt_tokens.unwrap_or(0);
            let cache_write = u.cache_creation_prompt_tokens.unwrap_or(0);
            let completion = u.completion_tokens.unwrap_or(0);
            let provider = u
                .provider
                .clone()
                .or_else(|| active_target.map(|t| t.provider.clone()))
                .unwrap_or_else(|| "unknown".to_owned());
            let requested_model = meta
                .map(|m| m.requested_model.as_str())
                .unwrap_or("unknown");
            let served_model = u
                .served_model
                .as_deref()
                .or_else(|| active_target.map(|t| t.model.as_str()))
                .unwrap_or(requested_model)
                .to_owned();
            let cost = if prompt > 0 || completion > 0 {
                self.catalog
                    .lookup(&served_model, requested_model)
                    .map(|p| p.cost_nano_usd_detailed(prompt, cached, cache_write, completion))
                    .unwrap_or(0)
            } else {
                0
            };
            (cost, provider, served_model)
        } else {
            (0, "unknown".to_owned(), "unknown".to_owned())
        };

        let policy = ctx.get_ext::<AiKeyPolicy>();
        if cost_nano > 0 {
            let key_label = policy.map(|p| p.key_id.as_str()).unwrap_or("anonymous");
            let team_label = policy.and_then(|p| p.team.as_deref()).unwrap_or("default");

            self.metrics
                .record_cost(&provider, &served_model, key_label, team_label, cost_nano);

            if let Some(slot) = ctx.get_ext::<AiRecordedCost>() {
                slot.set_nano_usd(cost_nano);
            }

            ctx.annotate_float("shunt.ai.cost_usd", nano_usd_to_usd(cost_nano));

            if let Some(u) = usage {
                info!(
                    request_id = summary.request_id,
                    provider = %provider,
                    model = %served_model,
                    key_id = %key_label,
                    team = %team_label,
                    prompt_tokens = u.prompt_tokens.unwrap_or(0),
                    cached_prompt_tokens = u.cached_prompt_tokens.unwrap_or(0),
                    cache_creation_prompt_tokens = u.cache_creation_prompt_tokens.unwrap_or(0),
                    completion_tokens = u.completion_tokens.unwrap_or(0),
                    cost_usd = nano_usd_to_usd(cost_nano),
                    "ai_cost"
                );
            }
        }

        // Compute net signed ledger delta (reconciling pre-flight hold if present, else +cost_nano).
        let (targets, signed_delta): (Vec<BudgetTarget>, i64) =
            if let Some((held_targets, reserved_nano)) = preflight_hold {
                let actual_i64 = cost_nano.min(i64::MAX as u64) as i64;
                let reserved_i64 = reserved_nano.min(i64::MAX as u64) as i64;
                (held_targets, actual_i64.saturating_sub(reserved_i64))
            } else if cost_nano > 0 {
                let targets = ctx
                    .get_ext::<AiBudgetState>()
                    .map(|s| s.targets.clone())
                    .unwrap_or_default();
                (targets, cost_nano.min(i64::MAX as u64) as i64)
            } else {
                (Vec::new(), 0)
            };

        if targets.is_empty() || signed_delta == 0 {
            return HookResult::Ready(());
        }

        if let Some(dist) = &self.distributed {
            let dist = Arc::clone(dist);
            return HookResult::pending(async move {
                for t in targets {
                    if let Err(err) = dist
                        .adjust_counter(&t.dist_key, signed_delta, t.window)
                        .await
                    {
                        warn!(
                            plugin = "ai-budget",
                            subject = %t.label,
                            error = %err,
                            "distributed budget adjustment failed"
                        );
                    }
                }
            });
        }

        for t in &targets {
            let prev = self.ledger.current_spend(&t.local_key, t.window_id);
            let after = self
                .ledger
                .adjust_spend(&t.local_key, t.window_id, signed_delta);
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
                        model: Some(served_model.clone()),
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
                        model: Some(served_model.clone()),
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
