use std::collections::{HashMap, HashSet};
use std::sync::{Arc, RwLock};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use shunt_plugin_sdk::{
    BuildContext, Bytes, Clock, DistributedStore, Flow, HookMask, HookResult, HttpPlugin,
    PluginBuildError, PluginConfig, PluginFactory, RequestCtx, ResponseHead, StatusCode,
    UpstreamSelection, header,
};
use tracing::{debug, info, warn};

use crate::alerts::{AiAlertEvent, AiAlertKind, AiAlertSeverity, push_alert_event};
use crate::types::{
    AiFailoverHistory, AiKeyPolicy, AiRequestMeta, ContextOverflowFloor, FailoverEvent,
};

fn default_retry_statuses() -> Vec<u16> {
    vec![429, 500, 502, 503, 504, 529]
}

fn default_failure_threshold() -> usize {
    1
}

fn default_max_cooldown_ms() -> u64 {
    60_000
}

fn default_true() -> bool {
    true
}

fn default_context_overflow_max_inspect_bytes() -> usize {
    65_536
}

/// Marker storing the target that was dispatched on the previous attempt so `ai-failover`
/// can record timeout / transport failures into `FailoverCircuitState` and `AiFailoverHistory`
/// when `shunt-engine` automatically retries after a `504` / `502` transport failure.
#[derive(Debug, Clone)]
struct LastAttemptTarget {
    attempt: usize,
    provider: String,
    upstream: String,
    model: String,
}

/// Classifies whether an upstream `400`/`413`/`422` response body indicates a prompt/context
/// window overflow across OpenAI, Anthropic, Google Gemini, AWS Bedrock, and vLLM/Ollama.
pub fn is_context_overflow_error(status: u16, body: &[u8]) -> bool {
    if !matches!(status, 400 | 413 | 422) {
        return false;
    }
    if status == 413 {
        return true;
    }
    let text = String::from_utf8_lossy(body).to_ascii_lowercase();
    const PATTERNS: &[&str] = &[
        "context_length_exceeded",
        "maximum context length",
        "prompt is too long",
        "exceeds the context window",
        "exceeds the maximum number of tokens",
        "input is too long",
        "too many input tokens",
        "input token count",
        "token limit",
        "context window exceeded",
        "max_tokens_exceeded",
        "request too large",
    ];
    PATTERNS.iter().any(|p| text.contains(p))
}

#[derive(Debug, Deserialize)]
#[serde(default)]
struct AiFailoverConfig {
    /// Upstream HTTP status codes that trigger automatic failover via `Flow::RetryUpstream`.
    #[serde(default = "default_retry_statuses")]
    retry_statuses: Vec<u16>,
    /// Optional per-target cooldown window (ms) backed by `StateStore` so unhealthy
    /// providers are skipped across subsequent requests and survive snapshot reloads.
    /// Set to `0` (default) to disable stateful cooldowns.
    cooldown_ms: u64,
    /// Consecutive retryable failures before activating cooldown (when `cooldown_ms > 0`).
    #[serde(default = "default_failure_threshold")]
    failure_threshold: usize,
    /// Honor numeric `Retry-After` headers when computing cooldown duration.
    respect_retry_after: bool,
    /// Upper cap on cooldown duration when honoring `Retry-After`.
    #[serde(default = "default_max_cooldown_ms")]
    max_cooldown_ms: u64,
    /// Share cooldown state via the gateway's distributed store when configured (default: true).
    #[serde(default = "default_true")]
    distributed: bool,
    /// Optional default per-attempt TTFT / response-headers timeout (ms) enforced via
    /// `UpstreamSelection::response_headers_timeout_override` when a target has no explicit
    /// `ttft_timeout_ms`.
    #[serde(default)]
    ttft_timeout_ms: Option<u64>,
    /// Inspect small `400`/`413`/`422` upstream error bodies pre-flush and automatically fail over
    /// to a larger-context fallback target when context-window overflow is detected (default: false).
    #[serde(default)]
    failover_on_context_overflow: bool,
    /// Max error response bytes buffered pre-flush for context-overflow inspection (default: 64 KiB).
    #[serde(default = "default_context_overflow_max_inspect_bytes")]
    context_overflow_max_inspect_bytes: usize,
}

impl Default for AiFailoverConfig {
    fn default() -> Self {
        Self {
            retry_statuses: default_retry_statuses(),
            cooldown_ms: 0,
            failure_threshold: default_failure_threshold(),
            respect_retry_after: false,
            max_cooldown_ms: default_max_cooldown_ms(),
            distributed: true,
            ttft_timeout_ms: None,
            failover_on_context_overflow: false,
            context_overflow_max_inspect_bytes: default_context_overflow_max_inspect_bytes(),
        }
    }
}

#[derive(Debug, Default)]
struct TargetHealthEntry {
    consecutive_failures: usize,
    cooldown_until: Option<Duration>,
}

/// Point-in-time provider/model cooldown snapshot for read-only inspection APIs.
#[derive(Debug, Clone, Serialize)]
pub struct CooldownSnapshot {
    pub target: String,
    pub consecutive_failures: usize,
    pub in_cooldown: bool,
    pub remaining_ms: u64,
}

/// Shared cooldown circuit-breaker state stored inside `StateStore` across reloads.
#[derive(Debug, Default)]
pub struct FailoverCircuitState {
    targets: RwLock<HashMap<String, TargetHealthEntry>>,
}

impl FailoverCircuitState {
    pub fn snapshot_cooldowns(&self, now: Duration) -> Vec<CooldownSnapshot> {
        let guard = self.targets.read().expect("FailoverCircuitState poisoned");
        let mut out: Vec<CooldownSnapshot> = guard
            .iter()
            .filter_map(|(target, entry)| {
                let remaining = entry
                    .cooldown_until
                    .and_then(|until| until.checked_sub(now));
                let in_cooldown = remaining.is_some_and(|r| !r.is_zero());
                if !in_cooldown && entry.consecutive_failures == 0 {
                    return None;
                }
                Some(CooldownSnapshot {
                    target: target.clone(),
                    consecutive_failures: entry.consecutive_failures,
                    in_cooldown,
                    remaining_ms: remaining.map(|d| d.as_millis() as u64).unwrap_or(0),
                })
            })
            .collect();
        out.sort_by(|a, b| {
            b.in_cooldown
                .cmp(&a.in_cooldown)
                .then_with(|| b.remaining_ms.cmp(&a.remaining_ms))
                .then_with(|| a.target.cmp(&b.target))
        });
        out
    }
    pub fn is_in_cooldown(&self, key: &str, now: Duration) -> bool {
        let guard = self.targets.read().expect("FailoverCircuitState poisoned");
        guard
            .get(key)
            .and_then(|e| e.cooldown_until)
            .map(|until| now < until)
            .unwrap_or(false)
    }

    pub fn consecutive_failures(&self, key: &str) -> usize {
        let guard = self.targets.read().expect("FailoverCircuitState poisoned");
        guard.get(key).map(|e| e.consecutive_failures).unwrap_or(0)
    }

    /// Records a failure and returns `true` when this failure activated/extended a cooldown window.
    pub fn record_failure(
        &self,
        key: &str,
        threshold: usize,
        cooldown: Duration,
        now: Duration,
    ) -> bool {
        let mut guard = self.targets.write().expect("FailoverCircuitState poisoned");
        let entry = guard.entry(key.to_owned()).or_default();
        let was_cooled = entry.cooldown_until.is_some_and(|until| now < until);
        entry.consecutive_failures = entry.consecutive_failures.saturating_add(1);
        if entry.consecutive_failures >= threshold.max(1) {
            let until = now.saturating_add(cooldown);
            entry.cooldown_until = Some(match entry.cooldown_until {
                Some(prev) => prev.max(until),
                None => until,
            });
            return !was_cooled;
        }
        false
    }

    pub fn record_success(&self, key: &str) {
        let mut guard = self.targets.write().expect("FailoverCircuitState poisoned");
        if let Some(entry) = guard.get_mut(key) {
            entry.consecutive_failures = 0;
            entry.cooldown_until = None;
        }
    }
}

/// Computes the effective cooldown duration, optionally honoring a numeric `Retry-After`
/// header value clamped to `[base_cooldown, max_cooldown]`.
pub fn compute_cooldown(
    base_cooldown: Duration,
    max_cooldown: Duration,
    respect_retry_after: bool,
    retry_after_header: Option<&str>,
) -> Duration {
    let upper = max_cooldown.max(base_cooldown);
    if !respect_retry_after {
        return base_cooldown;
    }
    if let Some(secs) = retry_after_header.and_then(|s| s.trim().parse::<u64>().ok()) {
        base_cooldown.max(Duration::from_secs(secs)).min(upper)
    } else {
        base_cooldown
    }
}

/// Factory for the `ai-failover` plugin.
pub struct AiFailoverFactory;

impl PluginFactory for AiFailoverFactory {
    fn name(&self) -> &str {
        "ai-failover"
    }

    fn build(
        &self,
        config: &PluginConfig,
        ctx: &BuildContext,
    ) -> Result<Arc<dyn HttpPlugin>, PluginBuildError> {
        let cfg: AiFailoverConfig = config.deserialize(self.name())?;
        if cfg.retry_statuses.is_empty() {
            return Err(PluginBuildError::BuildFailed {
                plugin: self.name().to_owned(),
                message: "`retry_statuses` cannot be empty".to_owned(),
            });
        }

        if cfg.ttft_timeout_ms == Some(0) {
            return Err(PluginBuildError::BuildFailed {
                plugin: self.name().to_owned(),
                message: "`ttft_timeout_ms` must be >= 1 when set".to_owned(),
            });
        }
        if cfg.context_overflow_max_inspect_bytes == 0 {
            return Err(PluginBuildError::BuildFailed {
                plugin: self.name().to_owned(),
                message: "`context_overflow_max_inspect_bytes` must be >= 1".to_owned(),
            });
        }

        let retry_statuses: HashSet<u16> = cfg.retry_statuses.into_iter().collect();
        let circuit = if cfg.cooldown_ms > 0 {
            let handle = ctx.state_handle();
            Some(handle.get_or_init("failover_circuit", FailoverCircuitState::default))
        } else {
            None
        };
        let distributed = if cfg.cooldown_ms > 0 && cfg.distributed {
            ctx.distributed_store()
        } else {
            None
        };

        Ok(Arc::new(AiFailoverPlugin {
            scope_id: ctx.scope_id().to_owned(),
            retry_statuses,
            cooldown: Duration::from_millis(cfg.cooldown_ms),
            failure_threshold: cfg.failure_threshold.max(1),
            respect_retry_after: cfg.respect_retry_after,
            max_cooldown: Duration::from_millis(cfg.max_cooldown_ms.max(cfg.cooldown_ms)),
            ttft_timeout: cfg.ttft_timeout_ms.map(Duration::from_millis),
            failover_on_context_overflow: cfg.failover_on_context_overflow,
            context_overflow_max_inspect_bytes: cfg.context_overflow_max_inspect_bytes,
            clock: ctx.clock(),
            circuit,
            distributed,
        }))
    }
}

/// Inspects upstream responses for retryable errors (`429`, `5xx`, `529`), TTFT timeouts,
/// and optional context-window overflow bodies, returning `Flow::RetryUpstream` to fail over
/// automatically to the next provider/model target.
pub struct AiFailoverPlugin {
    scope_id: String,
    retry_statuses: HashSet<u16>,
    cooldown: Duration,
    failure_threshold: usize,
    respect_retry_after: bool,
    max_cooldown: Duration,
    ttft_timeout: Option<Duration>,
    failover_on_context_overflow: bool,
    context_overflow_max_inspect_bytes: usize,
    clock: Arc<dyn Clock>,
    circuit: Option<Arc<FailoverCircuitState>>,
    distributed: Option<Arc<dyn DistributedStore>>,
}

impl AiFailoverPlugin {
    fn target_key(upstream: &str, model: &str) -> String {
        format!("{upstream}::{model}")
    }

    fn dist_cooldown_key(&self, upstream: &str, model: &str) -> String {
        format!("ai_cd:{}:{upstream}:{model}", self.scope_id)
    }
}

impl HttpPlugin for AiFailoverPlugin {
    fn name(&self) -> &str {
        "ai-failover"
    }

    fn hook_mask(&self) -> HookMask {
        let mut mask = HookMask::ON_RESPONSE_HEADERS;
        if self.circuit.is_some() || self.ttft_timeout.is_some() {
            mask |= HookMask::ON_UPSTREAM_SELECT;
        }
        if self.failover_on_context_overflow {
            mask |= HookMask::ON_RESPONSE_BODY_INSPECTED;
        }
        mask
    }

    fn on_upstream_select<'a>(
        &'a self,
        ctx: &'a mut RequestCtx,
        selection: &'a mut UpstreamSelection,
    ) -> HookResult<'a, Flow> {
        // If a previous attempt failed due to a transport/TTFT timeout (`shunt-engine` retried
        // before `on_response_headers`), record it in failover history & cooldown state.
        if ctx.attempt > 1
            && ctx.last_upstream_error.is_some()
            && let Some(prev) = ctx.remove_ext::<LastAttemptTarget>()
        {
            let status_code = ctx
                .last_upstream_status
                .unwrap_or(StatusCode::GATEWAY_TIMEOUT)
                .as_u16();
            if let Some(circuit) = &self.circuit {
                let local_key = Self::target_key(&prev.upstream, &prev.model);
                let newly_opened = circuit.record_failure(
                    &local_key,
                    self.failure_threshold,
                    self.cooldown,
                    self.clock.now(),
                );
                if newly_opened {
                    let (key_id, team) = ctx
                        .get_ext::<AiKeyPolicy>()
                        .map(|p| (Some(p.key_id.clone()), p.team.clone()))
                        .unwrap_or((None, None));
                    push_alert_event(
                        ctx,
                        AiAlertEvent {
                            kind: AiAlertKind::CircuitBreakerOpen,
                            severity: AiAlertSeverity::Error,
                            dedup_key: format!("{}::{}", prev.provider, prev.model),
                            title: format!(
                                "AI provider circuit breaker opened ({}/{})",
                                prev.provider, prev.model
                            ),
                            message: format!(
                                "Provider `{}` model `{}` entered cooldown for {}ms after transport/TTFT failure (HTTP {status_code})",
                                prev.provider,
                                prev.model,
                                self.cooldown.as_millis()
                            ),
                            subject: Some(local_key),
                            provider: Some(prev.provider.clone()),
                            model: Some(prev.model.clone()),
                            key_id,
                            team,
                            details: serde_json::json!({
                                "upstream": prev.upstream,
                                "status": status_code,
                                "cooldown_ms": self.cooldown.as_millis() as u64,
                            }),
                        },
                    );
                }
            }
            let event = FailoverEvent {
                attempt: prev.attempt,
                provider: prev.provider,
                upstream: prev.upstream,
                model: prev.model,
                status: status_code,
            };
            if let Some(history) = ctx.get_ext_mut::<AiFailoverHistory>() {
                history.events.push(event);
            } else {
                ctx.insert_ext(AiFailoverHistory {
                    events: vec![event],
                });
            }
        }

        // Apply default TTFT timeout override when no target-specific timeout was set.
        if selection.response_headers_timeout_override.is_none()
            && let Some(ttft) = self.ttft_timeout
        {
            selection.response_headers_timeout_override = Some(ttft);
        }

        let Some(circuit) = &self.circuit else {
            if let Some(target) = ctx
                .get_ext::<AiRequestMeta>()
                .and_then(AiRequestMeta::active_target)
                .cloned()
            {
                ctx.insert_ext(LastAttemptTarget {
                    attempt: ctx.attempt,
                    provider: target.provider,
                    upstream: target.upstream,
                    model: target.model,
                });
            }
            return HookResult::Ready(Flow::Continue);
        };
        let request_id = ctx.request_id;
        let Some(meta) = ctx.get_ext_mut::<AiRequestMeta>() else {
            return HookResult::Ready(Flow::Continue);
        };

        let len = meta.targets.len();
        if len <= 1 {
            if let Some(target) = meta.active_target().cloned() {
                ctx.insert_ext(LastAttemptTarget {
                    attempt: ctx.attempt,
                    provider: target.provider,
                    upstream: target.upstream,
                    model: target.model,
                });
            }
            return HookResult::Ready(Flow::Continue);
        }

        if let Some(dist) = &self.distributed {
            struct DistCooldownCandidate {
                idx: usize,
                local_key: String,
                dist_key: String,
                provider: String,
                upstream: String,
                model: String,
                ep_override: Option<String>,
                target_ttft: Option<u64>,
            }
            let dist = Arc::clone(dist);
            let now = self.clock.now();
            let start = meta.active_target_index;
            let candidates: Vec<DistCooldownCandidate> = (0..len)
                .map(|offset| {
                    let idx = (start + offset) % len;
                    let c = &meta.targets[idx];
                    DistCooldownCandidate {
                        idx,
                        local_key: Self::target_key(&c.upstream, &c.model),
                        dist_key: self.dist_cooldown_key(&c.upstream, &c.model),
                        provider: c.provider.clone(),
                        upstream: c.upstream.clone(),
                        model: c.model.clone(),
                        ep_override: c.endpoint_override.clone(),
                        target_ttft: c.ttft_timeout_ms,
                    }
                })
                .collect();
            let default_ttft = self.ttft_timeout;
            return HookResult::pending(async move {
                for cand in candidates {
                    if circuit.is_in_cooldown(&cand.local_key, now) {
                        continue;
                    }
                    let dist_cooled = match dist.has_flag(&cand.dist_key).await {
                        Ok(flag) => flag,
                        Err(err) => {
                            warn!(plugin = "ai-failover", error = %err, "distributed cooldown check failed");
                            false
                        }
                    };
                    if !dist_cooled {
                        if cand.idx != start {
                            if let Some(m) = ctx.get_ext_mut::<AiRequestMeta>() {
                                m.active_target_index = cand.idx;
                            }
                            selection.upstream = cand.upstream.clone();
                            selection.endpoint_override = cand.ep_override;
                            selection.response_headers_timeout_override =
                                cand.target_ttft.map(Duration::from_millis).or(default_ttft);
                        }
                        ctx.insert_ext(LastAttemptTarget {
                            attempt: ctx.attempt,
                            provider: cand.provider,
                            upstream: cand.upstream,
                            model: cand.model,
                        });
                        break;
                    }
                }
                Flow::Continue
            });
        }

        let now = self.clock.now();
        let start = meta.active_target_index;
        for offset in 0..len {
            let idx = (start + offset) % len;
            let cand = &meta.targets[idx];
            let key = Self::target_key(&cand.upstream, &cand.model);
            if !circuit.is_in_cooldown(&key, now) {
                if idx != start {
                    debug!(
                        request_id,
                        from_upstream = %meta.targets[start].upstream,
                        to_upstream = %cand.upstream,
                        model = %cand.model,
                        "ai-failover skipping cooled-down target"
                    );
                    meta.active_target_index = idx;
                    selection.upstream = cand.upstream.clone();
                    selection.endpoint_override = cand.endpoint_override.clone();
                    selection.response_headers_timeout_override = cand
                        .ttft_timeout_ms
                        .map(Duration::from_millis)
                        .or(self.ttft_timeout);
                }
                break;
            }
        }

        if let Some(target) = meta.active_target().cloned() {
            ctx.insert_ext(LastAttemptTarget {
                attempt: ctx.attempt,
                provider: target.provider,
                upstream: target.upstream,
                model: target.model,
            });
        }

        HookResult::Ready(Flow::Continue)
    }

    fn on_response_headers<'a>(
        &'a self,
        ctx: &'a mut RequestCtx,
        res: &'a mut ResponseHead,
    ) -> HookResult<'a, Flow> {
        let status_code = res.status.as_u16();
        let active_meta = ctx.get_ext::<AiRequestMeta>().map(|m| {
            (
                m.active_target().cloned(),
                m.max_attempts,
                m.requested_model.clone(),
            )
        });

        // Opt-in context-window overflow body inspection on 400/413/422 when retries remain.
        if self.failover_on_context_overflow
            && matches!(status_code, 400 | 413 | 422)
            && !self.retry_statuses.contains(&status_code)
            && let Some((_, max_attempts, _)) = &active_meta
            && ctx.attempt < *max_attempts
        {
            return HookResult::Ready(Flow::InspectResponseBody {
                max_bytes: self.context_overflow_max_inspect_bytes,
            });
        }

        if !self.retry_statuses.contains(&status_code) {
            if res.status.is_success()
                && let Some(circuit) = &self.circuit
                && let Some((Some(target), _, _)) = &active_meta
            {
                circuit.record_success(&Self::target_key(&target.upstream, &target.model));
                if let Some(dist) = &self.distributed {
                    let dist = Arc::clone(dist);
                    let dist_key = self.dist_cooldown_key(&target.upstream, &target.model);
                    return HookResult::pending(async move {
                        let _ = dist.delete(&dist_key).await;
                        Flow::Continue
                    });
                }
            }
            return HookResult::Ready(Flow::Continue);
        }

        if let Some((Some(target), max_attempts, requested_model)) = active_meta {
            let mut dist_set: Option<(String, Duration)> = None;
            let mut circuit_alert: Option<AiAlertEvent> = None;
            let (key_id, team) = ctx
                .get_ext::<AiKeyPolicy>()
                .map(|p| (Some(p.key_id.clone()), p.team.clone()))
                .unwrap_or((None, None));
            if let Some(circuit) = &self.circuit {
                let retry_after_str = res
                    .headers
                    .get(header::RETRY_AFTER)
                    .and_then(|v| v.to_str().ok());
                let cd = compute_cooldown(
                    self.cooldown,
                    self.max_cooldown,
                    self.respect_retry_after,
                    retry_after_str,
                );
                let local_key = Self::target_key(&target.upstream, &target.model);
                let newly_opened = circuit.record_failure(
                    &local_key,
                    self.failure_threshold,
                    cd,
                    self.clock.now(),
                );
                let failures = circuit.consecutive_failures(&local_key);
                if self.distributed.is_some() && failures >= self.failure_threshold {
                    dist_set = Some((self.dist_cooldown_key(&target.upstream, &target.model), cd));
                }
                if newly_opened {
                    circuit_alert = Some(AiAlertEvent {
                        kind: AiAlertKind::CircuitBreakerOpen,
                        severity: AiAlertSeverity::Error,
                        dedup_key: format!("{}::{}", target.provider, target.model),
                        title: format!(
                            "AI provider circuit breaker opened ({}/{})",
                            target.provider, target.model
                        ),
                        message: format!(
                            "Provider `{}` model `{}` entered cooldown for {}ms after {} consecutive failure(s) (HTTP {})",
                            target.provider,
                            target.model,
                            cd.as_millis(),
                            failures,
                            status_code
                        ),
                        subject: Some(local_key),
                        provider: Some(target.provider.clone()),
                        model: Some(target.model.clone()),
                        key_id: key_id.clone(),
                        team: team.clone(),
                        details: serde_json::json!({
                            "upstream": target.upstream,
                            "status": status_code,
                            "consecutive_failures": failures,
                            "cooldown_ms": cd.as_millis() as u64,
                        }),
                    });
                }
            }
            if let Some(ev) = circuit_alert {
                push_alert_event(ctx, ev);
            }

            let event = FailoverEvent {
                attempt: ctx.attempt,
                provider: target.provider.clone(),
                upstream: target.upstream.clone(),
                model: target.model.clone(),
                status: status_code,
            };

            if let Some(history) = ctx.get_ext_mut::<AiFailoverHistory>() {
                history.events.push(event);
            } else {
                ctx.insert_ext(AiFailoverHistory {
                    events: vec![event],
                });
            }

            let next_flow = if ctx.attempt < max_attempts {
                info!(
                    request_id = ctx.request_id,
                    attempt = ctx.attempt,
                    max_attempts,
                    requested_model = %requested_model,
                    failed_provider = %target.provider,
                    failed_upstream = %target.upstream,
                    status = status_code,
                    "ai-failover triggering upstream retry"
                );
                Flow::RetryUpstream
            } else {
                push_alert_event(
                    ctx,
                    AiAlertEvent {
                        kind: AiAlertKind::FailoverExhausted,
                        severity: AiAlertSeverity::Critical,
                        dedup_key: format!("exhausted::{requested_model}"),
                        title: format!("AI failover chain exhausted for {requested_model}"),
                        message: format!(
                            "All {max_attempts} failover attempt(s) for `{requested_model}` failed (last provider `{}` returned HTTP {status_code})",
                            target.provider
                        ),
                        subject: Some(requested_model.clone()),
                        provider: Some(target.provider.clone()),
                        model: Some(target.model.clone()),
                        key_id,
                        team,
                        details: serde_json::json!({
                            "attempts": ctx.attempt,
                            "max_attempts": max_attempts,
                            "last_status": status_code,
                            "last_upstream": target.upstream,
                        }),
                    },
                );
                Flow::Continue
            };

            if let (Some(dist), Some((dist_key, cd))) = (&self.distributed, dist_set) {
                let dist = Arc::clone(dist);
                return HookResult::pending(async move {
                    if let Err(err) = dist.set_flag(&dist_key, cd).await {
                        warn!(plugin = "ai-failover", error = %err, "distributed cooldown set failed");
                    }
                    next_flow
                });
            }

            return HookResult::Ready(next_flow);
        }

        // Route without ai-model-router: still allow status-based retry on multi-attempt routes.
        HookResult::Ready(Flow::RetryUpstream)
    }

    fn on_response_body_inspected<'a>(
        &'a self,
        ctx: &'a mut RequestCtx,
        res: &'a mut ResponseHead,
        body: &'a Bytes,
    ) -> HookResult<'a, Flow> {
        if !self.failover_on_context_overflow {
            return HookResult::Ready(Flow::Continue);
        }
        let status_code = res.status.as_u16();
        if !is_context_overflow_error(status_code, body) {
            return HookResult::Ready(Flow::Continue);
        }

        let active_meta = ctx.get_ext::<AiRequestMeta>().map(|m| {
            (
                m.active_target().cloned(),
                m.max_attempts,
                m.requested_model.clone(),
            )
        });
        if let Some((Some(target), max_attempts, requested_model)) = active_meta
            && ctx.attempt < max_attempts
        {
            if let Some(win) = target.context_window {
                let prev = ctx
                    .get_ext::<ContextOverflowFloor>()
                    .map(|f| f.0)
                    .unwrap_or(0);
                ctx.insert_ext(ContextOverflowFloor(prev.max(win)));
            }
            let event = FailoverEvent {
                attempt: ctx.attempt,
                provider: target.provider.clone(),
                upstream: target.upstream.clone(),
                model: target.model.clone(),
                status: status_code,
            };
            if let Some(history) = ctx.get_ext_mut::<AiFailoverHistory>() {
                history.events.push(event);
            } else {
                ctx.insert_ext(AiFailoverHistory {
                    events: vec![event],
                });
            }
            info!(
                request_id = ctx.request_id,
                attempt = ctx.attempt,
                max_attempts,
                requested_model = %requested_model,
                failed_provider = %target.provider,
                failed_model = %target.model,
                status = status_code,
                "ai-failover detected context-window overflow; retrying larger fallback target"
            );
            return HookResult::Ready(Flow::RetryUpstream);
        }

        HookResult::Ready(Flow::Continue)
    }
}
