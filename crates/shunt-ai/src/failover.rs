use std::collections::{HashMap, HashSet};
use std::sync::{Arc, RwLock};
use std::time::Duration;

use serde::Deserialize;
use shunt_plugin_sdk::{
    BuildContext, Clock, Flow, HookMask, HookResult, HttpPlugin, PluginBuildError, PluginConfig,
    PluginFactory, RequestCtx, ResponseHead, UpstreamSelection, header,
};
use tracing::{debug, info};

use crate::types::{AiFailoverHistory, AiRequestMeta, FailoverEvent};

fn default_retry_statuses() -> Vec<u16> {
    vec![429, 500, 502, 503, 504, 529]
}

fn default_failure_threshold() -> usize {
    1
}

fn default_max_cooldown_ms() -> u64 {
    60_000
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
}

impl Default for AiFailoverConfig {
    fn default() -> Self {
        Self {
            retry_statuses: default_retry_statuses(),
            cooldown_ms: 0,
            failure_threshold: default_failure_threshold(),
            respect_retry_after: false,
            max_cooldown_ms: default_max_cooldown_ms(),
        }
    }
}

#[derive(Debug, Default)]
struct TargetHealthEntry {
    consecutive_failures: usize,
    cooldown_until: Option<Duration>,
}

/// Shared cooldown circuit-breaker state stored inside `StateStore` across reloads.
#[derive(Debug, Default)]
pub struct FailoverCircuitState {
    targets: RwLock<HashMap<String, TargetHealthEntry>>,
}

impl FailoverCircuitState {
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

    pub fn record_failure(&self, key: &str, threshold: usize, cooldown: Duration, now: Duration) {
        let mut guard = self.targets.write().expect("FailoverCircuitState poisoned");
        let entry = guard.entry(key.to_owned()).or_default();
        entry.consecutive_failures = entry.consecutive_failures.saturating_add(1);
        if entry.consecutive_failures >= threshold.max(1) {
            let until = now.saturating_add(cooldown);
            entry.cooldown_until = Some(match entry.cooldown_until {
                Some(prev) => prev.max(until),
                None => until,
            });
        }
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

        let retry_statuses: HashSet<u16> = cfg.retry_statuses.into_iter().collect();
        let circuit = if cfg.cooldown_ms > 0 {
            let handle = ctx.state_handle();
            Some(handle.get_or_init("failover_circuit", FailoverCircuitState::default))
        } else {
            None
        };

        Ok(Arc::new(AiFailoverPlugin {
            retry_statuses,
            cooldown: Duration::from_millis(cfg.cooldown_ms),
            failure_threshold: cfg.failure_threshold.max(1),
            respect_retry_after: cfg.respect_retry_after,
            max_cooldown: Duration::from_millis(cfg.max_cooldown_ms.max(cfg.cooldown_ms)),
            clock: ctx.clock(),
            circuit,
        }))
    }
}

/// Inspects upstream responses for retryable errors (`429`, `5xx`, `529`) in
/// `on_response_headers` and returns `Flow::RetryUpstream` to fail over automatically
/// to the next provider/model target.
pub struct AiFailoverPlugin {
    retry_statuses: HashSet<u16>,
    cooldown: Duration,
    failure_threshold: usize,
    respect_retry_after: bool,
    max_cooldown: Duration,
    clock: Arc<dyn Clock>,
    circuit: Option<Arc<FailoverCircuitState>>,
}

impl AiFailoverPlugin {
    fn target_key(upstream: &str, model: &str) -> String {
        format!("{upstream}::{model}")
    }
}

impl HttpPlugin for AiFailoverPlugin {
    fn name(&self) -> &str {
        "ai-failover"
    }

    fn hook_mask(&self) -> HookMask {
        if self.circuit.is_some() {
            HookMask::ON_UPSTREAM_SELECT | HookMask::ON_RESPONSE_HEADERS
        } else {
            HookMask::ON_RESPONSE_HEADERS
        }
    }

    fn on_upstream_select<'a>(
        &'a self,
        ctx: &'a mut RequestCtx,
        selection: &'a mut UpstreamSelection,
    ) -> HookResult<'a, Flow> {
        let Some(circuit) = &self.circuit else {
            return HookResult::Ready(Flow::Continue);
        };
        let request_id = ctx.request_id;
        let Some(meta) = ctx.get_ext_mut::<AiRequestMeta>() else {
            return HookResult::Ready(Flow::Continue);
        };

        let len = meta.targets.len();
        if len <= 1 {
            return HookResult::Ready(Flow::Continue);
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
                }
                break;
            }
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

        if !self.retry_statuses.contains(&status_code) {
            if res.status.is_success()
                && let Some(circuit) = &self.circuit
                && let Some((Some(target), _, _)) = &active_meta
            {
                circuit.record_success(&Self::target_key(&target.upstream, &target.model));
            }
            return HookResult::Ready(Flow::Continue);
        }

        if let Some((Some(target), max_attempts, requested_model)) = active_meta {
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
                circuit.record_failure(
                    &Self::target_key(&target.upstream, &target.model),
                    self.failure_threshold,
                    cd,
                    self.clock.now(),
                );
            }

            let event = FailoverEvent {
                attempt: ctx.attempt,
                provider: target.provider,
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

            if ctx.attempt < max_attempts {
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
                return HookResult::Ready(Flow::RetryUpstream);
            }

            return HookResult::Ready(Flow::Continue);
        }

        // Route without ai-model-router: still allow status-based retry on multi-attempt routes.
        HookResult::Ready(Flow::RetryUpstream)
    }
}
