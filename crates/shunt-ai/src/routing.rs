use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, RwLock};

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::pricing::PricingCatalog;
use crate::tokens::estimate_request_tokens;
use crate::types::{AiCapability, AiEndpointKind, AiTarget, RoutingStrategy, wildcard_match};

/// OpenRouter-compatible per-request `provider: { ... }` routing preferences parsed from
/// the incoming JSON body when `allow_request_routing_overrides = true`.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(default)]
pub struct ProviderRoutingPreferences {
    /// Preferred provider priority order (first matching providers tried first).
    pub order: Vec<String>,
    /// Restrict routing strictly to these providers (intersected with virtual-key `allowed_providers`).
    pub only: Vec<String>,
    /// Exclude these providers from routing.
    pub ignore: Vec<String>,
    /// Per-request strategy sort override: `"price"`/`"cost"`, `"latency"`, `"throughput"`, `"headroom"`.
    pub sort: Option<String>,
    /// When `Some(false)`, truncate candidate targets to a single attempt (no fallbacks).
    pub allow_fallbacks: Option<bool>,
    /// OpenRouter data collection policy (`"deny"` requires `target.zdr == true`).
    pub data_collection: Option<String>,
    /// Shorthand Zero Data Retention requirement (`true` requires `target.zdr == true`).
    pub zdr: Option<bool>,
    /// Compliance region filter (target must match at least one listed region).
    pub regions: Vec<String>,
    /// Compliance tag filter (target must match all listed tags).
    pub tags: Vec<String>,
}

impl ProviderRoutingPreferences {
    /// Returns `true` if Zero Data Retention (`zdr = true` or `data_collection = "deny"`) is requested.
    pub fn requires_zdr(&self) -> bool {
        self.zdr == Some(true)
            || self
                .data_collection
                .as_deref()
                .is_some_and(|v| v.eq_ignore_ascii_case("deny"))
    }

    /// Maps `provider.sort` to a [`RoutingStrategy`] if specified.
    pub fn sort_strategy(&self) -> Option<RoutingStrategy> {
        let raw = self.sort.as_deref()?.trim().to_ascii_lowercase();
        match raw.as_str() {
            "price" | "cost" => Some(RoutingStrategy::Cost),
            "latency" | "ttft" => Some(RoutingStrategy::Latency),
            "throughput" | "tps" => Some(RoutingStrategy::Throughput),
            "headroom" | "capacity" => Some(RoutingStrategy::Headroom),
            "priority" => Some(RoutingStrategy::Priority),
            _ => None,
        }
    }
}

/// Filters and reorders `targets` according to [`ProviderRoutingPreferences`].
///
/// Note: `only` only narrows the already-ACL-checked `targets` list, so client preferences can
/// never escalate privileges beyond `AiKeyPolicy::allowed_providers`.
pub fn apply_provider_preferences(
    targets: Vec<AiTarget>,
    prefs: &ProviderRoutingPreferences,
) -> Vec<AiTarget> {
    let require_zdr = prefs.requires_zdr();
    let mut filtered: Vec<AiTarget> = targets
        .into_iter()
        .filter(|t| {
            if !prefs.only.is_empty() && !prefs.only.iter().any(|p| wildcard_match(p, &t.provider))
            {
                return false;
            }
            if !prefs.ignore.is_empty()
                && prefs.ignore.iter().any(|p| wildcard_match(p, &t.provider))
            {
                return false;
            }
            if require_zdr && !t.zdr {
                return false;
            }
            if !t.matches_any_region(&prefs.regions) {
                return false;
            }
            if !t.matches_all_tags(&prefs.tags) {
                return false;
            }
            true
        })
        .collect();

    if !prefs.order.is_empty() && filtered.len() > 1 {
        filtered.sort_by_key(|t| {
            prefs
                .order
                .iter()
                .position(|p| wildcard_match(p, &t.provider))
                .unwrap_or(usize::MAX)
        });
    }

    filtered
}

/// Filters `targets` by context window capacity using `estimated_input_tokens` and optional
/// `safety_margin_tokens`. Targets without an explicit or catalog `context_window` are kept
/// (unbounded/unknown), while targets whose known window is `< required` are excluded.
pub fn filter_targets_by_context_window(
    targets: Vec<AiTarget>,
    catalog: &PricingCatalog,
    requested_model: &str,
    estimated_input_tokens: u64,
    safety_margin_tokens: u64,
) -> Vec<AiTarget> {
    let required = estimated_input_tokens.saturating_add(safety_margin_tokens);
    if required == 0 {
        return targets;
    }
    targets
        .into_iter()
        .filter(|t| {
            let effective_window = t.context_window.or_else(|| {
                catalog
                    .lookup(&t.model, requested_model)
                    .and_then(|p| p.max_input_tokens)
            });
            match effective_window {
                Some(win) => required <= win,
                None => true,
            }
        })
        .collect()
}

/// Extracts an optional end-user identifier from an AI request JSON payload:
/// OpenAI `user` string field or Anthropic `metadata.user_id`.
pub fn extract_end_user_from_body(body: &Value) -> Option<String> {
    if let Some(u) = body
        .get("user")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        return Some(u.to_owned());
    }
    body.get("metadata")
        .and_then(|m| m.get("user_id"))
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
}

/// Tuning parameters for [`RoutingStrategy::Throughput`] (EWMA output tokens/sec ranking).
#[derive(Debug, Clone, Copy, Deserialize, Serialize)]
#[serde(default)]
pub struct ThroughputRoutingConfig {
    /// EWMA smoothing factor `alpha` in `(0.0, 1.0]` (default: `0.3`).
    pub ewma_alpha: f64,
    /// Penalty divisor applied to EWMA error rate:
    /// `score = ewma_tps / (1.0 + error_penalty_weight * ewma_error_rate)` (default: `5.0`).
    pub error_penalty_weight: f64,
    /// Minimum observations per target before exiting cold-start exploration (default: `1`).
    pub min_samples: u64,
    /// Re-explore targets whose last observation is older than this window in ms (default: `60000`).
    pub stale_after_ms: u64,
}

impl Default for ThroughputRoutingConfig {
    fn default() -> Self {
        Self {
            ewma_alpha: 0.3,
            error_penalty_weight: 5.0,
            min_samples: 1,
            stale_after_ms: 60_000,
        }
    }
}

impl ThroughputRoutingConfig {
    pub fn validate(&self) -> Result<(), String> {
        if !self.ewma_alpha.is_finite() || self.ewma_alpha <= 0.0 || self.ewma_alpha > 1.0 {
            return Err("`throughput.ewma_alpha` must be a finite number in (0.0, 1.0]".to_owned());
        }
        if !self.error_penalty_weight.is_finite() || self.error_penalty_weight < 0.0 {
            return Err(
                "`throughput.error_penalty_weight` must be a non-negative finite number".to_owned(),
            );
        }
        Ok(())
    }
}

/// Per-target rolling EWMA output tokens/sec and error-rate snapshot.
#[derive(Debug, Clone, Copy)]
pub struct TargetThroughputStats {
    pub ewma_tps: f64,
    pub ewma_error_rate: f64,
    pub samples: u64,
    pub last_updated_ms: u64,
}

impl TargetThroughputStats {
    /// Effective routing score (higher is better):
    /// `ewma_tps / (1.0 + error_penalty_weight * ewma_error_rate)`.
    #[inline]
    pub fn score(&self, error_penalty_weight: f64) -> f64 {
        self.ewma_tps / (1.0 + error_penalty_weight * self.ewma_error_rate)
    }
}

/// Read-only snapshot of one EWMA throughput target for Admin Inspector APIs.
#[derive(Debug, Clone, Serialize)]
pub struct ThroughputEntrySnapshot {
    pub target: String,
    pub ewma_tps: f64,
    pub ewma_error_rate: f64,
    pub samples: u64,
    pub age_ms: u64,
}

/// `StateStore`-backed EWMA output tokens/sec table surviving snapshot reloads.
#[derive(Debug, Default)]
pub struct TargetThroughputTable {
    entries: RwLock<HashMap<String, TargetThroughputStats>>,
}

impl TargetThroughputTable {
    pub fn target_key(provider: &str, upstream: &str, model: &str) -> String {
        format!("{provider}::{upstream}::{model}")
    }

    pub fn snapshot_entries(&self, now_ms: u64) -> Vec<ThroughputEntrySnapshot> {
        let guard = self.entries.read().expect("TargetThroughputTable poisoned");
        let mut out: Vec<ThroughputEntrySnapshot> = guard
            .iter()
            .map(|(target, s)| ThroughputEntrySnapshot {
                target: target.clone(),
                ewma_tps: s.ewma_tps,
                ewma_error_rate: s.ewma_error_rate,
                samples: s.samples,
                age_ms: now_ms.saturating_sub(s.last_updated_ms),
            })
            .collect();
        out.sort_by(|a, b| a.target.cmp(&b.target));
        out
    }

    pub fn get(&self, key: &str) -> Option<TargetThroughputStats> {
        self.entries
            .read()
            .expect("TargetThroughputTable poisoned")
            .get(key)
            .copied()
    }

    /// Records a successful output throughput observation (tokens per second).
    pub fn record_success(&self, key: &str, tps: f64, alpha: f64, now_ms: u64) {
        let clamped = if tps.is_finite() && tps > 0.01 {
            tps
        } else {
            0.01
        };
        let mut guard = self
            .entries
            .write()
            .expect("TargetThroughputTable poisoned");
        let entry = guard
            .entry(key.to_owned())
            .or_insert(TargetThroughputStats {
                ewma_tps: clamped,
                ewma_error_rate: 0.0,
                samples: 0,
                last_updated_ms: now_ms,
            });
        if entry.samples == 0 {
            entry.ewma_tps = clamped;
            entry.ewma_error_rate = 0.0;
        } else {
            entry.ewma_tps = alpha * clamped + (1.0 - alpha) * entry.ewma_tps;
            entry.ewma_error_rate *= 1.0 - alpha;
        }
        entry.samples = entry.samples.saturating_add(1);
        entry.last_updated_ms = now_ms;
    }

    /// Records a failed attempt, penalizing error rate without distorting throughput estimate.
    pub fn record_error(&self, key: &str, alpha: f64, now_ms: u64) {
        const DEFAULT_COLD_ERROR_TPS: f64 = 1.0;
        let mut guard = self
            .entries
            .write()
            .expect("TargetThroughputTable poisoned");
        let entry = guard
            .entry(key.to_owned())
            .or_insert(TargetThroughputStats {
                ewma_tps: DEFAULT_COLD_ERROR_TPS,
                ewma_error_rate: 1.0,
                samples: 0,
                last_updated_ms: now_ms,
            });
        if entry.samples == 0 {
            entry.ewma_tps = DEFAULT_COLD_ERROR_TPS;
            entry.ewma_error_rate = 1.0;
        } else {
            entry.ewma_error_rate = alpha * 1.0 + (1.0 - alpha) * entry.ewma_error_rate;
        }
        entry.samples = entry.samples.saturating_add(1);
        entry.last_updated_ms = now_ms;
    }

    /// Ranks `targets` for [`RoutingStrategy::Throughput`]: explores cold/stale targets first,
    /// then ranks measured targets descending by effective tokens/sec score.
    pub fn order_targets(
        &self,
        targets: Vec<AiTarget>,
        cfg: &ThroughputRoutingConfig,
        now_ms: u64,
        explore_cursor: usize,
    ) -> Vec<AiTarget> {
        let len = targets.len();
        if len <= 1 {
            return targets;
        }

        let guard = self.entries.read().expect("TargetThroughputTable poisoned");
        let mut needs_probe: Vec<usize> = Vec::new();
        let mut measured: Vec<(usize, f64)> = Vec::new();

        for (idx, t) in targets.iter().enumerate() {
            let key = Self::target_key(&t.provider, &t.upstream, &t.model);
            match guard.get(&key) {
                Some(stats) => {
                    let is_cold = stats.samples < cfg.min_samples;
                    let is_stale = cfg.stale_after_ms > 0
                        && now_ms.saturating_sub(stats.last_updated_ms) >= cfg.stale_after_ms;
                    if is_cold || is_stale {
                        needs_probe.push(idx);
                    } else {
                        measured.push((idx, stats.score(cfg.error_penalty_weight)));
                    }
                }
                None => needs_probe.push(idx),
            }
        }
        drop(guard);

        // Higher throughput score is better; break ties by original index.
        measured.sort_by(|a, b| b.1.total_cmp(&a.1).then_with(|| a.0.cmp(&b.0)));

        let mut indexed: Vec<Option<AiTarget>> = targets.into_iter().map(Some).collect();
        let mut out = Vec::with_capacity(len);

        if !needs_probe.is_empty() {
            let rot = explore_cursor % needs_probe.len();
            for offset in 0..needs_probe.len() {
                let idx = needs_probe[(rot + offset) % needs_probe.len()];
                out.push(indexed[idx].take().unwrap());
            }
        }
        for (idx, _) in measured {
            out.push(indexed[idx].take().unwrap());
        }

        out
    }
}

/// Per-target live RPM/TPM headroom window state (combining local usage + upstream header hints).
#[derive(Debug, Clone, Copy, Default)]
struct TargetHeadroomState {
    window_id: u64,
    local_requests: u64,
    local_tokens: u64,
    header_rpm_limit: Option<u64>,
    header_rpm_remaining: Option<u64>,
    header_tpm_limit: Option<u64>,
    header_tpm_remaining: Option<u64>,
    header_updated_ms: u64,
}

/// Read-only snapshot of one headroom routing target for Admin Inspector APIs.
#[derive(Debug, Clone, Serialize)]
pub struct HeadroomEntrySnapshot {
    pub target: String,
    pub local_requests: u64,
    pub local_tokens: u64,
    pub header_rpm_remaining: Option<u64>,
    pub header_tpm_remaining: Option<u64>,
}

/// `StateStore`-backed upstream RPM/TPM headroom table powering [`RoutingStrategy::Headroom`].
#[derive(Debug, Default)]
pub struct TargetHeadroomTable {
    entries: RwLock<HashMap<String, TargetHeadroomState>>,
}

const HEADROOM_WINDOW_MS: u64 = 60_000;
const HEADROOM_HEADER_FRESH_MS: u64 = 60_000;

impl TargetHeadroomTable {
    pub fn target_key(provider: &str, upstream: &str, model: &str) -> String {
        format!("{provider}::{upstream}::{model}")
    }

    pub fn snapshot_entries(&self, now_ms: u64) -> Vec<HeadroomEntrySnapshot> {
        let win = now_ms / HEADROOM_WINDOW_MS;
        let guard = self.entries.read().expect("TargetHeadroomTable poisoned");
        let mut out: Vec<HeadroomEntrySnapshot> = guard
            .iter()
            .map(|(target, s)| {
                let (local_requests, local_tokens) = if s.window_id == win {
                    (s.local_requests, s.local_tokens)
                } else {
                    (0, 0)
                };
                HeadroomEntrySnapshot {
                    target: target.clone(),
                    local_requests,
                    local_tokens,
                    header_rpm_remaining: s.header_rpm_remaining,
                    header_tpm_remaining: s.header_tpm_remaining,
                }
            })
            .collect();
        out.sort_by(|a, b| a.target.cmp(&b.target));
        out
    }

    /// Records a dispatched request and estimated/actual token count against the current 60s window.
    pub fn record_usage(&self, key: &str, requests: u64, tokens: u64, now_ms: u64) {
        let win = now_ms / HEADROOM_WINDOW_MS;
        let mut guard = self.entries.write().expect("TargetHeadroomTable poisoned");
        let entry = guard.entry(key.to_owned()).or_default();
        if entry.window_id != win {
            entry.window_id = win;
            entry.local_requests = 0;
            entry.local_tokens = 0;
        }
        entry.local_requests = entry.local_requests.saturating_add(requests);
        entry.local_tokens = entry.local_tokens.saturating_add(tokens);
    }

    /// Incorporates authoritative upstream rate-limit response headers (OpenAI / Anthropic).
    pub fn record_upstream_headers(
        &self,
        key: &str,
        rpm_limit: Option<u64>,
        rpm_remaining: Option<u64>,
        tpm_limit: Option<u64>,
        tpm_remaining: Option<u64>,
        now_ms: u64,
    ) {
        if rpm_limit.is_none()
            && rpm_remaining.is_none()
            && tpm_limit.is_none()
            && tpm_remaining.is_none()
        {
            return;
        }
        let mut guard = self.entries.write().expect("TargetHeadroomTable poisoned");
        let entry = guard.entry(key.to_owned()).or_default();
        if let Some(v) = rpm_limit {
            entry.header_rpm_limit = Some(v);
        }
        if let Some(v) = rpm_remaining {
            entry.header_rpm_remaining = Some(v);
        }
        if let Some(v) = tpm_limit {
            entry.header_tpm_limit = Some(v);
        }
        if let Some(v) = tpm_remaining {
            entry.header_tpm_remaining = Some(v);
        }
        entry.header_updated_ms = now_ms;
    }

    /// Computes remaining capacity headroom ratio in `[0.0, 1.0]` for `target` (higher = more free headroom).
    pub fn headroom_ratio(&self, target: &AiTarget, now_ms: u64) -> f64 {
        let key = Self::target_key(&target.provider, &target.upstream, &target.model);
        let guard = self.entries.read().expect("TargetHeadroomTable poisoned");
        let Some(s) = guard.get(&key) else {
            return 1.0;
        };

        let win = now_ms / HEADROOM_WINDOW_MS;
        let (local_req, local_tok) = if s.window_id == win {
            (s.local_requests, s.local_tokens)
        } else {
            (0, 0)
        };
        let header_fresh = now_ms.saturating_sub(s.header_updated_ms) < HEADROOM_HEADER_FRESH_MS;

        let mut ratio = 1.0f64;

        if let Some(rpm_lim) = target.upstream_rpm.filter(|&v| v > 0) {
            let rem = rpm_lim.saturating_sub(local_req) as f64;
            ratio = ratio.min((rem / (rpm_lim as f64)).clamp(0.0, 1.0));
        }
        if let Some(tpm_lim) = target.upstream_tpm.filter(|&v| v > 0) {
            let rem = tpm_lim.saturating_sub(local_tok) as f64;
            ratio = ratio.min((rem / (tpm_lim as f64)).clamp(0.0, 1.0));
        }
        if header_fresh {
            if let (Some(rem), Some(lim)) = (
                s.header_rpm_remaining,
                s.header_rpm_limit
                    .or(target.upstream_rpm)
                    .filter(|&v| v > 0),
            ) {
                ratio = ratio.min(((rem as f64) / (lim as f64)).clamp(0.0, 1.0));
            }
            if let (Some(rem), Some(lim)) = (
                s.header_tpm_remaining,
                s.header_tpm_limit
                    .or(target.upstream_tpm)
                    .filter(|&v| v > 0),
            ) {
                ratio = ratio.min(((rem as f64) / (lim as f64)).clamp(0.0, 1.0));
            }
        }

        ratio
    }

    /// Orders `targets` descending by remaining RPM/TPM headroom ratio, breaking ties by
    /// original configured order.
    pub fn order_targets(&self, targets: Vec<AiTarget>, now_ms: u64) -> Vec<AiTarget> {
        if targets.len() <= 1 {
            return targets;
        }
        let mut scored: Vec<(usize, f64, AiTarget)> = targets
            .into_iter()
            .enumerate()
            .map(|(idx, t)| {
                let ratio = self.headroom_ratio(&t, now_ms);
                (idx, ratio, t)
            })
            .collect();
        scored.sort_by(|a, b| b.1.total_cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
        scored.into_iter().map(|(_, _, t)| t).collect()
    }
}

/// Policy for ranking targets whose models have no entry in [`PricingCatalog`] during
/// [`crate::RoutingStrategy::Cost`] routing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum UnknownCostPolicy {
    /// Rank unpriced targets last (`u64::MAX`) so explicitly priced models are chosen first.
    #[default]
    Last,
    /// Treat unpriced targets (e.g., self-hosted local vLLM/Ollama models) as `$0.00`.
    Free,
}

/// Tuning parameters for [`crate::RoutingStrategy::Latency`] (EWMA TTFT/TTFB & error-rate ranking).
#[derive(Debug, Clone, Copy, Deserialize, Serialize)]
#[serde(default)]
pub struct LatencyRoutingConfig {
    /// EWMA smoothing factor `alpha` in `(0.0, 1.0]` (default: `0.3`).
    pub ewma_alpha: f64,
    /// Penalty multiplier applied to EWMA error rate:
    /// `score = ewma_latency_ms * (1.0 + error_penalty_weight * ewma_error_rate)` (default: `5.0`).
    pub error_penalty_weight: f64,
    /// Minimum observations per target before exiting cold-start exploration (default: `1`).
    pub min_samples: u64,
    /// Re-explore targets whose last observation is older than this window in ms (default: `60000`).
    /// Set to `0` to disable staleness re-exploration.
    pub stale_after_ms: u64,
}

impl Default for LatencyRoutingConfig {
    fn default() -> Self {
        Self {
            ewma_alpha: 0.3,
            error_penalty_weight: 5.0,
            min_samples: 1,
            stale_after_ms: 60_000,
        }
    }
}

impl LatencyRoutingConfig {
    pub fn validate(&self) -> Result<(), String> {
        if !self.ewma_alpha.is_finite() || self.ewma_alpha <= 0.0 || self.ewma_alpha > 1.0 {
            return Err("`latency.ewma_alpha` must be a finite number in (0.0, 1.0]".to_owned());
        }
        if !self.error_penalty_weight.is_finite() || self.error_penalty_weight < 0.0 {
            return Err(
                "`latency.error_penalty_weight` must be a non-negative finite number".to_owned(),
            );
        }
        Ok(())
    }
}

/// Inspects a parsed JSON AI request body across OpenAI Chat, Anthropic Messages, OpenAI Responses,
/// and Embeddings to detect all capabilities required to serve the request faithfully.
pub fn detect_required_capabilities(endpoint: AiEndpointKind, body: &Value) -> Vec<AiCapability> {
    let mut caps = Vec::with_capacity(4);

    match endpoint {
        AiEndpointKind::Embeddings => {
            caps.push(AiCapability::Embeddings);
            return caps;
        }
        AiEndpointKind::Rerank => {
            caps.push(AiCapability::Rerank);
            return caps;
        }
        AiEndpointKind::Moderations => {
            caps.push(AiCapability::Moderations);
            return caps;
        }
        AiEndpointKind::ImagesGenerations
        | AiEndpointKind::ImagesEdits
        | AiEndpointKind::ImagesVariations => {
            caps.push(AiCapability::Images);
            return caps;
        }
        AiEndpointKind::AudioSpeech
        | AiEndpointKind::AudioTranscriptions
        | AiEndpointKind::AudioTranslations => {
            caps.push(AiCapability::Audio);
            return caps;
        }
        AiEndpointKind::Realtime => {
            caps.push(AiCapability::Realtime);
            return caps;
        }
        AiEndpointKind::Files => {
            caps.push(AiCapability::Files);
            return caps;
        }
        AiEndpointKind::Batches => {
            caps.push(AiCapability::Batches);
            return caps;
        }
        AiEndpointKind::Completions => {
            caps.push(AiCapability::Completions);
            if body.get("stream").and_then(Value::as_bool) == Some(true) {
                caps.push(AiCapability::Streaming);
            }
            return caps;
        }
        AiEndpointKind::ModelsList
        | AiEndpointKind::ModelRetrieve
        | AiEndpointKind::GenerationRetrieve => {
            return caps;
        }
        AiEndpointKind::ChatCompletions
        | AiEndpointKind::AnthropicMessages
        | AiEndpointKind::AnthropicCountTokens
        | AiEndpointKind::OpenAiResponses => {
            caps.push(AiCapability::Chat);
        }
    }

    // Streaming
    if endpoint.is_conversational() && body.get("stream").and_then(Value::as_bool) == Some(true) {
        caps.push(AiCapability::Streaming);
    }

    // Tool calling (OpenAI Chat / Anthropic Messages / OpenAI Responses / legacy functions)
    let has_tools = body
        .get("tools")
        .and_then(Value::as_array)
        .is_some_and(|a| !a.is_empty())
        || body
            .get("functions")
            .and_then(Value::as_array)
            .is_some_and(|a| !a.is_empty());
    if has_tools {
        caps.push(AiCapability::Tools);
    }

    // Vision / multimodal image content
    if body_contains_vision(body) {
        caps.push(AiCapability::Vision);
    }

    // Structured output / JSON schema
    let has_json_schema = body
        .get("response_format")
        .and_then(|rf| rf.get("type"))
        .and_then(Value::as_str)
        .is_some_and(|t| matches!(t, "json_schema" | "json_object"))
        || body
            .get("text")
            .and_then(|t| t.get("format"))
            .and_then(|f| f.get("type"))
            .and_then(Value::as_str)
            .is_some_and(|t| matches!(t, "json_schema" | "json_object"));
    if has_json_schema {
        caps.push(AiCapability::JsonSchema);
    }

    // Reasoning / extended thinking
    let has_reasoning = body.get("reasoning_effort").is_some_and(|v| !v.is_null())
        || body
            .get("reasoning")
            .and_then(|r| r.get("effort"))
            .is_some_and(|v| !v.is_null())
        || body
            .get("thinking")
            .and_then(|t| t.get("type"))
            .and_then(Value::as_str)
            == Some("enabled");
    if has_reasoning {
        caps.push(AiCapability::Reasoning);
    }

    caps
}

fn body_contains_vision(body: &Value) -> bool {
    if let Some(messages) = body.get("messages").and_then(Value::as_array) {
        for msg in messages {
            if let Some(parts) = msg.get("content").and_then(Value::as_array)
                && parts.iter().any(is_vision_content_part)
            {
                return true;
            }
        }
    }

    if let Some(inputs) = body.get("input").and_then(Value::as_array) {
        for item in inputs {
            if is_vision_content_part(item) {
                return true;
            }
            if let Some(parts) = item.get("content").and_then(Value::as_array)
                && parts.iter().any(is_vision_content_part)
            {
                return true;
            }
        }
    }

    false
}

fn is_vision_content_part(part: &Value) -> bool {
    matches!(
        part.get("type").and_then(Value::as_str),
        Some("image_url" | "input_image" | "image")
    )
}

/// Lock-free per-group atomic cursors stored in `StateStore` so smooth weighted splits and
/// latency cold-start exploration survive snapshot reloads cleanly.
#[derive(Debug, Default)]
pub struct RoutingCursorTable {
    cursors: RwLock<HashMap<String, Arc<AtomicUsize>>>,
}

impl RoutingCursorTable {
    pub fn next(&self, group_key: &str) -> usize {
        if let Some(counter) = self
            .cursors
            .read()
            .expect("RoutingCursorTable poisoned")
            .get(group_key)
        {
            return counter.fetch_add(1, Ordering::Relaxed);
        }
        let mut guard = self.cursors.write().expect("RoutingCursorTable poisoned");
        let counter = guard
            .entry(group_key.to_owned())
            .or_insert_with(|| Arc::new(AtomicUsize::new(0)));
        counter.fetch_add(1, Ordering::Relaxed)
    }
}

const fn gcd_u32(mut a: u32, mut b: u32) -> u32 {
    while b != 0 {
        let r = a % b;
        a = b;
        b = r;
    }
    a
}

/// Selects primary target index via smooth weighted round-robin (GCD-reduced Nginx SWRR).
pub fn pick_weighted_primary(weights: &[u32], cursor: usize) -> usize {
    let len = weights.len();
    debug_assert!(len > 0);
    if len == 1 {
        return 0;
    }
    let norm: Vec<u32> = weights.iter().map(|&w| w.max(1)).collect();
    if norm.iter().all(|&w| w == norm[0]) {
        return cursor % len;
    }

    let g = norm.iter().copied().reduce(gcd_u32).unwrap_or(1).max(1);
    let reduced: Vec<u32> = norm.iter().map(|&w| w / g).collect();
    let total: usize = reduced.iter().map(|&w| w as usize).sum();

    if total > 0 && total <= 4096 {
        let slot = cursor % total;
        let mut current = vec![0i64; len];
        let total_i64 = total as i64;
        let mut chosen = 0usize;
        for step in 0..=slot {
            let mut best_idx = 0usize;
            let mut best_val = i64::MIN;
            for (i, &w) in reduced.iter().enumerate() {
                current[i] += w as i64;
                if current[i] > best_val {
                    best_val = current[i];
                    best_idx = i;
                }
            }
            current[best_idx] -= total_i64;
            if step == slot {
                chosen = best_idx;
            }
        }
        return chosen;
    }

    // Fallback for huge co-prime weight sums.
    let total_w: u64 = norm.iter().map(|&w| w as u64).sum();
    let mut target = (cursor as u64).wrapping_mul(2_654_435_761) % total_w;
    for (i, &w) in norm.iter().enumerate() {
        let w64 = w as u64;
        if target < w64 {
            return i;
        }
        target -= w64;
    }
    0
}

/// Orders `targets` for [`crate::RoutingStrategy::Weighted`]: selects the smooth weighted primary
/// using `cursor`, followed by remaining targets ordered by descending weight (cyclic tie-break)
/// so failover never retries the failed primary first.
pub fn order_weighted_targets(targets: Vec<AiTarget>, cursor: usize) -> Vec<AiTarget> {
    let len = targets.len();
    if len <= 1 {
        return targets;
    }

    let weights: Vec<u32> = targets.iter().map(|t| t.weight.max(1)).collect();
    let primary_idx = pick_weighted_primary(&weights, cursor);

    let mut remaining: Vec<usize> = (1..len).map(|off| (primary_idx + off) % len).collect();
    remaining.sort_by(|&a, &b| weights[b].cmp(&weights[a]));

    let mut indexed: Vec<Option<AiTarget>> = targets.into_iter().map(Some).collect();
    let mut out = Vec::with_capacity(len);
    out.push(indexed[primary_idx].take().unwrap());
    for idx in remaining {
        out.push(indexed[idx].take().unwrap());
    }
    out
}

/// Per-target rolling EWMA latency and error-rate snapshot.
#[derive(Debug, Clone, Copy)]
pub struct TargetLatencyStats {
    pub ewma_latency_ms: f64,
    pub ewma_error_rate: f64,
    pub samples: u64,
    pub last_updated_ms: u64,
}

impl TargetLatencyStats {
    /// Effective routing score (lower is better):
    /// `ewma_latency_ms * (1.0 + error_penalty_weight * ewma_error_rate)`.
    #[inline]
    pub fn score(&self, error_penalty_weight: f64) -> f64 {
        self.ewma_latency_ms * (1.0 + error_penalty_weight * self.ewma_error_rate)
    }
}

/// Read-only snapshot of one EWMA latency target for Admin Inspector APIs.
#[derive(Debug, Clone, Serialize)]
pub struct LatencyEntrySnapshot {
    pub target: String,
    pub ewma_latency_ms: f64,
    pub ewma_error_rate: f64,
    pub samples: u64,
    pub age_ms: u64,
}

/// `StateStore`-backed EWMA TTFT/latency and error-rate table surviving snapshot reloads.
#[derive(Debug, Default)]
pub struct TargetLatencyTable {
    entries: RwLock<HashMap<String, TargetLatencyStats>>,
}

impl TargetLatencyTable {
    pub fn target_key(provider: &str, upstream: &str, model: &str) -> String {
        format!("{provider}::{upstream}::{model}")
    }

    pub fn snapshot_entries(&self, now_ms: u64) -> Vec<LatencyEntrySnapshot> {
        let guard = self.entries.read().expect("TargetLatencyTable poisoned");
        let mut out: Vec<LatencyEntrySnapshot> = guard
            .iter()
            .map(|(target, s)| LatencyEntrySnapshot {
                target: target.clone(),
                ewma_latency_ms: s.ewma_latency_ms,
                ewma_error_rate: s.ewma_error_rate,
                samples: s.samples,
                age_ms: now_ms.saturating_sub(s.last_updated_ms),
            })
            .collect();
        out.sort_by(|a, b| a.target.cmp(&b.target));
        out
    }

    pub fn get(&self, key: &str) -> Option<TargetLatencyStats> {
        self.entries
            .read()
            .expect("TargetLatencyTable poisoned")
            .get(key)
            .copied()
    }

    /// Records a successful request latency observation (TTFT or TTFB in milliseconds).
    pub fn record_success(&self, key: &str, latency_ms: f64, alpha: f64, now_ms: u64) {
        let clamped_ms = if latency_ms.is_finite() && latency_ms > 0.1 {
            latency_ms
        } else {
            0.1
        };
        let mut guard = self.entries.write().expect("TargetLatencyTable poisoned");
        let entry = guard.entry(key.to_owned()).or_insert(TargetLatencyStats {
            ewma_latency_ms: clamped_ms,
            ewma_error_rate: 0.0,
            samples: 0,
            last_updated_ms: now_ms,
        });
        if entry.samples == 0 {
            entry.ewma_latency_ms = clamped_ms;
            entry.ewma_error_rate = 0.0;
        } else {
            entry.ewma_latency_ms = alpha * clamped_ms + (1.0 - alpha) * entry.ewma_latency_ms;
            entry.ewma_error_rate *= 1.0 - alpha;
        }
        entry.samples = entry.samples.saturating_add(1);
        entry.last_updated_ms = now_ms;
    }

    /// Records a failed attempt (`429`/`5xx`/`529` or transport error).
    ///
    /// Deliberately does NOT lower `ewma_latency_ms` using fast error responses (e.g., a 2ms `429`),
    /// instead increasing `ewma_error_rate` toward `1.0` so unhealthy targets are penalized.
    pub fn record_error(&self, key: &str, alpha: f64, now_ms: u64) {
        const DEFAULT_COLD_ERROR_LATENCY_MS: f64 = 1_000.0;
        let mut guard = self.entries.write().expect("TargetLatencyTable poisoned");
        let entry = guard.entry(key.to_owned()).or_insert(TargetLatencyStats {
            ewma_latency_ms: DEFAULT_COLD_ERROR_LATENCY_MS,
            ewma_error_rate: 1.0,
            samples: 0,
            last_updated_ms: now_ms,
        });
        if entry.samples == 0 {
            entry.ewma_latency_ms = DEFAULT_COLD_ERROR_LATENCY_MS;
            entry.ewma_error_rate = 1.0;
        } else {
            entry.ewma_error_rate = alpha * 1.0 + (1.0 - alpha) * entry.ewma_error_rate;
        }
        entry.samples = entry.samples.saturating_add(1);
        entry.last_updated_ms = now_ms;
    }

    /// Ranks `targets` for [`crate::RoutingStrategy::Latency`].
    ///
    /// Cold-start (`samples < min_samples`) or stale (`now_ms - last_updated_ms >= stale_after_ms`)
    /// targets are explored first in deterministic round-robin order using `explore_cursor`,
    /// followed by measured targets sorted ascending by effective latency+error score.
    pub fn order_targets(
        &self,
        targets: Vec<AiTarget>,
        cfg: &LatencyRoutingConfig,
        now_ms: u64,
        explore_cursor: usize,
    ) -> Vec<AiTarget> {
        let len = targets.len();
        if len <= 1 {
            return targets;
        }

        let guard = self.entries.read().expect("TargetLatencyTable poisoned");
        let mut needs_probe: Vec<usize> = Vec::new();
        let mut measured: Vec<(usize, f64)> = Vec::new();

        for (idx, t) in targets.iter().enumerate() {
            let key = Self::target_key(&t.provider, &t.upstream, &t.model);
            match guard.get(&key) {
                Some(stats) => {
                    let is_cold = stats.samples < cfg.min_samples;
                    let is_stale = cfg.stale_after_ms > 0
                        && now_ms.saturating_sub(stats.last_updated_ms) >= cfg.stale_after_ms;
                    if is_cold || is_stale {
                        needs_probe.push(idx);
                    } else {
                        measured.push((idx, stats.score(cfg.error_penalty_weight)));
                    }
                }
                None => needs_probe.push(idx),
            }
        }
        drop(guard);

        measured.sort_by(|a, b| a.1.total_cmp(&b.1).then_with(|| a.0.cmp(&b.0)));

        let mut indexed: Vec<Option<AiTarget>> = targets.into_iter().map(Some).collect();
        let mut out = Vec::with_capacity(len);

        if !needs_probe.is_empty() {
            let rot = explore_cursor % needs_probe.len();
            for offset in 0..needs_probe.len() {
                let idx = needs_probe[(rot + offset) % needs_probe.len()];
                out.push(indexed[idx].take().unwrap());
            }
        }
        for (idx, _) in measured {
            out.push(indexed[idx].take().unwrap());
        }

        out
    }
}

/// Orders `targets` for [`crate::RoutingStrategy::Cost`] by estimated exact nano-USD request cost
/// (ascending), breaking ties by original configured target order.
pub fn order_cost_targets(
    targets: Vec<AiTarget>,
    catalog: &PricingCatalog,
    endpoint: AiEndpointKind,
    requested_model: &str,
    raw_body: &[u8],
    default_output_tokens: u64,
    unknown_policy: UnknownCostPolicy,
) -> Vec<AiTarget> {
    if targets.len() <= 1 {
        return targets;
    }

    let est = estimate_request_tokens(endpoint, raw_body);
    let est_output = match endpoint {
        AiEndpointKind::Embeddings => 0,
        _ => match est.requested_max_output {
            Some(max_out) if default_output_tokens > 0 => max_out.min(default_output_tokens),
            Some(max_out) => max_out,
            None => default_output_tokens,
        },
    };

    let mut scored: Vec<(usize, u64, AiTarget)> = targets
        .into_iter()
        .enumerate()
        .map(|(idx, t)| {
            let cost = match catalog.lookup(&t.model, requested_model) {
                Some(pricing) => pricing.cost_nano_usd(est.input_tokens, 0, est_output),
                None => match unknown_policy {
                    UnknownCostPolicy::Last => u64::MAX,
                    UnknownCostPolicy::Free => 0,
                },
            };
            (idx, cost, t)
        })
        .collect();

    scored.sort_by(|a, b| a.1.cmp(&b.1).then_with(|| a.0.cmp(&b.0)));
    scored.into_iter().map(|(_, _, t)| t).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn mk_target(provider: &str, model: &str, weight: u32) -> AiTarget {
        AiTarget {
            provider: provider.to_owned(),
            upstream: provider.to_owned(),
            model: model.to_owned(),
            endpoint_override: None,
            capabilities: Vec::new(),
            weight,
            default_params: std::collections::BTreeMap::new(),
            override_params: std::collections::BTreeMap::new(),
            context_window: None,
            max_output_tokens: None,
            zdr: false,
            regions: Vec::new(),
            tags: Vec::new(),
            upstream_rpm: None,
            upstream_tpm: None,
            ttft_timeout_ms: None,
        }
    }

    #[test]
    fn detects_capabilities_across_all_ingress_protocols() {
        // OpenAI Chat: streaming + tools + vision + json_schema + reasoning
        let openai_body = json!({
            "model": "smart",
            "stream": true,
            "reasoning_effort": "high",
            "response_format": { "type": "json_schema", "json_schema": { "name": "out" } },
            "tools": [{ "type": "function", "function": { "name": "calc" } }],
            "messages": [{
                "role": "user",
                "content": [
                    { "type": "text", "text": "describe" },
                    { "type": "image_url", "image_url": { "url": "https://example.com/a.png" } }
                ]
            }]
        });
        let caps = detect_required_capabilities(AiEndpointKind::ChatCompletions, &openai_body);
        assert!(caps.contains(&AiCapability::Chat));
        assert!(caps.contains(&AiCapability::Streaming));
        assert!(caps.contains(&AiCapability::Tools));
        assert!(caps.contains(&AiCapability::Vision));
        assert!(caps.contains(&AiCapability::JsonSchema));
        assert!(caps.contains(&AiCapability::Reasoning));

        // Anthropic Messages: vision + thinking
        let anth_body = json!({
            "model": "claude",
            "thinking": { "type": "enabled", "budget_tokens": 1024 },
            "messages": [{
                "role": "user",
                "content": [{ "type": "image", "source": { "type": "base64", "data": "..." } }]
            }]
        });
        let anth_caps = detect_required_capabilities(AiEndpointKind::AnthropicMessages, &anth_body);
        assert!(anth_caps.contains(&AiCapability::Chat));
        assert!(anth_caps.contains(&AiCapability::Vision));
        assert!(anth_caps.contains(&AiCapability::Reasoning));
        assert!(!anth_caps.contains(&AiCapability::Tools));
        assert!(!anth_caps.contains(&AiCapability::Streaming));

        // OpenAI Responses: input_image + text.format json_schema + reasoning.effort
        let resp_body = json!({
            "model": "gpt-4o",
            "reasoning": { "effort": "medium" },
            "text": { "format": { "type": "json_object" } },
            "input": [{
                "role": "user",
                "content": [{ "type": "input_image", "image_url": "https://example.com/b.png" }]
            }]
        });
        let resp_caps = detect_required_capabilities(AiEndpointKind::OpenAiResponses, &resp_body);
        assert!(resp_caps.contains(&AiCapability::Chat));
        assert!(resp_caps.contains(&AiCapability::Vision));
        assert!(resp_caps.contains(&AiCapability::JsonSchema));
        assert!(resp_caps.contains(&AiCapability::Reasoning));

        // Embeddings
        let emb_caps = detect_required_capabilities(
            AiEndpointKind::Embeddings,
            &json!({"model": "text-embedding-3-small", "input": "hi"}),
        );
        assert_eq!(emb_caps, vec![AiCapability::Embeddings]);
    }

    #[test]
    fn weighted_ordering_distributes_smoothly_and_preserves_failover_uniqueness() {
        let targets = vec![
            mk_target("primary", "m1", 80),
            mk_target("canary", "m2", 20),
        ];
        let mut primary_hits = 0usize;
        let mut canary_hits = 0usize;
        for c in 0..10 {
            let ordered = order_weighted_targets(targets.clone(), c);
            assert_eq!(ordered.len(), 2);
            assert_ne!(ordered[0].provider, ordered[1].provider);
            if ordered[0].provider == "primary" {
                primary_hits += 1;
            } else {
                canary_hits += 1;
            }
        }
        assert_eq!(primary_hits, 8);
        assert_eq!(canary_hits, 2);
    }

    #[test]
    fn latency_ranking_prefers_fastest_healthy_and_penalizes_errors() {
        let table = TargetLatencyTable::default();
        let cfg = LatencyRoutingConfig::default();
        let targets = vec![
            mk_target("slow", "m-slow", 1),
            mk_target("fast", "m-fast", 1),
            mk_target("flaky", "m-flaky", 1),
        ];

        // Cold-start rotates through all unmeasured targets
        let c0 = table.order_targets(targets.clone(), &cfg, 100, 0);
        let c1 = table.order_targets(targets.clone(), &cfg, 100, 1);
        assert_eq!(c0[0].provider, "slow");
        assert_eq!(c1[0].provider, "fast");

        // Record observations
        table.record_success("slow::slow::m-slow", 800.0, cfg.ewma_alpha, 1_000);
        table.record_success("fast::fast::m-fast", 120.0, cfg.ewma_alpha, 1_000);
        table.record_success("flaky::flaky::m-flaky", 100.0, cfg.ewma_alpha, 1_000);
        table.record_error("flaky::flaky::m-flaky", cfg.ewma_alpha, 1_010);
        table.record_error("flaky::flaky::m-flaky", cfg.ewma_alpha, 1_020);

        // fast (120ms, 0% err) beats flaky (100ms, ~51% err -> score ~355ms) beats slow (800ms)
        let ranked = table.order_targets(targets.clone(), &cfg, 2_000, 0);
        let names: Vec<&str> = ranked.iter().map(|t| t.provider.as_str()).collect();
        assert_eq!(names, vec!["fast", "flaky", "slow"]);

        // After stale_after_ms elapses for slow, slow gets re-explored
        table.record_success("fast::fast::m-fast", 120.0, cfg.ewma_alpha, 70_000);
        table.record_success("flaky::flaky::m-flaky", 250.0, cfg.ewma_alpha, 70_000);
        let reexplore = table.order_targets(targets, &cfg, 70_000, 0);
        assert_eq!(reexplore[0].provider, "slow");
    }

    #[test]
    fn cost_ranking_selects_cheapest_model_first() {
        let cat = PricingCatalog::new(HashMap::new(), true, None).unwrap();
        let targets = vec![
            mk_target("openai", "gpt-4o", 1),
            mk_target("anthropic", "claude-3-5-haiku-20241022", 1),
            mk_target("openai", "gpt-4o-mini", 1),
            mk_target("local", "unknown-local", 1),
        ];
        let body = br#"{"model":"smart","messages":[{"role":"user","content":"hello world"}]}"#;
        let ranked = order_cost_targets(
            targets,
            &cat,
            AiEndpointKind::ChatCompletions,
            "smart",
            body,
            256,
            UnknownCostPolicy::Last,
        );
        let models: Vec<&str> = ranked.iter().map(|t| t.model.as_str()).collect();
        // gpt-4o-mini ($0.15/$0.60) < claude-3-5-haiku ($0.80/$4.00) < gpt-4o ($2.50/$10.00) < unknown
        assert_eq!(
            models,
            vec![
                "gpt-4o-mini",
                "claude-3-5-haiku-20241022",
                "gpt-4o",
                "unknown-local"
            ]
        );
    }
}
