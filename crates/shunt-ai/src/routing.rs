use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, RwLock};

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::pricing::PricingCatalog;
use crate::tokens::estimate_request_tokens;
use crate::types::{AiCapability, AiEndpointKind, AiTarget};

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
