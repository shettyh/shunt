use serde::Serialize;
use shunt_plugin_sdk::{Clock, StateStore};

use crate::cache::AiCacheTable;
use crate::failover::{CooldownSnapshot, FailoverCircuitState};
use crate::presets::{KeyPoolSnapshot, KeyPoolTable};
use crate::routing::{LatencyEntrySnapshot, TargetLatencyTable};
use crate::usage_tracker::{AiMetrics, AiMetricsSnapshot, AiModelBreakdown};

#[derive(Debug, Clone, Serialize)]
pub struct ScopedKeyPoolSnapshot {
    pub scope: String,
    #[serde(flatten)]
    pub entry: KeyPoolSnapshot,
}

#[derive(Debug, Clone, Serialize)]
pub struct ScopedCooldownSnapshot {
    pub scope: String,
    #[serde(flatten)]
    pub entry: CooldownSnapshot,
}

#[derive(Debug, Clone, Serialize)]
pub struct ScopedLatencySnapshot {
    pub scope: String,
    #[serde(flatten)]
    pub entry: LatencyEntrySnapshot,
}

#[derive(Debug, Clone, Serialize)]
pub struct ScopedCacheSnapshot {
    pub scope: String,
    pub entries: usize,
    pub total_bytes: usize,
}

/// Complete read-only AI runtime state exposed via the Admin Inspector `/api/status` extension hook.
#[derive(Debug, Clone, Serialize)]
pub struct AiRuntimeInspect {
    pub totals: AiMetricsSnapshot,
    pub models: Vec<AiModelBreakdown>,
    pub cooldowns: Vec<ScopedCooldownSnapshot>,
    pub latency_targets: Vec<ScopedLatencySnapshot>,
    pub caches: Vec<ScopedCacheSnapshot>,
    pub key_pools: Vec<ScopedKeyPoolSnapshot>,
}

/// Collects a point-in-time read-only inspection payload covering AI usage totals,
/// per-model breakdowns, active failover cooldowns, EWMA smart-routing stats, and cache utilization.
///
/// Built purely on `shunt-plugin-sdk`'s generic `StateStore::collect_by_type` so neither
/// `shunt-core` nor `shunt-config` knows anything about AI concepts.
pub fn inspect_ai_runtime(
    metrics: &AiMetrics,
    state_store: &StateStore,
    clock: &dyn Clock,
) -> serde_json::Value {
    let detailed = metrics.detailed_snapshot();
    let now = clock.now();
    let now_ms = clock.now_ms();

    let mut cooldowns = Vec::new();
    for (scope, _key, circuit) in state_store.collect_by_type::<FailoverCircuitState>() {
        for entry in circuit.snapshot_cooldowns(now) {
            cooldowns.push(ScopedCooldownSnapshot {
                scope: scope.clone(),
                entry,
            });
        }
    }

    let mut latency_targets = Vec::new();
    for (scope, _key, table) in state_store.collect_by_type::<TargetLatencyTable>() {
        for entry in table.snapshot_entries(now_ms) {
            latency_targets.push(ScopedLatencySnapshot {
                scope: scope.clone(),
                entry,
            });
        }
    }

    let mut caches = Vec::new();
    for (scope, _key, table) in state_store.collect_by_type::<AiCacheTable>() {
        let (entries, total_bytes) = table.snapshot_stats();
        caches.push(ScopedCacheSnapshot {
            scope,
            entries,
            total_bytes,
        });
    }

    let mut key_pools = Vec::new();
    for (scope, _key, table) in state_store.collect_by_type::<KeyPoolTable>() {
        for entry in table.snapshot_pools(now) {
            key_pools.push(ScopedKeyPoolSnapshot {
                scope: scope.clone(),
                entry,
            });
        }
    }

    let report = AiRuntimeInspect {
        totals: detailed.totals,
        models: detailed.models,
        cooldowns,
        latency_targets,
        caches,
        key_pools,
    };

    serde_json::to_value(&report).unwrap_or_else(|_| serde_json::json!({}))
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;
    use std::sync::{Arc, RwLock};
    use std::time::Duration;

    use shunt_plugin_sdk::{BuildContext, ManualClock};

    use super::*;
    use crate::cache::CachedAiResponse;

    #[test]
    fn inspect_ai_runtime_collects_cooldowns_latency_and_cache() {
        let store = Arc::new(StateStore::new());
        let touched = Arc::new(RwLock::new(HashSet::new()));
        let clock = ManualClock::shared();
        clock.advance_ms(1_000);

        let build = BuildContext::new(
            "route:ai:ai-failover:0",
            Arc::clone(&store),
            Arc::clone(&touched),
        );
        let circuit = build
            .state_handle()
            .get_or_init("failover_circuit", FailoverCircuitState::default);
        circuit.record_failure("openai::gpt-4o", 1, Duration::from_secs(30), clock.now());

        let build_lat = BuildContext::new(
            "route:ai:ai-model-router:0",
            Arc::clone(&store),
            Arc::clone(&touched),
        );
        let lat = build_lat
            .state_handle()
            .get_or_init("ai_latency_table", TargetLatencyTable::default);
        lat.record_success("openai::openai::gpt-4o", 180.0, 0.3, clock.now_ms());

        let build_cache = BuildContext::new(
            "route:ai:ai-cache:0",
            Arc::clone(&store),
            Arc::clone(&touched),
        );
        let cache = build_cache
            .state_handle()
            .get_or_init("ai_cache_table", AiCacheTable::new);
        cache.insert(
            "k1".into(),
            CachedAiResponse {
                content_type: "application/json".into(),
                provider: "openai".into(),
                served_model: "gpt-4o".into(),
                body: b"{}".to_vec(),
            },
            clock.now(),
            Duration::from_secs(60),
            16,
            4096,
        );

        let metrics = AiMetrics::new();
        metrics.record_cache("hit", "chat", "gpt-4o");

        let val = inspect_ai_runtime(&metrics, &store, clock.as_ref());
        assert_eq!(val["totals"]["total_cache_hits"], 1);
        assert_eq!(val["cooldowns"].as_array().unwrap().len(), 1);
        assert_eq!(val["cooldowns"][0]["target"], "openai::gpt-4o");
        assert_eq!(val["cooldowns"][0]["in_cooldown"], true);
        assert_eq!(val["cooldowns"][0]["remaining_ms"], 30_000);
        assert_eq!(val["latency_targets"].as_array().unwrap().len(), 1);
        assert_eq!(val["caches"].as_array().unwrap().len(), 1);
        assert_eq!(val["caches"][0]["entries"], 1);
        assert_eq!(val["caches"][0]["total_bytes"], 2);
    }
}
