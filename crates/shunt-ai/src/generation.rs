//! Bounded, reload-persistent generation metadata store for `GET /v1/generation?id=...`.
//!
//! Populated off the hot path by `ai-usage-tracker` in `on_complete` and served directly in
//! `on_request_headers` with strict virtual-key tenant isolation and zero database dependencies.

use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};

use serde::Serialize;

/// Interior-mutable per-request cost accumulator (in exact integer nano-USD) shared between
/// `ai-budget` and `ai-usage-tracker` during `on_complete`.
#[derive(Debug, Clone, Default)]
pub struct AiRecordedCost(pub Arc<AtomicU64>);

impl AiRecordedCost {
    pub fn set_nano_usd(&self, nano_usd: u64) {
        self.0.store(nano_usd, Ordering::Relaxed);
    }

    pub fn nano_usd(&self) -> u64 {
        self.0.load(Ordering::Relaxed)
    }
}

/// Completed AI generation metadata record served by `GET /v1/generation?id=...`.
#[derive(Debug, Clone, Serialize)]
pub struct AiGenerationRecord {
    /// Canonical generation identifier (upstream response `id` if present, else `gen-<request_id>`).
    pub id: String,
    /// Gateway-synthesized alias (`gen-<request_id>`) emitted via `x-shunt-generation-id`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gateway_id: Option<String>,
    /// Unix epoch timestamp (milliseconds) when the generation completed.
    pub created_at_ms: u64,
    pub endpoint: String,
    pub model: String,
    pub served_model: String,
    pub provider_name: String,
    pub streamed: bool,
    pub status: u16,
    pub tokens_prompt: u64,
    pub tokens_completion: u64,
    pub tokens_cached_read: u64,
    pub tokens_cache_write: u64,
    pub tokens_reasoning: u64,
    pub total_cost: f64,
    pub latency_ms: f64,
    pub generation_time_ms: f64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub finish_reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cache_status: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub team: Option<String>,
}

/// Read-only stats snapshot of an [`AiGenerationStore`] for Admin Inspector `/api/status`.
#[derive(Debug, Clone, Serialize)]
pub struct GenerationStoreSnapshot {
    pub stored_records: usize,
    pub capacity: usize,
}

#[derive(Debug)]
struct StoredGeneration {
    record: Arc<AiGenerationRecord>,
    generation: u64,
}

#[derive(Debug, Default)]
struct StoreInner {
    records: HashMap<String, StoredGeneration>,
    /// Alias map (`gen-<request_id>` -> canonical `id`) so lookups work by either ID.
    aliases: HashMap<String, String>,
    /// FIFO insertion order of `(canonical_id, generation)` for O(1) bounded ring eviction.
    order: VecDeque<(String, u64)>,
    next_gen: u64,
    capacity: usize,
}

/// Bounded, reload-persistent FIFO ring store for completed AI generation records in `StateStore`.
#[derive(Debug, Default)]
pub struct AiGenerationStore {
    inner: RwLock<StoreInner>,
}

impl AiGenerationStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Inserts a completed generation record (and optional alias ID), evicting the oldest record
    /// when `capacity` is exceeded.
    pub fn insert(&self, record: AiGenerationRecord, capacity: usize) {
        if capacity == 0 {
            return;
        }
        let mut guard = self.inner.write().expect("AiGenerationStore poisoned");
        let inner = &mut *guard;
        inner.capacity = capacity;

        let canonical_id = record.id.clone();
        let alias = record
            .gateway_id
            .as_ref()
            .filter(|g| g.as_str() != canonical_id.as_str())
            .cloned();

        // Remove any prior alias pointing to an overwritten entry with the same canonical ID.
        if let Some(prev) = inner.records.remove(&canonical_id)
            && let Some(prev_alias) = &prev.record.gateway_id
            && prev_alias != &canonical_id
        {
            inner.aliases.remove(prev_alias);
        }

        while inner.records.len() >= capacity {
            let Some((evicted_id, evicted_gen)) = inner.order.pop_front() else {
                inner.records.clear();
                inner.aliases.clear();
                break;
            };
            let is_live = inner
                .records
                .get(&evicted_id)
                .is_some_and(|e| e.generation == evicted_gen);
            if is_live
                && let Some(evicted) = inner.records.remove(&evicted_id)
                && let Some(ev_alias) = &evicted.record.gateway_id
                && ev_alias != &evicted_id
            {
                inner.aliases.remove(ev_alias);
            }
        }

        inner.next_gen = inner.next_gen.wrapping_add(1);
        let generation = inner.next_gen;

        if let Some(a) = alias {
            inner.aliases.insert(a, canonical_id.clone());
        }
        inner.records.insert(
            canonical_id.clone(),
            StoredGeneration {
                record: Arc::new(record),
                generation,
            },
        );
        inner.order.push_back((canonical_id, generation));

        // Compact stale overwritten entries so repeated upstream IDs cannot grow `order` unboundedly.
        if inner.order.len() > inner.records.len().saturating_mul(2).max(64) {
            let records = &inner.records;
            inner.order.retain(|(id, seq)| {
                records
                    .get(id)
                    .is_some_and(|entry| entry.generation == *seq)
            });
        }
    }

    /// Looks up a generation record by either its canonical ID or its `x-shunt-generation-id` alias.
    pub fn get(&self, id: &str) -> Option<Arc<AiGenerationRecord>> {
        let guard = self.inner.read().expect("AiGenerationStore poisoned");
        if let Some(entry) = guard.records.get(id) {
            return Some(Arc::clone(&entry.record));
        }
        if let Some(canonical) = guard.aliases.get(id) {
            return guard.records.get(canonical).map(|e| Arc::clone(&e.record));
        }
        None
    }

    pub fn snapshot(&self) -> GenerationStoreSnapshot {
        let guard = self.inner.read().expect("AiGenerationStore poisoned");
        GenerationStoreSnapshot {
            stored_records: guard.records.len(),
            capacity: guard.capacity,
        }
    }

    /// Returns internal `(records_len, aliases_len, order_len)` for structural invariant tests.
    #[doc(hidden)]
    pub fn internal_counts(&self) -> (usize, usize, usize) {
        let guard = self.inner.read().expect("AiGenerationStore poisoned");
        (guard.records.len(), guard.aliases.len(), guard.order.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_record(id: &str, gw_id: Option<&str>, key_id: Option<&str>) -> AiGenerationRecord {
        AiGenerationRecord {
            id: id.to_owned(),
            gateway_id: gw_id.map(str::to_owned),
            created_at_ms: 1_700_000_000_000,
            endpoint: "chat_completions".to_owned(),
            model: "smart".to_owned(),
            served_model: "gpt-4o".to_owned(),
            provider_name: "openai".to_owned(),
            streamed: true,
            status: 200,
            tokens_prompt: 100,
            tokens_completion: 50,
            tokens_cached_read: 0,
            tokens_cache_write: 0,
            tokens_reasoning: 0,
            total_cost: 0.00125,
            latency_ms: 120.5,
            generation_time_ms: 650.0,
            finish_reason: Some("stop".to_owned()),
            cache_status: Some("miss".to_owned()),
            key_id: key_id.map(str::to_owned),
            team: Some("eng".to_owned()),
        }
    }

    #[test]
    fn generation_store_resolves_canonical_and_alias_and_evicts_fifo() {
        let store = AiGenerationStore::new();
        store.insert(sample_record("chatcmpl-1", Some("gen-1"), Some("k1")), 2);
        store.insert(sample_record("chatcmpl-2", Some("gen-2"), Some("k2")), 2);

        assert_eq!(store.get("chatcmpl-1").unwrap().id, "chatcmpl-1");
        assert_eq!(store.get("gen-1").unwrap().id, "chatcmpl-1");
        assert_eq!(store.get("gen-2").unwrap().id, "chatcmpl-2");

        // Inserting a 3rd evicts chatcmpl-1 AND its gen-1 alias.
        store.insert(sample_record("chatcmpl-3", Some("gen-3"), Some("k1")), 2);
        assert!(store.get("chatcmpl-1").is_none());
        assert!(store.get("gen-1").is_none());
        assert_eq!(store.get("chatcmpl-2").unwrap().id, "chatcmpl-2");
        assert_eq!(store.get("gen-3").unwrap().id, "chatcmpl-3");
        assert_eq!(store.snapshot().stored_records, 2);
    }

    #[test]
    fn generation_store_bounds_order_queue_and_preserves_overwritten_records() {
        let store = AiGenerationStore::new();
        for i in 0..500u64 {
            let gw = format!("gen-{i}");
            store.insert(sample_record("chatcmpl-dup", Some(&gw), Some("k1")), 4);
        }

        {
            let guard = store.inner.read().unwrap();
            assert_eq!(guard.records.len(), 1);
            assert_eq!(guard.aliases.len(), 1);
            assert!(
                guard.order.len() <= 64,
                "order queue should stay bounded on repeated IDs, got {}",
                guard.order.len()
            );
        }
        assert!(store.get("gen-0").is_none());
        assert_eq!(store.get("gen-499").unwrap().id, "chatcmpl-dup");

        // Overwriting an existing ID refreshes its FIFO age so stale queue entries cannot evict it.
        let store2 = AiGenerationStore::new();
        store2.insert(sample_record("id-a", Some("gen-a1"), Some("k1")), 2);
        store2.insert(sample_record("id-b", Some("gen-b1"), Some("k1")), 2);
        store2.insert(sample_record("id-a", Some("gen-a2"), Some("k1")), 2);
        // Inserting id-c must evict id-b (oldest live entry), NOT id-a.
        store2.insert(sample_record("id-c", Some("gen-c1"), Some("k1")), 2);
        assert!(store2.get("id-b").is_none());
        assert_eq!(
            store2.get("id-a").unwrap().gateway_id.as_deref(),
            Some("gen-a2")
        );
        assert_eq!(store2.get("id-c").unwrap().id, "id-c");
    }
}
