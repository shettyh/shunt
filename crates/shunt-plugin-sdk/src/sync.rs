//! Lock-free, monotonic versioned key-value tables synchronized from an external control plane.
//!
//! [`SyncedTable`] is a strictly protocol- and domain-agnostic SDK primitive (Channel 2 in
//! RFC 0023). Plugins obtain an optional handle via [`crate::BuildContext::synced_table`],
//! register a derived-view builder via [`SyncedTable::subscribe`], and read compiled typed
//! snapshots from their own `ArcSwap` on the hot path with zero allocations and zero JSON
//! parsing.
//!
//! When running standalone (`shunt.toml` without a control plane), `BuildContext::synced_table`
//! returns `None` and plugins incur zero overhead.

use std::collections::BTreeMap;
use std::fmt;
use std::sync::{Arc, Mutex, RwLock};

use arc_swap::ArcSwap;
use serde::{Deserialize, Serialize};

/// Immutable point-in-time snapshot of a [`SyncedTable`] namespace at sequence `seq`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SyncedTableSnapshot {
    /// Monotonic sequence number of the last applied event (or full sync).
    pub seq: u64,
    /// Current key-value entries in deterministic lexicographic key order.
    pub entries: BTreeMap<Arc<str>, Arc<serde_json::Value>>,
}

impl SyncedTableSnapshot {
    /// Looks up an entry by key.
    pub fn get(&self, key: &str) -> Option<&Arc<serde_json::Value>> {
        self.entries.get(key)
    }

    /// Number of live entries in this snapshot.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Returns `true` if the snapshot contains no entries.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Iterates over all `(key, value)` pairs in deterministic order.
    pub fn iter(&self) -> impl Iterator<Item = (&Arc<str>, &Arc<serde_json::Value>)> {
        self.entries.iter()
    }
}

/// Mutation operation applied to a single key inside a [`SyncedTable`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "op", content = "value", rename_all = "snake_case")]
pub enum SyncedDeltaOp {
    /// Inserts or replaces the JSON payload for the item key.
    Upsert(serde_json::Value),
    /// Removes the item key if present.
    Delete,
}

/// A single monotonic state delta event targeting `(namespace, key)`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyncedDelta {
    pub seq: u64,
    pub namespace: String,
    pub key: String,
    pub op: SyncedDeltaOp,
}

/// Subscriber callback invoked off the hot path whenever a [`SyncedTable`] snapshot changes.
pub type SyncedTableSubscriber = Arc<dyn Fn(&SyncedTableSnapshot) + Send + Sync>;

/// Monotonic versioned key-value table for a single logical namespace.
///
/// Hot-path readers call [`SyncedTable::load`] (lock-free `ArcSwap` load) or read a plugin-owned
/// derived `ArcSwap` populated via [`SyncedTable::subscribe`]. Control-plane sync tasks update
/// the table off the hot path via [`SyncedTable::apply_delta`] and [`SyncedTable::replace_full`].
pub struct SyncedTable {
    namespace: Arc<str>,
    state: ArcSwap<SyncedTableSnapshot>,
    write_lock: Mutex<()>,
    on_update: RwLock<Vec<SyncedTableSubscriber>>,
}

impl fmt::Debug for SyncedTable {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let snap = self.state.load();
        f.debug_struct("SyncedTable")
            .field("namespace", &self.namespace)
            .field("seq", &snap.seq)
            .field("entries_len", &snap.entries.len())
            .finish()
    }
}

impl SyncedTable {
    /// Creates an empty [`SyncedTable`] at sequence `0`.
    pub fn new(namespace: impl Into<Arc<str>>) -> Self {
        Self {
            namespace: namespace.into(),
            state: ArcSwap::from_pointee(SyncedTableSnapshot::default()),
            write_lock: Mutex::new(()),
            on_update: RwLock::new(Vec::new()),
        }
    }

    /// Logical namespace name (e.g., `"ai.virtual_keys"` or `"mcp.kill_switch"`).
    pub fn namespace(&self) -> &str {
        &self.namespace
    }

    /// Lock-free O(1) snapshot load suitable for request-path reads.
    pub fn load(&self) -> Arc<SyncedTableSnapshot> {
        self.state.load_full()
    }

    /// Current monotonic sequence number of this table.
    pub fn seq(&self) -> u64 {
        self.state.load().seq
    }

    /// Registers a derived-view builder callback invoked off the hot path on every update.
    ///
    /// Also invokes `cb` immediately once with the current snapshot so plugins constructed after
    /// an initial full sync (e.g., following a Channel 1 topology reload) populate their derived
    /// views without waiting for the next delta.
    pub fn subscribe(&self, cb: SyncedTableSubscriber) {
        let _write_guard = self
            .write_lock
            .lock()
            .expect("SyncedTable write_lock poisoned");
        let current = self.state.load_full();
        cb(&current);
        self.on_update
            .write()
            .expect("SyncedTable on_update lock poisoned")
            .push(cb);
    }

    /// Applies a single monotonic delta off the hot path.
    ///
    /// Returns `true` if the delta advanced the table (`seq > current.seq`), or `false` if the
    /// event was stale/duplicate and safely ignored.
    pub fn apply_delta(&self, seq: u64, key: &str, op: SyncedDeltaOp) -> bool {
        let _write_guard = self
            .write_lock
            .lock()
            .expect("SyncedTable write_lock poisoned");
        let current = self.state.load_full();
        if seq <= current.seq {
            return false;
        }

        let mut next_entries = current.entries.clone();
        match op {
            SyncedDeltaOp::Upsert(value) => {
                next_entries.insert(Arc::from(key), Arc::new(value));
            }
            SyncedDeltaOp::Delete => {
                next_entries.remove(key);
            }
        }

        let next = Arc::new(SyncedTableSnapshot {
            seq,
            entries: next_entries,
        });
        self.state.store(Arc::clone(&next));
        self.notify_locked(&next);
        true
    }

    /// Atomically replaces the entire table state at `seq` (e.g., on initial cold start or after
    /// a compacted cursor gap) and notifies all subscribers.
    pub fn replace_full(&self, seq: u64, entries: BTreeMap<Arc<str>, Arc<serde_json::Value>>) {
        let _write_guard = self
            .write_lock
            .lock()
            .expect("SyncedTable write_lock poisoned");
        let next = Arc::new(SyncedTableSnapshot { seq, entries });
        self.state.store(Arc::clone(&next));
        self.notify_locked(&next);
    }

    /// Convenience helper accepting owned `String` keys and `serde_json::Value` values.
    pub fn replace_full_json(&self, seq: u64, entries: BTreeMap<String, serde_json::Value>) {
        let converted = entries
            .into_iter()
            .map(|(k, v)| (Arc::<str>::from(k), Arc::new(v)))
            .collect();
        self.replace_full(seq, converted);
    }

    fn notify_locked(&self, snapshot: &SyncedTableSnapshot) {
        let subscribers: Vec<SyncedTableSubscriber> = self
            .on_update
            .read()
            .expect("SyncedTable on_update lock poisoned")
            .clone();
        for cb in subscribers {
            cb(snapshot);
        }
    }
}

/// Registry owning all [`SyncedTable`] namespaces attached to a Shunt runtime.
///
/// Shared across snapshot reloads inside `RuntimeRegistry` so Channel 2 state survives Channel 1
/// topology reloads and rollbacks untouched.
#[derive(Debug, Default)]
pub struct SyncedTableRegistry {
    tables: RwLock<BTreeMap<Arc<str>, Arc<SyncedTable>>>,
}

impl SyncedTableRegistry {
    /// Creates an empty [`SyncedTableRegistry`].
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns the existing [`SyncedTable`] for `namespace`, creating an empty table if absent.
    pub fn get_or_create(&self, namespace: &str) -> Arc<SyncedTable> {
        if let Some(existing) = self
            .tables
            .read()
            .expect("SyncedTableRegistry lock poisoned")
            .get(namespace)
            .cloned()
        {
            return existing;
        }
        let mut guard = self
            .tables
            .write()
            .expect("SyncedTableRegistry lock poisoned");
        if let Some(existing) = guard.get(namespace).cloned() {
            return existing;
        }
        let ns: Arc<str> = Arc::from(namespace);
        let table = Arc::new(SyncedTable::new(Arc::clone(&ns)));
        guard.insert(ns, Arc::clone(&table));
        table
    }

    /// Looks up an existing [`SyncedTable`] without creating it.
    pub fn get(&self, namespace: &str) -> Option<Arc<SyncedTable>> {
        self.tables
            .read()
            .expect("SyncedTableRegistry lock poisoned")
            .get(namespace)
            .cloned()
    }

    /// Lists all registered namespaces in deterministic lexicographic order.
    pub fn namespaces(&self) -> Vec<String> {
        self.tables
            .read()
            .expect("SyncedTableRegistry lock poisoned")
            .keys()
            .map(|k| k.to_string())
            .collect()
    }

    /// Returns the current monotonic sequence number for every registered namespace.
    pub fn cursors(&self) -> BTreeMap<String, u64> {
        self.tables
            .read()
            .expect("SyncedTableRegistry lock poisoned")
            .iter()
            .map(|(ns, tbl)| (ns.to_string(), tbl.seq()))
            .collect()
    }

    /// Applies a single [`SyncedDelta`], creating the target namespace table if needed.
    pub fn apply_delta(&self, delta: SyncedDelta) -> bool {
        let table = self.get_or_create(&delta.namespace);
        table.apply_delta(delta.seq, &delta.key, delta.op)
    }

    /// Atomically replaces the full contents of `namespace` at `seq`.
    pub fn replace_full_json(
        &self,
        namespace: &str,
        seq: u64,
        entries: BTreeMap<String, serde_json::Value>,
    ) {
        let table = self.get_or_create(namespace);
        table.replace_full_json(seq, entries);
    }

    /// Captures point-in-time snapshots of every registered namespace (e.g., for local LKG cache).
    pub fn snapshot_all(&self) -> BTreeMap<String, SyncedTableSnapshot> {
        self.tables
            .read()
            .expect("SyncedTableRegistry lock poisoned")
            .iter()
            .map(|(ns, tbl)| (ns.to_string(), (*tbl.load()).clone()))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicU64, Ordering};

    use proptest::prelude::*;
    use serde_json::json;

    use super::*;

    #[test]
    fn synced_table_monotonic_deltas_and_subscriber_updates() {
        let table = SyncedTable::new("test.keys");
        let observed_seq = Arc::new(AtomicU64::new(0));
        let observed_len = Arc::new(AtomicU64::new(0));

        let seq_clone = Arc::clone(&observed_seq);
        let len_clone = Arc::clone(&observed_len);
        table.subscribe(Arc::new(move |snap| {
            seq_clone.store(snap.seq, Ordering::SeqCst);
            len_clone.store(snap.len() as u64, Ordering::SeqCst);
        }));

        assert!(table.apply_delta(1, "k1", SyncedDeltaOp::Upsert(json!({"enabled": true}))));
        assert_eq!(observed_seq.load(Ordering::SeqCst), 1);
        assert_eq!(observed_len.load(Ordering::SeqCst), 1);

        // Stale/duplicate sequence is ignored cleanly.
        assert!(!table.apply_delta(1, "k1", SyncedDeltaOp::Delete));
        assert_eq!(table.load().len(), 1);

        // Advance with upsert + delete.
        assert!(table.apply_delta(5, "k2", SyncedDeltaOp::Upsert(json!({"limit": 100}))));
        assert!(table.apply_delta(6, "k1", SyncedDeltaOp::Delete));
        assert_eq!(table.seq(), 6);
        assert_eq!(table.load().len(), 1);
        assert!(table.load().get("k1").is_none());
        assert_eq!(
            table.load().get("k2").map(|v| v.as_ref()),
            Some(&json!({"limit": 100}))
        );

        // Late subscriber immediately receives the current snapshot.
        let late_seq = Arc::new(AtomicU64::new(0));
        let late_clone = Arc::clone(&late_seq);
        table.subscribe(Arc::new(move |snap| {
            late_clone.store(snap.seq, Ordering::SeqCst);
        }));
        assert_eq!(late_seq.load(Ordering::SeqCst), 6);
    }

    #[derive(Debug, Clone)]
    enum OpSpec {
        Upsert(String, i64),
        Delete(String),
        ReplayStale(String),
        FullSyncCompaction,
    }

    fn op_strategy() -> impl Strategy<Value = OpSpec> {
        let key_strat = prop_oneof![
            Just("k1".to_owned()),
            Just("k2".to_owned()),
            Just("k3".to_owned()),
            Just("k4".to_owned()),
            Just("k5".to_owned()),
        ];
        prop_oneof![
            (key_strat.clone(), -1000i64..1000i64).prop_map(|(k, v)| OpSpec::Upsert(k, v)),
            key_strat.clone().prop_map(OpSpec::Delete),
            key_strat.prop_map(OpSpec::ReplayStale),
            Just(OpSpec::FullSyncCompaction),
        ]
    }

    proptest! {
        /// RFC 0023 §6 property: applying an arbitrary sequence of upserts, deletes,
        /// duplicate/stale replays, and full-sync compactions always yields exact equivalence
        /// with a fresh full-sync state computed from the canonical log.
        #[test]
        fn prop_delta_stream_matches_full_sync_state(ops in prop::collection::vec(op_strategy(), 1..80)) {
            let reg = SyncedTableRegistry::new();
            let mut reference: BTreeMap<String, serde_json::Value> = BTreeMap::new();
            let mut seq: u64 = 0;

            for op in ops {
                match op {
                    OpSpec::Upsert(k, v) => {
                        seq += 1;
                        let val = json!({ "v": v });
                        reference.insert(k.clone(), val.clone());
                        let applied = reg.apply_delta(SyncedDelta {
                            seq,
                            namespace: "ns.prop".to_owned(),
                            key: k,
                            op: SyncedDeltaOp::Upsert(val),
                        });
                        prop_assert!(applied);
                    }
                    OpSpec::Delete(k) => {
                        seq += 1;
                        reference.remove(&k);
                        let applied = reg.apply_delta(SyncedDelta {
                            seq,
                            namespace: "ns.prop".to_owned(),
                            key: k,
                            op: SyncedDeltaOp::Delete,
                        });
                        prop_assert!(applied);
                    }
                    OpSpec::ReplayStale(k) => {
                        if seq > 0 {
                            let applied = reg.apply_delta(SyncedDelta {
                                seq, // duplicate current seq
                                namespace: "ns.prop".to_owned(),
                                key: k,
                                op: SyncedDeltaOp::Upsert(json!({ "stale": true })),
                            });
                            prop_assert!(!applied);
                        }
                    }
                    OpSpec::FullSyncCompaction => {
                        reg.replace_full_json("ns.prop", seq, reference.clone());
                    }
                }
            }

            let actual = reg.get_or_create("ns.prop").load();
            prop_assert_eq!(actual.seq, seq);
            let actual_map: BTreeMap<String, serde_json::Value> = actual
                .iter()
                .map(|(k, v)| (k.to_string(), (**v).clone()))
                .collect();
            prop_assert_eq!(actual_map, reference);
        }
    }
}
