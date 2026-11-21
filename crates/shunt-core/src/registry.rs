use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};

use shunt_plugin_sdk::state::StagedStateMap;
use shunt_plugin_sdk::{BuildContext, Clock, StateStore, SystemClock};

use crate::error::CoreError;
use crate::upstream::{UpstreamConfig, UpstreamPool, UpstreamPoolKey};

/// Shared runtime registry persisting warm upstream pools and stateful plugin state
/// across atomic snapshot reloads.
///
/// When an upstream's endpoints, TLS config, and pool settings are unchanged across
/// reloads, `RuntimeRegistry` returns the existing warm [`UpstreamPool`] (preserving
/// keep-alive TCP/TLS connections and passive health state). Pools and plugin state
/// scopes absent from the latest compiled snapshot are garbage-collected cleanly while
/// in-flight requests on older snapshots continue using their held `Arc`s until drained.
#[derive(Debug)]
pub struct RuntimeRegistry {
    next_pool_id: AtomicU64,
    pools: RwLock<HashMap<UpstreamPoolKey, Arc<UpstreamPool>>>,
    state_store: Arc<StateStore>,
    clock: Arc<dyn Clock>,
}

impl Default for RuntimeRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl RuntimeRegistry {
    pub fn new() -> Self {
        Self::with_clock(SystemClock::shared())
    }

    /// Creates a registry using a custom [`Clock`] (e.g. [`shunt_plugin_sdk::ManualClock`]
    /// for deterministic testing).
    pub fn with_clock(clock: Arc<dyn Clock>) -> Self {
        Self {
            next_pool_id: AtomicU64::new(1),
            pools: RwLock::new(HashMap::new()),
            state_store: Arc::new(StateStore::new()),
            clock,
        }
    }

    /// Returns the monotonic [`Clock`] shared by upstream pools and stateful plugins.
    pub fn clock(&self) -> &Arc<dyn Clock> {
        &self.clock
    }

    /// Read-only lookup of an existing cached [`UpstreamPool`] by key.
    pub fn get_pool(&self, key: &UpstreamPoolKey) -> Option<Arc<UpstreamPool>> {
        self.pools
            .read()
            .expect("RuntimeRegistry pools lock poisoned")
            .get(key)
            .cloned()
    }

    /// Constructs a new [`UpstreamPool`] bound to this registry's clock without inserting it
    /// into the live pool cache yet (used for transactional snapshot compilation).
    pub fn create_pool_unstaged(
        &self,
        config: &UpstreamConfig,
    ) -> Result<Arc<UpstreamPool>, CoreError> {
        let pool_id = self.next_pool_id.fetch_add(1, Ordering::Relaxed);
        Ok(Arc::new(UpstreamPool::new_with_clock(
            pool_id,
            config,
            Arc::clone(&self.clock),
        )?))
    }

    /// Atomically commits newly staged pools into the live cache (reusing any pool inserted
    /// concurrently under the same key) and optionally garbage-collects pools not in
    /// `gc_active_keys`.
    ///
    /// Returns the canonical `Arc<UpstreamPool>` map for every key in `staged` (in case a
    /// concurrent builder committed the same key first).
    pub fn commit_pools(
        &self,
        staged: HashMap<UpstreamPoolKey, Arc<UpstreamPool>>,
        gc_active_keys: Option<&HashSet<UpstreamPoolKey>>,
    ) -> HashMap<UpstreamPoolKey, Arc<UpstreamPool>> {
        let mut guard = self
            .pools
            .write()
            .expect("RuntimeRegistry pools lock poisoned");

        let mut canonical = HashMap::with_capacity(staged.len());
        for (key, pool) in staged {
            let entry = guard.entry(key.clone()).or_insert(pool);
            canonical.insert(key, Arc::clone(entry));
        }

        if let Some(active_keys) = gc_active_keys {
            guard.retain(|k, _| active_keys.contains(k));
        }

        canonical
    }

    /// Returns an existing warm [`UpstreamPool`] if `config.pool_key()` matches,
    /// or creates and caches a new one.
    pub fn get_or_create_pool(
        &self,
        config: &UpstreamConfig,
    ) -> Result<Arc<UpstreamPool>, CoreError> {
        let key = config.pool_key();

        if let Some(existing) = self.get_pool(&key) {
            return Ok(existing);
        }

        let created = self.create_pool_unstaged(config)?;

        let mut guard = self
            .pools
            .write()
            .expect("RuntimeRegistry pools lock poisoned");
        let pool = guard.entry(key).or_insert_with(|| created.clone()).clone();
        Ok(pool)
    }

    /// Garbage-collects cached pools not present in `active_keys`.
    ///
    /// Note: any in-flight request still holding an older `Arc<GatewaySnapshot>` keeps
    /// its `Arc<UpstreamPool>` alive until the request drains.
    pub fn gc_unused_pools(&self, active_keys: &HashSet<UpstreamPoolKey>) -> usize {
        let mut guard = self
            .pools
            .write()
            .expect("RuntimeRegistry pools lock poisoned");
        let before = guard.len();
        guard.retain(|k, _| active_keys.contains(k));
        before - guard.len()
    }

    /// Returns the number of cached upstream pools currently tracked.
    pub fn pool_count(&self) -> usize {
        self.pools
            .read()
            .expect("RuntimeRegistry pools lock poisoned")
            .len()
    }

    /// Returns the shared [`StateStore`] backing stateful plugins.
    pub fn state_store(&self) -> &Arc<StateStore> {
        &self.state_store
    }

    /// Starts a transactional plugin build session that stages newly initialized state entries
    /// and tracks touched scopes so failed compilations never pollute [`StateStore`], while
    /// successful compilations atomically commit staged state and GC orphaned scopes.
    pub fn begin_build_session(&self) -> BuildSession {
        BuildSession {
            state_store: Arc::clone(&self.state_store),
            touched_scopes: Arc::new(RwLock::new(HashSet::new())),
            staged_state: Arc::new(RwLock::new(HashMap::new())),
            clock: Arc::clone(&self.clock),
        }
    }
}

/// Transactional build session staging newly initialized plugin state and tracking touched scopes.
///
/// Dropping a `BuildSession` without calling [`BuildSession::commit_gc`] discards all staged
/// state entries without mutating [`StateStore`].
pub struct BuildSession {
    state_store: Arc<StateStore>,
    touched_scopes: Arc<RwLock<HashSet<String>>>,
    staged_state: Arc<RwLock<StagedStateMap>>,
    clock: Arc<dyn Clock>,
}

impl BuildSession {
    pub fn context_for(&self, scope_id: impl Into<String>) -> BuildContext {
        BuildContext::new_staged(
            scope_id,
            Arc::clone(&self.state_store),
            Arc::clone(&self.touched_scopes),
            Arc::clone(&self.staged_state),
            Arc::clone(&self.clock),
        )
    }

    /// Atomically commits all newly staged state entries into [`StateStore`] and
    /// garbage-collects any state scopes not touched during this compilation.
    /// Returns the number of removed state entries.
    pub fn commit_gc(&self) -> usize {
        let staged = std::mem::take(
            &mut *self
                .staged_state
                .write()
                .expect("staged_state lock poisoned"),
        );
        let live = self
            .touched_scopes
            .read()
            .expect("touched_scopes lock poisoned");
        self.state_store.commit_staged(staged, &live)
    }
}
