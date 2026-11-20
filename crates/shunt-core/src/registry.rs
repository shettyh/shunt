use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};

use shunt_plugin_sdk::{BuildContext, StateStore};

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
}

impl Default for RuntimeRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl RuntimeRegistry {
    pub fn new() -> Self {
        Self {
            next_pool_id: AtomicU64::new(1),
            pools: RwLock::new(HashMap::new()),
            state_store: Arc::new(StateStore::new()),
        }
    }

    /// Returns an existing warm [`UpstreamPool`] if `config.pool_key()` matches,
    /// or creates and caches a new one.
    pub fn get_or_create_pool(
        &self,
        config: &UpstreamConfig,
    ) -> Result<Arc<UpstreamPool>, CoreError> {
        let key = config.pool_key();

        if let Some(existing) = self
            .pools
            .read()
            .expect("RuntimeRegistry pools lock poisoned")
            .get(&key)
            .cloned()
        {
            return Ok(existing);
        }

        let pool_id = self.next_pool_id.fetch_add(1, Ordering::Relaxed);
        let created = Arc::new(UpstreamPool::new(pool_id, config)?);

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

    /// Starts a scoped plugin build session that tracks touched state scopes so
    /// orphaned plugin state can be garbage-collected once snapshot compilation succeeds.
    pub fn begin_build_session(&self) -> BuildSession {
        BuildSession {
            state_store: Arc::clone(&self.state_store),
            touched_scopes: Arc::new(RwLock::new(HashSet::new())),
        }
    }
}

/// Tracks plugin state scopes accessed during a snapshot compilation.
pub struct BuildSession {
    state_store: Arc<StateStore>,
    touched_scopes: Arc<RwLock<HashSet<String>>>,
}

impl BuildSession {
    pub fn context_for(&self, scope_id: impl Into<String>) -> BuildContext {
        BuildContext::new(
            scope_id,
            Arc::clone(&self.state_store),
            Arc::clone(&self.touched_scopes),
        )
    }

    /// Commits the build session, garbage-collecting any state scopes not touched
    /// during this compilation. Returns the number of removed state entries.
    pub fn commit_gc(&self) -> usize {
        let live = self
            .touched_scopes
            .read()
            .expect("touched_scopes lock poisoned");
        self.state_store.retain_scopes(&live)
    }
}
