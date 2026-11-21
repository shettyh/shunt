use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
use std::time::Duration;

use shunt_plugin_sdk::state::StagedStateMap;
use shunt_plugin_sdk::{
    BuildContext, Clock, DistributedStore, StateStore, SystemClock, TelemetrySink,
};

use crate::error::CoreError;
use crate::otlp::{OtlpExporterConfig, OtlpHttpExporter};
use crate::redis::{RedisStateStore, RedisStoreConfig};
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
    redis_stores: RwLock<HashMap<RedisStoreConfig, Arc<RedisStateStore>>>,
    otlp_exporters: RwLock<HashMap<OtlpExporterConfig, Arc<OtlpHttpExporter>>>,
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
            redis_stores: RwLock::new(HashMap::new()),
            otlp_exporters: RwLock::new(HashMap::new()),
            state_store: Arc::new(StateStore::new()),
            clock,
        }
    }

    /// Returns a cached warm [`OtlpHttpExporter`] matching `config`, or creates and caches one.
    pub fn get_or_create_otlp_exporter(
        &self,
        config: &OtlpExporterConfig,
    ) -> Arc<OtlpHttpExporter> {
        if let Some(existing) = self
            .otlp_exporters
            .read()
            .expect("RuntimeRegistry otlp_exporters lock poisoned")
            .get(config)
            .cloned()
        {
            return existing;
        }
        let mut guard = self
            .otlp_exporters
            .write()
            .expect("RuntimeRegistry otlp_exporters lock poisoned");
        guard
            .entry(config.clone())
            .or_insert_with(|| Arc::new(OtlpHttpExporter::new(config.clone())))
            .clone()
    }

    /// Garbage-collects cached OTLP exporters other than `active` (call only after snapshot commit).
    pub fn retain_otlp_exporter(&self, active: Option<&OtlpExporterConfig>) {
        let mut guard = self
            .otlp_exporters
            .write()
            .expect("RuntimeRegistry otlp_exporters lock poisoned");
        match active {
            Some(cfg) => guard.retain(|k, _| k == cfg),
            None => guard.clear(),
        }
    }

    /// Returns `true` if at least one telemetry exporter is currently registered.
    pub fn has_active_telemetry(&self) -> bool {
        !self
            .otlp_exporters
            .read()
            .expect("RuntimeRegistry otlp_exporters lock poisoned")
            .is_empty()
    }

    /// Flushes all active telemetry exporters up to `timeout` (e.g., on graceful shutdown).
    pub async fn flush_telemetry(&self, timeout: Duration) {
        let exporters: Vec<Arc<OtlpHttpExporter>> = self
            .otlp_exporters
            .read()
            .expect("RuntimeRegistry otlp_exporters lock poisoned")
            .values()
            .cloned()
            .collect();
        for exp in exporters {
            exp.flush(timeout).await;
        }
    }

    /// Renders Prometheus metrics for all active telemetry exporters.
    pub fn render_telemetry_prometheus(&self) -> String {
        let exporters: Vec<Arc<OtlpHttpExporter>> = self
            .otlp_exporters
            .read()
            .expect("RuntimeRegistry otlp_exporters lock poisoned")
            .values()
            .cloned()
            .collect();
        let mut out = String::new();
        for exp in exporters {
            let chunk = exp.render_prometheus();
            if !chunk.is_empty() {
                if !out.is_empty() && !out.ends_with('\n') {
                    out.push('\n');
                }
                out.push_str(&chunk);
            }
        }
        out
    }

    /// Returns a cached warm [`RedisStateStore`] matching `config`, or creates and caches one.
    pub fn get_or_create_redis_store(&self, config: &RedisStoreConfig) -> Arc<RedisStateStore> {
        if let Some(existing) = self
            .redis_stores
            .read()
            .expect("RuntimeRegistry redis_stores lock poisoned")
            .get(config)
            .cloned()
        {
            return existing;
        }
        let mut guard = self
            .redis_stores
            .write()
            .expect("RuntimeRegistry redis_stores lock poisoned");
        guard
            .entry(config.clone())
            .or_insert_with(|| Arc::new(RedisStateStore::new(config.clone())))
            .clone()
    }

    /// Garbage-collects cached Redis stores other than `active` (call only after snapshot commit).
    pub fn retain_redis_store(&self, active: Option<&RedisStoreConfig>) {
        let mut guard = self
            .redis_stores
            .write()
            .expect("RuntimeRegistry redis_stores lock poisoned");
        match active {
            Some(cfg) => guard.retain(|k, _| k == cfg),
            None => guard.clear(),
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
        self.begin_build_session_with_distributed(None)
    }

    /// Starts a transactional plugin build session with an optional [`DistributedStore`].
    pub fn begin_build_session_with_distributed(
        &self,
        distributed_store: Option<Arc<dyn DistributedStore>>,
    ) -> BuildSession {
        self.begin_build_session_with_services(distributed_store, None)
    }

    /// Starts a transactional plugin build session with optional gateway services
    /// (`DistributedStore` and `TelemetrySink`).
    pub fn begin_build_session_with_services(
        &self,
        distributed_store: Option<Arc<dyn DistributedStore>>,
        telemetry_sink: Option<Arc<dyn TelemetrySink>>,
    ) -> BuildSession {
        BuildSession {
            state_store: Arc::clone(&self.state_store),
            touched_scopes: Arc::new(RwLock::new(HashSet::new())),
            staged_state: Arc::new(RwLock::new(HashMap::new())),
            clock: Arc::clone(&self.clock),
            distributed_store,
            telemetry_sink,
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
    distributed_store: Option<Arc<dyn DistributedStore>>,
    telemetry_sink: Option<Arc<dyn TelemetrySink>>,
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
        .with_distributed_store(self.distributed_store.as_ref().map(Arc::clone))
        .with_telemetry_sink(self.telemetry_sink.as_ref().map(Arc::clone))
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
