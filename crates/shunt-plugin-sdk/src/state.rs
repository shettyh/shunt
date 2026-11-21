use std::any::Any;
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, RwLock};

use serde::de::DeserializeOwned;
use thiserror::Error;

use crate::clock::{Clock, SystemClock};
use crate::distributed::DistributedStore;
use crate::plugin::HttpPlugin;
use crate::telemetry::TelemetrySink;

/// Type-erased map used to stage newly created plugin state during transactional builds.
pub type StagedStateMap = HashMap<String, Arc<dyn Any + Send + Sync>>;

/// Errors returned while compiling/building a plugin from configuration.
#[derive(Debug, Error)]
pub enum PluginBuildError {
    #[error("unknown plugin `{0}`")]
    UnknownPlugin(String),
    #[error("invalid plugin configuration for `{plugin}`: {source}")]
    InvalidConfig {
        plugin: String,
        #[source]
        source: serde_json::Error,
    },
    #[error("plugin `{plugin}` build failed: {message}")]
    BuildFailed { plugin: String, message: String },
}

/// Format-agnostic plugin configuration payload.
#[derive(Debug, Clone, Default)]
pub struct PluginConfig {
    value: serde_json::Value,
}

impl PluginConfig {
    pub fn new(value: serde_json::Value) -> Self {
        Self { value }
    }

    pub fn empty() -> Self {
        Self {
            value: serde_json::Value::Object(serde_json::Map::new()),
        }
    }

    pub fn raw(&self) -> &serde_json::Value {
        &self.value
    }

    pub fn deserialize<T: DeserializeOwned>(
        &self,
        plugin_name: &str,
    ) -> Result<T, PluginBuildError> {
        serde_json::from_value(self.value.clone()).map_err(|source| {
            PluginBuildError::InvalidConfig {
                plugin: plugin_name.to_owned(),
                source,
            }
        })
    }
}

/// Shared backing store for stateful plugins across snapshot reloads.
///
/// Stateful plugins (rate limiters, token buckets, circuit breakers) obtain a scoped
/// [`StateHandle`] during [`PluginFactory::build`]. Keys touched during snapshot compilation
/// are recorded so orphaned state from removed plugins/routes can be garbage-collected.
#[derive(Debug, Default)]
pub struct StateStore {
    entries: RwLock<HashMap<String, Arc<dyn Any + Send + Sync>>>,
}

impl StateStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Looks up an existing typed state value under `full_key` without mutating the store.
    pub fn get<T>(&self, full_key: &str) -> Option<Arc<T>>
    where
        T: Send + Sync + 'static,
    {
        self.entries
            .read()
            .expect("StateStore lock poisoned")
            .get(full_key)
            .and_then(|v| Arc::clone(v).downcast::<T>().ok())
    }

    /// Gets or initializes a typed state value under `full_key`.
    ///
    /// If an existing value under `full_key` has a different concrete type, it is replaced.
    pub fn get_or_init<T, F>(&self, full_key: &str, init: F) -> Arc<T>
    where
        T: Send + Sync + 'static,
        F: FnOnce() -> T,
    {
        if let Some(existing) = self.get::<T>(full_key) {
            return existing;
        }

        let mut guard = self.entries.write().expect("StateStore lock poisoned");
        if let Some(existing) = guard
            .get(full_key)
            .and_then(|v| Arc::clone(v).downcast::<T>().ok())
        {
            return existing;
        }

        let created = Arc::new(init());
        let erased: Arc<dyn Any + Send + Sync> = created.clone();
        guard.insert(full_key.to_owned(), erased);
        created
    }

    /// Atomically commits newly staged state entries and garbage-collects any scopes
    /// absent from `live_scopes`. Returns the number of garbage-collected entries.
    pub fn commit_staged(&self, staged: StagedStateMap, live_scopes: &HashSet<String>) -> usize {
        let mut guard = self.entries.write().expect("StateStore lock poisoned");
        for (k, v) in staged {
            guard.insert(k, v);
        }
        let before = guard.len();
        guard.retain(|full_key, _| {
            full_key
                .split_once("::")
                .map(|(scope, _)| live_scopes.contains(scope))
                .unwrap_or(false)
        });
        before - guard.len()
    }

    /// Retains only entries whose namespace prefix is present in `live_scopes`.
    /// Returns the number of garbage-collected entries.
    pub fn retain_scopes(&self, live_scopes: &HashSet<String>) -> usize {
        let mut guard = self.entries.write().expect("StateStore lock poisoned");
        let before = guard.len();
        guard.retain(|full_key, _| {
            full_key
                .split_once("::")
                .map(|(scope, _)| live_scopes.contains(scope))
                .unwrap_or(false)
        });
        before - guard.len()
    }

    /// Number of stored state entries (primarily for diagnostics/tests).
    pub fn len(&self) -> usize {
        self.entries.read().expect("StateStore lock poisoned").len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// Scoped handle into [`StateStore`] given to a plugin during build.
#[derive(Clone, Debug)]
pub struct StateHandle {
    scope_id: String,
    store: Arc<StateStore>,
    staged: Option<Arc<RwLock<StagedStateMap>>>,
}

impl StateHandle {
    pub fn new(scope_id: impl Into<String>, store: Arc<StateStore>) -> Self {
        Self {
            scope_id: scope_id.into(),
            store,
            staged: None,
        }
    }

    /// Creates a transactional handle that reads existing state from `store` while
    /// staging newly initialized entries into `staged` until explicitly committed.
    pub fn new_staged(
        scope_id: impl Into<String>,
        store: Arc<StateStore>,
        staged: Arc<RwLock<StagedStateMap>>,
    ) -> Self {
        Self {
            scope_id: scope_id.into(),
            store,
            staged: Some(staged),
        }
    }

    pub fn scope_id(&self) -> &str {
        &self.scope_id
    }

    /// Gets or initializes a typed state value scoped to this plugin/route ID.
    pub fn get_or_init<T, F>(&self, key: &str, init: F) -> Arc<T>
    where
        T: Send + Sync + 'static,
        F: FnOnce() -> T,
    {
        let full_key = format!("{}::{}", self.scope_id, key);
        let Some(staged) = &self.staged else {
            return self.store.get_or_init(&full_key, init);
        };

        if let Some(existing) = self.store.get::<T>(&full_key) {
            return existing;
        }
        if let Some(existing) = staged
            .read()
            .expect("staged StateStore lock poisoned")
            .get(&full_key)
            .and_then(|v| Arc::clone(v).downcast::<T>().ok())
        {
            return existing;
        }

        let mut guard = staged.write().expect("staged StateStore lock poisoned");
        if let Some(existing) = self.store.get::<T>(&full_key) {
            return existing;
        }
        if let Some(existing) = guard
            .get(&full_key)
            .and_then(|v| Arc::clone(v).downcast::<T>().ok())
        {
            return existing;
        }

        let created = Arc::new(init());
        let erased: Arc<dyn Any + Send + Sync> = created.clone();
        guard.insert(full_key, erased);
        created
    }
}

/// Context passed to [`PluginFactory::build`] during snapshot compilation.
pub struct BuildContext {
    scope_id: String,
    store: Arc<StateStore>,
    touched_scopes: Arc<RwLock<HashSet<String>>>,
    staged: Option<Arc<RwLock<StagedStateMap>>>,
    clock: Arc<dyn Clock>,
    distributed_store: Option<Arc<dyn DistributedStore>>,
    telemetry_sink: Option<Arc<dyn TelemetrySink>>,
}

impl BuildContext {
    pub fn new(
        scope_id: impl Into<String>,
        store: Arc<StateStore>,
        touched_scopes: Arc<RwLock<HashSet<String>>>,
    ) -> Self {
        Self {
            scope_id: scope_id.into(),
            store,
            touched_scopes,
            staged: None,
            clock: SystemClock::shared(),
            distributed_store: None,
            telemetry_sink: None,
        }
    }

    /// Creates a transactional [`BuildContext`] with staged state and an explicit [`Clock`].
    pub fn new_staged(
        scope_id: impl Into<String>,
        store: Arc<StateStore>,
        touched_scopes: Arc<RwLock<HashSet<String>>>,
        staged: Arc<RwLock<StagedStateMap>>,
        clock: Arc<dyn Clock>,
    ) -> Self {
        Self {
            scope_id: scope_id.into(),
            store,
            touched_scopes,
            staged: Some(staged),
            clock,
            distributed_store: None,
            telemetry_sink: None,
        }
    }

    /// Attaches a custom [`Clock`] implementation (e.g., [`crate::ManualClock`] in tests).
    pub fn with_clock(mut self, clock: Arc<dyn Clock>) -> Self {
        self.clock = clock;
        self
    }

    /// Attaches an optional distributed state backend (e.g., Redis / Valkey).
    pub fn with_distributed_store(
        mut self,
        distributed_store: Option<Arc<dyn DistributedStore>>,
    ) -> Self {
        self.distributed_store = distributed_store;
        self
    }

    /// Attaches an optional gateway-level [`TelemetrySink`] (e.g., OTLP/HTTP exporter).
    pub fn with_telemetry_sink(mut self, telemetry_sink: Option<Arc<dyn TelemetrySink>>) -> Self {
        self.telemetry_sink = telemetry_sink;
        self
    }

    /// Stable identifier for this plugin attachment (e.g., `route:<id>:plugin:<name>`).
    pub fn scope_id(&self) -> &str {
        &self.scope_id
    }

    /// Monotonic clock shared by this runtime (defaults to [`SystemClock`]).
    pub fn clock(&self) -> Arc<dyn Clock> {
        Arc::clone(&self.clock)
    }

    /// Optional shared [`DistributedStore`] backend configured at the gateway level.
    ///
    /// Returns `None` in the default single-binary in-memory mode so plugins stay on the
    /// synchronous zero-allocation fast path.
    pub fn distributed_store(&self) -> Option<Arc<dyn DistributedStore>> {
        self.distributed_store.as_ref().map(Arc::clone)
    }

    /// Optional shared [`TelemetrySink`] configured at the gateway level (`[telemetry]`).
    pub fn telemetry_sink(&self) -> Option<Arc<dyn TelemetrySink>> {
        self.telemetry_sink.as_ref().map(Arc::clone)
    }

    /// Requests a scoped [`StateHandle`] whose entries will survive snapshot reloads
    /// as long as this `scope_id` remains present in future snapshots.
    pub fn state_handle(&self) -> StateHandle {
        self.touched_scopes
            .write()
            .expect("touched_scopes lock poisoned")
            .insert(self.scope_id.clone());
        match &self.staged {
            Some(staged) => StateHandle::new_staged(
                self.scope_id.clone(),
                Arc::clone(&self.store),
                Arc::clone(staged),
            ),
            None => StateHandle::new(self.scope_id.clone(), Arc::clone(&self.store)),
        }
    }
}

/// Factory registered in [`PluginRegistry`] to construct plugin instances during compilation.
pub trait PluginFactory: Send + Sync + 'static {
    /// Unique plugin type name (e.g., `"bearer-auth"`, `"ai-model-router"`).
    fn name(&self) -> &str;

    /// Validates `config` and constructs a compiled [`HttpPlugin`] instance.
    fn build(
        &self,
        config: &PluginConfig,
        ctx: &BuildContext,
    ) -> Result<Arc<dyn HttpPlugin>, PluginBuildError>;
}

/// Registry mapping plugin names to their [`PluginFactory`].
#[derive(Default)]
pub struct PluginRegistry {
    factories: HashMap<String, Arc<dyn PluginFactory>>,
}

impl PluginRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register<F: PluginFactory>(&mut self, factory: F) -> &mut Self {
        self.factories
            .insert(factory.name().to_owned(), Arc::new(factory));
        self
    }

    pub fn register_arc(&mut self, factory: Arc<dyn PluginFactory>) -> &mut Self {
        self.factories.insert(factory.name().to_owned(), factory);
        self
    }

    pub fn get(&self, name: &str) -> Option<&Arc<dyn PluginFactory>> {
        self.factories.get(name)
    }

    pub fn build(
        &self,
        name: &str,
        config: &PluginConfig,
        ctx: &BuildContext,
    ) -> Result<Arc<dyn HttpPlugin>, PluginBuildError> {
        let factory = self
            .get(name)
            .ok_or_else(|| PluginBuildError::UnknownPlugin(name.to_owned()))?;
        factory.build(config, ctx)
    }

    pub fn plugin_names(&self) -> Vec<&str> {
        let mut names: Vec<&str> = self.factories.keys().map(String::as_str).collect();
        names.sort_unstable();
        names
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicU64, Ordering};

    use super::*;

    #[test]
    fn state_store_persists_and_gcs_orphans() {
        let store = Arc::new(StateStore::new());
        let touched = Arc::new(RwLock::new(HashSet::new()));

        let ctx1 = BuildContext::new(
            "route:api:rate-limit",
            Arc::clone(&store),
            Arc::clone(&touched),
        );
        let h1 = ctx1.state_handle();
        let counter1 = h1.get_or_init("hits", || AtomicU64::new(0));
        counter1.fetch_add(5, Ordering::Relaxed);

        let ctx2 = BuildContext::new(
            "route:old:rate-limit",
            Arc::clone(&store),
            Arc::clone(&touched),
        );
        let h2 = ctx2.state_handle();
        let _ = h2.get_or_init("hits", || AtomicU64::new(1));

        // Reload: only route:api remains active.
        let mut live = HashSet::new();
        live.insert("route:api:rate-limit".to_owned());
        let removed = store.retain_scopes(&live);
        assert_eq!(removed, 1);
        assert_eq!(store.len(), 1);

        // Re-acquiring preserved state returns the same AtomicU64 with value 5.
        let counter_after = h1.get_or_init("hits", || AtomicU64::new(0));
        assert_eq!(counter_after.load(Ordering::Relaxed), 5);
    }
}
