use std::any::Any;
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, RwLock};

use serde::de::DeserializeOwned;
use thiserror::Error;

use crate::plugin::HttpPlugin;

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

    pub fn deserialize<T: DeserializeOwned>(&self, plugin_name: &str) -> Result<T, PluginBuildError> {
        serde_json::from_value(self.value.clone()).map_err(|source| PluginBuildError::InvalidConfig {
            plugin: plugin_name.to_owned(),
            source,
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

    /// Gets or initializes a typed state value under `full_key`.
    ///
    /// If an existing value under `full_key` has a different concrete type, it is replaced.
    pub fn get_or_init<T, F>(&self, full_key: &str, init: F) -> Arc<T>
    where
        T: Send + Sync + 'static,
        F: FnOnce() -> T,
    {
        if let Some(existing) = self
            .entries
            .read()
            .expect("StateStore lock poisoned")
            .get(full_key)
            .and_then(|v| Arc::clone(v).downcast::<T>().ok())
        {
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
}

impl StateHandle {
    pub fn new(scope_id: impl Into<String>, store: Arc<StateStore>) -> Self {
        Self {
            scope_id: scope_id.into(),
            store,
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
        self.store.get_or_init(&full_key, init)
    }
}

/// Context passed to [`PluginFactory::build`] during snapshot compilation.
pub struct BuildContext {
    scope_id: String,
    store: Arc<StateStore>,
    touched_scopes: Arc<RwLock<HashSet<String>>>,
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
        }
    }

    /// Stable identifier for this plugin attachment (e.g., `route:<id>:plugin:<name>`).
    pub fn scope_id(&self) -> &str {
        &self.scope_id
    }

    /// Requests a scoped [`StateHandle`] whose entries will survive snapshot reloads
    /// as long as this `scope_id` remains present in future snapshots.
    pub fn state_handle(&self) -> StateHandle {
        self.touched_scopes
            .write()
            .expect("touched_scopes lock poisoned")
            .insert(self.scope_id.clone());
        StateHandle::new(self.scope_id.clone(), Arc::clone(&self.store))
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
        self.factories
            .insert(factory.name().to_owned(), factory);
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

        let ctx1 = BuildContext::new("route:api:rate-limit", Arc::clone(&store), Arc::clone(&touched));
        let h1 = ctx1.state_handle();
        let counter1 = h1.get_or_init("hits", || AtomicU64::new(0));
        counter1.fetch_add(5, Ordering::Relaxed);

        let ctx2 = BuildContext::new("route:old:rate-limit", Arc::clone(&store), Arc::clone(&touched));
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
