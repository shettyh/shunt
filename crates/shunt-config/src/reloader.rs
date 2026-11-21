use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use arc_swap::ArcSwap;
use notify::{Event, EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use shunt_core::ServerReloader;
use tokio::sync::mpsc;
use tracing::{info, warn};

use crate::compiler::{SnapshotCompiler, SnapshotInspect};
use crate::error::ConfigError;
use crate::provider::ConfigProvider;

/// Coordinates synchronous atomic reloads from a [`ConfigProvider`] into a running gateway.
///
/// Serializes reload attempts with a mutex so concurrent file-watch events and `POST /reload`
/// calls never race or swap an older snapshot over a newer one.
pub struct ReloadController {
    provider: Arc<dyn ConfigProvider>,
    compiler: Arc<SnapshotCompiler>,
    reloader: ServerReloader,
    inspect: Arc<ArcSwap<SnapshotInspect>>,
    reload_lock: Mutex<()>,
}

impl ReloadController {
    pub fn new(
        provider: Arc<dyn ConfigProvider>,
        compiler: Arc<SnapshotCompiler>,
        reloader: ServerReloader,
        initial_inspect: SnapshotInspect,
    ) -> Self {
        Self {
            provider,
            compiler,
            reloader,
            inspect: Arc::new(ArcSwap::from_pointee(initial_inspect)),
            reload_lock: Mutex::new(()),
        }
    }

    /// Returns the redacted inspection view of the currently active snapshot.
    pub fn current_inspect(&self) -> Arc<SnapshotInspect> {
        self.inspect.load_full()
    }

    /// Synchronously loads, validates, compiles, and atomically swaps in the latest snapshot.
    ///
    /// On error, the last-known-good snapshot and TLS certs remain active untouched.
    pub fn reload(&self) -> Result<SnapshotInspect, ConfigError> {
        let _guard = self
            .reload_lock
            .lock()
            .expect("ReloadController lock poisoned");

        let loaded = self.provider.load()?;
        let bundle = self.compiler.compile(&loaded)?;

        if let Some(certs) = bundle.cert_store {
            self.reloader.reload_tls(certs);
        }
        self.reloader.swap_snapshot(bundle.snapshot);
        self.inspect.store(Arc::new(bundle.inspect.clone()));

        info!(
            version = bundle.inspect.version,
            digest = %bundle.inspect.digest,
            routes = bundle.inspect.routes.len(),
            upstreams = bundle.inspect.upstreams.len(),
            "reloaded gateway snapshot"
        );

        Ok(bundle.inspect)
    }
}

/// Handle keeping the background config file watcher alive. Dropping it stops watching.
pub struct ConfigWatcherHandle {
    _watcher: RecommendedWatcher,
    task: tokio::task::JoinHandle<()>,
}

impl ConfigWatcherHandle {
    pub fn stop(self) {
        self.task.abort();
    }
}

/// Starts a debounced file watcher on `watched_files` (watches parent directories so
/// atomic editor save/rename patterns are detected reliably).
pub fn start_file_watcher(
    watched_files: Vec<PathBuf>,
    controller: Arc<ReloadController>,
    debounce: Duration,
) -> Result<ConfigWatcherHandle, ConfigError> {
    let canonical_targets: HashSet<PathBuf> = watched_files
        .iter()
        .map(|p| std::fs::canonicalize(p).unwrap_or_else(|_| p.clone()))
        .collect();
    let target_filenames: HashSet<std::ffi::OsString> = watched_files
        .iter()
        .filter_map(|p| p.file_name().map(ToOwned::to_owned))
        .collect();

    let (tx, mut rx) = mpsc::channel::<()>(16);

    let mut watcher = notify::recommended_watcher(move |res: Result<Event, notify::Error>| {
        if let Ok(event) = res {
            let interesting_kind = matches!(
                event.kind,
                EventKind::Modify(_) | EventKind::Create(_) | EventKind::Remove(_)
            );
            if !interesting_kind {
                return;
            }
            let matches_target = event.paths.iter().any(|p| {
                let canon = std::fs::canonicalize(p).unwrap_or_else(|_| p.clone());
                canonical_targets.contains(&canon)
                    || p.file_name()
                        .map(|n| target_filenames.contains(n))
                        .unwrap_or(false)
            });
            if matches_target {
                let _ = tx.try_send(());
            }
        }
    })
    .map_err(|e| ConfigError::Watcher(e.to_string()))?;

    let mut watched_dirs = HashSet::new();
    for file in &watched_files {
        let dir = file
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("."));
        if watched_dirs.insert(dir.clone()) {
            watcher
                .watch(&dir, RecursiveMode::NonRecursive)
                .map_err(|e| ConfigError::Watcher(format!("watch `{}`: {e}", dir.display())))?;
        }
    }

    let task = tokio::spawn(async move {
        while rx.recv().await.is_some() {
            // Debounce rapid bursts of filesystem events (e.g. truncate + write + rename).
            tokio::time::sleep(debounce).await;
            while rx.try_recv().is_ok() {}

            if let Err(err) = controller.reload() {
                warn!(error = %err, "hot reload failed; keeping last-known-good snapshot");
            }
        }
    });

    Ok(ConfigWatcherHandle {
        _watcher: watcher,
        task,
    })
}
