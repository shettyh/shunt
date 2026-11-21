use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::sync::watch;
use tracing::{debug, warn};

use crate::snapshot::GatewaySnapshot;
use crate::upstream::UpstreamPool;

#[derive(Debug)]
struct ProbeTaskEntry {
    shutdown_tx: watch::Sender<bool>,
    handle: tokio::task::JoinHandle<()>,
}

/// Supervises background active health check tasks for all pools in the active [`GatewaySnapshot`].
///
/// Tasks are keyed by [`UpstreamPool::pool_id`]. Across atomic snapshot reloads:
/// - Unchanged pools keep their existing probe task and health state untouched.
/// - Newly added/modified pools with `active_health_check` spawn a probe task.
/// - Removed/obsolete pools have their probe task cancelled immediately.
#[derive(Debug, Default)]
pub struct ProbeSupervisor {
    tasks: Mutex<HashMap<u64, ProbeTaskEntry>>,
}

impl ProbeSupervisor {
    pub fn new() -> Self {
        Self::default()
    }

    /// Reconciles running active health probe tasks against `snapshot.upstreams`.
    ///
    /// Safe to call inside a Tokio runtime on `GatewayServer::bind` and every
    /// `ServerReloader::swap_snapshot`. If called outside a Tokio runtime (e.g., in a sync
    /// test), reconciliation is skipped cleanly without panicking.
    pub fn reconcile(&self, snapshot: &GatewaySnapshot) {
        let Ok(rt_handle) = tokio::runtime::Handle::try_current() else {
            return;
        };

        let mut desired: HashMap<u64, (String, Arc<UpstreamPool>)> = HashMap::new();
        for (name, pool) in &snapshot.upstreams {
            if pool.active_health_check().is_some() {
                desired
                    .entry(pool.pool_id())
                    .or_insert_with(|| (name.clone(), Arc::clone(pool)));
            }
        }

        let desired_ids: HashSet<u64> = desired.keys().copied().collect();
        let mut guard = self.tasks.lock().expect("ProbeSupervisor lock poisoned");

        // Cancel & remove tasks for pools no longer active in this snapshot.
        let obsolete: Vec<u64> = guard
            .keys()
            .copied()
            .filter(|id| !desired_ids.contains(id))
            .collect();
        for pool_id in obsolete {
            if let Some(entry) = guard.remove(&pool_id) {
                let _ = entry.shutdown_tx.send(true);
                entry.handle.abort();
                debug!(pool_id, "stopped active health probe task for retired pool");
            }
        }

        // Spawn probe tasks for newly active pools.
        for (pool_id, (upstream_name, pool)) in desired {
            if guard.contains_key(&pool_id) {
                continue;
            }
            let Some(cfg) = pool.active_health_check().cloned() else {
                continue;
            };
            let interval = cfg.interval.max(Duration::from_millis(10));
            let (shutdown_tx, mut shutdown_rx) = watch::channel(false);
            let handle = rt_handle.spawn(async move {
                debug!(
                    pool_id,
                    upstream = %upstream_name,
                    interval_ms = interval.as_millis() as u64,
                    "started active health probe task"
                );
                loop {
                    if *shutdown_rx.borrow() {
                        break;
                    }
                    pool.probe_all_once().await;

                    tokio::select! {
                        biased;
                        changed = shutdown_rx.changed() => {
                            if changed.is_err() || *shutdown_rx.borrow() {
                                break;
                            }
                        }
                        _ = tokio::time::sleep(interval) => {}
                    }
                }
                debug!(
                    pool_id,
                    upstream = %upstream_name,
                    "active health probe task exited"
                );
            });

            guard.insert(
                pool_id,
                ProbeTaskEntry {
                    shutdown_tx,
                    handle,
                },
            );
        }
    }

    /// Returns the number of active probe tasks currently running (useful for tests/diagnostics).
    pub fn active_task_count(&self) -> usize {
        self.tasks
            .lock()
            .expect("ProbeSupervisor lock poisoned")
            .len()
    }

    /// Stops and cancels all running probe tasks (called during graceful server shutdown).
    pub async fn shutdown_all(&self) {
        let entries: Vec<ProbeTaskEntry> = {
            let mut guard = self.tasks.lock().expect("ProbeSupervisor lock poisoned");
            guard.drain().map(|(_, v)| v).collect()
        };

        for entry in entries {
            let _ = entry.shutdown_tx.send(true);
            entry.handle.abort();
            if let Err(err) = entry.handle.await
                && !err.is_cancelled()
            {
                warn!(error = %err, "active health probe task exited with error");
            }
        }
    }
}

impl Drop for ProbeSupervisor {
    fn drop(&mut self) {
        if let Ok(mut guard) = self.tasks.lock() {
            for (_, entry) in guard.drain() {
                let _ = entry.shutdown_tx.send(true);
                entry.handle.abort();
            }
        }
    }
}
