//! Multi-listener [`GatewayServer`] supervisor and background Kubernetes Gateway API
//! controller reconciliation loop (`--k8s-controller`).

use std::collections::{BTreeMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use shunt_engine::{DynamicCertResolver, GatewayServer, ServerHandle, TlsListenerConfig};
use tokio::sync::{Mutex, watch};
use tracing::{info, warn};

use crate::compiler::SnapshotCompiler;
use crate::error::ConfigError;
use crate::provider::LoadedConfig;

use super::client::K8sApiConfigProvider;
use super::compiler::{CompiledK8sCluster, CompiledK8sListener, PortAllocator};

struct ManagedListener {
    handle: ServerHandle,
    is_tls: bool,
    digest: String,
    gateway_namespace: String,
    gateway_name: String,
    external_port: u16,
}

/// Manages one independent [`GatewayServer`] per active `(Gateway, external_port)` tuple
/// without modifying `shunt-engine`.
///
/// Supports atomic hot-reloading of routes, upstreams, SNI certs, and mTLS client CAs on
/// existing ports, dynamic binding of new ports, and graceful draining of removed ports.
pub struct MultiListenerSupervisor {
    compiler: Arc<SnapshotCompiler>,
    bind_ip: IpAddr,
    drain_timeout: Duration,
    listeners: BTreeMap<u16, ManagedListener>,
}

impl MultiListenerSupervisor {
    pub fn new(compiler: Arc<SnapshotCompiler>) -> Self {
        Self {
            compiler,
            bind_ip: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            drain_timeout: Duration::from_secs(30),
            listeners: BTreeMap::new(),
        }
    }

    pub fn with_bind_ip(mut self, bind_ip: IpAddr) -> Self {
        self.bind_ip = bind_ip;
        self
    }

    pub fn with_drain_timeout(mut self, drain_timeout: Duration) -> Self {
        self.drain_timeout = drain_timeout;
        self
    }

    /// Reconciles active bound listeners to match `cluster.listeners`.
    ///
    /// Returns the number of currently active listeners.
    pub async fn apply_cluster(
        &mut self,
        cluster: &CompiledK8sCluster,
    ) -> Result<usize, ConfigError> {
        let mut desired_ports: HashSet<u16> = HashSet::with_capacity(cluster.listeners.len());

        for listener in &cluster.listeners {
            desired_ports.insert(listener.internal_port);

            let action = match self.listeners.get(&listener.internal_port) {
                Some(cur) if cur.digest == listener.digest && cur.is_tls == listener.is_tls => {
                    continue;
                }
                Some(cur) if cur.is_tls == listener.is_tls => ReconcileAction::Reload,
                Some(_) => ReconcileAction::Rebind,
                None => ReconcileAction::Bind,
            };

            let loaded = LoadedConfig {
                source_name: format!(
                    "k8s:{}/{}:{}",
                    listener.gateway_namespace, listener.gateway_name, listener.external_port
                ),
                config: listener.config.clone(),
                digest: listener.digest.clone(),
            };
            let bundle = match self.compiler.compile(&loaded) {
                Ok(b) => b,
                Err(err) => {
                    warn!(
                        gateway = %format!("{}/{}", listener.gateway_namespace, listener.gateway_name),
                        port = listener.external_port,
                        error = %err,
                        "failed to compile listener snapshot; keeping previous state"
                    );
                    continue;
                }
            };

            match action {
                ReconcileAction::Reload => {
                    if let Some(cur) = self.listeners.get_mut(&listener.internal_port) {
                        let reloader = cur.handle.reloader();
                        reloader.swap_snapshot(bundle.snapshot);
                        if let Some(cert_store) = bundle.cert_store {
                            reloader.reload_tls(cert_store);
                        }
                        if cur.is_tls
                            && let Err(err) =
                                reloader.reload_client_auth(bundle.client_auth.as_ref())
                        {
                            warn!(
                                internal_port = listener.internal_port,
                                error = %err,
                                "failed to reload listener client CA"
                            );
                        }
                        cur.digest = listener.digest.clone();
                        cur.gateway_namespace = listener.gateway_namespace.clone();
                        cur.gateway_name = listener.gateway_name.clone();
                        cur.external_port = listener.external_port;
                        info!(
                            gateway = %format!("{}/{}", listener.gateway_namespace, listener.gateway_name),
                            external_port = listener.external_port,
                            internal_port = listener.internal_port,
                            "hot-reloaded Gateway listener snapshot"
                        );
                    }
                }
                ReconcileAction::Rebind => {
                    if let Some(old) = self.listeners.remove(&listener.internal_port) {
                        old.handle.shutdown().await;
                    }
                    self.bind_listener(listener, bundle).await?;
                }
                ReconcileAction::Bind => {
                    self.bind_listener(listener, bundle).await?;
                }
            }
        }

        // Gracefully drain listeners whose Gateway or port was removed.
        let stale_ports: Vec<u16> = self
            .listeners
            .keys()
            .copied()
            .filter(|p| !desired_ports.contains(p))
            .collect();
        for port in stale_ports {
            if let Some(removed) = self.listeners.remove(&port) {
                info!(
                    gateway = %format!("{}/{}", removed.gateway_namespace, removed.gateway_name),
                    external_port = removed.external_port,
                    internal_port = port,
                    "draining removed Gateway listener"
                );
                tokio::spawn(async move {
                    removed.handle.shutdown().await;
                });
            }
        }

        Ok(self.listeners.len())
    }

    async fn bind_listener(
        &mut self,
        listener: &CompiledK8sListener,
        bundle: crate::compiler::CompiledBundle,
    ) -> Result<(), ConfigError> {
        let mut srv = GatewayServer::new(bundle.snapshot).with_drain_timeout(self.drain_timeout);
        if listener.is_tls {
            if let Some(cert_store) = bundle.cert_store {
                let mut tls_cfg =
                    TlsListenerConfig::new(Arc::new(DynamicCertResolver::new(cert_store)));
                if let Some(client_auth) = bundle.client_auth {
                    tls_cfg = tls_cfg.with_client_auth(Some(client_auth));
                }
                srv = srv.with_tls(tls_cfg);
            } else {
                warn!(
                    gateway = %format!("{}/{}", listener.gateway_namespace, listener.gateway_name),
                    port = listener.external_port,
                    "skipping HTTPS listener with no valid TLS certificates"
                );
                return Ok(());
            }
        }

        let addr = SocketAddr::new(self.bind_ip, listener.internal_port);
        let handle = srv.bind(addr).await.map_err(|e| {
            ConfigError::K8s(format!(
                "failed to bind Gateway `{}/{}` port {} on {addr}: {e}",
                listener.gateway_namespace, listener.gateway_name, listener.external_port
            ))
        })?;

        info!(
            gateway = %format!("{}/{}", listener.gateway_namespace, listener.gateway_name),
            external_port = listener.external_port,
            internal_port = listener.internal_port,
            tls = listener.is_tls,
            "bound Gateway listener"
        );

        self.listeners.insert(
            listener.internal_port,
            ManagedListener {
                handle,
                is_tls: listener.is_tls,
                digest: listener.digest.clone(),
                gateway_namespace: listener.gateway_namespace.clone(),
                gateway_name: listener.gateway_name.clone(),
                external_port: listener.external_port,
            },
        );
        Ok(())
    }

    /// Returns a snapshot of currently bound `(internal_port -> SocketAddr)`.
    pub fn bound_addrs(&self) -> BTreeMap<u16, SocketAddr> {
        self.listeners
            .iter()
            .map(|(&p, l)| (p, l.handle.local_addr()))
            .collect()
    }

    /// Looks up the bound [`SocketAddr`] for a specific `(gateway_namespace, gateway_name, external_port)`.
    pub fn addr_for_gateway_port(
        &self,
        gw_ns: &str,
        gw_name: &str,
        external_port: u16,
    ) -> Option<SocketAddr> {
        self.listeners.values().find_map(|l| {
            if l.gateway_namespace == gw_ns
                && l.gateway_name == gw_name
                && l.external_port == external_port
            {
                Some(l.handle.local_addr())
            } else {
                None
            }
        })
    }

    /// Gracefully drains and shuts down all managed listeners.
    pub async fn shutdown_all(self) {
        for (_, managed) in self.listeners {
            managed.handle.shutdown().await;
        }
    }
}

#[derive(Clone, Copy)]
enum ReconcileAction {
    Bind,
    Reload,
    Rebind,
}

/// Handle for a running Kubernetes Gateway API controller reconciliation loop.
pub struct K8sControllerHandle {
    shutdown_tx: watch::Sender<bool>,
    task: tokio::task::JoinHandle<()>,
    supervisor: Arc<Mutex<MultiListenerSupervisor>>,
}

impl K8sControllerHandle {
    /// Returns a shared handle to inspect currently bound listener addresses.
    pub fn supervisor(&self) -> Arc<Mutex<MultiListenerSupervisor>> {
        Arc::clone(&self.supervisor)
    }

    /// Stops the controller reconciliation loop and gracefully drains all listeners.
    pub async fn shutdown(self) {
        let _ = self.shutdown_tx.send(true);
        let _ = self.task.await;
        let mut guard = self.supervisor.lock().await;
        let stale: Vec<u16> = guard.listeners.keys().copied().collect();
        for p in stale {
            if let Some(m) = guard.listeners.remove(&p) {
                m.handle.shutdown().await;
            }
        }
    }
}

/// Executes a single full controller reconciliation pass (fetch -> compile -> Services -> listeners -> statuses).
pub async fn reconcile_k8s_controller_once(
    provider: &K8sApiConfigProvider,
    allocator: &mut PortAllocator,
    supervisor: &mut MultiListenerSupervisor,
) -> Result<CompiledK8sCluster, ConfigError> {
    let compiled = provider.sync_cluster_once(allocator).await?;
    supervisor.apply_cluster(&compiled).await?;
    if provider.options().write_status {
        let _ = provider.reconcile_statuses(&compiled.status_plan).await?;
    }
    Ok(compiled)
}

/// Starts the background Kubernetes Gateway API controller loop (`--k8s-controller`),
/// running an initial reconciliation pass upfront so listeners and statuses come online immediately.
pub async fn start_k8s_controller_loop(
    provider: Arc<K8sApiConfigProvider>,
    supervisor: MultiListenerSupervisor,
) -> Result<K8sControllerHandle, ConfigError> {
    let opts = provider.options();
    let mut allocator = PortAllocator::new(opts.port_range_start, opts.port_range_end);
    let supervisor = Arc::new(Mutex::new(supervisor));

    // Initial reconciliation pass before spawning background ticker.
    {
        let mut sup = supervisor.lock().await;
        if let Err(err) = reconcile_k8s_controller_once(&provider, &mut allocator, &mut sup).await {
            warn!(error = %err, "initial Kubernetes Gateway API controller sync failed; will retry");
        }
    }

    let (shutdown_tx, mut shutdown_rx) = watch::channel(false);
    let interval = provider.poll_interval().max(Duration::from_millis(200));
    let sup_loop = Arc::clone(&supervisor);

    let task = tokio::spawn(async move {
        let mut ticker = tokio::time::interval(interval);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        ticker.tick().await;
        loop {
            tokio::select! {
                _ = shutdown_rx.changed() => {
                    if *shutdown_rx.borrow() {
                        break;
                    }
                }
                _ = ticker.tick() => {
                    let mut sup = sup_loop.lock().await;
                    if let Err(err) = reconcile_k8s_controller_once(&provider, &mut allocator, &mut sup).await {
                        warn!(error = %err, "Kubernetes Gateway API controller sync error; retrying");
                    }
                }
            }
        }
    });

    Ok(K8sControllerHandle {
        shutdown_tx,
        task,
        supervisor,
    })
}
