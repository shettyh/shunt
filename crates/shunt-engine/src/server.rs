use std::convert::Infallible;
use std::net::SocketAddr;
use std::pin::pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::time::Duration;

use arc_swap::ArcSwap;
use http::Request;
use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto::Builder as AutoServerBuilder;
use shunt_plugin_sdk::ClientCertInfo;
use tokio::sync::{Notify, watch};
use tokio_rustls::TlsAcceptor;
use tracing::{debug, info, warn};

use crate::error::CoreError;
use crate::pipeline::execute_request;
use crate::probe::ProbeSupervisor;
use crate::snapshot::GatewaySnapshot;
use crate::tls::{
    CertStore, ClientAuthConfig, DynamicCertResolver, TlsListenerConfig,
    build_server_config_with_auth, parse_client_cert_info,
};

/// Core HTTP/1.1 + HTTP/2 + TLS + WebSocket gateway server backed by `ArcSwap<GatewaySnapshot>`.
pub struct GatewayServer {
    snapshot: Arc<ArcSwap<GatewaySnapshot>>,
    tls: Option<TlsListenerConfig>,
    drain_timeout: Duration,
    trace_enabled: Arc<AtomicBool>,
}

impl GatewayServer {
    pub fn new(initial_snapshot: Arc<GatewaySnapshot>) -> Self {
        Self {
            snapshot: Arc::new(ArcSwap::from(initial_snapshot)),
            tls: None,
            drain_timeout: Duration::from_secs(30),
            trace_enabled: Arc::new(AtomicBool::new(false)),
        }
    }

    pub fn with_tls(mut self, tls: TlsListenerConfig) -> Self {
        self.tls = Some(tls);
        self
    }

    pub fn with_drain_timeout(mut self, timeout: Duration) -> Self {
        self.drain_timeout = timeout;
        self
    }

    pub fn with_trace_enabled(mut self, enabled: bool) -> Self {
        self.trace_enabled = Arc::new(AtomicBool::new(enabled));
        self
    }

    /// Binds to `addr` (supports port `0` for OS-assigned ephemeral ports) and starts
    /// accepting connections on the Tokio runtime.
    pub async fn bind(self, addr: SocketAddr) -> Result<ServerHandle, CoreError> {
        let socket = match addr {
            SocketAddr::V4(_) => tokio::net::TcpSocket::new_v4()?,
            SocketAddr::V6(_) => tokio::net::TcpSocket::new_v6()?,
        };
        let _ = socket.set_reuseaddr(true);
        socket.bind(addr)?;
        let listener = socket.listen(4096)?;
        let local_addr = listener.local_addr()?;

        let (tls_acceptor, tls_resolver, tls_alpn) = match self.tls {
            Some(tls_cfg) => {
                let server_cfg = tls_cfg.build_server_config()?;
                (
                    Some(Arc::new(ArcSwap::from_pointee(TlsAcceptor::from(
                        server_cfg,
                    )))),
                    Some(Arc::clone(tls_cfg.resolver())),
                    tls_cfg.alpn_protocols().to_vec(),
                )
            }
            None => (None, None, Vec::new()),
        };

        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let active_conns = Arc::new(AtomicUsize::new(0));
        let drain_notify = Arc::new(Notify::new());
        let next_request_id = Arc::new(AtomicU64::new(1));
        let probes = Arc::new(ProbeSupervisor::new());
        probes.reconcile(&self.snapshot.load());

        let snapshot_ref = Arc::clone(&self.snapshot);
        let tls_acceptor_loop = tls_acceptor.clone();
        let active_conns_loop = Arc::clone(&active_conns);
        let drain_notify_loop = Arc::clone(&drain_notify);
        let trace_enabled_loop = Arc::clone(&self.trace_enabled);
        let mut accept_shutdown_rx = shutdown_rx.clone();

        info!(%local_addr, tls = tls_acceptor.is_some(), "shunt gateway listening");

        let accept_task = tokio::spawn(async move {
            loop {
                tokio::select! {
                    biased;
                    _ = accept_shutdown_rx.changed() => {
                        if *accept_shutdown_rx.borrow() {
                            debug!(%local_addr, "accept loop stopping for graceful shutdown");
                            break;
                        }
                    }
                    accept_res = listener.accept() => {
                        let (tcp, peer_addr) = match accept_res {
                            Ok(pair) => pair,
                            Err(err) => {
                                warn!(error = %err, "TCP accept error");
                                continue;
                            }
                        };

                        let _ = tcp.set_nodelay(true);

                        let snapshot_conn = Arc::clone(&snapshot_ref);
                        let tls_acceptor_conn = tls_acceptor_loop
                            .as_ref()
                            .map(|swap| swap.load_full());
                        let active_conns_conn = Arc::clone(&active_conns_loop);
                        let drain_notify_conn = Arc::clone(&drain_notify_loop);
                        let next_req_id_conn = Arc::clone(&next_request_id);
                        let trace_enabled_conn = Arc::clone(&trace_enabled_loop);
                        let mut conn_shutdown_rx = shutdown_rx.clone();

                        active_conns_conn.fetch_add(1, Ordering::SeqCst);

                        tokio::spawn(async move {
                            let _guard = ActiveConnGuard {
                                counter: active_conns_conn,
                                notify: drain_notify_conn,
                            };

                            if let Some(acceptor) = tls_acceptor_conn {
                                match acceptor.accept(tcp).await {
                                    Ok(tls_stream) => {
                                        let server_conn = tls_stream.get_ref().1;
                                        let tls_sni =
                                            server_conn.server_name().map(str::to_owned);
                                        let client_cert = server_conn
                                            .peer_certificates()
                                            .and_then(|certs| certs.first())
                                            .and_then(|leaf| parse_client_cert_info(leaf.as_ref()))
                                            .map(Arc::new);
                                        serve_connection(
                                            TokioIo::new(tls_stream),
                                            peer_addr,
                                            true,
                                            tls_sni,
                                            client_cert,
                                            snapshot_conn,
                                            next_req_id_conn,
                                            trace_enabled_conn,
                                            &mut conn_shutdown_rx,
                                        )
                                        .await;
                                    }
                                    Err(err) => {
                                        debug!(%peer_addr, error = %err, "TLS handshake failed");
                                    }
                                }
                            } else {
                                serve_connection(
                                    TokioIo::new(tcp),
                                    peer_addr,
                                    false,
                                    None,
                                    None,
                                    snapshot_conn,
                                    next_req_id_conn,
                                    trace_enabled_conn,
                                    &mut conn_shutdown_rx,
                                )
                                .await;
                            }
                        });
                    }
                }
            }
        });

        Ok(ServerHandle {
            local_addr,
            snapshot: self.snapshot,
            tls_resolver,
            tls_acceptor,
            tls_alpn,
            trace_enabled: self.trace_enabled,
            probes,
            shutdown_tx,
            active_conns,
            drain_notify,
            drain_timeout: self.drain_timeout,
            accept_task: Some(accept_task),
        })
    }
}

#[allow(clippy::too_many_arguments)]
async fn serve_connection<I>(
    io: TokioIo<I>,
    peer_addr: SocketAddr,
    is_tls: bool,
    tls_sni: Option<String>,
    client_cert: Option<Arc<ClientCertInfo>>,
    snapshot_swap: Arc<ArcSwap<GatewaySnapshot>>,
    next_request_id: Arc<AtomicU64>,
    trace_enabled: Arc<AtomicBool>,
    shutdown_rx: &mut watch::Receiver<bool>,
) where
    I: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let service = service_fn(move |req: Request<hyper::body::Incoming>| {
        // Lock-free atomic load of the active snapshot once per request.
        // In-flight requests finish cleanly on this Arc even if a hot reload swaps in a new snapshot.
        let snapshot = snapshot_swap.load_full();
        let req_id = next_request_id.fetch_add(1, Ordering::Relaxed);
        let sni = tls_sni.clone();
        let cert = client_cert.clone();
        let trace = trace_enabled.load(Ordering::Relaxed);

        async move {
            let resp =
                execute_request(snapshot, req, req_id, peer_addr, is_tls, sni, cert, trace).await;
            Ok::<_, Infallible>(resp)
        }
    });

    let mut builder = AutoServerBuilder::new(TokioExecutor::new());
    builder.http1().keep_alive(true);
    let conn = builder.serve_connection_with_upgrades(io, service);
    let mut conn = pin!(conn);

    if *shutdown_rx.borrow() {
        conn.as_mut().graceful_shutdown();
        let _ = conn.await;
        return;
    }

    tokio::select! {
        res = conn.as_mut() => {
            if let Err(err) = res {
                debug!(%peer_addr, error = %err, "connection terminated with error");
            }
        }
        _ = shutdown_rx.changed() => {
            conn.as_mut().graceful_shutdown();
            if let Err(err) = conn.await {
                debug!(%peer_addr, error = %err, "connection terminated during graceful drain");
            }
        }
    }
}

struct ActiveConnGuard {
    counter: Arc<AtomicUsize>,
    notify: Arc<Notify>,
}

impl Drop for ActiveConnGuard {
    fn drop(&mut self) {
        if self.counter.fetch_sub(1, Ordering::SeqCst) == 1 {
            self.notify.notify_waiters();
        }
    }
}

/// Cloneable handle for atomically swapping snapshots and TLS certs on a running server
/// (e.g., from config file watchers, `POST /reload`, or `SIGHUP`).
#[derive(Clone)]
pub struct ServerReloader {
    snapshot: Arc<ArcSwap<GatewaySnapshot>>,
    tls_resolver: Option<Arc<DynamicCertResolver>>,
    tls_acceptor: Option<Arc<ArcSwap<TlsAcceptor>>>,
    tls_alpn: Vec<Vec<u8>>,
    probes: Arc<ProbeSupervisor>,
}

impl ServerReloader {
    pub fn swap_snapshot(&self, next: Arc<GatewaySnapshot>) {
        self.probes.reconcile(&next);
        self.snapshot.store(next);
    }

    pub fn current_snapshot(&self) -> Arc<GatewaySnapshot> {
        self.snapshot.load_full()
    }

    pub fn reload_tls(&self, next: CertStore) {
        if let Some(resolver) = &self.tls_resolver {
            resolver.reload(next);
        }
    }

    /// Atomically reloads the mTLS client certificate verifier for subsequent TLS handshakes
    /// (no-op if this server is not a TLS listener).
    pub fn reload_client_auth(
        &self,
        client_auth: Option<&ClientAuthConfig>,
    ) -> Result<(), CoreError> {
        if let (Some(resolver), Some(acceptor_swap)) = (&self.tls_resolver, &self.tls_acceptor) {
            let server_cfg = build_server_config_with_auth(resolver, &self.tls_alpn, client_auth)?;
            acceptor_swap.store(Arc::new(TlsAcceptor::from(server_cfg)));
        }
        Ok(())
    }
}

/// Control handle for a running [`GatewayServer`].
pub struct ServerHandle {
    local_addr: SocketAddr,
    snapshot: Arc<ArcSwap<GatewaySnapshot>>,
    tls_resolver: Option<Arc<DynamicCertResolver>>,
    tls_acceptor: Option<Arc<ArcSwap<TlsAcceptor>>>,
    tls_alpn: Vec<Vec<u8>>,
    trace_enabled: Arc<AtomicBool>,
    probes: Arc<ProbeSupervisor>,
    shutdown_tx: watch::Sender<bool>,
    active_conns: Arc<AtomicUsize>,
    drain_notify: Arc<Notify>,
    drain_timeout: Duration,
    accept_task: Option<tokio::task::JoinHandle<()>>,
}

impl ServerHandle {
    /// Returns the bound local socket address.
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// Returns a cloneable reloader for atomic snapshot & TLS cert swaps.
    pub fn reloader(&self) -> ServerReloader {
        ServerReloader {
            snapshot: Arc::clone(&self.snapshot),
            tls_resolver: self.tls_resolver.clone(),
            tls_acceptor: self.tls_acceptor.clone(),
            tls_alpn: self.tls_alpn.clone(),
            probes: Arc::clone(&self.probes),
        }
    }

    /// Atomically swaps in a new compiled [`GatewaySnapshot`] with zero downtime.
    ///
    /// In-flight requests continue on the previous `Arc<GatewaySnapshot>` until complete,
    /// while all new requests immediately observe the new snapshot.
    pub fn swap_snapshot(&self, next: Arc<GatewaySnapshot>) {
        self.probes.reconcile(&next);
        self.snapshot.store(next);
    }

    /// Returns the number of currently running active health check probe tasks.
    pub fn active_probe_tasks(&self) -> usize {
        self.probes.active_task_count()
    }

    /// Returns a reference to the currently active [`GatewaySnapshot`].
    pub fn current_snapshot(&self) -> Arc<GatewaySnapshot> {
        self.snapshot.load_full()
    }

    /// Hot-reloads TLS certificates for subsequent handshakes (no-op if not a TLS listener).
    pub fn reload_tls(&self, next: CertStore) {
        if let Some(resolver) = &self.tls_resolver {
            resolver.reload(next);
        }
    }

    /// Hot-reloads mTLS client CA verification for subsequent handshakes (no-op if not TLS).
    pub fn reload_client_auth(
        &self,
        client_auth: Option<&ClientAuthConfig>,
    ) -> Result<(), CoreError> {
        if let (Some(resolver), Some(acceptor_swap)) = (&self.tls_resolver, &self.tls_acceptor) {
            let server_cfg = build_server_config_with_auth(resolver, &self.tls_alpn, client_auth)?;
            acceptor_swap.store(Arc::new(TlsAcceptor::from(server_cfg)));
        }
        Ok(())
    }

    /// Enables or disables per-hook microsecond timing capture on subsequent requests.
    pub fn set_trace_enabled(&self, enabled: bool) {
        self.trace_enabled.store(enabled, Ordering::Relaxed);
    }

    /// Returns the number of currently open downstream connections.
    pub fn active_connections(&self) -> usize {
        self.active_conns.load(Ordering::SeqCst)
    }

    /// Initiates graceful shutdown: stops accepting new connections, signals HTTP/1.1 &
    /// HTTP/2 `graceful_shutdown()`, and awaits draining of all active connections up to
    /// `drain_timeout`. Returns `true` if all connections drained cleanly before timeout.
    pub async fn shutdown(mut self) -> bool {
        self.probes.shutdown_all().await;
        let _ = self.shutdown_tx.send(true);
        if let Some(task) = self.accept_task.take() {
            let _ = task.await;
        }

        if self.active_conns.load(Ordering::SeqCst) == 0 {
            return true;
        }

        let drain_fut = async {
            loop {
                let notified = self.drain_notify.notified();
                if self.active_conns.load(Ordering::SeqCst) == 0 {
                    break;
                }
                notified.await;
            }
        };

        tokio::time::timeout(self.drain_timeout, drain_fut)
            .await
            .is_ok()
    }
}
