use std::convert::Infallible;
use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::pin::{Pin, pin};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::task::{Context, Poll};
use std::time::Duration;

use arc_swap::ArcSwap;
use http::Request;
use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use hyper_util::server::conn::auto::Builder as AutoServerBuilder;
use shunt_plugin_sdk::ClientCertInfo;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::{Notify, Semaphore, watch};
use tokio_rustls::TlsAcceptor;
use tracing::{debug, info, warn};

use crate::error::CoreError;
use crate::pipeline::{DEFAULT_REQUEST_BODY_TIMEOUT, RequestMeta, execute_request};
use crate::probe::ProbeSupervisor;
use crate::snapshot::GatewaySnapshot;
use crate::tls::{
    CertStore, ClientAuthConfig, DynamicCertResolver, TlsListenerConfig,
    build_server_config_with_auth, parse_client_cert_info,
};

/// Default maximum concurrent accepted client connections.
pub const DEFAULT_MAX_CONNECTIONS: usize = 10_000;
/// Default downstream TLS handshake timeout.
pub const DEFAULT_TLS_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
/// Default HTTP/1.1 request header read timeout (Slowloris guard).
pub const DEFAULT_HEADER_READ_TIMEOUT: Duration = Duration::from_secs(30);
/// Default HTTP/2 maximum concurrent streams per connection.
pub const DEFAULT_HTTP2_MAX_CONCURRENT_STREAMS: u32 = 256;
/// Default HTTP/2 maximum header list size (64 KiB).
pub const DEFAULT_HTTP2_MAX_HEADER_LIST_SIZE: u32 = 64 * 1024;
/// Default HTTP/2 keep-alive PING interval.
pub const DEFAULT_HTTP2_KEEP_ALIVE_INTERVAL: Duration = Duration::from_secs(30);
/// Default HTTP/2 keep-alive PING timeout.
pub const DEFAULT_HTTP2_KEEP_ALIVE_TIMEOUT: Duration = Duration::from_secs(10);

/// Backoff duration after a transient TCP accept error (e.g., `EMFILE`/`ENFILE`) to avoid
/// spinning at 100% CPU under FD exhaustion.
const ACCEPT_ERROR_BACKOFF: Duration = Duration::from_millis(50);

/// Connection, handshake, header, body, and HTTP/2 resource limits enforced by [`GatewayServer`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ServerLimits {
    /// Maximum concurrent accepted client TCP connections (default: `10_000`).
    pub max_connections: usize,
    /// Maximum time allowed for a downstream TLS handshake (default: `10s`).
    pub tls_handshake_timeout: Duration,
    /// Maximum time to read HTTP/1.1 request headers (default: `30s`).
    pub header_read_timeout: Duration,
    /// Maximum total time to buffer a request body when buffering is active (default: `60s`).
    pub request_body_timeout: Option<Duration>,
    /// Maximum concurrent HTTP/2 streams per connection (default: `256`).
    pub http2_max_concurrent_streams: u32,
    /// Maximum HTTP/2 header list size in bytes (default: `64 KiB`).
    pub http2_max_header_list_size: u32,
    /// Optional HTTP/2 keep-alive PING interval (default: `Some(30s)`).
    pub http2_keep_alive_interval: Option<Duration>,
    /// HTTP/2 keep-alive PING timeout (default: `10s`).
    pub http2_keep_alive_timeout: Duration,
}

impl Default for ServerLimits {
    fn default() -> Self {
        Self {
            max_connections: DEFAULT_MAX_CONNECTIONS,
            tls_handshake_timeout: DEFAULT_TLS_HANDSHAKE_TIMEOUT,
            header_read_timeout: DEFAULT_HEADER_READ_TIMEOUT,
            request_body_timeout: Some(DEFAULT_REQUEST_BODY_TIMEOUT),
            http2_max_concurrent_streams: DEFAULT_HTTP2_MAX_CONCURRENT_STREAMS,
            http2_max_header_list_size: DEFAULT_HTTP2_MAX_HEADER_LIST_SIZE,
            http2_keep_alive_interval: Some(DEFAULT_HTTP2_KEEP_ALIVE_INTERVAL),
            http2_keep_alive_timeout: DEFAULT_HTTP2_KEEP_ALIVE_TIMEOUT,
        }
    }
}

/// Core HTTP/1.1 + HTTP/2 + TLS + WebSocket gateway server backed by `ArcSwap<GatewaySnapshot>`.
pub struct GatewayServer {
    snapshot: Arc<ArcSwap<GatewaySnapshot>>,
    tls: Option<TlsListenerConfig>,
    drain_timeout: Duration,
    limits: ServerLimits,
    trace_enabled: Arc<AtomicBool>,
}

impl GatewayServer {
    pub fn new(initial_snapshot: Arc<GatewaySnapshot>) -> Self {
        Self {
            snapshot: Arc::new(ArcSwap::from(initial_snapshot)),
            tls: None,
            drain_timeout: Duration::from_secs(30),
            limits: ServerLimits::default(),
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

    pub fn with_limits(mut self, limits: ServerLimits) -> Self {
        self.limits = limits;
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
        let limits = self.limits;
        let max_connections = limits.max_connections.max(1);
        let conn_semaphore = Arc::new(Semaphore::new(max_connections));
        let mut accept_shutdown_rx = shutdown_rx.clone();

        info!(
            %local_addr,
            tls = tls_acceptor.is_some(),
            max_connections,
            "shunt gateway listening"
        );

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
                                warn!(error = %err, "TCP accept error; backing off briefly");
                                tokio::select! {
                                    biased;
                                    _ = accept_shutdown_rx.changed() => {
                                        if *accept_shutdown_rx.borrow() {
                                            break;
                                        }
                                    }
                                    _ = tokio::time::sleep(ACCEPT_ERROR_BACKOFF) => {}
                                }
                                continue;
                            }
                        };

                        let Ok(conn_permit) = Arc::clone(&conn_semaphore).try_acquire_owned() else {
                            debug!(
                                %peer_addr,
                                max_connections,
                                "connection rejected: max_connections reached"
                            );
                            drop(tcp);
                            continue;
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
                            let _permit = conn_permit;
                            let _guard = ActiveConnGuard {
                                counter: active_conns_conn,
                                notify: drain_notify_conn,
                            };

                            if let Some(acceptor) = tls_acceptor_conn {
                                if *conn_shutdown_rx.borrow() {
                                    return;
                                }
                                let handshake = tokio::select! {
                                    biased;
                                    _ = conn_shutdown_rx.changed() => {
                                        debug!(%peer_addr, "TLS handshake cancelled by shutdown");
                                        return;
                                    }
                                    res = tokio::time::timeout(
                                        limits.tls_handshake_timeout,
                                        acceptor.accept(tcp),
                                    ) => res,
                                };
                                match handshake {
                                    Ok(Ok(tls_stream)) => {
                                        let server_conn = tls_stream.get_ref().1;
                                        let tls_sni =
                                            server_conn.server_name().map(str::to_owned);
                                        let client_cert = server_conn
                                            .peer_certificates()
                                            .and_then(|certs| certs.first())
                                            .and_then(|leaf| parse_client_cert_info(leaf.as_ref()))
                                            .map(Arc::new);
                                        serve_connection(
                                            TokioIo::new(InitialReadTimeoutIo::new(
                                                tls_stream,
                                                limits.header_read_timeout,
                                            )),
                                            peer_addr,
                                            tls_sni,
                                            client_cert,
                                            snapshot_conn,
                                            next_req_id_conn,
                                            trace_enabled_conn,
                                            limits,
                                            &mut conn_shutdown_rx,
                                        )
                                        .await;
                                    }
                                    Ok(Err(err)) => {
                                        debug!(%peer_addr, error = %err, "TLS handshake failed");
                                    }
                                    Err(_) => {
                                        debug!(
                                            %peer_addr,
                                            timeout = ?limits.tls_handshake_timeout,
                                            "TLS handshake timed out"
                                        );
                                    }
                                }
                            } else {
                                serve_connection(
                                    TokioIo::new(InitialReadTimeoutIo::new(
                                        tcp,
                                        limits.header_read_timeout,
                                    )),
                                    peer_addr,
                                    None,
                                    None,
                                    snapshot_conn,
                                    next_req_id_conn,
                                    trace_enabled_conn,
                                    limits,
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
    tls_sni: Option<String>,
    client_cert: Option<Arc<ClientCertInfo>>,
    snapshot_swap: Arc<ArcSwap<GatewaySnapshot>>,
    next_request_id: Arc<AtomicU64>,
    trace_enabled: Arc<AtomicBool>,
    limits: ServerLimits,
    shutdown_rx: &mut watch::Receiver<bool>,
) where
    I: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let request_body_timeout = limits.request_body_timeout;
    let service = service_fn(move |req: Request<hyper::body::Incoming>| {
        // Lock-free atomic load of the active snapshot once per request.
        // In-flight requests finish cleanly on this Arc even if a hot reload swaps in a new snapshot.
        let snapshot = snapshot_swap.load_full();
        let req_id = next_request_id.fetch_add(1, Ordering::Relaxed);
        let sni = tls_sni.clone();
        let cert = client_cert.clone();
        let trace = trace_enabled.load(Ordering::Relaxed);

        async move {
            let resp = execute_request(
                snapshot,
                req,
                RequestMeta {
                    request_id: req_id,
                    client_addr: peer_addr,
                    tls_sni: sni,
                    client_cert: cert,
                    trace_enabled: trace,
                    request_body_timeout,
                },
            )
            .await;
            Ok::<_, Infallible>(resp)
        }
    });

    let mut builder = AutoServerBuilder::new(TokioExecutor::new());
    builder
        .http1()
        .timer(TokioTimer::new())
        .header_read_timeout(limits.header_read_timeout)
        .keep_alive(true);
    builder
        .http2()
        .timer(TokioTimer::new())
        .max_concurrent_streams(limits.http2_max_concurrent_streams)
        .max_header_list_size(limits.http2_max_header_list_size)
        .keep_alive_interval(limits.http2_keep_alive_interval)
        .keep_alive_timeout(limits.http2_keep_alive_timeout);
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

/// HTTP/2 connection preface (RFC 9113 §3.4) probed by `hyper_util`'s `AutoServerBuilder::ReadVersion`.
const H2_PREFACE: &[u8; 24] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

/// Bounds `AutoServerBuilder::ReadVersion` initial protocol detection with `header_read_timeout`.
///
/// `hyper_util::server::conn::auto` reads up to 24 bytes of the HTTP/2 preface without a timer
/// before entering HTTP/1.1 or HTTP/2, so a client sending 0 bytes or a partial preface
/// (`"PRI * "`) would otherwise hold a `max_connections` slot indefinitely. This wrapper arms a
/// single deadline until protocol detection resolves (either a byte mismatches `H2_PREFACE` and
/// Hyper hands off to HTTP/1.1's `header_read_timeout`, or all 24 bytes of `H2_PREFACE` arrive
/// and Hyper enters HTTP/2), then disarms itself with zero steady-state overhead.
struct InitialReadTimeoutIo<I> {
    inner: I,
    deadline: Option<Pin<Box<tokio::time::Sleep>>>,
    preface_matched: usize,
}

impl<I> InitialReadTimeoutIo<I> {
    fn new(inner: I, timeout: Duration) -> Self {
        Self {
            inner,
            deadline: Some(Box::pin(tokio::time::sleep(timeout))),
            preface_matched: 0,
        }
    }
}

impl<I: AsyncRead + Unpin> AsyncRead for InitialReadTimeoutIo<I> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let before = buf.filled().len();
        match Pin::new(&mut self.inner).poll_read(cx, buf) {
            Poll::Ready(Ok(())) => {
                if self.deadline.is_some() {
                    let newly_read = &buf.filled()[before..];
                    for &b in newly_read {
                        if self.preface_matched < H2_PREFACE.len()
                            && b == H2_PREFACE[self.preface_matched]
                        {
                            self.preface_matched += 1;
                            if self.preface_matched == H2_PREFACE.len() {
                                self.deadline = None;
                                break;
                            }
                        } else {
                            self.deadline = None;
                            break;
                        }
                    }
                }
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Err(err)) => Poll::Ready(Err(err)),
            Poll::Pending => {
                if let Some(sleep) = self.deadline.as_mut()
                    && sleep.as_mut().poll(cx).is_ready()
                {
                    self.deadline = None;
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "initial protocol detection timed out",
                    )));
                }
                Poll::Pending
            }
        }
    }
}

impl<I: AsyncWrite + Unpin> AsyncWrite for InitialReadTimeoutIo<I> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }

    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write_vectored(cx, bufs)
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
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
