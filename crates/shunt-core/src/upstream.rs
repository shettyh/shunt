use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use http::Uri;
use hyper::rt::{Read, ReadBufCursor, Write};
use hyper_util::client::legacy::Client;
use hyper_util::client::legacy::connect::{Connected, Connection};
use hyper_util::rt::{TokioExecutor, TokioIo};
use rustls::pki_types::ServerName;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tower_service::Service;

use crate::body::ShuntBody;
use crate::error::CoreError;
use crate::tls::UpstreamTlsConfig;

/// Configuration for a logical upstream cluster.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct UpstreamConfig {
    pub name: String,
    /// Endpoint base URLs, e.g. `http://127.0.0.1:8080` or `https://api.openai.com`.
    pub endpoints: Vec<String>,
    /// Use HTTP/2 prior knowledge (h2c) for cleartext endpoints.
    pub http2_only: bool,
    /// Upstream TLS settings.
    pub tls: UpstreamTlsConfig,
    /// Timeout for TCP connect + TLS handshake.
    pub connect_timeout: Duration,
    /// Idle timeout for pooled keep-alive connections.
    pub pool_idle_timeout: Duration,
    /// Maximum idle connections kept per host.
    pub pool_max_idle_per_host: usize,
    /// Consecutive transport failures before marking an endpoint temporarily unhealthy.
    pub unhealthy_threshold: usize,
    /// Cooldown duration before retrying a passively marked unhealthy endpoint.
    pub unhealthy_cooldown: Duration,
}

impl UpstreamConfig {
    pub fn new(name: impl Into<String>, endpoints: Vec<String>) -> Self {
        Self {
            name: name.into(),
            endpoints,
            http2_only: false,
            tls: UpstreamTlsConfig::default(),
            connect_timeout: Duration::from_secs(5),
            pool_idle_timeout: Duration::from_secs(90),
            pool_max_idle_per_host: 64,
            unhealthy_threshold: 3,
            unhealthy_cooldown: Duration::from_secs(10),
        }
    }

    /// Computes the pool identity key used by [`crate::RuntimeRegistry`] to reuse warm
    /// connection pools and passive health state across snapshot reloads.
    pub fn pool_key(&self) -> UpstreamPoolKey {
        UpstreamPoolKey {
            endpoints: self.endpoints.clone(),
            http2_only: self.http2_only,
            tls: self.tls.clone(),
            connect_timeout: self.connect_timeout,
            pool_idle_timeout: self.pool_idle_timeout,
            pool_max_idle_per_host: self.pool_max_idle_per_host,
            unhealthy_threshold: self.unhealthy_threshold,
            unhealthy_cooldown: self.unhealthy_cooldown,
        }
    }
}

/// Stable pool key determining when an existing warm pool can be reused across reloads.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct UpstreamPoolKey {
    pub endpoints: Vec<String>,
    pub http2_only: bool,
    pub tls: UpstreamTlsConfig,
    pub connect_timeout: Duration,
    pub pool_idle_timeout: Duration,
    pub pool_max_idle_per_host: usize,
    pub unhealthy_threshold: usize,
    pub unhealthy_cooldown: Duration,
}

/// Parsed endpoint with passive health tracking.
#[derive(Debug)]
pub struct EndpointState {
    pub raw_url: String,
    pub base_uri: Uri,
    consecutive_failures: AtomicUsize,
    unhealthy_until_ms: AtomicU64,
}

impl EndpointState {
    fn new(raw_url: String) -> Result<Self, CoreError> {
        let base_uri: Uri = raw_url.parse().map_err(|e| CoreError::InvalidUri {
            uri: raw_url.clone(),
            message: format!("{e}"),
        })?;

        let scheme = base_uri.scheme_str().unwrap_or("http");
        if scheme != "http" && scheme != "https" {
            return Err(CoreError::InvalidUri {
                uri: raw_url,
                message: format!("unsupported scheme `{scheme}`"),
            });
        }
        if base_uri.authority().is_none() {
            return Err(CoreError::InvalidUri {
                uri: raw_url,
                message: "missing host/authority".to_owned(),
            });
        }

        Ok(Self {
            raw_url,
            base_uri,
            consecutive_failures: AtomicUsize::new(0),
            unhealthy_until_ms: AtomicU64::new(0),
        })
    }

    pub fn is_healthy(&self, now_ms: u64) -> bool {
        let until = self.unhealthy_until_ms.load(Ordering::Relaxed);
        until == 0 || now_ms >= until
    }

    pub fn consecutive_failures(&self) -> usize {
        self.consecutive_failures.load(Ordering::Relaxed)
    }

    fn record_success(&self) {
        self.consecutive_failures.store(0, Ordering::Relaxed);
        self.unhealthy_until_ms.store(0, Ordering::Relaxed);
    }

    fn record_failure(&self, now_ms: u64, threshold: usize, cooldown: Duration) {
        let fails = self.consecutive_failures.fetch_add(1, Ordering::Relaxed) + 1;
        if fails >= threshold.max(1) {
            let until = now_ms.saturating_add(cooldown.as_millis() as u64);
            self.unhealthy_until_ms.store(until, Ordering::Relaxed);
        }
    }
}

/// Warm HTTP/1.1 + HTTP/2 connection pool and passive health manager for an upstream.
pub struct UpstreamPool {
    pool_id: u64,
    key: UpstreamPoolKey,
    endpoints: Vec<EndpointState>,
    rr_cursor: AtomicUsize,
    created_at: Instant,
    client: Client<ShuntConnector, ShuntBody>,
    connector_h1_tls: Option<TlsConnector>,
}

impl std::fmt::Debug for UpstreamPool {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UpstreamPool")
            .field("pool_id", &self.pool_id)
            .field("endpoints", &self.key.endpoints)
            .field("http2_only", &self.key.http2_only)
            .finish()
    }
}

impl UpstreamPool {
    pub fn new(pool_id: u64, config: &UpstreamConfig) -> Result<Self, CoreError> {
        if config.endpoints.is_empty() {
            return Err(CoreError::EmptyUpstream(config.name.clone()));
        }

        let mut endpoints = Vec::with_capacity(config.endpoints.len());
        for ep in &config.endpoints {
            endpoints.push(EndpointState::new(ep.clone())?);
        }

        let tls_cfg = config.tls.build_client_config(None)?;
        let tls_connector = TlsConnector::from(tls_cfg);

        // Separate H1-only ALPN TLS connector for WebSocket upgrade handshakes.
        let h1_tls_cfg = config
            .tls
            .build_client_config(Some(vec![b"http/1.1".to_vec()]))?;
        let connector_h1_tls = Some(TlsConnector::from(h1_tls_cfg));

        let connector = ShuntConnector {
            connect_timeout: config.connect_timeout,
            tls_connector,
        };

        let mut builder = Client::builder(TokioExecutor::new());
        builder
            .pool_idle_timeout(config.pool_idle_timeout)
            .pool_max_idle_per_host(config.pool_max_idle_per_host);
        if config.http2_only {
            builder.http2_only(true);
        }

        let client = builder.build(connector);

        Ok(Self {
            pool_id,
            key: config.pool_key(),
            endpoints,
            rr_cursor: AtomicUsize::new(0),
            created_at: Instant::now(),
            client,
            connector_h1_tls,
        })
    }

    /// Unique identifier for this pool instance (useful for verifying pool reuse across reloads).
    pub fn pool_id(&self) -> u64 {
        self.pool_id
    }

    pub fn key(&self) -> &UpstreamPoolKey {
        &self.key
    }

    pub fn endpoints(&self) -> &[EndpointState] {
        &self.endpoints
    }

    fn now_ms(&self) -> u64 {
        self.created_at.elapsed().as_millis() as u64
    }

    /// Selects the next healthy endpoint (round-robin), preferring endpoints not in `tried_indices`.
    pub fn select_endpoint(&self, tried_indices: &[usize]) -> (usize, &EndpointState) {
        let len = self.endpoints.len();
        let start = self.rr_cursor.fetch_add(1, Ordering::Relaxed) % len;
        let now = self.now_ms();

        // Pass 1: healthy & not yet tried in this request
        for offset in 0..len {
            let idx = (start + offset) % len;
            if !tried_indices.contains(&idx) && self.endpoints[idx].is_healthy(now) {
                return (idx, &self.endpoints[idx]);
            }
        }

        // Pass 2: any endpoint not yet tried in this request (even if marked unhealthy)
        for offset in 0..len {
            let idx = (start + offset) % len;
            if !tried_indices.contains(&idx) {
                return (idx, &self.endpoints[idx]);
            }
        }

        // Pass 3: wrap around to any healthy endpoint, else start
        for offset in 0..len {
            let idx = (start + offset) % len;
            if self.endpoints[idx].is_healthy(now) {
                return (idx, &self.endpoints[idx]);
            }
        }

        (start, &self.endpoints[start])
    }

    pub fn record_success(&self, endpoint_idx: usize) {
        if let Some(ep) = self.endpoints.get(endpoint_idx) {
            ep.record_success();
        }
    }

    pub fn record_failure(&self, endpoint_idx: usize) {
        if let Some(ep) = self.endpoints.get(endpoint_idx) {
            ep.record_failure(
                self.now_ms(),
                self.key.unhealthy_threshold,
                self.key.unhealthy_cooldown,
            );
        }
    }

    /// Sends an HTTP request through the warm connection pool, enforcing `response_headers_timeout`.
    pub async fn send_request(
        &self,
        req: http::Request<ShuntBody>,
        response_headers_timeout: Option<Duration>,
    ) -> Result<http::Response<hyper::body::Incoming>, CoreError> {
        let fut = self.client.request(req);
        let res = match response_headers_timeout {
            Some(dur) => tokio::time::timeout(dur, fut)
                .await
                .map_err(|_| CoreError::ResponseHeadersTimeout(dur))?,
            None => fut.await,
        };

        res.map_err(|err| {
            // Preserve connect-timeout diagnostics if the connector timed out.
            if err.is_connect()
                && let Some(source) = std::error::Error::source(&err)
                && let Some(CoreError::ConnectTimeout(d)) = source.downcast_ref::<CoreError>()
            {
                return CoreError::ConnectTimeout(*d);
            }
            CoreError::HyperClient(err)
        })
    }

    /// Opens a dedicated HTTP/1.1 stream (TCP or TLS with ALPN `http/1.1`) for WebSocket upgrades.
    pub async fn connect_for_upgrade(&self, uri: &Uri) -> Result<ShuntStream, CoreError> {
        let tls = self
            .connector_h1_tls
            .clone()
            .expect("h1 tls connector initialized");
        connect_uri(uri, self.key.connect_timeout, tls).await
    }
}

/// Resolves an endpoint base URI + relative request path/query into a full target URI.
pub fn build_target_uri(base_uri: &Uri, req_uri: &Uri) -> Result<Uri, CoreError> {
    let scheme = base_uri.scheme_str().unwrap_or("http");
    let authority = base_uri
        .authority()
        .ok_or_else(|| CoreError::InvalidUri {
            uri: base_uri.to_string(),
            message: "missing authority".to_owned(),
        })?
        .as_str();

    let base_path = base_uri.path().trim_end_matches('/');
    let req_pq = req_uri
        .path_and_query()
        .map(|pq| pq.as_str())
        .unwrap_or("/");

    let combined_pq = if base_path.is_empty() || base_path == "/" {
        if req_pq.starts_with('/') {
            req_pq.to_owned()
        } else {
            format!("/{req_pq}")
        }
    } else if req_pq.starts_with('/') {
        format!("{base_path}{req_pq}")
    } else {
        format!("{base_path}/{req_pq}")
    };

    Uri::builder()
        .scheme(scheme)
        .authority(authority)
        .path_and_query(combined_pq)
        .build()
        .map_err(|e| CoreError::InvalidUri {
            uri: format!("{scheme}://{authority}"),
            message: e.to_string(),
        })
}

/// TCP or TLS upstream stream.
pub enum MaybeTlsStream {
    Http(TcpStream),
    Https(Box<tokio_rustls::client::TlsStream<TcpStream>>),
}

impl AsyncRead for MaybeTlsStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            MaybeTlsStream::Http(s) => Pin::new(s).poll_read(cx, buf),
            MaybeTlsStream::Https(s) => Pin::new(s.as_mut()).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for MaybeTlsStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        match self.get_mut() {
            MaybeTlsStream::Http(s) => Pin::new(s).poll_write(cx, buf),
            MaybeTlsStream::Https(s) => Pin::new(s.as_mut()).poll_write(cx, buf),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            MaybeTlsStream::Http(s) => Pin::new(s).poll_flush(cx),
            MaybeTlsStream::Https(s) => Pin::new(s.as_mut()).poll_flush(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            MaybeTlsStream::Http(s) => Pin::new(s).poll_shutdown(cx),
            MaybeTlsStream::Https(s) => Pin::new(s.as_mut()).poll_shutdown(cx),
        }
    }
}

/// Hyper-compatible upstream connection stream implementing `Read`, `Write`, and `Connection`.
pub struct ShuntStream {
    io: TokioIo<MaybeTlsStream>,
}

impl ShuntStream {
    pub fn new(stream: MaybeTlsStream) -> Self {
        Self {
            io: TokioIo::new(stream),
        }
    }
}

impl Read for ShuntStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: ReadBufCursor<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.io).poll_read(cx, buf)
    }
}

impl Write for ShuntStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.io).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.io).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.io).poll_shutdown(cx)
    }
}

impl Connection for ShuntStream {
    fn connected(&self) -> Connected {
        let conn = Connected::new();
        match self.io.inner() {
            MaybeTlsStream::Http(_) => conn,
            MaybeTlsStream::Https(tls) => {
                if tls.get_ref().1.alpn_protocol() == Some(b"h2") {
                    conn.negotiated_h2()
                } else {
                    conn
                }
            }
        }
    }
}

#[derive(Clone)]
struct ShuntConnector {
    connect_timeout: Duration,
    tls_connector: TlsConnector,
}

impl Service<Uri> for ShuntConnector {
    type Response = ShuntStream;
    type Error = CoreError;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, uri: Uri) -> Self::Future {
        let timeout = self.connect_timeout;
        let tls = self.tls_connector.clone();
        Box::pin(async move { connect_uri(&uri, timeout, tls).await })
    }
}

async fn connect_uri(
    uri: &Uri,
    connect_timeout: Duration,
    tls_connector: TlsConnector,
) -> Result<ShuntStream, CoreError> {
    let scheme = uri.scheme_str().unwrap_or("http");
    let host = uri
        .host()
        .ok_or_else(|| CoreError::InvalidUri {
            uri: uri.to_string(),
            message: "missing host".to_owned(),
        })?
        .trim_matches(|c| c == '[' || c == ']')
        .to_owned();

    let port = uri
        .port_u16()
        .unwrap_or(if scheme == "https" { 443 } else { 80 });

    let deadline = Instant::now() + connect_timeout;

    let connect_fut = async {
        if let Ok(ip) = host.parse::<std::net::IpAddr>() {
            TcpStream::connect(std::net::SocketAddr::new(ip, port)).await
        } else {
            TcpStream::connect((host.as_str(), port)).await
        }
    };

    let tcp = tokio::time::timeout(connect_timeout, connect_fut)
        .await
        .map_err(|_| CoreError::ConnectTimeout(connect_timeout))??;

    let _ = tcp.set_nodelay(true);

    if scheme == "https" {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(CoreError::ConnectTimeout(connect_timeout));
        }
        let server_name = ServerName::try_from(host.clone())
            .map_err(|e| CoreError::Tls(format!("invalid TLS server name `{host}`: {e}")))?;
        let tls_stream = tokio::time::timeout(remaining, tls_connector.connect(server_name, tcp))
            .await
            .map_err(|_| CoreError::ConnectTimeout(connect_timeout))?
            .map_err(|e| CoreError::Tls(format!("upstream TLS handshake failed: {e}")))?;
        Ok(ShuntStream::new(MaybeTlsStream::Https(Box::new(tls_stream))))
    } else {
        Ok(ShuntStream::new(MaybeTlsStream::Http(tcp)))
    }
}
