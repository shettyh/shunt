mod certs;
mod presets;
mod upstream;

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use bytes::Bytes;
use clap::{Parser, Subcommand};
use http::{HeaderName, HeaderValue, Method, Request, Response, Uri, header};
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper_util::rt::{TokioExecutor, TokioIo};
use rustls::ClientConfig;
use tokio::net::TcpStream;
use tokio::sync::Barrier;
use tokio_rustls::TlsConnector;

use crate::certs::{build_tls_client_config, generate_bench_certs, server_name_for_host};
use crate::presets::{BodyTemplate, resolve_preset};

#[derive(Parser, Debug)]
#[command(
    name = "shunt-bench",
    about = "Reproducible mock upstream, TLS cert generator & HTTP/H2/TLS/SSE/MCP load generator for Shunt benchmarks"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Generate ephemeral CA, server (`127.0.0.1` + `localhost`), and mTLS client PEM certs.
    GenCerts {
        /// Output directory where `ca.pem`, `server.pem`, `server-key.pem`, `client.pem`, `client-key.pem` are written.
        #[arg(long)]
        out_dir: PathBuf,
    },
    /// Start a high-performance HTTP/1.1 + HTTP/2 mock upstream server (API, AI & MCP).
    Upstream {
        /// Listen address (e.g., 127.0.0.1:18080).
        #[arg(long, default_value = "127.0.0.1:18080")]
        listen: SocketAddr,
        /// Fixed payload size in bytes for `/ping` responses.
        #[arg(long, default_value_t = 256)]
        payload_bytes: usize,
        /// Number of SSE / EventStream chunks emitted per stream.
        #[arg(long, default_value_t = 20)]
        sse_chunks: usize,
        /// Delay between consecutive SSE chunks in milliseconds.
        #[arg(long, default_value_t = 25)]
        sse_interval_ms: u64,
        /// Optional HTTP status code returned for all non-`/health` requests (e.g., `503` for failover tests).
        #[arg(long)]
        always_status: Option<u16>,
    },
    /// Run a multi-worker keep-alive HTTP/1.1, HTTP/2, TLS/mTLS, or open-loop throughput & latency benchmark.
    Http {
        /// Target URL (e.g., http://127.0.0.1:18081/ping or https://127.0.0.1:18081/ping).
        #[arg(long)]
        url: String,
        /// Number of concurrent workers.
        #[arg(short = 'c', long, default_value_t = 64)]
        concurrency: usize,
        /// Benchmark duration in seconds (ignored when `--single-wave` is set).
        #[arg(short = 'd', long, default_value_t = 10)]
        duration_secs: u64,
        /// Warmup duration in seconds before recording samples.
        #[arg(long, default_value_t = 2)]
        warmup_secs: u64,
        /// HTTP method (`GET`, `POST`, etc.).
        #[arg(long, default_value = "GET")]
        method: String,
        /// Optional raw request body for `POST`/`PUT` requests.
        #[arg(long)]
        body: Option<String>,
        /// Named built-in payload preset (e.g., `ai-anthropic-4k`, `mcp-tools-call`).
        #[arg(long)]
        body_preset: Option<String>,
        /// Replace `{{NONCE}}` in body with `0..N` (`0` = unique monotonic nonce per request).
        #[arg(long)]
        cache_cardinality: Option<usize>,
        /// Optional extra request headers (`Name: Value`), repeatable.
        #[arg(short = 'H', long = "header")]
        headers: Vec<String>,
        /// Use HTTP/2 (`h2` ALPN over HTTPS or `h2c` prior knowledge over HTTP).
        #[arg(long)]
        http2: bool,
        /// Number of multiplexed HTTP/2 connections shared across workers (default: min(c, 8)).
        #[arg(long)]
        h2_conns: Option<usize>,
        /// Expected HTTP status code counted as `ok` (default: 200; set e.g. 401/429/400 for rejection fast-paths).
        #[arg(long, default_value_t = 200)]
        expect_status: u16,
        /// Open-loop target rate in requests/second (coordinated-omission-free latency mode).
        #[arg(long)]
        rate: Option<u64>,
        /// Fire exactly one barrier-synchronized wave of `concurrency` requests (e.g., singleflight test).
        #[arg(long)]
        single_wave: bool,
        /// Optional CA certificate PEM path for verifying HTTPS targets.
        #[arg(long)]
        ca_cert: Option<PathBuf>,
        /// Skip TLS server certificate verification for HTTPS targets.
        #[arg(long)]
        insecure: bool,
        /// Optional client certificate PEM path for mTLS.
        #[arg(long)]
        client_cert: Option<PathBuf>,
        /// Optional client private key PEM path for mTLS.
        #[arg(long)]
        client_key: Option<PathBuf>,
        /// Optional Admin reload URL (e.g., `http://127.0.0.1:19090/reload`) polled during measurement.
        #[arg(long)]
        reload_url: Option<String>,
        /// Interval in milliseconds between `POST --reload-url` triggers (default: 500ms).
        #[arg(long, default_value_t = 500)]
        reload_interval_ms: u64,
        /// Emit compact JSON summary line instead of human-readable table.
        #[arg(long)]
        json: bool,
    },
    /// Run a high-concurrency SSE streaming benchmark (e.g., 500–1,000+ concurrent streams).
    Sse {
        /// Target URL (e.g., http://127.0.0.1:18081/sse or http://127.0.0.1:18081/v1/chat/completions).
        #[arg(long)]
        url: String,
        /// Number of concurrent streams to open simultaneously.
        #[arg(short = 'c', long, default_value_t = 1000)]
        concurrency: usize,
        /// Number of waves (rounds of `concurrency` streams).
        #[arg(long, default_value_t = 1)]
        waves: usize,
        /// HTTP method (`GET` for raw SSE passthrough, `POST` for AI/MCP endpoints).
        #[arg(long, default_value = "GET")]
        method: String,
        /// Optional raw JSON body for `POST` requests.
        #[arg(long)]
        body: Option<String>,
        /// Named built-in payload preset (e.g., `ai-anthropic-sse`, `mcp-tools-call-sse`).
        #[arg(long)]
        body_preset: Option<String>,
        /// Replace `{{NONCE}}` in body with `0..N` (`0` = unique monotonic nonce per stream).
        #[arg(long)]
        cache_cardinality: Option<usize>,
        /// Optional extra request headers (`Name: Value`), repeatable.
        #[arg(short = 'H', long = "header")]
        headers: Vec<String>,
        /// Expected HTTP status code (default: 200).
        #[arg(long, default_value_t = 200)]
        expect_status: u16,
        /// Require `[DONE]` sentinel in stream (disable for MCP SSE or non-OpenAI streams).
        #[arg(long, default_value_t = true, action = clap::ArgAction::Set)]
        require_done: bool,
        /// Optional CA certificate PEM path for verifying HTTPS targets.
        #[arg(long)]
        ca_cert: Option<PathBuf>,
        /// Skip TLS server certificate verification for HTTPS targets.
        #[arg(long)]
        insecure: bool,
        /// Emit compact JSON summary line instead of human-readable table.
        #[arg(long)]
        json: bool,
    },
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    match cli.command {
        Commands::GenCerts { out_dir } => {
            if let Err(e) = generate_bench_certs(&out_dir) {
                eprintln!("error: {e}");
                std::process::exit(1);
            }
            println!(
                "generated benchmark TLS/mTLS certs in {}",
                out_dir.display()
            );
        }
        Commands::Upstream {
            listen,
            payload_bytes,
            sse_chunks,
            sse_interval_ms,
            always_status,
        } => {
            upstream::run_upstream(
                listen,
                payload_bytes,
                sse_chunks,
                sse_interval_ms,
                always_status,
            )
            .await;
        }
        Commands::Http {
            url,
            concurrency,
            duration_secs,
            warmup_secs,
            method,
            body,
            body_preset,
            cache_cardinality,
            headers,
            http2,
            h2_conns,
            expect_status,
            rate,
            single_wave,
            ca_cert,
            insecure,
            client_cert,
            client_key,
            reload_url,
            reload_interval_ms,
            json,
        } => {
            let raw_body = resolve_body_arg(body, body_preset);
            let body_template = Arc::new(BodyTemplate::compile(raw_body, cache_cardinality));
            let tls_cfg = maybe_tls_config(
                &url,
                ca_cert.as_deref(),
                insecure,
                client_cert.as_deref(),
                client_key.as_deref(),
                http2,
            );
            run_http_bench(HttpBenchConfig {
                url,
                concurrency,
                duration: Duration::from_secs(duration_secs),
                warmup: Duration::from_secs(warmup_secs),
                method_str: method,
                body_template,
                cache_cardinality,
                raw_headers: headers,
                http2,
                h2_conns,
                expect_status,
                rate,
                single_wave,
                tls_cfg,
                reload_url,
                reload_interval_ms,
                json_out: json,
            })
            .await;
        }
        Commands::Sse {
            url,
            concurrency,
            waves,
            method,
            body,
            body_preset,
            cache_cardinality,
            headers,
            expect_status,
            require_done,
            ca_cert,
            insecure,
            json,
        } => {
            let raw_body = resolve_body_arg(body, body_preset);
            let body_template = Arc::new(BodyTemplate::compile(raw_body, cache_cardinality));
            let tls_cfg = maybe_tls_config(&url, ca_cert.as_deref(), insecure, None, None, false);
            run_sse_bench(SseBenchConfig {
                url,
                concurrency,
                waves,
                method_str: method,
                body_template,
                cache_cardinality,
                raw_headers: headers,
                expect_status,
                require_done,
                tls_cfg,
                json_out: json,
            })
            .await;
        }
    }
}

fn resolve_body_arg(body: Option<String>, body_preset: Option<String>) -> String {
    match (body, body_preset) {
        (Some(b), _) => b,
        (None, Some(preset)) => resolve_preset(&preset).unwrap_or_else(|e| {
            eprintln!("error: {e}");
            std::process::exit(1);
        }),
        (None, None) => String::new(),
    }
}

fn maybe_tls_config(
    url: &str,
    ca_cert: Option<&std::path::Path>,
    insecure: bool,
    client_cert: Option<&std::path::Path>,
    client_key: Option<&std::path::Path>,
    http2: bool,
) -> Option<Arc<ClientConfig>> {
    if !url.starts_with("https://") {
        return None;
    }
    match build_tls_client_config(ca_cert, insecure, client_cert, client_key, http2) {
        Ok(cfg) => Some(cfg),
        Err(e) => {
            eprintln!("error: {e}");
            std::process::exit(1);
        }
    }
}

// =============================================================================
// Low-Level Connection Helpers (HTTP/1.1 & HTTP/2 over Plain TCP or TLS/mTLS)
// =============================================================================

struct TargetEndpoint {
    scheme_https: bool,
    host: String,
    port: u16,
    authority: String,
    path_and_query: Uri,
    full_uri: Uri,
}

impl TargetEndpoint {
    fn parse(url: &str) -> Self {
        let uri: Uri = url.parse().expect("invalid target URL");
        let scheme_https = uri.scheme_str() == Some("https");
        let host = uri.host().expect("URL missing host").to_owned();
        let port = uri
            .port_u16()
            .unwrap_or(if scheme_https { 443 } else { 80 });
        let authority = uri
            .authority()
            .expect("URL missing authority")
            .as_str()
            .to_owned();
        let path_and_query: Uri = uri
            .path_and_query()
            .map(|pq| pq.as_str())
            .unwrap_or("/")
            .parse()
            .expect("valid path_and_query");
        Self {
            scheme_https,
            host,
            port,
            authority,
            path_and_query,
            full_uri: uri,
        }
    }
}

async fn connect_tcp(host: &str, port: u16) -> Result<TcpStream, ()> {
    let stream = if let Ok(ip) = host.parse::<std::net::IpAddr>() {
        TcpStream::connect(SocketAddr::new(ip, port)).await
    } else {
        TcpStream::connect((host, port)).await
    }
    .map_err(|_| ())?;
    let _ = stream.set_nodelay(true);
    Ok(stream)
}

async fn connect_h1(
    target: &TargetEndpoint,
    tls_cfg: Option<&Arc<ClientConfig>>,
) -> Result<hyper::client::conn::http1::SendRequest<Full<Bytes>>, ()> {
    let tcp = connect_tcp(&target.host, target.port).await?;
    if target.scheme_https {
        let cfg = tls_cfg.ok_or(())?;
        let connector = TlsConnector::from(Arc::clone(cfg));
        let server_name = server_name_for_host(&target.host).map_err(|_| ())?;
        let tls = connector.connect(server_name, tcp).await.map_err(|_| ())?;
        let (sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(tls))
            .await
            .map_err(|_| ())?;
        tokio::spawn(async move {
            let _ = conn.await;
        });
        Ok(sender)
    } else {
        let (sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(tcp))
            .await
            .map_err(|_| ())?;
        tokio::spawn(async move {
            let _ = conn.await;
        });
        Ok(sender)
    }
}

async fn connect_h2(
    target: &TargetEndpoint,
    tls_cfg: Option<&Arc<ClientConfig>>,
) -> Result<hyper::client::conn::http2::SendRequest<Full<Bytes>>, ()> {
    let tcp = connect_tcp(&target.host, target.port).await?;
    if target.scheme_https {
        let cfg = tls_cfg.ok_or(())?;
        let connector = TlsConnector::from(Arc::clone(cfg));
        let server_name = server_name_for_host(&target.host).map_err(|_| ())?;
        let tls = connector.connect(server_name, tcp).await.map_err(|_| ())?;
        let (sender, conn) =
            hyper::client::conn::http2::handshake(TokioExecutor::new(), TokioIo::new(tls))
                .await
                .map_err(|_| ())?;
        tokio::spawn(async move {
            let _ = conn.await;
        });
        Ok(sender)
    } else {
        let (sender, conn) =
            hyper::client::conn::http2::handshake(TokioExecutor::new(), TokioIo::new(tcp))
                .await
                .map_err(|_| ())?;
        tokio::spawn(async move {
            let _ = conn.await;
        });
        Ok(sender)
    }
}

enum WorkerConn {
    H1(Option<hyper::client::conn::http1::SendRequest<Full<Bytes>>>),
    H2(Option<hyper::client::conn::http2::SendRequest<Full<Bytes>>>),
}

impl WorkerConn {
    async fn send(
        &mut self,
        target: &TargetEndpoint,
        tls_cfg: Option<&Arc<ClientConfig>>,
        method: &Method,
        headers: &[(HeaderName, HeaderValue)],
        body: Bytes,
    ) -> Result<Response<Incoming>, ()> {
        match self {
            WorkerConn::H1(slot) => {
                if slot.as_ref().map(|s| s.is_closed()).unwrap_or(true) {
                    *slot = Some(connect_h1(target, tls_cfg).await?);
                }
                let sender = slot.as_mut().unwrap();
                if sender.ready().await.is_err() {
                    *slot = None;
                    return Err(());
                }
                let mut builder = Request::builder()
                    .method(method.clone())
                    .uri(target.path_and_query.clone())
                    .header(header::HOST, &target.authority);
                for (k, v) in headers {
                    builder = builder.header(k, v);
                }
                let req = builder.body(Full::new(body)).unwrap();
                sender.send_request(req).await.map_err(|_| {
                    *slot = None;
                })
            }
            WorkerConn::H2(slot) => {
                if slot.as_ref().map(|s| s.is_closed()).unwrap_or(true) {
                    *slot = Some(connect_h2(target, tls_cfg).await?);
                }
                let sender = slot.as_mut().unwrap();
                if sender.ready().await.is_err() {
                    *slot = None;
                    return Err(());
                }
                let mut builder = Request::builder()
                    .method(method.clone())
                    .uri(target.full_uri.clone());
                for (k, v) in headers {
                    builder = builder.header(k, v);
                }
                let req = builder.body(Full::new(body)).unwrap();
                sender.send_request(req).await.map_err(|_| {
                    *slot = None;
                })
            }
        }
    }

    fn reset(&mut self) {
        match self {
            WorkerConn::H1(s) => *s = None,
            WorkerConn::H2(s) => *s = None,
        }
    }
}

fn parse_headers(raw: &[String]) -> Vec<(HeaderName, HeaderValue)> {
    raw.iter()
        .map(|h| {
            let (k, v) = h
                .split_once(':')
                .unwrap_or_else(|| panic!("invalid header `{h}`, expected `Name: Value`"));
            let name = HeaderName::from_bytes(k.trim().as_bytes())
                .unwrap_or_else(|e| panic!("invalid header name `{k}`: {e}"));
            let val = HeaderValue::from_str(v.trim())
                .unwrap_or_else(|e| panic!("invalid header value `{v}`: {e}"));
            (name, val)
        })
        .collect()
}

// =============================================================================
// HTTP Keep-Alive / H2 / TLS / Open-Loop / Reload-Under-Load Benchmark
// =============================================================================

struct HttpBenchConfig {
    url: String,
    concurrency: usize,
    duration: Duration,
    warmup: Duration,
    method_str: String,
    body_template: Arc<BodyTemplate>,
    cache_cardinality: Option<usize>,
    raw_headers: Vec<String>,
    http2: bool,
    h2_conns: Option<usize>,
    expect_status: u16,
    rate: Option<u64>,
    single_wave: bool,
    tls_cfg: Option<Arc<ClientConfig>>,
    reload_url: Option<String>,
    reload_interval_ms: u64,
    json_out: bool,
}

async fn run_http_bench(cfg: HttpBenchConfig) {
    let target = Arc::new(TargetEndpoint::parse(&cfg.url));
    let method = Method::from_bytes(cfg.method_str.as_bytes()).expect("invalid HTTP method");
    let mut parsed_headers = parse_headers(&cfg.raw_headers);
    if !cfg.body_template.is_empty()
        && !parsed_headers
            .iter()
            .any(|(k, _)| *k == header::CONTENT_TYPE)
    {
        parsed_headers.push((
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/json"),
        ));
    }
    let headers = Arc::new(parsed_headers);

    // Pre-establish shared H2 connections for true HTTP/2 stream multiplexing across workers.
    let shared_h2: Option<Vec<hyper::client::conn::http2::SendRequest<Full<Bytes>>>> = if cfg.http2
    {
        let pool_size = cfg
            .h2_conns
            .unwrap_or_else(|| cfg.concurrency.min(8))
            .max(1);
        let mut conns = Vec::with_capacity(pool_size);
        for _ in 0..pool_size {
            if let Ok(sender) = connect_h2(&target, cfg.tls_cfg.as_ref()).await {
                conns.push(sender);
            }
        }
        if conns.is_empty() { None } else { Some(conns) }
    } else {
        None
    };

    let recording = Arc::new(AtomicBool::new(false));
    let stop = Arc::new(AtomicBool::new(false));
    let ok_count = Arc::new(AtomicU64::new(0));
    let err_count = Arc::new(AtomicU64::new(0));
    let total_bytes = Arc::new(AtomicU64::new(0));
    let seq_counter = Arc::new(AtomicU64::new(0));

    let reloads_ok = Arc::new(AtomicU64::new(0));
    let reloads_failed = Arc::new(AtomicU64::new(0));
    let reload_stop = Arc::new(AtomicBool::new(false));

    let mode = if cfg.single_wave {
        "single_wave"
    } else if cfg.rate.is_some() {
        "open_loop"
    } else {
        "closed_loop"
    };

    let (elapsed, mut all_latencies) = if cfg.single_wave {
        let barrier = Arc::new(Barrier::new(cfg.concurrency));
        let mut handles = Vec::with_capacity(cfg.concurrency);
        let wall_start = Instant::now();
        for w in 0..cfg.concurrency {
            let target = Arc::clone(&target);
            let method = method.clone();
            let headers = Arc::clone(&headers);
            let body_template = Arc::clone(&cfg.body_template);
            let tls_cfg = cfg.tls_cfg.clone();
            let barrier = Arc::clone(&barrier);
            let ok_count = Arc::clone(&ok_count);
            let err_count = Arc::clone(&err_count);
            let total_bytes = Arc::clone(&total_bytes);
            let seq_counter = Arc::clone(&seq_counter);
            let expect_status = cfg.expect_status;
            let cache_cardinality = cfg.cache_cardinality;
            let mut conn = if cfg.http2 {
                WorkerConn::H2(shared_h2.as_ref().map(|v| v[w % v.len()].clone()))
            } else {
                WorkerConn::H1(None)
            };

            handles.push(tokio::spawn(async move {
                barrier.wait().await;
                let seq = seq_counter.fetch_add(1, Ordering::Relaxed);
                let body = body_template.render(seq, cache_cardinality);
                let t0 = Instant::now();
                let res = conn
                    .send(&target, tls_cfg.as_ref(), &method, &headers, body)
                    .await;
                match res {
                    Ok(resp) => {
                        let status = resp.status().as_u16();
                        match resp.into_body().collect().await {
                            Ok(collected) => {
                                let lat = t0.elapsed().as_micros() as u64;
                                if status == expect_status {
                                    ok_count.fetch_add(1, Ordering::Relaxed);
                                    total_bytes.fetch_add(
                                        collected.to_bytes().len() as u64,
                                        Ordering::Relaxed,
                                    );
                                    return Some(lat);
                                }
                                err_count.fetch_add(1, Ordering::Relaxed);
                            }
                            Err(_) => {
                                err_count.fetch_add(1, Ordering::Relaxed);
                            }
                        }
                    }
                    Err(_) => {
                        err_count.fetch_add(1, Ordering::Relaxed);
                    }
                }
                None
            }));
        }
        let mut lats = Vec::with_capacity(cfg.concurrency);
        for h in handles {
            if let Ok(Some(l)) = h.await {
                lats.push(l);
            }
        }
        (wall_start.elapsed(), lats)
    } else if let Some(target_rps) = cfg.rate {
        // Coordinated-omission-free open-loop benchmark.
        let target_rps = target_rps.max(1);
        let warmup_end = Instant::now() + cfg.warmup;
        let measure_start = warmup_end;
        let measure_end = measure_start + cfg.duration;
        let interval_ns = 1_000_000_000.0 / (target_rps as f64);

        let reload_handle = spawn_reload_driver(
            cfg.reload_url.clone(),
            cfg.reload_interval_ms,
            cfg.warmup,
            Arc::clone(&reload_stop),
            Arc::clone(&reloads_ok),
            Arc::clone(&reloads_failed),
        );

        let mut handles = Vec::with_capacity(cfg.concurrency);
        for w in 0..cfg.concurrency {
            let target = Arc::clone(&target);
            let method = method.clone();
            let headers = Arc::clone(&headers);
            let body_template = Arc::clone(&cfg.body_template);
            let tls_cfg = cfg.tls_cfg.clone();
            let ok_count = Arc::clone(&ok_count);
            let err_count = Arc::clone(&err_count);
            let total_bytes = Arc::clone(&total_bytes);
            let seq_counter = Arc::clone(&seq_counter);
            let expect_status = cfg.expect_status;
            let cache_cardinality = cfg.cache_cardinality;
            let concurrency = cfg.concurrency;
            let mut conn = if cfg.http2 {
                WorkerConn::H2(shared_h2.as_ref().map(|v| v[w % v.len()].clone()))
            } else {
                WorkerConn::H1(None)
            };

            handles.push(tokio::spawn(async move {
                // Warmup phase at same rate without recording
                if !cfg.warmup.is_zero() {
                    let warmup_origin = Instant::now();
                    let mut k: u64 = 0;
                    loop {
                        let idx = (w as u64) + k * (concurrency as u64);
                        let sched =
                            warmup_origin + Duration::from_nanos((idx as f64 * interval_ns) as u64);
                        if sched >= warmup_end {
                            break;
                        }
                        let now = Instant::now();
                        if sched > now {
                            tokio::time::sleep(sched - now).await;
                        }
                        let seq = seq_counter.fetch_add(1, Ordering::Relaxed);
                        let body = body_template.render(seq, cache_cardinality);
                        if let Ok(resp) = conn
                            .send(&target, tls_cfg.as_ref(), &method, &headers, body)
                            .await
                        {
                            let _ = resp.into_body().collect().await;
                        } else {
                            conn.reset();
                        }
                        k += 1;
                    }
                }

                // Wait for exact measurement window start
                let now = Instant::now();
                if measure_start > now {
                    tokio::time::sleep(measure_start - now).await;
                }

                let mut latencies_us: Vec<u64> = Vec::with_capacity(8192);
                let mut k: u64 = 0;
                loop {
                    let idx = (w as u64) + k * (concurrency as u64);
                    let sched =
                        measure_start + Duration::from_nanos((idx as f64 * interval_ns) as u64);
                    if sched >= measure_end {
                        break;
                    }
                    let now = Instant::now();
                    if sched > now {
                        tokio::time::sleep(sched - now).await;
                    }
                    let seq = seq_counter.fetch_add(1, Ordering::Relaxed);
                    let body = body_template.render(seq, cache_cardinality);
                    let res = conn
                        .send(&target, tls_cfg.as_ref(), &method, &headers, body)
                        .await;
                    match res {
                        Ok(resp) => {
                            let status = resp.status().as_u16();
                            match resp.into_body().collect().await {
                                Ok(collected) => {
                                    // Measure from scheduled arrival time (eliminates coordinated omission).
                                    let elapsed_us = sched.elapsed().as_micros() as u64;
                                    if status == expect_status {
                                        ok_count.fetch_add(1, Ordering::Relaxed);
                                        total_bytes.fetch_add(
                                            collected.to_bytes().len() as u64,
                                            Ordering::Relaxed,
                                        );
                                        latencies_us.push(elapsed_us);
                                    } else {
                                        err_count.fetch_add(1, Ordering::Relaxed);
                                    }
                                }
                                Err(_) => {
                                    conn.reset();
                                    err_count.fetch_add(1, Ordering::Relaxed);
                                }
                            }
                        }
                        Err(_) => {
                            conn.reset();
                            err_count.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                    k += 1;
                }
                latencies_us
            }));
        }

        let mut lats = Vec::new();
        for h in handles {
            if let Ok(mut v) = h.await {
                lats.append(&mut v);
            }
        }
        reload_stop.store(true, Ordering::Release);
        if let Some(rh) = reload_handle {
            let _ = rh.await;
        }
        (measure_start.elapsed(), lats)
    } else {
        // Closed-loop max-throughput benchmark.
        let mut handles = Vec::with_capacity(cfg.concurrency);
        for w in 0..cfg.concurrency {
            let target = Arc::clone(&target);
            let method = method.clone();
            let headers = Arc::clone(&headers);
            let body_template = Arc::clone(&cfg.body_template);
            let tls_cfg = cfg.tls_cfg.clone();
            let recording = Arc::clone(&recording);
            let stop = Arc::clone(&stop);
            let ok_count = Arc::clone(&ok_count);
            let err_count = Arc::clone(&err_count);
            let total_bytes = Arc::clone(&total_bytes);
            let seq_counter = Arc::clone(&seq_counter);
            let expect_status = cfg.expect_status;
            let cache_cardinality = cfg.cache_cardinality;
            let mut conn = if cfg.http2 {
                WorkerConn::H2(shared_h2.as_ref().map(|v| v[w % v.len()].clone()))
            } else {
                WorkerConn::H1(None)
            };

            handles.push(tokio::spawn(async move {
                let mut latencies_us: Vec<u64> = Vec::with_capacity(8192);
                while !stop.load(Ordering::Relaxed) {
                    let seq = seq_counter.fetch_add(1, Ordering::Relaxed);
                    let body = body_template.render(seq, cache_cardinality);
                    let t0 = Instant::now();
                    let res = conn
                        .send(&target, tls_cfg.as_ref(), &method, &headers, body)
                        .await;
                    let rec = recording.load(Ordering::Relaxed);
                    match res {
                        Ok(resp) => {
                            let status = resp.status().as_u16();
                            match resp.into_body().collect().await {
                                Ok(collected) => {
                                    let elapsed_us = t0.elapsed().as_micros() as u64;
                                    if rec {
                                        if status == expect_status {
                                            ok_count.fetch_add(1, Ordering::Relaxed);
                                            total_bytes.fetch_add(
                                                collected.to_bytes().len() as u64,
                                                Ordering::Relaxed,
                                            );
                                            latencies_us.push(elapsed_us);
                                        } else {
                                            err_count.fetch_add(1, Ordering::Relaxed);
                                        }
                                    }
                                }
                                Err(_) => {
                                    conn.reset();
                                    if rec {
                                        err_count.fetch_add(1, Ordering::Relaxed);
                                    }
                                }
                            }
                        }
                        Err(_) => {
                            conn.reset();
                            if rec {
                                err_count.fetch_add(1, Ordering::Relaxed);
                            }
                        }
                    }
                }
                latencies_us
            }));
        }

        let reload_handle = spawn_reload_driver(
            cfg.reload_url.clone(),
            cfg.reload_interval_ms,
            cfg.warmup,
            Arc::clone(&reload_stop),
            Arc::clone(&reloads_ok),
            Arc::clone(&reloads_failed),
        );

        if !cfg.warmup.is_zero() {
            tokio::time::sleep(cfg.warmup).await;
        }
        let measure_start = Instant::now();
        recording.store(true, Ordering::Release);
        tokio::time::sleep(cfg.duration).await;
        stop.store(true, Ordering::Release);
        reload_stop.store(true, Ordering::Release);
        let elapsed = measure_start.elapsed();

        let mut lats = Vec::new();
        for h in handles {
            if let Ok(mut v) = h.await {
                lats.append(&mut v);
            }
        }
        if let Some(rh) = reload_handle {
            let _ = rh.await;
        }
        (elapsed, lats)
    };

    all_latencies.sort_unstable();

    let ok = ok_count.load(Ordering::Relaxed);
    let errs = err_count.load(Ordering::Relaxed);
    let bytes = total_bytes.load(Ordering::Relaxed);
    let rps = ok as f64 / elapsed.as_secs_f64().max(1e-9);
    let p50 = percentile(&all_latencies, 50.0);
    let p95 = percentile(&all_latencies, 95.0);
    let p99 = percentile(&all_latencies, 99.0);
    let p999 = percentile(&all_latencies, 99.9);
    let max = all_latencies.last().copied().unwrap_or(0);
    let r_ok = reloads_ok.load(Ordering::Relaxed);
    let r_fail = reloads_failed.load(Ordering::Relaxed);

    if cfg.json_out {
        let mut obj = serde_json::json!({
            "workload": if cfg.reload_url.is_some() { "reload" } else { "http" },
            "mode": mode,
            "url": cfg.url,
            "http2": cfg.http2,
            "tls": target.scheme_https,
            "concurrency": cfg.concurrency,
            "expect_status": cfg.expect_status,
            "duration_s": (elapsed.as_secs_f64() * 1000.0).round() / 1000.0,
            "ok": ok,
            "errors": errs,
            "bytes": bytes,
            "rps": (rps * 10.0).round() / 10.0,
            "p50_us": p50,
            "p95_us": p95,
            "p99_us": p99,
            "p999_us": p999,
            "max_us": max,
        });
        if let Some(target_rps) = cfg.rate {
            obj["target_rps"] = serde_json::json!(target_rps);
        }
        if cfg.reload_url.is_some() {
            obj["reloads_ok"] = serde_json::json!(r_ok);
            obj["reloads_failed"] = serde_json::json!(r_fail);
        }
        println!("{}", serde_json::to_string(&obj).unwrap());
    } else {
        println!(
            "HTTP Benchmark: {} (mode={mode}, c={}, d={:.2}s, h2={}, tls={}, expect={})",
            cfg.url,
            cfg.concurrency,
            elapsed.as_secs_f64(),
            cfg.http2,
            target.scheme_https,
            cfg.expect_status
        );
        println!("  Requests : {ok} ok, {errs} errors ({rps:.1} req/s)");
        println!(
            "  Latency  : p50={}µs | p95={}µs | p99={}µs | p999={}µs | max={}µs",
            p50, p95, p99, p999, max
        );
        if cfg.reload_url.is_some() {
            println!("  Reloads  : {r_ok} ok, {r_fail} failed");
        }
    }
}

fn spawn_reload_driver(
    reload_url: Option<String>,
    interval_ms: u64,
    warmup: Duration,
    stop: Arc<AtomicBool>,
    ok_counter: Arc<AtomicU64>,
    fail_counter: Arc<AtomicU64>,
) -> Option<tokio::task::JoinHandle<()>> {
    let url = reload_url?;
    let target = TargetEndpoint::parse(&url);
    let interval = Duration::from_millis(interval_ms.max(50));
    Some(tokio::spawn(async move {
        if !warmup.is_zero() {
            tokio::time::sleep(warmup).await;
        }
        let mut conn = WorkerConn::H1(None);
        while !stop.load(Ordering::Relaxed) {
            tokio::time::sleep(interval).await;
            if stop.load(Ordering::Relaxed) {
                break;
            }
            match conn
                .send(&target, None, &Method::POST, &[], Bytes::new())
                .await
            {
                Ok(resp) => {
                    let ok = resp.status().is_success();
                    let _ = resp.into_body().collect().await;
                    if ok {
                        ok_counter.fetch_add(1, Ordering::Relaxed);
                    } else {
                        fail_counter.fetch_add(1, Ordering::Relaxed);
                    }
                }
                Err(_) => {
                    conn.reset();
                    fail_counter.fetch_add(1, Ordering::Relaxed);
                }
            }
        }
    }))
}

// =============================================================================
// High-Concurrency SSE Streaming Benchmark (HTTP/1.1 & HTTPS/TLS)
// =============================================================================

struct SseBenchConfig {
    url: String,
    concurrency: usize,
    waves: usize,
    method_str: String,
    body_template: Arc<BodyTemplate>,
    cache_cardinality: Option<usize>,
    raw_headers: Vec<String>,
    expect_status: u16,
    require_done: bool,
    tls_cfg: Option<Arc<ClientConfig>>,
    json_out: bool,
}

async fn run_sse_bench(cfg: SseBenchConfig) {
    let target = Arc::new(TargetEndpoint::parse(&cfg.url));
    let method = Method::from_bytes(cfg.method_str.as_bytes()).expect("invalid HTTP method");
    let mut parsed_headers = parse_headers(&cfg.raw_headers);
    if !cfg.body_template.is_empty()
        && !parsed_headers
            .iter()
            .any(|(k, _)| *k == header::CONTENT_TYPE)
    {
        parsed_headers.push((
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/json"),
        ));
    }
    let headers = Arc::new(parsed_headers);
    let seq_counter = Arc::new(AtomicU64::new(0));

    let mut ttfc_us_all: Vec<u64> = Vec::with_capacity(cfg.concurrency * cfg.waves.max(1));
    let mut dur_us_all: Vec<u64> = Vec::with_capacity(cfg.concurrency * cfg.waves.max(1));
    let mut completed: u64 = 0;
    let mut failed: u64 = 0;
    let mut total_chunks: u64 = 0;
    let mut total_bytes: u64 = 0;

    let wall_start = Instant::now();

    for _ in 0..cfg.waves.max(1) {
        let mut handles = Vec::with_capacity(cfg.concurrency);
        for _ in 0..cfg.concurrency {
            let target = Arc::clone(&target);
            let method = method.clone();
            let headers = Arc::clone(&headers);
            let body_template = Arc::clone(&cfg.body_template);
            let tls_cfg = cfg.tls_cfg.clone();
            let seq_counter = Arc::clone(&seq_counter);
            let cache_cardinality = cfg.cache_cardinality;
            let expect_status = cfg.expect_status;
            let require_done = cfg.require_done;

            handles.push(tokio::spawn(async move {
                let seq = seq_counter.fetch_add(1, Ordering::Relaxed);
                let body = body_template.render(seq, cache_cardinality);
                let mut conn = WorkerConn::H1(None);

                let t0 = Instant::now();
                let Ok(resp) = conn
                    .send(&target, tls_cfg.as_ref(), &method, &headers, body)
                    .await
                else {
                    return Err(());
                };
                if resp.status().as_u16() != expect_status {
                    return Err(());
                }

                let mut body = resp.into_body();
                let mut ttfc_us: Option<u64> = None;
                let mut chunks: u64 = 0;
                let mut bytes: u64 = 0;
                let mut saw_done = false;

                while let Some(frame_res) = body.frame().await {
                    match frame_res {
                        Ok(frame) => {
                            if let Ok(data) = frame.into_data()
                                && !data.is_empty()
                            {
                                if ttfc_us.is_none() {
                                    ttfc_us = Some(t0.elapsed().as_micros() as u64);
                                }
                                chunks += 1;
                                bytes += data.len() as u64;
                                if data.windows(6).any(|w| w == b"[DONE]") {
                                    saw_done = true;
                                }
                            }
                        }
                        Err(_) => return Err(()),
                    }
                }

                if require_done && !saw_done {
                    return Err(());
                }
                if chunks == 0 {
                    return Err(());
                }

                Ok((
                    ttfc_us.unwrap_or(0),
                    t0.elapsed().as_micros() as u64,
                    chunks,
                    bytes,
                ))
            }));
        }

        for h in handles {
            match h.await {
                Ok(Ok((ttfc, dur, chunks, bytes))) => {
                    completed += 1;
                    ttfc_us_all.push(ttfc);
                    dur_us_all.push(dur);
                    total_chunks += chunks;
                    total_bytes += bytes;
                }
                _ => {
                    failed += 1;
                }
            }
        }
    }

    let wall = wall_start.elapsed();
    ttfc_us_all.sort_unstable();
    dur_us_all.sort_unstable();

    let ttfc_p50 = percentile(&ttfc_us_all, 50.0);
    let ttfc_p95 = percentile(&ttfc_us_all, 95.0);
    let ttfc_p99 = percentile(&ttfc_us_all, 99.0);
    let ttfc_p999 = percentile(&ttfc_us_all, 99.9);
    let dur_p50 = percentile(&dur_us_all, 50.0);
    let dur_p99 = percentile(&dur_us_all, 99.0);
    let chunks_per_sec = total_chunks as f64 / wall.as_secs_f64().max(1e-9);

    if cfg.json_out {
        let obj = serde_json::json!({
            "workload": "sse",
            "url": cfg.url,
            "tls": target.scheme_https,
            "concurrency": cfg.concurrency,
            "waves": cfg.waves,
            "wall_s": (wall.as_secs_f64() * 1000.0).round() / 1000.0,
            "completed": completed,
            "failed": failed,
            "chunks": total_chunks,
            "chunks_per_sec": (chunks_per_sec * 10.0).round() / 10.0,
            "bytes": total_bytes,
            "ttfc_p50_us": ttfc_p50,
            "ttfc_p95_us": ttfc_p95,
            "ttfc_p99_us": ttfc_p99,
            "ttfc_p999_us": ttfc_p999,
            "dur_p50_us": dur_p50,
            "dur_p99_us": dur_p99,
        });
        println!("{}", serde_json::to_string(&obj).unwrap());
    } else {
        println!(
            "SSE Benchmark: {} (c={}, waves={}, wall={:.2}s)",
            cfg.url,
            cfg.concurrency,
            cfg.waves,
            wall.as_secs_f64()
        );
        println!(
            "  Streams : {completed} completed, {failed} failed ({total_chunks} chunks, {chunks_per_sec:.1} chunks/s)"
        );
        println!(
            "  TTFC    : p50={}µs | p95={}µs | p99={}µs | p999={}µs",
            ttfc_p50, ttfc_p95, ttfc_p99, ttfc_p999
        );
        println!(
            "  Duration: p50={}ms | p99={}ms",
            dur_p50 / 1000,
            dur_p99 / 1000
        );
    }
}

fn percentile(sorted: &[u64], pct: f64) -> u64 {
    if sorted.is_empty() {
        return 0;
    }
    let idx = ((pct / 100.0) * (sorted.len() - 1) as f64).round() as usize;
    sorted[idx.min(sorted.len() - 1)]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn presets_produce_valid_json_and_expected_sizes() {
        for name in [
            "ai-openai-small",
            "ai-anthropic-small",
            "ai-anthropic-sse",
            "ai-anthropic-4k",
            "ai-anthropic-32k",
            "ai-openai-4k",
            "ai-guardrails-clean-4k",
            "ai-guardrails-dirty",
            "ai-guardrails-injection",
            "ai-cache-hit",
            "ai-cache-nonce",
            "ai-cache-sse",
            "ai-messages-ingress",
            "ai-responses-ingress",
            "ai-gemini-small",
            "ai-bedrock-small",
            "ai-bedrock-sse",
            "ai-failover-small",
            "mcp-initialize",
            "mcp-tools-list",
            "mcp-tools-call",
            "mcp-tools-call-dirty",
            "mcp-tools-call-sql-deny",
            "mcp-tools-call-loop",
            "mcp-tools-call-sse",
        ] {
            let body = resolve_preset(name).expect(name);
            let parsed: serde_json::Value = serde_json::from_str(&body)
                .unwrap_or_else(|e| panic!("preset `{name}` is not valid JSON: {e}"));
            assert!(parsed.is_object(), "preset `{name}` must be a JSON object");
        }

        let p4k = resolve_preset("ai-anthropic-4k").unwrap();
        let p32k = resolve_preset("ai-anthropic-32k").unwrap();
        assert!(p4k.len() >= 4096, "4k preset too small: {}", p4k.len());
        assert!(p32k.len() >= 32768, "32k preset too small: {}", p32k.len());
    }

    #[test]
    fn body_template_cardinality_and_unique_nonces() {
        let tmpl = BodyTemplate::compile("{\"k\":\"{{NONCE}}\"}".to_owned(), Some(3));
        assert_eq!(tmpl.render(0, Some(3)).as_ref(), br#"{"k":"0"}"#);
        assert_eq!(tmpl.render(1, Some(3)).as_ref(), br#"{"k":"1"}"#);
        assert_eq!(tmpl.render(2, Some(3)).as_ref(), br#"{"k":"2"}"#);
        assert_eq!(tmpl.render(3, Some(3)).as_ref(), br#"{"k":"0"}"#);

        let uniq = BodyTemplate::compile("{\"k\":\"{{NONCE}}\"}".to_owned(), Some(0));
        assert_eq!(uniq.render(42, Some(0)).as_ref(), br#"{"k":"42"}"#);
        assert_eq!(uniq.render(43, Some(0)).as_ref(), br#"{"k":"43"}"#);
    }

    #[test]
    fn generates_valid_tls_and_mtls_certs() {
        let dir =
            std::env::temp_dir().join(format!("shunt-bench-certs-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        generate_bench_certs(&dir).expect("cert generation succeeds");

        let cfg = build_tls_client_config(
            Some(&dir.join("ca.pem")),
            false,
            Some(&dir.join("client.pem")),
            Some(&dir.join("client-key.pem")),
            true,
        )
        .expect("mTLS client config builds");
        assert_eq!(cfg.alpn_protocols, vec![b"h2".to_vec()]);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn encodes_valid_aws_eventstream_frame() {
        let frame = upstream::encode_eventstream_frame(
            &[(":message-type", "event"), (":event-type", "messageStart")],
            br#"{"role":"assistant"}"#,
        );
        let total_len = u32::from_be_bytes([frame[0], frame[1], frame[2], frame[3]]) as usize;
        assert_eq!(total_len, frame.len());
    }
}
