use std::convert::Infallible;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use bytes::Bytes;
use clap::{Parser, Subcommand};
use http::{HeaderName, HeaderValue, Method, Request, Response, StatusCode, Uri, header};
use http_body::{Body, Frame};
use http_body_util::{BodyExt, Full};
use hyper::service::service_fn;
use hyper_util::client::legacy::Client;
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto::Builder as AutoServerBuilder;
use tokio::net::TcpStream;
use tokio::sync::mpsc;

#[derive(Parser, Debug)]
#[command(
    name = "shunt-bench",
    about = "Reproducible mock upstream & HTTP/SSE load generator for Shunt benchmarks"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Start a high-performance HTTP/1.1 + HTTP/2 mock upstream server.
    Upstream {
        /// Listen address (e.g., 127.0.0.1:18080).
        #[arg(long, default_value = "127.0.0.1:18080")]
        listen: SocketAddr,
        /// Fixed payload size in bytes for `/ping` responses.
        #[arg(long, default_value_t = 256)]
        payload_bytes: usize,
        /// Number of SSE chunks emitted per stream on `/sse` and `/v1/messages`.
        #[arg(long, default_value_t = 20)]
        sse_chunks: usize,
        /// Delay between consecutive SSE chunks in milliseconds.
        #[arg(long, default_value_t = 25)]
        sse_interval_ms: u64,
    },
    /// Run a multi-worker keep-alive HTTP throughput & latency benchmark.
    Http {
        /// Target URL (e.g., http://127.0.0.1:8080/ping).
        #[arg(long)]
        url: String,
        /// Number of concurrent keep-alive workers.
        #[arg(short = 'c', long, default_value_t = 64)]
        concurrency: usize,
        /// Benchmark duration in seconds.
        #[arg(short = 'd', long, default_value_t = 10)]
        duration_secs: u64,
        /// Warmup duration in seconds before recording samples.
        #[arg(long, default_value_t = 2)]
        warmup_secs: u64,
        /// HTTP method (`GET`, `POST`, etc.).
        #[arg(long, default_value = "GET")]
        method: String,
        /// Optional JSON body for `POST`/`PUT` requests.
        #[arg(long)]
        body: Option<String>,
        /// Optional extra request headers (`Name: Value`), repeatable.
        #[arg(short = 'H', long = "header")]
        headers: Vec<String>,
        /// Use HTTP/2 prior knowledge (h2c).
        #[arg(long)]
        http2: bool,
        /// Emit compact JSON summary line instead of human-readable table.
        #[arg(long)]
        json: bool,
    },
    /// Run a high-concurrency SSE streaming benchmark (e.g., 1,000+ concurrent streams).
    Sse {
        /// Target URL (e.g., http://127.0.0.1:8080/sse or http://127.0.0.1:8080/v1/chat/completions).
        #[arg(long)]
        url: String,
        /// Number of concurrent streams to open simultaneously.
        #[arg(short = 'c', long, default_value_t = 1000)]
        concurrency: usize,
        /// Number of waves (rounds of `concurrency` streams).
        #[arg(long, default_value_t = 1)]
        waves: usize,
        /// HTTP method (`GET` for raw SSE passthrough, `POST` for `/v1/chat/completions`).
        #[arg(long, default_value = "GET")]
        method: String,
        /// Optional JSON body for `POST` requests.
        #[arg(long)]
        body: Option<String>,
        /// Optional extra request headers (`Name: Value`), repeatable.
        #[arg(short = 'H', long = "header")]
        headers: Vec<String>,
        /// Emit compact JSON summary line instead of human-readable table.
        #[arg(long)]
        json: bool,
    },
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    match cli.command {
        Commands::Upstream {
            listen,
            payload_bytes,
            sse_chunks,
            sse_interval_ms,
        } => {
            run_upstream(listen, payload_bytes, sse_chunks, sse_interval_ms).await;
        }
        Commands::Http {
            url,
            concurrency,
            duration_secs,
            warmup_secs,
            method,
            body,
            headers,
            http2,
            json,
        } => {
            run_http_bench(
                &url,
                concurrency,
                Duration::from_secs(duration_secs),
                Duration::from_secs(warmup_secs),
                &method,
                body,
                &headers,
                http2,
                json,
            )
            .await;
        }
        Commands::Sse {
            url,
            concurrency,
            waves,
            method,
            body,
            headers,
            json,
        } => {
            run_sse_bench(&url, concurrency, waves, &method, body, &headers, json).await;
        }
    }
}

// =============================================================================
// Mock Upstream Server (H1 + H2, Fixed Payload + Raw SSE + Anthropic SSE)
// =============================================================================

type BoxBody = http_body_util::combinators::BoxBody<Bytes, Infallible>;

struct ChannelBody {
    rx: mpsc::Receiver<Result<Frame<Bytes>, Infallible>>,
}

impl Body for ChannelBody {
    type Data = Bytes;
    type Error = Infallible;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        self.rx.poll_recv(cx)
    }
}

async fn run_upstream(
    listen: SocketAddr,
    payload_bytes: usize,
    sse_chunks: usize,
    sse_interval_ms: u64,
) {
    let socket = match listen {
        SocketAddr::V4(_) => tokio::net::TcpSocket::new_v4().expect("v4 socket"),
        SocketAddr::V6(_) => tokio::net::TcpSocket::new_v6().expect("v6 socket"),
    };
    let _ = socket.set_reuseaddr(true);
    socket.bind(listen).expect("failed to bind upstream socket");
    let listener = socket.listen(4096).expect("failed to listen");
    let local_addr = listener.local_addr().unwrap();
    eprintln!(
        "shunt-bench upstream listening on {local_addr} (payload={payload_bytes}B, sse_chunks={sse_chunks}, sse_interval={sse_interval_ms}ms)"
    );

    let fixed_payload = Bytes::from(vec![b'a'; payload_bytes]);
    let interval = Duration::from_millis(sse_interval_ms);

    // Pre-build raw SSE and Anthropic SSE frames so upstream overhead is near zero.
    let raw_sse_frames: Arc<[Bytes]> = {
        let mut frames = Vec::with_capacity(sse_chunks + 1);
        for i in 0..sse_chunks {
            frames.push(Bytes::from(format!(
                "data: {{\"id\":\"chatcmpl-bench\",\"object\":\"chat.completion.chunk\",\"created\":1700000000,\"model\":\"bench\",\"choices\":[{{\"index\":0,\"delta\":{{\"content\":\"tok{i} \"}},\"finish_reason\":null}}]}}\n\n"
            )));
        }
        frames.push(Bytes::from_static(b"data: [DONE]\n\n"));
        Arc::from(frames)
    };

    let anthropic_sse_frames: Arc<[Bytes]> = {
        let mut frames = Vec::with_capacity(sse_chunks + 4);
        frames.push(Bytes::from_static(
            b"event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"id\":\"msg_bench\",\"type\":\"message\",\"role\":\"assistant\",\"content\":[],\"model\":\"claude-bench\",\"usage\":{\"input_tokens\":12,\"output_tokens\":1}}}\n\n",
        ));
        frames.push(Bytes::from_static(
            b"event: content_block_start\ndata: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"text\",\"text\":\"\"}}\n\n",
        ));
        for i in 0..sse_chunks {
            frames.push(Bytes::from(format!(
                "event: content_block_delta\ndata: {{\"type\":\"content_block_delta\",\"index\":0,\"delta\":{{\"type\":\"text_delta\",\"text\":\"tok{i} \"}}}}\n\n"
            )));
        }
        frames.push(Bytes::from(format!(
            "event: message_delta\ndata: {{\"type\":\"message_delta\",\"delta\":{{\"stop_reason\":\"end_turn\"}},\"usage\":{{\"output_tokens\":{sse_chunks}}}}}\n\n"
        )));
        frames.push(Bytes::from_static(
            b"event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n",
        ));
        Arc::from(frames)
    };

    let openai_chat_json = Bytes::from_static(
        br#"{"id":"chatcmpl-bench","object":"chat.completion","created":1700000000,"model":"gpt-bench","choices":[{"index":0,"message":{"role":"assistant","content":"Hello from mock OpenAI upstream!"},"finish_reason":"stop"}],"usage":{"prompt_tokens":12,"completion_tokens":20,"total_tokens":32}}"#,
    );
    let anthropic_msg_json = Bytes::from_static(
        br#"{"id":"msg_bench","type":"message","role":"assistant","model":"claude-bench","content":[{"type":"text","text":"Hello from mock Anthropic upstream!"}],"stop_reason":"end_turn","stop_sequence":null,"usage":{"input_tokens":12,"output_tokens":20}}"#,
    );
    // Realistic ~4 KB compressible JSON document for HTTP compression benchmarks (`/json`).
    let compressible_json = {
        let mut s = String::with_capacity(4300);
        s.push_str("{\"object\":\"list\",\"service\":\"shunt-bench\",\"items\":[");
        for i in 0..32 {
            if i > 0 {
                s.push(',');
            }
            s.push_str(&format!(
                "{{\"id\":\"item-{i:03}\",\"status\":\"active\",\"region\":\"us-east-1\",\"tier\":\"enterprise\",\"description\":\"Reproducible JSON API response payload for streaming compression benchmarking\",\"tags\":[\"gateway\",\"rust\",\"http\",\"zstd\"]}}"
            ));
        }
        s.push_str("]}");
        Bytes::from(s)
    };

    loop {
        let Ok((stream, _)) = listener.accept().await else {
            break;
        };
        let _ = stream.set_nodelay(true);
        let payload = fixed_payload.clone();
        let raw_frames = Arc::clone(&raw_sse_frames);
        let ant_frames = Arc::clone(&anthropic_sse_frames);
        let openai_json = openai_chat_json.clone();
        let ant_json = anthropic_msg_json.clone();
        let comp_json = compressible_json.clone();

        tokio::spawn(async move {
            let svc = service_fn(move |req: Request<hyper::body::Incoming>| {
                let payload = payload.clone();
                let raw_frames = Arc::clone(&raw_frames);
                let ant_frames = Arc::clone(&ant_frames);
                let openai_json = openai_json.clone();
                let ant_json = ant_json.clone();
                let comp_json = comp_json.clone();
                async move {
                    let path = req.uri().path().to_owned();
                    let resp: Response<BoxBody> = match path.as_str() {
                        "/json" => {
                            if !req.body().is_end_stream() {
                                let _ = req.into_body().collect().await;
                            }
                            json_response(comp_json)
                        }
                        "/sse" => {
                            if !req.body().is_end_stream() {
                                let _ = req.into_body().collect().await;
                            }
                            stream_sse_response(raw_frames, interval)
                        }
                        "/v1/chat/completions" | "/chat/completions" => {
                            let body_bytes = if !req.body().is_end_stream() {
                                req.into_body()
                                    .collect()
                                    .await
                                    .map(|c| c.to_bytes())
                                    .unwrap_or_default()
                            } else {
                                Bytes::new()
                            };
                            if wants_stream(&body_bytes) {
                                stream_sse_response(raw_frames, interval)
                            } else {
                                json_response(openai_json)
                            }
                        }
                        "/v1/messages" | "/messages" => {
                            let body_bytes = if !req.body().is_end_stream() {
                                req.into_body()
                                    .collect()
                                    .await
                                    .map(|c| c.to_bytes())
                                    .unwrap_or_default()
                            } else {
                                Bytes::new()
                            };
                            if wants_stream(&body_bytes) {
                                stream_sse_response(ant_frames, interval)
                            } else {
                                json_response(ant_json)
                            }
                        }
                        _ => Response::builder()
                            .status(StatusCode::OK)
                            .header(header::CONTENT_TYPE, "application/octet-stream")
                            .header(header::CONTENT_LENGTH, payload.len().to_string())
                            .body(Full::new(payload).boxed())
                            .unwrap(),
                    };
                    Ok::<_, Infallible>(resp)
                }
            });

            let mut builder = AutoServerBuilder::new(TokioExecutor::new());
            builder.http1().keep_alive(true);
            let _ = builder.serve_connection(TokioIo::new(stream), svc).await;
        });
    }
}

fn wants_stream(body: &[u8]) -> bool {
    body.windows(13).any(|w| w == b"\"stream\":true")
        || body.windows(14).any(|w| w == b"\"stream\": true")
}

fn json_response(body: Bytes) -> Response<BoxBody> {
    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::CONTENT_LENGTH, body.len().to_string())
        .body(Full::new(body).boxed())
        .unwrap()
}

fn stream_sse_response(frames: Arc<[Bytes]>, interval: Duration) -> Response<BoxBody> {
    let (tx, rx) = mpsc::channel::<Result<Frame<Bytes>, Infallible>>(8);
    tokio::spawn(async move {
        for (idx, frame) in frames.iter().enumerate() {
            if idx > 0 && !interval.is_zero() {
                tokio::time::sleep(interval).await;
            }
            if tx.send(Ok(Frame::data(frame.clone()))).await.is_err() {
                break;
            }
        }
    });

    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "text/event-stream; charset=utf-8")
        .header(header::CACHE_CONTROL, "no-cache")
        .body(ChannelBody { rx }.boxed())
        .unwrap()
}

// =============================================================================
// HTTP Keep-Alive Throughput & Latency Benchmark
// =============================================================================

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

#[allow(clippy::too_many_arguments)]
async fn run_http_bench(
    url: &str,
    concurrency: usize,
    duration: Duration,
    warmup: Duration,
    method_str: &str,
    body: Option<String>,
    raw_headers: &[String],
    http2: bool,
    json_out: bool,
) {
    let uri: Uri = url.parse().expect("invalid target URL");
    let method = Method::from_bytes(method_str.as_bytes()).expect("invalid HTTP method");
    let body_bytes = Bytes::from(body.unwrap_or_default());
    let mut parsed_headers = parse_headers(raw_headers);
    if !body_bytes.is_empty()
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
    let host = uri.host().expect("URL missing host").to_owned();
    let port = uri.port_u16().unwrap_or(80);
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

    let h2_client = if http2 {
        let mut client_builder = Client::builder(TokioExecutor::new());
        client_builder
            .pool_max_idle_per_host(concurrency.max(64))
            .pool_idle_timeout(Duration::from_secs(60))
            .http2_only(true);
        Some(Arc::new(client_builder.build_http::<Full<Bytes>>()))
    } else {
        None
    };

    let recording = Arc::new(AtomicBool::new(false));
    let stop = Arc::new(AtomicBool::new(false));
    let ok_count = Arc::new(AtomicU64::new(0));
    let err_count = Arc::new(AtomicU64::new(0));
    let total_bytes = Arc::new(AtomicU64::new(0));

    let mut handles = Vec::with_capacity(concurrency);
    for _ in 0..concurrency {
        let h2_client = h2_client.clone();
        let uri = uri.clone();
        let method = method.clone();
        let body_bytes = body_bytes.clone();
        let host = host.clone();
        let authority = authority.clone();
        let path_and_query = path_and_query.clone();
        let headers = Arc::clone(&headers);
        let recording = Arc::clone(&recording);
        let stop = Arc::clone(&stop);
        let ok_count = Arc::clone(&ok_count);
        let err_count = Arc::clone(&err_count);
        let total_bytes = Arc::clone(&total_bytes);

        handles.push(tokio::spawn(async move {
            let mut latencies_us: Vec<u64> = Vec::with_capacity(8192);
            let mut h1_sender: Option<hyper::client::conn::http1::SendRequest<Full<Bytes>>> = None;

            while !stop.load(Ordering::Relaxed) {
                let t0 = Instant::now();
                let res = if let Some(client) = &h2_client {
                    let mut builder = Request::builder().method(method.clone()).uri(uri.clone());
                    for (k, v) in headers.iter() {
                        builder = builder.header(k, v);
                    }
                    let req = builder.body(Full::new(body_bytes.clone())).unwrap();
                    client.request(req).await.map_err(|_| ())
                } else {
                    // Dedicated per-worker keep-alive H1 connection (zero client-pool lock contention).
                    if h1_sender.as_ref().map(|s| s.is_closed()).unwrap_or(true) {
                        let addr_res = if let Ok(ip) = host.parse::<std::net::IpAddr>() {
                            TcpStream::connect(SocketAddr::new(ip, port)).await
                        } else {
                            TcpStream::connect((host.as_str(), port)).await
                        };
                        match addr_res {
                            Ok(tcp) => {
                                let _ = tcp.set_nodelay(true);
                                match hyper::client::conn::http1::handshake(TokioIo::new(tcp)).await
                                {
                                    Ok((sender, conn)) => {
                                        tokio::spawn(async move {
                                            let _ = conn.await;
                                        });
                                        h1_sender = Some(sender);
                                    }
                                    Err(_) => {
                                        if recording.load(Ordering::Relaxed) {
                                            err_count.fetch_add(1, Ordering::Relaxed);
                                        }
                                        continue;
                                    }
                                }
                            }
                            Err(_) => {
                                if recording.load(Ordering::Relaxed) {
                                    err_count.fetch_add(1, Ordering::Relaxed);
                                }
                                continue;
                            }
                        }
                    }

                    let mut builder = Request::builder()
                        .method(method.clone())
                        .uri(path_and_query.clone())
                        .header(header::HOST, &authority);
                    for (k, v) in headers.iter() {
                        builder = builder.header(k, v);
                    }
                    let req = builder.body(Full::new(body_bytes.clone())).unwrap();

                    let sender = h1_sender.as_mut().unwrap();
                    if sender.ready().await.is_err() {
                        h1_sender = None;
                        if recording.load(Ordering::Relaxed) {
                            err_count.fetch_add(1, Ordering::Relaxed);
                        }
                        continue;
                    }
                    sender.send_request(req).await.map_err(|_| {
                        h1_sender = None;
                    })
                };

                let rec = recording.load(Ordering::Relaxed);

                match res {
                    Ok(resp) => {
                        let status = resp.status();
                        match resp.into_body().collect().await {
                            Ok(collected) => {
                                let elapsed_us = t0.elapsed().as_micros() as u64;
                                if rec {
                                    if status.is_success() {
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
                                h1_sender = None;
                                if rec {
                                    err_count.fetch_add(1, Ordering::Relaxed);
                                }
                            }
                        }
                    }
                    Err(_) => {
                        if rec {
                            err_count.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                }
            }
            latencies_us
        }));
    }

    if !warmup.is_zero() {
        tokio::time::sleep(warmup).await;
    }
    let measure_start = Instant::now();
    recording.store(true, Ordering::Release);
    tokio::time::sleep(duration).await;
    stop.store(true, Ordering::Release);
    let elapsed = measure_start.elapsed();

    let mut all_latencies: Vec<u64> = Vec::new();
    for h in handles {
        if let Ok(mut v) = h.await {
            all_latencies.append(&mut v);
        }
    }
    all_latencies.sort_unstable();

    let ok = ok_count.load(Ordering::Relaxed);
    let errs = err_count.load(Ordering::Relaxed);
    let bytes = total_bytes.load(Ordering::Relaxed);
    let rps = ok as f64 / elapsed.as_secs_f64();
    let p50 = percentile(&all_latencies, 50.0);
    let p95 = percentile(&all_latencies, 95.0);
    let p99 = percentile(&all_latencies, 99.0);
    let max = all_latencies.last().copied().unwrap_or(0);

    if json_out {
        println!(
            "{{\"workload\":\"http\",\"url\":\"{url}\",\"concurrency\":{concurrency},\"duration_s\":{:.3},\"ok\":{ok},\"errors\":{errs},\"bytes\":{bytes},\"rps\":{rps:.1},\"p50_us\":{p50},\"p95_us\":{p95},\"p99_us\":{p99},\"max_us\":{max}}}",
            elapsed.as_secs_f64()
        );
    } else {
        println!(
            "HTTP Benchmark: {url} (c={concurrency}, d={:.2}s, h2={http2})",
            elapsed.as_secs_f64()
        );
        println!("  Requests : {ok} ok, {errs} errors ({rps:.1} req/s)");
        println!(
            "  Latency  : p50={}µs | p95={}µs | p99={}µs | max={}µs",
            p50, p95, p99, max
        );
    }
}

// =============================================================================
// High-Concurrency SSE Streaming Benchmark (1,000+ concurrent streams)
// =============================================================================

async fn run_sse_bench(
    url: &str,
    concurrency: usize,
    waves: usize,
    method_str: &str,
    body: Option<String>,
    raw_headers: &[String],
    json_out: bool,
) {
    let uri: Uri = url.parse().expect("invalid target URL");
    let method = Method::from_bytes(method_str.as_bytes()).expect("invalid HTTP method");
    let headers = Arc::new(parse_headers(raw_headers));
    let body_bytes = Bytes::from(body.unwrap_or_default());

    let client = Arc::new(
        Client::builder(TokioExecutor::new())
            .pool_max_idle_per_host(concurrency.max(128))
            .build_http::<Full<Bytes>>(),
    );

    let mut ttfc_us_all: Vec<u64> = Vec::with_capacity(concurrency * waves);
    let mut dur_us_all: Vec<u64> = Vec::with_capacity(concurrency * waves);
    let mut completed: u64 = 0;
    let mut failed: u64 = 0;
    let mut total_chunks: u64 = 0;
    let mut total_bytes: u64 = 0;

    let wall_start = Instant::now();

    for _ in 0..waves.max(1) {
        let mut handles = Vec::with_capacity(concurrency);
        for _ in 0..concurrency {
            let client = Arc::clone(&client);
            let uri = uri.clone();
            let method = method.clone();
            let headers = Arc::clone(&headers);
            let body_bytes = body_bytes.clone();

            handles.push(tokio::spawn(async move {
                let mut builder = Request::builder().method(method).uri(uri);
                for (k, v) in headers.iter() {
                    builder = builder.header(k, v);
                }
                if !body_bytes.is_empty() {
                    builder = builder.header(header::CONTENT_TYPE, "application/json");
                }
                let req = builder.body(Full::new(body_bytes)).unwrap();

                let t0 = Instant::now();
                let Ok(resp) = client.request(req).await else {
                    return Err(());
                };
                if !resp.status().is_success() {
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

                if !saw_done {
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
    let dur_p50 = percentile(&dur_us_all, 50.0);
    let dur_p99 = percentile(&dur_us_all, 99.0);
    let chunks_per_sec = total_chunks as f64 / wall.as_secs_f64();

    if json_out {
        println!(
            "{{\"workload\":\"sse\",\"url\":\"{url}\",\"concurrency\":{concurrency},\"waves\":{waves},\"wall_s\":{:.3},\"completed\":{completed},\"failed\":{failed},\"chunks\":{total_chunks},\"chunks_per_sec\":{chunks_per_sec:.1},\"bytes\":{total_bytes},\"ttfc_p50_us\":{ttfc_p50},\"ttfc_p95_us\":{ttfc_p95},\"ttfc_p99_us\":{ttfc_p99},\"dur_p50_us\":{dur_p50},\"dur_p99_us\":{dur_p99}}}",
            wall.as_secs_f64()
        );
    } else {
        println!(
            "SSE Benchmark: {url} (c={concurrency}, waves={waves}, wall={:.2}s)",
            wall.as_secs_f64()
        );
        println!(
            "  Streams : {completed} completed, {failed} failed ({total_chunks} chunks, {chunks_per_sec:.1} chunks/s)"
        );
        println!(
            "  TTFC    : p50={}µs | p95={}µs | p99={}µs",
            ttfc_p50, ttfc_p95, ttfc_p99
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
