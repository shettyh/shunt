use std::collections::BTreeMap;
use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::Bytes;
use http::{HeaderName, HeaderValue, Request, Response, StatusCode, header};
use http_body::Frame;
use http_body_util::BodyExt;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use serde_json::Value;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::{mpsc, watch};

use crate::schema::{MockFault, MockResponseSpec, MockSpec};

/// Snapshot of an HTTP request received by an in-process mock upstream.
#[derive(Debug, Clone)]
pub struct CapturedRequest {
    pub method: String,
    pub path_and_query: String,
    pub headers: BTreeMap<String, String>,
    pub body: Bytes,
    pub json: Option<Value>,
}

/// Handle to a running in-process mock upstream server.
pub struct MockHandle {
    pub upstream: String,
    pub addr: SocketAddr,
    captures: Arc<Mutex<Vec<CapturedRequest>>>,
    shutdown_tx: watch::Sender<bool>,
    task: Option<tokio::task::JoinHandle<()>>,
}

impl MockHandle {
    pub fn endpoint_url(&self) -> String {
        format!("http://{}", self.addr)
    }

    pub fn captures(&self) -> Vec<CapturedRequest> {
        self.captures
            .lock()
            .expect("captures lock poisoned")
            .clone()
    }

    pub fn clear_captures(&self) {
        self.captures
            .lock()
            .expect("captures lock poisoned")
            .clear();
    }

    pub async fn shutdown(mut self) {
        let _ = self.shutdown_tx.send(true);
        if let Some(task) = self.task.take() {
            task.abort();
            let _ = task.await;
        }
    }
}

/// Spawns an in-process mock HTTP/SSE/fault-injecting upstream bound to `127.0.0.1:0`.
pub async fn spawn_mock(spec: &MockSpec) -> std::io::Result<MockHandle> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let captures = Arc::new(Mutex::new(Vec::new()));
    let (shutdown_tx, mut shutdown_rx) = watch::channel(false);

    if spec.is_connect_refused() {
        // Drop listener immediately so TCP connect fails deterministically with ECONNREFUSED.
        drop(listener);
        return Ok(MockHandle {
            upstream: spec.upstream.clone(),
            addr,
            captures,
            shutdown_tx,
            task: None,
        });
    }

    let sequence = Arc::new(spec.effective_sequence());
    let req_counter = Arc::new(AtomicUsize::new(0));
    let captures_bg = Arc::clone(&captures);

    let task = tokio::spawn(async move {
        loop {
            tokio::select! {
                biased;
                _ = shutdown_rx.changed() => {
                    if *shutdown_rx.borrow() {
                        break;
                    }
                }
                res = listener.accept() => {
                    let (mut tcp, _) = match res {
                        Ok(pair) => pair,
                        Err(_) => continue,
                    };
                    let seq = Arc::clone(&sequence);
                    let counter = Arc::clone(&req_counter);
                    let caps = Arc::clone(&captures_bg);

                    // Peek whether the next response is a raw TCP-level fault (reset or stall_headers).
                    let peek_idx = counter.load(Ordering::Acquire).min(seq.len().saturating_sub(1));
                    let peek_fault = seq.get(peek_idx).and_then(|r| r.fault);

                    if matches!(peek_fault, Some(MockFault::TcpResetMidStream | MockFault::StallHeaders)) {
                        let idx = counter.fetch_add(1, Ordering::AcqRel).min(seq.len().saturating_sub(1));
                        let resp_spec = seq[idx].clone();
                        tokio::spawn(async move {
                            // Drain HTTP request headers briefly so client finishes writing request.
                            let mut buf = [0u8; 4096];
                            let _ = tokio::time::timeout(Duration::from_millis(50), tcp.read(&mut buf)).await;
                            match resp_spec.fault {
                                Some(MockFault::StallHeaders) => {
                                    tokio::time::sleep(Duration::from_secs(30)).await;
                                }
                                Some(MockFault::TcpResetMidStream) => {
                                    // Send chunked 200 headers + first chunk, then abruptly drop without 0\r\n\r\n.
                                    let partial = b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\n\r\n6\r\nhello!\r\n";
                                    let _ = tcp.write_all(partial).await;
                                    let _ = tcp.flush().await;
                                    // Drop TCP stream immediately without finishing chunked terminator.
                                    drop(tcp);
                                }
                                _ => {}
                            }
                        });
                        continue;
                    }

                    tokio::spawn(async move {
                        let svc = service_fn(move |req: Request<hyper::body::Incoming>| {
                            let seq = Arc::clone(&seq);
                            let counter = Arc::clone(&counter);
                            let caps = Arc::clone(&caps);
                            async move {
                                let method = req.method().as_str().to_owned();
                                let path_and_query = req
                                    .uri()
                                    .path_and_query()
                                    .map(|pq| pq.as_str().to_owned())
                                    .unwrap_or_else(|| "/".to_owned());
                                let mut headers_map = BTreeMap::new();
                                for (k, v) in req.headers() {
                                    if let Ok(vs) = v.to_str() {
                                        headers_map.insert(k.as_str().to_ascii_lowercase(), vs.to_owned());
                                    }
                                }
                                let body_bytes = req
                                    .into_body()
                                    .collect()
                                    .await
                                    .map(|c| c.to_bytes())
                                    .unwrap_or_default();
                                let parsed_json = serde_json::from_slice::<Value>(&body_bytes).ok();

                                caps.lock().expect("captures poisoned").push(CapturedRequest {
                                    method,
                                    path_and_query,
                                    headers: headers_map,
                                    body: body_bytes,
                                    json: parsed_json,
                                });

                                let idx = counter
                                    .fetch_add(1, Ordering::AcqRel)
                                    .min(seq.len().saturating_sub(1));
                                let resp_spec = &seq[idx];
                                Ok::<_, Infallible>(build_mock_response(resp_spec).await)
                            }
                        });
                        let _ = http1::Builder::new()
                            .keep_alive(true)
                            .serve_connection(TokioIo::new(tcp), svc)
                            .await;
                    });
                }
            }
        }
    });

    Ok(MockHandle {
        upstream: spec.upstream.clone(),
        addr,
        captures,
        shutdown_tx,
        task: Some(task),
    })
}

struct ReceiverStream {
    rx: mpsc::Receiver<Result<Frame<Bytes>, Infallible>>,
}

impl http_body::Body for ReceiverStream {
    type Data = Bytes;
    type Error = Infallible;

    fn poll_frame(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        self.rx.poll_recv(cx)
    }
}

async fn build_mock_response(spec: &MockResponseSpec) -> Response<ReceiverStream> {
    // Handle StallHeaders inside hyper service if it appeared later in a sequence.
    if spec.fault == Some(MockFault::StallHeaders) {
        tokio::time::sleep(Duration::from_secs(30)).await;
    }

    if let Some(delay_ms) = spec.delay_ms
        && delay_ms > 0
    {
        tokio::time::sleep(Duration::from_millis(delay_ms)).await;
    }

    let status = StatusCode::from_u16(spec.status.unwrap_or(200)).unwrap_or(StatusCode::OK);
    let mut builder = Response::builder().status(status);

    let is_sse = !spec.sse_raw.is_empty();
    let is_eventstream = !spec.aws_eventstream.is_empty();
    let mut has_ct = false;
    for (k, v) in &spec.headers {
        if k.eq_ignore_ascii_case("content-type") {
            has_ct = true;
        }
        if let (Ok(hn), Ok(hv)) = (
            HeaderName::from_bytes(k.as_bytes()),
            HeaderValue::from_str(v),
        ) {
            builder = builder.header(hn, hv);
        }
    }

    if !has_ct {
        if is_sse {
            builder = builder.header(header::CONTENT_TYPE, "text/event-stream; charset=utf-8");
        } else if is_eventstream {
            builder = builder.header(header::CONTENT_TYPE, "application/vnd.amazon.eventstream");
        } else if spec.json.is_some() {
            builder = builder.header(header::CONTENT_TYPE, "application/json");
        }
    }

    let raw_chunks: Vec<Vec<u8>> = if !spec.sse_raw.is_empty() {
        spec.sse_raw.iter().map(|s| s.as_bytes().to_vec()).collect()
    } else if !spec.aws_eventstream.is_empty() {
        spec.aws_eventstream
            .iter()
            .map(|frame| {
                let payload = frame
                    .json
                    .as_ref()
                    .and_then(|v| serde_json::to_vec(v).ok())
                    .unwrap_or_default();
                let type_header = if frame.message_type == "exception" {
                    (":exception-type", frame.event_type.as_str())
                } else {
                    (":event-type", frame.event_type.as_str())
                };
                shunt_ai::encode_eventstream_frame(
                    &[
                        (":message-type", frame.message_type.as_str()),
                        type_header,
                        (":content-type", "application/json"),
                    ],
                    &payload,
                )
            })
            .collect()
    } else if !spec.chunks.is_empty() {
        spec.chunks.iter().map(|s| s.as_bytes().to_vec()).collect()
    } else if let Some(val) = &spec.json {
        vec![serde_json::to_vec(val).unwrap_or_default()]
    } else if let Some(body) = &spec.body {
        vec![body.as_bytes().to_vec()]
    } else {
        Vec::new()
    };

    // Apply optional `chunk_split_bytes` fragmentation.
    let final_chunks: Vec<Bytes> = if let Some(split) = spec.chunk_split_bytes.filter(|&n| n > 0) {
        let mut flat = Vec::new();
        for c in raw_chunks {
            flat.extend_from_slice(&c);
        }
        flat.chunks(split).map(Bytes::copy_from_slice).collect()
    } else {
        raw_chunks.into_iter().map(Bytes::from).collect()
    };

    let delay = spec.chunk_delay_ms.map(Duration::from_millis);
    let stall_chunk = spec.fault == Some(MockFault::StallChunk);
    let (tx, rx) = mpsc::channel(16);

    tokio::spawn(async move {
        for (idx, chunk) in final_chunks.into_iter().enumerate() {
            if idx > 0
                && let Some(d) = delay
            {
                tokio::time::sleep(d).await;
            }
            if tx.send(Ok(Frame::data(chunk))).await.is_err() {
                return;
            }
            if stall_chunk && idx == 0 {
                tokio::time::sleep(Duration::from_secs(30)).await;
                return;
            }
        }
        if stall_chunk {
            tokio::time::sleep(Duration::from_secs(30)).await;
        }
    });

    builder.body(ReceiverStream { rx }).unwrap()
}
