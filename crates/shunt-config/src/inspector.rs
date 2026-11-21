use std::collections::{BTreeMap, VecDeque};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use bytes::Bytes;
use serde::Serialize;
use shunt_plugin_sdk::{
    Flow, HookMask, HookResult, HttpPlugin, RequestCtx, RequestHead, RequestSummary,
    TraceAnnotations, TraceContext, header,
};
use tokio::sync::broadcast;

/// Internal plugin name for the opt-in Admin Inspector capture plugin.
pub const INSPECTOR_PLUGIN_NAME: &str = "admin-inspector";

/// Single non-streaming hook timing entry inside an [`InspectorTrace`].
#[derive(Debug, Clone, Serialize)]
pub struct InspectorHookSpan {
    pub plugin: String,
    pub hook: String,
    pub duration_us: u64,
}

/// Aggregated streaming chunk hook summary inside an [`InspectorTrace`].
#[derive(Debug, Clone, Serialize)]
pub struct InspectorChunkSummary {
    pub plugin: String,
    pub hook: String,
    pub chunks: usize,
    pub total_us: u64,
    pub avg_us: u64,
}

/// Completed per-request trace record buffered in [`TraceRingBuffer`] and streamed via SSE.
#[derive(Debug, Clone, Serialize)]
pub struct InspectorTrace {
    pub seq: u64,
    pub request_id: u64,
    pub timestamp_unix_ms: u64,
    pub method: String,
    pub path: String,
    pub host: Option<String>,
    pub route_id: Option<String>,
    pub upstream: Option<String>,
    pub endpoint: Option<String>,
    pub status: Option<u16>,
    pub attempts: usize,
    pub request_bytes: u64,
    pub response_bytes: u64,
    pub ttfb_us: Option<u64>,
    pub total_us: u64,
    pub aborted_mid_stream: bool,
    pub error: Option<String>,
    pub trace_id: Option<String>,
    pub hooks: Vec<InspectorHookSpan>,
    pub stream_chunks: Vec<InspectorChunkSummary>,
    pub attributes: BTreeMap<String, serde_json::Value>,
}

/// Aggregate rolling statistics derived from [`TraceRingBuffer`].
#[derive(Debug, Clone, Default, Serialize)]
pub struct TraceRingSummary {
    pub capacity: usize,
    pub buffered: usize,
    pub total_recorded: u64,
    pub total_errors: u64,
    pub status_2xx: u64,
    pub status_3xx: u64,
    pub status_4xx: u64,
    pub status_5xx: u64,
    pub p50_us: Option<u64>,
    pub p95_us: Option<u64>,
    pub p99_us: Option<u64>,
    pub avg_ttfb_us: Option<u64>,
    pub by_route: BTreeMap<String, u64>,
}

#[derive(Debug)]
struct RingInner {
    entries: VecDeque<InspectorTrace>,
    total_recorded: u64,
    total_errors: u64,
    status_2xx: u64,
    status_3xx: u64,
    status_4xx: u64,
    status_5xx: u64,
}

/// Bounded, non-blocking in-memory trace ring buffer with a live SSE broadcast channel.
///
/// Slow or disconnected SSE subscribers lag independently and NEVER stall or backpressure
/// the proxy data plane.
#[derive(Debug)]
pub struct TraceRingBuffer {
    capacity: usize,
    next_seq: AtomicU64,
    inner: Mutex<RingInner>,
    tx: broadcast::Sender<InspectorTrace>,
}

impl TraceRingBuffer {
    pub fn new(capacity: usize) -> Self {
        let cap = capacity.max(1);
        let broadcast_cap = cap.clamp(64, 1024);
        let (tx, _) = broadcast::channel(broadcast_cap);
        Self {
            capacity: cap,
            next_seq: AtomicU64::new(1),
            inner: Mutex::new(RingInner {
                entries: VecDeque::with_capacity(cap.min(1024)),
                total_recorded: 0,
                total_errors: 0,
                status_2xx: 0,
                status_3xx: 0,
                status_4xx: 0,
                status_5xx: 0,
            }),
            tx,
        }
    }

    pub fn capacity(&self) -> usize {
        self.capacity
    }

    /// Assigns the next monotonic `seq`, appends `trace` to the bounded ring buffer
    /// (evicting the oldest entry if full), updates lifetime counters, and broadcasts
    /// the event to all live SSE subscribers without blocking.
    pub fn push(&self, mut trace: InspectorTrace) -> InspectorTrace {
        let seq = self.next_seq.fetch_add(1, Ordering::Relaxed);
        trace.seq = seq;

        {
            let mut guard = self.inner.lock().expect("TraceRingBuffer lock poisoned");
            guard.total_recorded = guard.total_recorded.saturating_add(1);
            match trace.status {
                Some(200..=299) => guard.status_2xx += 1,
                Some(300..=399) => guard.status_3xx += 1,
                Some(400..=499) => {
                    guard.status_4xx += 1;
                    guard.total_errors += 1;
                }
                Some(500..=599) | None => {
                    guard.status_5xx += 1;
                    guard.total_errors += 1;
                }
                Some(_) => {}
            }
            if guard.entries.len() >= self.capacity {
                guard.entries.pop_front();
            }
            guard.entries.push_back(trace.clone());
        }

        let _ = self.tx.send(trace.clone());
        trace
    }

    /// Returns buffered traces in ascending `seq` order, optionally filtered to
    /// `seq > after_seq` and capped to the latest `limit` records.
    pub fn recent(&self, after_seq: Option<u64>, limit: Option<usize>) -> Vec<InspectorTrace> {
        let guard = self.inner.lock().expect("TraceRingBuffer lock poisoned");
        let mut items: Vec<InspectorTrace> = guard
            .entries
            .iter()
            .filter(|t| after_seq.map(|a| t.seq > a).unwrap_or(true))
            .cloned()
            .collect();
        if let Some(lim) = limit
            && items.len() > lim
        {
            let start = items.len() - lim;
            items.drain(0..start);
        }
        items
    }

    /// Subscribes to live newly-recorded traces.
    pub fn subscribe(&self) -> broadcast::Receiver<InspectorTrace> {
        self.tx.subscribe()
    }

    /// Computes a lightweight summary over lifetime counters + currently buffered traces.
    pub fn summary(&self) -> TraceRingSummary {
        let guard = self.inner.lock().expect("TraceRingBuffer lock poisoned");
        let buffered = guard.entries.len();

        let mut durations: Vec<u64> = Vec::with_capacity(buffered);
        let mut ttfb_sum: u128 = 0;
        let mut ttfb_count: u64 = 0;
        let mut by_route: BTreeMap<String, u64> = BTreeMap::new();

        for t in &guard.entries {
            durations.push(t.total_us);
            if let Some(ttfb) = t.ttfb_us {
                ttfb_sum += u128::from(ttfb);
                ttfb_count += 1;
            }
            let route_key = t.route_id.clone().unwrap_or_else(|| "unmatched".to_owned());
            *by_route.entry(route_key).or_insert(0) += 1;
        }
        durations.sort_unstable();

        TraceRingSummary {
            capacity: self.capacity,
            buffered,
            total_recorded: guard.total_recorded,
            total_errors: guard.total_errors,
            status_2xx: guard.status_2xx,
            status_3xx: guard.status_3xx,
            status_4xx: guard.status_4xx,
            status_5xx: guard.status_5xx,
            p50_us: percentile_sorted(&durations, 50),
            p95_us: percentile_sorted(&durations, 95),
            p99_us: percentile_sorted(&durations, 99),
            avg_ttfb_us: (ttfb_count > 0).then(|| (ttfb_sum / u128::from(ttfb_count)) as u64),
            by_route,
        }
    }
}

/// Nearest-rank percentile on a non-empty sorted slice (`pct` in `1..=100`).
pub fn percentile_sorted(sorted: &[u64], pct: usize) -> Option<u64> {
    if sorted.is_empty() {
        return None;
    }
    let n = sorted.len();
    let rank = (n * pct).div_ceil(100).clamp(1, n);
    Some(sorted[rank - 1])
}

/// Formats a single [`InspectorTrace`] as an SSE wire frame (`id`, `event: trace`, `data`).
pub fn format_sse_trace_event(trace: &InspectorTrace) -> Bytes {
    let payload = serde_json::to_string(trace).unwrap_or_else(|_| "{}".to_owned());
    Bytes::from(format!(
        "id: {}\nevent: trace\ndata: {payload}\n\n",
        trace.seq
    ))
}

/// Formats an SSE lag notification frame when a slow client falls behind the broadcast channel.
pub fn format_sse_lagged_event(skipped: u64) -> Bytes {
    Bytes::from(format!(
        "event: lagged\ndata: {{\"skipped\":{skipped}}}\n\n"
    ))
}

#[derive(Debug)]
struct CaptureState {
    buffer: Arc<TraceRingBuffer>,
    annotations: TraceAnnotations,
    timestamp_unix_ms: u64,
    method: String,
    path: String,
    host: Option<String>,
    finalized: Mutex<Option<FinalizedCapture>>,
}

#[derive(Debug)]
struct FinalizedCapture {
    request_id: u64,
    route_id: Option<String>,
    upstream: Option<String>,
    endpoint: Option<String>,
    status: Option<u16>,
    attempts: usize,
    request_bytes: u64,
    response_bytes: u64,
    ttfb_us: Option<u64>,
    total_us: u64,
    aborted_mid_stream: bool,
    error: Option<String>,
    trace_id: Option<String>,
    hooks: Vec<InspectorHookSpan>,
    stream_chunks: Vec<InspectorChunkSummary>,
}

impl Drop for CaptureState {
    fn drop(&mut self) {
        let Ok(mut guard) = self.finalized.lock() else {
            return;
        };
        let Some(fin) = guard.take() else {
            return;
        };
        drop(guard);

        let attributes: BTreeMap<String, serde_json::Value> = self
            .annotations
            .snapshot()
            .into_iter()
            .map(|(k, v)| (k, v.to_json_value()))
            .collect();

        let trace = InspectorTrace {
            seq: 0,
            request_id: fin.request_id,
            timestamp_unix_ms: self.timestamp_unix_ms,
            method: self.method.clone(),
            path: self.path.clone(),
            host: self.host.clone(),
            route_id: fin.route_id,
            upstream: fin.upstream,
            endpoint: fin.endpoint,
            status: fin.status,
            attempts: fin.attempts,
            request_bytes: fin.request_bytes,
            response_bytes: fin.response_bytes,
            ttfb_us: fin.ttfb_us,
            total_us: fin.total_us,
            aborted_mid_stream: fin.aborted_mid_stream,
            error: fin.error,
            trace_id: fin.trace_id,
            hooks: fin.hooks,
            stream_chunks: fin.stream_chunks,
            attributes,
        };
        self.buffer.push(trace);
    }
}

/// RAII extension guard held in `RequestCtx::extensions`.
///
/// Mirrors `SpanHandle`'s RAII emission design (RFC 0011): `InspectorCapturePlugin::on_complete`
/// records the core `RequestSummary` and hook timings, then every downstream route plugin
/// (such as `ai-usage-tracker` and `ai-budget`) runs its `on_complete` hook and enriches
/// `TraceAnnotations`. When `RequestCtx` drops after all `on_complete` hooks finish,
/// `CaptureState::drop` emits the single complete, fully-enriched [`InspectorTrace`].
#[derive(Debug, Clone)]
struct InspectorCaptureGuard {
    state: Arc<CaptureState>,
}

/// Opt-in global plugin capturing per-request hook waterfalls & annotations into
/// [`TraceRingBuffer`] when the Admin Inspector UI (`--ui` / `[admin] ui = true`) is enabled.
///
/// Built strictly on `shunt-plugin-sdk` with zero AI types and zero hot-path overhead when disabled.
pub struct InspectorCapturePlugin {
    buffer: Arc<TraceRingBuffer>,
}

impl InspectorCapturePlugin {
    pub fn new(buffer: Arc<TraceRingBuffer>) -> Self {
        Self { buffer }
    }
}

impl HttpPlugin for InspectorCapturePlugin {
    fn name(&self) -> &str {
        INSPECTOR_PLUGIN_NAME
    }

    fn hook_mask(&self) -> HookMask {
        HookMask::ON_REQUEST_HEADERS | HookMask::ON_COMPLETE
    }

    fn on_request_headers<'a>(
        &'a self,
        ctx: &'a mut RequestCtx,
        req: &'a mut RequestHead,
    ) -> HookResult<'a, Flow> {
        let host = req
            .headers
            .get(header::HOST)
            .and_then(|v| v.to_str().ok())
            .map(|s| s.trim().to_owned())
            .filter(|s| !s.is_empty())
            .or_else(|| ctx.tls_sni.clone());

        let annotations = TraceAnnotations::new();
        let guard = InspectorCaptureGuard {
            state: Arc::new(CaptureState {
                buffer: Arc::clone(&self.buffer),
                annotations: annotations.clone(),
                timestamp_unix_ms: current_unix_ms(),
                method: req.method.to_string(),
                path: req.uri.path().to_owned(),
                host,
                finalized: Mutex::new(None),
            }),
        };

        ctx.insert_ext(annotations);
        ctx.insert_ext(guard);
        HookResult::Ready(Flow::Continue)
    }

    fn on_complete<'a>(
        &'a self,
        ctx: &'a RequestCtx,
        summary: &'a RequestSummary,
    ) -> HookResult<'a, ()> {
        let Some(guard) = ctx.get_ext::<InspectorCaptureGuard>() else {
            return HookResult::Ready(());
        };

        let mut hooks = Vec::new();
        let mut chunk_acc: BTreeMap<(String, String), (usize, Duration)> = BTreeMap::new();

        for timing in &summary.hook_timings {
            if timing.plugin == INSPECTOR_PLUGIN_NAME || timing.plugin == "dev-waterfall" {
                continue;
            }
            if timing.hook == "on_response_body_chunk" || timing.hook == "on_request_body_chunk" {
                let entry = chunk_acc
                    .entry((timing.plugin.clone(), timing.hook.to_owned()))
                    .or_insert((0, Duration::ZERO));
                entry.0 += 1;
                entry.1 += timing.duration;
            } else {
                hooks.push(InspectorHookSpan {
                    plugin: timing.plugin.clone(),
                    hook: timing.hook.to_owned(),
                    duration_us: duration_to_us(timing.duration),
                });
            }
        }

        let stream_chunks: Vec<InspectorChunkSummary> = chunk_acc
            .into_iter()
            .map(|((plugin, hook), (chunks, total))| {
                let total_us = duration_to_us(total);
                let avg_us = total_us / (chunks.max(1) as u64);
                InspectorChunkSummary {
                    plugin,
                    hook,
                    chunks,
                    total_us,
                    avg_us,
                }
            })
            .collect();

        let trace_id = ctx
            .get_ext::<TraceContext>()
            .map(TraceContext::trace_id_hex);

        if let Ok(mut slot) = guard.state.finalized.lock() {
            *slot = Some(FinalizedCapture {
                request_id: summary.request_id,
                route_id: summary.route_id.clone(),
                upstream: summary.upstream.clone(),
                endpoint: summary.endpoint.clone(),
                status: summary.status.map(|s| s.as_u16()),
                attempts: summary.attempts,
                request_bytes: summary.request_bytes,
                response_bytes: summary.response_bytes,
                ttfb_us: summary.ttfb.map(duration_to_us),
                total_us: duration_to_us(summary.total_duration),
                aborted_mid_stream: summary.aborted_mid_stream,
                error: summary.error.clone(),
                trace_id,
                hooks,
                stream_chunks,
            });
        }

        HookResult::Ready(())
    }
}

fn duration_to_us(d: Duration) -> u64 {
    d.as_micros().min(u64::MAX as u128) as u64
}

fn current_unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis().min(u64::MAX as u128) as u64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mk_trace(status: Option<u16>, total_us: u64, route: &str) -> InspectorTrace {
        InspectorTrace {
            seq: 0,
            request_id: 1,
            timestamp_unix_ms: 1_700_000_000_000,
            method: "POST".into(),
            path: "/v1/chat/completions".into(),
            host: Some("localhost:8080".into()),
            route_id: Some(route.into()),
            upstream: Some("openai".into()),
            endpoint: Some("http://127.0.0.1:18080".into()),
            status,
            attempts: 1,
            request_bytes: 100,
            response_bytes: 200,
            ttfb_us: Some(total_us / 2),
            total_us,
            aborted_mid_stream: false,
            error: None,
            trace_id: None,
            hooks: Vec::new(),
            stream_chunks: Vec::new(),
            attributes: BTreeMap::new(),
        }
    }

    #[test]
    fn ring_buffer_enforces_capacity_and_tracks_summary() {
        let buf = TraceRingBuffer::new(3);
        let t1 = buf.push(mk_trace(Some(200), 100, "r1"));
        let t2 = buf.push(mk_trace(Some(200), 200, "r1"));
        let t3 = buf.push(mk_trace(Some(429), 300, "r2"));
        let t4 = buf.push(mk_trace(Some(502), 400, "r2"));

        assert_eq!((t1.seq, t2.seq, t3.seq, t4.seq), (1, 2, 3, 4));

        let all = buf.recent(None, None);
        assert_eq!(all.len(), 3);
        assert_eq!(all.iter().map(|t| t.seq).collect::<Vec<_>>(), vec![2, 3, 4]);

        let after_2 = buf.recent(Some(2), None);
        assert_eq!(
            after_2.iter().map(|t| t.seq).collect::<Vec<_>>(),
            vec![3, 4]
        );

        let limited = buf.recent(None, Some(2));
        assert_eq!(
            limited.iter().map(|t| t.seq).collect::<Vec<_>>(),
            vec![3, 4]
        );

        let summary = buf.summary();
        assert_eq!(summary.capacity, 3);
        assert_eq!(summary.buffered, 3);
        assert_eq!(summary.total_recorded, 4);
        assert_eq!(summary.total_errors, 2);
        assert_eq!(summary.status_2xx, 2);
        assert_eq!(summary.status_4xx, 1);
        assert_eq!(summary.status_5xx, 1);
        assert_eq!(summary.p50_us, Some(300));
        assert_eq!(summary.p99_us, Some(400));
    }

    #[test]
    fn sse_event_formatting_has_id_event_and_json_data() {
        let buf = TraceRingBuffer::new(4);
        let t = buf.push(mk_trace(Some(200), 150, "ai"));
        let frame = String::from_utf8(format_sse_trace_event(&t).to_vec()).unwrap();
        assert!(frame.starts_with("id: 1\nevent: trace\ndata: {"));
        assert!(frame.ends_with("\n\n"));
        assert!(frame.contains("\"route_id\":\"ai\""));
    }
}
