use std::collections::BTreeMap;
use std::collections::hash_map::RandomState;
use std::fmt;
use std::hash::{BuildHasher, Hasher};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

/// Parsed W3C Trace Context `traceparent` header (version `00`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ParsedTraceparent {
    pub trace_id: [u8; 16],
    pub parent_id: [u8; 8],
    pub trace_flags: u8,
}

impl ParsedTraceparent {
    /// Returns `true` when the W3C sampled flag (`0x01`) is set.
    #[inline]
    pub const fn is_sampled(self) -> bool {
        (self.trace_flags & 0x01) != 0
    }
}

/// Active W3C Trace Context attached to `RequestCtx::extensions` by `otel-trace`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TraceContext {
    pub trace_id: [u8; 16],
    pub span_id: [u8; 8],
    pub parent_span_id: Option<[u8; 8]>,
    pub trace_flags: u8,
    pub tracestate: Option<String>,
}

impl TraceContext {
    /// Parses a W3C `traceparent` header per W3C Trace Context Level 1/2 (`00-<32hex>-<16hex>-<2hex>`).
    ///
    /// Rejects version `ff`, non-lowercase or non-hex characters, all-zero `trace-id`,
    /// all-zero `parent-id`, and trailing fields on version `00`.
    pub fn parse_traceparent(raw: &str) -> Option<ParsedTraceparent> {
        let s = raw.trim();
        let bytes = s.as_bytes();
        // Version `00` must be strictly 55 bytes: `2 + 1 + 32 + 1 + 16 + 1 + 2`.
        // Future versions (`01`..`fe`) may carry extra `-<field>` suffixes per W3C spec.
        if bytes.len() < 55 {
            return None;
        }
        if bytes[2] != b'-' || bytes[35] != b'-' || bytes[52] != b'-' {
            return None;
        }

        let version = decode_hex_byte(bytes[0], bytes[1])?;
        if version == 0xff {
            return None;
        }
        if version == 0x00 && bytes.len() != 55 {
            return None;
        }
        if version != 0x00 && bytes.len() > 55 && bytes[55] != b'-' {
            return None;
        }

        let mut trace_id = [0u8; 16];
        decode_hex_exact(&bytes[3..35], &mut trace_id)?;
        if trace_id == [0u8; 16] {
            return None;
        }

        let mut parent_id = [0u8; 8];
        decode_hex_exact(&bytes[36..52], &mut parent_id)?;
        if parent_id == [0u8; 8] {
            return None;
        }

        let trace_flags = decode_hex_byte(bytes[53], bytes[54])?;

        Some(ParsedTraceparent {
            trace_id,
            parent_id,
            trace_flags,
        })
    }

    /// Generates a fresh root [`TraceContext`] with guaranteed non-zero IDs.
    pub fn new_root(sampled: bool) -> Self {
        Self {
            trace_id: generate_trace_id(),
            span_id: generate_span_id(),
            parent_span_id: None,
            trace_flags: if sampled { 0x01 } else { 0x00 },
            tracestate: None,
        }
    }

    /// Creates a child [`TraceContext`] inheriting `parent.trace_id` with a fresh `span_id`.
    pub fn child_from(
        parent: ParsedTraceparent,
        sampled: bool,
        tracestate: Option<String>,
    ) -> Self {
        let mut flags = parent.trace_flags & !0x01;
        if sampled {
            flags |= 0x01;
        }
        Self {
            trace_id: parent.trace_id,
            span_id: generate_span_id(),
            parent_span_id: Some(parent.parent_id),
            trace_flags: flags,
            tracestate,
        }
    }

    /// Deterministic ratio sampler on `trace_id` so sampling decisions are consistent and fast.
    pub fn should_sample_trace_id(trace_id: [u8; 16], sample_rate: f64) -> bool {
        if sample_rate <= 0.0 || !sample_rate.is_finite() {
            return false;
        }
        if sample_rate >= 1.0 {
            return true;
        }
        // Use the lower 64 bits of the trace ID (matching OpenTelemetry TraceIdRatioBased).
        let low = u64::from_be_bytes([
            trace_id[8],
            trace_id[9],
            trace_id[10],
            trace_id[11],
            trace_id[12],
            trace_id[13],
            trace_id[14],
            trace_id[15],
        ]);
        let threshold = (sample_rate * (u64::MAX as f64)) as u64;
        low <= threshold
    }

    /// Returns `true` when the sampled bit (`0x01`) is set.
    #[inline]
    pub const fn is_sampled(&self) -> bool {
        (self.trace_flags & 0x01) != 0
    }

    /// Lowercase 32-char hex `trace-id`.
    pub fn trace_id_hex(&self) -> String {
        encode_hex_lower(&self.trace_id)
    }

    /// Lowercase 16-char hex `span-id`.
    pub fn span_id_hex(&self) -> String {
        encode_hex_lower(&self.span_id)
    }

    /// Lowercase 16-char hex `parent-span-id` if present.
    pub fn parent_span_id_hex(&self) -> Option<String> {
        self.parent_span_id.as_ref().map(|b| encode_hex_lower(b))
    }

    /// Formats a valid W3C `traceparent` header value (`00-<trace_id>-<span_id>-<flags>`).
    pub fn format_traceparent(&self) -> String {
        format!(
            "00-{}-{}-{:02x}",
            self.trace_id_hex(),
            self.span_id_hex(),
            self.trace_flags
        )
    }
}

/// Typed OpenTelemetry span attribute value.
#[derive(Debug, Clone, PartialEq)]
pub enum SpanValue {
    String(String),
    Int(i64),
    Float(f64),
    Bool(bool),
}

impl SpanValue {
    /// Converts this typed attribute value into a JSON representation for read-only inspection APIs.
    pub fn to_json_value(&self) -> serde_json::Value {
        match self {
            SpanValue::String(s) => serde_json::Value::String(s.clone()),
            SpanValue::Int(i) => serde_json::Value::Number((*i).into()),
            SpanValue::Float(f) => serde_json::Number::from_f64(*f)
                .map(serde_json::Value::Number)
                .unwrap_or(serde_json::Value::Null),
            SpanValue::Bool(b) => serde_json::Value::Bool(*b),
        }
    }
}

/// OpenTelemetry span kind numeric code.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(u8)]
pub enum SpanKind {
    Internal = 1,
    #[default]
    Server = 2,
    Client = 3,
}

/// OpenTelemetry span status numeric code.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(u8)]
pub enum SpanStatusCode {
    #[default]
    Unset = 0,
    Ok = 1,
    Error = 2,
}

/// Timed structured event attached to a [`SpanRecord`] (OTLP `Span.Event`).
#[derive(Debug, Clone, PartialEq)]
pub struct SpanEvent {
    pub name: String,
    pub time_unix_nanos: u64,
    pub attributes: BTreeMap<String, SpanValue>,
}

/// Completed, immutable telemetry span passed to a [`TelemetrySink`].
#[derive(Debug, Clone, PartialEq)]
pub struct SpanRecord {
    pub trace_id: [u8; 16],
    pub span_id: [u8; 8],
    pub parent_span_id: Option<[u8; 8]>,
    pub trace_flags: u8,
    pub name: String,
    pub kind: SpanKind,
    pub start_time_unix_nanos: u64,
    pub end_time_unix_nanos: u64,
    pub status: SpanStatusCode,
    pub status_message: Option<String>,
    pub attributes: BTreeMap<String, SpanValue>,
    pub events: Vec<SpanEvent>,
}

impl SpanRecord {
    pub fn trace_id_hex(&self) -> String {
        encode_hex_lower(&self.trace_id)
    }

    pub fn span_id_hex(&self) -> String {
        encode_hex_lower(&self.span_id)
    }

    pub fn parent_span_id_hex(&self) -> Option<String> {
        self.parent_span_id.as_ref().map(|b| encode_hex_lower(b))
    }
}

/// General-purpose, non-blocking telemetry span sink shared across plugins via [`crate::BuildContext`].
///
/// Implementations MUST NOT block the caller (e.g., use a bounded non-blocking channel and
/// drop spans when saturated).
pub trait TelemetrySink: fmt::Debug + Send + Sync + 'static {
    /// Human-readable backend identifier (e.g., `"otlp_http"`, `"in_memory"`).
    fn backend_name(&self) -> &str;

    /// Enqueues a completed [`SpanRecord`] without blocking.
    /// Returns `true` if accepted or `false` if dropped due to backpressure.
    fn emit_span(&self, span: SpanRecord) -> bool;
}

/// Thread-safe bounded in-memory [`TelemetrySink`] for unit & integration testing.
#[derive(Debug)]
pub struct InMemoryTelemetrySink {
    capacity: usize,
    spans: Mutex<Vec<SpanRecord>>,
    dropped: AtomicU64,
}

impl Default for InMemoryTelemetrySink {
    fn default() -> Self {
        Self::new(1024)
    }
}

impl InMemoryTelemetrySink {
    pub fn new(capacity: usize) -> Self {
        Self {
            capacity: capacity.max(1),
            spans: Mutex::new(Vec::new()),
            dropped: AtomicU64::new(0),
        }
    }

    pub fn spans(&self) -> Vec<SpanRecord> {
        self.spans
            .lock()
            .expect("InMemoryTelemetrySink lock poisoned")
            .clone()
    }

    pub fn take_spans(&self) -> Vec<SpanRecord> {
        std::mem::take(
            &mut *self
                .spans
                .lock()
                .expect("InMemoryTelemetrySink lock poisoned"),
        )
    }

    pub fn dropped(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
    }
}

impl TelemetrySink for InMemoryTelemetrySink {
    fn backend_name(&self) -> &str {
        "in_memory"
    }

    fn emit_span(&self, span: SpanRecord) -> bool {
        let mut guard = self
            .spans
            .lock()
            .expect("InMemoryTelemetrySink lock poisoned");
        if guard.len() >= self.capacity {
            self.dropped.fetch_add(1, Ordering::Relaxed);
            return false;
        }
        guard.push(span);
        true
    }
}

#[derive(Debug)]
struct SpanBuilderData {
    record: SpanRecord,
    finalized: bool,
}

#[derive(Debug)]
struct SpanState {
    sink: Arc<dyn TelemetrySink>,
    inner: Mutex<SpanBuilderData>,
}

impl Drop for SpanState {
    fn drop(&mut self) {
        if let Ok(mut guard) = self.inner.lock() {
            if !guard.finalized {
                guard.record.end_time_unix_nanos = current_unix_nanos();
                if guard.record.status == SpanStatusCode::Unset {
                    guard.record.status = SpanStatusCode::Error;
                    guard.record.status_message = Some("request cancelled".to_owned());
                }
            }
            let record = guard.record.clone();
            drop(guard);
            let _ = self.sink.emit_span(record);
        }
    }
}

/// Interior-mutable per-request span handle attached to `RequestCtx::extensions` by `otel-trace`
/// ONLY when tracing is enabled and the request is sampled.
///
/// Any plugin (including `shunt-ai` plugins inside immutable `&RequestCtx` `on_complete` hooks)
/// can attach attributes or refine the span name without depending on OTLP or `shunt-core`.
/// When `RequestCtx` drops after all `on_complete` hooks finish, the completed [`SpanRecord`]
/// is emitted exactly once to the configured [`TelemetrySink`].
#[derive(Debug, Clone)]
pub struct SpanHandle {
    state: Arc<SpanState>,
}

impl SpanHandle {
    pub fn start(
        trace: &TraceContext,
        name: impl Into<String>,
        kind: SpanKind,
        start_time_unix_nanos: u64,
        sink: Arc<dyn TelemetrySink>,
    ) -> Self {
        let record = SpanRecord {
            trace_id: trace.trace_id,
            span_id: trace.span_id,
            parent_span_id: trace.parent_span_id,
            trace_flags: trace.trace_flags,
            name: name.into(),
            kind,
            start_time_unix_nanos,
            end_time_unix_nanos: start_time_unix_nanos,
            status: SpanStatusCode::Unset,
            status_message: None,
            attributes: BTreeMap::new(),
            events: Vec::new(),
        };
        Self {
            state: Arc::new(SpanState {
                sink,
                inner: Mutex::new(SpanBuilderData {
                    record,
                    finalized: false,
                }),
            }),
        }
    }

    pub fn set_name(&self, name: impl Into<String>) {
        if let Ok(mut guard) = self.state.inner.lock() {
            guard.record.name = name.into();
        }
    }

    pub fn set_str(&self, key: impl Into<String>, value: impl Into<String>) {
        if let Ok(mut guard) = self.state.inner.lock() {
            guard
                .record
                .attributes
                .insert(key.into(), SpanValue::String(value.into()));
        }
    }

    pub fn set_int(&self, key: impl Into<String>, value: i64) {
        if let Ok(mut guard) = self.state.inner.lock() {
            guard
                .record
                .attributes
                .insert(key.into(), SpanValue::Int(value));
        }
    }

    pub fn set_float(&self, key: impl Into<String>, value: f64) {
        if value.is_finite()
            && let Ok(mut guard) = self.state.inner.lock()
        {
            guard
                .record
                .attributes
                .insert(key.into(), SpanValue::Float(value));
        }
    }

    pub fn set_bool(&self, key: impl Into<String>, value: bool) {
        if let Ok(mut guard) = self.state.inner.lock() {
            guard
                .record
                .attributes
                .insert(key.into(), SpanValue::Bool(value));
        }
    }

    pub fn set_status(&self, status: SpanStatusCode, message: Option<String>) {
        if let Ok(mut guard) = self.state.inner.lock() {
            guard.record.status = status;
            guard.record.status_message = message;
        }
    }

    /// Appends a timed structured [`SpanEvent`] to this span.
    pub fn add_event(
        &self,
        name: impl Into<String>,
        time_unix_nanos: u64,
        attributes: BTreeMap<String, SpanValue>,
    ) {
        if let Ok(mut guard) = self.state.inner.lock() {
            guard.record.events.push(SpanEvent {
                name: name.into(),
                time_unix_nanos,
                attributes,
            });
        }
    }

    /// Marks the span's end timestamp and completion status (`otel-trace::on_complete`).
    /// Subsequent plugins running in `on_complete` may still attach additional attributes
    /// before `RequestCtx` drops and flushes the completed span.
    pub fn finalize(
        &self,
        end_time_unix_nanos: u64,
        status: SpanStatusCode,
        status_message: Option<String>,
    ) {
        if let Ok(mut guard) = self.state.inner.lock() {
            guard.record.end_time_unix_nanos =
                end_time_unix_nanos.max(guard.record.start_time_unix_nanos);
            guard.record.status = status;
            guard.record.status_message = status_message;
            guard.finalized = true;
        }
    }
}

/// Interior-mutable per-request key/value annotation bag attached to `RequestCtx::extensions`
/// by opt-in inspection plugins (e.g., the Admin Inspector UI).
///
/// Mirrors [`SpanHandle`]'s interior-mutability pattern so any plugin can attach structured
/// metadata during immutable `&RequestCtx` `on_complete` hooks without depending on OTLP,
/// `shunt-core`, or any specific plugin domain.
#[derive(Debug, Clone, Default)]
pub struct TraceAnnotations {
    inner: Arc<Mutex<BTreeMap<String, SpanValue>>>,
}

impl TraceAnnotations {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn set_str(&self, key: impl Into<String>, value: impl Into<String>) {
        if let Ok(mut guard) = self.inner.lock() {
            guard.insert(key.into(), SpanValue::String(value.into()));
        }
    }

    pub fn set_int(&self, key: impl Into<String>, value: i64) {
        if let Ok(mut guard) = self.inner.lock() {
            guard.insert(key.into(), SpanValue::Int(value));
        }
    }

    pub fn set_float(&self, key: impl Into<String>, value: f64) {
        if value.is_finite()
            && let Ok(mut guard) = self.inner.lock()
        {
            guard.insert(key.into(), SpanValue::Float(value));
        }
    }

    pub fn set_bool(&self, key: impl Into<String>, value: bool) {
        if let Ok(mut guard) = self.inner.lock() {
            guard.insert(key.into(), SpanValue::Bool(value));
        }
    }

    /// Returns a cloned snapshot of all recorded annotations.
    pub fn snapshot(&self) -> BTreeMap<String, SpanValue> {
        self.inner
            .lock()
            .map(|guard| guard.clone())
            .unwrap_or_default()
    }
}

/// Returns the current wall-clock timestamp in nanoseconds since Unix epoch.
pub fn current_unix_nanos() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos().min(u64::MAX as u128) as u64)
        .unwrap_or(0)
}

/// Generates a non-zero 128-bit trace ID using fast, zero-dependency entropy.
pub fn generate_trace_id() -> [u8; 16] {
    loop {
        let a = next_random_u64();
        let b = next_random_u64();
        if a != 0 || b != 0 {
            let mut out = [0u8; 16];
            out[..8].copy_from_slice(&a.to_be_bytes());
            out[8..].copy_from_slice(&b.to_be_bytes());
            return out;
        }
    }
}

/// Generates a non-zero 64-bit span ID using fast, zero-dependency entropy.
pub fn generate_span_id() -> [u8; 8] {
    loop {
        let v = next_random_u64();
        if v != 0 {
            return v.to_be_bytes();
        }
    }
}

fn next_random_u64() -> u64 {
    static COUNTER: AtomicU64 = AtomicU64::new(1);
    let seq = COUNTER.fetch_add(1, Ordering::Relaxed);
    let mut hasher = RandomState::new().build_hasher();
    hasher.write_u64(seq);
    hasher.write_u64(current_unix_nanos());
    let mut x = hasher.finish();
    // SplitMix64 finalizer for strong bit avalanche across all 64 bits.
    x = x.wrapping_add(0x9e37_79b9_7f4a_7c15);
    x = (x ^ (x >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    x = (x ^ (x >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    x ^ (x >> 31)
}

pub fn encode_hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

fn decode_hex_exact(src: &[u8], dst: &mut [u8]) -> Option<()> {
    if src.len() != dst.len() * 2 {
        return None;
    }
    for (i, slot) in dst.iter_mut().enumerate() {
        *slot = decode_hex_byte(src[i * 2], src[i * 2 + 1])?;
    }
    Some(())
}

#[inline]
fn decode_hex_byte(hi: u8, lo: u8) -> Option<u8> {
    Some((decode_lower_nibble(hi)? << 4) | decode_lower_nibble(lo)?)
}

/// W3C Trace Context mandates lowercase hex digits (`0-9`, `a-f`).
#[inline]
const fn decode_lower_nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn traceparent_parse_and_format_roundtrip() {
        let raw = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01";
        let parsed = TraceContext::parse_traceparent(raw).expect("valid traceparent");
        assert!(parsed.is_sampled());
        assert_eq!(
            encode_hex_lower(&parsed.trace_id),
            "4bf92f3577b34da6a3ce929d0e0e4736"
        );
        assert_eq!(encode_hex_lower(&parsed.parent_id), "00f067aa0ba902b7");

        let child = TraceContext::child_from(parsed, true, Some("rojo=00f067aa0ba902b7".into()));
        assert_eq!(child.trace_id, parsed.trace_id);
        assert_eq!(child.parent_span_id, Some(parsed.parent_id));
        assert_ne!(child.span_id, parsed.parent_id);
        assert!(child.is_sampled());

        let formatted = child.format_traceparent();
        let reparsed = TraceContext::parse_traceparent(&formatted).expect("roundtrip valid");
        assert_eq!(reparsed.trace_id, child.trace_id);
        assert_eq!(reparsed.parent_id, child.span_id);
        assert_eq!(reparsed.trace_flags, 0x01);
    }

    #[test]
    fn traceparent_rejects_malformed_inputs() {
        let invalid = [
            "",
            "00-00000000000000000000000000000000-00f067aa0ba902b7-01", // zero trace id
            "00-4bf92f3577b34da6a3ce929d0e0e4736-0000000000000000-01", // zero parent id
            "ff-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01", // forbidden version ff
            "00-4BF92F3577B34DA6A3CE929D0E0E4736-00f067aa0ba902b7-01", // uppercase hex
            "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01-extra", // trailing on v00
            "00-short-00f067aa0ba902b7-01",
        ];
        for bad in invalid {
            assert!(
                TraceContext::parse_traceparent(bad).is_none(),
                "expected `{bad}` to be rejected"
            );
        }
        // Future version `01` with extra field is permitted by W3C spec.
        assert!(
            TraceContext::parse_traceparent(
                "01-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01-extra"
            )
            .is_some()
        );
    }

    #[test]
    fn span_handle_emits_on_drop_after_enrichment() {
        let sink = Arc::new(InMemoryTelemetrySink::new(16));
        let trace = TraceContext::new_root(true);
        {
            let handle = SpanHandle::start(
                &trace,
                "POST /v1/chat/completions",
                SpanKind::Server,
                1000,
                Arc::clone(&sink) as Arc<dyn TelemetrySink>,
            );
            handle.set_str("http.request.method", "POST");
            handle.finalize(2500, SpanStatusCode::Ok, None);
            // Simulate a downstream `on_complete` plugin enriching after finalize.
            handle.set_str("gen_ai.provider.name", "openai");
            handle.set_int("gen_ai.usage.input_tokens", 42);
            assert!(sink.spans().is_empty(), "must not emit until handle drops");
        }
        let spans = sink.spans();
        assert_eq!(spans.len(), 1);
        assert_eq!(spans[0].start_time_unix_nanos, 1000);
        assert_eq!(spans[0].end_time_unix_nanos, 2500);
        assert_eq!(
            spans[0].attributes.get("gen_ai.provider.name"),
            Some(&SpanValue::String("openai".to_owned()))
        );
        assert_eq!(
            spans[0].attributes.get("gen_ai.usage.input_tokens"),
            Some(&SpanValue::Int(42))
        );
    }

    #[test]
    fn request_ctx_annotate_populates_both_span_handle_and_trace_annotations() {
        let sink = Arc::new(InMemoryTelemetrySink::new(8));
        let trace = TraceContext::new_root(true);
        let annotations = TraceAnnotations::new();
        {
            let mut ctx = crate::RequestCtx::new(7, "127.0.0.1:4000".parse().unwrap(), None);
            assert!(!ctx.has_trace_collectors());
            ctx.insert_ext(SpanHandle::start(
                &trace,
                "POST /v1/chat/completions",
                SpanKind::Server,
                100,
                Arc::clone(&sink) as Arc<dyn TelemetrySink>,
            ));
            ctx.insert_ext(annotations.clone());
            assert!(ctx.has_trace_collectors());

            ctx.annotate_str("gen_ai.provider.name", "openai");
            ctx.annotate_int("gen_ai.usage.input_tokens", 12);
            ctx.annotate_float("shunt.ai.cost_usd", 0.0025);
            ctx.annotate_bool("shunt.ai.stream", false);
        }

        let snap = annotations.snapshot();
        assert_eq!(
            snap.get("gen_ai.provider.name"),
            Some(&SpanValue::String("openai".to_owned()))
        );
        assert_eq!(
            snap.get("gen_ai.usage.input_tokens"),
            Some(&SpanValue::Int(12))
        );
        assert_eq!(snap.get("shunt.ai.stream"), Some(&SpanValue::Bool(false)));
        assert_eq!(
            snap.get("shunt.ai.cost_usd").unwrap().to_json_value(),
            serde_json::json!(0.0025)
        );

        let spans = sink.spans();
        assert_eq!(spans.len(), 1);
        assert_eq!(
            spans[0].attributes.get("gen_ai.provider.name"),
            Some(&SpanValue::String("openai".to_owned()))
        );
    }
}
