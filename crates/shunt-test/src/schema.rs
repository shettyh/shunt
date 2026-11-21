use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Top-level `shunt.spec.toml` contract specification.
#[derive(Debug, Clone, Deserialize)]
pub struct SpecFile {
    pub spec: SpecHeader,
    /// Test-only environment variable overrides applied during snapshot compilation.
    #[serde(default)]
    pub env: BTreeMap<String, String>,
    /// Reusable mock upstream definitions.
    #[serde(default)]
    pub mocks: Vec<MockSpec>,
    /// Ordered contract test cases.
    #[serde(default)]
    pub cases: Vec<CaseSpec>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct SpecHeader {
    pub name: String,
    /// Optional path to `shunt.toml` (resolved relative to spec file or workspace root).
    #[serde(default)]
    pub config: Option<String>,
    /// Optional inline `shunt.toml` content (for self-contained specs).
    #[serde(default)]
    pub config_inline: Option<String>,
}

/// Fault injection modes supported by in-process mock upstreams.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MockFault {
    /// Drop the raw TCP connection immediately after sending headers + first chunk.
    TcpResetMidStream,
    /// Accept connection and read request, then stall without sending response headers.
    StallHeaders,
    /// Send response headers + initial chunk, then stall indefinitely before next chunk.
    StallChunk,
    /// Bind an ephemeral port and immediately close it so TCP connect fails with ECONNREFUSED.
    ConnectRefused,
}

/// Single AWS EventStream frame specification for mocking binary Bedrock streams.
#[derive(Debug, Clone, Deserialize)]
pub struct AwsEventStreamFrameSpec {
    pub event_type: String,
    #[serde(default = "default_event_message_type")]
    pub message_type: String,
    #[serde(default)]
    pub json: Option<Value>,
}

fn default_event_message_type() -> String {
    "event".to_owned()
}

/// Scripted HTTP / SSE / EventStream response served by a mock upstream.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct MockResponseSpec {
    pub status: Option<u16>,
    pub headers: BTreeMap<String, String>,
    pub body: Option<String>,
    pub json: Option<Value>,
    /// Raw SSE frames to stream (automatically sets `content-type: text/event-stream`).
    pub sse_raw: Vec<String>,
    /// Binary AWS EventStream frames to encode & stream (sets `content-type: application/vnd.amazon.eventstream`).
    pub aws_eventstream: Vec<AwsEventStreamFrameSpec>,
    /// Arbitrary raw chunks to stream sequentially.
    pub chunks: Vec<String>,
    /// Optional byte chunking size to simulate fragmented TCP frames.
    pub chunk_split_bytes: Option<usize>,
    /// Optional delay (ms) between streamed chunks.
    pub chunk_delay_ms: Option<u64>,
    /// Optional fault injection behavior.
    pub fault: Option<MockFault>,
}

/// Named mock upstream definition bound to a logical upstream name in `shunt.toml`.
#[derive(Debug, Clone, Deserialize)]
pub struct MockSpec {
    pub upstream: String,
    pub name: String,
    /// Sequential per-request responses (repeats last entry once exhausted).
    #[serde(default)]
    pub sequence: Vec<MockResponseSpec>,
    /// Single-response shorthand (used when `sequence` is empty).
    #[serde(flatten)]
    pub single: MockResponseSpec,
}

impl MockSpec {
    /// Returns the effective sequence of responses for this mock.
    pub fn effective_sequence(&self) -> Vec<MockResponseSpec> {
        if self.sequence.is_empty() {
            vec![self.single.clone()]
        } else {
            self.sequence.clone()
        }
    }

    pub fn is_connect_refused(&self) -> bool {
        self.single.fault == Some(MockFault::ConnectRefused) && self.sequence.is_empty()
    }
}

/// A single contract test case (either single request/expect or multi-step scenario).
#[derive(Debug, Clone, Deserialize)]
pub struct CaseSpec {
    pub name: String,
    /// Mock names from `[[mocks]]` active for this case.
    #[serde(default)]
    pub use_mocks: Vec<String>,
    /// Single-request shorthand.
    #[serde(default)]
    pub request: Option<RequestSpec>,
    /// Single-request expectation shorthand.
    #[serde(default)]
    pub expect: Option<ExpectSpec>,
    /// Multi-step scenario (supports requests, clock advances, and hot reloads).
    #[serde(default)]
    pub steps: Vec<StepSpec>,
}

/// A single step inside a multi-step `[[cases.steps]]` scenario.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct StepSpec {
    pub name: Option<String>,
    /// Advance the injected `ManualClock` deterministically by this many milliseconds.
    pub advance_clock_ms: Option<u64>,
    /// Trigger an atomic hot reload with new inline TOML config (upstreams are auto-rebound).
    pub reload_config_inline: Option<String>,
    /// Expected outcome of `reload_config_inline` (defaults to `true` = expect reload success).
    pub expect_reload_ok: Option<bool>,
    /// Assert that these upstream names kept the exact same `pool_id` across the reload.
    pub expect_pool_reused: Vec<String>,
    /// Reset captured upstream request logs before this step.
    pub reset_captures: bool,
    /// Optional HTTP request to send to the gateway.
    pub request: Option<RequestSpec>,
    /// Optional expectations on the response, upstreams, metrics, and snapshot.
    pub expect: Option<ExpectSpec>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct RequestSpec {
    #[serde(default = "default_method")]
    pub method: String,
    pub path: String,
    #[serde(default)]
    pub headers: BTreeMap<String, String>,
    #[serde(default)]
    pub body: Option<String>,
    #[serde(default)]
    pub json: Option<Value>,
}

fn default_method() -> String {
    "GET".to_owned()
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct ExpectSpec {
    pub status: Option<u16>,
    /// Exact header value assertions (header names compared case-insensitively).
    pub headers: BTreeMap<String, String>,
    /// Substring header value assertions.
    pub headers_contains: BTreeMap<String, String>,
    /// Headers that must be present (any value).
    pub headers_present: Vec<String>,
    /// Headers that must NOT be present.
    pub headers_absent: Vec<String>,
    pub body_eq: Option<String>,
    pub body_contains: Option<String>,
    pub body_not_contains: Option<String>,
    /// Assert response body parses as JSON equal to this value.
    pub json_eq: Option<Value>,
    /// RFC 6901 JSON pointer assertions against parsed response JSON (e.g. `"/choices/0/message/content"`).
    pub json_path: BTreeMap<String, Value>,
    /// Assert the stream returned a transport/stream error (for mid-stream fault tests).
    pub stream_error: Option<bool>,
    /// Assert concatenated text deltas (or raw SSE data) contains this substring.
    pub sse_contains_text: Option<String>,
    /// Assert the final SSE event's data equals this string (e.g. `"[DONE]"`).
    pub sse_ends_with: Option<String>,
    /// Assert the final SSE event's `event:` name equals this string (e.g. `"message_stop"`, `"response.completed"`).
    pub sse_last_event: Option<String>,
    /// Assert every listed SSE `event:` name appeared at least once in the stream.
    pub sse_events_present: Vec<String>,
    /// Assert exact number of parsed SSE events.
    pub sse_event_count: Option<usize>,
    /// Assert Prometheus metric counter deltas (summed by metric name or exact series selector).
    pub metrics_delta: BTreeMap<String, f64>,
    /// Assert none of these secret substrings appear anywhere in `GET /snapshot`.
    pub snapshot_redacts: Vec<String>,
    /// Assertions against requests captured by in-process mock upstreams.
    pub upstream_calls: Vec<UpstreamCallExpect>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct UpstreamCallExpect {
    pub upstream: String,
    /// Exact expected number of calls captured for this upstream.
    pub count: Option<usize>,
    /// 0-based index of the captured call to inspect (defaults to last call).
    pub call_index: Option<usize>,
    pub method: Option<String>,
    pub path: Option<String>,
    pub headers: BTreeMap<String, String>,
    pub headers_contains: BTreeMap<String, String>,
    pub headers_present: Vec<String>,
    pub headers_absent: Vec<String>,
    pub body_contains: Option<String>,
    pub json_path: BTreeMap<String, Value>,
}
