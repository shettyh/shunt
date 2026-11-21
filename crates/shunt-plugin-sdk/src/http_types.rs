use std::time::Duration;

use bytes::Bytes;
use http::{HeaderMap, Method, StatusCode, Uri, Version};

/// Mutable HTTP request metadata exposed to plugins (decoupled from `hyper`).
#[derive(Debug, Clone)]
pub struct RequestHead {
    pub method: Method,
    pub uri: Uri,
    pub version: Version,
    pub headers: HeaderMap,
}

/// Mutable HTTP response metadata exposed to plugins (decoupled from `hyper`).
#[derive(Debug, Clone)]
pub struct ResponseHead {
    pub status: StatusCode,
    pub version: Version,
    pub headers: HeaderMap,
}

/// Per-attempt upstream request that plugins can mutate specifically for the chosen target
/// (e.g., injecting provider-specific auth headers, rewriting path, or translating buffered JSON).
#[derive(Debug, Clone)]
pub struct UpstreamRequest {
    pub method: Method,
    pub uri: Uri,
    pub headers: HeaderMap,
    /// Present when the route buffered the request body (`HookMask::REQUEST_BODY_BUFFERED`).
    /// Cheaply cloned per retry attempt via `Bytes` reference counting.
    pub body: Option<Bytes>,
    /// Resolved base URI of the selected upstream endpoint for this attempt
    /// (e.g., `https://bedrock-runtime.us-east-1.amazonaws.com` or `http://127.0.0.1:18080`).
    /// Populated by `shunt-core` prior to `on_upstream_request` so signing/auth plugins
    /// can inspect the exact target scheme, authority, and base path.
    pub endpoint_uri: Option<Uri>,
}

/// Mutable routing decision passed to `on_route`.
#[derive(Debug, Clone)]
pub struct RouteDecision {
    pub route_id: String,
    pub upstream: String,
    pub max_attempts: usize,
}

/// Mutable upstream target selection passed to `on_upstream_select` on each attempt.
#[derive(Debug, Clone)]
pub struct UpstreamSelection {
    /// Logical upstream name in the active snapshot.
    pub upstream: String,
    /// Optional explicit endpoint override (e.g., `"https://api.anthropic.com"`).
    /// When `None`, the upstream's pool selects the next healthy endpoint.
    pub endpoint_override: Option<String>,
    /// 1-indexed attempt number.
    pub attempt: usize,
    /// Maximum configured attempts for this request.
    pub max_attempts: usize,
}

/// Per-hook execution timing entry (populated when tracing is enabled, e.g., `shunt dev`).
#[derive(Debug, Clone)]
pub struct HookTiming {
    pub plugin: String,
    pub hook: &'static str,
    pub duration: Duration,
}

/// Final summary passed to `on_complete` after the response has flushed or aborted.
#[derive(Debug, Clone)]
pub struct RequestSummary {
    pub request_id: u64,
    pub route_id: Option<String>,
    pub upstream: Option<String>,
    pub endpoint: Option<String>,
    pub status: Option<StatusCode>,
    pub attempts: usize,
    pub request_bytes: u64,
    pub response_bytes: u64,
    pub ttfb: Option<Duration>,
    pub total_duration: Duration,
    pub error: Option<String>,
    pub aborted_mid_stream: bool,
    pub hook_timings: Vec<HookTiming>,
}
