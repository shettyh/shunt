//! Public plugin SDK for the Shunt HTTP gateway.
//!
//! This crate intentionally exposes clean, decoupled HTTP and streaming primitives
//! (`http`, `bytes`) and never leaks `hyper` internals.

pub mod clock;
pub mod context;
pub mod distributed;
pub mod flow;
pub mod http_types;
pub mod mask;
pub mod plugin;
pub mod state;
pub mod telemetry;

pub use bytes::Bytes;
pub use clock::{Clock, ManualClock, SystemClock};
pub use context::RequestCtx;
pub use distributed::{
    DistributedStore, DistributedStoreError, FailurePolicy, InMemoryDistributedStore, QuotaOutcome,
};
pub use flow::{BoxFuture, BufferedResponse, Flow, HookResult, StreamFlow};
pub use http::{HeaderMap, HeaderName, HeaderValue, Method, StatusCode, Uri, Version, header};
pub use http_types::{
    HookTiming, RequestHead, RequestSummary, ResponseHead, RouteDecision, UpstreamRequest,
    UpstreamSelection,
};
pub use mask::HookMask;
pub use plugin::HttpPlugin;
pub use state::{
    BuildContext, PluginBuildError, PluginConfig, PluginFactory, PluginRegistry, StateHandle,
    StateStore,
};
pub use telemetry::{
    InMemoryTelemetrySink, ParsedTraceparent, SpanHandle, SpanKind, SpanRecord, SpanStatusCode,
    SpanValue, TelemetrySink, TraceAnnotations, TraceContext, current_unix_nanos, encode_hex_lower,
    generate_span_id, generate_trace_id,
};
