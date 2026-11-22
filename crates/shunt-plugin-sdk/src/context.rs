use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

use http::{Extensions, StatusCode};

use crate::http_types::HookTiming;
use crate::telemetry::{SpanHandle, SpanValue, TraceAnnotations, current_unix_nanos};

/// Per-request context threaded through every lifecycle hook.
///
/// Plugins communicate across hooks (and across plugins) via typed values stored
/// in `extensions`.
#[derive(Debug)]
pub struct RequestCtx {
    pub request_id: u64,
    pub client_addr: SocketAddr,
    pub tls_sni: Option<String>,
    pub route_id: Option<String>,
    pub attempt: usize,
    pub started_at: Instant,
    pub extensions: Extensions,
    pub trace_enabled: bool,
    pub hook_timings: Vec<HookTiming>,
    pub last_upstream_error: Option<String>,
    pub last_upstream_status: Option<StatusCode>,
}

impl RequestCtx {
    pub fn new(request_id: u64, client_addr: SocketAddr, tls_sni: Option<String>) -> Self {
        Self {
            request_id,
            client_addr,
            tls_sni,
            route_id: None,
            attempt: 0,
            started_at: Instant::now(),
            extensions: Extensions::new(),
            trace_enabled: false,
            hook_timings: Vec::new(),
            last_upstream_error: None,
            last_upstream_status: None,
        }
    }

    /// Inserts a typed value into the per-request extension map.
    #[inline]
    pub fn insert_ext<T: Clone + Send + Sync + 'static>(&mut self, val: T) -> Option<T> {
        self.extensions.insert(val)
    }

    /// Gets a shared reference to a typed value from the per-request extension map.
    #[inline]
    pub fn get_ext<T: Send + Sync + 'static>(&self) -> Option<&T> {
        self.extensions.get::<T>()
    }

    /// Gets a mutable reference to a typed value from the per-request extension map.
    #[inline]
    pub fn get_ext_mut<T: Send + Sync + 'static>(&mut self) -> Option<&mut T> {
        self.extensions.get_mut::<T>()
    }

    /// Removes a typed value from the per-request extension map.
    #[inline]
    pub fn remove_ext<T: Send + Sync + 'static>(&mut self) -> Option<T> {
        self.extensions.remove::<T>()
    }

    /// Records a hook timing entry when tracing is enabled.
    #[inline]
    pub fn record_timing(&mut self, plugin: &str, hook: &'static str, duration: Duration) {
        if self.trace_enabled {
            self.hook_timings.push(HookTiming {
                plugin: plugin.to_owned(),
                hook,
                duration,
            });
        }
    }

    /// Returns `true` if either an active OTel [`SpanHandle`] or opt-in [`TraceAnnotations`]
    /// collector is attached to this request.
    #[inline]
    pub fn has_trace_collectors(&self) -> bool {
        self.extensions.get::<SpanHandle>().is_some()
            || self.extensions.get::<TraceAnnotations>().is_some()
    }

    /// Attaches a string attribute to any active [`SpanHandle`] and/or [`TraceAnnotations`]
    /// collector on this request (no-op with zero allocations when neither is attached).
    #[inline]
    pub fn annotate_str(&self, key: &str, value: &str) {
        if let Some(span) = self.extensions.get::<SpanHandle>() {
            span.set_str(key, value);
        }
        if let Some(ann) = self.extensions.get::<TraceAnnotations>() {
            ann.set_str(key, value);
        }
    }

    /// Attaches a signed integer attribute to any active [`SpanHandle`] and/or [`TraceAnnotations`]
    /// collector on this request (no-op when neither is attached).
    #[inline]
    pub fn annotate_int(&self, key: &str, value: i64) {
        if let Some(span) = self.extensions.get::<SpanHandle>() {
            span.set_int(key, value);
        }
        if let Some(ann) = self.extensions.get::<TraceAnnotations>() {
            ann.set_int(key, value);
        }
    }

    /// Attaches a finite floating-point attribute to any active [`SpanHandle`] and/or
    /// [`TraceAnnotations`] collector on this request (no-op when neither is attached).
    #[inline]
    pub fn annotate_float(&self, key: &str, value: f64) {
        if let Some(span) = self.extensions.get::<SpanHandle>() {
            span.set_float(key, value);
        }
        if let Some(ann) = self.extensions.get::<TraceAnnotations>() {
            ann.set_float(key, value);
        }
    }

    /// Attaches a boolean attribute to any active [`SpanHandle`] and/or [`TraceAnnotations`]
    /// collector on this request (no-op when neither is attached).
    #[inline]
    pub fn annotate_bool(&self, key: &str, value: bool) {
        if let Some(span) = self.extensions.get::<SpanHandle>() {
            span.set_bool(key, value);
        }
        if let Some(ann) = self.extensions.get::<TraceAnnotations>() {
            ann.set_bool(key, value);
        }
    }

    /// Appends a structured timed event to any active [`SpanHandle`] on this request
    /// (zero-cost no-op when no sampled span is attached).
    #[inline]
    pub fn add_span_event(&self, name: impl Into<String>, attributes: BTreeMap<String, SpanValue>) {
        if let Some(span) = self.extensions.get::<SpanHandle>() {
            span.add_event(name, current_unix_nanos(), attributes);
        }
    }
}
