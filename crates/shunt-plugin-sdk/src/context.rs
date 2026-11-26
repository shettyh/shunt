use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use http::{Extensions, StatusCode};

use crate::http_types::HookTiming;
use crate::telemetry::{SpanHandle, SpanValue, TraceAnnotations, current_unix_nanos};

/// Verified peer client TLS certificate metadata extracted during an mTLS handshake.
///
/// Populated once per TLS connection on [`RequestCtx::client_cert`] and shared cheaply
/// via [`Arc`] across pipelined/multiplexed requests with zero heap allocation per request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientCertInfo {
    /// Subject Common Name (`CN`, OID `2.5.4.3`) if present.
    pub subject_cn: Option<String>,
    /// Canonical formatted Subject Distinguished Name (e.g. `"CN=svc-a,O=Acme"`).
    pub subject_dn: String,
    /// Canonical formatted Issuer Distinguished Name.
    pub issuer_dn: String,
    /// Subject Alternative Name DNS entries (`dNSName`).
    pub san_dns: Vec<String>,
    /// Subject Alternative Name URI entries (`uniformResourceIdentifier`, e.g. SPIFFE IDs).
    pub san_uris: Vec<String>,
    /// Subject Alternative Name RFC822 email entries (`rfc822Name`).
    pub san_emails: Vec<String>,
    /// Lowercase hexadecimal certificate serial number.
    pub serial_hex: String,
    /// Lowercase SHA-256 hex digest of the DER-encoded leaf certificate.
    pub sha256_fingerprint: String,
}

type PathParamEntry = (Arc<str>, String);

/// Captured path parameters extracted from a matched `path_template` or named-capture `path_regex`
/// route.
///
/// Uses an `Option<Box<[(Arc<str>, String)]>>` representation so static routes (`Exact`, `Prefix`,
/// `Any`) and `HookMask::EMPTY` routes incur zero heap allocation.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PathParams {
    entries: Option<Box<[PathParamEntry]>>,
}

impl PathParams {
    /// Creates an empty parameter set with zero heap allocation.
    #[inline]
    pub const fn empty() -> Self {
        Self { entries: None }
    }

    /// Creates a parameter set from pre-extracted `(name, value)` pairs.
    #[inline]
    pub fn from_pairs(pairs: Vec<(Arc<str>, String)>) -> Self {
        if pairs.is_empty() {
            Self { entries: None }
        } else {
            Self {
                entries: Some(pairs.into_boxed_slice()),
            }
        }
    }

    /// Looks up a captured path parameter by name.
    #[inline]
    pub fn get(&self, name: &str) -> Option<&str> {
        let entries = self.entries.as_deref()?;
        entries
            .iter()
            .find_map(|(k, v)| (k.as_ref() == name).then_some(v.as_str()))
    }

    /// Returns `true` if no path parameters were captured.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.entries.as_deref().is_none_or(<[_]>::is_empty)
    }

    /// Returns the number of captured path parameters.
    #[inline]
    pub fn len(&self) -> usize {
        self.entries.as_deref().map_or(0, <[_]>::len)
    }

    /// Iterates over captured `(name, value)` pairs in match order.
    #[inline]
    pub fn iter(&self) -> impl Iterator<Item = (&str, &str)> {
        self.entries
            .as_deref()
            .unwrap_or(&[])
            .iter()
            .map(|(k, v)| (k.as_ref(), v.as_str()))
    }
}

/// Per-request context threaded through every lifecycle hook.
///
/// Plugins communicate across hooks (and across plugins) via typed values stored
/// in `extensions`.
#[derive(Debug)]
pub struct RequestCtx {
    pub request_id: u64,
    pub client_addr: SocketAddr,
    /// `true` when the client connection terminated TLS on the gateway listener.
    pub is_tls: bool,
    pub tls_sni: Option<String>,
    /// Verified peer client certificate metadata when presented over an mTLS listener.
    pub client_cert: Option<Arc<ClientCertInfo>>,
    pub route_id: Option<String>,
    /// Captured path parameters from a matched `path_template` or named-capture `path_regex` route.
    pub path_params: PathParams,
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
        let is_tls = tls_sni.is_some();
        Self {
            request_id,
            client_addr,
            is_tls,
            tls_sni,
            client_cert: None,
            route_id: None,
            path_params: PathParams::empty(),
            attempt: 0,
            started_at: Instant::now(),
            extensions: Extensions::new(),
            trace_enabled: false,
            hook_timings: Vec::new(),
            last_upstream_error: None,
            last_upstream_status: None,
        }
    }

    /// Marks whether the client connection terminated TLS on the listener.
    #[inline]
    pub fn with_tls(mut self, is_tls: bool) -> Self {
        self.is_tls = is_tls;
        self
    }

    /// Returns the value of a captured path parameter by name (e.g., `"order_id"`).
    #[inline]
    pub fn path_param(&self, name: &str) -> Option<&str> {
        self.path_params.get(name)
    }

    /// Attaches verified peer client TLS certificate metadata to this request context.
    #[inline]
    pub fn with_client_cert(mut self, client_cert: Option<Arc<ClientCertInfo>>) -> Self {
        self.client_cert = client_cert;
        self
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
