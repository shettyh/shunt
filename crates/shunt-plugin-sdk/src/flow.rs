use std::future::Future;
use std::pin::Pin;

use bytes::Bytes;
use http::{HeaderMap, HeaderValue, StatusCode, header};

/// Heap-allocated, `Send` boxed future used only when a plugin hook performs async I/O.
pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// Hybrid sync/async return type for plugin hooks.
///
/// Synchronous in-memory plugins return [`HookResult::Ready`] with zero heap allocation.
/// Plugins performing async I/O return [`HookResult::Pending`].
pub enum HookResult<'a, T = Flow> {
    Ready(T),
    Pending(BoxFuture<'a, T>),
}

impl<'a, T> HookResult<'a, T> {
    /// Returns a synchronously resolved hook result without allocation.
    #[inline]
    pub fn ready(value: T) -> Self {
        Self::Ready(value)
    }

    /// Returns an asynchronously resolved hook result.
    #[inline]
    pub fn pending<F>(fut: F) -> Self
    where
        F: Future<Output = T> + Send + 'a,
    {
        Self::Pending(Box::pin(fut))
    }

    /// Resolves the hook result, awaiting only if `Pending`.
    #[inline]
    pub async fn resolve(self) -> T {
        match self {
            Self::Ready(v) => v,
            Self::Pending(fut) => fut.await,
        }
    }
}

/// Control-flow directive returned by pre-stream request/response hooks.
#[derive(Debug)]
pub enum Flow {
    /// Proceed to the next plugin / pipeline stage.
    Continue,
    /// Short-circuit the pipeline and send this response immediately downstream.
    Respond(BufferedResponse),
    /// Retry the upstream request against the next candidate endpoint/upstream.
    ///
    /// Allowed only pre-flush and when the request body is empty or buffered.
    RetryUpstream,
    /// Buffer up to `max_bytes` of the upstream response body pre-flush and invoke
    /// [`crate::HttpPlugin::on_response_body_inspected`] before deciding whether to
    /// [`Flow::RetryUpstream`], [`Flow::Respond`], or [`Flow::Continue`] (flush verbatim).
    ///
    /// Valid only when returned from `on_response_headers`.
    InspectResponseBody { max_bytes: usize },
}

/// Control-flow directive returned by streaming body chunk hooks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StreamFlow {
    /// Emit the (possibly modified) chunk and continue streaming.
    Continue,
    /// Abort the active stream cleanly with a diagnostic reason.
    Abort(String),
}

/// Complete, in-memory HTTP response returned by plugins via [`Flow::Respond`].
#[derive(Debug, Clone)]
pub struct BufferedResponse {
    pub status: StatusCode,
    pub headers: HeaderMap,
    pub body: Bytes,
}

impl BufferedResponse {
    pub fn new(status: StatusCode, body: impl Into<Bytes>) -> Self {
        Self {
            status,
            headers: HeaderMap::new(),
            body: body.into(),
        }
    }

    pub fn text(status: StatusCode, body: impl Into<String>) -> Self {
        let mut resp = Self::new(status, Bytes::from(body.into()));
        resp.headers.insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("text/plain; charset=utf-8"),
        );
        resp
    }

    pub fn json(status: StatusCode, body: impl Into<Bytes>) -> Self {
        let mut resp = Self::new(status, body);
        resp.headers.insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/json"),
        );
        resp
    }

    pub fn with_header(mut self, name: header::HeaderName, value: HeaderValue) -> Self {
        self.headers.insert(name, value);
        self
    }
}
