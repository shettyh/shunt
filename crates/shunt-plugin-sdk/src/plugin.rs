use bytes::Bytes;

use crate::context::RequestCtx;
use crate::flow::{Flow, HookResult, StreamFlow};
use crate::http_types::{
    RequestHead, RequestSummary, ResponseHead, RouteDecision, UpstreamRequest, UpstreamSelection,
};
use crate::mask::HookMask;

/// Core HTTP plugin trait implemented identically by first-party and third-party plugins.
///
/// Plugins declare the hooks they participate in via [`HttpPlugin::hook_mask`].
/// Any hook whose bit is not set in the route's combined `HookMask` is never called.
pub trait HttpPlugin: Send + Sync + 'static {
    /// Stable plugin instance name (used for logging, tracing, and diagnostics).
    fn name(&self) -> &str;

    /// Bitmask of lifecycle hooks this plugin implements.
    fn hook_mask(&self) -> HookMask;

    /// Optional request body cap (in bytes) when this plugin opts into
    /// [`HookMask::REQUEST_BODY_BUFFERED`]. If multiple plugins or the route specify
    /// caps, the snapshot compiler uses the most restrictive (minimum) non-zero cap,
    /// or the route default if none is set.
    fn max_request_body_bytes(&self) -> Option<usize> {
        None
    }

    /// Stage 1: Inspect or mutate incoming request headers, or short-circuit with [`Flow::Respond`].
    fn on_request_headers<'a>(
        &'a self,
        _ctx: &'a mut RequestCtx,
        _req: &'a mut RequestHead,
    ) -> HookResult<'a, Flow> {
        HookResult::Ready(Flow::Continue)
    }

    /// Stage 2: Inspect or mutate the buffered request body (only called when
    /// [`HookMask::REQUEST_BODY_BUFFERED`] is set).
    fn on_request_body_buffered<'a>(
        &'a self,
        _ctx: &'a mut RequestCtx,
        _body: &'a mut Bytes,
    ) -> HookResult<'a, Flow> {
        HookResult::Ready(Flow::Continue)
    }

    /// Stage 3: Inspect or override the matched route and target upstream.
    fn on_route<'a>(
        &'a self,
        _ctx: &'a mut RequestCtx,
        _decision: &'a mut RouteDecision,
    ) -> HookResult<'a, Flow> {
        HookResult::Ready(Flow::Continue)
    }

    /// Stage 4a: Choose or override the upstream / endpoint for the current attempt.
    fn on_upstream_select<'a>(
        &'a self,
        _ctx: &'a mut RequestCtx,
        _selection: &'a mut UpstreamSelection,
    ) -> HookResult<'a, Flow> {
        HookResult::Ready(Flow::Continue)
    }

    /// Stage 4b: Mutate the per-attempt upstream request (auth headers, target path,
    /// or translated buffered body).
    fn on_upstream_request<'a>(
        &'a self,
        _ctx: &'a mut RequestCtx,
        _req: &'a mut UpstreamRequest,
    ) -> HookResult<'a, Flow> {
        HookResult::Ready(Flow::Continue)
    }

    /// Stage 4c (unbuffered streaming only): Inspect or rewrite outgoing request body chunks.
    fn on_request_body_chunk<'a>(
        &'a self,
        _ctx: &'a mut RequestCtx,
        _chunk: &'a mut Bytes,
        _end_of_stream: bool,
    ) -> HookResult<'a, StreamFlow> {
        HookResult::Ready(StreamFlow::Continue)
    }

    /// Stage 4d: Inspect or mutate upstream response headers prior to flushing downstream.
    /// May return [`Flow::RetryUpstream`] (if body is empty/buffered and attempts remain),
    /// [`Flow::InspectResponseBody`] to inspect a bounded response body pre-flush, or
    /// [`Flow::Respond`] to override the response.
    fn on_response_headers<'a>(
        &'a self,
        _ctx: &'a mut RequestCtx,
        _res: &'a mut ResponseHead,
    ) -> HookResult<'a, Flow> {
        HookResult::Ready(Flow::Continue)
    }

    /// Stage 4e (conditional pre-flush): Inspect a bounded buffered upstream response body
    /// after a plugin returned [`Flow::InspectResponseBody`] from `on_response_headers`.
    ///
    /// Only invoked when [`HookMask::ON_RESPONSE_BODY_INSPECTED`] is set and an earlier
    /// `on_response_headers` hook requested inspection. May return [`Flow::RetryUpstream`],
    /// [`Flow::Respond`], or [`Flow::Continue`] (which flushes the buffered response verbatim).
    fn on_response_body_inspected<'a>(
        &'a self,
        _ctx: &'a mut RequestCtx,
        _res: &'a mut ResponseHead,
        _body: &'a Bytes,
    ) -> HookResult<'a, Flow> {
        HookResult::Ready(Flow::Continue)
    }

    /// Stage 6: Inspect or rewrite response body chunks while streaming downstream.
    ///
    /// Called once per upstream chunk (`end_of_stream = false`), and once more when the
    /// upstream body reaches EOF (`end_of_stream = true`, with an empty `Bytes`) so plugins
    /// can flush any trailing partial frame (e.g., SSE line buffers).
    fn on_response_body_chunk<'a>(
        &'a self,
        _ctx: &'a mut RequestCtx,
        _chunk: &'a mut Bytes,
        _end_of_stream: bool,
    ) -> HookResult<'a, StreamFlow> {
        HookResult::Ready(StreamFlow::Continue)
    }

    /// Stage 7: Off-hot-path completion hook called after response flush, short-circuit,
    /// or stream abort.
    fn on_complete<'a>(
        &'a self,
        _ctx: &'a RequestCtx,
        _summary: &'a RequestSummary,
    ) -> HookResult<'a, ()> {
        HookResult::Ready(())
    }
}
