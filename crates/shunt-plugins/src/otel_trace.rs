use std::sync::Arc;

use serde::Deserialize;
use shunt_plugin_sdk::{
    BuildContext, Flow, HeaderName, HeaderValue, HookMask, HookResult, HttpPlugin,
    PluginBuildError, PluginConfig, PluginFactory, RequestCtx, RequestHead, RequestSummary,
    ResponseHead, SpanHandle, SpanKind, SpanStatusCode, TelemetrySink, TraceContext,
    UpstreamRequest, current_unix_nanos, header,
};

fn default_sample_rate() -> f64 {
    1.0
}

fn default_true() -> bool {
    true
}

#[derive(Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct OtelTraceConfig {
    /// Sampling ratio in `[0.0, 1.0]` applied to root traces (or all traces when
    /// `respect_parent_sampling = false`). Default: `1.0`.
    #[serde(default = "default_sample_rate")]
    sample_rate: f64,
    /// When `true` (default), follow the sampled flag from a valid incoming W3C `traceparent`.
    #[serde(default = "default_true")]
    respect_parent_sampling: bool,
    /// Inject W3C `traceparent` (and `tracestate` when present) onto upstream requests (default: `true`).
    #[serde(default = "default_true")]
    propagate_headers: bool,
    /// Emit `x-trace-id` header on client responses (default: `false`; enables `ON_RESPONSE_HEADERS`
    /// only when `true`).
    #[serde(default)]
    emit_response_header: bool,
}

impl Default for OtelTraceConfig {
    fn default() -> Self {
        Self {
            sample_rate: default_sample_rate(),
            respect_parent_sampling: true,
            propagate_headers: true,
            emit_response_header: false,
        }
    }
}

/// Factory for the `otel-trace` plugin.
pub struct OtelTraceFactory;

impl PluginFactory for OtelTraceFactory {
    fn name(&self) -> &str {
        "otel-trace"
    }

    fn build(
        &self,
        config: &PluginConfig,
        ctx: &BuildContext,
    ) -> Result<Arc<dyn HttpPlugin>, PluginBuildError> {
        let cfg: OtelTraceConfig = config.deserialize(self.name())?;
        if !cfg.sample_rate.is_finite() || !(0.0..=1.0).contains(&cfg.sample_rate) {
            return Err(PluginBuildError::BuildFailed {
                plugin: self.name().to_owned(),
                message: "`sample_rate` must be a finite number in [0.0, 1.0]".to_owned(),
            });
        }
        Ok(Arc::new(OtelTracePlugin {
            sample_rate: cfg.sample_rate,
            respect_parent_sampling: cfg.respect_parent_sampling,
            propagate_headers: cfg.propagate_headers,
            emit_response_header: cfg.emit_response_header,
            sink: ctx.telemetry_sink(),
        }))
    }
}

/// W3C Trace Context propagation and OpenTelemetry HTTP span emitter.
///
/// - Parses incoming `traceparent` / `tracestate` headers and establishes a [`TraceContext`].
/// - Propagates `traceparent` / `tracestate` to upstream services in `on_upstream_request`.
/// - When sampled and a gateway `[telemetry]` [`TelemetrySink`] is configured, attaches a
///   [`SpanHandle`] to `ctx.extensions` so downstream plugins (e.g., `shunt-ai`) can enrich
///   the span with GenAI semantic attributes without coupling to OTLP or `shunt-engine`.
pub struct OtelTracePlugin {
    sample_rate: f64,
    respect_parent_sampling: bool,
    propagate_headers: bool,
    emit_response_header: bool,
    sink: Option<Arc<dyn TelemetrySink>>,
}

impl OtelTracePlugin {
    pub fn new(
        sample_rate: f64,
        respect_parent_sampling: bool,
        propagate_headers: bool,
        emit_response_header: bool,
        sink: Option<Arc<dyn TelemetrySink>>,
    ) -> Self {
        Self {
            sample_rate: sample_rate.clamp(0.0, 1.0),
            respect_parent_sampling,
            propagate_headers,
            emit_response_header,
            sink,
        }
    }
}

impl HttpPlugin for OtelTracePlugin {
    fn name(&self) -> &str {
        "otel-trace"
    }

    fn hook_mask(&self) -> HookMask {
        let mut mask = HookMask::ON_REQUEST_HEADERS;
        if self.propagate_headers {
            mask |= HookMask::ON_UPSTREAM_REQUEST;
        }
        if self.emit_response_header {
            mask |= HookMask::ON_RESPONSE_HEADERS;
        }
        if self.sink.is_some() {
            mask |= HookMask::ON_COMPLETE;
        }
        mask
    }

    fn on_request_headers<'a>(
        &'a self,
        ctx: &'a mut RequestCtx,
        req: &'a mut RequestHead,
    ) -> HookResult<'a, Flow> {
        let parent = req
            .headers
            .get("traceparent")
            .and_then(|v| v.to_str().ok())
            .and_then(TraceContext::parse_traceparent);

        let tracestate = req
            .headers
            .get("tracestate")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.trim().to_owned())
            .filter(|s| !s.is_empty());

        let trace_ctx = match parent {
            Some(p) => {
                let sampled = if self.respect_parent_sampling {
                    p.is_sampled()
                } else {
                    TraceContext::should_sample_trace_id(p.trace_id, self.sample_rate)
                };
                TraceContext::child_from(p, sampled, tracestate)
            }
            None => {
                let mut root = TraceContext::new_root(false);
                let sampled = TraceContext::should_sample_trace_id(root.trace_id, self.sample_rate);
                if sampled {
                    root.trace_flags = 0x01;
                }
                root
            }
        };

        if let Some(sink) = &self.sink
            && trace_ctx.is_sampled()
        {
            let method = req.method.as_str().to_owned();
            let path = req.uri.path().to_owned();
            let span_name = format!("{method} {path}");
            let span = SpanHandle::start(
                &trace_ctx,
                span_name,
                SpanKind::Server,
                current_unix_nanos(),
                Arc::clone(sink),
            );
            span.set_str("http.request.method", method);
            span.set_str("url.path", path);
            if let Some(host) = req
                .headers
                .get(header::HOST)
                .and_then(|v| v.to_str().ok())
                .map(str::trim)
                .filter(|h| !h.is_empty())
            {
                span.set_str("server.address", host);
            } else if let Some(sni) = &ctx.tls_sni {
                span.set_str("server.address", sni.as_str());
            }
            span.set_str("network.peer.address", ctx.client_addr.ip().to_string());
            ctx.insert_ext(span);
        }

        ctx.insert_ext(trace_ctx);
        HookResult::Ready(Flow::Continue)
    }

    fn on_upstream_request<'a>(
        &'a self,
        ctx: &'a mut RequestCtx,
        req: &'a mut UpstreamRequest,
    ) -> HookResult<'a, Flow> {
        if !self.propagate_headers {
            return HookResult::Ready(Flow::Continue);
        }
        if let Some(tc) = ctx.get_ext::<TraceContext>() {
            if let Ok(val) = HeaderValue::from_str(&tc.format_traceparent()) {
                req.headers
                    .insert(HeaderName::from_static("traceparent"), val);
            }
            if let Some(ts) = &tc.tracestate
                && let Ok(val) = HeaderValue::from_str(ts)
            {
                req.headers
                    .insert(HeaderName::from_static("tracestate"), val);
            }
        }
        HookResult::Ready(Flow::Continue)
    }

    fn on_response_headers<'a>(
        &'a self,
        ctx: &'a mut RequestCtx,
        res: &'a mut ResponseHead,
    ) -> HookResult<'a, Flow> {
        if self.emit_response_header
            && let Some(tc) = ctx.get_ext::<TraceContext>()
            && let Ok(val) = HeaderValue::from_str(&tc.trace_id_hex())
        {
            res.headers
                .insert(HeaderName::from_static("x-trace-id"), val);
        }
        HookResult::Ready(Flow::Continue)
    }

    fn on_complete<'a>(
        &'a self,
        ctx: &'a RequestCtx,
        summary: &'a RequestSummary,
    ) -> HookResult<'a, ()> {
        let Some(span) = ctx.get_ext::<SpanHandle>() else {
            return HookResult::Ready(());
        };

        span.set_int("shunt.request_id", summary.request_id as i64);
        if let Some(route) = &summary.route_id {
            span.set_str("http.route", route.as_str());
        }
        if let Some(up) = &summary.upstream {
            span.set_str("shunt.upstream", up.as_str());
        }
        if let Some(ep) = &summary.endpoint {
            span.set_str("shunt.upstream.endpoint", ep.as_str());
        }
        if let Some(status) = summary.status {
            span.set_int("http.response.status_code", status.as_u16() as i64);
        }
        span.set_int("shunt.attempts", summary.attempts as i64);
        span.set_int("shunt.request.bytes", summary.request_bytes as i64);
        span.set_int("shunt.response.bytes", summary.response_bytes as i64);
        if let Some(ttfb) = summary.ttfb {
            span.set_float("shunt.ttfb_ms", ttfb.as_secs_f64() * 1000.0);
        }
        if summary.aborted_mid_stream {
            span.set_bool("shunt.stream_aborted", true);
        }

        let (status_code, status_msg) = if summary.aborted_mid_stream {
            (
                SpanStatusCode::Error,
                summary
                    .error
                    .clone()
                    .or_else(|| Some("response stream aborted".to_owned())),
            )
        } else if let Some(err) = &summary.error {
            (SpanStatusCode::Error, Some(err.clone()))
        } else if let Some(s) = summary.status
            && s.is_server_error()
        {
            (SpanStatusCode::Error, Some(format!("HTTP {}", s.as_u16())))
        } else {
            (SpanStatusCode::Ok, None)
        };

        span.finalize(current_unix_nanos(), status_code, status_msg);
        HookResult::Ready(())
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;
    use std::net::SocketAddr;
    use std::sync::RwLock;
    use std::time::Duration;

    use shunt_plugin_sdk::{
        HeaderMap, InMemoryTelemetrySink, Method, SpanValue, StateStore, StatusCode, Uri, Version,
    };

    use super::*;

    fn test_build_ctx(sink: Option<Arc<dyn TelemetrySink>>) -> BuildContext {
        BuildContext::new(
            "global:otel-trace",
            Arc::new(StateStore::new()),
            Arc::new(RwLock::new(HashSet::new())),
        )
        .with_telemetry_sink(sink)
    }

    #[test]
    fn propagates_w3c_traceparent_and_emits_http_span() {
        let sink = Arc::new(InMemoryTelemetrySink::new(16));
        let factory = OtelTraceFactory;
        let plugin = factory
            .build(
                &PluginConfig::new(serde_json::json!({
                    "sample_rate": 1.0,
                    "emit_response_header": true
                })),
                &test_build_ctx(Some(Arc::clone(&sink) as Arc<dyn TelemetrySink>)),
            )
            .unwrap();

        assert!(plugin.hook_mask().contains(HookMask::ON_RESPONSE_HEADERS));
        assert!(plugin.hook_mask().contains(HookMask::ON_COMPLETE));

        let addr: SocketAddr = "127.0.0.1:50000".parse().unwrap();
        let mut ctx = RequestCtx::new(7, addr, None);
        let mut headers = HeaderMap::new();
        headers.insert(
            HeaderName::from_static("traceparent"),
            HeaderValue::from_static("00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"),
        );
        headers.insert(
            HeaderName::from_static("tracestate"),
            HeaderValue::from_static("vendor=abc"),
        );
        let mut req_head = RequestHead {
            method: Method::POST,
            uri: Uri::from_static("/v1/chat/completions"),
            version: Version::HTTP_11,
            headers,
        };

        assert!(matches!(
            plugin.on_request_headers(&mut ctx, &mut req_head),
            HookResult::Ready(Flow::Continue)
        ));

        let mut up_req = UpstreamRequest {
            method: Method::POST,
            uri: Uri::from_static("/v1/chat/completions"),
            headers: HeaderMap::new(),
            body: None,
            endpoint_uri: None,
        };
        assert!(matches!(
            plugin.on_upstream_request(&mut ctx, &mut up_req),
            HookResult::Ready(Flow::Continue)
        ));
        let forwarded = up_req.headers.get("traceparent").unwrap().to_str().unwrap();
        assert!(forwarded.starts_with("00-4bf92f3577b34da6a3ce929d0e0e4736-"));
        assert!(!forwarded.contains("00f067aa0ba902b7"));
        assert_eq!(up_req.headers.get("tracestate").unwrap(), "vendor=abc");

        let mut res_head = ResponseHead {
            status: StatusCode::OK,
            version: Version::HTTP_11,
            headers: HeaderMap::new(),
        };
        assert!(matches!(
            plugin.on_response_headers(&mut ctx, &mut res_head),
            HookResult::Ready(Flow::Continue)
        ));
        assert_eq!(
            res_head.headers.get("x-trace-id").unwrap(),
            "4bf92f3577b34da6a3ce929d0e0e4736"
        );

        let summary = RequestSummary {
            request_id: 7,
            route_id: Some("ai_route".into()),
            upstream: Some("openai".into()),
            endpoint: Some("http://127.0.0.1:8080".into()),
            status: Some(StatusCode::OK),
            attempts: 1,
            request_bytes: 120,
            response_bytes: 256,
            ttfb: Some(Duration::from_millis(12)),
            total_duration: Duration::from_millis(25),
            error: None,
            aborted_mid_stream: false,
            hook_timings: Vec::new(),
        };
        assert!(matches!(
            plugin.on_complete(&ctx, &summary),
            HookResult::Ready(())
        ));
        drop(ctx);

        let spans = sink.spans();
        assert_eq!(spans.len(), 1);
        assert_eq!(spans[0].trace_id_hex(), "4bf92f3577b34da6a3ce929d0e0e4736");
        assert_eq!(
            spans[0].parent_span_id_hex().as_deref(),
            Some("00f067aa0ba902b7")
        );
        assert_eq!(
            spans[0].attributes.get("http.route"),
            Some(&SpanValue::String("ai_route".to_owned()))
        );
        assert_eq!(
            spans[0].attributes.get("http.response.status_code"),
            Some(&SpanValue::Int(200))
        );
    }

    #[test]
    fn unsampled_parent_suppresses_span_allocation_and_export() {
        let sink = Arc::new(InMemoryTelemetrySink::new(16));
        let plugin = OtelTracePlugin::new(
            1.0,
            true,
            true,
            false,
            Some(Arc::clone(&sink) as Arc<dyn TelemetrySink>),
        );
        assert!(!plugin.hook_mask().contains(HookMask::ON_RESPONSE_HEADERS));

        let addr: SocketAddr = "127.0.0.1:50001".parse().unwrap();
        let mut ctx = RequestCtx::new(8, addr, None);
        let mut headers = HeaderMap::new();
        headers.insert(
            HeaderName::from_static("traceparent"),
            HeaderValue::from_static("00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-00"),
        );
        let mut req_head = RequestHead {
            method: Method::GET,
            uri: Uri::from_static("/ping"),
            version: Version::HTTP_11,
            headers,
        };
        plugin.on_request_headers(&mut ctx, &mut req_head);
        assert!(ctx.get_ext::<SpanHandle>().is_none());
        drop(ctx);
        assert!(sink.spans().is_empty());
    }
}
