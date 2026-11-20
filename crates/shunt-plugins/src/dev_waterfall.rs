use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use shunt_plugin_sdk::{
    Flow, HookMask, HookResult, HttpPlugin, RequestCtx, RequestHead, RequestSummary,
};

#[derive(Debug, Clone)]
struct DevReqMeta {
    method: String,
    path: String,
}

/// Sink callback receiving formatted waterfall lines (defaults to stderr).
pub type WaterfallSink = Arc<dyn Fn(String) + Send + Sync>;

/// Developer-mode waterfall plugin used by `shunt dev`.
///
/// Built strictly on `shunt-plugin-sdk`, rendering per-hook microsecond timings
/// and upstream TTFB for every request.
pub struct DevWaterfallPlugin {
    sink: WaterfallSink,
}

impl DevWaterfallPlugin {
    pub fn stderr() -> Self {
        Self {
            sink: Arc::new(|line| eprintln!("{line}")),
        }
    }

    pub fn with_sink(sink: WaterfallSink) -> Self {
        Self { sink }
    }
}

impl HttpPlugin for DevWaterfallPlugin {
    fn name(&self) -> &str {
        "dev-waterfall"
    }

    fn hook_mask(&self) -> HookMask {
        HookMask::ON_REQUEST_HEADERS | HookMask::ON_COMPLETE
    }

    fn on_request_headers<'a>(
        &'a self,
        ctx: &'a mut RequestCtx,
        req: &'a mut RequestHead,
    ) -> HookResult<'a, Flow> {
        ctx.insert_ext(DevReqMeta {
            method: req.method.to_string(),
            path: req.uri.path().to_owned(),
        });
        HookResult::Ready(Flow::Continue)
    }

    fn on_complete<'a>(
        &'a self,
        ctx: &'a RequestCtx,
        summary: &'a RequestSummary,
    ) -> HookResult<'a, ()> {
        let line = format_waterfall(ctx, summary);
        (self.sink)(line);
        HookResult::Ready(())
    }
}

/// Formats a single request's per-hook timing waterfall string.
pub fn format_waterfall(ctx: &RequestCtx, summary: &RequestSummary) -> String {
    let meta = ctx.get_ext::<DevReqMeta>();
    let method = meta.map(|m| m.method.as_str()).unwrap_or("REQ");
    let path = meta.map(|m| m.path.as_str()).unwrap_or("/");
    let status = summary
        .status
        .map(|s| s.as_u16().to_string())
        .unwrap_or_else(|| "ERR".to_owned());

    let mut segments: Vec<String> = Vec::new();
    segments.push(format!("{status} {method} {path}"));

    // Aggregate per-plugin chunk hook calls while keeping non-chunk hooks in execution order.
    let mut stream_chunks: BTreeMap<String, (usize, Duration)> = BTreeMap::new();
    for timing in &summary.hook_timings {
        if timing.plugin == "dev-waterfall" {
            continue;
        }
        if timing.hook == "on_response_body_chunk" || timing.hook == "on_request_body_chunk" {
            let entry = stream_chunks
                .entry(timing.plugin.clone())
                .or_insert((0, Duration::ZERO));
            entry.0 += 1;
            entry.1 += timing.duration;
        } else {
            segments.push(format!(
                "{}: {}",
                timing.plugin,
                format_duration(timing.duration)
            ));
        }
    }

    if let Some(ttfb) = summary.ttfb {
        segments.push(format!("upstream TTFB: {}", format_duration(ttfb)));
    }

    for (plugin, (chunks, total)) in stream_chunks {
        let avg = total / (chunks.max(1) as u32);
        segments.push(format!(
            "{plugin}: {}/chunk ({chunks} chunks)",
            format_duration(avg)
        ));
    }

    segments.push(format!("total: {}", format_duration(summary.total_duration)));

    if let Some(err) = &summary.error {
        segments.push(format!("ERR: {err}"));
    }

    segments.join(" │ ")
}

fn format_duration(d: Duration) -> String {
    let us = d.as_micros();
    if us < 1_000 {
        format!("{us}µs")
    } else if us < 1_000_000 {
        format!("{:.1}ms", d.as_secs_f64() * 1_000.0)
    } else {
        format!("{:.2}s", d.as_secs_f64())
    }
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;
    use std::time::Duration;

    use shunt_plugin_sdk::{HookTiming, RequestCtx, RequestSummary, StatusCode};

    use super::*;

    #[test]
    fn formats_dev_waterfall_with_hooks_ttfb_and_chunks() {
        let addr: SocketAddr = "127.0.0.1:5000".parse().unwrap();
        let mut ctx = RequestCtx::new(1, addr, None);
        ctx.insert_ext(DevReqMeta {
            method: "POST".into(),
            path: "/v1/chat/completions".into(),
        });
        let summary = RequestSummary {
            request_id: 1,
            route_id: Some("ai".into()),
            upstream: Some("openai".into()),
            endpoint: Some("http://127.0.0.1:8080".into()),
            status: Some(StatusCode::OK),
            attempts: 1,
            request_bytes: 120,
            response_bytes: 512,
            ttfb: Some(Duration::from_millis(312)),
            total_duration: Duration::from_millis(340),
            error: None,
            aborted_mid_stream: false,
            hook_timings: vec![
                HookTiming {
                    plugin: "bearer-auth".into(),
                    hook: "on_request_headers",
                    duration: Duration::from_micros(4),
                },
                HookTiming {
                    plugin: "sse-translate".into(),
                    hook: "on_response_body_chunk",
                    duration: Duration::from_micros(2),
                },
                HookTiming {
                    plugin: "sse-translate".into(),
                    hook: "on_response_body_chunk",
                    duration: Duration::from_micros(4),
                },
            ],
        };

        let line = format_waterfall(&ctx, &summary);
        assert!(line.contains("200 POST /v1/chat/completions"), "got: {line}");
        assert!(line.contains("bearer-auth: 4µs"), "got: {line}");
        assert!(line.contains("upstream TTFB: 312.0ms"), "got: {line}");
        assert!(line.contains("sse-translate: 3µs/chunk (2 chunks)"), "got: {line}");
    }
}
