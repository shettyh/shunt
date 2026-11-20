use std::sync::Arc;

use serde::Deserialize;
use shunt_plugin_sdk::{
    BuildContext, Flow, HookMask, HookResult, HttpPlugin, PluginBuildError, PluginConfig,
    PluginFactory, RequestCtx, RequestHead, RequestSummary,
};
use tracing::info;

use crate::request_id::RequestId;

#[derive(Debug, Clone)]
struct RequestMeta {
    method: String,
    path: String,
}

#[derive(Debug, Deserialize, Default)]
#[serde(default)]
struct AccessLogConfig {
    include_timings: bool,
}

pub struct AccessLogFactory;

impl PluginFactory for AccessLogFactory {
    fn name(&self) -> &str {
        "access-log"
    }

    fn build(
        &self,
        config: &PluginConfig,
        _ctx: &BuildContext,
    ) -> Result<Arc<dyn HttpPlugin>, PluginBuildError> {
        let cfg: AccessLogConfig = config.deserialize(self.name())?;
        Ok(Arc::new(AccessLogPlugin {
            include_timings: cfg.include_timings,
        }))
    }
}

pub struct AccessLogPlugin {
    include_timings: bool,
}

impl HttpPlugin for AccessLogPlugin {
    fn name(&self) -> &str {
        "access-log"
    }

    fn hook_mask(&self) -> HookMask {
        HookMask::ON_REQUEST_HEADERS | HookMask::ON_COMPLETE
    }

    fn on_request_headers<'a>(
        &'a self,
        ctx: &'a mut RequestCtx,
        req: &'a mut RequestHead,
    ) -> HookResult<'a, Flow> {
        ctx.insert_ext(RequestMeta {
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
        let meta = ctx.get_ext::<RequestMeta>();
        let method = meta.map(|m| m.method.as_str()).unwrap_or("-");
        let path = meta.map(|m| m.path.as_str()).unwrap_or("-");
        let req_id = ctx
            .get_ext::<RequestId>()
            .map(|r| r.0.as_str())
            .unwrap_or("-");
        let status = summary.status.map(|s| s.as_u16()).unwrap_or(0);
        let route = summary.route_id.as_deref().unwrap_or("-");
        let upstream = summary.upstream.as_deref().unwrap_or("-");
        let ttfb_us = summary.ttfb.map(|d| d.as_micros() as u64).unwrap_or(0);
        let total_us = summary.total_duration.as_micros() as u64;

        if self.include_timings && !summary.hook_timings.is_empty() {
            let timings: Vec<String> = summary
                .hook_timings
                .iter()
                .map(|t| format!("{}:{}={}us", t.plugin, t.hook, t.duration.as_micros()))
                .collect();
            info!(
                request_id = %req_id,
                client = %ctx.client_addr,
                %method,
                %path,
                %route,
                %upstream,
                status,
                attempts = summary.attempts,
                req_bytes = summary.request_bytes,
                res_bytes = summary.response_bytes,
                ttfb_us,
                total_us,
                aborted = summary.aborted_mid_stream,
                error = summary.error.as_deref().unwrap_or(""),
                timings = %timings.join(","),
                "request completed"
            );
        } else {
            info!(
                request_id = %req_id,
                client = %ctx.client_addr,
                %method,
                %path,
                %route,
                %upstream,
                status,
                attempts = summary.attempts,
                req_bytes = summary.request_bytes,
                res_bytes = summary.response_bytes,
                ttfb_us,
                total_us,
                aborted = summary.aborted_mid_stream,
                error = summary.error.as_deref().unwrap_or(""),
                "request completed"
            );
        }

        HookResult::Ready(())
    }
}
