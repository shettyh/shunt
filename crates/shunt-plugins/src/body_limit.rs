use std::sync::Arc;

use serde::Deserialize;
use shunt_plugin_sdk::{
    BufferedResponse, BuildContext, Flow, HookMask, HookResult, HttpPlugin, PluginBuildError,
    PluginConfig, PluginFactory, RequestCtx, RequestHead, StatusCode, header,
};

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct BodyLimitConfig {
    /// Maximum permitted request body size in bytes (enforced on both `Content-Length`
    /// and unbuffered streaming chunked/HTTP2 bodies via `shunt-core`).
    max_bytes: usize,
    /// Optional HTTP status code returned on rejection (default: `413`).
    #[serde(default = "default_status_code")]
    status_code: u16,
}

fn default_status_code() -> u16 {
    413
}

pub struct BodyLimitFactory;

impl PluginFactory for BodyLimitFactory {
    fn name(&self) -> &str {
        "body-limit"
    }

    fn build(
        &self,
        config: &PluginConfig,
        _ctx: &BuildContext,
    ) -> Result<Arc<dyn HttpPlugin>, PluginBuildError> {
        let cfg: BodyLimitConfig = config.deserialize(self.name())?;
        let status =
            StatusCode::from_u16(cfg.status_code).map_err(|e| PluginBuildError::BuildFailed {
                plugin: self.name().to_owned(),
                message: format!("invalid `status_code` `{}`: {e}", cfg.status_code),
            })?;
        if !status.is_client_error() {
            return Err(PluginBuildError::BuildFailed {
                plugin: self.name().to_owned(),
                message: format!("`status_code` must be 4xx, got {}", cfg.status_code),
            });
        }
        Ok(Arc::new(BodyLimitPlugin {
            max_bytes: cfg.max_bytes,
            status,
        }))
    }
}

/// Request body size limiter that rejects oversized `Content-Length` requests synchronously
/// in `on_request_headers` AND informs `shunt-core` via [`HttpPlugin::max_request_body_bytes`]
/// to enforce the exact same cap on unbuffered chunked/HTTP2 streaming bodies without buffering.
pub struct BodyLimitPlugin {
    max_bytes: usize,
    status: StatusCode,
}

impl HttpPlugin for BodyLimitPlugin {
    fn name(&self) -> &str {
        "body-limit"
    }

    fn hook_mask(&self) -> HookMask {
        HookMask::ON_REQUEST_HEADERS
    }

    fn max_request_body_bytes(&self) -> Option<usize> {
        Some(self.max_bytes)
    }

    fn on_request_headers<'a>(
        &'a self,
        ctx: &'a mut RequestCtx,
        req: &'a mut RequestHead,
    ) -> HookResult<'a, Flow> {
        if let Some(cl) = req
            .headers
            .get(header::CONTENT_LENGTH)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.trim().parse::<usize>().ok())
            && cl > self.max_bytes
        {
            ctx.annotate_int("http.request.body_limit_bytes", self.max_bytes as i64);
            return HookResult::Ready(Flow::Respond(BufferedResponse::json(
                self.status,
                format!(
                    r#"{{"error":"payload_too_large","max_bytes":{}}}"#,
                    self.max_bytes
                ),
            )));
        }
        HookResult::Ready(Flow::Continue)
    }
}
