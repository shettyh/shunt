use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::Deserialize;
use shunt_plugin_sdk::{
    BuildContext, Flow, HeaderName, HeaderValue, HookMask, HookResult, HttpPlugin,
    PluginBuildError, PluginConfig, PluginFactory, RequestCtx, RequestHead, ResponseHead,
};

/// Typed request ID stored in [`RequestCtx::extensions`].
#[derive(Debug, Clone)]
pub struct RequestId(pub String);

#[derive(Debug, Deserialize)]
#[serde(default)]
struct RequestIdConfig {
    header_name: String,
    trust_incoming: bool,
    echo_in_response: bool,
}

impl Default for RequestIdConfig {
    fn default() -> Self {
        Self {
            header_name: "x-request-id".to_owned(),
            trust_incoming: true,
            echo_in_response: true,
        }
    }
}

pub struct RequestIdFactory;

impl PluginFactory for RequestIdFactory {
    fn name(&self) -> &str {
        "request-id"
    }

    fn build(
        &self,
        config: &PluginConfig,
        _ctx: &BuildContext,
    ) -> Result<Arc<dyn HttpPlugin>, PluginBuildError> {
        let cfg: RequestIdConfig = config.deserialize(self.name())?;
        let header_name = HeaderName::from_bytes(cfg.header_name.as_bytes()).map_err(|e| {
            PluginBuildError::BuildFailed {
                plugin: self.name().to_owned(),
                message: format!("invalid header_name `{}`: {e}", cfg.header_name),
            }
        })?;
        let seed = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(1);

        Ok(Arc::new(RequestIdPlugin {
            header_name,
            trust_incoming: cfg.trust_incoming,
            echo_in_response: cfg.echo_in_response,
            prefix: format!("{:08x}", (seed ^ (seed >> 32)) as u32),
            seq: AtomicU64::new(1),
        }))
    }
}

pub struct RequestIdPlugin {
    header_name: HeaderName,
    trust_incoming: bool,
    echo_in_response: bool,
    prefix: String,
    seq: AtomicU64,
}

impl HttpPlugin for RequestIdPlugin {
    fn name(&self) -> &str {
        "request-id"
    }

    fn hook_mask(&self) -> HookMask {
        if self.echo_in_response {
            HookMask::ON_REQUEST_HEADERS | HookMask::ON_RESPONSE_HEADERS
        } else {
            HookMask::ON_REQUEST_HEADERS
        }
    }

    fn on_request_headers<'a>(
        &'a self,
        ctx: &'a mut RequestCtx,
        req: &'a mut RequestHead,
    ) -> HookResult<'a, Flow> {
        let existing = if self.trust_incoming {
            req.headers
                .get(&self.header_name)
                .and_then(|v| v.to_str().ok())
                .map(str::trim)
                .filter(|s| !s.is_empty() && s.len() <= 128)
                .map(str::to_owned)
        } else {
            None
        };

        let id = existing.unwrap_or_else(|| {
            let n = self.seq.fetch_add(1, Ordering::Relaxed);
            format!("req-{}-{n:08x}", self.prefix)
        });

        if let Ok(val) = HeaderValue::from_str(&id) {
            req.headers.insert(self.header_name.clone(), val);
        }
        ctx.insert_ext(RequestId(id));
        HookResult::Ready(Flow::Continue)
    }

    fn on_response_headers<'a>(
        &'a self,
        ctx: &'a mut RequestCtx,
        res: &'a mut ResponseHead,
    ) -> HookResult<'a, Flow> {
        if let Some(RequestId(id)) = ctx.get_ext::<RequestId>()
            && let Ok(val) = HeaderValue::from_str(id)
        {
            res.headers.insert(self.header_name.clone(), val);
        }
        HookResult::Ready(Flow::Continue)
    }
}
