use std::collections::HashMap;
use std::sync::Arc;

use serde::Deserialize;
use shunt_plugin_sdk::{
    BuildContext, Flow, HeaderMap, HeaderName, HeaderValue, HookMask, HookResult, HttpPlugin,
    PluginBuildError, PluginConfig, PluginFactory, RequestCtx, RequestHead, ResponseHead,
    UpstreamRequest,
};

#[derive(Debug, Deserialize, Default)]
#[serde(default)]
struct HeaderRewriteConfig {
    request_set: HashMap<String, String>,
    request_add: HashMap<String, String>,
    request_remove: Vec<String>,
    upstream_set: HashMap<String, String>,
    upstream_remove: Vec<String>,
    response_set: HashMap<String, String>,
    response_add: HashMap<String, String>,
    response_remove: Vec<String>,
}

struct HeaderOps {
    set: Vec<(HeaderName, HeaderValue)>,
    add: Vec<(HeaderName, HeaderValue)>,
    remove: Vec<HeaderName>,
}

impl HeaderOps {
    fn is_empty(&self) -> bool {
        self.set.is_empty() && self.add.is_empty() && self.remove.is_empty()
    }

    fn apply(&self, headers: &mut HeaderMap) {
        for name in &self.remove {
            headers.remove(name);
        }
        for (name, val) in &self.set {
            headers.insert(name.clone(), val.clone());
        }
        for (name, val) in &self.add {
            headers.append(name.clone(), val.clone());
        }
    }
}

fn compile_pairs(
    plugin: &str,
    map: HashMap<String, String>,
) -> Result<Vec<(HeaderName, HeaderValue)>, PluginBuildError> {
    let mut out = Vec::with_capacity(map.len());
    for (k, v) in map {
        let name = HeaderName::from_bytes(k.as_bytes()).map_err(|e| {
            PluginBuildError::BuildFailed {
                plugin: plugin.to_owned(),
                message: format!("invalid header name `{k}`: {e}"),
            }
        })?;
        let val = HeaderValue::from_str(&v).map_err(|e| PluginBuildError::BuildFailed {
            plugin: plugin.to_owned(),
            message: format!("invalid header value for `{k}`: {e}"),
        })?;
        out.push((name, val));
    }
    Ok(out)
}

fn compile_names(plugin: &str, names: Vec<String>) -> Result<Vec<HeaderName>, PluginBuildError> {
    names
        .into_iter()
        .map(|k| {
            HeaderName::from_bytes(k.as_bytes()).map_err(|e| PluginBuildError::BuildFailed {
                plugin: plugin.to_owned(),
                message: format!("invalid header name `{k}`: {e}"),
            })
        })
        .collect()
}

pub struct HeaderRewriteFactory;

impl PluginFactory for HeaderRewriteFactory {
    fn name(&self) -> &str {
        "header-rewrite"
    }

    fn build(
        &self,
        config: &PluginConfig,
        _ctx: &BuildContext,
    ) -> Result<Arc<dyn HttpPlugin>, PluginBuildError> {
        let cfg: HeaderRewriteConfig = config.deserialize(self.name())?;
        let req_ops = HeaderOps {
            set: compile_pairs(self.name(), cfg.request_set)?,
            add: compile_pairs(self.name(), cfg.request_add)?,
            remove: compile_names(self.name(), cfg.request_remove)?,
        };
        let up_ops = HeaderOps {
            set: compile_pairs(self.name(), cfg.upstream_set)?,
            add: Vec::new(),
            remove: compile_names(self.name(), cfg.upstream_remove)?,
        };
        let res_ops = HeaderOps {
            set: compile_pairs(self.name(), cfg.response_set)?,
            add: compile_pairs(self.name(), cfg.response_add)?,
            remove: compile_names(self.name(), cfg.response_remove)?,
        };

        let mut mask = HookMask::EMPTY;
        if !req_ops.is_empty() {
            mask |= HookMask::ON_REQUEST_HEADERS;
        }
        if !up_ops.is_empty() {
            mask |= HookMask::ON_UPSTREAM_REQUEST;
        }
        if !res_ops.is_empty() {
            mask |= HookMask::ON_RESPONSE_HEADERS;
        }

        Ok(Arc::new(HeaderRewritePlugin {
            mask,
            req_ops,
            up_ops,
            res_ops,
        }))
    }
}

pub struct HeaderRewritePlugin {
    mask: HookMask,
    req_ops: HeaderOps,
    up_ops: HeaderOps,
    res_ops: HeaderOps,
}

impl HttpPlugin for HeaderRewritePlugin {
    fn name(&self) -> &str {
        "header-rewrite"
    }

    fn hook_mask(&self) -> HookMask {
        self.mask
    }

    fn on_request_headers<'a>(
        &'a self,
        _ctx: &'a mut RequestCtx,
        req: &'a mut RequestHead,
    ) -> HookResult<'a, Flow> {
        self.req_ops.apply(&mut req.headers);
        HookResult::Ready(Flow::Continue)
    }

    fn on_upstream_request<'a>(
        &'a self,
        _ctx: &'a mut RequestCtx,
        req: &'a mut UpstreamRequest,
    ) -> HookResult<'a, Flow> {
        self.up_ops.apply(&mut req.headers);
        HookResult::Ready(Flow::Continue)
    }

    fn on_response_headers<'a>(
        &'a self,
        _ctx: &'a mut RequestCtx,
        res: &'a mut ResponseHead,
    ) -> HookResult<'a, Flow> {
        self.res_ops.apply(&mut res.headers);
        HookResult::Ready(Flow::Continue)
    }
}
