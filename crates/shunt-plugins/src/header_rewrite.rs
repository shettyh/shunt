use std::collections::HashMap;
use std::sync::Arc;

use serde::Deserialize;
use shunt_plugin_sdk::{
    BuildContext, Flow, HeaderMap, HeaderName, HeaderValue, HookMask, HookResult, HttpPlugin,
    PathParams, PluginBuildError, PluginConfig, PluginFactory, RequestCtx, RequestHead,
    ResponseHead, UpstreamRequest,
};

/// Accepts either a single header value string or a list of values (for multi-value `add`).
#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
pub(crate) enum HeaderValueOrList {
    Single(String),
    Multiple(Vec<String>),
}

impl HeaderValueOrList {
    pub(crate) fn into_vec(self) -> Vec<String> {
        match self {
            HeaderValueOrList::Single(v) => vec![v],
            HeaderValueOrList::Multiple(vs) => vs,
        }
    }
}

#[derive(Debug, Deserialize, Default)]
#[serde(default)]
struct HeaderRewriteConfig {
    request_set: HashMap<String, String>,
    request_add: HashMap<String, HeaderValueOrList>,
    request_remove: Vec<String>,
    upstream_set: HashMap<String, String>,
    upstream_add: HashMap<String, HeaderValueOrList>,
    upstream_remove: Vec<String>,
    response_set: HashMap<String, String>,
    response_add: HashMap<String, HeaderValueOrList>,
    response_remove: Vec<String>,
    /// Optional upstream `Host` header rewrite (e.g. Kubernetes Gateway API `URLRewrite.hostname`).
    upstream_host: Option<String>,
    /// Replace full upstream request path (e.g. Gateway API `ReplaceFullPath`).
    path_replace_full: Option<String>,
    /// Prefix to strip when replacing with `path_replace_prefix`.
    path_match_prefix: Option<String>,
    /// Replacement prefix for `path_match_prefix` (e.g. Gateway API `ReplacePrefixMatch`).
    path_replace_prefix: Option<String>,
}

pub(crate) enum HeaderValSpec {
    Static(HeaderValue),
    Template(String),
}

impl HeaderValSpec {
    fn resolve(&self, params: &PathParams) -> Option<HeaderValue> {
        match self {
            HeaderValSpec::Static(v) => Some(v.clone()),
            HeaderValSpec::Template(raw) => {
                let expanded = expand_path_params(raw, params);
                HeaderValue::from_str(&expanded).ok()
            }
        }
    }
}

pub(crate) struct HeaderOps {
    pub(crate) set: Vec<(HeaderName, HeaderValSpec)>,
    pub(crate) add: Vec<(HeaderName, HeaderValSpec)>,
    pub(crate) remove: Vec<HeaderName>,
}

impl HeaderOps {
    pub(crate) fn is_empty(&self) -> bool {
        self.set.is_empty() && self.add.is_empty() && self.remove.is_empty()
    }

    pub(crate) fn apply(&self, headers: &mut HeaderMap, params: &PathParams) {
        for (name, spec) in &self.set {
            if let Some(val) = spec.resolve(params) {
                headers.insert(name.clone(), val);
            }
        }
        for (name, spec) in &self.add {
            if let Some(val) = spec.resolve(params) {
                headers.append(name.clone(), val);
            }
        }
        for name in &self.remove {
            headers.remove(name);
        }
    }
}

fn has_param_placeholder(s: &str) -> bool {
    let Some(open) = s.find('{') else {
        return false;
    };
    s[open + 1..].contains('}')
}

/// Expands `{param_name}` placeholders using captured `params`, leaving unknown placeholders untouched.
fn expand_path_params(template: &str, params: &PathParams) -> String {
    if params.is_empty() || !template.contains('{') {
        return template.to_owned();
    }
    let mut out = String::with_capacity(template.len());
    let mut rest = template;
    while let Some(open) = rest.find('{') {
        out.push_str(&rest[..open]);
        let after_open = &rest[open + 1..];
        if let Some(close) = after_open.find('}') {
            let key = &after_open[..close];
            if let Some(val) = params.get(key) {
                out.push_str(val);
            } else {
                out.push('{');
                out.push_str(key);
                out.push('}');
            }
            rest = &after_open[close + 1..];
        } else {
            out.push('{');
            rest = after_open;
        }
    }
    out.push_str(rest);
    out
}

pub(crate) fn compile_pairs(
    plugin: &str,
    map: HashMap<String, String>,
) -> Result<Vec<(HeaderName, HeaderValSpec)>, PluginBuildError> {
    let mut out = Vec::with_capacity(map.len());
    for (k, v) in map {
        let name =
            HeaderName::from_bytes(k.as_bytes()).map_err(|e| PluginBuildError::BuildFailed {
                plugin: plugin.to_owned(),
                message: format!("invalid header name `{k}`: {e}"),
            })?;
        // Validate header value syntax upfront (even for templated strings, verify no control chars).
        let val = HeaderValue::from_str(&v).map_err(|e| PluginBuildError::BuildFailed {
            plugin: plugin.to_owned(),
            message: format!("invalid header value for `{k}`: {e}"),
        })?;
        let spec = if has_param_placeholder(&v) {
            HeaderValSpec::Template(v)
        } else {
            HeaderValSpec::Static(val)
        };
        out.push((name, spec));
    }
    Ok(out)
}

pub(crate) fn compile_multi_pairs(
    plugin: &str,
    map: HashMap<String, HeaderValueOrList>,
) -> Result<Vec<(HeaderName, HeaderValSpec)>, PluginBuildError> {
    let mut out = Vec::with_capacity(map.len());
    for (k, vals) in map {
        let name =
            HeaderName::from_bytes(k.as_bytes()).map_err(|e| PluginBuildError::BuildFailed {
                plugin: plugin.to_owned(),
                message: format!("invalid header name `{k}`: {e}"),
            })?;
        for v in vals.into_vec() {
            let val = HeaderValue::from_str(&v).map_err(|e| PluginBuildError::BuildFailed {
                plugin: plugin.to_owned(),
                message: format!("invalid header value for `{k}`: {e}"),
            })?;
            let spec = if has_param_placeholder(&v) {
                HeaderValSpec::Template(v)
            } else {
                HeaderValSpec::Static(val)
            };
            out.push((name.clone(), spec));
        }
    }
    Ok(out)
}

pub(crate) fn compile_names(
    plugin: &str,
    names: Vec<String>,
) -> Result<Vec<HeaderName>, PluginBuildError> {
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
            add: compile_multi_pairs(self.name(), cfg.request_add)?,
            remove: compile_names(self.name(), cfg.request_remove)?,
        };
        let up_ops = HeaderOps {
            set: compile_pairs(self.name(), cfg.upstream_set)?,
            add: compile_multi_pairs(self.name(), cfg.upstream_add)?,
            remove: compile_names(self.name(), cfg.upstream_remove)?,
        };
        let res_ops = HeaderOps {
            set: compile_pairs(self.name(), cfg.response_set)?,
            add: compile_multi_pairs(self.name(), cfg.response_add)?,
            remove: compile_names(self.name(), cfg.response_remove)?,
        };

        let upstream_host = match cfg.upstream_host {
            Some(h) => {
                Some(
                    HeaderValue::from_str(&h).map_err(|e| PluginBuildError::BuildFailed {
                        plugin: self.name().to_owned(),
                        message: format!("invalid `upstream_host` `{h}`: {e}"),
                    })?,
                )
            }
            None => None,
        };
        if cfg.path_replace_full.is_some() && cfg.path_replace_prefix.is_some() {
            return Err(PluginBuildError::BuildFailed {
                plugin: self.name().to_owned(),
                message: "cannot specify both `path_replace_full` and `path_replace_prefix`"
                    .to_owned(),
            });
        }

        let has_upstream_rewrite = !up_ops.is_empty()
            || upstream_host.is_some()
            || cfg.path_replace_full.is_some()
            || cfg.path_replace_prefix.is_some();

        let mut mask = HookMask::EMPTY;
        if !req_ops.is_empty() {
            mask |= HookMask::ON_REQUEST_HEADERS;
        }
        if has_upstream_rewrite {
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
            upstream_host,
            path_replace_full: cfg.path_replace_full,
            path_match_prefix: cfg.path_match_prefix,
            path_replace_prefix: cfg.path_replace_prefix,
        }))
    }
}

pub struct HeaderRewritePlugin {
    mask: HookMask,
    req_ops: HeaderOps,
    up_ops: HeaderOps,
    res_ops: HeaderOps,
    upstream_host: Option<HeaderValue>,
    path_replace_full: Option<String>,
    path_match_prefix: Option<String>,
    path_replace_prefix: Option<String>,
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
        ctx: &'a mut RequestCtx,
        req: &'a mut RequestHead,
    ) -> HookResult<'a, Flow> {
        self.req_ops.apply(&mut req.headers, &ctx.path_params);
        HookResult::Ready(Flow::Continue)
    }

    fn on_upstream_request<'a>(
        &'a self,
        ctx: &'a mut RequestCtx,
        req: &'a mut UpstreamRequest,
    ) -> HookResult<'a, Flow> {
        self.up_ops.apply(&mut req.headers, &ctx.path_params);
        if let Some(host) = &self.upstream_host {
            req.headers
                .insert(shunt_plugin_sdk::header::HOST, host.clone());
        }
        if let Some(full) = &self.path_replace_full {
            let expanded_full = if has_param_placeholder(full) && !ctx.path_params.is_empty() {
                expand_path_params(full, &ctx.path_params)
            } else {
                full.clone()
            };
            let next_pq = match req.uri.query() {
                Some(q) => format!("{expanded_full}?{q}"),
                None => expanded_full,
            };
            if let Ok(parsed) = next_pq.parse() {
                req.uri = parsed;
            }
        } else if let Some(rep) = &self.path_replace_prefix {
            let match_pfx = self.path_match_prefix.as_deref().unwrap_or("/");
            let rewritten = crate::redirect::replace_path_prefix(req.uri.path(), match_pfx, rep);
            let next_pq = match req.uri.query() {
                Some(q) => format!("{rewritten}?{q}"),
                None => rewritten,
            };
            if let Ok(parsed) = next_pq.parse() {
                req.uri = parsed;
            }
        }
        HookResult::Ready(Flow::Continue)
    }

    fn on_response_headers<'a>(
        &'a self,
        ctx: &'a mut RequestCtx,
        res: &'a mut ResponseHead,
    ) -> HookResult<'a, Flow> {
        self.res_ops.apply(&mut res.headers, &ctx.path_params);
        HookResult::Ready(Flow::Continue)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;
    use std::net::SocketAddr;
    use std::sync::{Arc, RwLock};

    use shunt_plugin_sdk::{HeaderMap, Method, PathParams, StateStore, StatusCode, Uri, Version};

    use super::*;

    #[test]
    fn header_rewrite_expands_path_params_and_preserves_unknown_placeholders() {
        let factory = HeaderRewriteFactory;
        let build_ctx = BuildContext::new(
            "route:orders:header-rewrite",
            Arc::new(StateStore::new()),
            Arc::new(RwLock::new(HashSet::new())),
        );
        let plugin = factory
            .build(
                &PluginConfig::new(serde_json::json!({
                    "upstream_set": {
                        "x-order-id": "{order_id}",
                        "x-literal": "static-value",
                        "x-unknown": "{\"keep\":\"{missing}\"}"
                    },
                    "response_set": {
                        "x-echo-order": "ord-{order_id}"
                    },
                    "path_replace_full": "/internal/orders/{order_id}/state"
                })),
                &build_ctx,
            )
            .unwrap();

        let addr: SocketAddr = "127.0.0.1:40000".parse().unwrap();
        let mut ctx = RequestCtx::new(1, addr, None);
        ctx.path_params =
            PathParams::from_pairs(vec![(Arc::from("order_id"), "ord_987".to_owned())]);

        let mut up_req = UpstreamRequest {
            method: Method::GET,
            uri: Uri::from_static("/orders/ord_987/status?verbose=true"),
            headers: HeaderMap::new(),
            body: None,
            endpoint_uri: None,
        };
        assert!(matches!(
            plugin.on_upstream_request(&mut ctx, &mut up_req),
            HookResult::Ready(Flow::Continue)
        ));
        assert_eq!(up_req.headers.get("x-order-id").unwrap(), "ord_987");
        assert_eq!(up_req.headers.get("x-literal").unwrap(), "static-value");
        assert_eq!(
            up_req.headers.get("x-unknown").unwrap(),
            "{\"keep\":\"{missing}\"}"
        );
        assert_eq!(
            up_req.uri.to_string(),
            "/internal/orders/ord_987/state?verbose=true"
        );

        let mut res_head = ResponseHead {
            status: StatusCode::OK,
            version: Version::HTTP_11,
            headers: HeaderMap::new(),
        };
        assert!(matches!(
            plugin.on_response_headers(&mut ctx, &mut res_head),
            HookResult::Ready(Flow::Continue)
        ));
        assert_eq!(res_head.headers.get("x-echo-order").unwrap(), "ord-ord_987");
    }
}
