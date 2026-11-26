use std::sync::Arc;

use serde::Deserialize;
use shunt_plugin_sdk::{
    BufferedResponse, BuildContext, Flow, HeaderValue, HookMask, HookResult, HttpPlugin,
    PluginBuildError, PluginConfig, PluginFactory, RequestCtx, RequestHead, StatusCode, header,
};

#[derive(Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct RedirectConfig {
    /// Redirect HTTP status code (`301`, `302`, `303`, `307`, `308`; default: `302`).
    status_code: u16,
    /// Target scheme (`"http"` or `"https"`). Defaults to `"https"` when omitted and host is set,
    /// or preserves relative location when both scheme and hostname are omitted.
    scheme: Option<String>,
    /// Target hostname override. When omitted, reuses incoming `Host` header.
    hostname: Option<String>,
    /// Target port override.
    port: Option<u16>,
    /// Replace the entire request path with this literal path.
    path_replace_full: Option<String>,
    /// Matched prefix to replace when `path_replace_prefix` is set.
    path_match_prefix: Option<String>,
    /// Replacement prefix paired with `path_match_prefix`.
    path_replace_prefix: Option<String>,
    /// Preserve incoming query string (default: `true`).
    preserve_query: bool,
}

impl Default for RedirectConfig {
    fn default() -> Self {
        Self {
            status_code: 302,
            scheme: None,
            hostname: None,
            port: None,
            path_replace_full: None,
            path_match_prefix: None,
            path_replace_prefix: None,
            preserve_query: true,
        }
    }
}

pub struct RedirectFactory;

impl PluginFactory for RedirectFactory {
    fn name(&self) -> &str {
        "redirect"
    }

    fn build(
        &self,
        config: &PluginConfig,
        _ctx: &BuildContext,
    ) -> Result<Arc<dyn HttpPlugin>, PluginBuildError> {
        let cfg: RedirectConfig = config.deserialize(self.name())?;
        if !matches!(cfg.status_code, 301 | 302 | 303 | 307 | 308) {
            return Err(PluginBuildError::BuildFailed {
                plugin: self.name().to_owned(),
                message: format!(
                    "redirect `status_code` must be 301, 302, 303, 307, or 308 (got {})",
                    cfg.status_code
                ),
            });
        }
        if let Some(scheme) = &cfg.scheme
            && scheme != "http"
            && scheme != "https"
        {
            return Err(PluginBuildError::BuildFailed {
                plugin: self.name().to_owned(),
                message: format!("redirect `scheme` must be `http` or `https` (got `{scheme}`)"),
            });
        }
        if cfg.path_replace_full.is_some() && cfg.path_replace_prefix.is_some() {
            return Err(PluginBuildError::BuildFailed {
                plugin: self.name().to_owned(),
                message: "cannot specify both `path_replace_full` and `path_replace_prefix`"
                    .to_owned(),
            });
        }
        let status = StatusCode::from_u16(cfg.status_code).expect("validated redirect status");
        Ok(Arc::new(RedirectPlugin {
            status,
            scheme: cfg.scheme,
            hostname: cfg.hostname,
            port: cfg.port,
            path_replace_full: cfg.path_replace_full,
            path_match_prefix: cfg.path_match_prefix,
            path_replace_prefix: cfg.path_replace_prefix,
            preserve_query: cfg.preserve_query,
        }))
    }
}

/// Short-circuiting HTTP redirect plugin (also used as the compilation target for
/// Kubernetes Gateway API `RequestRedirect` filters).
pub struct RedirectPlugin {
    status: StatusCode,
    scheme: Option<String>,
    hostname: Option<String>,
    port: Option<u16>,
    path_replace_full: Option<String>,
    path_match_prefix: Option<String>,
    path_replace_prefix: Option<String>,
    preserve_query: bool,
}

impl RedirectPlugin {
    fn compute_location(&self, ctx: &RequestCtx, req: &RequestHead) -> String {
        let orig_path = req.uri.path();
        let new_path = if let Some(full) = &self.path_replace_full {
            full.clone()
        } else if let Some(rep) = &self.path_replace_prefix {
            let match_pfx = self.path_match_prefix.as_deref().unwrap_or("/");
            replace_path_prefix(orig_path, match_pfx, rep)
        } else {
            orig_path.to_owned()
        };

        let path_and_query = match (self.preserve_query, req.uri.query()) {
            (true, Some(q)) => format!("{new_path}?{q}"),
            _ => new_path,
        };

        let (incoming_host, incoming_port) = req
            .headers
            .get(header::HOST)
            .and_then(|v| v.to_str().ok())
            .map(split_host_port)
            .unwrap_or_else(|| (req.uri.host().map(str::to_owned), req.uri.port_u16()));

        if self.scheme.is_none() && self.hostname.is_none() && self.port.is_none() {
            return path_and_query;
        }

        let incoming_scheme =
            req.uri
                .scheme_str()
                .unwrap_or(if ctx.is_tls { "https" } else { "http" });
        let scheme = self.scheme.as_deref().unwrap_or(incoming_scheme);
        let host = self
            .hostname
            .as_deref()
            .or(incoming_host.as_deref())
            .unwrap_or("localhost");

        // Per Kubernetes Gateway API v1 `HTTPRequestRedirectFilter` semantics:
        // - If `port` is explicitly set, use it (omitting default port 80/443 for the target scheme).
        // - Else if `scheme` is explicitly set, derive port from the target scheme (omit port).
        // - Else preserve the incoming request's non-default port.
        let effective_port = if let Some(p) = self.port {
            Some(p)
        } else if self.scheme.is_some() {
            None
        } else {
            incoming_port
        };

        let include_port = effective_port
            .filter(|&p| !((scheme == "http" && p == 80) || (scheme == "https" && p == 443)));

        match include_port {
            Some(p) => format!("{scheme}://{host}:{p}{path_and_query}"),
            None => format!("{scheme}://{host}{path_and_query}"),
        }
    }
}

fn split_host_port(host_hdr: &str) -> (Option<String>, Option<u16>) {
    let trimmed = host_hdr.trim();
    if trimmed.is_empty() {
        return (None, None);
    }
    if let Some(rest) = trimmed.strip_prefix('[') {
        if let Some((ip, after)) = rest.split_once(']') {
            let port = after.strip_prefix(':').and_then(|p| p.parse::<u16>().ok());
            return (Some(format!("[{ip}]")), port);
        }
        return (Some(trimmed.to_owned()), None);
    }
    if let Some((h, p)) = trimmed.split_once(':') {
        (Some(h.to_owned()), p.parse::<u16>().ok())
    } else {
        (Some(trimmed.to_owned()), None)
    }
}

pub(crate) fn replace_path_prefix(path: &str, match_prefix: &str, replacement: &str) -> String {
    let rep_clean = replacement.trim_end_matches('/');
    if match_prefix == "/" || match_prefix.is_empty() {
        if path == "/" {
            return if replacement.is_empty() {
                "/".to_owned()
            } else {
                replacement.to_owned()
            };
        }
        if rep_clean.is_empty() {
            return path.to_owned();
        }
        return if path.starts_with('/') {
            format!("{rep_clean}{path}")
        } else {
            format!("{rep_clean}/{path}")
        };
    }

    let trimmed_match = match_prefix.trim_end_matches('/');
    let Some(suffix) = path.strip_prefix(trimmed_match) else {
        return path.to_owned();
    };
    if suffix.is_empty() {
        if replacement.is_empty() {
            "/".to_owned()
        } else {
            replacement.to_owned()
        }
    } else if suffix == "/" {
        if rep_clean.is_empty() {
            "/".to_owned()
        } else {
            format!("{rep_clean}/")
        }
    } else if suffix.starts_with('/') {
        format!("{rep_clean}{suffix}")
    } else {
        format!("{rep_clean}/{suffix}")
    }
}

impl HttpPlugin for RedirectPlugin {
    fn name(&self) -> &str {
        "redirect"
    }

    fn hook_mask(&self) -> HookMask {
        HookMask::ON_REQUEST_HEADERS
    }

    fn on_request_headers<'a>(
        &'a self,
        ctx: &'a mut RequestCtx,
        req: &'a mut RequestHead,
    ) -> HookResult<'a, Flow> {
        let location = self.compute_location(ctx, req);
        let mut resp = BufferedResponse::new(self.status, "");
        if let Ok(val) = HeaderValue::from_str(&location) {
            resp.headers.insert(header::LOCATION, val);
        }
        HookResult::Ready(Flow::Respond(resp))
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;
    use std::net::SocketAddr;
    use std::sync::{Arc, RwLock};

    use shunt_plugin_sdk::{HeaderMap, Method, StateStore, Uri, Version};

    use super::*;

    fn build_redirect(cfg: serde_json::Value) -> Arc<dyn HttpPlugin> {
        let build_ctx = BuildContext::new(
            "route:test:redirect",
            Arc::new(StateStore::new()),
            Arc::new(RwLock::new(HashSet::new())),
        );
        RedirectFactory
            .build(&PluginConfig::new(cfg), &build_ctx)
            .unwrap()
    }

    fn run_redirect(
        plugin: &Arc<dyn HttpPlugin>,
        is_tls: bool,
        host: &str,
        uri: &str,
    ) -> (StatusCode, String) {
        let addr: SocketAddr = "127.0.0.1:40000".parse().unwrap();
        let mut ctx = RequestCtx::new(1, addr, None).with_tls(is_tls);
        let mut headers = HeaderMap::new();
        if !host.is_empty() {
            headers.insert(header::HOST, HeaderValue::from_str(host).unwrap());
        }
        let mut req = RequestHead {
            method: Method::GET,
            uri: uri.parse::<Uri>().unwrap(),
            version: Version::HTTP_11,
            headers,
        };
        match plugin.on_request_headers(&mut ctx, &mut req) {
            HookResult::Ready(Flow::Respond(resp)) => (
                resp.status,
                resp.headers
                    .get(header::LOCATION)
                    .unwrap()
                    .to_str()
                    .unwrap()
                    .to_owned(),
            ),
            _ => panic!("expected Flow::Respond"),
        }
    }

    #[test]
    fn redirect_preserves_http_scheme_and_non_default_port() {
        let plugin = build_redirect(serde_json::json!({
            "hostname": "new.example.com",
            "status_code": 302
        }));
        let (st, loc) = run_redirect(&plugin, false, "old.example.com:8080", "/hello?x=1");
        assert_eq!(st, StatusCode::FOUND);
        assert_eq!(loc, "http://new.example.com:8080/hello?x=1");

        let (_, loc_tls) = run_redirect(&plugin, true, "old.example.com:443", "/hello");
        assert_eq!(loc_tls, "https://new.example.com/hello");
    }

    #[test]
    fn redirect_scheme_change_drops_old_non_default_port() {
        let plugin = build_redirect(serde_json::json!({
            "scheme": "https",
            "status_code": 301
        }));
        let (st, loc) = run_redirect(&plugin, false, "example.com:8080", "/secure");
        assert_eq!(st, StatusCode::MOVED_PERMANENTLY);
        assert_eq!(loc, "https://example.com/secure");
    }

    #[test]
    fn replace_path_prefix_matches_gateway_api_edge_cases() {
        assert_eq!(replace_path_prefix("/v2", "/v2", "/v3"), "/v3");
        assert_eq!(replace_path_prefix("/v2/", "/v2", "/v3"), "/v3/");
        assert_eq!(replace_path_prefix("/v2/foo", "/v2", "/v3"), "/v3/foo");
        assert_eq!(replace_path_prefix("/v2", "/v2", "/"), "/");
        assert_eq!(replace_path_prefix("/v2/", "/v2", "/"), "/");
        assert_eq!(replace_path_prefix("/v2/foo", "/v2", "/"), "/foo");
        assert_eq!(replace_path_prefix("/v2/", "/v2/", "/"), "/");
        assert_eq!(replace_path_prefix("/v2/foo", "/v2/", "/"), "/foo");
        assert_eq!(replace_path_prefix("/", "/", "/v3"), "/v3");
        assert_eq!(replace_path_prefix("/foo", "/", "/v3"), "/v3/foo");
        assert_eq!(replace_path_prefix("/v2", "/v2", "/v3/"), "/v3/");
    }
}
