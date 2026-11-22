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
    fn compute_location(&self, req: &RequestHead) -> String {
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

        let incoming_host = req
            .headers
            .get(header::HOST)
            .and_then(|v| v.to_str().ok())
            .map(strip_host_port)
            .or_else(|| req.uri.host().map(str::to_owned));

        if self.scheme.is_none() && self.hostname.is_none() && self.port.is_none() {
            return path_and_query;
        }

        let scheme = self
            .scheme
            .as_deref()
            .or_else(|| req.uri.scheme_str())
            .unwrap_or("https");
        let host = self
            .hostname
            .as_deref()
            .or(incoming_host.as_deref())
            .unwrap_or("localhost");

        let include_port = self
            .port
            .filter(|&p| !((scheme == "http" && p == 80) || (scheme == "https" && p == 443)));

        match include_port {
            Some(p) => format!("{scheme}://{host}:{p}{path_and_query}"),
            None => format!("{scheme}://{host}{path_and_query}"),
        }
    }
}

fn strip_host_port(host_hdr: &str) -> String {
    if let Some(rest) = host_hdr.strip_prefix('[') {
        if let Some((ip, _)) = rest.split_once(']') {
            return format!("[{ip}]");
        }
        return host_hdr.to_owned();
    }
    host_hdr
        .split_once(':')
        .map(|(h, _)| h)
        .unwrap_or(host_hdr)
        .to_owned()
}

pub(crate) fn replace_path_prefix(path: &str, match_prefix: &str, replacement: &str) -> String {
    let trimmed_match = match_prefix.trim_end_matches('/');
    let suffix = if trimmed_match.is_empty() {
        path
    } else if let Some(rest) = path.strip_prefix(trimmed_match) {
        rest
    } else {
        return path.to_owned();
    };
    let rep_clean = replacement.trim_end_matches('/');
    if suffix.is_empty() {
        if rep_clean.is_empty() {
            "/".to_owned()
        } else {
            rep_clean.to_owned()
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
        _ctx: &'a mut RequestCtx,
        req: &'a mut RequestHead,
    ) -> HookResult<'a, Flow> {
        let location = self.compute_location(req);
        let mut resp = BufferedResponse::new(self.status, "");
        if let Ok(val) = HeaderValue::from_str(&location) {
            resp.headers.insert(header::LOCATION, val);
        }
        HookResult::Ready(Flow::Respond(resp))
    }
}
