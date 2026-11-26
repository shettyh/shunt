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
    /// Optional allowlist of hosts permitted when reflecting incoming `Host` headers
    /// (case-insensitive, port stripped). Empty allows any syntactically valid `Host`.
    allowed_hosts: Vec<String>,
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
            allowed_hosts: Vec::new(),
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
        if let Some(host) = &cfg.hostname
            && extract_valid_host(host).is_none()
        {
            return Err(PluginBuildError::BuildFailed {
                plugin: self.name().to_owned(),
                message: format!("redirect `hostname` `{host}` is not a valid host"),
            });
        }
        if cfg.path_replace_full.is_some() && cfg.path_replace_prefix.is_some() {
            return Err(PluginBuildError::BuildFailed {
                plugin: self.name().to_owned(),
                message: "cannot specify both `path_replace_full` and `path_replace_prefix`"
                    .to_owned(),
            });
        }
        if let Some(full) = &cfg.path_replace_full
            && !is_safe_relative_location(full)
        {
            return Err(PluginBuildError::BuildFailed {
                plugin: self.name().to_owned(),
                message: format!(
                    "redirect `path_replace_full` `{full}` must start with a single `/` and not `//` or `/\\`"
                ),
            });
        }
        let allowed_hosts = cfg
            .allowed_hosts
            .into_iter()
            .map(|h| h.trim().to_ascii_lowercase())
            .filter(|h| !h.is_empty())
            .collect();
        let status = StatusCode::from_u16(cfg.status_code).expect("validated redirect status");
        Ok(Arc::new(RedirectPlugin {
            status,
            scheme: cfg.scheme,
            hostname: cfg.hostname,
            allowed_hosts,
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
    allowed_hosts: Vec<String>,
    port: Option<u16>,
    path_replace_full: Option<String>,
    path_match_prefix: Option<String>,
    path_replace_prefix: Option<String>,
    preserve_query: bool,
}

impl RedirectPlugin {
    fn compute_location(&self, req: &RequestHead) -> Result<String, &'static str> {
        let orig_path = req.uri.path();
        let new_path = if let Some(full) = &self.path_replace_full {
            full.clone()
        } else if let Some(rep) = &self.path_replace_prefix {
            let match_pfx = self.path_match_prefix.as_deref().unwrap_or("/");
            replace_path_prefix(orig_path, match_pfx, rep)
        } else {
            orig_path.to_owned()
        };

        if !is_safe_relative_location(&new_path) {
            return Err("unsafe redirect path");
        }

        let path_and_query = match (self.preserve_query, req.uri.query()) {
            (true, Some(q)) => format!("{new_path}?{q}"),
            _ => new_path,
        };

        if self.scheme.is_none() && self.hostname.is_none() && self.port.is_none() {
            return Ok(path_and_query);
        }

        let scheme = self
            .scheme
            .as_deref()
            .or_else(|| {
                req.uri
                    .scheme_str()
                    .filter(|s| s.eq_ignore_ascii_case("http") || s.eq_ignore_ascii_case("https"))
            })
            .unwrap_or("https");

        let host = if let Some(h) = self.hostname.as_deref() {
            h.to_owned()
        } else {
            let mut host_headers = req.headers.get_all(header::HOST).iter();
            let reflected = if let Some(first) = host_headers.next() {
                if host_headers.next().is_some() {
                    return Err("duplicate Host header");
                }
                let raw = first.to_str().map_err(|_| "invalid Host header")?;
                extract_valid_host(raw).ok_or("invalid Host header")?
            } else if let Some(uri_host) = req.uri.host() {
                extract_valid_host(uri_host).ok_or("invalid URI host")?
            } else {
                return Err("missing Host header");
            };

            if !self.allowed_hosts.is_empty()
                && !self
                    .allowed_hosts
                    .iter()
                    .any(|allowed| allowed.eq_ignore_ascii_case(&reflected))
            {
                return Err("Host header not in allowed_hosts");
            }
            reflected
        };

        let include_port = self
            .port
            .filter(|&p| !((scheme == "http" && p == 80) || (scheme == "https" && p == 443)));

        Ok(match include_port {
            Some(p) => format!("{scheme}://{host}:{p}{path_and_query}"),
            None => format!("{scheme}://{host}{path_and_query}"),
        })
    }
}

/// Returns `true` iff `path` is a safe origin-relative path (starts with a single `/`,
/// never `//` or `/\`, and contains no control characters or backslashes).
pub(crate) fn is_safe_relative_location(path: &str) -> bool {
    let bytes = path.as_bytes();
    if bytes.first() != Some(&b'/') {
        return false;
    }
    if matches!(bytes.get(1), Some(b'/' | b'\\')) {
        return false;
    }
    !bytes.iter().any(|&b| b < 0x20 || b == 0x7F || b == b'\\')
}

/// Strictly validates an HTTP `Host` header (optional `:port`) and returns the host portion
/// without port, rejecting `@`, `/`, `?`, `#`, `\`, whitespace, control chars, or bad ports.
pub(crate) fn extract_valid_host(host_hdr: &str) -> Option<String> {
    let trimmed = host_hdr.trim();
    if trimmed.is_empty() || trimmed != host_hdr {
        return None;
    }
    if host_hdr.bytes().any(|b| {
        b <= 0x20
            || b == 0x7F
            || matches!(b, b'@' | b'/' | b'?' | b'#' | b'\\' | b'<' | b'>' | b'"')
    }) {
        return None;
    }

    if let Some(rest) = host_hdr.strip_prefix('[') {
        let (ip, after) = rest.split_once(']')?;
        ip.parse::<std::net::Ipv6Addr>().ok()?;
        if !after.is_empty() {
            let port_str = after.strip_prefix(':')?;
            if port_str.is_empty() || port_str.parse::<u16>().is_err() {
                return None;
            }
        }
        return Some(format!("[{ip}]"));
    }

    let (host, port_opt) = match host_hdr.split_once(':') {
        Some((h, p)) => (h, Some(p)),
        None => (host_hdr, None),
    };
    if host.is_empty() || host.contains(':') || host.contains('[') || host.contains(']') {
        return None;
    }
    if let Some(p) = port_opt
        && (p.is_empty() || p.parse::<u16>().is_err())
    {
        return None;
    }
    // Validate RFC 3986 reg-name / IPv4 characters.
    if !host
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_'))
    {
        return None;
    }
    Some(host.to_owned())
}

pub(crate) fn replace_path_prefix(path: &str, match_prefix: &str, replacement: &str) -> String {
    let trimmed_match = match_prefix.trim_end_matches('/');
    let suffix = if trimmed_match.is_empty() {
        path
    } else if let Some(rest) = path.strip_prefix(trimmed_match) {
        if !rest.is_empty() && !rest.starts_with('/') {
            return path.to_owned();
        }
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
        let location = match self.compute_location(req) {
            Ok(loc) => loc,
            Err(_) => {
                return HookResult::Ready(Flow::Respond(BufferedResponse::new(
                    StatusCode::BAD_REQUEST,
                    "invalid redirect target",
                )));
            }
        };
        let Ok(val) = HeaderValue::from_str(&location) else {
            return HookResult::Ready(Flow::Respond(BufferedResponse::new(
                StatusCode::BAD_REQUEST,
                "invalid redirect target",
            )));
        };
        let mut resp = BufferedResponse::new(self.status, "");
        resp.headers.insert(header::LOCATION, val);
        HookResult::Ready(Flow::Respond(resp))
    }
}
