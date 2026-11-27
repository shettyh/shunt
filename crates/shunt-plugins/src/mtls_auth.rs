use std::sync::Arc;

use serde::Deserialize;
use shunt_plugin_sdk::{
    BufferedResponse, BuildContext, Flow, HeaderName, HeaderValue, HookMask, HookResult,
    HttpPlugin, PluginBuildError, PluginConfig, PluginFactory, RequestCtx, RequestHead, StatusCode,
};

use crate::bearer_auth::AuthSubject;

#[derive(Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct MtlsAuthConfig {
    /// Reject requests without a verified client certificate (default: `true`).
    require_cert: bool,
    /// Allowed Subject Common Names (supports exact match or single-label `*` glob excluding `.`).
    allowed_cns: Vec<String>,
    /// Allowed SAN DNS names (supports exact match or leftmost single-label `*.suffix` wildcard).
    allowed_san_dns: Vec<String>,
    /// Allowed SAN URIs (supports exact match, single-segment `*` excluding `/`, or multi-segment `**`).
    allowed_san_uris: Vec<String>,
    /// Allowed lowercase or uppercase SHA-256 hex fingerprints of the leaf certificate.
    allowed_fingerprints: Vec<String>,
    /// Explicitly revoked/denied SHA-256 hex fingerprints (checked before allowlists).
    denied_fingerprints: Vec<String>,
    /// Optional header injected with Subject CN (or matched SAN URI / DN fallback). Incoming values are always stripped first.
    subject_header: Option<String>,
    /// Optional header injected with full Subject DN.
    dn_header: Option<String>,
    /// Optional header injected with leaf certificate SHA-256 hex fingerprint.
    fingerprint_header: Option<String>,
    /// Optional header injected with the matched SAN URI (or first SAN URI when no allowlist is set).
    san_uri_header: Option<String>,
}

impl Default for MtlsAuthConfig {
    fn default() -> Self {
        Self {
            require_cert: true,
            allowed_cns: Vec::new(),
            allowed_san_dns: Vec::new(),
            allowed_san_uris: Vec::new(),
            allowed_fingerprints: Vec::new(),
            denied_fingerprints: Vec::new(),
            subject_header: None,
            dn_header: None,
            fingerprint_header: None,
            san_uri_header: None,
        }
    }
}

pub struct MtlsAuthFactory;

impl PluginFactory for MtlsAuthFactory {
    fn name(&self) -> &str {
        "mtls-auth"
    }

    fn build(
        &self,
        config: &PluginConfig,
        _ctx: &BuildContext,
    ) -> Result<Arc<dyn HttpPlugin>, PluginBuildError> {
        let cfg: MtlsAuthConfig = config.deserialize(self.name())?;

        let parse_opt_hdr =
            |field: &str, val: Option<String>| -> Result<Option<HeaderName>, PluginBuildError> {
                match val {
                    Some(raw) => HeaderName::from_bytes(raw.as_bytes())
                        .map(Some)
                        .map_err(|e| PluginBuildError::BuildFailed {
                            plugin: self.name().to_owned(),
                            message: format!("invalid `{field}` header name `{raw}`: {e}"),
                        }),
                    None => Ok(None),
                }
            };

        let normalize_fps = |raw: Vec<String>| -> Result<Vec<String>, PluginBuildError> {
            let fps: Vec<String> = raw
                .into_iter()
                .map(|fp| fp.trim().replace(':', "").to_ascii_lowercase())
                .collect();
            for fp in &fps {
                if fp.len() != 64 || !fp.bytes().all(|b| b.is_ascii_hexdigit()) {
                    return Err(PluginBuildError::BuildFailed {
                        plugin: self.name().to_owned(),
                        message: format!(
                            "invalid SHA-256 fingerprint `{fp}` (expected 64 hex characters)"
                        ),
                    });
                }
            }
            Ok(fps)
        };

        let allowed_fingerprints = normalize_fps(cfg.allowed_fingerprints)?;
        let denied_fingerprints = normalize_fps(cfg.denied_fingerprints)?;

        Ok(Arc::new(MtlsAuthPlugin {
            require_cert: cfg.require_cert,
            allowed_cns: cfg.allowed_cns,
            allowed_san_dns: cfg.allowed_san_dns,
            allowed_san_uris: cfg.allowed_san_uris,
            allowed_fingerprints,
            denied_fingerprints,
            subject_header: parse_opt_hdr("subject_header", cfg.subject_header)?,
            dn_header: parse_opt_hdr("dn_header", cfg.dn_header)?,
            fingerprint_header: parse_opt_hdr("fingerprint_header", cfg.fingerprint_header)?,
            san_uri_header: parse_opt_hdr("san_uri_header", cfg.san_uri_header)?,
        }))
    }
}

pub struct MtlsAuthPlugin {
    require_cert: bool,
    allowed_cns: Vec<String>,
    allowed_san_dns: Vec<String>,
    allowed_san_uris: Vec<String>,
    allowed_fingerprints: Vec<String>,
    denied_fingerprints: Vec<String>,
    subject_header: Option<HeaderName>,
    dn_header: Option<HeaderName>,
    fingerprint_header: Option<HeaderName>,
    san_uri_header: Option<HeaderName>,
}

impl MtlsAuthPlugin {
    fn strip_managed_headers(&self, req: &mut RequestHead) {
        if let Some(h) = &self.subject_header {
            req.headers.remove(h);
        }
        if let Some(h) = &self.dn_header {
            req.headers.remove(h);
        }
        if let Some(h) = &self.fingerprint_header {
            req.headers.remove(h);
        }
        if let Some(h) = &self.san_uri_header {
            req.headers.remove(h);
        }
    }
}

impl HttpPlugin for MtlsAuthPlugin {
    fn name(&self) -> &str {
        "mtls-auth"
    }

    fn hook_mask(&self) -> HookMask {
        HookMask::ON_REQUEST_HEADERS
    }

    fn on_request_headers<'a>(
        &'a self,
        ctx: &'a mut RequestCtx,
        req: &'a mut RequestHead,
    ) -> HookResult<'a, Flow> {
        // Always strip client-supplied identity headers first to prevent spoofing.
        self.strip_managed_headers(req);

        let Some(cert) = ctx.client_cert.as_ref().cloned() else {
            if self.require_cert {
                return HookResult::Ready(Flow::Respond(BufferedResponse::json(
                    StatusCode::UNAUTHORIZED,
                    r#"{"error":"client_certificate_required"}"#,
                )));
            }
            return HookResult::Ready(Flow::Continue);
        };

        if self
            .denied_fingerprints
            .iter()
            .any(|fp| fp == &cert.sha256_fingerprint)
        {
            return HookResult::Ready(Flow::Respond(BufferedResponse::json(
                StatusCode::FORBIDDEN,
                r#"{"error":"client_certificate_revoked"}"#,
            )));
        }

        if !self.allowed_cns.is_empty() {
            let ok = cert
                .subject_cn
                .as_deref()
                .map(|cn| self.allowed_cns.iter().any(|p| cn_wildcard_match(p, cn)))
                .unwrap_or(false);
            if !ok {
                return HookResult::Ready(Flow::Respond(BufferedResponse::json(
                    StatusCode::FORBIDDEN,
                    r#"{"error":"client_certificate_cn_forbidden"}"#,
                )));
            }
        }

        if !self.allowed_san_dns.is_empty() {
            let ok = cert.san_dns.iter().any(|dns| {
                self.allowed_san_dns
                    .iter()
                    .any(|p| dns_wildcard_match(p, dns))
            });
            if !ok {
                return HookResult::Ready(Flow::Respond(BufferedResponse::json(
                    StatusCode::FORBIDDEN,
                    r#"{"error":"client_certificate_san_dns_forbidden"}"#,
                )));
            }
        }

        let matched_san_uri: Option<&str> = if !self.allowed_san_uris.is_empty() {
            let found = cert
                .san_uris
                .iter()
                .find(|uri| {
                    self.allowed_san_uris
                        .iter()
                        .any(|p| uri_wildcard_match(p, uri))
                })
                .map(String::as_str);
            if found.is_none() {
                return HookResult::Ready(Flow::Respond(BufferedResponse::json(
                    StatusCode::FORBIDDEN,
                    r#"{"error":"client_certificate_san_uri_forbidden"}"#,
                )));
            }
            found
        } else {
            cert.san_uris.first().map(String::as_str)
        };

        if !self.allowed_fingerprints.is_empty()
            && !self
                .allowed_fingerprints
                .iter()
                .any(|fp| fp == &cert.sha256_fingerprint)
        {
            return HookResult::Ready(Flow::Respond(BufferedResponse::json(
                StatusCode::FORBIDDEN,
                r#"{"error":"client_certificate_fingerprint_forbidden"}"#,
            )));
        }

        let subject = cert
            .subject_cn
            .clone()
            .or_else(|| matched_san_uri.map(str::to_owned))
            .unwrap_or_else(|| cert.subject_dn.clone());

        if let Some(h) = &self.subject_header
            && let Ok(val) = HeaderValue::from_str(&subject)
        {
            req.headers.insert(h.clone(), val);
        }
        if let Some(h) = &self.dn_header
            && !cert.subject_dn.is_empty()
            && let Ok(val) = HeaderValue::from_str(&cert.subject_dn)
        {
            req.headers.insert(h.clone(), val);
        }
        if let Some(h) = &self.fingerprint_header
            && let Ok(val) = HeaderValue::from_str(&cert.sha256_fingerprint)
        {
            req.headers.insert(h.clone(), val);
        }
        if let Some(h) = &self.san_uri_header
            && let Some(uri) = matched_san_uri
            && let Ok(val) = HeaderValue::from_str(uri)
        {
            req.headers.insert(h.clone(), val);
        }

        ctx.annotate_str("auth.method", "mtls");
        ctx.annotate_str("auth.subject", &subject);
        ctx.insert_ext(AuthSubject(subject));
        HookResult::Ready(Flow::Continue)
    }
}

/// Single-label DNS wildcard matching (RFC 6125 / RFC 9525, ASCII case-insensitive):
/// - Exact match when `pattern` contains no `*`
/// - Leftmost single-label wildcard `*.suffix` matching a single non-empty DNS label containing no `.`
pub(crate) fn dns_wildcard_match(pattern: &str, dns: &str) -> bool {
    if dns.is_empty() || dns.bytes().any(|b| b < 0x20 || b == 0x7F) {
        return false;
    }
    if let Some(suffix) = pattern.strip_prefix("*.") {
        if suffix.is_empty() || suffix.contains('*') {
            return false;
        }
        if dns.len() <= suffix.len() + 1 {
            return false;
        }
        let split_at = dns.len() - suffix.len() - 1;
        if dns.as_bytes()[split_at] != b'.' {
            return false;
        }
        let label = &dns[..split_at];
        let rest = &dns[split_at + 1..];
        !label.is_empty() && !label.contains('.') && rest.eq_ignore_ascii_case(suffix)
    } else if pattern.contains('*') {
        // Non-leading `*` in DNS patterns is disallowed per RFC 6125.
        false
    } else {
        pattern.eq_ignore_ascii_case(dns)
    }
}

/// Common Name wildcard matching: `*` matches zero or more characters excluding `.`
/// (and rejects control characters). Leading `*.` requires a non-empty label.
pub(crate) fn cn_wildcard_match(pattern: &str, value: &str) -> bool {
    if value.is_empty() || value.bytes().any(|b| b < 0x20 || b == 0x7F) {
        return false;
    }
    if pattern.starts_with("*.") && value.starts_with('.') {
        return false;
    }
    wildcard_match_excluding(pattern.as_bytes(), value.as_bytes(), false, b".")
}

/// URI / SPIFFE wildcard matching:
/// - Single `*` matches within a single path segment (excludes `/`, `?`, `#`).
/// - Double `**` matches across multiple path segments (still excludes `?` and `#`).
pub(crate) fn uri_wildcard_match(pattern: &str, uri: &str) -> bool {
    if uri.bytes().any(|b| b < 0x20 || b == 0x7F) {
        return false;
    }
    uri_wildcard_match_bytes(pattern.as_bytes(), uri.as_bytes())
}

#[derive(Clone, Copy)]
enum UriPatToken {
    Byte(u8),
    SingleStar,
    DoubleStar,
}

fn uri_wildcard_match_bytes(pat: &[u8], val: &[u8]) -> bool {
    let mut tokens = Vec::with_capacity(pat.len());
    let mut i = 0usize;
    while i < pat.len() {
        if pat[i] == b'*' {
            let start = i;
            while i < pat.len() && pat[i] == b'*' {
                i += 1;
            }
            if i - start >= 2 {
                tokens.push(UriPatToken::DoubleStar);
            } else {
                tokens.push(UriPatToken::SingleStar);
            }
        } else {
            tokens.push(UriPatToken::Byte(pat[i]));
            i += 1;
        }
    }

    let n = val.len();
    let mut prev = vec![false; n + 1];
    let mut curr = vec![false; n + 1];
    prev[0] = true;

    for token in tokens {
        match token {
            UriPatToken::Byte(b) => {
                curr[0] = false;
                for j in 0..n {
                    curr[j + 1] = prev[j] && val[j] == b;
                }
            }
            UriPatToken::SingleStar => {
                curr[0] = prev[0];
                for j in 0..n {
                    let allowed = !matches!(val[j], b'/' | b'?' | b'#');
                    curr[j + 1] = prev[j + 1] || (curr[j] && allowed);
                }
            }
            UriPatToken::DoubleStar => {
                curr[0] = prev[0];
                for j in 0..n {
                    let allowed = !matches!(val[j], b'?' | b'#');
                    curr[j + 1] = prev[j + 1] || (curr[j] && allowed);
                }
            }
        }
        std::mem::swap(&mut prev, &mut curr);
    }

    prev[n]
}

fn wildcard_match_excluding(pat: &[u8], val: &[u8], ascii_ci: bool, excluded: &[u8]) -> bool {
    let (mut p, mut v) = (0usize, 0usize);
    let (mut star_idx, mut match_idx) = (None, 0usize);

    while v < val.len() {
        let eq = p < pat.len()
            && if ascii_ci {
                pat[p].eq_ignore_ascii_case(&val[v])
            } else {
                pat[p] == val[v]
            };
        if eq {
            p += 1;
            v += 1;
        } else if p < pat.len() && pat[p] == b'*' {
            star_idx = Some(p);
            match_idx = v;
            p += 1;
        } else if let Some(si) = star_idx {
            if excluded.contains(&val[match_idx]) {
                return false;
            }
            p = si + 1;
            match_idx += 1;
            v = match_idx;
        } else {
            return false;
        }
    }

    while p < pat.len() && pat[p] == b'*' {
        p += 1;
    }
    p == pat.len()
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;
    use std::sync::RwLock;

    use http::{HeaderMap, Method, Uri, Version};
    use serde_json::json;
    use shunt_plugin_sdk::{ClientCertInfo, StateStore};

    use super::*;

    fn build_plugin(cfg: serde_json::Value) -> Arc<dyn HttpPlugin> {
        let store = Arc::new(StateStore::new());
        let bctx = BuildContext::new("test-mtls", store, Arc::new(RwLock::new(HashSet::new())));
        MtlsAuthFactory
            .build(&PluginConfig::new(cfg), &bctx)
            .unwrap()
    }

    #[tokio::test]
    async fn mtls_auth_enforces_spiffe_and_strips_spoofed_headers() {
        let plugin = build_plugin(json!({
            "require_cert": true,
            "allowed_san_uris": ["spiffe://prod.cluster/ns/payments/**"],
            "subject_header": "x-client-cn",
            "san_uri_header": "x-client-spiffe",
            "fingerprint_header": "x-client-fp"
        }));

        // Missing cert -> 401 and spoofed headers stripped
        let mut ctx = RequestCtx::new(1, "127.0.0.1:1234".parse().unwrap(), None);
        let mut req = RequestHead {
            method: Method::GET,
            uri: Uri::from_static("/pay"),
            version: Version::HTTP_11,
            headers: HeaderMap::new(),
        };
        req.headers.insert(
            HeaderName::from_static("x-client-cn"),
            HeaderValue::from_static("spoofed"),
        );
        let flow = plugin
            .on_request_headers(&mut ctx, &mut req)
            .resolve()
            .await;
        assert!(matches!(flow, Flow::Respond(r) if r.status == StatusCode::UNAUTHORIZED));
        assert!(!req.headers.contains_key("x-client-cn"));

        // Wrong SPIFFE namespace -> 403
        let bad_cert = Arc::new(ClientCertInfo {
            subject_cn: Some("rogue".to_owned()),
            subject_dn: "CN=rogue".to_owned(),
            issuer_dn: "CN=CA".to_owned(),
            san_dns: vec!["rogue.internal".to_owned()],
            san_uris: vec!["spiffe://prod.cluster/ns/other/sa/rogue".to_owned()],
            san_emails: vec![],
            serial_hex: "01".to_owned(),
            sha256_fingerprint: "a".repeat(64),
        });
        let mut ctx2 = RequestCtx::new(2, "127.0.0.1:1234".parse().unwrap(), None)
            .with_client_cert(Some(bad_cert));
        let flow2 = plugin
            .on_request_headers(&mut ctx2, &mut req)
            .resolve()
            .await;
        assert!(matches!(flow2, Flow::Respond(r) if r.status == StatusCode::FORBIDDEN));

        // Valid SPIFFE -> Continue + verified headers injected
        let good_cert = Arc::new(ClientCertInfo {
            subject_cn: Some("checkout-svc".to_owned()),
            subject_dn: "CN=checkout-svc,O=Acme".to_owned(),
            issuer_dn: "CN=CA".to_owned(),
            san_dns: vec!["checkout.internal".to_owned()],
            san_uris: vec!["spiffe://prod.cluster/ns/payments/sa/checkout".to_owned()],
            san_emails: vec![],
            serial_hex: "02".to_owned(),
            sha256_fingerprint: "b".repeat(64),
        });
        let mut ctx3 = RequestCtx::new(3, "127.0.0.1:1234".parse().unwrap(), None)
            .with_client_cert(Some(good_cert));
        let flow3 = plugin
            .on_request_headers(&mut ctx3, &mut req)
            .resolve()
            .await;
        assert!(matches!(flow3, Flow::Continue));
        assert_eq!(req.headers.get("x-client-cn").unwrap(), "checkout-svc");
        assert_eq!(
            req.headers.get("x-client-spiffe").unwrap(),
            "spiffe://prod.cluster/ns/payments/sa/checkout"
        );
        assert_eq!(req.headers.get("x-client-fp").unwrap(), &"b".repeat(64));
        assert_eq!(ctx3.get_ext::<AuthSubject>().unwrap().0, "checkout-svc");
    }
}
