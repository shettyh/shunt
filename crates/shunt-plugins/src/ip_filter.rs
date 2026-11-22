use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::str::FromStr;
use std::sync::Arc;

use serde::Deserialize;
use shunt_plugin_sdk::{
    BufferedResponse, BuildContext, Flow, HeaderName, HookMask, HookResult, HttpPlugin,
    PluginBuildError, PluginConfig, PluginFactory, RequestCtx, RequestHead, StatusCode,
};

/// Resolved effective client IP attached to [`RequestCtx::extensions`] by [`IpFilterPlugin`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResolvedClientIp(pub IpAddr);

/// Pure-Rust IPv4 / IPv6 CIDR network prefix.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IpNet {
    V4 { network: u32, prefix_len: u8 },
    V6 { network: u128, prefix_len: u8 },
}

impl IpNet {
    /// Parses a bare IP (`"10.0.0.1"`, `"::1"`) or CIDR (`"10.0.0.0/8"`, `"2001:db8::/32"`).
    pub fn parse(raw: &str) -> Result<Self, String> {
        let s = raw.trim();
        if s.is_empty() {
            return Err("empty IP/CIDR entry".to_owned());
        }
        match s.split_once('/') {
            Some((addr_str, prefix_str)) => {
                let ip = IpAddr::from_str(addr_str.trim())
                    .map_err(|e| format!("invalid IP `{addr_str}` in CIDR `{raw}`: {e}"))?;
                let prefix_len: u8 = prefix_str
                    .trim()
                    .parse()
                    .map_err(|e| format!("invalid prefix length `{prefix_str}` in `{raw}`: {e}"))?;
                match ip {
                    IpAddr::V4(v4) => {
                        if prefix_len > 32 {
                            return Err(format!(
                                "IPv4 prefix length `{prefix_len}` > 32 in `{raw}`"
                            ));
                        }
                        let mask = v4_mask(prefix_len);
                        Ok(IpNet::V4 {
                            network: u32::from(v4) & mask,
                            prefix_len,
                        })
                    }
                    IpAddr::V6(v6) => {
                        if prefix_len > 128 {
                            return Err(format!(
                                "IPv6 prefix length `{prefix_len}` > 128 in `{raw}`"
                            ));
                        }
                        let mask = v6_mask(prefix_len);
                        Ok(IpNet::V6 {
                            network: u128::from(v6) & mask,
                            prefix_len,
                        })
                    }
                }
            }
            None => {
                let ip = IpAddr::from_str(s).map_err(|e| format!("invalid IP `{raw}`: {e}"))?;
                Ok(match ip {
                    IpAddr::V4(v4) => IpNet::V4 {
                        network: u32::from(v4),
                        prefix_len: 32,
                    },
                    IpAddr::V6(v6) => IpNet::V6 {
                        network: u128::from(v6),
                        prefix_len: 128,
                    },
                })
            }
        }
    }

    /// Returns `true` if `ip` falls inside this CIDR network.
    ///
    /// Normalizes IPv4-mapped IPv6 addresses (`::ffff:a.b.c.d`) against IPv4 CIDRs and vice versa.
    #[inline]
    pub fn contains(&self, ip: IpAddr) -> bool {
        let normalized = normalize_ip(ip);
        match (*self, normalized) {
            (
                IpNet::V4 {
                    network,
                    prefix_len,
                },
                IpAddr::V4(v4),
            ) => (u32::from(v4) & v4_mask(prefix_len)) == network,
            (
                IpNet::V6 {
                    network,
                    prefix_len,
                },
                IpAddr::V6(v6),
            ) => (u128::from(v6) & v6_mask(prefix_len)) == network,
            (
                IpNet::V6 {
                    network,
                    prefix_len,
                },
                IpAddr::V4(v4),
            ) => {
                let mapped = v4.to_ipv6_mapped();
                (u128::from(mapped) & v6_mask(prefix_len)) == network
            }
            (IpNet::V4 { .. }, IpAddr::V6(_)) => false,
        }
    }
}

#[inline]
fn v4_mask(prefix_len: u8) -> u32 {
    if prefix_len == 0 {
        0
    } else {
        u32::MAX << (32 - prefix_len)
    }
}

#[inline]
fn v6_mask(prefix_len: u8) -> u128 {
    if prefix_len == 0 {
        0
    } else {
        u128::MAX << (128 - prefix_len)
    }
}

/// Converts IPv4-mapped IPv6 addresses (`::ffff:1.2.3.4`) into canonical `IpAddr::V4`.
#[inline]
pub fn normalize_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V4(v4) => IpAddr::V4(v4),
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => IpAddr::V4(v4),
            None => IpAddr::V6(v6),
        },
    }
}

/// Precedence when both `allow` and `deny` lists are configured.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IpPrecedence {
    /// Deny rules override allow rules (default: allow `10.0.0.0/8`, deny `10.0.0.5/32`).
    #[default]
    DenyFirst,
    /// Allow rules override deny rules (e.g., deny `10.0.0.0/8`, allow `10.0.1.5/32`).
    AllowFirst,
}

#[derive(Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct IpFilterConfig {
    allow: Vec<String>,
    deny: Vec<String>,
    precedence: IpPrecedence,
    /// CIDRs of trusted upstream load balancers / reverse proxies permitted to supply
    /// `X-Forwarded-For` or `client_ip_header`.
    trusted_proxies: Vec<String>,
    /// Extract client IP from `X-Forwarded-For` right-to-left while hops belong to `trusted_proxies`.
    use_forwarded_for: bool,
    /// Optional single-IP header (e.g. `cf-connecting-ip`, `x-real-ip`) consulted only when
    /// `ctx.client_addr` matches `trusted_proxies`.
    client_ip_header: Option<String>,
    /// HTTP status code returned on rejection (default: `403`).
    status_code: u16,
}

impl Default for IpFilterConfig {
    fn default() -> Self {
        Self {
            allow: Vec::new(),
            deny: Vec::new(),
            precedence: IpPrecedence::DenyFirst,
            trusted_proxies: Vec::new(),
            use_forwarded_for: false,
            client_ip_header: None,
            status_code: 403,
        }
    }
}

pub struct IpFilterFactory;

impl PluginFactory for IpFilterFactory {
    fn name(&self) -> &str {
        "ip-filter"
    }

    fn build(
        &self,
        config: &PluginConfig,
        _ctx: &BuildContext,
    ) -> Result<Arc<dyn HttpPlugin>, PluginBuildError> {
        let cfg: IpFilterConfig = config.deserialize(self.name())?;
        if cfg.allow.is_empty() && cfg.deny.is_empty() {
            return Err(PluginBuildError::BuildFailed {
                plugin: self.name().to_owned(),
                message: "ip-filter requires at least one entry in `allow` or `deny`".to_owned(),
            });
        }

        let allow = parse_cidr_list(self.name(), "allow", &cfg.allow)?;
        let deny = parse_cidr_list(self.name(), "deny", &cfg.deny)?;
        let trusted_proxies =
            parse_cidr_list(self.name(), "trusted_proxies", &cfg.trusted_proxies)?;

        let client_ip_header = match cfg.client_ip_header {
            Some(raw) => Some(HeaderName::from_bytes(raw.as_bytes()).map_err(|e| {
                PluginBuildError::BuildFailed {
                    plugin: self.name().to_owned(),
                    message: format!("invalid `client_ip_header` `{raw}`: {e}"),
                }
            })?),
            None => None,
        };

        let status =
            StatusCode::from_u16(cfg.status_code).map_err(|e| PluginBuildError::BuildFailed {
                plugin: self.name().to_owned(),
                message: format!("invalid `status_code` `{}`: {e}", cfg.status_code),
            })?;
        if !status.is_client_error() && !status.is_server_error() {
            return Err(PluginBuildError::BuildFailed {
                plugin: self.name().to_owned(),
                message: format!("`status_code` must be 4xx or 5xx, got {}", cfg.status_code),
            });
        }

        Ok(Arc::new(IpFilterPlugin {
            allow,
            deny,
            precedence: cfg.precedence,
            trusted_proxies,
            use_forwarded_for: cfg.use_forwarded_for,
            client_ip_header,
            status,
        }))
    }
}

fn parse_cidr_list(
    plugin: &str,
    field: &str,
    raw: &[String],
) -> Result<Vec<IpNet>, PluginBuildError> {
    raw.iter()
        .map(|s| {
            IpNet::parse(s).map_err(|msg| PluginBuildError::BuildFailed {
                plugin: plugin.to_owned(),
                message: format!("{field}: {msg}"),
            })
        })
        .collect()
}

pub struct IpFilterPlugin {
    allow: Vec<IpNet>,
    deny: Vec<IpNet>,
    precedence: IpPrecedence,
    trusted_proxies: Vec<IpNet>,
    use_forwarded_for: bool,
    client_ip_header: Option<HeaderName>,
    status: StatusCode,
}

impl IpFilterPlugin {
    /// Resolves the effective client IP using `peer_ip`, `trusted_proxies`, and optional
    /// forwarded headers (right-to-left XFF traversal so spoofed leftmost entries are ignored).
    pub fn resolve_client_ip(&self, peer_ip: IpAddr, req: &RequestHead) -> IpAddr {
        let peer = normalize_ip(peer_ip);
        let peer_is_trusted = self.trusted_proxies.iter().any(|net| net.contains(peer));
        if !peer_is_trusted {
            return peer;
        }

        if let Some(hdr) = &self.client_ip_header
            && let Some(raw) = req.headers.get(hdr).and_then(|v| v.to_str().ok())
            && let Some(parsed) = parse_forwarded_ip(raw)
        {
            return normalize_ip(parsed);
        }

        if self.use_forwarded_for {
            let xff_name = HeaderName::from_static("x-forwarded-for");
            let mut hops: Vec<IpAddr> = Vec::new();
            for val in req.headers.get_all(&xff_name) {
                if let Ok(s) = val.to_str() {
                    for part in s.split(',') {
                        if let Some(ip) = parse_forwarded_ip(part) {
                            hops.push(normalize_ip(ip));
                        }
                    }
                }
            }
            // Walk right-to-left: the rightmost hop NOT in `trusted_proxies` is the real client.
            for &hop in hops.iter().rev() {
                if !self.trusted_proxies.iter().any(|net| net.contains(hop)) {
                    return hop;
                }
            }
            if let Some(&first) = hops.first() {
                return first;
            }
        }

        peer
    }

    /// Evaluates allow/deny rules against `ip`. Returns `true` if permitted.
    #[inline]
    pub fn is_allowed(&self, ip: IpAddr) -> bool {
        let in_allow = self.allow.iter().any(|net| net.contains(ip));
        let in_deny = self.deny.iter().any(|net| net.contains(ip));

        match self.precedence {
            IpPrecedence::DenyFirst => {
                if in_deny {
                    return false;
                }
                self.allow.is_empty() || in_allow
            }
            IpPrecedence::AllowFirst => {
                if in_allow {
                    return true;
                }
                if in_deny {
                    return false;
                }
                self.allow.is_empty()
            }
        }
    }
}

fn parse_forwarded_ip(raw: &str) -> Option<IpAddr> {
    let trimmed = raw.trim().trim_matches('"');
    if trimmed.is_empty() {
        return None;
    }
    if let Ok(ip) = IpAddr::from_str(trimmed) {
        return Some(ip);
    }
    // Handle `[ipv6]:port` or `ipv4:port`
    if let Some(rest) = trimmed.strip_prefix('[')
        && let Some((v6_str, _)) = rest.split_once(']')
        && let Ok(v6) = Ipv6Addr::from_str(v6_str)
    {
        return Some(IpAddr::V6(v6));
    }
    if let Some((v4_str, port_str)) = trimmed.rsplit_once(':')
        && port_str.parse::<u16>().is_ok()
        && let Ok(v4) = Ipv4Addr::from_str(v4_str)
    {
        return Some(IpAddr::V4(v4));
    }
    None
}

impl HttpPlugin for IpFilterPlugin {
    fn name(&self) -> &str {
        "ip-filter"
    }

    fn hook_mask(&self) -> HookMask {
        HookMask::ON_REQUEST_HEADERS
    }

    fn on_request_headers<'a>(
        &'a self,
        ctx: &'a mut RequestCtx,
        req: &'a mut RequestHead,
    ) -> HookResult<'a, Flow> {
        let client_ip = self.resolve_client_ip(ctx.client_addr.ip(), req);
        ctx.insert_ext(ResolvedClientIp(client_ip));

        if self.is_allowed(client_ip) {
            HookResult::Ready(Flow::Continue)
        } else {
            ctx.annotate_str("security.ip_filter", "denied");
            HookResult::Ready(Flow::Respond(BufferedResponse::json(
                self.status,
                r#"{"error":"ip_forbidden"}"#,
            )))
        }
    }
}

#[cfg(test)]
mod tests {
    use http::{HeaderMap, HeaderValue, Method, Uri, Version};

    use super::*;

    fn req_with_xff(xff: &str) -> RequestHead {
        let mut headers = HeaderMap::new();
        headers.insert(
            HeaderName::from_static("x-forwarded-for"),
            HeaderValue::from_str(xff).unwrap(),
        );
        RequestHead {
            method: Method::GET,
            uri: Uri::from_static("/"),
            version: Version::HTTP_11,
            headers,
        }
    }

    #[test]
    fn cidr_matching_ipv4_ipv6_and_mapped() {
        let net4 = IpNet::parse("10.20.0.0/16").unwrap();
        assert!(net4.contains("10.20.5.9".parse().unwrap()));
        assert!(!net4.contains("10.21.0.1".parse().unwrap()));
        // IPv4-mapped IPv6 matches IPv4 CIDR
        assert!(net4.contains("::ffff:10.20.1.2".parse().unwrap()));

        let net6 = IpNet::parse("2001:db8::/32").unwrap();
        assert!(net6.contains("2001:db8:abcd::1".parse().unwrap()));
        assert!(!net6.contains("2001:db9::1".parse().unwrap()));

        let all4 = IpNet::parse("0.0.0.0/0").unwrap();
        assert!(all4.contains("203.0.113.5".parse().unwrap()));
    }

    #[test]
    fn xff_right_to_left_blocks_spoofing() {
        let plugin = IpFilterPlugin {
            allow: vec![IpNet::parse("203.0.113.0/24").unwrap()],
            deny: vec![],
            precedence: IpPrecedence::DenyFirst,
            trusted_proxies: vec![IpNet::parse("10.0.0.0/8").unwrap()],
            use_forwarded_for: true,
            client_ip_header: None,
            status: StatusCode::FORBIDDEN,
        };

        // Attacker at 198.51.100.7 spoofs XFF: 203.0.113.5, through trusted proxy 10.0.0.2
        let req = req_with_xff("203.0.113.5, 198.51.100.7");
        let resolved = plugin.resolve_client_ip("10.0.0.2".parse().unwrap(), &req);
        assert_eq!(resolved, "198.51.100.7".parse::<IpAddr>().unwrap());
        assert!(!plugin.is_allowed(resolved));

        // Untrusted peer cannot spoof XFF at all
        let req2 = req_with_xff("203.0.113.5");
        let resolved2 = plugin.resolve_client_ip("198.51.100.7".parse().unwrap(), &req2);
        assert_eq!(resolved2, "198.51.100.7".parse::<IpAddr>().unwrap());

        // Legitimate client 203.0.113.42 through two trusted proxies 10.0.0.5 -> 10.0.0.2
        let req3 = req_with_xff("203.0.113.42, 10.0.0.5");
        let resolved3 = plugin.resolve_client_ip("10.0.0.2".parse().unwrap(), &req3);
        assert_eq!(resolved3, "203.0.113.42".parse::<IpAddr>().unwrap());
        assert!(plugin.is_allowed(resolved3));
    }

    #[test]
    fn precedence_modes_work() {
        let deny_first = IpFilterPlugin {
            allow: vec![IpNet::parse("10.0.0.0/8").unwrap()],
            deny: vec![IpNet::parse("10.0.0.99/32").unwrap()],
            precedence: IpPrecedence::DenyFirst,
            trusted_proxies: vec![],
            use_forwarded_for: false,
            client_ip_header: None,
            status: StatusCode::FORBIDDEN,
        };
        assert!(deny_first.is_allowed("10.0.0.1".parse().unwrap()));
        assert!(!deny_first.is_allowed("10.0.0.99".parse().unwrap()));
        assert!(!deny_first.is_allowed("192.168.1.1".parse().unwrap()));

        let allow_first = IpFilterPlugin {
            allow: vec![IpNet::parse("10.0.1.5/32").unwrap()],
            deny: vec![IpNet::parse("10.0.0.0/8").unwrap()],
            precedence: IpPrecedence::AllowFirst,
            trusted_proxies: vec![],
            use_forwarded_for: false,
            client_ip_header: None,
            status: StatusCode::FORBIDDEN,
        };
        assert!(allow_first.is_allowed("10.0.1.5".parse().unwrap()));
        assert!(!allow_first.is_allowed("10.0.1.6".parse().unwrap()));
    }
}
