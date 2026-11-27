use std::collections::HashSet;
use std::sync::Arc;

use regex::{Regex, RegexBuilder};
use shunt_plugin_sdk::PathParams;
pub use shunt_plugin_sdk::{validate_request_path, validate_request_path_allow_encoded_slashes};

/// Default compiled regex size limit (1 MiB) to guard against pathological patterns on reload.
pub const DEFAULT_PATH_REGEX_SIZE_LIMIT: usize = 1024 * 1024;

/// A single compiled segment of a [`CompiledPathTemplate`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TemplateSegment {
    /// Exact literal segment (e.g. `"orders"`).
    Literal(Arc<str>),
    /// Single-segment named parameter (e.g. `{order_id}` — matches one non-empty segment without `/`).
    Param(Arc<str>),
    /// Catch-all final wildcard parameter (e.g. `{*filepath}` — matches 1+ remaining bytes including `/`).
    Wildcard(Arc<str>),
}

/// Precompiled segment-based path template (e.g. `"/orders/{order_id}/status"` or `"/files/{*rest}"`).
///
/// Matching is strictly zero-allocation and uses a precomputed `static_prefix` for fast SIMD rejection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompiledPathTemplate {
    raw: Arc<str>,
    static_prefix: Arc<str>,
    segments: Arc<[TemplateSegment]>,
    param_count: usize,
    has_wildcard: bool,
}

impl CompiledPathTemplate {
    /// Parses and validates a path template string.
    ///
    /// Rules:
    /// - Must start with `/` and contain no query (`?`) or fragment (`#`).
    /// - No empty segments (`//`) and no trailing `/` except for root `"/"`.
    /// - Parameters use `{name}` (single segment) or `{*name}` (final catch-all wildcard).
    /// - Parameter names must match `[A-Za-z_][A-Za-z0-9_]*` and be unique within the template.
    /// - Partial-segment braces (e.g. `/orders/ord-{id}`) are rejected; use `path_regex` instead.
    pub fn parse(raw: &str) -> Result<Self, String> {
        if !raw.starts_with('/') {
            return Err(format!("path_template `{raw}` must start with `/`"));
        }
        if raw.contains('?') || raw.contains('#') {
            return Err(format!(
                "path_template `{raw}` must not contain query (`?`) or fragment (`#`) components"
            ));
        }
        if raw == "/" {
            return Ok(Self {
                raw: Arc::from("/"),
                static_prefix: Arc::from("/"),
                segments: Arc::from([]),
                param_count: 0,
                has_wildcard: false,
            });
        }
        if raw.ends_with('/') {
            return Err(format!(
                "path_template `{raw}` must not have a trailing `/` (except root `/`)"
            ));
        }

        let parts: Vec<&str> = raw[1..].split('/').collect();
        let total = parts.len();
        let mut segments = Vec::with_capacity(total);
        let mut seen_params: HashSet<&str> = HashSet::new();
        let mut param_count = 0usize;
        let mut has_wildcard = false;

        for (idx, part) in parts.iter().enumerate() {
            if part.is_empty() {
                return Err(format!(
                    "path_template `{raw}` contains an empty segment (`//`)"
                ));
            }
            if part.starts_with('{') && part.ends_with('}') && part.len() >= 2 {
                let inner = &part[1..part.len() - 1];
                if inner.contains('{') || inner.contains('}') {
                    return Err(format!(
                        "path_template `{raw}` has malformed braces in segment `{part}`"
                    ));
                }
                if let Some(name) = inner.strip_prefix('*') {
                    if !is_valid_param_name(name) {
                        return Err(format!(
                            "path_template `{raw}` has invalid wildcard parameter name `{name}` (expected `[A-Za-z_][A-Za-z0-9_]*`)"
                        ));
                    }
                    if idx + 1 != total {
                        return Err(format!(
                            "path_template `{raw}` wildcard parameter `{{*{name}}}` must be the final segment"
                        ));
                    }
                    if !seen_params.insert(name) {
                        return Err(format!(
                            "path_template `{raw}` contains duplicate parameter name `{name}`"
                        ));
                    }
                    param_count += 1;
                    has_wildcard = true;
                    segments.push(TemplateSegment::Wildcard(Arc::from(name)));
                } else {
                    if !is_valid_param_name(inner) {
                        return Err(format!(
                            "path_template `{raw}` has invalid parameter name `{inner}` (expected `[A-Za-z_][A-Za-z0-9_]*`)"
                        ));
                    }
                    if !seen_params.insert(inner) {
                        return Err(format!(
                            "path_template `{raw}` contains duplicate parameter name `{inner}`"
                        ));
                    }
                    param_count += 1;
                    segments.push(TemplateSegment::Param(Arc::from(inner)));
                }
            } else if part.contains('{') || part.contains('}') {
                return Err(format!(
                    "path_template `{raw}` has partial-segment or unbalanced braces in `{part}`; use full-segment `{{param}}` or `path_regex`"
                ));
            } else {
                segments.push(TemplateSegment::Literal(Arc::from(*part)));
            }
        }

        let first_dyn = segments
            .iter()
            .position(|s| !matches!(s, TemplateSegment::Literal(_)));
        let static_prefix: Arc<str> = match first_dyn {
            None => Arc::from(raw),
            Some(0) => Arc::from("/"),
            Some(k) => {
                let mut buf = String::with_capacity(raw.len());
                buf.push('/');
                for seg in &segments[..k] {
                    if let TemplateSegment::Literal(lit) = seg {
                        buf.push_str(lit);
                        buf.push('/');
                    }
                }
                Arc::from(buf)
            }
        };

        Ok(Self {
            raw: Arc::from(raw),
            static_prefix,
            segments: Arc::from(segments),
            param_count,
            has_wildcard,
        })
    }

    #[inline]
    pub fn raw(&self) -> &str {
        &self.raw
    }

    #[inline]
    pub fn static_prefix(&self) -> &str {
        &self.static_prefix
    }

    #[inline]
    pub fn segments(&self) -> &[TemplateSegment] {
        &self.segments
    }

    #[inline]
    pub fn param_count(&self) -> usize {
        self.param_count
    }

    #[inline]
    pub fn has_params(&self) -> bool {
        self.param_count > 0
    }

    #[inline]
    pub fn has_wildcard(&self) -> bool {
        self.has_wildcard
    }

    /// Zero-allocation check whether `path` matches this compiled template.
    #[inline]
    pub fn matches(&self, path: &str) -> bool {
        if !path.starts_with(self.static_prefix.as_ref()) {
            return false;
        }
        if self.segments.is_empty() {
            return path == "/";
        }
        if !self.has_params() {
            return path == self.raw.as_ref();
        }

        let mut rest = &path[1..];
        let last_idx = self.segments.len() - 1;
        for (i, seg) in self.segments.iter().enumerate() {
            let is_last = i == last_idx;
            match seg {
                TemplateSegment::Wildcard(_) => {
                    return !rest.is_empty();
                }
                TemplateSegment::Literal(lit) => {
                    if is_last {
                        return rest == lit.as_ref();
                    }
                    let Some(after_lit) = rest.strip_prefix(lit.as_ref()) else {
                        return false;
                    };
                    let Some(next) = after_lit.strip_prefix('/') else {
                        return false;
                    };
                    rest = next;
                }
                TemplateSegment::Param(_) => {
                    if is_last {
                        return !rest.is_empty() && !rest.contains('/');
                    }
                    let Some(slash_pos) = rest.find('/') else {
                        return false;
                    };
                    if slash_pos == 0 {
                        return false;
                    }
                    rest = &rest[slash_pos + 1..];
                }
            }
        }
        false
    }

    /// Extracts captured parameters from a matching `path`.
    ///
    /// Returns [`PathParams::empty`] (zero heap allocation) if `path` does not match or
    /// the template contains no parameter segments.
    pub fn extract_params(&self, path: &str) -> PathParams {
        if self.param_count == 0 || !path.starts_with(self.static_prefix.as_ref()) {
            return PathParams::empty();
        }
        if self.segments.is_empty() {
            return PathParams::empty();
        }

        let mut pairs = Vec::with_capacity(self.param_count);
        let mut rest = &path[1..];
        let last_idx = self.segments.len() - 1;

        for (i, seg) in self.segments.iter().enumerate() {
            let is_last = i == last_idx;
            match seg {
                TemplateSegment::Wildcard(name) => {
                    if rest.is_empty() {
                        return PathParams::empty();
                    }
                    pairs.push((Arc::clone(name), rest.to_owned()));
                    return PathParams::from_pairs(pairs);
                }
                TemplateSegment::Literal(lit) => {
                    if is_last {
                        if rest == lit.as_ref() {
                            return PathParams::from_pairs(pairs);
                        }
                        return PathParams::empty();
                    }
                    let Some(after_lit) = rest.strip_prefix(lit.as_ref()) else {
                        return PathParams::empty();
                    };
                    let Some(next) = after_lit.strip_prefix('/') else {
                        return PathParams::empty();
                    };
                    rest = next;
                }
                TemplateSegment::Param(name) => {
                    if is_last {
                        if rest.is_empty() || rest.contains('/') {
                            return PathParams::empty();
                        }
                        pairs.push((Arc::clone(name), rest.to_owned()));
                        return PathParams::from_pairs(pairs);
                    }
                    let Some(slash_pos) = rest.find('/') else {
                        return PathParams::empty();
                    };
                    if slash_pos == 0 {
                        return PathParams::empty();
                    }
                    pairs.push((Arc::clone(name), rest[..slash_pos].to_owned()));
                    rest = &rest[slash_pos + 1..];
                }
            }
        }

        PathParams::empty()
    }
}

fn is_valid_param_name(name: &str) -> bool {
    let mut bytes = name.bytes();
    let Some(first) = bytes.next() else {
        return false;
    };
    if !(first.is_ascii_alphabetic() || first == b'_') {
        return false;
    }
    bytes.all(|b| b.is_ascii_alphanumeric() || b == b'_')
}

/// Precompiled, linear-time, full-path anchored regular expression matcher.
///
/// Patterns are internally wrapped as `\A(?:<raw>)\z` so partial/substring matches cannot
/// accidentally hijack unrelated paths, and compiled with explicit size limits to guard
/// against pathological patterns during reload.
#[derive(Debug, Clone)]
pub struct CompiledPathRegex {
    raw: Arc<str>,
    anchored: Arc<str>,
    regex: Arc<Regex>,
    named_captures: Arc<[Arc<str>]>,
}

impl PartialEq for CompiledPathRegex {
    fn eq(&self, other: &Self) -> bool {
        self.raw == other.raw
    }
}

impl Eq for CompiledPathRegex {}

impl CompiledPathRegex {
    /// Compiles and validates a full-path regular expression with bounded memory limits.
    pub fn compile(raw: &str) -> Result<Self, String> {
        if raw.is_empty() {
            return Err("path_regex cannot be empty".to_owned());
        }
        let anchored = format!(r"\A(?:{raw})\z");
        let regex = RegexBuilder::new(&anchored)
            .size_limit(DEFAULT_PATH_REGEX_SIZE_LIMIT)
            .dfa_size_limit(DEFAULT_PATH_REGEX_SIZE_LIMIT)
            .build()
            .map_err(|e| format!("invalid path_regex `{raw}`: {e}"))?;

        let named_captures: Vec<Arc<str>> = regex
            .capture_names()
            .flatten()
            .map(Arc::<str>::from)
            .collect();

        Ok(Self {
            raw: Arc::from(raw),
            anchored: Arc::from(anchored),
            regex: Arc::new(regex),
            named_captures: Arc::from(named_captures),
        })
    }

    #[inline]
    pub fn raw(&self) -> &str {
        &self.raw
    }

    #[inline]
    pub fn anchored_pattern(&self) -> &str {
        &self.anchored
    }

    #[inline]
    pub fn named_captures(&self) -> &[Arc<str>] {
        &self.named_captures
    }

    #[inline]
    pub fn has_named_captures(&self) -> bool {
        !self.named_captures.is_empty()
    }

    #[inline]
    pub fn matches(&self, path: &str) -> bool {
        self.regex.is_match(path)
    }

    /// Extracts named capture groups (`(?P<name>...)`) from a matching `path`.
    ///
    /// Returns [`PathParams::empty`] (zero heap allocation) when the pattern has no named
    /// capture groups or does not match.
    pub fn extract_params(&self, path: &str) -> PathParams {
        if self.named_captures.is_empty() {
            return PathParams::empty();
        }
        let Some(caps) = self.regex.captures(path) else {
            return PathParams::empty();
        };
        let mut pairs = Vec::with_capacity(self.named_captures.len());
        for name in self.named_captures.iter() {
            if let Some(m) = caps.name(name) {
                pairs.push((Arc::clone(name), m.as_str().to_owned()));
            }
        }
        PathParams::from_pairs(pairs)
    }
}

/// Path matching rule for a route.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum PathMatch {
    /// Matches any path.
    #[default]
    Any,
    /// Matches an exact path (e.g. `"/v1/chat/completions"`).
    Exact(String),
    /// Matches paths starting with the prefix (e.g. `"/api"` matches `"/api"` and `"/api/foo"`).
    Prefix(String),
    /// Matches a segment-based path template (e.g. `"/orders/{order_id}/status"` or `"/files/{*rest}"`).
    Template(CompiledPathTemplate),
    /// Matches a full-path anchored linear-time regular expression.
    Regex(CompiledPathRegex),
}

impl PathMatch {
    /// Returns `true` if `path` matches this path rule (zero-allocation).
    pub fn matches(&self, path: &str) -> bool {
        match self {
            PathMatch::Any => true,
            PathMatch::Exact(exact) => path == exact,
            PathMatch::Prefix(prefix) => {
                if prefix == "/" {
                    return true;
                }
                let trimmed = prefix.trim_end_matches('/');
                if path == trimmed {
                    return true;
                }
                path.starts_with(trimmed) && path.as_bytes().get(trimmed.len()) == Some(&b'/')
            }
            PathMatch::Template(tpl) => tpl.matches(path),
            PathMatch::Regex(re) => re.matches(path),
        }
    }

    /// Returns `true` if this matcher can capture named path parameters.
    #[inline]
    pub fn has_params(&self) -> bool {
        match self {
            PathMatch::Template(tpl) => tpl.has_params(),
            PathMatch::Regex(re) => re.has_named_captures(),
            PathMatch::Any | PathMatch::Exact(_) | PathMatch::Prefix(_) => false,
        }
    }

    /// Extracts captured path parameters from `path`, returning [`PathParams::empty`] if none.
    #[inline]
    pub fn extract_params(&self, path: &str) -> PathParams {
        match self {
            PathMatch::Template(tpl) => tpl.extract_params(path),
            PathMatch::Regex(re) => re.extract_params(path),
            PathMatch::Any | PathMatch::Exact(_) | PathMatch::Prefix(_) => PathParams::empty(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn template_parsing_and_matching() {
        let tpl = CompiledPathTemplate::parse("/orders/{order_id}/status").unwrap();
        assert_eq!(tpl.static_prefix(), "/orders/");
        assert_eq!(tpl.param_count(), 1);
        assert!(tpl.has_params());
        assert!(!tpl.has_wildcard());

        assert!(tpl.matches("/orders/123/status"));
        assert!(tpl.matches("/orders/ord_abc-99/status"));
        assert!(!tpl.matches("/orders//status"));
        assert!(!tpl.matches("/orders/123/status/"));
        assert!(!tpl.matches("/orders/123/status/extra"));
        assert!(!tpl.matches("/orders/123"));
        assert!(!tpl.matches("/other/123/status"));

        let params = tpl.extract_params("/orders/123/status");
        assert_eq!(params.get("order_id"), Some("123"));
        assert_eq!(params.len(), 1);
    }

    #[test]
    fn template_wildcard_matching_and_extraction() {
        let tpl = CompiledPathTemplate::parse("/files/{*filepath}").unwrap();
        assert_eq!(tpl.static_prefix(), "/files/");
        assert!(tpl.has_wildcard());
        assert!(tpl.matches("/files/a"));
        assert!(tpl.matches("/files/a/b/c.txt"));
        assert!(!tpl.matches("/files"));
        assert!(!tpl.matches("/files/"));

        let params = tpl.extract_params("/files/docs/2026/report.pdf");
        assert_eq!(params.get("filepath"), Some("docs/2026/report.pdf"));

        let root_wild = CompiledPathTemplate::parse("/{*all}").unwrap();
        assert_eq!(root_wild.static_prefix(), "/");
        assert!(root_wild.matches("/a/b"));
        assert!(!root_wild.matches("/"));
        assert_eq!(root_wild.extract_params("/a/b").get("all"), Some("a/b"));
    }

    #[test]
    fn template_validation_rejects_malformed_patterns() {
        assert!(CompiledPathTemplate::parse("orders/{id}").is_err());
        assert!(CompiledPathTemplate::parse("/orders/{id}/").is_err());
        assert!(CompiledPathTemplate::parse("/orders//{id}").is_err());
        assert!(CompiledPathTemplate::parse("/orders/{}").is_err());
        assert!(CompiledPathTemplate::parse("/orders/{123}").is_err());
        assert!(CompiledPathTemplate::parse("/orders/{*rest}/status").is_err());
        assert!(CompiledPathTemplate::parse("/orders/{id}/items/{id}").is_err());
        assert!(CompiledPathTemplate::parse("/orders/ord-{id}").is_err());
        assert!(CompiledPathTemplate::parse("/orders/{id}?a=1").is_err());
    }

    #[test]
    fn regex_full_path_anchoring_and_named_captures() {
        let re = CompiledPathRegex::compile(r"/orders/(?P<order_id>[0-9]+)/status").unwrap();
        assert!(re.has_named_captures());
        assert!(re.matches("/orders/42/status"));
        assert!(!re.matches("/orders/abc/status"));
        assert!(!re.matches("/prefix/orders/42/status"));
        assert!(!re.matches("/orders/42/status/extra"));

        let params = re.extract_params("/orders/42/status");
        assert_eq!(params.get("order_id"), Some("42"));

        // Explicit ^...$ anchors continue working identically.
        let anchored = CompiledPathRegex::compile(r"^/v[12]/health$").unwrap();
        assert!(!anchored.has_named_captures());
        assert!(anchored.matches("/v1/health"));
        assert!(anchored.matches("/v2/health"));
        assert!(!anchored.matches("/v3/health"));

        assert!(CompiledPathRegex::compile("").is_err());
        assert!(CompiledPathRegex::compile("[unclosed").is_err());
    }
}
