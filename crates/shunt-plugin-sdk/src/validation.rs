//! Zero-dependency HTTP request path and `Content-Length` validation helpers shared
//! between `shunt-engine` and `shunt-plugins`.

use std::fmt;

use http::{HeaderMap, header};

/// Errors produced when validating HTTP `Content-Length` headers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContentLengthError {
    /// Non-ASCII, empty, non-digit, negative, or overflowing `Content-Length` value.
    Invalid,
    /// Multiple `Content-Length` headers or comma-separated values with differing lengths.
    Conflicting,
}

impl ContentLengthError {
    /// Returns a stable machine-readable error code for JSON error responses.
    pub const fn code(self) -> &'static str {
        match self {
            Self::Invalid => "invalid_content_length",
            Self::Conflicting => "conflicting_content_length",
        }
    }

    /// Returns a human-readable description of the validation failure.
    pub const fn message(self) -> &'static str {
        match self {
            Self::Invalid => "malformed Content-Length header",
            Self::Conflicting => "conflicting Content-Length headers",
        }
    }
}

impl fmt::Display for ContentLengthError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.message())
    }
}

impl std::error::Error for ContentLengthError {}

/// Parses and validates all `Content-Length` headers on a request.
///
/// Rejects non-ASCII, empty, non-digit, negative, overflowing, or conflicting duplicate values
/// so request-smuggling and `body-limit` fail-open bypasses are blocked with `400 Bad Request`.
pub fn parse_and_validate_content_length(
    headers: &HeaderMap,
) -> Result<Option<usize>, ContentLengthError> {
    let mut resolved: Option<usize> = None;
    for raw in headers.get_all(header::CONTENT_LENGTH) {
        let s = raw.to_str().map_err(|_| ContentLengthError::Invalid)?;
        for part in s.split(',') {
            let trimmed = part.trim();
            if trimmed.is_empty() || !trimmed.bytes().all(|b| b.is_ascii_digit()) {
                return Err(ContentLengthError::Invalid);
            }
            let val = trimmed
                .parse::<usize>()
                .map_err(|_| ContentLengthError::Invalid)?;
            if let Some(prev) = resolved {
                if prev != val {
                    return Err(ContentLengthError::Conflicting);
                }
            } else {
                resolved = Some(val);
            }
        }
    }
    Ok(resolved)
}

/// Strictly validates an incoming HTTP request path in a single zero-allocation linear scan.
///
/// Rejects ambiguous and path-traversal sequences that cause gateway-vs-backend routing
/// differentials:
/// - non-`/` leading byte (except RFC 9110 asterisk-form `"*"`)
/// - ASCII control characters (`0x00..=0x1F`, `0x7F`) or raw backslashes (`\`)
/// - empty path segments (`//`)
/// - dot-segments (`.` or `..`)
/// - malformed `%` escapes or percent-encoded control bytes (`%00..%1F`, `%7F`),
///   dots (`%2e`/`%2E`), slashes (`%2f`/`%2F`), backslashes (`%5c`/`%5C`), or
///   RFC 3986 unreserved characters (`ALPHA / DIGIT / - / _ / ~`, e.g., `/%61dmin`)
#[inline]
pub fn validate_request_path(path: &str) -> Result<(), &'static str> {
    validate_request_path_impl(path, false)
}

/// Validates an incoming HTTP request path on routes with `allow_raw_path = true`.
///
/// Relaxes **only** percent-encoded forward slashes (`%2f` / `%2F`) for backends that embed
/// opaque slash-containing keys in path segments (e.g., object storage). All traversal,
/// dot-segment, empty-segment (`//`), backslash, malformed `%`, encoded control byte, and
/// encoded unreserved character (`/%61dmin`) protections remain enforced.
#[inline]
pub fn validate_request_path_allow_encoded_slashes(path: &str) -> Result<(), &'static str> {
    validate_request_path_impl(path, true)
}

#[inline]
fn validate_request_path_impl(path: &str, allow_encoded_slashes: bool) -> Result<(), &'static str> {
    if path == "*" {
        return Ok(());
    }
    let bytes = path.as_bytes();
    if bytes.first() != Some(&b'/') {
        return Err("request path must start with `/`");
    }

    let len = bytes.len();
    let mut i = 0usize;
    let mut seg_start = 1usize;

    while i < len {
        let b = bytes[i];
        if b < 0x20 || b == 0x7F {
            return Err("control character in request path");
        }
        if b == b'\\' {
            return Err("backslash in request path");
        }
        if b == b'/' {
            if i > 0 {
                if bytes[i - 1] == b'/' {
                    return Err("empty path segment (`//`) in request path");
                }
                let seg = &bytes[seg_start..i];
                if seg == b"." || seg == b".." {
                    return Err("dot-segment in request path");
                }
                seg_start = i + 1;
            }
            i += 1;
            continue;
        }
        if b == b'%' {
            if i + 2 >= len {
                return Err("malformed percent-encoding in request path");
            }
            let Some(hi) = decode_hex_nibble(bytes[i + 1]) else {
                return Err("malformed percent-encoding in request path");
            };
            let Some(lo) = decode_hex_nibble(bytes[i + 2]) else {
                return Err("malformed percent-encoding in request path");
            };
            let decoded = (hi << 4) | lo;
            match decoded {
                0x00..=0x1F | 0x7F => return Err("encoded control character in request path"),
                b'.' => return Err("encoded dot (`%2e`) in request path"),
                b'/' if !allow_encoded_slashes => {
                    return Err("encoded slash (`%2f`) in request path");
                }
                b'\\' => return Err("encoded backslash (`%5c`) in request path"),
                b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'~' => {
                    return Err("encoded unreserved character in request path");
                }
                _ => {}
            }
            i += 3;
            continue;
        }
        i += 1;
    }

    if seg_start < len {
        let last_seg = &bytes[seg_start..len];
        if last_seg == b"." || last_seg == b".." {
            return Err("dot-segment in request path");
        }
    }

    Ok(())
}

#[inline]
fn decode_hex_nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}
