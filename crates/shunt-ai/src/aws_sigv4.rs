//! Pure-Rust AWS Signature Version 4 (`AWS4-HMAC-SHA256`) request signer.
//!
//! Built directly on `sha2` with zero external cloud SDK dependencies.

use std::fmt::Write as _;
use std::time::{SystemTime, UNIX_EPOCH};

use sha2::{Digest, Sha256};
use shunt_plugin_sdk::{HeaderName, HeaderValue, UpstreamRequest, Uri, header};

use crate::types::is_rfc3986_unreserved;

/// AWS SigV4 credentials and target signing scope.
#[derive(Debug, Clone)]
pub struct AwsSigV4Credentials {
    pub access_key_id: String,
    pub secret_access_key: String,
    pub session_token: Option<String>,
    pub region: String,
    pub service: String,
}

/// Output headers produced by [`sign_canonical`] / [`sign_upstream_request`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SigV4Output {
    pub authorization: String,
    pub amz_date: String,
    pub payload_sha256: String,
    pub signed_headers: String,
    pub canonical_request: String,
    pub string_to_sign: String,
    pub signature: String,
}

/// Computes `SHA-256(data)` and returns lowercase hex.
pub fn sha256_hex(data: &[u8]) -> String {
    let digest = Sha256::digest(data);
    hex_lower(&digest)
}

/// Computes `HMAC-SHA256(key, data)` per RFC 2104.
pub fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    const BLOCK_SIZE: usize = 64;
    let mut k_block = [0u8; BLOCK_SIZE];
    if key.len() > BLOCK_SIZE {
        let hashed = Sha256::digest(key);
        k_block[..32].copy_from_slice(&hashed);
    } else {
        k_block[..key.len()].copy_from_slice(key);
    }

    let mut ipad = [0x36u8; BLOCK_SIZE];
    let mut opad = [0x5cu8; BLOCK_SIZE];
    for i in 0..BLOCK_SIZE {
        ipad[i] ^= k_block[i];
        opad[i] ^= k_block[i];
    }

    let mut inner = Sha256::new();
    inner.update(ipad);
    inner.update(data);
    let inner_hash = inner.finalize();

    let mut outer = Sha256::new();
    outer.update(opad);
    outer.update(inner_hash);
    let outer_hash = outer.finalize();

    let mut out = [0u8; 32];
    out.copy_from_slice(&outer_hash);
    out
}

/// Derives the AWS SigV4 signing key (`kSigning`).
pub fn derive_signing_key(
    secret_access_key: &str,
    date_stamp: &str,
    region: &str,
    service: &str,
) -> [u8; 32] {
    let mut secret = Vec::with_capacity(4 + secret_access_key.len());
    secret.extend_from_slice(b"AWS4");
    secret.extend_from_slice(secret_access_key.as_bytes());

    let k_date = hmac_sha256(&secret, date_stamp.as_bytes());
    let k_region = hmac_sha256(&k_date, region.as_bytes());
    let k_service = hmac_sha256(&k_region, service.as_bytes());
    hmac_sha256(&k_service, b"aws4_request")
}

/// Formats a Unix timestamp (seconds since 1970-01-01T00:00:00Z) into `(amz_date, date_stamp)`,
/// e.g. `("20150830T123600Z", "20150830")`.
pub fn format_amz_timestamps(unix_secs: u64) -> (String, String) {
    let days = (unix_secs / 86_400) as i64;
    let rem = unix_secs % 86_400;
    let hour = rem / 3_600;
    let minute = (rem % 3_600) / 60;
    let second = rem % 60;

    let (year, month, day) = civil_from_days(days);
    let date_stamp = format!("{year:04}{month:02}{day:02}");
    let amz_date = format!("{date_stamp}T{hour:02}{minute:02}{second:02}Z");
    (amz_date, date_stamp)
}

/// Howard Hinnant's civil-from-days algorithm (days since 1970-01-01 -> UTC (year, month, day)).
fn civil_from_days(days_since_epoch: i64) -> (i64, u32, u32) {
    let z = days_since_epoch + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = (yoe as i64) + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = if m <= 2 { y + 1 } else { y };
    (year, m as u32, d as u32)
}

/// Computes the AWS SigV4 canonical URI from a raw HTTP path.
///
/// When `double_encode` is `true` (required for all AWS services except S3, including Bedrock),
/// every non-unreserved byte (including `%` in already-encoded segments like `%3A`) is
/// percent-encoded again, turning `%3A` into `%253A`.
pub fn canonical_uri(raw_path: &str, double_encode: bool) -> String {
    if raw_path.is_empty() {
        return "/".to_owned();
    }
    let normalized = if raw_path.starts_with('/') {
        raw_path.to_owned()
    } else {
        format!("/{raw_path}")
    };

    if double_encode {
        aws_uri_encode(&normalized, false)
    } else {
        // Single-encode: preserve existing `%XX` escapes while encoding any raw unsafe bytes.
        let bytes = normalized.as_bytes();
        let mut out = String::with_capacity(bytes.len());
        let mut i = 0;
        while i < bytes.len() {
            let b = bytes[i];
            if b == b'/' || is_rfc3986_unreserved(b) {
                out.push(b as char);
                i += 1;
            } else if b == b'%'
                && i + 2 < bytes.len()
                && bytes[i + 1].is_ascii_hexdigit()
                && bytes[i + 2].is_ascii_hexdigit()
            {
                out.push('%');
                out.push((bytes[i + 1] as char).to_ascii_uppercase());
                out.push((bytes[i + 2] as char).to_ascii_uppercase());
                i += 3;
            } else {
                push_percent_byte(&mut out, b);
                i += 1;
            }
        }
        out
    }
}

/// Computes the AWS SigV4 canonical query string (sorted by parameter name, then value).
pub fn canonical_query_string(raw_query: Option<&str>) -> String {
    let Some(q) = raw_query.filter(|s| !s.is_empty()) else {
        return String::new();
    };
    let mut pairs: Vec<(String, String)> = q
        .split('&')
        .filter(|part| !part.is_empty())
        .map(|part| match part.split_once('=') {
            Some((k, v)) => (
                aws_uri_encode(&crate::types::percent_decode(k), true),
                aws_uri_encode(&crate::types::percent_decode(v), true),
            ),
            None => (
                aws_uri_encode(&crate::types::percent_decode(part), true),
                String::new(),
            ),
        })
        .collect();
    pairs.sort();
    pairs
        .into_iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect::<Vec<_>>()
        .join("&")
}

/// Low-level AWS SigV4 signer over explicit method, path, query, headers, payload, and timestamp.
///
/// `headers` is a list of `(header_name, header_value)` pairs to include in the signature
/// (names will be lowercased and sorted; whitespace in values is trimmed and collapsed).
#[allow(clippy::too_many_arguments)]
pub fn sign_canonical(
    creds: &AwsSigV4Credentials,
    method: &str,
    raw_path: &str,
    raw_query: Option<&str>,
    headers: &[(String, String)],
    payload: &[u8],
    unix_secs: u64,
    double_encode_path: bool,
) -> SigV4Output {
    let (amz_date, date_stamp) = format_amz_timestamps(unix_secs);
    let payload_sha256 = sha256_hex(payload);

    let mut norm_headers: Vec<(String, String)> = headers
        .iter()
        .map(|(k, v)| (k.trim().to_ascii_lowercase(), collapse_whitespace(v)))
        .collect();
    norm_headers.sort_by(|a, b| a.0.cmp(&b.0));

    // Merge duplicate header names with `,` per SigV4 spec.
    let mut merged: Vec<(String, String)> = Vec::with_capacity(norm_headers.len());
    for (k, v) in norm_headers {
        if let Some(last) = merged.last_mut()
            && last.0 == k
        {
            last.1.push(',');
            last.1.push_str(&v);
        } else {
            merged.push((k, v));
        }
    }

    let mut canonical_headers = String::new();
    let mut signed_header_names = Vec::with_capacity(merged.len());
    for (k, v) in &merged {
        let _ = writeln!(canonical_headers, "{k}:{v}");
        signed_header_names.push(k.as_str());
    }
    let signed_headers = signed_header_names.join(";");

    let canon_uri = canonical_uri(raw_path, double_encode_path);
    let canon_query = canonical_query_string(raw_query);

    let canonical_request = format!(
        "{}\n{}\n{}\n{}\n{}\n{}",
        method.to_ascii_uppercase(),
        canon_uri,
        canon_query,
        canonical_headers,
        signed_headers,
        payload_sha256
    );

    let credential_scope = format!(
        "{}/{}/{}/aws4_request",
        date_stamp, creds.region, creds.service
    );
    let canonical_request_hash = sha256_hex(canonical_request.as_bytes());
    let string_to_sign = format!(
        "AWS4-HMAC-SHA256\n{}\n{}\n{}",
        amz_date, credential_scope, canonical_request_hash
    );

    let signing_key = derive_signing_key(
        &creds.secret_access_key,
        &date_stamp,
        &creds.region,
        &creds.service,
    );
    let sig_bytes = hmac_sha256(&signing_key, string_to_sign.as_bytes());
    let signature = hex_lower(&sig_bytes);

    let authorization = format!(
        "AWS4-HMAC-SHA256 Credential={}/{}, SignedHeaders={}, Signature={}",
        creds.access_key_id, credential_scope, signed_headers, signature
    );

    SigV4Output {
        authorization,
        amz_date,
        payload_sha256,
        signed_headers,
        canonical_request,
        string_to_sign,
        signature,
    }
}

/// Derives the canonical `Host` header value from a resolved endpoint `Uri`, omitting default
/// ports (`80` for `http`, `443` for `https`) and preserving non-default ports (e.g., local mocks).
pub fn host_header_from_endpoint(endpoint_uri: &Uri) -> Result<String, String> {
    let authority = endpoint_uri
        .authority()
        .ok_or_else(|| format!("endpoint URI `{endpoint_uri}` is missing authority"))?;
    let scheme = endpoint_uri.scheme_str().unwrap_or("https");
    let host = authority.host();
    match authority.port_u16() {
        Some(port) if !((scheme == "https" && port == 443) || (scheme == "http" && port == 80)) => {
            Ok(format!("{host}:{port}"))
        }
        _ => Ok(host.to_owned()),
    }
}

/// Signs an [`UpstreamRequest`] in-place with AWS SigV4 headers (`x-amz-date`,
/// `x-amz-content-sha256`, optional `x-amz-security-token`, and `authorization`).
pub fn sign_upstream_request(
    req: &mut UpstreamRequest,
    creds: &AwsSigV4Credentials,
    now_unix_secs: Option<u64>,
) -> Result<SigV4Output, String> {
    let endpoint_uri = req.endpoint_uri.as_ref().ok_or_else(|| {
        "cannot sign AWS SigV4 request: UpstreamRequest.endpoint_uri is not set".to_owned()
    })?;
    let host = host_header_from_endpoint(endpoint_uri)?;

    // Combine endpoint base path (if any) with req.uri path, matching `shunt-engine::build_target_uri`.
    let base_path = endpoint_uri.path().trim_end_matches('/');
    let req_path = req.uri.path();
    let full_path = if base_path.is_empty() || base_path == "/" {
        if req_path.starts_with('/') {
            req_path.to_owned()
        } else {
            format!("/{req_path}")
        }
    } else if req_path.starts_with('/') {
        format!("{base_path}{req_path}")
    } else {
        format!("{base_path}/{req_path}")
    };

    let unix_secs = now_unix_secs.unwrap_or_else(|| {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    });

    let payload = req.body.as_deref().unwrap_or(&[]);
    let (amz_date, _) = format_amz_timestamps(unix_secs);
    let payload_sha256 = sha256_hex(payload);

    let mut headers_to_sign = vec![
        ("host".to_owned(), host.clone()),
        ("x-amz-content-sha256".to_owned(), payload_sha256.clone()),
        ("x-amz-date".to_owned(), amz_date.clone()),
    ];
    if let Some(ct) = req
        .headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
    {
        headers_to_sign.push(("content-type".to_owned(), ct.to_owned()));
    }
    if let Some(token) = &creds.session_token {
        headers_to_sign.push(("x-amz-security-token".to_owned(), token.clone()));
    }

    let double_encode = !creds.service.eq_ignore_ascii_case("s3");
    let signed = sign_canonical(
        creds,
        req.method.as_str(),
        &full_path,
        req.uri.query(),
        &headers_to_sign,
        payload,
        unix_secs,
        double_encode,
    );

    if let Ok(v) = HeaderValue::from_str(&signed.amz_date) {
        req.headers.insert(HeaderName::from_static("x-amz-date"), v);
    }
    if let Ok(v) = HeaderValue::from_str(&signed.payload_sha256) {
        req.headers
            .insert(HeaderName::from_static("x-amz-content-sha256"), v);
    }
    if let Some(token) = &creds.session_token
        && let Ok(v) = HeaderValue::from_str(token)
    {
        req.headers
            .insert(HeaderName::from_static("x-amz-security-token"), v);
    }
    let auth_val = HeaderValue::from_str(&signed.authorization)
        .map_err(|e| format!("invalid Authorization header value: {e}"))?;
    req.headers.insert(header::AUTHORIZATION, auth_val);

    Ok(signed)
}

fn aws_uri_encode(input: &str, encode_slash: bool) -> String {
    let mut out = String::with_capacity(input.len());
    for &b in input.as_bytes() {
        if is_rfc3986_unreserved(b) || (!encode_slash && b == b'/') {
            out.push(b as char);
        } else {
            push_percent_byte(&mut out, b);
        }
    }
    out
}

fn push_percent_byte(out: &mut String, b: u8) {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    out.push('%');
    out.push(HEX[(b >> 4) as usize] as char);
    out.push(HEX[(b & 0x0F) as usize] as char);
}

fn collapse_whitespace(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut in_ws = false;
    for ch in s.trim().chars() {
        if ch.is_ascii_whitespace() {
            if !in_ws {
                out.push(' ');
                in_ws = true;
            }
        } else {
            out.push(ch);
            in_ws = false;
        }
    }
    out
}

fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0F) as usize] as char);
    }
    out
}

#[cfg(test)]
mod tests {
    use shunt_plugin_sdk::{Bytes, HeaderMap, Method};

    use super::*;

    /// Official AWS Signature Version 4 test suite vector: `get-vanilla`.
    #[test]
    fn official_aws_sigv4_get_vanilla_vector() {
        // 2015-08-30T12:36:00Z = 1440938160
        let unix_secs = 1_440_938_160;
        assert_eq!(
            format_amz_timestamps(unix_secs),
            ("20150830T123600Z".to_owned(), "20150830".to_owned())
        );

        let creds = AwsSigV4Credentials {
            access_key_id: "AKIDEXAMPLE".to_owned(),
            secret_access_key: "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY".to_owned(),
            session_token: None,
            region: "us-east-1".to_owned(),
            service: "service".to_owned(),
        };

        let headers = vec![
            ("Host".to_owned(), "example.amazonaws.com".to_owned()),
            ("X-Amz-Date".to_owned(), "20150830T123600Z".to_owned()),
        ];

        let out = sign_canonical(&creds, "GET", "/", None, &headers, b"", unix_secs, true);
        assert_eq!(
            out.signature,
            "5fa00fa31553b73ebf1942676e86291e8372ff2a2260956d9b8aae1d763fbf31"
        );
        assert_eq!(
            out.authorization,
            "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/service/aws4_request, SignedHeaders=host;x-amz-date, Signature=5fa00fa31553b73ebf1942676e86291e8372ff2a2260956d9b8aae1d763fbf31"
        );
    }

    /// Official AWS Signature Version 4 documentation example (IAM ListUsers).
    #[test]
    fn official_aws_sigv4_iam_docs_vector() {
        let unix_secs = 1_440_938_160; // 2015-08-30T12:36:00Z
        let creds = AwsSigV4Credentials {
            access_key_id: "AKIDEXAMPLE".to_owned(),
            secret_access_key: "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY".to_owned(),
            session_token: None,
            region: "us-east-1".to_owned(),
            service: "iam".to_owned(),
        };

        let headers = vec![
            (
                "Content-Type".to_owned(),
                "application/x-www-form-urlencoded; charset=utf-8".to_owned(),
            ),
            ("Host".to_owned(), "iam.amazonaws.com".to_owned()),
            ("X-Amz-Date".to_owned(), "20150830T123600Z".to_owned()),
        ];

        let out = sign_canonical(
            &creds,
            "GET",
            "/",
            Some("Action=ListUsers&Version=2010-05-08"),
            &headers,
            b"",
            unix_secs,
            true,
        );
        assert_eq!(
            sha256_hex(out.canonical_request.as_bytes()),
            "f536975d06c0309214f805bb90ccff089219ecd68b2577efef23edd43b7e1a59"
        );
        assert_eq!(
            hex_lower(&derive_signing_key(
                &creds.secret_access_key,
                "20150830",
                "us-east-1",
                "iam"
            )),
            "c4afb1cc5771d871763a393e44b703571b55cc28424d1a5e86da6ed3c154a4b9"
        );
        assert_eq!(
            out.signature,
            "5d672d79c15b13162d9279b0855cfba6789a8edb4c82c400e06b5924a6f2b5d7"
        );
    }

    #[test]
    fn bedrock_double_encodes_model_colon_and_preserves_mock_port() {
        let creds = AwsSigV4Credentials {
            access_key_id: "AKIAIOSFODNN7EXAMPLE".to_owned(),
            secret_access_key: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY".to_owned(),
            session_token: Some("AQoDYXdzEJr".to_owned()),
            region: "us-east-1".to_owned(),
            service: "bedrock".to_owned(),
        };

        let mut headers = HeaderMap::new();
        headers.insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/json"),
        );

        let mut up_req = UpstreamRequest {
            method: Method::POST,
            uri: "/model/anthropic.claude-3-5-sonnet-20241022-v2%3A0/converse"
                .parse()
                .unwrap(),
            headers,
            body: Some(Bytes::from_static(br#"{"messages":[]}"#)),
            endpoint_uri: Some("http://127.0.0.1:18080".parse().unwrap()),
        };

        let signed = sign_upstream_request(&mut up_req, &creds, Some(1_700_000_000)).unwrap();
        assert!(
            signed
                .canonical_request
                .contains("/model/anthropic.claude-3-5-sonnet-20241022-v2%253A0/converse")
        );
        assert!(signed.canonical_request.contains("host:127.0.0.1:18080\n"));
        assert!(
            signed
                .authorization
                .starts_with("AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20231114/us-east-1/bedrock/aws4_request,")
        );
        assert_eq!(
            signed.signed_headers,
            "content-type;host;x-amz-content-sha256;x-amz-date;x-amz-security-token"
        );
        assert!(up_req.headers.contains_key(header::AUTHORIZATION));
        assert!(up_req.headers.contains_key("x-amz-date"));
        assert!(up_req.headers.contains_key("x-amz-content-sha256"));
        assert_eq!(
            up_req.headers.get("x-amz-security-token").unwrap(),
            "AQoDYXdzEJr"
        );
    }

    #[test]
    fn host_header_omits_default_ports() {
        let https_default: Uri = "https://bedrock-runtime.us-east-1.amazonaws.com:443"
            .parse()
            .unwrap();
        assert_eq!(
            host_header_from_endpoint(&https_default).unwrap(),
            "bedrock-runtime.us-east-1.amazonaws.com"
        );

        let http_custom: Uri = "http://127.0.0.1:9999".parse().unwrap();
        assert_eq!(
            host_header_from_endpoint(&http_custom).unwrap(),
            "127.0.0.1:9999"
        );
    }
}
