//! Zero-dependency, binary-safe RFC 7578 `multipart/form-data` parser and text-field rewriter.
//!
//! Used by `ai-model-router` and `ai-provider-adapter` for multipart AI endpoints
//! (`/v1/audio/transcriptions`, `/v1/audio/translations`, `/v1/images/edits`,
//! `/v1/images/variations`, `/v1/files`) so model aliases can be extracted, ACL-checked,
//! and rewritten without corrupting arbitrary binary audio/image/file parts.

/// Extracts the multipart boundary token from a `Content-Type` header value.
///
/// Accepts `multipart/form-data; boundary=abc`, `multipart/form-data; boundary="abc"`,
/// case-insensitive media/parameter names, and extra parameters (e.g., `charset=utf-8`).
pub fn parse_multipart_boundary(content_type: &str) -> Option<String> {
    let mut parts = content_type.split(';');
    let media_type = parts.next()?.trim();
    if !media_type.eq_ignore_ascii_case("multipart/form-data") {
        return None;
    }

    for param in parts {
        let param = param.trim();
        let Some((key, raw_val)) = param.split_once('=') else {
            continue;
        };
        if !key.trim().eq_ignore_ascii_case("boundary") {
            continue;
        }
        let val = raw_val.trim();
        let unquoted = if val.len() >= 2 && val.starts_with('"') && val.ends_with('"') {
            &val[1..val.len() - 1]
        } else {
            val
        };
        if !unquoted.is_empty() && unquoted.len() <= 200 && unquoted.is_ascii() {
            return Some(unquoted.to_owned());
        }
    }
    None
}

/// Byte span of a parsed multipart part's value payload inside the original body buffer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FieldValueSpan {
    start: usize,
    end: usize,
}

/// Finds the exact byte range of the first form-data part whose `name` matches `field_name`
/// (and does not carry a `filename` parameter, so file upload parts are never confused with
/// form fields).
fn find_text_field_span(body: &[u8], boundary: &str, field_name: &str) -> Option<FieldValueSpan> {
    if boundary.is_empty() || field_name.is_empty() || body.is_empty() {
        return None;
    }

    let mut delim = Vec::with_capacity(boundary.len() + 2);
    delim.extend_from_slice(b"--");
    delim.extend_from_slice(boundary.as_bytes());

    let mut pos = find_subslice(body, &delim, 0)?;

    while pos + delim.len() <= body.len() {
        let after_delim = pos + delim.len();
        // Closing boundary: `--<boundary>--`
        if body[after_delim..].starts_with(b"--") {
            break;
        }

        // Advance past line break after boundary (`\r\n` or `\n`).
        let part_headers_start = if body[after_delim..].starts_with(b"\r\n") {
            after_delim + 2
        } else if body[after_delim..].starts_with(b"\n") {
            after_delim + 1
        } else {
            // Spurious match not followed by CRLF/LF or `--`: search further.
            match find_subslice(body, &delim, after_delim) {
                Some(next) => {
                    pos = next;
                    continue;
                }
                None => break,
            }
        };

        // Find end of part headers (`\r\n\r\n` or `\n\n`).
        let (headers_end, value_start) =
            if let Some(rel) = find_header_body_separator(&body[part_headers_start..]) {
                (part_headers_start + rel.0, part_headers_start + rel.1)
            } else {
                break;
            };

        // Find the next boundary delimiter preceded by `\r\n` or `\n` (or directly at start).
        let Some((value_end, next_boundary_pos)) = find_next_boundary(body, &delim, value_start)
        else {
            break;
        };

        let headers_bytes = &body[part_headers_start..headers_end];
        if headers_match_text_field(headers_bytes, field_name) {
            return Some(FieldValueSpan {
                start: value_start,
                end: value_end,
            });
        }

        pos = next_boundary_pos;
    }

    None
}

/// Extracts the UTF-8 trimmed text value of form field `field_name` from a `multipart/form-data`
/// request body. Binary parts (e.g., audio/image files) are skipped untouched.
pub fn extract_multipart_text_field(
    body: &[u8],
    boundary: &str,
    field_name: &str,
) -> Option<String> {
    let span = find_text_field_span(body, boundary, field_name)?;
    let raw = std::str::from_utf8(&body[span.start..span.end]).ok()?;
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_owned())
    }
}

/// Rewrites the value of text form field `field_name` in a `multipart/form-data` body to
/// `new_value`, returning `Some(rewritten)` only when the field existed and its value changed.
///
/// All other parts (including arbitrary binary payloads, headers, line endings, and boundaries)
/// are preserved byte-for-byte.
pub fn rewrite_multipart_text_field(
    body: &[u8],
    boundary: &str,
    field_name: &str,
    new_value: &str,
) -> Option<Vec<u8>> {
    let span = find_text_field_span(body, boundary, field_name)?;
    let current = &body[span.start..span.end];
    if current == new_value.as_bytes() {
        return None;
    }
    let mut out = Vec::with_capacity(
        body.len()
            .saturating_sub(span.end - span.start)
            .saturating_add(new_value.len()),
    );
    out.extend_from_slice(&body[..span.start]);
    out.extend_from_slice(new_value.as_bytes());
    out.extend_from_slice(&body[span.end..]);
    Some(out)
}

fn find_header_body_separator(slice: &[u8]) -> Option<(usize, usize)> {
    let crlf = find_subslice(slice, b"\r\n\r\n", 0).map(|idx| (idx, idx + 4));
    let lf = find_subslice(slice, b"\n\n", 0).map(|idx| (idx, idx + 2));
    match (crlf, lf) {
        (Some(a), Some(b)) => Some(if a.0 <= b.0 { a } else { b }),
        (Some(a), None) => Some(a),
        (None, Some(b)) => Some(b),
        (None, None) => None,
    }
}

fn find_next_boundary(body: &[u8], delim: &[u8], start: usize) -> Option<(usize, usize)> {
    let mut search_from = start;
    while let Some(idx) = find_subslice(body, delim, search_from) {
        // RFC 7578: the preceding CRLF (or LF) belongs to the boundary delimiter, not the body.
        if idx >= start + 2 && &body[idx - 2..idx] == b"\r\n" {
            let after = idx + delim.len();
            if is_valid_boundary_terminator(&body[after..]) {
                return Some((idx - 2, idx));
            }
        } else if idx > start && body[idx - 1] == b'\n' {
            let after = idx + delim.len();
            if is_valid_boundary_terminator(&body[after..]) {
                return Some((idx - 1, idx));
            }
        } else if idx == start {
            let after = idx + delim.len();
            if is_valid_boundary_terminator(&body[after..]) {
                return Some((start, idx));
            }
        }
        search_from = idx + 1;
    }
    None
}

fn is_valid_boundary_terminator(tail: &[u8]) -> bool {
    tail.is_empty()
        || tail.starts_with(b"\r\n")
        || tail.starts_with(b"\n")
        || tail.starts_with(b"--")
}

fn headers_match_text_field(headers_bytes: &[u8], field_name: &str) -> bool {
    let Ok(headers_str) = std::str::from_utf8(headers_bytes) else {
        return false;
    };
    for line in headers_str.lines() {
        let line = line.trim_end_matches('\r');
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        if !name.trim().eq_ignore_ascii_case("content-disposition") {
            continue;
        }
        let mut matched_name = false;
        let mut has_filename = false;
        for part in value.split(';').skip(1) {
            let part = part.trim();
            let Some((k, v)) = part.split_once('=') else {
                continue;
            };
            let key = k.trim();
            let val = unquote_param(v.trim());
            if key.eq_ignore_ascii_case("name") && val == field_name {
                matched_name = true;
            } else if key.eq_ignore_ascii_case("filename") {
                has_filename = true;
            }
        }
        if matched_name && !has_filename {
            return true;
        }
    }
    false
}

fn unquote_param(val: &str) -> &str {
    if val.len() >= 2 && val.starts_with('"') && val.ends_with('"') {
        &val[1..val.len() - 1]
    } else {
        val
    }
}

fn find_subslice(haystack: &[u8], needle: &[u8], from: usize) -> Option<usize> {
    if needle.is_empty() || from >= haystack.len() || needle.len() > haystack.len() - from {
        return None;
    }
    haystack[from..]
        .windows(needle.len())
        .position(|w| w == needle)
        .map(|rel| from + rel)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_quoted_and_unquoted_boundaries() {
        assert_eq!(
            parse_multipart_boundary("multipart/form-data; boundary=----ShuntBound123"),
            Some("----ShuntBound123".to_owned())
        );
        assert_eq!(
            parse_multipart_boundary(r#"MULTIPART/FORM-DATA; charset=utf-8; BOUNDARY="abc-999""#),
            Some("abc-999".to_owned())
        );
        assert_eq!(parse_multipart_boundary("application/json"), None);
        assert_eq!(
            parse_multipart_boundary("multipart/form-data; boundary="),
            None
        );
    }

    #[test]
    fn extracts_and_rewrites_model_preserving_binary_part() {
        let boundary = "ShuntBoundary42";
        let binary_audio: Vec<u8> = (0u8..=255).collect();
        let mut body = Vec::new();
        body.extend_from_slice(
            format!(
                "--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"clip.wav\"\r\nContent-Type: audio/wav\r\n\r\n"
            )
            .as_bytes(),
        );
        body.extend_from_slice(&binary_audio);
        body.extend_from_slice(
            format!(
                "\r\n--{boundary}\r\nContent-Disposition: form-data; name=\"model\"\r\n\r\nfast-whisper\r\n--{boundary}--\r\n"
            )
            .as_bytes(),
        );

        assert_eq!(
            extract_multipart_text_field(&body, boundary, "model").as_deref(),
            Some("fast-whisper")
        );
        // Binary file part with name="file" and filename="clip.wav" is not treated as a text field.
        assert_eq!(extract_multipart_text_field(&body, boundary, "file"), None);

        let rewritten =
            rewrite_multipart_text_field(&body, boundary, "model", "whisper-large-v3").unwrap();
        assert_eq!(
            extract_multipart_text_field(&rewritten, boundary, "model").as_deref(),
            Some("whisper-large-v3")
        );
        // Confirm every binary byte survived intact.
        assert!(
            rewritten
                .windows(binary_audio.len())
                .any(|w| w == binary_audio.as_slice())
        );

        // No-op rewrite returns None.
        assert_eq!(
            rewrite_multipart_text_field(&rewritten, boundary, "model", "whisper-large-v3"),
            None
        );
    }

    #[test]
    fn handles_lf_only_and_malformed_payloads_safely() {
        let boundary = "bnd";
        let body =
            b"--bnd\nContent-Disposition: form-data; name=\"model\"\n\ngpt-image-1\n--bnd--\n";
        assert_eq!(
            extract_multipart_text_field(body, boundary, "model").as_deref(),
            Some("gpt-image-1")
        );
        assert_eq!(
            extract_multipart_text_field(b"garbage", boundary, "model"),
            None
        );
        assert_eq!(
            rewrite_multipart_text_field(b"--bnd\r\nno-end", boundary, "model", "x"),
            None
        );
    }
}
