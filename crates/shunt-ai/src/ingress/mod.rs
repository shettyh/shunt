//! Multi-protocol AI ingress translators (RFC 0008).
//!
//! Converts non-Chat-Completions client frontends (`POST /v1/messages` Anthropic Messages API
//! and `POST /v1/responses` OpenAI Responses API) to and from Shunt's canonical OpenAI Chat
//! Completions wire IR so any ingress frontend can route to and fail over across any configured
//! upstream provider dialect without N x M translator explosion.

pub mod anthropic;
pub mod responses;

use serde_json::Value;

pub(crate) fn write_named_sse_json(out: &mut Vec<u8>, event_name: &str, val: &Value) {
    out.extend_from_slice(b"event: ");
    out.extend_from_slice(event_name.as_bytes());
    out.extend_from_slice(b"\ndata: ");
    if let Ok(encoded) = serde_json::to_vec(val) {
        out.extend_from_slice(&encoded);
    }
    out.extend_from_slice(b"\n\n");
}
