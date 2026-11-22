#![no_main]

use libfuzzer_sys::fuzz_target;
use shunt_mcp::{
    BuiltinMcpDetector, canonical_json_bytes, extract_mcp_response_payloads, glob_match,
    lookup_json_dot_path, parse_mcp_jsonrpc_request, redact_text_for_detector,
    scan_text_for_detector, split_namespaced,
};

fuzz_target!(|data: &[u8]| {
    let _ = parse_mcp_jsonrpc_request(data, false);
    let _ = parse_mcp_jsonrpc_request(data, true);
    let _ = extract_mcp_response_payloads(Some("application/json"), data);
    let _ = extract_mcp_response_payloads(Some("text/event-stream"), data);

    if let Ok(text) = std::str::from_utf8(data) {
        let _ = split_namespaced(text, "__");
        let _ = glob_match("*delete*", text);
        for det in [
            BuiltinMcpDetector::Email,
            BuiltinMcpDetector::Ssn,
            BuiltinMcpDetector::CreditCard,
            BuiltinMcpDetector::AwsKey,
            BuiltinMcpDetector::ApiKey,
            BuiltinMcpDetector::PrivateKey,
            BuiltinMcpDetector::Jwt,
            BuiltinMcpDetector::PromptInjection,
        ] {
            if scan_text_for_detector(det, text) {
                let _ = redact_text_for_detector(det, text);
            }
        }
        if let Ok(val) = serde_json::from_str::<serde_json::Value>(text) {
            let _ = canonical_json_bytes(&val);
            let _ = lookup_json_dot_path(&val, "params.arguments.sql");
        }
    }
});
