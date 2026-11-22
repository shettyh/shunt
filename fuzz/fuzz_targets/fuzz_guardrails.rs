#![no_main]

use libfuzzer_sys::fuzz_target;
use shunt_ai::{
    GuardrailAction, LocalRedactor, RedactionMode, extract_request_text, extract_response_text,
    is_valid_ipv4, is_valid_luhn, is_valid_ssn, parse_bedrock_guardrail_response,
    parse_lakera_guardrail_response, parse_llama_guard_response, parse_opa_guardrail_response,
    parse_presidio_analyze_response, parse_webhook_guardrail_response,
};

fuzz_target!(|data: &[u8]| {
    let _ = parse_webhook_guardrail_response(data, GuardrailAction::Block);
    let _ = parse_opa_guardrail_response(data, GuardrailAction::Block);
    let _ = parse_presidio_analyze_response(data, 0.5, GuardrailAction::Redact);
    let _ = parse_lakera_guardrail_response(data, GuardrailAction::Block);
    let _ = parse_bedrock_guardrail_response(data, GuardrailAction::Block);
    let _ = parse_llama_guard_response(data, GuardrailAction::Block);
    let _ = extract_request_text(data, &[]);
    let _ = extract_response_text(data);

    if let Ok(s) = std::str::from_utf8(data) {
        let _ = is_valid_luhn(s);
        let _ = is_valid_ssn(s);
        let _ = is_valid_ipv4(s);
        if let Ok(redactor) = LocalRedactor::new(true, true, &[], RedactionMode::Mask) {
            let _ = redactor.redact_text(s);
        }
    }
});
