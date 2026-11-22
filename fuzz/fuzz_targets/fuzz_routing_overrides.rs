#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let as_str = String::from_utf8_lossy(data);
    let _ = shunt_ai::parse_external_pricing_json(&as_str);
    let _ = shunt_ai::is_context_overflow_error(400, data);
    let _ = shunt_ai::is_context_overflow_error(413, data);
    let _ = shunt_ai::is_context_overflow_error(422, data);
    let _ = serde_json::from_slice::<shunt_ai::ProviderRoutingPreferences>(data);
    if let Ok(v) = serde_json::from_slice::<serde_json::Value>(data) {
        let _ = shunt_ai::extract_end_user_from_body(&v);
    }
});
