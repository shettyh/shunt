#![no_main]

use libfuzzer_sys::fuzz_target;
use shunt_ai::{
    base64_std_decode, decode_pem_pkcs8_private_key, parse_aws_json_credentials,
    parse_aws_sts_xml_credentials, parse_oauth_bearer_response, parse_rfc3339_utc_secs,
};

fuzz_target!(|data: &[u8]| {
    if let Ok(text) = std::str::from_utf8(data) {
        let _ = parse_rfc3339_utc_secs(text);
        let _ = parse_aws_sts_xml_credentials(text);
        let _ = decode_pem_pkcs8_private_key(text);
        let _ = base64_std_decode(text);
    }
    let _ = parse_aws_json_credentials(data);
    let _ = parse_oauth_bearer_response(data, "fuzz");
});
