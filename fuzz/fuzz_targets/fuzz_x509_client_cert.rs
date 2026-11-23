#![no_main]
use libfuzzer_sys::fuzz_target;
use shunt_engine::parse_client_cert_info;

fuzz_target!(|data: &[u8]| {
    let _ = parse_client_cert_info(data);
});
