#![no_main]
use libfuzzer_sys::fuzz_target;
use shunt_plugins::{
    ContentEncoding, IpNet, negotiate_accept_encoding, parse_jwks_json, parse_jwt_unverified,
    parse_spki_pem_public_key,
};

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        let _ = parse_jwt_unverified(s);
        let _ = parse_jwks_json(s);
        let _ = parse_spki_pem_public_key(s);
        let _ = IpNet::parse(s);
        let _ = negotiate_accept_encoding(
            s,
            &[
                ContentEncoding::Zstd,
                ContentEncoding::Br,
                ContentEncoding::Gzip,
            ],
        );
    }
});
