#![no_main]

use libfuzzer_sys::fuzz_target;
use shunt_core::{RespValue, decode_resp_frame, encode_resp_value};

fuzz_target!(|data: &[u8]| {
    // 1. Arbitrary bytes must never panic or OOM the RESP2 frame decoder.
    let mut cursor = 0;
    while cursor < data.len() {
        match decode_resp_frame(&data[cursor..]) {
            Ok(Some((val, consumed))) => {
                if consumed == 0 {
                    break;
                }
                let mut reencoded = Vec::new();
                encode_resp_value(&val, &mut reencoded);
                let decoded = decode_resp_frame(&reencoded);
                assert!(matches!(decoded, Ok(Some((ref v, c))) if *v == val && c == reencoded.len()));
                cursor += consumed;
            }
            Ok(None) | Err(_) => break,
        }
    }

    // 2. Also exercise RespValue helpers on a bulk string constructed from fuzz bytes.
    let mut wire = Vec::new();
    encode_resp_value(&RespValue::BulkString(Some(data.to_vec())), &mut wire);
    let _ = decode_resp_frame(&wire);
});
