#![no_main]

use libfuzzer_sys::fuzz_target;
use shunt_ai::ingress::responses::{
    ChatToResponsesSseTranslator, chat_to_responses_response, responses_to_chat_request,
};

fuzz_target!(|data: &[u8]| {
    // 1. Streaming SSE translator must never panic on arbitrary byte splits.
    let mut tr = ChatToResponsesSseTranslator::new("fuzz-model");
    for chunk in data.chunks(19) {
        let _ = tr.push_chunk(chunk);
    }
    let _ = tr.finish();

    // 2. Request & non-streaming JSON translators must never panic on arbitrary bytes.
    let _ = responses_to_chat_request(data, "fuzz-model");
    let _ = chat_to_responses_response(data, http::StatusCode::OK, "fuzz-model");
});
