#![no_main]

use libfuzzer_sys::fuzz_target;
use shunt_ai::ingress::anthropic::{
    OpenAiToAnthropicSseTranslator, anthropic_to_openai_request, openai_to_anthropic_response,
};

fuzz_target!(|data: &[u8]| {
    // 1. Streaming SSE translator must never panic on arbitrary byte splits.
    let mut tr = OpenAiToAnthropicSseTranslator::new("fuzz-model");
    for chunk in data.chunks(17) {
        let _ = tr.push_chunk(chunk);
    }
    let _ = tr.finish();

    // 2. Request & non-streaming JSON translators must never panic on arbitrary bytes.
    let _ = anthropic_to_openai_request(data, "fuzz-model");
    let _ = openai_to_anthropic_response(data, http::StatusCode::OK, "fuzz-model");
});
