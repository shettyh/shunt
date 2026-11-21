#![no_main]

use http::StatusCode;
use libfuzzer_sys::fuzz_target;
use shunt_ai::translate::{
    AnthropicSseTranslator, anthropic_to_openai_response, openai_to_anthropic_request,
    rewrite_openai_request,
};

fuzz_target!(|data: &[u8]| {
    let _ = rewrite_openai_request(data, "gpt-4o", true);
    let _ = openai_to_anthropic_request(data, "claude-3-5-sonnet-20241022", 1024);
    let _ = anthropic_to_openai_response(data, StatusCode::OK, "claude-3-5-sonnet-20241022");
    let _ = anthropic_to_openai_response(
        data,
        StatusCode::BAD_REQUEST,
        "claude-3-5-sonnet-20241022",
    );

    let mut translator = AnthropicSseTranslator::new("claude-3-5-sonnet-20241022");
    for chunk in data.chunks(7) {
        let _ = translator.push_chunk(chunk);
    }
    let _ = translator.finish();
});
