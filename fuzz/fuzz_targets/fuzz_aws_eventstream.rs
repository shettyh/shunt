#![no_main]

use http::StatusCode;
use libfuzzer_sys::fuzz_target;
use shunt_ai::aws_eventstream::AwsEventStreamDecoder;
use shunt_ai::dialects::bedrock::{
    BedrockStreamTranslator, bedrock_converse_to_openai_response,
    openai_to_bedrock_converse_request,
};

fuzz_target!(|data: &[u8]| {
    let _ = openai_to_bedrock_converse_request(data);
    let _ = bedrock_converse_to_openai_response(
        data,
        StatusCode::OK,
        "anthropic.claude-3-5-sonnet-20241022-v2:0",
    );
    let _ = bedrock_converse_to_openai_response(
        data,
        StatusCode::BAD_REQUEST,
        "anthropic.claude-3-5-sonnet-20241022-v2:0",
    );

    let mut dec = AwsEventStreamDecoder::new();
    for chunk in data.chunks(5) {
        let _ = dec.push(chunk);
    }

    let mut translator = BedrockStreamTranslator::new("anthropic.claude-3-5-sonnet-20241022-v2:0");
    for chunk in data.chunks(7) {
        let _ = translator.push_chunk(chunk);
    }
    let _ = translator.finish();
});
