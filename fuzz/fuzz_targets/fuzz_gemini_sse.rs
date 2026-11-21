#![no_main]

use http::StatusCode;
use libfuzzer_sys::fuzz_target;
use shunt_ai::dialects::gemini::{
    GeminiSseTranslator, gemini_to_openai_embeddings_response, gemini_to_openai_response,
    openai_to_gemini_embeddings_request, openai_to_gemini_request,
};

fuzz_target!(|data: &[u8]| {
    let _ = openai_to_gemini_request(data);
    let _ = openai_to_gemini_embeddings_request(data, "text-embedding-004", false);
    let _ = openai_to_gemini_embeddings_request(data, "text-embedding-004", true);
    let _ = gemini_to_openai_response(data, StatusCode::OK, "gemini-2.5-flash");
    let _ = gemini_to_openai_response(data, StatusCode::BAD_REQUEST, "gemini-2.5-flash");
    let _ = gemini_to_openai_embeddings_response(data, StatusCode::OK, "text-embedding-004");

    let mut translator = GeminiSseTranslator::new("gemini-2.5-flash");
    for chunk in data.chunks(11) {
        let _ = translator.push_chunk(chunk);
    }
    let _ = translator.finish();
});
