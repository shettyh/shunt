#![no_main]

use libfuzzer_sys::fuzz_target;
use shunt_plugin_sdk::StatusCode;

fuzz_target!(|data: &[u8]| {
    let as_str = String::from_utf8_lossy(data);
    let _ = shunt_ai::parse_multipart_boundary(&as_str);
    let _ = shunt_ai::extract_multipart_text_field(data, "shunt-boundary", "model");
    let _ = shunt_ai::rewrite_multipart_text_field(data, "shunt-boundary", "model", "whisper-1");

    let _ = shunt_ai::extract_query_param(Some(&as_str), "model");
    let _ = shunt_ai::extract_query_param(Some(&as_str), "id");

    let _ = shunt_ai::extract_rerank_context(data);
    let _ = shunt_ai::rewrite_rerank_request(data, "rerank-v3");
    let _ = shunt_ai::openai_to_bedrock_rerank_request(data, "amazon.rerank-v1:0", "us-east-1");
    let _ = shunt_ai::bedrock_to_openai_rerank_response(data, StatusCode::OK, "amazon.rerank-v1:0", None);
    let _ = shunt_ai::normalize_voyage_rerank_response(data, StatusCode::OK, "rerank-2");

    let _ = shunt_ai::openai_to_gemini_imagen_request(data);
    let _ = shunt_ai::gemini_imagen_to_openai_response(data, StatusCode::OK);
    let _ = shunt_ai::rewrite_openai_completions_request(data, "gpt-3.5-turbo-instruct", true);
    let _ = shunt_ai::parse_embedding_vector(data);
});
