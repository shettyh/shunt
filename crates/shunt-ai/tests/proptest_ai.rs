use std::collections::HashMap;
use std::time::Duration;

use proptest::prelude::*;
use serde_json::{Value, json};
use shunt_ai::aws_eventstream::{AwsEventStreamDecoder, encode_eventstream_frame};
use shunt_ai::dialects::bedrock::{BedrockStreamTranslator, openai_to_bedrock_converse_request};
use shunt_ai::dialects::gemini::{GeminiSseTranslator, openai_to_gemini_request};
use shunt_ai::failover::{FailoverCircuitState, compute_cooldown};
use shunt_ai::ingress::anthropic::{
    OpenAiToAnthropicSseTranslator, anthropic_to_openai_request, openai_to_anthropic_response,
};
use shunt_ai::ingress::responses::{
    ChatToResponsesSseTranslator, chat_to_responses_response, responses_to_chat_request,
};
use shunt_ai::sse::SseParser;
use shunt_ai::translate::{AnthropicSseTranslator, openai_to_anthropic_request};
use shunt_plugin_sdk::{Clock, ManualClock};

fn partition_bytes(bytes: &[u8], sizes: &[usize]) -> Vec<Vec<u8>> {
    let mut chunks = Vec::new();
    let mut idx = 0;
    for &sz in sizes {
        if idx >= bytes.len() {
            break;
        }
        let end = (idx + sz).min(bytes.len());
        chunks.push(bytes[idx..end].to_vec());
        idx = end;
    }
    if idx < bytes.len() {
        chunks.push(bytes[idx..].to_vec());
    }
    chunks
}

fn arb_sse_line() -> impl Strategy<Value = String> {
    prop_oneof![
        "[a-zA-Z0-9_.-]{0,16}".prop_map(|e| format!("event: {e}")),
        "[a-zA-Z0-9_ .,{}\":\\-\\u{00E9}\\u{1F600}]{0,32}".prop_map(|d| format!("data: {d}")),
        "[a-zA-Z0-9_ ]{0,20}".prop_map(|c| format!(": {c}")),
        "[a-z]{1,8}: [a-z0-9]{0,8}",
        Just(String::new()),
    ]
}

fn arb_eol() -> impl Strategy<Value = &'static str> {
    prop_oneof![Just("\n"), Just("\r\n"), Just("\r")]
}

fn arb_sse_stream() -> impl Strategy<Value = Vec<u8>> {
    (
        any::<bool>(),
        prop::collection::vec((arb_sse_line(), arb_eol()), 0..25),
    )
        .prop_map(|(with_bom, lines)| {
            let mut out = Vec::new();
            if with_bom {
                out.extend_from_slice(&[0xEF, 0xBB, 0xBF]);
            }
            for (line, eol) in lines {
                out.extend_from_slice(line.as_bytes());
                out.extend_from_slice(eol.as_bytes());
            }
            out
        })
}

proptest! {
    #[test]
    fn sse_parser_chunk_split_invariance_structured(
        stream in arb_sse_stream(),
        chunk_sizes in prop::collection::vec(0usize..8, 0..64),
    ) {
        let mut whole = SseParser::new();
        let mut whole_events = whole.push(&stream);
        whole_events.extend(whole.finish());

        let mut chunked = SseParser::new();
        let mut chunked_events = Vec::new();
        for c in partition_bytes(&stream, &chunk_sizes) {
            chunked_events.extend(chunked.push(&c));
        }
        chunked_events.extend(chunked.finish());

        prop_assert_eq!(&whole_events, &chunked_events);

        // Also check 1-byte-at-a-time split!
        let mut byte_by_byte = SseParser::new();
        let mut b_events = Vec::new();
        for &b in &stream {
            b_events.extend(byte_by_byte.push(&[b]));
        }
        b_events.extend(byte_by_byte.finish());

        prop_assert_eq!(whole_events, b_events);
    }

    #[test]
    fn sse_parser_arbitrary_bytes_never_panics_and_is_chunk_invariant(
        stream in prop::collection::vec(any::<u8>(), 0..256),
        chunk_sizes in prop::collection::vec(0usize..12, 0..64),
    ) {
        let mut whole = SseParser::new();
        let mut whole_events = whole.push(&stream);
        whole_events.extend(whole.finish());

        let mut chunked = SseParser::new();
        let mut chunked_events = Vec::new();
        for c in partition_bytes(&stream, &chunk_sizes) {
            chunked_events.extend(chunked.push(&c));
        }
        chunked_events.extend(chunked.finish());

        prop_assert_eq!(whole_events, chunked_events);
    }

    #[test]
    fn sse_parser_discards_event_only_frames(
        ev_name in "[a-zA-Z0-9_-]{1,16}",
        data_val in "[a-zA-Z0-9_-]{1,16}",
        eol in arb_eol(),
    ) {
        let raw = format!("event: {ev_name}{eol}{eol}data: {data_val}{eol}{eol}");
        let mut p = SseParser::new();
        let mut events = p.push(raw.as_bytes());
        events.extend(p.finish());
        prop_assert_eq!(events.len(), 1);
        prop_assert_eq!(events[0].event.as_deref(), None);
        prop_assert_eq!(events[0].data.as_str(), data_val.as_str());
    }
}

#[derive(Debug, Clone)]
enum AnthropicPiece {
    Text(String),
    Tool {
        id: String,
        name: String,
        arg_parts: Vec<String>,
    },
    Ping,
}

fn arb_anthropic_piece() -> impl Strategy<Value = AnthropicPiece> {
    prop_oneof![
        "[a-zA-Z0-9 .,!?]{1,24}".prop_map(AnthropicPiece::Text),
        (
            "[a-z0-9_]{1,10}",
            "[a-z_]{1,12}",
            prop::collection::vec("[a-z0-9{}:\", ]{1,12}", 1..4),
        )
            .prop_map(|(id, name, arg_parts)| AnthropicPiece::Tool {
                id,
                name,
                arg_parts,
            }),
        Just(AnthropicPiece::Ping),
    ]
}

proptest! {
    #[test]
    fn anthropic_sse_translator_preserves_text_tools_and_usage_across_arbitrary_splits(
        pieces in prop::collection::vec(arb_anthropic_piece(), 1..10),
        input_tokens in 0u64..10_000,
        output_tokens in 0u64..10_000,
        chunk_sizes in prop::collection::vec(1usize..17, 1..64),
    ) {
        let mut raw_sse = String::new();
        raw_sse.push_str(&format!(
            "event: message_start\ndata: {}\n\n",
            json!({
                "type": "message_start",
                "message": {
                    "id": "msg_prop",
                    "model": "claude-3-5-sonnet",
                    "usage": { "input_tokens": input_tokens }
                }
            })
        ));

        let mut expected_text = String::new();
        let mut expected_tool_args: Vec<(String, String, String)> = Vec::new();
        let mut block_idx = 0usize;

        for piece in &pieces {
            match piece {
                AnthropicPiece::Text(t) => {
                    expected_text.push_str(t);
                    raw_sse.push_str(&format!(
                        "event: content_block_start\ndata: {}\n\n",
                        json!({"type": "content_block_start", "index": block_idx, "content_block": {"type": "text", "text": ""}})
                    ));
                    raw_sse.push_str(&format!(
                        "event: content_block_delta\ndata: {}\n\n",
                        json!({"type": "content_block_delta", "index": block_idx, "delta": {"type": "text_delta", "text": t}})
                    ));
                    raw_sse.push_str(&format!(
                        "event: content_block_stop\ndata: {}\n\n",
                        json!({"type": "content_block_stop", "index": block_idx})
                    ));
                    block_idx += 1;
                }
                AnthropicPiece::Tool { id, name, arg_parts } => {
                    let combined: String = arg_parts.concat();
                    expected_tool_args.push((id.clone(), name.clone(), combined));
                    raw_sse.push_str(&format!(
                        "event: content_block_start\ndata: {}\n\n",
                        json!({"type": "content_block_start", "index": block_idx, "content_block": {"type": "tool_use", "id": id, "name": name, "input": {}}})
                    ));
                    for part in arg_parts {
                        raw_sse.push_str(&format!(
                            "event: content_block_delta\ndata: {}\n\n",
                            json!({"type": "content_block_delta", "index": block_idx, "delta": {"type": "input_json_delta", "partial_json": part}})
                        ));
                    }
                    raw_sse.push_str(&format!(
                        "event: content_block_stop\ndata: {}\n\n",
                        json!({"type": "content_block_stop", "index": block_idx})
                    ));
                    block_idx += 1;
                }
                AnthropicPiece::Ping => {
                    raw_sse.push_str("event: ping\ndata: {\"type\":\"ping\"}\n\n");
                }
            }
        }

        raw_sse.push_str(&format!(
            "event: message_delta\ndata: {}\n\n",
            json!({
                "type": "message_delta",
                "delta": { "stop_reason": "end_turn" },
                "usage": { "output_tokens": output_tokens }
            })
        ));
        raw_sse.push_str("event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n");

        let mut translator = AnthropicSseTranslator::new("fallback");
        let mut out_bytes = Vec::new();
        for c in partition_bytes(raw_sse.as_bytes(), &chunk_sizes) {
            out_bytes.extend_from_slice(&translator.push_chunk(&c));
        }
        out_bytes.extend_from_slice(&translator.finish());

        let out_str = String::from_utf8(out_bytes).expect("output SSE must be valid UTF-8");
        prop_assert!(out_str.ends_with("data: [DONE]\n\n"));

        let mut out_parser = SseParser::new();
        let mut out_events = out_parser.push(out_str.as_bytes());
        out_events.extend(out_parser.finish());
        prop_assert!(!out_events.is_empty());
        prop_assert_eq!(out_events.last().unwrap().data.as_str(), "[DONE]");

        let mut got_text = String::new();
        let mut got_tools: HashMap<usize, (String, String, String)> = HashMap::new();
        let mut got_usage: Option<(u64, u64)> = None;

        for ev in &out_events[..out_events.len() - 1] {
            let v: Value = serde_json::from_str(&ev.data)
                .expect("every non-[DONE] frame must be valid JSON");
            if let Some(u) = v.get("usage") {
                got_usage = Some((
                    u["prompt_tokens"].as_u64().unwrap(),
                    u["completion_tokens"].as_u64().unwrap(),
                ));
            }
            if let Some(choices) = v.get("choices").and_then(Value::as_array) {
                for ch in choices {
                    if let Some(delta) = ch.get("delta") {
                        if let Some(c) = delta.get("content").and_then(Value::as_str) {
                            got_text.push_str(c);
                        }
                        if let Some(tcs) = delta.get("tool_calls").and_then(Value::as_array) {
                            for tc in tcs {
                                let idx = tc["index"].as_u64().unwrap() as usize;
                                let entry = got_tools.entry(idx).or_default();
                                if let Some(id) = tc.get("id").and_then(Value::as_str) {
                                    entry.0 = id.to_owned();
                                }
                                if let Some(func) = tc.get("function") {
                                    if let Some(name) = func.get("name").and_then(Value::as_str) {
                                        entry.1 = name.to_owned();
                                    }
                                    if let Some(args) = func.get("arguments").and_then(Value::as_str) {
                                        entry.2.push_str(args);
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        prop_assert_eq!(got_text, expected_text);
        prop_assert_eq!(got_usage, Some((input_tokens, output_tokens)));
        prop_assert_eq!(got_tools.len(), expected_tool_args.len());
        for (idx, expected) in expected_tool_args.iter().enumerate() {
            prop_assert_eq!(got_tools.get(&idx), Some(expected));
        }
    }
}

#[derive(Debug, Clone)]
enum GenMsg {
    System(String),
    Developer(String),
    User(String),
    Assistant(String),
    Tool { id: String, content: String },
}

fn arb_gen_msg() -> impl Strategy<Value = GenMsg> {
    prop_oneof![
        "[a-zA-Z0-9 ]{0,20}".prop_map(GenMsg::System),
        "[a-zA-Z0-9 ]{0,20}".prop_map(GenMsg::Developer),
        "[a-zA-Z0-9 ]{1,20}".prop_map(GenMsg::User),
        "[a-zA-Z0-9 ]{1,20}".prop_map(GenMsg::Assistant),
        ("[a-z0-9_]{1,12}", "[a-zA-Z0-9 ]{0,20}")
            .prop_map(|(id, content)| GenMsg::Tool { id, content }),
    ]
}

proptest! {
    #[test]
    fn openai_to_anthropic_request_invariants(
        msgs in prop::collection::vec(arb_gen_msg(), 0..20),
        max_tokens in prop::option::of(0u64..10000),
        default_max in 0u64..8192,
    ) {
        let mut expected_systems = Vec::new();
        let mut expected_tool_ids = Vec::new();
        let json_msgs: Vec<Value> = msgs.iter().map(|m| match m {
            GenMsg::System(s) => {
                if !s.is_empty() { expected_systems.push(s.clone()); }
                json!({"role": "system", "content": s})
            }
            GenMsg::Developer(s) => {
                if !s.is_empty() { expected_systems.push(s.clone()); }
                json!({"role": "developer", "content": s})
            }
            GenMsg::User(s) => json!({"role": "user", "content": s}),
            GenMsg::Assistant(s) => json!({"role": "assistant", "content": s}),
            GenMsg::Tool { id, content } => {
                expected_tool_ids.push(id.clone());
                json!({"role": "tool", "tool_call_id": id, "content": content})
            }
        }).collect();

        let mut req = json!({
            "model": "gpt-4o",
            "messages": json_msgs,
        });
        if let Some(mt) = max_tokens {
            req["max_tokens"] = json!(mt);
        }

        let bytes = serde_json::to_vec(&req).unwrap();
        let out_bytes = openai_to_anthropic_request(&bytes, "claude-3-5-sonnet", default_max)
            .expect("valid OpenAI request must translate");
        let out: Value = serde_json::from_slice(&out_bytes).expect("output must be valid JSON");

        // Invariant 1: max_tokens > 0
        let mt = out["max_tokens"].as_u64().expect("max_tokens must be u64");
        prop_assert!(mt > 0);

        // Invariant 2: strictly alternating user/assistant roles
        let out_msgs = out["messages"].as_array().expect("messages must be array");
        let mut prev_role: Option<&str> = None;
        let mut found_tool_ids = Vec::new();
        for m in out_msgs {
            let role = m["role"].as_str().expect("role must be str");
            prop_assert!(role == "user" || role == "assistant");
            prop_assert_ne!(prev_role, Some(role), "adjacent messages must not share role");
            prev_role = Some(role);

            if let Some(blocks) = m["content"].as_array() {
                for b in blocks {
                    if b.get("type").and_then(Value::as_str) == Some("tool_result") {
                        found_tool_ids.push(b["tool_use_id"].as_str().unwrap().to_owned());
                    }
                }
            }
        }

        // Invariant 3: all non-empty system/developer prompts preserved
        if expected_systems.is_empty() {
            prop_assert!(out.get("system").is_none());
        } else {
            let joined = expected_systems.join("\n\n");
            prop_assert_eq!(out["system"].as_str(), Some(joined.as_str()));
        }

        // Invariant 4: all tool_call_ids mapped to tool_result
        prop_assert_eq!(found_tool_ids, expected_tool_ids);
    }

    #[test]
    fn openai_to_anthropic_never_panics_on_arbitrary_bytes(
        raw in prop::collection::vec(any::<u8>(), 0..256),
    ) {
        let _ = openai_to_anthropic_request(&raw, "claude-test", 1024);
    }
}

#[derive(Debug, Clone)]
enum CircuitOp {
    Failure {
        target: usize,
        retry_after: Option<u64>,
    },
    Success {
        target: usize,
    },
    AdvanceMs(u64),
    Query {
        target: usize,
    },
}

fn arb_circuit_op() -> impl Strategy<Value = CircuitOp> {
    prop_oneof![
        (0usize..4, prop::option::of(0u64..120)).prop_map(|(target, retry_after)| {
            CircuitOp::Failure {
                target,
                retry_after,
            }
        }),
        (0usize..4).prop_map(|target| CircuitOp::Success { target }),
        (0u64..30_000).prop_map(CircuitOp::AdvanceMs),
        (0usize..4).prop_map(|target| CircuitOp::Query { target }),
    ]
}

proptest! {
    #[test]
    fn failover_circuit_state_matches_reference_model(
        threshold in 1usize..5,
        cooldown_ms in 100u64..10_000,
        max_cooldown_ms in 100u64..60_000,
        respect_retry_after in any::<bool>(),
        ops in prop::collection::vec(arb_circuit_op(), 1..80),
    ) {
        let base_cd = Duration::from_millis(cooldown_ms);
        let max_cd = Duration::from_millis(max_cooldown_ms.max(cooldown_ms));
        let clock = ManualClock::new();
        let circuit = FailoverCircuitState::default();

        // Pure reference model: target_key -> (consecutive_failures, Option<cooldown_until>)
        let mut model: HashMap<String, (usize, Option<Duration>)> = HashMap::new();

        for op in ops {
            match op {
                CircuitOp::Failure { target, retry_after } => {
                    let key = format!("up-{target}::model-{target}");
                    let header = retry_after.map(|s| s.to_string());
                    let cd = compute_cooldown(base_cd, max_cd, respect_retry_after, header.as_deref());

                    // Invariant: computed cooldown always within [base_cd, max_cd]
                    prop_assert!(cd >= base_cd && cd <= max_cd);

                    let now = clock.now();
                    circuit.record_failure(&key, threshold, cd, now);

                    let entry = model.entry(key.clone()).or_insert((0, None));
                    entry.0 += 1;
                    if entry.0 >= threshold {
                        let until = now.saturating_add(cd);
                        entry.1 = Some(match entry.1 {
                            Some(prev) => prev.max(until),
                            None => until,
                        });
                    }

                    prop_assert_eq!(circuit.consecutive_failures(&key), entry.0);
                    let expected_cd = entry.1.map(|u| now < u).unwrap_or(false);
                    prop_assert_eq!(circuit.is_in_cooldown(&key, now), expected_cd);
                }
                CircuitOp::Success { target } => {
                    let key = format!("up-{target}::model-{target}");
                    circuit.record_success(&key);
                    if let Some(entry) = model.get_mut(&key) {
                        *entry = (0, None);
                    }
                    prop_assert_eq!(circuit.consecutive_failures(&key), 0);
                    prop_assert!(!circuit.is_in_cooldown(&key, clock.now()));
                }
                CircuitOp::AdvanceMs(dt) => {
                    clock.advance_ms(dt);
                }
                CircuitOp::Query { target } => {
                    let key = format!("up-{target}::model-{target}");
                    let now = clock.now();
                    let expected = model
                        .get(&key)
                        .and_then(|(_, u)| *u)
                        .map(|u| now < u)
                        .unwrap_or(false);
                    prop_assert_eq!(circuit.is_in_cooldown(&key, now), expected);
                }
            }
        }
    }
}

proptest! {
    #[test]
    fn gemini_sse_translator_preserves_text_tools_and_usage_across_arbitrary_splits(
        texts in prop::collection::vec("[a-zA-Z0-9 .,!?]{1,20}", 1..8),
        tool_name in "[a-z_]{1,12}",
        prompt_tokens in 1u64..10_000,
        cand_tokens in 1u64..10_000,
        chunk_sizes in prop::collection::vec(1usize..19, 1..64),
    ) {
        let mut raw_sse = String::new();
        let expected_text: String = texts.concat();

        for t in &texts {
            raw_sse.push_str(&format!(
                "data: {}\n\n",
                json!({
                    "responseId": "gem_prop_1",
                    "modelVersion": "gemini-2.5-flash",
                    "candidates": [{
                        "content": { "role": "model", "parts": [{ "text": t }] }
                    }]
                })
            ));
        }

        raw_sse.push_str(&format!(
            "data: {}\n\n",
            json!({
                "responseId": "gem_prop_1",
                "modelVersion": "gemini-2.5-flash",
                "candidates": [{
                    "content": {
                        "role": "model",
                        "parts": [{ "functionCall": { "name": tool_name, "args": { "k": "v" } } }]
                    },
                    "finishReason": "STOP"
                }],
                "usageMetadata": {
                    "promptTokenCount": prompt_tokens,
                    "candidatesTokenCount": cand_tokens,
                    "totalTokenCount": prompt_tokens + cand_tokens
                }
            })
        ));

        let mut tr = GeminiSseTranslator::new("gemini-2.5-flash");
        let mut out_bytes = Vec::new();
        for c in partition_bytes(raw_sse.as_bytes(), &chunk_sizes) {
            out_bytes.extend_from_slice(&tr.push_chunk(&c));
        }
        out_bytes.extend_from_slice(&tr.finish());

        let out_str = String::from_utf8(out_bytes).expect("Gemini SSE output must be valid UTF-8");
        prop_assert!(out_str.ends_with("data: [DONE]\n\n"));

        let mut parser = SseParser::new();
        let mut events = parser.push(out_str.as_bytes());
        events.extend(parser.finish());
        prop_assert_eq!(events.last().unwrap().data.as_str(), "[DONE]");

        let mut got_text = String::new();
        let mut got_tool_name = None;
        let mut got_finish = None;
        let mut got_usage = None;

        for ev in &events[..events.len() - 1] {
            let v: Value = serde_json::from_str(&ev.data).expect("chunk must be valid JSON");
            if let Some(u) = v.get("usage") {
                got_usage = Some((
                    u["prompt_tokens"].as_u64().unwrap(),
                    u["completion_tokens"].as_u64().unwrap(),
                ));
            }
            if let Some(choices) = v.get("choices").and_then(Value::as_array) {
                for ch in choices {
                    if let Some(fr) = ch.get("finish_reason").and_then(Value::as_str) {
                        got_finish = Some(fr.to_owned());
                    }
                    if let Some(delta) = ch.get("delta") {
                        if let Some(c) = delta.get("content").and_then(Value::as_str) {
                            got_text.push_str(c);
                        }
                        if let Some(tcs) = delta.get("tool_calls").and_then(Value::as_array) {
                            for tc in tcs {
                                if let Some(n) = tc["function"]["name"].as_str() {
                                    got_tool_name = Some(n.to_owned());
                                }
                            }
                        }
                    }
                }
            }
        }

        prop_assert_eq!(got_text, expected_text);
        prop_assert_eq!(got_tool_name.as_deref(), Some(tool_name.as_str()));
        prop_assert_eq!(got_finish.as_deref(), Some("tool_calls"));
        prop_assert_eq!(got_usage, Some((prompt_tokens, cand_tokens)));
    }

    #[test]
    fn aws_eventstream_decoder_chunk_split_invariance(
        payloads in prop::collection::vec(prop::collection::vec(any::<u8>(), 0..64), 1..10),
        chunk_sizes in prop::collection::vec(1usize..13, 1..64),
    ) {
        let mut wire = Vec::new();
        for (i, p) in payloads.iter().enumerate() {
            let ev_type = format!("ev_{i}");
            wire.extend_from_slice(&encode_eventstream_frame(
                &[(":message-type", "event"), (":event-type", &ev_type)],
                p,
            ));
        }

        let mut whole = AwsEventStreamDecoder::new();
        let whole_msgs = whole.push(&wire).expect("valid encoded stream must decode");
        prop_assert_eq!(whole.buffered_len(), 0);
        prop_assert_eq!(whole_msgs.len(), payloads.len());

        let mut chunked = AwsEventStreamDecoder::new();
        let mut chunked_msgs = Vec::new();
        for c in partition_bytes(&wire, &chunk_sizes) {
            chunked_msgs.extend(chunked.push(&c).expect("chunked decode must succeed"));
        }
        prop_assert_eq!(chunked.buffered_len(), 0);
        prop_assert_eq!(&whole_msgs, &chunked_msgs);

        let mut byte_by_byte = AwsEventStreamDecoder::new();
        let mut b_msgs = Vec::new();
        for &b in &wire {
            b_msgs.extend(byte_by_byte.push(&[b]).expect("1-byte decode must succeed"));
        }
        prop_assert_eq!(byte_by_byte.buffered_len(), 0);
        prop_assert_eq!(whole_msgs, b_msgs);
    }

    #[test]
    fn bedrock_stream_translator_preserves_text_tools_and_usage_across_arbitrary_splits(
        texts in prop::collection::vec("[a-zA-Z0-9 .,!?]{1,20}", 1..8),
        tool_arg_parts in prop::collection::vec("[a-z0-9{}:\", ]{1,12}", 1..4),
        input_tokens in 1u64..10_000,
        output_tokens in 1u64..10_000,
        chunk_sizes in prop::collection::vec(1usize..15, 1..64),
    ) {
        let expected_text: String = texts.concat();
        let expected_args: String = tool_arg_parts.concat();

        let mut wire = Vec::new();
        wire.extend_from_slice(&encode_eventstream_frame(
            &[(":message-type", "event"), (":event-type", "messageStart")],
            br#"{"role":"assistant"}"#,
        ));
        for t in &texts {
            let p = serde_json::to_vec(&json!({
                "contentBlockIndex": 0,
                "delta": { "text": t }
            }))
            .unwrap();
            wire.extend_from_slice(&encode_eventstream_frame(
                &[(":message-type", "event"), (":event-type", "contentBlockDelta")],
                &p,
            ));
        }
        wire.extend_from_slice(&encode_eventstream_frame(
            &[(":message-type", "event"), (":event-type", "contentBlockStart")],
            br#"{"contentBlockIndex":1,"start":{"toolUse":{"toolUseId":"tu_prop","name":"calc"}}}"#,
        ));
        for part in &tool_arg_parts {
            let p = serde_json::to_vec(&json!({
                "contentBlockIndex": 1,
                "delta": { "toolUse": { "input": part } }
            }))
            .unwrap();
            wire.extend_from_slice(&encode_eventstream_frame(
                &[(":message-type", "event"), (":event-type", "contentBlockDelta")],
                &p,
            ));
        }
        wire.extend_from_slice(&encode_eventstream_frame(
            &[(":message-type", "event"), (":event-type", "messageStop")],
            br#"{"stopReason":"tool_use"}"#,
        ));
        let meta = serde_json::to_vec(&json!({
            "usage": {
                "inputTokens": input_tokens,
                "outputTokens": output_tokens,
                "totalTokens": input_tokens + output_tokens
            }
        }))
        .unwrap();
        wire.extend_from_slice(&encode_eventstream_frame(
            &[(":message-type", "event"), (":event-type", "metadata")],
            &meta,
        ));

        let mut tr = BedrockStreamTranslator::new("anthropic.claude-3-5-sonnet-20241022-v2:0");
        let mut out_bytes = Vec::new();
        for c in partition_bytes(&wire, &chunk_sizes) {
            out_bytes.extend_from_slice(&tr.push_chunk(&c));
        }
        out_bytes.extend_from_slice(&tr.finish());

        let out_str = String::from_utf8(out_bytes).expect("Bedrock SSE output must be valid UTF-8");
        prop_assert!(out_str.ends_with("data: [DONE]\n\n"));

        let mut parser = SseParser::new();
        let mut events = parser.push(out_str.as_bytes());
        events.extend(parser.finish());
        prop_assert_eq!(events.last().unwrap().data.as_str(), "[DONE]");

        let mut got_text = String::new();
        let mut got_args = String::new();
        let mut got_usage = None;
        for ev in &events[..events.len() - 1] {
            let v: Value = serde_json::from_str(&ev.data).expect("chunk must be valid JSON");
            if let Some(u) = v.get("usage") {
                got_usage = Some((
                    u["prompt_tokens"].as_u64().unwrap(),
                    u["completion_tokens"].as_u64().unwrap(),
                ));
            }
            if let Some(choices) = v.get("choices").and_then(Value::as_array) {
                for ch in choices {
                    if let Some(delta) = ch.get("delta") {
                        if let Some(c) = delta.get("content").and_then(Value::as_str) {
                            got_text.push_str(c);
                        }
                        if let Some(tcs) = delta.get("tool_calls").and_then(Value::as_array) {
                            for tc in tcs {
                                if let Some(a) = tc["function"]["arguments"].as_str() {
                                    got_args.push_str(a);
                                }
                            }
                        }
                    }
                }
            }
        }

        prop_assert_eq!(got_text, expected_text);
        prop_assert_eq!(got_args, expected_args);
        prop_assert_eq!(got_usage, Some((input_tokens, output_tokens)));
    }

    #[test]
    fn gemini_bedrock_and_eventstream_never_panic_on_arbitrary_bytes(
        raw in prop::collection::vec(any::<u8>(), 0..256),
    ) {
        let _ = openai_to_gemini_request(&raw);
        let _ = openai_to_bedrock_converse_request(&raw);
        let mut dec = AwsEventStreamDecoder::new();
        let _ = dec.push(&raw);
    }

    #[test]
    fn openai_to_anthropic_sse_preserves_text_tools_usage_and_lifecycle(
        texts in prop::collection::vec("[a-zA-Z0-9 .,!?]{1,20}", 1..8),
        tool_arg_parts in prop::collection::vec("[a-z0-9{}:\", ]{1,12}", 1..4),
        input_tokens in 1u64..10_000,
        output_tokens in 1u64..10_000,
        chunk_sizes in prop::collection::vec(1usize..17, 1..64),
    ) {
        let expected_text: String = texts.concat();
        let expected_args: String = tool_arg_parts.concat();

        let mut sse = String::new();
        for (i, t) in texts.iter().enumerate() {
            let delta = if i == 0 {
                json!({ "role": "assistant", "content": t })
            } else {
                json!({ "content": t })
            };
            let chunk = json!({
                "id": "chatcmpl-prop",
                "object": "chat.completion.chunk",
                "model": "gpt-4o",
                "choices": [{ "index": 0, "delta": delta, "finish_reason": Value::Null }]
            });
            sse.push_str(&format!("data: {chunk}\n\n"));
        }
        for (i, part) in tool_arg_parts.iter().enumerate() {
            let tc = if i == 0 {
                json!({
                    "index": 0,
                    "id": "call_prop_1",
                    "type": "function",
                    "function": { "name": "calc", "arguments": part }
                })
            } else {
                json!({
                    "index": 0,
                    "function": { "arguments": part }
                })
            };
            let chunk = json!({
                "id": "chatcmpl-prop",
                "object": "chat.completion.chunk",
                "model": "gpt-4o",
                "choices": [{ "index": 0, "delta": { "tool_calls": [tc] }, "finish_reason": Value::Null }]
            });
            sse.push_str(&format!("data: {chunk}\n\n"));
        }
        sse.push_str(&format!(
            "data: {}\n\n",
            json!({
                "id": "chatcmpl-prop",
                "object": "chat.completion.chunk",
                "model": "gpt-4o",
                "choices": [{ "index": 0, "delta": {}, "finish_reason": "tool_calls" }]
            })
        ));
        sse.push_str(&format!(
            "data: {}\n\n",
            json!({
                "id": "chatcmpl-prop",
                "object": "chat.completion.chunk",
                "model": "gpt-4o",
                "choices": [],
                "usage": {
                    "prompt_tokens": input_tokens,
                    "completion_tokens": output_tokens,
                    "total_tokens": input_tokens + output_tokens
                }
            })
        ));
        sse.push_str("data: [DONE]\n\n");

        let mut tr = OpenAiToAnthropicSseTranslator::new("fallback");
        let mut out_bytes = Vec::new();
        for c in partition_bytes(sse.as_bytes(), &chunk_sizes) {
            out_bytes.extend_from_slice(&tr.push_chunk(&c));
        }
        out_bytes.extend_from_slice(&tr.finish());

        let mut parser = SseParser::new();
        let mut events = parser.push(&out_bytes);
        events.extend(parser.finish());

        prop_assert!(events.len() >= 4);
        prop_assert_eq!(events.first().unwrap().event.as_deref(), Some("message_start"));
        prop_assert_eq!(events.last().unwrap().event.as_deref(), Some("message_stop"));

        let mut starts = 0usize;
        let mut stops = 0usize;
        let mut got_text = String::new();
        let mut got_args = String::new();
        let mut got_usage = None;
        for ev in &events {
            let v: Value = serde_json::from_str(&ev.data).expect("valid JSON");
            match ev.event.as_deref() {
                Some("content_block_start") => starts += 1,
                Some("content_block_stop") => stops += 1,
                Some("content_block_delta") => match v["delta"]["type"].as_str() {
                    Some("text_delta") => got_text.push_str(v["delta"]["text"].as_str().unwrap()),
                    Some("input_json_delta") => {
                        got_args.push_str(v["delta"]["partial_json"].as_str().unwrap())
                    }
                    _ => {}
                },
                Some("message_delta") => {
                    prop_assert_eq!(v["delta"]["stop_reason"].as_str(), Some("tool_use"));
                    got_usage = Some((
                        v["usage"]["input_tokens"].as_u64().unwrap(),
                        v["usage"]["output_tokens"].as_u64().unwrap(),
                    ));
                }
                _ => {}
            }
        }
        prop_assert_eq!(starts, stops);
        prop_assert_eq!(starts, 2);
        prop_assert_eq!(got_text, expected_text);
        prop_assert_eq!(got_args, expected_args);
        prop_assert_eq!(got_usage, Some((input_tokens, output_tokens)));
    }

    #[test]
    fn chat_to_responses_sse_has_monotonic_sequence_and_preserves_content(
        texts in prop::collection::vec("[a-zA-Z0-9 .,!?]{1,20}", 1..8),
        input_tokens in 1u64..10_000,
        output_tokens in 1u64..10_000,
        chunk_sizes in prop::collection::vec(1usize..17, 1..64),
    ) {
        let expected_text: String = texts.concat();

        let mut sse = String::new();
        for t in &texts {
            let chunk = json!({
                "id": "chatcmpl-resp-prop",
                "object": "chat.completion.chunk",
                "created": 1700000100,
                "model": "gpt-4o",
                "choices": [{ "index": 0, "delta": { "content": t }, "finish_reason": Value::Null }]
            });
            sse.push_str(&format!("data: {chunk}\n\n"));
        }
        sse.push_str(&format!(
            "data: {}\n\n",
            json!({
                "id": "chatcmpl-resp-prop",
                "object": "chat.completion.chunk",
                "created": 1700000100,
                "model": "gpt-4o",
                "choices": [{ "index": 0, "delta": {}, "finish_reason": "stop" }],
                "usage": {
                    "prompt_tokens": input_tokens,
                    "completion_tokens": output_tokens,
                    "total_tokens": input_tokens + output_tokens
                }
            })
        ));
        sse.push_str("data: [DONE]\n\n");

        let mut tr = ChatToResponsesSseTranslator::new("fallback");
        let mut out_bytes = Vec::new();
        for c in partition_bytes(sse.as_bytes(), &chunk_sizes) {
            out_bytes.extend_from_slice(&tr.push_chunk(&c));
        }
        out_bytes.extend_from_slice(&tr.finish());

        let mut parser = SseParser::new();
        let mut events = parser.push(&out_bytes);
        events.extend(parser.finish());

        prop_assert!(events.len() >= 6);
        prop_assert_eq!(events[0].event.as_deref(), Some("response.created"));
        prop_assert_eq!(events[1].event.as_deref(), Some("response.in_progress"));
        prop_assert_eq!(events.last().unwrap().event.as_deref(), Some("response.completed"));

        let mut got_text = String::new();
        for (idx, ev) in events.iter().enumerate() {
            let v: Value = serde_json::from_str(&ev.data).expect("valid JSON");
            prop_assert_eq!(v["sequence_number"].as_u64(), Some(idx as u64));
            if ev.event.as_deref() == Some("response.output_text.delta") {
                got_text.push_str(v["delta"].as_str().unwrap());
            }
        }

        let completed: Value = serde_json::from_str(&events.last().unwrap().data).unwrap();
        prop_assert_eq!(got_text, expected_text.clone());
        prop_assert_eq!(
            completed["response"]["output"][0]["content"][0]["text"].as_str(),
            Some(expected_text.as_str())
        );
        prop_assert_eq!(completed["response"]["usage"]["input_tokens"].as_u64(), Some(input_tokens));
        prop_assert_eq!(completed["response"]["usage"]["output_tokens"].as_u64(), Some(output_tokens));
    }

    #[test]
    fn composed_bedrock_to_anthropic_and_gemini_to_responses_are_chunk_invariant(
        texts in prop::collection::vec("[a-zA-Z0-9 ]{1,16}", 1..6),
        chunk_sizes in prop::collection::vec(1usize..13, 1..48),
    ) {
        let expected_text: String = texts.concat();

        // 1. Bedrock binary EventStream -> Canonical OpenAI SSE -> Anthropic SSE
        let mut bedrock_wire = Vec::new();
        bedrock_wire.extend_from_slice(&encode_eventstream_frame(
            &[(":message-type", "event"), (":event-type", "messageStart")],
            br#"{"role":"assistant"}"#,
        ));
        for t in &texts {
            let p = serde_json::to_vec(&json!({ "contentBlockIndex": 0, "delta": { "text": t } })).unwrap();
            bedrock_wire.extend_from_slice(&encode_eventstream_frame(
                &[(":message-type", "event"), (":event-type", "contentBlockDelta")],
                &p,
            ));
        }
        bedrock_wire.extend_from_slice(&encode_eventstream_frame(
            &[(":message-type", "event"), (":event-type", "messageStop")],
            br#"{"stopReason":"end_turn"}"#,
        ));
        bedrock_wire.extend_from_slice(&encode_eventstream_frame(
            &[(":message-type", "event"), (":event-type", "metadata")],
            br#"{"usage":{"inputTokens":5,"outputTokens":4,"totalTokens":9}}"#,
        ));

        let mut up = BedrockStreamTranslator::new("bedrock-model");
        let mut ing = OpenAiToAnthropicSseTranslator::new("bedrock-model");
        let mut out = Vec::new();
        for c in partition_bytes(&bedrock_wire, &chunk_sizes) {
            let mid = up.push_chunk(&c);
            if !mid.is_empty() {
                out.extend_from_slice(&ing.push_chunk(&mid));
            }
        }
        let up_tail = up.finish();
        if !up_tail.is_empty() {
            out.extend_from_slice(&ing.push_chunk(&up_tail));
        }
        out.extend_from_slice(&ing.finish());

        let mut parser = SseParser::new();
        let mut events = parser.push(&out);
        events.extend(parser.finish());
        prop_assert_eq!(events.first().unwrap().event.as_deref(), Some("message_start"));
        prop_assert_eq!(events.last().unwrap().event.as_deref(), Some("message_stop"));
        let mut got_anth_text = String::new();
        for ev in &events {
            if ev.event.as_deref() == Some("content_block_delta") {
                let v: Value = serde_json::from_str(&ev.data).unwrap();
                if let Some(t) = v["delta"]["text"].as_str() {
                    got_anth_text.push_str(t);
                }
            }
        }
        prop_assert_eq!(got_anth_text, expected_text.clone());

        // 2. Gemini SSE -> Canonical OpenAI SSE -> OpenAI Responses SSE
        let mut gem_wire = String::new();
        for (idx, t) in texts.iter().enumerate() {
            let is_last = idx + 1 == texts.len();
            let frame = if is_last {
                json!({
                    "responseId": "gem_comp",
                    "modelVersion": "gemini-2.5-flash",
                    "candidates": [{ "content": { "role": "model", "parts": [{ "text": t }] }, "finishReason": "STOP" }],
                    "usageMetadata": { "promptTokenCount": 4, "candidatesTokenCount": 3, "totalTokenCount": 7 }
                })
            } else {
                json!({
                    "responseId": "gem_comp",
                    "modelVersion": "gemini-2.5-flash",
                    "candidates": [{ "content": { "role": "model", "parts": [{ "text": t }] } }]
                })
            };
            gem_wire.push_str(&format!("data: {frame}\n\n"));
        }

        let mut g_up = GeminiSseTranslator::new("gemini-2.5-flash");
        let mut r_ing = ChatToResponsesSseTranslator::new("gemini-2.5-flash");
        let mut r_out = Vec::new();
        for c in partition_bytes(gem_wire.as_bytes(), &chunk_sizes) {
            let mid = g_up.push_chunk(&c);
            if !mid.is_empty() {
                r_out.extend_from_slice(&r_ing.push_chunk(&mid));
            }
        }
        let g_tail = g_up.finish();
        if !g_tail.is_empty() {
            r_out.extend_from_slice(&r_ing.push_chunk(&g_tail));
        }
        r_out.extend_from_slice(&r_ing.finish());

        let mut r_parser = SseParser::new();
        let mut r_events = r_parser.push(&r_out);
        r_events.extend(r_parser.finish());
        prop_assert_eq!(r_events.last().unwrap().event.as_deref(), Some("response.completed"));
        let completed: Value = serde_json::from_str(&r_events.last().unwrap().data).unwrap();
        prop_assert_eq!(
            completed["response"]["output"][0]["content"][0]["text"].as_str(),
            Some(expected_text.as_str())
        );
    }

    #[test]
    fn ingress_translators_never_panic_on_arbitrary_bytes(
        raw in prop::collection::vec(any::<u8>(), 0..256),
    ) {
        let _ = anthropic_to_openai_request(&raw, "m");
        let _ = openai_to_anthropic_response(&raw, http::StatusCode::OK, "m");
        let _ = responses_to_chat_request(&raw, "m");
        let _ = chat_to_responses_response(&raw, http::StatusCode::OK, "m");

        let mut a_sse = OpenAiToAnthropicSseTranslator::new("m");
        let _ = a_sse.push_chunk(&raw);
        let _ = a_sse.finish();

        let mut r_sse = ChatToResponsesSseTranslator::new("m");
        let _ = r_sse.push_chunk(&raw);
        let _ = r_sse.finish();
    }

    #[test]
    fn token_estimator_never_panics_and_is_monotonic(
        raw in prop::collection::vec(any::<u8>(), 0..256),
        prefix in "[a-zA-Z0-9 ]{0,64}",
        suffix in "[a-zA-Z0-9 ]{1,64}",
    ) {
        for ep in [
            shunt_ai::AiEndpointKind::ChatCompletions,
            shunt_ai::AiEndpointKind::AnthropicMessages,
            shunt_ai::AiEndpointKind::AnthropicCountTokens,
            shunt_ai::AiEndpointKind::OpenAiResponses,
            shunt_ai::AiEndpointKind::Embeddings,
        ] {
            let est = shunt_ai::estimate_request_tokens(ep, &raw);
            prop_assert!(est.input_tokens >= 1);
        }

        let t1 = shunt_ai::estimate_text_tokens(&prefix);
        let combined = format!("{prefix}{suffix}");
        let t2 = shunt_ai::estimate_text_tokens(&combined);
        prop_assert!(t2 >= t1);
    }

    #[test]
    fn pricing_cost_nano_usd_invariants(
        in_price in 0.0f64..100.0,
        out_price in 0.0f64..200.0,
        cached_ratio in 0.0f64..1.0,
        prompt_tokens in 0u64..10_000_000,
        cached_tokens in 0u64..10_000_000,
        completion_tokens in 0u64..10_000_000,
    ) {
        let cached_price = in_price * cached_ratio;
        let pricing = shunt_ai::ModelPricing::new(in_price, out_price, Some(cached_price));
        let cost_with_cache = pricing.cost_nano_usd(prompt_tokens, cached_tokens, completion_tokens);
        let cost_no_cache = pricing.cost_nano_usd(prompt_tokens, 0, completion_tokens);

        // Cached tokens are never more expensive than uncached when cached_price <= in_price.
        prop_assert!(cost_with_cache <= cost_no_cache);
        let usd = shunt_ai::nano_usd_to_usd(cost_with_cache);
        prop_assert!(usd.is_finite() && usd >= 0.0);
    }

    #[test]
    fn weighted_target_ordering_preserves_set_and_ratios(
        weights in prop::collection::vec(1u32..30, 2..6),
    ) {
        let targets: Vec<shunt_ai::AiTarget> = weights
            .iter()
            .enumerate()
            .map(|(i, &w)| shunt_ai::AiTarget {
                provider: format!("p{i}"),
                upstream: format!("u{i}"),
                model: format!("m{i}"),
                endpoint_override: None,
                capabilities: Vec::new(),
                weight: w,
                default_params: std::collections::BTreeMap::new(),
                override_params: std::collections::BTreeMap::new(),
            })
            .collect();
        let total_w: usize = weights.iter().map(|&w| w as usize).sum();
        let mut primary_counts = vec![0usize; weights.len()];

        for c in 0..total_w {
            let ordered = shunt_ai::order_weighted_targets(targets.clone(), c);
            prop_assert_eq!(ordered.len(), targets.len());
            // Every target appears exactly once in the failover chain.
            let mut seen = std::collections::HashSet::new();
            for t in &ordered {
                prop_assert!(seen.insert(t.provider.clone()));
            }
            let first_idx: usize = ordered[0].provider[1..].parse().unwrap();
            primary_counts[first_idx] += 1;
        }

        for (i, &w) in weights.iter().enumerate() {
            prop_assert_eq!(primary_counts[i], w as usize);
        }
    }

    #[test]
    fn cost_ordering_is_monotonic_non_decreasing(
        prices in prop::collection::vec(0.0f64..50.0, 2..6),
    ) {
        let mut overrides = HashMap::new();
        let mut targets = Vec::new();
        for (i, &p) in prices.iter().enumerate() {
            let model = format!("cost-m-{i}");
            overrides.insert(
                model.clone(),
                shunt_ai::ModelPricing::new(p, p * 2.0, None),
            );
            targets.push(shunt_ai::AiTarget {
                provider: format!("p{i}"),
                upstream: format!("u{i}"),
                model,
                endpoint_override: None,
                capabilities: Vec::new(),
                weight: 1,
                default_params: std::collections::BTreeMap::new(),
                override_params: std::collections::BTreeMap::new(),
            });
        }
        let cat = shunt_ai::PricingCatalog::new(overrides, false, None).unwrap();
        let body = br#"{"model":"alias","messages":[{"role":"user","content":"hello world"}]}"#;
        let ordered = shunt_ai::order_cost_targets(
            targets,
            &cat,
            shunt_ai::AiEndpointKind::ChatCompletions,
            "alias",
            body,
            256,
            shunt_ai::UnknownCostPolicy::Last,
        );
        let est = shunt_ai::estimate_request_tokens(shunt_ai::AiEndpointKind::ChatCompletions, body);
        let costs: Vec<u64> = ordered
            .iter()
            .map(|t| {
                cat.lookup(&t.model, "alias")
                    .unwrap()
                    .cost_nano_usd(est.input_tokens, 0, 256)
            })
            .collect();
        for pair in costs.windows(2) {
            prop_assert!(pair[0] <= pair[1]);
        }
    }

    #[test]
    fn capability_detector_never_panics_on_arbitrary_json_bytes(
        raw in prop::collection::vec(any::<u8>(), 0..256),
    ) {
        if let Ok(val) = serde_json::from_slice::<Value>(&raw) {
            for ep in [
                shunt_ai::AiEndpointKind::ChatCompletions,
                shunt_ai::AiEndpointKind::AnthropicMessages,
                shunt_ai::AiEndpointKind::OpenAiResponses,
                shunt_ai::AiEndpointKind::Embeddings,
            ] {
                let _ = shunt_ai::detect_required_capabilities(ep, &val);
            }
        }
    }

    #[test]
    fn canonical_cache_key_is_permutation_invariant(
        pairs in prop::collection::vec(("[a-z0-9_]{1,10}", "[a-z0-9 ]{0,20}"), 1..12),
    ) {
        let mut forward = serde_json::Map::new();
        let mut reverse = serde_json::Map::new();
        for (k, v) in &pairs {
            forward.insert(k.clone(), Value::String(v.clone()));
        }
        // Insert identical final key-value pairs in reversed order.
        let ordered_entries: Vec<(String, Value)> = forward
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();
        for (k, v) in ordered_entries.into_iter().rev() {
            reverse.insert(k, v);
        }
        let vf = Value::Object(forward);
        let vr = Value::Object(reverse);
        prop_assert_eq!(shunt_ai::canonical_json_bytes(&vf), shunt_ai::canonical_json_bytes(&vr));
        let kf = shunt_ai::compute_cache_key(
            "key:t1",
            shunt_ai::AiEndpointKind::ChatCompletions,
            "gpt-4o",
            Some(("openai", "gpt-4o")),
            &vf,
        );
        let kr = shunt_ai::compute_cache_key(
            "key:t1",
            shunt_ai::AiEndpointKind::ChatCompletions,
            "gpt-4o",
            Some(("openai", "gpt-4o")),
            &vr,
        );
        prop_assert_eq!(kf, kr);
    }

    #[test]
    fn ai_cache_table_never_exceeds_entry_or_byte_bounds(
        max_entries in 1usize..16,
        max_total_bytes in 32usize..512,
        ops in prop::collection::vec((0u8..3, 0usize..24, 1usize..128, 0u64..2000), 1..120),
    ) {
        let table = shunt_ai::AiCacheTable::new();
        let mut now_ms = 0u64;
        let ttl = Duration::from_secs(5);
        for (kind, key_id, payload_len, dt_ms) in ops {
            now_ms = now_ms.saturating_add(dt_ms);
            let now = Duration::from_millis(now_ms);
            let key = format!("k-{key_id}");
            match kind {
                0 | 1 => {
                    let entry = shunt_ai::CachedAiResponse {
                        content_type: "application/json".to_owned(),
                        provider: "openai".to_owned(),
                        served_model: "gpt-4o".to_owned(),
                        body: vec![b'a'; payload_len],
                    };
                    table.insert(key, entry, now, ttl, max_entries, max_total_bytes);
                }
                _ => {
                    let _ = table.get(&key, now);
                }
            }
            prop_assert!(
                table.len() <= max_entries,
                "len {} > max_entries {max_entries}",
                table.len()
            );
            prop_assert!(
                table.total_bytes() <= max_total_bytes,
                "total_bytes {} > max_total_bytes {max_total_bytes}",
                table.total_bytes()
            );
        }
    }

    #[test]
    fn pricing_cache_write_and_tiered_invariants(
        base_in in 0.0f64..100.0,
        base_out in 0.0f64..200.0,
        read_frac in 0.0f64..1.0,
        write_mult in 1.0f64..2.0,
        long_mult in 1.0f64..3.0,
        prompt_tokens in 0u64..500_000,
        cached_read in 0u64..600_000,
        cache_write in 0u64..600_000,
        completion_tokens in 0u64..50_000,
    ) {
        let read_rate = base_in * read_frac;
        let write_rate = base_in * write_mult;
        let pricing = shunt_ai::ModelPricing::new(base_in, base_out, Some(read_rate))
            .with_cache_write(write_rate)
            .with_long_context_tier(
                200_000,
                base_in * long_mult,
                base_out * long_mult,
                Some(read_rate * long_mult),
                Some(write_rate * long_mult),
            );
        let cost = pricing.cost_nano_usd_detailed(
            prompt_tokens,
            cached_read,
            cache_write,
            completion_tokens,
        );
        prop_assert!(cost <= i64::MAX as u64);
        // With cache_write >= base_in and cached_read == 0, cost >= no-cache-write cost.
        let cost_write = pricing.cost_nano_usd_detailed(prompt_tokens, 0, cache_write, completion_tokens);
        let cost_plain = pricing.cost_nano_usd_detailed(prompt_tokens, 0, 0, completion_tokens);
        prop_assert!(cost_write >= cost_plain);
        // Above threshold, tiered cost >= non-tiered cost for identical token counts.
        if prompt_tokens > 200_000 {
            let flat = shunt_ai::ModelPricing::new(base_in, base_out, Some(read_rate))
                .with_cache_write(write_rate);
            let flat_cost = flat.cost_nano_usd_detailed(
                prompt_tokens,
                cached_read,
                cache_write,
                completion_tokens,
            );
            prop_assert!(cost >= flat_cost);
        }
    }

    #[test]
    fn key_pool_selects_valid_index_and_skips_cooled_keys(
        pool_len in 2usize..8,
        cooled_idx in 0usize..8,
        cooldown_ms in 100u64..10_000,
        step_ms in 0u64..15_000,
    ) {
        let cooled = cooled_idx % pool_len;
        let table = shunt_ai::KeyPoolTable::default();
        let t0 = Duration::from_secs(1);
        table.record_cooldown("p", pool_len, cooled, Duration::from_millis(cooldown_ms), t0);

        // Before cooldown expires, cooled key is never selected while healthy keys exist.
        for _ in 0..(pool_len * 2) {
            let picked = table.select_key("p", pool_len, t0, &[]);
            prop_assert!(picked < pool_len);
            prop_assert_ne!(picked, cooled);
        }

        // At any later timestamp, selection is always in bounds.
        let t1 = t0 + Duration::from_millis(step_ms);
        let picked_later = table.select_key("p", pool_len, t1, &[]);
        prop_assert!(picked_later < pool_len);
        if step_ms >= cooldown_ms {
            // Once expired, snapshot reports 0 cooled down keys.
            let snaps = table.snapshot_pools(t1);
            prop_assert_eq!(snaps[0].cooled_down_keys, 0);
            prop_assert_eq!(snaps[0].healthy_keys, pool_len);
        }
    }

    #[test]
    fn bedrock_embeddings_and_vertex_never_panic(raw in prop::collection::vec(any::<u8>(), 0..512)) {
        let _ = shunt_ai::openai_to_bedrock_embeddings_request(&raw, "amazon.titan-embed-text-v2:0");
        let _ = shunt_ai::openai_to_bedrock_embeddings_request(&raw, "cohere.embed-english-v3");
        let _ = shunt_ai::bedrock_embeddings_to_openai_response(
            &raw,
            http::StatusCode::OK,
            "amazon.titan-embed-text-v2:0",
        );
        let _ = shunt_ai::adapt_anthropic_body_for_vertex(&raw, Some("vertex-2023-10-16"));
    }

    #[test]
    fn rfc3339_roundtrips_with_amz_timestamps(unix_secs in 0u64..4_102_444_800u64) {
        // Construct an RFC 3339 UTC string from `aws_sigv4::format_amz_timestamps` and verify exact round-trip.
        let (amz, _) = shunt_ai::aws_sigv4::format_amz_timestamps(unix_secs);
        // amz is YYYYMMDDTHHMMSSZ
        let iso = format!(
            "{}-{}-{}T{}:{}:{}Z",
            &amz[0..4],
            &amz[4..6],
            &amz[6..8],
            &amz[9..11],
            &amz[11..13],
            &amz[13..15],
        );
        let parsed = shunt_ai::parse_rfc3339_utc_secs(&iso).expect("valid UTC timestamp");
        prop_assert_eq!(parsed, unix_secs);
    }

    #[test]
    fn cloud_auth_parsers_never_panic(raw in prop::collection::vec(any::<u8>(), 0..512)) {
        if let Ok(s) = std::str::from_utf8(&raw) {
            let _ = shunt_ai::parse_rfc3339_utc_secs(s);
            let _ = shunt_ai::parse_aws_sts_xml_credentials(s);
            let _ = shunt_ai::decode_pem_pkcs8_private_key(s);
            let _ = shunt_ai::base64_std_decode(s);
        }
        let _ = shunt_ai::parse_aws_json_credentials(&raw);
        let _ = shunt_ai::parse_oauth_bearer_response(&raw, "fuzz");
    }

    #[test]
    fn cloud_token_deadlines_and_sts_xml_roundtrip(
        now_secs in 0u64..100_000u64,
        ttl_secs in 1u64..86_400u64,
        margin_secs in 0u64..3_600u64,
        cap_secs in prop::option::of(1u64..3_600u64),
        ak in "[A-Z0-9]{4,24}",
        sk in "[A-Za-z0-9/+=]{8,40}",
        tok in "[A-Za-z0-9/+=]{8,40}",
    ) {
        let now = Duration::from_secs(now_secs);
        let ttl = Duration::from_secs(ttl_secs);
        let margin = Duration::from_secs(margin_secs);
        let cap = cap_secs.map(Duration::from_secs);

        let (refresh_at, hard_exp) = shunt_ai::compute_token_deadlines(now, ttl, margin, cap);
        prop_assert!(refresh_at >= now);
        prop_assert!(refresh_at <= hard_exp);
        prop_assert!(hard_exp >= now + Duration::from_secs(1));
        if let Some(c) = cap {
            prop_assert!(hard_exp <= now + c);
        }

        let xml = format!(
            "<AssumeRoleResponse><AssumeRoleResult><Credentials>\
             <AccessKeyId>{ak}</AccessKeyId>\
             <SecretAccessKey>{sk}</SecretAccessKey>\
             <SessionToken>{tok}</SessionToken>\
             <Expiration>2030-06-15T12:00:00Z</Expiration>\
             </Credentials></AssumeRoleResult></AssumeRoleResponse>"
        );
        let parsed = shunt_ai::parse_aws_sts_xml_credentials(&xml).expect("valid STS XML");
        prop_assert_eq!(parsed.access_key_id, ak);
        prop_assert_eq!(parsed.secret_access_key, sk);
        prop_assert_eq!(parsed.session_token.as_deref(), Some(tok.as_str()));
        prop_assert!(parsed.expiration_unix_secs.is_some());
    }

    #[test]
    fn guardrail_luhn_detects_valid_generated_cards_and_rejects_single_digit_flip(
        prefix in prop::collection::vec(0u8..10u8, 12..18),
        flip_idx in 0usize..12,
    ) {
        // Skip trivial all-identical digit prefixes.
        let mut digits = prefix;
        if digits.iter().all(|&d| d == digits[0]) {
            digits[0] = (digits[0] + 1) % 10;
        }
        // Compute valid Luhn check digit.
        let mut sum = 0u32;
        let mut double = true;
        for &d in digits.iter().rev() {
            let mut v = d as u32;
            if double {
                v *= 2;
                if v > 9 {
                    v -= 9;
                }
            }
            sum += v;
            double = !double;
        }
        let check = ((10 - (sum % 10)) % 10) as u8;
        digits.push(check);

        let card: String = digits.iter().map(|d| (b'0' + d) as char).collect();
        prop_assert!(shunt_ai::is_valid_luhn(&card), "expected valid Luhn card: {card}");

        // Flip a single digit -> must fail Luhn check.
        let mut corrupted = digits.clone();
        let idx = flip_idx % corrupted.len();
        corrupted[idx] = (corrupted[idx] + 1) % 10;
        let bad_card: String = corrupted.iter().map(|d| (b'0' + d) as char).collect();
        prop_assert!(!shunt_ai::is_valid_luhn(&bad_card), "corrupted card passed Luhn: {bad_card}");
    }

    #[test]
    fn guardrail_redactor_is_idempotent_and_never_leaks_injected_secrets(
        prefix in "[a-zA-Z0-9 ]{0,32}",
        suffix in "[a-zA-Z0-9 ]{0,32}",
        aws_tail in "[A-Z0-9]{16}",
        user in "[a-z]{3,10}",
        domain in "[a-z]{3,10}",
    ) {
        let redactor = shunt_ai::LocalRedactor::new(true, true, &[], shunt_ai::RedactionMode::Mask)
            .expect("redactor builds");
        let aws_key = format!("AKIA{aws_tail}");
        let email = format!("{user}@{domain}.com");
        let text = format!("{prefix} {aws_key} {email} {suffix}");
        let (once, count1) = redactor.redact_text(&text);
        prop_assert!(count1 >= 2);
        prop_assert!(!once.contains(&aws_key), "AWS key leaked: {once}");
        prop_assert!(!once.contains(&email), "email leaked: {once}");

        // Idempotence: redacting already-redacted text changes nothing.
        let (twice, count2) = redactor.redact_text(&once);
        prop_assert_eq!(once, twice);
        prop_assert_eq!(count2, 0);
    }

    #[test]
    fn guardrail_external_parsers_and_extractors_never_panic(raw in prop::collection::vec(any::<u8>(), 0..512)) {
        let _ = shunt_ai::parse_webhook_guardrail_response(&raw, shunt_ai::GuardrailAction::Block);
        let _ = shunt_ai::parse_opa_guardrail_response(&raw, shunt_ai::GuardrailAction::Block);
        let _ = shunt_ai::parse_presidio_analyze_response(&raw, 0.5, shunt_ai::GuardrailAction::Redact);
        let _ = shunt_ai::parse_lakera_guardrail_response(&raw, shunt_ai::GuardrailAction::Block);
        let _ = shunt_ai::parse_bedrock_guardrail_response(&raw, shunt_ai::GuardrailAction::Block);
        let _ = shunt_ai::parse_llama_guard_response(&raw, shunt_ai::GuardrailAction::Block);
        let _ = shunt_ai::extract_request_text(&raw, &[]);
        let _ = shunt_ai::extract_response_text(&raw);
    }

    #[test]
    fn multipart_model_rewrite_preserves_arbitrary_binary_parts(
        boundary in "[A-Za-z0-9]{6,20}",
        old_model in "[a-zA-Z0-9._-]{1,24}",
        new_model in "[a-zA-Z0-9._-]{1,24}",
        binary_payload in prop::collection::vec(any::<u8>(), 0..512),
    ) {
        // Ensure random binary payload does not accidentally contain the boundary delimiter.
        let delim = format!("--{boundary}");
        prop_assume!(
            !binary_payload
                .windows(delim.len())
                .any(|w| w == delim.as_bytes())
        );

        let mut body = Vec::new();
        body.extend_from_slice(
            format!(
                "--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"audio.bin\"\r\nContent-Type: application/octet-stream\r\n\r\n"
            )
            .as_bytes(),
        );
        body.extend_from_slice(&binary_payload);
        body.extend_from_slice(
            format!(
                "\r\n--{boundary}\r\nContent-Disposition: form-data; name=\"model\"\r\n\r\n{old_model}\r\n--{boundary}--\r\n"
            )
            .as_bytes(),
        );

        let extracted_old = shunt_ai::extract_multipart_text_field(&body, &boundary, "model");
        prop_assert_eq!(extracted_old.as_deref(), Some(old_model.as_str()));

        if old_model == new_model {
            prop_assert!(
                shunt_ai::rewrite_multipart_text_field(&body, &boundary, "model", &new_model)
                    .is_none()
            );
        } else {
            let rewritten =
                shunt_ai::rewrite_multipart_text_field(&body, &boundary, "model", &new_model)
                    .expect("expected rewrite when model differs");
            let extracted_new =
                shunt_ai::extract_multipart_text_field(&rewritten, &boundary, "model");
            prop_assert_eq!(extracted_new.as_deref(), Some(new_model.as_str()));
            if !binary_payload.is_empty() {
                prop_assert!(
                    rewritten
                        .windows(binary_payload.len())
                        .any(|w| w == binary_payload.as_slice()),
                    "binary part corrupted during multipart model rewrite"
                );
            }
        }
    }

    #[test]
    fn cosine_similarity_is_bounded_symmetric_and_self_unit(
        a in prop::collection::vec(-100.0f32..100.0f32, 1..64),
        b in prop::collection::vec(-100.0f32..100.0f32, 1..64),
    ) {
        let len = a.len().min(b.len());
        let sa = &a[..len];
        let sb = &b[..len];
        let sim_ab = shunt_ai::cosine_similarity(sa, sb);
        let sim_ba = shunt_ai::cosine_similarity(sb, sa);
        prop_assert!(sim_ab.is_finite());
        prop_assert!((-1.0001..=1.0001).contains(&sim_ab));
        prop_assert!((sim_ab - sim_ba).abs() < 1e-5);

        let norm_sq: f64 = sa.iter().map(|&x| (x as f64) * (x as f64)).sum();
        if norm_sq > 1e-6 {
            let self_sim = shunt_ai::cosine_similarity(sa, sa);
            prop_assert!((self_sim - 1.0).abs() < 1e-4, "self_sim={self_sim}");
        }
    }

    #[test]
    fn multimodal_parsers_and_translators_never_panic(
        raw in prop::collection::vec(any::<u8>(), 0..512),
    ) {
        let s = String::from_utf8_lossy(&raw);
        let _ = shunt_ai::parse_multipart_boundary(&s);
        let _ = shunt_ai::extract_multipart_text_field(&raw, "boundary", "model");
        let _ = shunt_ai::rewrite_multipart_text_field(&raw, "boundary", "model", "gpt-4o");
        let _ = shunt_ai::openai_to_bedrock_rerank_request(&raw, "amazon.rerank-v1:0", "us-east-1");
        let _ = shunt_ai::bedrock_to_openai_rerank_response(
            &raw,
            shunt_plugin_sdk::StatusCode::OK,
            "amazon.rerank-v1:0",
            None,
        );
        let _ = shunt_ai::normalize_voyage_rerank_response(
            &raw,
            shunt_plugin_sdk::StatusCode::OK,
            "rerank-2",
        );
        let _ = shunt_ai::openai_to_gemini_imagen_request(&raw);
        let _ = shunt_ai::gemini_imagen_to_openai_response(&raw, shunt_plugin_sdk::StatusCode::OK);
        let _ = shunt_ai::parse_embedding_vector(&raw);
        let _ = shunt_ai::extract_query_param(Some(&s), "model");
    }
}
