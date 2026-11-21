use std::collections::HashMap;
use std::time::Duration;

use proptest::prelude::*;
use serde_json::{Value, json};
use shunt_ai::aws_eventstream::{AwsEventStreamDecoder, encode_eventstream_frame};
use shunt_ai::dialects::bedrock::{BedrockStreamTranslator, openai_to_bedrock_converse_request};
use shunt_ai::dialects::gemini::{GeminiSseTranslator, openai_to_gemini_request};
use shunt_ai::failover::{FailoverCircuitState, compute_cooldown};
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
}
