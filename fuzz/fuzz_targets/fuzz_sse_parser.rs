#![no_main]

use libfuzzer_sys::fuzz_target;
use shunt_ai::sse::SseParser;

fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }

    // Use first byte as chunk step size (1..=32) to verify chunk-split invariance under fuzzing.
    let step = ((data[0] as usize) % 32) + 1;
    let payload = &data[1..];

    let mut whole = SseParser::new();
    let mut whole_events = whole.push(payload);
    whole_events.extend(whole.finish());

    let mut chunked = SseParser::new();
    let mut chunked_events = Vec::new();
    for chunk in payload.chunks(step) {
        chunked_events.extend(chunked.push(chunk));
    }
    chunked_events.extend(chunked.finish());

    assert_eq!(whole_events, chunked_events);
});
