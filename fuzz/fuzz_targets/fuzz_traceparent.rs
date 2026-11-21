#![no_main]

use libfuzzer_sys::fuzz_target;
use shunt_plugin_sdk::TraceContext;

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data)
        && let Some(parsed) = TraceContext::parse_traceparent(s)
    {
        assert_ne!(parsed.trace_id, [0u8; 16]);
        assert_ne!(parsed.parent_id, [0u8; 8]);
        let child = TraceContext::child_from(parsed, parsed.is_sampled(), None);
        let formatted = child.format_traceparent();
        let reparsed = TraceContext::parse_traceparent(&formatted)
            .expect("formatted child traceparent must always parse");
        assert_eq!(reparsed.trace_id, parsed.trace_id);
        assert_eq!(reparsed.parent_id, child.span_id);
    }
});
