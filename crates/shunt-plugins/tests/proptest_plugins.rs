use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;

use proptest::prelude::*;
use shunt_plugin_sdk::{Clock, ManualClock, TraceContext};
use shunt_plugins::rate_limit::{BucketTable, TokenBucket};
use shunt_plugins::{
    ContentEncoding, IpNet, base64url_decode, base64url_encode, negotiate_accept_encoding,
    parse_jwks_json, parse_jwt_unverified,
};

#[derive(Debug, Clone)]
enum BucketOp {
    Consume,
    AdvanceMs(u64),
}

fn arb_bucket_op() -> impl Strategy<Value = BucketOp> {
    prop_oneof![
        Just(BucketOp::Consume),
        (0u64..2_500).prop_map(BucketOp::AdvanceMs),
    ]
}

#[derive(Debug, Clone)]
enum TableOp {
    Request { key_id: usize },
    AdvanceMs(u64),
    Shrink(usize),
}

fn arb_table_op() -> impl Strategy<Value = TableOp> {
    prop_oneof![
        (0usize..120).prop_map(|key_id| TableOp::Request { key_id }),
        (0u64..5_000).prop_map(TableOp::AdvanceMs),
        (1usize..25).prop_map(TableOp::Shrink),
    ]
}

proptest! {
    #[test]
    fn token_bucket_obeys_capacity_rate_and_retry_after_invariants(
        rps in 0.5f64..100.0,
        burst in 1u32..50,
        ops in prop::collection::vec(arb_bucket_op(), 1..120),
    ) {
        let clock = ManualClock::new();
        let mut bucket = TokenBucket::new(burst, clock.now());
        let mut allowed: u64 = 0;

        for op in ops {
            match op {
                BucketOp::Consume => {
                    let now = clock.now();
                    match bucket.try_consume(rps, f64::from(burst), now) {
                        Ok(remaining) => {
                            allowed += 1;
                            prop_assert!(remaining < burst);
                        }
                        Err(retry_after) => {
                            prop_assert!(retry_after >= 1, "Retry-After must be >= 1");
                        }
                    }

                    // Tokens always finite and within [0, burst]
                    let t = bucket.tokens();
                    prop_assert!(t.is_finite());
                    prop_assert!(t >= 0.0 && t <= f64::from(burst) + 1e-9);

                    // Over [0, T], total allowed <= burst + floor(T * rps) (+1e-6 FP tolerance)
                    let total_secs = clock.now().as_secs_f64();
                    let upper_bound = f64::from(burst) + (total_secs * rps).floor() + 1e-6;
                    prop_assert!(
                        (allowed as f64) <= upper_bound,
                        "allowed={allowed} exceeded burst({burst}) + floor(T({total_secs})*rps({rps}))"
                    );
                }
                BucketOp::AdvanceMs(dt) => {
                    clock.advance_ms(dt);
                }
            }
        }
    }

    #[test]
    fn bucket_table_enforces_bounded_cardinality_across_ops(
        initial_max in 1usize..30,
        idle_ttl_ms in 0u64..10_000,
        rps in 1.0f64..50.0,
        burst in 1u32..10,
        ops in prop::collection::vec(arb_table_op(), 1..150),
    ) {
        let clock = ManualClock::new();
        let table = BucketTable::new();
        let mut max_entries = initial_max;
        let idle_ttl = Duration::from_millis(idle_ttl_ms);

        for op in ops {
            match op {
                TableOp::Request { key_id } => {
                    let key = format!("client-{key_id}");
                    let res = table.check_and_consume(
                        key,
                        rps,
                        burst,
                        clock.now(),
                        max_entries,
                        idle_ttl,
                    );
                    if let Err(retry_after) = res {
                        prop_assert!(retry_after >= 1);
                    }
                    prop_assert!(
                        table.len() <= max_entries,
                        "table.len()={} exceeded max_entries={max_entries}",
                        table.len()
                    );
                }
                TableOp::AdvanceMs(dt) => {
                    clock.advance_ms(dt);
                }
                TableOp::Shrink(new_cap) => {
                    max_entries = new_cap.max(1);
                    table.shrink_to(max_entries);
                    prop_assert!(
                        table.len() <= max_entries,
                        "after shrink_to({max_entries}), table.len()={}",
                        table.len()
                    );
                }
            }
        }
    }

    #[test]
    fn traceparent_parser_never_panics_and_enforces_w3c_invariants(input in ".*") {
        if let Some(parsed) = TraceContext::parse_traceparent(&input) {
            prop_assert_ne!(parsed.trace_id, [0u8; 16]);
            prop_assert_ne!(parsed.parent_id, [0u8; 8]);
            let child = TraceContext::child_from(parsed, parsed.is_sampled(), None);
            let formatted = child.format_traceparent();
            let reparsed = TraceContext::parse_traceparent(&formatted);
            prop_assert!(reparsed.is_some());
            let reparsed = reparsed.unwrap();
            prop_assert_eq!(reparsed.trace_id, parsed.trace_id);
            prop_assert_eq!(reparsed.parent_id, child.span_id);
            prop_assert_eq!(reparsed.is_sampled(), child.is_sampled());
        }
    }

    #[test]
    fn trace_id_ratio_sampling_is_monotonic(
        trace_id in any::<[u8; 16]>(),
        r1 in 0.0f64..=1.0,
        r2 in 0.0f64..=1.0,
    ) {
        let (low, high) = if r1 <= r2 { (r1, r2) } else { (r2, r1) };
        if TraceContext::should_sample_trace_id(trace_id, low) {
            prop_assert!(TraceContext::should_sample_trace_id(trace_id, high));
        }
        prop_assert!(!TraceContext::should_sample_trace_id(trace_id, 0.0));
        prop_assert!(TraceContext::should_sample_trace_id(trace_id, 1.0));
    }

    #[test]
    fn base64url_round_trip_arbitrary_bytes(data in prop::collection::vec(any::<u8>(), 0..512)) {
        let encoded = base64url_encode(&data);
        prop_assert!(!encoded.contains('='));
        prop_assert!(!encoded.contains('+'));
        prop_assert!(!encoded.contains('/'));
        let decoded = base64url_decode(&encoded).expect("valid base64url must decode");
        prop_assert_eq!(decoded, data);
    }

    #[test]
    fn jwt_and_jwks_parsers_never_panic_on_arbitrary_input(input in ".*") {
        let _ = parse_jwt_unverified(&input);
        let _ = parse_jwks_json(&input);
    }

    #[test]
    fn cidr_contains_monotonic_with_prefix_length(
        ip_bits in any::<u32>(),
        net_bits in any::<u32>(),
        p1 in 0u8..=32,
        p2 in 0u8..=32,
    ) {
        let (narrow, wide) = if p1 >= p2 { (p1, p2) } else { (p2, p1) };
        let base_ip = Ipv4Addr::from(net_bits);
        let target = IpAddr::V4(Ipv4Addr::from(ip_bits));
        let narrow_net = IpNet::parse(&format!("{base_ip}/{narrow}")).unwrap();
        let wide_net = IpNet::parse(&format!("{base_ip}/{wide}")).unwrap();
        if narrow_net.contains(target) {
            prop_assert!(wide_net.contains(target));
        }
        // Any IPv4 address always matches its own /32 and 0.0.0.0/0
        let self_net = IpNet::parse(&format!("{}/32", Ipv4Addr::from(ip_bits))).unwrap();
        prop_assert!(self_net.contains(target));
    }

    #[test]
    fn accept_encoding_negotiation_never_panics_and_returns_supported(header in ".*") {
        let supported = [ContentEncoding::Zstd, ContentEncoding::Br, ContentEncoding::Gzip];
        if let Some(enc) = negotiate_accept_encoding(&header, &supported) {
            prop_assert!(supported.contains(&enc));
        }
    }
}
