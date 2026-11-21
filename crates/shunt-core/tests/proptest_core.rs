use std::sync::Arc;
use std::time::Duration;

use http::header::{self, HeaderName, HeaderValue};
use http::{HeaderMap, Uri};
use proptest::prelude::*;
use shunt_core::pipeline::{strip_hop_by_hop_headers, strip_uri_prefix};
use shunt_core::{
    EndpointState, PathMatch, UpstreamConfig, UpstreamPool, host_matches, select_endpoint_index,
};
use shunt_plugin_sdk::{Clock, ManualClock};

proptest! {
    #[test]
    fn path_prefix_never_matches_partial_segment(
        seg in "[a-z0-9_-]{1,12}",
        extra in "[a-z0-9_-]{1,8}",
        rest in "[a-z0-9_/-]{0,16}",
    ) {
        let prefix = format!("/{seg}");
        let matcher = PathMatch::Prefix(prefix.clone());

        // Exact segment & child segments must match
        let with_slash = format!("{prefix}/");
        let with_rest = format!("{prefix}/{rest}");
        prop_assert!(matcher.matches(&prefix));
        prop_assert!(matcher.matches(&with_slash));
        prop_assert!(matcher.matches(&with_rest));

        // Sibling segment starting with same letters must NEVER match
        let sibling = format!("/{seg}{extra}");
        let sibling_rest = format!("{sibling}/{rest}");
        prop_assert!(!matcher.matches(&sibling));
        prop_assert!(!matcher.matches(&sibling_rest));
    }

    #[test]
    fn host_matches_case_insensitive_and_wildcard_safe(
        sub in "[a-zA-Z0-9-]{1,10}",
        label in "[a-zA-Z0-9-]{1,10}",
        tld in "[a-zA-Z]{2,6}",
    ) {
        let suffix = format!("{label}.{tld}");
        let wildcard = format!("*.{suffix}");
        let valid_child = format!("{sub}.{suffix}");
        let deep_child = format!("{sub}.{sub}.{suffix}");
        let evil_suffix = format!("{sub}{suffix}");

        // Exact is case-insensitive
        prop_assert!(host_matches(&suffix.to_ascii_lowercase(), &suffix.to_ascii_uppercase()));
        prop_assert!(host_matches(&suffix.to_ascii_uppercase(), &suffix.to_ascii_lowercase()));

        // Wildcard matches subdomains regardless of casing
        prop_assert!(host_matches(&wildcard, &valid_child));
        prop_assert!(host_matches(&wildcard.to_ascii_uppercase(), &valid_child.to_ascii_lowercase()));
        prop_assert!(host_matches(&wildcard, &deep_child));

        // Wildcard NEVER matches bare suffix or non-dot-separated suffix
        prop_assert!(!host_matches(&wildcard, &suffix));
        prop_assert!(!host_matches(&wildcard, &evil_suffix));
    }

    #[test]
    fn strip_uri_prefix_preserves_leading_slash_and_query(
        seg in "[a-z0-9_-]{1,10}",
        tail in prop::option::of("[a-z0-9_-]{1,10}"),
        query in prop::option::of("[a-z0-9_=&-]{1,20}"),
    ) {
        let prefix = format!("/{seg}");
        let path = match &tail {
            Some(t) => format!("/{seg}/{t}"),
            None => format!("/{seg}"),
        };
        let raw_uri = match &query {
            Some(q) => format!("{path}?{q}"),
            None => path.clone(),
        };
        let uri: Uri = raw_uri.parse().unwrap();
        let stripped = strip_uri_prefix(&uri, &prefix);

        prop_assert!(stripped.path().starts_with('/'));
        prop_assert_eq!(stripped.query(), query.as_deref());

        let expected_path = match &tail {
            Some(t) => format!("/{t}"),
            None => "/".to_owned(),
        };
        prop_assert_eq!(stripped.path(), expected_path.as_str());
    }

    #[test]
    fn strip_hop_by_hop_removes_nominated_and_rfc9110_headers(
        custom_hops in prop::collection::vec("[a-z]{3,8}", 0..4),
        keep_headers in prop::collection::vec("[a-z]{3,8}", 0..4),
        te_is_trailers in any::<bool>(),
    ) {
        let mut map = HeaderMap::new();

        // Standard RFC 9110 hop-by-hop headers
        let keep_alive = HeaderName::from_static("keep-alive");
        map.insert(keep_alive.clone(), HeaderValue::from_static("timeout=5"));
        map.insert(header::PROXY_AUTHENTICATE, HeaderValue::from_static("Basic"));
        map.insert(header::PROXY_AUTHORIZATION, HeaderValue::from_static("Basic abc"));
        map.insert(header::TRAILER, HeaderValue::from_static("x-checksum"));
        map.insert(header::TRANSFER_ENCODING, HeaderValue::from_static("chunked"));
        map.insert(header::UPGRADE, HeaderValue::from_static("h2c"));

        if te_is_trailers {
            map.insert(header::TE, HeaderValue::from_static("Trailers"));
        } else {
            map.insert(header::TE, HeaderValue::from_static("gzip"));
        }

        // Nominate custom headers via Connection: ...
        let mut conn_tokens = Vec::new();
        let mut hop_names = Vec::new();
        for h in &custom_hops {
            let full = format!("x-hop-{h}");
            let name = HeaderName::from_bytes(full.as_bytes()).unwrap();
            map.insert(name.clone(), HeaderValue::from_static("1"));
            conn_tokens.push(full);
            hop_names.push(name);
        }
        if !conn_tokens.is_empty() {
            map.insert(
                header::CONNECTION,
                HeaderValue::from_str(&conn_tokens.join(", ")).unwrap(),
            );
        } else {
            map.insert(header::CONNECTION, HeaderValue::from_static("keep-alive"));
        }

        // Safe end-to-end headers (distinct prefix `x-keep-`)
        let mut keep_names = Vec::new();
        for k in &keep_headers {
            let full = format!("x-keep-{k}");
            let name = HeaderName::from_bytes(full.as_bytes()).unwrap();
            map.insert(name.clone(), HeaderValue::from_static("v"));
            keep_names.push(name);
        }

        strip_hop_by_hop_headers(&mut map);

        prop_assert!(!map.contains_key(header::CONNECTION));
        prop_assert!(!map.contains_key(&keep_alive));
        prop_assert!(!map.contains_key(header::PROXY_AUTHENTICATE));
        prop_assert!(!map.contains_key(header::PROXY_AUTHORIZATION));
        prop_assert!(!map.contains_key(header::TRAILER));
        prop_assert!(!map.contains_key(header::TRANSFER_ENCODING));
        prop_assert!(!map.contains_key(header::UPGRADE));

        for hn in &hop_names {
            prop_assert!(!map.contains_key(hn));
        }
        for kn in &keep_names {
            prop_assert!(map.contains_key(kn));
        }

        if te_is_trailers {
            prop_assert!(map.contains_key(header::TE));
        } else {
            prop_assert!(!map.contains_key(header::TE));
        }
    }
}

#[derive(Debug, Clone)]
enum HealthOp {
    Fail(usize),
    Succeed(usize),
    AdvanceMs(u64),
    Select(Vec<usize>),
}

fn arb_health_op(num_eps: usize) -> impl Strategy<Value = HealthOp> {
    prop_oneof![
        (0..num_eps).prop_map(HealthOp::Fail),
        (0..num_eps).prop_map(HealthOp::Succeed),
        (0u64..15_000).prop_map(HealthOp::AdvanceMs),
        prop::collection::vec(0..num_eps, 0..=num_eps).prop_map(HealthOp::Select),
    ]
}

proptest! {
    #[test]
    fn endpoint_state_and_pool_selection_match_reference_model(
        num_eps in 1usize..6,
        threshold in 1usize..5,
        cooldown_ms in 100u64..10_000,
        ops in prop::collection::vec(arb_health_op(5), 1..80),
    ) {
        let clock = Arc::new(ManualClock::new());
        let endpoints: Vec<String> = (0..num_eps)
            .map(|i| format!("http://127.0.0.1:{}", 10000 + i))
            .collect();
        let mut cfg = UpstreamConfig::new("test-up", endpoints);
        cfg.unhealthy_threshold = threshold;
        cfg.unhealthy_cooldown = Duration::from_millis(cooldown_ms);

        let pool = UpstreamPool::new_with_clock(1, &cfg, clock.clone()).unwrap();

        // Reference model: per-endpoint (consecutive_failures, unhealthy_until_ms)
        let mut model: Vec<(usize, u64)> = vec![(0, 0); num_eps];

        for op in ops {
            match op {
                HealthOp::Fail(raw_idx) => {
                    let idx = raw_idx % num_eps;
                    let now = clock.now_ms();
                    pool.record_failure(idx);

                    model[idx].0 = model[idx].0.saturating_add(1).min(u16::MAX as usize);
                    if model[idx].0 >= threshold {
                        let candidate = now.saturating_add(cooldown_ms);
                        model[idx].1 = model[idx].1.max(candidate);
                    }
                }
                HealthOp::Succeed(raw_idx) => {
                    let idx = raw_idx % num_eps;
                    pool.record_success(idx);
                    model[idx] = (0, 0);
                }
                HealthOp::AdvanceMs(dt) => {
                    clock.advance_ms(dt);
                }
                HealthOp::Select(raw_tried) => {
                    let tried: Vec<usize> = raw_tried.into_iter().map(|i| i % num_eps).collect();
                    let now = clock.now_ms();
                    let (chosen, ep) = pool.select_endpoint(&tried);
                    prop_assert!(chosen < num_eps);
                    prop_assert_eq!(ep.raw_url.as_str(), pool.endpoints()[chosen].raw_url.as_str());

                    let healthy_flags: Vec<bool> = model
                        .iter()
                        .map(|&(_, until)| until == 0 || now >= until)
                        .collect();

                    let has_healthy_untried = (0..num_eps)
                        .any(|i| !tried.contains(&i) && healthy_flags[i]);
                    let has_any_untried = (0..num_eps).any(|i| !tried.contains(&i));
                    let has_any_healthy = (0..num_eps).any(|i| healthy_flags[i]);

                    if has_healthy_untried {
                        prop_assert!(!tried.contains(&chosen) && healthy_flags[chosen]);
                    } else if has_any_untried {
                        prop_assert!(!tried.contains(&chosen));
                    } else if has_any_healthy {
                        prop_assert!(healthy_flags[chosen]);
                    }
                }
            }

            // Assert exact lockstep state & NoSplitHealthState invariant for every endpoint
            let now = clock.now_ms();
            for (i, ep) in pool.endpoints().iter().enumerate() {
                let (fails, until) = ep.health_snapshot();
                prop_assert_eq!((fails, until), model[i]);

                // NoSplitHealthState invariants:
                if fails == 0 {
                    prop_assert_eq!(until, 0);
                }
                if fails < threshold {
                    prop_assert_eq!(until, 0);
                }
                if fails >= threshold {
                    prop_assert!(until > 0);
                }

                // Immediate recovery once now >= until
                prop_assert_eq!(ep.is_healthy(now), until == 0 || now >= until);
            }
        }
    }

    #[test]
    fn pure_select_endpoint_index_is_total_and_respects_priority(
        healthy in prop::collection::vec(any::<bool>(), 1..10),
        start in 0usize..100,
        tried in prop::collection::vec(0usize..10, 0..10),
    ) {
        let len = healthy.len();
        let chosen = select_endpoint_index(start, &tried, &healthy);
        prop_assert!(chosen < len);

        let has_healthy_untried = (0..len).any(|i| !tried.contains(&i) && healthy[i]);
        let has_untried = (0..len).any(|i| !tried.contains(&i));
        let has_healthy = healthy.iter().any(|&h| h);

        if has_healthy_untried {
            prop_assert!(!tried.contains(&chosen) && healthy[chosen]);
        } else if has_untried {
            prop_assert!(!tried.contains(&chosen));
        } else if has_healthy {
            prop_assert!(healthy[chosen]);
        } else {
            prop_assert_eq!(chosen, start % len);
        }
    }

    #[test]
    fn endpoint_state_single_word_atomic_never_splits_under_sequential_transitions(
        ops in prop::collection::vec((any::<bool>(), 0u64..10_000), 1..60),
        threshold in 1usize..6,
        cooldown_ms in 1u64..5_000,
    ) {
        let ep = EndpointState::new("http://127.0.0.1:8080".to_owned()).unwrap();
        let mut now = 0u64;
        for (is_fail, dt) in ops {
            now = now.saturating_add(dt);
            if is_fail {
                ep.record_failure(now, threshold, Duration::from_millis(cooldown_ms));
            } else {
                ep.record_success();
            }
            let (fails, until) = ep.health_snapshot();
            if fails == 0 {
                prop_assert_eq!(until, 0);
            } else if fails < threshold {
                prop_assert_eq!(until, 0);
            } else {
                prop_assert!(until >= cooldown_ms);
            }
        }
    }
}
