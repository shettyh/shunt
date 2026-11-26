use std::sync::Arc;
use std::time::Duration;

use http::header::{self, HeaderName, HeaderValue};
use http::{HeaderMap, Uri};
use proptest::prelude::*;
use shunt_engine::pipeline::{strip_hop_by_hop_headers, strip_uri_prefix};
use shunt_engine::{
    CompiledPathRegex, CompiledPathTemplate, EndpointState, PathMatch, RouteIndex, RouteMatch,
    RouteSpec, RuntimeRegistry, SnapshotBuilder, UpstreamConfig, UpstreamPool, host_matches,
    select_endpoint_index,
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
        let stripped = strip_uri_prefix(&uri, &prefix).unwrap();

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

    #[test]
    fn resp2_frame_roundtrip_and_prefix_invariance(
        simple in "[a-zA-Z0-9 _:-]{0,32}",
        err_msg in "[a-zA-Z0-9 _:-]{0,32}",
        num in any::<i64>(),
        bulk in prop::option::of(prop::collection::vec(any::<u8>(), 0..64)),
    ) {
        let frame = shunt_engine::RespValue::Array(Some(vec![
            shunt_engine::RespValue::SimpleString(simple),
            shunt_engine::RespValue::Error(err_msg),
            shunt_engine::RespValue::Integer(num),
            shunt_engine::RespValue::BulkString(bulk),
            shunt_engine::RespValue::Array(None),
        ]));
        let mut wire = Vec::new();
        shunt_engine::encode_resp_value(&frame, &mut wire);

        for cut in 0..wire.len() {
            prop_assert_eq!(shunt_engine::decode_resp_frame(&wire[..cut]), Ok(None));
        }
        let decoded = shunt_engine::decode_resp_frame(&wire).unwrap().unwrap();
        prop_assert_eq!(decoded.0, frame);
        prop_assert_eq!(decoded.1, wire.len());
    }

    #[test]
    fn resp2_decoder_never_panics_on_arbitrary_bytes(
        raw in prop::collection::vec(any::<u8>(), 0..256),
    ) {
        let _ = shunt_engine::decode_resp_frame(&raw);
    }

    #[test]
    fn swrr_schedule_preserves_exact_weight_ratios(
        weights in prop::collection::vec(1u32..50, 2..6),
    ) {
        let schedule = shunt_engine::build_swrr_schedule(&weights);
        if weights.iter().all(|&w| w == weights[0]) {
            prop_assert!(schedule.is_empty());
        } else {
            prop_assert!(!schedule.is_empty());
            let total_w: u64 = weights.iter().map(|&w| w as u64).sum();
            let slen = schedule.len() as u64;
            for (idx, &w) in weights.iter().enumerate() {
                let count = schedule.iter().filter(|&&i| i == idx).count() as u64;
                // Exact proportion: count / slen == w / total_w
                prop_assert_eq!(count * total_w, (w as u64) * slen);
            }
        }
    }

    #[test]
    fn select_weighted_endpoint_index_respects_3_pass_health_priority(
        weights in prop::collection::vec(1u32..40, 1..8),
        healthy_raw in prop::collection::vec(any::<bool>(), 1..8),
        cursor in 0usize..500,
        tried in prop::collection::vec(0usize..8, 0..8),
    ) {
        let len = weights.len().min(healthy_raw.len());
        let weights = &weights[..len];
        let healthy = &healthy_raw[..len];
        let schedule = shunt_engine::build_swrr_schedule(weights);

        let chosen = shunt_engine::select_weighted_endpoint_index(
            cursor,
            weights,
            &schedule,
            &tried,
            healthy,
        );
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
        }
    }

    #[test]
    fn route_match_headers_require_all_configured_pairs_case_insensitively(
        k1 in "[a-z]{2,8}",
        v1 in "[a-z0-9_-]{1,12}",
        k2 in "[a-z]{2,8}",
        v2 in "[a-z0-9_-]{1,12}",
        extra_v in "[a-z0-9_-]{1,12}",
    ) {
        let h1 = HeaderName::from_bytes(format!("x-hdr-a-{k1}").as_bytes()).unwrap();
        let h2 = HeaderName::from_bytes(format!("x-hdr-b-{k2}").as_bytes()).unwrap();
        let rm = shunt_engine::RouteMatch::prefix("/v2")
            .with_header(h1.clone(), v1.clone())
            .with_header(h2.clone(), v2.clone());

        // Request with both required headers (plus an extra value on h1) must match.
        let req_ok = http::Request::builder()
            .uri("/v2/items")
            .header(h1.as_str().to_ascii_uppercase(), extra_v.as_str())
            .header(h1.as_str(), v1.as_str())
            .header(h2.as_str().to_ascii_uppercase(), v2.as_str())
            .body(())
            .unwrap();
        prop_assert!(rm.matches(&req_ok));

        // Missing the second required header must never match.
        let req_missing = http::Request::builder()
            .uri("/v2/items")
            .header(h1.as_str(), v1.as_str())
            .body(())
            .unwrap();
        prop_assert!(!rm.matches(&req_missing));

        // Wrong value on the second header must never match.
        let wrong_v2 = format!("{v2}-mismatch");
        let req_wrong = http::Request::builder()
            .uri("/v2/items")
            .header(h1.as_str(), v1.as_str())
            .header(h2.as_str(), wrong_v2.as_str())
            .body(())
            .unwrap();
        prop_assert!(!rm.matches(&req_wrong));
    }

    #[test]
    fn x509_der_client_cert_parser_never_panics_on_arbitrary_bytes(
        raw in prop::collection::vec(any::<u8>(), 0..512),
    ) {
        if let Some(info) = shunt_engine::parse_client_cert_info(&raw) {
            prop_assert_eq!(info.sha256_fingerprint.len(), 64);
        }
    }

    #[test]
    fn path_template_matches_and_extracts_exact_params(
        tenant in "[a-z0-9_-]{1,10}",
        order_id in "[a-zA-Z0-9_-]{1,12}",
        tail_a in "[a-z0-9._-]{1,8}",
        tail_b in "[a-z0-9._-]{1,8}",
    ) {
        let tpl = CompiledPathTemplate::parse("/{tenant}/orders/{order_id}/status").unwrap();
        let good = format!("/{tenant}/orders/{order_id}/status");
        prop_assert!(tpl.matches(&good));
        let params = tpl.extract_params(&good);
        prop_assert_eq!(params.get("tenant"), Some(tenant.as_str()));
        prop_assert_eq!(params.get("order_id"), Some(order_id.as_str()));
        prop_assert_eq!(params.len(), 2);

        // Extra slash inside a single-segment param or trailing slash must never match.
        let bad_nested = format!("/{tenant}/orders/{order_id}/extra/status");
        let bad_trailing = format!("/{tenant}/orders/{order_id}/status/");
        let bad_empty = format!("/{tenant}/orders//status");
        prop_assert!(!tpl.matches(&bad_nested));
        prop_assert!(!tpl.matches(&bad_trailing));
        prop_assert!(!tpl.matches(&bad_empty));

        // Catch-all wildcard captures multi-segment tails cleanly.
        let wild = CompiledPathTemplate::parse("/files/{*filepath}").unwrap();
        let tail = format!("{tail_a}/{tail_b}");
        let wild_path = format!("/files/{tail}");
        prop_assert!(wild.matches(&wild_path));
        let wild_params = wild.extract_params(&wild_path);
        prop_assert_eq!(wild_params.get("filepath"), Some(tail.as_str()));
        prop_assert!(!wild.matches("/files"));
        prop_assert!(!wild.matches("/files/"));
    }

    #[test]
    fn snapshot_and_route_index_match_route_is_equivalent_to_linear_scan(
        route_kinds in prop::collection::vec((0u8..16, 0u8..4, 0u8..4, 0u8..3), 1..48),
        req_path in prop_oneof![
            Just("/"),
            Just("//"),
            Just("/orders"),
            Just("/orders/"),
            Just("/orders//status"),
            Just("/orders/123/status"),
            Just("/orders/123/status/"),
            Just("/orders/abc/status"),
            Just("/orders/status"),
            Just("/orders/123/cancel"),
            Just("/invoices/2026/42.pdf"),
            Just("/files"),
            Just("/files/"),
            Just("/files//a"),
            Just("/files/a/b/c.txt"),
            Just("/api/v1/items"),
            Just("/a//b/c"),
            Just("/other"),
        ],
        req_host in prop_oneof![
            Just("api.example.com"),
            Just("sub.example.com"),
            Just("other.org"),
        ],
        req_method in prop_oneof![
            Just(http::Method::GET),
            Just(http::Method::POST),
            Just(http::Method::DELETE),
        ],
        req_canary in any::<bool>(),
    ) {
        let reg = RuntimeRegistry::new();
        let mut builder = SnapshotBuilder::new(1).upstream(UpstreamConfig::new(
            "be",
            vec!["http://127.0.0.1:8081".to_owned()],
        ));
        let canary_hdr = HeaderName::from_static("x-canary");

        for (i, (kind, host_kind, method_kind, hdr_kind)) in route_kinds.iter().enumerate() {
            let path = match kind {
                0 => PathMatch::Exact("/orders/123/status".to_owned()),
                1 => PathMatch::Exact("/".to_owned()),
                2 => PathMatch::Prefix("/orders".to_owned()),
                3 => PathMatch::Prefix("/orders/".to_owned()),
                4 => PathMatch::Prefix("/".to_owned()),
                5 => PathMatch::Prefix("/a//b".to_owned()),
                6 => PathMatch::Template(
                    CompiledPathTemplate::parse("/orders/{order_id}/status").unwrap(),
                ),
                7 => PathMatch::Template(
                    CompiledPathTemplate::parse("/{tenant}/status").unwrap(),
                ),
                8 => PathMatch::Template(
                    CompiledPathTemplate::parse("/files/{*filepath}").unwrap(),
                ),
                9 => PathMatch::Template(
                    CompiledPathTemplate::parse("/{*all}").unwrap(),
                ),
                10 => PathMatch::Template(
                    CompiledPathTemplate::parse("/orders/123/status").unwrap(),
                ),
                11 => PathMatch::Template(
                    CompiledPathTemplate::parse("/").unwrap(),
                ),
                12 => PathMatch::Regex(
                    CompiledPathRegex::compile(r"/orders/(?P<id>[0-9]+)/status").unwrap(),
                ),
                13 => PathMatch::Regex(
                    CompiledPathRegex::compile(r"/invoices/[0-9]{4}/[0-9]+\.pdf").unwrap(),
                ),
                14 => PathMatch::Regex(CompiledPathRegex::compile(r"/api/v[0-9]+/.*").unwrap()),
                _ => PathMatch::Any,
            };
            let mut matcher = RouteMatch {
                path,
                ..RouteMatch::default()
            };
            match host_kind {
                1 => matcher.hosts.push("api.example.com".to_owned()),
                2 => matcher.hosts.push("*.example.com".to_owned()),
                3 => matcher.hosts.push("other.org".to_owned()),
                _ => {}
            }
            match method_kind {
                1 => matcher.methods.push(http::Method::GET),
                2 => matcher.methods.push(http::Method::POST),
                3 => matcher.methods.push(http::Method::DELETE),
                _ => {}
            }
            match hdr_kind {
                1 => matcher.headers.push((canary_hdr.clone(), "true".to_owned())),
                2 => matcher.headers.push((canary_hdr.clone(), "false".to_owned())),
                _ => {}
            }
            builder = builder.route(RouteSpec::new(format!("r_{i}"), matcher, "be"));
        }

        let snap = builder.build(&reg, false).unwrap();
        let index = RouteIndex::build(&snap.routes);

        let mut req_builder = http::Request::builder()
            .method(req_method)
            .uri(req_path)
            .header(http::header::HOST, req_host);
        if req_canary {
            req_builder = req_builder.header("x-canary", "true");
        }
        let req = req_builder.body(()).unwrap();

        let linear = snap.match_route_linear(&req).map(|r| r.id.as_str());
        let fast = snap.match_route(&req).map(|r| r.id.as_str());
        let indexed = index.match_route(&snap.routes, &req).map(|r| r.id.as_str());
        prop_assert_eq!(fast, linear);
        prop_assert_eq!(indexed, linear);
    }
}
