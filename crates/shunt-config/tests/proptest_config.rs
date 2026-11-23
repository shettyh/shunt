use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use proptest::prelude::*;
use serde_json::{Map, Value};
use shunt_config::{
    ConfigProvider, GatewayConfig, InlineConfigProvider, InspectorTrace, RouteGroupIr, RouteIr,
    SnapshotCompiler, TraceRingBuffer, UpstreamEndpointIr, UpstreamIr, host_pattern_subsumes,
    join_route_paths, redact_secrets, route_subsumes,
};
use shunt_engine::{PathMatch, RouteMatch, RuntimeRegistry, UpstreamConfig, UpstreamPoolKey};
use shunt_plugin_sdk::{
    BuildContext, HookMask, HttpPlugin, PluginBuildError, PluginConfig, PluginFactory,
    PluginRegistry,
};

const SECRET_SUBSTRINGS: &[&str] = &[
    "token",
    "secret",
    "password",
    "passwd",
    "api_key",
    "apikey",
    "authorization",
    "private_key",
    "credential",
];

fn random_case(base: &str, mask: u64) -> String {
    base.chars()
        .enumerate()
        .map(|(i, c)| {
            if (mask >> (i % 64)) & 1 == 1 {
                c.to_ascii_uppercase()
            } else {
                c.to_ascii_lowercase()
            }
        })
        .collect()
}

proptest! {
    #[test]
    fn redact_secrets_eliminates_all_nested_secret_values_regardless_of_casing(
        prefix in "[a-z_-]{0,6}",
        suffix in "[a-z_-]{0,6}",
        pattern_idx in 0usize..SECRET_SUBSTRINGS.len(),
        case_mask in any::<u64>(),
        secret_val in "[A-Za-z0-9]{12,24}",
        safe_val in "[a-z]{6,12}",
    ) {
        let raw_key = format!("{prefix}{}{suffix}", SECRET_SUBSTRINGS[pattern_idx]);
        let cased_key = random_case(&raw_key, case_mask);

        // Ensure secret_val cannot collide with safe_val or "[REDACTED]"
        prop_assume!(!secret_val.contains("REDACTED"));
        prop_assume!(secret_val != safe_val);

        let mut inner = Map::new();
        inner.insert(cased_key.clone(), Value::String(secret_val.clone()));
        inner.insert("public_label".to_owned(), Value::String(safe_val.clone()));

        let mut root = Map::new();
        root.insert(cased_key, Value::String(secret_val.clone()));
        root.insert("nested".to_owned(), Value::Array(vec![Value::Object(inner)]));
        root.insert("normal_field".to_owned(), Value::String(safe_val.clone()));

        let redacted = redact_secrets(&Value::Object(root));
        let serialized = serde_json::to_string(&redacted).unwrap();

        prop_assert!(
            !serialized.contains(&secret_val),
            "secret `{secret_val}` survived redaction in: {serialized}"
        );
        prop_assert!(serialized.contains("[REDACTED]"));
        prop_assert_eq!(redacted["normal_field"].as_str(), Some(safe_val.as_str()));
        prop_assert_eq!(
            redacted["nested"][0]["public_label"].as_str(),
            Some(safe_val.as_str())
        );
    }
}

/// Stateful dummy plugin that allocates a persistent counter in `StateStore` during build.
struct StatefulCounterPlugin {
    _counter: Arc<AtomicU64>,
}

impl HttpPlugin for StatefulCounterPlugin {
    fn name(&self) -> &str {
        "test-counter"
    }

    fn hook_mask(&self) -> HookMask {
        HookMask::EMPTY
    }
}

struct StatefulCounterFactory;

impl PluginFactory for StatefulCounterFactory {
    fn name(&self) -> &str {
        "test-counter"
    }

    fn build(
        &self,
        config: &PluginConfig,
        ctx: &BuildContext,
    ) -> Result<Arc<dyn HttpPlugin>, PluginBuildError> {
        if config.raw().get("fail").and_then(Value::as_bool) == Some(true) {
            return Err(PluginBuildError::BuildFailed {
                plugin: self.name().to_owned(),
                message: "injected failure".to_owned(),
            });
        }
        let counter = ctx.state_handle().get_or_init("hits", || AtomicU64::new(0));
        counter.fetch_add(1, Ordering::Relaxed);
        Ok(Arc::new(StatefulCounterPlugin { _counter: counter }))
    }
}

#[derive(Debug, Clone)]
enum CompilerOp {
    Valid {
        upstream_ports: Vec<u16>,
        route_ids: Vec<u8>,
    },
    InvalidMidway {
        extra_port: u16,
        extra_route: u8,
    },
    InvalidUnknownUpstream,
}

fn arb_compiler_op() -> impl Strategy<Value = CompilerOp> {
    prop_oneof![
        (
            prop::collection::vec(10000u16..10006, 1..4),
            prop::collection::vec(0u8..5, 1..4),
        )
            .prop_map(|(upstream_ports, route_ids)| CompilerOp::Valid {
                upstream_ports,
                route_ids,
            }),
        (11000u16..11010, 10u8..20).prop_map(|(extra_port, extra_route)| {
            CompilerOp::InvalidMidway {
                extra_port,
                extra_route,
            }
        }),
        Just(CompilerOp::InvalidUnknownUpstream),
    ]
}

fn render_valid_toml(
    ports: &[u16],
    route_ids: &[u8],
) -> (String, Vec<UpstreamPoolKey>, BTreeSet<String>) {
    let mut toml = String::from("[server]\nlisten = \"127.0.0.1:0\"\n[admin]\nenabled = false\n");

    let unique_ports: BTreeSet<u16> = ports.iter().copied().collect();
    let mut keys = Vec::new();
    let mut up_names = Vec::new();
    for p in &unique_ports {
        let name = format!("up_{p}");
        let ep = format!("http://127.0.0.1:{p}");
        toml.push_str(&format!(
            "\n[[upstreams]]\nname = \"{name}\"\nendpoints = [\"{ep}\"]\n"
        ));
        let mut cfg = UpstreamConfig::new(name.clone(), vec![ep]);
        cfg.connect_timeout = std::time::Duration::from_millis(5_000);
        cfg.pool_idle_timeout = std::time::Duration::from_millis(90_000);
        cfg.pool_max_idle_per_host = 64;
        cfg.unhealthy_threshold = 3;
        cfg.unhealthy_cooldown = std::time::Duration::from_millis(10_000);
        keys.push(cfg.pool_key());
        up_names.push(name);
    }

    let unique_routes: BTreeSet<u8> = route_ids.iter().copied().collect();
    let mut scopes = BTreeSet::new();
    for (i, rid) in unique_routes.iter().enumerate() {
        let up = &up_names[i % up_names.len()];
        let route_id = format!("r_{rid}");
        let scope = format!("route:{route_id}:counter-{rid}");
        scopes.insert(scope);
        toml.push_str(&format!(
            "\n[[routes]]\nid = \"{route_id}\"\npath_prefix = \"/{route_id}\"\nupstream = \"{up}\"\n\
             [[routes.plugins]]\nname = \"test-counter\"\nid = \"counter-{rid}\"\n"
        ));
    }

    (toml, keys, scopes)
}

proptest! {
    #[test]
    fn transactional_compiler_and_registry_match_reference_model(
        ops in prop::collection::vec(arb_compiler_op(), 1..30),
    ) {
        let mut reg = PluginRegistry::new();
        reg.register(StatefulCounterFactory);
        let runtime = Arc::new(RuntimeRegistry::new());
        let compiler = SnapshotCompiler::new(Arc::new(reg), Arc::clone(&runtime));

        // Reference model: active pool keys -> pool_id, active scopes -> build count
        let mut model_pools: BTreeMap<String, u64> = BTreeMap::new();
        let mut model_scopes: BTreeSet<String> = BTreeSet::new();
        let mut last_version: u64 = 0;

        for op in ops {
            match op {
                CompilerOp::Valid { upstream_ports, route_ids } => {
                    let (toml, _keys, scopes) = render_valid_toml(&upstream_ports, &route_ids);
                    let loaded = InlineConfigProvider::from_toml("prop.toml", toml)
                        .load()
                        .unwrap();
                    let bundle = compiler.compile(&loaded).expect("valid config must compile");

                    // Monotonic versions
                    prop_assert!(bundle.snapshot.version > last_version);
                    last_version = bundle.snapshot.version;

                    // Verify unchanged upstream keys preserved exact pool_id!
                    let mut next_model_pools = BTreeMap::new();
                    for up in &bundle.inspect.upstreams {
                        if let Some(&prev_id) = model_pools.get(&up.name) {
                            prop_assert_eq!(
                                up.pool_id, prev_id,
                                "unchanged upstream `{}` must reuse warm pool_id", up.name
                            );
                        }
                        next_model_pools.insert(up.name.clone(), up.pool_id);
                    }
                    model_pools = next_model_pools;
                    model_scopes = scopes;

                    // Exact pool & state counts after GC
                    prop_assert_eq!(runtime.pool_count(), model_pools.len());
                    prop_assert_eq!(runtime.state_store().len(), model_scopes.len());
                }
                CompilerOp::InvalidMidway { extra_port, extra_route } => {
                    // Builds a brand-new stateful plugin on route 1 (which would pollute StateStore
                    // if not staged), then fails on route 2's plugin!
                    let toml = format!(
                        r#"
[server]
listen = "127.0.0.1:0"
[admin]
enabled = false

[[upstreams]]
name = "ephemeral_{extra_port}"
endpoints = ["http://127.0.0.1:{extra_port}"]

[[routes]]
id = "ok_{extra_route}"
path_prefix = "/ok"
upstream = "ephemeral_{extra_port}"
[[routes.plugins]]
name = "test-counter"
id = "ephemeral-counter-{extra_route}"

[[routes]]
id = "boom_{extra_route}"
path_prefix = "/boom"
upstream = "ephemeral_{extra_port}"
[[routes.plugins]]
name = "test-counter"
[routes.plugins.config]
fail = true
"#
                    );
                    let loaded = InlineConfigProvider::from_toml("bad-midway.toml", toml)
                        .load()
                        .unwrap();
                    let before_pools = runtime.pool_count();
                    let before_state = runtime.state_store().len();

                    prop_assert!(compiler.compile(&loaded).is_err());

                    // Transactional invariant: failed compile NEVER mutates pool count or StateStore!
                    prop_assert_eq!(runtime.pool_count(), before_pools);
                    prop_assert_eq!(runtime.state_store().len(), before_state);
                    prop_assert_eq!(runtime.pool_count(), model_pools.len());
                    prop_assert_eq!(runtime.state_store().len(), model_scopes.len());
                }
                CompilerOp::InvalidUnknownUpstream => {
                    let toml = r#"
[server]
listen = "127.0.0.1:0"
[admin]
enabled = false
[[upstreams]]
name = "orphan_up"
endpoints = ["http://127.0.0.1:19999"]
[[routes]]
id = "bad_route"
path_prefix = "/"
upstream = "does_not_exist"
"#;
                    let loaded = InlineConfigProvider::from_toml("bad-up.toml", toml)
                        .load()
                        .unwrap();
                    let before_pools = runtime.pool_count();
                    let before_state = runtime.state_store().len();

                    prop_assert!(compiler.compile(&loaded).is_err());

                    prop_assert_eq!(runtime.pool_count(), before_pools);
                    prop_assert_eq!(runtime.state_store().len(), before_state);
                }
            }
        }
    }
}

fn arb_path_match() -> impl Strategy<Value = PathMatch> {
    prop_oneof![
        Just(PathMatch::Any),
        prop_oneof![
            Just("/".to_owned()),
            Just("/api".to_owned()),
            Just("/api/v1".to_owned()),
            Just("/apiv2".to_owned()),
            Just("/v1/chat".to_owned()),
        ]
        .prop_map(PathMatch::Prefix),
        prop_oneof![
            Just("/".to_owned()),
            Just("/api".to_owned()),
            Just("/api/v1".to_owned()),
            Just("/apiv2".to_owned()),
            Just("/v1/chat".to_owned()),
        ]
        .prop_map(PathMatch::Exact),
    ]
}

fn arb_host_list() -> impl Strategy<Value = Vec<String>> {
    prop::collection::vec(
        prop_oneof![
            Just("example.com".to_owned()),
            Just("api.example.com".to_owned()),
            Just("v1.api.example.com".to_owned()),
            Just("*.example.com".to_owned()),
            Just("*.api.example.com".to_owned()),
            Just("other.org".to_owned()),
        ],
        0..3,
    )
}

fn arb_method_list() -> impl Strategy<Value = Vec<http::Method>> {
    prop::collection::vec(
        prop_oneof![
            Just(http::Method::GET),
            Just(http::Method::POST),
            Just(http::Method::PUT),
            Just(http::Method::DELETE),
        ],
        0..3,
    )
}

fn arb_route_match() -> impl Strategy<Value = RouteMatch> {
    (arb_host_list(), arb_path_match(), arb_method_list()).prop_map(|(hosts, path, methods)| {
        RouteMatch {
            hosts,
            path,
            methods,
            headers: Vec::new(),
        }
    })
}

proptest! {
    /// Soundness proof (by exhaustive random testing) of `shunt verify`'s route-shadowing algebra:
    /// `route_subsumes(r1, r2) ==> ∀ req, r2.matches(req) ==> r1.matches(req)`.
    #[test]
    fn route_subsumes_is_sound_against_real_route_matcher(
        r1 in arb_route_match(),
        r2 in arb_route_match(),
        req_host in prop_oneof![
            Just("example.com"),
            Just("api.example.com"),
            Just("v1.api.example.com"),
            Just("sub.example.com"),
            Just("other.org"),
        ],
        req_path in prop_oneof![
            Just("/"),
            Just("/api"),
            Just("/api/"),
            Just("/api/v1"),
            Just("/api/v1/users"),
            Just("/apiv2"),
            Just("/apiv2/foo"),
            Just("/v1/chat"),
            Just("/other"),
        ],
        req_method in prop_oneof![
            Just(http::Method::GET),
            Just(http::Method::POST),
            Just(http::Method::PUT),
            Just(http::Method::DELETE),
        ],
    ) {
        if route_subsumes(&r1, &r2) {
            let req = http::Request::builder()
                .method(req_method)
                .uri(req_path)
                .header(http::header::HOST, req_host)
                .body(())
                .unwrap();
            if r2.matches(&req) {
                prop_assert!(
                    r1.matches(&req),
                    "soundness violation: r1={r1:?} claimed to subsume r2={r2:?}, but r2 matched {req_host}{req_path} while r1 did not"
                );
            }
        }
    }

    /// Invariants of the Admin Inspector `TraceRingBuffer`:
    /// 1. Buffered count never exceeds `capacity`.
    /// 2. Sequence numbers are strictly increasing (`1..=N`).
    /// 3. `recent(Some(after), None)` contains only traces with `seq > after`.
    /// 4. Percentiles are monotonic (`p50 <= p95 <= p99`).
    /// 5. Status counters sum to `total_recorded`.
    #[test]
    fn trace_ring_buffer_preserves_capacity_monotonic_seq_and_percentile_order(
        capacity in 1usize..32,
        events in prop::collection::vec((prop_oneof![Just(Some(200u16)), Just(Some(302u16)), Just(Some(429u16)), Just(Some(502u16)), Just(None)], 0u64..500_000), 1..80),
        after_offset in 0u64..80,
    ) {
        let ring = TraceRingBuffer::new(capacity);
        let mut last_seq = 0u64;
        for (idx, (status, total_us)) in events.iter().enumerate() {
            let pushed = ring.push(InspectorTrace {
                seq: 0,
                request_id: idx as u64 + 1,
                timestamp_unix_ms: 1_700_000_000_000,
                method: "GET".into(),
                path: "/p".into(),
                host: None,
                route_id: Some("r".into()),
                upstream: Some("u".into()),
                endpoint: None,
                status: *status,
                attempts: 1,
                request_bytes: 0,
                response_bytes: 0,
                ttfb_us: Some(total_us / 2),
                total_us: *total_us,
                aborted_mid_stream: false,
                error: None,
                trace_id: None,
                hooks: Vec::new(),
                stream_chunks: Vec::new(),
                attributes: BTreeMap::new(),
            });
            prop_assert_eq!(pushed.seq, last_seq + 1);
            last_seq = pushed.seq;
        }

        let all = ring.recent(None, None);
        prop_assert!(all.len() <= capacity);
        prop_assert_eq!(all.len(), events.len().min(capacity));
        for w in all.windows(2) {
            prop_assert!(w[0].seq < w[1].seq);
        }

        let after_slice = ring.recent(Some(after_offset), None);
        for t in &after_slice {
            prop_assert!(t.seq > after_offset);
        }

        let summary = ring.summary();
        prop_assert_eq!(summary.buffered, all.len());
        prop_assert_eq!(summary.total_recorded, events.len() as u64);
        prop_assert_eq!(
            summary.status_2xx + summary.status_3xx + summary.status_4xx + summary.status_5xx,
            summary.total_recorded
        );
        if let (Some(p50), Some(p95), Some(p99)) = (summary.p50_us, summary.p95_us, summary.p99_us) {
            prop_assert!(p50 <= p95);
            prop_assert!(p95 <= p99);
        }
    }

    /// Normalization invariants for `join_route_paths`:
    /// 1. Result always starts with `/`.
    /// 2. Joining slash-free segments never introduces `//`.
    /// 3. For any group prefix `gp` and suffix `rp`, `PathMatch::Prefix(gp)` always matches `join_route_paths(gp, rp)`.
    #[test]
    fn join_route_paths_preserves_prefix_boundary_and_slash_invariants(
        g_segs in prop::collection::vec("[a-z0-9_-]{1,6}", 0..4),
        r_segs in prop::collection::vec("[a-z0-9_-]{1,6}", 0..4),
        g_trailing in any::<bool>(),
    ) {
        let gp = if g_segs.is_empty() {
            "/".to_owned()
        } else if g_trailing {
            format!("/{}/", g_segs.join("/"))
        } else {
            format!("/{}", g_segs.join("/"))
        };
        let rp = if r_segs.is_empty() {
            "/".to_owned()
        } else {
            format!("/{}", r_segs.join("/"))
        };

        let joined = join_route_paths(&gp, &rp);
        prop_assert!(joined.starts_with('/'));
        prop_assert!(!joined.contains("//"), "double slash in `{joined}` from `{gp}` + `{rp}`");
        prop_assert!(
            PathMatch::Prefix(gp.clone()).matches(&joined),
            "PathMatch::Prefix({gp}) must match joined path `{joined}`"
        );
    }

    /// Soundness proof for route group narrowing:
    /// Whenever `GatewayConfig::validate()` accepts a grouped route, every request matched by
    /// the lowered `RouteMatch` MUST also match the group's own `RouteMatch`.
    #[test]
    fn valid_grouped_route_never_escapes_group_matcher_boundary(
        g_hosts in arb_host_list(),
        r_hosts in arb_host_list(),
        g_prefix in prop_oneof![
            Just(None),
            Just(Some("/".to_owned())),
            Just(Some("/api".to_owned())),
            Just(Some("/api/v2".to_owned())),
        ],
        r_path in prop_oneof![
            Just((None, None)),
            Just((Some("/".to_owned()), None)),
            Just((Some("/users".to_owned()), None)),
            Just((None, Some("/health".to_owned()))),
        ],
        g_methods in prop::collection::vec(prop_oneof![Just("GET"), Just("POST"), Just("DELETE")], 0..3),
        r_methods in prop::collection::vec(prop_oneof![Just("GET"), Just("POST"), Just("DELETE")], 0..3),
        req_host in prop_oneof![
            Just("example.com"),
            Just("api.example.com"),
            Just("v1.api.example.com"),
            Just("other.org"),
        ],
        req_path in prop_oneof![
            Just("/"),
            Just("/api"),
            Just("/api/users"),
            Just("/api/v2"),
            Just("/api/v2/users"),
            Just("/api/v2/health"),
            Just("/users"),
            Just("/health"),
        ],
        req_method in prop_oneof![
            Just(http::Method::GET),
            Just(http::Method::POST),
            Just(http::Method::DELETE),
        ],
    ) {
        let cfg = GatewayConfig {
            upstreams: vec![UpstreamIr {
                name: "be".to_owned(),
                endpoints: vec![UpstreamEndpointIr::Url("http://127.0.0.1:8081".to_owned())],
                http2_only: false,
                connect_timeout_ms: 5_000,
                pool_idle_timeout_ms: 90_000,
                pool_max_idle_per_host: 64,
                unhealthy_threshold: 3,
                unhealthy_cooldown_ms: 10_000,
                tls: Default::default(),
                health_check: None,
            }],
            route_groups: vec![RouteGroupIr {
                id: "g".to_owned(),
                hosts: g_hosts.clone(),
                path_prefix: g_prefix.clone(),
                methods: g_methods.iter().map(|s| (*s).to_owned()).collect(),
                upstream: Some("be".to_owned()),
                ..RouteGroupIr::default()
            }],
            routes: vec![RouteIr {
                id: "r".to_owned(),
                group: Some("g".to_owned()),
                hosts: r_hosts.clone(),
                path_prefix: r_path.0,
                path_exact: r_path.1,
                methods: r_methods.iter().map(|s| (*s).to_owned()).collect(),
                headers: BTreeMap::new(),
                upstream: None,
                strip_prefix: None,
                max_body_bytes: None,
                max_attempts: None,
                response_headers_timeout_ms: None,
                idle_chunk_timeout_ms: None,
                allow_websockets: None,
                mirrors: Vec::new(),
                plugins: Vec::new(),
            }],
            ..GatewayConfig::default()
        };

        if cfg.validate().is_ok() {
            let resolved = cfg.resolve_route(&cfg.routes[0]).unwrap();
            let group_matcher = RouteMatch {
                hosts: g_hosts.iter().map(|h| h.to_ascii_lowercase()).collect(),
                path: g_prefix.map(PathMatch::Prefix).unwrap_or(PathMatch::Any),
                methods: g_methods
                    .iter()
                    .map(|m| http::Method::from_bytes(m.as_bytes()).unwrap())
                    .collect(),
                headers: Vec::new(),
            };
            let route_matcher = RouteMatch {
                hosts: resolved.hosts.iter().map(|h| h.to_ascii_lowercase()).collect(),
                path: if let Some(exact) = resolved.path_exact {
                    PathMatch::Exact(exact)
                } else if let Some(prefix) = resolved.path_prefix {
                    PathMatch::Prefix(prefix)
                } else {
                    PathMatch::Any
                },
                methods: resolved
                    .methods
                    .iter()
                    .map(|m| http::Method::from_bytes(m.as_bytes()).unwrap())
                    .collect(),
                headers: Vec::new(),
            };

            let req = http::Request::builder()
                .method(req_method)
                .uri(req_path)
                .header(http::header::HOST, req_host)
                .body(())
                .unwrap();
            if route_matcher.matches(&req) {
                prop_assert!(
                    group_matcher.matches(&req),
                    "grouped route escaped group boundary: group={group_matcher:?}, route={route_matcher:?}, req={req_host}{req_path}"
                );
            }
            // Verify host_pattern_subsumes reflexivity on every resolved host.
            for h in &resolved.hosts {
                prop_assert!(host_pattern_subsumes(h, h));
            }
        }
    }
}
