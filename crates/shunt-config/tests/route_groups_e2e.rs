use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;

use bytes::Bytes;
use http::{Method, Request, Response, StatusCode, header};
use http_body_util::{BodyExt, Full};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use serde_json::Value;
use shunt_config::{
    AdminServer, ConfigProvider, InlineConfigProvider, ReloadController, RoutePolicy, Severity,
    SnapshotCompiler, VerifyPolicy, join_route_paths, verify_bundle,
};
use shunt_engine::{GatewayServer, RuntimeRegistry, ShuntBody};
use shunt_plugin_sdk::PluginRegistry;
use shunt_plugins::{PrometheusMetrics, register_builtin_plugins};
use tokio::net::{TcpListener, TcpStream};

async fn spawn_echo_upstream(label: &'static str) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                let svc = service_fn(move |req: Request<hyper::body::Incoming>| async move {
                    let path = req.uri().path().to_owned();
                    let group_hdr = req
                        .headers()
                        .get("x-from-group")
                        .and_then(|v| v.to_str().ok())
                        .unwrap_or("")
                        .to_owned();
                    let route_hdr = req
                        .headers()
                        .get("x-from-route")
                        .and_then(|v| v.to_str().ok())
                        .unwrap_or("")
                        .to_owned();
                    let payload =
                        format!("{label}|path={path}|group={group_hdr}|route={route_hdr}");
                    Ok::<_, Infallible>(
                        Response::builder()
                            .status(StatusCode::OK)
                            .body(ShuntBody::full(Bytes::from(payload)))
                            .unwrap(),
                    )
                });
                let _ = http1::Builder::new()
                    .serve_connection(TokioIo::new(stream), svc)
                    .await;
            });
        }
    });

    addr
}

async fn send_h1(
    addr: SocketAddr,
    req: Request<Full<Bytes>>,
) -> (StatusCode, http::HeaderMap, Bytes) {
    let stream = TcpStream::connect(addr).await.unwrap();
    let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(stream))
        .await
        .unwrap();
    tokio::spawn(async move {
        let _ = conn.await;
    });
    let res = sender.send_request(req).await.unwrap();
    let status = res.status();
    let headers = res.headers().clone();
    let body = res.into_body().collect().await.unwrap().to_bytes();
    (status, headers, body)
}

fn setup_compiler() -> (Arc<SnapshotCompiler>, Arc<RuntimeRegistry>) {
    let metrics = Arc::new(PrometheusMetrics::new());
    let mut plugins = PluginRegistry::new();
    register_builtin_plugins(&mut plugins, metrics);
    let runtime = Arc::new(RuntimeRegistry::new());
    let compiler = Arc::new(SnapshotCompiler::new(
        Arc::new(plugins),
        Arc::clone(&runtime),
    ));
    (compiler, runtime)
}

#[test]
fn join_route_paths_handles_slash_boundaries() {
    assert_eq!(join_route_paths("/v2", "/users"), "/v2/users");
    assert_eq!(join_route_paths("/v2/", "/users"), "/v2/users");
    assert_eq!(join_route_paths("/v2", "/"), "/v2");
    assert_eq!(join_route_paths("/v2/", "/"), "/v2");
    assert_eq!(join_route_paths("/", "/users"), "/users");
    assert_eq!(join_route_paths("/", "/"), "/");
    assert_eq!(join_route_paths("/v2", "/users/"), "/v2/users/");
}

#[test]
fn validates_route_group_errors_and_safe_narrowing() {
    let invalid_toml = r#"
[server]
listen = "127.0.0.1:0"
[admin]
enabled = false

[[upstreams]]
name = "svc"
endpoints = ["http://127.0.0.1:8081"]

[[route_groups]]
id = "api"
hosts = ["*.example.com"]
path_prefix = "no-leading-slash"
strip_prefix = "bad-strip"
methods = ["GET", "POST"]
headers = { "x-tenant" = "acme" }
upstream = "missing_up"
max_attempts = 0

[[route_groups]]
id = "api"

[[route_groups]]
id = "empty_up"
hosts = ["api.example.com"]
methods = ["GET"]
headers = { "x-env" = "prod" }

[[routes]]
id = "unknown_group_route"
group = "does_not_exist"
path_prefix = "/x"
upstream = "svc"

[[routes]]
id = "missing_upstream_route"
group = "empty_up"
path_prefix = "/y"

[[routes]]
id = "widened_route"
group = "empty_up"
hosts = ["other.org"]
methods = ["DELETE"]
headers = { "X-Env" = "staging" }
upstream = "svc"
"#;

    let loaded = InlineConfigProvider::from_toml("bad.toml", invalid_toml)
        .load()
        .unwrap();
    let err = loaded.config.validate().unwrap_err().to_string();
    assert!(
        err.contains("duplicate route group id `api`"),
        "got:\n{err}"
    );
    assert!(
        err.contains("`path_prefix` (`no-leading-slash`) must start with `/`"),
        "got:\n{err}"
    );
    assert!(
        err.contains("`strip_prefix` (`bad-strip`) must start with `/`"),
        "got:\n{err}"
    );
    assert!(
        err.contains("references unknown upstream `missing_up`"),
        "got:\n{err}"
    );
    assert!(
        err.contains("route_groups.api: `max_attempts` must be >= 1"),
        "got:\n{err}"
    );
    assert!(
        err.contains("references unknown route group `does_not_exist`"),
        "got:\n{err}"
    );
    assert!(err.contains("must specify `upstream`"), "got:\n{err}");
    assert!(
        err.contains("host `other.org` is not allowed"),
        "got:\n{err}"
    );
    assert!(
        err.contains("method `DELETE` is not allowed"),
        "got:\n{err}"
    );
    assert!(
        err.contains("contradicts route group `empty_up` header matcher"),
        "got:\n{err}"
    );
}

#[tokio::test]
async fn route_groups_share_rate_limit_state_inherit_defaults_and_survive_reload() {
    let users_up = spawn_echo_upstream("users").await;
    let orders_up = spawn_echo_upstream("orders").await;
    let public_up = spawn_echo_upstream("public").await;

    let cfg_v1 = format!(
        r#"
[server]
listen = "127.0.0.1:0"

[admin]
enabled = true
listen = "127.0.0.1:0"

[[plugins]]
name = "request-id"

[[upstreams]]
name = "users_svc"
endpoints = ["http://{users_up}"]

[[upstreams]]
name = "orders_svc"
endpoints = ["http://{orders_up}"]

[[upstreams]]
name = "public_svc"
endpoints = ["http://{public_up}"]

[[route_groups]]
id = "api_v2"
hosts = ["*.example.com"]
path_prefix = "/v2"
strip_prefix = "/v2"
methods = ["GET", "POST"]
headers = {{ "x-api-version" = "2" }}
upstream = "users_svc"
max_attempts = 2
response_headers_timeout_ms = 12000

[[route_groups.plugins]]
name = "bearer-auth"
[route_groups.plugins.config]
tokens = ["group-secret-token-42"]

[[route_groups.plugins]]
name = "rate-limit"
id = "api-v2-rl"
[route_groups.plugins.config]
requests_per_second = 0.001
burst = 2
key = "global"

[[route_groups.plugins]]
name = "header-rewrite"
[route_groups.plugins.config]
request_set = {{ "x-from-group" = "api_v2" }}
response_set = {{ "x-group" = "api_v2", "x-order" = "from-group" }}

[[routes]]
id = "users"
group = "api_v2"
hosts = ["api.example.com"]
path_prefix = "/users"
methods = ["GET"]
# Inherits upstream = "users_svc", strip_prefix = "/v2", max_attempts = 2

[[routes]]
id = "orders"
group = "api_v2"
path_prefix = "/orders"
upstream = "orders_svc"
max_attempts = 3

[[routes.plugins]]
name = "header-rewrite"
[routes.plugins.config]
request_set = {{ "x-from-route" = "orders" }}
response_set = {{ "x-order" = "from-route" }}

[[routes]]
id = "public_health"
path_exact = "/health"
upstream = "public_svc"
"#
    );

    let (compiler, runtime) = setup_compiler();
    let provider = Arc::new(InlineConfigProvider::from_toml("v1.toml", cfg_v1));
    let loaded = provider.load().unwrap();
    let bundle = compiler.compile(&loaded).unwrap();

    // Verify compiled snapshot metadata before serving.
    assert_eq!(bundle.inspect.route_groups.len(), 1);
    assert_eq!(bundle.inspect.route_groups[0].id, "api_v2");
    assert_eq!(
        bundle.inspect.route_groups[0].routes,
        vec!["users".to_owned(), "orders".to_owned()]
    );
    assert_eq!(bundle.inspect.routes[0].group.as_deref(), Some("api_v2"));
    assert_eq!(bundle.inspect.routes[0].path, "/v2/users*");
    assert_eq!(bundle.inspect.routes[0].upstream, "users_svc");
    assert_eq!(bundle.inspect.routes[0].max_attempts, 2);
    assert_eq!(bundle.inspect.routes[1].group.as_deref(), Some("api_v2"));
    assert_eq!(bundle.inspect.routes[1].path, "/v2/orders*");
    assert_eq!(bundle.inspect.routes[1].upstream, "orders_svc");
    assert_eq!(bundle.inspect.routes[1].max_attempts, 3);
    assert_eq!(bundle.inspect.routes[2].group, None);
    // Group rate-limit created ONE shared state scope, not two.
    assert_eq!(runtime.state_store().len(), 1);

    let gw = GatewayServer::new(bundle.snapshot)
        .bind("127.0.0.1:0".parse().unwrap())
        .await
        .unwrap();
    let controller = Arc::new(ReloadController::new(
        provider,
        Arc::clone(&compiler),
        gw.reloader(),
        bundle.inspect,
    ));
    let admin = AdminServer::new(controller, Arc::new(String::new))
        .bind("127.0.0.1:0".parse().unwrap())
        .await
        .unwrap();

    // 1. Snapshot redacts secrets in route_groups plugins and exposes group scopes.
    let (st, _, snap_body) = send_h1(
        admin.local_addr(),
        Request::builder()
            .uri("/snapshot")
            .body(Full::new(Bytes::new()))
            .unwrap(),
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    let snap_text = String::from_utf8(snap_body.to_vec()).unwrap();
    assert!(
        !snap_text.contains("group-secret-token-42"),
        "group secret leaked in /snapshot"
    );
    let snap_json: Value = serde_json::from_str(&snap_text).unwrap();
    assert_eq!(snap_json["route_groups"][0]["id"], "api_v2");
    assert_eq!(
        snap_json["routes"][1]["plugin_details"][1]["scope_id"],
        "group:api_v2:api-v2-rl"
    );
    assert_eq!(
        snap_json["routes"][1]["plugin_details"][3]["scope_id"],
        "route:orders:header-rewrite:0"
    );

    // 2. Missing group header matcher -> 404.
    let (st, _, _) = send_h1(
        gw.local_addr(),
        Request::builder()
            .method(Method::GET)
            .uri("/v2/users/1")
            .header(header::HOST, "api.example.com")
            .body(Full::new(Bytes::new()))
            .unwrap(),
    )
    .await;
    assert_eq!(st, StatusCode::NOT_FOUND);

    // 3. Narrowed host check: `users` only allows `api.example.com`, while `orders` inherits `*.example.com`.
    let (st, _, _) = send_h1(
        gw.local_addr(),
        Request::builder()
            .method(Method::GET)
            .uri("/v2/users/1")
            .header(header::HOST, "other.example.com")
            .header("x-api-version", "2")
            .header(header::AUTHORIZATION, "Bearer group-secret-token-42")
            .body(Full::new(Bytes::new()))
            .unwrap(),
    )
    .await;
    assert_eq!(st, StatusCode::NOT_FOUND);

    // 4. Request #1 hits `users` -> succeeds, consumes 1st token from SHARED group bucket (remaining=1).
    let (st, hdrs, body) = send_h1(
        gw.local_addr(),
        Request::builder()
            .method(Method::GET)
            .uri("/v2/users/42")
            .header(header::HOST, "api.example.com")
            .header("x-api-version", "2")
            .header(header::AUTHORIZATION, "Bearer group-secret-token-42")
            .body(Full::new(Bytes::new()))
            .unwrap(),
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(hdrs.get("x-group").unwrap(), "api_v2");
    assert_eq!(hdrs.get("x-order").unwrap(), "from-group");
    assert_eq!(hdrs.get("x-ratelimit-remaining").unwrap(), "1");
    assert_eq!(
        String::from_utf8(body.to_vec()).unwrap(),
        "users|path=/users/42|group=api_v2|route="
    );

    // 5. Request #2 hits `orders` (different route in same group!) -> consumes 2nd token (remaining=0),
    //    and route plugin overrides group response header (`x-order = from-route`), proving global->group->route order.
    let (st, hdrs, body) = send_h1(
        gw.local_addr(),
        Request::builder()
            .method(Method::POST)
            .uri("/v2/orders/99")
            .header(header::HOST, "shop.example.com")
            .header("x-api-version", "2")
            .header(header::AUTHORIZATION, "Bearer group-secret-token-42")
            .body(Full::new(Bytes::new()))
            .unwrap(),
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(hdrs.get("x-group").unwrap(), "api_v2");
    assert_eq!(hdrs.get("x-order").unwrap(), "from-route");
    assert_eq!(hdrs.get("x-ratelimit-remaining").unwrap(), "0");
    assert_eq!(
        String::from_utf8(body.to_vec()).unwrap(),
        "orders|path=/orders/99|group=api_v2|route=orders"
    );

    // 6. Request #3 back to `users` -> 429 because shared group bucket is exhausted!
    let (st, _, _) = send_h1(
        gw.local_addr(),
        Request::builder()
            .method(Method::GET)
            .uri("/v2/users/42")
            .header(header::HOST, "api.example.com")
            .header("x-api-version", "2")
            .header(header::AUTHORIZATION, "Bearer group-secret-token-42")
            .body(Full::new(Bytes::new()))
            .unwrap(),
    )
    .await;
    assert_eq!(st, StatusCode::TOO_MANY_REQUESTS);

    // 7. Ungrouped `/health` route is unaffected by group auth/rate-limit.
    let (st, _, body) = send_h1(
        gw.local_addr(),
        Request::builder()
            .method(Method::GET)
            .uri("/health")
            .body(Full::new(Bytes::new()))
            .unwrap(),
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(
        String::from_utf8(body.to_vec()).unwrap(),
        "public|path=/health|group=|route="
    );

    // 8. Removing the group on a subsequent compile garbage-collects its StateStore scope.
    let cfg_v2 = format!(
        r#"
[server]
listen = "127.0.0.1:0"
[admin]
enabled = false
[[upstreams]]
name = "public_svc"
endpoints = ["http://{public_up}"]
[[routes]]
id = "public_health"
path_exact = "/health"
upstream = "public_svc"
"#
    );
    let loaded_v2 = InlineConfigProvider::from_toml("v2.toml", cfg_v2)
        .load()
        .unwrap();
    let _bundle_v2 = compiler.compile(&loaded_v2).unwrap();
    assert_eq!(runtime.state_store().len(), 0);

    admin.shutdown().await;
    assert!(gw.shutdown().await);
}

#[test]
fn verify_checks_unused_groups_match_group_policies_and_lowered_shadowing() {
    let (compiler, _runtime) = setup_compiler();
    let toml_src = r#"
[server]
listen = "127.0.0.1:0"
[admin]
enabled = false

[telemetry]
enabled = true
endpoint = "http://127.0.0.1:4318/v1/traces"

[[upstreams]]
name = "svc"
endpoints = ["http://127.0.0.1:8081"]
connect_timeout_ms = 5000

[[route_groups]]
id = "api_v2"
path_prefix = "/v2"
upstream = "svc"
response_headers_timeout_ms = 2000

[[route_groups.plugins]]
name = "otel-trace"

[[route_groups]]
id = "orphan_group"
path_prefix = "/unused"

[[routes]]
id = "broad_v2"
path_prefix = "/v2"
upstream = "svc"

[[routes]]
id = "shadowed_users"
group = "api_v2"
path_prefix = "/users"
"#;

    let loaded = InlineConfigProvider::from_toml("verify-groups.toml", toml_src)
        .load()
        .unwrap();
    let bundle = compiler.compile(&loaded).unwrap();

    let policy = VerifyPolicy {
        route_policies: vec![RoutePolicy {
            match_route: String::new(),
            match_group: Some("api_*".to_owned()),
            require_plugins: vec!["otel-trace".to_owned(), "jwt-auth".to_owned()],
            forbid_hooks: vec![],
            require_hooks: vec![],
        }],
        ..Default::default()
    };

    let report = verify_bundle(&bundle, Some(&policy), false);
    assert!(!report.passed);
    // Lowered `/v2/users` is detected as shadowed by earlier `/v2`.
    assert!(
        report
            .diagnostics
            .iter()
            .any(|d| d.rule == "route.shadowed" && d.subject.as_deref() == Some("shadowed_users"))
    );
    // Group-inherited timeout (2000ms) <= upstream connect_timeout_ms (5000ms) is caught.
    assert!(
        report
            .diagnostics
            .iter()
            .any(|d| d.rule == "route.timeout_order"
                && d.subject.as_deref() == Some("shadowed_users"))
    );
    // Unused group emits a warning.
    assert!(report.diagnostics.iter().any(|d| {
        d.rule == "route_group.unused"
            && d.severity == Severity::Warning
            && d.subject.as_deref() == Some("orphan_group")
    }));
    // `otel-trace` on `api_v2` satisfies `telemetry.no_trace_plugin`.
    assert!(
        !report
            .diagnostics
            .iter()
            .any(|d| d.rule == "telemetry.no_trace_plugin")
    );
    // `match_group = "api_*"` requires `jwt-auth` on `shadowed_users` (but NOT on `broad_v2`),
    // and passes `otel-trace` because it was inherited from the group.
    let policy_errs: Vec<_> = report
        .diagnostics
        .iter()
        .filter(|d| d.rule == "policy.require_plugin")
        .collect();
    assert_eq!(policy_errs.len(), 1);
    assert_eq!(policy_errs[0].subject.as_deref(), Some("shadowed_users"));
    assert!(policy_errs[0].message.contains("jwt-auth"));
}

#[test]
fn verify_detects_cross_boundary_plugin_ordering_between_group_and_route() {
    use shunt_plugin_sdk::{
        BuildContext, HookMask, HttpPlugin, PluginBuildError, PluginConfig, PluginFactory,
    };

    struct DummyPlugin(&'static str);
    impl HttpPlugin for DummyPlugin {
        fn name(&self) -> &str {
            self.0
        }
        fn hook_mask(&self) -> HookMask {
            HookMask::EMPTY
        }
    }
    struct DummyFactory(&'static str);
    impl PluginFactory for DummyFactory {
        fn name(&self) -> &str {
            self.0
        }
        fn build(
            &self,
            _config: &PluginConfig,
            _ctx: &BuildContext,
        ) -> Result<Arc<dyn HttpPlugin>, PluginBuildError> {
            Ok(Arc::new(DummyPlugin(self.0)))
        }
    }

    let mut reg = PluginRegistry::new();
    reg.register(DummyFactory("ai-model-router"));
    reg.register(DummyFactory("ai-virtual-keys"));
    let compiler = SnapshotCompiler::new(Arc::new(reg), Arc::new(RuntimeRegistry::new()));

    let toml_src = r#"
[server]
listen = "127.0.0.1:0"
[admin]
enabled = false

[[upstreams]]
name = "openai"
endpoints = ["http://127.0.0.1:8081"]

[[route_groups]]
id = "ai_group"
path_prefix = "/v1"
upstream = "openai"

[[route_groups.plugins]]
name = "ai-model-router"

[[routes]]
id = "chat"
group = "ai_group"
path_prefix = "/chat/completions"

[[routes.plugins]]
name = "ai-virtual-keys"
"#;

    let loaded = InlineConfigProvider::from_toml("cross-order.toml", toml_src)
        .load()
        .unwrap();
    let bundle = compiler.compile(&loaded).unwrap();
    let report = verify_bundle(&bundle, None, false);
    assert!(!report.passed);
    assert!(
        report
            .diagnostics
            .iter()
            .any(|d| d.rule == "ai.plugin_order" && d.subject.as_deref() == Some("chat")),
        "expected ai.plugin_order across group+route boundary, got: {:?}",
        report.diagnostics
    );
}
