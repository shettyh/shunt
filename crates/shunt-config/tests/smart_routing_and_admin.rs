use std::sync::Arc;

use bytes::Bytes;
use http::{Request, StatusCode};
use http_body_util::{BodyExt, Full};
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;
use serde_json::Value;
use shunt_config::{
    AdminServer, ConfigProvider, InlineConfigProvider, ReloadController, SnapshotCompiler,
    verify_bundle,
};
use shunt_engine::{GatewayServer, RuntimeRegistry};
use shunt_plugin_sdk::{
    BuildContext, HookMask, HttpPlugin, PluginBuildError, PluginConfig, PluginFactory,
    PluginRegistry,
};
use shunt_plugins::{PrometheusMetrics, register_builtin_plugins};

struct StubPlugin(&'static str);

impl HttpPlugin for StubPlugin {
    fn name(&self) -> &str {
        self.0
    }
    fn hook_mask(&self) -> HookMask {
        HookMask::EMPTY
    }
}

struct StubFactory(&'static str);

impl PluginFactory for StubFactory {
    fn name(&self) -> &str {
        self.0
    }
    fn build(
        &self,
        _config: &PluginConfig,
        _ctx: &BuildContext,
    ) -> Result<Arc<dyn HttpPlugin>, PluginBuildError> {
        Ok(Arc::new(StubPlugin(self.0)))
    }
}

fn build_compiler() -> SnapshotCompiler {
    let metrics = Arc::new(PrometheusMetrics::new());
    let mut reg = PluginRegistry::new();
    register_builtin_plugins(&mut reg, metrics);
    reg.register(StubFactory("ai-model-router"))
        .register(StubFactory("ai-provider-adapter"));
    SnapshotCompiler::new(Arc::new(reg), Arc::new(RuntimeRegistry::new()))
}

#[test]
fn validates_weights_and_active_health_check_fields() {
    let bad_weight = InlineConfigProvider::from_toml(
        "bad_weight.toml",
        r#"
[server]
listen = "127.0.0.1:0"
[admin]
enabled = false
[[upstreams]]
name = "u1"
endpoints = [{ url = "http://127.0.0.1:8080", weight = 0 }]
[[routes]]
id = "r1"
path_prefix = "/"
upstream = "u1"
"#,
    )
    .load()
    .unwrap();
    let err = bad_weight.config.validate().unwrap_err().to_string();
    assert!(err.contains("weight must be >= 1"), "unexpected err: {err}");

    let bad_hc = InlineConfigProvider::from_toml(
        "bad_hc.toml",
        r#"
[server]
listen = "127.0.0.1:0"
[admin]
enabled = false
[[upstreams]]
name = "u1"
endpoints = ["http://127.0.0.1:8080"]
[upstreams.health_check]
kind = "http"
path = "no-leading-slash"
interval_ms = 0
expected_statuses = []
[[routes]]
id = "r1"
path_prefix = "/"
upstream = "u1"
"#,
    )
    .load()
    .unwrap();
    let err = bad_hc.config.validate().unwrap_err().to_string();
    assert!(err.contains("interval_ms"), "unexpected err: {err}");
    assert!(err.contains("must start with `/`"), "unexpected err: {err}");
    assert!(err.contains("expected_statuses"), "unexpected err: {err}");
}

#[test]
fn verify_warns_on_health_check_timeout_and_checks_detailed_ai_models() {
    let compiler = build_compiler();
    let loaded = InlineConfigProvider::from_toml(
        "verify_smart.toml",
        r#"
[server]
listen = "127.0.0.1:0"
[admin]
enabled = false

[[upstreams]]
name = "up_a"
endpoints = [{ url = "http://127.0.0.1:8081", weight = 70 }, { url = "http://127.0.0.1:8082", weight = 30 }]
[upstreams.health_check]
kind = "http"
path = "/health"
interval_ms = 1000
timeout_ms = 1500

[[routes]]
id = "ai"
path_prefix = "/v1"
upstream = "up_a"

[[routes.plugins]]
name = "ai-model-router"
[routes.plugins.config.models.smart]
strategy = "weighted"
targets = [
  { provider = "known_p", upstream = "up_a", weight = 80 },
  { provider = "ghost_p", upstream = "missing_up", weight = 20 },
]

[[routes.plugins]]
name = "ai-provider-adapter"
[routes.plugins.config.providers.known_p]
dialect = "openai_compatible"
[routes.plugins.config.providers.known_p.auth]
type = "none"
"#,
    )
    .load()
    .unwrap();

    let bundle = compiler.compile(&loaded).unwrap();
    let report = verify_bundle(&bundle, None, false);

    assert!(!report.passed);
    assert!(
        report
            .diagnostics
            .iter()
            .any(|d| d.rule == "upstream.health_check_timeout"
                && d.subject.as_deref() == Some("up_a")),
        "expected upstream.health_check_timeout warning: {:?}",
        report.diagnostics
    );
    assert!(
        report
            .diagnostics
            .iter()
            .any(|d| d.rule == "ai.unknown_upstream"),
        "expected ai.unknown_upstream for detailed model entry: {:?}",
        report.diagnostics
    );
    assert!(
        report
            .diagnostics
            .iter()
            .any(|d| d.rule == "ai.unknown_provider"),
        "expected ai.unknown_provider for detailed model entry: {:?}",
        report.diagnostics
    );
}

#[tokio::test]
async fn admin_upstreams_endpoint_exposes_live_weights_and_health() {
    let compiler = Arc::new(build_compiler());
    let provider = Arc::new(InlineConfigProvider::from_toml(
        "admin_up.toml",
        r#"
[server]
listen = "127.0.0.1:0"
[admin]
enabled = true
listen = "127.0.0.1:0"

[[upstreams]]
name = "api_pool"
endpoints = [
  { url = "http://127.0.0.1:19901", weight = 80 },
  { url = "http://127.0.0.1:19902", weight = 20 },
]

[[routes]]
id = "r1"
path_prefix = "/"
upstream = "api_pool"
"#,
    ));

    let loaded = provider.load().unwrap();
    let bundle = compiler.compile(&loaded).unwrap();
    let gw = GatewayServer::new(bundle.snapshot)
        .bind("127.0.0.1:0".parse().unwrap())
        .await
        .unwrap();

    let controller = Arc::new(ReloadController::new(
        provider,
        compiler,
        gw.reloader(),
        bundle.inspect,
    ));
    let admin = AdminServer::new(controller, Arc::new(String::new))
        .bind("127.0.0.1:0".parse().unwrap())
        .await
        .unwrap();

    let client = Client::builder(TokioExecutor::new()).build_http::<Full<Bytes>>();
    let req = Request::builder()
        .uri(format!("http://{}/upstreams", admin.local_addr()))
        .body(Full::new(Bytes::new()))
        .unwrap();
    let resp = client.request(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let json: Value = serde_json::from_slice(&body).unwrap();

    assert_eq!(json["version"], 1);
    let ups = json["upstreams"].as_array().unwrap();
    assert_eq!(ups.len(), 1);
    assert_eq!(ups[0]["name"], "api_pool");
    assert_eq!(ups[0]["active_health_check"], false);
    let eps = ups[0]["endpoints"].as_array().unwrap();
    assert_eq!(eps.len(), 2);
    assert_eq!(eps[0]["weight"], 80);
    assert_eq!(eps[0]["healthy"], true);
    assert_eq!(eps[1]["weight"], 20);
    assert_eq!(eps[1]["healthy"], true);

    admin.shutdown().await;
    gw.shutdown().await;
}
