use std::collections::{BTreeMap, HashMap};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock, RwLock};
use std::time::{Duration, Instant};

use bytes::Bytes;
use http::{HeaderName, HeaderValue, Method, Request, StatusCode, header};
use http_body_util::{BodyExt, Full};
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;
use serde::Serialize;
use serde_json::Value;
use shunt_ai::sse::SseParser;
use shunt_ai::{AiMetrics, inspect_ai_runtime, register_ai_plugins};
use shunt_config::provider::sha256_hex;
use shunt_config::{
    AdminServer, ConfigError, ConfigProvider, FileConfigProvider, GatewayConfig,
    InspectorCapturePlugin, LoadedConfig, MetricsRenderer, ReloadController, SnapshotCompiler,
    TraceRingBuffer, UpstreamEndpointIr,
};
use shunt_engine::{GatewayServer, RuntimeRegistry};
use shunt_mcp::{McpMetrics, inspect_mcp_runtime, register_mcp_plugins};
use shunt_plugin_sdk::{ManualClock, PluginRegistry};
use shunt_plugins::{PrometheusMetrics, register_builtin_plugins};
use thiserror::Error;

use crate::mock::{CapturedRequest, MockHandle, spawn_mock};
use crate::schema::{CaseSpec, ExpectSpec, MockSpec, RequestSpec, SpecFile, StepSpec};

#[derive(Debug, Error)]
pub enum SpecError {
    #[error("failed to read spec file `{path}`: {source}")]
    ReadSpec {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to parse spec TOML `{source_name}`: {source}")]
    ParseSpec {
        source_name: String,
        #[source]
        source: toml::de::Error,
    },
    #[error("configuration error: {0}")]
    Config(#[from] ConfigError),
    #[error("spec error: {0}")]
    InvalidSpec(String),
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

#[derive(Debug, Clone, Serialize)]
pub struct CaseReport {
    pub name: String,
    pub passed: bool,
    pub duration_ms: u64,
    pub failures: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SpecRunReport {
    pub spec_name: String,
    pub total: usize,
    pub passed: usize,
    pub failed: usize,
    pub cases: Vec<CaseReport>,
}

impl SpecRunReport {
    pub fn all_passed(&self) -> bool {
        self.failed == 0
    }
}

/// Process-wide lock protecting temporary `[env]` overrides during synchronous config compilation.
fn env_lock() -> &'static Mutex<()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}

struct EnvGuard {
    _lock: std::sync::MutexGuard<'static, ()>,
    previous: Vec<(String, Option<String>)>,
}

impl EnvGuard {
    fn apply(overrides: &BTreeMap<String, String>) -> Self {
        let lock = env_lock().lock().expect("ENV_LOCK poisoned");
        let mut previous = Vec::with_capacity(overrides.len());
        for (k, v) in overrides {
            previous.push((k.clone(), std::env::var(k).ok()));
            // SAFETY: Protected by process-wide `env_lock()` for the short duration of
            // synchronous `SnapshotCompiler::compile()`.
            unsafe {
                std::env::set_var(k, v);
            }
        }
        Self {
            _lock: lock,
            previous,
        }
    }
}

impl Drop for EnvGuard {
    fn drop(&mut self) {
        for (k, prev) in self.previous.drain(..).rev() {
            // SAFETY: Protected by `self._lock`.
            unsafe {
                match prev {
                    Some(v) => std::env::set_var(&k, v),
                    None => std::env::remove_var(&k),
                }
            }
        }
    }
}

/// Dynamic in-memory [`ConfigProvider`] used by `shunt test` to support hot-reload steps
/// with automatic upstream endpoint rebinding to in-process mocks.
struct MutableTestConfigProvider {
    source_name: String,
    current_toml: RwLock<String>,
    mock_endpoints: HashMap<String, Vec<String>>,
}

impl MutableTestConfigProvider {
    fn new(
        source_name: String,
        initial_toml: String,
        mock_endpoints: HashMap<String, Vec<String>>,
    ) -> Self {
        Self {
            source_name,
            current_toml: RwLock::new(initial_toml),
            mock_endpoints,
        }
    }

    fn set_toml(&self, toml_src: String) {
        *self
            .current_toml
            .write()
            .expect("MutableTestConfigProvider poisoned") = toml_src;
    }
}

impl ConfigProvider for MutableTestConfigProvider {
    fn source_name(&self) -> String {
        self.source_name.clone()
    }

    fn load(&self) -> Result<LoadedConfig, ConfigError> {
        let raw = self
            .current_toml
            .read()
            .expect("MutableTestConfigProvider poisoned")
            .clone();
        let mut config: GatewayConfig =
            toml::from_str(&raw).map_err(|source| ConfigError::TomlParse {
                source_name: self.source_name.clone(),
                source,
            })?;
        rebind_config_to_mocks(&mut config, &self.mock_endpoints);
        Ok(LoadedConfig {
            source_name: self.source_name.clone(),
            config,
            digest: sha256_hex(raw.as_bytes()),
        })
    }
}

fn rebind_config_to_mocks(
    config: &mut GatewayConfig,
    mock_endpoints: &HashMap<String, Vec<String>>,
) {
    config.server.listen = "127.0.0.1:0".to_owned();
    config.server.drain_timeout_ms = config.server.drain_timeout_ms.min(2_000);
    config.admin.enabled = true;
    config.admin.listen = "127.0.0.1:0".to_owned();

    if let Some(ep) = config.telemetry.endpoint.as_deref()
        && let Some(rewritten) = rewrite_mock_url(ep, mock_endpoints)
    {
        config.telemetry.endpoint = Some(rewritten);
    }

    for plugin in &mut config.plugins {
        rewrite_mock_urls_in_value(&mut plugin.config, mock_endpoints);
    }
    for route in &mut config.routes {
        for plugin in &mut route.plugins {
            rewrite_mock_urls_in_value(&mut plugin.config, mock_endpoints);
        }
    }

    for up in &mut config.upstreams {
        if let Some(endpoints) = mock_endpoints.get(&up.name) {
            let prev = std::mem::take(&mut up.endpoints);
            up.endpoints = endpoints
                .iter()
                .enumerate()
                .map(|(idx, url)| {
                    let weight = prev.get(idx).map(UpstreamEndpointIr::weight).unwrap_or(1);
                    if weight == 1 {
                        UpstreamEndpointIr::Url(url.clone())
                    } else {
                        UpstreamEndpointIr::Weighted {
                            url: url.clone(),
                            weight,
                        }
                    }
                })
                .collect();
        }
    }
}

fn rewrite_mock_url(raw: &str, mock_endpoints: &HashMap<String, Vec<String>>) -> Option<String> {
    let rest = raw.strip_prefix("mock://")?;
    let (mock_name, suffix) = match rest.split_once('/') {
        Some((name, path)) => (name, format!("/{path}")),
        None => (rest, String::new()),
    };
    let base_url = mock_endpoints
        .get(mock_name)
        .and_then(|v| v.first())
        .map(String::as_str)
        .unwrap_or("http://127.0.0.1:1");
    Some(format!("{}{suffix}", base_url.trim_end_matches('/')))
}

fn rewrite_mock_urls_in_value(val: &mut Value, mock_endpoints: &HashMap<String, Vec<String>>) {
    match val {
        Value::String(s) => {
            if let Some(rewritten) = rewrite_mock_url(s, mock_endpoints) {
                *s = rewritten;
            }
        }
        Value::Array(items) => {
            for item in items {
                rewrite_mock_urls_in_value(item, mock_endpoints);
            }
        }
        Value::Object(map) => {
            for v in map.values_mut() {
                rewrite_mock_urls_in_value(v, mock_endpoints);
            }
        }
        _ => {}
    }
}

/// Loads and runs a TOML contract spec file (`shunt.spec.toml`).
pub async fn run_spec_file(
    spec_path: &Path,
    config_override: Option<&Path>,
    filter: Option<&str>,
) -> Result<SpecRunReport, SpecError> {
    let raw = std::fs::read_to_string(spec_path).map_err(|source| SpecError::ReadSpec {
        path: spec_path.to_path_buf(),
        source,
    })?;
    let base_dir = spec_path.parent().unwrap_or_else(|| Path::new("."));
    run_spec_str(
        &spec_path.display().to_string(),
        &raw,
        base_dir,
        config_override,
        filter,
    )
    .await
}

/// Parses and executes a TOML contract spec string.
pub async fn run_spec_str(
    source_name: &str,
    spec_toml: &str,
    base_dir: &Path,
    config_override: Option<&Path>,
    filter: Option<&str>,
) -> Result<SpecRunReport, SpecError> {
    let spec: SpecFile = toml::from_str(spec_toml).map_err(|source| SpecError::ParseSpec {
        source_name: source_name.to_owned(),
        source,
    })?;

    let (base_config_name, base_config_toml) =
        load_base_config_toml(&spec, base_dir, config_override)?;

    let mocks_by_name: HashMap<String, MockSpec> = spec
        .mocks
        .iter()
        .map(|m| (m.name.clone(), m.clone()))
        .collect();

    let mut reports = Vec::new();
    let mut passed_count = 0usize;
    let mut failed_count = 0usize;

    for case in &spec.cases {
        if let Some(f) = filter
            && !case
                .name
                .to_ascii_lowercase()
                .contains(&f.to_ascii_lowercase())
        {
            continue;
        }
        let report = run_case(
            case,
            &spec.env,
            &mocks_by_name,
            &base_config_name,
            &base_config_toml,
        )
        .await;
        if report.passed {
            passed_count += 1;
        } else {
            failed_count += 1;
        }
        reports.push(report);
    }

    Ok(SpecRunReport {
        spec_name: spec.spec.name,
        total: reports.len(),
        passed: passed_count,
        failed: failed_count,
        cases: reports,
    })
}

fn load_base_config_toml(
    spec: &SpecFile,
    base_dir: &Path,
    config_override: Option<&Path>,
) -> Result<(String, String), SpecError> {
    if let Some(path) = config_override {
        let raw = std::fs::read_to_string(path).map_err(|source| ConfigError::ReadFile {
            path: path.to_path_buf(),
            source,
        })?;
        // Validate it loads cleanly via FileConfigProvider too (handles YAML if needed).
        if matches!(
            path.extension().and_then(|e| e.to_str()),
            Some("yaml" | "yml" | "YAML" | "YML")
        ) {
            let loaded = FileConfigProvider::new(path).load()?;
            let as_toml = toml::to_string(&loaded.config)
                .map_err(|e| SpecError::InvalidSpec(format!("re-encode YAML config: {e}")))?;
            return Ok((path.display().to_string(), as_toml));
        }
        return Ok((path.display().to_string(), raw));
    }

    if let Some(inline) = &spec.spec.config_inline {
        return Ok((format!("{}:inline", spec.spec.name), inline.clone()));
    }

    if let Some(cfg_rel) = &spec.spec.config {
        let candidate_rel = base_dir.join(cfg_rel);
        let chosen = if candidate_rel.exists() {
            candidate_rel
        } else {
            PathBuf::from(cfg_rel)
        };
        let raw = std::fs::read_to_string(&chosen).map_err(|source| ConfigError::ReadFile {
            path: chosen.clone(),
            source,
        })?;
        return Ok((chosen.display().to_string(), raw));
    }

    Err(SpecError::InvalidSpec(
        "spec must specify `spec.config`, `spec.config_inline`, or CLI `-c <config>`".to_owned(),
    ))
}

async fn run_case(
    case: &CaseSpec,
    env_overrides: &BTreeMap<String, String>,
    mocks_by_name: &HashMap<String, MockSpec>,
    base_config_name: &str,
    base_config_toml: &str,
) -> CaseReport {
    let started = Instant::now();
    let mut failures = Vec::new();

    // 1. Spawn requested in-process MockUpstreams
    let mut mock_handles: Vec<MockHandle> = Vec::new();
    let mut mock_endpoints: HashMap<String, Vec<String>> = HashMap::new();
    for mock_name in &case.use_mocks {
        let Some(mock_spec) = mocks_by_name.get(mock_name) else {
            return CaseReport {
                name: case.name.clone(),
                passed: false,
                duration_ms: started.elapsed().as_millis() as u64,
                failures: vec![format!(
                    "unknown mock `{mock_name}` referenced in use_mocks"
                )],
            };
        };
        match spawn_mock(mock_spec).await {
            Ok(handle) => {
                mock_endpoints
                    .entry(handle.upstream.clone())
                    .or_default()
                    .push(handle.endpoint_url());
                mock_handles.push(handle);
            }
            Err(e) => {
                shutdown_mocks(mock_handles).await;
                return CaseReport {
                    name: case.name.clone(),
                    passed: false,
                    duration_ms: started.elapsed().as_millis() as u64,
                    failures: vec![format!("failed to spawn mock `{mock_name}`: {e}")],
                };
            }
        }
    }

    // 2. Compile initial snapshot with injected ManualClock + isolated [env]
    let clock = ManualClock::shared();
    let metrics = Arc::new(PrometheusMetrics::new());
    let ai_metrics = Arc::new(AiMetrics::new());
    let mcp_metrics = Arc::new(McpMetrics::new());
    let mut plugin_registry = PluginRegistry::new();
    register_builtin_plugins(&mut plugin_registry, Arc::clone(&metrics));
    register_ai_plugins(&mut plugin_registry, Arc::clone(&ai_metrics));
    register_mcp_plugins(&mut plugin_registry, Arc::clone(&mcp_metrics));
    let runtime_registry = Arc::new(RuntimeRegistry::with_clock(clock.clone()));
    let provider = Arc::new(MutableTestConfigProvider::new(
        base_config_name.to_owned(),
        base_config_toml.to_owned(),
        mock_endpoints,
    ));

    let initial_loaded = {
        let _env = EnvGuard::apply(env_overrides);
        provider.load()
    };
    let loaded = match initial_loaded {
        Ok(l) => l,
        Err(err) => {
            shutdown_mocks(mock_handles).await;
            return CaseReport {
                name: case.name.clone(),
                passed: false,
                duration_ms: started.elapsed().as_millis() as u64,
                failures: vec![format!("failed to load gateway config: {err}")],
            };
        }
    };

    let ui_enabled = loaded.config.admin.ui;
    let mut compiler =
        SnapshotCompiler::new(Arc::new(plugin_registry), Arc::clone(&runtime_registry));
    let trace_store = if ui_enabled {
        let store = Arc::new(TraceRingBuffer::new(loaded.config.admin.ui_trace_capacity));
        compiler = compiler
            .with_extra_global_plugin(Arc::new(InspectorCapturePlugin::new(Arc::clone(&store))));
        Some(store)
    } else {
        None
    };
    let compiler = Arc::new(compiler);

    let initial_bundle = {
        let _env = EnvGuard::apply(env_overrides);
        compiler.compile(&loaded)
    };

    let bundle = match initial_bundle {
        Ok(b) => b,
        Err(err) => {
            shutdown_mocks(mock_handles).await;
            return CaseReport {
                name: case.name.clone(),
                passed: false,
                duration_ms: started.elapsed().as_millis() as u64,
                failures: vec![format!("failed to compile gateway config: {err}")],
            };
        }
    };

    // 3. Bind real GatewayServer + AdminServer on ephemeral 127.0.0.1:0 ports
    let gw_handle = match GatewayServer::new(bundle.snapshot)
        .with_drain_timeout(Duration::from_secs(2))
        .with_trace_enabled(ui_enabled)
        .with_listener_config(bundle.config.server.to_listener_config())
        .bind("127.0.0.1:0".parse().unwrap())
        .await
    {
        Ok(h) => h,
        Err(err) => {
            shutdown_mocks(mock_handles).await;
            return CaseReport {
                name: case.name.clone(),
                passed: false,
                duration_ms: started.elapsed().as_millis() as u64,
                failures: vec![format!("failed to bind GatewayServer: {err}")],
            };
        }
    };

    let controller = Arc::new(ReloadController::new(
        provider.clone(),
        Arc::clone(&compiler),
        gw_handle.reloader(),
        bundle.inspect,
    ));

    let m_clone = Arc::clone(&metrics);
    let ai_m_clone = Arc::clone(&ai_metrics);
    let mcp_m_clone = Arc::clone(&mcp_metrics);
    let ctrl_metrics = Arc::clone(&controller);
    let rt_metrics = Arc::clone(&runtime_registry);
    let render_all_metrics: MetricsRenderer = Arc::new(move || {
        let mut out = m_clone.render_prometheus();
        let snap = ctrl_metrics.current_snapshot();
        let up_out = snap.render_upstream_health_prometheus();
        if !up_out.is_empty() {
            if !out.is_empty() && !out.ends_with('\n') {
                out.push('\n');
            }
            out.push_str(&up_out);
        }
        let mirror_out = snap.render_mirror_metrics_prometheus();
        if !mirror_out.is_empty() {
            if !out.is_empty() && !out.ends_with('\n') {
                out.push('\n');
            }
            out.push_str(&mirror_out);
        }
        let tel_out = rt_metrics.render_telemetry_prometheus();
        if !tel_out.is_empty() {
            if !out.is_empty() && !out.ends_with('\n') {
                out.push('\n');
            }
            out.push_str(&tel_out);
        }
        let ai_out = ai_m_clone.render_prometheus();
        if !ai_out.is_empty() {
            if !out.is_empty() && !out.ends_with('\n') {
                out.push('\n');
            }
            out.push_str(&ai_out);
        }
        let mcp_out = mcp_m_clone.render_prometheus();
        if !mcp_out.is_empty() {
            if !out.is_empty() && !out.ends_with('\n') {
                out.push('\n');
            }
            out.push_str(&mcp_out);
        }
        out
    });

    let ai_m_status = Arc::clone(&ai_metrics);
    let mcp_m_status = Arc::clone(&mcp_metrics);
    let rt_status = Arc::clone(&runtime_registry);
    let rt_mcp_status = Arc::clone(&runtime_registry);
    let mut admin_server =
        AdminServer::new(Arc::clone(&controller), Arc::clone(&render_all_metrics))
            .with_ui_enabled(ui_enabled)
            .with_status_provider(
                "ai",
                Arc::new(move || {
                    inspect_ai_runtime(
                        &ai_m_status,
                        rt_status.state_store(),
                        rt_status.clock().as_ref(),
                    )
                }),
            )
            .with_status_provider(
                "mcp",
                Arc::new(move || {
                    inspect_mcp_runtime(
                        &mcp_m_status,
                        rt_mcp_status.state_store(),
                        rt_mcp_status.clock().as_ref(),
                    )
                }),
            );
    if let Some(store) = trace_store {
        admin_server = admin_server.with_trace_store(store);
    }

    let admin_handle = match admin_server.bind("127.0.0.1:0".parse().unwrap()).await {
        Ok(h) => h,
        Err(err) => {
            gw_handle.shutdown().await;
            shutdown_mocks(mock_handles).await;
            return CaseReport {
                name: case.name.clone(),
                passed: false,
                duration_ms: started.elapsed().as_millis() as u64,
                failures: vec![format!("failed to bind AdminServer: {err}")],
            };
        }
    };

    let gw_addr = gw_handle.local_addr();
    let admin_addr = admin_handle.local_addr();
    let client = Client::builder(TokioExecutor::new()).build_http::<Full<Bytes>>();

    // Normalize single-request shorthand vs multi-step `steps`.
    let steps: Vec<StepSpec> = if !case.steps.is_empty() {
        case.steps.clone()
    } else if case.request.is_some() || case.expect.is_some() {
        vec![StepSpec {
            name: None,
            request: case.request.clone(),
            expect: case.expect.clone(),
            ..Default::default()
        }]
    } else {
        failures.push("case defines neither `request` nor `steps`".to_owned());
        Vec::new()
    };

    for (idx, step) in steps.iter().enumerate() {
        let step_label = step
            .name
            .as_deref()
            .map(|n| format!("step #{idx} ({n})"))
            .unwrap_or_else(|| format!("step #{idx}"));

        if step.reset_captures {
            for m in &mock_handles {
                m.clear_captures();
            }
        }

        if let Some(ms) = step.advance_clock_ms {
            clock.advance_ms(ms);
        }

        if let Some(ms) = step.wait_ms
            && ms > 0
        {
            tokio::time::sleep(Duration::from_millis(ms)).await;
        }

        if let Some(new_toml) = &step.reload_config_inline {
            let before_pools: HashMap<String, u64> = controller
                .current_inspect()
                .upstreams
                .iter()
                .map(|u| (u.name.clone(), u.pool_id))
                .collect();

            provider.set_toml(new_toml.clone());
            let reload_res = {
                let _env = EnvGuard::apply(env_overrides);
                controller.reload()
            };
            let expect_ok = step.expect_reload_ok.unwrap_or(true);
            match (expect_ok, reload_res) {
                (true, Ok(inspect)) => {
                    for up_name in &step.expect_pool_reused {
                        let before_id = before_pools.get(up_name);
                        let after_id = inspect
                            .upstreams
                            .iter()
                            .find(|u| &u.name == up_name)
                            .map(|u| u.pool_id);
                        if before_id.is_none() || before_id != after_id.as_ref() {
                            failures.push(format!(
                                "{step_label}: expected upstream `{up_name}` pool_id to be reused (before={before_id:?}, after={after_id:?})"
                            ));
                        }
                    }
                }
                (true, Err(e)) => {
                    failures.push(format!(
                        "{step_label}: expected reload to succeed, got: {e}"
                    ));
                }
                (false, Ok(inspect)) => {
                    failures.push(format!(
                        "{step_label}: expected reload to fail, but succeeded with v{}",
                        inspect.version
                    ));
                }
                (false, Err(_)) => {}
            }
        }

        if let Some(req_spec) = &step.request {
            let metrics_before = parse_prometheus_metrics(&render_all_metrics());
            let target_addr = if req_spec.admin { admin_addr } else { gw_addr };

            match send_gateway_request(&client, target_addr, req_spec).await {
                Ok(resp_outcome) => {
                    if step.flush_telemetry || runtime_registry.has_active_telemetry() {
                        // Allow off-hot-path `on_complete` tasks to finish enriching & dropping
                        // `SpanHandle` before flushing the OTLP batch worker.
                        tokio::time::sleep(Duration::from_millis(25)).await;
                        runtime_registry
                            .flush_telemetry(Duration::from_secs(2))
                            .await;
                    }
                    if let Some(expect) = &step.expect {
                        check_expectations(
                            &step_label,
                            &resp_outcome,
                            expect,
                            &mock_handles,
                            &metrics_before,
                            &render_all_metrics,
                            &client,
                            admin_addr,
                            &mut failures,
                        )
                        .await;
                    }
                }
                Err(e) => {
                    failures.push(format!("{step_label}: HTTP request failed: {e}"));
                }
            }
        } else if step.flush_telemetry {
            tokio::time::sleep(Duration::from_millis(25)).await;
            runtime_registry
                .flush_telemetry(Duration::from_secs(2))
                .await;
        }
    }

    admin_handle.shutdown().await;
    gw_handle.shutdown().await;
    shutdown_mocks(mock_handles).await;

    CaseReport {
        name: case.name.clone(),
        passed: failures.is_empty(),
        duration_ms: started.elapsed().as_millis() as u64,
        failures,
    }
}

async fn shutdown_mocks(mocks: Vec<MockHandle>) {
    for m in mocks {
        m.shutdown().await;
    }
}

struct ResponseOutcome {
    status: StatusCode,
    headers: http::HeaderMap,
    body: Bytes,
    stream_error: Option<String>,
}

async fn send_gateway_request(
    client: &Client<hyper_util::client::legacy::connect::HttpConnector, Full<Bytes>>,
    gw_addr: SocketAddr,
    spec: &RequestSpec,
) -> Result<ResponseOutcome, String> {
    let method: Method = spec
        .method
        .parse()
        .map_err(|e| format!("invalid method `{}`: {e}", spec.method))?;
    let path = if spec.path.starts_with('/') {
        spec.path.clone()
    } else {
        format!("/{}", spec.path)
    };
    let uri = format!("http://{gw_addr}{path}");

    let mut builder = Request::builder().method(method).uri(uri);
    let mut has_ct = false;
    for (k, v) in &spec.headers {
        if k.eq_ignore_ascii_case("content-type") {
            has_ct = true;
        }
        let hn = HeaderName::from_bytes(k.as_bytes())
            .map_err(|e| format!("invalid header name `{k}`: {e}"))?;
        let hv =
            HeaderValue::from_str(v).map_err(|e| format!("invalid header value for `{k}`: {e}"))?;
        builder = builder.header(hn, hv);
    }

    let body_bytes = if let Some(json_val) = &spec.json {
        if !has_ct {
            builder = builder.header(header::CONTENT_TYPE, "application/json");
        }
        Bytes::from(
            serde_json::to_vec(json_val)
                .map_err(|e| format!("serialize request json failed: {e}"))?,
        )
    } else if let Some(b) = &spec.body {
        Bytes::from(b.clone())
    } else {
        Bytes::new()
    };

    let req = builder
        .body(Full::new(body_bytes))
        .map_err(|e| format!("build request: {e}"))?;

    let res = client
        .request(req)
        .await
        .map_err(|e| format!("send request: {e}"))?;

    let status = res.status();
    let headers = res.headers().clone();

    let mut body_buf = Vec::new();
    let mut incoming = res.into_body();
    let mut stream_error = None;
    while let Some(frame_res) = incoming.frame().await {
        match frame_res {
            Ok(frame) => {
                if let Ok(data) = frame.into_data() {
                    body_buf.extend_from_slice(&data);
                }
            }
            Err(e) => {
                stream_error = Some(e.to_string());
                break;
            }
        }
    }

    Ok(ResponseOutcome {
        status,
        headers,
        body: Bytes::from(body_buf),
        stream_error,
    })
}

#[allow(clippy::too_many_arguments)]
async fn check_expectations(
    step_label: &str,
    resp: &ResponseOutcome,
    expect: &ExpectSpec,
    mocks: &[MockHandle],
    metrics_before: &ParsedMetrics,
    render_metrics: &Arc<dyn Fn() -> String + Send + Sync>,
    client: &Client<hyper_util::client::legacy::connect::HttpConnector, Full<Bytes>>,
    admin_addr: SocketAddr,
    failures: &mut Vec<String>,
) {
    if let Some(exp_status) = expect.status
        && resp.status.as_u16() != exp_status
    {
        failures.push(format!(
            "{step_label}: expected status {exp_status}, got {} (body: {})",
            resp.status.as_u16(),
            String::from_utf8_lossy(&resp.body)
        ));
    }

    if let Some(exp_stream_err) = expect.stream_error {
        let got_err = resp.stream_error.is_some();
        if got_err != exp_stream_err {
            failures.push(format!(
                "{step_label}: expected stream_error={exp_stream_err}, got {got_err} ({:?})",
                resp.stream_error
            ));
        }
    } else if let Some(err) = &resp.stream_error {
        failures.push(format!("{step_label}: unexpected stream error: {err}"));
    }

    for (k, exp_v) in &expect.headers {
        let actual = resp.headers.get(k.as_str()).and_then(|v| v.to_str().ok());
        if actual != Some(exp_v.as_str()) {
            failures.push(format!(
                "{step_label}: header `{k}` expected `{exp_v}`, got `{actual:?}`"
            ));
        }
    }

    for (k, needle) in &expect.headers_contains {
        let actual = resp
            .headers
            .get(k.as_str())
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        if !actual.contains(needle.as_str()) {
            failures.push(format!(
                "{step_label}: header `{k}` expected to contain `{needle}`, got `{actual}`"
            ));
        }
    }

    for k in &expect.headers_present {
        if !resp.headers.contains_key(k.as_str()) {
            failures.push(format!("{step_label}: expected header `{k}` to be present"));
        }
    }

    for k in &expect.headers_absent {
        if resp.headers.contains_key(k.as_str()) {
            failures.push(format!("{step_label}: expected header `{k}` to be absent"));
        }
    }

    let body_text = String::from_utf8_lossy(&resp.body);
    if let Some(eq) = &expect.body_eq
        && body_text.as_ref() != eq.as_str()
    {
        failures.push(format!(
            "{step_label}: body expected `{eq}`, got `{body_text}`"
        ));
    }
    if let Some(sub) = &expect.body_contains
        && !body_text.contains(sub.as_str())
    {
        failures.push(format!(
            "{step_label}: body expected to contain `{sub}`, got `{body_text}`"
        ));
    }
    if let Some(sub) = &expect.body_not_contains
        && body_text.contains(sub.as_str())
    {
        failures.push(format!(
            "{step_label}: body expected NOT to contain `{sub}`, got `{body_text}`"
        ));
    }

    if expect.json_eq.is_some() || !expect.json_path.is_empty() {
        match serde_json::from_slice::<Value>(&resp.body) {
            Ok(parsed) => {
                if let Some(exp_json) = &expect.json_eq
                    && &parsed != exp_json
                {
                    failures.push(format!(
                        "{step_label}: json_eq mismatch\n  expected: {exp_json}\n  actual:   {parsed}"
                    ));
                }
                for (ptr, exp_val) in &expect.json_path {
                    let got = parsed.pointer(ptr);
                    if got != Some(exp_val) {
                        failures.push(format!(
                            "{step_label}: json_path `{ptr}` expected {exp_val}, got {got:?}"
                        ));
                    }
                }
            }
            Err(e) => {
                failures.push(format!(
                    "{step_label}: response body is not valid JSON ({e}): {body_text}"
                ));
            }
        }
    }

    // SSE assertions
    if expect.sse_contains_text.is_some()
        || expect.sse_ends_with.is_some()
        || expect.sse_last_event.is_some()
        || !expect.sse_events_present.is_empty()
        || expect.sse_event_count.is_some()
    {
        let mut parser = SseParser::new();
        let mut events = parser.push(&resp.body);
        events.extend(parser.finish());

        if let Some(exp_count) = expect.sse_event_count
            && events.len() != exp_count
        {
            failures.push(format!(
                "{step_label}: expected {exp_count} SSE events, got {}",
                events.len()
            ));
        }

        if let Some(exp_end) = &expect.sse_ends_with {
            let last_data = events.last().map(|e| e.data.as_str());
            if last_data != Some(exp_end.as_str()) {
                failures.push(format!(
                    "{step_label}: expected final SSE event data `{exp_end}`, got `{last_data:?}`"
                ));
            }
        }

        if let Some(exp_last_ev) = &expect.sse_last_event {
            let last_ev = events.last().and_then(|e| e.event.as_deref());
            if last_ev != Some(exp_last_ev.as_str()) {
                failures.push(format!(
                    "{step_label}: expected final SSE event name `{exp_last_ev}`, got `{last_ev:?}`"
                ));
            }
        }

        if !expect.sse_events_present.is_empty() {
            let seen: Vec<&str> = events.iter().filter_map(|e| e.event.as_deref()).collect();
            for req_ev in &expect.sse_events_present {
                if !seen.iter().any(|&s| s == req_ev) {
                    failures.push(format!(
                        "{step_label}: expected SSE event `{req_ev}` not found in stream (seen: {seen:?})"
                    ));
                }
            }
        }

        if let Some(needle) = &expect.sse_contains_text {
            // Collect OpenAI Chat, Anthropic Messages, and OpenAI Responses delta text + raw SSE data.
            let mut delta_text = String::new();
            let mut raw_joined = String::new();
            for ev in &events {
                raw_joined.push_str(&ev.data);
                if let Ok(v) = serde_json::from_str::<Value>(&ev.data) {
                    if let Some(choices) = v.get("choices").and_then(Value::as_array) {
                        for ch in choices {
                            if let Some(c) = ch
                                .get("delta")
                                .and_then(|d| d.get("content"))
                                .and_then(Value::as_str)
                            {
                                delta_text.push_str(c);
                            }
                        }
                    }
                    // Anthropic `content_block_delta` text_delta
                    if v.get("type").and_then(Value::as_str) == Some("content_block_delta")
                        && let Some(t) = v
                            .get("delta")
                            .and_then(|d| d.get("text"))
                            .and_then(Value::as_str)
                    {
                        delta_text.push_str(t);
                    }
                    // OpenAI Responses `response.output_text.delta`
                    if v.get("type").and_then(Value::as_str) == Some("response.output_text.delta")
                        && let Some(t) = v.get("delta").and_then(Value::as_str)
                    {
                        delta_text.push_str(t);
                    }
                }
            }
            if !delta_text.contains(needle.as_str()) && !raw_joined.contains(needle.as_str()) {
                failures.push(format!(
                    "{step_label}: SSE stream did not contain text `{needle}` (delta=`{delta_text}`)"
                ));
            }
        }
    }

    // Upstream captured call assertions
    for up_exp in &expect.upstream_calls {
        let mut captured: Vec<CapturedRequest> = Vec::new();
        for m in mocks {
            if m.upstream == up_exp.upstream {
                captured.extend(m.captures());
            }
        }

        if let Some(exp_count) = up_exp.count
            && captured.len() != exp_count
        {
            failures.push(format!(
                "{step_label}: upstream `{}` expected {exp_count} calls, got {}",
                up_exp.upstream,
                captured.len()
            ));
            continue;
        }

        let target_call = match up_exp.call_index {
            Some(idx) => captured.get(idx),
            None => captured.last(),
        };

        let needs_call = up_exp.method.is_some()
            || up_exp.path.is_some()
            || !up_exp.headers.is_empty()
            || !up_exp.headers_contains.is_empty()
            || !up_exp.headers_present.is_empty()
            || !up_exp.headers_absent.is_empty()
            || up_exp.body_contains.is_some()
            || !up_exp.json_path.is_empty();

        if needs_call {
            let Some(call) = target_call else {
                failures.push(format!(
                    "{step_label}: upstream `{}` received no captured requests",
                    up_exp.upstream
                ));
                continue;
            };

            if let Some(exp_m) = &up_exp.method
                && !call.method.eq_ignore_ascii_case(exp_m)
            {
                failures.push(format!(
                    "{step_label}: upstream `{}` expected method `{exp_m}`, got `{}`",
                    up_exp.upstream, call.method
                ));
            }

            if let Some(exp_p) = &up_exp.path
                && &call.path_and_query != exp_p
            {
                failures.push(format!(
                    "{step_label}: upstream `{}` expected path `{exp_p}`, got `{}`",
                    up_exp.upstream, call.path_and_query
                ));
            }

            for (hk, hv) in &up_exp.headers {
                let got = call.headers.get(&hk.to_ascii_lowercase());
                if got.map(String::as_str) != Some(hv.as_str()) {
                    failures.push(format!(
                        "{step_label}: upstream `{}` header `{hk}` expected `{hv}`, got `{got:?}`",
                        up_exp.upstream
                    ));
                }
            }

            for (hk, needle) in &up_exp.headers_contains {
                let got = call
                    .headers
                    .get(&hk.to_ascii_lowercase())
                    .map(String::as_str)
                    .unwrap_or("");
                if !got.contains(needle.as_str()) {
                    failures.push(format!(
                        "{step_label}: upstream `{}` header `{hk}` expected to contain `{needle}`, got `{got}`",
                        up_exp.upstream
                    ));
                }
            }

            for hk in &up_exp.headers_present {
                if !call.headers.contains_key(&hk.to_ascii_lowercase()) {
                    failures.push(format!(
                        "{step_label}: upstream `{}` expected header `{hk}` to be present",
                        up_exp.upstream
                    ));
                }
            }

            for hk in &up_exp.headers_absent {
                if call.headers.contains_key(&hk.to_ascii_lowercase()) {
                    failures.push(format!(
                        "{step_label}: upstream `{}` expected header `{hk}` to be absent",
                        up_exp.upstream
                    ));
                }
            }

            if let Some(sub) = &up_exp.body_contains {
                let text = String::from_utf8_lossy(&call.body);
                if !text.contains(sub.as_str()) {
                    failures.push(format!(
                        "{step_label}: upstream `{}` body expected to contain `{sub}`, got `{text}`",
                        up_exp.upstream
                    ));
                }
            }

            if !up_exp.json_path.is_empty() {
                match &call.json {
                    Some(parsed) => {
                        for (ptr, exp_val) in &up_exp.json_path {
                            let got = parsed.pointer(ptr);
                            if got != Some(exp_val) {
                                failures.push(format!(
                                    "{step_label}: upstream `{}` json_path `{ptr}` expected {exp_val}, got {got:?}",
                                    up_exp.upstream
                                ));
                            }
                        }
                    }
                    None => {
                        failures.push(format!(
                            "{step_label}: upstream `{}` request body is not valid JSON: {}",
                            up_exp.upstream,
                            String::from_utf8_lossy(&call.body)
                        ));
                    }
                }
            }
        }
    }

    // Snapshot redaction assertions (`GET /snapshot`)
    if !expect.snapshot_redacts.is_empty() {
        let req = Request::builder()
            .uri(format!("http://{admin_addr}/snapshot"))
            .body(Full::new(Bytes::new()))
            .unwrap();
        match client.request(req).await {
            Ok(res) => {
                let body = res
                    .into_body()
                    .collect()
                    .await
                    .map(|c| c.to_bytes())
                    .unwrap_or_default();
                let snap_str = String::from_utf8_lossy(&body);
                for secret in &expect.snapshot_redacts {
                    if snap_str.contains(secret.as_str()) {
                        failures.push(format!(
                            "{step_label}: secret `{secret}` leaked in GET /snapshot!"
                        ));
                    }
                }
            }
            Err(e) => {
                failures.push(format!("{step_label}: failed to query GET /snapshot: {e}"));
            }
        }
    }

    // Prometheus metrics_delta assertions (poll briefly since `on_complete` runs asynchronously)
    if !expect.metrics_delta.is_empty() {
        let deadline = Instant::now() + Duration::from_millis(300);
        loop {
            let after = parse_prometheus_metrics(&render_metrics());
            let all_match = expect
                .metrics_delta
                .iter()
                .all(|(metric, &expected_delta)| {
                    let delta = metric_value(&after, metric) - metric_value(metrics_before, metric);
                    (delta - expected_delta).abs() < 1e-6
                });
            if all_match {
                break;
            }
            if Instant::now() >= deadline {
                for (metric, &expected_delta) in &expect.metrics_delta {
                    let delta = metric_value(&after, metric) - metric_value(metrics_before, metric);
                    if (delta - expected_delta).abs() >= 1e-6 {
                        failures.push(format!(
                            "{step_label}: metric `{metric}` expected delta {expected_delta}, got {delta}"
                        ));
                    }
                }
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    }
}

#[derive(Default)]
struct ParsedMetrics {
    by_name: HashMap<String, f64>,
    by_series: HashMap<String, f64>,
}

fn parse_prometheus_metrics(text: &str) -> ParsedMetrics {
    let mut parsed = ParsedMetrics::default();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((series, val_str)) = line.rsplit_once(' ') else {
            continue;
        };
        let Ok(val) = val_str.trim().parse::<f64>() else {
            continue;
        };
        let name = series
            .split_once('{')
            .map(|(n, _)| n)
            .unwrap_or(series)
            .to_owned();
        *parsed.by_name.entry(name).or_insert(0.0) += val;
        *parsed.by_series.entry(series.to_owned()).or_insert(0.0) += val;
    }
    parsed
}

fn metric_value(parsed: &ParsedMetrics, key: &str) -> f64 {
    if key.contains('{') {
        parsed.by_series.get(key).copied().unwrap_or(0.0)
    } else {
        parsed.by_name.get(key).copied().unwrap_or(0.0)
    }
}
