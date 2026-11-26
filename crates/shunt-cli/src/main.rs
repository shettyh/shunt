use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use clap::{Parser, Subcommand, ValueEnum};
use shunt_ai::{AiMetrics, inspect_ai_runtime, register_ai_plugins};
use shunt_config::{
    AdminServer, ConfigProvider, DEFAULT_K8S_CONTROLLER_NAME, FileConfigProvider,
    InspectorCapturePlugin, K8sApiConfigProvider, K8sClientConfig, K8sGatewayOptions,
    K8sManifestConfigProvider, MultiListenerSupervisor, ReloadController, Severity,
    SnapshotCompiler, SnapshotInspect, TraceRingBuffer, load_policy_file, start_file_watcher,
    start_k8s_controller_loop, start_k8s_sync_loop, ui_feature_compiled, verify_bundle,
};
use shunt_engine::{DynamicCertResolver, GatewayServer, RuntimeRegistry, TlsListenerConfig};
use shunt_mcp::{McpMetrics, inspect_mcp_runtime, register_mcp_plugins};
use shunt_plugin_sdk::PluginRegistry;
use shunt_plugins::{DevWaterfallPlugin, PrometheusMetrics, register_builtin_plugins};
use tracing::{error, info, warn};
use tracing_subscriber::EnvFilter;

#[derive(Copy, Clone, Debug, PartialEq, Eq, ValueEnum)]
enum OutputFormat {
    Text,
    Json,
}

#[derive(Parser, Debug)]
#[command(
    name = "shunt",
    version,
    about = "Ultra-lean, pluggable Rust HTTP gateway"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Validate config, compile snapshot, and print compiled routes + active HookMasks.
    Check {
        /// Path to shunt.toml (or .yaml/.yml).
        #[arg(short = 'c', long = "config", default_value = "shunt.toml")]
        config: PathBuf,
        /// Optional path to Kubernetes Gateway API YAML manifest file or directory.
        #[arg(long = "k8s-manifest")]
        k8s_manifest: Option<PathBuf>,
        /// Kubernetes GatewayClass controllerName filter (when using `--k8s-manifest`).
        #[arg(long = "k8s-controller-name", default_value = DEFAULT_K8S_CONTROLLER_NAME)]
        k8s_controller_name: String,
        /// Optional Kubernetes namespace filter.
        #[arg(long = "k8s-namespace")]
        k8s_namespace: Option<String>,
    },
    /// Run static IR, route-shadowing, AI chain, and declarative policy verification.
    Verify {
        /// Path to shunt.toml (or .yaml/.yml).
        #[arg(short = 'c', long = "config", default_value = "shunt.toml")]
        config: PathBuf,
        /// Optional path to Kubernetes Gateway API YAML manifest file or directory.
        #[arg(long = "k8s-manifest")]
        k8s_manifest: Option<PathBuf>,
        /// Kubernetes GatewayClass controllerName filter.
        #[arg(long = "k8s-controller-name", default_value = DEFAULT_K8S_CONTROLLER_NAME)]
        k8s_controller_name: String,
        /// Optional Kubernetes namespace filter.
        #[arg(long = "k8s-namespace")]
        k8s_namespace: Option<String>,
        /// Optional external policy TOML file overriding `[verify]` rules.
        #[arg(long = "policy")]
        policy: Option<PathBuf>,
        /// Output format (`text` or `json`).
        #[arg(long = "format", value_enum, default_value_t = OutputFormat::Text)]
        format: OutputFormat,
        /// Treat warnings as errors (non-zero exit code).
        #[arg(long = "strict")]
        strict: bool,
    },
    /// Execute declarative TOML contract tests (`shunt.spec.toml`) against in-process mocks.
    Test {
        /// Optional override path to shunt.toml (defaults to `spec.config` inside the spec file).
        #[arg(short = 'c', long = "config")]
        config: Option<PathBuf>,
        /// Path to shunt.spec.toml contract test suite.
        #[arg(short = 's', long = "spec")]
        spec: PathBuf,
        /// Only run test cases whose name contains this substring (case-insensitive).
        #[arg(long = "filter")]
        filter: Option<String>,
        /// Output format (`text` or `json`).
        #[arg(long = "format", value_enum, default_value_t = OutputFormat::Text)]
        format: OutputFormat,
    },
    /// Run the production gateway with atomic hot reloads, Admin API, and graceful draining.
    Run {
        /// Path to shunt.toml (or .yaml/.yml).
        #[arg(short = 'c', long = "config", default_value = "shunt.toml")]
        config: PathBuf,
        /// Disable automatic file watching (reloads still work via POST /reload or SIGHUP).
        #[arg(long = "no-watch")]
        no_watch: bool,
        /// Enable the read-only Admin Inspector Web UI and live trace waterfall on the Admin listener.
        #[arg(long = "ui")]
        ui: bool,
        /// Optional path to Kubernetes Gateway API YAML manifest file or directory.
        #[arg(long = "k8s-manifest")]
        k8s_manifest: Option<PathBuf>,
        /// Enable live Kubernetes Gateway API sync from cluster API server (in-cluster or `--k8s-api-server`).
        #[arg(long = "k8s-gateway")]
        k8s_gateway: bool,
        /// Enable full Kubernetes Gateway API `GATEWAY-HTTP` controller mode (multi-listener, `.status` PATCH, per-Gateway Service reconciliation).
        #[arg(long = "k8s-controller")]
        k8s_controller: bool,
        /// Explicit Kubernetes API server URL (defaults to in-cluster `KUBERNETES_SERVICE_HOST`).
        #[arg(long = "k8s-api-server")]
        k8s_api_server: Option<String>,
        /// Optional Kubernetes namespace filter.
        #[arg(long = "k8s-namespace")]
        k8s_namespace: Option<String>,
        /// Kubernetes GatewayClass controllerName filter.
        #[arg(long = "k8s-controller-name", default_value = DEFAULT_K8S_CONTROLLER_NAME)]
        k8s_controller_name: String,
        /// Kubernetes Service type for managed per-Gateway Services (`ClusterIP`, `LoadBalancer`, `NodePort`).
        #[arg(long = "k8s-service-type", default_value = "ClusterIP")]
        k8s_service_type: String,
        /// Comma-separated pod label selector for managed per-Gateway Services (e.g. `app.kubernetes.io/name=shunt`).
        #[arg(
            long = "k8s-pod-selector",
            default_value = "app.kubernetes.io/name=shunt"
        )]
        k8s_pod_selector: String,
        /// Internal pod port range `<start>-<end>` for multi-Gateway listener isolation in `--k8s-controller` mode.
        #[arg(long = "k8s-port-range", default_value = "10080-19999")]
        k8s_port_range: String,
        /// Poll interval in milliseconds for live `--k8s-gateway` / `--k8s-controller` sync (default: 5000, or 1000 in controller mode).
        #[arg(long = "k8s-poll-interval-ms")]
        k8s_poll_interval_ms: Option<u64>,
        /// Gateway listener address override when using `--k8s-manifest` or `--k8s-gateway`.
        #[arg(long = "listen", default_value = "0.0.0.0:8080")]
        listen: String,
    },
    /// Run in developer mode with auto file-watch reload and live per-hook µs trace waterfalls.
    Dev {
        /// Path to shunt.toml (or .yaml/.yml).
        #[arg(short = 'c', long = "config", default_value = "shunt.toml")]
        config: PathBuf,
        /// Enable the read-only Admin Inspector Web UI and live trace waterfall on the Admin listener.
        #[arg(long = "ui")]
        ui: bool,
        /// Optional path to Kubernetes Gateway API YAML manifest file or directory.
        #[arg(long = "k8s-manifest")]
        k8s_manifest: Option<PathBuf>,
        /// Kubernetes GatewayClass controllerName filter.
        #[arg(long = "k8s-controller-name", default_value = DEFAULT_K8S_CONTROLLER_NAME)]
        k8s_controller_name: String,
        /// Optional Kubernetes namespace filter.
        #[arg(long = "k8s-namespace")]
        k8s_namespace: Option<String>,
    },
}

enum ServerSource {
    File(PathBuf),
    K8sManifest {
        path: PathBuf,
        options: K8sGatewayOptions,
    },
    K8sApi {
        api_server: Option<String>,
        poll_interval_ms: u64,
        options: K8sGatewayOptions,
    },
}

#[tokio::main]
async fn main() -> ExitCode {
    let cli = Cli::parse();

    match cli.command {
        Commands::Check {
            config,
            k8s_manifest,
            k8s_controller_name,
            k8s_namespace,
        } => {
            let provider: Box<dyn ConfigProvider> = match k8s_manifest {
                Some(path) => Box::new(K8sManifestConfigProvider::new(
                    path,
                    K8sGatewayOptions {
                        controller_name: k8s_controller_name,
                        namespace: k8s_namespace,
                        ..K8sGatewayOptions::default()
                    },
                )),
                None => Box::new(FileConfigProvider::new(config)),
            };
            run_check(provider.as_ref())
        }
        Commands::Verify {
            config,
            k8s_manifest,
            k8s_controller_name,
            k8s_namespace,
            policy,
            format,
            strict,
        } => {
            let provider: Box<dyn ConfigProvider> = match k8s_manifest {
                Some(path) => Box::new(K8sManifestConfigProvider::new(
                    path,
                    K8sGatewayOptions {
                        controller_name: k8s_controller_name,
                        namespace: k8s_namespace,
                        ..K8sGatewayOptions::default()
                    },
                )),
                None => Box::new(FileConfigProvider::new(config)),
            };
            run_verify(provider.as_ref(), policy, format, strict)
        }
        Commands::Test {
            config,
            spec,
            filter,
            format,
        } => run_test(config, spec, filter, format).await,
        Commands::Run {
            config,
            no_watch,
            ui,
            k8s_manifest,
            k8s_gateway,
            k8s_controller,
            k8s_api_server,
            k8s_namespace,
            k8s_controller_name,
            k8s_service_type,
            k8s_pod_selector,
            k8s_port_range,
            k8s_poll_interval_ms,
            listen,
        } => {
            init_tracing("info");
            if k8s_controller {
                let pod_selector = match parse_k8s_pod_selector(&k8s_pod_selector) {
                    Ok(m) => m,
                    Err(e) => {
                        eprintln!("error: invalid --k8s-pod-selector: {e}");
                        return ExitCode::FAILURE;
                    }
                };
                let (port_start, port_end) = match parse_port_range(&k8s_port_range) {
                    Ok(pair) => pair,
                    Err(msg) => {
                        eprintln!("error: {msg}");
                        return ExitCode::FAILURE;
                    }
                };
                let opts = K8sGatewayOptions {
                    controller_name: k8s_controller_name,
                    namespace: k8s_namespace,
                    listen,
                    admin_ui: ui,
                    write_status: true,
                    manage_services: true,
                    service_type: k8s_service_type,
                    pod_selector,
                    port_range_start: port_start,
                    port_range_end: port_end,
                    ..K8sGatewayOptions::default()
                };
                return run_k8s_controller(
                    k8s_api_server,
                    k8s_poll_interval_ms.unwrap_or(1_000),
                    opts,
                )
                .await;
            }
            let source = if k8s_gateway {
                ServerSource::K8sApi {
                    api_server: k8s_api_server,
                    poll_interval_ms: k8s_poll_interval_ms.unwrap_or(5_000),
                    options: K8sGatewayOptions {
                        controller_name: k8s_controller_name,
                        namespace: k8s_namespace,
                        listen,
                        admin_ui: ui,
                        ..K8sGatewayOptions::default()
                    },
                }
            } else if let Some(path) = k8s_manifest {
                ServerSource::K8sManifest {
                    path,
                    options: K8sGatewayOptions {
                        controller_name: k8s_controller_name,
                        namespace: k8s_namespace,
                        listen,
                        admin_ui: ui,
                        ..K8sGatewayOptions::default()
                    },
                }
            } else {
                ServerSource::File(config)
            };
            run_server(source, false, !no_watch, ui).await
        }
        Commands::Dev {
            config,
            ui,
            k8s_manifest,
            k8s_controller_name,
            k8s_namespace,
        } => {
            init_tracing("warn,shunt_cli=info,shunt_config=info");
            let source = match k8s_manifest {
                Some(path) => ServerSource::K8sManifest {
                    path,
                    options: K8sGatewayOptions {
                        controller_name: k8s_controller_name,
                        namespace: k8s_namespace,
                        admin_ui: ui,
                        ..K8sGatewayOptions::default()
                    },
                },
                None => ServerSource::File(config),
            };
            run_server(source, true, true, ui).await
        }
    }
}

fn parse_k8s_pod_selector(raw: &str) -> Result<BTreeMap<String, String>, String> {
    let mut map = BTreeMap::new();
    for entry in raw.split(',').map(str::trim).filter(|s| !s.is_empty()) {
        let (k, v) = entry
            .split_once('=')
            .ok_or_else(|| format!("expected `key=value` pair, got `{entry}`"))?;
        let key = k.trim();
        let val = v.trim();
        if key.is_empty() || val.is_empty() {
            return Err(format!("empty key or value in `{entry}`"));
        }
        map.insert(key.to_owned(), val.to_owned());
    }
    if map.is_empty() {
        return Err("pod selector must contain at least one `key=value` label".to_owned());
    }
    Ok(map)
}

fn parse_port_range(raw: &str) -> Result<(u16, u16), String> {
    let (a, b) = raw
        .split_once('-')
        .ok_or_else(|| format!("invalid --k8s-port-range `{raw}` (expected `<start>-<end>`)"))?;
    let start: u16 = a
        .trim()
        .parse()
        .map_err(|_| format!("invalid --k8s-port-range start `{a}`"))?;
    let end: u16 = b
        .trim()
        .parse()
        .map_err(|_| format!("invalid --k8s-port-range end `{b}`"))?;
    if start == 0 || end == 0 || start > end {
        return Err(format!(
            "invalid --k8s-port-range `{raw}`: start must be >= 1 and <= end"
        ));
    }
    Ok((start, end))
}

async fn run_k8s_controller(
    api_server: Option<String>,
    poll_interval_ms: u64,
    options: K8sGatewayOptions,
) -> ExitCode {
    let mut client_cfg = match api_server {
        Some(url) => K8sClientConfig {
            api_server: url,
            bearer_token: std::env::var("K8S_BEARER_TOKEN").ok(),
            token_path: None,
            ca_cert_pem: None,
            insecure_skip_verify: false,
            request_timeout: Duration::from_secs(10),
            poll_interval: Duration::from_millis(poll_interval_ms.max(200)),
        },
        None => match K8sClientConfig::from_in_cluster() {
            Ok(mut cfg) => {
                cfg.poll_interval = Duration::from_millis(poll_interval_ms.max(200));
                cfg
            }
            Err(err) => {
                eprintln!("error: {err}");
                return ExitCode::FAILURE;
            }
        },
    };
    if let Ok(tok) = std::env::var("K8S_BEARER_TOKEN")
        && !tok.is_empty()
    {
        client_cfg.bearer_token = Some(tok);
    }

    let api_prov = match K8sApiConfigProvider::new(client_cfg, options.clone()) {
        Ok(p) => Arc::new(p),
        Err(err) => {
            eprintln!("error: {err}");
            return ExitCode::FAILURE;
        }
    };

    let GatewayRegistries {
        plugins, runtime, ..
    } = build_registries();
    let compiler = Arc::new(SnapshotCompiler::new(plugins, Arc::clone(&runtime)));
    let supervisor = MultiListenerSupervisor::new(compiler);

    let ctrl_handle = match start_k8s_controller_loop(api_prov, supervisor).await {
        Ok(h) => h,
        Err(err) => {
            eprintln!("error: failed to start Kubernetes Gateway API controller: {err}");
            return ExitCode::FAILURE;
        }
    };

    info!(
        controller_name = %options.controller_name,
        service_type = %options.service_type,
        port_range = %format!("{}-{}", options.port_range_start, options.port_range_end),
        "shunt Kubernetes Gateway API controller ready"
    );

    wait_for_shutdown_only().await;
    info!("shutdown signal received; draining Gateway listeners");
    ctrl_handle.shutdown().await;
    runtime.flush_telemetry(Duration::from_secs(2)).await;
    info!("graceful controller shutdown complete");
    ExitCode::SUCCESS
}

async fn wait_for_shutdown_only() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        let mut sigterm = signal(SignalKind::terminate()).expect("SIGTERM handler");
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {}
            _ = sigterm.recv() => {}
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}
fn init_tracing(default_filter: &str) {
    let filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(default_filter));
    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .try_init();
}

struct GatewayRegistries {
    plugins: Arc<PluginRegistry>,
    runtime: Arc<RuntimeRegistry>,
    metrics: Arc<PrometheusMetrics>,
    ai_metrics: Arc<AiMetrics>,
    mcp_metrics: Arc<McpMetrics>,
}

fn build_registries() -> GatewayRegistries {
    let metrics = Arc::new(PrometheusMetrics::new());
    let ai_metrics = Arc::new(AiMetrics::new());
    let mcp_metrics = Arc::new(McpMetrics::new());
    let mut plugin_registry = PluginRegistry::new();
    register_builtin_plugins(&mut plugin_registry, Arc::clone(&metrics));
    register_ai_plugins(&mut plugin_registry, Arc::clone(&ai_metrics));
    register_mcp_plugins(&mut plugin_registry, Arc::clone(&mcp_metrics));
    let runtime = Arc::new(RuntimeRegistry::new());
    GatewayRegistries {
        plugins: Arc::new(plugin_registry),
        runtime,
        metrics,
        ai_metrics,
        mcp_metrics,
    }
}

fn run_check(provider: &dyn ConfigProvider) -> ExitCode {
    let loaded = match provider.load() {
        Ok(l) => l,
        Err(err) => {
            eprintln!("error: {err}");
            return ExitCode::FAILURE;
        }
    };

    let regs = build_registries();
    let compiler = SnapshotCompiler::new(regs.plugins, regs.runtime);
    match compiler.compile(&loaded) {
        Ok(bundle) => {
            println!("Configuration valid: {}", provider.source_name());
            print_snapshot_table(&bundle.inspect);
            ExitCode::SUCCESS
        }
        Err(err) => {
            eprintln!("error: {err}");
            ExitCode::FAILURE
        }
    }
}

fn run_verify(
    provider: &dyn ConfigProvider,
    policy_path: Option<PathBuf>,
    format: OutputFormat,
    strict: bool,
) -> ExitCode {
    let loaded = match provider.load() {
        Ok(l) => l,
        Err(err) => {
            eprintln!("error: {err}");
            return ExitCode::FAILURE;
        }
    };

    let policy = match policy_path {
        Some(p) => match load_policy_file(&p) {
            Ok(pol) => Some(pol),
            Err(err) => {
                eprintln!("error: {err}");
                return ExitCode::FAILURE;
            }
        },
        None => None,
    };

    let regs = build_registries();
    let compiler = SnapshotCompiler::new(regs.plugins, regs.runtime);
    let bundle = match compiler.compile(&loaded) {
        Ok(b) => b,
        Err(err) => {
            eprintln!("error: {err}");
            return ExitCode::FAILURE;
        }
    };

    let report = verify_bundle(&bundle, policy.as_ref(), strict);
    match format {
        OutputFormat::Json => {
            println!(
                "{}",
                serde_json::to_string_pretty(&report).unwrap_or_else(|_| "{}".to_owned())
            );
        }
        OutputFormat::Text => {
            if report.diagnostics.is_empty() {
                println!(
                    "Verification passed: {} (0 errors, 0 warnings)",
                    provider.source_name()
                );
            } else {
                for d in &report.diagnostics {
                    let level = match d.severity {
                        Severity::Error => "ERROR",
                        Severity::Warning => "WARN ",
                        Severity::Info => "INFO ",
                    };
                    match &d.subject {
                        Some(subj) => println!("[{level}] {} ({subj}): {}", d.rule, d.message),
                        None => println!("[{level}] {}: {}", d.rule, d.message),
                    }
                }
                println!(
                    "\nVerification {}: {} error(s), {} warning(s), {} info(s)",
                    if report.passed { "passed" } else { "FAILED" },
                    report.errors,
                    report.warnings,
                    report.infos
                );
            }
        }
    }

    if report.passed {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

async fn run_test(
    config_path: Option<PathBuf>,
    spec_path: PathBuf,
    filter: Option<String>,
    format: OutputFormat,
) -> ExitCode {
    let report = match shunt_test::run_spec_file(
        &spec_path,
        config_path.as_deref(),
        filter.as_deref(),
    )
    .await
    {
        Ok(r) => r,
        Err(err) => {
            eprintln!("error: {err}");
            return ExitCode::FAILURE;
        }
    };

    match format {
        OutputFormat::Json => {
            println!(
                "{}",
                serde_json::to_string_pretty(&report).unwrap_or_else(|_| "{}".to_owned())
            );
        }
        OutputFormat::Text => {
            println!("Spec: {} ({} case(s))", report.spec_name, report.total);
            for c in &report.cases {
                let mark = if c.passed { "PASS" } else { "FAIL" };
                println!("  [{mark}] {} ({}ms)", c.name, c.duration_ms);
                for f in &c.failures {
                    println!("         - {f}");
                }
            }
            println!(
                "\nResult: {} passed, {} failed (total {})",
                report.passed, report.failed, report.total
            );
        }
    }

    if report.all_passed() {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

async fn run_server(
    source: ServerSource,
    dev_mode: bool,
    watch_files: bool,
    cli_ui: bool,
) -> ExitCode {
    let mut watched_root: Option<PathBuf> = None;
    let mut k8s_api_provider: Option<Arc<K8sApiConfigProvider>> = None;

    let provider: Arc<dyn ConfigProvider> = match source {
        ServerSource::File(path) => {
            watched_root = Some(path.clone());
            Arc::new(FileConfigProvider::new(path))
        }
        ServerSource::K8sManifest { path, options } => {
            watched_root = Some(path.clone());
            Arc::new(K8sManifestConfigProvider::new(path, options))
        }
        ServerSource::K8sApi {
            api_server,
            poll_interval_ms,
            options,
        } => {
            let mut client_cfg = match api_server {
                Some(url) => K8sClientConfig {
                    api_server: url,
                    bearer_token: std::env::var("K8S_BEARER_TOKEN").ok(),
                    token_path: None,
                    ca_cert_pem: None,
                    insecure_skip_verify: false,
                    request_timeout: Duration::from_secs(10),
                    poll_interval: Duration::from_millis(poll_interval_ms.max(200)),
                },
                None => match K8sClientConfig::from_in_cluster() {
                    Ok(mut cfg) => {
                        cfg.poll_interval = Duration::from_millis(poll_interval_ms.max(200));
                        cfg
                    }
                    Err(err) => {
                        eprintln!("error: {err}");
                        return ExitCode::FAILURE;
                    }
                },
            };
            if let Ok(tok) = std::env::var("K8S_BEARER_TOKEN")
                && !tok.is_empty()
            {
                client_cfg.bearer_token = Some(tok);
            }
            let api_prov = match K8sApiConfigProvider::new(client_cfg, options) {
                Ok(p) => Arc::new(p),
                Err(err) => {
                    eprintln!("error: {err}");
                    return ExitCode::FAILURE;
                }
            };
            if let Err(err) = api_prov.sync_once().await {
                eprintln!("error: initial Kubernetes Gateway API sync failed: {err}");
                return ExitCode::FAILURE;
            }
            k8s_api_provider = Some(Arc::clone(&api_prov));
            api_prov
        }
    };

    let source_label = provider.source_name();
    let loaded = match provider.load() {
        Ok(l) => l,
        Err(err) => {
            eprintln!("error: {err}");
            return ExitCode::FAILURE;
        }
    };

    let ui_enabled = cli_ui || loaded.config.admin.ui;
    if ui_enabled && !loaded.config.admin.enabled {
        eprintln!(
            "error: Admin Inspector UI (`--ui` / `admin.ui = true`) requires `[admin] enabled = true`"
        );
        return ExitCode::FAILURE;
    }
    if ui_enabled && !ui_feature_compiled() {
        eprintln!(
            "error: Admin Inspector UI requested, but this `shunt` binary was compiled without the `admin-ui` Cargo feature"
        );
        return ExitCode::FAILURE;
    }

    let GatewayRegistries {
        plugins,
        runtime,
        metrics,
        ai_metrics,
        mcp_metrics,
    } = build_registries();
    let mut compiler = SnapshotCompiler::new(plugins, Arc::clone(&runtime));
    if dev_mode {
        compiler = compiler.with_extra_global_plugin(Arc::new(DevWaterfallPlugin::stderr()));
    }
    let trace_store = if ui_enabled {
        let store = Arc::new(TraceRingBuffer::new(loaded.config.admin.ui_trace_capacity));
        compiler = compiler
            .with_extra_global_plugin(Arc::new(InspectorCapturePlugin::new(Arc::clone(&store))));
        Some(store)
    } else {
        None
    };
    let compiler = Arc::new(compiler);

    let bundle = match compiler.compile(&loaded) {
        Ok(b) => b,
        Err(err) => {
            eprintln!("error: {err}");
            return ExitCode::FAILURE;
        }
    };

    let listen_addr: SocketAddr = match bundle.config.server.listen.parse() {
        Ok(a) => a,
        Err(err) => {
            eprintln!("error: invalid server.listen: {err}");
            return ExitCode::FAILURE;
        }
    };

    let mut gw = GatewayServer::new(bundle.snapshot)
        .with_drain_timeout(Duration::from_millis(bundle.config.server.drain_timeout_ms))
        .with_trace_enabled(dev_mode || ui_enabled);

    if let Some(certs) = bundle.cert_store {
        let resolver = Arc::new(DynamicCertResolver::new(certs));
        gw = gw.with_tls(TlsListenerConfig::new(resolver).with_client_auth(bundle.client_auth));
    }

    let server_handle = match gw.bind(listen_addr).await {
        Ok(h) => h,
        Err(err) => {
            error!(error = %err, "failed to bind gateway server");
            return ExitCode::FAILURE;
        }
    };

    let controller = Arc::new(ReloadController::new(
        provider.clone(),
        Arc::clone(&compiler),
        server_handle.reloader(),
        bundle.inspect.clone(),
    ));

    let admin_handle = if bundle.config.admin.enabled {
        let admin_addr: SocketAddr = match bundle.config.admin.listen.parse() {
            Ok(a) => a,
            Err(err) => {
                error!(error = %err, "invalid admin.listen");
                server_handle.shutdown().await;
                return ExitCode::FAILURE;
            }
        };
        let metrics_clone = Arc::clone(&metrics);
        let ai_metrics_clone = Arc::clone(&ai_metrics);
        let mcp_metrics_clone = Arc::clone(&mcp_metrics);
        let controller_metrics = Arc::clone(&controller);
        let runtime_metrics = Arc::clone(&runtime);
        let ai_metrics_status = Arc::clone(&ai_metrics);
        let mcp_metrics_status = Arc::clone(&mcp_metrics);
        let runtime_status = Arc::clone(&runtime);
        let runtime_mcp_status = Arc::clone(&runtime);
        let mut admin = AdminServer::new(
            Arc::clone(&controller),
            Arc::new(move || {
                let mut out = metrics_clone.render_prometheus();
                let snap = controller_metrics.current_snapshot();
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
                let tel_out = runtime_metrics.render_telemetry_prometheus();
                if !tel_out.is_empty() {
                    if !out.is_empty() && !out.ends_with('\n') {
                        out.push('\n');
                    }
                    out.push_str(&tel_out);
                }
                let ai_out = ai_metrics_clone.render_prometheus();
                if !ai_out.is_empty() {
                    if !out.is_empty() && !out.ends_with('\n') {
                        out.push('\n');
                    }
                    out.push_str(&ai_out);
                }
                let mcp_out = mcp_metrics_clone.render_prometheus();
                if !mcp_out.is_empty() {
                    if !out.is_empty() && !out.ends_with('\n') {
                        out.push('\n');
                    }
                    out.push_str(&mcp_out);
                }
                out
            }),
        )
        .with_ui_enabled(ui_enabled)
        .with_status_provider(
            "ai",
            Arc::new(move || {
                inspect_ai_runtime(
                    &ai_metrics_status,
                    runtime_status.state_store(),
                    runtime_status.clock().as_ref(),
                )
            }),
        )
        .with_status_provider(
            "mcp",
            Arc::new(move || {
                inspect_mcp_runtime(
                    &mcp_metrics_status,
                    runtime_mcp_status.state_store(),
                    runtime_mcp_status.clock().as_ref(),
                )
            }),
        );
        if let Some(store) = trace_store {
            admin = admin.with_trace_store(store);
        }
        match admin.bind(admin_addr).await {
            Ok(h) => Some(h),
            Err(err) => {
                error!(error = %err, "failed to bind admin server");
                server_handle.shutdown().await;
                return ExitCode::FAILURE;
            }
        }
    } else {
        None
    };

    let watcher_handle = if watch_files && let Some(root_path) = watched_root {
        let mut files = vec![root_path];
        files.extend(bundle.config.referenced_tls_files());
        match start_file_watcher(files, Arc::clone(&controller), Duration::from_millis(150)) {
            Ok(h) => Some(h),
            Err(err) => {
                warn!(error = %err, "file watcher unavailable; manual POST /reload still active");
                None
            }
        }
    } else {
        None
    };

    let k8s_sync_handle =
        k8s_api_provider.map(|api_prov| start_k8s_sync_loop(api_prov, Arc::clone(&controller)));

    if dev_mode {
        eprintln!(
            "shunt dev listening on {} (admin: {})",
            server_handle.local_addr(),
            admin_handle
                .as_ref()
                .map(|a| a.local_addr().to_string())
                .unwrap_or_else(|| "disabled".to_owned())
        );
        if ui_enabled && let Some(admin) = &admin_handle {
            eprintln!(
                "Admin Inspector UI (read-only): http://{}/ui",
                admin.local_addr()
            );
        }
        print_snapshot_table(&bundle.inspect);
        eprintln!("Watching {source_label} for live reloads...\n");
    } else {
        info!(
            listen = %server_handle.local_addr(),
            admin = %admin_handle
                .as_ref()
                .map(|a| a.local_addr().to_string())
                .unwrap_or_else(|| "disabled".to_owned()),
            inspector_ui = %if ui_enabled {
                admin_handle
                    .as_ref()
                    .map(|a| format!("http://{}/ui", a.local_addr()))
                    .unwrap_or_else(|| "disabled".to_owned())
            } else {
                "disabled".to_owned()
            },
            version = bundle.inspect.version,
            digest = %bundle.inspect.digest,
            "shunt gateway ready"
        );
    }

    wait_for_signals(Arc::clone(&controller)).await;

    info!("shutdown signal received; draining in-flight connections");
    if let Some(k8s_sync) = k8s_sync_handle {
        k8s_sync.stop();
    }
    if let Some(watcher) = watcher_handle {
        watcher.stop();
    }
    if let Some(admin) = admin_handle {
        admin.shutdown().await;
    }
    let clean = server_handle.shutdown().await;
    runtime.flush_telemetry(Duration::from_secs(2)).await;
    if clean {
        info!("graceful shutdown complete");
    } else {
        warn!("drain timeout elapsed with active connections remaining");
    }

    ExitCode::SUCCESS
}

async fn wait_for_signals(controller: Arc<ReloadController>) {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        let mut sigterm = signal(SignalKind::terminate()).expect("SIGTERM handler");
        let mut sighup = signal(SignalKind::hangup()).expect("SIGHUP handler");

        loop {
            tokio::select! {
                _ = tokio::signal::ctrl_c() => break,
                _ = sigterm.recv() => break,
                _ = sighup.recv() => {
                    info!("SIGHUP received; triggering config reload");
                    if let Err(err) = controller.reload() {
                        warn!(error = %err, "SIGHUP reload failed; keeping last-known-good snapshot");
                    }
                }
            }
        }
    }

    #[cfg(not(unix))]
    {
        let _ = controller;
        let _ = tokio::signal::ctrl_c().await;
    }
}

fn print_snapshot_table(inspect: &SnapshotInspect) {
    println!(
        "Snapshot v{} (digest: {}, state: {}, telemetry: {})",
        inspect.version,
        &inspect.digest[..inspect.digest.len().min(12)],
        inspect.state_backend,
        inspect.telemetry_backend
    );

    if !inspect.global_plugins.is_empty() {
        println!("\nGlobal Plugins:");
        for p in &inspect.global_plugins {
            println!("  - {:<18} mask=[{}]", p.name, p.hook_mask);
        }
    }

    if !inspect.route_groups.is_empty() {
        println!("\nRoute Groups ({}):", inspect.route_groups.len());
        for g in &inspect.route_groups {
            let prefix = g.path_prefix.as_deref().unwrap_or("*");
            let hosts = if g.hosts.is_empty() {
                "*".to_owned()
            } else {
                g.hosts.join(",")
            };
            let plugins = if g.plugins.is_empty() {
                "(none)".to_owned()
            } else {
                g.plugins
                    .iter()
                    .map(|p| p.name.as_str())
                    .collect::<Vec<_>>()
                    .join(" -> ")
            };
            println!(
                "  - {:<16} [{} {}] routes={} plugins=[{}]",
                g.id,
                hosts,
                prefix,
                g.routes.len(),
                plugins
            );
        }
    }

    println!("\nUpstreams ({}):", inspect.upstreams.len());
    for u in &inspect.upstreams {
        let proto = if u.http2_only { "h2c" } else { "h1/h2" };
        println!(
            "  - {:<18} pool=#{} [{}] -> {}",
            u.name,
            u.pool_id,
            proto,
            u.endpoints.join(", ")
        );
    }

    println!("\nRoutes ({}):", inspect.routes.len());
    for r in &inspect.routes {
        let hosts = if r.hosts.is_empty() {
            "*".to_owned()
        } else {
            r.hosts.join(",")
        };
        let methods = if r.methods.is_empty() {
            "ANY".to_owned()
        } else {
            r.methods.join(",")
        };
        let plugins = if r.plugins.is_empty() {
            "(none)".to_owned()
        } else {
            r.plugins.join(" -> ")
        };
        let group_tag = match &r.group {
            Some(gid) => format!(" group={gid}"),
            None => String::new(),
        };
        println!(
            "  - {:<16} [{} {} {}] -> {} (attempts={}{}, plugins=[{}])",
            r.id, methods, hosts, r.path, r.upstream, r.max_attempts, group_tag, plugins
        );
        println!("    HookMask: {}", r.hook_mask);
    }
}
