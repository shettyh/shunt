use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use clap::{Parser, Subcommand, ValueEnum};
use shunt_ai::{AiMetrics, register_ai_plugins};
use shunt_config::{
    AdminServer, ConfigProvider, FileConfigProvider, ReloadController, Severity, SnapshotCompiler,
    SnapshotInspect, load_policy_file, start_file_watcher, verify_bundle,
};
use shunt_core::{DynamicCertResolver, GatewayServer, RuntimeRegistry, TlsListenerConfig};
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
    },
    /// Run static IR, route-shadowing, AI chain, and declarative policy verification.
    Verify {
        /// Path to shunt.toml (or .yaml/.yml).
        #[arg(short = 'c', long = "config", default_value = "shunt.toml")]
        config: PathBuf,
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
    },
    /// Run in developer mode with auto file-watch reload and live per-hook µs trace waterfalls.
    Dev {
        /// Path to shunt.toml (or .yaml/.yml).
        #[arg(short = 'c', long = "config", default_value = "shunt.toml")]
        config: PathBuf,
    },
}

#[tokio::main]
async fn main() -> ExitCode {
    let cli = Cli::parse();

    match cli.command {
        Commands::Check { config } => run_check(config),
        Commands::Verify {
            config,
            policy,
            format,
            strict,
        } => run_verify(config, policy, format, strict),
        Commands::Test {
            config,
            spec,
            filter,
            format,
        } => run_test(config, spec, filter, format).await,
        Commands::Run { config, no_watch } => {
            init_tracing("info");
            run_server(config, false, !no_watch).await
        }
        Commands::Dev { config } => {
            init_tracing("warn,shunt_cli=info,shunt_config=info");
            run_server(config, true, true).await
        }
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

fn build_registries() -> (
    Arc<PluginRegistry>,
    Arc<RuntimeRegistry>,
    Arc<PrometheusMetrics>,
    Arc<AiMetrics>,
) {
    let metrics = Arc::new(PrometheusMetrics::new());
    let ai_metrics = Arc::new(AiMetrics::new());
    let mut plugin_registry = PluginRegistry::new();
    register_builtin_plugins(&mut plugin_registry, Arc::clone(&metrics));
    register_ai_plugins(&mut plugin_registry, Arc::clone(&ai_metrics));
    let runtime_registry = Arc::new(RuntimeRegistry::new());
    (
        Arc::new(plugin_registry),
        runtime_registry,
        metrics,
        ai_metrics,
    )
}

fn run_check(config_path: PathBuf) -> ExitCode {
    let provider = FileConfigProvider::new(&config_path);
    let loaded = match provider.load() {
        Ok(l) => l,
        Err(err) => {
            eprintln!("error: {err}");
            return ExitCode::FAILURE;
        }
    };

    let (plugins, runtime, _metrics, _ai_metrics) = build_registries();
    let compiler = SnapshotCompiler::new(plugins, runtime);
    match compiler.compile(&loaded) {
        Ok(bundle) => {
            println!("Configuration valid: {}", config_path.display());
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
    config_path: PathBuf,
    policy_path: Option<PathBuf>,
    format: OutputFormat,
    strict: bool,
) -> ExitCode {
    let provider = FileConfigProvider::new(&config_path);
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

    let (plugins, runtime, _metrics, _ai_metrics) = build_registries();
    let compiler = SnapshotCompiler::new(plugins, runtime);
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
                    config_path.display()
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

async fn run_server(config_path: PathBuf, dev_mode: bool, watch_files: bool) -> ExitCode {
    let provider = Arc::new(FileConfigProvider::new(&config_path));
    let loaded = match provider.load() {
        Ok(l) => l,
        Err(err) => {
            eprintln!("error: {err}");
            return ExitCode::FAILURE;
        }
    };

    let (plugins, runtime, metrics, ai_metrics) = build_registries();
    let mut compiler = SnapshotCompiler::new(plugins, runtime);
    if dev_mode {
        compiler = compiler.with_extra_global_plugin(Arc::new(DevWaterfallPlugin::stderr()));
    }
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
        .with_trace_enabled(dev_mode);

    if let Some(certs) = bundle.cert_store {
        let resolver = Arc::new(DynamicCertResolver::new(certs));
        gw = gw.with_tls(TlsListenerConfig::new(resolver));
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
        let controller_metrics = Arc::clone(&controller);
        let admin = AdminServer::new(
            Arc::clone(&controller),
            Arc::new(move || {
                let mut out = metrics_clone.render_prometheus();
                let up_out = controller_metrics
                    .current_snapshot()
                    .render_upstream_health_prometheus();
                if !up_out.is_empty() {
                    if !out.is_empty() && !out.ends_with('\n') {
                        out.push('\n');
                    }
                    out.push_str(&up_out);
                }
                let ai_out = ai_metrics_clone.render_prometheus();
                if !ai_out.is_empty() {
                    if !out.is_empty() && !out.ends_with('\n') {
                        out.push('\n');
                    }
                    out.push_str(&ai_out);
                }
                out
            }),
        );
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

    let watcher_handle = if watch_files {
        let mut files = vec![config_path.clone()];
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

    if dev_mode {
        eprintln!(
            "shunt dev listening on {} (admin: {})",
            server_handle.local_addr(),
            admin_handle
                .as_ref()
                .map(|a| a.local_addr().to_string())
                .unwrap_or_else(|| "disabled".to_owned())
        );
        print_snapshot_table(&bundle.inspect);
        eprintln!("Watching {} for live reloads...\n", config_path.display());
    } else {
        info!(
            listen = %server_handle.local_addr(),
            admin = %admin_handle
                .as_ref()
                .map(|a| a.local_addr().to_string())
                .unwrap_or_else(|| "disabled".to_owned()),
            version = bundle.inspect.version,
            digest = %bundle.inspect.digest,
            "shunt gateway ready"
        );
    }

    wait_for_signals(Arc::clone(&controller)).await;

    info!("shutdown signal received; draining in-flight connections");
    if let Some(watcher) = watcher_handle {
        watcher.stop();
    }
    if let Some(admin) = admin_handle {
        admin.shutdown().await;
    }
    let clean = server_handle.shutdown().await;
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
        "Snapshot v{} (digest: {}, state: {})",
        inspect.version,
        &inspect.digest[..inspect.digest.len().min(12)],
        inspect.state_backend
    );

    if !inspect.global_plugins.is_empty() {
        println!("\nGlobal Plugins:");
        for p in &inspect.global_plugins {
            println!("  - {:<18} mask=[{}]", p.name, p.hook_mask);
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
        println!(
            "  - {:<16} [{} {} {}] -> {} (attempts={}, plugins=[{}])",
            r.id, methods, hosts, r.path, r.upstream, r.max_attempts, plugins
        );
        println!("    HookMask: {}", r.hook_mask);
    }
}
