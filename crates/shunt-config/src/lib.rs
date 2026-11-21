//! Configuration IR, `shunt.toml` / YAML loader, file watcher, `SnapshotCompiler`,
//! and read-only Admin API for Shunt.

pub mod admin;
pub mod compiler;
pub mod error;
pub mod ir;
pub mod provider;
pub mod reloader;
pub mod verify;

pub use admin::{AdminHandle, AdminServer, MetricsRenderer};
pub use compiler::{
    CompiledBundle, PluginInspect, RouteInspect, SnapshotCompiler, SnapshotInspect, UpstreamInspect,
};
pub use error::ConfigError;
pub use ir::{
    ActiveHealthCheckIr, ActiveProbeKindIr, AdminConfig, GatewayConfig, PluginAttachment, RouteIr,
    ServerConfig, ServerTlsConfig, SniCertConfig, StateBackendKind, StateConfig,
    TelemetryBackendKind, TelemetryConfig, UpstreamEndpointIr, UpstreamIr, UpstreamTlsIr,
    redact_secrets,
};
pub use provider::{ConfigProvider, FileConfigProvider, InlineConfigProvider, LoadedConfig};
pub use reloader::{ConfigWatcherHandle, ReloadController, start_file_watcher};
pub use verify::{
    RoutePolicy, Severity, VerifyDiagnostic, VerifyPolicy, VerifyReport, load_policy_file,
    route_subsumes, verify_bundle,
};
