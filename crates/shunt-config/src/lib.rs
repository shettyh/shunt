//! Configuration IR, `shunt.toml` / YAML loader, file watcher, `SnapshotCompiler`,
//! and read-only Admin API for Shunt.

pub mod admin;
pub mod compiler;
pub mod error;
pub mod ir;
pub mod provider;
pub mod reloader;

pub use admin::{AdminHandle, AdminServer, MetricsRenderer};
pub use compiler::{
    CompiledBundle, PluginInspect, RouteInspect, SnapshotCompiler, SnapshotInspect, UpstreamInspect,
};
pub use error::ConfigError;
pub use ir::{
    AdminConfig, GatewayConfig, PluginAttachment, RouteIr, ServerConfig, ServerTlsConfig,
    SniCertConfig, UpstreamIr, UpstreamTlsIr, redact_secrets,
};
pub use provider::{ConfigProvider, FileConfigProvider, InlineConfigProvider, LoadedConfig};
pub use reloader::{ConfigWatcherHandle, ReloadController, start_file_watcher};
