use std::path::PathBuf;

use thiserror::Error;

/// Configuration loading, validation, compilation, and admin errors.
#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("failed to read config `{path}`: {source}")]
    ReadFile {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("TOML parse error in `{source_name}`: {source}")]
    TomlParse {
        source_name: String,
        #[source]
        source: toml::de::Error,
    },

    #[error("YAML parse error in `{source_name}`: {source}")]
    YamlParse {
        source_name: String,
        #[source]
        source: serde_yaml::Error,
    },

    #[error("configuration validation failed:\n{}", .0.join("\n"))]
    Validation(Vec<String>),

    #[error("plugin compilation error for `{scope}` ({plugin}): {source}")]
    PluginBuild {
        scope: String,
        plugin: String,
        #[source]
        source: shunt_plugin_sdk::PluginBuildError,
    },

    #[error("TLS certificate error: {0}")]
    Tls(String),

    #[error("core snapshot compilation error: {0}")]
    Core(#[from] shunt_core::CoreError),

    #[error("file watcher error: {0}")]
    Watcher(String),

    #[error("admin server error: {0}")]
    Admin(String),

    #[error("Kubernetes Gateway API error: {0}")]
    K8s(String),
}
