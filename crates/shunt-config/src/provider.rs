use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

use crate::error::ConfigError;
use crate::ir::GatewayConfig;

/// Loaded, parsed configuration with its content digest.
#[derive(Debug, Clone)]
pub struct LoadedConfig {
    pub source_name: String,
    pub config: GatewayConfig,
    pub digest: String,
}

/// Pluggable configuration source abstraction (file in v1; remote API / K8s CRD in v2+).
pub trait ConfigProvider: Send + Sync {
    fn source_name(&self) -> String;
    fn load(&self) -> Result<LoadedConfig, ConfigError>;
}

/// File-based [`ConfigProvider`] supporting `shunt.toml` and optional YAML (`.yaml`/`.yml`).
#[derive(Debug, Clone)]
pub struct FileConfigProvider {
    path: PathBuf,
}

impl FileConfigProvider {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl ConfigProvider for FileConfigProvider {
    fn source_name(&self) -> String {
        self.path.display().to_string()
    }

    fn load(&self) -> Result<LoadedConfig, ConfigError> {
        let raw = std::fs::read_to_string(&self.path).map_err(|source| ConfigError::ReadFile {
            path: self.path.clone(),
            source,
        })?;
        let digest = sha256_hex(raw.as_bytes());
        let source_name = self.source_name();

        let is_yaml = matches!(
            self.path.extension().and_then(|e| e.to_str()),
            Some("yaml" | "yml" | "YAML" | "YML")
        );

        let mut config: GatewayConfig = if is_yaml {
            serde_yaml::from_str(&raw).map_err(|source| ConfigError::YamlParse {
                source_name: source_name.clone(),
                source,
            })?
        } else {
            toml::from_str(&raw).map_err(|source| ConfigError::TomlParse {
                source_name: source_name.clone(),
                source,
            })?
        };

        if let Some(parent) = self.path.parent()
            && !parent.as_os_str().is_empty()
        {
            config.resolve_relative_paths(parent);
        }

        Ok(LoadedConfig {
            source_name,
            config,
            digest,
        })
    }
}

/// In-memory TOML/YAML provider useful for tests and embedded usage.
#[derive(Debug, Clone)]
pub struct InlineConfigProvider {
    source_name: String,
    toml_source: String,
}

impl InlineConfigProvider {
    pub fn from_toml(source_name: impl Into<String>, toml_source: impl Into<String>) -> Self {
        Self {
            source_name: source_name.into(),
            toml_source: toml_source.into(),
        }
    }
}

impl ConfigProvider for InlineConfigProvider {
    fn source_name(&self) -> String {
        self.source_name.clone()
    }

    fn load(&self) -> Result<LoadedConfig, ConfigError> {
        let config: GatewayConfig =
            toml::from_str(&self.toml_source).map_err(|source| ConfigError::TomlParse {
                source_name: self.source_name.clone(),
                source,
            })?;
        Ok(LoadedConfig {
            source_name: self.source_name.clone(),
            config,
            digest: sha256_hex(self.toml_source.as_bytes()),
        })
    }
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    let digest = hasher.finalize();
    let mut hex = String::with_capacity(digest.len() * 2);
    for byte in digest {
        use std::fmt::Write as _;
        let _ = write!(hex, "{byte:02x}");
    }
    hex
}
