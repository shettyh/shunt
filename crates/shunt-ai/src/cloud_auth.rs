//! Pure-Rust dynamic cloud IAM authentication (`aws_iam`, `gcp_iam`, `azure_ad`)
//! built strictly on `shunt-plugin-sdk`'s [`HttpClient`], [`Clock`], and
//! [`shunt_plugin_sdk::StateStore`].
//!
//! Zero external cloud SDK dependencies:
//! - **AWS IAM:** EC2 IMDSv2, ECS Task Role, EKS IRSA (`AssumeRoleWithWebIdentity`),
//!   environment credentials, and STS `AssumeRole` chaining (signed with `aws_sigv4`).
//! - **GCP IAM:** GCE/GKE Metadata Server / Workload Identity, Service Account RS256 JWT
//!   OAuth2 exchange (using `ring`, already in the workspace via `rustls`), and ADC
//!   `authorized_user` refresh tokens.
//! - **Azure Entra ID:** Managed Identity (IMDS), Service Principal `client_credentials`,
//!   and AKS Workload Identity (`federated_token_file`).

use std::collections::HashMap;
use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex, RwLock};
use std::task::{Context, Poll, Waker};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use ring::rand::SystemRandom;
use ring::signature::{RSA_PKCS1_SHA256, RsaKeyPair};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use shunt_plugin_sdk::{Clock, HeaderName, HeaderValue, HttpClient, HttpRequest, Uri, header};
use tracing::warn;

use crate::aws_sigv4::{
    AwsSigV4Credentials, format_amz_timestamps, host_header_from_endpoint, sign_canonical,
};
use crate::types::{is_rfc3986_unreserved, percent_encode_path_segment, resolve_env_secret};

const DEFAULT_REFRESH_MARGIN_SECS: u64 = 300;
const DEFAULT_CLOUD_AUTH_TIMEOUT_MS: u64 = 5_000;
const DEFAULT_MAX_TOKEN_RESPONSE_BYTES: usize = 512 * 1024; // 512 KiB
const DEFAULT_AWS_IMDS_ENDPOINT: &str = "http://169.254.169.254";
const DEFAULT_AWS_ECS_HOST: &str = "http://169.254.170.2";
const DEFAULT_AWS_SESSION_NAME: &str = "shunt-gateway";
const DEFAULT_AWS_ENV_TTL_SECS: u64 = 3_600;
const DEFAULT_GCP_METADATA_ENDPOINT: &str = "http://metadata.google.internal";
const DEFAULT_GCP_TOKEN_URI: &str = "https://oauth2.googleapis.com/token";
const DEFAULT_GCP_SCOPE: &str = "https://www.googleapis.com/auth/cloud-platform";
const DEFAULT_AZURE_SCOPE: &str = "https://cognitiveservices.azure.com/.default";
const DEFAULT_AZURE_AUTHORITY_HOST: &str = "https://login.microsoftonline.com";
const DEFAULT_AZURE_IMDS_ENDPOINT: &str = "http://169.254.169.254";

fn default_refresh_margin_secs() -> u64 {
    DEFAULT_REFRESH_MARGIN_SECS
}

fn default_timeout_ms() -> u64 {
    DEFAULT_CLOUD_AUTH_TIMEOUT_MS
}

fn default_azure_scope() -> String {
    DEFAULT_AZURE_SCOPE.to_owned()
}

/// AWS IAM credential discovery mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AwsIamMode {
    /// AWS default chain: env -> web_identity (EKS IRSA) -> ecs -> imds (+ optional AssumeRole).
    #[default]
    Auto,
    /// Static/temporary environment variables (`AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_SESSION_TOKEN`).
    Env,
    /// EC2 Instance Metadata Service v2 (`PUT /latest/api/token` + role credentials).
    Imds,
    /// ECS Task Role (`AWS_CONTAINER_CREDENTIALS_FULL_URI` or `AWS_CONTAINER_CREDENTIALS_RELATIVE_URI`).
    Ecs,
    /// EKS IRSA / OIDC Web Identity (`AssumeRoleWithWebIdentity` using `web_identity_token_file`).
    WebIdentity,
}

/// Configuration for `auth.type = "aws_iam"`.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AwsIamAuthConfig {
    #[serde(default)]
    pub mode: AwsIamMode,
    /// AWS SigV4 service name (default: `"bedrock"`).
    #[serde(default)]
    pub service: Option<String>,
    /// Optional IAM Role ARN for STS `AssumeRole` chaining or `AssumeRoleWithWebIdentity`.
    #[serde(default)]
    pub role_arn: Option<String>,
    /// STS session name (default: `"shunt-gateway"`).
    #[serde(default)]
    pub role_session_name: Option<String>,
    /// Optional STS `AssumeRole` `ExternalId`.
    #[serde(default)]
    pub external_id: Option<String>,
    /// Optional STS `DurationSeconds` (900..=43200).
    #[serde(default)]
    pub session_duration_secs: Option<u64>,
    /// Path to projected OIDC token file (defaults to `AWS_WEB_IDENTITY_TOKEN_FILE`).
    #[serde(default)]
    pub web_identity_token_file: Option<String>,
    /// EC2 IMDSv2 base URL (default: `"http://169.254.169.254"`).
    #[serde(default)]
    pub imds_endpoint: Option<String>,
    /// ECS Task Role credentials URI (defaults to ECS container env vars).
    #[serde(default)]
    pub ecs_credentials_uri: Option<String>,
    /// Optional ECS authorization header token (supports `env:VAR`).
    #[serde(default)]
    pub ecs_auth_token: Option<String>,
    /// STS endpoint base URL (default: `"https://sts.{region}.amazonaws.com"`).
    #[serde(default)]
    pub sts_endpoint: Option<String>,
    /// Proactive refresh margin before expiry in seconds (default: `300`).
    #[serde(default = "default_refresh_margin_secs")]
    pub refresh_margin_secs: u64,
    /// Optional upper cap on credential cache TTL in seconds.
    #[serde(default)]
    pub max_cache_ttl_secs: Option<u64>,
    /// Outbound HTTP timeout per credential exchange call in ms (default: `5000`).
    #[serde(default = "default_timeout_ms")]
    pub timeout_ms: u64,
}

/// GCP IAM credential discovery mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GcpIamMode {
    /// GCP ADC chain: `credentials_json` -> `credentials_file`/`GOOGLE_APPLICATION_CREDENTIALS` -> metadata server.
    #[default]
    Auto,
    /// GCE / GKE Metadata Server & Workload Identity (`Metadata-Flavor: Google`).
    Metadata,
    /// Service Account JSON key using RS256 JWT assertion exchange.
    ServiceAccount,
    /// Application Default Credentials `authorized_user` OAuth2 refresh token.
    AuthorizedUser,
}

/// Configuration for `auth.type = "gcp_iam"`.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GcpIamAuthConfig {
    #[serde(default)]
    pub mode: GcpIamMode,
    /// Path to Service Account or ADC JSON file (supports `env:VAR`; defaults to `GOOGLE_APPLICATION_CREDENTIALS`).
    #[serde(default)]
    pub credentials_file: Option<String>,
    /// Inline or `env:VAR` JSON credentials payload (auto-redacted in `/snapshot`).
    #[serde(default)]
    pub credentials_json: Option<String>,
    /// OAuth2 scopes (default: `["https://www.googleapis.com/auth/cloud-platform"]`).
    #[serde(default)]
    pub scopes: Vec<String>,
    /// Metadata server base URL (default: `"http://metadata.google.internal"`).
    #[serde(default)]
    pub metadata_endpoint: Option<String>,
    /// Optional OAuth2 token endpoint override (default: JSON `token_uri` or `"https://oauth2.googleapis.com/token"`).
    #[serde(default)]
    pub token_uri: Option<String>,
    /// Metadata server service account email/alias (default: `"default"`).
    #[serde(default)]
    pub service_account_email: Option<String>,
    /// Proactive refresh margin before expiry in seconds (default: `300`).
    #[serde(default = "default_refresh_margin_secs")]
    pub refresh_margin_secs: u64,
    /// Optional upper cap on credential cache TTL in seconds.
    #[serde(default)]
    pub max_cache_ttl_secs: Option<u64>,
    /// Outbound HTTP timeout per token exchange call in ms (default: `5000`).
    #[serde(default = "default_timeout_ms")]
    pub timeout_ms: u64,
}

/// Azure Entra ID credential discovery mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AzureAdMode {
    /// Azure chain: workload_identity -> client_credentials -> managed_identity (IMDS).
    #[default]
    Auto,
    /// Azure Managed Identity via IMDS (`Metadata: true`).
    ManagedIdentity,
    /// Service Principal OAuth2 `client_credentials` flow.
    ClientCredentials,
    /// AKS Workload Identity federated OIDC token file flow.
    WorkloadIdentity,
}

/// Configuration for `auth.type = "azure_ad"`.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AzureAdAuthConfig {
    #[serde(default)]
    pub mode: AzureAdMode,
    /// Azure Entra ID tenant ID (supports `env:VAR`; falls back to `AZURE_TENANT_ID`).
    #[serde(default)]
    pub tenant_id: Option<String>,
    /// Application / Managed Identity client ID (supports `env:VAR`; falls back to `AZURE_CLIENT_ID`).
    #[serde(default)]
    pub client_id: Option<String>,
    /// Service Principal client secret (supports `env:VAR`; falls back to `AZURE_CLIENT_SECRET`; auto-redacted).
    #[serde(default)]
    pub client_secret: Option<String>,
    /// Path to projected OIDC token file (supports `env:VAR`; falls back to `AZURE_FEDERATED_TOKEN_FILE`).
    #[serde(default)]
    pub federated_token_file: Option<String>,
    /// Entra ID OAuth2 scope (default: `"https://cognitiveservices.azure.com/.default"`).
    #[serde(default = "default_azure_scope")]
    pub scope: String,
    /// IMDS Managed Identity resource URI (defaults to `scope` with `/.default` stripped).
    #[serde(default)]
    pub resource: Option<String>,
    /// Entra ID authority host (default: `"https://login.microsoftonline.com"`).
    #[serde(default)]
    pub authority_host: Option<String>,
    /// Azure IMDS base URL (default: `"http://169.254.169.254"`).
    #[serde(default)]
    pub imds_endpoint: Option<String>,
    /// Proactive refresh margin before expiry in seconds (default: `300`).
    #[serde(default = "default_refresh_margin_secs")]
    pub refresh_margin_secs: u64,
    /// Optional upper cap on credential cache TTL in seconds.
    #[serde(default)]
    pub max_cache_ttl_secs: Option<u64>,
    /// Outbound HTTP timeout per token exchange call in ms (default: `5000`).
    #[serde(default = "default_timeout_ms")]
    pub timeout_ms: u64,
}

/// Resolved dynamic credential stored in [`CloudTokenCache`].
#[derive(Clone)]
pub enum ResolvedCloudCredential {
    /// AWS temporary or session SigV4 credentials.
    AwsSigV4(AwsSigV4Credentials),
    /// OAuth2 / IAM Bearer access token (GCP Vertex AI, Azure Entra ID).
    BearerToken(String),
}

impl fmt::Debug for ResolvedCloudCredential {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AwsSigV4(c) => f
                .debug_struct("ResolvedCloudCredential::AwsSigV4")
                .field("region", &c.region)
                .field("service", &c.service)
                .field("has_session_token", &c.session_token.is_some())
                .finish(),
            Self::BearerToken(_) => f.write_str("ResolvedCloudCredential::BearerToken([REDACTED])"),
        }
    }
}

/// Non-secret observability snapshot of a cached cloud IAM token entry (for `/api/status`).
#[derive(Debug, Clone, Serialize)]
pub struct CloudTokenSnapshot {
    pub provider: String,
    pub auth_kind: String,
    pub cached: bool,
    pub expires_in_ms: u64,
    pub refresh_count: u64,
    pub error_count: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_error: Option<String>,
}

/// Compiled dynamic cloud IAM configuration attached to a provider instance.
#[derive(Clone)]
pub struct CompiledCloudAuth {
    pub provider_name: String,
    pub cache_key: String,
    pub refresh_margin: Duration,
    pub max_cache_ttl: Option<Duration>,
    pub timeout: Duration,
    pub kind: CompiledCloudAuthKind,
}

impl fmt::Debug for CompiledCloudAuth {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CompiledCloudAuth")
            .field("provider_name", &self.provider_name)
            .field("auth_kind", &self.auth_kind_label())
            .field("refresh_margin", &self.refresh_margin)
            .field("timeout", &self.timeout)
            .finish()
    }
}

impl CompiledCloudAuth {
    pub fn auth_kind_label(&self) -> &'static str {
        match &self.kind {
            CompiledCloudAuthKind::AwsIam(_) => "aws_iam",
            CompiledCloudAuthKind::GcpIam(_) => "gcp_iam",
            CompiledCloudAuthKind::AzureAd(_) => "azure_ad",
        }
    }

    pub fn is_aws_sigv4(&self) -> bool {
        matches!(self.kind, CompiledCloudAuthKind::AwsIam(_))
    }

    pub fn compile_aws(
        provider_name: &str,
        region: String,
        cfg: AwsIamAuthConfig,
    ) -> Result<Self, String> {
        let service = cfg
            .service
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .unwrap_or("bedrock")
            .to_owned();
        let role_arn = resolve_optional_env(cfg.role_arn.as_deref(), "role_arn")?;
        let role_session_name = cfg
            .role_session_name
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .unwrap_or(DEFAULT_AWS_SESSION_NAME)
            .to_owned();
        let external_id = resolve_optional_env(cfg.external_id.as_deref(), "external_id")?;
        let web_identity_token_file = resolve_optional_env(
            cfg.web_identity_token_file.as_deref(),
            "web_identity_token_file",
        )?;
        let imds_endpoint = cfg
            .imds_endpoint
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .unwrap_or(DEFAULT_AWS_IMDS_ENDPOINT)
            .trim_end_matches('/')
            .to_owned();
        validate_http_base_url(&imds_endpoint, "imds_endpoint")?;

        let ecs_credentials_uri =
            resolve_optional_env(cfg.ecs_credentials_uri.as_deref(), "ecs_credentials_uri")?;
        if let Some(ref uri) = ecs_credentials_uri {
            validate_http_base_url(uri, "ecs_credentials_uri")?;
        }
        let ecs_auth_token = resolve_optional_env(cfg.ecs_auth_token.as_deref(), "ecs_auth_token")?;

        let sts_endpoint = cfg
            .sts_endpoint
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(|s| s.trim_end_matches('/').to_owned())
            .unwrap_or_else(|| format!("https://sts.{region}.amazonaws.com"));
        validate_http_base_url(&sts_endpoint, "sts_endpoint")?;

        if let Some(dur) = cfg.session_duration_secs
            && !(900..=43_200).contains(&dur)
        {
            return Err("`session_duration_secs` must be between 900 and 43200".to_owned());
        }

        let compiled = CompiledAwsIam {
            mode: cfg.mode,
            region,
            service,
            role_arn,
            role_session_name,
            external_id,
            session_duration_secs: cfg.session_duration_secs,
            web_identity_token_file,
            imds_endpoint,
            ecs_credentials_uri,
            ecs_auth_token,
            sts_endpoint,
        };

        let fingerprint = fingerprint_parts(&[
            "aws_iam",
            provider_name,
            &format!("{:?}", compiled.mode),
            &compiled.region,
            &compiled.service,
            compiled.role_arn.as_deref().unwrap_or(""),
            &compiled.role_session_name,
            compiled.external_id.as_deref().unwrap_or(""),
            compiled.web_identity_token_file.as_deref().unwrap_or(""),
            &compiled.imds_endpoint,
            compiled.ecs_credentials_uri.as_deref().unwrap_or(""),
            &compiled.sts_endpoint,
            &cfg.max_cache_ttl_secs.unwrap_or(0).to_string(),
        ]);

        Ok(Self {
            provider_name: provider_name.to_owned(),
            cache_key: format!("{provider_name}::{fingerprint}"),
            refresh_margin: Duration::from_secs(cfg.refresh_margin_secs),
            max_cache_ttl: cfg
                .max_cache_ttl_secs
                .map(|s| Duration::from_secs(s.max(1))),
            timeout: Duration::from_millis(cfg.timeout_ms.max(100)),
            kind: CompiledCloudAuthKind::AwsIam(compiled),
        })
    }

    pub fn compile_gcp(provider_name: &str, cfg: GcpIamAuthConfig) -> Result<Self, String> {
        let credentials_file =
            resolve_optional_env(cfg.credentials_file.as_deref(), "credentials_file")?;
        let credentials_json =
            resolve_optional_env(cfg.credentials_json.as_deref(), "credentials_json")?;
        if let Some(ref raw_json) = credentials_json {
            // Fail fast at config compile time if inline credentials JSON is malformed.
            let _: Value = serde_json::from_str(raw_json)
                .map_err(|e| format!("invalid `credentials_json`: {e}"))?;
        }

        let scopes = if cfg.scopes.is_empty() {
            vec![DEFAULT_GCP_SCOPE.to_owned()]
        } else {
            cfg.scopes
        };
        let metadata_endpoint = cfg
            .metadata_endpoint
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .unwrap_or(DEFAULT_GCP_METADATA_ENDPOINT)
            .trim_end_matches('/')
            .to_owned();
        validate_http_base_url(&metadata_endpoint, "metadata_endpoint")?;

        let token_uri = cfg
            .token_uri
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_owned);
        if let Some(ref uri) = token_uri {
            validate_http_base_url(uri, "token_uri")?;
        }

        let service_account_email = cfg
            .service_account_email
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .unwrap_or("default")
            .to_owned();

        let compiled = CompiledGcpIam {
            mode: cfg.mode,
            credentials_file,
            credentials_json,
            scopes,
            metadata_endpoint,
            token_uri,
            service_account_email,
        };

        let scopes_joined = compiled.scopes.join(" ");
        let cred_json_hash = compiled
            .credentials_json
            .as_deref()
            .map(|s| fingerprint_parts(&[s]))
            .unwrap_or_default();
        let fingerprint = fingerprint_parts(&[
            "gcp_iam",
            provider_name,
            &format!("{:?}", compiled.mode),
            compiled.credentials_file.as_deref().unwrap_or(""),
            &cred_json_hash,
            &scopes_joined,
            &compiled.metadata_endpoint,
            compiled.token_uri.as_deref().unwrap_or(""),
            &compiled.service_account_email,
            &cfg.max_cache_ttl_secs.unwrap_or(0).to_string(),
        ]);

        Ok(Self {
            provider_name: provider_name.to_owned(),
            cache_key: format!("{provider_name}::{fingerprint}"),
            refresh_margin: Duration::from_secs(cfg.refresh_margin_secs),
            max_cache_ttl: cfg
                .max_cache_ttl_secs
                .map(|s| Duration::from_secs(s.max(1))),
            timeout: Duration::from_millis(cfg.timeout_ms.max(100)),
            kind: CompiledCloudAuthKind::GcpIam(compiled),
        })
    }

    pub fn compile_azure(provider_name: &str, cfg: AzureAdAuthConfig) -> Result<Self, String> {
        let tenant_id = resolve_optional_env(cfg.tenant_id.as_deref(), "tenant_id")?;
        let client_id = resolve_optional_env(cfg.client_id.as_deref(), "client_id")?;
        let client_secret = resolve_optional_env(cfg.client_secret.as_deref(), "client_secret")?;
        let federated_token_file =
            resolve_optional_env(cfg.federated_token_file.as_deref(), "federated_token_file")?;

        let scope = cfg.scope.trim().to_owned();
        if scope.is_empty() {
            return Err("`scope` cannot be empty".to_owned());
        }
        let resource = cfg
            .resource
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_owned)
            .unwrap_or_else(|| {
                scope
                    .strip_suffix("/.default")
                    .unwrap_or(&scope)
                    .trim_end_matches('/')
                    .to_owned()
            });

        let authority_host = cfg
            .authority_host
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .unwrap_or(DEFAULT_AZURE_AUTHORITY_HOST)
            .trim_end_matches('/')
            .to_owned();
        validate_http_base_url(&authority_host, "authority_host")?;

        let imds_endpoint = cfg
            .imds_endpoint
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .unwrap_or(DEFAULT_AZURE_IMDS_ENDPOINT)
            .trim_end_matches('/')
            .to_owned();
        validate_http_base_url(&imds_endpoint, "imds_endpoint")?;

        let compiled = CompiledAzureAd {
            mode: cfg.mode,
            tenant_id,
            client_id,
            client_secret,
            federated_token_file,
            scope,
            resource,
            authority_host,
            imds_endpoint,
        };

        let secret_hash = compiled
            .client_secret
            .as_deref()
            .map(|s| fingerprint_parts(&[s]))
            .unwrap_or_default();
        let fingerprint = fingerprint_parts(&[
            "azure_ad",
            provider_name,
            &format!("{:?}", compiled.mode),
            compiled.tenant_id.as_deref().unwrap_or(""),
            compiled.client_id.as_deref().unwrap_or(""),
            &secret_hash,
            compiled.federated_token_file.as_deref().unwrap_or(""),
            &compiled.scope,
            &compiled.resource,
            &compiled.authority_host,
            &compiled.imds_endpoint,
            &cfg.max_cache_ttl_secs.unwrap_or(0).to_string(),
        ]);

        Ok(Self {
            provider_name: provider_name.to_owned(),
            cache_key: format!("{provider_name}::{fingerprint}"),
            refresh_margin: Duration::from_secs(cfg.refresh_margin_secs),
            max_cache_ttl: cfg
                .max_cache_ttl_secs
                .map(|s| Duration::from_secs(s.max(1))),
            timeout: Duration::from_millis(cfg.timeout_ms.max(100)),
            kind: CompiledCloudAuthKind::AzureAd(compiled),
        })
    }
}

#[derive(Clone)]
pub enum CompiledCloudAuthKind {
    AwsIam(CompiledAwsIam),
    GcpIam(CompiledGcpIam),
    AzureAd(CompiledAzureAd),
}

#[derive(Clone)]
pub struct CompiledAwsIam {
    pub mode: AwsIamMode,
    pub region: String,
    pub service: String,
    pub role_arn: Option<String>,
    pub role_session_name: String,
    pub external_id: Option<String>,
    pub session_duration_secs: Option<u64>,
    pub web_identity_token_file: Option<String>,
    pub imds_endpoint: String,
    pub ecs_credentials_uri: Option<String>,
    pub ecs_auth_token: Option<String>,
    pub sts_endpoint: String,
}

#[derive(Clone)]
pub struct CompiledGcpIam {
    pub mode: GcpIamMode,
    pub credentials_file: Option<String>,
    pub credentials_json: Option<String>,
    pub scopes: Vec<String>,
    pub metadata_endpoint: String,
    pub token_uri: Option<String>,
    pub service_account_email: String,
}

#[derive(Clone)]
pub struct CompiledAzureAd {
    pub mode: AzureAdMode,
    pub tenant_id: Option<String>,
    pub client_id: Option<String>,
    pub client_secret: Option<String>,
    pub federated_token_file: Option<String>,
    pub scope: String,
    pub resource: String,
    pub authority_host: String,
    pub imds_endpoint: String,
}

fn resolve_optional_env(raw: Option<&str>, field: &str) -> Result<Option<String>, String> {
    let Some(s) = raw.map(str::trim).filter(|s| !s.is_empty()) else {
        return Ok(None);
    };
    let val = resolve_env_secret(s).map_err(|e| format!("`{field}`: {e}"))?;
    let trimmed = val.trim();
    if trimmed.is_empty() {
        return Err(format!("`{field}` resolved to an empty value"));
    }
    Ok(Some(trimmed.to_owned()))
}

fn validate_http_base_url(url: &str, field: &str) -> Result<(), String> {
    let uri: Uri = url
        .parse()
        .map_err(|e| format!("invalid `{field}` URI `{url}`: {e}"))?;
    let scheme = uri.scheme_str().unwrap_or("");
    if (scheme != "http" && scheme != "https") || uri.authority().is_none() {
        return Err(format!(
            "`{field}` (`{url}`) must be a valid http:// or https:// URL"
        ));
    }
    Ok(())
}

fn fingerprint_parts(parts: &[&str]) -> String {
    let mut hasher = Sha256::new();
    for p in parts {
        hasher.update((p.len() as u64).to_be_bytes());
        hasher.update(p.as_bytes());
    }
    let digest = hasher.finalize();
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(16);
    for &b in &digest[..8] {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0F) as usize] as char);
    }
    out
}

// ---------------------------------------------------------------------------
// Cancellation-safe zero-dependency SingleflightGate & Reload-Persistent Cache
// ---------------------------------------------------------------------------

#[derive(Default)]
struct GateState {
    locked: bool,
    waiters: Vec<Waker>,
}

/// Zero-dependency, cancellation-safe async mutex for per-key token refresh coalescing.
#[derive(Default)]
struct SingleflightGate {
    state: Mutex<GateState>,
}

impl SingleflightGate {
    fn acquire(&self) -> AcquireGate<'_> {
        AcquireGate { gate: self }
    }
}

struct AcquireGate<'a> {
    gate: &'a SingleflightGate,
}

impl<'a> Future for AcquireGate<'a> {
    type Output = GatePermit<'a>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let mut guard = self
            .gate
            .state
            .lock()
            .expect("SingleflightGate lock poisoned");
        if !guard.locked {
            guard.locked = true;
            return Poll::Ready(GatePermit { gate: self.gate });
        }
        if !guard.waiters.iter().any(|w| w.will_wake(cx.waker())) {
            guard.waiters.push(cx.waker().clone());
        }
        Poll::Pending
    }
}

struct GatePermit<'a> {
    gate: &'a SingleflightGate,
}

impl Drop for GatePermit<'_> {
    fn drop(&mut self) {
        let waiters = {
            let mut guard = self
                .gate
                .state
                .lock()
                .expect("SingleflightGate lock poisoned");
            guard.locked = false;
            std::mem::take(&mut guard.waiters)
        };
        for w in waiters {
            w.wake();
        }
    }
}

#[derive(Clone)]
struct CachedTokenEntry {
    provider: String,
    auth_kind: String,
    credential: Option<ResolvedCloudCredential>,
    refresh_at: Duration,
    hard_expires_at: Duration,
    refresh_count: u64,
    error_count: u64,
    last_error: Option<String>,
}

/// Outcome of a synchronous cache probe.
#[derive(Debug, Clone)]
pub enum CacheLookup {
    /// Fresh token ready for synchronous zero-allocation injection.
    Fresh(ResolvedCloudCredential),
    /// Token is within proactive refresh window (still valid if refresh fails transiently).
    StaleWhileValid(ResolvedCloudCredential),
    /// Cache miss or token has passed hard expiry.
    ExpiredOrMiss,
}

/// Computes `(refresh_at, hard_expires_at)` for a token fetched at `now` with `ttl` and
/// configured proactive `refresh_margin`.
///
/// The effective margin is clamped to `ttl / 2` so short-TTL tokens (e.g., 60s test tokens)
/// still cache cleanly for at least half their lifetime before triggering proactive refresh.
pub fn compute_token_deadlines(
    now: Duration,
    ttl: Duration,
    configured_margin: Duration,
    max_cache_ttl: Option<Duration>,
) -> (Duration, Duration) {
    let bounded_ttl = match max_cache_ttl {
        Some(cap) => ttl.min(cap),
        None => ttl,
    }
    .max(Duration::from_secs(1));
    let effective_margin = configured_margin.min(bounded_ttl / 2);
    let refresh_after = bounded_ttl.saturating_sub(effective_margin);
    (
        now.saturating_add(refresh_after),
        now.saturating_add(bounded_ttl),
    )
}

/// Reload-persistent, `Clock`-driven dynamic cloud credential cache stored in `StateStore`.
#[derive(Default)]
pub struct CloudTokenCache {
    entries: RwLock<HashMap<String, CachedTokenEntry>>,
    gates: Mutex<HashMap<String, Arc<SingleflightGate>>>,
}

impl fmt::Debug for CloudTokenCache {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let len = self
            .entries
            .read()
            .expect("CloudTokenCache lock poisoned")
            .len();
        f.debug_struct("CloudTokenCache")
            .field("entries", &len)
            .finish()
    }
}

impl CloudTokenCache {
    /// Synchronous fast-path cache lookup (zero heap allocation when fresh).
    pub fn lookup(&self, cache_key: &str, now: Duration) -> CacheLookup {
        let guard = self.entries.read().expect("CloudTokenCache lock poisoned");
        let Some(entry) = guard.get(cache_key) else {
            return CacheLookup::ExpiredOrMiss;
        };
        let Some(cred) = &entry.credential else {
            return CacheLookup::ExpiredOrMiss;
        };
        if now < entry.refresh_at {
            CacheLookup::Fresh(cred.clone())
        } else if now < entry.hard_expires_at {
            CacheLookup::StaleWhileValid(cred.clone())
        } else {
            CacheLookup::ExpiredOrMiss
        }
    }

    /// Invalidates a cached credential (e.g., after an upstream `401`/`403` token rejection).
    pub fn invalidate(&self, cache_key: &str) {
        let mut guard = self.entries.write().expect("CloudTokenCache lock poisoned");
        if let Some(entry) = guard.get_mut(cache_key) {
            entry.credential = None;
            entry.refresh_at = Duration::ZERO;
            entry.hard_expires_at = Duration::ZERO;
        }
    }

    /// Stores a newly refreshed credential in the cache.
    pub fn store_success(
        &self,
        auth: &CompiledCloudAuth,
        cred: ResolvedCloudCredential,
        ttl: Duration,
        now: Duration,
    ) {
        let (refresh_at, hard_expires_at) =
            compute_token_deadlines(now, ttl, auth.refresh_margin, auth.max_cache_ttl);
        let mut guard = self.entries.write().expect("CloudTokenCache lock poisoned");
        let entry = guard
            .entry(auth.cache_key.clone())
            .or_insert_with(|| CachedTokenEntry {
                provider: auth.provider_name.clone(),
                auth_kind: auth.auth_kind_label().to_owned(),
                credential: None,
                refresh_at: Duration::ZERO,
                hard_expires_at: Duration::ZERO,
                refresh_count: 0,
                error_count: 0,
                last_error: None,
            });
        entry.credential = Some(cred);
        entry.refresh_at = refresh_at;
        entry.hard_expires_at = hard_expires_at;
        entry.refresh_count = entry.refresh_count.saturating_add(1);
        entry.last_error = None;
    }

    /// Records a refresh failure while preserving any still-valid stale credential.
    pub fn record_error(&self, auth: &CompiledCloudAuth, err: &str) {
        let mut guard = self.entries.write().expect("CloudTokenCache lock poisoned");
        let entry = guard
            .entry(auth.cache_key.clone())
            .or_insert_with(|| CachedTokenEntry {
                provider: auth.provider_name.clone(),
                auth_kind: auth.auth_kind_label().to_owned(),
                credential: None,
                refresh_at: Duration::ZERO,
                hard_expires_at: Duration::ZERO,
                refresh_count: 0,
                error_count: 0,
                last_error: None,
            });
        entry.error_count = entry.error_count.saturating_add(1);
        entry.last_error = Some(err.to_owned());
    }

    fn gate_for(&self, cache_key: &str) -> Arc<SingleflightGate> {
        let mut guard = self.gates.lock().expect("CloudTokenCache gates poisoned");
        guard
            .entry(cache_key.to_owned())
            .or_insert_with(|| Arc::new(SingleflightGate::default()))
            .clone()
    }

    /// Resolves a valid credential for `auth`, coalescing concurrent refreshes via singleflight
    /// and falling back to a still-valid cached token on transient proactive refresh errors.
    pub async fn get_or_refresh(
        &self,
        auth: &CompiledCloudAuth,
        http_client: &dyn HttpClient,
        clock: &dyn Clock,
    ) -> Result<ResolvedCloudCredential, String> {
        let now = clock.now();
        if let CacheLookup::Fresh(cred) = self.lookup(&auth.cache_key, now) {
            return Ok(cred);
        }

        let gate = self.gate_for(&auth.cache_key);
        let _permit = gate.acquire().await;

        // Re-check cache after acquiring singleflight permit: a leader may have just refreshed.
        let now = clock.now();
        let stale_fallback = match self.lookup(&auth.cache_key, now) {
            CacheLookup::Fresh(cred) => return Ok(cred),
            CacheLookup::StaleWhileValid(cred) => Some(cred),
            CacheLookup::ExpiredOrMiss => None,
        };

        match fetch_cloud_credential(auth, http_client).await {
            Ok((cred, ttl)) => {
                let refreshed_at = clock.now();
                self.store_success(auth, cred.clone(), ttl, refreshed_at);
                Ok(cred)
            }
            Err(err) => {
                self.record_error(auth, &err);
                if let Some(fallback) = stale_fallback {
                    warn!(
                        provider = %auth.provider_name,
                        auth_kind = auth.auth_kind_label(),
                        error = %err,
                        "proactive cloud IAM token refresh failed; continuing with still-valid cached credential"
                    );
                    Ok(fallback)
                } else {
                    Err(err)
                }
            }
        }
    }

    /// Returns a deterministic, non-secret snapshot of all tracked cloud credentials.
    pub fn snapshot_entries(&self, now: Duration) -> Vec<CloudTokenSnapshot> {
        let guard = self.entries.read().expect("CloudTokenCache lock poisoned");
        let mut out: Vec<CloudTokenSnapshot> = guard
            .values()
            .map(|e| {
                let valid = e.credential.is_some() && now < e.hard_expires_at;
                let expires_in_ms = if valid {
                    e.hard_expires_at
                        .saturating_sub(now)
                        .as_millis()
                        .min(u64::MAX as u128) as u64
                } else {
                    0
                };
                CloudTokenSnapshot {
                    provider: e.provider.clone(),
                    auth_kind: e.auth_kind.clone(),
                    cached: valid,
                    expires_in_ms,
                    refresh_count: e.refresh_count,
                    error_count: e.error_count,
                    last_error: e.last_error.clone(),
                }
            })
            .collect();
        out.sort_by(|a, b| (&a.provider, &a.auth_kind).cmp(&(&b.provider, &b.auth_kind)));
        out
    }
}

// ---------------------------------------------------------------------------
// Cloud Credential Fetchers (AWS, GCP, Azure)
// ---------------------------------------------------------------------------

async fn fetch_cloud_credential(
    auth: &CompiledCloudAuth,
    http: &dyn HttpClient,
) -> Result<(ResolvedCloudCredential, Duration), String> {
    match &auth.kind {
        CompiledCloudAuthKind::AwsIam(cfg) => {
            let (creds, ttl) = fetch_aws_credentials(cfg, auth.timeout, http).await?;
            Ok((ResolvedCloudCredential::AwsSigV4(creds), ttl))
        }
        CompiledCloudAuthKind::GcpIam(cfg) => {
            let (token, ttl) = fetch_gcp_token(cfg, auth.timeout, http).await?;
            Ok((ResolvedCloudCredential::BearerToken(token), ttl))
        }
        CompiledCloudAuthKind::AzureAd(cfg) => {
            let (token, ttl) = fetch_azure_token(cfg, auth.timeout, http).await?;
            Ok((ResolvedCloudCredential::BearerToken(token), ttl))
        }
    }
}

/// Parsed temporary AWS credentials returned by IMDS, ECS, or STS.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AwsStsCredentials {
    pub access_key_id: String,
    pub secret_access_key: String,
    pub session_token: Option<String>,
    /// Parsed RFC 3339 expiration timestamp (Unix seconds), when provided.
    pub expiration_unix_secs: Option<u64>,
}

async fn fetch_aws_credentials(
    cfg: &CompiledAwsIam,
    timeout: Duration,
    http: &dyn HttpClient,
) -> Result<(AwsSigV4Credentials, Duration), String> {
    let (base, used_web_identity) = match cfg.mode {
        AwsIamMode::Env => (load_aws_env_credentials()?, false),
        AwsIamMode::WebIdentity => (fetch_aws_web_identity(cfg, timeout, http).await?, true),
        AwsIamMode::Ecs => (fetch_aws_ecs_credentials(cfg, timeout, http).await?, false),
        AwsIamMode::Imds => (fetch_aws_imds_credentials(cfg, timeout, http).await?, false),
        AwsIamMode::Auto => {
            if let Ok(env_creds) = load_aws_env_credentials() {
                (env_creds, false)
            } else if resolve_aws_web_identity_inputs(cfg).is_some() {
                (fetch_aws_web_identity(cfg, timeout, http).await?, true)
            } else if resolve_aws_ecs_uri(cfg).is_some() {
                (fetch_aws_ecs_credentials(cfg, timeout, http).await?, false)
            } else {
                (fetch_aws_imds_credentials(cfg, timeout, http).await?, false)
            }
        }
    };

    let final_raw = if !used_web_identity && let Some(ref role_arn) = cfg.role_arn {
        fetch_aws_sts_assume_role(cfg, &base, role_arn, timeout, http).await?
    } else {
        base
    };

    let ttl = match final_raw.expiration_unix_secs {
        Some(exp) => {
            let now_unix = current_unix_secs();
            Duration::from_secs(exp.saturating_sub(now_unix).max(1))
        }
        None => Duration::from_secs(
            cfg.session_duration_secs
                .unwrap_or(DEFAULT_AWS_ENV_TTL_SECS),
        ),
    };

    Ok((
        AwsSigV4Credentials {
            access_key_id: final_raw.access_key_id,
            secret_access_key: final_raw.secret_access_key,
            session_token: final_raw.session_token,
            region: cfg.region.clone(),
            service: cfg.service.clone(),
        },
        ttl,
    ))
}

fn load_aws_env_credentials() -> Result<AwsStsCredentials, String> {
    let access_key_id = std::env::var("AWS_ACCESS_KEY_ID")
        .ok()
        .filter(|s| !s.trim().is_empty())
        .ok_or_else(|| "AWS_ACCESS_KEY_ID is not set".to_owned())?;
    let secret_access_key = std::env::var("AWS_SECRET_ACCESS_KEY")
        .ok()
        .filter(|s| !s.trim().is_empty())
        .ok_or_else(|| "AWS_SECRET_ACCESS_KEY is not set".to_owned())?;
    let session_token = std::env::var("AWS_SESSION_TOKEN")
        .ok()
        .filter(|s| !s.trim().is_empty());
    Ok(AwsStsCredentials {
        access_key_id,
        secret_access_key,
        session_token,
        expiration_unix_secs: None,
    })
}

fn resolve_aws_web_identity_inputs(cfg: &CompiledAwsIam) -> Option<(String, String)> {
    let token_file = cfg.web_identity_token_file.clone().or_else(|| {
        std::env::var("AWS_WEB_IDENTITY_TOKEN_FILE")
            .ok()
            .filter(|s| !s.trim().is_empty())
    })?;
    let role_arn = cfg.role_arn.clone().or_else(|| {
        std::env::var("AWS_ROLE_ARN")
            .ok()
            .filter(|s| !s.trim().is_empty())
    })?;
    Some((token_file, role_arn))
}

async fn fetch_aws_web_identity(
    cfg: &CompiledAwsIam,
    timeout: Duration,
    http: &dyn HttpClient,
) -> Result<AwsStsCredentials, String> {
    let (token_file, role_arn) = resolve_aws_web_identity_inputs(cfg).ok_or_else(|| {
        "aws_iam web_identity requires `web_identity_token_file` (or AWS_WEB_IDENTITY_TOKEN_FILE) and `role_arn` (or AWS_ROLE_ARN)".to_owned()
    })?;
    let raw_token = std::fs::read_to_string(&token_file)
        .map_err(|e| format!("failed to read web_identity_token_file `{token_file}`: {e}"))?;
    let token = raw_token.trim();
    if token.is_empty() {
        return Err(format!("web_identity_token_file `{token_file}` is empty"));
    }

    let mut params: Vec<(&str, String)> = vec![
        ("Action", "AssumeRoleWithWebIdentity".to_owned()),
        ("Version", "2011-06-15".to_owned()),
        ("RoleArn", role_arn),
        ("RoleSessionName", cfg.role_session_name.clone()),
        ("WebIdentityToken", token.to_owned()),
    ];
    if let Some(dur) = cfg.session_duration_secs {
        params.push(("DurationSeconds", dur.to_string()));
    }
    let body = form_urlencode_owned(&params);
    let uri: Uri = format!("{}/", cfg.sts_endpoint)
        .parse()
        .map_err(|e| format!("invalid AWS STS URI: {e}"))?;
    let req = HttpRequest::post(uri)
        .with_header(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/x-www-form-urlencoded"),
        )
        .with_body(body)
        .with_timeout(timeout)
        .with_max_response_bytes(DEFAULT_MAX_TOKEN_RESPONSE_BYTES);

    let resp = http
        .send(req)
        .await
        .map_err(|e| format!("AWS STS AssumeRoleWithWebIdentity request failed: {e}"))?;
    let text = String::from_utf8_lossy(&resp.body);
    if !resp.status.is_success() {
        return Err(format!(
            "AWS STS AssumeRoleWithWebIdentity returned HTTP {}: {}",
            resp.status.as_u16(),
            truncate_err(&text)
        ));
    }
    parse_aws_sts_xml_credentials(&text)
}

fn resolve_aws_ecs_uri(cfg: &CompiledAwsIam) -> Option<String> {
    if let Some(uri) = &cfg.ecs_credentials_uri {
        return Some(uri.clone());
    }
    if let Ok(full) = std::env::var("AWS_CONTAINER_CREDENTIALS_FULL_URI")
        && !full.trim().is_empty()
    {
        return Some(full.trim().to_owned());
    }
    if let Ok(rel) = std::env::var("AWS_CONTAINER_CREDENTIALS_RELATIVE_URI")
        && !rel.trim().is_empty()
    {
        let rel_clean = rel.trim();
        let slash = if rel_clean.starts_with('/') { "" } else { "/" };
        return Some(format!("{DEFAULT_AWS_ECS_HOST}{slash}{rel_clean}"));
    }
    None
}

fn resolve_aws_ecs_auth_token(cfg: &CompiledAwsIam) -> Result<Option<String>, String> {
    if let Some(tok) = &cfg.ecs_auth_token {
        return Ok(Some(tok.clone()));
    }
    if let Ok(path) = std::env::var("AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE")
        && !path.trim().is_empty()
    {
        let raw = std::fs::read_to_string(path.trim()).map_err(|e| {
            format!(
                "failed to read AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE `{}`: {e}",
                path.trim()
            )
        })?;
        let trimmed = raw.trim();
        if !trimmed.is_empty() {
            return Ok(Some(trimmed.to_owned()));
        }
    }
    if let Ok(tok) = std::env::var("AWS_CONTAINER_AUTHORIZATION_TOKEN")
        && !tok.trim().is_empty()
    {
        return Ok(Some(tok.trim().to_owned()));
    }
    Ok(None)
}

async fn fetch_aws_ecs_credentials(
    cfg: &CompiledAwsIam,
    timeout: Duration,
    http: &dyn HttpClient,
) -> Result<AwsStsCredentials, String> {
    let raw_uri = resolve_aws_ecs_uri(cfg).ok_or_else(|| {
        "aws_iam ecs mode requires `ecs_credentials_uri` or AWS_CONTAINER_CREDENTIALS_(FULL|RELATIVE)_URI".to_owned()
    })?;
    let uri: Uri = raw_uri
        .parse()
        .map_err(|e| format!("invalid ECS credentials URI `{raw_uri}`: {e}"))?;
    let mut req = HttpRequest::get(uri)
        .with_timeout(timeout)
        .with_max_response_bytes(DEFAULT_MAX_TOKEN_RESPONSE_BYTES);
    if let Some(auth_tok) = resolve_aws_ecs_auth_token(cfg)? {
        let hv = HeaderValue::from_str(&auth_tok)
            .map_err(|e| format!("invalid ECS authorization token header value: {e}"))?;
        req = req.with_header(header::AUTHORIZATION, hv);
    }
    let resp = http
        .send(req)
        .await
        .map_err(|e| format!("AWS ECS credentials request failed: {e}"))?;
    if !resp.status.is_success() {
        return Err(format!(
            "AWS ECS credentials endpoint returned HTTP {}: {}",
            resp.status.as_u16(),
            truncate_err(&String::from_utf8_lossy(&resp.body))
        ));
    }
    parse_aws_json_credentials(&resp.body)
}

async fn fetch_aws_imds_credentials(
    cfg: &CompiledAwsIam,
    timeout: Duration,
    http: &dyn HttpClient,
) -> Result<AwsStsCredentials, String> {
    // Step 1: Acquire IMDSv2 session token.
    let token_uri: Uri = format!("{}/latest/api/token", cfg.imds_endpoint)
        .parse()
        .map_err(|e| format!("invalid IMDS token URI: {e}"))?;
    let token_req = HttpRequest::put(token_uri)
        .with_header(
            HeaderName::from_static("x-aws-ec2-metadata-token-ttl-seconds"),
            HeaderValue::from_static("21600"),
        )
        .with_timeout(timeout)
        .with_max_response_bytes(4096);
    let token_resp = http
        .send(token_req)
        .await
        .map_err(|e| format!("AWS IMDSv2 token request failed: {e}"))?;
    if !token_resp.status.is_success() {
        return Err(format!(
            "AWS IMDSv2 token endpoint returned HTTP {}",
            token_resp.status.as_u16()
        ));
    }
    let imds_token = String::from_utf8_lossy(&token_resp.body).trim().to_owned();
    if imds_token.is_empty() {
        return Err("AWS IMDSv2 token endpoint returned an empty token".to_owned());
    }
    let imds_hdr = HeaderValue::from_str(&imds_token)
        .map_err(|e| format!("invalid IMDSv2 token header value: {e}"))?;

    // Step 2: Query attached IAM role name.
    let role_list_uri: Uri = format!(
        "{}/latest/meta-data/iam/security-credentials/",
        cfg.imds_endpoint
    )
    .parse()
    .map_err(|e| format!("invalid IMDS role list URI: {e}"))?;
    let role_list_req = HttpRequest::get(role_list_uri)
        .with_header(
            HeaderName::from_static("x-aws-ec2-metadata-token"),
            imds_hdr.clone(),
        )
        .with_timeout(timeout)
        .with_max_response_bytes(16 * 1024);
    let role_list_resp = http
        .send(role_list_req)
        .await
        .map_err(|e| format!("AWS IMDSv2 role lookup failed: {e}"))?;
    if !role_list_resp.status.is_success() {
        return Err(format!(
            "AWS IMDSv2 role lookup returned HTTP {}",
            role_list_resp.status.as_u16()
        ));
    }
    let role_name = String::from_utf8_lossy(&role_list_resp.body)
        .lines()
        .map(str::trim)
        .find(|line| !line.is_empty())
        .ok_or_else(|| "AWS IMDSv2 returned no IAM role name".to_owned())?
        .to_owned();

    // Step 3: Fetch temporary credentials JSON for that role.
    let creds_uri: Uri = format!(
        "{}/latest/meta-data/iam/security-credentials/{}",
        cfg.imds_endpoint,
        percent_encode_path_segment(&role_name)
    )
    .parse()
    .map_err(|e| format!("invalid IMDS credentials URI: {e}"))?;
    let creds_req = HttpRequest::get(creds_uri)
        .with_header(
            HeaderName::from_static("x-aws-ec2-metadata-token"),
            imds_hdr,
        )
        .with_timeout(timeout)
        .with_max_response_bytes(DEFAULT_MAX_TOKEN_RESPONSE_BYTES);
    let creds_resp = http
        .send(creds_req)
        .await
        .map_err(|e| format!("AWS IMDSv2 credentials request failed: {e}"))?;
    if !creds_resp.status.is_success() {
        return Err(format!(
            "AWS IMDSv2 credentials endpoint returned HTTP {}: {}",
            creds_resp.status.as_u16(),
            truncate_err(&String::from_utf8_lossy(&creds_resp.body))
        ));
    }
    parse_aws_json_credentials(&creds_resp.body)
}

async fn fetch_aws_sts_assume_role(
    cfg: &CompiledAwsIam,
    base: &AwsStsCredentials,
    role_arn: &str,
    timeout: Duration,
    http: &dyn HttpClient,
) -> Result<AwsStsCredentials, String> {
    let mut params: Vec<(&str, String)> = vec![
        ("Action", "AssumeRole".to_owned()),
        ("Version", "2011-06-15".to_owned()),
        ("RoleArn", role_arn.to_owned()),
        ("RoleSessionName", cfg.role_session_name.clone()),
    ];
    if let Some(ref ext_id) = cfg.external_id {
        params.push(("ExternalId", ext_id.clone()));
    }
    if let Some(dur) = cfg.session_duration_secs {
        params.push(("DurationSeconds", dur.to_string()));
    }
    let body = form_urlencode_owned(&params);
    let uri: Uri = format!("{}/", cfg.sts_endpoint)
        .parse()
        .map_err(|e| format!("invalid AWS STS URI: {e}"))?;
    let host = host_header_from_endpoint(&uri)?;
    let path = uri.path();
    let now_unix = current_unix_secs();
    let (amz_date, _) = format_amz_timestamps(now_unix);
    let payload_sha256 = crate::aws_sigv4::sha256_hex(body.as_bytes());
    let content_type = "application/x-www-form-urlencoded; charset=utf-8";

    let mut headers_to_sign = vec![
        ("content-type".to_owned(), content_type.to_owned()),
        ("host".to_owned(), host),
        ("x-amz-content-sha256".to_owned(), payload_sha256.clone()),
        ("x-amz-date".to_owned(), amz_date.clone()),
    ];
    if let Some(ref tok) = base.session_token {
        headers_to_sign.push(("x-amz-security-token".to_owned(), tok.clone()));
    }

    let sts_creds = AwsSigV4Credentials {
        access_key_id: base.access_key_id.clone(),
        secret_access_key: base.secret_access_key.clone(),
        session_token: base.session_token.clone(),
        region: cfg.region.clone(),
        service: "sts".to_owned(),
    };
    let signed = sign_canonical(
        &sts_creds,
        "POST",
        path,
        uri.query(),
        &headers_to_sign,
        body.as_bytes(),
        now_unix,
        true,
    );

    let mut req = HttpRequest::post(uri)
        .with_header(header::CONTENT_TYPE, HeaderValue::from_static(content_type))
        .with_header(
            HeaderName::from_static("x-amz-date"),
            HeaderValue::from_str(&signed.amz_date)
                .map_err(|e| format!("invalid x-amz-date header: {e}"))?,
        )
        .with_header(
            HeaderName::from_static("x-amz-content-sha256"),
            HeaderValue::from_str(&signed.payload_sha256)
                .map_err(|e| format!("invalid x-amz-content-sha256 header: {e}"))?,
        )
        .with_header(
            header::AUTHORIZATION,
            HeaderValue::from_str(&signed.authorization)
                .map_err(|e| format!("invalid STS Authorization header: {e}"))?,
        )
        .with_body(body)
        .with_timeout(timeout)
        .with_max_response_bytes(DEFAULT_MAX_TOKEN_RESPONSE_BYTES);

    if let Some(ref tok) = base.session_token {
        req = req.with_header(
            HeaderName::from_static("x-amz-security-token"),
            HeaderValue::from_str(tok)
                .map_err(|e| format!("invalid x-amz-security-token header: {e}"))?,
        );
    }

    let resp = http
        .send(req)
        .await
        .map_err(|e| format!("AWS STS AssumeRole request failed: {e}"))?;
    let text = String::from_utf8_lossy(&resp.body);
    if !resp.status.is_success() {
        return Err(format!(
            "AWS STS AssumeRole returned HTTP {}: {}",
            resp.status.as_u16(),
            truncate_err(&text)
        ));
    }
    parse_aws_sts_xml_credentials(&text)
}

/// Parses JSON credentials returned by EC2 IMDSv2 or ECS Task Role endpoints.
pub fn parse_aws_json_credentials(body: &[u8]) -> Result<AwsStsCredentials, String> {
    let val: Value =
        serde_json::from_slice(body).map_err(|e| format!("invalid AWS credentials JSON: {e}"))?;
    let access_key_id = val
        .get("AccessKeyId")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| "AWS credentials JSON missing `AccessKeyId`".to_owned())?
        .to_owned();
    let secret_access_key = val
        .get("SecretAccessKey")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| "AWS credentials JSON missing `SecretAccessKey`".to_owned())?
        .to_owned();
    let session_token = val
        .get("Token")
        .or_else(|| val.get("SessionToken"))
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .map(str::to_owned);
    let expiration_unix_secs = match val.get("Expiration").and_then(Value::as_str) {
        Some(raw) if !raw.trim().is_empty() => Some(parse_rfc3339_utc_secs(raw.trim())?),
        _ => None,
    };
    Ok(AwsStsCredentials {
        access_key_id,
        secret_access_key,
        session_token,
        expiration_unix_secs,
    })
}

// ---------------------------------------------------------------------------
// GCP IAM Fetchers (Metadata Server, Service Account RS256 JWT, Authorized User)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Deserialize)]
pub struct GcpServiceAccountKey {
    pub client_email: String,
    pub private_key: String,
    #[serde(default)]
    pub private_key_id: Option<String>,
    #[serde(default)]
    pub token_uri: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
struct GcpAuthorizedUserKey {
    client_id: String,
    client_secret: String,
    refresh_token: String,
    #[serde(default)]
    token_uri: Option<String>,
}

async fn fetch_gcp_token(
    cfg: &CompiledGcpIam,
    timeout: Duration,
    http: &dyn HttpClient,
) -> Result<(String, Duration), String> {
    match cfg.mode {
        GcpIamMode::Metadata => fetch_gcp_metadata_token(cfg, timeout, http).await,
        GcpIamMode::ServiceAccount => {
            let raw = load_gcp_credentials_raw(cfg)?.ok_or_else(|| {
                "gcp_iam service_account mode requires `credentials_json`, `credentials_file`, or GOOGLE_APPLICATION_CREDENTIALS".to_owned()
            })?;
            fetch_gcp_service_account_token(cfg, &raw, timeout, http).await
        }
        GcpIamMode::AuthorizedUser => {
            let raw = load_gcp_credentials_raw(cfg)?.ok_or_else(|| {
                "gcp_iam authorized_user mode requires `credentials_json`, `credentials_file`, or GOOGLE_APPLICATION_CREDENTIALS".to_owned()
            })?;
            fetch_gcp_authorized_user_token(cfg, &raw, timeout, http).await
        }
        GcpIamMode::Auto => {
            if let Some(raw) = load_gcp_credentials_raw(cfg)? {
                let val: Value = serde_json::from_str(&raw)
                    .map_err(|e| format!("invalid GCP credentials JSON: {e}"))?;
                let cred_type = val.get("type").and_then(Value::as_str).unwrap_or("");
                match cred_type {
                    "service_account" => {
                        fetch_gcp_service_account_token(cfg, &raw, timeout, http).await
                    }
                    "authorized_user" => {
                        fetch_gcp_authorized_user_token(cfg, &raw, timeout, http).await
                    }
                    other => Err(format!(
                        "unsupported GCP credentials JSON `type`: `{other}` (expected `service_account` or `authorized_user`)"
                    )),
                }
            } else {
                fetch_gcp_metadata_token(cfg, timeout, http).await
            }
        }
    }
}

fn load_gcp_credentials_raw(cfg: &CompiledGcpIam) -> Result<Option<String>, String> {
    if let Some(ref inline) = cfg.credentials_json {
        return Ok(Some(inline.clone()));
    }
    let path = cfg.credentials_file.clone().or_else(|| {
        std::env::var("GOOGLE_APPLICATION_CREDENTIALS")
            .ok()
            .filter(|s| !s.trim().is_empty())
    });
    match path {
        Some(p) => {
            let content = std::fs::read_to_string(&p)
                .map_err(|e| format!("failed to read GCP credentials file `{p}`: {e}"))?;
            Ok(Some(content))
        }
        None => Ok(None),
    }
}

async fn fetch_gcp_metadata_token(
    cfg: &CompiledGcpIam,
    timeout: Duration,
    http: &dyn HttpClient,
) -> Result<(String, Duration), String> {
    let email = percent_encode_path_segment(&cfg.service_account_email);
    let scopes_q = form_urlencode_component(&cfg.scopes.join(","));
    let uri: Uri = format!(
        "{}/computeMetadata/v1/instance/service-accounts/{email}/token?scopes={scopes_q}",
        cfg.metadata_endpoint
    )
    .parse()
    .map_err(|e| format!("invalid GCP metadata URI: {e}"))?;

    let req = HttpRequest::get(uri)
        .with_header(
            HeaderName::from_static("metadata-flavor"),
            HeaderValue::from_static("Google"),
        )
        .with_timeout(timeout)
        .with_max_response_bytes(DEFAULT_MAX_TOKEN_RESPONSE_BYTES);
    let resp = http
        .send(req)
        .await
        .map_err(|e| format!("GCP metadata token request failed: {e}"))?;
    if !resp.status.is_success() {
        return Err(format!(
            "GCP metadata server returned HTTP {}: {}",
            resp.status.as_u16(),
            truncate_err(&String::from_utf8_lossy(&resp.body))
        ));
    }
    parse_oauth_bearer_response(&resp.body, "GCP metadata")
}

async fn fetch_gcp_service_account_token(
    cfg: &CompiledGcpIam,
    raw_json: &str,
    timeout: Duration,
    http: &dyn HttpClient,
) -> Result<(String, Duration), String> {
    let sa: GcpServiceAccountKey = serde_json::from_str(raw_json)
        .map_err(|e| format!("invalid GCP service account JSON: {e}"))?;
    let token_uri = cfg
        .token_uri
        .as_deref()
        .or(sa.token_uri.as_deref())
        .filter(|s| !s.trim().is_empty())
        .unwrap_or(DEFAULT_GCP_TOKEN_URI);

    let assertion = sign_gcp_service_account_jwt(&sa, &cfg.scopes, token_uri, current_unix_secs())?;
    let body = form_urlencode(&[
        ("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer"),
        ("assertion", &assertion),
    ]);
    let uri: Uri = token_uri
        .parse()
        .map_err(|e| format!("invalid GCP OAuth2 token_uri `{token_uri}`: {e}"))?;

    let req = HttpRequest::post(uri)
        .with_header(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/x-www-form-urlencoded"),
        )
        .with_body(body)
        .with_timeout(timeout)
        .with_max_response_bytes(DEFAULT_MAX_TOKEN_RESPONSE_BYTES);
    let resp = http
        .send(req)
        .await
        .map_err(|e| format!("GCP Service Account OAuth2 token exchange failed: {e}"))?;
    if !resp.status.is_success() {
        return Err(format!(
            "GCP OAuth2 token endpoint returned HTTP {}: {}",
            resp.status.as_u16(),
            truncate_err(&String::from_utf8_lossy(&resp.body))
        ));
    }
    parse_oauth_bearer_response(&resp.body, "GCP OAuth2")
}

async fn fetch_gcp_authorized_user_token(
    cfg: &CompiledGcpIam,
    raw_json: &str,
    timeout: Duration,
    http: &dyn HttpClient,
) -> Result<(String, Duration), String> {
    let user: GcpAuthorizedUserKey = serde_json::from_str(raw_json)
        .map_err(|e| format!("invalid GCP authorized_user JSON: {e}"))?;
    let token_uri = cfg
        .token_uri
        .as_deref()
        .or(user.token_uri.as_deref())
        .filter(|s| !s.trim().is_empty())
        .unwrap_or(DEFAULT_GCP_TOKEN_URI);

    let body = form_urlencode(&[
        ("grant_type", "refresh_token"),
        ("client_id", &user.client_id),
        ("client_secret", &user.client_secret),
        ("refresh_token", &user.refresh_token),
    ]);
    let uri: Uri = token_uri
        .parse()
        .map_err(|e| format!("invalid GCP OAuth2 token_uri `{token_uri}`: {e}"))?;

    let req = HttpRequest::post(uri)
        .with_header(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/x-www-form-urlencoded"),
        )
        .with_body(body)
        .with_timeout(timeout)
        .with_max_response_bytes(DEFAULT_MAX_TOKEN_RESPONSE_BYTES);
    let resp = http
        .send(req)
        .await
        .map_err(|e| format!("GCP authorized_user token refresh failed: {e}"))?;
    if !resp.status.is_success() {
        return Err(format!(
            "GCP OAuth2 refresh endpoint returned HTTP {}: {}",
            resp.status.as_u16(),
            truncate_err(&String::from_utf8_lossy(&resp.body))
        ));
    }
    parse_oauth_bearer_response(&resp.body, "GCP OAuth2")
}

// ---------------------------------------------------------------------------
// Azure Entra ID Fetchers (Managed Identity IMDS, Client Credentials, Workload Identity)
// ---------------------------------------------------------------------------

async fn fetch_azure_token(
    cfg: &CompiledAzureAd,
    timeout: Duration,
    http: &dyn HttpClient,
) -> Result<(String, Duration), String> {
    let tenant_id = cfg.tenant_id.clone().or_else(|| {
        std::env::var("AZURE_TENANT_ID")
            .ok()
            .filter(|s| !s.trim().is_empty())
    });
    let client_id = cfg.client_id.clone().or_else(|| {
        std::env::var("AZURE_CLIENT_ID")
            .ok()
            .filter(|s| !s.trim().is_empty())
    });
    let client_secret = cfg.client_secret.clone().or_else(|| {
        std::env::var("AZURE_CLIENT_SECRET")
            .ok()
            .filter(|s| !s.trim().is_empty())
    });
    let federated_token_file = cfg.federated_token_file.clone().or_else(|| {
        std::env::var("AZURE_FEDERATED_TOKEN_FILE")
            .ok()
            .filter(|s| !s.trim().is_empty())
    });

    match cfg.mode {
        AzureAdMode::ManagedIdentity => {
            fetch_azure_imds_token(cfg, client_id.as_deref(), timeout, http).await
        }
        AzureAdMode::ClientCredentials => {
            let tid = tenant_id.as_deref().ok_or_else(|| {
                "azure_ad client_credentials requires `tenant_id` (or AZURE_TENANT_ID)".to_owned()
            })?;
            let cid = client_id.as_deref().ok_or_else(|| {
                "azure_ad client_credentials requires `client_id` (or AZURE_CLIENT_ID)".to_owned()
            })?;
            let secret = client_secret.as_deref().ok_or_else(|| {
                "azure_ad client_credentials requires `client_secret` (or AZURE_CLIENT_SECRET)"
                    .to_owned()
            })?;
            fetch_azure_client_credentials_token(cfg, tid, cid, secret, timeout, http).await
        }
        AzureAdMode::WorkloadIdentity => {
            let tid = tenant_id.as_deref().ok_or_else(|| {
                "azure_ad workload_identity requires `tenant_id` (or AZURE_TENANT_ID)".to_owned()
            })?;
            let cid = client_id.as_deref().ok_or_else(|| {
                "azure_ad workload_identity requires `client_id` (or AZURE_CLIENT_ID)".to_owned()
            })?;
            let tok_file = federated_token_file.as_deref().ok_or_else(|| {
                "azure_ad workload_identity requires `federated_token_file` (or AZURE_FEDERATED_TOKEN_FILE)".to_owned()
            })?;
            fetch_azure_workload_identity_token(cfg, tid, cid, tok_file, timeout, http).await
        }
        AzureAdMode::Auto => {
            if let (Some(tid), Some(cid), Some(tok_file)) = (
                tenant_id.as_deref(),
                client_id.as_deref(),
                federated_token_file.as_deref(),
            ) {
                fetch_azure_workload_identity_token(cfg, tid, cid, tok_file, timeout, http).await
            } else if let (Some(tid), Some(cid), Some(secret)) = (
                tenant_id.as_deref(),
                client_id.as_deref(),
                client_secret.as_deref(),
            ) {
                fetch_azure_client_credentials_token(cfg, tid, cid, secret, timeout, http).await
            } else {
                fetch_azure_imds_token(cfg, client_id.as_deref(), timeout, http).await
            }
        }
    }
}

async fn fetch_azure_imds_token(
    cfg: &CompiledAzureAd,
    client_id: Option<&str>,
    timeout: Duration,
    http: &dyn HttpClient,
) -> Result<(String, Duration), String> {
    let mut url = format!(
        "{}/metadata/identity/oauth2/token?api-version=2018-02-01&resource={}",
        cfg.imds_endpoint,
        form_urlencode_component(&cfg.resource)
    );
    if let Some(cid) = client_id {
        url.push_str("&client_id=");
        url.push_str(&form_urlencode_component(cid));
    }
    let uri: Uri = url
        .parse()
        .map_err(|e| format!("invalid Azure IMDS URI: {e}"))?;
    let req = HttpRequest::get(uri)
        .with_header(
            HeaderName::from_static("metadata"),
            HeaderValue::from_static("true"),
        )
        .with_timeout(timeout)
        .with_max_response_bytes(DEFAULT_MAX_TOKEN_RESPONSE_BYTES);
    let resp = http
        .send(req)
        .await
        .map_err(|e| format!("Azure Managed Identity IMDS request failed: {e}"))?;
    if !resp.status.is_success() {
        return Err(format!(
            "Azure IMDS returned HTTP {}: {}",
            resp.status.as_u16(),
            truncate_err(&String::from_utf8_lossy(&resp.body))
        ));
    }
    parse_oauth_bearer_response(&resp.body, "Azure IMDS")
}

async fn fetch_azure_client_credentials_token(
    cfg: &CompiledAzureAd,
    tenant_id: &str,
    client_id: &str,
    client_secret: &str,
    timeout: Duration,
    http: &dyn HttpClient,
) -> Result<(String, Duration), String> {
    let uri: Uri = format!(
        "{}/{}/oauth2/v2.0/token",
        cfg.authority_host,
        percent_encode_path_segment(tenant_id)
    )
    .parse()
    .map_err(|e| format!("invalid Azure Entra ID token URI: {e}"))?;
    let body = form_urlencode(&[
        ("grant_type", "client_credentials"),
        ("client_id", client_id),
        ("client_secret", client_secret),
        ("scope", &cfg.scope),
    ]);
    let req = HttpRequest::post(uri)
        .with_header(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/x-www-form-urlencoded"),
        )
        .with_body(body)
        .with_timeout(timeout)
        .with_max_response_bytes(DEFAULT_MAX_TOKEN_RESPONSE_BYTES);
    let resp = http
        .send(req)
        .await
        .map_err(|e| format!("Azure Entra ID client_credentials request failed: {e}"))?;
    if !resp.status.is_success() {
        return Err(format!(
            "Azure Entra ID returned HTTP {}: {}",
            resp.status.as_u16(),
            truncate_err(&String::from_utf8_lossy(&resp.body))
        ));
    }
    parse_oauth_bearer_response(&resp.body, "Azure Entra ID")
}

async fn fetch_azure_workload_identity_token(
    cfg: &CompiledAzureAd,
    tenant_id: &str,
    client_id: &str,
    federated_token_file: &str,
    timeout: Duration,
    http: &dyn HttpClient,
) -> Result<(String, Duration), String> {
    let raw_assertion = std::fs::read_to_string(federated_token_file).map_err(|e| {
        format!("failed to read federated_token_file `{federated_token_file}`: {e}")
    })?;
    let assertion = raw_assertion.trim();
    if assertion.is_empty() {
        return Err(format!(
            "federated_token_file `{federated_token_file}` is empty"
        ));
    }
    let uri: Uri = format!(
        "{}/{}/oauth2/v2.0/token",
        cfg.authority_host,
        percent_encode_path_segment(tenant_id)
    )
    .parse()
    .map_err(|e| format!("invalid Azure Entra ID token URI: {e}"))?;
    let body = form_urlencode(&[
        ("grant_type", "client_credentials"),
        ("client_id", client_id),
        (
            "client_assertion_type",
            "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
        ),
        ("client_assertion", assertion),
        ("scope", &cfg.scope),
    ]);
    let req = HttpRequest::post(uri)
        .with_header(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/x-www-form-urlencoded"),
        )
        .with_body(body)
        .with_timeout(timeout)
        .with_max_response_bytes(DEFAULT_MAX_TOKEN_RESPONSE_BYTES);
    let resp = http
        .send(req)
        .await
        .map_err(|e| format!("Azure Entra ID workload_identity request failed: {e}"))?;
    if !resp.status.is_success() {
        return Err(format!(
            "Azure Entra ID returned HTTP {}: {}",
            resp.status.as_u16(),
            truncate_err(&String::from_utf8_lossy(&resp.body))
        ));
    }
    parse_oauth_bearer_response(&resp.body, "Azure Entra ID")
}

/// Parses an OAuth2 / IMDS bearer token JSON response (`access_token` + integer or stringified `expires_in`).
pub fn parse_oauth_bearer_response(body: &[u8], label: &str) -> Result<(String, Duration), String> {
    let val: Value =
        serde_json::from_slice(body).map_err(|e| format!("invalid {label} JSON response: {e}"))?;
    let token = val
        .get("access_token")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| format!("{label} response missing `access_token`"))?
        .to_owned();
    let expires_in = val
        .get("expires_in")
        .and_then(parse_expires_in_value)
        .or_else(|| {
            val.get("expires_on")
                .and_then(parse_expires_in_value)
                .map(|exp_on| exp_on.saturating_sub(current_unix_secs()))
        })
        .unwrap_or(3_600)
        .max(1);
    Ok((token, Duration::from_secs(expires_in)))
}

/// Parses `expires_in` / `expires_on` values encoded either as a JSON integer or a stringified integer.
pub fn parse_expires_in_value(v: &Value) -> Option<u64> {
    match v {
        Value::Number(n) => n.as_u64(),
        Value::String(s) => s.trim().parse::<u64>().ok(),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Pure-Rust Parsers & RS256 JWT Signer (Fuzz-Tested)
// ---------------------------------------------------------------------------

/// Parses AWS STS XML response (`AssumeRole` or `AssumeRoleWithWebIdentity`) and extracts
/// `<Credentials>` fields without any external XML parser dependency.
pub fn parse_aws_sts_xml_credentials(xml: &str) -> Result<AwsStsCredentials, String> {
    let section = extract_xml_tag(xml, "Credentials").unwrap_or(xml);
    let access_key_id = extract_xml_tag(section, "AccessKeyId")
        .map(|s| xml_unescape(s.trim()))
        .filter(|s| !s.is_empty())
        .ok_or_else(|| "AWS STS XML response missing <AccessKeyId>".to_owned())?;
    let secret_access_key = extract_xml_tag(section, "SecretAccessKey")
        .map(|s| xml_unescape(s.trim()))
        .filter(|s| !s.is_empty())
        .ok_or_else(|| "AWS STS XML response missing <SecretAccessKey>".to_owned())?;
    let session_token = extract_xml_tag(section, "SessionToken")
        .map(|s| xml_unescape(s.trim()))
        .filter(|s| !s.is_empty());
    let expiration_unix_secs = match extract_xml_tag(section, "Expiration") {
        Some(raw) if !raw.trim().is_empty() => Some(parse_rfc3339_utc_secs(raw.trim())?),
        _ => None,
    };
    Ok(AwsStsCredentials {
        access_key_id,
        secret_access_key,
        session_token,
        expiration_unix_secs,
    })
}

fn extract_xml_tag<'a>(xml: &'a str, tag: &str) -> Option<&'a str> {
    let bytes = xml.as_bytes();
    let mut pos = 0;
    while pos < bytes.len() {
        let rel_open = xml[pos..].find('<')?;
        let open_idx = pos + rel_open;
        let rest = &xml[open_idx + 1..];
        let close_gt = rest.find('>')?;
        let tag_header = &rest[..close_gt];
        let trimmed = tag_header.trim();

        if !trimmed.starts_with('/') && !trimmed.starts_with('?') && !trimmed.starts_with('!') {
            let is_self_closing = trimmed.ends_with('/');
            let name_part = trimmed
                .split(|c: char| c.is_ascii_whitespace() || c == '/')
                .next()
                .unwrap_or("");
            let local_name = name_part
                .rsplit_once(':')
                .map(|(_, l)| l)
                .unwrap_or(name_part);

            if local_name == tag && !is_self_closing {
                let content_start = open_idx + 1 + close_gt + 1;
                // Find matching closing tag `</name_part>` (exact prefix match).
                let closing_exact = format!("</{name_part}>");
                if let Some(rel_end) = xml[content_start..].find(&closing_exact) {
                    return Some(&xml[content_start..content_start + rel_end]);
                }
            }
        }
        pos = open_idx + 1 + close_gt + 1;
    }
    None
}

fn xml_unescape(s: &str) -> String {
    if !s.contains('&') {
        return s.to_owned();
    }
    let mut out = String::with_capacity(s.len());
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'&'
            && let Some(rel_semi) = s[i..].find(';')
        {
            let entity = &s[i + 1..i + rel_semi];
            let decoded = match entity {
                "amp" => Some('&'),
                "lt" => Some('<'),
                "gt" => Some('>'),
                "quot" => Some('"'),
                "apos" => Some('\''),
                _ if entity.starts_with("#x") || entity.starts_with("#X") => {
                    u32::from_str_radix(&entity[2..], 16)
                        .ok()
                        .and_then(char::from_u32)
                }
                _ if entity.starts_with('#') => {
                    entity[1..].parse::<u32>().ok().and_then(char::from_u32)
                }
                _ => None,
            };
            if let Some(ch) = decoded {
                out.push(ch);
                i += rel_semi + 1;
                continue;
            }
        }
        let ch = s[i..].chars().next().unwrap();
        out.push(ch);
        i += ch.len_utf8();
    }
    out
}

/// Parses an RFC 3339 / ISO-8601 timestamp (e.g. `"2026-11-22T12:34:56Z"`,
/// `"2026-11-22T12:34:56.789Z"`, or `"2026-11-22T18:04:56+05:30"`) into UTC Unix seconds.
pub fn parse_rfc3339_utc_secs(input: &str) -> Result<u64, String> {
    let s = input.trim();
    let b = s.as_bytes();
    // Minimum length: `YYYY-MM-DDTHH:MM:SSZ` (20 bytes)
    if b.len() < 20 {
        return Err(format!("invalid RFC 3339 timestamp `{input}`: too short"));
    }
    if b[4] != b'-'
        || b[7] != b'-'
        || !matches!(b[10], b'T' | b't' | b' ')
        || b[13] != b':'
        || b[16] != b':'
    {
        return Err(format!(
            "invalid RFC 3339 timestamp `{input}`: unexpected separators"
        ));
    }

    let year = parse_ascii_digits::<i64>(&b[0..4])?;
    let month = parse_ascii_digits::<u32>(&b[5..7])?;
    let day = parse_ascii_digits::<u32>(&b[8..10])?;
    let hour = parse_ascii_digits::<u32>(&b[11..13])?;
    let minute = parse_ascii_digits::<u32>(&b[14..16])?;
    let second = parse_ascii_digits::<u32>(&b[17..19])?;

    if !(1970..=9999).contains(&year)
        || !(1..=12).contains(&month)
        || day == 0
        || day > days_in_month(year, month)
        || hour > 23
        || minute > 59
        || second > 60
    {
        return Err(format!(
            "invalid RFC 3339 timestamp `{input}`: date/time field out of range"
        ));
    }

    let mut pos = 19;
    // Skip optional fractional seconds `.123456789`
    if pos < b.len() && b[pos] == b'.' {
        pos += 1;
        let frac_start = pos;
        while pos < b.len() && b[pos].is_ascii_digit() {
            pos += 1;
        }
        if pos == frac_start {
            return Err(format!(
                "invalid RFC 3339 timestamp `{input}`: empty fractional seconds"
            ));
        }
    }

    let offset_secs: i64 = match b.get(pos) {
        Some(b'Z' | b'z') if pos + 1 == b.len() => 0,
        Some(sign @ (b'+' | b'-')) if pos + 6 == b.len() && b[pos + 3] == b':' => {
            let oh = parse_ascii_digits::<i64>(&b[pos + 1..pos + 3])?;
            let om = parse_ascii_digits::<i64>(&b[pos + 4..pos + 6])?;
            if oh > 23 || om > 59 {
                return Err(format!(
                    "invalid RFC 3339 timestamp `{input}`: timezone offset out of range"
                ));
            }
            let mag = oh * 3_600 + om * 60;
            if *sign == b'+' { mag } else { -mag }
        }
        _ => {
            return Err(format!(
                "invalid RFC 3339 timestamp `{input}`: missing or malformed timezone"
            ));
        }
    };

    let days = days_from_civil(year, month, day);
    let sec_clamped = second.min(59) as i64;
    let local_secs = days
        .checked_mul(86_400)
        .and_then(|d| d.checked_add((hour as i64) * 3_600 + (minute as i64) * 60 + sec_clamped))
        .ok_or_else(|| format!("RFC 3339 timestamp `{input}` overflowed"))?;
    let utc_secs = local_secs - offset_secs;
    u64::try_from(utc_secs).map_err(|_| format!("RFC 3339 timestamp `{input}` precedes Unix epoch"))
}

fn parse_ascii_digits<T: From<u32>>(bytes: &[u8]) -> Result<T, String> {
    let mut acc: u32 = 0;
    for &b in bytes {
        if !b.is_ascii_digit() {
            return Err("non-digit character in timestamp field".to_owned());
        }
        acc = acc
            .checked_mul(10)
            .and_then(|v| v.checked_add((b - b'0') as u32))
            .ok_or_else(|| "timestamp digit overflow".to_owned())?;
    }
    Ok(T::from(acc))
}

fn is_leap_year(year: i64) -> bool {
    (year % 4 == 0 && year % 100 != 0) || (year % 400 == 0)
}

fn days_in_month(year: i64, month: u32) -> u32 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 => {
            if is_leap_year(year) {
                29
            } else {
                28
            }
        }
        _ => 0,
    }
}

/// Howard Hinnant's civil-to-days algorithm (UTC `(year, month, day)` -> days since 1970-01-01).
fn days_from_civil(year: i64, month: u32, day: u32) -> i64 {
    let y = if month <= 2 { year - 1 } else { year };
    let era = y.div_euclid(400);
    let yoe = y.rem_euclid(400) as u64;
    let m = month as u64;
    let d = day as u64;
    let mp = if m > 2 { m - 3 } else { m + 9 };
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + (doe as i64) - 719_468
}

/// Decodes a PKCS#8 PEM private key (`-----BEGIN PRIVATE KEY-----` ... `-----END PRIVATE KEY-----`)
/// into raw DER bytes with zero external PEM/base64 dependencies.
pub fn decode_pem_pkcs8_private_key(pem_input: &str) -> Result<Vec<u8>, String> {
    // Handle env-var escaped newlines (`\n`) gracefully.
    let normalized;
    let src = if !pem_input.contains('\n') && pem_input.contains("\\n") {
        normalized = pem_input.replace("\\n", "\n");
        normalized.as_str()
    } else {
        pem_input
    };

    const BEGIN: &str = "-----BEGIN PRIVATE KEY-----";
    const END: &str = "-----END PRIVATE KEY-----";
    let start = src
        .find(BEGIN)
        .ok_or_else(|| "PEM private key missing `-----BEGIN PRIVATE KEY-----` header".to_owned())?
        + BEGIN.len();
    let rest = &src[start..];
    let end = rest
        .find(END)
        .ok_or_else(|| "PEM private key missing `-----END PRIVATE KEY-----` footer".to_owned())?;
    let body = &rest[..end];
    base64_std_decode(body)
}

/// Decodes standard RFC 4648 Base64 (ignoring ASCII whitespace).
pub fn base64_std_decode(input: &str) -> Result<Vec<u8>, String> {
    let mut vals: Vec<u8> = Vec::with_capacity(input.len());
    let mut pad_count = 0usize;
    for &b in input.as_bytes() {
        if b.is_ascii_whitespace() {
            continue;
        }
        if b == b'=' {
            pad_count += 1;
            continue;
        }
        if pad_count > 0 {
            return Err("invalid base64: non-padding character after `=`".to_owned());
        }
        let v = match b {
            b'A'..=b'Z' => b - b'A',
            b'a'..=b'z' => b - b'a' + 26,
            b'0'..=b'9' => b - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            _ => return Err(format!("invalid base64 byte: 0x{b:02x}")),
        };
        vals.push(v);
    }

    let total_chars = vals.len() + pad_count;
    if total_chars == 0 || !total_chars.is_multiple_of(4) || pad_count > 2 {
        return Err("invalid base64 length or padding".to_owned());
    }

    let mut out = Vec::with_capacity((total_chars / 4) * 3);
    let full_quads = vals.len() / 4;
    for i in 0..full_quads {
        let a = vals[i * 4];
        let b = vals[i * 4 + 1];
        let c = vals[i * 4 + 2];
        let d = vals[i * 4 + 3];
        out.push((a << 2) | (b >> 4));
        out.push((b << 4) | (c >> 2));
        out.push((c << 6) | d);
    }

    let rem = vals.len() % 4;
    match (rem, pad_count) {
        (0, 0) => {}
        (2, 2) => {
            let a = vals[full_quads * 4];
            let b = vals[full_quads * 4 + 1];
            out.push((a << 2) | (b >> 4));
        }
        (3, 1) => {
            let a = vals[full_quads * 4];
            let b = vals[full_quads * 4 + 1];
            let c = vals[full_quads * 4 + 2];
            out.push((a << 2) | (b >> 4));
            out.push((b << 4) | (c >> 2));
        }
        _ => return Err("invalid base64 trailing quantum".to_owned()),
    }
    Ok(out)
}

/// Encodes bytes as unpadded URL-safe Base64 (RFC 4648 §5, used for JWT segments).
pub fn base64url_encode(input: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
    let mut i = 0;
    while i + 3 <= input.len() {
        let n = ((input[i] as u32) << 16) | ((input[i + 1] as u32) << 8) | (input[i + 2] as u32);
        out.push(TABLE[((n >> 18) & 0x3f) as usize] as char);
        out.push(TABLE[((n >> 12) & 0x3f) as usize] as char);
        out.push(TABLE[((n >> 6) & 0x3f) as usize] as char);
        out.push(TABLE[(n & 0x3f) as usize] as char);
        i += 3;
    }
    match input.len() - i {
        1 => {
            let n = (input[i] as u32) << 16;
            out.push(TABLE[((n >> 18) & 0x3f) as usize] as char);
            out.push(TABLE[((n >> 12) & 0x3f) as usize] as char);
        }
        2 => {
            let n = ((input[i] as u32) << 16) | ((input[i + 1] as u32) << 8);
            out.push(TABLE[((n >> 18) & 0x3f) as usize] as char);
            out.push(TABLE[((n >> 12) & 0x3f) as usize] as char);
            out.push(TABLE[((n >> 6) & 0x3f) as usize] as char);
        }
        _ => {}
    }
    out
}

/// Constructs and cryptographically signs an RS256 OAuth2 JWT assertion for a GCP Service Account
/// using `ring::signature::RsaKeyPair::from_pkcs8` (`RSA_PKCS1_SHA256`).
pub fn sign_gcp_service_account_jwt(
    sa: &GcpServiceAccountKey,
    scopes: &[String],
    token_uri: &str,
    now_unix_secs: u64,
) -> Result<String, String> {
    let der = decode_pem_pkcs8_private_key(&sa.private_key)?;
    let key_pair = RsaKeyPair::from_pkcs8(&der)
        .map_err(|e| format!("failed to parse GCP PKCS#8 RSA private key: {e}"))?;

    let mut header_obj = serde_json::Map::new();
    header_obj.insert("alg".to_owned(), Value::String("RS256".to_owned()));
    header_obj.insert("typ".to_owned(), Value::String("JWT".to_owned()));
    if let Some(ref kid) = sa.private_key_id
        && !kid.trim().is_empty()
    {
        header_obj.insert("kid".to_owned(), Value::String(kid.clone()));
    }
    let header_json = serde_json::to_vec(&Value::Object(header_obj))
        .map_err(|e| format!("failed to serialize JWT header: {e}"))?;

    let claims = serde_json::json!({
        "iss": sa.client_email,
        "scope": scopes.join(" "),
        "aud": token_uri,
        "iat": now_unix_secs,
        "exp": now_unix_secs.saturating_add(3_600),
    });
    let claims_json =
        serde_json::to_vec(&claims).map_err(|e| format!("failed to serialize JWT claims: {e}"))?;

    let signing_input = format!(
        "{}.{}",
        base64url_encode(&header_json),
        base64url_encode(&claims_json)
    );

    let rng = SystemRandom::new();
    let mut sig = vec![0u8; key_pair.public().modulus_len()];
    key_pair
        .sign(&RSA_PKCS1_SHA256, &rng, signing_input.as_bytes(), &mut sig)
        .map_err(|_| "RSA_PKCS1_SHA256 signing failed".to_owned())?;

    Ok(format!("{signing_input}.{}", base64url_encode(&sig)))
}

fn form_urlencode(pairs: &[(&str, &str)]) -> String {
    pairs
        .iter()
        .map(|(k, v)| {
            format!(
                "{}={}",
                form_urlencode_component(k),
                form_urlencode_component(v)
            )
        })
        .collect::<Vec<_>>()
        .join("&")
}

fn form_urlencode_owned(pairs: &[(&str, String)]) -> String {
    pairs
        .iter()
        .map(|(k, v)| {
            format!(
                "{}={}",
                form_urlencode_component(k),
                form_urlencode_component(v)
            )
        })
        .collect::<Vec<_>>()
        .join("&")
}

fn form_urlencode_component(input: &str) -> String {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut out = String::with_capacity(input.len());
    for &b in input.as_bytes() {
        if is_rfc3986_unreserved(b) {
            out.push(b as char);
        } else {
            out.push('%');
            out.push(HEX[(b >> 4) as usize] as char);
            out.push(HEX[(b & 0x0F) as usize] as char);
        }
    }
    out
}

fn current_unix_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn truncate_err(s: &str) -> String {
    const MAX: usize = 256;
    let trimmed = s.trim();
    if trimmed.len() <= MAX {
        trimmed.to_owned()
    } else {
        let mut end = MAX;
        while !trimmed.is_char_boundary(end) {
            end -= 1;
        }
        format!("{}...", &trimmed[..end])
    }
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use ring::signature::{KeyPair, RSA_PKCS1_2048_8192_SHA256, UnparsedPublicKey};
    use shunt_plugin_sdk::{
        BoxFuture, Bytes, HeaderMap, HttpClientError, HttpResponse, ManualClock, StatusCode,
    };

    use super::*;

    type ScriptedHandler =
        Box<dyn Fn(&HttpRequest) -> Result<HttpResponse, HttpClientError> + Send + Sync + 'static>;

    struct MockHttpClient {
        requests: Mutex<Vec<HttpRequest>>,
        responses: Mutex<VecDeque<ScriptedHandler>>,
        call_count: AtomicUsize,
    }

    impl fmt::Debug for MockHttpClient {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.debug_struct("MockHttpClient")
                .field("calls", &self.call_count.load(Ordering::Relaxed))
                .finish()
        }
    }

    impl MockHttpClient {
        fn new() -> Self {
            Self {
                requests: Mutex::new(Vec::new()),
                responses: Mutex::new(VecDeque::new()),
                call_count: AtomicUsize::new(0),
            }
        }

        fn push_ok(&self, status: StatusCode, body: impl Into<Bytes>) {
            let body = body.into();
            self.responses.lock().unwrap().push_back(Box::new(move |_| {
                Ok(HttpResponse {
                    status,
                    headers: HeaderMap::new(),
                    body: body.clone(),
                })
            }));
        }

        fn push_err(&self, msg: &'static str) {
            self.responses.lock().unwrap().push_back(Box::new(move |_| {
                Err(HttpClientError::Transport(msg.to_owned()))
            }));
        }

        fn requests(&self) -> Vec<HttpRequest> {
            self.requests.lock().unwrap().clone()
        }

        fn calls(&self) -> usize {
            self.call_count.load(Ordering::Relaxed)
        }
    }

    impl HttpClient for MockHttpClient {
        fn send<'a>(
            &'a self,
            request: HttpRequest,
        ) -> BoxFuture<'a, Result<HttpResponse, HttpClientError>> {
            Box::pin(async move {
                self.call_count.fetch_add(1, Ordering::Relaxed);
                self.requests.lock().unwrap().push(request.clone());
                let handler = self.responses.lock().unwrap().pop_front().ok_or_else(|| {
                    HttpClientError::Transport("mock HttpClient queue exhausted".to_owned())
                })?;
                handler(&request)
            })
        }
    }

    #[test]
    fn rfc3339_parser_handles_utc_fractional_and_offsets() {
        assert_eq!(parse_rfc3339_utc_secs("1970-01-01T00:00:00Z").unwrap(), 0);
        assert_eq!(
            parse_rfc3339_utc_secs("2015-08-30T12:36:00Z").unwrap(),
            1_440_938_160
        );
        assert_eq!(
            parse_rfc3339_utc_secs("2015-08-30T12:36:00.987654Z").unwrap(),
            1_440_938_160
        );
        assert_eq!(
            parse_rfc3339_utc_secs("2015-08-30T18:06:00+05:30").unwrap(),
            1_440_938_160
        );
        assert_eq!(
            parse_rfc3339_utc_secs("2015-08-30T07:36:00-05:00").unwrap(),
            1_440_938_160
        );
        // Leap day 2024-02-29 valid; 2023-02-29 invalid.
        assert!(parse_rfc3339_utc_secs("2024-02-29T00:00:00Z").is_ok());
        assert!(parse_rfc3339_utc_secs("2023-02-29T00:00:00Z").is_err());
        assert!(parse_rfc3339_utc_secs("not-a-timestamp").is_err());
    }

    #[test]
    fn sts_xml_parser_extracts_credentials_and_unescapes_entities() {
        let xml = r#"<AssumeRoleResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">
          <AssumeRoleResult>
            <Credentials>
              <AccessKeyId>ASIAIOSFODNN7EXAMPLE</AccessKeyId>
              <SecretAccessKey>wJalrXUtnFEMI/K7MDENG/bPxRfiCY&amp;KEY</SecretAccessKey>
              <SessionToken>IQoJb3JpZ2luX2VjEC&lt;tok&gt;</SessionToken>
              <Expiration>2030-01-01T00:00:00Z</Expiration>
            </Credentials>
          </AssumeRoleResult>
        </AssumeRoleResponse>"#;
        let creds = parse_aws_sts_xml_credentials(xml).unwrap();
        assert_eq!(creds.access_key_id, "ASIAIOSFODNN7EXAMPLE");
        assert_eq!(
            creds.secret_access_key,
            "wJalrXUtnFEMI/K7MDENG/bPxRfiCY&KEY"
        );
        assert_eq!(
            creds.session_token.as_deref(),
            Some("IQoJb3JpZ2luX2VjEC<tok>")
        );
        assert!(creds.expiration_unix_secs.unwrap() > 1_890_000_000);
    }

    /// Test-only 2048-bit RSA PKCS#8 keypair used exclusively to verify RS256 JWT signing.
    const TEST_RSA_PKCS8_PEM: &str = concat!(
        "-----BEGIN ",
        "PRIVATE KEY-----\n",
        "MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQCiGQ0gptn4R29n\n",
        "bZuYy6fxh7+hFbzvsVu6c91zJY4vAbcd4REiEJdicBfq8lzgewEW/bbi6BspYdNx\n",
        "5OrDmEI6M/y8kFN593vofdAtSXXqaklWBFuEz8A+/pp5TW5NJ6G49KP9ziF506QG\n",
        "a520qWgj4/YBdJfH+UTc/Me8446ToxKyxc3upYYp1mENU2wMLxMCEArigfxsYRkI\n",
        "BCRApQGjJ0HIOg7mQS95h3CJGkMh5li+fQiJu74a89qI8P1rhQVvYD9O6uw4dqIz\n",
        "1sXUlXphrd9Py4aNEWxWQNseU+hm9KoydTvyO2R1gIjvyUyqXLd3FsCLjCubZOhR\n",
        "2cXR2uIRAgMBAAECggEAIS2LeFFub9j/PmY64M1edJtaZ7gxUcY1hjZM71KShaCO\n",
        "QHlermBC/A0BeD9fLzs9/9yyYEMtvAyf4MIAI0S42XzmkBniXCaBoBaQU5Sjo/VZ\n",
        "SVfe+5IiQUKPj6B/oR8phNfd8QcN5wegnQfN4bqC7EWuhqG8p1un8qtynoDdH+5/\n",
        "GGNG+qW5QeDUOqZoKaDw5WP+EBGsqBWtg6dps5SLhHE7f5A6JD7gEpSoPN6DjDhS\n",
        "6rBfMUfZTnZDBbisNuPGio5R5n5OGYQ4Q4S3fn5d4SyvEIrAU5WRAcYAffGYDM/U\n",
        "7VYWcLS3dhqoKqWQ6Zi5GWCMKSq/pYwyOTwoXt5G2QKBgQDfZK6+F8rAWKViR2ko\n",
        "DDv0Yp6d+TINCvyB1senohYSybdTQpmDsfsIJPdbHRmpHy8fPLu2zmUDq2TNP9ou\n",
        "YXR9Cb1s1qxp5iuWdkLFj5vT7mV2lYstF/Du7ItXac5Es2LuYQ+lcoKrZk5GUh6f\n",
        "Jwhalcu5KK9qaL7TT4uZVNW2hwKBgQC5wgChauYmIBXRGDvRQ0wLJnfi7dI6/3ud\n",
        "PF0r/MFBz2JrxxejDQROT7OQt5ASOqyNw80dozv15bNIwNTQza5pNOCvfcZXbD31\n",
        "Q5IwEnrr9wggt58HxPDEa4WbcoarjniflrYqxUge9IOOIKsHm6ZzgyzFA/6r5NMz\n",
        "yL03FGywpwKBgDrMo3oBhSpvqshdh341CirfMmTeTKBGPgRm5hJnhWvYkFpn80RI\n",
        "uoyAPmNLG4/6V0rfj4Ekfk4i9NtZbTI8EI9A2w0kzCjrnplx801Q6XE1FJvL7OAn\n",
        "pxEcTejqPpKyrN2Vyqp/o4k92miEAO9fNMGzH/ZSkSlu/JteGp53R/FNAoGANp2w\n",
        "28T3eDw0ze6nH8b+o8SiuSkdh9U4PinSZy2AkN3t3SyDaaBZJMFQVXtzM7jmpSPt\n",
        "ugoVhh4MUZbIu7/NyQcQDOkZGPktWmCMqe+1Do3qaNw0OO+Rrt7CQMsyh1xzYNDK\n",
        "LNcmdluEFpTKVIlSLmJiFmcvSNEVvAMIhxpNPr8CgYAq7COYeivC94c3ET28FqMb\n",
        "cSEy8lwf8AREvpaMBmEm9OnX5UTuq0wPQNFZ1m/MyTWzPefHSgMrvMKagJUGWs5R\n",
        "bcaHkdIR9r7eY3UGwQtSqGINwQL1AMf+Byt90PwJZfokJa0xkZUguWR+NVFKvIef\n",
        "XBf5WPxWUrKOGfs1mV/Jsw==\n",
        "-----END ",
        "PRIVATE KEY-----\n"
    );

    #[test]
    fn gcp_service_account_jwt_signs_and_verifies_with_ring() {
        let pem = TEST_RSA_PKCS8_PEM.to_owned();
        let der = decode_pem_pkcs8_private_key(&pem).unwrap();
        let ring_kp = RsaKeyPair::from_pkcs8(&der).unwrap();

        let sa = GcpServiceAccountKey {
            client_email: "shunt-gw@proj.iam.gserviceaccount.com".to_owned(),
            private_key: pem,
            private_key_id: Some("kid-123".to_owned()),
            token_uri: Some("https://oauth2.googleapis.com/token".to_owned()),
        };

        let jwt = sign_gcp_service_account_jwt(
            &sa,
            &["https://www.googleapis.com/auth/cloud-platform".to_owned()],
            "https://oauth2.googleapis.com/token",
            1_700_000_000,
        )
        .unwrap();

        let parts: Vec<&str> = jwt.split('.').collect();
        assert_eq!(parts.len(), 3);
        let signing_input = format!("{}.{}", parts[0], parts[1]);

        // Decode base64url signature back to bytes and verify cryptographically.
        let mut std_b64 = parts[2].replace('-', "+").replace('_', "/");
        while !std_b64.len().is_multiple_of(4) {
            std_b64.push('=');
        }
        let sig_bytes = base64_std_decode(&std_b64).unwrap();
        let pub_key =
            UnparsedPublicKey::new(&RSA_PKCS1_2048_8192_SHA256, ring_kp.public_key().as_ref());
        pub_key
            .verify(signing_input.as_bytes(), &sig_bytes)
            .unwrap();
    }

    #[tokio::test]
    async fn aws_imds_flow_caches_expires_and_stale_fallback_works() {
        let http = MockHttpClient::new();
        // Initial 3-step IMDSv2 fetch.
        http.push_ok(StatusCode::OK, "imds-session-tok-1");
        http.push_ok(StatusCode::OK, "bedrock-ec2-role\n");
        http.push_ok(
            StatusCode::OK,
            r#"{"AccessKeyId":"ASIA1","SecretAccessKey":"SEC1","Token":"STOK1","Expiration":"2099-01-01T00:00:00Z"}"#,
        );
        // Second fetch (during stale-while-valid window) fails transiently -> should fall back!
        http.push_err("imds temporarily unreachable");
        // Third fetch (after hard expiry) succeeds with rotated credentials.
        http.push_ok(StatusCode::OK, "imds-session-tok-2");
        http.push_ok(StatusCode::OK, "bedrock-ec2-role");
        http.push_ok(
            StatusCode::OK,
            r#"{"AccessKeyId":"ASIA2","SecretAccessKey":"SEC2","Token":"STOK2","Expiration":"2099-01-01T00:00:00Z"}"#,
        );

        let clock = ManualClock::shared();
        let cache = CloudTokenCache::default();
        let auth = CompiledCloudAuth::compile_aws(
            "bedrock",
            "us-east-1".to_owned(),
            AwsIamAuthConfig {
                mode: AwsIamMode::Imds,
                service: None,
                role_arn: None,
                role_session_name: None,
                external_id: None,
                session_duration_secs: None,
                web_identity_token_file: None,
                imds_endpoint: Some("http://127.0.0.1:16925".to_owned()),
                ecs_credentials_uri: None,
                ecs_auth_token: None,
                sts_endpoint: None,
                refresh_margin_secs: 15,
                max_cache_ttl_secs: Some(60),
                timeout_ms: 2000,
            },
        )
        .unwrap();

        // 1. Cold miss fetches IMDSv2 (3 calls).
        let c1 = cache
            .get_or_refresh(&auth, &http, clock.as_ref())
            .await
            .unwrap();
        assert_eq!(http.calls(), 3);
        match c1 {
            ResolvedCloudCredential::AwsSigV4(c) => {
                assert_eq!(c.access_key_id, "ASIA1");
                assert_eq!(c.session_token.as_deref(), Some("STOK1"));
            }
            _ => panic!("expected AwsSigV4"),
        }

        // 2. Warm hit at +30s (< 45s refresh_at) makes 0 HTTP calls.
        clock.advance(Duration::from_secs(30));
        let c2 = cache
            .get_or_refresh(&auth, &http, clock.as_ref())
            .await
            .unwrap();
        assert_eq!(http.calls(), 3);
        assert!(matches!(c2, ResolvedCloudCredential::AwsSigV4(c) if c.access_key_id == "ASIA1"));

        // 3. Proactive refresh window at +50s (>= 45s, < 60s): refresh fails transiently,
        //    so stale-while-valid fallback serves ASIA1 cleanly!
        clock.advance(Duration::from_secs(20));
        let c3 = cache
            .get_or_refresh(&auth, &http, clock.as_ref())
            .await
            .unwrap();
        assert_eq!(http.calls(), 4);
        assert!(matches!(c3, ResolvedCloudCredential::AwsSigV4(c) if c.access_key_id == "ASIA1"));

        // 4. Hard expiry at +65s (>= 60s): refreshes to ASIA2.
        clock.advance(Duration::from_secs(15));
        let c4 = cache
            .get_or_refresh(&auth, &http, clock.as_ref())
            .await
            .unwrap();
        assert_eq!(http.calls(), 7);
        assert!(matches!(c4, ResolvedCloudCredential::AwsSigV4(c) if c.access_key_id == "ASIA2"));
    }

    #[tokio::test]
    async fn singleflight_coalesces_concurrent_token_refreshes() {
        struct SlowTokenClient {
            calls: AtomicUsize,
        }
        impl fmt::Debug for SlowTokenClient {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("SlowTokenClient")
            }
        }
        impl HttpClient for SlowTokenClient {
            fn send<'a>(
                &'a self,
                _req: HttpRequest,
            ) -> BoxFuture<'a, Result<HttpResponse, HttpClientError>> {
                Box::pin(async move {
                    let n = self.calls.fetch_add(1, Ordering::SeqCst) + 1;
                    tokio::time::sleep(Duration::from_millis(30)).await;
                    Ok(HttpResponse {
                        status: StatusCode::OK,
                        headers: HeaderMap::new(),
                        body: Bytes::from(format!(
                            r#"{{"access_token":"tok-{n}","expires_in":3600}}"#
                        )),
                    })
                })
            }
        }

        let http = Arc::new(SlowTokenClient {
            calls: AtomicUsize::new(0),
        });
        let clock = ManualClock::shared();
        let cache = Arc::new(CloudTokenCache::default());
        let auth = Arc::new(
            CompiledCloudAuth::compile_gcp(
                "vertex",
                GcpIamAuthConfig {
                    mode: GcpIamMode::Metadata,
                    credentials_file: None,
                    credentials_json: None,
                    scopes: vec![],
                    metadata_endpoint: Some("http://127.0.0.1:18081".to_owned()),
                    token_uri: None,
                    service_account_email: None,
                    refresh_margin_secs: 300,
                    max_cache_ttl_secs: None,
                    timeout_ms: 2000,
                },
            )
            .unwrap(),
        );

        let mut handles = Vec::new();
        for _ in 0..8 {
            let cache_c = Arc::clone(&cache);
            let auth_c = Arc::clone(&auth);
            let http_c = Arc::clone(&http);
            let clock_c = Arc::clone(&clock);
            handles.push(tokio::spawn(async move {
                cache_c
                    .get_or_refresh(&auth_c, http_c.as_ref(), clock_c.as_ref())
                    .await
                    .unwrap()
            }));
        }

        for h in handles {
            let cred = h.await.unwrap();
            assert!(matches!(cred, ResolvedCloudCredential::BearerToken(t) if t == "tok-1"));
        }
        // All 8 concurrent requests must coalesce into a single HTTP token fetch.
        assert_eq!(http.calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn azure_imds_handles_string_expires_in_and_metadata_header() {
        let http = MockHttpClient::new();
        http.push_ok(
            StatusCode::OK,
            r#"{"access_token":"az-imds-tok","expires_in":"3599","token_type":"Bearer"}"#,
        );
        let clock = ManualClock::shared();
        let cache = CloudTokenCache::default();
        let auth = CompiledCloudAuth::compile_azure(
            "azure",
            AzureAdAuthConfig {
                mode: AzureAdMode::ManagedIdentity,
                tenant_id: None,
                client_id: Some("uami-123".to_owned()),
                client_secret: None,
                federated_token_file: None,
                scope: DEFAULT_AZURE_SCOPE.to_owned(),
                resource: None,
                authority_host: None,
                imds_endpoint: Some("http://127.0.0.1:16926".to_owned()),
                refresh_margin_secs: 300,
                max_cache_ttl_secs: None,
                timeout_ms: 2000,
            },
        )
        .unwrap();

        let cred = cache
            .get_or_refresh(&auth, &http, clock.as_ref())
            .await
            .unwrap();
        assert!(matches!(cred, ResolvedCloudCredential::BearerToken(t) if t == "az-imds-tok"));
        let reqs = http.requests();
        assert_eq!(reqs.len(), 1);
        assert_eq!(reqs[0].headers.get("metadata").unwrap(), "true");
        let uri_str = reqs[0].uri.to_string();
        assert!(uri_str.contains("api-version=2018-02-01"));
        assert!(uri_str.contains("resource=https%3A%2F%2Fcognitiveservices.azure.com"));
        assert!(uri_str.contains("client_id=uami-123"));
    }
}
