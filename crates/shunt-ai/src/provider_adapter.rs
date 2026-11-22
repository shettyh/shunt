use std::collections::{BTreeMap, HashMap, HashSet};
use std::fmt;
use std::sync::Arc;
use std::time::Duration;

use serde::Deserialize;
use serde_json::Value;
use shunt_plugin_sdk::{
    BuildContext, Bytes, Clock, Flow, HeaderName, HeaderValue, HookMask, HookResult, HttpClient,
    HttpPlugin, PluginBuildError, PluginConfig, PluginFactory, RequestCtx, ResponseHead,
    RouteDecision, StatusCode, StreamFlow, UpstreamRequest, Uri, header,
};
use tracing::{info, warn};

use crate::aws_sigv4::{AwsSigV4Credentials, sign_upstream_request};
use crate::cache::{AiCachePending, AiTranslatedResponseBody};
use crate::cloud_auth::{
    AwsIamAuthConfig, AzureAdAuthConfig, CacheLookup, CloudTokenCache, CompiledCloudAuth,
    GcpIamAuthConfig, ResolvedCloudCredential,
};
use crate::dialects::bedrock::{
    BedrockStreamTranslator, bedrock_converse_path, bedrock_converse_to_openai_response,
    bedrock_embeddings_to_openai_response, bedrock_invoke_path,
    openai_to_bedrock_converse_request_for_model, openai_to_bedrock_embeddings_request,
};
use crate::dialects::gemini::{
    GeminiSseTranslator, gemini_chat_path, gemini_embeddings_path,
    gemini_to_openai_embeddings_response, gemini_to_openai_response,
    openai_to_gemini_embeddings_request, openai_to_gemini_request,
};
use crate::failover::compute_cooldown;
use crate::ingress::anthropic::{
    OpenAiToAnthropicSseTranslator, anthropic_to_openai_request, openai_to_anthropic_response,
    rewrite_anthropic_request,
};
use crate::ingress::responses::{
    ChatToResponsesSseTranslator, chat_to_responses_response, responses_to_chat_request,
    rewrite_openai_responses_request,
};
use crate::presets::{
    DefaultAuthShape, KeyPoolTable, ProviderPreset, default_auth_shape_for_dialect,
};
use crate::translate::{
    AnthropicSseTranslator, DropParamsConfig, adapt_anthropic_body_for_vertex,
    anthropic_to_openai_response, apply_request_param_transforms, openai_to_anthropic_request,
    rewrite_openai_embeddings_request, rewrite_openai_request, vertex_anthropic_path,
};
use crate::types::{
    AiEndpointKind, AiRequestMeta, IntraProviderKeyRetry, ProviderDialect, endpoint_error_response,
    percent_encode_path_segment, resolve_env_secret,
};

const DEFAULT_OPENAI_CHAT_PATH: &str = "/v1/chat/completions";
const DEFAULT_OPENAI_EMBEDDINGS_PATH: &str = "/v1/embeddings";
const DEFAULT_ANTHROPIC_PATH: &str = "/v1/messages";
const DEFAULT_ANTHROPIC_VERSION: &str = "2023-06-01";
const DEFAULT_ANTHROPIC_MAX_TOKENS: u64 = 4096;
const DEFAULT_AZURE_API_VERSION: &str = "2024-10-21";
const DEFAULT_BEDROCK_SERVICE: &str = "bedrock";
const DEFAULT_MAX_NON_STREAM_RESPONSE_BYTES: usize = 16 * 1024 * 1024; // 16 MiB
const DEFAULT_KEY_COOLDOWN_MS: u64 = 30_000;
const MAX_KEY_POOL_AUTO_ATTEMPTS: usize = 16;

fn default_auth_none() -> ProviderAuthConfig {
    ProviderAuthConfig::None
}

fn default_key_cooldown_ms() -> u64 {
    DEFAULT_KEY_COOLDOWN_MS
}

fn default_key_rotate_statuses() -> Vec<u16> {
    vec![429, 401, 403]
}

/// Authentication mechanism attached to an upstream provider instance.
///
/// Every secret field (`api_key`, `api_keys`, `secret_access_key`, `session_token`) uses canonical
/// redaction-matched names so `GET /snapshot` redacts all credentials automatically.
#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ProviderAuthConfig {
    None,
    Bearer {
        #[serde(default)]
        api_key: Option<String>,
        #[serde(default)]
        api_keys: Vec<String>,
    },
    Header {
        header: String,
        #[serde(default)]
        api_key: Option<String>,
        #[serde(default)]
        api_keys: Vec<String>,
        #[serde(default)]
        prefix: Option<String>,
    },
    #[serde(rename = "aws_sigv4")]
    AwsSigv4 {
        access_key_id: String,
        secret_access_key: String,
        #[serde(default)]
        session_token: Option<String>,
        #[serde(default)]
        service: Option<String>,
    },
    /// Client BYOK passthrough: extracts the caller's API key from the incoming request
    /// (optional `source_header`, or standard `x-api-key` / `x-goog-api-key` / `api-key` /
    /// `Authorization: Bearer ...`) and injects it into the upstream provider's expected auth header.
    #[serde(rename = "client_passthrough")]
    ClientPassthrough {
        #[serde(default)]
        source_header: Option<String>,
        #[serde(default)]
        header: Option<String>,
        #[serde(default)]
        prefix: Option<String>,
    },
    /// Dynamic AWS IAM credentials (EC2 IMDSv2, ECS Task Role, EKS IRSA, env, STS `AssumeRole`)
    /// cached in `StateStore` and used to sign upstream requests via SigV4.
    #[serde(rename = "aws_iam")]
    AwsIam(AwsIamAuthConfig),
    /// Dynamic Google Cloud IAM credentials (GCE/GKE Metadata Server / Workload Identity,
    /// Service Account JSON RS256 JWT, or ADC `authorized_user`) injecting a Bearer token.
    #[serde(rename = "gcp_iam")]
    GcpIam(GcpIamAuthConfig),
    /// Dynamic Microsoft Entra ID credentials (Azure Managed Identity IMDS, Service Principal
    /// `client_credentials`, or AKS Workload Identity) injecting a Bearer token.
    #[serde(rename = "azure_ad")]
    AzureAd(AzureAdAuthConfig),
}

/// Declarative configuration for a single named provider instance in `providers.<name>`.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderInstanceConfig {
    /// Optional built-in provider preset (`openai`, `anthropic`, `gemini`, `azure_openai`,
    /// `bedrock`, `groq`, `deepseek`, `fireworks`, `together`, `mistral`, `cohere`, `xai`,
    /// `openrouter`, `ollama`, `vllm`) supplying canonical dialect, paths, and auth header shape.
    #[serde(default)]
    pub preset: Option<ProviderPreset>,
    /// Wire dialect spoken by this provider (optional when `preset` is specified).
    #[serde(default)]
    pub dialect: Option<ProviderDialect>,
    #[serde(default = "default_auth_none")]
    pub auth: ProviderAuthConfig,
    /// Ergonomic single-key shorthand using the preset/dialect's default auth header.
    #[serde(default)]
    pub api_key: Option<String>,
    /// Ergonomic multi-key pool shorthand using the preset/dialect's default auth header,
    /// rotating keys round-robin with automatic `429`/`401`/`403` cooldowns.
    #[serde(default)]
    pub api_keys: Vec<String>,
    /// Cooldown duration (ms) applied to a pooled upstream API key after a rotatable error
    /// (default: `30_000`).
    #[serde(default = "default_key_cooldown_ms")]
    pub key_cooldown_ms: u64,
    /// Upstream HTTP status codes that cool down the active pooled key and trigger immediate
    /// intra-provider key rotation (default: `[429, 401, 403]`).
    #[serde(default = "default_key_rotate_statuses")]
    pub key_rotate_statuses: Vec<u16>,
    /// Override chat completions path (used by `openai_compatible` and `anthropic`).
    #[serde(default)]
    pub chat_path: Option<String>,
    /// Override embeddings path (used by `openai_compatible`).
    #[serde(default)]
    pub embeddings_path: Option<String>,
    /// Optional native OpenAI Responses API path (e.g., `"/v1/responses"` or
    /// `"/openai/v1/responses"`). When configured on `openai_compatible` or `azure_openai`,
    /// `POST /v1/responses` uses zero-translation native passthrough; when omitted,
    /// `/v1/responses` transparently translates through Chat Completions.
    #[serde(default)]
    pub responses_path: Option<String>,
    /// OpenAI-compatible: inject `stream_options.include_usage = true` on streaming chat
    /// (default: `true`, or preset default e.g. `false` for `mistral`).
    #[serde(default)]
    pub include_stream_usage: Option<bool>,
    /// OpenAI-compatible: optional `OpenAI-Organization` header.
    #[serde(default)]
    pub organization: Option<String>,
    /// OpenAI-compatible: optional `OpenAI-Project` header.
    #[serde(default)]
    pub project: Option<String>,
    /// Anthropic: `anthropic-version` header (default: `"2023-06-01"`, or `"vertex-2023-10-16"`
    /// in the JSON body when `vertex_project` & `vertex_location` are set).
    #[serde(default)]
    pub anthropic_version: Option<String>,
    /// Anthropic: fallback `max_tokens` when client omits it (default: `4096`).
    #[serde(default)]
    pub default_max_tokens: Option<u64>,
    /// Azure OpenAI: `?api-version=` query value (default: `"2024-10-21"`).
    #[serde(default)]
    pub api_version: Option<String>,
    /// Google Cloud Vertex AI project ID (used by `gemini` and Claude-on-Vertex `anthropic`;
    /// requires `vertex_location`).
    #[serde(default)]
    pub vertex_project: Option<String>,
    /// Google Cloud Vertex AI location (e.g., `"us-central1"` or `"us-east5"`; requires `vertex_project`).
    #[serde(default)]
    pub vertex_location: Option<String>,
    /// AWS Bedrock region (e.g., `"us-east-1"`, required for `aws_sigv4`).
    #[serde(default)]
    pub region: Option<String>,
    /// LiteLLM-style parameter dropping: `true` strips unsupported cross-dialect params, or
    /// pass an explicit list of top-level keys to strip (default: `false`).
    #[serde(default)]
    pub drop_params: DropParamsConfig,
    /// Per-provider default JSON request parameters applied when absent/null in the client body.
    #[serde(default)]
    pub default_params: BTreeMap<String, Value>,
    /// Per-provider JSON request parameter overrides injected unconditionally before translation.
    #[serde(default)]
    pub override_params: BTreeMap<String, Value>,
    /// Arbitrary extra static headers attached on upstream requests.
    #[serde(default)]
    pub extra_headers: HashMap<String, String>,
}

#[derive(Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct AiProviderAdapterConfig {
    /// Named provider instances (e.g. `providers.openai`, `providers.ollama`, `providers.bedrock`).
    providers: HashMap<String, ProviderInstanceConfig>,
    /// Attach `x-shunt-provider`, `x-shunt-model`, `x-shunt-attempt` (and `x-shunt-key-index` for pools).
    response_headers: bool,
    /// Safety cap when buffering non-streaming JSON responses for translation.
    max_non_stream_response_bytes: usize,
}

impl Default for AiProviderAdapterConfig {
    fn default() -> Self {
        Self {
            providers: HashMap::new(),
            response_headers: true,
            max_non_stream_response_bytes: DEFAULT_MAX_NON_STREAM_RESPONSE_BYTES,
        }
    }
}

enum CompiledAuth {
    None,
    StaticHeader(HeaderName, HeaderValue),
    HeaderPool(HeaderName, Vec<HeaderValue>),
    AwsSigV4(AwsSigV4Credentials),
    ClientPassthrough {
        source_header: Option<HeaderName>,
        target_header: HeaderName,
        target_prefix: Option<String>,
    },
    CloudIam(Arc<CompiledCloudAuth>),
}

impl CompiledAuth {
    fn pool_len(&self) -> usize {
        match self {
            CompiledAuth::HeaderPool(_, vals) => vals.len(),
            _ => 1,
        }
    }

    fn is_cloud_iam(&self) -> bool {
        matches!(self, CompiledAuth::CloudIam(_))
    }
}

struct CompiledProvider {
    dialect: ProviderDialect,
    auth: CompiledAuth,
    key_cooldown: Duration,
    key_rotate_statuses: HashSet<u16>,
    chat_path: Uri,
    embeddings_path: Uri,
    responses_path: Option<Uri>,
    include_stream_usage: bool,
    organization: Option<HeaderValue>,
    project: Option<HeaderValue>,
    anthropic_version: HeaderValue,
    anthropic_version_raw: String,
    default_max_tokens: u64,
    api_version: String,
    vertex: Option<(String, String)>,
    drop_params: DropParamsConfig,
    default_params: BTreeMap<String, Value>,
    override_params: BTreeMap<String, Value>,
    extra_headers: Vec<(HeaderName, HeaderValue)>,
}

/// Active pooled key selected for the ongoing upstream attempt.
#[derive(Debug, Clone)]
struct ActiveProviderKey {
    provider: String,
    key_index: usize,
    pool_len: usize,
}

/// Tracks key indices already attempted on the current provider during this request.
#[derive(Debug, Clone)]
struct TriedProviderKeys {
    provider: String,
    tried: Vec<usize>,
}

/// Cached caller BYOK credential for retries (Debug implementation intentionally redacts value).
#[derive(Clone)]
struct ClientByokCredential(String);

impl fmt::Debug for ClientByokCredential {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ClientByokCredential([REDACTED])")
    }
}

/// Tracks dynamic cloud auth providers that already performed one forced refresh retry
/// on the current request (prevents infinite retry loops on permanent 401/403 errors).
#[derive(Debug, Default, Clone)]
struct CloudAuthRefreshedProviders(HashSet<String>);

/// Target client ingress response format.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum IngressResponseFormat {
    OpenAiChat,
    AnthropicMessages,
    OpenAiResponses,
}

/// Stage 1 of streaming response translation: upstream wire format -> canonical OpenAI SSE.
#[derive(Debug, Clone)]
enum UpstreamStreamStage {
    OpenAiSse,
    AnthropicSse(Box<AnthropicSseTranslator>),
    GeminiSse(Box<GeminiSseTranslator>),
    BedrockStream(Box<BedrockStreamTranslator>),
}

impl UpstreamStreamStage {
    fn push_chunk(&mut self, chunk: &Bytes) -> Bytes {
        match self {
            UpstreamStreamStage::OpenAiSse => chunk.clone(),
            UpstreamStreamStage::AnthropicSse(tr) => tr.push_chunk(chunk),
            UpstreamStreamStage::GeminiSse(tr) => tr.push_chunk(chunk),
            UpstreamStreamStage::BedrockStream(tr) => tr.push_chunk(chunk),
        }
    }

    fn finish(&mut self) -> Bytes {
        match self {
            UpstreamStreamStage::OpenAiSse => Bytes::new(),
            UpstreamStreamStage::AnthropicSse(tr) => tr.finish(),
            UpstreamStreamStage::GeminiSse(tr) => tr.finish(),
            UpstreamStreamStage::BedrockStream(tr) => tr.finish(),
        }
    }
}

/// Stage 2 of streaming response translation: canonical OpenAI SSE -> client ingress SSE.
#[derive(Debug, Clone)]
enum IngressStreamStage {
    Identity,
    ToAnthropic(Box<OpenAiToAnthropicSseTranslator>),
    ToResponses(Box<ChatToResponsesSseTranslator>),
}

impl IngressStreamStage {
    fn push_chunk(&mut self, chunk: &Bytes) -> Bytes {
        match self {
            IngressStreamStage::Identity => chunk.clone(),
            IngressStreamStage::ToAnthropic(tr) => tr.push_chunk(chunk),
            IngressStreamStage::ToResponses(tr) => tr.push_chunk(chunk),
        }
    }

    fn finish(&mut self) -> Bytes {
        match self {
            IngressStreamStage::Identity => Bytes::new(),
            IngressStreamStage::ToAnthropic(tr) => tr.finish(),
            IngressStreamStage::ToResponses(tr) => tr.finish(),
        }
    }
}

/// Stage 1 kind for buffered non-streaming JSON responses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum UpstreamJsonKind {
    OpenAi,
    Anthropic,
    Gemini,
    GeminiEmbeddings,
    Bedrock,
    BedrockEmbeddings,
}

impl UpstreamJsonKind {
    const fn label(self) -> &'static str {
        match self {
            UpstreamJsonKind::OpenAi => "OpenAI",
            UpstreamJsonKind::Anthropic => "Anthropic",
            UpstreamJsonKind::Gemini => "Gemini",
            UpstreamJsonKind::GeminiEmbeddings => "Gemini embeddings",
            UpstreamJsonKind::Bedrock => "Bedrock",
            UpstreamJsonKind::BedrockEmbeddings => "Bedrock embeddings",
        }
    }
}

/// Per-request response translation state stored in `RequestCtx::extensions`.
#[derive(Debug, Clone)]
enum AdapterResponseState {
    /// Native same-protocol passthrough (zero parsing/copy overhead).
    Passthrough,
    /// Two-stage live streaming translator: upstream -> canonical OpenAI SSE -> ingress SSE.
    Streaming {
        upstream: UpstreamStreamStage,
        ingress: IngressStreamStage,
    },
    /// Two-stage buffered JSON translator: upstream JSON -> canonical OpenAI JSON -> ingress JSON.
    BufferedJson {
        upstream: UpstreamJsonKind,
        ingress: IngressResponseFormat,
        status: StatusCode,
        fallback_model: String,
        buffer: Vec<u8>,
    },
}

/// Factory for the `ai-provider-adapter` plugin.
pub struct AiProviderAdapterFactory;

impl PluginFactory for AiProviderAdapterFactory {
    fn name(&self) -> &str {
        "ai-provider-adapter"
    }

    fn build(
        &self,
        config: &PluginConfig,
        ctx: &BuildContext,
    ) -> Result<Arc<dyn HttpPlugin>, PluginBuildError> {
        let cfg: AiProviderAdapterConfig = config.deserialize(self.name())?;

        if cfg.providers.is_empty() {
            return Err(PluginBuildError::BuildFailed {
                plugin: self.name().to_owned(),
                message: "configure at least one provider under `providers.<name>`".to_owned(),
            });
        }

        let mut compiled = HashMap::with_capacity(cfg.providers.len());
        let mut has_key_pools = false;
        let mut has_dynamic_auth = false;
        for (name, pcfg) in cfg.providers {
            if name.trim().is_empty() {
                return Err(PluginBuildError::BuildFailed {
                    plugin: self.name().to_owned(),
                    message: "provider name in `providers` cannot be empty".to_owned(),
                });
            }
            let cp = compile_provider(self.name(), &name, pcfg)?;
            if cp.auth.pool_len() > 1 {
                has_key_pools = true;
            }
            if cp.auth.is_cloud_iam() {
                has_dynamic_auth = true;
            }
            compiled.insert(name, cp);
        }

        let key_pools = if has_key_pools {
            Some(
                ctx.state_handle()
                    .get_or_init("ai_key_pools", KeyPoolTable::default),
            )
        } else {
            None
        };

        let (http_client, cloud_tokens) = if has_dynamic_auth {
            let client = ctx.http_client().ok_or_else(|| PluginBuildError::BuildFailed {
                plugin: self.name().to_owned(),
                message: "dynamic cloud IAM auth (`aws_iam`, `gcp_iam`, `azure_ad`) requires a runtime HttpClient in BuildContext".to_owned(),
            })?;
            let cache = ctx
                .state_handle()
                .get_or_init("ai_cloud_tokens", CloudTokenCache::default);
            (Some(client), Some(cache))
        } else {
            (None, None)
        };

        Ok(Arc::new(AiProviderAdapterPlugin {
            providers: compiled,
            response_headers: cfg.response_headers,
            max_non_stream_response_bytes: cfg.max_non_stream_response_bytes.max(1024),
            has_key_pools,
            has_dynamic_auth,
            clock: ctx.clock(),
            key_pools,
            http_client,
            cloud_tokens,
        }))
    }
}

fn compile_key_list(
    plugin: &str,
    field_prefix: &str,
    single: Option<String>,
    many: Vec<String>,
) -> Result<Vec<String>, PluginBuildError> {
    if single.is_some() && !many.is_empty() {
        return Err(PluginBuildError::BuildFailed {
            plugin: plugin.to_owned(),
            message: format!("`{field_prefix}` cannot specify both `api_key` and `api_keys`"),
        });
    }
    let raw_keys: Vec<String> = match single {
        Some(k) => vec![k],
        None => many,
    };
    if raw_keys.is_empty() {
        return Err(PluginBuildError::BuildFailed {
            plugin: plugin.to_owned(),
            message: format!("`{field_prefix}` requires `api_key` or a non-empty `api_keys` list"),
        });
    }
    let mut resolved = Vec::with_capacity(raw_keys.len());
    for (idx, raw) in raw_keys.into_iter().enumerate() {
        let secret = resolve_env_secret(&raw).map_err(|msg| PluginBuildError::BuildFailed {
            plugin: plugin.to_owned(),
            message: format!("{field_prefix}[{idx}]: {msg}"),
        })?;
        if secret.trim().is_empty() {
            return Err(PluginBuildError::BuildFailed {
                plugin: plugin.to_owned(),
                message: format!("{field_prefix}[{idx}] resolved to an empty key"),
            });
        }
        resolved.push(secret);
    }
    Ok(resolved)
}

fn compile_header_auth(
    plugin: &str,
    field_prefix: &str,
    header_name: HeaderName,
    prefix: Option<&str>,
    secrets: Vec<String>,
) -> Result<CompiledAuth, PluginBuildError> {
    let mut values = Vec::with_capacity(secrets.len());
    for secret in secrets {
        let full = match prefix {
            Some(p) => format!("{p}{secret}"),
            None => secret,
        };
        let hv = HeaderValue::from_str(&full).map_err(|e| PluginBuildError::BuildFailed {
            plugin: plugin.to_owned(),
            message: format!("invalid {field_prefix} header value: {e}"),
        })?;
        values.push(hv);
    }
    if values.len() == 1 {
        Ok(CompiledAuth::StaticHeader(
            header_name,
            values.into_iter().next().unwrap(),
        ))
    } else {
        Ok(CompiledAuth::HeaderPool(header_name, values))
    }
}

fn compile_provider(
    plugin: &str,
    provider_name: &str,
    cfg: ProviderInstanceConfig,
) -> Result<CompiledProvider, PluginBuildError> {
    let prefix = format!("providers.{provider_name}");
    let preset_defaults = cfg.preset.map(ProviderPreset::defaults);

    let dialect = match (cfg.dialect, preset_defaults) {
        (Some(d), _) => d,
        (None, Some(pd)) => pd.dialect,
        (None, None) => {
            return Err(PluginBuildError::BuildFailed {
                plugin: plugin.to_owned(),
                message: format!("`{prefix}` must specify either `dialect` or `preset`"),
            });
        }
    };

    if cfg.vertex_project.is_some() != cfg.vertex_location.is_some() {
        return Err(PluginBuildError::BuildFailed {
            plugin: plugin.to_owned(),
            message: format!(
                "`{prefix}` must specify both `vertex_project` and `vertex_location` together"
            ),
        });
    }
    let vertex = match (cfg.vertex_project, cfg.vertex_location) {
        (Some(proj), Some(loc)) => {
            if proj.trim().is_empty() || loc.trim().is_empty() {
                return Err(PluginBuildError::BuildFailed {
                    plugin: plugin.to_owned(),
                    message: format!(
                        "`{prefix}.vertex_project` and `vertex_location` cannot be empty"
                    ),
                });
            }
            Some((proj, loc))
        }
        _ => None,
    };

    let has_shorthand_keys = cfg.api_key.is_some() || !cfg.api_keys.is_empty();
    let has_explicit_auth = !matches!(cfg.auth, ProviderAuthConfig::None);
    if has_shorthand_keys && has_explicit_auth {
        return Err(PluginBuildError::BuildFailed {
            plugin: plugin.to_owned(),
            message: format!(
                "`{prefix}` cannot combine top-level `api_key`/`api_keys` with explicit `auth`"
            ),
        });
    }

    let default_shape = if vertex.is_some() {
        default_auth_shape_for_dialect(dialect, true)
    } else if let Some(pd) = preset_defaults {
        pd.default_auth
    } else {
        default_auth_shape_for_dialect(dialect, false)
    };

    let auth = if has_shorthand_keys {
        let secrets = compile_key_list(
            plugin,
            &format!("{prefix}.api_key"),
            cfg.api_key,
            cfg.api_keys,
        )?;
        let effective_shape = match default_shape {
            DefaultAuthShape::None => DefaultAuthShape::Bearer,
            other => other,
        };
        let header_name = effective_shape
            .header_name()
            .unwrap_or(header::AUTHORIZATION);
        compile_header_auth(
            plugin,
            &format!("{prefix}.api_key"),
            header_name,
            effective_shape.prefix(),
            secrets,
        )?
    } else {
        match cfg.auth {
            ProviderAuthConfig::None => CompiledAuth::None,
            ProviderAuthConfig::Bearer { api_key, api_keys } => {
                let secrets =
                    compile_key_list(plugin, &format!("{prefix}.auth"), api_key, api_keys)?;
                compile_header_auth(
                    plugin,
                    &format!("{prefix}.auth"),
                    header::AUTHORIZATION,
                    Some("Bearer "),
                    secrets,
                )?
            }
            ProviderAuthConfig::Header {
                header: header_name,
                api_key,
                api_keys,
                prefix: val_prefix,
            } => {
                let hn = HeaderName::from_bytes(header_name.as_bytes()).map_err(|e| {
                    PluginBuildError::BuildFailed {
                        plugin: plugin.to_owned(),
                        message: format!("invalid {prefix}.auth.header `{header_name}`: {e}"),
                    }
                })?;
                let secrets =
                    compile_key_list(plugin, &format!("{prefix}.auth"), api_key, api_keys)?;
                compile_header_auth(
                    plugin,
                    &format!("{prefix}.auth"),
                    hn,
                    val_prefix.as_deref(),
                    secrets,
                )?
            }
            ProviderAuthConfig::AwsSigv4 {
                access_key_id,
                secret_access_key,
                session_token,
                service,
            } => {
                let raw_region = cfg
                    .region
                    .as_deref()
                    .map(str::trim)
                    .filter(|r| !r.is_empty())
                    .ok_or_else(|| PluginBuildError::BuildFailed {
                        plugin: plugin.to_owned(),
                        message: format!(
                            "`{prefix}.region` is required when using `auth.type = \"aws_sigv4\"`"
                        ),
                    })?;
                let region = resolve_env_secret(raw_region).map_err(|msg| {
                    PluginBuildError::BuildFailed {
                        plugin: plugin.to_owned(),
                        message: format!("{prefix}.region: {msg}"),
                    }
                })?;
                let ak = resolve_env_secret(&access_key_id).map_err(|msg| {
                    PluginBuildError::BuildFailed {
                        plugin: plugin.to_owned(),
                        message: format!("{prefix}.auth.access_key_id: {msg}"),
                    }
                })?;
                let sk = resolve_env_secret(&secret_access_key).map_err(|msg| {
                    PluginBuildError::BuildFailed {
                        plugin: plugin.to_owned(),
                        message: format!("{prefix}.auth.secret_access_key: {msg}"),
                    }
                })?;
                let st = match session_token {
                    Some(raw) => Some(resolve_env_secret(&raw).map_err(|msg| {
                        PluginBuildError::BuildFailed {
                            plugin: plugin.to_owned(),
                            message: format!("{prefix}.auth.session_token: {msg}"),
                        }
                    })?),
                    None => None,
                };
                CompiledAuth::AwsSigV4(AwsSigV4Credentials {
                    access_key_id: ak,
                    secret_access_key: sk,
                    session_token: st,
                    region,
                    service: service.unwrap_or_else(|| DEFAULT_BEDROCK_SERVICE.to_owned()),
                })
            }
            ProviderAuthConfig::ClientPassthrough {
                source_header,
                header: target_header_raw,
                prefix: target_prefix_raw,
            } => {
                let source_hn = match source_header {
                    Some(raw) => Some(HeaderName::from_bytes(raw.as_bytes()).map_err(|e| {
                        PluginBuildError::BuildFailed {
                            plugin: plugin.to_owned(),
                            message: format!("invalid {prefix}.auth.source_header `{raw}`: {e}"),
                        }
                    })?),
                    None => None,
                };
                let (target_header, target_prefix) = match target_header_raw {
                    Some(raw) => {
                        let hn = HeaderName::from_bytes(raw.as_bytes()).map_err(|e| {
                            PluginBuildError::BuildFailed {
                                plugin: plugin.to_owned(),
                                message: format!("invalid {prefix}.auth.header `{raw}`: {e}"),
                            }
                        })?;
                        (hn, target_prefix_raw)
                    }
                    None => {
                        let effective = match default_shape {
                            DefaultAuthShape::None => DefaultAuthShape::Bearer,
                            other => other,
                        };
                        (
                            effective.header_name().unwrap_or(header::AUTHORIZATION),
                            target_prefix_raw.or_else(|| effective.prefix().map(str::to_owned)),
                        )
                    }
                };
                CompiledAuth::ClientPassthrough {
                    source_header: source_hn,
                    target_header,
                    target_prefix,
                }
            }
            ProviderAuthConfig::AwsIam(aws_cfg) => {
                let raw_region = cfg
                    .region
                    .as_deref()
                    .map(str::trim)
                    .filter(|r| !r.is_empty())
                    .ok_or_else(|| PluginBuildError::BuildFailed {
                        plugin: plugin.to_owned(),
                        message: format!(
                            "`{prefix}.region` is required when using `auth.type = \"aws_iam\"`"
                        ),
                    })?;
                let region = resolve_env_secret(raw_region).map_err(|msg| {
                    PluginBuildError::BuildFailed {
                        plugin: plugin.to_owned(),
                        message: format!("{prefix}.region: {msg}"),
                    }
                })?;
                let compiled = CompiledCloudAuth::compile_aws(provider_name, region, aws_cfg)
                    .map_err(|e| PluginBuildError::BuildFailed {
                        plugin: plugin.to_owned(),
                        message: format!("{prefix}.auth: {e}"),
                    })?;
                CompiledAuth::CloudIam(Arc::new(compiled))
            }
            ProviderAuthConfig::GcpIam(gcp_cfg) => {
                let compiled =
                    CompiledCloudAuth::compile_gcp(provider_name, gcp_cfg).map_err(|e| {
                        PluginBuildError::BuildFailed {
                            plugin: plugin.to_owned(),
                            message: format!("{prefix}.auth: {e}"),
                        }
                    })?;
                CompiledAuth::CloudIam(Arc::new(compiled))
            }
            ProviderAuthConfig::AzureAd(azure_cfg) => {
                let compiled =
                    CompiledCloudAuth::compile_azure(provider_name, azure_cfg).map_err(|e| {
                        PluginBuildError::BuildFailed {
                            plugin: plugin.to_owned(),
                            message: format!("{prefix}.auth: {e}"),
                        }
                    })?;
                CompiledAuth::CloudIam(Arc::new(compiled))
            }
        }
    };

    let default_chat_path = preset_defaults
        .map(|pd| pd.chat_path)
        .unwrap_or(match dialect {
            ProviderDialect::Anthropic => DEFAULT_ANTHROPIC_PATH,
            _ => DEFAULT_OPENAI_CHAT_PATH,
        });
    let raw_chat_path = cfg.chat_path.as_deref().unwrap_or(default_chat_path);
    let chat_path: Uri = raw_chat_path
        .parse()
        .map_err(|e| PluginBuildError::BuildFailed {
            plugin: plugin.to_owned(),
            message: format!("invalid {prefix}.chat_path `{raw_chat_path}`: {e}"),
        })?;

    let default_emb_path = preset_defaults
        .map(|pd| pd.embeddings_path)
        .unwrap_or(DEFAULT_OPENAI_EMBEDDINGS_PATH);
    let raw_emb_path = cfg.embeddings_path.as_deref().unwrap_or(default_emb_path);
    let embeddings_path: Uri = raw_emb_path
        .parse()
        .map_err(|e| PluginBuildError::BuildFailed {
            plugin: plugin.to_owned(),
            message: format!("invalid {prefix}.embeddings_path `{raw_emb_path}`: {e}"),
        })?;

    let raw_responses_path = cfg
        .responses_path
        .as_deref()
        .or_else(|| preset_defaults.and_then(|pd| pd.responses_path));
    let responses_path: Option<Uri> = match raw_responses_path {
        Some(raw) => Some(raw.parse().map_err(|e| PluginBuildError::BuildFailed {
            plugin: plugin.to_owned(),
            message: format!("invalid {prefix}.responses_path `{raw}`: {e}"),
        })?),
        None => None,
    };

    let include_stream_usage = cfg.include_stream_usage.unwrap_or_else(|| {
        preset_defaults
            .map(|pd| pd.include_stream_usage)
            .unwrap_or(true)
    });

    let organization = parse_optional_header(
        plugin,
        &format!("{prefix}.organization"),
        cfg.organization.as_deref(),
    )?;
    let project =
        parse_optional_header(plugin, &format!("{prefix}.project"), cfg.project.as_deref())?;

    let raw_anth_ver = cfg
        .anthropic_version
        .as_deref()
        .unwrap_or(DEFAULT_ANTHROPIC_VERSION);
    let anthropic_version =
        HeaderValue::from_str(raw_anth_ver).map_err(|e| PluginBuildError::BuildFailed {
            plugin: plugin.to_owned(),
            message: format!("invalid {prefix}.anthropic_version: {e}"),
        })?;

    let extra_headers = compile_extra_headers(plugin, &cfg.extra_headers)?;

    Ok(CompiledProvider {
        dialect,
        auth,
        key_cooldown: Duration::from_millis(cfg.key_cooldown_ms),
        key_rotate_statuses: cfg.key_rotate_statuses.into_iter().collect(),
        chat_path,
        embeddings_path,
        responses_path,
        include_stream_usage,
        organization,
        project,
        anthropic_version,
        anthropic_version_raw: raw_anth_ver.to_owned(),
        default_max_tokens: cfg
            .default_max_tokens
            .unwrap_or(DEFAULT_ANTHROPIC_MAX_TOKENS)
            .max(1),
        api_version: cfg
            .api_version
            .unwrap_or_else(|| DEFAULT_AZURE_API_VERSION.to_owned()),
        vertex,
        drop_params: cfg.drop_params,
        default_params: cfg.default_params,
        override_params: cfg.override_params,
        extra_headers,
    })
}

fn parse_optional_header(
    plugin: &str,
    field: &str,
    value: Option<&str>,
) -> Result<Option<HeaderValue>, PluginBuildError> {
    match value {
        Some(v) => HeaderValue::from_str(v)
            .map(Some)
            .map_err(|e| PluginBuildError::BuildFailed {
                plugin: plugin.to_owned(),
                message: format!("invalid header value for `{field}`: {e}"),
            }),
        None => Ok(None),
    }
}

fn compile_extra_headers(
    plugin: &str,
    map: &HashMap<String, String>,
) -> Result<Vec<(HeaderName, HeaderValue)>, PluginBuildError> {
    let mut out = Vec::with_capacity(map.len());
    for (k, v) in map {
        let name =
            HeaderName::from_bytes(k.as_bytes()).map_err(|e| PluginBuildError::BuildFailed {
                plugin: plugin.to_owned(),
                message: format!("invalid header name `{k}`: {e}"),
            })?;
        let val = HeaderValue::from_str(v).map_err(|e| PluginBuildError::BuildFailed {
            plugin: plugin.to_owned(),
            message: format!("invalid header value for `{k}`: {e}"),
        })?;
        out.push((name, val));
    }
    Ok(out)
}

fn extract_client_byok_secret(
    headers: &shunt_plugin_sdk::HeaderMap,
    source_header: Option<&HeaderName>,
) -> Option<String> {
    let extract_val = |hn: &HeaderName| -> Option<String> {
        let raw = headers.get(hn)?.to_str().ok()?.trim();
        if raw.is_empty() {
            return None;
        }
        if *hn == header::AUTHORIZATION
            && let Some(rest) = raw
                .strip_prefix("Bearer ")
                .or_else(|| raw.strip_prefix("bearer "))
        {
            let trimmed = rest.trim();
            if !trimmed.is_empty() {
                return Some(trimmed.to_owned());
            }
        }
        Some(raw.to_owned())
    };

    if let Some(src) = source_header {
        return extract_val(src);
    }

    for name in [
        HeaderName::from_static("x-api-key"),
        HeaderName::from_static("x-goog-api-key"),
        HeaderName::from_static("api-key"),
        header::AUTHORIZATION,
    ] {
        if let Some(s) = extract_val(&name) {
            return Some(s);
        }
    }
    None
}

/// Adapts canonical OpenAI `/v1/chat/completions`, `/v1/messages`, `/v1/responses`, and
/// `/v1/embeddings` requests & responses across named provider instances (`openai_compatible`,
/// `anthropic` direct & Claude-on-Vertex, `azure_openai`, `gemini` AI Studio & Vertex,
/// `bedrock` Converse & Embeddings), with built-in provider presets, multi-key pools, and BYOK.
pub struct AiProviderAdapterPlugin {
    providers: HashMap<String, CompiledProvider>,
    response_headers: bool,
    max_non_stream_response_bytes: usize,
    has_key_pools: bool,
    has_dynamic_auth: bool,
    clock: Arc<dyn Clock>,
    key_pools: Option<Arc<KeyPoolTable>>,
    http_client: Option<Arc<dyn HttpClient>>,
    cloud_tokens: Option<Arc<CloudTokenCache>>,
}

impl HttpPlugin for AiProviderAdapterPlugin {
    fn name(&self) -> &str {
        "ai-provider-adapter"
    }

    fn hook_mask(&self) -> HookMask {
        let mut mask = HookMask::ON_UPSTREAM_REQUEST
            | HookMask::ON_RESPONSE_HEADERS
            | HookMask::RESPONSE_BODY_STREAM;
        if self.has_key_pools || self.has_dynamic_auth {
            mask |= HookMask::ON_ROUTE;
        }
        mask
    }

    fn on_route<'a>(
        &'a self,
        ctx: &'a mut RequestCtx,
        decision: &'a mut RouteDecision,
    ) -> HookResult<'a, Flow> {
        if (self.has_key_pools || self.has_dynamic_auth)
            && let Some(meta) = ctx.get_ext::<AiRequestMeta>()
        {
            let needed: usize = meta
                .targets
                .iter()
                .map(|t| {
                    self.providers
                        .get(&t.provider)
                        .map(|p| {
                            if p.auth.is_cloud_iam() {
                                2
                            } else {
                                p.auth.pool_len()
                            }
                        })
                        .unwrap_or(1)
                })
                .sum::<usize>()
                .clamp(1, MAX_KEY_POOL_AUTO_ATTEMPTS);
            decision.max_attempts = decision.max_attempts.max(needed);
        }
        HookResult::Ready(Flow::Continue)
    }

    fn on_upstream_request<'a>(
        &'a self,
        ctx: &'a mut RequestCtx,
        req: &'a mut UpstreamRequest,
    ) -> HookResult<'a, Flow> {
        // Reset any previous attempt's response translation state and active key marker.
        ctx.remove_ext::<AdapterResponseState>();
        ctx.remove_ext::<ActiveProviderKey>();

        let Some((target, endpoint, stream_requested)) = ctx
            .get_ext::<AiRequestMeta>()
            .and_then(|m| m.active_target().map(|t| (t.clone(), m.endpoint, m.stream)))
        else {
            return HookResult::Ready(Flow::Continue);
        };

        let Some(provider) = self.providers.get(&target.provider) else {
            let resp = endpoint_error_response(
                endpoint,
                StatusCode::INTERNAL_SERVER_ERROR,
                "server_error",
                Some("provider_not_configured"),
                &format!(
                    "Provider `{}` is not configured in `ai-provider-adapter`",
                    target.provider
                ),
            );
            return HookResult::Ready(Flow::Respond(resp));
        };

        // Capture caller BYOK secret BEFORE stripping downstream credentials.
        let byok_header: Option<(HeaderName, HeaderValue)> =
            if let CompiledAuth::ClientPassthrough {
                ref source_header,
                ref target_header,
                ref target_prefix,
            } = provider.auth
            {
                let secret = ctx
                    .get_ext::<ClientByokCredential>()
                    .map(|c| c.0.clone())
                    .or_else(|| extract_client_byok_secret(&req.headers, source_header.as_ref()));
                let Some(secret) = secret else {
                    let resp = endpoint_error_response(
                        endpoint,
                        StatusCode::UNAUTHORIZED,
                        "authentication_error",
                        Some("missing_provider_api_key"),
                        &format!(
                            "Provider `{}` requires a client API key (BYOK passthrough)",
                            target.provider
                        ),
                    );
                    return HookResult::Ready(Flow::Respond(resp));
                };
                ctx.insert_ext(ClientByokCredential(secret.clone()));
                let full = match target_prefix {
                    Some(p) => format!("{p}{secret}"),
                    None => secret,
                };
                match HeaderValue::from_str(&full) {
                    Ok(hv) => Some((target_header.clone(), hv)),
                    Err(_) => {
                        let resp = endpoint_error_response(
                            endpoint,
                            StatusCode::BAD_REQUEST,
                            "invalid_request_error",
                            Some("invalid_provider_api_key"),
                            "Client API key contains invalid HTTP header characters",
                        );
                        return HookResult::Ready(Flow::Respond(resp));
                    }
                }
            } else {
                None
            };

        let is_vertex_anthropic =
            provider.dialect == ProviderDialect::Anthropic && provider.vertex.is_some();
        let is_native_anthropic = endpoint == AiEndpointKind::AnthropicMessages
            && provider.dialect == ProviderDialect::Anthropic;
        let is_native_responses = endpoint == AiEndpointKind::OpenAiResponses
            && matches!(
                provider.dialect,
                ProviderDialect::OpenAiCompatible | ProviderDialect::AzureOpenAi
            )
            && provider.responses_path.is_some();

        // Preserve client `anthropic-version` / `anthropic-beta` only on direct native Anthropic passthrough.
        let client_anthropic_version = if is_native_anthropic && !is_vertex_anthropic {
            req.headers
                .get(HeaderName::from_static("anthropic-version"))
                .cloned()
        } else {
            None
        };

        // Strip downstream credentials & any prior-attempt provider headers, and disable
        // upstream compression so body translation & token inspection see plain JSON/SSE/EventStream.
        req.headers.remove(header::AUTHORIZATION);
        req.headers.remove(HeaderName::from_static("x-api-key"));
        req.headers.remove(HeaderName::from_static("api-key"));
        req.headers
            .remove(HeaderName::from_static("x-goog-api-key"));
        req.headers.remove(HeaderName::from_static("x-amz-date"));
        req.headers
            .remove(HeaderName::from_static("x-amz-security-token"));
        req.headers
            .remove(HeaderName::from_static("x-amz-content-sha256"));
        if !is_native_anthropic || is_vertex_anthropic {
            req.headers
                .remove(HeaderName::from_static("anthropic-version"));
            req.headers
                .remove(HeaderName::from_static("anthropic-beta"));
        }
        req.headers.insert(
            header::ACCEPT_ENCODING,
            HeaderValue::from_static("identity"),
        );
        req.headers.insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/json"),
        );

        // Apply static, pooled, or BYOK auth headers upfront (SigV4 & dynamic cloud IAM finalize after path/body translation).
        match &provider.auth {
            CompiledAuth::None | CompiledAuth::AwsSigV4(_) | CompiledAuth::CloudIam(_) => {}
            CompiledAuth::StaticHeader(name, val) => {
                req.headers.insert(name.clone(), val.clone());
            }
            CompiledAuth::HeaderPool(name, pool) => {
                let tried_same_provider = match ctx.get_ext::<TriedProviderKeys>() {
                    Some(t) if t.provider == target.provider => t.tried.clone(),
                    _ => Vec::new(),
                };
                let now = self.clock.now();
                let key_index = self
                    .key_pools
                    .as_ref()
                    .map(|kp| {
                        kp.select_key(&target.provider, pool.len(), now, &tried_same_provider)
                    })
                    .unwrap_or(0);
                let mut next_tried = tried_same_provider;
                if !next_tried.contains(&key_index) {
                    next_tried.push(key_index);
                }
                ctx.insert_ext(TriedProviderKeys {
                    provider: target.provider.clone(),
                    tried: next_tried,
                });
                ctx.insert_ext(ActiveProviderKey {
                    provider: target.provider.clone(),
                    key_index,
                    pool_len: pool.len(),
                });
                req.headers.insert(name.clone(), pool[key_index].clone());
            }
            CompiledAuth::ClientPassthrough { .. } => {
                if let Some((hn, hv)) = byok_header {
                    req.headers.insert(hn, hv);
                }
            }
        }
        for (k, v) in &provider.extra_headers {
            req.headers.insert(k.clone(), v.clone());
        }

        // Fast path 1: Native Anthropic `/v1/messages` -> Anthropic or Claude-on-Vertex upstream.
        if is_native_anthropic {
            if let Some((ref proj, ref loc)) = provider.vertex {
                let path_str = vertex_anthropic_path(proj, loc, &target.model, stream_requested);
                match path_str.parse::<Uri>() {
                    Ok(uri) => req.uri = uri,
                    Err(e) => {
                        return HookResult::Ready(bad_request_translation(
                            endpoint,
                            &format!("invalid Vertex Anthropic URI `{path_str}`: {e}"),
                        ));
                    }
                }
                if let Some(body) = &req.body {
                    let normalized = match apply_request_param_transforms(
                        body,
                        &provider.default_params,
                        &target.default_params,
                        &provider.override_params,
                        &target.override_params,
                        &provider.drop_params,
                        provider.dialect,
                        &target.model,
                    ) {
                        Ok(Some(v)) => Bytes::from(v),
                        Ok(None) => body.clone(),
                        Err(err) => {
                            return HookResult::Ready(bad_request_translation(endpoint, &err));
                        }
                    };
                    match adapt_anthropic_body_for_vertex(
                        &normalized,
                        Some(&provider.anthropic_version_raw),
                    ) {
                        Ok(adapted) => req.body = Some(Bytes::from(adapted)),
                        Err(err) => {
                            return HookResult::Ready(bad_request_translation(endpoint, &err));
                        }
                    }
                }
                return self.finalize_upstream_auth(endpoint, provider, req);
            }

            req.uri = provider.chat_path.clone();
            req.headers.insert(
                HeaderName::from_static("anthropic-version"),
                client_anthropic_version.unwrap_or_else(|| provider.anthropic_version.clone()),
            );
            if let Some(body) = &req.body {
                let working = match apply_request_param_transforms(
                    body,
                    &provider.default_params,
                    &target.default_params,
                    &provider.override_params,
                    &target.override_params,
                    &provider.drop_params,
                    provider.dialect,
                    &target.model,
                ) {
                    Ok(Some(v)) => Some(Bytes::from(v)),
                    Ok(None) => None,
                    Err(err) => return HookResult::Ready(bad_request_translation(endpoint, &err)),
                };
                let src = working.as_ref().unwrap_or(body);
                match rewrite_anthropic_request(src, &target.model) {
                    Ok(Some(rewritten)) => req.body = Some(Bytes::from(rewritten)),
                    Ok(None) => {
                        if let Some(w) = working {
                            req.body = Some(w);
                        }
                    }
                    Err(err) => return HookResult::Ready(bad_request_translation(endpoint, &err)),
                }
            }
            return self.finalize_upstream_auth(endpoint, provider, req);
        }

        // Fast path 2: Native OpenAI Responses `/v1/responses` -> provider with `responses_path`.
        if is_native_responses {
            if provider.dialect == ProviderDialect::OpenAiCompatible {
                if let Some(org) = &provider.organization {
                    req.headers
                        .insert(HeaderName::from_static("openai-organization"), org.clone());
                }
                if let Some(proj) = &provider.project {
                    req.headers
                        .insert(HeaderName::from_static("openai-project"), proj.clone());
                }
            }
            req.uri = provider.responses_path.clone().unwrap();
            if let Some(body) = &req.body {
                let working = match apply_request_param_transforms(
                    body,
                    &provider.default_params,
                    &target.default_params,
                    &provider.override_params,
                    &target.override_params,
                    &provider.drop_params,
                    provider.dialect,
                    &target.model,
                ) {
                    Ok(Some(v)) => Some(Bytes::from(v)),
                    Ok(None) => None,
                    Err(err) => return HookResult::Ready(bad_request_translation(endpoint, &err)),
                };
                let src = working.as_ref().unwrap_or(body);
                match rewrite_openai_responses_request(src, &target.model) {
                    Ok(Some(rewritten)) => req.body = Some(Bytes::from(rewritten)),
                    Ok(None) => {
                        if let Some(w) = working {
                            req.body = Some(w);
                        }
                    }
                    Err(err) => return HookResult::Ready(bad_request_translation(endpoint, &err)),
                }
            }
            return self.finalize_upstream_auth(endpoint, provider, req);
        }

        // Hub-and-spoke ingress normalization: translate non-Chat conversational requests into
        // canonical OpenAI Chat Completions JSON once before applying overrides & dialect dispatch.
        let mut canonical_body: Option<Bytes> = match (endpoint, req.body.as_ref()) {
            (AiEndpointKind::AnthropicMessages, Some(raw)) => {
                match anthropic_to_openai_request(raw, &target.model) {
                    Ok(v) => Some(Bytes::from(v)),
                    Err(err) => return HookResult::Ready(bad_request_translation(endpoint, &err)),
                }
            }
            (AiEndpointKind::OpenAiResponses, Some(raw)) => {
                match responses_to_chat_request(raw, &target.model) {
                    Ok(v) => Some(Bytes::from(v)),
                    Err(err) => return HookResult::Ready(bad_request_translation(endpoint, &err)),
                }
            }
            (_, opt) => opt.cloned(),
        };

        // Apply provider/target default_params, override_params, and drop_params.
        if let Some(body) = &canonical_body {
            match apply_request_param_transforms(
                body,
                &provider.default_params,
                &target.default_params,
                &provider.override_params,
                &target.override_params,
                &provider.drop_params,
                provider.dialect,
                &target.model,
            ) {
                Ok(Some(transformed)) => canonical_body = Some(Bytes::from(transformed)),
                Ok(None) => {}
                Err(err) => return HookResult::Ready(bad_request_translation(endpoint, &err)),
            }
        }

        match provider.dialect {
            ProviderDialect::OpenAiCompatible => {
                if let Some(org) = &provider.organization {
                    req.headers
                        .insert(HeaderName::from_static("openai-organization"), org.clone());
                }
                if let Some(proj) = &provider.project {
                    req.headers
                        .insert(HeaderName::from_static("openai-project"), proj.clone());
                }

                match endpoint {
                    AiEndpointKind::Embeddings => {
                        req.uri = provider.embeddings_path.clone();
                        if let Some(body) = &canonical_body {
                            match rewrite_openai_embeddings_request(body, &target.model) {
                                Ok(Some(rewritten)) => req.body = Some(Bytes::from(rewritten)),
                                Ok(None) => req.body = Some(body.clone()),
                                Err(err) => {
                                    return HookResult::Ready(bad_request_translation(
                                        endpoint, &err,
                                    ));
                                }
                            }
                        }
                    }
                    _ => {
                        req.uri = provider.chat_path.clone();
                        if let Some(body) = &canonical_body {
                            match rewrite_openai_request(
                                body,
                                &target.model,
                                provider.include_stream_usage,
                            ) {
                                Ok(Some(rewritten)) => req.body = Some(Bytes::from(rewritten)),
                                Ok(None) => req.body = Some(body.clone()),
                                Err(err) => {
                                    return HookResult::Ready(bad_request_translation(
                                        endpoint, &err,
                                    ));
                                }
                            }
                        }
                    }
                }
            }
            ProviderDialect::AzureOpenAi => {
                let encoded_deployment = percent_encode_path_segment(&target.model);
                let path_str = match endpoint {
                    AiEndpointKind::Embeddings => format!(
                        "/openai/deployments/{encoded_deployment}/embeddings?api-version={}",
                        percent_encode_path_segment(&provider.api_version)
                    ),
                    _ => format!(
                        "/openai/deployments/{encoded_deployment}/chat/completions?api-version={}",
                        percent_encode_path_segment(&provider.api_version)
                    ),
                };
                match path_str.parse::<Uri>() {
                    Ok(uri) => req.uri = uri,
                    Err(e) => {
                        return HookResult::Ready(bad_request_translation(
                            endpoint,
                            &format!("invalid Azure OpenAI URI `{path_str}`: {e}"),
                        ));
                    }
                }

                if let Some(body) = &canonical_body {
                    let res = match endpoint {
                        AiEndpointKind::Embeddings => {
                            rewrite_openai_embeddings_request(body, &target.model)
                        }
                        _ => rewrite_openai_request(
                            body,
                            &target.model,
                            provider.include_stream_usage,
                        ),
                    };
                    match res {
                        Ok(Some(rewritten)) => req.body = Some(Bytes::from(rewritten)),
                        Ok(None) => req.body = Some(body.clone()),
                        Err(err) => {
                            return HookResult::Ready(bad_request_translation(endpoint, &err));
                        }
                    }
                }
            }
            ProviderDialect::Anthropic => {
                if endpoint == AiEndpointKind::Embeddings {
                    let resp = endpoint_error_response(
                        endpoint,
                        StatusCode::BAD_REQUEST,
                        "invalid_request_error",
                        Some("unsupported_endpoint"),
                        &format!(
                            "Provider `{}` (dialect `anthropic`) does not support `/v1/embeddings`",
                            target.provider
                        ),
                    );
                    return HookResult::Ready(Flow::Respond(resp));
                }

                if let Some((ref proj, ref loc)) = provider.vertex {
                    let path_str =
                        vertex_anthropic_path(proj, loc, &target.model, stream_requested);
                    match path_str.parse::<Uri>() {
                        Ok(uri) => req.uri = uri,
                        Err(e) => {
                            return HookResult::Ready(bad_request_translation(
                                endpoint,
                                &format!("invalid Vertex Anthropic URI `{path_str}`: {e}"),
                            ));
                        }
                    }
                } else {
                    req.uri = provider.chat_path.clone();
                    req.headers.insert(
                        HeaderName::from_static("anthropic-version"),
                        provider.anthropic_version.clone(),
                    );
                }

                if let Some(body) = &canonical_body {
                    let translated = match openai_to_anthropic_request(
                        body,
                        &target.model,
                        provider.default_max_tokens,
                    ) {
                        Ok(t) => t,
                        Err(err) => {
                            return HookResult::Ready(bad_request_translation(endpoint, &err));
                        }
                    };
                    if provider.vertex.is_some() {
                        match adapt_anthropic_body_for_vertex(
                            &translated,
                            Some(&provider.anthropic_version_raw),
                        ) {
                            Ok(adapted) => req.body = Some(Bytes::from(adapted)),
                            Err(err) => {
                                return HookResult::Ready(bad_request_translation(endpoint, &err));
                            }
                        }
                    } else {
                        req.body = Some(Bytes::from(translated));
                    }
                }
            }
            ProviderDialect::Gemini => {
                let vertex_ref = provider
                    .vertex
                    .as_ref()
                    .map(|(p, l)| (p.as_str(), l.as_str()));

                match endpoint {
                    AiEndpointKind::Embeddings => {
                        let Some(body) = &canonical_body else {
                            return HookResult::Ready(bad_request_translation(
                                endpoint,
                                "missing embeddings request body",
                            ));
                        };
                        let (translated, is_batch) = match openai_to_gemini_embeddings_request(
                            body,
                            &target.model,
                            vertex_ref.is_some(),
                        ) {
                            Ok(pair) => pair,
                            Err(err) => {
                                return HookResult::Ready(bad_request_translation(endpoint, &err));
                            }
                        };
                        let path_str = gemini_embeddings_path(&target.model, is_batch, vertex_ref);
                        match path_str.parse::<Uri>() {
                            Ok(uri) => req.uri = uri,
                            Err(e) => {
                                return HookResult::Ready(bad_request_translation(
                                    endpoint,
                                    &format!("invalid Gemini embeddings URI `{path_str}`: {e}"),
                                ));
                            }
                        }
                        req.body = Some(Bytes::from(translated));
                    }
                    _ => {
                        let path_str =
                            gemini_chat_path(&target.model, stream_requested, vertex_ref);
                        match path_str.parse::<Uri>() {
                            Ok(uri) => req.uri = uri,
                            Err(e) => {
                                return HookResult::Ready(bad_request_translation(
                                    endpoint,
                                    &format!("invalid Gemini URI `{path_str}`: {e}"),
                                ));
                            }
                        }
                        if let Some(body) = &canonical_body {
                            match openai_to_gemini_request(body) {
                                Ok(translated) => req.body = Some(Bytes::from(translated)),
                                Err(err) => {
                                    return HookResult::Ready(bad_request_translation(
                                        endpoint, &err,
                                    ));
                                }
                            }
                        }
                    }
                }
            }
            ProviderDialect::Bedrock => {
                if endpoint == AiEndpointKind::Embeddings {
                    let Some(body) = &canonical_body else {
                        return HookResult::Ready(bad_request_translation(
                            endpoint,
                            "missing embeddings request body",
                        ));
                    };
                    let translated = match openai_to_bedrock_embeddings_request(body, &target.model)
                    {
                        Ok(t) => t,
                        Err(err) => {
                            return HookResult::Ready(bad_request_translation(endpoint, &err));
                        }
                    };
                    let path_str = bedrock_invoke_path(&target.model);
                    match path_str.parse::<Uri>() {
                        Ok(uri) => req.uri = uri,
                        Err(e) => {
                            return HookResult::Ready(bad_request_translation(
                                endpoint,
                                &format!("invalid Bedrock embeddings URI `{path_str}`: {e}"),
                            ));
                        }
                    }
                    req.body = Some(Bytes::from(translated));
                    return self.finalize_upstream_auth(endpoint, provider, req);
                }

                let path_str = bedrock_converse_path(&target.model, stream_requested);
                match path_str.parse::<Uri>() {
                    Ok(uri) => req.uri = uri,
                    Err(e) => {
                        return HookResult::Ready(bad_request_translation(
                            endpoint,
                            &format!("invalid Bedrock URI `{path_str}`: {e}"),
                        ));
                    }
                }

                if let Some(body) = &canonical_body {
                    match openai_to_bedrock_converse_request_for_model(body, &target.model) {
                        Ok(translated) => req.body = Some(Bytes::from(translated)),
                        Err(err) => {
                            return HookResult::Ready(bad_request_translation(endpoint, &err));
                        }
                    }
                }
            }
        }

        self.finalize_upstream_auth(endpoint, provider, req)
    }

    fn on_response_headers<'a>(
        &'a self,
        ctx: &'a mut RequestCtx,
        res: &'a mut ResponseHead,
    ) -> HookResult<'a, Flow> {
        let Some((target, endpoint, stream_requested, max_attempts)) =
            ctx.get_ext::<AiRequestMeta>().and_then(|m| {
                m.active_target()
                    .map(|t| (t.clone(), m.endpoint, m.stream, m.max_attempts))
            })
        else {
            return HookResult::Ready(Flow::Continue);
        };

        let Some(provider) = self.providers.get(&target.provider) else {
            ctx.insert_ext(AdapterResponseState::Passthrough);
            return HookResult::Ready(Flow::Continue);
        };

        // Reactive dynamic cloud IAM token invalidation + single automatic refresh retry on
        // upstream 401 (or 403 for AWS SigV4 expired session tokens).
        if let CompiledAuth::CloudIam(ref cloud_auth) = provider.auth
            && let Some(ref cloud_tokens) = self.cloud_tokens
        {
            let status_code = res.status.as_u16();
            let token_rejected =
                status_code == 401 || (status_code == 403 && cloud_auth.is_aws_sigv4());
            if token_rejected {
                cloud_tokens.invalidate(&cloud_auth.cache_key);
                let already_retried = ctx
                    .get_ext::<CloudAuthRefreshedProviders>()
                    .is_some_and(|s| s.0.contains(&target.provider));
                if !already_retried && ctx.attempt < max_attempts {
                    let mut set = ctx
                        .get_ext::<CloudAuthRefreshedProviders>()
                        .cloned()
                        .unwrap_or_default();
                    set.0.insert(target.provider.clone());
                    ctx.insert_ext(set);
                    ctx.insert_ext(IntraProviderKeyRetry);
                    info!(
                        request_id = ctx.request_id,
                        provider = %target.provider,
                        auth_kind = cloud_auth.auth_kind_label(),
                        status = status_code,
                        attempt = ctx.attempt,
                        "invalidated cached cloud IAM token after upstream rejection; retrying with fresh credential"
                    );
                    return HookResult::Ready(Flow::RetryUpstream);
                }
            }
        }

        // Multi-key pool health tracking & intra-provider key rotation on rotatable errors.
        if let Some(active_key) = ctx.get_ext::<ActiveProviderKey>().cloned()
            && active_key.pool_len > 1
            && let Some(key_pools) = &self.key_pools
        {
            let status_code = res.status.as_u16();
            if provider.key_rotate_statuses.contains(&status_code) {
                let retry_after_str = res
                    .headers
                    .get(header::RETRY_AFTER)
                    .and_then(|v| v.to_str().ok());
                let max_cd = provider.key_cooldown.max(Duration::from_secs(300));
                let cd = compute_cooldown(provider.key_cooldown, max_cd, true, retry_after_str);
                let now = self.clock.now();
                key_pools.record_cooldown(
                    &active_key.provider,
                    active_key.pool_len,
                    active_key.key_index,
                    cd,
                    now,
                );
                let tried = ctx
                    .get_ext::<TriedProviderKeys>()
                    .filter(|t| t.provider == active_key.provider)
                    .map(|t| t.tried.clone())
                    .unwrap_or_default();
                if ctx.attempt < max_attempts
                    && key_pools.has_untried_healthy_key(
                        &active_key.provider,
                        active_key.pool_len,
                        now,
                        &tried,
                    )
                {
                    info!(
                        request_id = ctx.request_id,
                        provider = %active_key.provider,
                        key_index = active_key.key_index,
                        status = status_code,
                        attempt = ctx.attempt,
                        "ai-provider-adapter rotating pooled API key after retryable status"
                    );
                    ctx.insert_ext(IntraProviderKeyRetry);
                    return HookResult::Ready(Flow::RetryUpstream);
                }
            } else if res.status.is_success() {
                key_pools.record_success(
                    &active_key.provider,
                    active_key.pool_len,
                    active_key.key_index,
                );
            }
        }

        if self.response_headers {
            if let Ok(val) = HeaderValue::from_str(&target.provider) {
                res.headers
                    .insert(HeaderName::from_static("x-shunt-provider"), val);
            }
            if let Ok(val) = HeaderValue::from_str(&target.model) {
                res.headers
                    .insert(HeaderName::from_static("x-shunt-model"), val);
            }
            if let Ok(val) = HeaderValue::from_str(&ctx.attempt.to_string()) {
                res.headers
                    .insert(HeaderName::from_static("x-shunt-attempt"), val);
            }
            if let Some(active_key) = ctx.get_ext::<ActiveProviderKey>()
                && active_key.pool_len > 1
                && let Ok(val) = HeaderValue::from_str(&active_key.key_index.to_string())
            {
                res.headers
                    .insert(HeaderName::from_static("x-shunt-key-index"), val);
            }
        }

        // Native same-protocol passthrough fast paths (zero translation overhead).
        let is_native_passthrough = match (endpoint, provider.dialect) {
            (
                AiEndpointKind::ChatCompletions | AiEndpointKind::Embeddings,
                ProviderDialect::OpenAiCompatible | ProviderDialect::AzureOpenAi,
            ) => true,
            (AiEndpointKind::AnthropicMessages, ProviderDialect::Anthropic) => true,
            (
                AiEndpointKind::OpenAiResponses,
                ProviderDialect::OpenAiCompatible | ProviderDialect::AzureOpenAi,
            ) => provider.responses_path.is_some(),
            _ => false,
        };
        if is_native_passthrough {
            ctx.insert_ext(AdapterResponseState::Passthrough);
            return HookResult::Ready(Flow::Continue);
        }

        let content_type_lower = res
            .headers
            .get(header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .map(str::to_ascii_lowercase)
            .unwrap_or_default();

        // Special-case Gemini & Bedrock embeddings JSON (always non-streaming).
        if endpoint == AiEndpointKind::Embeddings
            && matches!(
                provider.dialect,
                ProviderDialect::Gemini | ProviderDialect::Bedrock
            )
        {
            res.headers.insert(
                header::CONTENT_TYPE,
                HeaderValue::from_static("application/json"),
            );
            let upstream = if provider.dialect == ProviderDialect::Bedrock {
                UpstreamJsonKind::BedrockEmbeddings
            } else {
                UpstreamJsonKind::GeminiEmbeddings
            };
            ctx.insert_ext(AdapterResponseState::BufferedJson {
                upstream,
                ingress: IngressResponseFormat::OpenAiChat,
                status: res.status,
                fallback_model: target.model,
                buffer: Vec::new(),
            });
            return HookResult::Ready(Flow::Continue);
        }

        let ingress_format = match endpoint {
            AiEndpointKind::AnthropicMessages => IngressResponseFormat::AnthropicMessages,
            AiEndpointKind::OpenAiResponses => IngressResponseFormat::OpenAiResponses,
            _ => IngressResponseFormat::OpenAiChat,
        };

        let is_stream = res.status.is_success()
            && match provider.dialect {
                ProviderDialect::Bedrock => {
                    content_type_lower.contains("application/vnd.amazon.eventstream")
                        || stream_requested
                }
                _ => content_type_lower.contains("text/event-stream") || stream_requested,
            };

        if is_stream {
            set_sse_headers(res);
            let upstream = match provider.dialect {
                ProviderDialect::OpenAiCompatible | ProviderDialect::AzureOpenAi => {
                    UpstreamStreamStage::OpenAiSse
                }
                ProviderDialect::Anthropic => UpstreamStreamStage::AnthropicSse(Box::new(
                    AnthropicSseTranslator::new(target.model.clone()),
                )),
                ProviderDialect::Gemini => UpstreamStreamStage::GeminiSse(Box::new(
                    GeminiSseTranslator::new(target.model.clone()),
                )),
                ProviderDialect::Bedrock => UpstreamStreamStage::BedrockStream(Box::new(
                    BedrockStreamTranslator::new(target.model.clone()),
                )),
            };
            let ingress = match ingress_format {
                IngressResponseFormat::OpenAiChat => IngressStreamStage::Identity,
                IngressResponseFormat::AnthropicMessages => IngressStreamStage::ToAnthropic(
                    Box::new(OpenAiToAnthropicSseTranslator::new(target.model)),
                ),
                IngressResponseFormat::OpenAiResponses => IngressStreamStage::ToResponses(
                    Box::new(ChatToResponsesSseTranslator::new(target.model)),
                ),
            };
            ctx.insert_ext(AdapterResponseState::Streaming { upstream, ingress });
        } else {
            res.headers.insert(
                header::CONTENT_TYPE,
                HeaderValue::from_static("application/json"),
            );
            let upstream = match provider.dialect {
                ProviderDialect::OpenAiCompatible | ProviderDialect::AzureOpenAi => {
                    UpstreamJsonKind::OpenAi
                }
                ProviderDialect::Anthropic => UpstreamJsonKind::Anthropic,
                ProviderDialect::Gemini => UpstreamJsonKind::Gemini,
                ProviderDialect::Bedrock => UpstreamJsonKind::Bedrock,
            };
            ctx.insert_ext(AdapterResponseState::BufferedJson {
                upstream,
                ingress: ingress_format,
                status: res.status,
                fallback_model: target.model,
                buffer: Vec::new(),
            });
        }

        HookResult::Ready(Flow::Continue)
    }

    fn on_response_body_chunk<'a>(
        &'a self,
        ctx: &'a mut RequestCtx,
        chunk: &'a mut Bytes,
        end_of_stream: bool,
    ) -> HookResult<'a, StreamFlow> {
        let Some(state) = ctx.get_ext_mut::<AdapterResponseState>() else {
            return HookResult::Ready(StreamFlow::Continue);
        };

        let max_bytes = self.max_non_stream_response_bytes;

        match state {
            AdapterResponseState::Passthrough => HookResult::Ready(StreamFlow::Continue),
            AdapterResponseState::Streaming { upstream, ingress } => {
                let mut canonical = if chunk.is_empty() {
                    Bytes::new()
                } else {
                    upstream.push_chunk(chunk)
                };
                if end_of_stream {
                    canonical = concat_bytes(canonical, upstream.finish());
                }

                let mut out = if canonical.is_empty() {
                    Bytes::new()
                } else {
                    ingress.push_chunk(&canonical)
                };
                if end_of_stream {
                    out = concat_bytes(out, ingress.finish());
                }

                *chunk = out;
                HookResult::Ready(StreamFlow::Continue)
            }
            AdapterResponseState::BufferedJson {
                upstream,
                ingress,
                status,
                fallback_model,
                buffer,
            } => {
                let upstream_kind = *upstream;
                let ingress_fmt = *ingress;
                let resp_status = *status;
                let res = handle_buffered_json_translation(
                    upstream_kind.label(),
                    buffer,
                    chunk,
                    end_of_stream,
                    max_bytes,
                    |buf| {
                        let canonical: Vec<u8> = match upstream_kind {
                            UpstreamJsonKind::OpenAi => buf.to_vec(),
                            UpstreamJsonKind::Anthropic => {
                                anthropic_to_openai_response(buf, resp_status, fallback_model)?
                            }
                            UpstreamJsonKind::Gemini => {
                                gemini_to_openai_response(buf, resp_status, fallback_model)?
                            }
                            UpstreamJsonKind::GeminiEmbeddings => {
                                return gemini_to_openai_embeddings_response(
                                    buf,
                                    resp_status,
                                    fallback_model,
                                );
                            }
                            UpstreamJsonKind::Bedrock => bedrock_converse_to_openai_response(
                                buf,
                                resp_status,
                                fallback_model,
                            )?,
                            UpstreamJsonKind::BedrockEmbeddings => {
                                return bedrock_embeddings_to_openai_response(
                                    buf,
                                    resp_status,
                                    fallback_model,
                                );
                            }
                        };

                        match ingress_fmt {
                            IngressResponseFormat::OpenAiChat => Ok(canonical),
                            IngressResponseFormat::AnthropicMessages => {
                                openai_to_anthropic_response(
                                    &canonical,
                                    resp_status,
                                    fallback_model,
                                )
                            }
                            IngressResponseFormat::OpenAiResponses => {
                                chat_to_responses_response(&canonical, resp_status, fallback_model)
                            }
                        }
                    },
                );
                if end_of_stream && !chunk.is_empty() && ctx.get_ext::<AiCachePending>().is_some() {
                    ctx.insert_ext(AiTranslatedResponseBody(chunk.clone()));
                }
                res
            }
        }
    }
}

impl AiProviderAdapterPlugin {
    fn finalize_upstream_auth<'a>(
        &'a self,
        endpoint: AiEndpointKind,
        provider: &'a CompiledProvider,
        req: &'a mut UpstreamRequest,
    ) -> HookResult<'a, Flow> {
        match &provider.auth {
            CompiledAuth::AwsSigV4(creds) => {
                if let Err(err) = sign_upstream_request(req, creds, None) {
                    let resp = endpoint_error_response(
                        endpoint,
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "server_error",
                        Some("aws_sigv4_signing_failed"),
                        &err,
                    );
                    return HookResult::Ready(Flow::Respond(resp));
                }
                HookResult::Ready(Flow::Continue)
            }
            CompiledAuth::CloudIam(cloud_auth) => {
                let (Some(cache), Some(http_client)) = (&self.cloud_tokens, &self.http_client)
                else {
                    let resp = endpoint_error_response(
                        endpoint,
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "server_error",
                        Some("cloud_auth_unavailable"),
                        "Dynamic cloud IAM auth is not initialized",
                    );
                    return HookResult::Ready(Flow::Respond(resp));
                };

                // Zero-allocation synchronous fast path when cached token is fresh.
                if let CacheLookup::Fresh(cred) =
                    cache.lookup(&cloud_auth.cache_key, self.clock.now())
                {
                    return HookResult::Ready(apply_resolved_cloud_credential(
                        endpoint, req, &cred,
                    ));
                }

                let cache = Arc::clone(cache);
                let http_client = Arc::clone(http_client);
                let clock = Arc::clone(&self.clock);
                let cloud_auth = Arc::clone(cloud_auth);

                HookResult::Pending(Box::pin(async move {
                    match cache
                        .get_or_refresh(&cloud_auth, http_client.as_ref(), clock.as_ref())
                        .await
                    {
                        Ok(cred) => apply_resolved_cloud_credential(endpoint, req, &cred),
                        Err(err) => {
                            warn!(
                                provider = %cloud_auth.provider_name,
                                auth_kind = cloud_auth.auth_kind_label(),
                                error = %err,
                                "dynamic cloud IAM credential acquisition failed"
                            );
                            Flow::Respond(endpoint_error_response(
                                endpoint,
                                StatusCode::SERVICE_UNAVAILABLE,
                                "server_error",
                                Some("cloud_auth_failed"),
                                &format!(
                                    "Failed to acquire cloud IAM credentials for provider `{}`: {err}",
                                    cloud_auth.provider_name
                                ),
                            ))
                        }
                    }
                }))
            }
            _ => HookResult::Ready(Flow::Continue),
        }
    }
}

fn apply_resolved_cloud_credential(
    endpoint: AiEndpointKind,
    req: &mut UpstreamRequest,
    cred: &ResolvedCloudCredential,
) -> Flow {
    match cred {
        ResolvedCloudCredential::AwsSigV4(creds) => {
            if let Err(err) = sign_upstream_request(req, creds, None) {
                return Flow::Respond(endpoint_error_response(
                    endpoint,
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "server_error",
                    Some("aws_sigv4_signing_failed"),
                    &err,
                ));
            }
            Flow::Continue
        }
        ResolvedCloudCredential::BearerToken(token) => {
            let full = format!("Bearer {token}");
            match HeaderValue::from_str(&full) {
                Ok(hv) => {
                    req.headers.insert(header::AUTHORIZATION, hv);
                    Flow::Continue
                }
                Err(e) => Flow::Respond(endpoint_error_response(
                    endpoint,
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "server_error",
                    Some("cloud_auth_failed"),
                    &format!("Cloud IAM token contains invalid HTTP header characters: {e}"),
                )),
            }
        }
    }
}

fn concat_bytes(first: Bytes, second: Bytes) -> Bytes {
    if first.is_empty() {
        return second;
    }
    if second.is_empty() {
        return first;
    }
    let mut merged = Vec::with_capacity(first.len() + second.len());
    merged.extend_from_slice(&first);
    merged.extend_from_slice(&second);
    Bytes::from(merged)
}

fn bad_request_translation(endpoint: AiEndpointKind, err: &str) -> Flow {
    Flow::Respond(endpoint_error_response(
        endpoint,
        StatusCode::BAD_REQUEST,
        "invalid_request_error",
        Some("request_translation_failed"),
        err,
    ))
}

fn set_sse_headers(res: &mut ResponseHead) {
    res.headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/event-stream; charset=utf-8"),
    );
    res.headers
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-cache"));
}

fn handle_buffered_json_translation<'a, F>(
    dialect_label: &str,
    buffer: &mut Vec<u8>,
    chunk: &mut Bytes,
    end_of_stream: bool,
    max_bytes: usize,
    translate: F,
) -> HookResult<'a, StreamFlow>
where
    F: FnOnce(&[u8]) -> Result<Vec<u8>, String>,
{
    if !end_of_stream {
        if buffer.len().saturating_add(chunk.len()) > max_bytes {
            return HookResult::Ready(StreamFlow::Abort(format!(
                "{dialect_label} JSON response exceeded max_non_stream_response_bytes ({max_bytes})"
            )));
        }
        buffer.extend_from_slice(chunk);
        *chunk = Bytes::new();
        return HookResult::Ready(StreamFlow::Continue);
    }

    if buffer.is_empty() {
        return HookResult::Ready(StreamFlow::Continue);
    }

    match translate(buffer) {
        Ok(translated) => {
            *chunk = Bytes::from(translated);
        }
        Err(err) => {
            warn!(error = %err, dialect = dialect_label, "failed to translate JSON response; passing raw body");
            *chunk = Bytes::from(std::mem::take(buffer));
        }
    }
    HookResult::Ready(StreamFlow::Continue)
}
