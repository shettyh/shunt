use std::collections::HashMap;
use std::sync::Arc;

use serde::Deserialize;
use shunt_plugin_sdk::{
    BuildContext, Bytes, Flow, HeaderName, HeaderValue, HookMask, HookResult, HttpPlugin,
    PluginBuildError, PluginConfig, PluginFactory, RequestCtx, ResponseHead, StatusCode,
    StreamFlow, UpstreamRequest, Uri, header,
};
use tracing::warn;

use crate::aws_sigv4::{AwsSigV4Credentials, sign_upstream_request};
use crate::cache::{AiCachePending, AiTranslatedResponseBody};
use crate::dialects::bedrock::{
    BedrockStreamTranslator, bedrock_converse_path, bedrock_converse_to_openai_response,
    openai_to_bedrock_converse_request,
};
use crate::dialects::gemini::{
    GeminiSseTranslator, gemini_chat_path, gemini_embeddings_path,
    gemini_to_openai_embeddings_response, gemini_to_openai_response,
    openai_to_gemini_embeddings_request, openai_to_gemini_request,
};
use crate::ingress::anthropic::{
    OpenAiToAnthropicSseTranslator, anthropic_to_openai_request, openai_to_anthropic_response,
    rewrite_anthropic_request,
};
use crate::ingress::responses::{
    ChatToResponsesSseTranslator, chat_to_responses_response, responses_to_chat_request,
    rewrite_openai_responses_request,
};
use crate::translate::{
    AnthropicSseTranslator, anthropic_to_openai_response, openai_to_anthropic_request,
    rewrite_openai_embeddings_request, rewrite_openai_request,
};
use crate::types::{
    AiEndpointKind, AiRequestMeta, ProviderDialect, endpoint_error_response,
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

fn default_true() -> bool {
    true
}

fn default_auth_none() -> ProviderAuthConfig {
    ProviderAuthConfig::None
}

/// Authentication mechanism attached to an upstream provider instance.
///
/// Every secret field (`api_key`, `secret_access_key`, `session_token`) uses canonical
/// redaction-matched names so `GET /snapshot` redacts all credentials automatically.
#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ProviderAuthConfig {
    None,
    Bearer {
        api_key: String,
    },
    Header {
        header: String,
        api_key: String,
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
}

/// Declarative configuration for a single named provider instance in `providers.<name>`.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderInstanceConfig {
    pub dialect: ProviderDialect,
    #[serde(default = "default_auth_none")]
    pub auth: ProviderAuthConfig,
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
    /// OpenAI-compatible: inject `stream_options.include_usage = true` on streaming chat (default: true).
    #[serde(default = "default_true")]
    pub include_stream_usage: bool,
    /// OpenAI-compatible: optional `OpenAI-Organization` header.
    #[serde(default)]
    pub organization: Option<String>,
    /// OpenAI-compatible: optional `OpenAI-Project` header.
    #[serde(default)]
    pub project: Option<String>,
    /// Anthropic: `anthropic-version` header (default: `"2023-06-01"`).
    #[serde(default)]
    pub anthropic_version: Option<String>,
    /// Anthropic: fallback `max_tokens` when client omits it (default: `4096`).
    #[serde(default)]
    pub default_max_tokens: Option<u64>,
    /// Azure OpenAI: `?api-version=` query value (default: `"2024-10-21"`).
    #[serde(default)]
    pub api_version: Option<String>,
    /// Google Gemini Vertex AI: GCP project ID (requires `vertex_location`).
    #[serde(default)]
    pub vertex_project: Option<String>,
    /// Google Gemini Vertex AI: GCP location (e.g., `"us-central1"`, requires `vertex_project`).
    #[serde(default)]
    pub vertex_location: Option<String>,
    /// AWS Bedrock region (e.g., `"us-east-1"`, required for `aws_sigv4`).
    #[serde(default)]
    pub region: Option<String>,
    /// Arbitrary extra static headers attached on upstream requests.
    #[serde(default)]
    pub extra_headers: HashMap<String, String>,
}

#[derive(Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct AiProviderAdapterConfig {
    /// Named provider instances (e.g. `providers.openai`, `providers.ollama`, `providers.bedrock`).
    providers: HashMap<String, ProviderInstanceConfig>,
    /// Attach `x-shunt-provider`, `x-shunt-model`, and `x-shunt-attempt` response headers.
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
    AwsSigV4(AwsSigV4Credentials),
}

struct CompiledProvider {
    dialect: ProviderDialect,
    auth: CompiledAuth,
    chat_path: Uri,
    embeddings_path: Uri,
    responses_path: Option<Uri>,
    include_stream_usage: bool,
    organization: Option<HeaderValue>,
    project: Option<HeaderValue>,
    anthropic_version: HeaderValue,
    default_max_tokens: u64,
    api_version: String,
    vertex: Option<(String, String)>,
    extra_headers: Vec<(HeaderName, HeaderValue)>,
}

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
}

impl UpstreamJsonKind {
    const fn label(self) -> &'static str {
        match self {
            UpstreamJsonKind::OpenAi => "OpenAI",
            UpstreamJsonKind::Anthropic => "Anthropic",
            UpstreamJsonKind::Gemini => "Gemini",
            UpstreamJsonKind::GeminiEmbeddings => "Gemini embeddings",
            UpstreamJsonKind::Bedrock => "Bedrock",
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
        _ctx: &BuildContext,
    ) -> Result<Arc<dyn HttpPlugin>, PluginBuildError> {
        let cfg: AiProviderAdapterConfig = config.deserialize(self.name())?;

        if cfg.providers.is_empty() {
            return Err(PluginBuildError::BuildFailed {
                plugin: self.name().to_owned(),
                message: "configure at least one provider under `providers.<name>`".to_owned(),
            });
        }

        let mut compiled = HashMap::with_capacity(cfg.providers.len());
        for (name, pcfg) in cfg.providers {
            if name.trim().is_empty() {
                return Err(PluginBuildError::BuildFailed {
                    plugin: self.name().to_owned(),
                    message: "provider name in `providers` cannot be empty".to_owned(),
                });
            }
            let cp = compile_provider(self.name(), &name, pcfg)?;
            compiled.insert(name, cp);
        }

        Ok(Arc::new(AiProviderAdapterPlugin {
            providers: compiled,
            response_headers: cfg.response_headers,
            max_non_stream_response_bytes: cfg.max_non_stream_response_bytes.max(1024),
        }))
    }
}

fn compile_provider(
    plugin: &str,
    provider_name: &str,
    cfg: ProviderInstanceConfig,
) -> Result<CompiledProvider, PluginBuildError> {
    let prefix = format!("providers.{provider_name}");

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

    let auth = match cfg.auth {
        ProviderAuthConfig::None => CompiledAuth::None,
        ProviderAuthConfig::Bearer { api_key } => {
            let secret =
                resolve_env_secret(&api_key).map_err(|msg| PluginBuildError::BuildFailed {
                    plugin: plugin.to_owned(),
                    message: format!("{prefix}.auth.api_key: {msg}"),
                })?;
            let val = HeaderValue::from_str(&format!("Bearer {secret}")).map_err(|e| {
                PluginBuildError::BuildFailed {
                    plugin: plugin.to_owned(),
                    message: format!("invalid {prefix}.auth.api_key header value: {e}"),
                }
            })?;
            CompiledAuth::StaticHeader(header::AUTHORIZATION, val)
        }
        ProviderAuthConfig::Header {
            header: header_name,
            api_key,
            prefix: val_prefix,
        } => {
            let hn = HeaderName::from_bytes(header_name.as_bytes()).map_err(|e| {
                PluginBuildError::BuildFailed {
                    plugin: plugin.to_owned(),
                    message: format!("invalid {prefix}.auth.header `{header_name}`: {e}"),
                }
            })?;
            let secret =
                resolve_env_secret(&api_key).map_err(|msg| PluginBuildError::BuildFailed {
                    plugin: plugin.to_owned(),
                    message: format!("{prefix}.auth.api_key: {msg}"),
                })?;
            let full = match val_prefix {
                Some(p) => format!("{p}{secret}"),
                None => secret,
            };
            let hv = HeaderValue::from_str(&full).map_err(|e| PluginBuildError::BuildFailed {
                plugin: plugin.to_owned(),
                message: format!("invalid {prefix}.auth.api_key header value: {e}"),
            })?;
            CompiledAuth::StaticHeader(hn, hv)
        }
        ProviderAuthConfig::AwsSigv4 {
            access_key_id,
            secret_access_key,
            session_token,
            service,
        } => {
            let region = cfg
                .region
                .as_deref()
                .map(str::trim)
                .filter(|r| !r.is_empty())
                .ok_or_else(|| PluginBuildError::BuildFailed {
                    plugin: plugin.to_owned(),
                    message: format!(
                        "`{prefix}.region` is required when using `auth.type = \"aws_sigv4\"`"
                    ),
                })?
                .to_owned();
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
            let st =
                match session_token {
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
    };

    let default_chat_path = match cfg.dialect {
        ProviderDialect::Anthropic => DEFAULT_ANTHROPIC_PATH,
        _ => DEFAULT_OPENAI_CHAT_PATH,
    };
    let raw_chat_path = cfg.chat_path.as_deref().unwrap_or(default_chat_path);
    let chat_path: Uri = raw_chat_path
        .parse()
        .map_err(|e| PluginBuildError::BuildFailed {
            plugin: plugin.to_owned(),
            message: format!("invalid {prefix}.chat_path `{raw_chat_path}`: {e}"),
        })?;

    let raw_emb_path = cfg
        .embeddings_path
        .as_deref()
        .unwrap_or(DEFAULT_OPENAI_EMBEDDINGS_PATH);
    let embeddings_path: Uri = raw_emb_path
        .parse()
        .map_err(|e| PluginBuildError::BuildFailed {
            plugin: plugin.to_owned(),
            message: format!("invalid {prefix}.embeddings_path `{raw_emb_path}`: {e}"),
        })?;

    let responses_path: Option<Uri> = match cfg.responses_path.as_deref() {
        Some(raw) => Some(raw.parse().map_err(|e| PluginBuildError::BuildFailed {
            plugin: plugin.to_owned(),
            message: format!("invalid {prefix}.responses_path `{raw}`: {e}"),
        })?),
        None => None,
    };

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
        dialect: cfg.dialect,
        auth,
        chat_path,
        embeddings_path,
        responses_path,
        include_stream_usage: cfg.include_stream_usage,
        organization,
        project,
        anthropic_version,
        default_max_tokens: cfg
            .default_max_tokens
            .unwrap_or(DEFAULT_ANTHROPIC_MAX_TOKENS)
            .max(1),
        api_version: cfg
            .api_version
            .unwrap_or_else(|| DEFAULT_AZURE_API_VERSION.to_owned()),
        vertex,
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

/// Adapts canonical OpenAI `/v1/chat/completions` and `/v1/embeddings` requests & responses
/// across arbitrary named provider instances (`openai_compatible`, `anthropic`, `azure_openai`,
/// `gemini`, `bedrock`).
pub struct AiProviderAdapterPlugin {
    providers: HashMap<String, CompiledProvider>,
    response_headers: bool,
    max_non_stream_response_bytes: usize,
}

impl HttpPlugin for AiProviderAdapterPlugin {
    fn name(&self) -> &str {
        "ai-provider-adapter"
    }

    fn hook_mask(&self) -> HookMask {
        HookMask::ON_UPSTREAM_REQUEST
            | HookMask::ON_RESPONSE_HEADERS
            | HookMask::RESPONSE_BODY_STREAM
    }

    fn on_upstream_request<'a>(
        &'a self,
        ctx: &'a mut RequestCtx,
        req: &'a mut UpstreamRequest,
    ) -> HookResult<'a, Flow> {
        // Reset any previous attempt's response translation state.
        ctx.remove_ext::<AdapterResponseState>();

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

        let is_native_anthropic = endpoint == AiEndpointKind::AnthropicMessages
            && provider.dialect == ProviderDialect::Anthropic;
        let is_native_responses = endpoint == AiEndpointKind::OpenAiResponses
            && matches!(
                provider.dialect,
                ProviderDialect::OpenAiCompatible | ProviderDialect::AzureOpenAi
            )
            && provider.responses_path.is_some();

        // Preserve client `anthropic-version` / `anthropic-beta` only on native Anthropic passthrough.
        let client_anthropic_version = if is_native_anthropic {
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
        if !is_native_anthropic {
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

        // Apply static auth headers upfront (SigV4 signing happens after path/body translation).
        if let CompiledAuth::StaticHeader(ref name, ref val) = provider.auth {
            req.headers.insert(name.clone(), val.clone());
        }
        for (k, v) in &provider.extra_headers {
            req.headers.insert(k.clone(), v.clone());
        }

        // Fast path 1: Native Anthropic `/v1/messages` -> Anthropic upstream (zero schema loss).
        if is_native_anthropic {
            req.uri = provider.chat_path.clone();
            req.headers.insert(
                HeaderName::from_static("anthropic-version"),
                client_anthropic_version.unwrap_or_else(|| provider.anthropic_version.clone()),
            );
            if let Some(body) = &req.body {
                match rewrite_anthropic_request(body, &target.model) {
                    Ok(Some(rewritten)) => req.body = Some(Bytes::from(rewritten)),
                    Ok(None) => {}
                    Err(err) => return HookResult::Ready(bad_request_translation(endpoint, &err)),
                }
            }
            return finalize_sigv4_if_needed(endpoint, provider, req);
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
                match rewrite_openai_responses_request(body, &target.model) {
                    Ok(Some(rewritten)) => req.body = Some(Bytes::from(rewritten)),
                    Ok(None) => {}
                    Err(err) => return HookResult::Ready(bad_request_translation(endpoint, &err)),
                }
            }
            return finalize_sigv4_if_needed(endpoint, provider, req);
        }

        // Hub-and-spoke ingress normalization: translate non-Chat conversational requests into
        // canonical OpenAI Chat Completions JSON once before dispatching to any upstream dialect.
        let canonical_body: Option<Bytes> = match (endpoint, req.body.as_ref()) {
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

                req.uri = provider.chat_path.clone();
                req.headers.insert(
                    HeaderName::from_static("anthropic-version"),
                    provider.anthropic_version.clone(),
                );

                if let Some(body) = &canonical_body {
                    match openai_to_anthropic_request(
                        body,
                        &target.model,
                        provider.default_max_tokens,
                    ) {
                        Ok(translated) => req.body = Some(Bytes::from(translated)),
                        Err(err) => {
                            return HookResult::Ready(bad_request_translation(endpoint, &err));
                        }
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
                    let resp = endpoint_error_response(
                        endpoint,
                        StatusCode::NOT_IMPLEMENTED,
                        "not_implemented_error",
                        Some("unsupported_endpoint"),
                        &format!(
                            "Provider `{}` (dialect `bedrock`) does not yet support `/v1/embeddings`",
                            target.provider
                        ),
                    );
                    return HookResult::Ready(Flow::Respond(resp));
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
                    match openai_to_bedrock_converse_request(body) {
                        Ok(translated) => req.body = Some(Bytes::from(translated)),
                        Err(err) => {
                            return HookResult::Ready(bad_request_translation(endpoint, &err));
                        }
                    }
                }
            }
        }

        finalize_sigv4_if_needed(endpoint, provider, req)
    }

    fn on_response_headers<'a>(
        &'a self,
        ctx: &'a mut RequestCtx,
        res: &'a mut ResponseHead,
    ) -> HookResult<'a, Flow> {
        let Some((target, endpoint, stream_requested)) = ctx
            .get_ext::<AiRequestMeta>()
            .and_then(|m| m.active_target().map(|t| (t.clone(), m.endpoint, m.stream)))
        else {
            return HookResult::Ready(Flow::Continue);
        };

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
        }

        let Some(provider) = self.providers.get(&target.provider) else {
            ctx.insert_ext(AdapterResponseState::Passthrough);
            return HookResult::Ready(Flow::Continue);
        };

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

        // Special-case Gemini embeddings JSON (always non-streaming).
        if provider.dialect == ProviderDialect::Gemini && endpoint == AiEndpointKind::Embeddings {
            res.headers.insert(
                header::CONTENT_TYPE,
                HeaderValue::from_static("application/json"),
            );
            ctx.insert_ext(AdapterResponseState::BufferedJson {
                upstream: UpstreamJsonKind::GeminiEmbeddings,
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

fn finalize_sigv4_if_needed<'a>(
    endpoint: AiEndpointKind,
    provider: &CompiledProvider,
    req: &mut UpstreamRequest,
) -> HookResult<'a, Flow> {
    if let CompiledAuth::AwsSigV4(ref creds) = provider.auth
        && let Err(err) = sign_upstream_request(req, creds, None)
    {
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
