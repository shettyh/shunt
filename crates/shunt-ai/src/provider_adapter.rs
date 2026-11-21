use std::collections::HashMap;
use std::sync::Arc;

use serde::Deserialize;
use shunt_plugin_sdk::{
    BuildContext, Bytes, Flow, HeaderName, HeaderValue, HookMask, HookResult, HttpPlugin,
    PluginBuildError, PluginConfig, PluginFactory, RequestCtx, ResponseHead, StatusCode,
    StreamFlow, UpstreamRequest, Uri, header,
};
use tracing::warn;

use crate::translate::{
    AnthropicSseTranslator, anthropic_to_openai_response, openai_to_anthropic_request,
    rewrite_openai_request,
};
use crate::types::{AiProvider, AiRequestMeta, openai_error_response, resolve_env_secret};

const DEFAULT_OPENAI_PATH: &str = "/v1/chat/completions";
const DEFAULT_ANTHROPIC_PATH: &str = "/v1/messages";
const DEFAULT_ANTHROPIC_VERSION: &str = "2023-06-01";
const DEFAULT_ANTHROPIC_MAX_TOKENS: u64 = 4096;
const DEFAULT_MAX_NON_STREAM_RESPONSE_BYTES: usize = 16 * 1024 * 1024; // 16 MiB

#[derive(Debug, Deserialize)]
#[serde(default)]
struct OpenAiAdapterConfig {
    api_key: Option<String>,
    path: String,
    organization: Option<String>,
    project: Option<String>,
    include_stream_usage: bool,
    extra_headers: HashMap<String, String>,
}

impl Default for OpenAiAdapterConfig {
    fn default() -> Self {
        Self {
            api_key: None,
            path: DEFAULT_OPENAI_PATH.to_owned(),
            organization: None,
            project: None,
            include_stream_usage: true,
            extra_headers: HashMap::new(),
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(default)]
struct AnthropicAdapterConfig {
    api_key: Option<String>,
    path: String,
    anthropic_version: String,
    default_max_tokens: u64,
    extra_headers: HashMap<String, String>,
}

impl Default for AnthropicAdapterConfig {
    fn default() -> Self {
        Self {
            api_key: None,
            path: DEFAULT_ANTHROPIC_PATH.to_owned(),
            anthropic_version: DEFAULT_ANTHROPIC_VERSION.to_owned(),
            default_max_tokens: DEFAULT_ANTHROPIC_MAX_TOKENS,
            extra_headers: HashMap::new(),
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(default)]
struct AiProviderAdapterConfig {
    openai: OpenAiAdapterConfig,
    anthropic: AnthropicAdapterConfig,
    /// Attach `x-shunt-provider`, `x-shunt-model`, and `x-shunt-attempt` response headers.
    response_headers: bool,
    /// Safety cap when buffering non-streaming Anthropic JSON responses for translation.
    max_non_stream_response_bytes: usize,
}

impl Default for AiProviderAdapterConfig {
    fn default() -> Self {
        Self {
            openai: OpenAiAdapterConfig::default(),
            anthropic: AnthropicAdapterConfig::default(),
            response_headers: true,
            max_non_stream_response_bytes: DEFAULT_MAX_NON_STREAM_RESPONSE_BYTES,
        }
    }
}

struct CompiledOpenAi {
    auth_header: Option<HeaderValue>,
    path_uri: Uri,
    organization: Option<HeaderValue>,
    project: Option<HeaderValue>,
    include_stream_usage: bool,
    extra_headers: Vec<(HeaderName, HeaderValue)>,
}

struct CompiledAnthropic {
    api_key_header: Option<HeaderValue>,
    path_uri: Uri,
    anthropic_version: HeaderValue,
    default_max_tokens: u64,
    extra_headers: Vec<(HeaderName, HeaderValue)>,
}

/// Per-request response translation state stored in `RequestCtx::extensions`.
#[derive(Debug, Clone)]
enum AdapterResponseState {
    Passthrough,
    AnthropicSse(Box<AnthropicSseTranslator>),
    AnthropicJson {
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

        let openai_auth = match &cfg.openai.api_key {
            Some(raw) => {
                let secret = resolve_env_secret(raw).map_err(|msg| PluginBuildError::BuildFailed {
                    plugin: self.name().to_owned(),
                    message: format!("openai.api_key: {msg}"),
                })?;
                let val = HeaderValue::from_str(&format!("Bearer {secret}")).map_err(|e| {
                    PluginBuildError::BuildFailed {
                        plugin: self.name().to_owned(),
                        message: format!("invalid openai.api_key header value: {e}"),
                    }
                })?;
                Some(val)
            }
            None => None,
        };

        let openai_path: Uri =
            cfg.openai
                .path
                .parse()
                .map_err(|e| PluginBuildError::BuildFailed {
                    plugin: self.name().to_owned(),
                    message: format!("invalid openai.path `{}`: {e}", cfg.openai.path),
                })?;

        let organization = parse_optional_header(
            self.name(),
            "openai.organization",
            cfg.openai.organization.as_deref(),
        )?;
        let project = parse_optional_header(
            self.name(),
            "openai.project",
            cfg.openai.project.as_deref(),
        )?;
        let openai_extra = compile_extra_headers(self.name(), &cfg.openai.extra_headers)?;

        let anthropic_key = match &cfg.anthropic.api_key {
            Some(raw) => {
                let secret = resolve_env_secret(raw).map_err(|msg| PluginBuildError::BuildFailed {
                    plugin: self.name().to_owned(),
                    message: format!("anthropic.api_key: {msg}"),
                })?;
                let val =
                    HeaderValue::from_str(&secret).map_err(|e| PluginBuildError::BuildFailed {
                        plugin: self.name().to_owned(),
                        message: format!("invalid anthropic.api_key header value: {e}"),
                    })?;
                Some(val)
            }
            None => None,
        };

        let anthropic_path: Uri =
            cfg.anthropic
                .path
                .parse()
                .map_err(|e| PluginBuildError::BuildFailed {
                    plugin: self.name().to_owned(),
                    message: format!("invalid anthropic.path `{}`: {e}", cfg.anthropic.path),
                })?;

        let anthropic_version =
            HeaderValue::from_str(&cfg.anthropic.anthropic_version).map_err(|e| {
                PluginBuildError::BuildFailed {
                    plugin: self.name().to_owned(),
                    message: format!("invalid anthropic.anthropic_version: {e}"),
                }
            })?;

        let anthropic_extra = compile_extra_headers(self.name(), &cfg.anthropic.extra_headers)?;

        Ok(Arc::new(AiProviderAdapterPlugin {
            openai: CompiledOpenAi {
                auth_header: openai_auth,
                path_uri: openai_path,
                organization,
                project,
                include_stream_usage: cfg.openai.include_stream_usage,
                extra_headers: openai_extra,
            },
            anthropic: CompiledAnthropic {
                api_key_header: anthropic_key,
                path_uri: anthropic_path,
                anthropic_version,
                default_max_tokens: cfg.anthropic.default_max_tokens.max(1),
                extra_headers: anthropic_extra,
            },
            response_headers: cfg.response_headers,
            max_non_stream_response_bytes: cfg.max_non_stream_response_bytes.max(1024),
        }))
    }
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
        let name = HeaderName::from_bytes(k.as_bytes()).map_err(|e| PluginBuildError::BuildFailed {
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

/// Adapts canonical OpenAI `/v1/chat/completions` requests and responses across
/// OpenAI and Anthropic upstreams (supporting both JSON and live SSE streaming).
pub struct AiProviderAdapterPlugin {
    openai: CompiledOpenAi,
    anthropic: CompiledAnthropic,
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

        let Some(target) = ctx
            .get_ext::<AiRequestMeta>()
            .and_then(AiRequestMeta::active_target)
            .cloned()
        else {
            return HookResult::Ready(Flow::Continue);
        };

        // Strip downstream credentials and disable upstream compression so body
        // translation & token inspection always receive plain JSON/SSE frames.
        req.headers.remove(header::AUTHORIZATION);
        req.headers.remove(HeaderName::from_static("x-api-key"));
        req.headers.insert(
            header::ACCEPT_ENCODING,
            HeaderValue::from_static("identity"),
        );
        req.headers.insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/json"),
        );

        match target.provider {
            AiProvider::OpenAi => {
                req.uri = self.openai.path_uri.clone();
                if let Some(auth) = &self.openai.auth_header {
                    req.headers.insert(header::AUTHORIZATION, auth.clone());
                }
                if let Some(org) = &self.openai.organization {
                    req.headers
                        .insert(HeaderName::from_static("openai-organization"), org.clone());
                }
                if let Some(proj) = &self.openai.project {
                    req.headers
                        .insert(HeaderName::from_static("openai-project"), proj.clone());
                }
                for (k, v) in &self.openai.extra_headers {
                    req.headers.insert(k.clone(), v.clone());
                }

                if let Some(body) = &req.body {
                    match rewrite_openai_request(
                        body,
                        &target.model,
                        self.openai.include_stream_usage,
                    ) {
                        Ok(Some(rewritten)) => {
                            req.body = Some(Bytes::from(rewritten));
                        }
                        Ok(None) => {}
                        Err(err) => {
                            let resp = openai_error_response(
                                StatusCode::BAD_REQUEST,
                                "invalid_request_error",
                                Some("request_translation_failed"),
                                &err,
                            );
                            return HookResult::Ready(Flow::Respond(resp));
                        }
                    }
                }
            }
            AiProvider::Anthropic => {
                req.uri = self.anthropic.path_uri.clone();
                if let Some(key) = &self.anthropic.api_key_header {
                    req.headers
                        .insert(HeaderName::from_static("x-api-key"), key.clone());
                }
                req.headers.insert(
                    HeaderName::from_static("anthropic-version"),
                    self.anthropic.anthropic_version.clone(),
                );
                for (k, v) in &self.anthropic.extra_headers {
                    req.headers.insert(k.clone(), v.clone());
                }

                if let Some(body) = &req.body {
                    match openai_to_anthropic_request(
                        body,
                        &target.model,
                        self.anthropic.default_max_tokens,
                    ) {
                        Ok(translated) => {
                            req.body = Some(Bytes::from(translated));
                        }
                        Err(err) => {
                            let resp = openai_error_response(
                                StatusCode::BAD_REQUEST,
                                "invalid_request_error",
                                Some("request_translation_failed"),
                                &err,
                            );
                            return HookResult::Ready(Flow::Respond(resp));
                        }
                    }
                }
            }
        }

        HookResult::Ready(Flow::Continue)
    }

    fn on_response_headers<'a>(
        &'a self,
        ctx: &'a mut RequestCtx,
        res: &'a mut ResponseHead,
    ) -> HookResult<'a, Flow> {
        let Some((target, stream_requested)) = ctx
            .get_ext::<AiRequestMeta>()
            .and_then(|m| m.active_target().map(|t| (t.clone(), m.stream)))
        else {
            return HookResult::Ready(Flow::Continue);
        };

        if self.response_headers {
            res.headers.insert(
                HeaderName::from_static("x-shunt-provider"),
                HeaderValue::from_static(target.provider.as_str()),
            );
            if let Ok(val) = HeaderValue::from_str(&target.model) {
                res.headers
                    .insert(HeaderName::from_static("x-shunt-model"), val);
            }
            if let Ok(val) = HeaderValue::from_str(&ctx.attempt.to_string()) {
                res.headers
                    .insert(HeaderName::from_static("x-shunt-attempt"), val);
            }
        }

        match target.provider {
            AiProvider::OpenAi => {
                ctx.insert_ext(AdapterResponseState::Passthrough);
            }
            AiProvider::Anthropic => {
                let is_sse = res
                    .headers
                    .get(header::CONTENT_TYPE)
                    .and_then(|v| v.to_str().ok())
                    .map(|ct| ct.to_ascii_lowercase().contains("text/event-stream"))
                    .unwrap_or(false);

                if res.status.is_success() && (is_sse || stream_requested) {
                    res.headers.insert(
                        header::CONTENT_TYPE,
                        HeaderValue::from_static("text/event-stream; charset=utf-8"),
                    );
                    res.headers.insert(
                        header::CACHE_CONTROL,
                        HeaderValue::from_static("no-cache"),
                    );
                    ctx.insert_ext(AdapterResponseState::AnthropicSse(Box::new(
                        AnthropicSseTranslator::new(target.model),
                    )));
                } else {
                    res.headers.insert(
                        header::CONTENT_TYPE,
                        HeaderValue::from_static("application/json"),
                    );
                    ctx.insert_ext(AdapterResponseState::AnthropicJson {
                        status: res.status,
                        fallback_model: target.model,
                        buffer: Vec::new(),
                    });
                }
            }
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

        match state {
            AdapterResponseState::Passthrough => HookResult::Ready(StreamFlow::Continue),
            AdapterResponseState::AnthropicSse(translator) => {
                if end_of_stream {
                    *chunk = translator.finish();
                } else {
                    *chunk = translator.push_chunk(chunk);
                }
                HookResult::Ready(StreamFlow::Continue)
            }
            AdapterResponseState::AnthropicJson {
                status,
                fallback_model,
                buffer,
            } => {
                if !end_of_stream {
                    if buffer.len().saturating_add(chunk.len()) > self.max_non_stream_response_bytes
                    {
                        return HookResult::Ready(StreamFlow::Abort(format!(
                            "Anthropic JSON response exceeded max_non_stream_response_bytes ({})",
                            self.max_non_stream_response_bytes
                        )));
                    }
                    buffer.extend_from_slice(chunk);
                    *chunk = Bytes::new();
                    return HookResult::Ready(StreamFlow::Continue);
                }

                if buffer.is_empty() {
                    return HookResult::Ready(StreamFlow::Continue);
                }

                match anthropic_to_openai_response(buffer, *status, fallback_model) {
                    Ok(translated) => {
                        *chunk = Bytes::from(translated);
                    }
                    Err(err) => {
                        warn!(error = %err, "failed to translate Anthropic JSON response; passing raw body");
                        *chunk = Bytes::from(std::mem::take(buffer));
                    }
                }
                HookResult::Ready(StreamFlow::Continue)
            }
        }
    }
}
