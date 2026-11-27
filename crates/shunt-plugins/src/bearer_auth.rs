use std::sync::Arc;

use serde::Deserialize;
use shunt_plugin_sdk::{
    BufferedResponse, BuildContext, Flow, HeaderValue, HookMask, HookResult, HttpPlugin,
    PluginBuildError, PluginConfig, PluginFactory, RequestCtx, RequestHead, StatusCode, header,
};

/// Authenticated subject attached to [`RequestCtx::extensions`] on successful bearer auth.
#[derive(Debug, Clone)]
pub struct AuthSubject(pub String);

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum TokenSpec {
    Plain(String),
    Named { token: String, subject: String },
}

#[derive(Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct BearerAuthConfig {
    tokens: Vec<TokenSpec>,
    realm: String,
    strip_header: bool,
}

impl Default for BearerAuthConfig {
    fn default() -> Self {
        Self {
            tokens: Vec::new(),
            realm: "shunt".to_owned(),
            strip_header: true,
        }
    }
}

struct CompiledToken {
    secret: Vec<u8>,
    subject: String,
}

pub struct BearerAuthFactory;

impl PluginFactory for BearerAuthFactory {
    fn name(&self) -> &str {
        "bearer-auth"
    }

    fn build(
        &self,
        config: &PluginConfig,
        _ctx: &BuildContext,
    ) -> Result<Arc<dyn HttpPlugin>, PluginBuildError> {
        let cfg: BearerAuthConfig = config.deserialize(self.name())?;
        if cfg.tokens.is_empty() {
            return Err(PluginBuildError::BuildFailed {
                plugin: self.name().to_owned(),
                message: "bearer-auth requires at least one token in `tokens`".to_owned(),
            });
        }

        let mut compiled = Vec::with_capacity(cfg.tokens.len());
        for (idx, spec) in cfg.tokens.into_iter().enumerate() {
            let (raw_token, subject) = match spec {
                TokenSpec::Plain(t) => (t, format!("token-{idx}")),
                TokenSpec::Named { token, subject } => (token, subject),
            };
            let resolved =
                resolve_env_secret(&raw_token).map_err(|msg| PluginBuildError::BuildFailed {
                    plugin: self.name().to_owned(),
                    message: msg,
                })?;
            if resolved.is_empty() {
                return Err(PluginBuildError::BuildFailed {
                    plugin: self.name().to_owned(),
                    message: format!("token for subject `{subject}` resolved to empty string"),
                });
            }
            compiled.push(CompiledToken {
                secret: resolved.into_bytes(),
                subject,
            });
        }

        let escaped_realm = cfg.realm.replace('\\', "\\\\").replace('"', "\\\"");
        let www_authenticate = HeaderValue::from_str(&format!("Bearer realm=\"{escaped_realm}\""))
            .unwrap_or_else(|_| HeaderValue::from_static("Bearer"));

        Ok(Arc::new(BearerAuthPlugin {
            tokens: compiled,
            www_authenticate,
            strip_header: cfg.strip_header,
        }))
    }
}

fn resolve_env_secret(raw: &str) -> Result<String, String> {
    if let Some(var_name) = raw.strip_prefix("env:") {
        std::env::var(var_name).map_err(|_| format!("environment variable `{var_name}` not set"))
    } else {
        Ok(raw.to_owned())
    }
}

/// Constant-time byte slice equality to prevent timing side-channels on bearer tokens.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (&x, &y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

pub struct BearerAuthPlugin {
    tokens: Vec<CompiledToken>,
    www_authenticate: HeaderValue,
    strip_header: bool,
}

impl HttpPlugin for BearerAuthPlugin {
    fn name(&self) -> &str {
        "bearer-auth"
    }

    fn hook_mask(&self) -> HookMask {
        HookMask::ON_REQUEST_HEADERS
    }

    fn on_request_headers<'a>(
        &'a self,
        ctx: &'a mut RequestCtx,
        req: &'a mut RequestHead,
    ) -> HookResult<'a, Flow> {
        let mut auth_headers = req.headers.get_all(header::AUTHORIZATION).iter();
        let first_auth = auth_headers.next();
        if auth_headers.next().is_some() {
            return HookResult::Ready(Flow::Respond(BufferedResponse::json(
                StatusCode::BAD_REQUEST,
                r#"{"error":"multiple_authorization_headers"}"#,
            )));
        }

        let presented = first_auth
            .and_then(|v| v.to_str().ok())
            .and_then(|s| {
                let trimmed = s.trim();
                let prefix = trimmed.get(..7)?;
                if prefix.eq_ignore_ascii_case("bearer ") {
                    Some(trimmed[7..].trim())
                } else {
                    None
                }
            })
            .filter(|s| !s.is_empty());

        if let Some(token) = presented {
            let token_bytes = token.as_bytes();
            let mut matched_subject: Option<&str> = None;
            for candidate in &self.tokens {
                if constant_time_eq(token_bytes, &candidate.secret) {
                    matched_subject = Some(candidate.subject.as_str());
                }
            }
            if let Some(subject) = matched_subject {
                ctx.insert_ext(AuthSubject(subject.to_owned()));
                if self.strip_header {
                    req.headers.remove(header::AUTHORIZATION);
                }
                return HookResult::Ready(Flow::Continue);
            }
        }

        let resp = BufferedResponse::json(StatusCode::UNAUTHORIZED, r#"{"error":"unauthorized"}"#)
            .with_header(header::WWW_AUTHENTICATE, self.www_authenticate.clone());

        HookResult::Ready(Flow::Respond(resp))
    }
}
