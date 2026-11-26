use std::sync::Arc;

use serde::Deserialize;
use shunt_plugin_sdk::{
    BufferedResponse, BuildContext, Flow, HeaderMap, HeaderValue, HookMask, HookResult, HttpPlugin,
    Method, PluginBuildError, PluginConfig, PluginFactory, RequestCtx, RequestHead, ResponseHead,
    StatusCode, header,
};

#[derive(Debug, Clone)]
struct MatchedCorsOrigin(String);

#[derive(Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct CorsConfig {
    allow_origins: Vec<String>,
    allow_methods: Vec<String>,
    allow_headers: Vec<String>,
    expose_headers: Vec<String>,
    allow_credentials: bool,
    max_age_secs: Option<u64>,
}

impl Default for CorsConfig {
    fn default() -> Self {
        Self {
            allow_origins: vec!["*".to_owned()],
            allow_methods: vec![
                "GET".to_owned(),
                "POST".to_owned(),
                "PUT".to_owned(),
                "PATCH".to_owned(),
                "DELETE".to_owned(),
                "OPTIONS".to_owned(),
            ],
            allow_headers: vec!["authorization".to_owned(), "content-type".to_owned()],
            expose_headers: Vec::new(),
            allow_credentials: false,
            max_age_secs: Some(600),
        }
    }
}

pub struct CorsFactory;

impl PluginFactory for CorsFactory {
    fn name(&self) -> &str {
        "cors"
    }

    fn build(
        &self,
        config: &PluginConfig,
        _ctx: &BuildContext,
    ) -> Result<Arc<dyn HttpPlugin>, PluginBuildError> {
        let cfg: CorsConfig = config.deserialize(self.name())?;
        let allow_any = cfg.allow_origins.iter().any(|o| o == "*");
        if allow_any && cfg.allow_credentials {
            return Err(PluginBuildError::BuildFailed {
                plugin: self.name().to_owned(),
                message: "cannot combine `allow_origins = [\"*\"]` with `allow_credentials = true`"
                    .to_owned(),
            });
        }

        let allow_methods = HeaderValue::from_str(&cfg.allow_methods.join(", ")).map_err(|e| {
            PluginBuildError::BuildFailed {
                plugin: self.name().to_owned(),
                message: format!("invalid allow_methods: {e}"),
            }
        })?;
        let allow_headers = HeaderValue::from_str(&cfg.allow_headers.join(", ")).map_err(|e| {
            PluginBuildError::BuildFailed {
                plugin: self.name().to_owned(),
                message: format!("invalid allow_headers: {e}"),
            }
        })?;
        let expose_headers = if cfg.expose_headers.is_empty() {
            None
        } else {
            Some(
                HeaderValue::from_str(&cfg.expose_headers.join(", ")).map_err(|e| {
                    PluginBuildError::BuildFailed {
                        plugin: self.name().to_owned(),
                        message: format!("invalid expose_headers: {e}"),
                    }
                })?,
            )
        };
        let max_age = cfg
            .max_age_secs
            .and_then(|s| HeaderValue::from_str(&s.to_string()).ok());

        Ok(Arc::new(CorsPlugin {
            allow_any,
            allow_origins: cfg.allow_origins,
            allow_methods,
            allow_headers,
            expose_headers,
            allow_credentials: cfg.allow_credentials,
            max_age,
        }))
    }
}

pub struct CorsPlugin {
    allow_any: bool,
    allow_origins: Vec<String>,
    allow_methods: HeaderValue,
    allow_headers: HeaderValue,
    expose_headers: Option<HeaderValue>,
    allow_credentials: bool,
    max_age: Option<HeaderValue>,
}

impl CorsPlugin {
    fn resolve_origin(&self, origin: &str) -> Option<String> {
        if self.allow_any {
            Some("*".to_owned())
        } else if self.allow_origins.iter().any(|o| o == origin) {
            Some(origin.to_owned())
        } else {
            None
        }
    }

    fn apply_common_headers(&self, headers: &mut HeaderMap, matched_origin: &str) {
        if let Ok(v) = HeaderValue::from_str(matched_origin) {
            headers.insert(header::ACCESS_CONTROL_ALLOW_ORIGIN, v);
        }
        if !self.allow_any {
            headers.append(header::VARY, HeaderValue::from_static("Origin"));
        }
        if self.allow_credentials {
            headers.insert(
                header::ACCESS_CONTROL_ALLOW_CREDENTIALS,
                HeaderValue::from_static("true"),
            );
        }
        if let Some(expose) = &self.expose_headers {
            headers.insert(header::ACCESS_CONTROL_EXPOSE_HEADERS, expose.clone());
        }
    }
}

impl HttpPlugin for CorsPlugin {
    fn name(&self) -> &str {
        "cors"
    }

    fn hook_mask(&self) -> HookMask {
        HookMask::ON_REQUEST_HEADERS | HookMask::ON_RESPONSE_HEADERS
    }

    fn on_request_headers<'a>(
        &'a self,
        ctx: &'a mut RequestCtx,
        req: &'a mut RequestHead,
    ) -> HookResult<'a, Flow> {
        let Some(origin) = req
            .headers
            .get(header::ORIGIN)
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned)
        else {
            return HookResult::Ready(Flow::Continue);
        };

        let Some(allowed_origin) = self.resolve_origin(&origin) else {
            return HookResult::Ready(Flow::Continue);
        };

        // Short-circuit CORS preflight (`OPTIONS` + `Access-Control-Request-Method`).
        if req.method == Method::OPTIONS
            && req
                .headers
                .contains_key(header::ACCESS_CONTROL_REQUEST_METHOD)
        {
            let mut resp = BufferedResponse::new(StatusCode::NO_CONTENT, Vec::new());
            self.apply_common_headers(&mut resp.headers, &allowed_origin);
            resp.headers.insert(
                header::ACCESS_CONTROL_ALLOW_METHODS,
                self.allow_methods.clone(),
            );
            resp.headers.insert(
                header::ACCESS_CONTROL_ALLOW_HEADERS,
                self.allow_headers.clone(),
            );
            if let Some(max_age) = &self.max_age {
                resp.headers
                    .insert(header::ACCESS_CONTROL_MAX_AGE, max_age.clone());
            }
            return HookResult::Ready(Flow::Respond(resp));
        }

        ctx.insert_ext(MatchedCorsOrigin(allowed_origin));
        HookResult::Ready(Flow::Continue)
    }

    fn on_response_headers<'a>(
        &'a self,
        ctx: &'a mut RequestCtx,
        res: &'a mut ResponseHead,
    ) -> HookResult<'a, Flow> {
        if let Some(MatchedCorsOrigin(origin)) = ctx.get_ext::<MatchedCorsOrigin>() {
            self.apply_common_headers(&mut res.headers, origin);
        }
        HookResult::Ready(Flow::Continue)
    }
}
