use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Instant;

use serde::Deserialize;
use shunt_plugin_sdk::{
    BufferedResponse, BuildContext, Flow, HeaderName, HeaderValue, HookMask, HookResult,
    HttpPlugin, PluginBuildError, PluginConfig, PluginFactory, RequestCtx, RequestHead,
    ResponseHead, StatusCode, header,
};

#[derive(Debug, Clone)]
struct RateLimitRemaining(u32);

#[derive(Debug, Deserialize, Default, Clone, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum KeyStrategy {
    Global,
    #[default]
    ClientIp,
    Header,
}

#[derive(Debug, Deserialize)]
#[serde(default)]
struct RateLimitConfig {
    requests_per_second: f64,
    burst: u32,
    key: KeyStrategy,
    header_name: Option<String>,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            requests_per_second: 100.0,
            burst: 100,
            key: KeyStrategy::ClientIp,
            header_name: None,
        }
    }
}

#[derive(Debug)]
struct TokenBucket {
    tokens: f64,
    last_refill: Instant,
}

impl TokenBucket {
    fn new(burst: u32) -> Self {
        Self {
            tokens: f64::from(burst),
            last_refill: Instant::now(),
        }
    }

    /// Attempts to consume 1 token. Returns `Ok(remaining)` or `Err(retry_after_secs)`.
    fn try_consume(&mut self, rps: f64, burst: f64, now: Instant) -> Result<u32, u64> {
        let elapsed = now.saturating_duration_since(self.last_refill).as_secs_f64();
        if elapsed > 0.0 {
            self.tokens = (self.tokens + elapsed * rps).min(burst);
            self.last_refill = now;
        }

        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            Ok(self.tokens.floor() as u32)
        } else {
            let needed = 1.0 - self.tokens;
            let wait_secs = (needed / rps).ceil().max(1.0) as u64;
            Err(wait_secs)
        }
    }
}

#[derive(Debug, Default)]
struct BucketTable {
    buckets: Mutex<HashMap<String, TokenBucket>>,
}

pub struct RateLimitFactory;

impl PluginFactory for RateLimitFactory {
    fn name(&self) -> &str {
        "rate-limit"
    }

    fn build(
        &self,
        config: &PluginConfig,
        ctx: &BuildContext,
    ) -> Result<Arc<dyn HttpPlugin>, PluginBuildError> {
        let cfg: RateLimitConfig = config.deserialize(self.name())?;
        if !(cfg.requests_per_second.is_finite() && cfg.requests_per_second > 0.0) {
            return Err(PluginBuildError::BuildFailed {
                plugin: self.name().to_owned(),
                message: "`requests_per_second` must be a positive finite number".to_owned(),
            });
        }
        if cfg.burst == 0 {
            return Err(PluginBuildError::BuildFailed {
                plugin: self.name().to_owned(),
                message: "`burst` must be >= 1".to_owned(),
            });
        }

        let header_name = if cfg.key == KeyStrategy::Header {
            let raw = cfg.header_name.as_deref().ok_or_else(|| {
                PluginBuildError::BuildFailed {
                    plugin: self.name().to_owned(),
                    message: "`header_name` is required when `key = \"header\"`".to_owned(),
                }
            })?;
            Some(HeaderName::from_bytes(raw.as_bytes()).map_err(|e| {
                PluginBuildError::BuildFailed {
                    plugin: self.name().to_owned(),
                    message: format!("invalid header_name `{raw}`: {e}"),
                }
            })?)
        } else {
            None
        };

        // Acquire persistent state from RuntimeRegistry's StateStore so rate-limit
        // buckets survive hot config reloads without resetting!
        let state = ctx
            .state_handle()
            .get_or_init("token_buckets", BucketTable::default);

        Ok(Arc::new(RateLimitPlugin {
            rps: cfg.requests_per_second,
            burst: cfg.burst,
            key_strategy: cfg.key,
            header_name,
            state,
        }))
    }
}

pub struct RateLimitPlugin {
    rps: f64,
    burst: u32,
    key_strategy: KeyStrategy,
    header_name: Option<HeaderName>,
    state: Arc<BucketTable>,
}

impl HttpPlugin for RateLimitPlugin {
    fn name(&self) -> &str {
        "rate-limit"
    }

    fn hook_mask(&self) -> HookMask {
        HookMask::ON_REQUEST_HEADERS | HookMask::ON_RESPONSE_HEADERS
    }

    fn on_request_headers<'a>(
        &'a self,
        ctx: &'a mut RequestCtx,
        req: &'a mut RequestHead,
    ) -> HookResult<'a, Flow> {
        let bucket_key = match self.key_strategy {
            KeyStrategy::Global => "global".to_owned(),
            KeyStrategy::ClientIp => ctx.client_addr.ip().to_string(),
            KeyStrategy::Header => self
                .header_name
                .as_ref()
                .and_then(|name| req.headers.get(name))
                .and_then(|v| v.to_str().ok())
                .map(str::to_owned)
                .unwrap_or_else(|| ctx.client_addr.ip().to_string()),
        };

        let now = Instant::now();
        let outcome = {
            let mut map = self.state.buckets.lock().expect("BucketTable lock poisoned");
            let bucket = map
                .entry(bucket_key)
                .or_insert_with(|| TokenBucket::new(self.burst));
            bucket.try_consume(self.rps, f64::from(self.burst), now)
        };

        match outcome {
            Ok(remaining) => {
                ctx.insert_ext(RateLimitRemaining(remaining));
                HookResult::Ready(Flow::Continue)
            }
            Err(retry_after) => {
                let mut resp = BufferedResponse::json(
                    StatusCode::TOO_MANY_REQUESTS,
                    r#"{"error":"rate_limit_exceeded"}"#,
                );
                if let Ok(v) = HeaderValue::from_str(&retry_after.to_string()) {
                    resp.headers.insert(header::RETRY_AFTER, v);
                }
                if let Ok(v) = HeaderValue::from_str(&self.burst.to_string()) {
                    resp.headers
                        .insert(HeaderName::from_static("x-ratelimit-limit"), v);
                }
                resp.headers.insert(
                    HeaderName::from_static("x-ratelimit-remaining"),
                    HeaderValue::from_static("0"),
                );
                HookResult::Ready(Flow::Respond(resp))
            }
        }
    }

    fn on_response_headers<'a>(
        &'a self,
        ctx: &'a mut RequestCtx,
        res: &'a mut ResponseHead,
    ) -> HookResult<'a, Flow> {
        if let Some(RateLimitRemaining(rem)) = ctx.get_ext::<RateLimitRemaining>() {
            if let Ok(v) = HeaderValue::from_str(&self.burst.to_string()) {
                res.headers
                    .insert(HeaderName::from_static("x-ratelimit-limit"), v);
            }
            if let Ok(v) = HeaderValue::from_str(&rem.to_string()) {
                res.headers
                    .insert(HeaderName::from_static("x-ratelimit-remaining"), v);
            }
        }
        HookResult::Ready(Flow::Continue)
    }
}
