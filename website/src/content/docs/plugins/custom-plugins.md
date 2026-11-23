---
title: Writing Custom Plugins
description: Build zero-overhead Rust plugins using shunt-plugin-sdk with HookMask, HookResult::Ready, StateStore, and HttpClient.
---

First-party and third-party plugins use the **exact same** `shunt-plugin-sdk` crate—with zero `hyper` internals exposed.

## 1. Implement `HttpPlugin`

Declare only the hooks your plugin needs in `hook_mask()`, and return `HookResult::Ready(...)` whenever no async I/O is required to stay on the zero-allocation sync fast path:

```rust
use shunt_plugin_sdk::{
    Flow, HeaderName, HeaderValue, HookMask, HookResult, HttpPlugin, RequestCtx, RequestHead,
};

pub struct PoweredByPlugin;

impl HttpPlugin for PoweredByPlugin {
    fn name(&self) -> &str {
        "powered-by"
    }

    fn hook_mask(&self) -> HookMask {
        HookMask::ON_REQUEST_HEADERS
    }

    fn on_request_headers<'a>(
        &'a self,
        _ctx: &'a mut RequestCtx,
        req: &'a mut RequestHead,
    ) -> HookResult<'a, Flow> {
        req.headers.insert(
            HeaderName::from_static("x-gateway"),
            HeaderValue::from_static("shunt"),
        );
        HookResult::Ready(Flow::Continue)
    }
}
```

## 2. Implement `PluginFactory`

Parse typed config once during snapshot compilation so invalid configs fail fast before live traffic ever hits the plugin:

```rust
use std::sync::Arc;
use serde::Deserialize;
use shunt_plugin_sdk::{HttpPlugin, PluginBuildContext, PluginBuildError, PluginFactory};

#[derive(Deserialize)]
struct PoweredByConfig {
    #[serde(default = "default_value")]
    value: String,
}

fn default_value() -> String {
    "shunt".to_owned()
}

pub struct PoweredByFactory;

impl PluginFactory for PoweredByFactory {
    fn name(&self) -> &str {
        "powered-by"
    }

    fn build(
        &self,
        raw_config: serde_json::Value,
        _ctx: &PluginBuildContext,
    ) -> Result<Arc<dyn HttpPlugin>, PluginBuildError> {
        let _cfg: PoweredByConfig = serde_json::from_value(raw_config)
            .map_err(|e| PluginBuildError::InvalidConfig(e.to_string()))?;
        Ok(Arc::new(PoweredByPlugin))
    }
}
```

## 3. SDK Capabilities Available to Plugins

- **Typed `RequestCtx::extensions`:** Share typed state between plugins on the same request (e.g., auth principal from `jwt-auth` consumed by `mcp-auth` or custom plugins).
- **Reload-Persistent `StateStore` (`ctx.state_store()`):** Store counters, rate-limit buckets, or caches keyed by plugin `id`—automatically backed by either in-process memory or Redis/Valkey.
- **Outbound `HttpClient` (`ctx.http_client()`):** Make pooled async HTTP/HTTPS calls (for JWKS refresh, OPA webhooks, external guardrails, or Cloud IAM) without adding another HTTP client crate.
- **Dynamic Routing & Retries:** Set `ctx.set_upstream_override(...)` and return `Flow::RetryUpstream` from `on_response_headers` or `on_upstream_error` to drive custom failover loops.
- **Short-Circuiting:** Return `Flow::Respond(response)` from any pre-upstream hook to answer immediately with zero upstream I/O.
