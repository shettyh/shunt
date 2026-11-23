---
title: Architecture & HookMask
description: Understand Shunt's strict crate isolation, zero-allocation HookMask fast path, hybrid sync/async dispatch, and ArcSwap atomic reloads.
---

Shunt is built around four architectural invariants that keep it fast, small, and easy to reason about.

## High-Level Data & Control Plane

<div class="shunt-diagram-frame">
<svg viewBox="0 0 760 220" fill="none" xmlns="http://www.w3.org/2000/svg" role="img" aria-label="Shunt control plane and data plane architecture">
  <rect x="16" y="18" width="210" height="58" rx="8" fill="var(--sl-color-bg)" stroke="var(--sl-color-hairline)" stroke-width="1.3"/>
  <text x="121" y="42" text-anchor="middle" fill="var(--sl-color-white)" font-size="12" font-weight="700">Config Providers</text>
  <text x="121" y="60" text-anchor="middle" fill="var(--sl-color-gray-3)" font-family="monospace" font-size="10">shunt.toml · YAML · K8s Gateway API</text>

  <line x1="226" y1="47" x2="278" y2="47" stroke="var(--sl-color-accent)" stroke-width="1.8" stroke-dasharray="4 3"/>

  <rect x="278" y="18" width="206" height="58" rx="8" fill="var(--sl-color-bg)" stroke="var(--sl-color-accent)" stroke-width="1.4"/>
  <text x="381" y="42" text-anchor="middle" fill="var(--sl-color-white)" font-size="12" font-weight="700">SnapshotCompiler + ArcSwap</text>
  <text x="381" y="60" text-anchor="middle" fill="var(--sl-color-accent)" font-family="monospace" font-size="10">IR Validate → Precompute HookMask</text>

  <line x1="484" y1="47" x2="536" y2="47" stroke="var(--sl-color-hairline)" stroke-width="1.6"/>

  <rect x="536" y="18" width="208" height="58" rx="8" fill="var(--sl-color-bg)" stroke="var(--sl-color-hairline)" stroke-width="1.3"/>
  <text x="640" y="42" text-anchor="middle" fill="var(--sl-color-white)" font-size="12" font-weight="700">Admin Plane (:9090)</text>
  <text x="640" y="60" text-anchor="middle" fill="var(--sl-color-gray-3)" font-family="monospace" font-size="10">/health · /metrics · /ui · /reload</text>

  <line x1="381" y1="76" x2="381" y2="122" stroke="var(--sl-color-accent)" stroke-width="1.8"/>
  <text x="392" y="103" fill="var(--sl-color-gray-3)" font-family="monospace" font-size="10">lock-free Arc load / request</text>

  <rect x="16" y="124" width="728" height="80" rx="10" fill="var(--sl-color-bg)" stroke="var(--sl-color-accent)" stroke-width="1.4" stroke-dasharray="5 3"/>
  <text x="34" y="144" fill="var(--sl-color-accent)" font-family="monospace" font-size="10" font-weight="700">SHUNT-ENGINE DATA PLANE (STRICTLY TRANSPORT-ONLY)</text>

  <rect x="34" y="154" width="148" height="36" rx="6" fill="var(--sl-color-gray-6)" stroke="var(--sl-color-hairline)"/>
  <text x="108" y="176" text-anchor="middle" fill="var(--sl-color-white)" font-family="monospace" font-size="11">Listener / SNI mTLS</text>

  <line x1="182" y1="172" x2="212" y2="172" stroke="var(--sl-color-accent)" stroke-width="1.6"/>

  <rect x="212" y="154" width="150" height="36" rx="6" fill="var(--sl-color-gray-6)" stroke="var(--sl-color-hairline)"/>
  <text x="287" y="176" text-anchor="middle" fill="var(--sl-color-white)" font-family="monospace" font-size="11">Route + HookMask</text>

  <line x1="362" y1="172" x2="392" y2="172" stroke="var(--sl-color-accent)" stroke-width="1.6"/>

  <rect x="392" y="154" width="160" height="36" rx="6" fill="var(--sl-color-gray-6)" stroke="var(--sl-color-accent)"/>
  <text x="472" y="176" text-anchor="middle" fill="var(--sl-color-white)" font-family="monospace" font-size="11">Plugin Chain (SDK)</text>

  <line x1="552" y1="172" x2="582" y2="172" stroke="var(--sl-color-accent)" stroke-width="1.6"/>

  <rect x="582" y="154" width="144" height="36" rx="6" fill="var(--sl-color-gray-6)" stroke="var(--sl-color-hairline)"/>
  <text x="654" y="176" text-anchor="middle" fill="var(--sl-color-white)" font-family="monospace" font-size="11">Upstream Pool</text>
</svg>
</div>

## 1. Strict Crate Isolation

Every feature above raw HTTP/TLS/WebSocket/SSE transport lives strictly on top of `shunt-plugin-sdk`. **Zero AI or MCP concepts ever leak into `shunt-engine`.**

| Crate | Role |
| --- | --- |
| `shunt-plugin-sdk` | Public traits (`HttpPlugin`, `PluginFactory`), `HookMask`, `HookResult`, `Flow`, `StateStore`, `HttpClient` (zero `hyper` internals) |
| `shunt-engine` | `tokio` + `hyper` v1 + `rustls` data plane, `ArcSwap` snapshots, hook runner, connection pools, active/passive health, retry loop, OTLP exporter |
| `shunt-config` | Canonical IR, TOML/YAML & Kubernetes Gateway API v1 providers, `SnapshotCompiler`, static verifier, Admin API & Inspector UI |
| `shunt-plugins` | 15 general HTTP gateway plugins |
| `shunt-ai` | 11 multi-provider AI gateway plugins |
| `shunt-mcp` | 5 MCP & agentic governance plugins |
| `shunt-test` | Declarative TOML conformance test harness and in-process mock upstreams |
| `shunt-cli` | `shunt` CLI binary (`check`, `verify`, `test`, `dev`, `run`) |

## 2. Pay Only for What You Use (`HookMask`)

At snapshot compile time, Shunt unions the `HookMask` bitflags declared by every plugin attached to a route and bakes that mask into the compiled route:

- **Routes with `HookMask::EMPTY`** skip the hook runner completely and stream bytes zero-copy.
- **Routes without body hooks** (`REQUEST_BODY_BUFFERED` / `RESPONSE_BODY_BUFFERED`) never buffer request or response payloads.
- **Per-chunk streaming hooks** (`ON_RESPONSE_BODY_CHUNK`) run only on routes with plugins that opt in (e.g., live SSE translation, streaming compression, or streaming guardrails).

Run `shunt check -c shunt.toml` to inspect the compiled `HookMask` for every route.

## 3. Hybrid Sync / Async Dispatch

Most gateway logic (header manipulation, routing decisions, token-bucket checks, SSE parsing, CIDR checks) completes synchronously in memory. Instead of allocating a `Box<dyn Future>` on every hook call, `HttpPlugin` returns:

```rust
pub enum HookResult<'a, T = Flow> {
    Ready(T),
    Pending(BoxFuture<'a, T>),
}
```

- **`HookResult::Ready`** — zero heap allocation on the hot path.
- **`HookResult::Pending`** — only used when a hook performs genuine async I/O (Redis state, JWKS fetch, Cloud IAM refresh, external guardrail callout, semantic embedding lookup).

## 4. Request Lifecycle & Per-Attempt Loop

```text
Incoming Request
  ├─ 1. on_request_headers(ctx, req)            [can short-circuit Flow::Respond]
  ├─ 2. on_request_body_buffered(ctx, &mut Bytes) [only if REQUEST_BODY_BUFFERED]
  ├─ 3. Per-attempt upstream loop (1..=max_attempts):
  │      ├─ on_upstream_request(ctx, req)       [inject provider auth / rewrite path]
  │      ├─ Send request (connect_timeout + response_headers_timeout)
  │      ├─ on_upstream_error(ctx, err)         [can trigger Flow::RetryUpstream]
  │      ├─ on_response_headers(ctx, resp)      [can trigger Flow::RetryUpstream]
  │      ├─ on_response_body_chunk(ctx, chunk)  [streaming transform / SSE translate]
  │      └─ on_response_body_buffered(ctx, body)[buffered response inspect/cache]
  └─ 4. on_complete(ctx, &CompletionInfo)       [always runs: metrics, budgets, audit, traces]
```

## 5. Lock-Free Atomic Reloads (`ArcSwap`)

When configuration or TLS certificates change (via file watcher, `POST /reload`, `SIGHUP`, or live Kubernetes sync):

1. The new config is parsed, structurally validated, and compiled into a fresh `GatewaySnapshot`.
2. If **anything** fails (syntax, missing env var, bad TLS cert, invalid plugin config), the reload is rejected and the active snapshot continues serving untouched.
3. On success, Shunt swaps the `Arc<GatewaySnapshot>` atomically via `ArcSwap`:
   - New requests immediately see the new snapshot.
   - In-flight requests and long-lived SSE/WebSocket streams finish cleanly on the snapshot they started with.
   - Warm upstream connection pools and stateful plugin stores (keyed by plugin `id`) are reused seamlessly across reloads.
