# RFC 0001: Plugin SDK & Request Lifecycle

- **Status:** Implemented
- **Crates:** `shunt-plugin-sdk`, `shunt-core`

## Summary

This RFC defines Shunt's plugin contract (`HttpPlugin`, `HookMask`, `HookResult`, `Flow`, `StreamFlow`, `RequestCtx`) and the 7-stage request execution pipeline in `shunt-core`. Every feature above raw HTTP/TLS transport—first-party or third-party—is implemented through this single public SDK with zero privileged internal shortcuts.

## Motivation

Most HTTP gateways suffer from one of two extremes:

1. **Monolithic cores** that accumulate domain-specific logic (auth, retries, AI routing, rate limiting) inside the proxy engine, making the core hard to read and evolve.
2. **Over-abstracted middleware stacks** (e.g., nested async `Service` wrappers around every request/body) that allocate boxed futures on every hop, buffer bodies unexpectedly, or couple plugin authors tightly to internal transport types (`hyper::body::Incoming`).

Shunt needs a plugin seam that is:
- **Zero-cost when unused** (a 0-plugin passthrough route should run unbuffered and allocation-free).
- **Expressive enough for real proxies and AI gateways** (opt-in body inspection, dynamic routing, per-attempt request rewriting, live SSE chunk translation, and mid-stream fault isolation).
- **Decoupled from `hyper`** so the SDK remains small, stable, and clean for a future Wasm Component Model / WIT bridge.

## Goals & Non-Goals

### Goals
- Expose clean HTTP types (`http` crate types + `bytes::Bytes`) without leaking `hyper` internals.
- Avoid heap-allocating futures for synchronous in-memory hooks.
- Skip unused lifecycle hooks in O(1) via precomputed per-route bitmasks.
- Support both zero-copy streaming passthrough and bounded opt-in request buffering.
- Support multi-attempt upstream retries/failover with target-specific mutation on every attempt.
- Isolate plugin panics cleanly at the hook boundary (both pre-flush and mid-stream).

### Non-Goals
- Dynamic runtime loading (`dlopen` / Wasm) in v1 (deferred to v2+).
- Full response-body buffering hook in the SDK (plugins that need bounded response buffering can accumulate inside `on_response_body_chunk` and flush on `end_of_stream = true`).

## Design

### 1. Hybrid Sync/Async Dispatch (`HookResult`)

Most proxy hooks are purely in-memory (header rewrites, bearer token checks, local token buckets, SSE framing, JSON parsing). Making every hook `async fn` in a dyn trait forces a `Pin<Box<dyn Future>>` allocation per hook call.

Instead, every `HttpPlugin` method returns `HookResult<'a, T>`:

```rust
pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

pub enum HookResult<'a, T = Flow> {
    Ready(T),
    Pending(BoxFuture<'a, T>),
}
```

- Synchronous hooks return `HookResult::Ready(...)` with **zero heap allocation**.
- Hooks that perform real async I/O (remote auth, Redis lookup) return `HookResult::pending(async move { ... })`.
- The pipeline resolves `HookResult` by only awaiting when `Pending` is returned.

### 2. Per-Route `HookMask` Bitmasks

Each plugin declares the exact hooks it participates in via `HttpPlugin::hook_mask(&self) -> HookMask` (a `Copy` `u32` bitflag):

```text
ON_REQUEST_HEADERS    (1 << 0)
REQUEST_BODY_BUFFERED (1 << 1)
REQUEST_BODY_STREAM   (1 << 2)
ON_ROUTE              (1 << 3)
ON_UPSTREAM_SELECT    (1 << 4)
ON_UPSTREAM_REQUEST   (1 << 5)
ON_RESPONSE_HEADERS   (1 << 6)
RESPONSE_BODY_STREAM  (1 << 7)
ON_COMPLETE           (1 << 8)
```

During snapshot compilation, `SnapshotBuilder` ORs the `HookMask` of every plugin (global + route) into `CompiledRoute::hook_mask`. On the hot path:
- If `hook_mask` lacks `REQUEST_BODY_BUFFERED`, the incoming request body is **never buffered**.
- If `hook_mask` lacks `RESPONSE_BODY_STREAM` and `ON_COMPLETE`, the upstream response body flows through as a **zero-copy passthrough** (`ShuntBody::Passthrough`).
- Each stage skips the entire plugin loop with a single bitwise check.

### 3. Seven-Stage Lifecycle & Per-Attempt Loop

```text
Incoming Request
  │
  ├─ 1. on_request_headers(ctx, &mut RequestHead)
  │       └─ Flow::Respond(BufferedResponse) short-circuits immediately
  │
  ├─ 2. [if HookMask::REQUEST_BODY_BUFFERED]
  │       Buffer body up to effective max_body_bytes (413 Payload Too Large on overflow)
  │       └─ on_request_body_buffered(ctx, &mut Bytes)
  │
  ├─ 3. on_route(ctx, &mut RouteDecision)          [override upstream / max_attempts]
  │
  ├─ 4. Per-Attempt Upstream Loop (attempt = 1..=max_attempts):
  │       ├─ 4a. on_upstream_select(ctx, &mut UpstreamSelection)
  │       ├─ 4b. Clone canonical RequestHead + O(1) refcount clone of buffered Bytes
  │       ├─ 4c. on_upstream_request(ctx, &mut UpstreamRequest)
  │       │        [target-specific auth, URI rewrite, body translation]
  │       ├─ 4d. Send via UpstreamPool (connect_timeout + response_headers_timeout)
  │       │        [transport/timeout errors auto-retry if attempts remain & replayable]
  │       └─ 4e. on_response_headers(ctx, &mut ResponseHead)
  │                └─ Flow::RetryUpstream (only pre-flush & if body empty or buffered)
  │
  ├─ 5. Commit response headers downstream
  │
  ├─ 6. Stream response body (enforcing idle_chunk_timeout):
  │       ├─ [if HookMask::RESPONSE_BODY_STREAM]: bounded mpsc pump (cap 16)
  │       │    calls on_response_body_chunk(ctx, &mut Bytes, false) per chunk,
  │       │    and on_response_body_chunk(ctx, &mut Bytes, true) at EOF to flush buffers
  │       └─ [else]: zero-copy passthrough (optionally byte-counted for on_complete)
  │
  └─ 7. on_complete(ctx, &RequestSummary)          [off hot path, after flush/abort]
```

### 4. Key Invariants

- **Canonical replay on retry:** Stages 4b–4c always start from a fresh clone of the canonical `RequestHead` and `Bytes` (an O(1) refcount increment). Provider-specific mutations on Attempt 1 (headers, path, translated body) never leak into Attempt 2.
- **Mandatory body cap:** Whenever `REQUEST_BODY_BUFFERED` is enabled, `SnapshotBuilder` takes the minimum of the route's `max_body_bytes` and all plugins' `max_request_body_bytes()` (defaulting to `1 MiB`). Both upfront `Content-Length` checks and streaming byte counting enforce `413 Payload Too Large`.
- **Inter-plugin communication:** Plugins pass typed metadata across hooks and across plugins via `RequestCtx::extensions` (`http::Extensions`)—e.g., `AuthSubject`, `RequestId`, `AiRequestMeta`, `AiUsage`.
- **Content-Length hygiene:** When `up_req.body` is buffered, `pipeline` removes `Transfer-Encoding` and sets exact `Content-Length`. When `RESPONSE_BODY_STREAM` is active, `pipeline` removes `Content-Length` so chunked/H2 streams can change length safely.
- **Panic isolation (`catch.rs`):** Every hook call (both sync and polled async future) is wrapped in `catch_unwind`. Pre-flush panics return `500 Internal Server Error`; mid-stream panics abort the stream cleanly and still run `on_complete` with `aborted_mid_stream = true`.

## Alternatives Considered & Rejected

### 1. Tower `Service` / `Layer` Middleware Stack
- **Why considered:** Idiomatic in the Rust HTTP ecosystem (`hyper`, `axum`, `tonic`).
- **Why rejected:** Tower's type-level layer composition does not fit runtime-compiled per-route plugin chains loaded from `shunt.toml`. Type-erasing every layer (`BoxCloneService`) reintroduces per-layer future boxing, makes per-attempt upstream loops awkward, and leaks `hyper` body generics into plugins.

### 2. Async-Only `#[async_trait]` Plugin Trait
- **Why considered:** Simpler method signatures without `HookResult`.
- **Why rejected:** Forces heap allocation for every hook invocation—even a 200ns header check or an SSE chunk hook firing hundreds of times per stream. `HookResult::Ready` keeps the fast path completely allocation-free while still supporting async I/O when needed.

### 3. Unbounded Request Buffering for Retries
- **Why considered:** Allows retrying any POST request automatically.
- **Why rejected:** Violates "pay only for what you use" and opens memory-exhaustion vectors on large uploads. Making buffering strictly opt-in via `REQUEST_BODY_BUFFERED` with a mandatory `max_body_bytes` cap keeps streaming routes O(1) memory while giving JSON/AI routes safe replayability.

## Future Work

- **Wasm Component Model (Tier 2 plugins):** Because `shunt-plugin-sdk` never exposes `hyper` types and uses plain `RequestHead`/`ResponseHead`/`Bytes`/`Flow`, a WIT adapter plugin can host Wasm guests behind the exact same `HttpPlugin` trait in v2.
- **Async Event Bus (Tier 3 harness plugins):** `on_complete` provides the natural boundary for emitting structured telemetry events to out-of-process governance/audit consumers.
