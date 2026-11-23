# Shunt — Core Design

**Status:** Finalized v1 Architecture (Ready for Implementation)  
**Positioning:** Open-source, developer-first, ultra-lean, pluggable Rust HTTP gateway core — validated by building a multi-provider AI router/gateway (`shunt-ai`) strictly as a plugin pack on top.

---

## 1. Core Philosophy

1. **Tiny, readable core:** A developer can read `shunt-engine` in an afternoon and understand the full path from TCP accept to response flush.
2. **Everything above transport is a plugin:** First-party features (auth, rate limiting, CORS, retries, metrics, AI routing) use the *exact same* `shunt-plugin-sdk` as third-party plugins. No privileged internal shortcuts.
3. **Pay only for what you use:** Per-route `HookMask` bitmasks and a hybrid sync/async dispatch model mean routes without body or I/O plugins run unbuffered and allocation-free on the hot path.
4. **Dev-first ergonomics:** Instant hot reloads, atomic zero-downtime snapshot swaps, and a `shunt dev` mode with live per-hook microsecond trace waterfalls.
5. **AI-agnostic core, AI-proven primitives:** Zero AI concepts (`Model`, `Prompt`, `Token`) inside `shunt-engine`. Building `shunt-ai` strictly as plugins proves the core's streaming, dynamic routing, failover, split-timeout, and accounting primitives.

---

## 2. High-Level Architecture

The system is organized around **four deep seams**:

```text
  Config Provider              Read-Only Admin API       Future: Harness Plugins (v2+)
  (shunt.toml + watcher)       (127.0.0.1:9090)          (Audit, exporters, watchers)
           │                          │                            ▲
           ▼                          ▼                            │ bounded async bus
  ┌────────────────────────────────────────────────────────────────────────────┐
  │                        Snapshot Compiler                                   │
  │  Parse -> Validate -> Build Factories (w/ RuntimeRegistry) -> ArcSwap      │
  └────────────────────────────────────────────────────────────────────────────┘
                                      │ (lock-free Arc load per request)
                                      ▼
  ┌────────────────────────────────────────────────────────────────────────────┐
  │                       LEAN CORE DATA PLANE (Rust)                          │
  │                                                                            │
  │   Listener/TLS ─▶ HTTP Engine ─▶ [ Hook Pipeline ] ─▶ Per-Attempt Loop     │
  │   (tokio/rustls)  (H1/H2/WS/SSE)  Sync fast-path       └─▶ Upstream Pool   │
  │                                   + Async opt-in           (reused across  │
  │                                                             reloads)       │
  └────────────────────────────────────────────────────────────────────────────┘
```

---

## 3. Core Transport & Runtime (`shunt-engine`)

- **Runtime:** Standard multi-threaded **`tokio`** runtime (broad Rust ecosystem compatibility, clean `Send + Sync` plugins, cross-platform macOS/Linux).
- **HTTP & TLS stack:** Built directly on **`hyper` v1 + `rustls`**.
- **v1 Protocols:**
  - HTTP/1.1 and HTTP/2 (both downstream and upstream)
  - TLS termination with SNI and hot-reloadable certificates
  - Streaming bodies (SSE, chunked transfer, gRPC-compatible H2 streams)
  - WebSocket upgrades (`hyper::upgrade::on`)
- **Split Timeouts:**
  - `connect_timeout`: TCP + TLS handshake to upstream
  - `response_headers_timeout`: time-to-first-byte (TTFB / TTFT)
  - `idle_chunk_timeout`: max gap between consecutive body chunks on long-lived streams
- **Graceful Draining:** On reload or shutdown, in-flight requests and streams finish cleanly on the `Arc<GatewaySnapshot>` they started with while new requests immediately use the latest snapshot.

---

## 4. Plugin SDK & Request Lifecycle (`shunt-plugin-sdk`)

`shunt-plugin-sdk` deliberately exposes clean, decoupled types (`http` crate types, `bytes::Bytes`, typed `Extensions`) and **never leaks `hyper` internals**, keeping the door cleanly open for a Tier 2 Wasm Component Model / scripting bridge in v2.

### 4.1 Hybrid Sync Fast-Path + Optional Async Dispatch

In-memory plugins (header rewrites, routing, SSE chunk parsing, local token buckets) return synchronously with **zero heap allocation**. Only hooks that perform actual async I/O (remote auth, cache lookups) return a future:

```rust
pub enum Flow {
    Continue,
    Respond(Response),
    RetryUpstream,
}

pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

pub enum HookResult<T = Flow> {
    Ready(T),
    Pending(BoxFuture<'static, T>), // or scoped lifetime via trait/executor
}
```

*(Implementation detail: keep `HookResult::Ready(Flow)` as the fast path so the runner only awaits when `Pending` is returned.)*

### 4.2 Registration & Compiled Per-Route Chains

- Each plugin implements `PluginFactory` and registers under a unique name in a `PluginRegistry`.
- During snapshot compilation, `SnapshotCompiler` parses and validates each plugin's typed config block once, calls `PluginFactory::build(config, &build_ctx)`, and bakes immutable `Arc<dyn HttpPlugin>` chains into every compiled route (supporting global + per-route layering).
- The compiler precomputes a **`HookMask`** bitmask for every route from its active plugin chain so unused hooks are skipped with a single bitwise check.

### 4.3 Full Request Lifecycle & Per-Attempt Upstream Loop

```text
Incoming Request
  │
  ├─ 1. on_request_headers(ctx, req)           [can short-circuit Respond]
  ├─ 2. (if HookMask::REQUEST_BODY_BUFFERED)   [buffer up to max_body_bytes, else 413]
  │      └─ on_request_body_buffered(ctx, &mut Bytes)
  ├─ 3. on_route(ctx, &mut RouteDecision)      [override route / dynamic target]
  │
  ├─ 4. Per-Attempt Upstream Loop (max_attempts):
  │      ├─ on_upstream_select(ctx, &mut UpstreamSelection)
  │      ├─ Clone canonical request head (+ cheap Bytes refcount clone if buffered)
  │      ├─ on_upstream_request(ctx, &mut UpstreamRequest)  [target-specific auth/path/body]
  │      ├─ Send to upstream pool (connect + TTFB timeout)
  │      ├─ (if non-buffered & HookMask::REQUEST_BODY_STREAM) stream chunks via on_request_body_chunk
  │      └─ on_response_headers(ctx, &mut ResponseHead)
  │           └─ If Flow::RetryUpstream (allowed ONLY pre-flush & if body is empty or buffered):
  │                continue loop -> next upstream candidate
  │
  ├─ 5. Commit response headers downstream
  ├─ 6. Stream response body:
  │      ├─ If HookMask::RESPONSE_BODY_STREAM:
  │      │    on_response_body_chunk(ctx, &mut Bytes, end_of_stream: bool) per chunk
  │      └─ Else: zero-copy passthrough stream
  │
  └─ 7. on_complete(ctx, &RequestSummary)      [off hot path, after flush/abort]
```

### 4.4 Body & Streaming Guarantees

- **Request body buffering (`REQUEST_BODY_BUFFERED`):** Strictly opt-in per route/plugin with a mandatory `max_body_bytes` cap (returning `413 Payload Too Large` on overflow). Enables body-driven routing (e.g., routing by JSON `"model"`), JSON translation, and zero-copy `Bytes` cloning across retry attempts. Routes without this flag stream unbuffered.
- **Response body streaming (`RESPONSE_BODY_STREAM`):** `on_response_body_chunk(ctx, &mut Bytes, end_of_stream: bool)` supports both read-only inspection (SSE token counting) and live chunk rewriting (Anthropic SSE → OpenAI SSE), using `end_of_stream` to flush any partial SSE line buffer.
- **Fault isolation & mid-stream errors:** Plugin panics are caught at the hook boundary so a buggy plugin never crashes a worker task. If an error or panic happens *before* response headers are committed, core returns a clean `502`/`500` (or allows retry). If it occurs *after* headers are flushed, core cleanly aborts/resets the stream, logs structured diagnostics, and invokes `on_complete` with the failure status.

---

## 5. Hot Reload & State Lifecycle (`RuntimeRegistry`)

Config reloads produce a brand-new immutable `GatewaySnapshot` swapped atomically via `ArcSwap`:

- **Upstream Connection Pools & Health State:** Managed by a shared `RuntimeRegistry` passed into `SnapshotCompiler`. When an upstream's endpoint address and TLS config are unchanged across reloads, the existing warm connection pool and passive/active health state are reused (avoiding cold TLS thundering herds). Pools removed from config are dereferenced and cleaned up once in-flight requests drain.
- **Stateful Plugins:** Plugins are stateless per-snapshot by default. Stateful plugins (rate limiters, token-per-minute buckets, circuit breakers) request a scoped `StateStore` handle keyed by stable plugin/route ID from `BuildContext` during `PluginFactory::build()`, preserving counters across reloads and garbage-collecting orphaned keys when removed.

---

## 6. Configuration & Admin API (`shunt-config`)

- **Canonical IR:** `shunt.toml` (and optional YAML) parses into a typed canonical IR, which compiles into `GatewaySnapshot`. Invalid reloads fail atomically with actionable diagnostics while leaving the last-known-good snapshot serving traffic.
- **v1 Authoritative Source:** `shunt.toml` is the sole source of truth in v1 (file watcher + explicit reload). All config inputs sit behind a `ConfigProvider` trait so remote API / K8s CRD providers can be added in v2 without touching `shunt-engine`.
- **Read-Only Admin Listener (v1):**
  - Always bound to a **separate listener** (`127.0.0.1:9090` by default — never shared with public proxy listeners).
  - Endpoints:
    - `GET /health` — liveness/readiness + active snapshot digest
    - `GET /metrics` — Prometheus exposition format
    - `GET /snapshot` — inspect active compiled routes, upstreams, and plugin hook bitmasks (secrets redacted)
    - `POST /reload` — trigger synchronous validation and reload of `shunt.toml` (returns compilation diagnostics on error)

---

## 7. Showcase Plugin Pack (`shunt-ai`)

`shunt-ai` is implemented **100% through `shunt-plugin-sdk`** as the primary validation of the core architecture.

### v1 Vertical Slice
- **Unified Frontend:** OpenAI-compatible `POST /v1/chat/completions` (both non-streaming JSON and streaming `text/event-stream`).
- **Two Backend Providers:** OpenAI and Anthropic.
- **Plugins Included:**
  1. `ai-model-router`: Opts into `REQUEST_BODY_BUFFERED`, parses `"model"` and `"stream"`, stores typed `AiRequestMeta` in `ctx.extensions`, selects ordered provider/model fallback chain in `on_route` / `on_upstream_select`.
  2. `ai-provider-adapter` (OpenAI + Anthropic): Runs in `on_upstream_request` (injecting target-specific auth headers, endpoint path, and translating OpenAI JSON → Anthropic Messages JSON when targeting Anthropic) and `on_response_body_chunk` (translating Anthropic SSE frames → OpenAI `chat.completion.chunk` SSE frames live).
  3. `ai-failover`: Inspects upstream errors / `429` / `5xx` in `on_response_headers` and returns `Flow::RetryUpstream` to fail over automatically to the next configured provider/model.
  4. `ai-usage-tracker`: Inspects response JSON or SSE chunks for input/output token usage, records TTFT + total duration + token counts into `ctx.extensions`, and emits structured metrics/logs in `on_complete`.

---

## 8. Workspace Layout

```text
shunt/
├── Cargo.toml
├── docs/
│   └── design.md            # This specification
├── crates/
│   ├── shunt-plugin-sdk/    # Public traits, HookMask, HookResult, Flow, RequestCtx, StateStore
│   ├── shunt-engine/          # Tokio/Hyper/Rustls server, upstream pools, RuntimeRegistry, hook runner
│   ├── shunt-config/        # Canonical IR, shunt.toml loader/watcher, SnapshotCompiler, Admin API
│   ├── shunt-plugins/       # First-party general plugins (request-id, logging, bearer-auth, rate-limit, CORS, metrics)
│   ├── shunt-ai/            # AI router plugin pack (model router, OpenAI/Anthropic adapters, failover, SSE accounting)
│   └── shunt-cli/           # CLI binary: `shunt run`, `shunt dev`, `shunt check`
└── benches/                 # Reproducible benchmark harnesses vs. Envoy & Caddy
```

---

## 9. Developer Experience (`shunt-cli`) & Benchmark Bar

### CLI Commands
- `shunt check -c shunt.toml` — validates config, compiles snapshot, prints compiled route table + active `HookMask`s, exits non-zero on error.
- `shunt run -c shunt.toml` — production server with atomic hot reload and graceful `SIGTERM` draining.
- `shunt dev -c shunt.toml` — development mode with auto file-watch reload and pretty per-request terminal waterfall showing exact microsecond timing per plugin hook (e.g., `auth: 4µs │ ai-router: 18µs │ upstream TTFB: 312ms │ sse-translate: 2µs/chunk`).

### Performance & Verification Bar (v1)
Reproducible benchmark harness comparing `shunt` against **Caddy** and **Envoy** on identical hardware across three workloads:
1. **Raw HTTP/1.1 & HTTP/2 + TLS passthrough** (0 plugins, `HookMask::EMPTY`)
2. **3-plugin chain** (request-id + bearer-auth + local rate-limit)
3. **High-concurrency SSE streaming** (1,000+ concurrent streams with live chunk inspection/translation)

**v1 Target:** Beat Caddy across all three workloads and match or stay within **10–15% of tuned Envoy** on throughput (RPS) and p99 latency, with zero dropped requests during live config reloads.

---

## 10. Phased Implementation Plan

1. **Phase 1 — Core Engine & SDK (`shunt-plugin-sdk`, `shunt-engine`):**
   - `HookMask`, `HookResult` (sync/async), `Flow`, `RequestCtx`, `PluginFactory`, `RuntimeRegistry`.
   - `tokio` + `hyper` v1 + `rustls` H1/H2 listener & upstream pool, WebSocket upgrade, split timeouts, graceful drain, `ArcSwap` snapshot runner, per-attempt upstream loop.
2. **Phase 2 — Config, Admin & Built-in Plugins (`shunt-config`, `shunt-plugins`, `shunt-cli`):**
   - `shunt.toml` IR + `SnapshotCompiler` + file watcher + read-only Admin listener.
   - Dogfooded plugins: request-id/logging, bearer-auth, rate-limit (using `StateStore`), header-rewrite/CORS, Prometheus metrics.
   - `shunt check`, `shunt run`, and `shunt dev` per-hook µs trace waterfall.
3. **Phase 3 — AI Router Showcase (`shunt-ai`):**
   - OpenAI + Anthropic adapters, model router, streaming SSE translation, `429`/`5xx` failover, token/TTFT usage tracking.
4. **Phase 4 — Benchmarks & Hardening (`benches/`):**
   - Automated benchmark scripts vs. Caddy & Envoy, reload-under-load soak tests, panic/fault-injection tests.

### Deferred to v2+
- Tier 2 dynamic plugins (Wasm Component Model / WIT via `wasmtime` and/or lightweight scripting)
- Tier 3 out-of-process Pi-harness event/governance plugins
- Remote API-pushed config (`PUT /config`) & Kubernetes Gateway API `ConfigProvider`
- `shunt build --with <crate>` custom binary builder CLI
- HTTP/3 (QUIC)
