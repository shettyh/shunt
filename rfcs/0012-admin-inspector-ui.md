# RFC 0012: Admin Read-Only Inspector UI (`--ui`)

- **Status:** Implemented
- **Crates:** `shunt-plugin-sdk`, `shunt-config`, `shunt-ai`, `shunt-cli`, `shunt-test`

## 1. Summary

This RFC introduces an **opt-in, strictly read-only Admin Inspector Web UI** served exclusively on Shunt's dedicated Admin listener (`127.0.0.1:9090` by default) via `shunt dev --ui`, `shunt run --ui`, or `[admin] ui = true` in `shunt.toml`. Built from a single zero-dependency embedded HTML/CSS/JS asset (~24 KB, gated behind a default-on `admin-ui` Cargo feature), it requires **zero database**, **zero external CDN/build toolchain**, and imposes **zero hot-path overhead** when disabled.

Operators and developers get live browser visibility into:
- **Live Per-Hook µs Trace Waterfall (SSE):** Real-time request stream backed by a bounded in-memory ring buffer (`TraceRingBuffer`) with per-hook timings, upstream TTFB, aggregated stream chunk timings, W3C `trace_id`, and structured HTTP/GenAI trace attributes.
- **Compiled Snapshot & `HookMask` Graph:** Visual route-to-plugin-to-upstream pipeline with per-plugin and compiled route `HookMask` bit badges (secrets redacted).
- **Upstreams & Active/Passive Health:** Live endpoint weights, active probe status/latency, and passive failure counters from `GET /upstreams`.
- **AI Runtime & Provider Cooldowns:** Pluggable read-only status inspection showing per-model token/cost/TTFT breakdowns, `StateStore`-backed failover cooldowns, smart-routing EWMA latency tables, and `ai-cache` utilization—without leaking any AI types into `shunt-engine`, `shunt-plugin-sdk`, or `shunt-config`.
- **Searchable Prometheus Metrics:** Live filtered view of `GET /metrics`.

## 2. Motivation

`shunt dev` already prints a helpful per-request microsecond waterfall to stderr, and `AdminServer` exposes `/health`, `/snapshot`, `/upstreams`, and `/metrics`. However, during active API and AI gateway development or incident triage, terminal logs scroll quickly and correlating compiled `HookMask`s, upstream health weights, provider failover cooldowns, cache hits, token spend, and per-hook timings across multiple JSON endpoints is tedious.

At the same time, Shunt must preserve its strict architectural guardrails:
- `shunt.toml` (or the active `ConfigProvider`) remains the sole source of truth—no embedded write/edit control plane in the data-plane binary.
- Zero database, zero heavy web frameworks or Node/npm build chains, and zero hot-path allocations when `--ui` is off.
- Strict crate isolation: **zero AI concepts** in `shunt-engine`, `shunt-plugin-sdk`, or `shunt-config`.

## 3. Goals & Non-Goals

### Goals
- **Opt-in runtime activation:** Disabled by default (`[admin] ui = false`). Enabled via `--ui` on `shunt dev` / `shunt run` or `[admin] ui = true` in `shunt.toml`. Compiled assets gated behind a default-on `admin-ui` Cargo feature so ultra-minimal custom builds can omit them with `--no-default-features`.
- **Zero overhead when disabled:** No capture plugin attached, no `trace_enabled` hook timing instrumentation (unless `shunt dev`), no ring buffer allocation, and `404 Not Found` on `/`, `/ui`, `/api/traces`, and `/api/traces/stream`.
- **Non-blocking bounded trace capture & SSE streaming:** Bounded `TraceRingBuffer` (`ui_trace_capacity`, default `256`, max `10_000`) plus `tokio::sync::broadcast` so slow or disconnected browser tabs lag independently (`event: lagged`) and never backpressure the proxy data plane. Supports `Last-Event-ID` / `?after=` seamless replay and clean cancellation on Admin shutdown.
- **AI-free enrichment & status seams:** Reuse the RAII drop-on-complete pattern from RFC 0011 (`TraceAnnotations` + `RequestCtx::annotate_*` and `StateStore::collect_by_type` in `shunt-plugin-sdk`, plus pluggable `StatusProvider` callbacks on `AdminServer`) so `shunt-ai` surfaces rich GenAI trace attributes, cooldowns, EWMA latency, and cache metrics without any AI dependency in core or config crates.
- **Hardened local-first defaults:** Strict browser security headers (`Content-Security-Policy`, `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, `Cache-Control: no-store`), secret redaction preserved on `/snapshot`, and `shunt verify` warning (`admin.ui_non_loopback`) if `admin.ui = true` is bound to a non-loopback address.

### Non-Goals (Intentionally Cut)
- **Read/write management console or config editing:** Deferred to Layer 3 (`shunt-console`, RFC 0015) as a separate companion service.
- **Historical persistence or SQLite/Postgres storage:** Traces live strictly in a bounded in-memory ring buffer; historical analytics belong in OTLP collectors (RFC 0011) and Prometheus/Grafana.
- **Frontend build toolchains (React/Vite/npm):** Keeping the Inspector UI as a single self-contained vanilla HTML/CSS/JS file ensures reproducible `cargo build` with zero Node dependencies and offline/air-gapped operation.

## 4. Design

### 4.1 AI-Free SDK Inspection Seams (`shunt-plugin-sdk`)

1. **`TraceAnnotations` & `RequestCtx::annotate_*`:**
   - `TraceAnnotations` is an interior-mutable `Arc<Mutex<BTreeMap<String, SpanValue>>>` placed in `RequestCtx::extensions` **only** when `InspectorCapturePlugin` is active.
   - `RequestCtx::annotate_str` / `annotate_int` / `annotate_float` / `annotate_bool` write to `SpanHandle` (RFC 0011) and/or `TraceAnnotations` when present—performing zero allocations when neither OTLP tracing nor Admin Inspector UI is enabled.
   - `shunt-ai` (`ai-usage-tracker`, `ai-budget`, `ai-cache`) writes canonical GenAI semantic attributes via `ctx.annotate_*`, automatically enriching both OTLP spans and Inspector trace waterfalls.
2. **`StateStore::collect_by_type<T>()`:**
   - Generic read-only typed scan over live `StateStore` entries returning `(scope_id, key, Arc<T>)` sorted deterministically.
   - Allows `shunt-ai::inspect_ai_runtime()` to read live `FailoverCircuitState` cooldowns, `TargetLatencyTable` EWMA latency observations, and `AiCacheTable` utilization without introducing separate global registries or risking leaks across hot reloads.

### 4.2 Bounded Trace Ring Buffer & RAII Capture Plugin (`shunt-config`)

- **`TraceRingBuffer`:** Holds a bounded `VecDeque<InspectorTrace>`, monotonic `seq: AtomicU64`, lifetime status/error counters, and a bounded `tokio::sync::broadcast::Sender<InspectorTrace>`. Computes rolling `p50`/`p95`/`p99` and average TTFB off the hot path on read.
- **`InspectorCapturePlugin`:** Built strictly on `shunt-plugin-sdk` (`HookMask::ON_REQUEST_HEADERS | HookMask::ON_COMPLETE`) and attached via `SnapshotCompiler::with_extra_global_plugin` only when UI is enabled. Uses an RAII `InspectorCaptureGuard` in `RequestCtx::extensions` so `on_complete` records core `RequestSummary` + hook timings, downstream route plugins (`ai-usage-tracker`, `ai-budget`, etc.) finish enriching `TraceAnnotations`, and `Drop` emits the single complete `InspectorTrace` into `TraceRingBuffer` once `RequestCtx` drops.

### 4.3 Admin Endpoints & Snapshot Graph (`shunt-config`)

- **`RouteInspect::plugin_details`:** Adds `{ name, scope_id, hook_mask }` per route plugin to `GET /snapshot` (never exposing raw route plugin config blobs, keeping all route secrets redacted).
- **New Read-Only Admin Endpoints:**
  - `GET /` and `GET /ui` (when `ui_enabled` & `feature = "admin-ui"`): Serves embedded `assets/inspector.html` with strict CSP & framing headers.
  - `GET /api/traces[?after=<seq>&limit=<n>]` (when `trace_store` attached): Returns `{ summary, traces }` JSON.
  - `GET /api/traces/stream` (when `trace_store` attached): `text/event-stream` SSE endpoint over `ShuntBody::channel`. Subscribes to `broadcast` *before* reading the ring buffer so zero events are missed between `Last-Event-ID`/`?after=` replay and live delivery, deduplicating by `seq`, emitting `: keep-alive` comments every 15s, and exiting immediately on `AdminHandle::shutdown()`.
  - `GET /api/status`: Returns snapshot metadata, `ui_enabled`, `trace_capture_enabled`, and `extensions: BTreeMap<String, Value>` populated by registered `StatusProvider` callbacks (e.g., `"ai"` registered by `shunt-cli` and `shunt-test`).

### 4.4 CLI, Config & Static Verification

- **`[admin]` IR additions:**
  - `ui = false` (bool)
  - `ui_trace_capacity = 256` (validated `1..=10_000`; `admin.ui = true` with `admin.enabled = false` is rejected at validation time).
- **CLI:** `shunt dev --ui` and `shunt run --ui` activate the UI even if `shunt.toml` keeps `admin.ui = false`.
- **`shunt verify`:** Emits `admin.ui_non_loopback` (`Warning`, or `Error` when `require_loopback_admin = true`) if `admin.ui = true` on a non-loopback `admin.listen`.

## 5. Alternatives Considered & Rejected

1. **Embedding a separate HTTP framework (e.g., `axum` / `tower-http`) or `rust-embed`:** Rejected because `AdminServer` already runs on `hyper` + `shunt_engine::ShuntBody::channel`, and a single embedded HTML asset via `include_str!` adds zero dependencies and keeps binary size minimal.
2. **Bundling a React/TypeScript SPA requiring Node/npm in CI:** Rejected because it breaks single-toolchain `cargo build`, slows CI, and adds unnecessary supply-chain surface for a ~500-line read-only developer inspector.
3. **Allowing live config edits or virtual key CRUD inside `--ui`:** Rejected to keep `shunt.toml` / `ConfigProvider` strictly authoritative in the data plane; centralized write management belongs in Layer 3 (`shunt-console`, RFC 0015).

## 6. Verification

- **Unit & Integration Tests:** `crates/shunt-config/tests/admin_inspector_ui.rs`, `crates/shunt-ai/src/inspector.rs`, `crates/shunt-plugin-sdk/src/{state,telemetry}.rs` covering disabled-404 behavior, HTML security headers, live trace capture, SSE `Last-Event-ID` replay & live streaming, clean shutdown with open SSE clients, `admin.ui_non_loopback` verification, and dual `SpanHandle` + `TraceAnnotations` enrichment.
- **Property Tests (`proptest`):** `TraceRingBuffer` strict capacity bound, monotonic `seq`, `after_seq` filtering, status counter conservation, and `p50 <= p95 <= p99` monotonicity.
- **Conformance Spec:** `specs/conformance/10-admin-inspector-ui.spec.toml` exercising end-to-end UI HTML serving, `/snapshot` `plugin_details` + secret redaction, AI failover + cache hit trace capture on `/api/traces`, and AI totals + active cooldowns + cache entries on `/api/status`.
