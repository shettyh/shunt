# Shunt

[![CI](https://github.com/shettyh/shunt/actions/workflows/ci.yml/badge.svg)](https://github.com/shettyh/shunt/actions/workflows/ci.yml)
[![Security](https://github.com/shettyh/shunt/actions/workflows/security.yml/badge.svg)](https://github.com/shettyh/shunt/actions/workflows/security.yml)
[![Nightly Benchmarks](https://github.com/shettyh/shunt/actions/workflows/nightly-bench.yml/badge.svg)](https://github.com/shettyh/shunt/actions/workflows/nightly-bench.yml)
[![Release](https://github.com/shettyh/shunt/actions/workflows/release.yml/badge.svg)](https://github.com/shettyh/shunt/actions/workflows/release.yml)
[![MSRV 1.91](https://img.shields.io/badge/MSRV-1.91-blue.svg)](Cargo.toml)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache--2.0-blue.svg)](LICENSE)

**Shunt** is an open-source, ultra-lean, pluggable Rust HTTP & AI gateway built on `tokio`, `hyper` v1, `rustls`, and `arc-swap`.

It pairs a tiny, zero-allocation-fast-path HTTP data plane (`shunt-core`) with a clean plugin SDK (`shunt-plugin-sdk`) where every feature above transport—auth, rate limiting, CORS, Prometheus metrics, and even a full multi-provider AI gateway (`shunt-ai`)—is built strictly as a plugin.

---

## Why Shunt?

- **Tiny, readable core (`shunt-core`)**: HTTP/1.1 & HTTP/2 (downstream and upstream), SNI TLS termination with hot-reloadable certificates, streaming bodies (SSE, chunked, H2), WebSocket upgrades, weighted upstream pools with active HTTP/TCP health probes, optional Redis/Valkey distributed state, zero-dependency OTLP/HTTP trace export, and split timeouts (`connect`, `response_headers` / TTFB, `idle_chunk`).
- **Everything above transport is a plugin**: First-party plugins (`shunt-plugins`, `shunt-ai`) depend strictly on `shunt-plugin-sdk`—never on `shunt-core`—and never see `hyper` internals.
- **Pay only for what you use**: Each compiled route carries a precomputed `HookMask` bitmask and uses a hybrid sync (`HookResult::Ready`) / async (`HookResult::Pending`) dispatch model. Routes with no body or I/O plugins run unbuffered and allocation-free on the hot path.
- **Atomic zero-downtime hot reloads**: Reloading `shunt.toml` (or YAML) compiles a new immutable `GatewaySnapshot` and swaps it lock-free via `ArcSwap`, reusing warm upstream connection pools and `StateStore`-backed plugin state (rate limiters, provider cooldowns, budgets, caches) while draining in-flight requests cleanly.
- **Developer-first CLI (`shunt`)**: Validate configs and inspect compiled routes + `HookMask`s with `shunt check`, run static policy checks with `shunt verify` and TOML contract suites with `shunt test`, or run `shunt dev --ui` for automatic file-watch reloads, live per-hook µs trace waterfalls, and an opt-in browser Inspector UI.
- **AI-agnostic core, full-featured AI gateway (`shunt-ai`)**: Zero AI concepts live in `shunt-core`. `shunt-ai` provides multi-protocol ingress (`/v1/chat/completions`, `/v1/messages`, `/v1/responses`, `/v1/embeddings`, `/v1/models`), 5 upstream dialects (`openai_compatible`, `anthropic`, `azure_openai`, `gemini`/Vertex AI, `bedrock` Converse + SigV4 + EventStream), virtual API keys, RPM/TPM rate limits, nano-USD cost budgets, smart routing (`priority`/`weighted`/`latency`/`cost` + capability guards), automatic failover with cooldowns, exact-match caching, and Prometheus + OTLP GenAI observability—implemented 100% through `shunt-plugin-sdk`.

---

## Benchmarks

Reproducible head-to-head results on Apple Silicon (local loopback, `c=64` HTTP / `c=1,000` SSE) comparing **Shunt (`--release`)**, **Envoy 1.40.2**, and **Caddy 2.11.9** against the same `shunt-bench` upstream:

| Workload | Shunt | Envoy 1.40.2 | Caddy 2.11.9 |
| --- | ---: | ---: | ---: |
| **Raw HTTP/1.1 Passthrough** (`c=64`, 0 plugins) | **89,240 req/s** · p99 **922 µs** · 20.1 MB RSS | 75,515 req/s · p99 1,010 µs · 57.5 MB RSS | 69,264 req/s · p99 2,089 µs · 71.4 MB RSS |
| **3-Plugin Chain** (`c=64`, req-id + auth + rate-limit) | **87,714 req/s** · p99 **956 µs** · 21.0 MB RSS | 76,431 req/s · p99 1,018 µs · 55.6 MB RSS | 45,557 req/s · p99 12,083 µs · 71.6 MB RSS |
| **1,000 Concurrent SSE Streams** (20 chunks @ 25ms) | **1,000/0** · 30,456 chunks/s · **83.3 MB RSS** | 1,000/0 · 30,749 chunks/s · 92.2 MB RSS | 1,000/0 · 30,316 chunks/s · 159.2 MB RSS |
| **Shunt-AI SSE** *(live Anthropic → OpenAI translate + usage)* | **1,000/0** · 28,990 chunks/s · **93.8 MB RSS** | — | — |

Head-to-head AI Gateway benchmark (`./benches/scripts/run_litellm_bench.sh`) on **Apple M5 Pro** against **LiteLLM Proxy 1.110.2** (stateless no-DB mode, both 1-worker default and 4-worker `--num_workers 4`, total process-tree RSS):

| AI Workload (`POST /v1/chat/completions`) | Shunt AI *(8-plugin governed)* | LiteLLM 1.110.2 *(4 workers)* | LiteLLM 1.110.2 *(1 worker)* |
| --- | ---: | ---: | ---: |
| **Cold Start & Idle RSS** | **33 ms** · **10.5 MB RSS** | 4,151 ms · 1,852 MB RSS | 2,326 ms · 363 MB RSS |
| **OpenAI Passthrough** (`c=64`, JSON) | **71,185 req/s** · p99 **1.15 ms** · **26 MB** | 987 req/s · p99 101.7 ms · 1,921 MB | 361 req/s · p99 186.5 ms · 385 MB |
| **Anthropic ↔ OpenAI Translate** (`c=64`, JSON) | **70,551 req/s** · p99 **1.17 ms** · **27 MB** | 985 req/s · p99 72.6 ms · 2,051 MB | 340 req/s · p99 223.7 ms · 416 MB |
| **200 Concurrent SSE Streams** *(Anthropic → OpenAI)* | **200/0** · TTFC p50 **6.3 ms** · **38 MB** | 200/0 · TTFC p50 233.2 ms · 2,081 MB | 200/0 · TTFC p50 535.9 ms · 439 MB |
| **1,000 Concurrent SSE Streams** *(Anthropic → OpenAI)* | **1,000/0** · 0.82s · **103 MB** | 1,000/0 · 2.74s · 2,209 MB | 1,000/0 · 7.95s · 538 MB |

See [`benches/README.md`](benches/README.md) for full methodology, configurations, and reproduction commands.

---

## Quick Start

### 1. Build or Install

Requires Rust **1.91+** (edition 2024).

```bash
# Build the release binary
cargo build --release -p shunt-cli --bin shunt

# Or install `shunt` into ~/.cargo/bin
cargo install --path crates/shunt-cli
```

Prebuilt release archives (`linux`, `macos`, `windows`) and multi-arch distroless Docker images (`ghcr.io/shettyh/shunt`) are published automatically via [GitHub Releases](https://github.com/shettyh/shunt/releases):

```bash
# Run with Docker
docker run --rm -p 8080:8080 -p 9090:9090 \
  -v "$PWD/examples/shunt.toml:/etc/shunt/shunt.toml:ro" \
  ghcr.io/shettyh/shunt:latest
```

### 2. Validate, Verify & Run a Gateway

```bash
# Validate config, compile snapshot, and print routes + HookMasks
shunt check -c examples/shunt.toml

# Run static IR, route-shadowing, AI chain, and declarative policy verification
shunt verify -c examples/shunt.toml

# Run declarative TOML conformance tests against in-process mocks
shunt test -s specs/conformance/01-core-routing-and-plugins.spec.toml

# Development mode: file-watch hot reloads + live per-hook µs trace waterfalls (add `--ui` for browser Inspector)
shunt dev --ui -c examples/shunt.toml

# Production mode: atomic reloads (file watch, POST /reload, SIGHUP) + graceful draining
shunt run -c examples/shunt.toml
```

Pass `--no-watch` to `shunt run` to disable file watching while keeping `POST /reload` and `SIGHUP` active.

### 3. Run the AI Gateway Examples (`shunt-ai`)

[`examples/shunt-ai.toml`](examples/shunt-ai.toml) configures a unified `/v1/*` AI gateway with model aliases (`smart`, `fast`), automatic failover, live streaming translation, and token/TTFT accounting. Additional ready-to-run configs cover [multi-provider & multi-protocol ingress](examples/shunt-ai-multi-provider.toml), [virtual keys, TPM quotas & spend budgets](examples/shunt-ai-governance.toml), [weighted/latency/cost smart routing & active health probes](examples/shunt-ai-smart-routing.toml), [OTLP tracing & exact-match AI caching](examples/shunt-ai-observability-cache.toml), and the [Admin Inspector UI](examples/shunt-inspector-ui.toml):

```bash
export OPENAI_API_KEY="sk-..."
export ANTHROPIC_API_KEY="sk-ant-..."

shunt check -c examples/shunt-ai.toml
shunt dev   -c examples/shunt-ai.toml
```

```bash
curl http://127.0.0.1:8080/v1/chat/completions \
  -H "Content-Type: application/json" \
  -d '{"model":"smart","stream":true,"messages":[{"role":"user","content":"Hello!"}]}'
```

---

## Configuration & Admin API

Shunt reads `shunt.toml` (or `.yaml` / `.yml`) into a typed canonical IR (`shunt-config`). Invalid reloads fail atomically with diagnostics while keeping the last-known-good snapshot serving traffic.

The read-only Admin API always binds to a separate listener (`127.0.0.1:9090` by default):

| Endpoint | Description |
| --- | --- |
| `GET /health` | Liveness/readiness status, snapshot version, digest, and route/upstream counts |
| `GET /metrics` | Prometheus exposition metrics (HTTP gateway, upstream health, OTLP, and `shunt-ai` counters) |
| `GET /snapshot` | Active compiled routes, upstreams, and per-plugin `HookMask`s (secrets redacted) |
| `GET /upstreams` | Live upstream pool endpoint weights, active probe status, and passive health |
| `GET /api/status` | Snapshot status and pluggable runtime extensions (e.g., AI usage, provider cooldowns, EWMA latency, cache stats) |
| `GET /` & `GET /ui` | Opt-in read-only Admin Inspector Web UI (`--ui` or `[admin] ui = true`, zero DB) |
| `GET /api/traces` & `/api/traces/stream` | Opt-in bounded trace ring buffer & live SSE trace waterfall stream (`--ui` or `[admin] ui = true`) |
| `POST /reload` | Synchronously revalidate and atomically swap the configuration snapshot |

---

## Built-in Plugins

### General HTTP Plugins (`shunt-plugins`)

| Plugin | Purpose |
| --- | --- |
| `request-id` | Generates or propagates `x-request-id` across request/response headers and context |
| `access-log` | Structured `tracing` access logging in `on_complete` |
| `bearer-auth` | Bearer token verification with subject injection into `RequestCtx` |
| `rate-limit` | Token-bucket rate limiting backed by reload-persistent `StateStore` (or Redis/Valkey) |
| `header-rewrite` | Set/append/remove request and response headers |
| `cors` | Configurable CORS preflight handling and response headers |
| `otel-trace` | W3C `traceparent`/`tracestate` propagation and OpenTelemetry span emission via `[telemetry]` |
| `metrics` | Prometheus request counters and latency histograms served via `GET /metrics` |
| `dev-waterfall` | Live per-hook microsecond trace waterfall (automatically attached by `shunt dev`) |

### AI Gateway Plugin Pack (`shunt-ai`)

| Plugin | Purpose |
| --- | --- |
| `ai-virtual-keys` | Constant-time SHA-256 virtual API key auth (`Authorization` / `x-api-key` / custom header) with team, model/provider ACLs, per-key overrides, and quota/budget policies |
| `ai-model-router` | Serves `/v1/models` & local `/v1/messages/count_tokens`, parses `/v1/chat/completions`, `/v1/messages`, `/v1/responses`, and `/v1/embeddings`, enforces capability guards, and routes via `priority`, `weighted`, `latency`, or `cost` strategies |
| `ai-cache` | Exact-match SHA-256 response cache for deterministic conversational & embeddings requests (in-memory LRU+TTL or Redis/Valkey) with tenant scoping and `Cache-Control` handling |
| `ai-token-rate-limit` | Pre-flight token estimation + post-response `AiUsage` reconciliation enforcing RPM/TPM limits locally or across Redis/Valkey replicas |
| `ai-budget` | Exact integer nano-USD cost accounting & rolling spend budgets (virtual key / team / global) with soft warnings, hard `429`/`402` enforcement, and `shunt_ai_cost_usd_total` metrics |
| `ai-provider-adapter` | Injects provider auth (Bearer, header, AWS SigV4) and translates JSON, SSE, and AWS EventStream across `openai_compatible`, `anthropic`, `azure_openai`, `gemini`/Vertex AI, and `bedrock` (with zero-copy native passthrough where matching) |
| `ai-failover` | Triggers `Flow::RetryUpstream` on `429`/`5xx`/`529` with `StateStore`/Redis-backed provider cooldowns and `Retry-After` support |
| `ai-usage-tracker` | Extracts prompt, cached-prompt, and completion tokens + TTFT across all dialects for Prometheus metrics, structured logs, and OTLP GenAI span enrichment |

---

## Writing a Plugin

Plugins implement `HttpPlugin` from `shunt-plugin-sdk` and declare only the lifecycle hooks they need via `HookMask`. Synchronous hooks return `HookResult::Ready(...)` with zero heap allocation:

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

---

## Architecture & Workspace Layout

```text
  Config Provider (shunt.toml + watcher)       Admin API (127.0.0.1:9090)
                    │                                      │
                    └──────────────┬───────────────────────┘
                                   ▼
                         SnapshotCompiler (IR)
                Parse -> Validate -> Build Factories -> ArcSwap
                                   │ (lock-free Arc load per request)
                                   ▼
  Listener/TLS (tokio/rustls) ─▶ HTTP Engine (H1/H2/WS/SSE) ─▶ Hook Pipeline ─▶ Upstream Pool
                                                               (HookMask +       (reused across
                                                                retry loop)       hot reloads)
```

| Crate | Role |
| --- | --- |
| [`crates/shunt-plugin-sdk`](crates/shunt-plugin-sdk) | Public `HttpPlugin`, `PluginFactory`, `HookMask`, `HookResult`, `Flow`, `RequestCtx`, and `StateStore` |
| [`crates/shunt-core`](crates/shunt-core) | `tokio` / `hyper` v1 / `rustls` server, `ArcSwap` snapshots, `RuntimeRegistry`, hook runner, and retry loop |
| [`crates/shunt-config`](crates/shunt-config) | Canonical IR, TOML/YAML loader, file watcher, `SnapshotCompiler`, and Admin API |
| [`crates/shunt-plugins`](crates/shunt-plugins) | First-party HTTP plugins built strictly on `shunt-plugin-sdk` |
| [`crates/shunt-ai`](crates/shunt-ai) | Multi-provider AI router & gateway plugin pack built 100% on `shunt-plugin-sdk` |
| [`crates/shunt-test`](crates/shunt-test) | Declarative TOML conformance test harness (`shunt.spec.toml`) and in-process mock upstreams |
| [`crates/shunt-cli`](crates/shunt-cli) | `shunt` CLI binary (`check`, `verify`, `test`, `run`, `dev`) |
| [`benches/shunt-bench`](benches/shunt-bench) | Self-contained mock upstream and HTTP/SSE load generator |

---

## Design Docs & RFCs

- [Product & Architecture Vision](docs/vision.md)
- [Core Design Specification](docs/design.md)
- [Architecture RFCs](rfcs/README.md):
  - [RFC 0001](rfcs/0001-plugin-sdk-and-lifecycle.md) — Plugin SDK & Request Lifecycle
  - [RFC 0002](rfcs/0002-atomic-snapshots-and-state-lifecycle.md) — Atomic Snapshots, Pool Reuse & State Lifecycle
  - [RFC 0003](rfcs/0003-config-ir-and-admin-plane.md) — Config IR, Hot Reload, Admin API & Dev Ergonomics
  - [RFC 0004](rfcs/0004-shunt-ai-plugin-pack.md) — `shunt-ai`: Multi-Provider AI Gateway as a Pure Plugin Pack
  - [RFC 0005](rfcs/0005-benchmarks-and-hardening.md) — Benchmark Harness vs. Envoy & Caddy & Hardening
  - [RFC 0006](rfcs/0006-verification-and-spec-testing.md) — Layered Verification, Property Testing & Spec-Driven TOML Testing
  - [RFC 0007](rfcs/0007-generalized-ai-providers-and-endpoints.md) — Generalized AI Providers & Expanded OpenAI Endpoints
  - [RFC 0008](rfcs/0008-multi-protocol-ai-ingress.md) — Multi-Protocol AI Ingress (`/v1/messages` & `/v1/responses`)
  - [RFC 0009](rfcs/0009-virtual-keys-budgets-and-distributed-state.md) — Virtual Keys, Token Rate Limits, Cost Budgets & Distributed `StateStore`
  - [RFC 0010](rfcs/0010-smart-routing-and-active-health-checks.md) — Smart Routing & Active Upstream Health Checks
  - [RFC 0011](rfcs/0011-otlp-observability-and-ai-cache.md) — OTLP/HTTP Observability & Exact-Match AI Response Cache
  - [RFC 0012](rfcs/0012-admin-inspector-ui.md) — Admin Read-Only Inspector UI (`--ui`)

---

## Development & Testing

```bash
# Format & lint (matches CI)
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked -- -D warnings

# Run unit, integration, and doc tests
cargo test --workspace --locked
# Or with cargo-nextest:
cargo nextest run --workspace --locked

# Build rustdoc with warnings denied
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --locked

# Run benchmark suite (compares against Envoy & Caddy if on PATH)
./benches/scripts/run_all.sh
```

---

## License

Licensed under the [Apache License, Version 2.0](LICENSE).
