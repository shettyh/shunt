# Shunt

[![CI](https://github.com/shettyh/shunt/actions/workflows/ci.yml/badge.svg)](https://github.com/shettyh/shunt/actions/workflows/ci.yml)
[![Security](https://github.com/shettyh/shunt/actions/workflows/security.yml/badge.svg)](https://github.com/shettyh/shunt/actions/workflows/security.yml)
[![Nightly Benchmarks](https://github.com/shettyh/shunt/actions/workflows/nightly-bench.yml/badge.svg)](https://github.com/shettyh/shunt/actions/workflows/nightly-bench.yml)
[![Release](https://github.com/shettyh/shunt/actions/workflows/release.yml/badge.svg)](https://github.com/shettyh/shunt/actions/workflows/release.yml)
[![MSRV 1.91](https://img.shields.io/badge/MSRV-1.91-blue.svg)](Cargo.toml)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache--2.0-blue.svg)](LICENSE)

**Shunt** is an ultra-lean, pluggable Rust gateway for **HTTP APIs**, **multi-provider AI**, and **MCP (Model Context Protocol)** traffic—built on `tokio`, `hyper` v1, `rustls`, and `arc-swap`.

A tiny, zero-allocation-fast-path data plane (`shunt-engine`) pairs with a strict plugin SDK (`shunt-plugin-sdk`) so every feature above transport—from JWT auth and compression to AI routing/guardrails and MCP governance—ships as a composable plugin in a single binary with zero required external dependencies.

---

## Why Shunt?

- **Tiny, high-performance core (`shunt-engine`)**: HTTP/1.1 & HTTP/2, SNI TLS & mTLS with hot-reloadable certs, SSE & WebSockets, split timeouts (`connect`, `response_headers`, `idle_chunk`), active/passive upstream health probes, optional Redis/Valkey state, and zero-dependency OTLP/HTTP tracing.
- **Pay only for what you use**: Compiled routes carry a precomputed `HookMask` bitmask and hybrid sync (`HookResult::Ready`) / async (`HookResult::Pending`) dispatch—routes without body or I/O plugins stay unbuffered and allocation-free.
- **Zero-downtime atomic reloads & Kubernetes Gateway API**: Hot-reload `shunt.toml`/YAML (file watch, `POST /reload`, `SIGHUP`) or sync Kubernetes Gateway API v1 resources (`--k8s-manifest` / `--k8s-gateway`) via lock-free `ArcSwap` snapshots while reusing warm pools and plugin state.
- **Strict plugin boundary**: First-party packs (`shunt-plugins`, `shunt-ai`, `shunt-mcp`) depend only on `shunt-plugin-sdk`—never on `shunt-engine` or `hyper` internals. Zero AI or MCP concepts leak into the core.
- **Developer-first workflow**: Static config/policy checks (`shunt check`, `shunt verify`), declarative TOML contract tests (`shunt test`), and `shunt dev --ui` for live per-hook µs waterfalls and an opt-in read-only Admin Inspector UI.

---

## Benchmarks at a Glance

Unified local loopback suite ([`bench.sh`](benches/scripts/bench.sh), [RFC 0020](rfcs/0020-unified-comprehensive-benchmarks.md)) on Apple M5 Pro (`c=64` HTTP / `c=1,000` SSE) comparing a single Shunt release binary against **Envoy 1.40.2**, **Caddy v2.11.9**, and **LiteLLM Proxy 1.110.2** (4 workers, stateless no-DB). **Bold** marks the best result in each row.

### API Gateway vs. Envoy & Caddy

| Workload | Metric | Shunt | Envoy 1.40 | Caddy 2.11 |
| --- | --- | ---: | ---: | ---: |
| **HTTP/1.1 Passthrough** *(0 plugins)* | RPS / p99 / RSS | **84.8k** / **1.02 ms** / **22.5 MB** | 78.3k / 1.15 ms / 53.6 MB | 69.9k / 2.28 ms / 72.9 MB |
| **TLS 1.3 + HTTP/2** | RPS / p99 / RSS | 90.9k / **0.96 ms** / **22.6 MB** | **99.9k** / 1.41 ms / 53.2 MB | 67.0k / 2.24 ms / 77.0 MB |
| **JWT HS256 + `zstd`** | RPS / p99 / RSS | **68.7k** / **1.27 ms** / **38.5 MB** | 66.3k / 1.42 ms / 84.4 MB | 62.8k* / 1.98 ms / 252.7 MB |
| **200-Route Table + Weighted LB** | RPS / p99 / RSS | **78.9k** / **1.06 ms** / **23.6 MB** | 62.0k / 1.24 ms / 56.4 MB | — |
| **Open-Loop 25k RPS** *(tail latency)* | p99 / p99.9 | **3.37 ms** / **4.22 ms** | 5.81 ms / 16.2 ms | 4.69 ms / 6.25 ms |

<sub>*Caddy tested with `zstd` only (no JWT). Higher RPS is better; lower latency & RSS are better.</sub>

### AI Gateway vs. LiteLLM (4 Workers)

| Workload | Shunt *(8-plugin governed)* | LiteLLM *(4w, stateless)* | Shunt Advantage |
| --- | ---: | ---: | ---: |
| **4 KB Multi-Turn Translate** *(throughput / p99)* | **56.3k req/s** *(1.57 ms)* | 598 req/s *(117.4 ms)* | **94× faster** · **65× less RAM** *(32 vs 2,071 MB)* |
| **1,000 Concurrent SSE Streams** *(chunks/s / TTFC p99)* | **31.1k ch/s** *(132 ms)* | 3.3k ch/s *(6,070 ms)* | **9.4× throughput** · **46× lower TTFC** |
| **Cold Start & Idle Memory** | **32–37 ms** · **11–13 MB** | 15,207 ms · 1,873 MB | **>400× faster start** · **~150× less RAM** |

### MCP, Fast-Paths & Stability Highlights

- **MCP 5-plugin governance:** **77.1k req/s** (`tools/call`, p99 1.17 ms), **160.0k req/s** loop-breaker fast-path, **200/200** concurrent SSE tool calls (`7.4k ch/s`).
- **Gateway fast-paths:** **141.3k req/s** exact-match AI cache hit, **89.6k req/s** mTLS + HTTP/2 (p99 0.98 ms), **60.4k req/s** AWS Bedrock SigV4 signing.
- **Zero-downtime reloads & soak:** **84.8k req/s** during live `POST /reload` (**9/9** reloads, **0** errors); **+1.0 MB** RSS delta across 672k AI requests.

See [`benches/README.md`](benches/README.md) for full tables, methodology, and reproduction commands.

---

## Quick Start

Requires Rust **1.91+** (edition 2024), or grab prebuilt binaries / multi-arch Docker images (`ghcr.io/shettyh/shunt`) from [GitHub Releases](https://github.com/shettyh/shunt/releases).

```bash
# Install from crates.io (installs the `shunt` binary)
cargo install shunt-cli

# Or install from source
cargo install --path crates/shunt-cli

# Or run with Docker
docker run --rm -p 8080:8080 -p 9090:9090 \
  -v "$PWD/examples/shunt.toml:/etc/shunt/shunt.toml:ro" \
  ghcr.io/shettyh/shunt:latest
```

Validate, test, and run any gateway profile:

```bash
# HTTP API gateway (dev mode with live reloads + browser Inspector UI on :9090/ui)
shunt dev --ui -c examples/shunt-api-gateway.toml

# Multi-provider AI gateway (export OPENAI_API_KEY / ANTHROPIC_API_KEY first)
shunt dev -c examples/shunt-ai.toml

# Virtual MCP & agentic governance gateway
shunt dev -c examples/shunt-mcp-gateway.toml

# Kubernetes Gateway API v1 manifests (or `--k8s-gateway` for live in-cluster sync)
shunt check --k8s-manifest examples/k8s-gateway-api.yaml

# Static policy verification & declarative TOML conformance tests
shunt verify -c examples/shunt.toml
shunt test -s specs/conformance/01-core-routing-and-plugins.spec.toml
```

Browse all 16 ready-to-run configs in [`examples/`](examples/) (including [`shunt-route-groups.toml`](examples/shunt-route-groups.toml), indexed in [`docs/reference.md`](docs/reference.md#example-configurations)).

---

## Plugin Packs

- **General HTTP (`shunt-plugins`)** — `request-id`, `access-log`, `bearer-auth`, `jwt-auth`, `mtls-auth`, `ip-filter`, `body-limit`, `compression`, `redirect`, `rate-limit`, `header-rewrite`, `cors`, `otel-trace`, `metrics`, `dev-waterfall`.
- **AI Gateway (`shunt-ai`)** — `ai-virtual-keys`, `ai-model-router`, `ai-guardrails`, `ai-cache`, `ai-token-rate-limit`, `ai-budget`, `ai-provider-adapter`, `ai-failover`, `ai-usage-tracker`, `ai-audit`, `ai-alerts`. Covers OpenAI/Anthropic/Responses/Embeddings/Multimodal ingress, 5 upstream dialects + Cloud IAM, smart routing, caching (exact, streaming, semantic), guardrails, budgets, and OTLP GenAI telemetry.
- **MCP & Agentic Governance (`shunt-mcp`)** — `mcp-auth`, `mcp-router`, `mcp-guardrails`, `mcp-rate-limit`, `mcp-telemetry`. Streamable HTTP JSON-RPC multiplexing, per-agent tool/resource/prompt ACLs, approval gates, PII/prompt-injection scanning, stuck-agent loop breaking, and audit telemetry.

See [`docs/reference.md`](docs/reference.md) for the complete plugin matrix, Admin API (`:9090`), and CLI reference.

---

## Writing a Plugin

Implement `HttpPlugin` from `shunt-plugin-sdk` and declare only the hooks you use via `HookMask`:

```rust
use shunt_plugin_sdk::{
    Flow, HeaderName, HeaderValue, HookMask, HookResult, HttpPlugin, RequestCtx, RequestHead,
};

pub struct PoweredByPlugin;

impl HttpPlugin for PoweredByPlugin {
    fn name(&self) -> &str { "powered-by" }
    fn hook_mask(&self) -> HookMask { HookMask::ON_REQUEST_HEADERS }

    fn on_request_headers<'a>(
        &'a self,
        _ctx: &'a mut RequestCtx,
        req: &'a mut RequestHead,
    ) -> HookResult<'a, Flow> {
        req.headers.insert(HeaderName::from_static("x-gateway"), HeaderValue::from_static("shunt"));
        HookResult::Ready(Flow::Continue)
    }
}
```

---

## Architecture & Workspace

```text
  Config / K8s Gateway API ──▶ SnapshotCompiler (IR) ──▶ ArcSwap ──▶ Admin API (:9090)
                                                           │ (lock-free load)
                                                           ▼
  Listener/TLS (tokio/rustls) ─▶ HTTP Engine ─▶ Hook Pipeline (HookMask) ─▶ Upstream Pool
```

| Crate | Role |
| --- | --- |
| [`shunt-plugin-sdk`](crates/shunt-plugin-sdk) | Public `HttpPlugin`, `PluginFactory`, `HookMask`, `HookResult`, `Flow`, `StateStore`, `HttpClient` |
| [`shunt-engine`](crates/shunt-engine) | `tokio`/`hyper` v1/`rustls` data plane, `ArcSwap` snapshots, hook runner, pools, and retry loop |
| [`shunt-config`](crates/shunt-config) | Canonical IR, TOML/YAML & K8s Gateway API providers, `SnapshotCompiler`, Admin API & Inspector UI |
| [`shunt-plugins`](crates/shunt-plugins) | First-party HTTP gateway plugins |
| [`shunt-ai`](crates/shunt-ai) | Multi-provider AI gateway plugin pack |
| [`shunt-mcp`](crates/shunt-mcp) | Model Context Protocol (MCP) & agentic governance plugin pack |
| [`shunt-test`](crates/shunt-test) | Declarative TOML conformance test harness and mock upstreams |
| [`shunt-cli`](crates/shunt-cli) | `shunt` CLI binary (`check`, `verify`, `test`, `dev`, `run`) |
| [`shunt-bench`](benches/shunt-bench) | Mock upstream and HTTP/SSE benchmark load generator |

---

## Documentation & Development

- **Docs Website**: [shettyh.github.io/shunt](https://shettyh.github.io/shunt/) (source in [`website/`](website/))
- **Repo Docs**: [Plugin, Admin API & Examples Reference](docs/reference.md) · [Product Vision](docs/vision.md) · [Core Design](docs/design.md) · [Architecture RFCs (0001–0021)](rfcs/README.md) · [Benchmarks](benches/README.md)

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
```

Licensed under the [Apache License, Version 2.0](LICENSE).
