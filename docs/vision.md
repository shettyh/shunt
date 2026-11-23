# Shunt — Product & Architecture Vision

**Status:** Living Document  
**Current Baseline:** `v0.1.2` (RFCs 0001–0020 implemented across HTTP API, AI, and MCP gateways)  
**Primary Focus (Now):** **Adoption, Usability & Ecosystem** — Docs, CLI onboarding DX, zero-friction installers, and turnkey deploy/observability kits  
**Next Platform Milestones:** Wasm Component Model plugins (`Tier 2`) & optional Companion Control Plane (`shunt-console`)

---

## 1. North Star

**Shunt** aims to be the **fastest, cleanest single-binary Rust gateway for AI workloads, MCP agents, and modern HTTP APIs**—combining a tiny, Envoy-beating data plane (`shunt-engine`) with a zero-overhead plugin SDK (`shunt-plugin-sdk`).

Most teams today face an awkward split:
- For **AI & agentic traffic**, they run slow, memory-hungry Python proxies (LiteLLM), pay SaaS markups and send sensitive traffic outside their VPC (OpenRouter), or stitch together separate unverified wrappers for MCP servers.
- For **API traffic**, they choose between deeply complex proxies built for 10,000-service meshes (Envoy, Kong) or simpler reverse proxies that lack programmable gateway primitives.

Shunt bridges all three with one architectural bet:

> **Keep `shunt-engine` small, verifiable, and strictly protocol/AI-agnostic—and build a world-class self-hosted AI Gateway (`shunt-ai`), MCP Agentic Gateway (`shunt-mcp`), and Modern HTTP API Gateway (`shunt-plugins`) entirely as composable plugins on top.**

Every core capability (distributed state, virtual keys/JWT/mTLS, weighted & latency-aware routing, active health checks, OpenTelemetry tracing, streaming/SSE/WebSockets, outbound `HttpClient`) is a general-purpose engine or SDK primitive shared across all three pillars.

---

## 2. Where We Are Today (`v0.1.2`, RFCs 0001–0020 Implemented)

Shunt has a verified, high-performance, feature-complete gateway foundation ([docs/design.md](design.md), [rfcs/README.md](../rfcs/README.md)):

- **Data plane (`shunt-engine`):** HTTP/1.1 & HTTP/2 (downstream + upstream), SNI TLS & mTLS with hot-reloadable certs/CAs, WebSocket upgrades, streaming bodies/SSE, split timeouts (`connect`, `response_headers`/TTFB, `idle_chunk`), weighted upstream pools with active HTTP/TCP health probes + passive endpoint health tracking, fire-and-forget traffic mirroring, optional Redis/Valkey `DistributedStore`, zero-dependency bounded async OTLP/HTTP JSON trace export, outbound `HttpClient` primitive, and lock-free `ArcSwap` atomic reloads with warm pool reuse.
- **Proven performance ([RFC 0020](../rfcs/0020-unified-comprehensive-benchmarks.md)):**
  - **API Gateway:** **84.8k req/s** raw HTTP/1.1, **90.9k req/s** TLS 1.3 + HTTP/2 (`962 µs` p99, `22.6 MB` RSS), **89.6k req/s** mTLS + HTTP/2, **68.7k req/s** HS256 JWT + streaming `zstd`, **78.9k req/s** 200-route weighted LB, and **3.37 ms** p99 open-loop at 25k RPS (outperforming Envoy 1.40.2 and Caddy v2.11.9 on HTTP/1.1, plugin chains, JWT+`zstd`, 200-route LB, and open-loop tail latency).
  - **AI Gateway:** **56.3k req/s** (`1.57 ms` p99, `31.8 MB` RSS) on 4 KB multi-turn Anthropic ↔ OpenAI translation through the full 8-plugin governed chain (**94×** throughput and **65×** less RAM than 4-worker LiteLLM 1.110.2), **31.1k ch/s** across 1,000 concurrent SSE streams (**9.4×** throughput, **46×** lower TTFC p99), and **141.3k req/s** exact-match cache hits.
  - **MCP Gateway:** **77.1k req/s** governed `tools/call` (p99 `1.17 ms`), **160.0k req/s** loop-breaker fast-path, **200/200** concurrent Streamable HTTP SSE tool calls.
  - **Reloads & Soak:** **84.8k req/s** with `0` errors across live `POST /reload` every 500 ms; **+1.0 MB** RSS delta across 672k governed AI requests.
- **General HTTP API Gateway (`shunt-plugins`, RFC 0018):** `request-id`, `access-log`, `bearer-auth`, pure-Rust `jwt-auth` (JWKS/OIDC), `mtls-auth` (CN/SAN/SPIFFE/fingerprint), CIDR `ip-filter`, streaming `body-limit`, SSE-aware `compression` (`zstd`/`br`/`gzip`/`deflate`), `redirect`, `rate-limit`, `header-rewrite`, `cors`, `otel-trace`, `metrics`, `dev-waterfall`, plus zero-bloat **Kubernetes Gateway API v1** (`--k8s-manifest` & live `--k8s-gateway`).
- **Multi-Provider AI Gateway (`shunt-ai`, RFCs 0004, 0007–0011, 0013–0017):**
  - **Multi-protocol & multimodal ingress:** `/v1/chat/completions`, `/v1/messages` (+ `/v1/messages/count_tokens`), `/v1/responses`, `/v1/embeddings`, `/v1/models`, `/v1/rerank`, `/v1/images/*`, `/v1/audio/*`, `/v1/realtime` (WebSocket), `/v1/completions`, `/v1/moderations`, `/v1/batches`, `/v1/files`, and `/v1/generation`.
  - **5 upstream dialects + 17 provider presets + Cloud IAM:** `openai_compatible`, `anthropic` (incl. Claude on Vertex), `azure_openai`, `gemini` (AI Studio & Vertex AI), `bedrock` (Converse, ConverseStream EventStream, Embeddings + SigV4), multi-key pools, BYOK passthrough, and zero-SDK auto-refreshing AWS IAM / GCP IAM / Azure Entra ID auth.
  - **Routing, governance, safety & caching:** Virtual keys (`expires_at`, org/team hierarchy, per-model limits, concurrency caps), RPM/TPM reconciliation, nano-USD budgets with pre-flight holds & external pricing catalogs, smart routing (`priority`, `weighted`, `latency`, `cost`, `throughput`, `headroom`, OpenRouter per-request overrides, capability & context-window guards), failover (status, TTFT timeout, context-overflow), inline & external guardrails (PII/secrets, prompt injection, OPA/Presidio/Lakera/Bedrock/Llama Guard), redacted audit sinks & Slack/PagerDuty alert webhooks, and exact/streaming/singleflight/semantic caching.
- **MCP & Agentic Governance Gateway (`shunt-mcp`, RFC 0019):** Virtual Streamable HTTP JSON-RPC 2.0 multiplexer (`mcp-auth`, `mcp-router`, `mcp-guardrails`, `mcp-rate-limit`, `mcp-telemetry`), RFC 9728 OAuth Protected Resource metadata, per-agent server/tool/resource/prompt ACLs, `Mcp-Session-Id` principal binding, approval gates, per-tool JSON argument rules, outbound secret redaction, inbound indirect prompt-injection defense (JSON + SSE), OPA webhooks, and stuck-agent loop breaking.
- **Developer, inspector & verification ergonomics:** `shunt check`, `shunt verify`, `shunt test`, `shunt dev` / `shunt run` with opt-in read-only Admin Inspector Web UI (`--ui`) and live SSE trace waterfalls, plus layered verification (TLA+, Kani, proptest, 18 fuzz targets, and 17 TOML conformance specs).

---

## 3. Positioning & Non-Goals

### Where Shunt Fits

| Dimension | Hosted SaaS (OpenRouter, Cloudflare AI) | Self-Hosted Python/Enterprise (LiteLLM, Kong AI, Envoy AI) | **Shunt** |
| --- | --- | --- | --- |
| **Deployment** | Managed SaaS (data leaves VPC) | Heavy Python stack or complex K8s/DB control plane | **Single ~20 MB Rust binary + `shunt.toml`** |
| **Hot-path overhead** | Network hop + SaaS latency | High Python latency / large memory footprint | **Sub-ms p99, zero-alloc sync fast path** |
| **Extensibility** | Closed or webhook-only | Heavy/coupled plugin models | **Typed `shunt-plugin-sdk` (Rust now, Wasm next)** |
| **Unified surface** | AI-only or CDN-coupled | Separate stacks for API, AI, and MCP | **One gateway for HTTP APIs, `/v1/*` AI, and `/mcp` agents** |

### Explicit Non-Goals

1. **Not a hosted model marketplace / billing SaaS:** Shunt is a self-hosted BYOK (Bring Your Own Key) gateway, not a resale marketplace like OpenRouter.
2. **Not an Envoy service-mesh clone:** We will not chase L4 TCP/UDP proxying, xDS, SPIFFE sidecar meshes, or legacy enterprise ESB features.
3. **Never leak AI or MCP concepts into `shunt-engine`:** `Model`, `Prompt`, `Token`, provider schemas, and MCP JSON-RPC stay strictly inside `shunt-ai` and `shunt-mcp`. If a plugin pack needs a new transport/lifecycle capability, we design a general-purpose primitive for it.

---

## 4. Next Priorities: Adoption, Usability & Ecosystem

With the core data plane and all three plugin packs (`shunt-plugins`, `shunt-ai`, `shunt-mcp`) implemented and benchmarked, the highest-leverage work is reducing **time-to-first-success** for new users from ~10 minutes to **under 60 seconds**.

### Phase U1 — Documentation Website & Self-Serve Knowledge Base *(In Progress)*
- **Dedicated docs site (`website/`, Astro Starlight on GitHub Pages):**
  - Persona-based 5-minute quickstarts (HTTP API Gateway, Multi-Provider AI Gateway, MCP Agentic Gateway).
  - Complete per-plugin configuration reference (keys, types, defaults, hook masks, plugin ordering, copy-paste TOML snippets).
  - Practical recipes & migration guides (*Migrating from LiteLLM*, *Using Shunt with Claude Code / Codex / Ollama*, *Exporting OTLP GenAI traces*).
  - Full interactive search (Pagefind) and auto-generated `llms.txt` / `llms-full.txt` so AI coding assistants generate valid `shunt.toml` configs on the first try.
- **Visual onboarding polish:** Screenshots/GIFs of the Admin Inspector UI (`shunt dev --ui`) and `shunt dev` µs waterfalls on the landing page and `README.md`.

### Phase U2 — CLI Onboarding & Config Authoring DX *(Next)*
- **`shunt init` scaffolding wizard & presets:**
  - `shunt init --preset api | ai | ai-ollama | mcp | k8s` (plus interactive mode) to generate ready-to-run starter configs directly from the binary without cloning the repo.
  - Optional `--demo` / built-in local echo upstream mode so new users can run `shunt dev --ui` and watch live trace waterfalls with zero external setup.
- **JSON Schema & IDE Autocomplete (`shunt schema`):**
  - Generate canonical JSON Schema for `GatewayConfig` and plugin config blocks (`shunt schema > shunt.schema.json`), register with SchemaStore, and document `#:schema` hints for Taplo/VS Code/JetBrains autocomplete and inline hover docs.
- **In-terminal plugin discovery (`shunt plugins`):**
  - `shunt plugins` to list all registered plugins by pack and `shunt plugins show <name>` to inspect hook masks, fields, and a minimal copy-paste TOML block without leaving the terminal.
- **CLI ergonomics:**
  - `shunt completions <bash|zsh|fish|powershell>` via `clap_complete`.
  - Actionable error hints (e.g., suggesting `shunt init` when `shunt.toml` is missing) and surfacing `--ui` prominently during `shunt dev`.

### Phase U3 — Zero-Friction Distribution & Turnkey Deploy Kits *(Next)*
- **One-liner & package manager installs:**
  - Automated **Homebrew tap** (`brew install shettyh/tap/shunt`) updated by `.github/workflows/release.yml`.
  - Verified shell (`install.sh`) and PowerShell (`install.ps1`) installers consuming existing GitHub Release archives and `SHA256SUMS.txt`.
  - `cargo-binstall` metadata in `crates/shunt-cli/Cargo.toml` for instant prebuilt Rust installs.
- **Turnkey Observability & Deployment Stacks (`deploy/`):**
  - Official **Grafana dashboards** (JSON provisioning files) for HTTP gateway latency/errors, `shunt_ai_*` token/cost/failover/cache analytics, and `shunt_mcp_*` tool governance & loop-breaker metrics.
  - Ready-to-run **Docker Compose** quickstart stacks (`shunt + prometheus + grafana`, `shunt + redis`, `shunt + jaeger / arize-phoenix`).
  - Official **Helm chart** (`deploy/helm/shunt`) supporting both ConfigMap-backed `shunt.toml` and live Kubernetes Gateway API (`--k8s-gateway`) deployments.

---

## 5. UI & Control Plane Strategy

To give developers and companies strong visibility and self-service management **without bloating the `shunt` data-plane binary or breaking GitOps workflows**, UI capabilities are deliberately split into three decoupled layers:

### Layer 1 — Opt-In Read-Only Inspector UI (Admin Listener Only, Zero DB) *(Implemented — RFC 0012)*
- Served optionally on the Admin listener (`127.0.0.1:9090`, via `shunt dev --ui`, `shunt run --ui`, or `[admin] ui = true`, gated behind the `admin-ui` Cargo feature) from tiny embedded static assets with **zero database** and **zero hot-path overhead**.
- Powered purely by read-only Admin APIs (`/health`, `/snapshot`, `/upstreams`, `/metrics`, `/api/status`) plus a bounded trace ring buffer (`/api/traces`) and live SSE stream (`/api/traces/stream`).
- Strictly read-only so `shunt.toml` (or the active `ConfigProvider`) remains the sole source of truth.

### Layer 2 — First-Class Integration with Existing Observability Stacks *(OTLP/Prometheus Implemented; Dashboards in Phase U3)*
- Built-in **OpenTelemetry (`OTLP/HTTP`) trace export** (RFC 0011, compatible with Langfuse, Arize Phoenix, Jaeger, Tempo, and ClickHouse) and **Prometheus `/metrics`**, paired with official **Grafana dashboards** and Docker Compose recipes (Phase U3).

### Layer 3 — Full Management UI & Runtime CRUD Control Plane (`shunt-console`) *(Future — Proposed RFC 0023)*
- A full read/write management portal and runtime CRUD API (dynamic virtual key creation/rotation/expiry, spend ledger queries, model/route edits) will **never** be embedded inside `shunt` or `shunt-engine`. Instead, when teams need centralized UI- or API-driven management, it lives as a **separate optional companion service** (`shunt-console`, backed by SQLite/Postgres) that drives one or more stateless `shunt` data-plane instances strictly through the `ConfigProvider` and telemetry/admin seams.
- Solo developers and GitOps teams deploy only the ~20 MB `shunt` binary; larger organizations deploy `shunt` + `shunt-console` side by side.

---

## 6. Architectural Guardrails

Five non-negotiable invariants protect Shunt's simplicity and speed as it grows:

1. **Strict crate isolation (zero AI/MCP in `shunt-engine`):** `shunt-engine` never contains AI or MCP concepts and never depends on `shunt-ai`, `shunt-mcp`, `shunt-plugins`, a database, or a UI framework. Every feature above HTTP/TLS/WS/SSE transport lives strictly on top of `shunt-plugin-sdk`.
2. **Pay only for what you use:** Every hook or capability is gated by `HookMask` and preserves the zero-allocation sync fast path for routes that do not opt in.
3. **Single-binary zero-dependency default:** External dependencies (Redis, OTLP collectors, K8s API, `shunt-console`) are always *opt-in*. `shunt run -c shunt.toml` always works out of the box with zero sidecars or databases.
4. **Atomic, zero-downtime everything:** Config, TLS certs/CAs, virtual keys, pricing tables, and provider lists reload atomically via `ArcSwap` with graceful draining.
5. **Verified by construction:** Core, AI, and MCP primitives follow RFC 0005 & RFC 0006—backed by declarative TOML specs (`shunt test`), property tests, fuzz targets for untrusted parsers, and regression benchmarks.

---

## 7. Roadmap Summary (Completed & Upcoming)

RFCs **0001–0020** are implemented and verified in the codebase (see [rfcs/README.md](../rfcs/README.md) for the full index). Upcoming milestones in priority order:

| Priority | Track / Proposed RFC | Scope | Status |
| --- | --- | --- | --- |
| **1** | **Phase U1 — Documentation Website** | Astro Starlight docs site (`website/`), GitHub Pages CI, per-plugin config reference, quickstarts, LiteLLM migration guide, and `llms.txt` | **In Progress** |
| **2** | **Phase U2 — CLI Onboarding & Schema DX** | `shunt init` presets/demo mode, `shunt schema` (JSON Schema + SchemaStore), `shunt plugins`, `shunt completions`, friendly error hints | **Next** |
| **3** | **Phase U3 — Distribution & Deploy Kits** | Homebrew tap, `install.sh`/`install.ps1`, `cargo-binstall` metadata, official Grafana dashboards, Docker Compose stacks, Helm chart | **Next** |
| **4** | **Proposed RFC 0022 — Wasm Component Model Plugin Host** | Tier 2 hot-reloadable Wasm plugins (WIT) on `shunt-plugin-sdk` so non-Rust teams can extend Shunt without recompiling | Planned |
| **5** | **Proposed RFC 0023 — Companion Control Plane (`shunt-console`)** | Optional DB-backed management UI & runtime CRUD control plane for AI, MCP, and API gateway fleets driving `shunt` via `ConfigProvider` | Planned |
| **6** | **HTTP/3 (QUIC) & gRPC Observability** | Optional QUIC/HTTP3 listener and gRPC status/trailer metrics in `shunt-engine` / `shunt-plugins` | Planned |

---

## 8. Success Metrics

- **Onboarding bar:** A brand-new user can install `shunt`, scaffold or copy a working config, send a real request, and inspect the live µs trace waterfall in **under 60 seconds**.
- **AI & MCP adoption bar:** A developer can replace LiteLLM or point an OpenAI SDK / Claude Code / MCP client at a single `shunt` binary in under 2 minutes, routing across cloud + local models with failover, guardrails, budgets, and OTLP traces in **< 50 MB idle RSS** and **< 1 ms gateway overhead**.
- **API Gateway adoption bar:** A team can run Shunt in front of production HTTP APIs (single node or Kubernetes Gateway API) with JWT/mTLS auth, distributed rate limits, weighted canaries, and Prometheus/OTLP metrics while maintaining Shunt's benchmark lead over Caddy and parity/lead over Envoy.
