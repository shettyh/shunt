# Shunt — Product & Architecture Vision

**Status:** Living Document  
**Current Baseline:** `v0.0.1` (RFCs 0001–0012 implemented)  
**Primary Focus (Now):** **Path A** — Ultra-Lean Self-Hosted AI Gateway (`shunt-ai`)  
**Expansion Horizon:** **Path B** — Developer-First Modern API Gateway

---

## 1. North Star

**Shunt** aims to be the **fastest, cleanest single-binary Rust gateway for both AI workloads and modern HTTP APIs**—combining a tiny, Envoy-beating data plane (`shunt-core`) with a zero-overhead plugin SDK (`shunt-plugin-sdk`).

Most teams today face an awkward split:
- For **AI traffic**, they run slow, memory-hungry Python proxies (LiteLLM), pay SaaS markups and send sensitive traffic outside their VPC (OpenRouter), or adopt heavyweight enterprise stacks (Kong/Envoy AI Gateway).
- For **API traffic**, they choose between deeply complex proxies built for 10,000-service meshes (Envoy, Kong) or simpler reverse proxies that lack programmable gateway primitives.

Shunt bridges both with one architectural bet:

> **Keep `shunt-core` small, verifiable, and strictly AI-agnostic—and prove its power by building a world-class self-hosted AI Gateway (`Path A`) and a developer-first HTTP API Gateway (`Path B`) entirely as composable plugins on top.**

Every core capability required to win Path A (distributed state, virtual keys/JWT, weighted & latency-aware routing, active health checks, OpenTelemetry tracing, high-concurrency streaming) directly accelerates Path B.

---

## 2. Where We Are Today (`v0.0.1`, RFCs 0001–0012 Implemented)

Shunt has a verified, high-performance foundation ([docs/design.md](design.md), [rfcs/README.md](../rfcs/README.md)):

- **Data plane (`shunt-core`):** HTTP/1.1 & HTTP/2 (downstream + upstream), SNI TLS with hot-reloadable certs, WebSocket upgrades, streaming bodies/SSE, split timeouts (`connect`, `response_headers`/TTFB, `idle_chunk`), weighted upstream pools with active HTTP/TCP health probes + passive endpoint health tracking, optional Redis/Valkey `DistributedStore`, zero-dependency bounded async OTLP/HTTP JSON trace export, and lock-free `ArcSwap` atomic reloads with warm pool reuse.
- **Proven performance:** ~87.7k req/s at 956 µs p99 and **21 MB RSS** with a 3-plugin chain (outperforming Envoy 1.40 and Caddy 2.11 in local benchmarks), **71.2k req/s at 1.15 ms p99 and 26 MB RSS** through the full 8-plugin governed AI chain (~72× faster throughput and ~74× less RAM than 4-worker stateless LiteLLM 1.110.2), and 1,000 concurrent live-translated SSE streams in **~99–103 MB RSS**.
- **Pure-plugin multi-provider AI gateway (`shunt-ai`):**
  - **Multi-protocol ingress:** `POST /v1/chat/completions`, `POST /v1/messages` (+ local `/v1/messages/count_tokens`), `POST /v1/responses`, `POST /v1/embeddings`, and synthesized `GET /v1/models` / `GET /v1/models/{id}`.
  - **5 upstream dialects:** Generalized `openai_compatible` (OpenAI, Ollama, vLLM, SGLang, Groq, DeepSeek, Fireworks, Together, etc.), `anthropic`, `azure_openai`, `gemini` (AI Studio & Vertex AI), and `bedrock` (Converse & ConverseStream with pure-Rust AWS SigV4 + binary EventStream framing).
  - **Governance, routing & caching:** Virtual API keys (`ai-virtual-keys`) with model/provider ACLs and per-key overrides, RPM/TPM token-aware rate limiting with post-response reconciliation (`ai-token-rate-limit`), nano-USD pricing & rolling spend budgets (`ai-budget`), smart routing (`priority`, `weighted`, `latency`, `cost` + multi-protocol capability guards), `429`/`5xx`/`529` failover with `Retry-After` cooldowns, exact-match LRU/Redis response caching (`ai-cache`), and Prometheus + OTLP GenAI observability (`ai-usage-tracker`, `otel-trace`).
- **Developer, inspector & verification ergonomics:** `shunt check`, `shunt verify`, `shunt test`, `shunt dev` / `shunt run` with opt-in read-only Admin Inspector Web UI (`--ui`) and live SSE trace waterfalls, plus layered verification (TLA+, Kani, proptest, 10 fuzz targets, and 10 TOML conformance specs).

---

## 3. Positioning & Non-Goals

### Where Shunt Fits

| Dimension | Hosted SaaS (OpenRouter, Cloudflare AI) | Self-Hosted Python/Enterprise (LiteLLM, Kong AI, Envoy AI) | **Shunt** |
| --- | --- | --- | --- |
| **Deployment** | Managed SaaS (data leaves VPC) | Heavy Python stack or complex K8s/DB control plane | **Single ~20 MB Rust binary + `shunt.toml`** |
| **Hot-path overhead** | Network hop + SaaS latency | High Python latency / large memory footprint | **Sub-ms p99, zero-alloc sync fast path** |
| **Extensibility** | Closed or webhook-only | Heavy/coupled plugin models | **Typed `shunt-plugin-sdk` (Rust now, Wasm next)** |
| **AI + HTTP unified** | AI-only or CDN-coupled | Separate stacks or bolted-on enterprise modules | **One gateway for `/v1/*` AI routes and standard APIs** |

### Explicit Non-Goals

1. **Not a hosted model marketplace / billing SaaS:** Shunt is a self-hosted BYOK (Bring Your Own Key) gateway, not a resale marketplace like OpenRouter.
2. **Not an Envoy service-mesh clone:** We will not chase L4 TCP/UDP proxying, xDS, SPIFFE sidecar meshes, or legacy enterprise ESB features.
3. **Never leak AI concepts into `shunt-core`:** `Model`, `Prompt`, `Token`, and provider schemas stay strictly inside `shunt-ai` (and future AI plugins). If `shunt-ai` needs a new capability, we design a general-purpose transport/SDK primitive for it.

---

## 4. Path A (Primary Focus): The Ultra-Lean Self-Hosted AI Gateway

**Why Path A first:** Developers, AI startups, and enterprises urgently need a reliable, low-latency, self-hosted gateway in front of LLM providers, coding agents, and internal GPU clusters (vLLM / Ollama / SGLang). Existing self-hosted options are either too heavy (LiteLLM), too coupled to specific storage engines (TensorZero), or too complex to operate (Envoy/Kong AI Gateway). Shunt can own the **"fast, zero-bloat self-hosted OpenRouter / LiteLLM alternative"** niche right now.

### Phase A1 — Universal Provider & Protocol Breadth *(Implemented — RFCs 0007–0008)*

Remove the biggest adoption blocker: supporting the providers and API shapes developers use every day.

- **Generalized OpenAI-compatible provider config:** Any OpenAI-compatible endpoint (Ollama, vLLM, SGLang, Groq, DeepSeek, Fireworks, Together, Mistral, xAI, OpenRouter) works out of the box with per-provider base URL, auth header, custom headers, and capability flags.
- **First-class cloud & frontier adapters:**
  - **Google Gemini** (AI Studio & Vertex AI)
  - **AWS Bedrock** (Converse & ConverseStream API + pure-Rust SigV4 & binary EventStream framing)
  - **Azure OpenAI** (deployment-scoped routing + `api-key` / bearer auth)
- **Expanded API surface:** `POST /v1/responses`, `POST /v1/embeddings`, `GET /v1/models`, `GET /v1/models/{id}`.
- **Anthropic `/v1/messages` ingress (dual frontend):** Anthropic-native SDKs and coding agents (e.g., Claude Code) route transparently to Anthropic (native zero-loss passthrough) or OpenAI, Azure, Gemini, Bedrock, and local vLLM/Ollama with live bidirectional translation and local `POST /v1/messages/count_tokens`.

### Phase A2 — Governance, Quotas & Multi-Replica Scale *(Implemented — RFC 0009)*

Make Shunt production-ready for teams and companies managing shared LLM spend across developers, apps, and environments.

- **Distributed `StateStore` (Redis / Valkey backend):** Optional async distributed backend (keeping in-memory as the zero-dependency default) so rate limits, cooldowns, budgets, and cache entries work accurately across multiple Shunt replicas.
- **Virtual API Keys & Multi-Tenant Policies (`ai-virtual-keys`):** Scoped SHA-256 client keys mapped to teams, allowed model aliases, allowed providers, per-model provider overrides, RPM/TPM limits, and spend budgets.
- **Token-Aware Rate Limiting (`ai-token-rate-limit`):** Enforces **TPM** and **RPM** limits using pre-flight token estimation + post-response reconciliation from `AiUsage`.
- **Cost Attribution & Spend Budgets (`ai-budget`):** Bundled and overridable model pricing tables (input, output, cached-input read tokens), `shunt_ai_cost_usd_total` metrics, per-key/per-team/global rolling budgets, and soft-warning vs. hard-reject (`429` / `402`) enforcement.

### Phase A3 — Smart Routing, Caching & LLM Observability *(Implemented — RFCs 0010–0011)*

Move beyond static failover into intelligent traffic optimization and deep visibility.

- **Smart Routing Strategies:** `weighted` splits (SWRR canary/A-B), `latency` (EWMA TTFT/TTFB & error-rate ranking with cold-start/stale re-exploration), `cost` (cheapest estimated nano-USD), and multi-protocol **capability guards** (`chat`, `streaming`, `tools`, `vision`, `json_schema`, `reasoning`, `embeddings`).
- **Exact-Match AI Response Caching (`ai-cache`):** Canonicalized SHA-256 request caching for deterministic/embeddings calls with in-memory LRU+TTL or Redis backend and `Cache-Control` support.
- **LLM Observability (`otel-trace` + OTLP/HTTP):** Zero-dependency bounded async OTLP/HTTP JSON trace exporter with W3C `traceparent` propagation and GenAI semantic conventions (model, provider, TTFT, tokens, cache status, failover chain, cost).

### Phase A4 — Production AI Parity *(Next Priority — Closing Remaining LiteLLM / OpenRouter Gaps)*

Close the remaining non-UI feature gaps needed for seamless drop-in replacement of LiteLLM and OpenRouter in demanding production environments—while keeping `shunt-core` strictly AI-agnostic and zero-bloat:

- **Deep Protocol & Translation Polish:**
  - Cross-provider **reasoning / extended thinking** translation (`reasoning_effort` ↔ Anthropic `thinking` ↔ Gemini `thinkingConfig` ↔ Bedrock) with response `thinking`/`reasoning_content` mapping and `reasoning_tokens` accounting.
  - **Prompt-cache write accounting & translation:** Track `cache_creation_input_tokens` and `cache_write_per_million_usd` in `PricingCatalog`, plus translate `cache_control` ↔ Bedrock `cachePoint`.
  - **Structured outputs & parameter normalization:** `response_format` (`json_schema`) translation for Anthropic and Bedrock, LiteLLM-style `drop_params` (strip unsupported provider-specific params cleanly instead of upstream `400`), per-model default/override parameters, and PDF/`document` + audio content parts.
  - **Claude / MaaS on Vertex AI** (`/publishers/anthropic/models/...`) and **Bedrock Embeddings**.
- **Dynamic Cloud Identity & Provider Ergonomics:**
  - Auto-refreshing cloud credentials for production VPCs: **AWS IAM Roles** (EC2 IMDS, EKS IRSA, ECS Task Role, STS AssumeRole), **GCP ADC / Service Account / Workload Identity** (OAuth2), and **Azure Entra ID / Managed Identity**.
  - **Built-in provider presets** (Groq, DeepSeek, Fireworks, Together, Mistral, Cohere, xAI, OpenRouter, Ollama) to eliminate repetitive URL/path boilerplate, **multi-key upstream pools** with automatic `429` rotation, and optional **client BYOK passthrough**.
- **Pluggable Guardrails & Audit Sinks (`ai-guardrails`):**
  - Fast built-in **PII / secret detection & redaction** and regex/keyword/policy filters on request and response paths.
  - **External guardrail callout hooks** (pre-request, post-response, and streaming) for Presidio, Lakera, Bedrock Guardrails, Llama Guard, or generic HTTP/OPA webhooks.
  - Opt-in redacted **prompt/completion audit sinks** (JSONL / OTLP GenAI events / async webhook) and **budget/circuit-breaker alert webhooks** (Slack/PagerDuty/HTTP).
- **Expanded AI Endpoints & Streaming Cache:**
  - `POST /v1/rerank` (Cohere / Jina / Voyage / Bedrock / vLLM), `POST /v1/images/*`, `POST /v1/audio/*`, `/v1/realtime` (WebSocket voice/live proxy), `POST /v1/completions` (legacy FIM), `POST /v1/moderations`, `POST /v1/batches` + `/v1/files`, and `GET /v1/generation?id=...`.
  - **Streaming SSE caching & replay** and **singleflight coalescing** in `ai-cache`, plus a clean opt-in seam for **semantic vector caching**.
- **Advanced Routing, Pricing & Governance:**
  - **OpenRouter-style per-request routing overrides** (`models[]` fallback list, `provider: { order, only, ignore, sort, allow_fallbacks, data_collection }`) and **ZDR / compliance region tags**.
  - **Context-window capability guards**, **context-overflow / TTFT-timeout failover**, **output throughput (tokens/sec)** & **upstream RPM/TPM headroom** routing, and **traffic shadowing / mirroring**.
  - **Fine-grained quotas & pricing:** Per-key `max_parallel_requests` (concurrency), key expiration (`expires_at`), per-model RPM/TPM/budgets per key, end-user (`user` field) & org hierarchy, pre-flight budget reservations, tiered/long-context pricing, external JSON pricing catalog loading, and enriched `GET /v1/models` metadata (`context_length`, `pricing`, capabilities).

---

## 5. Path B (Organic Expansion): Developer-First Modern API Gateway

**Vision for Path B:** Be **"Caddy for APIs"**—the gateway teams choose when they need Envoy-class speed and real API management (auth, rate limits, canaries, observability, K8s integration) without Envoy/Kong operational misery.

### Shared Foundations Unlocked by Path A

Many core API gateway features land directly as part of Path A:

| Capability | Needed by Path A (AI) | Unlocks in Path B (API Gateway) |
| --- | --- | --- |
| **Redis / Valkey `StateStore`** | Multi-replica TPM, budgets, cooldowns | Distributed API rate limiting & circuit breakers |
| **Weighted & health-aware routing** | Model A/B tests & TTFT routing | Canary / blue-green deployments & load shedding |
| **Active health checks** | Probing local vLLM / Ollama / inference nodes | Upstream service health & automatic ejection |
| **OpenTelemetry (`OTLP`)** | LLM trace & TTFT visibility | End-to-end distributed HTTP tracing |
| **Virtual keys / Auth** | Multi-tenant AI keys & policies | API key management & tenant isolation |

### Phase B1 — Production HTTP Gateway Essentials

- **Authentication & Security:** JWT / JWKS verification, OIDC/OAuth2 introspection, mTLS client-certificate verification, IP allow/deny lists, and configurable request/response body limits.
- **Traffic Management:** Active HTTP/TCP health checks, outlier detection / circuit breakers, weighted upstream pools, traffic mirroring (shadowing), and automatic retries with idempotency/method guards.
- **Protocol & Transport Polish:** Response compression (`gzip`, `br`, `zstd`) with safe streaming awareness, HTTP/3 (QUIC) listener support, and first-class gRPC status/trailer metrics.

### Phase B2 — Dynamic Control Planes & Cloud-Native Deployment

Leverage the `ConfigProvider` trait designed in [docs/design.md](design.md#L142) without changing `shunt-core`:

- **Kubernetes Gateway API provider:** Watch `Gateway`, `HTTPRoute`, and `Secret` (TLS) resources and compile them directly into Shunt's immutable `GatewaySnapshot`.
- **Control-plane / API config provider:** Optional remote pull (HTTP/GitOps/etcd) or authenticated push endpoint for fleet-wide config distribution, plus official Helm chart and Terraform/Docker Compose recipes.

### Phase B3 — Runtime Extensibility Without Recompiling

Today, custom plugins implement `HttpPlugin` in Rust and compile into the binary (Tier 1). To broaden adoption across non-Rust teams:

- **Tier 2 — Wasm Component Model (WIT) plugins:** Expose `shunt-plugin-sdk`'s hyper-free types over WIT (`wasmtime`) so teams can write hot-reloadable plugins in Rust, Go, TypeScript, or Python with sandboxed fault isolation.
- **External callout plugins (`ext_authz` / webhook):** Clean async HTTP/gRPC callout plugins for integrating existing auth, policy (OPA), or guardrail services.
- **Embeddable Rust ecosystem (`crates.io`):** Publish `shunt-plugin-sdk`, `shunt-core`, `shunt-plugins`, and `shunt-ai` as clean library crates so Rust teams can embed Shunt as a batteries-included alternative to raw `hyper` or `pingora`.

---

## 6. UI & Control Plane Strategy

To give developers and companies strong visibility and self-service management **without bloating the `shunt` data-plane binary or breaking GitOps workflows**, UI capabilities are deliberately split into three decoupled layers:

### Layer 1 — Opt-In Read-Only Inspector UI (Admin Listener Only, Zero DB) *(Implemented — RFC 0012)*
- Served optionally on the Admin listener (`127.0.0.1:9090`, via `shunt dev --ui`, `shunt run --ui`, or `[admin] ui = true`, gated behind the `admin-ui` Cargo feature) from tiny embedded static assets with **zero database** and **zero hot-path overhead**.
- Powered purely by read-only Admin APIs (`/health`, `/snapshot`, `/upstreams`, `/metrics`, `/api/status`) plus a bounded trace ring buffer (`/api/traces`) and live SSE stream (`/api/traces/stream`):
  - Compiled route, upstream, `HookMask`, and provider cooldown inspector
  - Browser-based live per-hook µs trace waterfall
  - Real-time request, failover, TTFT, token, cache, and cost counters from an in-memory ring buffer
- Strictly read-only so `shunt.toml` (or the active `ConfigProvider`) remains the sole source of truth.

### Layer 2 — First-Class Integration with Existing Observability Stacks
- Built-in **OpenTelemetry (`OTLP/HTTP`) trace export** (RFC 0011, compatible with Langfuse, Arize Phoenix, Jaeger, Tempo, and ClickHouse) and **Prometheus `/metrics`**, paired with official **Grafana dashboards**.
- Teams keep historical analytics, alerting, and prompt tracing in the tools they already operate rather than managing another siloed dashboard.

### Layer 3 — Full Management UI & Runtime CRUD Control Plane (`shunt-console`)
- A full read/write management portal and runtime CRUD API (dynamic virtual key creation/rotation/expiry, spend ledger queries, model/route edits) will **never** be embedded inside `shunt` or `shunt-core`. Instead, when teams need centralized UI- or API-driven management, it lives as a **separate optional companion service** (`shunt-console`, backed by SQLite/Postgres) that drives one or more stateless `shunt` data-plane instances strictly through the `ConfigProvider` and telemetry/admin seams.
- `shunt-console` covers **both** AI Gateway and HTTP API Gateway management in one control plane:
  - **AI Gateway Management:** Programmatic & UI virtual API key CRUD (with expiration & rotation), team/org/end-user spend budgets & historical ledger APIs, model alias & fallback routing editor, provider credential management, interactive model playground, and historical token/cost dashboards.
  - **API Gateway Management:** Visual CRUD for routes, upstream pools, weighted canary/blue-green traffic splits, active health status, SNI TLS certificates, and global/per-route plugin chains (JWT/OIDC, rate limits, CORS, header rewrites, Wasm plugins) with pre-publish config validation (`shunt check` / `shunt verify` semantics).
  - **Fleet & Governance:** Multi-instance `shunt` fleet status, config revision history, diff previews, one-click atomic snapshot rollout/rollback across nodes, audit logs, and SSO/RBAC.
- Solo developers and GitOps teams deploy only the ~20 MB `shunt` binary; larger organizations deploy `shunt` + `shunt-console` side by side.

---

## 7. Architectural Guardrails

As Shunt grows across Path A, Path B, and optional UI/control-plane layers, five non-negotiable invariants protect its simplicity and speed:

1. **Strict crate isolation (zero AI in `shunt-core`):** `shunt-core` never contains AI concepts (`Model`, `Prompt`, `Token`, provider schemas) and never depends on `shunt-ai`, `shunt-plugins`, a database, or a UI framework. Every feature above HTTP/TLS/WS/SSE transport lives strictly on top of `shunt-plugin-sdk`.
2. **Pay only for what you use:** Every new hook or capability must be gated by `HookMask` and preserve the zero-allocation sync fast path for routes that do not opt in.
3. **Single-binary zero-dependency default:** External dependencies (Redis, OTLP collectors, K8s API, `shunt-console`) are always *opt-in*. `shunt run -c shunt.toml` must always work out of the box with zero sidecars or databases.
4. **Atomic, zero-downtime everything:** Config, TLS certs, virtual keys, pricing tables, and provider lists reload atomically via `ArcSwap` with graceful draining.
5. **Verified by construction:** New core and AI primitives follow RFC 0005 & RFC 0006—backed by declarative TOML specs (`shunt test`), property tests, fuzz targets for untrusted network/SSE parsers, and regression benchmarks.

---

## 8. Concrete Next Milestones (Recommended RFC Queue)

RFCs **0001–0012** are implemented and verified in the codebase (see [rfcs/README.md](../rfcs/README.md) for the full index). To finish Path A's production parity with LiteLLM & OpenRouter while laying clean rails for Path B and `shunt-console`, the recommended sequence of upcoming RFCs is:

| Priority | Proposed RFC | Scope | Path |
| --- | --- | --- | --- |
| **1** | **RFC 0013 — Deep Protocol Parity, Provider Presets & Multi-Key Pools** *(Implemented)* | Cross-provider reasoning/thinking translation, prompt-cache write (`cache_creation_input_tokens`) & tiered pricing, `drop_params` + param overrides, Anthropic/Bedrock `json_schema`, Claude-on-Vertex, Bedrock embeddings, built-in provider presets, multi-key upstream pools, and BYOK passthrough | Path A (A4) |
| **2** | **RFC 0014 — Dynamic Cloud IAM Auth & Outbound HTTP Client Primitive** *(Implemented)* | AI-free `HttpClient` seam in `shunt-plugin-sdk` + `hyper`/`rustls` impl in `shunt-core`, powering cached, reload-persistent token refresh for AWS IAM (IMDSv2/ECS/EKS IRSA/STS), GCP ADC/Workload Identity/Service Account JWT, and Azure Entra ID (Managed Identity/`client_credentials`/Workload Identity) | Path A (A4) + Path B |
| **3** | **RFC 0015 — Pluggable AI Guardrails (`ai-guardrails`) & Audit/Webhook Sinks** *(Implemented)* | Built-in PII/secret redaction & regex/policy filters, async external guardrail callouts (pre/post/stream), opt-in redacted prompt/completion audit sinks (JSONL, OTLP GenAI span events, signed webhooks), and budget/circuit-breaker/guardrail alert webhooks (Slack, PagerDuty, HTTP) | Path A (A4) |
| **4** | **RFC 0016 — Multimodal Endpoints & Streaming AI Cache** *(Implemented)* | `POST /v1/rerank`, `/v1/images/*`, `/v1/audio/*`, `/v1/realtime` (WS), `/v1/completions`, `/v1/batches` + `/v1/files`, `GET /v1/generation`, plus streaming SSE caching/replay, singleflight coalescing, and semantic cache seam in `ai-cache` | Path A (A4) |
| **5** | **RFC 0017 — Per-Request Routing, Concurrency Quotas & Advanced Failover** *(Implemented)* | OpenRouter-style per-request `models[]`/`provider`/ZDR routing, context-window guards, overflow & TTFT-timeout failover, throughput/headroom routing, traffic shadowing, per-key `max_parallel_requests`/`expires_at`/per-model quotas, pre-flight budget holds, and external JSON pricing catalogs | Path A (A4) + Path B |
| **6** | **RFC 0018 — JWT/OIDC Auth, HTTP Security, Compression & Kubernetes Gateway API** *(Implemented)* | Pure-Rust JWT/JWKS/OIDC auth (`jwt-auth`), CIDR `ip-filter`, mTLS client-cert auth (`mtls-auth`) with hot CA reload, streaming `body-limit`, streaming-safe `compression` (`zstd`/`br`/`gzip`/`deflate`), `redirect`, header route matching, and zero-bloat Kubernetes Gateway API v1 `ConfigProvider` (manifests + live API sync) | Path B (B1–B2) |
| **7** | **RFC 0019 — `shunt-mcp`: MCP & Agentic Governance Plugin Pack** *(Implemented)* | Pure-SDK Streamable HTTP MCP gateway & multi-server virtual multiplexer (`mcp-auth`, `mcp-router`, `mcp-guardrails`, `mcp-rate-limit`, `mcp-telemetry`): virtual keys / JWT / mTLS identity, RFC 9728 OAuth metadata, session hijacking protection, ACL-filtered `tools/list` fan-out, per-tool JSON argument policies, approval gates, PII/secret redaction, indirect prompt-injection defense (JSON & SSE), OPA policy webhooks, and stuck-agent loop breaking | Path A (Agentic) |
| **8** | **RFC 0020 — Wasm Component Model Plugin Host** | Tier 2 hot-reloadable Wasm plugins on `shunt-plugin-sdk` | Path B (B3) |
| **9** | **RFC 0021 — Companion Control Plane (`shunt-console`)** | Separate optional DB-backed management UI & runtime CRUD control plane for both AI Gateway (virtual key/budget/spend APIs, models, playground) and API Gateway (routes, upstreams, canaries, plugins, TLS, fleet rollouts) driving `shunt` via `ConfigProvider` | Path A + Path B |

---

## 9. Success Metrics

- **Path A adoption bar:** A developer can replace LiteLLM or point an OpenAI SDK / Claude Code client at a single `shunt` binary in under 2 minutes, routing across cloud + local models with failover, budgets, and OTLP traces in **< 50 MB idle RSS** and **< 1 ms gateway overhead**.
- **Path B adoption bar:** A team can run Shunt in front of production HTTP APIs (single node or Kubernetes) with JWT auth, distributed rate limits, weighted canaries, and Prometheus/OTLP metrics while maintaining Shunt's benchmark lead over Caddy and parity/lead over Envoy.
