# Shunt — Product & Architecture Vision

**Status:** Living Document  
**Current Baseline:** `v0.0.1` (RFCs 0001–0006 implemented)  
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

## 2. Where We Are Today (`v0.0.1` Baseline)

Shunt already has a verified, high-performance foundation ([docs/design.md](design.md), [rfcs/README.md](../rfcs/README.md)):

- **Data plane (`shunt-core`):** HTTP/1.1 & HTTP/2 (downstream + upstream), SNI TLS with hot-reloadable certs, WebSocket upgrades, streaming bodies/SSE, split timeouts (`connect`, `response_headers`/TTFB, `idle_chunk`), passive endpoint health tracking, and lock-free `ArcSwap` atomic reloads with warm pool reuse.
- **Proven performance:** ~87.7k req/s at 956 µs p99 and **21 MB RSS** with a 3-plugin chain (outperforming Envoy 1.40 and Caddy 2.11 in local benchmarks), and 1,000 concurrent live-translated SSE streams in **~94 MB RSS**.
- **Pure-plugin AI vertical slice (`shunt-ai`):** OpenAI-compatible `POST /v1/chat/completions`, OpenAI + Anthropic backends, live Anthropic ↔ OpenAI JSON & SSE translation (including tool calls & images), model aliases/wildcards, automatic `429`/`5xx`/`529` failover with `StateStore`-backed cooldowns, and TTFT/token Prometheus metrics.
- **Developer & verification ergonomics:** `shunt check`, `shunt dev` (hot reload + per-hook µs waterfall), `shunt verify` / `shunt test`, plus layered verification (TLA+, Kani, proptest, fuzzing, TOML specs).

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

### Phase A1 — Universal Provider & Protocol Breadth *(Immediate Priority)*

Remove the biggest adoption blocker: supporting the providers and API shapes developers use every day.

- **Generalized OpenAI-compatible provider config:** Replace the closed two-variant `AiProvider` enum with a clean adapter model where any OpenAI-compatible endpoint (Ollama, vLLM, SGLang, Groq, DeepSeek, Fireworks, Together, Mistral, xAI, OpenRouter) works out of the box with per-provider base URL, auth header, custom headers, and capability flags.
- **First-class cloud & frontier adapters:**
  - **Google Gemini** (AI Studio & Vertex AI)
  - **AWS Bedrock** (Converse API + SigV4 signing)
  - **Azure OpenAI** (deployment-scoped routing + `api-key` / Entra auth)
- **Expanded API surface:**
  - `POST /v1/responses` (OpenAI Responses API)
  - `POST /v1/embeddings`
  - `GET /v1/models` (auto-synthesized from configured aliases and rules)
- **Anthropic `/v1/messages` ingress (dual frontend):**
  - Allow Anthropic-native SDKs and coding agents (e.g., Claude Code) to point at Shunt and route transparently to Anthropic, Bedrock, Vertex, OpenAI, Gemini, or local vLLM/Ollama with live bidirectional translation.

### Phase A2 — Governance, Quotas & Multi-Replica Scale

Make Shunt production-ready for teams and companies managing shared LLM spend across developers, apps, and environments.

- **Distributed `StateStore` (Redis / Valkey backend):** Extend `StateStore` with an optional async distributed backend (keeping in-memory as the zero-dependency default) so rate limits, cooldowns, and budgets work accurately across multiple Shunt replicas.
- **Virtual API Keys & Multi-Tenant Policies:**
  - Scoped client keys (e.g., per team, service, or developer) mapped to allowed model aliases, provider overrides, RPM/TPM limits, and spend budgets.
  - Clean separation between client virtual keys and upstream provider credentials.
- **Token-Aware Rate Limiting (`ai-token-rate-limit`):**
  - Enforce **TPM (tokens/min)** and **RPM (requests/min)** limits using pre-flight token estimation + post-response reconciliation from `AiUsage`.
- **Cost Attribution & Spend Budgets (`ai-budget`):**
  - Configurable/bundled model pricing tables (input, output, cached-input tokens).
  - Real-time cost metrics (`shunt_ai_cost_usd_total`), per-key/per-team rolling budgets (daily/monthly), and soft-warning vs. hard-reject (`429` / `402`) enforcement.

### Phase A3 — Smart Routing, Caching & LLM Observability

Move beyond static failover into intelligent traffic optimization and deep visibility.

- **Smart Routing Strategies:**
  - **Weighted splits** (canary/shadow testing new models, e.g., 90% Sonnet / 10% Haiku or local vLLM).
  - **Latency / TTFT-aware & health-aware routing** (prefer fastest healthy provider dynamically).
  - **Cost-aware routing** (cheapest provider meeting model/capability constraints).
  - **Capability guards** (avoid failing over a vision or tool-calling request to a target that lacks that capability).
- **Prompt / Response Caching (`ai-cache`):**
  - Exact-match request caching (deterministic/low-temperature calls) with local or Redis backend; pluggable seam for semantic vector caching.
- **LLM Observability & Auditability:**
  - **OpenTelemetry (`OTLP`) GenAI semantic conventions** (spans with model, provider, TTFT, token counts, failover chain, cost).
  - Asynchronous off-hot-path exporters (structured JSONL audit logs, Langfuse/Phoenix/ClickHouse sinks via a bounded async event bus so exporters never block the data plane).
- **Pluggable Guardrails:**
  - Pre-upstream and streaming hook integration for PII redaction, prompt-injection scanning, or external guardrail callouts.

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

### Layer 1 — Opt-In Read-Only Inspector UI (Admin Listener Only, Zero DB)
- Served optionally on the Admin listener (`127.0.0.1:9090`, e.g. `shunt dev --ui` or gated behind a Cargo feature) from tiny embedded static assets with **zero database** and **zero hot-path overhead**.
- Powered purely by existing read-only Admin APIs (`/health`, `/snapshot`, `/metrics`) plus a live SSE stream of the same per-hook timings used by `shunt dev`:
  - Compiled route, upstream, `HookMask`, and provider cooldown inspector
  - Browser-based live per-hook µs trace waterfall
  - Real-time request, failover, TTFT, token, and cost counters from an in-memory ring buffer
- Strictly read-only so `shunt.toml` (or the active `ConfigProvider`) remains the sole source of truth.

### Layer 2 — First-Class Integration with Existing Observability Stacks
- Ship official **Grafana dashboards** (backed by Shunt's Prometheus metrics) and **OpenTelemetry (`OTLP`) HTTP + GenAI trace export** (compatible with Langfuse, Arize Phoenix, Jaeger, Tempo, and ClickHouse).
- Teams keep historical analytics, alerting, and prompt tracing in the tools they already operate rather than managing another siloed dashboard.

### Layer 3 — Full Management UI as a Separate Companion Control Plane (`shunt-console`)
- A full read/write management portal will **never** be embedded inside `shunt` or `shunt-core`. Instead, when teams need centralized UI-driven management, it lives as a **separate optional companion service** (`shunt-console`, backed by SQLite/Postgres) that drives one or more stateless `shunt` data-plane instances strictly through the `ConfigProvider` and telemetry/admin seams.
- `shunt-console` covers **both** AI Gateway and HTTP API Gateway management in one control plane:
  - **AI Gateway Management:** Virtual API key CRUD, team/project spend budgets, model alias & fallback routing editor, provider credential management, interactive model playground, and historical token/cost dashboards.
  - **API Gateway Management:** Visual CRUD for routes, upstream pools, weighted canary/blue-green traffic splits, active health status, SNI TLS certificates, and global/per-route plugin chains (JWT/OIDC, rate limits, CORS, header rewrites, Wasm plugins) with pre-publish config validation (`shunt check` semantics).
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

To execute Path A immediately while laying clean rails for Path B, the recommended sequence of upcoming RFCs is:

| Priority | Proposed RFC | Scope | Path |
| --- | --- | --- | --- |
| **1** | **RFC 0007 — Generalized AI Providers & Endpoints** | OpenAI-compatible custom providers (Ollama, vLLM, Groq, DeepSeek, Fireworks, OpenRouter), Gemini + Azure + Bedrock adapters, `/v1/models` and `/v1/embeddings` | Path A (A1) |
| **2** | **RFC 0008 — Multi-Protocol AI Ingress** | Anthropic `/v1/messages` frontend + OpenAI `/v1/responses` support (bidirectional translation across backends) | Path A (A1) |
| **3** | **RFC 0009 — Virtual Keys, TPM Limits, Cost Budgets & Distributed `StateStore`** | Virtual API keys, pricing catalog, cost budgets, TPM/RPM limiter, optional Redis/Valkey `StateStore` | Path A (A2) + Path B |
| **4** | **RFC 0010 — Smart Routing & Active Upstream Health Checks** | Weighted upstream pools, active HTTP/TCP upstream probes, weighted/TTFT/cost AI routing, multi-protocol capability guards | Path A (A3) + Path B (B1) |
| **5** | **RFC 0011 — OTLP/HTTP Observability & Exact-Match AI Cache** | Zero-dependency bounded async OTLP/HTTP JSON trace exporter, W3C `traceparent` + HTTP & GenAI tracing, exact-match `ai-cache` (in-memory LRU+TTL & optional Redis) | Path A (A3) + Path B (B1) |
| **6** | **RFC 0012 — Admin Read-Only Inspector UI (`--ui`)** | Opt-in embedded read-only Web UI on Admin listener for live trace waterfalls, snapshot/HookMask graph & AI usage | Path A + Path B |
| **7** | **RFC 0013 — JWT/OIDC Auth & Kubernetes Gateway API** | JWKS/JWT auth plugin + K8s Gateway API `ConfigProvider` | Path B (B1–B2) |
| **8** | **RFC 0014 — Wasm Component Model Plugin Host** | Tier 2 hot-reloadable Wasm plugins on `shunt-plugin-sdk` | Path B (B3) |
| **9** | **RFC 0015 — Companion Control Plane (`shunt-console`)** | Separate optional DB-backed management UI & control plane for both AI Gateway (keys, budgets, models, playground) and API Gateway (routes, upstreams, canaries, plugins, TLS, fleet rollouts) driving `shunt` via `ConfigProvider` | Path A + Path B |

---

## 9. Success Metrics

- **Path A adoption bar:** A developer can replace LiteLLM or point an OpenAI SDK / Claude Code client at a single `shunt` binary in under 2 minutes, routing across cloud + local models with failover, budgets, and OTLP traces in **< 50 MB idle RSS** and **< 1 ms gateway overhead**.
- **Path B adoption bar:** A team can run Shunt in front of production HTTP APIs (single node or Kubernetes) with JWT auth, distributed rate limits, weighted canaries, and Prometheus/OTLP metrics while maintaining Shunt's benchmark lead over Caddy and parity/lead over Envoy.
