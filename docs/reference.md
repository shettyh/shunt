# Shunt Reference

Complete reference for Shunt's built-in plugin packs, Admin API, CLI flags, and ready-to-run example configurations.

---

## Built-in Plugins

Every first-party plugin depends strictly on `shunt-plugin-sdk`—never on `shunt-engine`.

### General HTTP Plugins (`shunt-plugins`)

| Plugin | Purpose |
| --- | --- |
| `request-id` | Generates or propagates `x-request-id` across request/response headers and `RequestCtx` |
| `access-log` | Structured `tracing` access logging in `on_complete` |
| `bearer-auth` | Bearer token verification with subject injection into `RequestCtx` |
| `jwt-auth` | Pure-Rust JWT/JWKS/OIDC verification (`HS*`/`RS*`/`PS*`/`ES*`/`EdDSA`), cached JWKS auto-refresh, scope/claim assertions, and anti-spoofing claim header forwarding |
| `mtls-auth` | Mutual TLS client certificate authorization (CN, SAN DNS, SPIFFE SAN URI, SHA-256 fingerprint) and verified identity header injection |
| `ip-filter` | IPv4/IPv6 CIDR allow/deny filtering with trusted-proxy right-to-left `X-Forwarded-For` resolution |
| `body-limit` | Synchronous `Content-Length` and zero-copy streaming request body size enforcement (`413 Payload Too Large`) |
| `compression` | Streaming-safe, SSE-aware response compression (`zstd`, `br`, `gzip`, `deflate`) with `Vary` and RFC 9110 `ETag` weakening |
| `redirect` | Configurable HTTP redirects (`301`/`302`/`307`/`308`, scheme/host/port/path rewrites) |
| `rate-limit` | Token-bucket rate limiting backed by reload-persistent `StateStore` (or Redis/Valkey) |
| `header-rewrite` | Set/append/remove request, upstream, and response headers plus host/path rewrites with `{param}` interpolation |
| `cors` | Configurable CORS preflight handling and response headers |
| `otel-trace` | W3C `traceparent`/`tracestate` propagation and OpenTelemetry span emission via `[telemetry]` |
| `metrics` | Prometheus request counters and latency histograms served via `GET /metrics` |
| `dev-waterfall` | Live per-hook microsecond trace waterfall (automatically attached by `shunt dev`) |

### AI Gateway Plugin Pack (`shunt-ai`)

| Plugin | Purpose |
| --- | --- |
| `ai-virtual-keys` | Constant-time SHA-256 virtual API key auth (`Authorization` / `x-api-key` / custom header) with team, model/provider ACLs, per-key overrides, and quota/budget policies |
| `ai-model-router` | Multi-protocol ingress (`/v1/chat/completions`, `/v1/messages`, `/v1/responses`, `/v1/embeddings`, `/v1/models`, multimodal images/audio/rerank/realtime, generation lookup), capability & context-window guards, per-request routing preferences, shadow mirroring, and `priority`/`weighted`/`latency`/`cost`/`throughput` routing |
| `ai-guardrails` | Built-in PII & secret detection/redaction, prompt-injection heuristics, regex/keyword rules, and async external callouts (Webhook, OPA, Presidio, Lakera Guard, Bedrock Guardrails, Llama Guard) across request, response, and streaming SSE paths |
| `ai-cache` | Exact-match SHA-256, streaming SSE replay, singleflight deduplication, and semantic response caching (in-memory LRU+TTL or Redis/Valkey) with tenant scoping and `Cache-Control` support |
| `ai-token-rate-limit` | Pre-flight token estimation + post-response `AiUsage` reconciliation enforcing RPM/TPM limits, quota windows, and in-flight concurrency caps locally or across Redis/Valkey |
| `ai-budget` | Exact integer nano-USD cost accounting & rolling spend budgets (virtual key / team / global) with soft warnings, hard `429`/`402` enforcement, and `shunt_ai_cost_usd_total` metrics |
| `ai-provider-adapter` | Provider presets, multi-key pools, dynamic Cloud IAM auth (AWS STS/IMDS/IRSA, GCP OAuth/Metadata, Azure AD), and JSON/SSE/EventStream translation across `openai_compatible`, `anthropic`, `azure_openai`, `gemini`/Vertex AI, and `bedrock` |
| `ai-failover` | Automatic `Flow::RetryUpstream` on `429`/`5xx`/`529` and context-overflow errors with `StateStore`/Redis-backed cooldowns, circuit breakers, key-pool rotation, and `Retry-After` support |
| `ai-usage-tracker` | Extracts prompt, cached-prompt, reasoning, and completion tokens + TTFT across all dialects for Prometheus metrics, structured logs, generation lookup, and OTLP GenAI spans |
| `ai-audit` | Opt-in redacted prompt & completion audit sinks to JSONL files, OTLP GenAI span events, or HMAC-signed async HTTP webhooks |
| `ai-alerts` | Non-blocking, deduplicated operational alerts for budget thresholds, circuit breakers, failover exhaustion, and guardrail blocks to Slack, PagerDuty, or HTTP webhooks |

### MCP & Agentic Governance Plugin Pack (`shunt-mcp`)

| Plugin | Purpose |
| --- | --- |
| `mcp-auth` | Constant-time SHA-256 virtual keys or forwarded `jwt-auth`/`mtls-auth` identity, RFC 9728 `/.well-known/oauth-protected-resource` discovery, per-agent server/tool/resource/prompt ACLs, and `Mcp-Session-Id` principal binding |
| `mcp-router` | Streamable HTTP JSON-RPC 2.0 router & multi-server virtual MCP multiplexer (`initialize`, cached concurrent ACL-filtered `tools/list`/`resources/list`/`prompts/list` fan-out, `<server>__<tool>` routing, `Mcp-Name` mirroring, stateful upstream handshakes) |
| `mcp-guardrails` | Tool allow/deny policies, approval gates (`x-shunt-approved` / `_meta.approved`), per-tool JSON argument regex/schema rules, outbound PII/secret redaction, inbound indirect prompt-injection & secret scanning (JSON + SSE), and OPA/HTTP policy webhooks |
| `mcp-rate-limit` | Per-principal RPM & `tools/call` RPM, per-tool quotas, per-session call caps, identical-call agent loop breaker, and RAII `max_parallel_calls` concurrency caps (local or Redis/Valkey) |
| `mcp-telemetry` | `shunt_mcp_*` Prometheus metrics, OTLP `mcp.*` span enrichment, structured SHA-256 audit logs, and `/api/status` (`"mcp"`) runtime inspection |

---

## Server Listener Tuning (`[server]`)

Opt-in per-core `SO_REUSEPORT` accept sharding and configurable listen backlogs reduce single-socket accept contention under Linux connection storms and allow overlapping rolling restarts:

| Key | Type | Default | Description |
| --- | --- | --- | --- |
| `listen` | string | `"0.0.0.0:8080"` | Proxy listener bind address (`host:port`) |
| `drain_timeout_ms` | integer | `30000` | Graceful connection drain timeout on `SIGTERM` / `SIGINT` |
| `reuseport` | bool | `false` | Bind multiple `SO_REUSEPORT` listener shards sharing `listen` (Unix) |
| `accept_shards` | integer (optional) | CPU core count | Explicit listener shard count (`1..=128`; requires `reuseport = true`) |
| `backlog` | integer | `4096` | TCP listen backlog per listener socket |

---

## Admin API

The Admin API always binds to a separate listener (`127.0.0.1:9090` by default), isolated from the public proxy data plane.

| Endpoint | Description |
| --- | --- |
| `GET /health` | Liveness/readiness status, snapshot version, digest, and route/upstream counts |
| `GET /metrics` | Prometheus exposition metrics (HTTP gateway, upstream health, mirroring, OTLP, `shunt-ai`, and `shunt-mcp`) |
| `GET /snapshot` | Active compiled routes, upstreams, and per-plugin `HookMask`s (secrets redacted) |
| `GET /upstreams` | Live upstream pool endpoint weights, active probe status, and passive health |
| `GET /api/status` | Snapshot status and pluggable runtime extensions (`listener` shards/reuseport/backlog, `ai` usage/cooldowns/latency/cache, `mcp` catalog/sessions/guardrails) |
| `GET /` & `GET /ui` | Opt-in read-only Admin Inspector Web UI (`--ui` or `[admin] ui = true`, zero DB) |
| `GET /api/traces` & `/api/traces/stream` | Opt-in bounded trace ring buffer & live SSE trace waterfall stream (`--ui` or `[admin] ui = true`) |
| `POST /reload` | Synchronously revalidate and atomically swap the configuration snapshot |

---

## CLI Commands

| Command | Description |
| --- | --- |
| `shunt check [-c FILE \| --k8s-manifest PATH]` | Validate config or Kubernetes Gateway API manifests, compile snapshot, and print routes + `HookMask`s |
| `shunt verify [-c FILE \| --k8s-manifest PATH] [--policy FILE] [--strict] [--format json]` | Static IR, route-shadowing, plugin-chain, and declarative policy verification |
| `shunt test -s SPEC.toml [-c FILE] [--filter STR]` | Execute declarative TOML conformance tests against in-process mock upstreams |
| `shunt dev [-c FILE \| --k8s-manifest PATH] [--ui]` | Development mode with file-watch hot reloads, stderr per-hook µs waterfalls, and optional Inspector UI |
| `shunt run [-c FILE \| --k8s-manifest PATH \| --k8s-gateway] [--no-watch] [--ui]` | Production mode with atomic reloads (file watch, `POST /reload`, `SIGHUP`, or live K8s API sync) and graceful draining |

---

## Example Configurations

| File | Demonstrates |
| --- | --- |
| [`examples/shunt.toml`](../examples/shunt.toml) | Minimal HTTP reverse proxy with `request-id`, `rate-limit`, and `metrics` |
| [`examples/shunt-api-gateway.toml`](../examples/shunt-api-gateway.toml) | Modern HTTP API gateway (`jwt-auth`, `ip-filter`, `body-limit`, `compression`, `redirect`) |
| [`examples/shunt-route-groups.toml`](../examples/shunt-route-groups.toml) | Reusable `[[route_groups]]` with inherited match/timeout defaults, shared `jwt-auth`/`rate-limit` instances, and `match_group` policies |
| [`examples/shunt-path-templates-and-regex.toml`](../examples/shunt-path-templates-and-regex.toml) | Parameterized `path_template` (`/orders/{order_id}/status`, `/files/{*filepath}`), linear-time `path_regex`, route-group lowering, and `{param}` `header-rewrite` interpolation |
| [`examples/k8s-gateway-api.yaml`](../examples/k8s-gateway-api.yaml) | Kubernetes Gateway API v1 (`GatewayClass`, `Gateway`, `HTTPRoute`) |
| [`examples/shunt-inspector-ui.toml`](../examples/shunt-inspector-ui.toml) | Opt-in Admin Inspector Web UI and live trace waterfall (`--ui`) |
| [`examples/shunt-ai.toml`](../examples/shunt-ai.toml) | Core AI gateway with model aliases, failover, SSE translation, and token accounting |
| [`examples/shunt-ai-multi-provider.toml`](../examples/shunt-ai-multi-provider.toml) | Multi-protocol ingress (`/v1/chat/completions`, `/v1/messages`, `/v1/responses`, `/v1/embeddings`) across OpenAI, Anthropic, Azure, Gemini, and Bedrock |
| [`examples/shunt-ai-governance.toml`](../examples/shunt-ai-governance.toml) | Virtual API keys, team/model ACLs, RPM/TPM rate limits, and nano-USD spend budgets |
| [`examples/shunt-ai-smart-routing.toml`](../examples/shunt-ai-smart-routing.toml) | Weighted canary splits, EWMA latency & cost routing, capability guards, and active health probes |
| [`examples/shunt-ai-observability-cache.toml`](../examples/shunt-ai-observability-cache.toml) | Zero-dependency OTLP/HTTP GenAI tracing and exact-match AI response caching |
| [`examples/shunt-ai-presets-and-parity.toml`](../examples/shunt-ai-presets-and-parity.toml) | Provider presets, multi-key pools, reasoning translation, and `drop_params` |
| [`examples/shunt-ai-cloud-iam.toml`](../examples/shunt-ai-cloud-iam.toml) | Auto-refreshing AWS Bedrock, GCP Vertex AI, and Azure AD Cloud IAM authentication |
| [`examples/shunt-ai-guardrails-audit-alerts.toml`](../examples/shunt-ai-guardrails-audit-alerts.toml) | Inline/external AI guardrails (`ai-guardrails`), redacted audit sinks (`ai-audit`), and Slack/PagerDuty alerts (`ai-alerts`) |
| [`examples/shunt-ai-multimodal-cache.toml`](../examples/shunt-ai-multimodal-cache.toml) | Multimodal endpoints, realtime WebSockets, generation lookup, and streaming/singleflight/semantic caching |
| [`examples/shunt-ai-advanced-routing.toml`](../examples/shunt-ai-advanced-routing.toml) | Per-request routing preferences, concurrency quotas, shadow mirroring, and context-overflow failover |
| [`examples/shunt-mcp-gateway.toml`](../examples/shunt-mcp-gateway.toml) | Virtual Streamable HTTP MCP multiplexer with auth, per-agent tool ACLs, guardrails, loop breaking, and telemetry |
