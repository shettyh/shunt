# RFC 0019: `shunt-mcp` — Model Context Protocol (MCP) & Agentic Governance Plugin Pack

- **Status:** Implemented
- **Crates:** `shunt-mcp`, `shunt-config`, `shunt-cli`, `shunt-test`, `specs/`, `examples/`, `fuzz/`

## 1. Summary

This RFC introduces **`shunt-mcp`**, a complete Model Context Protocol (MCP) Streamable HTTP router, multi-server virtual multiplexer, and agentic security/governance plugin pack built **100% strictly on `shunt-plugin-sdk`** with **zero dependencies on `shunt-core` or `shunt-ai`**.

It adds five composable plugins:

1. **`mcp-auth`**: Constant-time SHA-256 virtual API keys or upstream identity-header integration (`jwt-auth`, `mtls-auth`, `bearer-auth`), RFC 9728 `/.well-known/oauth-protected-resource` discovery metadata + `WWW-Authenticate` challenges, per-agent server/tool/resource/prompt/method ACLs, and `Mcp-Session-Id` principal binding to prevent cross-tenant session hijacking.
2. **`mcp-router`**: Spec-compliant MCP Streamable HTTP JSON-RPC 2.0 handler supporting both **single-server passthrough governance** and **multi-server virtual MCP multiplexing** (`initialize` session minting, concurrent `HttpClient`-backed `tools/list` / `resources/list` / `resources/templates/list` / `prompts/list` fan-out with TTL caching and ACL tool-hiding, `<server>__<tool>` namespacing and stripping, `Mcp-Name` header mirroring, optional lazy stateful upstream `initialize` handshakes, `resources/read` prefix routing, `prompts/get` routing, `GET` SSE streams, and `DELETE` session teardown).
3. **`mcp-guardrails`**: Global tool allow/deny policies, high-risk tool approval gating (`x-shunt-approved: true` or `params._meta.approved: true`), per-tool JSON argument validation rules (`required_args`, `forbidden_args`, `allow_patterns`, `deny_patterns`, `max_arg_bytes`), built-in PII/secret scanning & in-place redaction on outbound arguments, **indirect prompt-injection** & secret scanning on inbound tool outputs (both JSON via `Flow::InspectResponseBody` and SSE via `on_response_body_chunk`), and optional async external policy webhooks (OPA / custom HTTP).
4. **`mcp-rate-limit`**: Per-principal RPM & `tools/call` RPM, per-tool rate limits, per-session hard tool-call budgets (`max_calls_per_session`), an identical-call **agent loop breaker** hashing `(scope, tool, canonical_arguments)`, and RAII in-flight concurrency caps (`max_parallel_calls`) backed by bounded reload-persistent `StateStore` (sync zero-alloc fast path) or Redis/Valkey `DistributedStore`.
5. **`mcp-telemetry`**: Prometheus exposition metrics (`shunt_mcp_*`), OTLP span & Admin Inspector `TraceAnnotations` enrichment (`mcp.*` attributes), structured audit logs with SHA-256 argument fingerprints, and `GET /api/status` (`"mcp"`) runtime introspection.

## 2. Motivation

While LLM inference gateways (`shunt-ai`, RFCs 0004–0017) standardize model routing and token spend, autonomous coding and enterprise agents introduce a distinct, higher-risk network boundary: **MCP tool execution**.

Production teams adopting MCP face five recurring operational and security gaps:
- **Tool sprawl & credential leakage:** Agents need access to multiple internal/external MCP servers (GitHub, Postgres, Slack, Jira) without holding raw server credentials or managing N separate connections.
- **Over-privileged tool discovery:** Exposing destructive tools (`delete_repo`, `drop_table`) in `tools/list` leaks capabilities and tempts models into unsafe calls.
- **Unvalidated arguments & indirect prompt injection:** Agents can emit SQL writes, path traversals, SSRF targets, or secrets in tool arguments—and poisoned tool outputs (e.g., malicious GitHub issues or web pages) can inject instructions back into the agent's context window.
- **Runaway agent loops:** A confused agent repeatedly calling the same tool with identical arguments can exhaust quotas or mutate production systems in seconds.
- **Ungoverned CI deployments:** Teams lack a way to statically verify (`shunt verify`) and deterministically CI-test (`shunt test`) their MCP security and routing policies before rollout.

Building `shunt-mcp` strictly on `shunt-plugin-sdk` lets teams govern **HTTP APIs, LLM inference, and MCP agent tool traffic in one ~14 MiB Rust binary** with zero database required and full GitOps/CI testability.

## 3. Goals & Non-Goals

### Goals
- **Zero MCP leakage in `shunt-core` or `shunt-plugin-sdk`:** Reuse existing general-purpose primitives (`HttpPlugin`, `HookMask`, `Flow::InspectResponseBody`, `HttpClient`, `StateStore`, `DistributedStore`, `Clock`, `SpanValue`).
- **Pay only for what you use:** Non-MCP routes pay zero cost. Warm `tools/list` catalogs, local rate limits, loop checks, and auth run synchronously (`HookResult::Ready`).
- **Least-privilege tool disclosure:** `tools/list`, `resources/list`, and `prompts/list` filter items against `McpPrincipal` ACLs *before* returning results to the agent.
- **Defense in depth for tool I/O:** Validate structured JSON arguments before execution, redact outbound secrets in place, gate destructive tools behind explicit approval, and block/redact indirect prompt injections in inbound tool outputs (JSON & SSE).
- **Bounded memory under adversarial traffic:** Session tables, session-binding tables, catalog caches, and rate-limit buckets enforce explicit capacities and TTL pruning.
- **Full verification bar:** Static `shunt verify` rules (`mcp.plugin_order`, `mcp.unknown_upstream`, `mcp.auth_recommended`), deterministic `shunt test` conformance spec, property tests, and a libFuzzer target (`fuzz_mcp_jsonrpc`).

### Non-Goals
- **`stdio` subprocess spawning:** Shunt is a network HTTP/TLS data plane; local `stdio` MCP servers can be fronted by a lightweight stdio-to-HTTP bridge if needed, keeping process-spawning attack surface out of the gateway binary.
- **Agent orchestration / LLM loop execution:** Shunt governs and routes agent-to-tool traffic; it does not execute agent planning loops internally.

## 4. Design

### 4.1 Recommended Plugin Pipeline Ordering

```text
  Incoming MCP Streamable HTTP (POST / GET / DELETE / .well-known)
       │
       ├─ 1. mcp-auth         [on_request_headers]   Virtual key or JWT/mTLS identity, OAuth discovery, session-to-principal binding
       ├─ 2. mcp-router       [on_request_headers,   Parse JSON-RPC 2.0, enforce ACLs, handle initialize/ping/tools/list locally,
       │                       on_request_body_buf,  select backend upstream, rewrite params.name & inject upstream auth/session]
       │                       on_route/select/req]
       ├─ 3. mcp-guardrails   [on_request_body_buf,  Tool policies, approval gate, JSON arg rules, PII/secret redaction, OPA webhook,
       │                       on_response_headers,  inbound JSON & SSE indirect prompt-injection / secret scanning]
       │                       inspected / chunk]
       ├─ 4. mcp-rate-limit   [on_request_body_buf,  Principal RPM, tool RPM, per-tool limits, per-session cap, identical-call loop
       │                       on_complete]          breaker (SHA-256 canonical args), RAII max_parallel_calls guard
       └─ 5. mcp-telemetry    [on_response_headers,  shunt_mcp_* Prometheus metrics, OTLP mcp.* span attrs, JSON/SSE tool-error
                               chunk, on_complete]   detection, structured SHA-256 audit log, /api/status("mcp")
```

### 4.2 Dual-Mode `mcp-router`

- **Single-Server Passthrough Mode (`servers` omitted):** Parses JSON-RPC 2.0 on `POST`, attaches `McpRequestMeta`, enforces `McpPrincipal` ACLs, injects optional `upstream_auth` / `upstream_path` / `Mcp-Name`, and passes `GET` SSE and `DELETE` transparently.
- **Multi-Server Virtual Multiplexer Mode (`servers.<name>` configured):**
  - `initialize`: Negotiates `protocolVersion` (`2025-11-25`, `2025-06-18`, `2025-03-26`, `2024-11-05`), mints a virtual `Mcp-Session-Id` bound to the calling principal in `McpSessionTable`, and advertises aggregated capabilities.
  - `tools/list`, `resources/list`, `resources/templates/list`, `prompts/list`: Concurrently fans out via `BuildContext::http_client()` (`tokio::task::JoinSet`) across enabled, ACL-permitted servers, caches raw catalogs in `McpCatalogTable` (with configurable TTL; warm hits execute synchronously in `HookResult::Ready`), namespaces tool/prompt names as `<server><sep><name>` (`__` default), and filters out unauthorized items per principal.
  - `tools/call` & `prompts/get`: Splits `<server><sep><name>`, verifies server & item ACLs, routes via `on_route`/`on_upstream_select`, rewrites `params.name` to the raw backend name in `on_upstream_request` (preserving any prior `mcp-guardrails` argument redactions), injects server auth, and—when `stateful = true`—lazily performs an upstream `initialize` + `notifications/initialized` handshake and caches the backend `Mcp-Session-Id`.
  - `resources/read`: Routes via longest-matching `resource_prefixes` (or `<server>://` URI scheme).
  - `DELETE`: Verifies session owner principal and evicts the gateway session from `McpSessionTable`.

### 4.3 Security & Agent-Loop Invariants

1. **Session hijacking prevention:** Both `mcp-auth` (`McpSessionBindingTable`) and `mcp-router` (`McpSessionTable.owner_principal`) reject any request presenting an `Mcp-Session-Id` owned by a different principal with HTTP `403` / JSON-RPC `-32003`.
2. **Secret redaction by construction:** All secret config fields are named `api_key`, so `shunt-config`'s `GET /snapshot` redactor strips them automatically without MCP-specific redaction code.
3. **Approval header stripping:** `mcp-router` unconditionally strips `x-shunt-approved` before forwarding upstream so internal approval flags cannot leak or be echoed.
4. **Deterministic loop breaking:** `mcp-rate-limit` canonicalizes JSON argument keys (`canonical_json_bytes`) before SHA-256 hashing so semantically identical arguments with reordered JSON keys still trip the loop breaker reliably.
5. **Leak-free concurrency limits:** `max_parallel_calls` uses an RAII drop guard stored in `RequestCtx::extensions`, guaranteeing decrement on normal completion, short-circuit, stream abort, or panic.

### 4.4 Static Verification (`shunt verify`)

Added to `shunt-config::verify`:
- `mcp.plugin_order` (Error): `mcp-auth` must precede `mcp-router`; `mcp-guardrails` and `mcp-rate-limit` must follow `mcp-router`.
- `mcp.unknown_upstream` (Error): every `servers.<name>.upstream` must exist in `[[upstreams]]`.
- `mcp.auth_recommended` (Info): informs operators when an `mcp-router` route has no authentication plugin attached.

## 5. Alternatives Considered & Rejected

1. **Adding MCP-specific hooks or JSON-RPC framing to `shunt-core`:** Rejected—violates Shunt's zero-AI/zero-protocol-leakage guardrail in `shunt-core`. Every transport need (buffered POST inspection, `HttpClient` fan-out, `Flow::InspectResponseBody`, SSE chunk hooks, `StateStore`, `DistributedStore`) already existed as general-purpose primitives in `shunt-plugin-sdk`.
2. **Bundling `shunt-mcp` inside `shunt-ai`:** Rejected—teams may deploy an MCP governance gateway independently of LLM inference proxying (or embed `shunt-mcp` without pulling in LLM dialect translators). Keeping `shunt-mcp` as its own pure-SDK crate preserves clean modularity.
3. **Allowing JSON-RPC batch arrays by default:** Rejected—batching multiple `tools/call` invocations in a single HTTP request complicates per-tool routing, approval gating, and loop breaking across heterogeneous upstream servers. Batch parsing is supported in `parse_mcp_jsonrpc_request` for single-server mode (`allow_batch = true`), while defaulting safely to `false`.

## 6. Future Work

- **Ergonomic `[mcp]` / `[ai]` config sugar in `shunt-config`:** Compile concise top-level TOML blocks into the canonical pure-plugin IR chains to reduce onboarding boilerplate while keeping `shunt-core` unchanged.
- **MCP OAuth token exchange / per-server downstream token delegation:** Exchange agent JWTs for scoped downstream OAuth tokens per backend MCP server via `HttpClient`.
- **Cross-tool agent cost attribution:** Correlate `x-shunt-session-id` / `Mcp-Session-Id` spans across both `shunt-ai` LLM calls and `shunt-mcp` tool calls via W3C `traceparent`.
