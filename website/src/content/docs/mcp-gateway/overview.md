---
title: Virtual MCP & Agent Governance
description: Multiplex multiple Streamable HTTP MCP servers with per-agent ACLs, session hijacking protection, argument policies, approval gates, indirect prompt-injection defense, and loop breaking.
---

`shunt-mcp` turns Shunt into a single governed **Streamable HTTP MCP** (Model Context Protocol) gateway—protecting internal tools and databases from compromised prompts, over-privileged agents, and runaway tool-call loops.

## Why an MCP Gateway?

When AI coding agents connect directly to raw MCP servers (GitHub, Postgres, Slack, Jira):
- Every agent sees every destructive tool (`drop_table`, `delete_repo`) in `tools/list`.
- Upstream credentials are scattered across developer laptops.
- Malicious tool outputs (e.g., an untrusted GitHub issue or web page) can inject hidden instructions (**indirect prompt injection**).
- Stuck agents repeatedly invoke the same failing tool dozens of times.

`shunt-mcp` solves all of these at **77.1k req/s** (`1.17 ms` p99) with a 5-plugin chain built strictly on `shunt-plugin-sdk`.

## Canonical MCP Plugin Chain

```text
1. mcp-auth        Authenticate virtual keys / JWT / mTLS, serve RFC 9728 OAuth metadata, bind Mcp-Session-Id
2. mcp-router      Multiplex backend MCP servers, cache & ACL-filter tools/list, route <server>__<tool>
3. mcp-guardrails  Enforce tool allow/deny, approval gates, JSON arg rules, PII redaction, prompt-injection scan, OPA
4. mcp-rate-limit  Enforce per-principal RPM, per-tool quotas, session call caps, concurrency & loop breaker
5. mcp-telemetry   Emit shunt_mcp_* Prometheus metrics, OTLP mcp.* spans & SHA-256 audit logs
```

## Key Capabilities

### 1. Virtual Multiplexing & ACL-Filtered Discovery (`mcp-router`)
- Serves a single `/mcp` endpoint in front of any number of backend Streamable HTTP MCP servers.
- Handles `initialize` locally and fans out `tools/list`, `resources/list`, and `prompts/list` concurrently across backends with TTL caching (`catalog_ttl_secs`).
- Namespaces tools automatically (`github__create_issue`, `postgres__query`) and **hides unauthorized tools** based on the caller's ACL before returning the list.
- Supports `mirror_mcp_name_header = true` and stateful upstream MCP handshakes (`stateful = true`).

### 2. Identity, OAuth Discovery & Session Binding (`mcp-auth`)
- Supports constant-time SHA-256 virtual keys or forwarded identity from `jwt-auth` / `mtls-auth`.
- Serves **RFC 9728** `/.well-known/oauth-protected-resource` discovery JSON directly.
- Binds `Mcp-Session-Id` to the originating principal (`bind_session_to_principal = true`) to prevent cross-agent session hijacking.

### 3. Argument Rules, Approval Gates & Indirect Prompt-Injection Defense (`mcp-guardrails`)
- **Per-tool JSON argument validation:** Require fields, enforce byte limits, and match `allow_patterns` / `deny_patterns` (e.g., force read-only `SELECT` queries on `postgres__query` and block path traversal `../`).
- **Human-in-the-loop approval gates:** Require `x-shunt-approved: true` or `params._meta.approved = true` for sensitive tools (`require_approval_tools`).
- **Outbound secret redaction:** Scrub AWS keys, private keys, and PII from tool arguments before they leave your boundary.
- **Inbound indirect prompt-injection scanning:** Inspect JSON and **SSE** tool responses for prompt-injection payloads or leaked secrets and block with JSON-RPC error `-32005`.
- **External OPA / HTTP policy webhooks:** Call out to Open Policy Agent for dynamic authorization decisions.

### 4. Stuck-Agent Loop Breaker & Quotas (`mcp-rate-limit`)
- Detects identical repeated tool calls within `window_secs` (`max_repeats`) and short-circuits with `429` at **160k req/s**.
- Enforces per-principal RPM, `tools/call` RPM, per-tool quotas (`tool_limits`), per-session call caps (`max_calls_per_session`), and RAII `max_parallel_calls` concurrency limits locally or across Redis/Valkey.

See [Quickstart: MCP Gateway](/shunt/getting-started/quickstart-mcp/) and [MCP Plugins Reference](/shunt/plugins/mcp-plugins/) for full configuration details.
