---
title: MCP Plugins (shunt-mcp)
description: Complete configuration reference for all 5 MCP and agentic governance plugins in shunt-mcp.
---

All 5 plugins in `shunt-mcp` run strictly on top of `shunt-plugin-sdk` and compose together on a Streamable HTTP MCP route.

## Plugin Summary

| Plugin | Purpose |
| --- | --- |
| `mcp-auth` | Virtual keys / forwarded JWT & mTLS identity, RFC 9728 OAuth metadata, per-agent server/tool/resource/prompt ACLs, `Mcp-Session-Id` principal binding |
| `mcp-router` | Streamable HTTP JSON-RPC 2.0 router & multi-server virtual multiplexer (`initialize`, cached ACL-filtered `tools/list`, `<server>__<tool>` routing) |
| `mcp-guardrails` | Tool allow/deny policies, approval gates, per-tool JSON argument regex/schema rules, outbound secret redaction, inbound prompt-injection defense (JSON + SSE), OPA webhooks |
| `mcp-rate-limit` | Per-principal RPM & `tools/call` RPM, per-tool quotas, per-session call caps, identical-call loop breaker, and RAII `max_parallel_calls` |
| `mcp-telemetry` | `shunt_mcp_*` Prometheus metrics, OTLP `mcp.*` span enrichment, structured SHA-256 audit logs, and `/api/status` (`"mcp"`) inspection |

---

## Configuration Reference

### `mcp-auth`
```toml
[[routes.plugins]]
name = "mcp-auth"
id = "mcp-auth"
[routes.plugins.config]
strip_key_header = true
bind_session_to_principal = true

[routes.plugins.config.oauth_protected_resource]
path = "/.well-known/oauth-protected-resource"
resource = "https://mcp.example.com"
authorization_servers = ["https://auth.example.com"]
scopes_supported = ["mcp:tools:read", "mcp:tools:write"]

[[routes.plugins.config.keys]]
id = "eng-alice"
api_key = "env:MCP_ALICE_KEY"
team = "platform"
agent_id = "claude-code"
allowed_servers = ["github", "postgres"]
allowed_tools = ["github__*", "postgres__*"]
denied_tools = ["*delete*", "*drop*"]
allowed_resources = ["github://*", "postgres://*"]
allowed_prompts = ["github__*"]
rpm = 60
tool_rpm = 30
max_calls_per_session = 25
max_parallel_calls = 4
```

### `mcp-router`
```toml
[[routes.plugins]]
name = "mcp-router"
id = "mcp-router"
[routes.plugins.config]
max_body_bytes = 2097152
namespace_separator = "__"
server_name = "shunt-mcp-gateway"
catalog_ttl_secs = 60
session_ttl_secs = 3600
response_headers = true
mirror_mcp_name_header = true

[routes.plugins.config.servers.github]
upstream = "github_mcp"
endpoint = "http://127.0.0.1:18081/mcp"
path = "/mcp"
auth = { type = "bearer", api_key = "env:GITHUB_MCP_TOKEN" }
resource_prefixes = ["github://"]
stateful = false
```

### `mcp-guardrails`
```toml
[[routes.plugins]]
name = "mcp-guardrails"
id = "mcp-guardrails"
[routes.plugins.config]
denied_tools = ["*drop_database*"]
require_approval_tools = ["github__create_issue"]
argument_detectors = ["aws_key", "private_key"]
argument_action = "redact"
response_detectors = ["prompt_injection", "private_key"]
response_action = "block"

[[routes.plugins.config.argument_rules]]
tool = "postgres__query"
max_arg_bytes = 4096
required_args = ["sql"]
allow_patterns = { sql = "(?i)^\\s*SELECT\\b" }
deny_patterns = { sql = "(?i)\\b(DROP|DELETE|UPDATE|INSERT|ALTER|TRUNCATE)\\b" }

[[routes.plugins.config.argument_rules]]
tool = "github__*"
deny_patterns = { path = "\\.\\.[/\\\\]" }
```

### `mcp-rate-limit`
```toml
[[routes.plugins]]
name = "mcp-rate-limit"
id = "mcp-rate-limit"
[routes.plugins.config]
rpm = 120
tool_rpm = 60
window_secs = 60
max_calls_per_session = 50
max_parallel_calls = 8

[routes.plugins.config.tool_limits."github__create_issue"]
rpm = 5
window_secs = 60

[routes.plugins.config.loop_breaker]
max_repeats = 2
window_secs = 60
```

### `mcp-telemetry`
```toml
[[routes.plugins]]
name = "mcp-telemetry"
id = "mcp-telemetry"
[routes.plugins.config]
log_calls = true
inspect_tool_errors = true
```
