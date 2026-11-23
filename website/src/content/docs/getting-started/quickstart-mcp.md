---
title: "Quickstart: MCP Gateway"
description: Multiplex multiple Streamable HTTP MCP servers behind one governed endpoint with per-agent ACLs, SQL/argument guardrails, and loop breaking.
---

Shunt's `shunt-mcp` plugin pack exposes a single **virtual Streamable HTTP MCP endpoint** (`/mcp`) in front of multiple backend MCP servers. It enforces least-privilege tool visibility, blocks destructive arguments and indirect prompt injections, and stops stuck AI agents from burning infinite tool-call loops.

## 1. Create `shunt-mcp.toml`

```toml
[server]
listen = "127.0.0.1:8080"
drain_timeout_ms = 15000

[admin]
enabled = true
listen = "127.0.0.1:9090"

[[plugins]]
name = "request-id"

[[plugins]]
name = "metrics"

[[upstreams]]
name = "github_mcp"
endpoints = ["http://127.0.0.1:18081"]
connect_timeout_ms = 5000

[[upstreams]]
name = "postgres_mcp"
endpoints = ["http://127.0.0.1:18082"]
connect_timeout_ms = 5000

[[routes]]
id = "mcp_virtual_gateway"
path_prefix = "/"
methods = ["GET", "POST", "DELETE"]
upstream = "github_mcp"
max_body_bytes = 2097152
response_headers_timeout_ms = 30000
idle_chunk_timeout_ms = 60000

# 1. Authenticate agents & attach least-privilege tool/resource ACLs
[[routes.plugins]]
name = "mcp-auth"
id = "mcp-auth"
[routes.plugins.config]
strip_key_header = true
bind_session_to_principal = true

[[routes.plugins.config.keys]]
id = "eng-alice"
api_key = "env:MCP_ALICE_KEY"
team = "platform"
agent_id = "claude-code"
allowed_servers = ["github", "postgres"]
allowed_tools = ["github__*", "postgres__*"]
denied_tools = ["*delete*", "*drop*"]
rpm = 60
tool_rpm = 30
max_calls_per_session = 25
max_parallel_calls = 4

# 2. Virtual MCP multiplexer aggregating `github` + `postgres`
[[routes.plugins]]
name = "mcp-router"
id = "mcp-router"
[routes.plugins.config]
namespace_separator = "__"
server_name = "shunt-mcp-gateway"
catalog_ttl_secs = 60
session_ttl_secs = 3600
response_headers = true

[routes.plugins.config.servers.github]
upstream = "github_mcp"
endpoint = "http://127.0.0.1:18081/mcp"
path = "/mcp"
auth = { type = "bearer", api_key = "env:GITHUB_MCP_TOKEN" }

[routes.plugins.config.servers.postgres]
upstream = "postgres_mcp"
endpoint = "http://127.0.0.1:18082/mcp"
path = "/mcp"
auth = { type = "header", header = "x-api-key", api_key = "env:POSTGRES_MCP_TOKEN" }

# 3. Tool policies, approval gates, argument rules & prompt-injection defense
[[routes.plugins]]
name = "mcp-guardrails"
id = "mcp-guardrails"
[routes.plugins.config]
require_approval_tools = ["github__create_issue"]
argument_detectors = ["aws_key", "private_key"]
argument_action = "redact"
response_detectors = ["prompt_injection", "private_key"]
response_action = "block"

[[routes.plugins.config.argument_rules]]
tool = "postgres__query"
required_args = ["sql"]
allow_patterns = { sql = "(?i)^\\s*SELECT\\b" }
deny_patterns = { sql = "(?i)\\b(DROP|DELETE|UPDATE|INSERT|ALTER|TRUNCATE)\\b" }

# 4. Agent loop breaker, session call caps & per-tool quotas
[[routes.plugins]]
name = "mcp-rate-limit"
id = "mcp-rate-limit"
[routes.plugins.config]
rpm = 120
tool_rpm = 60
max_calls_per_session = 50
max_parallel_calls = 8

[routes.plugins.config.loop_breaker]
max_repeats = 2
window_secs = 60

# 5. Prometheus metrics, OTLP `mcp.*` span attributes & audit logs
[[routes.plugins]]
name = "mcp-telemetry"
id = "mcp-telemetry"
[routes.plugins.config]
log_calls = true
inspect_tool_errors = true
```

## 2. Verify & Run

```bash
export MCP_ALICE_KEY="sk-mcp-alice"
export GITHUB_MCP_TOKEN="ghp_..."
export POSTGRES_MCP_TOKEN="pg_..."

shunt verify -c shunt-mcp.toml
shunt dev --ui -c shunt-mcp.toml
```

## 3. Call the Virtual MCP Endpoint

### Initialize a Session

```bash
curl -i http://127.0.0.1:8080/mcp \
  -H "Authorization: Bearer $MCP_ALICE_KEY" \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"demo","version":"1.0"}}}'
```

Save the returned `Mcp-Session-Id` header—because `bind_session_to_principal = true`, Shunt rejects any attempt by a different principal to reuse that session ID.

### List ACL-Filtered Tools Across All Servers

```bash
curl http://127.0.0.1:8080/mcp \
  -H "Authorization: Bearer $MCP_ALICE_KEY" \
  -H "Mcp-Session-Id: <session-id>" \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":2,"method":"tools/list"}'
```

Shunt fans out to `github` and `postgres` concurrently, namespaces tools as `github__<tool>` and `postgres__<tool>`, caches the catalog, and strips any tools disallowed by the caller's ACL before returning the list.

## Next Steps

- Explore all features in [Virtual MCP & Agent Governance](/shunt/mcp-gateway/overview/)
- Review every config option in [MCP Plugins Reference](/shunt/plugins/mcp-plugins/)
