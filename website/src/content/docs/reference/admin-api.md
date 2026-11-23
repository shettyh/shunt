---
title: Admin API (:9090)
description: Reference for Shunt's isolated Admin listener endpoints (/health, /metrics, /snapshot, /upstreams, /api/status, /ui, /api/traces, /reload).
---

The Admin API always binds to its own listener (`127.0.0.1:9090` by default under `[admin]`), strictly isolated from the public proxy listener (`[server]`).

## Endpoints

| Method & Path | Description |
| --- | --- |
| `GET /health` | Liveness/readiness JSON with active snapshot `version`, `digest`, and route/upstream counts |
| `GET /metrics` | Prometheus text exposition covering HTTP gateway, upstream health, mirroring, OTLP exporter, `shunt-ai`, and `shunt-mcp` |
| `GET /snapshot` | Active compiled `route_groups`, routes (with `group` membership and `group:`/`route:` plugin scopes), upstreams, and per-plugin `HookMask` bitmasks (all secrets and private keys redacted) |
| `GET /upstreams` | Live upstream pool endpoint weights, active HTTP/TCP probe status, and passive circuit health |
| `GET /api/status` | Combined snapshot summary plus pluggable runtime status (`"ai"` usage/cooldowns/latency/cache and `"mcp"` catalog/sessions/guardrails) |
| `POST /reload` | Synchronously re-read, validate, compile, and atomically swap the configuration snapshot via `ArcSwap` |
| `GET /` & `GET /ui` | Opt-in read-only Admin Inspector Web UI (enabled via `--ui` or `[admin] ui = true`) |
| `GET /api/traces` | Opt-in JSON snapshot of the bounded in-memory request trace ring buffer (`--ui`) |
| `GET /api/traces/stream` | Opt-in Server-Sent Events (SSE) live stream of per-hook microsecond trace waterfalls (`--ui`) |

## Common Operations

### Check Gateway Health & Active Snapshot

```bash
curl -s http://127.0.0.1:9090/health | jq
curl -s http://127.0.0.1:9090/snapshot | jq
```

**Sample `GET /snapshot` response (abbreviated):**

```json
{
  "version": 1,
  "digest": "fd1970ac5990",
  "source": "examples/shunt-route-groups.toml",
  "state_backend": "memory",
  "telemetry_backend": "disabled",
  "global_plugins": [
    { "name": "request-id", "scope_id": "global:request-id:0", "hook_mask": "on_request_headers | on_response_headers", "config": {} }
  ],
  "route_groups": [
    {
      "id": "billing_api",
      "hosts": ["api.example.com"],
      "path_prefix": "/billing",
      "methods": [],
      "upstream": "billing_svc",
      "plugins": [
        { "name": "jwt-auth", "scope_id": "group:billing_api:billing-jwt", "hook_mask": "on_request_headers", "config": { "issuer": "https://auth.example.com", "keys": [{ "kid": "demo-hs1", "secret": "<redacted>" }] } },
        { "name": "rate-limit", "scope_id": "group:billing_api:billing-shared-rl", "hook_mask": "on_request_headers", "config": { "requests_per_second": 50.0, "burst": 100 } }
      ],
      "routes": ["billing_invoices", "billing_subscriptions"]
    }
  ],
  "routes": [
    {
      "id": "billing_invoices",
      "group": "billing_api",
      "hosts": ["api.example.com"],
      "path": "/billing/invoices*",
      "methods": ["GET", "POST"],
      "upstream": "billing_svc",
      "max_attempts": 1,
      "max_body_bytes": 1048576,
      "plugins": ["request-id", "metrics", "jwt-auth", "rate-limit"],
      "plugin_details": [
        { "name": "jwt-auth", "scope_id": "group:billing_api:billing-jwt" },
        { "name": "rate-limit", "scope_id": "group:billing_api:billing-shared-rl" }
      ]
    }
  ]
}
```

### Trigger a Zero-Downtime Reload

```bash
curl -X POST http://127.0.0.1:9090/reload
```

If the updated `shunt.toml` has any syntax, schema, or missing `env:` error, `POST /reload` returns an HTTP error with diagnostics while the previously active snapshot keeps serving uninterrupted.

### Inspect Upstream Health & AI/MCP Runtime Status

```bash
curl -s http://127.0.0.1:9090/upstreams | jq
curl -s http://127.0.0.1:9090/api/status | jq
```

**Sample `GET /upstreams` response:**

```json
{
  "version": 1,
  "upstreams": [
    {
      "name": "orders_pool",
      "pool_id": 1,
      "active_health_check": true,
      "endpoints": [
        {
          "url": "http://10.0.1.10:8080",
          "weight": 90,
          "healthy": true,
          "active_healthy": true,
          "passive_healthy": true,
          "passive_failures": 0,
          "active_probes_ok": 42,
          "active_probes_err": 0,
          "last_probe_latency_us": 815
        }
      ]
    }
  ]
}
```
