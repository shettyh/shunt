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
| `GET /snapshot` | Active compiled routes, upstreams, and per-plugin `HookMask` bitmasks (all secrets and private keys redacted) |
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
