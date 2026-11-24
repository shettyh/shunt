---
title: Production & Troubleshooting
description: Multi-replica Redis state, zero-downtime reloads, TLS rotation, security hardening checklist, and common troubleshooting answers for running Shunt in production.
---

Shunt ships as a single zero-dependency binary out of the box, and scales cleanly to multi-replica production deployments when you opt into shared Redis state, isolated admin ports, and CI verification.

## 1. Multi-Replica Deployments (`[state] backend = "redis"`)

By default, `[state]` uses the zero-dependency in-process `StateStore` (`backend = "memory"`). When running multiple Shunt replicas behind a load balancer, enable Redis or Valkey so quotas, budgets, caches, and circuit breakers stay synchronized across pods:

```toml
[state]
backend = "redis"
url = "env:SHUNT_REDIS_URL"      # redis:// or rediss://
key_prefix = "shunt:prod:"
pool_size = 16
connect_timeout_ms = 1000
command_timeout_ms = 250
failure_policy = "fail_open"     # or "fail_closed" for strict financial/security limits
```

| Plugin | Shared via Redis (`backend = "redis"`)? | Local Per-Replica Cache / State |
| --- | --- | --- |
| `rate-limit` | **Yes** (shared token buckets) | Fallback on `fail_open` |
| `ai-token-rate-limit` | **Yes** (RPM, TPM, concurrency quotas) | Fallback on `fail_open` |
| `ai-budget` | **Yes** (nano-USD spend windows & holds) | Fallback on `fail_open` |
| `ai-cache` | **Yes** (exact & streaming response cache) | Local singleflight coalescing |
| `ai-failover` | **Yes** (provider circuit cooldowns) | — |
| `mcp-rate-limit` | **Yes** (principal/tool quotas & loop breaker) | — |
| `jwt-auth`, `ai-provider-adapter`, `mcp-router` | No (each replica maintains its own warm JWKS, Cloud IAM token, and MCP tool catalog cache) | Reload-persistent in-memory cache |

:::tip[Always Set Stable Plugin `id`s]
Give every stateful plugin an explicit `id = "..."` (e.g., `id = "api-v2-rl"`). Both in-memory `StateStore` scopes (`group:<group_id>:<id>`, `route:<route_id>:<id>`) and Redis key prefixes derive from this ID so counters survive config reloads and plugin reordering.
:::

---

## 2. Zero-Downtime Reloads & TLS Rotation

`shunt run` supports three reload triggers—all using the exact same atomic `ArcSwap` pipeline:

1. **File watcher (default):** Watches `shunt.toml`/YAML plus every TLS `cert`, `key`, `client_ca`, and `sni` cert path. Pass `--no-watch` to disable automatic watching.
2. **Admin API:** `curl -X POST http://127.0.0.1:9090/reload` (returns HTTP 200 on commit or 4xx/5xx with diagnostics if validation fails).
3. **UNIX signal:** Send `SIGHUP` to the `shunt` PID (ideal for systemd or sidecar reloaders).

**Fail-safe guarantee:** If the new config has a syntax error, missing `env:VAR`, unreadable TLS certificate, or invalid plugin config, Shunt rejects the reload and **keeps serving traffic on the last valid snapshot** with zero dropped connections.

For graceful shutdown on deploy/rollout, send `SIGTERM`—Shunt stops accepting new connections across every listener shard and waits up to `server.drain_timeout_ms` (default `30000`) for in-flight HTTP, SSE, and WebSocket streams to finish cleanly.

For high connection-churn Linux deployments (bursty short-lived HTTP/1.1 or TLS handshakes, SSE/WebSocket reconnect storms, or overlapping VM/systemd binary restarts), enable per-core `SO_REUSEPORT` listener sharding under `[server]`:

```toml
[server]
listen = "0.0.0.0:8080"
reuseport = true         # Binds one SO_REUSEPORT accept shard per CPU core (1..=128)
# accept_shards = 8      # Optional explicit shard count override
backlog = 4096           # Per-shard TCP listen backlog
```

On Linux, each shard gets its own kernel accept queue and Tokio accept loop; on platforms without `SO_REUSEPORT` (such as Windows), Shunt logs a warning and falls back cleanly to a single listener socket. Live listener details are reported under `GET /api/status` (`"listener"`).

---

## 3. Production Security Checklist

- **Isolate the Admin listener (`:9090`):** Keep `[admin] listen = "127.0.0.1:9090"` (or an internal VPC/pod-only interface). Never expose `:9090`—especially `POST /reload` and `/ui`—on a public load balancer.
- **Keep secrets out of Git:** Use `env:VAR_NAME` for API keys, JWT secrets, Redis passwords, webhook signing secrets, and OTLP headers. `shunt check` fails eagerly if any referenced env var is unset.
- **Prevent header spoofing behind proxies:**
  - Set `trusted_proxies = [...]` on `ip-filter` whenever `use_forwarded_for = true`.
  - Keep `strip_header = true` on `bearer-auth`, `jwt-auth`, `ai-virtual-keys`, and `mcp-auth` so client credentials never leak upstream.
- **Gate deployments in CI:** Run both checks before pushing config updates:
  ```bash
  shunt check -c shunt.toml
  shunt verify -c shunt.toml --strict
  ```

---

## 4. Troubleshooting Quick Reference

### Route isn't matching (or wrong route matches)
- Routes are evaluated **top-to-bottom** (first match wins). Place `path_exact` and more specific `path_prefix` rules before broader prefixes like `/`.
- Run `shunt check -c shunt.toml` to inspect the **lowered** paths (e.g., `group.path_prefix = "/v2"` + `route.path_prefix = "/users"` compiles to `/v2/users*`).
- Run `shunt verify -c shunt.toml` to catch shadowed routes automatically.

### Validation error on a grouped route (`hosts`, `methods`, `headers`, or `upstream`)
- **Safe narrowing:** A route in a `[[route_groups]]` cannot widen its group's security boundary. For example, if a group specifies `hosts = ["*.example.com"]` and a route specifies `hosts = ["other.com"]`, validation rejects it.
- **Missing upstream:** Every route needs an effective upstream—either set `upstream = "..."` on the `[[route_groups]]` block (inherited by all member routes) or on each `[[routes]]` entry. Upstreams themselves are always declared at top-level `[[upstreams]]`.

### Unexpected `413 Payload Too Large`
- Check both the route/group `max_body_bytes` and any `body-limit` plugin's `max_bytes`.
- When a route activates `REQUEST_BODY_BUFFERED` (for example via `ai-model-router` or `mcp-router`), Shunt applies a `1 MiB` default buffer limit unless `max_body_bytes` is raised on the route, route group, or plugin. The effective cap is the minimum of all configured limits.

### Why is my HTTP route buffering bodies?
- Run `shunt check -c shunt.toml` and check each route's `HookMask`.
- Pure HTTP plugins (`jwt-auth`, `rate-limit`, `body-limit`, `compression`, `header-rewrite`, `cors`) **never** set `REQUEST_BODY_BUFFERED` or `RESPONSE_BODY_BUFFERED`. If you see those flags on an HTTP route, a plugin that inspects JSON payloads (such as an AI or MCP plugin) is attached to that route or its route group. You can enforce zero-buffering in CI with `forbid_hooks = ["REQUEST_BODY_BUFFERED"]` under `[verify.route_policies]`.

### Reload rejected (`POST /reload` or file watch)
- Check `shunt` stderr logs or the HTTP response body from `POST /reload`. Common causes are an unset `env:VAR` in the process environment, an invalid PEM key/cert pair during rotation, or a typo in a plugin config field. The previously active snapshot continues serving uninterrupted until the issue is fixed.
