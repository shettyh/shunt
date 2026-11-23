---
title: Configuration (shunt.toml)
description: Complete schema reference for shunt.toml and YAML configuration files including server, TLS/mTLS, admin, state, telemetry, upstreams, route groups, routes, and mirrors.
---

Shunt accepts **TOML** (`.toml`, canonical) or **YAML** (`.yaml` / `.yml`) configuration files, as well as [Kubernetes Gateway API v1](/shunt/api-gateway/kubernetes/) manifests.

## How `shunt.toml` Fits Together

Every Shunt configuration is composed of **four distinct top-level primitives** that compile down into a flat, zero-overhead routing table (`GatewaySnapshot`) before a single request is served:

<div class="shunt-diagram-frame">
<svg viewBox="0 0 760 250" fill="none" xmlns="http://www.w3.org/2000/svg" role="img" aria-label="How upstreams, route groups, routes, and plugins compile into flat routes">
  <rect x="16" y="16" width="166" height="62" rx="8" fill="var(--sl-color-bg)" stroke="var(--sl-color-hairline)" stroke-width="1.3"/>
  <text x="99" y="40" text-anchor="middle" fill="var(--sl-color-white)" font-family="monospace" font-size="11.5" font-weight="700">[[plugins]]</text>
  <text x="99" y="58" text-anchor="middle" fill="var(--sl-color-gray-3)" font-size="10.5">Global (all routes)</text>

  <rect x="200" y="16" width="176" height="62" rx="8" fill="var(--sl-color-bg)" stroke="var(--sl-color-accent)" stroke-width="1.4"/>
  <text x="288" y="40" text-anchor="middle" fill="var(--sl-color-white)" font-family="monospace" font-size="11.5" font-weight="700">[[route_groups]]</text>
  <text x="288" y="58" text-anchor="middle" fill="var(--sl-color-gray-3)" font-size="10.5">Shared defaults &amp; plugins</text>

  <rect x="394" y="16" width="166" height="62" rx="8" fill="var(--sl-color-bg)" stroke="var(--sl-color-hairline)" stroke-width="1.3"/>
  <text x="477" y="40" text-anchor="middle" fill="var(--sl-color-white)" font-family="monospace" font-size="11.5" font-weight="700">[[routes]]</text>
  <text x="477" y="58" text-anchor="middle" fill="var(--sl-color-gray-3)" font-size="10.5">Ordered match table</text>

  <rect x="578" y="16" width="166" height="62" rx="8" fill="var(--sl-color-bg)" stroke="var(--sl-color-hairline)" stroke-width="1.3"/>
  <text x="661" y="40" text-anchor="middle" fill="var(--sl-color-white)" font-family="monospace" font-size="11.5" font-weight="700">[[upstreams]]</text>
  <text x="661" y="58" text-anchor="middle" fill="var(--sl-color-gray-3)" font-size="10.5">Shared backend pools</text>

  <line x1="394" y1="47" x2="376" y2="47" stroke="var(--sl-color-accent)" stroke-width="1.5" stroke-dasharray="3 2"/>
  <line x1="560" y1="47" x2="578" y2="47" stroke="var(--sl-color-gray-4)" stroke-width="1.5" stroke-dasharray="3 2"/>

  <line x1="99" y1="78" x2="99" y2="128" stroke="var(--sl-color-gray-4)" stroke-width="1.4"/>
  <line x1="288" y1="78" x2="288" y2="128" stroke="var(--sl-color-accent)" stroke-width="1.5"/>
  <line x1="477" y1="78" x2="477" y2="128" stroke="var(--sl-color-gray-4)" stroke-width="1.4"/>
  <line x1="661" y1="78" x2="661" y2="128" stroke="var(--sl-color-gray-4)" stroke-width="1.4"/>

  <text x="380" y="112" text-anchor="middle" fill="var(--sl-color-accent)" font-family="monospace" font-size="10.5" font-weight="600">SnapshotCompiler lowers everything at compile time (zero data-plane overhead)</text>

  <rect x="16" y="130" width="728" height="104" rx="10" fill="var(--sl-color-bg)" stroke="var(--sl-color-accent)" stroke-width="1.4" stroke-dasharray="5 3"/>
  <text x="34" y="152" fill="var(--sl-color-accent)" font-family="monospace" font-size="10" font-weight="700">COMPILED SNAPSHOT (FLAT FIRST-MATCH-WINS TABLE)</text>

  <rect x="34" y="164" width="496" height="52" rx="6" fill="var(--sl-color-gray-6)" stroke="var(--sl-color-hairline)"/>
  <text x="50" y="185" fill="var(--sl-color-white)" font-family="monospace" font-size="11" font-weight="600">CompiledRoute: /v2/users*</text>
  <text x="50" y="203" fill="var(--sl-color-gray-3)" font-family="monospace" font-size="10">plugins: [global...] → [group (shared Arc)...] → [route...]  ·  HookMask</text>

  <line x1="530" y1="190" x2="564" y2="190" stroke="var(--sl-color-accent)" stroke-width="1.6"/>

  <rect x="564" y="164" width="162" height="52" rx="6" fill="var(--sl-color-gray-6)" stroke="var(--sl-color-hairline)"/>
  <text x="645" y="185" text-anchor="middle" fill="var(--sl-color-white)" font-family="monospace" font-size="11" font-weight="600">UpstreamPool</text>
  <text x="645" y="203" text-anchor="middle" fill="var(--sl-color-gray-3)" font-family="monospace" font-size="10">by name (route → group)</text>
</svg>
</div>

- **`[[upstreams]]` are always top-level:** Backend pools, TLS settings, and active health checks live at the top level so multiple routes, route groups, mirrors, and dynamic routers (`ai-model-router`, `mcp-router`) can share warm connection pools by name.
- **`[[route_groups]]` reference upstreams—they don't nest them:** Set `upstream = "my_pool"` on a group to provide a default backend for all member routes (individual routes can omit `upstream` to inherit it, or set their own `upstream` to override it).
- **`[[routes]]` stay in one flat ordered list:** Routes opt into a group with `group = "<id>"`. Keeping routes flat guarantees unambiguous top-to-bottom first-match-wins precedence and clean TOML.

### Choosing Plugin Scope: Global vs. Group vs. Route

Plugins execute in deterministic **`global` → `group` → `route`** order. Where you attach a plugin controls both **which routes run it** and **how state is shared**:

| Scope | TOML Block | Instantiation & `StateStore` Scope | Best Used For |
| --- | --- | --- | --- |
| **Global** | `[[plugins]]` | Built once (`global:<id>`); runs on **every** route | `request-id`, `metrics`, `access-log`, `otel-trace`, gateway-wide rate limits |
| **Route Group** | `[[route_groups.plugins]]` | Built **once per group** (`group:<group_id>:<id>`); shared via `Arc` across all member routes | Shared `rate-limit` quota across sibling routes, single warm `jwt-auth` JWKS cache, `ip-filter`, `cors`, shared AI/MCP policies |
| **Route** | `[[routes.plugins]]` | Built **once per route** (`route:<route_id>:<id>`); isolated state | Route-specific `header-rewrite`, `redirect`, `compression`, or isolated per-endpoint quotas |

:::tip[Preserve State Across Hot Reloads with `id`]
For stateful plugins (`rate-limit`, `jwt-auth`, `ai-token-rate-limit`, `ai-budget`, `ai-cache`, `ai-failover`, `mcp-rate-limit`), always set an explicit `id = "..."` on the plugin block. Without an explicit `id`, the scope falls back to the plugin's positional index (`name:0`), so reordering plugins resets in-memory counters on reload.
:::

---

## Environment Variable Substitution (`env:`)

Secret fields across plugins, `[state]`, and `[telemetry]` support the `env:VAR_NAME` convention so secrets never live in Git:

```toml
api_key = "env:OPENAI_API_KEY"
url = "env:SHUNT_REDIS_URL"
```

Missing environment variables are caught eagerly during `shunt check` and snapshot compilation—never halfway through a live request.

---

## `[server]` & `[server.tls]`

Controls the public proxy listener, graceful draining, SNI TLS, and mutual TLS (mTLS).

```toml
[server]
listen = "0.0.0.0:8080"     # Default: "0.0.0.0:8080"
drain_timeout_ms = 30000    # Default: 30000 (graceful shutdown / reload drain)

[server.tls]
cert = "certs/server.crt"           # Default PEM cert chain (relative paths resolve from config dir)
key = "certs/server.key"            # Default PEM private key
client_ca = "certs/client-ca.crt"   # Optional PEM client CA bundle for mTLS
client_auth = "optional"            # "none" | "optional" | "required" (defaults to "required" if client_ca is set)

[[server.tls.sni]]
host = "api.example.com"
cert = "certs/api.crt"
key = "certs/api.key"
```

:::tip[Automatic TLS Certificate Rotation]
Shunt's file watcher tracks `cert`, `key`, `client_ca`, and all `sni` cert paths in addition to `shunt.toml`. Rotating certificates on disk automatically hot-reloads the `rustls` resolver with zero downtime.
:::

---

## `[admin]`

The Admin API always binds to a **separate listener** from `[server]`, isolated from public data-plane traffic.

```toml
[admin]
enabled = true              # Default: true
listen = "127.0.0.1:9090"   # Default: "127.0.0.1:9090"
ui = false                  # Default: false (or pass `--ui` to `shunt dev` / `shunt run`)
ui_trace_capacity = 256     # Default: 256 (bounded ring buffer, max: 10000)
```

---

## `[state]`

Configures the backing `StateStore` shared by stateful plugins (`rate-limit`, `ai-token-rate-limit`, `ai-budget`, `ai-failover`, `ai-cache`, `mcp-rate-limit`).

```toml
[state]
backend = "memory"          # "memory" (default, zero-dependency) | "redis"
url = "env:SHUNT_REDIS_URL" # redis:// or rediss:// (required when backend = "redis")
username = ""               # Optional Redis ACL username
password = "env:REDIS_PASS" # Optional password override
key_prefix = "shunt:"       # Default: "shunt:"
pool_size = 8               # Default: 8
connect_timeout_ms = 1000   # Default: 1000
command_timeout_ms = 250    # Default: 250
failure_policy = "fail_open"# "fail_open" (default) | "fail_closed"
insecure_skip_verify = false# Skip TLS verification for rediss:// (dev only)
```

---

## `[telemetry]`

Configures Shunt's built-in, zero-dependency bounded async **OTLP/HTTP JSON** trace exporter (compatible with Jaeger, Grafana Tempo, Langfuse, Arize Phoenix, Datadog, and Honeycomb).

```toml
[telemetry]
enabled = true
backend = "otlp_http"
endpoint = "http://127.0.0.1:4318/v1/traces" # Supports env:VAR
service_name = "shunt-gateway"               # Default: "shunt"
queue_capacity = 4096                        # Default: 4096 (drops excess spans without blocking)
batch_size = 128                             # Default: 128
flush_interval_ms = 1000                     # Default: 1000
export_timeout_ms = 5000                     # Default: 5000
insecure_skip_verify = false
resource_attributes = { "deployment.environment" = "production" }
headers = { Authorization = "env:OTLP_AUTH_HEADER" }
```

Attach the [`otel-trace`](/shunt/plugins/http-plugins/#otel-trace) plugin globally or per-route to emit spans.

---

## `[[plugins]]` (Global Plugins)

Global plugins run on **every route** before group-level `[[route_groups.plugins]]` and route-specific `[[routes.plugins]]`:

```toml
[[plugins]]
name = "request-id"

[[plugins]]
name = "metrics"

[[plugins]]
name = "rate-limit"
id = "global-rl"            # Stable ID preserves state across hot reloads
[plugins.config]
requests_per_second = 500.0
burst = 1000
```

---

## `[[upstreams]]`

Defines named backend pools, connection pooling, upstream TLS, passive health ejection, and optional background active health probes.

Upstreams are always declared at the top level and referenced by name from `[[routes]]`, `[[route_groups]]` (as a default `upstream`), `[[routes.mirrors]]`, `ai-model-router`, and `mcp-router`. This keeps warm TCP/TLS pools, active health probes, and `/upstreams` health reports shared across the whole gateway.

```toml
[[upstreams]]
name = "api_backend"
endpoints = [
  { url = "http://127.0.0.1:18080", weight = 90 },
  { url = "http://127.0.0.1:18081", weight = 10 },
]
# Simple unweighted shorthand also works:
# endpoints = ["https://api.openai.com"]

http2_only = false              # Default: false
connect_timeout_ms = 5000       # Default: 5000
pool_idle_timeout_ms = 90000    # Default: 90000
pool_max_idle_per_host = 64     # Default: 64
unhealthy_threshold = 3         # Passive consecutive failures before ejection (default: 3)
unhealthy_cooldown_ms = 10000   # Passive cooldown before re-trying endpoint (default: 10000)

[upstreams.tls]
ca_cert = "certs/upstream-ca.pem" # Optional custom root CA
insecure_skip_verify = false
alpn = ["h2", "http/1.1"]

[upstreams.health_check]
kind = "http"                   # "http" | "tcp"
path = "/health"                # Default: "/health"
method = "GET"                  # Default: "GET"
expected_statuses = [200]       # Default: [200]
headers = {}                    # Optional probe headers
interval_ms = 10000             # Default: 10000
timeout_ms = 2000               # Default: 2000
unhealthy_threshold = 2         # Default: 2
healthy_threshold = 1           # Default: 1
initial_healthy = true          # Default: true
```

---

## `[[route_groups]]` (Reusable Route Groups & Shared Plugin Chains)

Route groups define shared match defaults (`hosts`, `path_prefix`, `methods`, `headers`), shared execution defaults (`upstream`, `strip_prefix`, `max_body_bytes`, `max_attempts`, timeouts, `allow_websockets`, `mirrors`), and a **shared plugin chain** instantiated **once per group**.

Every member route (`group = "<id>"`) shares the exact same `Arc<dyn HttpPlugin>` instances under `group:<group_id>:<plugin_id>`—so `rate-limit` shares one token bucket across all routes in the group and `jwt-auth` shares one JWKS cache—while lowering to flat `CompiledRoute`s with **zero runtime overhead**.

```toml
[[route_groups]]
id = "api_v2"
hosts = ["*.example.com"]
path_prefix = "/v2"
strip_prefix = "/v2"
methods = ["GET", "POST"]
headers = { "x-api-version" = "2" }
upstream = "default_api_backend"    # Optional default upstream for member routes
max_body_bytes = 1048576
max_attempts = 2
response_headers_timeout_ms = 10000
idle_chunk_timeout_ms = 30000
allow_websockets = false

[[route_groups.plugins]]
name = "jwt-auth"
id = "api-v2-jwt"
[route_groups.plugins.config]
jwks_uri = "https://auth.example.com/.well-known/jwks.json"
issuer = "https://auth.example.com"
audience = "shunt-api"

[[route_groups.plugins]]
name = "rate-limit"
id = "api-v2-shared-rl"
[route_groups.plugins.config]
requests_per_second = 100.0
burst = 200
key = "client_ip"
```

### Inheritance & Safe Narrowing Rules

| Field | Lowering Behavior (`route` over `group`) |
| --- | --- |
| **`path_prefix` / `path_exact`** | Joined cleanly onto `group.path_prefix` (e.g. `/v2` + `/users` → `/v2/users`) |
| **`hosts`** | Inherited when omitted; if specified on route, every host must be subsumed by `group.hosts` |
| **`methods`** | Inherited when omitted; if specified on route, every method must be allowed by `group.methods` |
| **`headers`** | Merged (`group.headers` + `route.headers`); contradictory values for the same header are rejected |
| **`upstream`, `strip_prefix`, `max_body_bytes`, `max_attempts`, timeouts, `allow_websockets`** | Route overrides group when explicitly set; otherwise falls back to group, then gateway default |
| **`mirrors`** | `group.mirrors` followed by `route.mirrors` |
| **`plugins`** | Deterministic execution order: `global` → `group` (shared `Arc`) → `route` |

:::tip[Explicit First-Match Precedence]
Routes remain in a single ordered `[[routes]]` array and opt into a group via `group = "api_v2"`. This preserves unambiguous top-to-bottom route matching order and lets `shunt verify` detect shadowed routes across lowered paths.
:::

---

## `[[routes]]` & `[[routes.mirrors]]`

Routes are matched top-to-bottom (exact paths and more specific matchers should be listed first; `shunt verify` catches shadowed routes automatically).

```toml
[[routes]]
id = "api_v2_users"
group = "api_v2"                    # Optional reference to a [[route_groups]] ID
hosts = ["api.example.com"]         # Optional host filter (supports *.example.com)
path_prefix = "/users"              # Joined onto group.path_prefix if grouped; or use `path_exact`
# path_exact = "/health"
methods = ["GET", "POST"]           # Empty = inherit group methods (or all HTTP methods)
headers = { "x-track" = "canary" }  # Optional exact header matchers (all must match)
upstream = "api_backend"            # Required unless inherited from `group.upstream`
strip_prefix = "/v2"                # Optional prefix stripped before forwarding
max_body_bytes = 2097152            # Optional max buffered body size
max_attempts = 2                    # Default: 1 (or group default)
response_headers_timeout_ms = 30000 # TTFB / TTFT timeout (default: 30000)
idle_chunk_timeout_ms = 60000       # Max gap between stream chunks (default: 60000)
allow_websockets = true             # Default: true

# Optional fire-and-forget traffic mirroring
[[routes.mirrors]]
upstream = "shadow_eval"
sample_rate = 0.05                  # [0.0, 1.0], default: 1.0
timeout_ms = 2000                   # Default: 5000
max_in_flight = 32                  # Default: 128
headers = { "x-shunt-mirror" = "eval" }

[[routes.plugins]]
name = "compression"
[routes.plugins.config]
encodings = ["zstd", "br", "gzip"]
```

---

## `[verify]` (Declarative Policy Rules)

Embed organization-wide security and reliability guardrails directly in `shunt.toml` (or pass `--policy policy.toml` to `shunt verify`). See [Verification & Testing](/shunt/concepts/verification/).
