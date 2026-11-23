---
title: Configuration (shunt.toml)
description: Complete schema reference for shunt.toml and YAML configuration files including server, TLS/mTLS, admin, state, telemetry, upstreams, routes, and mirrors.
---

Shunt accepts **TOML** (`.toml`, canonical) or **YAML** (`.yaml` / `.yml`) configuration files, as well as [Kubernetes Gateway API v1](/shunt/api-gateway/kubernetes/) manifests.

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

Global plugins run on **every route** before route-specific `[[routes.plugins]]`:

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

## `[[routes]]` & `[[routes.mirrors]]`

Routes are matched top-to-bottom (exact paths and more specific matchers should be listed first; `shunt verify` catches shadowed routes automatically).

```toml
[[routes]]
id = "api_v2"
hosts = ["api.example.com"]         # Optional host filter (supports *.example.com)
path_prefix = "/v2"                 # Specify `path_prefix` or `path_exact`
# path_exact = "/v2/health"
methods = ["GET", "POST"]           # Empty = all HTTP methods
headers = { "x-track" = "canary" }  # Optional exact header matchers (all must match)
upstream = "api_backend"
strip_prefix = "/v2"                # Optional prefix stripped before forwarding
max_body_bytes = 2097152            # Optional max buffered body size
max_attempts = 2                    # Default: 1
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
