---
title: HTTP Plugins (shunt-plugins)
description: Complete configuration reference for all 15 built-in HTTP API gateway plugins in shunt-plugins.
---

All 15 plugins in `shunt-plugins` can be attached globally (`[[plugins]]`), per route group (`[[route_groups.plugins]]`), or per route (`[[routes.plugins]]`). Plugins execute in **`global → group → route`** order.

:::tip[Zero Buffering & Shared Group State]
None of the 15 plugins in `shunt-plugins` buffer full request or response bodies—routes using only HTTP plugins stay streaming and allocation-free. For stateful/cached plugins (`rate-limit`, `jwt-auth`), attach them on `[[route_groups.plugins]]` with a stable `id = "..."` to share one bucket or JWKS cache across sibling routes and preserve state across hot reloads.
:::

## Plugin Matrix

| Plugin | Hooks Used | Body Buffering | State / Redis | Purpose |
| --- | --- | --- | --- | --- |
| `request-id` | Request / Response Headers | None | Stateless | Generate or propagate `x-request-id` |
| `access-log` | Complete | None | Stateless | Structured `tracing` access logs |
| `bearer-auth` | Request Headers | None | Stateless (`env:`) | Static bearer token auth with subject injection |
| `jwt-auth` | Request Headers | None | In-memory JWKS cache (`env:`) | Pure-Rust JWT/JWKS/OIDC verification & claim forwarding |
| `mtls-auth` | Request Headers | None | Stateless | Mutual TLS client cert authorization (CN, SAN, SPIFFE, SHA-256) |
| `ip-filter` | Request Headers | None | Stateless | IPv4/IPv6 CIDR allow/deny with trusted-proxy `X-Forwarded-For` |
| `body-limit` | Request Headers (stream limit) | None (streaming cap) | Stateless | Enforce max request body size on `Content-Length` & chunked streams |
| `compression` | Request / Response Headers + Chunk | Streaming chunk | Stateless | Streaming-safe, SSE-aware `zstd`/`br`/`gzip`/`deflate` |
| `redirect` | Request Headers | None | Stateless | HTTP `301`/`302`/`303`/`307`/`308` redirects & path rewrites |
| `rate-limit` | Request Headers | None | Stateful (Memory / Redis) | Token-bucket rate limiting across local or Redis/Valkey state |
| `header-rewrite` | Request / Upstream / Response Headers | None | Stateless | Set, add, or remove headers and rewrite upstream host/path |
| `cors` | Request / Response Headers | None | Stateless | CORS preflight (`OPTIONS`) & response headers |
| `otel-trace` | Request / Upstream / Response / Complete | None | Shared OTLP exporter | W3C `traceparent`/`tracestate` & OTLP span emission |
| `metrics` | Complete | None | Global Prometheus registry | Prometheus counters & histograms on `/metrics` |
| `dev-waterfall` | Complete | None | Stateless | Per-hook µs trace waterfall (auto-attached by `shunt dev`) |

---

## Configuration Reference

### `request-id`
```toml
[[plugins]]
name = "request-id"
[plugins.config]
header_name = "x-request-id" # default
trust_incoming = true        # reuse client header if valid
echo_in_response = true      # return header on responses
```

### `access-log`
```toml
[[plugins]]
name = "access-log"
[plugins.config]
include_timings = true
```

### `bearer-auth`
```toml
[[routes.plugins]]
name = "bearer-auth"
[routes.plugins.config]
realm = "shunt"
strip_header = true
tokens = [
  { token = "env:API_TOKEN_ALICE", subject = "alice" },
]
```

### `jwt-auth`
Pure-Rust verification supporting `HS256`/`HS384`/`HS512`, `RS256`/`RS384`/`RS512`, `PS256`/`PS384`/`PS512`, `ES256`/`ES384`, and `EdDSA`:
```toml
[[routes.plugins]]
name = "jwt-auth"
[routes.plugins.config]
# Remote JWKS or OIDC auto-discovery:
jwks_uri = "https://auth.example.com/.well-known/jwks.json"
# oidc_discovery = true
# oidc_discovery_url = "https://auth.example.com/.well-known/openid-configuration"
# Or static keys / inline JWKS:
# keys = [{ kid = "k1", secret = "env:SHUNT_JWT_SECRET" }]
algorithms = ["RS256", "ES256", "EdDSA"]
issuer = "https://auth.example.com"
audience = "shunt-api"
required_scopes = ["read"]
forward_claims = { "sub" = "x-user-id", "org.id" = "x-org-id" } # strips incoming headers first
strip_header = true
allow_missing = false
jwks_cache_ttl_secs = 300
jwks_min_refresh_secs = 10
jwks_timeout_ms = 5000
```

### `mtls-auth`
Requires `[server.tls]` with `client_ca` and `client_auth = "required"` (or `"optional"`):
```toml
[[routes.plugins]]
name = "mtls-auth"
[routes.plugins.config]
require_cert = true
allowed_cns = ["*.svc.internal"]
allowed_san_dns = ["payments.svc.internal"]
allowed_san_uris = ["spiffe://prod/ns/payments/*"]
allowed_fingerprints = []
subject_header = "x-client-cn"
dn_header = "x-client-dn"
fingerprint_header = "x-client-sha256"
san_uri_header = "x-spiffe-id"
```

### `ip-filter`
```toml
[[routes.plugins]]
name = "ip-filter"
[routes.plugins.config]
allow = ["127.0.0.0/8", "10.0.0.0/8", "::1/128"]
deny = ["10.99.0.0/16"]
precedence = "deny_first" # "deny_first" | "allow_first"
trusted_proxies = ["127.0.0.1/32"]
use_forwarded_for = true
# client_ip_header = "cf-connecting-ip"
status_code = 403
```

### `body-limit`
```toml
[[routes.plugins]]
name = "body-limit"
[routes.plugins.config]
max_bytes = 1048576 # 1 MiB (enforced on Content-Length & streaming bodies)
status_code = 413
```

### `compression`
Streaming-safe compression that automatically skips `text/event-stream` (SSE), binary media, and pre-compressed payloads, sets `Vary: Accept-Encoding`, and weakens strong `ETag`s per RFC 9110:
```toml
[[routes.plugins]]
name = "compression"
[routes.plugins.config]
encodings = ["zstd", "br", "gzip"] # also supports "deflate"
min_size_bytes = 1024
level = 4
content_types = [] # empty = built-in streaming-safe filter
flush_chunks = false
```

### `redirect`
```toml
[[routes.plugins]]
name = "redirect"
[routes.plugins.config]
status_code = 301 # 301 | 302 | 303 | 307 | 308
scheme = "https"
hostname = "api.example.com"
path_match_prefix = "/legacy"
path_replace_prefix = "/v2"
preserve_query = true
```

### `rate-limit`
```toml
[[routes.plugins]]
name = "rate-limit"
id = "public-rl" # preserves token buckets across hot reloads
[routes.plugins.config]
requests_per_second = 50.0
burst = 100
key = "client_ip" # "client_ip" | "header" | "subject" | "global"
# header_name = "x-api-key"
max_entries = 100000
idle_ttl_ms = 300000
distributed = true # uses [state] Redis/Valkey when configured
```

### `header-rewrite`
Supports static values as well as `{param}` interpolation from captured `path_template` parameters or named `path_regex` capture groups (`(?P<name>...)`) in `request_set`/`request_add`, `upstream_set`, `response_set`/`response_add`, and `path_replace_full` (zero overhead when no `{...}` placeholders are configured):

```toml
[[routes.plugins]]
name = "header-rewrite"
[routes.plugins.config]
request_set = { "x-gateway" = "shunt" }
request_add = {}
request_remove = ["x-internal-debug"]
upstream_set = { "x-order-id" = "{order_id}" }
upstream_remove = []
response_set = { "x-powered-by" = "shunt" }
response_add = {}
response_remove = ["server"]
# Optional URL/Host rewrites:
# upstream_host = "backend.internal"
# path_replace_full = "/internal/orders/{order_id}/state"
# path_match_prefix = "/old"
# path_replace_prefix = "/new"
```

### `cors`
```toml
[[routes.plugins]]
name = "cors"
[routes.plugins.config]
allow_origins = ["https://app.example.com"] # or ["*"]
allow_methods = ["GET", "POST", "PUT", "DELETE", "OPTIONS"]
allow_headers = ["Authorization", "Content-Type"]
expose_headers = ["x-request-id"]
allow_credentials = false
max_age_secs = 86400
```

### `otel-trace`
Requires `[telemetry] enabled = true` for remote OTLP export:
```toml
[[plugins]]
name = "otel-trace"
[plugins.config]
sample_rate = 1.0
respect_parent_sampling = true
propagate_headers = true
emit_response_header = false # true emits `x-trace-id` on responses
```

### `metrics`
No configuration required; exposes Prometheus metrics on the Admin listener (`GET /metrics`):
```toml
[[plugins]]
name = "metrics"
```
