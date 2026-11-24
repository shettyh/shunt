---
title: API Gateway Overview
description: High-performance HTTP/1.1 & HTTP/2 reverse proxying with host/path/header routing, weighted upstream pools, active health checks, and traffic mirroring.
---

Shunt's HTTP API Gateway combines the lean `shunt-engine` data plane with **15 composable plugins** in `shunt-plugins`—giving you sub-millisecond routing, weighted load balancing, active health probes, security, compression, and Kubernetes Gateway API v1 in a single binary.

## Core Routing & Load Balancing

Routes are evaluated top-to-bottom and can match on any combination of **hostnames** (including wildcards like `*.example.com`), **exact, prefix, parameterized template (`path_template`), or linear-time regex (`path_regex`) paths**, **HTTP methods**, and **exact request headers**:

```toml
[[upstreams]]
name = "orders_pool"
endpoints = [
  { url = "http://10.0.1.10:8080", weight = 90 },
  { url = "http://10.0.1.11:8080", weight = 10 },
]
connect_timeout_ms = 2000
pool_idle_timeout_ms = 90000
unhealthy_threshold = 3
unhealthy_cooldown_ms = 10000

[upstreams.health_check]
kind = "http"
path = "/healthz"
expected_statuses = [200]
interval_ms = 5000
timeout_ms = 1000
unhealthy_threshold = 2
healthy_threshold = 1

[[routes]]
id = "orders_canary_header"
hosts = ["api.example.com"]
path_prefix = "/v2/orders"
headers = { "x-release-track" = "canary" }
upstream = "orders_pool"

[[routes]]
id = "orders_v2"
hosts = ["api.example.com"]
path_prefix = "/v2/orders"
methods = ["GET", "POST", "PUT", "DELETE"]
upstream = "orders_pool"
max_attempts = 2
response_headers_timeout_ms = 10000
idle_chunk_timeout_ms = 30000
```

## Path Templates, Regex & Parameter Rewriting

Use `path_template` for zero-allocation REST path parameters (`{param}`) and catch-all wildcards (`{*filepath}`), or `path_regex` for constrained full-path patterns (accelerated via a single-pass `RegexSet` with ReDoS-safe linear-time guarantees):

```toml
[[routes]]
id = "order_status"
path_template = "/orders/{order_id}/status"
methods = ["GET"]
upstream = "orders_status_svc"

[[routes.plugins]]
name = "header-rewrite"
[routes.plugins.config]
upstream_set = { "x-order-id" = "{order_id}" }
path_replace_full = "/internal/orders/{order_id}/state"

[[routes]]
id = "static_assets"
path_template = "/files/{*filepath}"
methods = ["GET"]
upstream = "assets_svc"

[[routes]]
id = "invoice_pdf"
path_regex = '/invoices/(?P<year>[0-9]{4})/(?P<invoice_id>[0-9]+)\.pdf'
methods = ["GET"]
upstream = "billing_svc"

[[routes.plugins]]
name = "header-rewrite"
[routes.plugins.config]
upstream_set = { "x-invoice-year" = "{year}", "x-invoice-id" = "{invoice_id}" }
```

Captured parameters are extracted strictly on demand (zero heap allocation on static or `HookMask::EMPTY` routes) and work seamlessly with `[[route_groups]]` (`group.path_prefix` + `route.path_template`) and `shunt verify` route-shadowing checks. See [`examples/shunt-path-templates-and-regex.toml`](https://github.com/shettyh/shunt/blob/main/examples/shunt-path-templates-and-regex.toml).

## Route Groups & Shared Plugin Chains

When serving multiple routes under a shared API prefix, security perimeter, or backend service, define a reusable `[[route_groups]]` block and attach routes with `group = "<id>"`. Backend pools always stay at top-level `[[upstreams]]` and are referenced by name.

Two patterns cover almost all real-world gateways:

### Pattern 1: Single-Backend Group (Inherited Default `upstream`)

Set `upstream = "<pool>"` once on the group so every member route inherits it without repeating `upstream`:

```toml
[[upstreams]]
name = "billing_svc"
endpoints = ["http://10.0.2.10:8080"]

[[route_groups]]
id = "billing_api"
hosts = ["api.example.com"]
path_prefix = "/billing"
upstream = "billing_svc"             # Inherited by all routes in this group
response_headers_timeout_ms = 15000

[[route_groups.plugins]]
name = "jwt-auth"
id = "billing-jwt"
[route_groups.plugins.config]
jwks_uri = "https://auth.example.com/.well-known/jwks.json"
issuer = "https://auth.example.com"
audience = "shunt-api"

[[routes]]
id = "billing_invoices"
group = "billing_api"
path_prefix = "/invoices"            # lowered to "/billing/invoices" -> billing_svc
methods = ["GET", "POST"]

[[routes]]
id = "billing_subscriptions"
group = "billing_api"
path_prefix = "/subscriptions"       # lowered to "/billing/subscriptions" -> billing_svc
```

### Pattern 2: Multi-Service API Surface (Shared Auth & Rate-Limit Bucket)

Omit `upstream` on the group (or override it per route) when several microservices live under one versioned API perimeter:

```toml
[[route_groups]]
id = "api_v2"
hosts = ["api.example.com"]
path_prefix = "/v2"
strip_prefix = "/v2"
response_headers_timeout_ms = 10000

[[route_groups.plugins]]
name = "jwt-auth"
id = "api-v2-jwt"
[route_groups.plugins.config]
jwks_uri = "https://auth.example.com/.well-known/jwks.json"
issuer = "https://auth.example.com"
audience = "shunt-api"

[[route_groups.plugins]]
name = "rate-limit"
id = "api-v2-rl"
[route_groups.plugins.config]
requests_per_second = 100.0
burst = 200
key = "client_ip"

[[routes]]
id = "users_v2"
group = "api_v2"
path_prefix = "/users"      # lowered to "/v2/users"
upstream = "users_pool"

[[routes]]
id = "orders_v2"
group = "api_v2"
path_prefix = "/orders"     # lowered to "/v2/orders"
upstream = "orders_pool"
```

Group plugins are compiled **once** under `group:<group_id>:<plugin_id>` and shared across all member routes—so `users_v2` and `orders_v2` share a single `rate-limit` bucket and a single `jwt-auth` JWKS cache with zero data-plane overhead. Effective plugin execution order is always `global → group → route`. See [`[[route_groups]]`](/shunt/concepts/configuration/#route_groups-reusable-route-groups--shared-plugin-chains) and [`examples/shunt-route-groups.toml`](https://github.com/shettyh/shunt/blob/main/examples/shunt-route-groups.toml) for full lowering and narrowing rules.

## Active & Passive Health Checking

Shunt layers two complementary health mechanisms on every upstream pool:

1. **Active Background Probes (`[upstreams.health_check]`):** Periodically sends HTTP or TCP probes to each endpoint, ejecting unhealthy backends after `unhealthy_threshold` failures and returning them after `healthy_threshold` consecutive successes.
2. **Passive Circuit Ejection (`unhealthy_threshold`, `unhealthy_cooldown_ms`):** Immediately marks endpoints unhealthy on live connect/request errors without waiting for the next probe cycle.

Live endpoint weights and health status are always visible at `GET http://127.0.0.1:9090/upstreams` and in the `/ui` Inspector.

## Recommended API Plugin Order

```text
1. request-id       Generate or propagate x-request-id
2. ip-filter        Block disallowed CIDRs before parsing auth or bodies
3. mtls-auth        Authorize verified client certs (SPIFFE / CN / SAN)
4. jwt-auth         Verify JWT/JWKS/OIDC & forward trusted claim headers
5. rate-limit       Enforce per-IP / per-subject token buckets (local or Redis)
6. body-limit       Cap request payload size (Content-Length + streaming)
7. cors             Handle preflight OPTIONS & CORS response headers
8. header-rewrite   Rewrite request/upstream/response headers or URL paths
9. compression      Streaming-safe zstd / br / gzip response compression
10. otel-trace      W3C traceparent propagation & OTLP span export
11. metrics         Prometheus request/latency histograms
12. access-log      Structured access logging in on_complete
```

Every plugin is optional—routes with zero body or streaming plugins stay completely unbuffered and allocation-free.
