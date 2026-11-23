---
title: API Gateway Overview
description: High-performance HTTP/1.1 & HTTP/2 reverse proxying with host/path/header routing, weighted upstream pools, active health checks, and traffic mirroring.
---

Shunt's HTTP API Gateway combines the lean `shunt-engine` data plane with **15 composable plugins** in `shunt-plugins`—giving you sub-millisecond routing, weighted load balancing, active health probes, security, compression, and Kubernetes Gateway API v1 in a single binary.

## Core Routing & Load Balancing

Routes are evaluated top-to-bottom and can match on any combination of **hostnames** (including wildcards like `*.example.com`), **exact or prefix paths**, **HTTP methods**, and **exact request headers**:

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
