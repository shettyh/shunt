---
title: "Quickstart: HTTP API Gateway"
description: Stand up a high-performance HTTP API gateway with rate limiting, JWT auth, compression, and live trace waterfalls in 2 minutes.
---

This guide creates a local HTTP API gateway with request IDs, Prometheus metrics, CORS, rate limiting, and streaming response compression—plus live hot reloads and the browser Admin Inspector UI.

## 1. Create `shunt.toml`

Save the following file as `shunt.toml`:

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

[[plugins]]
name = "access-log"

[[upstreams]]
name = "httpbin"
endpoints = ["https://httpbin.org"]
connect_timeout_ms = 5000

[[routes]]
id = "public_api"
path_prefix = "/api"
strip_prefix = "/api"
upstream = "httpbin"
max_attempts = 2
response_headers_timeout_ms = 10000
idle_chunk_timeout_ms = 30000

[[routes.plugins]]
name = "cors"
[routes.plugins.config]
allow_origins = ["*"]

[[routes.plugins]]
name = "rate-limit"
id = "public-rl"
[routes.plugins.config]
requests_per_second = 50.0
burst = 100
key = "client_ip"

[[routes.plugins]]
name = "compression"
[routes.plugins.config]
encodings = ["zstd", "br", "gzip"]
min_size_bytes = 512

[[routes.plugins]]
name = "header-rewrite"
[routes.plugins.config]
response_set = { "x-powered-by" = "shunt" }
```

## 2. Validate & Statically Verify

Before starting the server, check syntax, compiled routes, and active `HookMask` bitmasks:

```bash
shunt check -c shunt.toml
shunt verify -c shunt.toml
```

`shunt check` prints every compiled route alongside its exact `HookMask`, confirming which hooks are active and whether the route stays unbuffered on the hot path.

## 3. Run in Dev Mode with Inspector UI

```bash
shunt dev --ui -c shunt.toml
```

You now have:
- **Proxy data plane:** `http://127.0.0.1:8080`
- **Admin API:** `http://127.0.0.1:9090` (`/health`, `/metrics`, `/snapshot`, `/upstreams`)
- **Read-Only Admin Inspector UI:** `http://127.0.0.1:9090/ui`

## 4. Send a Test Request

```bash
curl -i -H "Accept-Encoding: zstd, gzip" http://127.0.0.1:8080/api/json
```

Look at your terminal to see the live per-hook microsecond waterfall, or open `http://127.0.0.1:9090/ui` in your browser to inspect:
- Live SSE request trace waterfalls
- Compiled routes, plugins, and `HookMask`s
- Upstream health & Prometheus metrics

## 5. Try Zero-Downtime Hot Reload

While `shunt dev` is running, edit `response_set` in `shunt.toml` and save the file. Shunt automatically re-validates, compiles a new immutable snapshot, and swaps it atomically via `ArcSwap` with zero dropped connections—preserving rate-limit bucket state across reloads because the plugin has a stable `id = "public-rl"`.

## Next Steps

- Add pure-Rust JWT/JWKS authentication, CIDR IP filtering, and streaming body limits: see [HTTP Plugins Reference](/shunt/plugins/http-plugins/)
- Run Shunt with Kubernetes Gateway API manifests: see [Kubernetes Gateway API](/shunt/api-gateway/kubernetes/)
- Deploy to production with `shunt run -c shunt.toml`
