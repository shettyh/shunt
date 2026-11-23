---
title: Traffic, Compression & Mirroring
description: Configure streaming-safe zstd/brotli/gzip response compression, HTTP redirects, header/URL rewrites, and fire-and-forget traffic shadowing.
---

## Streaming-Safe Response Compression (`compression`)

Shunt's `compression` plugin negotiates `Accept-Encoding` in server preference order (`zstd`, `br`, `gzip`, `deflate`) while respecting streaming safety:

- Automatically skips `text/event-stream` (SSE), images, audio/video, and already-compressed archives.
- Sets `Vary: Accept-Encoding` and weakens strong `ETag` headers per RFC 9110.
- Skips payloads smaller than `min_size_bytes`.

```toml
[[routes.plugins]]
name = "compression"
[routes.plugins.config]
encodings = ["zstd", "br", "gzip"]
min_size_bytes = 1024
level = 4
```

## Redirects & URL / Header Rewrites

Use `redirect` for clean HTTP `301`/`302`/`307`/`308` moves and `header-rewrite` for request/upstream/response header mutations or path rewrites:

```toml
[[routes]]
id = "legacy_v1_redirect"
path_prefix = "/v1"
upstream = "api_backend"

[[routes.plugins]]
name = "redirect"
[routes.plugins.config]
status_code = 301
scheme = "https"
hostname = "api.example.com"
path_match_prefix = "/v1"
path_replace_prefix = "/v2"
preserve_query = true
```

## Fire-and-Forget Traffic Mirroring (`[[routes.mirrors]]`)

Shadow a sampled percentage of production traffic to a staging or evaluation upstream without adding latency to the primary response:

```toml
[[routes]]
id = "checkout_v2"
path_prefix = "/v2/checkout"
upstream = "checkout_prod"

[[routes.mirrors]]
upstream = "checkout_shadow"
sample_rate = 0.10 # mirror 10% of requests
timeout_ms = 2000
max_in_flight = 64 # bounded concurrency so slow shadow backends never pile up
[routes.mirrors.headers]
x-shunt-mirror = "shadow-eval"
```

Mirror attempts, successes, and dropped/timed-out mirrors are exposed directly on `GET /metrics`.
