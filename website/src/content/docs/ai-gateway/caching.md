---
title: AI Caching (Exact, SSE & Semantic)
description: Cut LLM latency and spend to zero on repeated queries with exact-match SHA-256 caching, streaming SSE replay, singleflight coalescing, and semantic vector caching.
---

`ai-cache` intercepts repeated AI requests before they hit rate limits, budgets, or upstream providers—serving exact-match hits at **>140k req/s** with sub-millisecond latency.

:::tip[Placement Matters]
Place `ai-cache` directly **after** `ai-model-router` (and `ai-guardrails`) and **before** `ai-token-rate-limit`, `ai-budget`, and `ai-provider-adapter`. That way cache hits consume zero upstream tokens, quota, or spend.
:::

## Caching Modes

1. **Exact-Match Canonical SHA-256 Caching:** Canonicalizes the normalized JSON payload, target model, and tenant scope (`global`, `virtual_key`, or `team`). By default (`require_deterministic = true`), caches embeddings and deterministic (`temperature = 0` or seeded) chat/responses calls.
2. **Streaming SSE Capture & Replay (`cache_streaming = true`):** Captures live `text/event-stream` chunks on the first request and replays the full SSE stream instantaneously on subsequent hits.
3. **Singleflight Thundering-Herd Coalescing (`singleflight = true`):** When 100 identical requests arrive simultaneously on a cold cache, Shunt sends **1** upstream request and fans the result out to all 100 callers.
4. **Semantic Vector Caching (`[routes.plugins.config.semantic]`):** Computes query embeddings via any OpenAI- or Ollama-compatible `/v1/embeddings` endpoint and returns cached answers above `similarity_threshold`.

## Example Configuration

```toml
[[routes.plugins]]
name = "ai-cache"
id = "ai-cache"
[routes.plugins.config]
ttl_secs = 600
max_entries = 2048
max_total_bytes = 33554432
max_entry_bytes = 1048576
scope = "virtual_key"       # "global" | "virtual_key" | "team"
require_deterministic = true
respect_cache_control = true
emit_headers = true         # sets `x-shunt-cache: HIT | MISS | BYPASS`

# Streaming SSE replay & thundering-herd coalescing
cache_streaming = true
singleflight = true
singleflight_timeout_ms = 30000

# Optional semantic vector cache
[routes.plugins.config.semantic]
mode = "embedding_http"
endpoint = "https://api.openai.com/v1/embeddings"
model = "text-embedding-3-small"
api_key = "env:OPENAI_API_KEY"
similarity_threshold = 0.95
max_entries = 512
timeout_ms = 2000
```

## Multi-Replica Redis/Valkey Caching

When `[state] backend = "redis"` is configured at the gateway level, `ai-cache` automatically shares cached entries across all Shunt replicas without changing your route config.

## Client Cache-Control Support

When `respect_cache_control = true`, callers can bypass caching on a per-request basis using standard HTTP `Cache-Control: no-cache` or `Cache-Control: no-store` headers.
