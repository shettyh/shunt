---
title: Smart Routing & Failover
description: Route AI traffic by priority, weighted canary, EWMA latency, cost, throughput, or headroom—with capability guards, OpenRouter per-request overrides, and automatic failover.
---

`ai-model-router` maps logical model aliases (like `smart`, `fast`, `canary`) and glob rules (`claude-*`, `gpt-*`) to ordered fallback chains across providers and upstreams.

## Routing Strategies

| Strategy | Behavior |
| --- | --- |
| `priority` *(default)* | Strict ordered fallback from first target to last |
| `weighted` | Smooth Weighted Round-Robin (SWRR) for canary / A-B splits (e.g., 90% frontier / 10% local vLLM) |
| `latency` | Ranks targets by EWMA TTFT/TTFB with error-rate penalties and stale re-exploration |
| `cost` | Picks the lowest estimated nano-USD target first using Shunt's built-in or external pricing catalog |
| `throughput` | Ranks targets by observed EWMA output tokens/second |
| `headroom` | Ranks targets by remaining upstream RPM/TPM capacity (`upstream_rpm`, `upstream_tpm`) |

```toml
[[routes.plugins]]
name = "ai-model-router"
[routes.plugins.config]
include_routing_headers = true
use_builtin_pricing = true
enforce_context_window = true
allow_request_routing_overrides = true

# Weighted canary split with capability guards
[routes.plugins.config.models.canary]
strategy = "weighted"
targets = [
  { provider = "anthropic", upstream = "anthropic", model = "claude-sonnet-4-20250514", weight = 90, capabilities = ["chat", "streaming", "tools", "vision", "reasoning"], zdr = true, regions = ["us", "eu"] },
  { provider = "vllm", upstream = "local_vllm", model = "qwen-2.5-72b", weight = 10, capabilities = ["chat", "streaming", "tools"] },
]

# Cost-aware routing
[routes.plugins.config.models.cheapest]
strategy = "cost"
targets = [
  { provider = "openai", upstream = "openai", model = "gpt-4o-mini" },
  { provider = "gemini", upstream = "gemini", model = "gemini-2.5-flash" },
]
```

## Capability & Context-Window Guards

- **Capability filtering:** Annotate targets with `capabilities = ["chat", "streaming", "tools", "vision", "json_schema", "reasoning", "embeddings", "rerank", "images", "audio", "realtime"]`. If an incoming request uses vision images or JSON schema, Shunt automatically skips targets lacking that capability.
- **Context-window guards:** Set `context_window` and `enforce_context_window = true` so prompts exceeding a small-context model automatically route to a larger-context fallback (e.g., 128k → 200k → 1M).
- **Default & override params:** Attach `default_params = { temperature = 0.2 }` or `override_params = { reasoning_effort = "high" }` per target.

## OpenRouter-Style Per-Request Overrides

When `allow_request_routing_overrides = true`, callers can steer routing directly in the JSON body:

```json
{
  "model": "frontier",
  "models": ["frontier", "fast"],
  "provider": {
    "order": ["anthropic", "gemini"],
    "ignore": ["openai"],
    "sort": "throughput",
    "zdr": true,
    "regions": ["eu"],
    "allow_fallbacks": true
  },
  "messages": [{"role": "user", "content": "Summarize this EU compliance doc."}]
}
```

## Automatic Failover & Circuit Breakers (`ai-failover`)

`ai-failover` pairs with `ai-model-router` to retry the next healthy target transparently via `Flow::RetryUpstream`:

```toml
[[routes.plugins]]
name = "ai-failover"
id = "ai-failover"
[routes.plugins.config]
retry_statuses = [429, 500, 502, 503, 504, 529]
cooldown_ms = 30000
failure_threshold = 2
respect_retry_after = true
ttft_timeout_ms = 15000
failover_on_context_overflow = true
```

- **Status & `Retry-After` cooldowns:** Opens a circuit cooldown (shared via Redis when `[state] backend = "redis"`) after `failure_threshold` consecutive failures or honors upstream `Retry-After`.
- **TTFT timeout failover:** Fails over if a provider stalls before sending the first response byte/chunk.
- **Context-overflow failover:** Detects context-length `400` error bodies and retries on the next larger-context target in the chain.
