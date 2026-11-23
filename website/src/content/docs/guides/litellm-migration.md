---
title: Migrating from LiteLLM
description: Side-by-side configuration mapping for moving from LiteLLM Proxy YAML to a single-binary Shunt AI Gateway.
---

If you already run **LiteLLM Proxy** and want a single-binary, GitOps-friendly Rust gateway with zero required database, this guide maps LiteLLM's configuration concepts directly to `shunt.toml`.

## Concept Mapping

| LiteLLM Concept | Shunt Equivalent |
| --- | --- |
| `model_list` + `litellm_params` | `[[upstreams]]` + `ai-model-router` (`models`) + `ai-provider-adapter` (`providers`) |
| `router_settings.fallbacks` / `cooldown_time` | Ordered `models.<alias>` targets + `ai-failover` (`cooldown_ms`, `respect_retry_after`) |
| `routing_strategy: latency-based-routing` / `cost` | `strategy = "latency"` / `"cost"` / `"weighted"` / `"throughput"` / `"headroom"` |
| `drop_params: true` | `drop_params = true` per provider in `ai-provider-adapter` |
| Virtual Keys, Teams & Budgets | `ai-virtual-keys` + `ai-token-rate-limit` + `ai-budget` (in-memory or Redis/Valkey, zero Postgres required) |
| `model_prices_and_context_window.json` | Built-in `PricingCatalog` (`use_builtin_pricing = true`) or `pricing_file = "prices.json"` (supports LiteLLM JSON format directly) |
| Redis Cache | `[state] backend = "redis"` + `ai-cache` (exact, streaming SSE, singleflight, semantic) |
| Callbacks (Langfuse / Phoenix / OTel) | Built-in `[telemetry]` OTLP/HTTP GenAI exporter + `otel-trace` |
| Guardrails (Presidio / Lakera / Bedrock) | `ai-guardrails` (built-in PII/secrets/injection + external callouts) |

## Side-by-Side Example

### Before (`litellm_config.yaml`)

```yaml
model_list:
  - model_name: smart
    litellm_params:
      model: openai/gpt-4o
      api_key: os.environ/OPENAI_API_KEY
  - model_name: smart
    litellm_params:
      model: anthropic/claude-sonnet-4-20250514
      api_key: os.environ/ANTHROPIC_API_KEY

litellm_settings:
  drop_params: true
  num_retries: 2
```

### After (`shunt.toml`)

```toml
[server]
listen = "0.0.0.0:8080"

[admin]
enabled = true
listen = "127.0.0.1:9090"

[[upstreams]]
name = "openai"
endpoints = ["https://api.openai.com"]

[[upstreams]]
name = "anthropic"
endpoints = ["https://api.anthropic.com"]

[[routes]]
id = "ai"
path_prefix = "/v1"
methods = ["GET", "POST"]
upstream = "openai"
max_attempts = 2

[[routes.plugins]]
name = "ai-model-router"
[routes.plugins.config]
auto_max_attempts = true
serve_models_endpoint = true
[routes.plugins.config.models]
smart = [
  { provider = "openai", upstream = "openai", model = "gpt-4o" },
  { provider = "anthropic", upstream = "anthropic", model = "claude-sonnet-4-20250514" },
]

[[routes.plugins]]
name = "ai-provider-adapter"
[routes.plugins.config.providers.openai]
preset = "openai"
api_key = "env:OPENAI_API_KEY"
drop_params = true
[routes.plugins.config.providers.anthropic]
preset = "anthropic"
api_key = "env:ANTHROPIC_API_KEY"
drop_params = true

[[routes.plugins]]
name = "ai-failover"
id = "ai-failover"
[routes.plugins.config]
cooldown_ms = 15000
respect_retry_after = true

[[routes.plugins]]
name = "ai-usage-tracker"
```

## Key Architectural Difference

Shunt is **GitOps-first and stateless by default**: `shunt.toml` (or Kubernetes manifests) is the single source of truth, reloaded atomically with zero downtime via `ArcSwap`—requiring no database to boot or serve traffic. When scaling horizontally across multiple replicas, opt in to `[state] backend = "redis"` so rate limits, budgets, cooldowns, and cache entries stay synchronized.
