---
title: "Quickstart: AI Gateway"
description: Route OpenAI SDK and Claude Code traffic across OpenAI, Anthropic, and local Ollama with automatic failover and token accounting in 2 minutes.
---

Shunt turns a single ~20 MB binary into a multi-provider AI gateway that accepts **OpenAI Chat Completions** (`/v1/chat/completions`), **Anthropic Messages** (`/v1/messages`), **OpenAI Responses** (`/v1/responses`), and **Embeddings** (`/v1/embeddings`)—translating JSON and live SSE streams on the fly across providers.

## 1. Create `shunt-ai.toml`

Save this configuration as `shunt-ai.toml`:

```toml
[server]
listen = "127.0.0.1:8080"
drain_timeout_ms = 30000

[admin]
enabled = true
listen = "127.0.0.1:9090"

[[plugins]]
name = "request-id"

[[plugins]]
name = "metrics"

[[upstreams]]
name = "openai"
endpoints = ["https://api.openai.com"]
connect_timeout_ms = 5000

[[upstreams]]
name = "anthropic"
endpoints = ["https://api.anthropic.com"]
connect_timeout_ms = 5000

[[routes]]
id = "ai_gateway"
path_prefix = "/v1"
methods = ["GET", "POST"]
upstream = "openai"
max_attempts = 2
response_headers_timeout_ms = 60000
idle_chunk_timeout_ms = 30000

# 1. Model aliases, capability guards, and /v1/models synthesis
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
fast = [
  { provider = "openai", upstream = "openai", model = "gpt-4o-mini" },
  { provider = "anthropic", upstream = "anthropic", model = "claude-3-5-haiku-20241022" },
]

# 2. Provider presets, auth injection, and bidirectional JSON/SSE translation
[[routes.plugins]]
name = "ai-provider-adapter"
[routes.plugins.config]
response_headers = true

[routes.plugins.config.providers.openai]
preset = "openai"
api_key = "env:OPENAI_API_KEY"
drop_params = true

[routes.plugins.config.providers.anthropic]
preset = "anthropic"
api_key = "env:ANTHROPIC_API_KEY"
drop_params = true

# 3. Automatic 429/5xx/529 failover with Retry-After cooldowns
[[routes.plugins]]
name = "ai-failover"
id = "ai-failover"
[routes.plugins.config]
retry_statuses = [429, 500, 502, 503, 504, 529]
cooldown_ms = 15000
failure_threshold = 2
respect_retry_after = true

# 4. Token, TTFT, and Prometheus metrics accounting
[[routes.plugins]]
name = "ai-usage-tracker"
[routes.plugins.config]
log_usage = true
```

## 2. Export API Keys & Start Shunt

```bash
export OPENAI_API_KEY="sk-..."
export ANTHROPIC_API_KEY="sk-ant-..."

shunt verify -c shunt-ai.toml
shunt dev --ui -c shunt-ai.toml
```

## 3. Send Requests Using Any SDK

### OpenAI-compatible client (`POST /v1/chat/completions`)

```bash
curl http://127.0.0.1:8080/v1/chat/completions \
  -H "Content-Type: application/json" \
  -d '{
    "model": "smart",
    "stream": true,
    "messages": [{"role": "user", "content": "Explain Rust ArcSwap in one sentence."}]
  }'
```

### Anthropic SDK / Claude Code (`POST /v1/messages`)

```bash
curl http://127.0.0.1:8080/v1/messages \
  -H "Content-Type: application/json" \
  -H "anthropic-version: 2023-06-01" \
  -d '{
    "model": "smart",
    "max_tokens": 256,
    "messages": [{"role": "user", "content": "Hello from Anthropic protocol!"}]
  }'
```

Even though the `smart` alias targets OpenAI first, Shunt transparently translates the Anthropic `/v1/messages` request to OpenAI and translates the response (or SSE stream) back to Anthropic format—and fails over to Anthropic automatically if OpenAI returns `429` or `5xx`.

### List Available Models

```bash
curl http://127.0.0.1:8080/v1/models
```

## 4. Inspect Usage, Cooldowns & Traces

- Open **`http://127.0.0.1:9090/ui`** to view live per-hook µs waterfalls, token counts, TTFT, and provider cooldowns.
- Scrape **`http://127.0.0.1:9090/metrics`** for `shunt_ai_*` Prometheus metrics.
- Query **`http://127.0.0.1:9090/api/status`** for live JSON runtime diagnostics.

## Next Steps

- Add [Virtual Keys, Budgets & Guardrails](/shunt/ai-gateway/governance-and-safety/)
- Enable [Exact, Streaming & Semantic AI Caching](/shunt/ai-gateway/caching/)
- Configure [Cloud IAM for Bedrock, Vertex AI & Azure](/shunt/ai-gateway/providers/)
- See [Using Shunt with Claude Code, Codex & Local Ollama](/shunt/guides/coding-agents/)
