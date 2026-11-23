---
title: Coding Agents & Local LLMs
description: Connect Claude Code, OpenAI SDKs, Codex CLI, and local Ollama/vLLM servers through Shunt with transparent protocol translation and fallback.
---

Because Shunt natively serves `/v1/chat/completions`, `/v1/messages`, and `/v1/responses` on the same `/v1` route, you can point any AI SDK or coding agent at Shunt and route transparently between cloud frontier models and local Ollama/vLLM clusters.

## 1. Hybrid Local Ollama + Cloud Failover Config

```toml
[server]
listen = "127.0.0.1:8080"

[admin]
enabled = true
listen = "127.0.0.1:9090"

[[upstreams]]
name = "ollama"
endpoints = ["http://127.0.0.1:11434"]
connect_timeout_ms = 2000

[[upstreams]]
name = "anthropic"
endpoints = ["https://api.anthropic.com"]
connect_timeout_ms = 5000

[[upstreams]]
name = "openai"
endpoints = ["https://api.openai.com"]
connect_timeout_ms = 5000

[[routes]]
id = "dev_ai"
path_prefix = "/v1"
methods = ["GET", "POST"]
upstream = "anthropic"
max_attempts = 2
response_headers_timeout_ms = 60000
idle_chunk_timeout_ms = 60000

[[routes.plugins]]
name = "ai-model-router"
[routes.plugins.config]
auto_max_attempts = true
serve_models_endpoint = true
serve_count_tokens_endpoint = true

[routes.plugins.config.models]
coding = [
  { provider = "anthropic", upstream = "anthropic", model = "claude-sonnet-4-20250514" },
  { provider = "openai", upstream = "openai", model = "gpt-4o" },
]
local = [
  { provider = "ollama", upstream = "ollama", model = "qwen2.5-coder:14b" },
  { provider = "openai", upstream = "openai", model = "gpt-4o-mini" },
]

[[routes.plugins]]
name = "ai-provider-adapter"
[routes.plugins.config.providers.ollama]
preset = "ollama"
[routes.plugins.config.providers.anthropic]
preset = "anthropic"
api_key = "env:ANTHROPIC_API_KEY"
drop_params = true
[routes.plugins.config.providers.openai]
preset = "openai"
api_key = "env:OPENAI_API_KEY"
drop_params = true

[[routes.plugins]]
name = "ai-failover"
id = "dev-failover"
[routes.plugins.config]
cooldown_ms = 15000

[[routes.plugins]]
name = "ai-usage-tracker"
[routes.plugins.config]
log_usage = true
```

Start Shunt with live trace inspection:

```bash
shunt dev --ui -c shunt-coding.toml
```

## 2. Point Your Tools at Shunt

### Claude Code / Anthropic SDK (`POST /v1/messages`)

```bash
export ANTHROPIC_BASE_URL="http://127.0.0.1:8080"
export ANTHROPIC_API_KEY="shunt-local-or-virtual-key"
```

You can now ask Claude Code to use `coding` (native Anthropic with automatic OpenAI failover) or `local` (transparently translated to local Ollama!).

### OpenAI Python / TypeScript SDK

```python
from openai import OpenAI

client = OpenAI(
    base_url="http://127.0.0.1:8080/v1",
    api_key="shunt-local-or-virtual-key",
)

resp = client.chat.completions.create(
    model="coding",
    messages=[{"role": "user", "content": "Write a Rust binary search."}],
)
print(resp.choices[0].message.content)
```

### OpenAI Responses API / Codex CLI (`POST /v1/responses`)

```bash
export OPENAI_BASE_URL="http://127.0.0.1:8080/v1"
export OPENAI_API_KEY="shunt-local-or-virtual-key"
```

Open `http://127.0.0.1:9090/ui` to watch live token counts, TTFT, and failover events as your agent runs.
