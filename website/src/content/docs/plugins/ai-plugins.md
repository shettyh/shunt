---
title: AI Plugins (shunt-ai)
description: Complete configuration reference for all 11 built-in AI gateway plugins in shunt-ai.
---

All 11 plugins in `shunt-ai` run strictly on top of `shunt-plugin-sdk`. Attach them on a route (`[[routes.plugins]]`) or share stateful instances across multiple `/v1/*` routes using `[[route_groups.plugins]]` with stable `id = "..."` values. See [AI Gateway Overview](/shunt/ai-gateway/overview/) for the recommended execution order.

## Plugin Summary

| Plugin | Body Handling | State / Redis | Purpose |
| --- | --- | --- | --- |
| `ai-virtual-keys` | Headers only | Stateless (`env:`) | Constant-time SHA-256 virtual keys with team/org, model/provider ACLs, expiry, and quota overrides |
| `ai-model-router` | Buffers request JSON | In-memory EWMA latency/throughput/headroom | Multi-protocol ingress, model aliases, smart routing (`priority`/`weighted`/`latency`/`cost`/`throughput`/`headroom`), capability/context guards, `/v1/models` |
| `ai-guardrails` | Request / response + streaming SSE | In-memory stats (`env:` webhooks) | Inline PII/secret redaction, prompt-injection heuristics, regex/keyword/policy filters, and external callouts |
| `ai-cache` | Buffers cacheable JSON / replays SSE | Stateful (Memory / Redis) | Exact-match SHA-256, streaming SSE replay, singleflight coalescing, and semantic vector caching |
| `ai-token-rate-limit` | Reads parsed request + `AiUsage` | Stateful (Memory / Redis) | Pre-flight token estimation + post-response `AiUsage` reconciliation for RPM/TPM & concurrency caps |
| `ai-budget` | Reads parsed request + `AiUsage` | Stateful (Memory / Redis) | Exact integer nano-USD spend tracking, rolling budgets (key/user/team/org/global), pre-flight reservations & pricing catalogs |
| `ai-provider-adapter` | Translates request JSON + streaming SSE/EventStream | In-memory key-pool & Cloud IAM token cache (`env:`) | 17 presets, 5 dialects, multi-key pools, BYOK passthrough, Cloud IAM (AWS/GCP/Azure), `drop_params` & protocol translation |
| `ai-failover` | Headers + upstream errors | Stateful (Memory / Redis) | Automatic `Flow::RetryUpstream` on `429`/`5xx`/`529`, TTFT timeouts & context overflow with circuit cooldowns |
| `ai-usage-tracker` | Streaming SSE / response inspect | In-memory generation store + Prometheus/OTLP | Token & TTFT extraction across all dialects, Prometheus metrics, OTLP GenAI spans, and `GET /v1/generation` |
| `ai-audit` | Complete (redacted summaries) | Async sink (`env:` webhooks) | Opt-in redacted prompt & completion audit sinks (JSONL, OTLP span events, HMAC-signed HTTP webhooks) |
| `ai-alerts` | Complete | In-memory dedup window (`env:` webhooks) | Non-blocking deduplicated alerts to Slack, PagerDuty, or signed HTTP webhooks |

---

## Key Configuration Snippets

### `ai-virtual-keys`
```toml
[[routes.plugins]]
name = "ai-virtual-keys"
id = "vkeys"
[routes.plugins.config]
strip_key_header = true
accept_bearer = true
accept_x_api_key = true

[[routes.plugins.config.keys]]
id = "prod-app"
api_key = "env:SHUNT_APP_KEY"
org = "acme"
team = "platform"
expires_at = "2028-01-01T00:00:00Z"
allowed_models = ["smart", "fast", "claude-*"]
allowed_providers = ["openai", "anthropic"]
rpm = 120
tpm = 200000
max_parallel_requests = 16
budget_usd = 50.0
budget_soft_limit_usd = 40.0
budget_window = "daily"
[routes.plugins.config.keys.model_limits.smart]
rpm = 30
budget_usd = 25.0
```

### `ai-model-router`
```toml
[[routes.plugins]]
name = "ai-model-router"
id = "router"
[routes.plugins.config]
max_body_bytes = 2097152
auto_max_attempts = true
serve_models_endpoint = true
serve_count_tokens_endpoint = true
include_routing_headers = true
allow_request_routing_overrides = true
enforce_context_window = true
context_window_safety_margin_tokens = 256
use_builtin_pricing = true
# pricing_file = "prices.json"
exposed_models = ["smart", "fast"]

[routes.plugins.config.models.smart]
strategy = "latency" # "priority" | "weighted" | "latency" | "cost" | "throughput" | "headroom"
targets = [
  { provider = "openai", upstream = "openai", model = "gpt-4o", context_window = 128000, capabilities = ["chat", "streaming", "tools", "vision", "json_schema"] },
  { provider = "anthropic", upstream = "anthropic", model = "claude-sonnet-4-20250514", context_window = 200000, capabilities = ["chat", "streaming", "tools", "vision", "reasoning"], zdr = true, regions = ["us", "eu"] },
]

[[routes.plugins.config.rules]]
pattern = "claude-*"
targets = [{ provider = "anthropic", upstream = "anthropic" }]
```

### `ai-provider-adapter`
```toml
[[routes.plugins]]
name = "ai-provider-adapter"
[routes.plugins.config]
response_headers = true

[routes.plugins.config.providers.openai]
preset = "openai"
api_keys = ["env:OPENAI_KEY_1", "env:OPENAI_KEY_2"]
key_cooldown_ms = 30000
drop_params = true

[routes.plugins.config.providers.anthropic]
preset = "anthropic"
api_key = "env:ANTHROPIC_API_KEY"
drop_params = true

[routes.plugins.config.providers.bedrock]
preset = "bedrock"
region = "us-east-1"
auth = { type = "aws_iam", mode = "auto", refresh_margin_secs = 300 }
```

### `ai-guardrails`
```toml
[[routes.plugins]]
name = "ai-guardrails"
[routes.plugins.config]
presets = ["pii", "secrets", "prompt_injection"]
direction = "both" # "request" | "response" | "both"
action = "redact"  # "block" | "redact" | "log"
redaction_mode = "mask"
on_stream_violation = "redact_and_stop"
stream_holdback_chars = 64

[routes.plugins.config.policy]
max_prompt_chars = 65536
max_messages = 64
blocked_roles = ["developer"]
```

### `ai-cache`
```toml
[[routes.plugins]]
name = "ai-cache"
id = "ai-cache"
[routes.plugins.config]
ttl_secs = 600
max_entries = 2048
max_total_bytes = 33554432
max_entry_bytes = 1048576
scope = "virtual_key" # "global" | "virtual_key" | "team"
require_deterministic = true
respect_cache_control = true
emit_headers = true
cache_streaming = true
singleflight = true
singleflight_timeout_ms = 30000
```

### `ai-token-rate-limit`
```toml
[[routes.plugins]]
name = "ai-token-rate-limit"
id = "token-rl"
[routes.plugins.config]
rpm = 60
tpm = 100000
window_secs = 60
max_parallel_requests = 32
key_by = "virtual_key"
reconcile_usage = true
```

### `ai-budget`
```toml
[[routes.plugins]]
name = "ai-budget"
id = "budget"
[routes.plugins.config]
scope = "virtual_key"
default_limit_usd = 25.0
soft_warning_ratio = 0.8
window = "daily" # "hourly" | "daily" | "monthly"
mode = "hard"    # "hard" | "soft"
reject_status = 429
preflight_reserve = true
reserve_output_tokens_cap = 1024
use_builtin_pricing = true
```

### `ai-failover`
```toml
[[routes.plugins]]
name = "ai-failover"
id = "failover"
[routes.plugins.config]
retry_statuses = [429, 500, 502, 503, 504, 529]
cooldown_ms = 30000
failure_threshold = 2
respect_retry_after = true
ttft_timeout_ms = 15000
failover_on_context_overflow = true
```

### `ai-usage-tracker`
```toml
[[routes.plugins]]
name = "ai-usage-tracker"
[routes.plugins.config]
log_usage = true
generation_store_capacity = 4096
serve_generation_endpoint = true
emit_generation_id_header = true
```

### `ai-audit` & `ai-alerts`
```toml
[[routes.plugins]]
name = "ai-audit"
[routes.plugins.config]
include_prompt = true
include_completion = true
redact_pii = true
redact_secrets = true
max_capture_bytes = 32768
sample_rate = 1.0
[routes.plugins.config.jsonl]
path = "./logs/shunt-ai-audit.jsonl"
max_file_bytes = 104857600
[routes.plugins.config.otlp_events]
enabled = true

[[routes.plugins]]
name = "ai-alerts"
[routes.plugins.config]
dedup_window_ms = 60000
events = ["budget_soft_warning", "budget_hard_exceeded", "circuit_breaker_open", "failover_exhausted", "guardrail_block"]
[[routes.plugins.config.targets]]
type = "slack"
name = "ai_ops"
url = "env:SLACK_WEBHOOK_URL"
channel = "#ai-gateway-alerts"
```
