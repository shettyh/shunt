---
title: Governance, Guardrails & Alerts
description: Control multi-tenant LLM spend and safety with virtual keys, RPM/TPM/concurrency limits, nano-USD budgets, inline/external guardrails, redacted audit sinks, and operational alerts.
---

Shunt provides complete multi-tenant AI governance inside the gateway—backed by in-memory state by default or **Redis/Valkey** (`[state] backend = "redis"`) across multiple replicas.

## 1. Virtual API Keys (`ai-virtual-keys`)

Issue scoped virtual keys to apps, developers, or teams without ever exposing upstream provider credentials:

```toml
[[routes.plugins]]
name = "ai-virtual-keys"
id = "vkeys"
[routes.plugins.config]
strip_key_header = true
accept_bearer = true
accept_x_api_key = true

[[routes.plugins.config.keys]]
id = "eng-alice"
api_key = "env:ALICE_VIRTUAL_KEY"
org = "acme"
team = "engineering"
expires_at = "2028-01-01T00:00:00Z"
allowed_models = ["smart", "fast", "claude-*"]
allowed_providers = ["openai", "anthropic"]
rpm = 60
tpm = 100000
max_parallel_requests = 8
budget_usd = 25.0
budget_soft_limit_usd = 20.0
budget_window = "daily"

[routes.plugins.config.keys.model_limits.smart]
rpm = 20
max_parallel_requests = 2
budget_usd = 15.0
```

Keys are verified using constant-time SHA-256 comparison.

## 2. Token-Aware Rate Limits & Concurrency (`ai-token-rate-limit`)

Estimates prompt tokens pre-flight and reconciles actual `AiUsage` tokens in `on_complete`, while tracking RAII in-flight concurrency:

```toml
[[routes.plugins]]
name = "ai-token-rate-limit"
id = "token-rl"
[routes.plugins.config]
rpm = 30
tpm = 50000
window_secs = 60
max_parallel_requests = 32
key_by = "virtual_key"
reconcile_usage = true
```

## 3. Exact Nano-USD Spend Budgets (`ai-budget`)

Tracks exact integer nano-USD spend across virtual keys, end users (`user` field), teams, orgs, and global totals using Shunt's built-in pricing catalog (or an external JSON pricing file, including LiteLLM's `model_prices_and_context_window.json` format):

```toml
[[routes.plugins]]
name = "ai-budget"
id = "budget"
[routes.plugins.config]
scope = "virtual_key"
default_limit_usd = 10.0
soft_warning_ratio = 0.8
window = "daily"          # "hourly" | "daily" | "monthly"
mode = "hard"             # "hard" | "soft"
reject_status = 429       # 429 or 402
preflight_reserve = true  # atomic pre-flight hold before upstream call
use_builtin_pricing = true

[routes.plugins.config.team_budgets.engineering]
limit_usd = 200.0
soft_limit_usd = 160.0
window = "monthly"

[routes.plugins.config.org_budgets.acme]
limit_usd = 1000.0
window = "monthly"
```

## 4. Inline & External Guardrails (`ai-guardrails`)

Protect requests, buffered responses, and **live SSE streams** (with configurable character holdback) using fast built-in detectors plus optional external callouts (**OPA**, **Presidio**, **Lakera Guard**, **AWS Bedrock Guardrails**, **Llama Guard**, or custom HTTP webhooks):

```toml
[[routes.plugins]]
name = "ai-guardrails"
[routes.plugins.config]
presets = ["pii", "secrets", "prompt_injection"]
direction = "both"
action = "redact"                   # "block" | "redact" | "log"
redaction_mode = "mask"
on_stream_violation = "redact_and_stop"
stream_holdback_chars = 64

[routes.plugins.config.policy]
max_prompt_chars = 65536
max_messages = 64
blocked_roles = ["developer"]

[[routes.plugins.config.regex_rules]]
name = "internal_ticket"
pattern = "ACME-[0-9]{4,8}"
direction = "both"
action = "redact"
replacement = "[REDACTED:TICKET]"

[[routes.plugins.config.keyword_rules]]
name = "confidential_codenames"
keywords = ["project_obsidian"]
direction = "request"
action = "block"
message = "Confidential project codename is not permitted in external prompts"
```

## 5. Redacted Audit Sinks (`ai-audit`) & Alerts (`ai-alerts`)

- **`ai-audit`**: Captures PII/secret-redacted prompts and completions asynchronously to **JSONL files** (with size rotation), **OTLP GenAI span events**, or **HMAC-signed HTTP SIEM webhooks**.
- **`ai-alerts`**: Sends non-blocking, deduplicated notifications to **Slack**, **PagerDuty**, or **signed HTTP webhooks** on `budget_soft_warning`, `budget_hard_exceeded`, `circuit_breaker_open`, `failover_exhausted`, and `guardrail_block`.

See `examples/shunt-ai-guardrails-audit-alerts.toml` for a complete copy-paste configuration.
