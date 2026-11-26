# RFC 0025: `shunt-console` — AI Gateway Governance, Virtual Keys & FinOps Ledger

- **Status:** Draft
- **Crates / Directories:** `shunt-ai`, `console/crates/shunt-console-core`, `console/crates/shunt-console-api`, `console/web`
- **Depends On:** [RFC 0023](./0023-shunt-console-architecture-and-control-plane.md), [RFC 0009](./0009-virtual-keys-budgets-and-distributed-state.md), [RFC 0015](./0015-guardrails-audit-and-webhooks.md)

## 1. Summary

This RFC specifies **Pillar C (AI Gateway Governance & FinOps)** of `shunt-console`. It delivers a multi-tenant **Org → Team → User → Virtual Key** control plane synced fleet-wide in ~20–50 ms over Channel 2 (`ai.virtual_keys`, `ai.budgets`, `ai.pricing`), a visual **Provider, Model Alias & Smart-Routing Catalog** covering all 17+ Shunt presets and Cloud IAM bindings, a durable **FinOps Spend Ledger & Cost Attribution Engine** fed by `shunt-ai`'s existing OTLP/audit streams, an interactive **AI Playground**, and a **Guardrails Studio**.

Because virtual keys, budget ceilings, and pricing tables sync over Channel 2 into lock-free `ArcSwap` indices inside `shunt-ai`, developers gain instant self-service key issuance and sub-second revocation with **zero hot-path latency regression** and **zero coupling to topology rollbacks**.

## 2. Motivation

Teams adopting Shunt as a self-hosted replacement for LiteLLM or SaaS AI routers love Shunt's 94× throughput and 65× memory advantage ([RFC 0020](./0020-unified-comprehensive-benchmarks.md)), but enterprise AI platform teams still need day-2 governance workflows that `shunt.toml` alone cannot provide:
- **Self-service virtual key lifecycle:** Developers need to mint scoped API keys with expiry dates, allowed model lists, and dollar caps—and security teams need to rotate keys with zero downtime or revoke a leaked key across every proxy in milliseconds.
- **Durable FinOps & chargeback:** Prometheus counters reset on restart and lose high-cardinality `(org, team, virtual_key, end_user, model, provider)` breakdowns. Finance and engineering leads need durable spend ledgers, budget burn-rate alerts, and visibility into dollars saved by `ai-cache`.
- **Safe experimentation:** Engineers need a Playground to compare routing/failover policies across OpenAI, Anthropic, Gemini, Bedrock, Azure, and local Ollama models, and a sandbox to tune PII/prompt-injection guardrails before enabling them in production.

## 3. Goals & Non-Goals

### Goals
- **Instant fleet-wide virtual key & budget sync (Channel 2):** Mint, update, rotate (with configurable overlap grace window), disable, or revoke virtual keys and budget ceilings across 100% of nodes in ~20–50 ms via `SyncedTable` namespaces (`ai.virtual_keys`, `ai.budgets`, `ai.pricing`). In the Web UI ([RFC 0023 §4.8](./0023-shunt-console-architecture-and-control-plane.md#48-web-console-ux-principles)), these appear as native **Virtual Keys**, **Budgets**, and **Model Pricing** pages marked with an `Instant Sync` badge rather than raw Channel 2 tables.
- **Zero plaintext key storage or transit:** Plaintext virtual keys (`sk-shunt-...`) are displayed once at creation and stored/synced strictly as `sha256:<64-hex>` hashes.
- **Seamless `shunt-ai` integration:** `ai-virtual-keys` and `ai-budget` read an optional `SyncedTable` handle from `BuildContext::synced_table(...)`, rebuilding a pre-indexed `ArcSwap` lookup table on delta updates while preserving exact compatibility with static `shunt.toml` keys.
- **Complete Provider & Model Catalog UI:** Manage all 5 upstream dialects (`openai_compatible`, `anthropic`, `azure_openai`, `gemini`, `bedrock`), 17+ presets, multi-key pools, Cloud IAM bindings, BYOK passthrough, smart-routing policies (`priority`, `weighted`, `latency`, `cost`, `throughput`, `headroom`), failover rules, and cache settings.
- **Durable FinOps Spend Ledger:** Ingest `shunt-ai` OTLP GenAI spans and `ai-audit` records into hourly/daily rollups + detailed attribution records (org, team, key, end-user, model, provider, tags), including `ai-cache` cost savings and burn-rate projections.
- **AI Playground & Guardrails Studio:** Live prompt testing through real cluster routing/guardrails/cache policies, plus inline guardrail payload testing.

### Non-Goals
- **Hosting or billing a public multi-company SaaS model marketplace:** Shunt remains a self-hosted BYOK AI gateway; FinOps focuses on internal cost attribution, budgets, and chargeback reporting.
- **Storing full raw prompt/completion transcripts by default:** To minimize PII exposure and DB bloat, the FinOps ledger records metadata, token counts, nano-USD costs, and SHA-256 fingerprints by default; payload logging remains strictly opt-in via [RFC 0027](./0027-shunt-console-observability-and-audit.md).

## 4. Design

### 4.1 Data-Plane Integration (`shunt-ai` + Channel 2 `SyncedTable`)

`ai-virtual-keys` and `ai-budget` opt into Channel 2 via a single optional config field (`sync_namespace`, auto-populated by `ConsoleCompiler`):

```toml
# Compiled automatically by shunt-console into Channel 1 Topology:
[[routes.plugins]]
name = "ai-virtual-keys"
[routes.plugins.config]
sync_namespace = "ai.virtual_keys"   # Static `keys = [...]` still supported & merged if present
strip_key_header = true
```

#### Channel 2 Namespaces Owned by `shunt-ai`

1. **`ai.virtual_keys`** — keyed by `key_id` (e.g. `"vk_01J..."`):
   ```json
   {
     "id": "vk_01J...",
     "key_hashes": [
       "sha256:4a7f...",
       "sha256:9c12..."
     ],
     "org": "acme-eng",
     "team": "search-ml",
     "owner": "alice@acme.com",
     "enabled": true,
     "expires_at": 1798761600,
     "allowed_models": ["gpt-4o*", "claude-sonnet-*"],
     "allowed_providers": ["openai-prod", "anthropic-prod"],
     "rpm": 120,
     "tpm": 250000,
     "max_parallel_requests": 16,
     "budget_usd": 500.0,
     "budget_soft_limit_usd": 400.0,
     "budget_window": "monthly",
     "model_limits": { "o3": { "budget_usd": 100.0, "rpm": 10 } },
     "metadata": { "cost_center": "CC-410", "env": "prod" }
   }
   ```
   - **Zero-downtime key rotation:** Supporting `key_hashes: Vec<String>` lets `shunt-console` issue a replacement secret while keeping the previous hash active for a configurable grace period (e.g., 24 hours), then automatically emitting a delta removing the old hash when the grace window expires.
   - **Hot-path lookup:** On every `ai.virtual_keys` delta, the plugin's subscriber callback rebuilds an `Arc<HashMap<[u8; 32], Arc<AiKeyPolicy>>>` and swaps it atomically via `ArcSwap`. Request-path authentication remains a single constant-time SHA-256 hash + lock-free map lookup.

2. **`ai.budgets`** — keyed by `"org:<slug>"` or `"team:<org>/<slug>"`:
   - Holds org-level and team-level `limit_usd`, `soft_limit_usd`, `window`, and `mode` (`hard` | `soft`), applied dynamically by `ai-budget` without reloading topology.

3. **`ai.pricing`** — keyed by model/glob (e.g. `"gpt-4o"`, `"claude-sonnet-4-*"`):
   - Holds live `ModelPricing` overrides (input/output/cached/reasoning USD per 1M tokens) so operators can update provider pricing tables immediately across the fleet without cutting a topology revision.

### 4.2 Virtual Key, Org & Team Governance UX

- **Hierarchical guardrails:** An `OrgAdmin` sets org-wide hard budget caps and allowed provider lists; a `TeamLead` allocates team sub-budgets and model allowlists; a `Developer` can self-serve personal keys strictly bounded by their team's ceilings (`key.budget_usd <= team.max_key_budget_usd` and `key.allowed_models ⊆ team.allowed_models`).
- **One-click emergency revocation:** Clicking **Revoke** sets `enabled = false` (or deletes the entry), appends a `DELETE` event to `control_events`, and propagates to all cluster nodes in ~20–50 ms—displaying live convergence confirmation (`12/12 nodes revoked`) using node heartbeat `synced_seqs`.
- **Optional `DistributedStore` (Redis/Valkey) Bridge:** When a cluster is configured with Redis for cross-node spend enforcement, `shunt-console` can optionally connect to the same Redis cluster to display **real-time exact in-window spend** (including active pre-flight holds) and provide an audited **"Reset / Top-Up Current Window"** operator action.

### 4.3 Provider Vault, Model Alias & Smart-Routing Studio

- **Provider Wizard:** Guided creation for all 17+ presets (OpenAI, Anthropic, Azure OpenAI, Gemini AI Studio/Vertex, AWS Bedrock, Groq, Together, Fireworks, DeepSeek, Mistral, Cohere, xAI, OpenRouter, Ollama, vLLM, etc.), binding API keys or Cloud IAM roles (`aws_iam`, `gcp_iam`, `azure_entra`) via Secrets Vault ([RFC 0023](./0023-shunt-console-architecture-and-control-plane.md)).
- **Multi-Key Pool Health:** Visual table of every key inside a provider pool showing weight, cooldown status, recent 429/5xx rates, and one-click key drain/disable.
- **Virtual Model & Fallback Designer:** Visual chain builder mapping a logical model alias (e.g., `prod-reasoning`) to ordered or smart-routed targets (`anthropic/claude-sonnet-4` → fallback `bedrock/claude-sonnet-4` → fallback `openai/gpt-4o`), configuring strategy (`priority`, `weighted`, `latency`, `cost`, `throughput`, `headroom`), TTFT timeout failover, context-overflow fallback, and capability guards (`vision`, `tools`, `json_schema`).
- **Pricing Catalog Sync:** Built-in Shunt pricing table + one-click import from external JSON catalogs (Shunt or LiteLLM format) + custom per-model overrides synced over Channel 2 (`ai.pricing`).

### 4.4 FinOps Spend Ledger & Analytics

Data planes export completion telemetry via existing `otel-trace` (`gen_ai.*` attributes) and/or `ai-audit` sinks pointing at `shunt-console`'s `/ingest/v1/traces` and `/ingest/v1/audit` endpoints ([RFC 0027](./0027-shunt-console-observability-and-audit.md)).

#### Storage Model (SQLite / Postgres)
- **`ai_usage_events` (bounded retention, e.g. 30–90 days):**
  `(ts, cluster_id, trace_id, request_id, org_id, team_id, key_id, end_user, endpoint_kind, model_requested, model_served, provider_id, status_code, input_tokens, output_tokens, cached_tokens, reasoning_tokens, cost_nano_usd, saved_cost_nano_usd, ttft_ms, total_ms, cache_status, failover_count, guardrail_action, tags_json)`
- **`ai_spend_rollups_hourly` & `ai_spend_rollups_daily` (long-term retention, years):**
  Pre-aggregated by `(bucket_ts, cluster_id, org_id, team_id, key_id, model_served, provider_id)` tracking `request_count`, `error_count`, `cache_hits`, `input_tokens`, `output_tokens`, `cached_tokens`, `cost_nano_usd`, `saved_cost_nano_usd`, and latency quantiles (`p50`, `p95`, `p99`).
  - Storing exact integer **`cost_nano_usd` (`i64`)** matches `shunt-ai`'s canonical nano-USD accounting ([RFC 0009](./0009-virtual-keys-budgets-and-distributed-state.md)), preventing floating-point drift across millions of requests.

#### FinOps Dashboards & Alerts
- **Executive & Team Views:** Spend over time, top models/providers/teams/keys, token efficiency (prompt vs. completion vs. cached ratio), **Cache ROI** (`saved_cost_nano_usd` from exact/streaming/semantic `ai-cache`), and end-of-month burn-rate forecast.
- **Budget & Anomaly Alerts:** Trigger Slack, PagerDuty, email, or webhook alerts on soft-limit crossing (e.g. 80%), hard-limit denials, provider failover storms, or sudden spend spikes (`>3×` rolling 7-day baseline).
- **CSV / JSON Chargeback Exports:** Filtered by billing period, org, team, and `metadata` cost-center tags.

### 4.5 AI Playground & Guardrails Studio

- **AI Playground:**
  - Interactive chat / responses / embeddings / multimodal workbench that sends requests through a real target `shunt` cluster using a chosen virtual key (or ephemeral playground test key).
  - Side-by-side **Model / Policy Comparison Mode** (run the same prompt against two model aliases or routing policies).
  - Inline **Execution Inspector** next to every response: selected provider/model, failover attempts, `ai-cache` status, TTFT & tokens/sec, exact nano-USD cost, and triggered guardrail detections.
- **Guardrails Studio:**
  - Visual configuration for `ai-guardrails` ([RFC 0015](./0015-guardrails-audit-and-webhooks.md)): built-in PII & secret detectors (SSN, credit cards, API keys, emails), prompt-injection rules, action per rule (`block`, `redact`, `log_only`), and external guardrail connectors (OPA, Presidio, Lakera, Bedrock Guardrails, Llama Guard).
  - **Live Sandbox Tester (`POST /api/v1/clusters/{cluster}/ai/guardrails:test`):** Runs `shunt-ai`'s actual inline guardrail engine in-process against sample input/output text to preview matches, redactions, and block decisions before publishing.

### 4.6 REST API Endpoints (Summary)

- `GET|PUT|DELETE /api/v1/orgs/{org}/teams/{team}`
- `GET|POST /api/v1/orgs/{org}/virtual-keys`, `GET|PATCH|DELETE /api/v1/orgs/{org}/virtual-keys/{key_id}`
- `POST /api/v1/orgs/{org}/virtual-keys/{key_id}:rotate` (returns new plaintext secret once + sets grace expiry)
- `POST /api/v1/orgs/{org}/virtual-keys/{key_id}:revoke` (immediate Channel 2 `DELETE`)
- `GET|PUT|DELETE /api/v1/clusters/{cluster}/ai/{providers|models|routing|guardrails|cache}/{slug}`
- `GET|PUT /api/v1/clusters/{cluster}/ai/pricing` (writes Channel 2 `ai.pricing`)
- `GET /api/v1/orgs/{org}/finops/summary`, `/timeseries`, `/breakdown`, `/export.csv`
- `POST /api/v1/clusters/{cluster}/ai/guardrails:test`

## 5. Alternatives Considered & Rejected

1. **Enforcing AI budgets centrally inside `shunt-console` on every LLM request:**
   - *Rejected:* Putting `shunt-console` in the synchronous LLM request path introduces a single point of failure and adds network latency. Enforcement stays inside `shunt-ai` (`StateStore` / optional Redis `DistributedStore`) using ceilings synced over Channel 2, while `shunt-console` provides durable FinOps analytics and live limit updates.
2. **Storing encrypted virtual keys so admins can "reveal" them again later:**
   - *Rejected:* Unnecessary credential exposure. Hashing with SHA-256 on creation + supporting zero-downtime grace-window rotation is strictly safer and means plaintext virtual keys never exist in the database or on the Channel 2 wire.
3. **Querying Prometheus as the FinOps spend ledger:**
   - *Rejected:* Prometheus cannot safely hold high-cardinality labels like `key_id` + `end_user` + `cost_center` across thousands of keys without TSDB cardinality explosion, and lacks exact billing-period accounting. Dedicated SQL rollups using exact `cost_nano_usd` integers are both accurate and compact.

## 6. Verification Strategy

- **Channel 2 Virtual Key Sync Tests:** Integration tests verifying key creation, grace-window dual-hash rotation, immediate revocation across multiple `shunt` nodes, and hot-path invariance during simultaneous Channel 1 topology rollbacks.
- **FinOps Accounting Property Tests:** Verify exact `cost_nano_usd` conservation (`sum(hourly_rollups) == sum(raw_events)`) with zero floating-point rounding drift and accurate `saved_cost_nano_usd` attribution on cache hits.
- **RBAC Boundary Tests:** Verify `Developer` users cannot mint keys exceeding their team's `max_key_budget_usd` or `allowed_models`, and cannot view another team's spend or keys.
- **Guardrails Sandbox Parity Tests:** Verify `POST /ai/guardrails:test` produces identical redaction/block outputs to live `shunt-ai` request processing.

## 7. Future Work

- **Automated Provider Key Health Rotation:** Automatically disable failing keys in a multi-key pool and alert owners when upstream returns persistent `401`/`403`.
- **Prompt Template & Eval Registry (Optional):** Lightweight versioned system-prompt variables and regression eval runs against model routing changes.
- **Chargeback Integrations:** Scheduled webhook/export connectors for Stripe internal metering, Snowflake, and BigQuery.
