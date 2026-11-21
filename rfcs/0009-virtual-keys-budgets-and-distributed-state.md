# RFC 0009: Virtual Keys, Token Rate Limits, Cost Budgets & Distributed `StateStore`

- **Status:** Implemented
- **Crates:** `shunt-plugin-sdk`, `shunt-core`, `shunt-config`, `shunt-plugins`, `shunt-ai`, `shunt-cli`, `shunt-test`, `fuzz`

## Summary

RFC 0009 delivers Phase A2 of [docs/vision.md](../docs/vision.md) (and unlocks multi-replica state for Path B HTTP gateways) across four composable pieces:

1. **Optional Distributed `StateStore` (`DistributedStore` + Pure-Rust Redis / Valkey Client):** Introduces a general-purpose, AI-agnostic `DistributedStore` trait in `shunt-plugin-sdk` and a zero-external-SDK pooled RESP2 client (`RedisStateStore`, supporting `redis://` and `rediss://` TLS, `AUTH`, `SELECT`, atomic Lua `EVAL`, and warm pool reuse across reloads) in `shunt-core`. In-memory `StateStore` remains the zero-dependency default preserving the zero-allocation sync fast path (`HookResult::Ready`).
2. **Virtual API Keys & Multi-Tenant Policies (`ai-virtual-keys`):** Authenticates scoped client keys (`Authorization: Bearer`, `x-api-key`, or custom header) via constant-time SHA-256 comparison (supporting `env:` secrets and pre-hashed `sha256:` digests), strips client keys before upstream dispatch, and attaches `AiKeyPolicy` (`allowed_models`, `allowed_providers`, `provider_overrides`, per-key RPM/TPM, per-key spend budgets, and `team` tags) to `ctx.extensions`.
3. **Token-Aware Rate Limiting (`ai-token-rate-limit`) & Local Token Estimator:** Enforces RPM and TPM limits with deterministic pre-flight token estimation across OpenAI Chat, Anthropic Messages, OpenAI Responses, and Embeddings (also powering local `POST /v1/messages/count_tokens`), plus post-response reconciliation in `on_complete` against actual `AiUsage`.
4. **Model Pricing Catalog, Cost Attribution & Spend Budgets (`ai-budget`):** Computes exact integer nano-USD spend (`input`, `cached_input`, `output` tokens) using a bundled + overridable pricing catalog, emits `shunt_ai_cost_usd_total` Prometheus metrics, enforces per-key and per-team rolling budgets with soft-warning headers or hard `429`/`402` rejections, and coordinates seamlessly across replicas when `[state] backend = "redis"` is enabled.

## Motivation

Phase A1 (RFCs 0007–0008) made Shunt a universal multi-provider, multi-protocol AI gateway. Running it in production for teams and multi-replica deployments requires four governance and scaling primitives:

- **Credential isolation & access control:** Developers and services should never hold raw OpenAI/Anthropic/AWS keys; teams need scoped virtual keys with model ACLs and per-tenant routing overrides that reload atomically via `ArcSwap`.
- **Token-aware fairness (TPM + RPM):** Request-count limits alone cannot protect upstream provider TPM quotas when one request carries 100k prompt tokens and another carries 20.
- **Cost visibility & hard spend caps:** Teams need real-time USD cost attribution (including discounted cached input tokens) and rolling per-key / per-team budgets before runaway loops exhaust provider accounts.
- **Multi-replica consistency without bloating the default binary:** Running 3+ Shunt instances behind a load balancer requires shared rate limits, budgets, and failover cooldowns via Redis/Valkey, while solo/single-node deployments must still run as a single binary with zero sidecars and zero sync-path overhead.

## Goals & Non-Goals

### Goals
- **Strict architectural isolation:** `shunt-core` and `shunt-plugin-sdk` remain 100% AI-agnostic. `DistributedStore` and `RedisStateStore` expose general-purpose atomic primitives (`try_consume_quota`, `adjust_counter`, `get_counter`, `set_flag`, `has_flag`, `delete`) consumed equally by `shunt-plugins::rate-limit` (Path B) and `shunt-ai` (Path A).
- **Zero-allocation sync fast path preserved:** When `[state] backend = "memory"` (default), `BuildContext::distributed_store()` returns `None` and every plugin hook returns `HookResult::Ready` without boxing or async I/O.
- **Zero heavy SDK dependencies:** Implement RESP2 framing, connection pooling, `rediss://` TLS (reusing existing `tokio-rustls` + `webpki-roots`), and atomic Lua scripts directly in `shunt-core` (~600 lines) with zero new crates in `Cargo.lock`.
- **Exact drift-free cost accounting:** Represent spend in integer **nano-USD** (`1 USD = 1_000_000_000 nano-USD`) so Redis `INCRBY`/Lua and local `u64` ledgers accumulate exact costs with zero floating-point drift.
- **Automatic secret redaction:** Virtual key secrets use the canonical `api_key` field name (redacted automatically in `GET /snapshot`), and raw secrets are hashed to SHA-256 at snapshot compile time so plaintext keys are never retained in memory.
- **Layered verification (RFC 0006):** Back the RESP2 codec, token estimator, pricing math, virtual keys, quotas, budgets, and multi-replica Redis coordination with unit tests, TOML conformance specs (`07-virtual-keys-quotas-budgets.spec.toml`), multi-replica TCP E2E tests, property tests, and a RESP2 fuzz target (`fuzz_resp_parser`).

### Non-Goals
- **Database-backed dynamic key CRUD API inside `shunt`:** Virtual keys, budgets, and pricing tables remain declarative in `shunt.toml` / `ConfigProvider` and reload atomically via `ArcSwap`. Dynamic DB-backed key management belongs in the companion control plane (`shunt-console`, RFC 0014).
- **Heavy BPE vocabulary files (`tiktoken` / SentencePiece) embedded in binary:** Pre-flight estimation uses a fast, deterministic, zero-dependency heuristic calibrated to modern BPE tokenizers and reconciles exact token counts from upstream `AiUsage` in `on_complete`.
- **Redis Cluster / Sentinel topology discovery:** v1 targets standalone / managed Redis & Valkey endpoints (including TLS `rediss://` and ACL auth); Cluster `MOVED` redirection can layer cleanly onto `RedisStateStore` later without changing `DistributedStore`.

---

## Design

### 1. General-Purpose `DistributedStore` Trait (`shunt-plugin-sdk`)

```rust
pub trait DistributedStore: fmt::Debug + Send + Sync + 'static {
    fn backend_name(&self) -> &str;
    fn failure_policy(&self) -> FailurePolicy;

    fn try_consume_quota<'a>(
        &'a self,
        key: &'a str,
        amount: u64,
        limit: u64,
        window: Duration,
    ) -> BoxFuture<'a, Result<QuotaOutcome, DistributedStoreError>>;

    fn adjust_counter<'a>(
        &'a self,
        key: &'a str,
        delta: i64,
        ttl: Duration,
    ) -> BoxFuture<'a, Result<i64, DistributedStoreError>>;

    fn get_counter<'a>(&'a self, key: &'a str) -> BoxFuture<'a, Result<i64, DistributedStoreError>>;
    fn set_flag<'a>(&'a self, key: &'a str, ttl: Duration) -> BoxFuture<'a, Result<(), DistributedStoreError>>;
    fn has_flag<'a>(&'a self, key: &'a str) -> BoxFuture<'a, Result<bool, DistributedStoreError>>;
    fn delete<'a>(&'a self, key: &'a str) -> BoxFuture<'a, Result<(), DistributedStoreError>>;
}
```

- `BuildContext::distributed_store(&self) -> Option<Arc<dyn DistributedStore>>` exposes the active backend during `PluginFactory::build`.
- Gateway-level `[state]` configuration in `shunt.toml` selects `backend = "memory"` (default) or `backend = "redis"` with `url`, optional `username`/`password` (`env:` supported), `key_prefix`, `pool_size`, `connect_timeout_ms`, `command_timeout_ms`, and `failure_policy` (`fail_open` default or `fail_closed`).
- `RuntimeRegistry` caches warm `RedisStateStore` pools keyed by `RedisStoreConfig` (identical to `UpstreamPoolKey` reuse) and only garbage-collects obsolete stores after a snapshot compiles cleanly.

### 2. Pure-Rust Pooled Redis / Valkey Backend (`shunt-core::redis`)

- **Bounded RESP2 codec:** `decode_resp_frame` enforces strict upper bounds on line length (64 KiB), bulk size (16 MiB), array length (4,096), and recursion depth (16), returning `Ok(None)` on partial frames and `Err(RespError)` on malformed wire bytes.
- **Single-round-trip atomic Lua scripts:**
  - `try_consume_quota` atomically checks `current + amount <= limit`, increments via `INCRBY`, sets `PEXPIRE` on new keys, and returns `{allowed, current, remaining, retry_after_secs}` without mutating counters on rejection.
  - `adjust_counter` atomically adds positive or negative `delta` (clamping at `>= 0`) while preserving the existing `PTTL` so post-response token refunds and spend charges never extend or reset windows.
- **Connection pool & recovery:** Semaphore-bounded idle connection pool with `AUTH`/`SELECT` handshake, per-command timeout, and automatic single retry on stale pooled EOF.
- **Consumers across both paths:**
  - `shunt-plugins::rate-limit` (Path B): shares HTTP rate limits across replicas when `[state] backend = "redis"`.
  - `shunt-ai::ai-failover`: shares provider cooldown flags (`set_flag`/`has_flag`/`delete`) across replicas.
  - `shunt-ai::ai-token-rate-limit` & `shunt-ai::ai-budget`: share RPM/TPM windows and nano-USD spend ledgers across replicas.

### 3. Virtual API Keys (`ai-virtual-keys`) & `ai-model-router` Integration

```text
Incoming Request
  │
  ▼  on_request_headers (sync)
[ai-virtual-keys]
  ├─ Extract key: custom_header | Authorization: Bearer | x-api-key
  ├─ Constant-time SHA-256 comparison across compiled keys
  ├─ Reject missing/invalid (401) or disabled (403) in protocol-native JSON
  ├─ Strip client key headers (`strip_key_header = true`)
  └─ Insert `AiKeyPolicy` into `ctx.extensions`
  │
  ▼  on_request_headers / on_request_body_buffered (sync)
[ai-model-router]
  ├─ `GET /v1/models` & `GET /v1/models/{id}` filtered by `AiKeyPolicy::allowed_models`
  ├─ `POST /v1/messages/count_tokens` served locally via `estimate_request_tokens`
  ├─ Enforce `allowed_models` (403), apply `provider_overrides`, filter `allowed_providers`
  └─ Insert `AiRequestMeta`
```

### 4. Token-Aware Rate Limiting (`ai-token-rate-limit`)

- **Pre-flight (`on_request_body_buffered`):**
  - Resolves effective `rpm` and `tpm` (`AiKeyPolicy` override -> plugin default).
  - Estimates input tokens via `shunt_ai::tokens::estimate_request_tokens(endpoint, body)` (plus optional capped `max_tokens` output reservation).
  - Reserves 1 RPM + estimated TPM atomically in local `QuotaWindowTable` (sync `HookResult::Ready`) or `DistributedStore` (async `HookResult::Pending`).
  - Rejects excess traffic with protocol-native `429`, `Retry-After`, and `x-ratelimit-{limit,remaining}-{requests,tokens}` headers.
- **Post-response reconciliation (`on_complete`):**
  - Runs after `ai-usage-tracker` finishes `on_response_body_chunk(..., end_of_stream = true)`.
  - If short-circuited before upstream (`summary.attempts == 0`, e.g., rejected by `ai-budget`), refunds `-1` RPM and `-estimated_tokens` TPM.
  - Otherwise computes `delta = actual_total_tokens - estimated_tokens` from `AiUsage` and applies `adjust` (clamped at `>= 0`).

### 5. Pricing Catalog, Cost Attribution & Spend Budgets (`ai-budget`)

- **Pricing catalog (`shunt-ai::pricing`):**
  - Exact integer nano-USD pricing: `$1.00 / 1M tokens == 1_000 nano-USD / token`.
  - Accounts for `uncached_prompt = prompt_tokens.saturating_sub(cached_prompt_tokens)`, `cached_prompt_tokens` (extracted across OpenAI `prompt_tokens_details.cached_tokens`, Anthropic `cache_read_input_tokens`, Gemini `cachedContentTokenCount`, and Bedrock `cacheReadInputTokens`), and `completion_tokens`.
  - Lookup order: exact user override -> most-specific wildcard user override -> bundled reference catalog (`use_builtin_pricing = true`) -> optional `default_pricing`.
- **Budget enforcement (`ai-budget`):**
  - Evaluates both primary scope (`virtual_key`, `team`, or `global`) and optional `team_budgets.<team>` aggregate budgets in the same pre-flight check.
  - Emits `x-shunt-budget-{limit,spent,remaining}-usd` headers and `x-shunt-budget-warning` when crossing `soft_limit_usd` / `soft_warning_ratio`.
  - Rejects with `429` or `402` (`reject_status`) in `hard` mode, or warns-only in `soft` mode.
  - Charges exact nano-USD in `on_complete` and updates `AiMetrics` (`shunt_ai_cost_usd_total{provider,model,key,team}`).

### 6. Static Verification (`shunt verify`)

`shunt-config/src/verify.rs` extends `ai.plugin_order` to guarantee:
- `ai-virtual-keys` appears before `ai-model-router` (so auth and model ACLs run before routing).
- `ai-token-rate-limit` and `ai-budget` appear after `ai-model-router` (so endpoint/model metadata is populated).

---

## Alternatives Considered & Rejected

### 1. Pulling in an External Redis Crate (`redis-rs` + `deadpool-redis`)
- **Why considered:** Ready-made RESP client with cluster support.
- **Why rejected:** Adds dozens of transitive dependencies and bloat to every build (including single-binary zero-dependency deployments), complicates offline `--locked` verification, and is much heavier than the 6 focused atomic commands `DistributedStore` requires. Building a pure-Rust RESP2 client directly on `tokio` + `tokio-rustls` keeps `Cargo.lock` completely unchanged and mirrors RFC 0007's pure-Rust AWS SigV4/EventStream strategy.

### 2. Floating-Point (`f64` / `INCRBYFLOAT`) Spend Counters
- **Why considered:** Directly matches USD config fields.
- **Why rejected:** Accumulating tiny token costs (`$0.00000125`) in binary floating point causes rounding drift across thousands of requests and complicates atomic integer comparisons in Lua/atomics. Integer nano-USD (`1e-9` USD) is exact for every realistic token price down to `$0.001 / 1M tokens` and supports up to `$9.2B` per window in `i64`.

### 3. Embedding `tiktoken` / BPE Tokenizer Tables in the Gateway Binary
- **Why considered:** Exact pre-flight token counts for OpenAI models.
- **Why rejected:** Adds multi-megabyte vocabulary assets to the binary, still differs across Anthropic/Gemini/Llama tokenizers, and increases pre-flight CPU latency. Fast deterministic text/JSON estimation + exact post-response reconciliation from provider `AiUsage` gives near-zero latency and exact long-run TPM accuracy across every provider.

### 4. Merging `ai-virtual-keys`, `ai-token-rate-limit`, and `ai-budget` into One Monolithic Plugin
- **Why considered:** Fewer `[[routes.plugins]]` blocks in `shunt.toml`.
- **Why rejected:** Violates Shunt's pay-only-for-what-you-use composability (teams should be able to use virtual keys without budgets, or cost attribution without TPM limits, or swap in a custom external auth/policy plugin via `AiKeyPolicy` in `ctx.extensions`).

---

## Verification

- **Unit tests:** RESP2 codec & mock TCP Redis tests (`crates/shunt-core/src/redis.rs`), token estimator (`crates/shunt-ai/src/tokens.rs`), pricing catalog (`crates/shunt-ai/src/pricing.rs`), virtual key SHA-256 matching (`crates/shunt-ai/src/virtual_keys.rs`), local quota reservation/reconciliation (`crates/shunt-ai/src/token_rate_limit.rs`).
- **Conformance spec (`specs/conformance/07-virtual-keys-quotas-budgets.spec.toml`):** Verifies virtual key auth (plaintext, `env:`, `sha256:`, disabled, Anthropic/OpenAI native errors, header stripping, `/snapshot` redaction), model ACLs + `/v1/models` filtering, per-key provider overrides, local `/v1/messages/count_tokens`, RPM/TPM limits + `AiUsage` reconciliation + `ManualClock` reset, cached-token cost attribution (`shunt_ai_cost_usd_total`), soft warnings, hard `402` rejection, reload ledger persistence, and team aggregate budgets.
- **Multi-replica E2E tests (`crates/shunt-ai/tests/distributed_governance_e2e.rs`):** Runs two independent `GatewayServer` replicas backed by a shared in-process TCP mock Redis server, verifying shared HTTP `rate-limit` (Path B), shared `ai-failover` cooldowns, shared `ai-budget` cutoff across replicas, and `fail_open` vs `fail_closed` outage behavior.
- **Property tests:** RESP2 round-trip, prefix invariance, and fuzz-byte panic-freedom in `crates/shunt-core/tests/proptest_core.rs`; token estimator monotonicity/panic-freedom and pricing nano-USD invariants in `crates/shunt-ai/tests/proptest_ai.rs`.
- **Fuzz target:** `fuzz/fuzz_targets/fuzz_resp_parser.rs`.

---

## Future Work

- **RFC 0010:** Smart routing (weighted splits, TTFT/latency-aware, cost-aware routing using RFC 0009's `PricingCatalog`), active upstream health checks, and OpenTelemetry (`OTLP`) HTTP + GenAI tracing.
- **Redis Cluster / Sentinel support:** Optional `MOVED`/`ASK` slot routing inside `RedisStateStore` without changing the `DistributedStore` trait.
- **RFC 0014 (`shunt-console`):** Companion DB-backed management UI for CRUD over virtual keys, budgets, and pricing pushed via `ConfigProvider`.
