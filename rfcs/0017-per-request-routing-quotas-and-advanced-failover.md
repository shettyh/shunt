# RFC 0017: Per-Request Routing, Concurrency Quotas & Advanced Failover

- **Status:** Implemented
- **Crates:** `shunt-plugin-sdk`, `shunt-core`, `shunt-config`, `shunt-ai`, `specs/`, `examples/`, `fuzz/`

## 1. Summary

This RFC completes Phase A4 of Shunt's AI gateway parity roadmap while contributing four general-purpose, strictly AI-free primitives to `shunt-plugin-sdk` and `shunt-core` (which also accelerate Path B API gateway workloads). It introduces:

1. **AI-free Core/SDK primitives:** per-attempt response-headers timeout overrides (`UpstreamSelection::response_headers_timeout_override`), pre-flush conditional response-body inspection (`Flow::InspectResponseBody` + `on_response_body_inspected`), deterministic wall-clock timestamps on `Clock::unix_timestamp_secs`, and route-level fire-and-forget HTTP traffic mirroring (`RouteIr::mirrors`).
2. **OpenRouter-style per-request routing & compliance:** opt-in `models[]` fallback lists and `provider: { order, only, ignore, sort, allow_fallbacks, data_collection, zdr, regions, tags }` overrides, target metadata (`context_window`, `max_output_tokens`, `zdr`, `regions`, `tags`, `upstream_rpm/tpm`, `ttft_timeout_ms`), context-window capability guards, and AI-aware sampled traffic shadowing.
3. **Throughput & headroom routing + advanced failover:** `RoutingStrategy::Throughput` (EWMA output tokens/sec), `RoutingStrategy::Headroom` (live upstream RPM/TPM capacity ratio + response-header feedback), TTFT-timeout failover, and context-overflow error-body failover across OpenAI, Anthropic, Gemini, and Bedrock.
4. **Fine-grained quotas, concurrency & pricing catalogs:** virtual-key `expires_at`, `org` + end-user (`user` / `metadata.user_id`) hierarchy, per-model limits on virtual keys, RAII leak-free `max_parallel_requests` concurrency limits, opt-in pre-flight budget holds with reconciliation, external JSON pricing catalog loading (Shunt & LiteLLM formats), and enriched `GET /v1/models` metadata.

## 2. Motivation

Production teams running shared multi-tenant LLM gateways hit four operational edges that static failover and simple RPM/TPM counters cannot solve alone:

- **Per-request routing & compliance controls:** Applications using OpenRouter SDKs frequently pass per-request `models[]` fallback chains, `provider.order`/`only`/`ignore`/`sort`, or Zero Data Retention (`data_collection: "deny"`) and EU/US region constraints—which must always stay bounded by the tenant's virtual-key ACLs.
- **Slow-provider & context-overflow recovery:** A provider that stalls before sending response headers or returns HTTP 400 (`context_length_exceeded` / `prompt is too long`) forces application retries unless the gateway can enforce per-target TTFT deadlines and inspect small 4xx error bodies pre-flush to fail over to a larger-context fallback.
- **Burst & concurrency protection:** Post-response budget charging allows N concurrent expensive requests to burst past a hard USD budget before `on_complete` runs; similarly, without `max_parallel_requests`, a single tenant can saturate GPU/provider concurrency slots.
- **Live catalog & traffic validation:** Teams need external JSON pricing catalogs (e.g., LiteLLM's `model_prices_and_context_window.json`) reloaded atomically with `shunt.toml`, rich `/v1/models` metadata for client UIs/SDKs, and safe shadow traffic mirroring for evaluating new models or API backends without affecting production latency.

## 3. Goals & Non-Goals

### Goals
- **Zero AI in `shunt-core` and `shunt-plugin-sdk`:** Every transport primitive (timeout override, pre-flush response-body inspection, wall-clock `Clock`, route mirroring) is strictly generic HTTP infrastructure.
- **Pay only for what you use:** Zero heap allocation and zero extra buffering on `200 OK` or routes that do not enable mirroring, body inspection, concurrency quotas, or pre-flight holds.
- **Client overrides can never escalate privileges:** Per-request `models[]` and `provider.*` filters strictly intersect with `AiKeyPolicy::allowed_models` and `allowed_providers`.
- **Leak-free RAII resource guards:** Concurrency leases and pre-flight budget holds release/refund deterministically on normal completion, short-circuit, stream abort, client disconnect, or plugin panic.
- **Zero-dependency single-binary default:** External pricing files are read locally at snapshot compilation time (atomic hot reload, no network dependency on startup).

### Non-Goals
- **Remote background HTTP polling of pricing catalogs:** Fetching third-party GitHub URLs at runtime breaks deterministic air-gapped VPC deployments; teams update a local JSON file via CI/GitOps and let Shunt hot-reload it atomically.
- **Streaming body replay for HTTP mirrors:** Route-level HTTP mirroring clones only buffered bodies (or empty bodies) up to a bounded cap and runs inside a bounded-concurrency detached task pool so slow shadow upstreams can never OOM or stall primary traffic.

## 4. Design

### 4.1 AI-Free Core & SDK Primitives

1. **`UpstreamSelection::response_headers_timeout_override: Option<Duration>`**
   - When set in `on_upstream_select`, `shunt-core::pipeline::execute_request` passes this deadline instead of `route.timeouts.response_headers_timeout` to `pool.send_request(...)`.
   - When `CoreError::ResponseHeadersTimeout` occurs and `attempt < max_attempts && body_is_replayable`, `shunt-core` records `ctx.last_upstream_status = Some(504)` and `ctx.last_upstream_error`, then continues to the next attempt.
2. **`Flow::InspectResponseBody { max_bytes: usize }` & `HookMask::ON_RESPONSE_BODY_INSPECTED`**
   - Valid only from `on_response_headers` when `body_is_replayable` (or pre-flush inspection is desired).
   - When a plugin returns `Flow::InspectResponseBody { max_bytes }`, `shunt-core` reads the upstream response body bounded by `max_bytes` using `collect_body_limited`.
   - If the body fits within `max_bytes`, `shunt-core` invokes `on_response_body_inspected(&mut ctx, &mut res_head, &body)` on plugins with `HookMask::ON_RESPONSE_BODY_INSPECTED`.
   - Returning `Flow::RetryUpstream` (when `attempt < max_attempts && body_is_replayable`) discards the buffered error response and advances the retry loop. Returning `Flow::Respond(resp)` overrides the response. Returning `Flow::Continue` flushes the already-buffered `res_head` + `body` downstream verbatim (with `on_complete` still firing).
   - If the response exceeds `max_bytes`, `shunt-core` skips retry inspection cleanly and returns a safe error or falls through without unbounded memory growth.
3. **`Clock::unix_timestamp_secs(&self) -> u64`**
   - Defaulted method on `Clock` backed by `SystemTime::UNIX_EPOCH` on `SystemClock` and an explicitly settable epoch offset (`set_unix_timestamp_secs`) + elapsed duration on `ManualClock`.
4. **Route-Level HTTP Traffic Mirroring (`TrafficMirrorSpec` / `RouteMirrorIr`)**
   - Configured via `[[routes.mirrors]]` with `upstream`, `sample_rate` (`0.0..=1.0`), `timeout_ms` (default `5000`), `max_in_flight` (default `128`), and optional extra `headers`.
   - Zero overhead when `mirrors` is empty. When active, deterministically samples requests via a lock-free atomic counter, clones the canonical request head + buffered body (when present or empty), acquires a `try_acquire_owned` semaphore permit (dropping excess mirror load silently rather than queueing unbounded memory), and dispatches asynchronously to the target `UpstreamPool` in `tokio::spawn`.

### 4.2 Per-Request Routing Overrides, Compliance Tags & Context-Window Guards

- `TargetSpec` / `AiTarget` gains:
  - `context_window: Option<u64>`
  - `max_output_tokens: Option<u64>`
  - `zdr: bool`
  - `regions: Vec<String>`
  - `tags: Vec<String>`
  - `upstream_rpm: Option<u64>`
  - `upstream_tpm: Option<u64>`
  - `ttft_timeout_ms: Option<u64>`
- `AiModelRouterConfig` gains `allow_request_routing_overrides: bool` (default `false`), `context_window_safety_margin_tokens: u64` (default `0`), `pricing_file: Option<PathBuf>`, and `shadow_targets: Vec<ShadowTargetSpec>`.
- When `allow_request_routing_overrides = true`, `ai-model-router` parses OpenRouter-style `models` (array of strings) and `provider` (`{ order, only, ignore, sort, allow_fallbacks, data_collection, zdr, regions, tags }`), validates every model against `AiKeyPolicy::allows_model`, resolves and deduplicates candidate targets, enforces `allowed_providers` ∩ `only` \ `ignore`, applies `zdr`/`data_collection == "deny"`, `regions`, `tags`, and `context_window` guards, applies `provider.order` or `provider.sort` (`price`/`latency`/`throughput`/`headroom`), truncates to 1 if `allow_fallbacks == false`, and strips top-level `models` & `provider` keys from the outgoing JSON payload in `ai-provider-adapter`.

### 4.3 `Throughput` & `Headroom` Strategies and Advanced Failover

- **`RoutingStrategy::Throughput`:** `TargetThroughputTable` in `StateStore` tracks EWMA output tokens/sec (`completion_tokens / generation_secs`) and EWMA error rate per target, ranking by `ewma_tps / (1.0 + error_penalty_weight * ewma_error_rate)` descending with cold-start & staleness exploration.
- **`RoutingStrategy::Headroom`:** `TargetHeadroomTable` in `StateStore` tracks live rolling per-minute RPM/TPM usage per target and incorporates authoritative upstream `x-ratelimit-remaining-requests` / `x-ratelimit-limit-requests` / `x-ratelimit-remaining-tokens` / `x-ratelimit-limit-tokens` headers, ranking targets by highest remaining capacity ratio `[0.0, 1.0]` descending.
- **TTFT-Timeout Failover:** `ai-model-router` / `ai-failover` sets `selection.response_headers_timeout_override` from `target.ttft_timeout_ms` or `ai-failover.ttft_timeout_ms`. When a retry attempt enters `on_upstream_select` with `ctx.last_upstream_status == Some(504)` (timeout from previous attempt), `ai-failover` records the timeout failure into `FailoverCircuitState`, `AiFailoverHistory`, and alerts.
- **Context-Overflow Failover:** When `failover_on_context_overflow = true` on `ai-failover` and upstream responds `400`/`413`/`422` with attempts remaining, `ai-failover` returns `Flow::InspectResponseBody { max_bytes: 65_536 }`. In `on_response_body_inspected`, it matches canonical context-overflow signatures across OpenAI, Anthropic, Gemini, and Bedrock, marks the failed target's `context_window` as too small for this request (so subsequent attempts skip targets with `context_window <= failed_window`), records a `FailoverEvent`, and returns `Flow::RetryUpstream`.

### 4.4 Fine-Grained Quotas, Concurrency Leases, Key Expiration & Pre-Flight Budget Holds

- **`ai-virtual-keys`:**
  - `expires_at`: RFC 3339 UTC timestamp (parsed with a zero-dependency pure-Rust parser) or Unix seconds integer; checked against `clock.unix_timestamp_secs()` in `on_request_headers` (`401 api_key_expired`).
  - `org: Option<String>` and `max_parallel_requests: Option<u64>`.
  - `model_limits: HashMap<String, ModelLimitOverride>` (exact or glob) supplying per-model `rpm`, `tpm`, `max_parallel_requests`, `budget_usd`, `budget_soft_limit_usd`, `budget_window`.
  - End-user extraction (`user` / `metadata.user_id` / header) stored in `AiEndUser` extension for scoping and telemetry.
- **Concurrency Limiter (`ai-token-rate-limit`):**
  - Enforces default, per-key, per-key+model, and end-user `max_parallel_requests` using a reload-persistent `ConcurrencyTable` (locally) or TTL-leased `DistributedStore` counter (with RAII `ConcurrencyLeaseGuard` stored in `ctx.extensions` that decrements immediately on drop).
- **Pre-Flight Budget Holds (`ai-budget`):**
  - Supports `org_budgets`, `team_budgets`, per-key+model budgets, and optional `end_user_budget_usd`.
  - When `preflight_reserve = true`, estimates max cost upfront (`estimate_request_tokens` + capped `max_tokens`), reserves nano-USD atomically against all active budget scopes before upstream dispatch, stores an RAII `BudgetHoldGuard` (refunding automatically if dropped before reconciliation), and adjusts by `(actual_cost - reserved_cost)` in `on_complete`.

### 4.5 External JSON Pricing Catalogs & Enriched `GET /v1/models`

- `PricingCatalog::load_json_file(path)` parses either Shunt's canonical JSON map or LiteLLM's `model_prices_and_context_window.json` format (converting per-token USD floats to per-1M USD and importing `max_input_tokens` / `max_output_tokens`).
- `GET /v1/models` and `GET /v1/models/{id}` include `context_length`, `max_output_tokens`, `capabilities`, `pricing`, `providers`, `zdr`, and `regions` alongside standard OpenAI fields.

## 5. Alternatives Considered & Rejected

1. **Always buffering 4xx upstream responses in `shunt-core`:** Rejected—forces unnecessary buffering on routes that never inspect error bodies; opt-in `Flow::InspectResponseBody { max_bytes }` preserves zero-copy passthrough everywhere else.
2. **Adding `chrono` or `time` crates just to parse RFC 3339 `expires_at`:** Rejected—a 40-line pure-Rust RFC 3339 UTC timestamp parser (Howard Hinnant's civil-from-days formula) keeps the dependency graph minimal and compile times fast.
3. **Fetching remote pricing JSON over HTTP at startup:** Rejected—breaks single-binary zero-dependency startup and air-gapped VPC deployments; local file loading integrates cleanly with `shunt`'s existing atomic file-watch hot reload.

## 6. Verification

- **Unit tests:** RFC 3339 parser, LiteLLM & Shunt JSON pricing loader, OpenRouter override intersection & security invariants, context-window guard, EWMA throughput & headroom scoring, context-overflow error classifier, RAII concurrency & budget-hold drop guards.
- **Core engine tests:** Per-attempt timeout override failover, pre-flush `Flow::InspectResponseBody` retry & passthrough, and route-level HTTP traffic mirroring.
- **E2E integration tests (`crates/shunt-ai/tests/advanced_routing_and_quotas_e2e.rs`):** Full end-to-end coverage across routing overrides, ZDR/region filters, context-window guards, throughput & headroom routing, AI shadowing, TTFT-timeout failover, context-overflow 400 failover, key expiration, `max_parallel_requests`, per-model quotas, org/end-user budgets, pre-flight holds, external pricing file loading, and enriched `/v1/models`.
- **Property tests (`proptest`):** Security intersection invariant (client `provider.only` never escalates past `allowed_providers`), context-window monotonicity, concurrency lease zero-leak invariant, budget hold+reconcile exactness, and panic-freedom of RFC 3339 / pricing JSON / overflow classifiers.
- **Fuzz target (`fuzz_routing_overrides`):** Untrusted `models[]`/`provider` JSON, context-overflow error bodies, RFC 3339 timestamps, and external pricing JSON.
- **Conformance spec (`specs/conformance/15-advanced-routing-quotas-failover.spec.toml`)** & runnable example (`examples/shunt-ai-advanced-routing.toml`).
