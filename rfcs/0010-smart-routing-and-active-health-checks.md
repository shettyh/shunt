# RFC 0010: Smart Routing & Active Upstream Health Checks

- **Status:** Implemented
- **Crates:** `shunt-core`, `shunt-config`, `shunt-ai`, `shunt-cli`, `shunt-test`

## Summary

RFC 0010 delivers the first half of Phase A3 and core Path B1 traffic-management primitives from [docs/vision.md](../docs/vision.md) across two strictly isolated layers:

1. **Weighted Upstream Pools & Active Health Checks (`shunt-core`, `shunt-config`, 100% AI-agnostic):**
   - Adds per-endpoint `weight` support to `UpstreamConfig` / `UpstreamPool` using a precomputed, lock-free Smooth Weighted Round-Robin (SWRR) schedule composed with Shunt's 3-pass health-preferring selector.
   - Adds optional background **active HTTP and TCP health probes** (`[upstreams.health_check]`) managed by a reload-safe `ProbeSupervisor` bound to `GatewayServer`, with atomic active+passive health composition, `GET /upstreams` admin visibility, and Prometheus health/probe metrics.
2. **Smart AI Routing Strategies & Capability Guards (`shunt-ai`, 100% plugin-side via `shunt-plugin-sdk`):**
   - Expands `ai-model-router` with four composable routing strategies—`priority` (default), `weighted` (smooth canary/A-B splits), `latency` (EWMA TTFT/latency & error-rate-aware ranking), and `cost` (estimated nano-USD ranking via RFC 0009's `PricingCatalog`)—configurable globally or per model/rule.
   - Adds automatic multi-protocol **capability detection & guards** (`chat`, `streaming`, `tools`, `vision`, `json_schema`, `reasoning`, `embeddings`) across OpenAI Chat, Anthropic Messages, OpenAI Responses, and Embeddings so requests never route or fail over to incapable targets.

## Motivation

With Phase A1 (universal providers & multi-protocol ingress) and Phase A2 (virtual keys, TPM/RPM quotas, cost budgets, Redis `StateStore`) shipped, production AI and HTTP deployments hit two operational bottlenecks:

- **Static failover leaves performance, cost, and safety on the table:**
  - Teams rolling out new models or local vLLM/SGLang clusters need deterministic **weighted canary splits** (e.g., 90% primary / 10% canary) without external load balancers.
  - Cloud LLM latency varies dramatically by region and time of day; static priority order keeps sending traffic to a sluggish 4-second provider when a 300ms alternate is available.
  - Multi-provider aliases with different pricing benefit from **cost-aware routing** that picks the cheapest capable model first and only fails over to pricier tiers on `429`/`5xx`.
  - Without **capability guards**, a multimodal vision request, tool-calling loop, or strict `json_schema` request can silently fail over to a cheaper/local fallback model that rejects images or tools.
- **Passive-only health tracking cannot proactively eject or recover endpoints:**
  - Local inference fleets (vLLM, Ollama, SGLang) and Path B HTTP microservices often become unready during model loading or OOM restarts before client traffic hits them.
  - Active background HTTP/TCP probes eject unhealthy nodes *before* user requests suffer timeouts and re-admit recovered nodes immediately once healthy probes pass.

## Goals & Non-Goals

### Goals
- **Strict architectural isolation:** Zero AI concepts in `shunt-core` or `shunt-plugin-sdk`. Weighted upstream pools, active HTTP/TCP probes, `ProbeSupervisor`, and `GET /upstreams` serve Path A and Path B identically.
- **Pay only for what you use:**
  - Uniform-weight upstreams keep the zero-allocation modulo round-robin fast path; weighted upstreams use a lock-free `AtomicUsize` index over a precomputed SWRR schedule.
  - Upstreams without `health_check` spawn zero background tasks.
  - `ai-model-router` only sets `HookMask::ON_COMPLETE` when at least one model/rule uses `latency` strategy, and only sets `HookMask::ON_RESPONSE_HEADERS` when `include_routing_headers = true`.
- **Zero network side effects during compile/check/verify:** `SnapshotBuilder::build` and `SnapshotCompiler::compile` never spawn probe tasks; only a running `GatewayServer` supervises probes via `ProbeSupervisor`.
- **Reload-safe lifecycle:** `ActiveHealthCheckConfig` and endpoint weights are part of `UpstreamPoolKey`. Unchanged upstreams preserve their warm connections, active probe task, and health state across hot reloads; modified or removed upstreams cancel obsolete probe tasks immediately on atomic swap.
- **Zero new external dependencies:** Active HTTP probes reuse `UpstreamPool`'s existing `hyper` + `rustls` connector; TCP probes use `tokio::net::TcpStream` directly.

### Non-Goals
- **OpenTelemetry (`OTLP`) tracing & Grafana dashboards:** Deferred to RFC 0011 to keep RFC 0010 focused and independently verifiable.
- **Prompt/response caching (`ai-cache`) & external guardrails:** Deferred to RFC 0011+.
- **Traffic mirroring / shadowing (async body duplication):** Deferred to Path B traffic-mirroring work.
- **Distributed cross-replica EWMA latency synchronization:** Latency/TTFT EWMA is intentionally local per Shunt replica (reflecting that replica's actual network path and regional RTT to providers) and stored in `StateStore` so it survives local hot reloads.

---

## Design

### 1. Weighted Upstream Pools (`shunt-core`, `shunt-config`)

#### Canonical Types & Config Schema
In `shunt-core`:
```rust
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct UpstreamEndpoint {
    pub url: String,
    /// Relative selection weight (>= 1).
    pub weight: u32,
}
```
In `shunt.toml` (`shunt-config::UpstreamEndpointIr`), each entry in `upstreams[].endpoints` accepts either a bare URL string (weight `1`) or an explicit `{ url, weight }` table:
```toml
[[upstreams]]
name = "inference_pool"
endpoints = [
  { url = "http://10.0.0.1:8000", weight = 80 },
  { url = "http://10.0.0.2:8000", weight = 20 },
]
```

#### Lock-Free Smooth Weighted Round-Robin (SWRR) + 3-Pass Health Selection
- At `UpstreamPool` construction time:
  - If all endpoints have equal weight (`uniform`), `schedule` is empty and selection uses the existing `rr_cursor % len` fast path.
  - Otherwise, weights are reduced by their GCD. When the reduced sum `W <= 4096`, Nginx's Smooth Weighted Round-Robin algorithm runs **once at build time** to produce a `Vec<usize>` schedule of length `W` (e.g., `[80, 20]` → GCD `20` → `[4, 1]` → `[0, 0, 1, 0, 0]`). When `W > 4096`, selection falls back to deterministic cumulative-weight selection.
- On the hot path (`UpstreamPool::select_endpoint(&self, tried_indices)`):
  1. Advance `cursor = self.rr_cursor.fetch_add(1, Ordering::Relaxed)` (single lock-free atomic op).
  2. Fast path: check `idx = schedule[cursor % schedule.len()]`. If `!tried_indices.contains(&idx) && endpoints[idx].is_healthy(now)`, return `(idx, &endpoints[idx])` immediately (O(1), zero locks, zero allocations).
  3. Fallback passes preserving Shunt's 3-pass health optimality invariant:
     - **Pass 1:** First healthy & untried endpoint scanning forward in the smooth schedule from `cursor % schedule.len()` (preserving proportional weights across remaining healthy endpoints).
     - **Pass 2:** First untried endpoint scanning forward in the schedule.
     - **Pass 3:** First healthy endpoint scanning forward in the schedule, else `schedule[cursor % schedule.len()]`.

---

### 2. Active Upstream Health Checks (`shunt-core`, `shunt-config`)

#### Configuration Schema
```toml
[[upstreams]]
name = "vllm_cluster"
endpoints = [
  { url = "http://10.0.0.1:8000", weight = 70 },
  { url = "http://10.0.0.2:8000", weight = 30 },
]

[upstreams.health_check]
kind = "http"                # "http" (default) | "tcp"
path = "/health"             # HTTP only (default: "/health")
method = "GET"               # HTTP only (default: "GET")
expected_statuses = [200]    # HTTP only (default: [200])
headers = { accept = "application/json" }
interval_ms = 5000           # Probe interval (default: 10000)
timeout_ms = 1000            # Per-probe timeout (default: 2000)
unhealthy_threshold = 2      # Consecutive failures to eject (default: 2)
healthy_threshold = 1        # Consecutive successes to recover (default: 1)
initial_healthy = true       # Initial active health before first probe (default: true)
```

#### Atomic Active + Passive Health Composition
`EndpointState` keeps its single-word atomic passive health (`AtomicU64` packing `(consecutive_failures: u16, unhealthy_until_ms: u48)`) and adds atomic active health fields:
- `active_healthy: AtomicBool` (initialized to `initial_healthy`, or `true` when active probes are disabled)
- `active_consecutive_failures: AtomicU32`
- `active_consecutive_successes: AtomicU32`
- `active_probes_ok: AtomicU64`
- `active_probes_err: AtomicU64`
- `last_probe_latency_us: AtomicU64`

Hot-path health check:
```rust
pub fn is_healthy(&self, now_ms: u64) -> bool {
    self.is_active_healthy() && self.is_passively_healthy(now_ms)
}
```
Probe transition rules (`EndpointState::record_active_probe(ok, latency_us, unhealthy_threshold, healthy_threshold)`):
- On probe **success**: reset `active_consecutive_failures = 0`, increment `active_consecutive_successes` and `active_probes_ok`. Once `active_consecutive_successes >= healthy_threshold`, store `active_healthy = true` and call `record_success()` to clear any passive cooldown for immediate recovery.
- On probe **failure**: reset `active_consecutive_successes = 0`, increment `active_consecutive_failures` and `active_probes_err`. Once `active_consecutive_failures >= unhealthy_threshold`, store `active_healthy = false`.

#### Reload-Safe `ProbeSupervisor` Lifecycle
```text
GatewayServer::bind(initial_snapshot)
  └─ ProbeSupervisor::reconcile(&initial_snapshot)
       ├─ Spawns 1 background task per pool_id with active_health_check.is_some()
       └─ Runs initial probe pass promptly, then sleeps `interval` per cycle

ServerReloader::swap_snapshot(next_snapshot)
  └─ ProbeSupervisor::reconcile(&next_snapshot)
       ├─ Unchanged pool_id  ──► task keeps running untouched (health state preserved)
       ├─ New pool_id        ──► spawns probe task
       └─ Removed pool_id    ──► signals watch::Sender(true) & aborts/removes task

ServerHandle::shutdown()
  └─ ProbeSupervisor::shutdown_all()  ──► cancels & joins all probe tasks cleanly
```
- `SnapshotBuilder::build` and `SnapshotCompiler::compile` never spawn background tasks, so `shunt check`, `shunt verify`, and synchronous unit tests remain 100% offline.
- `UpstreamPool::probe_endpoint_once(&self, idx: usize) -> bool` executes a single HTTP or TCP probe directly (reusing the pool's TLS & HTTP connector) for deterministic testing and background loops.

#### Admin & Prometheus Visibility
- **`GET /upstreams` (Admin API):** Reads live atomic state from `reloader.current_snapshot()` without locking the hot path, returning per-upstream `pool_id`, `active_health_check`, and per-endpoint `{ url, weight, healthy, active_healthy, passive_healthy, passive_failures, active_probes_ok, active_probes_err, last_probe_latency_us }`.
- **Prometheus (`GET /metrics`):** `GatewaySnapshot::render_upstream_health_prometheus()` renders:
  - `shunt_upstream_endpoint_healthy{upstream="...",endpoint="..."}` (`1` or `0`)
  - `shunt_upstream_active_probes_total{upstream="...",endpoint="...",result="success|failure"}`

---

### 3. Capability Detection & Guards (`shunt-ai`)

`AiCapability` expands to:
`Chat | Streaming | Tools | Vision | JsonSchema | Reasoning | Embeddings`.

In `ai-model-router::on_request_body_buffered`, `detect_required_capabilities(endpoint, &json_value)` inspects the parsed request JSON across all supported ingress protocols:

| Capability | Detection Rule |
| --- | --- |
| `Embeddings` | Endpoint is `AiEndpointKind::Embeddings` |
| `Chat` | Endpoint is `ChatCompletions`, `AnthropicMessages`, or `OpenAiResponses` |
| `Streaming` | `stream == true` on a conversational endpoint |
| `Tools` | Non-empty `tools` array (Chat/Anthropic/Responses) or non-empty `functions` array |
| `Vision` | Message/input content blocks containing `type` in `{"image_url", "input_image", "image"}` |
| `JsonSchema` | `response_format.type` (Chat) or `text.format.type` (Responses) in `{"json_schema", "json_object"}` |
| `Reasoning` | Non-null `reasoning_effort`, `reasoning.effort`, or Anthropic `thinking.type == "enabled"` |

Filtering semantics:
- A target with `capabilities = []` (omitted) is treated as unrestricted (supports all capabilities) to keep simple configs ergonomic.
- A target with an explicit `capabilities` list is retained iff it supports **every** required capability detected on the request.
- Because filtering occurs before populating `AiRequestMeta.targets`, both primary selection and `ai-failover` retries automatically respect capability guards.
- If zero targets remain after capability filtering, `ai-model-router` responds with protocol-native `400 Bad Request` (`code = "unsupported_capability"`) listing the required capabilities.

---

### 4. Smart Routing Strategies in `ai-model-router` (`shunt-ai`)

#### Configuration Schema
`ai-model-router` adds `strategy` (default `"priority"`), optional per-model `{ strategy, targets }` tables (alongside the compact target-array shorthand), `weight` on each target (default `1`), `latency` tuning options, `pricing` overrides, and optional `include_routing_headers`:

```toml
[[routes.plugins]]
name = "ai-model-router"
id = "smart-router"
[routes.plugins.config]
strategy = "priority"                # Router default: priority | weighted | latency | cost
include_routing_headers = false      # Optional x-shunt-routing-strategy / selected provider headers
use_builtin_pricing = true           # Used by `cost` strategy (RFC 0009 PricingCatalog)
unknown_cost_policy = "last"         # "last" (default) | "free"

[routes.plugins.config.latency]
ewma_alpha = 0.3                     # Smoothing factor in (0.0, 1.0] (default: 0.3)
error_penalty_weight = 5.0           # Multiplier on EWMA error rate (default: 5.0)
min_samples = 1                      # Exploration samples per target before pure EWMA ranking
stale_after_ms = 60000               # Re-explore targets with no observations within this window

[routes.plugins.config.models.canary]
strategy = "weighted"
targets = [
  { provider = "anthropic", upstream = "anthropic", model = "claude-sonnet-4-20250514", weight = 90, capabilities = ["chat", "streaming", "tools", "vision"] },
  { provider = "local_vllm", upstream = "vllm", model = "qwen-2.5-72b", weight = 10, capabilities = ["chat", "streaming", "tools"] },
]

[routes.plugins.config.models.fastest]
strategy = "latency"
targets = [
  { provider = "openai", upstream = "openai", model = "gpt-4o-mini" },
  { provider = "gemini", upstream = "gemini", model = "gemini-2.5-flash" },
]

[routes.plugins.config.models.cheapest]
strategy = "cost"
targets = [
  { provider = "openai", upstream = "openai", model = "gpt-4o" },
  { provider = "openai", upstream = "openai", model = "gpt-4o-mini" },
  { provider = "gemini", upstream = "gemini", model = "gemini-2.0-flash" },
]
```

#### Strategy Semantics
1. **`priority` (default):** Preserves configured target order verbatim. Zero extra state or hooks.
2. **`weighted`:**
   - Uses a `StateStore`-backed atomic cursor per route/group (`WeightedCursorTable`) and smooth weighted round-robin to select the primary target proportionally to `weight`.
   - Orders remaining eligible targets in weight-descending smooth order behind the primary so `ai-failover` never retries the failed primary first.
3. **`latency`:**
   - Uses a `StateStore`-backed `TargetLatencyTable` keyed by `(provider, upstream, model)` (survives snapshot reloads).
   - `ai-model-router` enables `HookMask::ON_COMPLETE` **only** when at least one model, rule, or default uses `latency`.
   - In `on_complete`:
     - Records each failed attempt in `AiFailoverHistory` as an error observation (`ewma_error_rate` rises toward `1.0`).
     - Records the final served target's latency sample from `AiUsage::first_token_at` (true TTFT when `ai-usage-tracker` is present) → `RequestSummary::ttfb` → `RequestSummary::total_duration`, and updates `ewma_latency_ms` and `ewma_error_rate` using `alpha`.
   - Ranking algorithm:
     - Targets with `samples < min_samples` or stale (`now - last_updated >= stale_after_ms`) are prioritized for exploration (rotating deterministically via an atomic cursor so cold-start traffic spreads across all candidates).
     - Measured targets are sorted ascending by `score = ewma_latency_ms * (1.0 + error_penalty_weight * ewma_error_rate)`.
     - Ties break by configured target order.
4. **`cost`:**
   - Estimates input tokens via `shunt_ai::tokens::estimate_request_tokens(endpoint, body)` and output tokens (`max_tokens` capped to `estimated_output_tokens`, or `estimated_output_tokens` default `256` when `max_tokens` is absent; `0` for embeddings).
   - Evaluates `PricingCatalog::lookup(&target.model, &requested_model)` to compute exact integer `cost_nano_usd`.
   - Targets without pricing receive `u64::MAX` (`unknown_cost_policy = "last"`) or `0` (`"free"`).
   - Sorts eligible targets ascending by estimated `cost_nano_usd` (ties break by config order), giving cheapest-first routing with automatic failover to the next-cheapest target.

---

### 5. Static Verification (`shunt verify`)

- `upstream.health_check_timeout`: emits a warning when an upstream's `health_check.timeout_ms >= health_check.interval_ms`.
- `extract_ai_target_chains` in `shunt-config/src/verify.rs` supports both array shorthand (`models.<alias> = [...]`) and structured form (`models.<alias> = { strategy = "...", targets = [...] }`) so `ai.unknown_upstream`, `ai.unknown_provider`, and `ai.attempts_insufficient` remain 100% accurate.

---

## Alternatives Considered & Rejected

### 1. Mutex-Protected Nginx SWRR on Every Request
- **Why considered:** Textbook SWRR mutates `current_weight` per endpoint on every request.
- **Why rejected:** Introduces lock contention or CAS loops across all endpoints on the hot path, regressing Shunt's lock-free `shunt-core` throughput. Precomputing the GCD-reduced smooth schedule at pool construction time achieves identical smooth interleaving with a single `AtomicUsize::fetch_add(1)` on the fast path.

### 2. Spawning Active Health Probe Tasks Inside `SnapshotBuilder::build`
- **Why considered:** Self-contained inside `UpstreamPool::new`.
- **Why rejected:** `shunt check`, `shunt verify`, and synchronous unit tests call `SnapshotBuilder::build` / `SnapshotCompiler::compile` without running a server (or even without a Tokio runtime). Spawning network probes during config validation would cause unexpected outbound connections and leaked tasks. Driving probes via `GatewayServer`'s `ProbeSupervisor` keeps compilation pure and makes reload/shutdown cancellation exact.

### 3. Adding AI-Specific Strategy Hooks Into `shunt-core`
- **Why considered:** Core could inspect model pricing or TTFT directly.
- **Why rejected:** Violates Shunt's foundational invariant (*zero AI in `shunt-core`*). Keeping weighted pools and active HTTP/TCP probes AI-agnostic in `shunt-core` while building weighted/latency/cost/capability AI routing inside `shunt-ai` proves `shunt-plugin-sdk`'s composability and immediately benefits Path B HTTP gateways.

### 4. Separate `ai-smart-router` Plugin Instead of Extending `ai-model-router`
- **Why considered:** Splitting strategy logic into a second plugin.
- **Why rejected:** `ai-model-router` already owns model resolution, capability filtering, target chain construction (`AiRequestMeta`), and `GET /v1/models` synthesis. Splitting would duplicate target schema definitions and complicate `shunt verify` ordering. Extending `ai-model-router` with pay-only-for-what-you-use `HookMask` gating keeps configuration cohesive with zero cost for `priority`-only routes.

---

## Verification

- **Unit tests:**
  - `shunt-core`: SWRR schedule smoothness & GCD reduction, weighted 3-pass health selection, active+passive health composition, HTTP & TCP active probe execution, and `ProbeSupervisor` reload/shutdown cancellation.
  - `shunt-config`: weighted endpoint & `health_check` TOML parsing, validation errors, `upstream.health_check_timeout` verify rule, and `GET /upstreams` admin response.
  - `shunt-ai`: multi-protocol capability extraction (`vision`, `tools`, `json_schema`, `reasoning`, `streaming`, `embeddings`), weighted/latency/cost strategy ranking, EWMA update math, and cold-start exploration.
- **Conformance spec (`specs/conformance/08-smart-routing-and-active-health.spec.toml`):** End-to-end tests covering Path B weighted upstream pools, active HTTP & TCP health ejection/recovery, `GET /upstreams` & Prometheus health metrics, AI weighted canary splits, capability guards across OpenAI/Anthropic/Responses + failover exclusion, latency/TTFT-aware dynamic routing, and cost-aware routing + failover.
- **Property tests (`proptest_core.rs`, `proptest_ai.rs`):** SWRR exact ratio preservation & 3-pass health optimality; capability extractor panic-freedom; cost & latency ranking invariants.
- **Example config:** `examples/shunt-ai-smart-routing.toml`.

## Future Work

- **RFC 0011:** OpenTelemetry (`OTLP`) HTTP & GenAI tracing, bounded async telemetry bus, exact-match `ai-cache`, and starter Grafana dashboards.
- **RFC 0012:** Opt-in Read-Only Admin Inspector UI (`--ui`) surfacing live `/upstreams` health, smart routing stats, and trace waterfalls.
