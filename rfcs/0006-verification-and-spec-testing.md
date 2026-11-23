# RFC 0006: Layered Verification, Property Testing & Spec-Driven TOML Testing

- **Status:** Implemented
- **Crates:** `shunt-plugin-sdk`, `shunt-engine`, `shunt-config`, `shunt-plugins`, `shunt-ai`, `shunt-test`, `shunt-cli`, `specs/`, `fuzz/`

## Summary

This RFC defines Shunt's layered verification architecture to make the data plane, configuration compiler, and AI gateway plugins provably reliable:

1. **Deterministic Foundation & Pre-Hardening:** Introduce an injectable `Clock` abstraction, eliminate atomic split-state races in passive health, cap `rate-limit` bucket cardinality, make `SseParser` strictly WHATWG-compliant, and stage `StateStore` / `RuntimeRegistry` commits atomically.
2. **Property-Based, Stateful Model & Fuzz Testing:** Exercise real Rust parsers, translators, matchers, and stateful lifecycle managers with `proptest`, `proptest-state-machine`, and `cargo-fuzz`.
3. **User-Facing Spec-Driven TOML Verification (`shunt verify` & `shunt test`):** Turn `shunt.toml` into verifiable, executable gateway policy—combining static IR policy/shadowing checks (`shunt verify`) with a declarative TOML contract test runner (`shunt test`) featuring fault-injecting mock upstreams.
4. **Formal Model Checking (TLA+ & Kani):** Prove protocol-level concurrency and lifecycle invariants (`AtomicReload`, `RequestPipeline`, `PassiveHealth`) with TLC, and verify bounded safety of pure hot-path Rust functions directly with Kani.

## Motivation

Shunt's v0.0.1 test suite relies on hand-written unit, integration, and soak tests. While effective for happy paths and known regressions, example-based tests leave four high-risk blind spots common to HTTP/AI proxies:

1. **Protocol & Chunk-Boundary Fragility:** Streaming parsers (`SseParser`), protocol translators (`openai_to_anthropic_request`, `AnthropicSseTranslator`), URI rewriters (`strip_uri_prefix`), and secret redactors (`redact_secrets`) process arbitrary untrusted input split across arbitrary TCP frame boundaries. Already observable edge cases include `SseParser::flush_event` dispatching event-only frames without `data:` lines and missing bare `\r` handling.
2. **Concurrency & Reload Interleavings:** Lock-free `ArcSwap` snapshot swaps, `BuildSession` orphan GC, warm `UpstreamPool` reuse, graceful draining, and passive health atomics (`EndpointState`'s separate `Relaxed` updates to `consecutive_failures` and `unhealthy_until_ms`) have subtle interleavings that normal tests rarely trigger.
3. **Unbounded State & Partial Side Effects:** `RateLimitPlugin`'s `BucketTable` grows unboundedly with unique client IPs/headers, and a failed `SnapshotCompiler::compile()` can leave newly initialized keys/pools resident in `StateStore` / `RuntimeRegistry` until a later successful reload.
4. **Unverified Operator Configurations:** Gateway outages frequently come from *valid* configs with unintended semantics—shadowed routes, `max_attempts < targets.len()` in failover chains, missing auth on public routes, accidental body buffering on streaming routes, or broken provider fallback behavior. Operators currently have no first-class way to write declarative contract tests against their own `shunt.toml`.

## Goals & Non-Goals

### Goals
- Keep `shunt-engine`'s hot path zero-allocation and unaffected in benchmark throughput/p99 (verification hooks/clocks must compile to zero or negligible overhead in production).
- Catch real implementation bugs directly in Rust code via `proptest`, stateful reference models, `cargo-fuzz`, and Kani.
- Prove concurrency safety and liveness invariants for Shunt's core state machines using focused TLA+ specs checked in CI.
- Ship **spec-driven TOML verification** (`shunt verify` and `shunt test`) as first-class CLI commands useful to both Shunt contributors (conformance suite) and end users (testing their own `shunt.toml` in CI).
- Ensure every verification layer runs reproducibly locally and in GitHub Actions with deterministic seeds and actionable failure output.

### Non-Goals
- Full mechanized proof of `tokio`, `hyper`, or `rustls` in Lean 4 / Coq (high maintenance burden with a wide translation gap from async Rust).
- Turning the TOML test spec format into a general-purpose Turing-complete scripting language.
- Distributed multi-node consensus verification (Shunt v1 state is single-process; distributed plugins can add their own specs later).

## Design

Shunt adopts a **4-layer Verification Pyramid**, matching each class of bug to the tool with the highest signal-to-effort ratio:

```text
                ┌──────────────────────────────────────┐
                │  Layer 4: Formal Models              │  Design concurrency safety/liveness
                │  • TLA+ (TLC): Reload, Pipeline,     │  + Rust-native bounded proofs
                │    PassiveHealth                     │
                │  • Kani: pure hot-path Rust proofs   │
                ├──────────────────────────────────────┤
                │  Layer 3: Spec-Driven TOML CLI       │  Operator & CI conformance
                │  • `shunt verify` (static IR proofs) │  against real `shunt.toml`
                │  • `shunt test` (contract runner)    │
                ├──────────────────────────────────────┤
                │  Layer 2: Property & Fuzz Testing    │  Exhaustive input & state-space
                │  • `proptest` + state-machine models │  exploration on real Rust code
                │  • `cargo-fuzz` (SSE/JSON/HTTP)      │
                ├──────────────────────────────────────┤
                │  Layer 1: Deterministic Primitives   │  Injectable Clock, atomic health
                │  • `Clock` trait, bounded buckets,   │  word, transactional compile GC
                │    WHATWG SSE, atomic health state   │
                └──────────────────────────────────────┘
```

---

### Layer 1: Deterministic Primitives & Pre-Hardening

Before writing formal models or stateful property tests, four foundational seams must be tightened so the implementation itself is clean and deterministically testable:

1. **Injectable `Clock` Abstraction (`shunt-plugin-sdk` + `shunt-engine`)**:
   - Introduce a lightweight `Clock: Send + Sync + 'static` trait (with `SystemClock` using `Instant::now()` as default and `ManualClock` for deterministic tests/simulations).
   - Expose `BuildContext::clock(&self) -> Arc<dyn Clock>` (defaulting to `SystemClock`) so `RateLimitPlugin`, `AiFailoverPlugin`, and `UpstreamPool` never have to sleep in unit/property tests or `shunt test`.
2. **Single-Word Atomic Health State (`crates/shunt-engine/src/upstream.rs`)**:
   - Replace the pair of `Relaxed` atomics (`consecutive_failures` + `unhealthy_until_ms`) in `EndpointState` with a single `AtomicU64` (packing `failures: u16` + `unhealthy_until_ms: u48`) updated via CAS (`fetch_update`), or a compact `Mutex<HealthState>` on the slow error/recovery path with an `Acquire`/`Release` fast-path read. This eliminates split-state races permanently.
3. **Bounded Cardinality in `RateLimitPlugin` (`crates/shunt-plugins/src/rate_limit.rs`)**:
   - Add `max_entries` (default e.g. `100_000`) and idle eviction TTL to `BucketTable` (plus optional sharded buckets to avoid global `Mutex` contention) so adversarial `X-Forwarded-For` / API-key cardinality cannot exhaust memory.
4. **WHATWG-Strict `SseParser` (`crates/shunt-ai/src/sse.rs`) & Transactional `BuildSession` (`shunt-engine` / `shunt-config`)**:
   - Fix `SseParser` to discard frames with no `data:` lines (even if `event:` was set), handle bare `\r` line endings, and strip UTF-8 BOM at stream start.
   - Ensure failed `SnapshotCompiler::compile()` calls roll back or avoid polluting `StateStore` / `RuntimeRegistry` with newly created keys/pools (e.g., staging newly inserted keys/pools inside `BuildSession` and committing them only on success).

---

### Layer 2: Property-Based, Stateful Model & Fuzz Testing

Add `proptest` (dev-dependency across crates) and optional `fuzz/` targets (`cargo-fuzz`) targeting every high-risk transformation and state machine:

#### 2.1 Stateless Algebraic & Parser Properties (`proptest`)
| Target | Key Invariants Verified |
| --- | --- |
| `SseParser` (`shunt-ai`) | **Chunk-split invariance:** for any generated SSE payload and any random partition into slices (including 1-byte and multi-byte UTF-8 splits), `feed_chunked(slices) == feed_whole(bytes)`. Never panics on arbitrary bytes. |
| `AnthropicSseTranslator` (`shunt-ai`) | Any valid sequence of Anthropic SSE events (`message_start`, `content_block_*`, `message_delta`, `message_stop`) split arbitrarily produces valid OpenAI `data: {json}\n\n` frames terminated by `data: [DONE]\n\n`, preserving concatenated text and tool-call argument deltas identically. |
| `openai_to_anthropic_request` (`shunt-ai`) | Output is always valid JSON with `max_tokens > 0`, strictly alternating `user`/`assistant` message roles (no two adjacent messages share a role), all `system`/`developer` prompts preserved, all `tool_call_id`s mapped to `tool_result`, never panics on arbitrary `serde_json::Value`. |
| `PathMatch`, `RouteMatch`, `host_matches`, `strip_uri_prefix` (`shunt-engine`) | `Prefix("/a")` never matches `"/ab"`; `host_matches` is case-insensitive and never matches bare suffix for `*.suffix`; `strip_uri_prefix` always produces a path starting with `/` and preserves query strings verbatim. |
| `redact_secrets` (`shunt-config`) | For any arbitrarily nested JSON object containing sensitive key substrings in any casing (`Api_Key`, `x-token`, `password`, etc.), no original secret string ever survives anywhere in the serialized output. |
| `strip_hop_by_hop_headers` & framing (`shunt-engine`) | `Connection`-nominated headers and RFC 9110 hop-by-hop headers are always removed; buffered outgoing requests never contain both `Content-Length` and `Transfer-Encoding`. |

#### 2.2 Stateful Model-Based Tests (`proptest` / reference state machines)
Generate random sequences of operations and compare the real Rust implementation against a tiny pure reference model after every step:
- **`RuntimeRegistry` + `StateStore` + `SnapshotCompiler`:** Sequence of `{CompileValid(routes, upstreams), CompileInvalid, Reload, AssertPoolReused, AssertOrphansGCd}`. Asserts: failed compile leaves live snapshot, pool count, and state count unchanged; unchanged `UpstreamPoolKey` preserves `pool_id`; removed scopes are GC'd only after successful compile.
- **`TokenBucket` + `RateLimitPlugin` (with `ManualClock`):** Sequence of `{Request(key), AdvanceTime(dt)}`. Asserts: tokens stay within `[0, burst]`, no NaN/Inf, total allowed requests over any interval `[0, T]` never exceeds `burst + floor(T * rps)`, `Retry-After >= 1`, and map cardinality never exceeds `max_entries`.
- **`EndpointState` / `UpstreamPool::select_endpoint` & `FailoverCircuitState` (with `ManualClock`):** Sequence of `{Select(tried), RecordFailure, RecordSuccess, AdvanceTime(dt)}`. Asserts: `select_endpoint` always returns an in-bounds index, prioritizes healthy & untried endpoints, respects `failure_threshold`, honors `Retry-After` clamped to `[cooldown, max_cooldown]`, and recovers immediately once `now >= cooldown_until`.

#### 2.3 Coverage-Guided Fuzzing (`fuzz/`)
Dedicated `cargo-fuzz` targets (run nightly or on-demand in CI) for:
- `fuzz_sse_parser` (raw bytes + chunk boundaries)
- `fuzz_anthropic_translate` (arbitrary JSON request/response payloads)
- `fuzz_config_parse` (arbitrary TOML/YAML strings into `GatewayConfig::validate`)
- `fuzz_route_match` (arbitrary URI/Host/Method combinations)

---

### Layer 3: Spec-Driven TOML Verification (`shunt verify` & `shunt test`)

Promote declarative verification to a first-class feature in `shunt-config` + `shunt-cli` (zero impact on `shunt-engine`'s runtime hot path).

#### 3.1 Static Policy & Invariant Verifier (`shunt verify`)

```bash
shunt verify -c shunt.toml [--policy policy.toml] [--format text|json]
```

Compiles `shunt.toml` into `GatewayConfig` + `CompiledBundle` and runs a deterministic suite of static analyzers over the IR and compiled `GatewaySnapshot`, reporting structured `Error` / `Warning` diagnostics (with non-zero exit on any error, or `--strict` for warnings):

| Rule ID | Check | Severity (Default) |
| --- | --- | --- |
| `route.shadowed` | Route $j$ is completely subsumed by earlier route $i < j$ (exact/prefix path, host wildcard, and method inclusion algebra). | Error |
| `route.timeout_order` | `upstream.connect_timeout_ms >= route.response_headers_timeout_ms`. | Warning |
| `route.body_cap_missing` | Route enables `HookMask::REQUEST_BODY_BUFFERED` without an explicit `max_body_bytes` (relying on default). | Info / Policy |
| `ai.attempts_insufficient` | `ai-model-router` defines a target chain of length $N$, `auto_max_attempts = false`, and `route.max_attempts < N`. | Error |
| `ai.unknown_upstream` | Any target in `ai-model-router` references an upstream name not declared in `[[upstreams]]`. | Error |
| `ai.plugin_order` | `ai-provider-adapter` or `ai-failover` appears *before* `ai-model-router` in `routes.plugins`. | Error |
| `admin.non_loopback` | `admin.enabled = true` and `admin.listen` binds to a non-loopback address (`0.0.0.0`, etc.). | Warning |
| `policy.require_plugin` | Optional policy rule asserting every matching route includes required plugins (e.g., `bearer-auth`, `rate-limit`). | Configurable |
| `policy.assert_hook_mask` | Optional policy rule asserting a hot-path route compiles with specific `HookMask` constraints (e.g., `forbid = ["REQUEST_BODY_BUFFERED", "RESPONSE_BODY_STREAM"]`). | Configurable |

Optional `[verify]` / `policy.toml` example:
```toml
[verify]
forbid_shadowed_routes = true
require_loopback_admin = true

[[verify.route_policies]]
match_route = "public_*"
require_plugins = ["request-id", "bearer-auth", "rate-limit"]

[[verify.route_policies]]
match_route = "raw_passthrough"
forbid_hooks = ["REQUEST_BODY_BUFFERED", "RESPONSE_BODY_STREAM"]
```

#### 3.2 Executable TOML Contract Test Runner (`shunt test`)

```bash
shunt test -c shunt.toml -s shunt.spec.toml [--filter <pattern>] [--format text|json]
```

Runs hermetic, end-to-end tests against the real `GatewayServer` and `SnapshotCompiler` **entirely in-process on ephemeral localhost ports**:

```text
  shunt.toml ──▶ Rewrite upstream endpoints to in-process MockUpstream servers
                         │
                         ▼
                 SnapshotCompiler ──▶ GatewayServer (127.0.0.1:0)
                         │                     ▲
                         │                     │ HTTP/1.1, H2, SSE, WS
                         ▼                     │
                 MockUpstream(s)  ◀────  SpecRunner executes [[cases]]
                 (scripted responses,    (with optional ManualClock steps,
                  faults, chunk splits)   reload steps, & metric assertions)
```

Key capabilities of the TOML spec schema (`shunt.spec.toml`):
- **Upstream Endpoint Rebinding:** Automatically maps logical upstream names (e.g. `openai`, `anthropic`, `backend`) from `shunt.toml` to local in-process mock HTTP/SSE servers without editing `shunt.toml`.
- **Environment Overrides (`[env]`):** Supply test-only dummy secrets (`OPENAI_API_KEY = "test-key"`) isolated to the test runner.
- **Scripted & Fault-Injecting Mock Upstreams (`[[mocks]]`):**
  - Static or sequential responses (`status`, `headers`, `body` / `json`).
  - Streaming SSE responses (`sse_events` / raw `chunks`, configurable `chunk_split_bytes`, `chunk_delay_ms`).
  - Fault injection: `fault = "tcp_reset_mid_stream"`, `fault = "stall_headers"`, `fault = "stall_chunk"`, `fault = "connect_refused"`.
  - Inbound request capture assertions (verify the exact method, path, headers, and JSON body Shunt forwarded to the upstream!).
- **Multi-Step Scenarios & Stateful Verification (`[[cases]]`):**
  - Single-request cases or ordered `[[cases.steps]]` (including `advance_clock_ms` via `ManualClock` and `reload_config` steps to test hot-reload state persistence!).
  - Rich assertions on downstream response: `status`, `headers` (exact/contains/absent), `body_contains`, `json_eq` / JSON-pointer assertions (`json_path`), `sse_events` count/order/termination (`[DONE]`), `upstream_requests` captured per mock, `snapshot_redacts` (verifying secrets never appear in `GET /snapshot`), and `metrics_delta` (verifying Prometheus counters incremented accurately).

Example `shunt.spec.toml`:
```toml
[spec]
name = "ai-gateway-contract"
config = "examples/shunt-ai.toml"

[env]
OPENAI_API_KEY = "sk-test-openai"
ANTHROPIC_API_KEY = "sk-test-anthropic"

[[mocks]]
upstream = "openai"
name = "openai_429_then_ok"
sequence = [
  { status = 429, headers = { "retry-after" = "10" }, json = { error = { message = "rate limited" } } },
  { status = 200, json = { id = "chatcmpl-2", choices = [{ message = { role = "assistant", content = "recovered" }, finish_reason = "stop" }], usage = { prompt_tokens = 4, completion_tokens = 2 } } }
]

[[mocks]]
upstream = "anthropic"
name = "anthropic_sse"
chunk_split_bytes = 9
sse_raw = [
  "event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"id\":\"msg_1\",\"usage\":{\"input_tokens\":5}}}\n\n",
  "event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"hello\"}}\n\n",
  "event: message_delta\ndata: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"end_turn\"},\"usage\":{\"output_tokens\":3}}\n\n",
  "event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n"
]

[[cases]]
name = "smart alias fails over from OpenAI 429 to Anthropic live SSE"
use_mocks = ["openai_429_then_ok", "anthropic_sse"]

[cases.request]
method = "POST"
path = "/v1/chat/completions"
headers = { "content-type" = "application/json" }
json = { model = "smart", stream = true, messages = [{ role = "user", content = "hi" }] }

[cases.expect]
status = 200
headers = { "x-shunt-provider" = "anthropic", "x-shunt-attempt" = "2" }
sse_contains_text = "hello"
sse_ends_with = "[DONE]"
metrics_delta = { "shunt_ai_failovers_total" = 1 }

[[cases.expect.upstream_calls]]
upstream = "anthropic"
path = "/v1/messages"
headers_present = ["x-api-key", "anthropic-version"]
headers_absent = ["authorization"]
json_path = { "/model" = "claude-3-5-sonnet-20241022", "/stream" = true }
```

In addition, Shunt's own repository will maintain a canonical `specs/conformance/*.spec.toml` suite executed in `cargo test` and CI, proving every RFC 0001–0005 contract declaratively.

---

### Layer 4: Formal Model Checking (TLA+ & Kani)

Formal methods are scoped strictly to the subsystems where state-space interleavings or subtle edge cases justify the rigor.

#### 4.1 TLA+ Specifications (`specs/tla/`)

Three compact, self-contained TLA+ specs checked by **TLC** in CI:

1. **`specs/tla/AtomicReload.tla`** (models RFC 0002 + `ReloadController` + `RuntimeRegistry` + `GatewayServer` drain):
   - **Actors:** Concurrent incoming requests (`load_full` snapshot), concurrent reload triggers (`file_watcher`, `POST /reload`, `SIGHUP`), `SnapshotCompiler` (succeed or fail mid-compile), and graceful shutdown.
   - **Safety Invariants:**
     - `RequestSnapshotConsistency`: Every in-flight request completes using the exact single snapshot version it loaded at entry (never observes mixed routes/pools).
     - `FailedReloadNoMutation`: A failed compilation leaves the active snapshot, live pool set, and live `StateStore` scopes untouched.
     - `MonotonicVersions`: Active snapshot version is strictly non-decreasing (no stale reload overwrites a newer snapshot).
     - `NoUseAfterGC`: No pool or `StateStore` scope referenced by the active snapshot is ever GC'd.
   - **Liveness Properties (under weak fairness):**
     - `OrphanEventualGC`: After a successful reload removing a pool/scope, once older in-flight requests drain, its refcount reaches 0 and it is absent from the registry.
     - `GracefulDrainTerminates`: Shutdown eventually transitions to `Stopped` once `active_conns = 0` or `drain_timeout` fires.

2. **`specs/tla/RequestPipeline.tla`** (models RFC 0001 7-stage lifecycle + retry loop + panic isolation):
   - **Actors:** Single request progressing through Stages 1–7 with nondeterministic plugin outcomes (`Continue`, `Respond`, `RetryUpstream`, `Panic`, `UpstreamError`, `MidStreamAbort`, `IdleTimeout`) and `HookMask` configurations.
   - **Safety Invariants:**
     - `OnCompleteAtMostOnce`: `on_complete` runs at most once per request.
     - `NoRetryAfterCommit`: `RetryUpstream` never transitions back to Stage 4 after Stage 5 (headers committed downstream).
     - `NoUnbufferedNonEmptyReplay`: Attempt `> 1` never occurs if request body is unbuffered and non-empty.
     - `CanonicalRequestIsolation`: Per-attempt mutations on attempt $k$ are never visible at the start of attempt $k+1$.
     - `ZeroAllocFastPath`: If `HookMask` lacks `REQUEST_BODY_BUFFERED`, body is never buffered; if it lacks `RESPONSE_BODY_STREAM`, response stays passthrough.
   - **Liveness Property:**
     - `MatchedRequestCompletes`: Every matched request eventually terminates and (when `HookMask::ON_COMPLETE` is set) invokes `on_complete` exactly once—even under panics or mid-stream aborts.

3. **`specs/tla/PassiveHealth.tla`** (models `EndpointState` + `FailoverCircuitState`):
   - **Actors:** Concurrent requests recording failures/successes, selecting endpoints, and monotonic clock ticks.
   - **Safety Invariants:**
     - `NoSplitHealthState`: If `consecutive_failures == 0`, then `unhealthy_until == 0` (and vice versa once threshold is crossed).
     - `ThresholdRespected`: An endpoint never enters cooldown with fewer than `threshold` consecutive failures.
     - `SelectionTotality`: `select_endpoint` always returns a valid endpoint index even when all endpoints are unhealthy or tried.

**Bridging TLA+ to Rust Code:**
- Add lightweight optional **trace validation** (under a `#[cfg(test)]` trace recorder): Rust integration/soak tests emit JSON state-transition sequences for `ReloadController` and `execute_request`, which a TLC trace-checking spec verifies as valid behaviors of `AtomicReload.tla` / `RequestPipeline.tla`.
- Complement TLA+ with **`loom`** tests on the actual Rust atomic/lock primitives (`EndpointState`, `ActiveConnGuard` + `Notify`) to catch memory-ordering bugs (`Relaxed` vs `Acquire`/`Release`/`SeqCst`) that TLA+ abstracts away.

#### 4.2 Rust-Native Bounded Verification with Kani (`#[cfg(kani)]`)

Add a small set of `#[kani::proof]` harnesses directly in `shunt-engine` and `shunt-plugins` (run in CI via `cargo kani`):
- `HookMask` bitwise algebra (`contains`, `is_empty`, union/intersection identities).
- `PathMatch::matches` & `host_matches` & `strip_uri_prefix` (panic-freedom & prefix-boundary safety for bounded strings).
- `UpstreamPool::select_endpoint` index selection logic (panic-freedom, always `< len`, healthy-untried preference).
- `TokenBucket::try_consume` (no NaN, no overflow, `0.0 <= tokens <= burst`, `retry_after >= 1` on reject).

---

### CI Integration

Add a dedicated `.github/workflows/verify.yml` workflow alongside existing `ci.yml`:
- **On every PR (fast, < 3 min):**
  - `cargo test --workspace` (includes `proptest` + stateful model tests + `specs/conformance/*.spec.toml`)
  - `shunt verify` on all `examples/*.toml` and `benches/configs/shunt-*.toml`
  - `shunt test` on `specs/conformance/*.spec.toml`
  - TLC model check on `specs/tla/*.tla` (fast bounded state configs)
- **Nightly / Weekly (deeper exploration):**
  - High-case-count `PROPTEST_CASES=10000` run
  - `cargo kani` bounded proof suite
  - `cargo-fuzz` time-boxed runs (60s per target) with corpus caching
  - `loom` concurrency permutation tests

## Alternatives Considered & Rejected

### 1. Formalizing Shunt in Lean 4 Instead of TLA+ + Kani
- **Why considered:** Lean 4 provides machine-checked deductive proofs for arbitrary (unbounded) domains rather than bounded model checking.
- **Why rejected (for core gateway verification):** Modeling Tokio async execution, `ArcSwap`, Hyper streams, and HTTP framing in Lean 4 creates a large specification-to-code gap and steep proof-maintenance cost whenever Rust code evolves. **TLA+** is far better suited for concurrent state-machine protocols (`AtomicReload`, `RequestPipeline`), while **Kani** verifies bounded safety directly against the real Rust source code with zero translation layer. (Lean 4 remains an optional future research exercise if we ever want an unbounded algebraic proof of `shunt verify`'s route-shadowing decision procedure.)

### 2. Building Only Internal Rust Integration Tests Instead of `shunt test` / `shunt verify`
- **Why considered:** Faster to implement; no TOML test schema to design or maintain.
- **Why rejected:** Misses a major user-facing advantage. Gateway operators routinely struggle to test routing rules, failover chains, rate limits, and secret redaction before shipping config changes. Making spec-driven TOML verification a first-class CLI workflow (`shunt verify`, `shunt test`) solves Shunt's own conformance testing *and* gives users a uniquely ergonomic DX that Envoy and Caddy lack out of the box.

### 3. Driving `shunt test` Against External Docker Containers / Live APIs
- **Why considered:** Closer to production network topology.
- **Why rejected:** Slow, flaky, non-deterministic, and requires external credentials. Running `GatewayServer` and scripted `MockUpstream` servers in-process on `127.0.0.1:0` with `ManualClock` runs an entire multi-failover, rate-limit, and SSE-translation contract suite in milliseconds with zero network flakiness.

### 4. Replacing `Instant::now()` with `tokio::time::pause()` Everywhere Instead of a `Clock` Trait
- **Why considered:** Avoids adding a `Clock` trait to `shunt-plugin-sdk`.
- **Why rejected:** `tokio::time::pause()` only controls `tokio::time::Instant`, not `std::time::Instant`, and applies globally to a single-threaded Tokio runtime—it does not work cleanly for pure synchronous `proptest` state-machine tests or multi-threaded `GatewayServer` contract tests. A tiny `Clock` trait (`Arc<dyn Clock>`) works identically in sync unit tests, `proptest`, and async `shunt test` scenarios.

## Implementation Plan

- **Phase 1 — Deterministic Foundation & Property Tests**
  - Add `Clock` (`SystemClock` / `ManualClock`) in `shunt-plugin-sdk` + `BuildContext::clock()`.
  - Fix the 4 pre-hardening findings (`EndpointState` atomic health word, `RateLimitPlugin` bounded buckets, WHATWG `SseParser`, transactional `BuildSession` staging).
  - Add `proptest` suites for `SseParser`, `translate.rs`, `RouteMatch` / `strip_uri_prefix`, `redact_secrets`, and stateful model tests for `RuntimeRegistry`, `TokenBucket`, and `FailoverCircuitState`.
- **Phase 2 — Spec-Driven TOML Verification (`shunt verify` & `shunt test`)**
  - Implement static IR verifier (`shunt-config::verify`) with route-shadowing algebra, AI plugin order/attempt checks, timeout/admin/policy rules, and wire `shunt verify` into `shunt-cli`.
  - Implement declarative TOML contract test engine (`shunt-config::spec_test` or new `shunt-test` crate) with scripted/fault-injecting `MockUpstream`, `ManualClock` stepping, reload steps, and metric/redaction assertions; wire `shunt test` into `shunt-cli`.
  - Author `specs/conformance/*.spec.toml` covering RFCs 0001–0005.
- **Phase 3 — Formal Models (TLA+, Loom, Kani) & Fuzzing**
  - Author `specs/tla/{AtomicReload,RequestPipeline,PassiveHealth}.tla` + `.cfg` files and wire TLC into `.github/workflows/verify.yml`.
  - Add `#[cfg(kani)]` harnesses and `loom` atomic tests for `shunt-engine` / `shunt-plugins`.
  - Add `fuzz/` targets (`cargo-fuzz`) and optional TLC trace validation from Rust soak/integration tests.

## Future Work

- **Deterministic Simulation Testing (DST):** Combine `ManualClock` with a simulated in-memory transport/fault injector to run seeded multi-thousand-step randomized chaos simulations (network partitions, slowloris, rapid config churn) reproducibly from a single `u64` seed.
- **Optional Lean 4 Proof of Route-Shadowing Algebra:** Mechanize soundness and completeness of `shunt verify`'s `RouteMatch` subsumption checker (`route_subsumes(r1, r2) ↔ ∀ req, matches(r2, req) → matches(r1, req)`).
- **JSON Schema Generation:** Emit a versioned JSON Schema for both `shunt.toml` and `shunt.spec.toml` for IDE autocomplete and validation.
