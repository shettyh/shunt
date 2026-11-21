# RFC 0005: Benchmark Harness vs. Envoy & Caddy & Hardening

- **Status:** Draft
- **Crates:** `benches/` (Phase 4)

## Summary

This RFC specifies the reproducible benchmark harness comparing Shunt against **Caddy** and **Envoy** on identical hardware across three target workloads, alongside the reload-under-load soak tests and fault-injection/panic hardening suite for Phase 4.

## Motivation

Shunt's core architectural bets—`HookMask` bitmask fast-paths, hybrid sync/async `HookResult`, zero-copy streaming passthrough, and lock-free `ArcSwap` reloads—exist to deliver high throughput and low tail latency without sacrificing plugin ergonomics. Claims about performance and zero-downtime reloads must be backed by automated, reproducible measurements and adversarial stress tests.

## Goals & Non-Goals

### Goals
- Automated, single-command benchmark harness in `benches/` comparing **Shunt**, **Caddy**, and **Envoy** against the same local mock upstream(s).
- Cover the three v1 target workloads:
  1. **Raw HTTP/1.1 & HTTP/2 (+ TLS) passthrough** (`HookMask::EMPTY`, 0 plugins).
  2. **3-plugin chain** (`request-id` + `bearer-auth` + `rate-limit`).
  3. **High-concurrency SSE streaming** (1,000+ concurrent streams with live chunk inspection/translation).
- Target bar: beat Caddy across all three workloads and match or stay within **10–15% of tuned Envoy** on RPS and p99 latency.
- Automated **reload-under-load soak test** proving zero dropped requests and bounded memory during continuous config swaps.
- Expanded **fault-injection & panic-isolation test suite** (slowloris/stalled upstreams, mid-stream resets, panicking sync & async hooks, oversized bodies, rapid concurrent reloads).

### Non-Goals
- Multi-node distributed load generation or cloud-specific benchmarking infrastructure (v1 targets reproducible single-machine loopback/localhost benchmarks with clear CPU/memory reporting).

## Design

### 1. Reproducible Benchmark Harness (`benches/`)

Proposed layout:
```text
benches/
├── README.md                  # Hardware notes, tool setup, how to reproduce & read results
├── upstream-bench/            # Ultra-fast Rust mock HTTP/1.1 + H2 + SSE upstream server
├── configs/
│   ├── shunt-raw.toml
│   ├── shunt-plugins.toml
│   ├── shunt-sse.toml
│   ├── caddy-raw.json
│   ├── caddy-plugins.json
│   ├── caddy-sse.json
│   ├── envoy-raw.yaml
│   ├── envoy-plugins.yaml
│   └── envoy-sse.yaml
└── scripts/
    ├── run_all.sh             # Runs workloads sequentially, collects RPS/p50/p99/RSS/CPU
    ├── bench_raw.sh
    ├── bench_plugins.sh
    └── bench_sse.rs           # High-concurrency (1,000+ streams) SSE load generator
```

#### Workload Specifications
1. **Workload 1 — Raw Passthrough (`HookMask::EMPTY`):**
   - Upstream returns a small fixed payload (`256 B`) with keep-alive enabled.
   - Measure HTTP/1.1 and HTTP/2 + TLS using `oha` or `wrk2` (with graceful detection/fallback) across concurrency levels (`64`, `256`).
   - Metrics: RPS, p50 / p95 / p99 latency, peak RSS, CPU utilization.
2. **Workload 2 — 3-Plugin Chain:**
   - Equivalent pipeline across Shunt (`request-id` + `bearer-auth` + high-burst `rate-limit`), Caddy, and Envoy.
   - Verifies that Shunt's sync `HookResult::Ready` fast path adds minimal per-request overhead.
3. **Workload 3 — High-Concurrency SSE Streaming (1,000+ streams):**
   - Custom Rust SSE load generator (`bench_sse`) opens 1,000+ concurrent streams, each emitting N chunks over several seconds (both passthrough and Anthropic → OpenAI live translation in Shunt).
   - Metrics: time-to-first-chunk (TTFC) p50/p99, per-chunk added latency, dropped/aborted streams (must be 0), peak RSS.

### 2. Reload-Under-Load Soak Suite

An automated integration/soak test (`crates/shunt-core` or `benches/`):
- Drives continuous concurrent traffic (mix of short HTTP requests + multi-second SSE streams) while firing config reloads every 50–100ms (alternating routes, plugin configs, and TLS certs).
- Asserts:
  - **Zero** `5xx`, connection resets, or truncated SSE streams.
  - Warm `UpstreamPool` IDs remain unchanged for unmodified upstreams.
  - Orphaned pools and `StateStore` scopes are garbage-collected (bounded count).

### 3. Fault-Injection & Hardening Tests

- **Mid-stream upstream TCP reset / abrupt EOF** during SSE translation and passthrough → clean abort, `on_complete` invoked with `aborted_mid_stream = true`, server stays healthy.
- **Idle-chunk timeout** on stalled SSE stream → stream terminated promptly after `idle_chunk_timeout_ms`.
- **Async hook panics** (panic after `.await` inside `HookResult::Pending`) in every lifecycle stage → isolated cleanly without crashing Tokio worker tasks.
- **Concurrent client disconnects** mid-upload and mid-SSE stream → backpressure channel drops cleanly with no task leaks.
- **Invalid/corrupt config files during rapid file-watcher edits** → gateway logs error and keeps serving the last-known-good snapshot with zero disruption.

## Alternatives Considered & Rejected

### 1. Micro-Benchmarks Only (`criterion` on Internal Functions)
- **Why considered:** Fast to run in CI and no external binaries needed.
- **Why rejected:** Micro-benchmarks miss socket/epoll contention, Hyper connection pooling behavior, allocator pressure under 1,000+ concurrent streams, and end-to-end comparison against real Envoy/Caddy binaries. We can keep targeted micro-benchmarks where helpful, but end-to-end workloads are the primary verification bar.

### 2. Benchmarking Against Live External APIs (OpenAI / Anthropic)
- **Why considered:** Realistic network conditions.
- **Why rejected:** Dominated by external network jitter and LLM inference latency, making proxy overhead impossible to measure reproducibly. A local Rust mock upstream isolates gateway overhead accurately.

## Future Work

- Continuous regression tracking in CI (running Shunt-only smoke benchmarks on PRs and full Envoy/Caddy comparisons on release tags).
- Flamegraph / allocation profiling (`dhat` / `samply`) to optimize any hot spots discovered by Workload 1–3.
