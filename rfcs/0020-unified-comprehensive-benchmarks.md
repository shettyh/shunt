# RFC 0020: Unified & Comprehensive Gateway Benchmark Suite (API, AI & MCP)

- **Status:** Implemented
- **Crates:** `benches/shunt-bench`, `benches/configs/`, `benches/scripts/`, `benches/results/`, `.github/workflows/nightly-bench.yml`

## 1. Summary

This RFC replaces Shunt's fragmented benchmark scripts (`run_all.sh`, `run_litellm_bench.sh`, and `nightly_report.sh`) and flat configuration layout with a **single unified benchmark architecture** organized cleanly across Shunt's three gateway pillars—**API Gateway**, **AI Gateway**, and **MCP Gateway**—plus **Stability & Hot-Reload**.

It upgrades `shunt-bench` (with zero new external Cargo dependencies) to support TLS 1.3 / mTLS / HTTP/2, coordinated-omission-free open-loop latency measurement (`--rate`), realistic multi-size payloads, dirty guardrail corpora, cache-miss/mixed-cardinality drivers, live reload-under-load driving, and mock upstreams covering HTTP, multi-dialect AI (OpenAI, Anthropic, Responses, Gemini, Bedrock), and Streamable HTTP MCP JSON-RPC 2.0. All workloads run through one orchestrator (`benches/scripts/bench.sh`) emitting a canonical JSONL schema rendered by `benches/scripts/render_report.py`.

## 2. Motivation

As Shunt expanded from a core HTTP reverse proxy ([RFC 0005](./0005-benchmarks-and-hardening.md)) into a full API Gateway ([RFC 0018](./0018-jwt-http-security-compression-and-k8s-gateway.md)), multi-provider AI Gateway ([RFCs 0004–0017](./README.md)), and MCP Agentic Gateway ([RFC 0019](./0019-mcp-and-agentic-gateway.md)), the benchmark harness grew organically in three separate places:

1. **Fragmented runners & inconsistent metrics:**
   - `run_all.sh` compared Shunt vs. Envoy and Caddy for basic HTTP/SSE, mixed in one AI SSE translation case (`W3b`), emitted plain text only, and did not record cold-start time, idle RSS, or multi-process tree RSS.
   - `run_litellm_bench.sh` compared Shunt AI vs. LiteLLM with cold-start and tree RSS, but emitted plain text only and overlapped with `run_all.sh`.
   - `nightly_report.sh` duplicated process orchestration a third time for CI and collapsed API and AI HTTP workloads into two flat tables (`HTTP/1.1` and `SSE`).
2. **Thin API Gateway coverage:**
   - Tested only 1 route, 1 upstream, plain HTTP/1.1, a 256 B `/ping`, and Shunt-only JWT/compression.
   - Omitted **TLS 1.3 / HTTP/2** (even though `--http2` existed in `shunt-bench` and was an original RFC 0005 goal), **mTLS**, **multi-route tables + load balancing**, **large streaming payloads**, **401/429 rejection fast-paths**, **observability overhead**, **Envoy/Caddy parity on JWT & compression**, and **hot-reload under live load**.
3. **Micro-prompt bias in AI Gateway benchmarks:**
   - Every AI workload sent a ~70 B `"hi"` prompt, tested `ai-guardrails` only on clean inputs (zero redactions/blocks), and tested `ai-cache` only at 100% hit rate.
   - Omitted **realistic 4 KB / 32 KB multi-turn prompts**, **guardrail redaction & prompt-injection blocking**, **cache misses / mixed hit ratios / singleflight coalescing**, **multi-protocol ingress (`/v1/messages`, `/v1/responses`)**, **Bedrock SigV4/EventStream & Gemini**, and **failover latency**.
4. **Zero MCP Gateway coverage:**
   - `shunt-mcp` is a first-class gateway pillar in `README.md`, yet had zero throughput, latency, or memory benchmarks.
5. **Closed-loop-only latency measurement:**
   - Pure closed-loop load generation (`-c` workers looping as fast as possible) measures saturation throughput well, but suffers from coordinated omission under queueing and omits CPU efficiency (`cpu_ms / 1k reqs`).

## 3. Goals & Non-Goals

### Goals
- **One canonical runner & schema:** Replace `run_all.sh`, `run_litellm_bench.sh`, and `nightly_report.sh` with a single orchestrator (`benches/scripts/bench.sh`) and report renderer (`benches/scripts/render_report.py`) parameterized by `--suite`, `--profile`, and `--competitors`.
- **Clean break per Pre-Release Compatibility Policy:** Remove legacy split scripts and reorganize configs under `benches/configs/{api,ai,mcp}/`.
- **Zero new external crate dependencies:** Extend `benches/shunt-bench` using existing workspace dependencies (`rustls`, `tokio-rustls`, `rcgen`, `serde`, `serde_json`).
- **Comprehensive 4-suite matrix:**
  1. `api` — HTTP/1.1, HTTPS/H2, mTLS, plugin chains, JWT & zstd (with Envoy/Caddy parity), 200-route LB, large streaming, 401/429 shedding, observability tax, SSE, and open-loop latency.
  2. `ai` — Small & realistic 4 KB / 32 KB prompts, multi-dialect translation, governed 8-plugin chain, clean/redact/block guardrails, cache hit/miss/mixed/singleflight, multi-protocol ingress, Bedrock SigV4, failover, and high-concurrency SSE (with LiteLLM parity).
  3. `mcp` — Warm virtual `tools/list` ACL filtering, full 5-plugin governed `tools/call`, guardrail redaction/blocking, identical-call loop breaking, and Streamable HTTP SSE.
  4. `soak` — Zero-error live hot-reload under load (`POST /reload`) and steady-state RSS growth guardrail.
- **Honest, comparable metrics:** Capture `rps`, `p50`/`p95`/`p99`/`p999`/`max`, `errors`, `cold_start_ms`, `idle_rss_mb`, `post_rss_mb`, `proc_count`, and `cpu_ms_per_1k_req` consistently across every gateway and suite.
- **CI-friendly profiles:** Keep nightly CI fast (`--profile ci`, ~2–3 min on a 2-core runner) while giving developers `--profile quick` (~30s) and `--profile full` (complete local head-to-head suite).

### Non-Goals
- Multi-node distributed load generation or cloud-hosted benchmarking infrastructure (reproducible single-machine loopback remains the primary target).
- Live third-party LLM API benchmarking (external network and inference latency obscure gateway overhead).
- Maintaining backwards-compatibility wrapper scripts for the deprecated split scripts.

## 4. Design

### 4.1 Canonical Directory Layout

```text
benches/
├── README.md                        # Methodology, reproduction commands & reference tables (API / AI / MCP / Soak)
├── shunt-bench/                     # Self-contained Rust mock upstream, TLS cert gen & HTTP/H2/TLS/SSE/MCP load generator
├── configs/
│   ├── api/
│   │   ├── shunt-raw.toml           # HookMask::EMPTY raw passthrough
│   │   ├── shunt-tls.toml           # TLS 1.3 + HTTP/2 (cert paths injected via template/generated dir)
│   │   ├── shunt-mtls.toml          # mTLS client cert verification + mtls-auth
│   │   ├── shunt-plugins.toml       # request-id + bearer-auth + rate-limit
│   │   ├── shunt-security.toml      # request-id + ip-filter + jwt-auth (HS256) + body-limit + zstd compression
│   │   ├── shunt-routing-lb.toml    # 200 routes + 3-endpoint weighted/EWMA pool + active health probes
│   │   ├── shunt-observability.toml # 3-plugin chain + metrics + otel-trace + access-log
│   │   ├── shunt-reject.toml        # Strict rate-limit / auth rejection fast-path
│   │   ├── shunt-sse.toml           # High-concurrency SSE passthrough
│   │   ├── shunt-reload.toml        # Admin API enabled for reload-under-load soak
│   │   ├── envoy-raw.yaml
│   │   ├── envoy-tls.yaml
│   │   ├── envoy-plugins.yaml
│   │   ├── envoy-jwt-zstd.yaml      # Envoy native jwt_authn + zstd compressor parity
│   │   ├── envoy-routing-lb.yaml    # 200-route table + 3-endpoint LB parity
│   │   ├── envoy-sse.yaml
│   │   ├── caddy-raw.json
│   │   ├── caddy-tls.json
│   │   ├── caddy-plugins.json       # Fixed keep-alive/connection tuning for zero-error parity
│   │   ├── caddy-zstd.json          # Caddy encode zstd parity
│   │   └── caddy-sse.json
│   ├── ai/
│   │   ├── shunt-minimal.toml       # 3-plugin: ai-model-router + ai-provider-adapter + ai-usage-tracker
│   │   ├── shunt-governed.toml      # 8-plugin full governance chain
│   │   ├── shunt-guardrails.toml    # Inline PII/secrets/prompt-injection/regex/keywords (request + response + SSE)
│   │   ├── shunt-cache.toml         # Exact-match + streaming SSE + singleflight ai-cache
│   │   ├── shunt-multiprotocol.toml # /v1/messages, /v1/responses, Gemini & Bedrock SigV4 dialects
│   │   ├── shunt-failover.toml      # Primary fault upstream -> secondary healthy upstream failover
│   │   ├── litellm-stateless.yaml   # LiteLLM no-DB stateless baseline
│   │   └── litellm-auth.yaml        # LiteLLM master_key + in-memory rpm/tpm
│   └── mcp/
│       └── shunt-mcp-governed.toml  # Full 5-plugin MCP multiplexer: mcp-auth + mcp-router + mcp-guardrails + mcp-rate-limit + mcp-telemetry
├── scripts/
│   ├── bench.sh                     # Unified orchestrator (--suite, --profile, --competitors, --output-json, --output-md)
│   └── render_report.py             # Renders unified JSONL into sectioned Markdown + enforces CI guardrails
└── results/
    └── nightly.md                   # Auto-generated nightly report across API / AI / MCP / Soak
```

### 4.2 `shunt-bench` Upgrades

#### Subcommands
1. **`shunt-bench gen-certs --out-dir <dir>`**
   - Uses workspace `rcgen` to generate deterministic ephemeral PEM files in `<dir>`: `ca.pem`, `server.pem`, `server-key.pem` (SANs: `127.0.0.1`, `localhost`), and `client.pem`, `client-key.pem` (signed by `ca.pem` for mTLS).
   - Avoids committing private keys or depending on platform-specific `openssl` flags.

2. **`shunt-bench upstream`** (extended HTTP/1.1 + HTTP/2 mock server)
   - **API routes:**
     - `/ping` — fixed `--payload-bytes` (default `256` B).
     - `/json` — ~4.3 KB compressible JSON payload.
     - `/bytes/<n>` — streams `n` bytes (capped at 4 MiB) in 16 KiB chunks for zero-copy large-body tests.
     - `/health` — fast `200 OK` (`{"status":"ok"}`) for active health probes.
     - `/status/<code>` — returns deterministic HTTP status (`429`, `500`, `503`, etc.) for failover testing.
     - `/sse` — OpenAI-format SSE stream (`--sse-chunks`, `--sse-interval-ms`).
   - **AI routes:**
     - `/v1/chat/completions` & `/chat/completions` — OpenAI JSON & SSE (supports dirty-response trigger when request contains `"__BENCH_DIRTY_RESPONSE__"` to test outbound/response guardrail redaction).
     - `/v1/messages` & `/messages` — Anthropic JSON & SSE (same dirty-response trigger).
     - `/v1/responses` & `/responses` — OpenAI Responses API JSON & SSE.
     - `/v1beta/models/*` — Gemini `generateContent` JSON & `streamGenerateContent` SSE.
     - `/model/*` — AWS Bedrock `invoke` JSON & `invoke-with-response-stream` binary AWS EventStream frames (with valid prelude + message CRC32 checksums).
   - **MCP route:**
     - `/mcp` — Streamable HTTP JSON-RPC 2.0 server supporting:
       - `initialize` → returns server capabilities + `Mcp-Session-Id`.
       - `ping` → empty JSON-RPC result.
       - `tools/list` → returns a realistic 12-tool catalog (mix of allowed/denied tools for ACL filtering).
       - `tools/call` → returns structured MCP tool result JSON (or SSE stream when `arguments.stream == true`, or indirect prompt-injection payload when `arguments.mode == "dirty"`).
       - `resources/list` & `resources/read` → deterministic stub responses.
   - Multi-port support: `bench.sh` can spawn multiple upstream instances (e.g., `:18080`, `:18082`, `:18083`, and a fault upstream `:18084` returning `503` via `--always-status 503`) for multi-endpoint load balancing and failover tests.

3. **`shunt-bench http`** (enhanced load generator)
   - **TLS & mTLS:** Automatically handles `https://` using workspace `tokio-rustls` + `rustls` with `--ca-cert <pem>` (or `--insecure`), optional `--client-cert` / `--client-key`, and ALPN negotiation (`h2` when `--http2` is set, else `http/1.1`).
   - **Open-loop rate mode (`--rate <rps>`):** Schedules requests on a deterministic pacing grid across workers and records latency from the *scheduled* timestamp (`Instant` before queue wait) rather than the actual send timestamp, preventing coordinated omission. Reports `mode: "open_loop"`, `target_rps`, `achieved_rps`, and `p50`/`p95`/`p99`/`p999`/`max`.
   - **Status assertion (`--expect-status <u16>`, default `200`):** Treats only the expected status code as `ok` (enabling accurate 401 auth rejection, 429 rate-limit shedding, and 400 guardrail block benchmarks with `errors == 0`).
   - **Payload presets & cache cardinality:**
     - `--body-preset <name>`: Built-in reproducible payloads (`ai-openai-small`, `ai-anthropic-small`, `ai-anthropic-4k`, `ai-anthropic-32k`, `ai-guardrails-clean-4k`, `ai-guardrails-dirty`, `ai-guardrails-injection`, `ai-responses-small`, `ai-bedrock-small`, `ai-gemini-small`, `mcp-tools-list`, `mcp-tools-call`, `mcp-tools-call-dirty`, `mcp-tools-call-loop`).
     - `--cache-cardinality <N>`: Substitutes `{{NONCE}}` in the request body with deterministic integers `0..N` (or monotonically increasing when `N == 0`), enabling exact **100% miss (`N=0`)**, **100% hit (`N=1`)**, and **mixed hit-rate (`N=2`, `N=10`)** cache benchmarks.
   - **Singleflight wave mode (`--single-wave`):** Fires `c` identical requests simultaneously from a barrier and reports total wall time, `ok`, `errors`, and `p50`/`p99` (used to validate `ai-cache` singleflight thundering-herd coalescing).
   - **Live reload driver (`--reload-url <url> --reload-interval-ms <ms>`):** Spawns a background task issuing `POST <reload_url>` throughout the measurement window and outputs `reloads_ok` and `reloads_failed` in the JSON result.

4. **`shunt-bench sse`** (enhanced streaming load generator)
   - Adds `https://` TLS support (`--ca-cert` / `--insecure`), `--body-preset`, `--expect-status`, `--require-done <bool>` (default `true`; `false` for non-OpenAI SSE formats like MCP SSE or guardrail `redact_and_stop`), and `ttfc_p999_us` in JSON output.

### 4.3 Canonical Workload Matrix & Profiles

| Suite | Workload ID | Description | Competitors | `quick` | `ci` | `full` |
| --- | --- | --- | --- | :---: | :---: | :---: |
| `api` | `api_raw_h1` | Raw HTTP/1.1 passthrough (256B, `HookMask::EMPTY`) | Envoy, Caddy | x | x | x |
| `api` | `api_raw_h2_tls` | Raw HTTPS + HTTP/2 (TLS 1.3 ALPN `h2`) | Envoy, Caddy | | x | x |
| `api` | `api_mtls_h2` | mTLS client cert verification + `mtls-auth` | — | | | x |
| `api` | `api_plugins_3` | 3-plugin chain (`request-id` + `bearer-auth` + `rate-limit`) | Envoy, Caddy | x | x | x |
| `api` | `api_jwt_security` | `request-id` + `ip-filter` + `jwt-auth` (HS256) + `body-limit` | Envoy | x | x | x |
| `api` | `api_jwt_zstd` | Security chain + streaming `zstd` on ~4.3 KB `/json` | Envoy, Caddy | | x | x |
| `api` | `api_routing_lb` | 200-route table + 3-endpoint EWMA/weighted pool + health probes | Envoy | | x | x |
| `api` | `api_large_stream` | 256 KB streaming passthrough (zero-copy check) | Envoy, Caddy | | x | x |
| `api` | `api_reject_401` | Invalid auth rejection fast-path (`--expect-status 401`) | Envoy | | x | x |
| `api` | `api_reject_429` | Rate-limit load-shedding fast-path (`--expect-status 429`) | Envoy | | | x |
| `api` | `api_observability_tax` | 3-plugin chain + `metrics` + `otel-trace` + `access-log` | — | | | x |
| `api` | `api_openloop_p99` | Open-loop fixed-rate (`--rate 25000`) latency on 3-plugin chain | Envoy, Caddy | | | x |
| `api` | `api_sse_passthrough` | High-concurrency SSE passthrough (`c=500` CI / `1000` full) | Envoy, Caddy | x | x | x |
| `ai` | `ai_openai_small` | Non-streaming OpenAI passthrough (3-plugin & 8-plugin governed) | LiteLLM (1w/4w) | x | x | x |
| `ai` | `ai_anthropic_small` | Non-streaming Anthropic ↔ OpenAI translate (3-plugin & 8-plugin) | LiteLLM (1w/4w) | x | x | x |
| `ai` | `ai_anthropic_4k` | Realistic 4 KB multi-turn prompt translate (8-plugin governed) | LiteLLM (4w) | | x | x |
| `ai` | `ai_anthropic_32k` | Realistic 32 KB multi-turn prompt translate (8-plugin governed) | LiteLLM (4w) | | | x |
| `ai` | `ai_guardrails_clean` | Inline guardrails (PII/secrets/injection/regex) on clean 4 KB prompt | — | | x | x |
| `ai` | `ai_guardrails_redact` | Inline guardrails redacting PII + secrets in request & response | — | | x | x |
| `ai` | `ai_guardrails_block` | Inline guardrails blocking prompt-injection pre-upstream (`400`) | — | | x | x |
| `ai` | `ai_cache_hit_json` | `ai-cache` exact-match 100% hit (zero upstream I/O) | — | x | x | x |
| `ai` | `ai_cache_miss_json` | `ai-cache` 100% miss (SHA-256 key hash + body capture + store) | — | | x | x |
| `ai` | `ai_cache_singleflight` | 100 concurrent identical uncached requests coalesced to 1 upstream call | — | | x | x |
| `ai` | `ai_multiprotocol` | `/v1/messages` ingress + `/v1/responses` + Bedrock SigV4 | — | | x | x |
| `ai` | `ai_failover` | Primary upstream `503` → `ai-failover` retry to healthy secondary | — | | x | x |
| `ai` | `ai_sse_translate` | High-concurrency Anthropic → OpenAI SSE translation (3-plugin & 8-plugin) | LiteLLM (1w/4w) | x | x | x |
| `ai` | `ai_sse_guardrails` | High-concurrency SSE with 64-char streaming holdback scanning | — | | x | x |
| `ai` | `ai_sse_cache_replay` | High-concurrency streaming SSE cache replay | — | | x | x |
| `mcp` | `mcp_tools_list_warm` | Virtual 2-server `tools/list` with ACL filtering (warm catalog cache) | — | x | x | x |
| `mcp` | `mcp_tools_call_governed` | Full 5-plugin MCP governance chain (`tools/call`, clean) | — | x | x | x |
| `mcp` | `mcp_guardrails_block` | Indirect prompt-injection blocking + SQL policy rejection (`tools/call`) | — | | x | x |
| `mcp` | `mcp_loop_breaker` | Runaway identical-call agent loop detection fast-path | — | | x | x |
| `mcp` | `mcp_sse_stream` | Concurrent Streamable HTTP SSE MCP tool calls | — | | x | x |
| `soak` | `soak_reload_under_load` | Continuous HTTP load with live `POST /reload` every 500ms (`0` errors) | — | | x | x |
| `soak` | `soak_rss_stability` | Consecutive governed AI bursts on same PID (`delta <= MAX_RSS_GROWTH_MB`) | — | | x | x |

### 4.4 Process Instrumentation & Unified JSONL Schema

Every case executed by `benches/scripts/bench.sh` records a single JSON object per line containing:
- Identity: `suite` (`api` | `ai` | `mcp` | `soak`), `id`, `label`, `gateway` (`shunt` | `envoy` | `caddy` | `litellm`), `variant` (e.g. `shunt-governed`, `litellm-4w-auth`), `workload` (`http` | `sse` | `reload` | `rss_soak`).
- Process metrics: `cold_start_ms`, `idle_rss_mb`, `post_rss_mb`, `proc_count`, `cpu_ms` (process-tree user+sys CPU delta during workload), `cpu_ms_per_1k_req`.
- Load-generator metrics: all fields emitted by `shunt-bench --json` (`rps`, `p50_us`, `p95_us`, `p99_us`, `p999_us`, `max_us`, `errors`, `completed`, `failed`, `chunks_per_sec`, `ttfc_p50_us`, `ttfc_p99_us`, `reloads_ok`, `reloads_failed`, etc.).

`benches/scripts/render_report.py` consumes this JSONL file and emits:
1. Environment & benchmark parameters table.
2. Footprint & Cold-Start summary (grouped by gateway/variant).
3. Sectioned results tables for **API Gateway**, **AI Gateway**, **MCP Gateway**, and **Stability & Reload Guardrails**.
4. Non-zero exit status if any workload records `errors > 0`, `failed > 0`, `reloads_failed > 0`, or `rss_delta_mb > MAX_RSS_GROWTH_MB`.

### 4.5 Phased Implementation Order

1. **Phase 1 — `shunt-bench` v2:** Add `gen-certs`, TLS/mTLS/H2 client support, `--rate` open-loop mode, `--expect-status`, payload presets & `--cache-cardinality`, `--single-wave`, `--reload-url`, and extended mock upstream endpoints (large bytes, status faults, Gemini/Responses/Bedrock EventStream, MCP JSON-RPC 2.0) with unit tests.
2. **Phase 2 — API Gateway configs (`benches/configs/api/`):** Author Shunt, Envoy, and Caddy configs covering all `api` suite workloads, verify with `shunt verify`, and fix Caddy's zero-error parity.
3. **Phase 3 — AI Gateway configs (`benches/configs/ai/`):** Author Shunt and LiteLLM configs covering all `ai` suite workloads (governed, guardrails, cache, multi-protocol/Bedrock, failover) and verify with `shunt verify`.
4. **Phase 4 — MCP Gateway configs (`benches/configs/mcp/`):** Author the 5-plugin Shunt MCP benchmark config and verify with `shunt verify`.
5. **Phase 5 — Unified Runner, CI & Docs:** Implement `benches/scripts/bench.sh` and `benches/scripts/render_report.py`, remove legacy split scripts and flat configs, update `.github/workflows/nightly-bench.yml`, execute local head-to-head benchmarks, and refresh `benches/README.md`, `README.md`, and RFC 0020 status.

## 5. Alternatives Considered & Rejected

1. **Keep separate API and AI scripts and add a third `run_mcp_bench.sh`:** Rejected—triplicating process lifecycle, port probing, tree-RSS collection, CPU accounting, and report formatting causes metric drift and makes cross-pillar CI reporting brittle.
2. **Adopt an external load generator (`oha`, `wrk2`, `k6`, `ghz`) as a required dependency:** Rejected—external tools vary across macOS/Linux CI runners, lack native multi-protocol SSE `[DONE]` / MCP JSON-RPC validation, and break Shunt's zero-dependency single-command reproduction promise. Extending `shunt-bench` using workspace crates keeps everything self-contained and deterministic.
3. **Rewrite the entire orchestrator in Rust inside `shunt-bench`:** Considered, and deferred for v1 of this refactor. Keeping process supervision + competitor CLI invocation in a clean POSIX/bash + Python 3 renderer (`bench.sh` + `render_report.py`) keeps competitor CLI flags transparent and easy to inspect/tweak, while keeping all hot-path networking, TLS, load generation, and mock servers in Rust (`shunt-bench`).
4. **Commit static TLS certificates to `benches/configs/`:** Rejected—triggers secret-scanning false positives and eventually expires. Generating ephemeral certs via `shunt-bench gen-certs` at runtime is deterministic, clean, and zero-maintenance.

## 6. Future Work

- **Compiled AI Gateway comparison profiles:** Add opt-in auto-detected profiles for compiled AI gateways (e.g., Bifrost or Envoy AI Gateway) alongside LiteLLM in `benches/configs/ai/`.
- **Automated nightly regression alerting:** Compare `nightly.jsonl` against a rolling baseline artifact to flag >15% RPS regressions or >25% p99 regressions in CI PR comments.
- **Redis/Valkey distributed governance benchmark profile:** Opt-in `--with-redis` flag measuring local `StateStore` vs. Redis/Valkey `DistributedStore` overhead for `rate-limit`, `ai-token-rate-limit`, `ai-budget`, and `mcp-rate-limit`.
