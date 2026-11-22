# Shunt Benchmarks

Reproducible, unified end-to-end benchmark suite (see [RFC 0020](../rfcs/0020-unified-comprehensive-benchmarks.md)) covering all three Shunt gateway pillars plus stability guardrails on identical local hardware:

1. **API Gateway (`--suite api`)**: Shunt vs. **Envoy** and **Caddy** across HTTP/1.1, TLS 1.3 + HTTP/2, mTLS, 3-plugin chain, HS256 JWT + streaming `zstd`, 200-route weighted LB + active health probes, 256 KB zero-copy streaming, 401/429 rejection fast-paths, observability overhead, coordinated-omission-free open-loop latency, and 1,000-stream SSE passthrough.
2. **AI Gateway (`--suite ai`)**: Shunt vs. **LiteLLM Proxy** (1w stateless & 4w auth+RPM/TPM) across ~70 B, realistic 4 KB, and 32 KB multi-turn prompts, 8-plugin governance, inline guardrails (clean, active PII/secret redaction, prompt-injection blocking, streaming holdback), exact/miss/singleflight/streaming AI cache, multi-protocol ingress (`/v1/messages`, `/v1/responses`), AWS Bedrock SigV4 + binary EventStream, Google Gemini, upstream 503 failover, and 1,000-stream live SSE translation.
3. **MCP & Agentic Gateway (`--suite mcp`)**: Full 5-plugin `shunt-mcp` governance chain (`mcp-auth`, `mcp-router`, `mcp-guardrails`, `mcp-rate-limit`, `mcp-telemetry`) across warm 2-server `tools/list` ACL filtering, governed `tools/call`, destructive SQL blocking, inbound indirect prompt-injection blocking, stuck-agent loop breaking, and Streamable HTTP SSE tool calls.
4. **Stability & Hot-Reload (`--suite soak`)**: Zero-error live `POST /reload` under continuous HTTP load (`ArcSwap`) and steady-state RSS growth guardrail.

---

## Components

- **`benches/shunt-bench`**: Self-contained Rust binary (zero external CLI tools required) providing:
  - `shunt-bench gen-certs`: Generates ephemeral CA, server (`127.0.0.1`/`localhost`), and mTLS client PEM certs using workspace `rcgen`.
  - `shunt-bench upstream`: HTTP/1.1 + HTTP/2 mock upstream serving API (`/ping`, `/json`, `/bytes/<n>`, `/health`, `/status/<code>`, `/sse`), AI (`/v1/chat/completions`, `/v1/messages`, `/v1/responses`, `/v1beta/models/*`, `/model/*/converse*` with CRC32-verified binary AWS EventStream), and MCP (`/mcp` JSON-RPC 2.0 + SSE).
  - `shunt-bench http`: Multi-worker HTTP/1.1, HTTP/2 (`h2`/`h2c`), TLS 1.3 / mTLS, closed-loop throughput, open-loop fixed-rate (`--rate <rps>`), `--single-wave`, `--expect-status`, payload presets + `--cache-cardinality`, and live `--reload-url` driver.
  - `shunt-bench sse`: High-concurrency SSE streaming load generator reporting completion, chunks/s, TTFC p50/p95/p99/p99.9, and wall time.
- **`benches/configs/{api,ai,mcp}/`**: Suite-partitioned Shunt, Envoy, Caddy, and LiteLLM configurations.
- **`benches/scripts/bench.sh`**: Single canonical orchestrator recording cold start, idle/post-run process-tree RSS, CPU-ms per 1k requests, and `shunt-bench --json` into unified JSONL.
- **`benches/scripts/render_report.py`**: Renders JSONL into sectioned Markdown reports and enforces zero-error / reload / RSS guardrails.

---

## Quick Start

```bash
# Quick developer sanity run (~30s, Shunt-only across all 4 suites):
./benches/scripts/bench.sh --profile quick --suite all

# Full head-to-head run (auto-detects Envoy, Caddy & LiteLLM if installed):
./benches/scripts/bench.sh --profile full --suite all --competitors auto

# Run a single suite (api, ai, mcp, soak, or comma-separated):
./benches/scripts/bench.sh --suite api --profile full --competitors envoy,caddy
./benches/scripts/bench.sh --suite ai  --profile full --competitors litellm
./benches/scripts/bench.sh --suite mcp --profile ci

# Generate a CI-style Markdown report + raw JSONL:
./benches/scripts/bench.sh --profile ci --suite all --competitors none \
  --output-md benches/results/nightly.md --output-json /tmp/shunt-bench.jsonl
```

### Installing Optional Competitors for Head-to-Head Runs

```bash
# Envoy & Caddy (macOS Homebrew):
brew install envoy caddy

# LiteLLM Proxy in an isolated virtualenv (auto-detected at /tmp/litellm-bench-venv/bin/litellm):
uv venv --python 3.12 /tmp/litellm-bench-venv
uv pip install --python /tmp/litellm-bench-venv/bin/python 'litellm[proxy]'
```

---

## Reference Results (Apple M5 Pro, macOS arm64, Local Loopback)

Measured with `./benches/scripts/bench.sh --profile full --suite all --competitors auto` (`DURATION_SECS=5`, `WARMUP_SECS=2`, `HTTP_CONCURRENCY=64`, `SSE_MED_CONCURRENCY=200`, `SSE_CONCURRENCY=1000`, `SSE_CHUNKS=20`, `SSE_INTERVAL_MS=25`, `OPENLOOP_RATE=25000`) comparing a single **Shunt (`--release`)** binary against **Envoy 1.40.2**, **Caddy v2.11.9**, and **LiteLLM Proxy 1.110.2** (stateless no-DB mode, 1w & 4w, summing RSS and CPU across all worker processes).

### Footprint & Cold Start

| Gateway / Profile | Cold Start | Idle RSS | Processes |
| --- | ---: | ---: | ---: |
| **Shunt** *(API raw / TLS / 3-plugin / JWT+zstd / 200-route LB)* | **34–42 ms** | **10.3–12.1 MB** | 1 |
| **Shunt AI** *(3-plugin / 8-plugin governed / guardrails / cache / multi-protocol)* | **32–37 ms** | **11.3–12.9 MB** | 1 |
| **Shunt MCP** *(5-plugin virtual multiplexer + guardrails + loop breaker)* | **35 ms** | **12.5 MB** | 1 |
| **Envoy 1.40.2** *(raw / TLS / 3-filter / jwt+zstd / 200-route LB)* | 48–68 ms | 45.6–47.8 MB | 1 |
| **Caddy v2.11.9** *(raw / TLS / headers+auth / zstd)* | 65–70 ms | 41.7–42.6 MB | 1 |
| **LiteLLM 1.110.2** *(1 worker, stateless no-DB)* | 7,688 ms | 369.0 MB | 1 |
| **LiteLLM 1.110.2** *(4 workers, auth + in-memory rpm/tpm)* | 15,207 ms | 1,873.2 MB | 6 |

---

### 1. API Gateway Suite

#### HTTP Throughput, Tail Latency & CPU Efficiency (`c=64`)

| Workload | Gateway | Throughput | p50 | p99 | p99.9 | CPU / 1k | RSS | Errors |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Raw HTTP/1.1 Passthrough (`256 B`, `HookMask::EMPTY`) | **Shunt (raw)** | **84,771 req/s** | **748 µs** | **1.02 ms** | **1.19 ms** | **84.4 ms** | **22.5 MB** | 0 |
| ↳ | Envoy 1.40.2 | 78,315 req/s | 797 µs | 1.15 ms | 1.30 ms | 105.6 ms | 53.6 MB | 0 |
| ↳ | Caddy v2.11.9 | 69,862 req/s | 845 µs | 2.28 ms | 3.30 ms | 175.8 ms | 72.9 MB | 0 |
| 256 KB Streaming Passthrough (Zero-Copy) | **Shunt (raw)** | **17,488 req/s** | **3.66 ms** | **4.44 ms** | **4.77 ms** | **240.0 ms** | 73.4 MB | 0 |
| ↳ | Envoy 1.40.2 | 14,925 req/s | 4.29 ms | 5.15 ms | 5.77 ms | 330.0 ms | **66.1 MB** | 0 |
| ↳ | Caddy v2.11.9 | 13,785 req/s | 4.64 ms | 5.74 ms | 6.50 ms | 454.1 ms | 72.9 MB | 0 |
| HTTPS + HTTP/2 Multiplexed Passthrough (TLS 1.3) | **Shunt (TLS 1.3 + H2)** | 90,928 req/s | 695 µs | **962 µs** | **1.13 ms** | 87.7 ms | **22.6 MB** | 0 |
| ↳ | Envoy 1.40.2 | **99,865 req/s** | **550 µs** | 1.41 ms | 2.02 ms | **60.8 ms** | 53.2 MB | 0 |
| ↳ | Caddy v2.11.9 | 66,982 req/s | 870 µs | 2.24 ms | 3.05 ms | 188.2 ms | 77.0 MB | 0 |
| mTLS + `mtls-auth` SPIFFE/CN Verification (HTTP/2) | **Shunt (mTLS + H2)** | **89,556 req/s** | **710 µs** | **984 µs** | **1.12 ms** | **92.8 ms** | **23.5 MB** | 0 |
| 3-Plugin Chain (`request-id` + `bearer-auth` + `rate-limit`) | **Shunt (3-plugin)** | **83,596 req/s** | **758 µs** | **1.04 ms** | **1.20 ms** | **89.0 ms** | **24.0 MB** | 0 |
| ↳ | Envoy 1.40.2 | 71,981 req/s | 881 µs | 1.11 ms | 1.34 ms | 118.8 ms | 55.4 MB | 0 |
| ↳ | Caddy v2.11.9 *(headers + auth)* | 69,174 req/s | 846 µs | 2.40 ms | 3.50 ms | 176.7 ms | 72.4 MB | 0 |
| Auth Rejection Fast-Path (`401`, Zero Upstream I/O) | **Shunt (3-plugin)** | **178,979 req/s** | **354 µs** | **595 µs** | **712 µs** | **32.8 ms** | **24.1 MB** | 0 |
| ↳ | Envoy 1.40.2 | 149,018 req/s | 424 µs | 601 µs | 715 µs | 56.4 ms | 56.2 MB | 0 |
| JWT HS256 & Security Chain (`ip-filter` + `jwt-auth` + `body-limit`) | **Shunt (JWT + Security)** | 71,576 req/s | 887 µs | **1.21 ms** | 1.52 ms | **117.1 ms** | **25.2 MB** | 0 |
| ↳ | Envoy 1.40.2 *(`jwt_authn`)* | **76,846 req/s** | **794 µs** | 1.30 ms | **1.50 ms** | 125.2 ms | 56.9 MB | 0 |
| JWT + Security + Streaming `zstd` (~4.3 KB `/json`) | **Shunt (JWT + zstd)** | **68,664 req/s** | **924 µs** | **1.27 ms** | **1.72 ms** | **136.2 ms** | **38.5 MB** | 0 |
| ↳ | Envoy 1.40.2 *(`jwt_authn + zstd`)* | 66,309 req/s | 957 µs | 1.42 ms | 2.38 ms | 169.4 ms | 84.4 MB | 0 |
| ↳ | Caddy v2.11.9 *(`encode zstd`, no JWT)* | 62,834 req/s | 980 µs | 1.98 ms | 4.42 ms | 189.5 ms | 252.7 MB | 0 |
| 200-Route Table + 3-Endpoint Weighted LB + Health Probes | **Shunt (200 routes + LB)** | **78,900 req/s** | **804 µs** | **1.06 ms** | **1.24 ms** | **85.2 ms** | **23.6 MB** | 0 |
| ↳ | Envoy 1.40.2 | 62,018 req/s | 1.02 ms | 1.24 ms | 1.39 ms | 126.2 ms | 56.4 MB | 0 |
| Rate-Limit Shedding Fast-Path (`429`, Zero Upstream I/O) | **Shunt (`rate-limit` 429)** | **177,667 req/s** | **357 µs** | **587 µs** | **700 µs** | **34.5 ms** | **18.3 MB** | 0 |
| ↳ | Envoy 1.40.2 *(`local_ratelimit` 429)* | 142,781 req/s | 442 µs | 628 µs | 734 µs | 56.7 ms | 54.0 MB | 0 |
| Observability Tax (3-Plugin + `metrics` + `otel-trace` + `access-log`) | **Shunt (full observability)** | **73,856 req/s** | **858 µs** | **1.18 ms** | **1.42 ms** | **105.9 ms** | **25.7 MB** | 0 |

#### Open-Loop Fixed-Rate Tail Latency (`25,000 req/s`, Coordinated-Omission Free)

| Workload | Gateway | Achieved RPS | p50 | p99 | p99.9 | Max | CPU / 1k | RSS | Errors |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Open-Loop 3-Plugin Chain | **Shunt (3-plugin)** | 24,987 req/s | **1.46 ms** | **3.37 ms** | **4.22 ms** | **6.00 ms** | **46.2 ms** | **24.2 MB** | 0 |
| ↳ | Envoy 1.40.2 | 24,990 req/s | 1.76 ms | 5.81 ms | 16.23 ms | 21.38 ms | 98.0 ms | 56.7 MB | 0 |
| ↳ | Caddy v2.11.9 | 24,990 req/s | 1.60 ms | 4.69 ms | 6.25 ms | 8.33 ms | 189.2 ms | 72.5 MB | 0 |

#### High-Concurrency SSE Passthrough (`c=1,000`, 20 chunks @ 25ms)

| Workload | Gateway | Completed / Failed | Chunks/s | TTFC p50 / p99 | Wall Time | RSS |
| --- | --- | :---: | ---: | ---: | ---: | ---: |
| SSE Passthrough | **Shunt** | **1,000 / 0** | 31,478/s | 71.4 ms / 135.4 ms | 0.67s | **86.1 MB** |
| ↳ | Envoy 1.40.2 | 1,000 / 0 | 25,582/s | 136.0 ms / 286.8 ms | 0.82s | 91.7 MB |
| ↳ | Caddy v2.11.9 | 1,000 / 0 | **31,774/s** | **50.1 ms** / **135.2 ms** | **0.66s** | 158.7 MB |

---

### 2. AI Gateway Suite

#### Non-Streaming Chat, Translation, Realistic Payloads, Guardrails, Cache, Multi-Protocol & Failover (`c=64`)

| Workload | Gateway | Throughput | p50 | p99 | p99.9 | CPU / 1k | RSS | Errors |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| OpenAI Chat Passthrough (~70 B) | **Shunt AI (3-plugin)** | **70,143 req/s** | **906 µs** | **1.21 ms** | **1.44 ms** | **132.5 ms** | **26.6 MB** | 0 |
| ↳ | **Shunt AI Governed (8-plugin)** | **64,918 req/s** | **978 µs** | **1.32 ms** | **1.58 ms** | **151.4 ms** | **28.7 MB** | 0 |
| ↳ | LiteLLM (1w, stateless) | 317 req/s | 208.9 ms | 222.7 ms | 224.0 ms | 4,483 ms | 390.6 MB | 0 |
| ↳ | LiteLLM (4w, auth+rpm/tpm) | 703 req/s | 95.2 ms | 115.3 ms | 117.2 ms | 8,039 ms | 1,942 MB (6p) | 0 |
| Anthropic ↔ OpenAI Translate (~70 B) | **Shunt AI (3-plugin)** | **67,932 req/s** | **936 µs** | **1.25 ms** | **1.44 ms** | **141.1 ms** | **28.0 MB** | 0 |
| ↳ | **Shunt AI Governed (8-plugin)** | **60,544 req/s** | **1.05 ms** | **1.39 ms** | **1.61 ms** | **164.6 ms** | **29.6 MB** | 0 |
| ↳ | LiteLLM (1w, stateless) | 305 req/s | 218.5 ms | 236.7 ms | 236.7 ms | 4,685 ms | 421.3 MB | 0 |
| ↳ | LiteLLM (4w, auth+rpm/tpm) | 727 req/s | 87.6 ms | 115.4 ms | 120.7 ms | 7,814 ms | 2,068 MB (6p) | 0 |
| Realistic 4 KB Multi-Turn Translate (Governed) | **Shunt AI Governed (8-plugin)** | **56,296 req/s** | **1.12 ms** | **1.57 ms** | **1.96 ms** | **220.9 ms** | **31.8 MB** | 0 |
| ↳ | LiteLLM (4w, auth+rpm/tpm) | 598 req/s | 110.2 ms | 117.4 ms | 118.6 ms | 9,542 ms | 2,071 MB (6p) | 0 |
| Realistic 32 KB Multi-Turn Translate (Governed) | **Shunt AI Governed (8-plugin)** | **23,377 req/s** | **2.57 ms** | **7.17 ms** | **16.24 ms** | **669.2 ms** | **57.4 MB** | 0 |
| ↳ | LiteLLM (4w, auth+rpm/tpm) | 485 req/s | 134.6 ms | 154.6 ms | 160.0 ms | 11,765 ms | 2,075 MB (6p) | 0 |
| Inline Guardrails — Clean 4 KB Prompt | **Shunt AI Guardrailed** | **45,956 req/s** | 1.25 ms | 2.75 ms | 7.65 ms | 294.4 ms | 37.6 MB | 0 |
| Inline Guardrails — Active PII/Secret Redaction (Req + Resp) | **Shunt AI Guardrailed** | **54,056 req/s** | 1.17 ms | 1.78 ms | 2.62 ms | 250.7 ms | 41.5 MB | 0 |
| Inline Guardrails — Prompt-Injection Block (`400` Pre-Upstream) | **Shunt AI Guardrailed** | **139,606 req/s** | 447 µs | 778 µs | 951 µs | 62.3 ms | 45.8 MB | 0 |
| AI Cache — 100% Exact-Match Hit (Zero Upstream I/O) | **Shunt AI Cached** | **141,280 req/s** | 443 µs | 768 µs | 1.02 ms | 60.5 ms | 27.5 MB | 0 |
| AI Cache — 100% Miss Path (Key Hash + Capture + Evict) | **Shunt AI Cached** | **57,743 req/s** | 1.10 ms | 1.50 ms | 1.78 ms | 170.6 ms | 36.5 MB | 0 |
| Multi-Protocol Ingress (`POST /v1/messages` → OpenAI) | **Shunt AI Multi-Protocol** | **63,183 req/s** | 1.00 ms | 1.35 ms | 1.53 ms | 149.9 ms | 27.3 MB | 0 |
| Multi-Protocol Ingress (`POST /v1/responses` → Anthropic) | **Shunt AI Multi-Protocol** | **57,096 req/s** | 1.11 ms | 1.51 ms | 2.30 ms | 162.1 ms | 28.3 MB | 0 |
| AWS Bedrock Converse + Pure-Rust SigV4 Signing | **Shunt AI Multi-Protocol** | **60,385 req/s** | 1.05 ms | 1.41 ms | 1.62 ms | 166.1 ms | 31.6 MB | 0 |
| Google Gemini `generateContent` Dialect Translation | **Shunt AI Multi-Protocol** | **58,674 req/s** | 1.08 ms | 1.45 ms | 1.69 ms | 154.9 ms | 31.7 MB | 0 |
| Upstream 503 Failover & Circuit Breaker (`ai-failover`) | **Shunt AI Failover** | **63,068 req/s** | 1.01 ms | 1.37 ms | 1.67 ms | 144.1 ms | 29.7 MB | 0 |

- **Singleflight Thundering-Herd Coalescing (`ai-cache`):** 100 concurrent identical cache misses coalesced with **100 / 0** ok/errors, p50 **2.49 ms**, p99 **3.44 ms**, **4 ms** wall time.

#### High-Concurrency AI SSE Streaming (`20 chunks @ 25ms`)

| Workload | Gateway | Concurrency | Completed / Failed | Chunks/s | TTFC p50 / p99 | Wall Time | RSS |
| --- | --- | ---: | :---: | ---: | ---: | ---: | ---: |
| Live SSE Translation (`Anthropic → OpenAI`) | **Shunt AI Governed (8-plugin)** | 200 | **200 / 0** | **7,059/s** | **8.6 ms** / **33.4 ms** | **0.65s** | **67.7 MB** |
| ↳ | LiteLLM (4w, auth+rpm/tpm) | 200 | 200 / 0 | 4,838/s | 287.0 ms / 374.2 ms | 0.91s | 2,102 MB (6p) |
| ↳ | LiteLLM (1w, stateless) | 200 | 200 / 0 | 1,815/s | 794.7 ms / 1.89 s | 2.42s | 440.9 MB |
| Live SSE Translation (`Anthropic → OpenAI`) | **Shunt AI Governed (8-plugin)** | 1,000 | **1,000 / 0** | **31,145/s** | **72.1 ms** / **131.6 ms** | **0.74s** | **132.8 MB** |
| ↳ | **Shunt AI (3-plugin)** | 1,000 | **1,000 / 0** | 30,876/s | 72.2 ms / **130.3 ms** | **0.74s** | **103.8 MB** |
| ↳ | LiteLLM (4w, auth+rpm/tpm) | 1,000 | 1,000 / 0 | 3,319/s | 1.39 s / 6.07 s | 6.63s | 2,165 MB (6p) |
| Guardrailed SSE (`Anthropic → OpenAI` + 64-char Holdback) | **Shunt AI Guardrailed** | 1,000 | **1,000 / 0** | 14,755/s *(coalesced)* | **47.8 ms** / 133.6 ms | 0.75s | 121.7 MB |
| Streaming SSE Cache Replay (`ai-cache`, Zero Upstream I/O) | **Shunt AI Cached** | 1,000 | **1,000 / 0** | 9,782/s | **38.1 ms** / **94.8 ms** | **0.10s** | **45.5 MB** |
| AWS Bedrock `ConverseStream` Binary EventStream → OpenAI SSE | **Shunt AI Multi-Protocol** | 200 | **200 / 0** | **7,272/s** | **6.1 ms** / 69.4 ms | **0.66s** | **42.6 MB** |

---

### 3. MCP & Agentic Gateway Suite (`shunt-mcp`, 5-Plugin Chain)

| Workload | Throughput | p50 | p99 | p99.9 | CPU / 1k | RSS | Errors |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Virtual 2-Server `tools/list` + ACL Tool Filtering (Warm Catalog) | **63,531 req/s** | 978 µs | 2.13 ms | 2.64 ms | 148.0 ms | 25.8 MB | 0 |
| Governed `tools/call` (Auth + Route + SQL/Secret Guardrails + Limits) | **77,069 req/s** | 819 µs | 1.17 ms | 1.37 ms | 128.2 ms | 57.2 MB | 0 |
| MCP Guardrails — Destructive SQL Argument Block (`403` Pre-Upstream) | **162,837 req/s** | 385 µs | 671 µs | 819 µs | 50.0 ms | 55.7 MB | 0 |
| MCP Guardrails — Inbound Indirect Prompt-Injection Block (JSON-RPC `-32005`) | **75,901 req/s** | 830 µs | 1.21 ms | 1.55 ms | 129.7 ms | 56.4 MB | 0 |
| MCP Agent Loop Breaker — Identical-Call Rejection (`429` Fast-Path) | **160,028 req/s** | 391 µs | 672 µs | 812 µs | 56.9 ms | 52.5 MB | 0 |

- **Streamable HTTP SSE `tools/call` (`c=200`, 5-plugin governed):** **200 / 0** completed, **7,443 chunks/s**, TTFC p50 **6.45 ms** / p99 **31.64 ms**, wall time **0.56s**, RSS **64.5 MB**.

---

### 4. Stability, Hot-Reload & Memory Guardrails

- **Live `POST /reload` Under Load** (`c=64`, 3-plugin chain, reloading every 500 ms): **84,760 req/s**, p50 **749 µs**, p99 **1.02 ms**, **9 / 0** reloads succeeded, **0** request errors (**PASS**).
- **Steady-State RSS Stability** (8-plugin governed AI, 345k OpenAI + 327k Anthropic requests on the same PID): `28.6 MB → 29.6 MB` (**+1.0 MB** delta, guardrail `<= 20.0 MB`, **PASS**).
