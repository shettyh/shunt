---
title: Benchmarks
description: Reproducible end-to-end Shunt performance benchmarks across HTTP API, multi-provider AI, MCP agentic governance, and zero-downtime hot reloads.
---

All benchmarks are produced by Shunt's self-contained, reproducible Rust benchmark harness (`benches/shunt-bench` + `benches/scripts/bench.sh`, RFC 0020) running a single `--release` binary on local loopback (**Apple M5 Pro, macOS arm64**, `c=64` HTTP concurrency, `c=200` / `c=1,000` SSE concurrency, `DURATION_SECS=5`, `WARMUP_SECS=2`).

## Footprint & Cold Start

| Shunt Profile | Cold Start | Idle RSS | Processes |
| --- | ---: | ---: | ---: |
| **HTTP API Core** *(raw / TLS / 3-plugin / JWT+zstd / 200-route LB)* | **34–42 ms** | **10.3–12.1 MB** | 1 |
| **AI Gateway** *(3-plugin / 8-plugin governed / guardrails / cache / multi-protocol)* | **32–37 ms** | **11.3–12.9 MB** | 1 |
| **MCP Gateway** *(5-plugin virtual multiplexer + guardrails + loop breaker)* | **35 ms** | **12.5 MB** | 1 |

---

## 1. HTTP API Gateway Suite (`--suite api`)

### Closed-Loop Throughput, Tail Latency & Efficiency (`c=64`)

| Workload | Throughput | p50 | p99 | p99.9 | CPU / 1k | RSS | Errors |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Raw HTTP/1.1 Passthrough (`256 B`, `HookMask::EMPTY`) | **84,771 req/s** | 748 µs | **1.02 ms** | 1.19 ms | 84.4 ms | 22.5 MB | 0 |
| 256 KB Streaming Passthrough (Zero-Copy) | **17,488 req/s** | 3.66 ms | **4.44 ms** | 4.77 ms | 240.0 ms | 73.4 MB | 0 |
| HTTPS + HTTP/2 Multiplexed (TLS 1.3) | **90,928 req/s** | 695 µs | **962 µs** | 1.13 ms | 87.7 ms | 22.6 MB | 0 |
| mTLS + `mtls-auth` SPIFFE/CN Verification (HTTP/2) | **89,556 req/s** | 710 µs | **984 µs** | 1.12 ms | 92.8 ms | 23.5 MB | 0 |
| 3-Plugin Chain (`request-id` + `bearer-auth` + `rate-limit`) | **83,596 req/s** | 758 µs | **1.04 ms** | 1.20 ms | 89.0 ms | 24.0 MB | 0 |
| Auth Rejection Fast-Path (`401`, Zero Upstream I/O) | **178,979 req/s** | 354 µs | **595 µs** | 712 µs | 32.8 ms | 24.1 MB | 0 |
| Rate-Limit Shedding Fast-Path (`429`, Zero Upstream I/O) | **177,667 req/s** | 357 µs | **587 µs** | 700 µs | 34.5 ms | 18.3 MB | 0 |
| JWT HS256 & Security Chain (`ip-filter` + `jwt-auth` + `body-limit`) | **71,576 req/s** | 887 µs | **1.21 ms** | 1.52 ms | 117.1 ms | 25.2 MB | 0 |
| JWT + Security + Streaming `zstd` (~4.3 KB `/json`) | **68,664 req/s** | 924 µs | **1.27 ms** | 1.72 ms | 136.2 ms | 38.5 MB | 0 |
| 200-Route Table + 3-Endpoint Weighted LB + Health Probes | **78,900 req/s** | 804 µs | **1.06 ms** | 1.24 ms | 85.2 ms | 23.6 MB | 0 |
| Full Observability (`3-plugin` + `metrics` + `otel-trace` + `access-log`) | **73,856 req/s** | 858 µs | **1.18 ms** | 1.42 ms | 105.9 ms | 25.7 MB | 0 |

### Open-Loop Fixed-Rate & High-Concurrency SSE

- **Open-Loop 25,000 req/s** *(3-plugin chain, coordinated-omission free)*: **24,987 req/s** achieved, p50 **1.46 ms**, p99 **3.37 ms**, p99.9 **4.22 ms**, max **6.00 ms**, RSS **24.2 MB**, **0** errors.
- **1,000 Concurrent SSE Streams** *(20 chunks @ 25ms)*: **1,000 / 0** completed, **31,478 chunks/s**, TTFC p50 **71.4 ms** / p99 **135.4 ms**, wall time **0.67s**, RSS **86.1 MB**.

---

## 2. AI Gateway Suite (`--suite ai`)

### Chat, Translation, Guardrails, Cache, Multi-Protocol & Failover (`c=64`)

| Workload | Throughput | p50 | p99 | p99.9 | CPU / 1k | RSS | Errors |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| OpenAI Chat Passthrough (`3-plugin`) | **70,143 req/s** | 906 µs | **1.21 ms** | 1.44 ms | 132.5 ms | 26.6 MB | 0 |
| OpenAI Chat Governed (`8-plugin`) | **64,918 req/s** | 978 µs | **1.32 ms** | 1.58 ms | 151.4 ms | 28.7 MB | 0 |
| Anthropic ↔ OpenAI Translate (`3-plugin`) | **67,932 req/s** | 936 µs | **1.25 ms** | 1.44 ms | 141.1 ms | 28.0 MB | 0 |
| Anthropic ↔ OpenAI Translate (`8-plugin` governed) | **60,544 req/s** | 1.05 ms | **1.39 ms** | 1.61 ms | 164.6 ms | 29.6 MB | 0 |
| Realistic 4 KB Multi-Turn Translate (`8-plugin` governed) | **56,296 req/s** | 1.12 ms | **1.57 ms** | 1.96 ms | 220.9 ms | 31.8 MB | 0 |
| Realistic 32 KB Multi-Turn Translate (`8-plugin` governed) | **23,377 req/s** | 2.57 ms | **7.17 ms** | 16.24 ms | 669.2 ms | 57.4 MB | 0 |
| Inline Guardrails — Clean 4 KB Prompt | **45,956 req/s** | 1.25 ms | **2.75 ms** | 7.65 ms | 294.4 ms | 37.6 MB | 0 |
| Inline Guardrails — Active PII/Secret Redaction (Req + Resp) | **54,056 req/s** | 1.17 ms | **1.78 ms** | 2.62 ms | 250.7 ms | 41.5 MB | 0 |
| Inline Guardrails — Prompt-Injection Block (`400` Pre-Upstream) | **139,606 req/s** | 447 µs | **778 µs** | 951 µs | 62.3 ms | 45.8 MB | 0 |
| AI Cache — 100% Exact-Match Hit (Zero Upstream I/O) | **141,280 req/s** | 443 µs | **768 µs** | 1.02 ms | 60.5 ms | 27.5 MB | 0 |
| AI Cache — 100% Miss Path (Key Hash + Capture + Evict) | **57,743 req/s** | 1.10 ms | **1.50 ms** | 1.78 ms | 170.6 ms | 36.5 MB | 0 |
| Multi-Protocol Ingress (`POST /v1/messages` → OpenAI) | **63,183 req/s** | 1.00 ms | **1.35 ms** | 1.53 ms | 149.9 ms | 27.3 MB | 0 |
| Multi-Protocol Ingress (`POST /v1/responses` → Anthropic) | **57,096 req/s** | 1.11 ms | **1.51 ms** | 2.30 ms | 162.1 ms | 28.3 MB | 0 |
| AWS Bedrock Converse + Pure-Rust SigV4 Signing | **60,385 req/s** | 1.05 ms | **1.41 ms** | 1.62 ms | 166.1 ms | 31.6 MB | 0 |
| Google Gemini `generateContent` Dialect Translation | **58,674 req/s** | 1.08 ms | **1.45 ms** | 1.69 ms | 154.9 ms | 31.7 MB | 0 |
| Upstream 503 Failover & Circuit Breaker (`ai-failover`) | **63,068 req/s** | 1.01 ms | **1.37 ms** | 1.67 ms | 144.1 ms | 29.7 MB | 0 |

- **Singleflight Thundering-Herd Coalescing (`ai-cache`):** 100 concurrent identical cache misses coalesced with **100 / 0** ok/errors, p50 **2.49 ms**, p99 **3.44 ms**, **4 ms** total wall time.

### High-Concurrency AI SSE Streaming (`20 chunks @ 25ms`)

| Workload | Concurrency | Completed / Failed | Chunks/s | TTFC p50 / p99 | Wall Time | RSS |
| --- | ---: | :---: | ---: | ---: | ---: | ---: |
| Live SSE Translation (`Anthropic → OpenAI`, 8-plugin governed) | 200 | **200 / 0** | **7,059/s** | 8.6 ms / 33.4 ms | 0.65s | 67.7 MB |
| Live SSE Translation (`Anthropic → OpenAI`, 8-plugin governed) | 1,000 | **1,000 / 0** | **31,145/s** | 72.1 ms / 131.6 ms | 0.74s | 132.8 MB |
| Live SSE Translation (`Anthropic → OpenAI`, 3-plugin) | 1,000 | **1,000 / 0** | **30,876/s** | 72.2 ms / 130.3 ms | 0.74s | 103.8 MB |
| Guardrailed SSE (`Anthropic → OpenAI` + 64-char Holdback) | 1,000 | **1,000 / 0** | **14,755/s** *(coalesced)* | 47.8 ms / 133.6 ms | 0.75s | 121.7 MB |
| Streaming SSE Cache Replay (`ai-cache`, Zero Upstream I/O) | 1,000 | **1,000 / 0** | **9,782/s** | 38.1 ms / 94.8 ms | 0.10s | 45.5 MB |
| AWS Bedrock `ConverseStream` Binary EventStream → OpenAI SSE | 200 | **200 / 0** | **7,272/s** | 6.1 ms / 69.4 ms | 0.66s | 42.6 MB |

---

## 3. MCP & Agentic Gateway Suite (`--suite mcp`)

Full 5-plugin `shunt-mcp` governance chain (`mcp-auth`, `mcp-router`, `mcp-guardrails`, `mcp-rate-limit`, `mcp-telemetry`):

| Workload | Throughput | p50 | p99 | p99.9 | CPU / 1k | RSS | Errors |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Virtual 2-Server `tools/list` + ACL Filtering (Warm Catalog) | **63,531 req/s** | 978 µs | **2.13 ms** | 2.64 ms | 148.0 ms | 25.8 MB | 0 |
| Governed `tools/call` (Auth + Route + SQL/Secret Guardrails + Limits) | **77,069 req/s** | 819 µs | **1.17 ms** | 1.37 ms | 128.2 ms | 57.2 MB | 0 |
| Destructive SQL Argument Block (`403` Pre-Upstream) | **162,837 req/s** | 385 µs | **671 µs** | 819 µs | 50.0 ms | 55.7 MB | 0 |
| Inbound Indirect Prompt-Injection Block (JSON-RPC `-32005`) | **75,901 req/s** | 830 µs | **1.21 ms** | 1.55 ms | 129.7 ms | 56.4 MB | 0 |
| Agent Loop Breaker — Identical-Call Rejection (`429` Fast-Path) | **160,028 req/s** | 391 µs | **672 µs** | 812 µs | 56.9 ms | 52.5 MB | 0 |

- **Streamable HTTP SSE `tools/call` (`c=200`, 5-plugin governed):** **200 / 0** completed, **7,443 chunks/s**, TTFC p50 **6.45 ms** / p99 **31.64 ms**, wall time **0.56s**, RSS **64.5 MB**.

---

## 4. Stability, Hot-Reload & Memory Soak (`--suite soak`)

- **Live `POST /reload` Under Load** *(c=64, 3-plugin chain, reloading every 500 ms)*: **84,760 req/s**, p50 **749 µs**, p99 **1.02 ms**, **9 / 0** reloads succeeded, **0** request errors (**PASS**).
- **Steady-State RSS Stability** *(8-plugin governed AI, 672k requests on the same PID)*: `28.6 MB → 29.6 MB` (**+1.0 MB** delta, guardrail `<= 20.0 MB`, **PASS**).

---

## Reproduce on Your Own Hardware

```bash
# Quick ~30s Shunt-only run across all 4 suites:
./benches/scripts/bench.sh --profile quick --suite all

# Full Shunt benchmark report:
./benches/scripts/bench.sh --profile full --suite all --competitors none \
  --output-md /tmp/shunt-bench-report.md
```
