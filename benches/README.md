# Shunt Benchmarks

Reproducible end-to-end benchmark harness comparing **Shunt** against **Caddy** and **Envoy** on identical hardware across three workloads (see [RFC 0005](../rfcs/0005-benchmarks-and-hardening.md)).

## Components

- **`benches/shunt-bench`**: Self-contained Rust binary providing:
  - `shunt-bench upstream`: Ultra-fast HTTP/1.1 + HTTP/2 mock upstream serving `/ping` (fixed 256B), `/json` (compressible ~4.3 KB JSON), `/sse` (OpenAI SSE), `/v1/chat/completions` (OpenAI JSON/SSE), and `/v1/messages` (Anthropic JSON/SSE).
  - `shunt-bench http`: Multi-worker keep-alive HTTP/1.1 & HTTP/2 load generator reporting RPS and exact p50/p95/p99/max latencies.
  - `shunt-bench sse`: High-concurrency SSE load generator (default 1,000 concurrent streams) reporting stream completion, chunks/sec, TTFC p50/p95/p99, and total duration.
- **`benches/configs/`**: Equivalent Shunt, Caddy, Envoy, and LiteLLM configurations covering:
  1. **Workload 1 (`*-raw.*`)**: Raw passthrough (`HookMask::EMPTY`, 0 plugins).
  2. **Workload 2 (`*-plugins.*`)**: 3-plugin chain (`request-id` + `bearer-auth` + local `rate-limit`).
  3. **Workload 2b/2c (`shunt-security-compression.toml`)**: Modern API gateway security & compression chain (`request-id` + `ip-filter` + `jwt-auth` HS256 with issuer/audience/scope checks + `body-limit` + streaming `zstd`/`br`/`gzip`).
  4. **Workload 3 (`*-sse.*`)**: 1,000+ concurrent SSE streams (both raw passthrough and Shunt-AI live Anthropic → OpenAI SSE translation + token tracking).
  5. **AI Workloads (`shunt-ai-*.toml`, `litellm-bench*.yaml`)**: Minimal 3-plugin AI chain, 8-plugin governance chain, inline `ai-guardrails` (PII/secrets/prompt-injection/regex/keywords + streaming holdback), and `ai-cache` (exact-match JSON & streaming SSE cache replay).
- **`benches/scripts/run_all.sh`**: Automated orchestrator that builds `--release` binaries, launches the mock upstream, and runs every HTTP/SSE workload against Shunt (plus Caddy and Envoy whenever `caddy` / `envoy` are on `PATH`).
- **`benches/scripts/run_litellm_bench.sh`**: Reproducible head-to-head AI Gateway benchmark comparing **Shunt** (minimal 3-plugin, 8-plugin governed, inline guardrails, and exact/streaming cache) against **LiteLLM Proxy** (1-worker and 4-worker stateless no-DB modes) across non-streaming JSON chat completions, Anthropic ↔ OpenAI translation, and high-concurrency SSE streaming.

## Quick Start

```bash
# Run all 3 workloads against Shunt (and Caddy/Envoy if installed):
chmod +x benches/scripts/run_all.sh
./benches/scripts/run_all.sh

# Customize concurrency/duration:
DURATION_SECS=15 HTTP_CONCURRENCY=128 SSE_CONCURRENCY=1000 ./benches/scripts/run_all.sh
```

### Installing Caddy & Envoy for Head-to-Head Runs (macOS / Linux)

```bash
# macOS (Homebrew):
brew install caddy envoy

# Verify both are visible on PATH, then re-run:
./benches/scripts/run_all.sh
```

### Running Individual Workloads Manually

```bash
# Terminal 1: Start mock upstream
cargo run --release -p shunt-bench -- upstream --listen 127.0.0.1:18080

# Terminal 2: Start Shunt
RUST_LOG=error cargo run --release -p shunt-cli -- run --no-watch -c benches/configs/shunt-raw.toml

# Terminal 3: Drive HTTP or SSE load
cargo run --release -p shunt-bench -- http --url http://127.0.0.1:18081/ping -c 64 -d 10
cargo run --release -p shunt-bench -- sse  --url http://127.0.0.1:18081/sse  -c 1000
```

## Reference Results (macOS Apple M5 Pro, Local Loopback)

Measured with `./benches/scripts/run_all.sh` (`DURATION_SECS=6`, `WARMUP_SECS=2`, `HTTP_CONCURRENCY=64`, `SSE_CONCURRENCY=1000`, `SSE_CHUNKS=20`, `SSE_INTERVAL_MS=25`) comparing **Shunt (`--release`, 14.2 MiB binary)**, **Envoy 1.40.2**, and **Caddy 2.11.9** natively on identical hardware against the same `shunt-bench upstream`:

### Workload 1 — Raw HTTP/1.1 Passthrough (`c=64`, 0 plugins)

| Gateway | Throughput | p50 Latency | p99 Latency | Post-Run RSS | Errors |
| --- | ---: | ---: | ---: | ---: | ---: |
| **Shunt** (`HookMask::EMPTY`) | **88,649 req/s** | **718 µs** | **930 µs** | **22.4 MB** | 0 |
| **Envoy 1.40.2** | 80,314 req/s | 759 µs | 1,210 µs | 53.7 MB | 0 |
| **Caddy 2.11.9** | 68,802 req/s | 869 µs | 2,107 µs | 72.1 MB | 0 |

### Workload 2 — 3-Plugin Chain (`c=64`)

| Gateway | Throughput | p50 Latency | p99 Latency | Post-Run RSS | Errors |
| --- | ---: | ---: | ---: | ---: | ---: |
| **Shunt** (`request-id` + `bearer-auth` + `rate-limit`) | **87,820 req/s** | **725 µs** | **946 µs** | **23.8 MB** | 0 |
| **Envoy 1.40.2** (`request-id` + auth + `local_ratelimit`) | 74,943 req/s | 847 µs | 1,024 µs | 55.6 MB | 0 |
| **Caddy 2.11.9** (`headers` + auth) | 59,076 req/s | 874 µs | 6,744 µs | 72.3 MB | 357 |

### Workload 2b & 2c — JWT Security & Streaming Compression (`c=64`, RFC 0018)

| Workload (`shunt-security-compression.toml`) | Throughput | p50 Latency | p99 Latency | Post-Run RSS | Errors |
| --- | ---: | ---: | ---: | ---: | ---: |
| **JWT & Security Chain** (`req-id` + `ip-filter` + `jwt-auth` HS256 + `body-limit`, `/ping`) | **73,418 req/s** | **868 µs** | **1.12 ms** | **24.6 MB** | 0 |
| **JWT + Security + Streaming `zstd`** (~4.3 KB `/json` → 321 B compressed) | **70,187 req/s** | **907 µs** | **1.17 ms** | **33.9 MB** | 0 |

### Workload 3 — 1,000 Concurrent SSE Streams (`c=1,000`, 20 chunks @ 25ms)

| Gateway | Completed / Failed | Chunks/s | TTFC p50 / p99 | Wall Time | Post-Run RSS |
| --- | :---: | ---: | ---: | ---: | ---: |
| **Shunt (SSE passthrough)** | **1,000 / 0** | **32,822/s** | 48.4 ms / 110.1 ms | **0.64s** | **87.6 MB** |
| **Envoy 1.40.2 (SSE passthrough)** | 1,000 / 0 | 32,696/s | **47.9 ms** / **107.5 ms** | **0.64s** | 92.2 MB |
| **Caddy 2.11.9 (SSE passthrough)** | 1,000 / 0 | 26,107/s | 125.1 ms / 275.9 ms | 0.80s | 157.4 MB |
| **Shunt-AI** *(live Anthropic → OpenAI JSON + SSE translate + usage)* | **1,000 / 0** | 32,260/s *(23k chunks)* | **45.0 ms** / 110.6 ms | 0.71s | **100.1 MB** |

---

## AI Gateway Head-to-Head: Shunt vs. LiteLLM Proxy

Measured with `./benches/scripts/run_litellm_bench.sh` (`DURATION_SECS=8`, `WARMUP_SECS=2`, `HTTP_CONCURRENCY=64`, `SSE_MED_CONCURRENCY=200`, `SSE_HIGH_CONCURRENCY=1000`, `SSE_CHUNKS=20`, `SSE_INTERVAL_MS=25`) on **Apple M5 Pro (18 cores, macOS arm64)** against the same local `shunt-bench upstream` mock.

LiteLLM Proxy (`1.110.2`) was configured in its fastest stateless, no-database mode (`disable_spend_logs: true`, `disable_error_logs: true`, `turn_off_message_logging: true`, `telemetry: false`, `LITELLM_LOG=ERROR`) and tested with both **1 worker** (default) and **4 workers** (`--num_workers 4`), summing RSS across all worker processes.

### Footprint & Cold Start

| Gateway | Binary / Runtime | Cold Start | Idle RSS |
| --- | --- | ---: | ---: |
| **Shunt AI** *(3-plugin: router + adapter + usage)* | Single **14.2 MiB** Rust binary | **36 ms** | **11.2 MB** *(1 proc)* |
| **Shunt AI Governed** *(8-plugin: req-id + virtual-keys + router + rpm/tpm + budget + adapter + failover + usage)* | Single **14.2 MiB** Rust binary | **35 ms** | **11.6 MB** *(1 proc)* |
| **Shunt AI Guardrailed** *(req-id + router + `ai-guardrails` PII/secrets/injection + adapter + usage)* | Single **14.2 MiB** Rust binary | **32 ms** | **12.9 MB** *(1 proc)* |
| **Shunt AI Cached** *(8-plugin + `ai-cache` exact & streaming replay)* | Single **14.2 MiB** Rust binary | **33 ms** | **11.7 MB** *(1 proc)* |
| **LiteLLM 1.110.2** *(1 worker, no-DB)* | Python 3.12 (119 pkgs) | 7,360 ms | 369.2 MB *(1 proc)* |
| **LiteLLM 1.110.2** *(4 workers, no-DB)* | Python 3.12 (119 pkgs) | 14,153–15,067 ms | 1,870.2–1,872.5 MB *(6 proc)* |

### Workload AI-1 — Non-Streaming OpenAI Passthrough & Cache Hit (`POST /v1/chat/completions`, `c=64`)

| Gateway | Throughput | p50 Latency | p99 Latency | Post-Run RSS | Errors |
| --- | ---: | ---: | ---: | ---: | ---: |
| **Shunt AI Cached** *(`ai-cache` exact-match hit, 0 upstream I/O)* | **165,876 req/s** | **0.38 ms** | **0.63 ms** | **27.5 MB** | 0 |
| **Shunt AI** *(3-plugin)* | **70,964 req/s** | **0.90 ms** | **1.17 ms** | **26.5 MB** | 0 |
| **Shunt AI Governed** *(8-plugin)* | **69,537 req/s** | **0.92 ms** | **1.20 ms** | **28.8 MB** | 0 |
| **Shunt AI Guardrailed** *(both-direction PII/secrets/injection + regex/keywords)* | **69,278 req/s** | **0.92 ms** | **1.21 ms** | **35.9 MB** | 0 |
| **LiteLLM 1.110.2** *(4 workers, master_key + rpm/tpm)* | 1,024 req/s | 62.2 ms | 82.5 ms | 1,945.0 MB | 0 |
| **LiteLLM 1.110.2** *(4 workers, stateless)* | 988 req/s | 66.4 ms | 97.2 ms | 1,935.5 MB | 0 |
| **LiteLLM 1.110.2** *(1 worker, stateless)* | 341 req/s | 190.1 ms | 223.2 ms | 390.9 MB | 0 |

### Workload AI-2 — Non-Streaming Anthropic ↔ OpenAI Translation (`POST /v1/chat/completions`, `c=64`)

| Gateway | Throughput | p50 Latency | p99 Latency | Post-Run RSS | Errors |
| --- | ---: | ---: | ---: | ---: | ---: |
| **Shunt AI** *(3-plugin)* | **69,289 req/s** | **0.92 ms** | **1.23 ms** | **28.2 MB** | 0 |
| **Shunt AI Guardrailed** *(translate + both-direction PII/secrets/injection)* | **69,165 req/s** | **0.92 ms** | **1.22 ms** | **36.9 MB** | 0 |
| **Shunt AI Governed** *(8-plugin)* | **68,845 req/s** | **0.92 ms** | **1.22 ms** | **30.0 MB** | 0 |
| **LiteLLM 1.110.2** *(4 workers, stateless)* | 944 req/s | 66.4 ms | 84.3 ms | 2,059.9 MB | 0 |
| **LiteLLM 1.110.2** *(4 workers, master_key + rpm/tpm)* | 832 req/s | 76.1 ms | 100.8 ms | 2,071.0 MB | 0 |
| **LiteLLM 1.110.2** *(1 worker, stateless)* | 335 req/s | 193.8 ms | 209.0 ms | 421.7 MB | 0 |

### Workload AI-3 & AI-4 — Live SSE Streaming Translation, Guardrails & Cached Replay (`Anthropic → OpenAI`, 20 chunks @ 25ms)

| Gateway | Concurrency | Completed / Failed | Chunks/s | TTFC p50 / p99 | Wall Time | Post-Run RSS |
| --- | ---: | :---: | ---: | ---: | ---: | ---: |
| **Shunt AI Cached** *(streaming SSE cache replay, 0 upstream I/O)* | 200 | **200 / 0** | **36,188/s** | **3.9 ms** / **4.7 ms** | **0.01s** | **32.0 MB** |
| **Shunt AI Governed** *(8-plugin)* | 200 | **200 / 0** | **7,126/s** | **6.5 ms** / **35.4 ms** | **0.65s** | **40.9 MB** |
| **Shunt AI** *(3-plugin)* | 200 | **200 / 0** | 6,670/s | **6.5 ms** / 70.2 ms | 0.69s | **38.3 MB** |
| **Shunt AI Guardrailed** *(64-char streaming holdback scan)* | 200 | **200 / 0** | 3,282/s *(coalesced)* | **6.5 ms** / 59.3 ms | 0.67s | **47.2 MB** |
| **LiteLLM 1.110.2** *(4 workers, stateless)* | 200 | 200 / 0 | 5,237/s | 231.4 ms / 302.4 ms | 0.84s | 2,094.6 MB |
| **LiteLLM 1.110.2** *(4 workers, auth + rpm/tpm)* | 200 | 200 / 0 | 5,085/s | 255.3 ms / 332.2 ms | 0.87s | 2,104.4 MB |
| **LiteLLM 1.110.2** *(1 worker, stateless)* | 200 | 200 / 0 | 2,278/s | 542.8 ms / 1,392.3 ms | 1.93s | 446.7 MB |
| **Shunt AI Cached** *(streaming SSE cache replay, 0 upstream I/O)* | 1,000 | **1,000 / 0** | **44,552/s** | **12.2 ms** / **17.3 ms** | **0.02s** | **50.6 MB** |
| **Shunt AI Governed** *(8-plugin)* | 1,000 | **1,000 / 0** | **30,349/s** | 61.3 ms / 153.7 ms | **0.76s** | **107.9 MB** |
| **Shunt AI** *(3-plugin)* | 1,000 | **1,000 / 0** | 29,674/s | 72.8 ms / 162.0 ms | 0.78s | **103.9 MB** |
| **Shunt AI Guardrailed** *(64-char streaming holdback scan)* | 1,000 | **1,000 / 0** | 14,441/s *(coalesced)* | **50.0 ms** / **146.1 ms** | **0.76s** | **113.3 MB** |
| **LiteLLM 1.110.2** *(4 workers, stateless)* | 1,000 | 1,000 / 0 | 8,065/s | 968.1 ms / 2,189.2 ms | 2.73s | 2,228.2 MB |
| **LiteLLM 1.110.2** *(4 workers, auth + rpm/tpm)* | 1,000 | 1,000 / 0 | 7,370/s | 1,084.9 ms / 2,390.2 ms | 2.99s | 2,228.4 MB |
| **LiteLLM 1.110.2** *(1 worker, stateless)* | 1,000 | 1,000 / 0 | 2,608/s | 3,834.3 ms / 7,861.8 ms | 8.43s | 528.0 MB |

### Running the LiteLLM Benchmark Locally

```bash
# Install LiteLLM in an isolated temp virtualenv (Python 3.12 recommended):
uv venv --python 3.12 /tmp/litellm-bench-venv
uv pip install --python /tmp/litellm-bench-venv/bin/python 'litellm[proxy]'

# Run head-to-head comparison (auto-detects /tmp/litellm-bench-venv/bin/litellm):
./benches/scripts/run_litellm_bench.sh
```


