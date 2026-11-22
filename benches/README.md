# Shunt Benchmarks

Reproducible end-to-end benchmark harness comparing **Shunt** against **Caddy** and **Envoy** on identical hardware across three workloads (see [RFC 0005](../rfcs/0005-benchmarks-and-hardening.md)).

## Components

- **`benches/shunt-bench`**: Self-contained Rust binary providing:
  - `shunt-bench upstream`: Ultra-fast HTTP/1.1 + HTTP/2 mock upstream serving `/ping` (fixed 256B), `/sse` (OpenAI SSE), and `/v1/messages` (Anthropic SSE).
  - `shunt-bench http`: Multi-worker keep-alive HTTP/1.1 & HTTP/2 load generator reporting RPS and exact p50/p95/p99/max latencies.
  - `shunt-bench sse`: High-concurrency SSE load generator (default 1,000 concurrent streams) reporting stream completion, chunks/sec, TTFC p50/p95/p99, and total duration.
- **`benches/configs/`**: Equivalent Shunt, Caddy, and Envoy configurations for:
  1. **Workload 1 (`*-raw.*`)**: Raw passthrough (`HookMask::EMPTY`, 0 plugins).
  2. **Workload 2 (`*-plugins.*`)**: 3-plugin chain (`request-id` + `bearer-auth` + local `rate-limit`).
  3. **Workload 3 (`*-sse.*`)**: 1,000+ concurrent SSE streams (both raw passthrough and Shunt-AI live Anthropic → OpenAI SSE translation + token tracking).
- **`benches/scripts/run_all.sh`**: Automated orchestrator that builds `--release` binaries, launches the mock upstream, and runs every HTTP/SSE workload against Shunt (plus Caddy and Envoy whenever `caddy` / `envoy` are on `PATH`).
- **`benches/scripts/run_litellm_bench.sh`**: Reproducible head-to-head AI Gateway benchmark comparing **Shunt** (3-plugin minimal chain and 8-plugin full governance chain) against **LiteLLM Proxy** (1-worker and 4-worker stateless no-DB modes) across non-streaming JSON chat completions, Anthropic ↔ OpenAI translation, and high-concurrency SSE streaming.

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

## Reference Results (macOS Apple Silicon, Local Loopback)

Measured with `./benches/scripts/run_all.sh` (`DURATION_SECS=6`, `WARMUP_SECS=2`, `HTTP_CONCURRENCY=64`, `SSE_CONCURRENCY=1000`, `SSE_CHUNKS=20`, `SSE_INTERVAL_MS=25`) comparing **Shunt (`--release`)**, **Envoy 1.40.2**, and **Caddy 2.11.9** natively on identical hardware against the same `shunt-bench upstream`:

### Workload 1 — Raw HTTP/1.1 Passthrough (`c=64`, 0 plugins)

| Gateway | Throughput | p50 Latency | p99 Latency | Post-Run RSS | Errors |
| --- | ---: | ---: | ---: | ---: | ---: |
| **Shunt** (`HookMask::EMPTY`) | **89,240 req/s** | **713 µs** | **922 µs** | **20.1 MB** | 0 |
| **Envoy 1.40.2** | 75,515 req/s | 843 µs | 1,010 µs | 57.5 MB | 0 |
| **Caddy 2.11.9** | 69,264 req/s | 863 µs | 2,089 µs | 71.4 MB | 0 |

### Workload 2 — 3-Plugin Chain (`c=64`)

| Gateway | Throughput | p50 Latency | p99 Latency | Post-Run RSS | Errors |
| --- | ---: | ---: | ---: | ---: | ---: |
| **Shunt** (`request-id` + `bearer-auth` + `rate-limit`) | **87,714 req/s** | **724 µs** | **956 µs** | **21.0 MB** | 0 |
| **Envoy 1.40.2** (`request-id` + auth + `local_ratelimit`) | 76,431 req/s | 832 µs | 1,018 µs | 55.6 MB | 0 |
| **Caddy 2.11.9** (`headers` + auth) | 45,557 req/s | 891 µs | 12,083 µs | 71.6 MB | 999 |

### Workload 3 — 1,000 Concurrent SSE Streams (`c=1,000`, 20 chunks @ 25ms)

| Gateway | Completed / Failed | Chunks/s | TTFC p50 / p99 | Wall Time | Post-Run RSS |
| --- | :---: | ---: | ---: | ---: | ---: |
| **Shunt (SSE passthrough)** | **1,000 / 0** | 30,456/s | **71.8 ms** / 161.1 ms | 0.69s | **83.3 MB** |
| **Envoy 1.40.2 (SSE passthrough)** | 1,000 / 0 | **30,749/s** | 72.4 ms / 158.6 ms | 0.68s | 92.2 MB |
| **Caddy 2.11.9 (SSE passthrough)** | 1,000 / 0 | 30,316/s | 85.0 ms / **155.4 ms** | 0.69s | 159.2 MB |
| **Shunt-AI** *(live Anthropic → OpenAI JSON + SSE translate + usage)* | **1,000 / 0** | 28,990/s *(23k chunks)* | 99.4 ms / 187.3 ms | 0.79s | **93.8 MB** |

---

## AI Gateway Head-to-Head: Shunt vs. LiteLLM Proxy

Measured with `./benches/scripts/run_litellm_bench.sh` (`DURATION_SECS=8`, `WARMUP_SECS=2`, `HTTP_CONCURRENCY=64`, `SSE_MED_CONCURRENCY=200`, `SSE_HIGH_CONCURRENCY=1000`, `SSE_CHUNKS=20`, `SSE_INTERVAL_MS=25`) on **Apple M5 Pro (18 cores, macOS arm64)** against the same local `shunt-bench upstream` mock.

LiteLLM Proxy (`1.110.2`) was configured in its fastest stateless, no-database mode (`disable_spend_logs: true`, `disable_error_logs: true`, `turn_off_message_logging: true`, `telemetry: false`, `LITELLM_LOG=ERROR`) and tested with both **1 worker** (default) and **4 workers** (`--num_workers 4`), summing RSS across all worker processes.

### Footprint & Cold Start

| Gateway | Binary / Runtime | Cold Start | Idle RSS |
| --- | --- | ---: | ---: |
| **Shunt AI** *(3-plugin: router + adapter + usage)* | Single **8.9 MB** Rust binary | **31 ms** | **10.1 MB** *(1 proc)* |
| **Shunt AI Governed** *(8-plugin: req-id + virtual-keys + router + rpm/tpm + budget + adapter + failover + usage)* | Single **8.9 MB** Rust binary | **33 ms** | **10.5 MB** *(1 proc)* |
| **LiteLLM 1.110.2** *(1 worker, no-DB)* | Python 3.12 (119 pkgs) | 2,326 ms | 363.4 MB *(1 proc)* |
| **LiteLLM 1.110.2** *(4 workers, no-DB)* | Python 3.12 (119 pkgs) | 4,151–9,954 ms | 1,861.0 MB *(6 proc)* |

### Workload AI-1 — Non-Streaming OpenAI Passthrough (`POST /v1/chat/completions`, `c=64`)

| Gateway | Throughput | p50 Latency | p99 Latency | Post-Run RSS | Errors |
| --- | ---: | ---: | ---: | ---: | ---: |
| **Shunt AI** *(3-plugin)* | **71,796 req/s** | **0.89 ms** | **1.12 ms** | **24.7 MB** | 0 |
| **Shunt AI Governed** *(8-plugin)* | **71,185 req/s** | **0.90 ms** | **1.15 ms** | **26.0 MB** | 0 |
| **LiteLLM 1.110.2** *(4 workers, stateless)* | 1,044 req/s | 61.0 ms | 71.1 ms | 1,925.0 MB | 0 |
| **LiteLLM 1.110.2** *(4 workers, master_key + rpm/tpm)* | 987 req/s | 59.1 ms | 101.7 ms | 1,921.4 MB | 0 |
| **LiteLLM 1.110.2** *(1 worker, stateless)* | 361 req/s | 180.1 ms | 186.5 ms | 384.8 MB | 0 |

### Workload AI-2 — Non-Streaming Anthropic ↔ OpenAI Translation (`POST /v1/chat/completions`, `c=64`)

| Gateway | Throughput | p50 Latency | p99 Latency | Post-Run RSS | Errors |
| --- | ---: | ---: | ---: | ---: | ---: |
| **Shunt AI** *(3-plugin)* | **70,670 req/s** | **0.90 ms** | **1.15 ms** | **25.9 MB** | 0 |
| **Shunt AI Governed** *(8-plugin)* | **70,551 req/s** | **0.90 ms** | **1.17 ms** | **27.2 MB** | 0 |
| **LiteLLM 1.110.2** *(4 workers, stateless)* | 1,005 req/s | 64.9 ms | 70.9 ms | 2,050.7 MB | 0 |
| **LiteLLM 1.110.2** *(4 workers, master_key + rpm/tpm)* | 985 req/s | 64.6 ms | 72.6 ms | 2,050.6 MB | 0 |
| **LiteLLM 1.110.2** *(1 worker, stateless)* | 340 req/s | 190.0 ms | 223.7 ms | 415.5 MB | 0 |

### Workload AI-3 — Live SSE Streaming Translation (`Anthropic → OpenAI`, 20 chunks @ 25ms)

| Gateway | Concurrency | Completed / Failed | Chunks/s | TTFC p50 / p99 | Wall Time | Post-Run RSS |
| --- | ---: | :---: | ---: | ---: | ---: | ---: |
| **Shunt AI** *(3-plugin)* | 200 | **200 / 0** | 6,898/s | **6.6 ms** / **32.9 ms** | 0.67s | **35.9 MB** |
| **Shunt AI Governed** *(8-plugin)* | 200 | **200 / 0** | **6,944/s** | **6.3 ms** / 34.1 ms | **0.66s** | **37.6 MB** |
| **LiteLLM 1.110.2** *(4 workers, stateless)* | 200 | 200 / 0 | 5,275/s | 217.4 ms / 285.4 ms | 0.83s | 2,081.6 MB |
| **LiteLLM 1.110.2** *(4 workers, auth + rpm/tpm)* | 200 | 200 / 0 | 5,119/s | 233.2 ms / 307.8 ms | 0.86s | 2,081.2 MB |
| **LiteLLM 1.110.2** *(1 worker, stateless)* | 200 | 200 / 0 | 2,296/s | 535.9 ms / 1,359.7 ms | 1.92s | 438.7 MB |
| **Shunt AI** *(3-plugin)* | 1,000 | **1,000 / 0** | **29,788/s** | **56.7 ms** / **146.3 ms** | **0.77s** | **99.4 MB** |
| **Shunt AI Governed** *(8-plugin)* | 1,000 | **1,000 / 0** | 27,953/s | 101.7 ms / 191.6 ms | 0.82s | **103.0 MB** |
| **LiteLLM 1.110.2** *(4 workers, stateless)* | 1,000 | 1,000 / 0 | 7,999/s | 1,179.8 ms / 2,204.8 ms | 2.75s | 2,190.6 MB |
| **LiteLLM 1.110.2** *(4 workers, auth + rpm/tpm)* | 1,000 | 1,000 / 0 | 8,042/s | 1,075.5 ms / 2,179.7 ms | 2.74s | 2,208.9 MB |
| **LiteLLM 1.110.2** *(1 worker, stateless)* | 1,000 | 1,000 / 0 | 2,769/s | 3,409.3 ms / 7,345.6 ms | 7.95s | 538.0 MB |

### Running the LiteLLM Benchmark Locally

```bash
# Install LiteLLM in an isolated temp virtualenv (Python 3.12 recommended):
uv venv --python 3.12 /tmp/litellm-bench-venv
uv pip install --python /tmp/litellm-bench-venv/bin/python 'litellm[proxy]'

# Run head-to-head comparison (auto-detects /tmp/litellm-bench-venv/bin/litellm):
./benches/scripts/run_litellm_bench.sh
```


