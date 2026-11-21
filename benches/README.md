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
- **`benches/scripts/run_all.sh`**: Automated orchestrator that builds `--release` binaries, launches the mock upstream, and runs every workload against Shunt (plus Caddy and Envoy whenever `caddy` / `envoy` are on `PATH`).

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

