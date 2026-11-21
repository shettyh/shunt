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
