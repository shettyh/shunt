#!/usr/bin/env bash
set -euo pipefail

# Raise soft FD limit so 1,000+ concurrent SSE streams don't hit macOS's default 256 limit.
ulimit -n 16384 2>/dev/null || ulimit -n 8192 2>/dev/null || true

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
BENCH_DIR="$ROOT_DIR/benches"
CONFIG_DIR="$BENCH_DIR/configs"

DURATION_SECS="${DURATION_SECS:-8}"
WARMUP_SECS="${WARMUP_SECS:-2}"
HTTP_CONCURRENCY="${HTTP_CONCURRENCY:-64}"
SSE_CONCURRENCY="${SSE_CONCURRENCY:-1000}"
SSE_CHUNKS="${SSE_CHUNKS:-20}"
SSE_INTERVAL_MS="${SSE_INTERVAL_MS:-25}"

UPSTREAM_PORT=18080
GATEWAY_PORT=18081

echo "==> Building shunt and shunt-bench (release)..."
(cd "$ROOT_DIR" && cargo build --release -p shunt-cli -p shunt-bench >/dev/null)

SHUNT_BIN="$ROOT_DIR/target/release/shunt"
BENCH_BIN="$ROOT_DIR/target/release/shunt-bench"

UPSTREAM_PID=""
GW_PID=""

cleanup() {
    if [[ -n "$GW_PID" ]]; then
        kill "$GW_PID" 2>/dev/null || true
        wait "$GW_PID" 2>/dev/null || true
    fi
    if [[ -n "$UPSTREAM_PID" ]]; then
        kill "$UPSTREAM_PID" 2>/dev/null || true
        wait "$UPSTREAM_PID" 2>/dev/null || true
    fi
}
trap cleanup EXIT

wait_for_port_and_pid() {
    local port="$1"
    local pid="$2"
    local logfile="$3"
    for _ in $(seq 1 60); do
        if ! kill -0 "$pid" 2>/dev/null; then
            echo "error: process (pid=$pid) exited prematurely! Log:" >&2
            cat "$logfile" >&2 || true
            return 1
        fi
        if (echo >/dev/tcp/127.0.0.1/"$port") 2>/dev/null; then
            return 0
        fi
        sleep 0.1
    done
    echo "error: timed out waiting for 127.0.0.1:$port (pid=$pid). Log:" >&2
    cat "$logfile" >&2 || true
    return 1
}

wait_for_port_free() {
    local port="$1"
    for _ in $(seq 1 50); do
        if ! (echo >/dev/tcp/127.0.0.1/"$port") 2>/dev/null; then
            return 0
        fi
        sleep 0.1
    done
    echo "error: port 127.0.0.1:$port is still in use!" >&2
    return 1
}

rss_mb() {
    local pid="$1"
    local kb
    kb="$(ps -o rss= -p "$pid" 2>/dev/null | tr -d ' ' || echo 0)"
    awk -v kb="${kb:-0}" 'BEGIN { printf "%.1f MB", kb / 1024.0 }'
}

stop_gw() {
    if [[ -n "$GW_PID" ]]; then
        kill "$GW_PID" 2>/dev/null || true
        wait "$GW_PID" 2>/dev/null || true
        GW_PID=""
        wait_for_port_free "$GATEWAY_PORT"
    fi
}

wait_for_port_free "$UPSTREAM_PORT"
wait_for_port_free "$GATEWAY_PORT"

UPSTREAM_LOG="$(mktemp)"
GW_LOG="$(mktemp)"
trap 'cleanup; rm -f "$UPSTREAM_LOG" "$GW_LOG"' EXIT

echo "==> Starting mock upstream on 127.0.0.1:$UPSTREAM_PORT..."
"$BENCH_BIN" upstream \
    --listen "127.0.0.1:$UPSTREAM_PORT" \
    --payload-bytes 256 \
    --sse-chunks "$SSE_CHUNKS" \
    --sse-interval-ms "$SSE_INTERVAL_MS" >"$UPSTREAM_LOG" 2>&1 &
UPSTREAM_PID=$!
wait_for_port_and_pid "$UPSTREAM_PORT" "$UPSTREAM_PID" "$UPSTREAM_LOG"

run_gateway_workload() {
    local name="$1"
    local workload="$2"
    local start_cmd="$3"
    local bench_cmd="$4"

    echo ""
    echo "--------------------------------------------------------------------"
    echo "[$workload] $name"
    echo "--------------------------------------------------------------------"
    wait_for_port_free "$GATEWAY_PORT"
    : >"$GW_LOG"
    bash -c "exec $start_cmd" >"$GW_LOG" 2>&1 &
    GW_PID=$!
    wait_for_port_and_pid "$GATEWAY_PORT" "$GW_PID" "$GW_LOG"

    eval "$bench_cmd"
    echo "  RSS (post-run): $(rss_mb "$GW_PID") (pid=$GW_PID)"
    stop_gw
}

# ------------------------------------------------------------------------------
# Workload 1: Raw HTTP/1.1 Passthrough (0 plugins, HookMask::EMPTY)
# ------------------------------------------------------------------------------
W1_CMD="$BENCH_BIN http --url http://127.0.0.1:$GATEWAY_PORT/ping -c $HTTP_CONCURRENCY -d $DURATION_SECS --warmup-secs $WARMUP_SECS"
run_gateway_workload "Shunt (raw, HookMask::EMPTY)" "Workload 1: Raw Passthrough" \
    "env RUST_LOG=error $SHUNT_BIN run --no-watch -c $CONFIG_DIR/shunt-raw.toml" "$W1_CMD"

if command -v caddy >/dev/null 2>&1; then
    run_gateway_workload "Caddy (raw)" "Workload 1: Raw Passthrough" \
        "caddy run --config $CONFIG_DIR/caddy-raw.json" "$W1_CMD"
else
    echo "  (skipping Caddy — 'caddy' binary not found on PATH)"
fi

if command -v envoy >/dev/null 2>&1; then
    run_gateway_workload "Envoy (raw)" "Workload 1: Raw Passthrough" \
        "envoy -c $CONFIG_DIR/envoy-raw.yaml --log-level error" "$W1_CMD"
else
    echo "  (skipping Envoy — 'envoy' binary not found on PATH)"
fi

# ------------------------------------------------------------------------------
# Workload 2: 3-Plugin Chain (request-id + bearer-auth + rate-limit)
# ------------------------------------------------------------------------------
W2_CMD="$BENCH_BIN http --url http://127.0.0.1:$GATEWAY_PORT/ping -c $HTTP_CONCURRENCY -d $DURATION_SECS --warmup-secs $WARMUP_SECS -H 'Authorization: Bearer bench-secret-token'"
run_gateway_workload "Shunt (request-id + bearer-auth + rate-limit)" "Workload 2: 3-Plugin Chain" \
    "env RUST_LOG=error $SHUNT_BIN run --no-watch -c $CONFIG_DIR/shunt-plugins.toml" "$W2_CMD"

if command -v caddy >/dev/null 2>&1; then
    run_gateway_workload "Caddy (headers + auth)" "Workload 2: 3-Plugin Chain" \
        "caddy run --config $CONFIG_DIR/caddy-plugins.json" "$W2_CMD"
fi

if command -v envoy >/dev/null 2>&1; then
    run_gateway_workload "Envoy (request-id + auth + local_ratelimit)" "Workload 2: 3-Plugin Chain" \
        "envoy -c $CONFIG_DIR/envoy-plugins.yaml --log-level error" "$W2_CMD"
fi

# ------------------------------------------------------------------------------
# Workload 2b/2c: Modern API Gateway Security & Compression (RFC 0018)
# ------------------------------------------------------------------------------
# Deterministic HS256 JWT (iss=https://bench.shunt.dev, aud=shunt-api, scope="read write", exp=2100)
BENCH_JWT="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImJlbmNoLWhzMSJ9.eyJpc3MiOiJodHRwczovL2JlbmNoLnNodW50LmRldiIsImF1ZCI6InNodW50LWFwaSIsInN1YiI6ImJlbmNoLXVzZXIiLCJzY29wZSI6InJlYWQgd3JpdGUiLCJvcmciOnsiaWQiOiJhY21lIn0sImV4cCI6NDEwMjQ0NDgwMH0.oNwB3NTg0O9xnqR3IhQ9CqJfbgpiN597a1vthqYA7G0"

W2B_CMD="$BENCH_BIN http --url http://127.0.0.1:$GATEWAY_PORT/ping -c $HTTP_CONCURRENCY -d $DURATION_SECS --warmup-secs $WARMUP_SECS -H 'Authorization: Bearer $BENCH_JWT'"
run_gateway_workload "Shunt (req-id + ip-filter + jwt-auth HS256 + body-limit)" "Workload 2b: JWT & Security Chain" \
    "env RUST_LOG=error $SHUNT_BIN run --no-watch -c $CONFIG_DIR/shunt-security-compression.toml" "$W2B_CMD"

W2C_CMD="$BENCH_BIN http --url http://127.0.0.1:$GATEWAY_PORT/json -c $HTTP_CONCURRENCY -d $DURATION_SECS --warmup-secs $WARMUP_SECS -H 'Authorization: Bearer $BENCH_JWT' -H 'Accept-Encoding: zstd'"
run_gateway_workload "Shunt (JWT + security + streaming zstd on ~4KB JSON)" "Workload 2c: Security + zstd Compression" \
    "env RUST_LOG=error $SHUNT_BIN run --no-watch -c $CONFIG_DIR/shunt-security-compression.toml" "$W2C_CMD"

# ------------------------------------------------------------------------------
# Workload 3: High-Concurrency SSE Streaming (1,000+ concurrent streams)
# ------------------------------------------------------------------------------
W3_RAW_CMD="$BENCH_BIN sse --url http://127.0.0.1:$GATEWAY_PORT/sse -c $SSE_CONCURRENCY --waves 1 --method GET"
run_gateway_workload "Shunt (SSE passthrough, c=$SSE_CONCURRENCY)" "Workload 3a: SSE Passthrough" \
    "env RUST_LOG=error $SHUNT_BIN run --no-watch -c $CONFIG_DIR/shunt-sse.toml" "$W3_RAW_CMD"

W3_AI_CMD="$BENCH_BIN sse --url http://127.0.0.1:$GATEWAY_PORT/v1/chat/completions -c $SSE_CONCURRENCY --waves 1 --method POST --body '{\"model\":\"claude-bench\",\"stream\":true,\"messages\":[{\"role\":\"user\",\"content\":\"hi\"}]}'"
run_gateway_workload "Shunt-AI (Anthropic->OpenAI live SSE translate + usage, c=$SSE_CONCURRENCY)" "Workload 3b: SSE Live Translation" \
    "env RUST_LOG=error $SHUNT_BIN run --no-watch -c $CONFIG_DIR/shunt-sse-translate.toml" "$W3_AI_CMD"

if command -v caddy >/dev/null 2>&1; then
    run_gateway_workload "Caddy (SSE passthrough, c=$SSE_CONCURRENCY)" "Workload 3a: SSE Passthrough" \
        "caddy run --config $CONFIG_DIR/caddy-sse.json" "$W3_RAW_CMD"
fi

if command -v envoy >/dev/null 2>&1; then
    run_gateway_workload "Envoy (SSE passthrough, c=$SSE_CONCURRENCY)" "Workload 3a: SSE Passthrough" \
        "envoy -c $CONFIG_DIR/envoy-sse.yaml --log-level error" "$W3_RAW_CMD"
fi

echo ""
echo "==> Benchmark suite complete."
