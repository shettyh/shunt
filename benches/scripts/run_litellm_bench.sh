#!/usr/bin/env bash
set -euo pipefail

# Reproducible head-to-head AI Gateway benchmark: Shunt vs. LiteLLM Proxy
# Both gateways proxy against the exact same local `shunt-bench upstream` mock.

ulimit -n 16384 2>/dev/null || ulimit -n 8192 2>/dev/null || true

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
CONFIG_DIR="$ROOT_DIR/benches/configs"

DURATION_SECS="${DURATION_SECS:-8}"
WARMUP_SECS="${WARMUP_SECS:-2}"
HTTP_CONCURRENCY="${HTTP_CONCURRENCY:-64}"
SSE_MED_CONCURRENCY="${SSE_MED_CONCURRENCY:-200}"
SSE_HIGH_CONCURRENCY="${SSE_HIGH_CONCURRENCY:-1000}"
SSE_CHUNKS="${SSE_CHUNKS:-20}"
SSE_INTERVAL_MS="${SSE_INTERVAL_MS:-25}"
LITELLM_WORKERS="${LITELLM_WORKERS:-4}"

UPSTREAM_PORT="${UPSTREAM_PORT:-18080}"
GATEWAY_PORT="${GATEWAY_PORT:-18081}"

LITELLM_BIN="${LITELLM_BIN:-}"
if [[ "${SKIP_LITELLM:-0}" != "1" && -z "$LITELLM_BIN" ]]; then
    if command -v litellm >/dev/null 2>&1; then
        LITELLM_BIN="$(command -v litellm)"
    elif [[ -x "/tmp/litellm-bench-venv/bin/litellm" ]]; then
        LITELLM_BIN="/tmp/litellm-bench-venv/bin/litellm"
    fi
fi

echo "==> Building shunt and shunt-bench (release)..."
(cd "$ROOT_DIR" && cargo build --release -p shunt-cli -p shunt-bench >/dev/null)

SHUNT_BIN="$ROOT_DIR/target/release/shunt"
BENCH_BIN="$ROOT_DIR/target/release/shunt-bench"

UPSTREAM_PID=""
GW_PID=""
TMP_DIR="$(mktemp -d)"
UPSTREAM_LOG="$TMP_DIR/upstream.log"
GW_LOG="$TMP_DIR/gw.log"

kill_tree() {
    local root_pid="$1"
    if [[ -z "$root_pid" ]]; then
        return 0
    fi
    local children
    children="$(pgrep -P "$root_pid" 2>/dev/null || true)"
    for c in $children; do
        kill_tree "$c"
    done
    kill "$root_pid" 2>/dev/null || true
}

cleanup() {
    if [[ -n "$GW_PID" ]]; then
        kill_tree "$GW_PID"
        wait "$GW_PID" 2>/dev/null || true
    fi
    if [[ -n "$UPSTREAM_PID" ]]; then
        kill_tree "$UPSTREAM_PID"
        wait "$UPSTREAM_PID" 2>/dev/null || true
    fi
    rm -rf "$TMP_DIR"
}
trap cleanup EXIT

now_ms() {
    python3 -c 'import time; print(int(time.monotonic() * 1000))'
}

wait_for_port_and_pid() {
    local port="$1"
    local pid="$2"
    local logfile="$3"
    local max_iters="${4:-3000}"
    for _ in $(seq 1 "$max_iters"); do
        if ! kill -0 "$pid" 2>/dev/null; then
            echo "error: process (pid=$pid) exited prematurely! Log:" >&2
            cat "$logfile" >&2 || true
            return 1
        fi
        if (echo >/dev/tcp/127.0.0.1/"$port") 2>/dev/null; then
            return 0
        fi
        sleep 0.01
    done
    echo "error: timed out waiting for 127.0.0.1:$port (pid=$pid). Log:" >&2
    cat "$logfile" >&2 || true
    return 1
}

wait_for_port_free() {
    local port="$1"
    for _ in $(seq 1 100); do
        if ! (echo >/dev/tcp/127.0.0.1/"$port") 2>/dev/null; then
            return 0
        fi
        sleep 0.1
    done
    echo "error: port 127.0.0.1:$port is still in use!" >&2
    return 1
}

# Sum RSS (in MB) across root PID and all descendant worker processes.
tree_rss_mb() {
    local root_pid="$1"
    python3 - "$root_pid" <<'PY'
import subprocess, sys
root = int(sys.argv[1])
out = subprocess.check_output(["ps", "-axo", "pid=,ppid=,rss="], text=True)
children = {}
rss = {}
for line in out.splitlines():
    parts = line.split()
    if len(parts) != 3:
        continue
    pid, ppid, kb = int(parts[0]), int(parts[1]), int(parts[2])
    rss[pid] = kb
    children.setdefault(ppid, []).append(pid)

total_kb = 0
stack = [root]
seen = set()
while stack:
    p = stack.pop()
    if p in seen:
        continue
    seen.add(p)
    total_kb += rss.get(p, 0)
    stack.extend(children.get(p, []))

print(f"{total_kb / 1024.0:.1f} MB ({len(seen)} proc)")
PY
}

stop_gw() {
    if [[ -n "$GW_PID" ]]; then
        kill_tree "$GW_PID"
        wait "$GW_PID" 2>/dev/null || true
        GW_PID=""
        wait_for_port_free "$GATEWAY_PORT"
    fi
}

start_gw() {
    local start_cmd="$1"
    wait_for_port_free "$GATEWAY_PORT"
    : >"$GW_LOG"
    local t0 t1
    t0="$(now_ms)"
    bash -c "exec $start_cmd" >"$GW_LOG" 2>&1 &
    GW_PID=$!
    wait_for_port_and_pid "$GATEWAY_PORT" "$GW_PID" "$GW_LOG" 4000
    t1="$(now_ms)"
    echo "  Cold start : $((t1 - t0)) ms"
    sleep 0.8
    echo "  Idle RSS   : $(tree_rss_mb "$GW_PID")"
}

run_suite_for_gateway() {
    local name="$1"
    local start_cmd="$2"
    local auth_header="${3:-}"
    local run_high_sse="${4:-1}"

    echo ""
    echo "===================================================================="
    echo "Gateway: $name"
    echo "===================================================================="
    start_gw "$start_cmd"

    local extra_args=()
    if [[ -n "$auth_header" ]]; then
        extra_args=(-H "$auth_header")
    fi

    echo ""
    echo "--- [W-AI-1] Non-Streaming OpenAI Passthrough (c=$HTTP_CONCURRENCY, d=${DURATION_SECS}s) ---"
    "$BENCH_BIN" http \
        --url "http://127.0.0.1:$GATEWAY_PORT/v1/chat/completions" \
        --method POST \
        --body '{"model":"gpt-bench","stream":false,"messages":[{"role":"user","content":"hi"}]}' \
        -c "$HTTP_CONCURRENCY" -d "$DURATION_SECS" --warmup-secs "$WARMUP_SECS" \
        ${extra_args[@]+"${extra_args[@]}"}
    echo "  Post-W1 RSS: $(tree_rss_mb "$GW_PID")"

    echo ""
    echo "--- [W-AI-2] Non-Streaming Anthropic <-> OpenAI Translate (c=$HTTP_CONCURRENCY, d=${DURATION_SECS}s) ---"
    "$BENCH_BIN" http \
        --url "http://127.0.0.1:$GATEWAY_PORT/v1/chat/completions" \
        --method POST \
        --body '{"model":"claude-bench","stream":false,"messages":[{"role":"user","content":"hi"}]}' \
        -c "$HTTP_CONCURRENCY" -d "$DURATION_SECS" --warmup-secs "$WARMUP_SECS" \
        ${extra_args[@]+"${extra_args[@]}"}
    echo "  Post-W2 RSS: $(tree_rss_mb "$GW_PID")"

    echo ""
    echo "--- [W-AI-3a] Concurrent SSE Translate (c=$SSE_MED_CONCURRENCY, ${SSE_CHUNKS} chunks @ ${SSE_INTERVAL_MS}ms) ---"
    "$BENCH_BIN" sse \
        --url "http://127.0.0.1:$GATEWAY_PORT/v1/chat/completions" \
        --method POST \
        --body '{"model":"claude-bench","stream":true,"messages":[{"role":"user","content":"hi"}]}' \
        -c "$SSE_MED_CONCURRENCY" --waves 1 \
        ${extra_args[@]+"${extra_args[@]}"}
    echo "  Post-W3a RSS: $(tree_rss_mb "$GW_PID")"

    if [[ "$run_high_sse" == "1" ]]; then
        echo ""
        echo "--- [W-AI-3b] High-Concurrency SSE Translate (c=$SSE_HIGH_CONCURRENCY, ${SSE_CHUNKS} chunks @ ${SSE_INTERVAL_MS}ms) ---"
        "$BENCH_BIN" sse \
            --url "http://127.0.0.1:$GATEWAY_PORT/v1/chat/completions" \
            --method POST \
            --body '{"model":"claude-bench","stream":true,"messages":[{"role":"user","content":"hi"}]}' \
            -c "$SSE_HIGH_CONCURRENCY" --waves 1 \
            ${extra_args[@]+"${extra_args[@]}"}
        echo "  Post-W3b RSS: $(tree_rss_mb "$GW_PID")"
    fi

    stop_gw
}

wait_for_port_free "$UPSTREAM_PORT"
wait_for_port_free "$GATEWAY_PORT"

echo "==> Starting mock upstream on 127.0.0.1:$UPSTREAM_PORT..."
"$BENCH_BIN" upstream \
    --listen "127.0.0.1:$UPSTREAM_PORT" \
    --payload-bytes 256 \
    --sse-chunks "$SSE_CHUNKS" \
    --sse-interval-ms "$SSE_INTERVAL_MS" >"$UPSTREAM_LOG" 2>&1 &
UPSTREAM_PID=$!
wait_for_port_and_pid "$UPSTREAM_PORT" "$UPSTREAM_PID" "$UPSTREAM_LOG"

echo "==> Versions:"
echo "  Shunt  : $("$SHUNT_BIN" --version 2>/dev/null || echo 'shunt dev')"
if [[ -n "$LITELLM_BIN" ]]; then
    echo "  LiteLLM: $("$LITELLM_BIN" --version 2>/dev/null || echo "$LITELLM_BIN")"
fi

# 1. Shunt (minimal 3-plugin AI chain: router + adapter + usage)
run_suite_for_gateway \
    "Shunt AI (3-plugin: router + adapter + usage)" \
    "env RUST_LOG=error $SHUNT_BIN run --no-watch -c $CONFIG_DIR/shunt-ai-bench.toml" \
    "" 1

# 2. Shunt (full 8-plugin governance chain: req-id + virtual-keys + router + rpm/tpm + budget + adapter + failover + usage)
run_suite_for_gateway \
    "Shunt AI Governed (8-plugin: vkeys + router + rpm/tpm + budget + adapter + failover + usage)" \
    "env RUST_LOG=error $SHUNT_BIN run --no-watch -c $CONFIG_DIR/shunt-ai-governed.toml" \
    "Authorization: Bearer sk-bench-virtual-key" 1

# 3. LiteLLM Proxy (if installed)
if [[ -n "$LITELLM_BIN" ]]; then
    run_suite_for_gateway \
        "LiteLLM Proxy (1 worker, no-DB, stateless)" \
        "env LITELLM_LOG=ERROR $LITELLM_BIN --config $CONFIG_DIR/litellm-bench.yaml --host 127.0.0.1 --port $GATEWAY_PORT --num_workers 1" \
        "" 1

    run_suite_for_gateway \
        "LiteLLM Proxy ($LITELLM_WORKERS workers, no-DB, stateless)" \
        "env LITELLM_LOG=ERROR $LITELLM_BIN --config $CONFIG_DIR/litellm-bench.yaml --host 127.0.0.1 --port $GATEWAY_PORT --num_workers $LITELLM_WORKERS" \
        "" 1

    run_suite_for_gateway \
        "LiteLLM Proxy ($LITELLM_WORKERS workers, master_key + rpm/tpm)" \
        "env LITELLM_LOG=ERROR $LITELLM_BIN --config $CONFIG_DIR/litellm-bench-auth.yaml --host 127.0.0.1 --port $GATEWAY_PORT --num_workers $LITELLM_WORKERS" \
        "Authorization: Bearer sk-bench-virtual-key" 1
else
    echo ""
    echo "(skipping LiteLLM — set LITELLM_BIN or install litellm[proxy] in /tmp/litellm-bench-venv)"
fi

echo ""
echo "==> Shunt vs. LiteLLM benchmark complete."
