#!/usr/bin/env bash
set -euo pipefail

# Unified & Comprehensive Shunt Benchmark Orchestrator (RFC 0020)
# Covers 4 suites: API Gateway (api), AI Gateway (ai), MCP Gateway (mcp), and Stability/Soak (soak)
# with optional head-to-head competitors (Envoy, Caddy, LiteLLM) and unified JSONL -> Markdown output.

ulimit -n 16384 2>/dev/null || ulimit -n 8192 2>/dev/null || true

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
CONFIG_DIR="$ROOT_DIR/benches/configs"
RENDER_PY="$ROOT_DIR/benches/scripts/render_report.py"

SUITES="all"
PROFILE="full"
COMPETITORS=""
OUTPUT_JSON=""
OUTPUT_MD=""
REPORT_TITLE="Shunt Benchmark Report"
NO_BUILD=0

usage() {
    cat <<'EOF'
Usage: benches/scripts/bench.sh [options]

Options:
  --suite <list>        Suites to run: api, ai, mcp, soak, all, or comma-separated (default: all)
  --profile <name>      Workload profile: quick | ci | full (default: full)
  --competitors <list>  auto | none | comma-separated subset of envoy,caddy,litellm
                        (default: auto for full, none for quick/ci)
  --output-json <path>  Write raw JSONL benchmark results to <path>
  --output-md <path>    Write rendered Markdown report to <path>
  --title <text>        Markdown report H1 title (default: "Shunt Benchmark Report")
  --no-build            Skip `cargo build --release` (assumes binaries already built)
  -h, --help            Show this help message

Environment overrides:
  DURATION_SECS, WARMUP_SECS, HTTP_CONCURRENCY, SSE_CONCURRENCY, SSE_MED_CONCURRENCY,
  SSE_CHUNKS, SSE_INTERVAL_MS, OPENLOOP_RATE, LITELLM_WORKERS, LITELLM_BIN, MAX_RSS_GROWTH_MB
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --suite) SUITES="$2"; shift 2 ;;
        --profile) PROFILE="$2"; shift 2 ;;
        --competitors) COMPETITORS="$2"; shift 2 ;;
        --output-json) OUTPUT_JSON="$2"; shift 2 ;;
        --output-md) OUTPUT_MD="$2"; shift 2 ;;
        --title) REPORT_TITLE="$2"; shift 2 ;;
        --no-build) NO_BUILD=1; shift ;;
        -h|--help) usage; exit 0 ;;
        *) echo "error: unknown argument: $1" >&2; usage >&2; exit 2 ;;
    esac
done

case "$PROFILE" in
    quick)
        DURATION_SECS="${DURATION_SECS:-3}"
        WARMUP_SECS="${WARMUP_SECS:-1}"
        HTTP_CONCURRENCY="${HTTP_CONCURRENCY:-32}"
        SSE_MED_CONCURRENCY="${SSE_MED_CONCURRENCY:-100}"
        SSE_CONCURRENCY="${SSE_CONCURRENCY:-200}"
        OPENLOOP_RATE="${OPENLOOP_RATE:-15000}"
        [[ -z "$COMPETITORS" ]] && COMPETITORS="none"
        ;;
    ci)
        DURATION_SECS="${DURATION_SECS:-5}"
        WARMUP_SECS="${WARMUP_SECS:-2}"
        HTTP_CONCURRENCY="${HTTP_CONCURRENCY:-64}"
        SSE_MED_CONCURRENCY="${SSE_MED_CONCURRENCY:-200}"
        SSE_CONCURRENCY="${SSE_CONCURRENCY:-500}"
        OPENLOOP_RATE="${OPENLOOP_RATE:-15000}"
        [[ -z "$COMPETITORS" ]] && COMPETITORS="none"
        ;;
    full)
        DURATION_SECS="${DURATION_SECS:-8}"
        WARMUP_SECS="${WARMUP_SECS:-2}"
        HTTP_CONCURRENCY="${HTTP_CONCURRENCY:-64}"
        SSE_MED_CONCURRENCY="${SSE_MED_CONCURRENCY:-200}"
        SSE_CONCURRENCY="${SSE_CONCURRENCY:-1000}"
        OPENLOOP_RATE="${OPENLOOP_RATE:-25000}"
        [[ -z "$COMPETITORS" ]] && COMPETITORS="auto"
        ;;
    *)
        echo "error: invalid --profile '$PROFILE' (expected quick|ci|full)" >&2
        exit 2
        ;;
esac

SSE_CHUNKS="${SSE_CHUNKS:-20}"
SSE_INTERVAL_MS="${SSE_INTERVAL_MS:-25}"
LITELLM_WORKERS="${LITELLM_WORKERS:-4}"
MAX_RSS_GROWTH_MB="${MAX_RSS_GROWTH_MB:-20.0}"

UPSTREAM_PORT_1="${UPSTREAM_PORT_1:-18080}"
GATEWAY_PORT="${GATEWAY_PORT:-18081}"
UPSTREAM_PORT_2="${UPSTREAM_PORT_2:-18082}"
UPSTREAM_PORT_3="${UPSTREAM_PORT_3:-18083}"
FAULT_UPSTREAM_PORT="${FAULT_UPSTREAM_PORT:-18084}"
ADMIN_PORT="${ADMIN_PORT:-19090}"

# Deterministic HS256 JWT (iss=https://bench.shunt.dev, aud=shunt-api, scope="read write", exp=2100)
BENCH_JWT="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImJlbmNoLWhzMSJ9.eyJpc3MiOiJodHRwczovL2JlbmNoLnNodW50LmRldiIsImF1ZCI6InNodW50LWFwaSIsInN1YiI6ImJlbmNoLXVzZXIiLCJzY29wZSI6InJlYWQgd3JpdGUiLCJvcmciOnsiaWQiOiJhY21lIn0sImV4cCI6NDEwMjQ0NDgwMH0.oNwB3NTg0O9xnqR3IhQ9CqJfbgpiN597a1vthqYA7G0"

suite_enabled() {
    local target="$1"
    [[ "$SUITES" == "all" ]] && return 0
    [[ ",$SUITES," == *",$target,"* ]]
}

competitor_enabled() {
    local target="$1"
    [[ "$COMPETITORS" == "none" ]] && return 1
    [[ "$COMPETITORS" == "auto" ]] && return 0
    [[ ",$COMPETITORS," == *",$target,"* ]]
}

# Detect optional competitor binaries
ENVOY_BIN=""
CADDY_BIN=""
LITELLM_BIN="${LITELLM_BIN:-}"

if competitor_enabled "envoy" && command -v envoy >/dev/null 2>&1; then
    ENVOY_BIN="$(command -v envoy)"
fi
if competitor_enabled "caddy" && command -v caddy >/dev/null 2>&1; then
    CADDY_BIN="$(command -v caddy)"
fi
if competitor_enabled "litellm"; then
    if [[ -z "$LITELLM_BIN" ]]; then
        if command -v litellm >/dev/null 2>&1; then
            LITELLM_BIN="$(command -v litellm)"
        elif [[ -x "/tmp/litellm-bench-venv/bin/litellm" ]]; then
            LITELLM_BIN="/tmp/litellm-bench-venv/bin/litellm"
        fi
    fi
fi

if [[ "$NO_BUILD" != "1" ]]; then
    echo "==> Building shunt and shunt-bench (release)..." >&2
    (cd "$ROOT_DIR" && cargo build --release --locked -p shunt-cli -p shunt-bench >&2)
fi

SHUNT_BIN="$ROOT_DIR/target/release/shunt"
BENCH_BIN="$ROOT_DIR/target/release/shunt-bench"

TMP_DIR="$(mktemp -d)"
CERT_DIR="$TMP_DIR/certs"
GW_LOG="$TMP_DIR/gw.log"
RESULTS_JSONL="${OUTPUT_JSON:-$TMP_DIR/results.jsonl}"
ENV_JSON="$TMP_DIR/env.json"
mkdir -p "$(dirname "$RESULTS_JSONL")"
: >"$RESULTS_JSONL"

UPSTREAM_PIDS=()
GW_PID=""
GW_COLD_START_MS=0
GW_IDLE_RSS_MB=0.0
GW_IDLE_PROCS=1

kill_tree() {
    local root_pid="$1"
    [[ -z "$root_pid" ]] && return 0
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
    for pid in "${UPSTREAM_PIDS[@]+"${UPSTREAM_PIDS[@]}"}"; do
        kill_tree "$pid"
        wait "$pid" 2>/dev/null || true
    done
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

# Print "<rss_mb> <proc_count> <cpu_ms>" summed over root PID and all descendants.
tree_stats() {
    local root_pid="$1"
    python3 - "$root_pid" <<'PY'
import os, subprocess, sys

root = int(sys.argv[1])
out = subprocess.check_output(["ps", "-axo", "pid=,ppid=,rss=,time="], text=True)
children = {}
rss = {}
cpu_ms = {}

def parse_ps_time_ms(t: str) -> float:
    days = 0
    if "-" in t:
        d_part, t = t.split("-", 1)
        days = int(d_part)
    parts = t.split(":")
    if len(parts) == 2:
        mins = int(parts[0])
        secs = float(parts[1])
        return ((days * 86400) + mins * 60 + secs) * 1000.0
    if len(parts) == 3:
        hrs = int(parts[0])
        mins = int(parts[1])
        secs = float(parts[2])
        return ((days * 86400) + hrs * 3600 + mins * 60 + secs) * 1000.0
    return 0.0

for line in out.splitlines():
    parts = line.split()
    if len(parts) < 4:
        continue
    pid, ppid, kb, tstr = int(parts[0]), int(parts[1]), int(parts[2]), parts[3]
    rss[pid] = kb
    cpu_ms[pid] = parse_ps_time_ms(tstr)
    children.setdefault(ppid, []).append(pid)

total_kb = 0
total_cpu_ms = 0.0
stack = [root]
seen = set()
clk_tck = os.sysconf("SC_CLK_TCK") if hasattr(os, "sysconf") else 100

while stack:
    p = stack.pop()
    if p in seen:
        continue
    seen.add(p)
    total_kb += rss.get(p, 0)
    # Prefer /proc/<pid>/stat on Linux for exact jiffy CPU precision; fallback to ps time=
    proc_stat = f"/proc/{p}/stat"
    if os.path.exists(proc_stat):
        try:
            data = open(proc_stat, "r", encoding="utf-8").read()
            after_comm = data.rsplit(")", 1)[1].split()
            utime = int(after_comm[11])
            stime = int(after_comm[12])
            total_cpu_ms += ((utime + stime) / float(clk_tck)) * 1000.0
        except Exception:
            total_cpu_ms += cpu_ms.get(p, 0.0)
    else:
        total_cpu_ms += cpu_ms.get(p, 0.0)
    stack.extend(children.get(p, []))

print(f"{total_kb / 1024.0:.1f} {len(seen)} {total_cpu_ms:.1f}")
PY
}

render_cfg() {
    local src="$1"
    local dst="$TMP_DIR/$(basename "$src")"
    sed "s|{{CERT_DIR}}|$CERT_DIR|g" "$src" > "$dst"
    echo "$dst"
}

start_upstream() {
    local port="$1"
    shift
    wait_for_port_free "$port"
    local log="$TMP_DIR/upstream-$port.log"
    "$BENCH_BIN" upstream \
        --listen "127.0.0.1:$port" \
        --payload-bytes 256 \
        --sse-chunks "$SSE_CHUNKS" \
        --sse-interval-ms "$SSE_INTERVAL_MS" \
        "$@" >"$log" 2>&1 &
    local pid=$!
    UPSTREAM_PIDS+=("$pid")
    wait_for_port_and_pid "$port" "$pid" "$log" 500
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
    GW_COLD_START_MS=$((t1 - t0))
    sleep 0.4
    read -r GW_IDLE_RSS_MB GW_IDLE_PROCS _ <<< "$(tree_stats "$GW_PID")"
}

# Run a single shunt-bench command against the currently running gateway and append JSONL.
record_bench() {
    local suite="$1"
    local id="$2"
    local label="$3"
    local gateway="$4"
    local gateway_label="$5"
    shift 5

    echo "==> [$suite/$id] $gateway_label — $label" >&2
    local cpu_before post_rss proc_count cpu_after raw_json
    read -r _ _ cpu_before <<< "$(tree_stats "$GW_PID")"
    raw_json="$("$BENCH_BIN" "$@" --json)"
    read -r post_rss proc_count cpu_after <<< "$(tree_stats "$GW_PID")"

    python3 - "$raw_json" "$suite" "$id" "$label" "$gateway" "$gateway_label" \
        "$GW_COLD_START_MS" "$GW_IDLE_RSS_MB" "$GW_IDLE_PROCS" \
        "$post_rss" "$proc_count" "$cpu_before" "$cpu_after" <<'PY' >>"$RESULTS_JSONL"
import json, sys
row = json.loads(sys.argv[1])
row["suite"] = sys.argv[2]
row["id"] = sys.argv[3]
row["label"] = sys.argv[4]
row["gateway"] = sys.argv[5]
row["gateway_label"] = sys.argv[6]
row["cold_start_ms"] = int(sys.argv[7])
row["idle_rss_mb"] = float(sys.argv[8])
row["idle_proc_count"] = int(sys.argv[9])
row["post_rss_mb"] = float(sys.argv[10])
row["proc_count"] = int(sys.argv[11])
cpu_delta = max(0.0, float(sys.argv[13]) - float(sys.argv[12]))
row["cpu_ms"] = round(cpu_delta, 1)
ok = int(row.get("ok", 0))
if ok > 0 and cpu_delta > 0:
    row["cpu_ms_per_1k_req"] = round(cpu_delta / (ok / 1000.0), 2)
print(json.dumps(row))
PY
}

# ------------------------------------------------------------------------------
# Setup: Generate ephemeral TLS/mTLS certs & start required mock upstreams
# ------------------------------------------------------------------------------
echo "==> Generating ephemeral TLS/mTLS benchmark certs..." >&2
"$BENCH_BIN" gen-certs --out-dir "$CERT_DIR" >/dev/null

echo "==> Starting mock upstream(s)..." >&2
start_upstream "$UPSTREAM_PORT_1"
if suite_enabled "api" || suite_enabled "mcp"; then
    start_upstream "$UPSTREAM_PORT_2"
    start_upstream "$UPSTREAM_PORT_3"
fi
if suite_enabled "ai"; then
    start_upstream "$FAULT_UPSTREAM_PORT" --always-status 503
fi

# Collect versions
SHUNT_VER="$("$SHUNT_BIN" --version 2>/dev/null || echo 'shunt')"
VERSIONS_STR="$SHUNT_VER"
if [[ -n "$ENVOY_BIN" ]]; then
    ENVOY_VER="$("$ENVOY_BIN" --version 2>/dev/null | grep -m1 'version:' | sed 's/.*version: [^/]*\/\([^/]*\)\/.*/Envoy \1/' || echo 'Envoy')"
    [[ -n "$ENVOY_VER" ]] && VERSIONS_STR="$VERSIONS_STR · $ENVOY_VER"
fi
if [[ -n "$CADDY_BIN" ]]; then
    CADDY_VER="Caddy $("$CADDY_BIN" version 2>/dev/null | awk '{print $1}' || echo '')"
    [[ -n "$CADDY_VER" ]] && VERSIONS_STR="$VERSIONS_STR · $CADDY_VER"
fi
if [[ -n "$LITELLM_BIN" ]]; then
    LITELLM_PY="$(dirname "$LITELLM_BIN")/python"
    if [[ -x "$LITELLM_PY" ]]; then
        LITELLM_VER="$("$LITELLM_PY" -c "import importlib.metadata; print('LiteLLM ' + importlib.metadata.version('litellm'))" 2>/dev/null || echo 'LiteLLM')"
    else
        LITELLM_VER="LiteLLM"
    fi
    [[ -n "$LITELLM_VER" ]] && VERSIONS_STR="$VERSIONS_STR · $LITELLM_VER"
fi

# ==============================================================================
# SUITE 1: API GATEWAY
# ==============================================================================
if suite_enabled "api"; then
    echo "" >&2
    echo "==================== SUITE 1: API GATEWAY ====================" >&2

    # 1.1 Raw HTTP/1.1 Passthrough (+ 256KB large streaming in ci/full)
    start_gw "env RUST_LOG=error $SHUNT_BIN run --no-watch -c $CONFIG_DIR/api/shunt-raw.toml"
    record_bench "api" "api_raw_h1" "Raw HTTP/1.1 Passthrough (256B, \`HookMask::EMPTY\`)" \
        "shunt" "Shunt (raw)" \
        http --url "http://127.0.0.1:$GATEWAY_PORT/ping" -c "$HTTP_CONCURRENCY" -d "$DURATION_SECS" --warmup-secs "$WARMUP_SECS"
    if [[ "$PROFILE" != "quick" ]]; then
        record_bench "api" "api_large_stream" "256 KB Streaming Passthrough (Zero-Copy)" \
            "shunt" "Shunt (raw)" \
            http --url "http://127.0.0.1:$GATEWAY_PORT/bytes/262144" -c "$HTTP_CONCURRENCY" -d "$DURATION_SECS" --warmup-secs "$WARMUP_SECS"
    fi
    stop_gw

    if [[ -n "$ENVOY_BIN" ]]; then
        start_gw "$ENVOY_BIN -c $CONFIG_DIR/api/envoy-raw.yaml --log-level error"
        record_bench "api" "api_raw_h1" "Raw HTTP/1.1 Passthrough (256B, \`HookMask::EMPTY\`)" \
            "envoy" "Envoy (raw)" \
            http --url "http://127.0.0.1:$GATEWAY_PORT/ping" -c "$HTTP_CONCURRENCY" -d "$DURATION_SECS" --warmup-secs "$WARMUP_SECS"
        if [[ "$PROFILE" != "quick" ]]; then
            record_bench "api" "api_large_stream" "256 KB Streaming Passthrough (Zero-Copy)" \
                "envoy" "Envoy (raw)" \
                http --url "http://127.0.0.1:$GATEWAY_PORT/bytes/262144" -c "$HTTP_CONCURRENCY" -d "$DURATION_SECS" --warmup-secs "$WARMUP_SECS"
        fi
        stop_gw
    fi

    if [[ -n "$CADDY_BIN" ]]; then
        start_gw "$CADDY_BIN run --config $CONFIG_DIR/api/caddy-raw.json"
        record_bench "api" "api_raw_h1" "Raw HTTP/1.1 Passthrough (256B, \`HookMask::EMPTY\`)" \
            "caddy" "Caddy (raw)" \
            http --url "http://127.0.0.1:$GATEWAY_PORT/ping" -c "$HTTP_CONCURRENCY" -d "$DURATION_SECS" --warmup-secs "$WARMUP_SECS"
        if [[ "$PROFILE" != "quick" ]]; then
            record_bench "api" "api_large_stream" "256 KB Streaming Passthrough (Zero-Copy)" \
                "caddy" "Caddy (raw)" \
                http --url "http://127.0.0.1:$GATEWAY_PORT/bytes/262144" -c "$HTTP_CONCURRENCY" -d "$DURATION_SECS" --warmup-secs "$WARMUP_SECS"
        fi
        stop_gw
    fi

    # 1.2 TLS 1.3 + HTTP/2 Multiplexing (ci/full)
    if [[ "$PROFILE" != "quick" ]]; then
        SHUNT_TLS_CFG="$(render_cfg "$CONFIG_DIR/api/shunt-tls.toml")"
        start_gw "env RUST_LOG=error $SHUNT_BIN run --no-watch -c $SHUNT_TLS_CFG"
        record_bench "api" "api_raw_h2_tls" "HTTPS + HTTP/2 Multiplexed Passthrough (TLS 1.3)" \
            "shunt" "Shunt (TLS 1.3 + H2)" \
            http --url "https://127.0.0.1:$GATEWAY_PORT/ping" --http2 --ca-cert "$CERT_DIR/ca.pem" \
            -c "$HTTP_CONCURRENCY" -d "$DURATION_SECS" --warmup-secs "$WARMUP_SECS"
        stop_gw

        if [[ -n "$ENVOY_BIN" ]]; then
            ENVOY_TLS_CFG="$(render_cfg "$CONFIG_DIR/api/envoy-tls.yaml")"
            start_gw "$ENVOY_BIN -c $ENVOY_TLS_CFG --log-level error"
            record_bench "api" "api_raw_h2_tls" "HTTPS + HTTP/2 Multiplexed Passthrough (TLS 1.3)" \
                "envoy" "Envoy (TLS 1.3 + H2)" \
                http --url "https://127.0.0.1:$GATEWAY_PORT/ping" --http2 --ca-cert "$CERT_DIR/ca.pem" \
                -c "$HTTP_CONCURRENCY" -d "$DURATION_SECS" --warmup-secs "$WARMUP_SECS"
            stop_gw
        fi

        if [[ -n "$CADDY_BIN" ]]; then
            CADDY_TLS_CFG="$(render_cfg "$CONFIG_DIR/api/caddy-tls.json")"
            start_gw "$CADDY_BIN run --config $CADDY_TLS_CFG"
            record_bench "api" "api_raw_h2_tls" "HTTPS + HTTP/2 Multiplexed Passthrough (TLS 1.3)" \
                "caddy" "Caddy (TLS 1.3 + H2)" \
                http --url "https://127.0.0.1:$GATEWAY_PORT/ping" --http2 --ca-cert "$CERT_DIR/ca.pem" \
                -c "$HTTP_CONCURRENCY" -d "$DURATION_SECS" --warmup-secs "$WARMUP_SECS"
            stop_gw
        fi
    fi

    # 1.3 mTLS Client Cert Verification + mtls-auth (full)
    if [[ "$PROFILE" == "full" ]]; then
        SHUNT_MTLS_CFG="$(render_cfg "$CONFIG_DIR/api/shunt-mtls.toml")"
        start_gw "env RUST_LOG=error $SHUNT_BIN run --no-watch -c $SHUNT_MTLS_CFG"
        record_bench "api" "api_mtls_h2" "mTLS + \`mtls-auth\` SPIFFE/CN Verification (HTTP/2)" \
            "shunt" "Shunt (mTLS + H2)" \
            http --url "https://127.0.0.1:$GATEWAY_PORT/ping" --http2 \
            --ca-cert "$CERT_DIR/ca.pem" --client-cert "$CERT_DIR/client.pem" --client-key "$CERT_DIR/client-key.pem" \
            -c "$HTTP_CONCURRENCY" -d "$DURATION_SECS" --warmup-secs "$WARMUP_SECS"
        stop_gw
    fi

    # 1.4 3-Plugin Chain (+ 401 Auth Rejection Fast-Path + Open-Loop Latency in full)
    start_gw "env RUST_LOG=error $SHUNT_BIN run --no-watch -c $CONFIG_DIR/api/shunt-plugins.toml"
    record_bench "api" "api_plugins_3" "3-Plugin Chain (\`request-id\` + \`bearer-auth\` + \`rate-limit\`)" \
        "shunt" "Shunt (3-plugin)" \
        http --url "http://127.0.0.1:$GATEWAY_PORT/ping" -c "$HTTP_CONCURRENCY" -d "$DURATION_SECS" --warmup-secs "$WARMUP_SECS" \
        -H "Authorization: Bearer bench-secret-token"
    if [[ "$PROFILE" != "quick" ]]; then
        record_bench "api" "api_reject_401" "Auth Rejection Fast-Path (401, Zero Upstream I/O)" \
            "shunt" "Shunt (3-plugin)" \
            http --url "http://127.0.0.1:$GATEWAY_PORT/ping" -c "$HTTP_CONCURRENCY" -d "$DURATION_SECS" --warmup-secs "$WARMUP_SECS" \
            --expect-status 401 -H "Authorization: Bearer invalid-token"
    fi
    if [[ "$PROFILE" == "full" ]]; then
        record_bench "api" "api_openloop_p99" "Open-Loop 3-Plugin Chain (${OPENLOOP_RATE} req/s fixed rate)" \
            "shunt" "Shunt (3-plugin)" \
            http --url "http://127.0.0.1:$GATEWAY_PORT/ping" -c "$HTTP_CONCURRENCY" -d "$DURATION_SECS" --warmup-secs "$WARMUP_SECS" \
            --rate "$OPENLOOP_RATE" -H "Authorization: Bearer bench-secret-token"
    fi
    stop_gw

    if [[ -n "$ENVOY_BIN" ]]; then
        start_gw "$ENVOY_BIN -c $CONFIG_DIR/api/envoy-plugins.yaml --log-level error"
        record_bench "api" "api_plugins_3" "3-Plugin Chain (\`request-id\` + \`bearer-auth\` + \`rate-limit\`)" \
            "envoy" "Envoy (3-filter)" \
            http --url "http://127.0.0.1:$GATEWAY_PORT/ping" -c "$HTTP_CONCURRENCY" -d "$DURATION_SECS" --warmup-secs "$WARMUP_SECS" \
            -H "Authorization: Bearer bench-secret-token"
        if [[ "$PROFILE" != "quick" ]]; then
            record_bench "api" "api_reject_401" "Auth Rejection Fast-Path (401, Zero Upstream I/O)" \
                "envoy" "Envoy (3-filter)" \
                http --url "http://127.0.0.1:$GATEWAY_PORT/ping" -c "$HTTP_CONCURRENCY" -d "$DURATION_SECS" --warmup-secs "$WARMUP_SECS" \
                --expect-status 401 -H "Authorization: Bearer invalid-token"
        fi
        if [[ "$PROFILE" == "full" ]]; then
            record_bench "api" "api_openloop_p99" "Open-Loop 3-Plugin Chain (${OPENLOOP_RATE} req/s fixed rate)" \
                "envoy" "Envoy (3-filter)" \
                http --url "http://127.0.0.1:$GATEWAY_PORT/ping" -c "$HTTP_CONCURRENCY" -d "$DURATION_SECS" --warmup-secs "$WARMUP_SECS" \
                --rate "$OPENLOOP_RATE" -H "Authorization: Bearer bench-secret-token"
        fi
        stop_gw
    fi

    if [[ -n "$CADDY_BIN" ]]; then
        start_gw "$CADDY_BIN run --config $CONFIG_DIR/api/caddy-plugins.json"
        record_bench "api" "api_plugins_3" "3-Plugin Chain (\`request-id\` + \`bearer-auth\` + \`rate-limit\`)" \
            "caddy" "Caddy (headers + auth)" \
            http --url "http://127.0.0.1:$GATEWAY_PORT/ping" -c "$HTTP_CONCURRENCY" -d "$DURATION_SECS" --warmup-secs "$WARMUP_SECS" \
            -H "Authorization: Bearer bench-secret-token"
        if [[ "$PROFILE" == "full" ]]; then
            record_bench "api" "api_openloop_p99" "Open-Loop 3-Plugin Chain (${OPENLOOP_RATE} req/s fixed rate)" \
                "caddy" "Caddy (headers + auth)" \
                http --url "http://127.0.0.1:$GATEWAY_PORT/ping" -c "$HTTP_CONCURRENCY" -d "$DURATION_SECS" --warmup-secs "$WARMUP_SECS" \
                --rate "$OPENLOOP_RATE" -H "Authorization: Bearer bench-secret-token"
        fi
        stop_gw
    fi

    # 1.5 Modern API Security (HS256 JWT + IP Filter + Body Limit) & Streaming zstd Compression
    start_gw "env RUST_LOG=error $SHUNT_BIN run --no-watch -c $CONFIG_DIR/api/shunt-security.toml"
    record_bench "api" "api_jwt_security" "JWT HS256 & Security Chain (\`ip-filter\` + \`jwt-auth\` + \`body-limit\`)" \
        "shunt" "Shunt (JWT + Security)" \
        http --url "http://127.0.0.1:$GATEWAY_PORT/ping" -c "$HTTP_CONCURRENCY" -d "$DURATION_SECS" --warmup-secs "$WARMUP_SECS" \
        -H "Authorization: Bearer $BENCH_JWT"
    if [[ "$PROFILE" != "quick" ]]; then
        record_bench "api" "api_jwt_zstd" "JWT + Security + Streaming \`zstd\` (~4.3 KB \`/json\`)" \
            "shunt" "Shunt (JWT + zstd)" \
            http --url "http://127.0.0.1:$GATEWAY_PORT/json" -c "$HTTP_CONCURRENCY" -d "$DURATION_SECS" --warmup-secs "$WARMUP_SECS" \
            -H "Authorization: Bearer $BENCH_JWT" -H "Accept-Encoding: zstd"
    fi
    stop_gw

    if [[ -n "$ENVOY_BIN" ]]; then
        start_gw "$ENVOY_BIN -c $CONFIG_DIR/api/envoy-jwt-zstd.yaml --log-level error"
        record_bench "api" "api_jwt_security" "JWT HS256 & Security Chain (\`ip-filter\` + \`jwt-auth\` + \`body-limit\`)" \
            "envoy" "Envoy (jwt_authn)" \
            http --url "http://127.0.0.1:$GATEWAY_PORT/ping" -c "$HTTP_CONCURRENCY" -d "$DURATION_SECS" --warmup-secs "$WARMUP_SECS" \
            -H "Authorization: Bearer $BENCH_JWT"
        if [[ "$PROFILE" != "quick" ]]; then
            record_bench "api" "api_jwt_zstd" "JWT + Security + Streaming \`zstd\` (~4.3 KB \`/json\`)" \
                "envoy" "Envoy (jwt_authn + zstd)" \
                http --url "http://127.0.0.1:$GATEWAY_PORT/json" -c "$HTTP_CONCURRENCY" -d "$DURATION_SECS" --warmup-secs "$WARMUP_SECS" \
                -H "Authorization: Bearer $BENCH_JWT" -H "Accept-Encoding: zstd"
        fi
        stop_gw
    fi

    if [[ -n "$CADDY_BIN" && "$PROFILE" != "quick" ]]; then
        start_gw "$CADDY_BIN run --config $CONFIG_DIR/api/caddy-zstd.json"
        record_bench "api" "api_jwt_zstd" "JWT + Security + Streaming \`zstd\` (~4.3 KB \`/json\`)" \
            "caddy" "Caddy (encode zstd, no JWT)" \
            http --url "http://127.0.0.1:$GATEWAY_PORT/json" -c "$HTTP_CONCURRENCY" -d "$DURATION_SECS" --warmup-secs "$WARMUP_SECS" \
            -H "Accept-Encoding: zstd"
        stop_gw
    fi

    # 1.6 200-Route Table + 3-Endpoint Weighted LB + Active HTTP Health Probes (ci/full)
    if [[ "$PROFILE" != "quick" ]]; then
        start_gw "env RUST_LOG=error $SHUNT_BIN run --no-watch -c $CONFIG_DIR/api/shunt-routing-lb.toml"
        record_bench "api" "api_routing_lb" "200-Route Table + 3-Endpoint Weighted LB + Health Probes" \
            "shunt" "Shunt (200 routes + LB)" \
            http --url "http://127.0.0.1:$GATEWAY_PORT/svc/150/ping" -c "$HTTP_CONCURRENCY" -d "$DURATION_SECS" --warmup-secs "$WARMUP_SECS"
        stop_gw

        if [[ -n "$ENVOY_BIN" ]]; then
            start_gw "$ENVOY_BIN -c $CONFIG_DIR/api/envoy-routing-lb.yaml --log-level error"
            record_bench "api" "api_routing_lb" "200-Route Table + 3-Endpoint Weighted LB + Health Probes" \
                "envoy" "Envoy (200 routes + LB)" \
                http --url "http://127.0.0.1:$GATEWAY_PORT/svc/150/ping" -c "$HTTP_CONCURRENCY" -d "$DURATION_SECS" --warmup-secs "$WARMUP_SECS"
            stop_gw
        fi
    fi

    # 1.7 Rate-Limit Load Shedding (429) & Observability Tax (full)
    if [[ "$PROFILE" == "full" ]]; then
        start_gw "env RUST_LOG=error $SHUNT_BIN run --no-watch -c $CONFIG_DIR/api/shunt-reject.toml"
        record_bench "api" "api_reject_429" "Rate-Limit Shedding Fast-Path (429, Zero Upstream I/O)" \
            "shunt" "Shunt (rate-limit 429)" \
            http --url "http://127.0.0.1:$GATEWAY_PORT/ping" -c "$HTTP_CONCURRENCY" -d "$DURATION_SECS" --warmup-secs "$WARMUP_SECS" \
            --expect-status 429
        stop_gw

        if [[ -n "$ENVOY_BIN" ]]; then
            start_gw "$ENVOY_BIN -c $CONFIG_DIR/api/envoy-reject.yaml --log-level error"
            record_bench "api" "api_reject_429" "Rate-Limit Shedding Fast-Path (429, Zero Upstream I/O)" \
                "envoy" "Envoy (local_ratelimit 429)" \
                http --url "http://127.0.0.1:$GATEWAY_PORT/ping" -c "$HTTP_CONCURRENCY" -d "$DURATION_SECS" --warmup-secs "$WARMUP_SECS" \
                --expect-status 429
            stop_gw
        fi

        start_gw "env RUST_LOG=error $SHUNT_BIN run --no-watch -c $CONFIG_DIR/api/shunt-observability.toml"
        record_bench "api" "api_observability_tax" "Observability Tax (3-Plugin + \`metrics\` + \`otel-trace\` + \`access-log\`)" \
            "shunt" "Shunt (full observability)" \
            http --url "http://127.0.0.1:$GATEWAY_PORT/ping" -c "$HTTP_CONCURRENCY" -d "$DURATION_SECS" --warmup-secs "$WARMUP_SECS" \
            -H "Authorization: Bearer bench-secret-token"
        stop_gw
    fi

    # 1.8 High-Concurrency SSE Passthrough
    start_gw "env RUST_LOG=error $SHUNT_BIN run --no-watch -c $CONFIG_DIR/api/shunt-sse.toml"
    record_bench "api" "api_sse_passthrough" "SSE Passthrough (${SSE_CHUNKS} chunks @ ${SSE_INTERVAL_MS}ms)" \
        "shunt" "Shunt (SSE passthrough)" \
        sse --url "http://127.0.0.1:$GATEWAY_PORT/sse" -c "$SSE_CONCURRENCY" --waves 1 --method GET
    stop_gw

    if [[ -n "$ENVOY_BIN" ]]; then
        start_gw "$ENVOY_BIN -c $CONFIG_DIR/api/envoy-sse.yaml --log-level error"
        record_bench "api" "api_sse_passthrough" "SSE Passthrough (${SSE_CHUNKS} chunks @ ${SSE_INTERVAL_MS}ms)" \
            "envoy" "Envoy (SSE passthrough)" \
            sse --url "http://127.0.0.1:$GATEWAY_PORT/sse" -c "$SSE_CONCURRENCY" --waves 1 --method GET
        stop_gw
    fi

    if [[ -n "$CADDY_BIN" ]]; then
        start_gw "$CADDY_BIN run --config $CONFIG_DIR/api/caddy-sse.json"
        record_bench "api" "api_sse_passthrough" "SSE Passthrough (${SSE_CHUNKS} chunks @ ${SSE_INTERVAL_MS}ms)" \
            "caddy" "Caddy (SSE passthrough)" \
            sse --url "http://127.0.0.1:$GATEWAY_PORT/sse" -c "$SSE_CONCURRENCY" --waves 1 --method GET
        stop_gw
    fi
fi

# ==============================================================================
# SUITE 2: AI GATEWAY
# ==============================================================================
if suite_enabled "ai"; then
    echo "" >&2
    echo "==================== SUITE 2: AI GATEWAY ====================" >&2

    # 2.1 Shunt AI Minimal (3-plugin)
    start_gw "env RUST_LOG=error $SHUNT_BIN run --no-watch -c $CONFIG_DIR/ai/shunt-minimal.toml"
    record_bench "ai" "ai_openai_small" "OpenAI Chat Passthrough (~70B prompt)" \
        "shunt" "Shunt AI (3-plugin)" \
        http --url "http://127.0.0.1:$GATEWAY_PORT/v1/chat/completions" --method POST --body-preset ai-openai-small \
        -c "$HTTP_CONCURRENCY" -d "$DURATION_SECS" --warmup-secs "$WARMUP_SECS"
    record_bench "ai" "ai_anthropic_small" "Anthropic <-> OpenAI Translate (~70B prompt)" \
        "shunt" "Shunt AI (3-plugin)" \
        http --url "http://127.0.0.1:$GATEWAY_PORT/v1/chat/completions" --method POST --body-preset ai-anthropic-small \
        -c "$HTTP_CONCURRENCY" -d "$DURATION_SECS" --warmup-secs "$WARMUP_SECS"
    record_bench "ai" "ai_sse_translate" "Live SSE Translation (\`Anthropic -> OpenAI\`)" \
        "shunt" "Shunt AI (3-plugin)" \
        sse --url "http://127.0.0.1:$GATEWAY_PORT/v1/chat/completions" --method POST --body-preset ai-anthropic-sse \
        -c "$SSE_CONCURRENCY" --waves 1
    stop_gw

    # 2.2 Shunt AI Governed (8-plugin + realistic 4KB / 32KB prompts + SSE)
    start_gw "env RUST_LOG=error $SHUNT_BIN run --no-watch -c $CONFIG_DIR/ai/shunt-governed.toml"
    record_bench "ai" "ai_openai_small" "OpenAI Chat Passthrough (~70B prompt)" \
        "shunt" "Shunt AI Governed (8-plugin)" \
        http --url "http://127.0.0.1:$GATEWAY_PORT/v1/chat/completions" --method POST --body-preset ai-openai-small \
        -c "$HTTP_CONCURRENCY" -d "$DURATION_SECS" --warmup-secs "$WARMUP_SECS" \
        -H "Authorization: Bearer sk-bench-virtual-key"
    record_bench "ai" "ai_anthropic_small" "Anthropic <-> OpenAI Translate (~70B prompt)" \
        "shunt" "Shunt AI Governed (8-plugin)" \
        http --url "http://127.0.0.1:$GATEWAY_PORT/v1/chat/completions" --method POST --body-preset ai-anthropic-small \
        -c "$HTTP_CONCURRENCY" -d "$DURATION_SECS" --warmup-secs "$WARMUP_SECS" \
        -H "Authorization: Bearer sk-bench-virtual-key"
    if [[ "$PROFILE" != "quick" ]]; then
        record_bench "ai" "ai_anthropic_4k" "Realistic 4 KB Multi-Turn Translate (Governed)" \
            "shunt" "Shunt AI Governed (8-plugin)" \
            http --url "http://127.0.0.1:$GATEWAY_PORT/v1/chat/completions" --method POST --body-preset ai-anthropic-4k \
            -c "$HTTP_CONCURRENCY" -d "$DURATION_SECS" --warmup-secs "$WARMUP_SECS" \
            -H "Authorization: Bearer sk-bench-virtual-key"
    fi
    if [[ "$PROFILE" == "full" ]]; then
        record_bench "ai" "ai_anthropic_32k" "Realistic 32 KB Multi-Turn Translate (Governed)" \
            "shunt" "Shunt AI Governed (8-plugin)" \
            http --url "http://127.0.0.1:$GATEWAY_PORT/v1/chat/completions" --method POST --body-preset ai-anthropic-32k \
            -c "$HTTP_CONCURRENCY" -d "$DURATION_SECS" --warmup-secs "$WARMUP_SECS" \
            -H "Authorization: Bearer sk-bench-virtual-key"
        record_bench "ai" "ai_sse_translate" "Live SSE Translation (\`Anthropic -> OpenAI\`)" \
            "shunt" "Shunt AI Governed (8-plugin)" \
            sse --url "http://127.0.0.1:$GATEWAY_PORT/v1/chat/completions" --method POST --body-preset ai-anthropic-sse \
            -c "$SSE_MED_CONCURRENCY" --waves 1 -H "Authorization: Bearer sk-bench-virtual-key"
    fi
    record_bench "ai" "ai_sse_translate" "Live SSE Translation (\`Anthropic -> OpenAI\`)" \
        "shunt" "Shunt AI Governed (8-plugin)" \
        sse --url "http://127.0.0.1:$GATEWAY_PORT/v1/chat/completions" --method POST --body-preset ai-anthropic-sse \
        -c "$SSE_CONCURRENCY" --waves 1 -H "Authorization: Bearer sk-bench-virtual-key"
    stop_gw

    # 2.3 Shunt AI Guardrails (Clean 4KB, Active Redaction Both Directions, Prompt-Injection Block, SSE Holdback)
    if [[ "$PROFILE" != "quick" ]]; then
        start_gw "env RUST_LOG=error $SHUNT_BIN run --no-watch -c $CONFIG_DIR/ai/shunt-guardrails.toml"
        record_bench "ai" "ai_guardrails_clean" "Inline Guardrails — Clean 4 KB Prompt (Zero Violations)" \
            "shunt" "Shunt AI Guardrailed" \
            http --url "http://127.0.0.1:$GATEWAY_PORT/v1/chat/completions" --method POST --body-preset ai-guardrails-clean-4k \
            -c "$HTTP_CONCURRENCY" -d "$DURATION_SECS" --warmup-secs "$WARMUP_SECS"
        record_bench "ai" "ai_guardrails_redact" "Inline Guardrails — Active PII/Secret Redaction (Req + Resp)" \
            "shunt" "Shunt AI Guardrailed" \
            http --url "http://127.0.0.1:$GATEWAY_PORT/v1/chat/completions" --method POST --body-preset ai-guardrails-dirty \
            -c "$HTTP_CONCURRENCY" -d "$DURATION_SECS" --warmup-secs "$WARMUP_SECS"
        record_bench "ai" "ai_guardrails_block" "Inline Guardrails — Prompt-Injection Block (400 Pre-Upstream)" \
            "shunt" "Shunt AI Guardrailed" \
            http --url "http://127.0.0.1:$GATEWAY_PORT/v1/chat/completions" --method POST --body-preset ai-guardrails-injection \
            --expect-status 400 -c "$HTTP_CONCURRENCY" -d "$DURATION_SECS" --warmup-secs "$WARMUP_SECS"
        record_bench "ai" "ai_sse_guardrails" "Guardrailed SSE (\`Anthropic -> OpenAI\` + 64-char Holdback Scan)" \
            "shunt" "Shunt AI Guardrailed" \
            sse --url "http://127.0.0.1:$GATEWAY_PORT/v1/chat/completions" --method POST --body-preset ai-anthropic-sse \
            -c "$SSE_CONCURRENCY" --waves 1
        stop_gw
    fi

    # 2.4 Shunt AI Cache (100% Hit, 100% Miss, Singleflight Coalescing, Streaming SSE Cache Replay)
    start_gw "env RUST_LOG=error $SHUNT_BIN run --no-watch -c $CONFIG_DIR/ai/shunt-cache.toml"
    record_bench "ai" "ai_cache_hit_json" "AI Cache — 100% Exact-Match Hit (Zero Upstream I/O)" \
        "shunt" "Shunt AI Cached" \
        http --url "http://127.0.0.1:$GATEWAY_PORT/v1/chat/completions" --method POST --body-preset ai-cache-hit \
        -c "$HTTP_CONCURRENCY" -d "$DURATION_SECS" --warmup-secs "$WARMUP_SECS" \
        -H "Authorization: Bearer sk-bench-virtual-key"
    if [[ "$PROFILE" != "quick" ]]; then
        record_bench "ai" "ai_cache_miss_json" "AI Cache — 100% Miss Path (Key Hash + Capture + Evict)" \
            "shunt" "Shunt AI Cached" \
            http --url "http://127.0.0.1:$GATEWAY_PORT/v1/chat/completions" --method POST --body-preset ai-cache-nonce \
            --cache-cardinality 0 -c "$HTTP_CONCURRENCY" -d "$DURATION_SECS" --warmup-secs "$WARMUP_SECS" \
            -H "Authorization: Bearer sk-bench-virtual-key"
        record_bench "ai" "ai_cache_singleflight" "AI Cache — Singleflight Wave (100 Concurrent Identical Misses)" \
            "shunt" "Shunt AI Cached" \
            http --url "http://127.0.0.1:$GATEWAY_PORT/v1/chat/completions" --method POST \
            --body '{"model":"gpt-bench","temperature":0,"stream":false,"messages":[{"role":"user","content":"singleflight-burst-key"}]}' \
            --single-wave -c 100 -H "Authorization: Bearer sk-bench-virtual-key"
        # Prime streaming SSE cache entry with 1 call, then benchmark concurrent replay
        "$BENCH_BIN" sse --url "http://127.0.0.1:$GATEWAY_PORT/v1/chat/completions" \
            --method POST --body-preset ai-cache-sse -c 1 --waves 1 \
            -H "Authorization: Bearer sk-bench-virtual-key" >/dev/null
        record_bench "ai" "ai_sse_cache_replay" "AI Cache — Streaming SSE Cache Replay (Zero Upstream I/O)" \
            "shunt" "Shunt AI Cached" \
            sse --url "http://127.0.0.1:$GATEWAY_PORT/v1/chat/completions" --method POST --body-preset ai-cache-sse \
            -c "$SSE_CONCURRENCY" --waves 1 -H "Authorization: Bearer sk-bench-virtual-key"
    fi
    stop_gw

    # 2.5 Multi-Protocol Ingress (/v1/messages, /v1/responses) & Cloud Dialects (Gemini, Bedrock SigV4)
    if [[ "$PROFILE" != "quick" ]]; then
        start_gw "env RUST_LOG=error $SHUNT_BIN run --no-watch -c $CONFIG_DIR/ai/shunt-multiprotocol.toml"
        record_bench "ai" "ai_ingress_messages" "Multi-Protocol Ingress (\`POST /v1/messages\` -> OpenAI)" \
            "shunt" "Shunt AI Multi-Protocol" \
            http --url "http://127.0.0.1:$GATEWAY_PORT/v1/messages" --method POST --body-preset ai-messages-ingress \
            -c "$HTTP_CONCURRENCY" -d "$DURATION_SECS" --warmup-secs "$WARMUP_SECS"
        record_bench "ai" "ai_ingress_responses" "Multi-Protocol Ingress (\`POST /v1/responses\` -> Anthropic)" \
            "shunt" "Shunt AI Multi-Protocol" \
            http --url "http://127.0.0.1:$GATEWAY_PORT/v1/responses" --method POST --body-preset ai-responses-ingress \
            -c "$HTTP_CONCURRENCY" -d "$DURATION_SECS" --warmup-secs "$WARMUP_SECS"
        record_bench "ai" "ai_bedrock_sigv4" "AWS Bedrock Converse + Pure-Rust SigV4 Signing" \
            "shunt" "Shunt AI Multi-Protocol" \
            http --url "http://127.0.0.1:$GATEWAY_PORT/v1/chat/completions" --method POST --body-preset ai-bedrock-small \
            -c "$HTTP_CONCURRENCY" -d "$DURATION_SECS" --warmup-secs "$WARMUP_SECS"
        if [[ "$PROFILE" == "full" ]]; then
            record_bench "ai" "ai_gemini_dialect" "Google Gemini \`generateContent\` Dialect Translation" \
                "shunt" "Shunt AI Multi-Protocol" \
                http --url "http://127.0.0.1:$GATEWAY_PORT/v1/chat/completions" --method POST --body-preset ai-gemini-small \
                -c "$HTTP_CONCURRENCY" -d "$DURATION_SECS" --warmup-secs "$WARMUP_SECS"
            record_bench "ai" "ai_bedrock_sse" "AWS Bedrock \`ConverseStream\` Binary EventStream -> OpenAI SSE" \
                "shunt" "Shunt AI Multi-Protocol" \
                sse --url "http://127.0.0.1:$GATEWAY_PORT/v1/chat/completions" --method POST --body-preset ai-bedrock-sse \
                -c "$SSE_MED_CONCURRENCY" --waves 1
        fi
        stop_gw

        # 2.6 Failover & Circuit Breaker (primary 503 -> secondary 200)
        start_gw "env RUST_LOG=error $SHUNT_BIN run --no-watch -c $CONFIG_DIR/ai/shunt-failover.toml"
        record_bench "ai" "ai_failover" "Upstream 503 Failover & Circuit Breaker (\`ai-failover\`)" \
            "shunt" "Shunt AI Failover" \
            http --url "http://127.0.0.1:$GATEWAY_PORT/v1/chat/completions" --method POST --body-preset ai-failover-small \
            -c "$HTTP_CONCURRENCY" -d "$DURATION_SECS" --warmup-secs "$WARMUP_SECS"
        stop_gw
    fi

    # 2.7 LiteLLM Proxy Head-to-Head (when installed & enabled)
    if [[ -n "$LITELLM_BIN" ]]; then
        start_gw "env LITELLM_LOG=ERROR $LITELLM_BIN --config $CONFIG_DIR/ai/litellm-stateless.yaml --host 127.0.0.1 --port $GATEWAY_PORT --num_workers 1"
        record_bench "ai" "ai_openai_small" "OpenAI Chat Passthrough (~70B prompt)" \
            "litellm" "LiteLLM (1w, stateless)" \
            http --url "http://127.0.0.1:$GATEWAY_PORT/v1/chat/completions" --method POST --body-preset ai-openai-small \
            -c "$HTTP_CONCURRENCY" -d "$DURATION_SECS" --warmup-secs "$WARMUP_SECS"
        record_bench "ai" "ai_anthropic_small" "Anthropic <-> OpenAI Translate (~70B prompt)" \
            "litellm" "LiteLLM (1w, stateless)" \
            http --url "http://127.0.0.1:$GATEWAY_PORT/v1/chat/completions" --method POST --body-preset ai-anthropic-small \
            -c "$HTTP_CONCURRENCY" -d "$DURATION_SECS" --warmup-secs "$WARMUP_SECS"
        if [[ "$PROFILE" == "full" ]]; then
            record_bench "ai" "ai_sse_translate" "Live SSE Translation (\`Anthropic -> OpenAI\`)" \
                "litellm" "LiteLLM (1w, stateless)" \
                sse --url "http://127.0.0.1:$GATEWAY_PORT/v1/chat/completions" --method POST --body-preset ai-anthropic-sse \
                -c "$SSE_MED_CONCURRENCY" --waves 1
        fi
        stop_gw

        start_gw "env LITELLM_LOG=ERROR $LITELLM_BIN --config $CONFIG_DIR/ai/litellm-auth.yaml --host 127.0.0.1 --port $GATEWAY_PORT --num_workers $LITELLM_WORKERS"
        record_bench "ai" "ai_openai_small" "OpenAI Chat Passthrough (~70B prompt)" \
            "litellm" "LiteLLM (${LITELLM_WORKERS}w, auth+rpm/tpm)" \
            http --url "http://127.0.0.1:$GATEWAY_PORT/v1/chat/completions" --method POST --body-preset ai-openai-small \
            -c "$HTTP_CONCURRENCY" -d "$DURATION_SECS" --warmup-secs "$WARMUP_SECS" \
            -H "Authorization: Bearer sk-bench-virtual-key"
        record_bench "ai" "ai_anthropic_small" "Anthropic <-> OpenAI Translate (~70B prompt)" \
            "litellm" "LiteLLM (${LITELLM_WORKERS}w, auth+rpm/tpm)" \
            http --url "http://127.0.0.1:$GATEWAY_PORT/v1/chat/completions" --method POST --body-preset ai-anthropic-small \
            -c "$HTTP_CONCURRENCY" -d "$DURATION_SECS" --warmup-secs "$WARMUP_SECS" \
            -H "Authorization: Bearer sk-bench-virtual-key"
        record_bench "ai" "ai_anthropic_4k" "Realistic 4 KB Multi-Turn Translate (Governed)" \
            "litellm" "LiteLLM (${LITELLM_WORKERS}w, auth+rpm/tpm)" \
            http --url "http://127.0.0.1:$GATEWAY_PORT/v1/chat/completions" --method POST --body-preset ai-anthropic-4k \
            -c "$HTTP_CONCURRENCY" -d "$DURATION_SECS" --warmup-secs "$WARMUP_SECS" \
            -H "Authorization: Bearer sk-bench-virtual-key"
        if [[ "$PROFILE" == "full" ]]; then
            record_bench "ai" "ai_anthropic_32k" "Realistic 32 KB Multi-Turn Translate (Governed)" \
                "litellm" "LiteLLM (${LITELLM_WORKERS}w, auth+rpm/tpm)" \
                http --url "http://127.0.0.1:$GATEWAY_PORT/v1/chat/completions" --method POST --body-preset ai-anthropic-32k \
                -c "$HTTP_CONCURRENCY" -d "$DURATION_SECS" --warmup-secs "$WARMUP_SECS" \
                -H "Authorization: Bearer sk-bench-virtual-key"
            record_bench "ai" "ai_sse_translate" "Live SSE Translation (\`Anthropic -> OpenAI\`)" \
                "litellm" "LiteLLM (${LITELLM_WORKERS}w, auth+rpm/tpm)" \
                sse --url "http://127.0.0.1:$GATEWAY_PORT/v1/chat/completions" --method POST --body-preset ai-anthropic-sse \
                -c "$SSE_MED_CONCURRENCY" --waves 1 -H "Authorization: Bearer sk-bench-virtual-key"
        fi
        record_bench "ai" "ai_sse_translate" "Live SSE Translation (\`Anthropic -> OpenAI\`)" \
            "litellm" "LiteLLM (${LITELLM_WORKERS}w, auth+rpm/tpm)" \
            sse --url "http://127.0.0.1:$GATEWAY_PORT/v1/chat/completions" --method POST --body-preset ai-anthropic-sse \
            -c "$SSE_CONCURRENCY" --waves 1 -H "Authorization: Bearer sk-bench-virtual-key"
        stop_gw
    fi
fi

# ==============================================================================
# SUITE 3: MCP & AGENTIC GATEWAY
# ==============================================================================
if suite_enabled "mcp"; then
    echo "" >&2
    echo "==================== SUITE 3: MCP GATEWAY ====================" >&2

    start_gw "env RUST_LOG=error $SHUNT_BIN run --no-watch -c $CONFIG_DIR/mcp/shunt-mcp-governed.toml"

    # Prime tools/list catalog cache once so steady-state warm ACL-filtered path is measured.
    "$BENCH_BIN" http --url "http://127.0.0.1:$GATEWAY_PORT/mcp" --method POST --body-preset mcp-tools-list \
        --single-wave -c 1 -H "Authorization: Bearer sk-mcp-bench-key" >/dev/null

    record_bench "mcp" "mcp_tools_list_warm" "Virtual 2-Server \`tools/list\` + ACL Tool Filtering (Warm Catalog)" \
        "shunt" "Shunt MCP (5-plugin)" \
        http --url "http://127.0.0.1:$GATEWAY_PORT/mcp" --method POST --body-preset mcp-tools-list \
        -c "$HTTP_CONCURRENCY" -d "$DURATION_SECS" --warmup-secs "$WARMUP_SECS" \
        -H "Authorization: Bearer sk-mcp-bench-key"

    record_bench "mcp" "mcp_tools_call_governed" "Governed \`tools/call\` (Auth + Route + SQL/Secret Guardrails + Limits)" \
        "shunt" "Shunt MCP (5-plugin)" \
        http --url "http://127.0.0.1:$GATEWAY_PORT/mcp" --method POST --body-preset mcp-tools-call \
        --cache-cardinality 0 -c "$HTTP_CONCURRENCY" -d "$DURATION_SECS" --warmup-secs "$WARMUP_SECS" \
        -H "Authorization: Bearer sk-mcp-bench-key"

    if [[ "$PROFILE" != "quick" ]]; then
        record_bench "mcp" "mcp_guardrails_sql_deny" "MCP Guardrails — Destructive SQL Argument Block (403 Pre-Upstream)" \
            "shunt" "Shunt MCP (5-plugin)" \
            http --url "http://127.0.0.1:$GATEWAY_PORT/mcp" --method POST --body-preset mcp-tools-call-sql-deny \
            --expect-status 403 -c "$HTTP_CONCURRENCY" -d "$DURATION_SECS" --warmup-secs "$WARMUP_SECS" \
            -H "Authorization: Bearer sk-mcp-bench-key"

        record_bench "mcp" "mcp_guardrails_indirect_pi" "MCP Guardrails — Inbound Indirect Prompt-Injection Block (JSON-RPC -32005)" \
            "shunt" "Shunt MCP (5-plugin)" \
            http --url "http://127.0.0.1:$GATEWAY_PORT/mcp" --method POST --body-preset mcp-tools-call-dirty \
            --cache-cardinality 0 --expect-status 200 -c "$HTTP_CONCURRENCY" -d "$DURATION_SECS" --warmup-secs "$WARMUP_SECS" \
            -H "Authorization: Bearer sk-mcp-bench-key"

        record_bench "mcp" "mcp_loop_breaker" "MCP Agent Loop Breaker — Identical-Call Rejection (429 Fast-Path)" \
            "shunt" "Shunt MCP (5-plugin)" \
            http --url "http://127.0.0.1:$GATEWAY_PORT/mcp" --method POST --body-preset mcp-tools-call-loop \
            --expect-status 429 -c "$HTTP_CONCURRENCY" -d "$DURATION_SECS" --warmup-secs "$WARMUP_SECS" \
            -H "Authorization: Bearer sk-mcp-bench-key"

        record_bench "mcp" "mcp_sse_stream" "MCP Streamable HTTP SSE \`tools/call\` (Governed)" \
            "shunt" "Shunt MCP (5-plugin)" \
            sse --url "http://127.0.0.1:$GATEWAY_PORT/mcp" --method POST --body-preset mcp-tools-call-sse \
            --cache-cardinality 0 --require-done false -c "$SSE_MED_CONCURRENCY" --waves 1 \
            -H "Authorization: Bearer sk-mcp-bench-key"
    fi

    stop_gw
fi

# ==============================================================================
# SUITE 4: STABILITY, HOT-RELOAD & MEMORY GUARDRAILS
# ==============================================================================
if suite_enabled "soak"; then
    echo "" >&2
    echo "==================== SUITE 4: SOAK & RELOAD ====================" >&2

    # 4.1 Live Hot-Reload Under Load (POST /reload every 500ms)
    wait_for_port_free "$ADMIN_PORT"
    start_gw "env RUST_LOG=error $SHUNT_BIN run --no-watch -c $CONFIG_DIR/api/shunt-reload.toml"
    record_bench "soak" "soak_reload_under_load" "3-Plugin HTTP Under Continuous \`POST /reload\` (every 500ms)" \
        "shunt" "Shunt (ArcSwap Reload)" \
        http --url "http://127.0.0.1:$GATEWAY_PORT/ping" -c "$HTTP_CONCURRENCY" -d "$DURATION_SECS" --warmup-secs "$WARMUP_SECS" \
        -H "Authorization: Bearer bench-secret-token" \
        --reload-url "http://127.0.0.1:$ADMIN_PORT/reload" --reload-interval-ms 500
    stop_gw

    # 4.2 Steady-State RSS Stability Guardrail (2 consecutive bursts on same governed AI PID)
    echo "==> [soak/soak_rss_stability] Shunt AI Governed Steady-State RSS Guardrail" >&2
    start_gw "env RUST_LOG=error $SHUNT_BIN run --no-watch -c $CONFIG_DIR/ai/shunt-governed.toml"
    soak_b1_json="$("$BENCH_BIN" http \
        --url "http://127.0.0.1:$GATEWAY_PORT/v1/chat/completions" \
        --method POST --body-preset ai-openai-small \
        -c "$HTTP_CONCURRENCY" -d "$DURATION_SECS" --warmup-secs "$WARMUP_SECS" \
        -H "Authorization: Bearer sk-bench-virtual-key" --json)"
    read -r rss_burst1 _ _ <<< "$(tree_stats "$GW_PID")"
    soak_b2_json="$("$BENCH_BIN" http \
        --url "http://127.0.0.1:$GATEWAY_PORT/v1/chat/completions" \
        --method POST --body-preset ai-anthropic-small \
        -c "$HTTP_CONCURRENCY" -d "$DURATION_SECS" --warmup-secs 0 \
        -H "Authorization: Bearer sk-bench-virtual-key" --json)"
    read -r rss_burst2 _ _ <<< "$(tree_stats "$GW_PID")"
    stop_gw

    python3 - "$soak_b1_json" "$soak_b2_json" "$rss_burst1" "$rss_burst2" <<'PY' >>"$RESULTS_JSONL"
import json, sys
b1 = json.loads(sys.argv[1])
b2 = json.loads(sys.argv[2])
r1 = float(sys.argv[3])
r2 = float(sys.argv[4])
row = {
    "suite": "soak",
    "workload": "rss_soak",
    "id": "soak_rss_stability",
    "label": "Shunt-AI 8-Plugin Governed (Burst 1 OpenAI -> Burst 2 Anthropic on same PID)",
    "gateway": "shunt",
    "gateway_label": "Shunt AI Governed (8-plugin)",
    "requests_burst1": int(b1["ok"]),
    "requests_burst2": int(b2["ok"]),
    "errors": int(b1["errors"]) + int(b2["errors"]),
    "rss_burst1_mb": r1,
    "rss_burst2_mb": r2,
    "rss_delta_mb": round(r2 - r1, 1),
}
print(json.dumps(row))
PY
fi

# ------------------------------------------------------------------------------
# Render Unified Markdown Report & Enforce Guardrails
# ------------------------------------------------------------------------------
RUN_UTC="$(date -u '+%Y-%m-%d %H:%M:%S UTC')"
GIT_SHA="$(git -C "$ROOT_DIR" rev-parse --short HEAD 2>/dev/null || echo unknown)"
GIT_FULL_SHA="$(git -C "$ROOT_DIR" rev-parse HEAD 2>/dev/null || echo unknown)"
RUST_VER="$(rustc --version 2>/dev/null || echo unknown)"
OS_INFO="$(uname -srm)"
if [[ "$(uname -s)" == "Darwin" ]]; then
    CPU_MODEL="$(sysctl -n machdep.cpu.brand_string 2>/dev/null || echo unknown)"
    CPU_CORES="$(sysctl -n hw.ncpu 2>/dev/null || echo unknown)"
else
    CPU_MODEL="$(LC_ALL=C lscpu 2>/dev/null | awk -F: '/^Model name:/{gsub(/^[ \t]+/, "", $2); print $2; exit}' || true)"
    if [[ -z "$CPU_MODEL" || "$CPU_MODEL" == "-" ]]; then
        CPU_MODEL="$(awk -F: '/model name/{gsub(/^[ \t]+/, "", $2); print $2; exit}' /proc/cpuinfo 2>/dev/null || true)"
    fi
    CPU_MODEL="${CPU_MODEL:-unknown}"
    CPU_CORES="$(nproc 2>/dev/null || echo unknown)"
fi

python3 - "$ENV_JSON" \
    "$RUN_UTC" "$GIT_SHA" "$GIT_FULL_SHA" "$RUST_VER" "$OS_INFO" "$CPU_MODEL" "$CPU_CORES" \
    "$PROFILE" "$SUITES" "$COMPETITORS" "$VERSIONS_STR" \
    "$DURATION_SECS" "$WARMUP_SECS" "$HTTP_CONCURRENCY" "$SSE_CONCURRENCY" "$SSE_MED_CONCURRENCY" \
    "$SSE_CHUNKS" "$SSE_INTERVAL_MS" "$MAX_RSS_GROWTH_MB" <<'PY'
import json, sys
from pathlib import Path
keys = [
    "run_utc", "git_sha", "git_full_sha", "rust_ver", "os_info", "cpu_model", "cpu_cores",
    "profile", "suites", "competitors", "versions",
    "duration_secs", "warmup_secs", "http_concurrency", "sse_concurrency", "sse_med_concurrency",
    "sse_chunks", "sse_interval_ms", "max_rss_growth_mb",
]
data = dict(zip(keys, sys.argv[2:]))
Path(sys.argv[1]).write_text(json.dumps(data, indent=2), encoding="utf-8")
PY

RENDER_ARGS=(--jsonl "$RESULTS_JSONL" --env-json "$ENV_JSON" --title "$REPORT_TITLE")
if [[ -n "$OUTPUT_MD" ]]; then
    RENDER_ARGS+=(--output-md "$OUTPUT_MD")
fi

python3 "$RENDER_PY" "${RENDER_ARGS[@]}"
