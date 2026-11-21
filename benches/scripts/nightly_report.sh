#!/usr/bin/env bash
set -euo pipefail

# Nightly / CI benchmark report generator for Shunt.
# Runs all 4 Shunt workloads via `shunt-bench --json` and writes a formatted
# Markdown report suitable for $GITHUB_STEP_SUMMARY and automated PR updates.

ulimit -n 16384 2>/dev/null || ulimit -n 8192 2>/dev/null || true

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
CONFIG_DIR="$ROOT_DIR/benches/configs"
OUTPUT_FILE="${OUTPUT_FILE:-$ROOT_DIR/benches/results/nightly.md}"

DURATION_SECS="${DURATION_SECS:-6}"
WARMUP_SECS="${WARMUP_SECS:-2}"
HTTP_CONCURRENCY="${HTTP_CONCURRENCY:-64}"
SSE_CONCURRENCY="${SSE_CONCURRENCY:-500}"
SSE_CHUNKS="${SSE_CHUNKS:-20}"
SSE_INTERVAL_MS="${SSE_INTERVAL_MS:-25}"

UPSTREAM_PORT="${UPSTREAM_PORT:-18080}"
GATEWAY_PORT="${GATEWAY_PORT:-18081}"

echo "==> Building shunt and shunt-bench (release)..." >&2
(cd "$ROOT_DIR" && cargo build --release --locked -p shunt-cli -p shunt-bench >&2)

SHUNT_BIN="$ROOT_DIR/target/release/shunt"
BENCH_BIN="$ROOT_DIR/target/release/shunt-bench"

UPSTREAM_PID=""
GW_PID=""
TMP_DIR="$(mktemp -d)"

cleanup() {
    if [[ -n "$GW_PID" ]]; then
        kill "$GW_PID" 2>/dev/null || true
        wait "$GW_PID" 2>/dev/null || true
    fi
    if [[ -n "$UPSTREAM_PID" ]]; then
        kill "$UPSTREAM_PID" 2>/dev/null || true
        wait "$UPSTREAM_PID" 2>/dev/null || true
    fi
    rm -rf "$TMP_DIR"
}
trap cleanup EXIT

wait_for_port_and_pid() {
    local port="$1"
    local pid="$2"
    local logfile="$3"
    for _ in $(seq 1 100); do
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
    awk -v kb="${kb:-0}" 'BEGIN { printf "%.1f", kb / 1024.0 }'
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

UPSTREAM_LOG="$TMP_DIR/upstream.log"
GW_LOG="$TMP_DIR/gw.log"
RESULTS_JSONL="$TMP_DIR/results.jsonl"
: >"$RESULTS_JSONL"

echo "==> Starting mock upstream on 127.0.0.1:$UPSTREAM_PORT..." >&2
"$BENCH_BIN" upstream \
    --listen "127.0.0.1:$UPSTREAM_PORT" \
    --payload-bytes 256 \
    --sse-chunks "$SSE_CHUNKS" \
    --sse-interval-ms "$SSE_INTERVAL_MS" >"$UPSTREAM_LOG" 2>&1 &
UPSTREAM_PID=$!
wait_for_port_and_pid "$UPSTREAM_PORT" "$UPSTREAM_PID" "$UPSTREAM_LOG"

run_case() {
    local id="$1"
    local label="$2"
    local cfg="$3"
    shift 3

    echo "==> Running [$id] $label..." >&2
    wait_for_port_free "$GATEWAY_PORT"
    : >"$GW_LOG"
    RUST_LOG=error "$SHUNT_BIN" run --no-watch -c "$cfg" >"$GW_LOG" 2>&1 &
    GW_PID=$!
    wait_for_port_and_pid "$GATEWAY_PORT" "$GW_PID" "$GW_LOG"

    local raw_json
    raw_json="$("$BENCH_BIN" "$@" --json)"
    local rss
    rss="$(rss_mb "$GW_PID")"
    stop_gw

    python3 -c '
import json, sys
row = json.loads(sys.argv[1])
row["id"] = sys.argv[2]
row["label"] = sys.argv[3]
row["rss_mb"] = float(sys.argv[4])
print(json.dumps(row))
' "$raw_json" "$id" "$label" "$rss" >>"$RESULTS_JSONL"
}

run_case \
    "raw_http" \
    "Shunt Raw Passthrough (\`HookMask::EMPTY\`)" \
    "$CONFIG_DIR/shunt-raw.toml" \
    http \
    --url "http://127.0.0.1:$GATEWAY_PORT/ping" \
    -c "$HTTP_CONCURRENCY" \
    -d "$DURATION_SECS" \
    --warmup-secs "$WARMUP_SECS"

run_case \
    "plugins_http" \
    "Shunt 3-Plugin Chain (\`request-id\` + \`bearer-auth\` + \`rate-limit\`)" \
    "$CONFIG_DIR/shunt-plugins.toml" \
    http \
    --url "http://127.0.0.1:$GATEWAY_PORT/ping" \
    -c "$HTTP_CONCURRENCY" \
    -d "$DURATION_SECS" \
    --warmup-secs "$WARMUP_SECS" \
    -H "Authorization: Bearer bench-secret-token"

run_case \
    "sse_passthrough" \
    "Shunt SSE Passthrough" \
    "$CONFIG_DIR/shunt-sse.toml" \
    sse \
    --url "http://127.0.0.1:$GATEWAY_PORT/sse" \
    -c "$SSE_CONCURRENCY" \
    --waves 1 \
    --method GET

run_case \
    "sse_ai_translate" \
    "Shunt-AI Live SSE Translate (\`Anthropic -> OpenAI\` + usage)" \
    "$CONFIG_DIR/shunt-sse-translate.toml" \
    sse \
    --url "http://127.0.0.1:$GATEWAY_PORT/v1/chat/completions" \
    -c "$SSE_CONCURRENCY" \
    --waves 1 \
    --method POST \
    --body '{"model":"claude-bench","stream":true,"messages":[{"role":"user","content":"hi"}]}'

# Collect host / runner environment metadata.
RUN_UTC="$(date -u '+%Y-%m-%d %H:%M:%S UTC')"
GIT_SHA="$(git -C "$ROOT_DIR" rev-parse --short HEAD 2>/dev/null || echo unknown)"
GIT_FULL_SHA="$(git -C "$ROOT_DIR" rev-parse HEAD 2>/dev/null || echo unknown)"
RUST_VER="$(rustc --version 2>/dev/null || echo unknown)"
OS_INFO="$(uname -srm)"
if [[ "$(uname -s)" == "Darwin" ]]; then
    CPU_MODEL="$(sysctl -n machdep.cpu.brand_string 2>/dev/null || echo unknown)"
    CPU_CORES="$(sysctl -n hw.ncpu 2>/dev/null || echo unknown)"
else
    CPU_MODEL="$(awk -F: '/model name/{gsub(/^[ \t]+/, "", $2); print $2; exit}' /proc/cpuinfo 2>/dev/null || echo unknown)"
    CPU_CORES="$(nproc 2>/dev/null || echo unknown)"
fi

mkdir -p "$(dirname "$OUTPUT_FILE")"

python3 - "$RESULTS_JSONL" "$OUTPUT_FILE" \
    "$RUN_UTC" "$GIT_SHA" "$GIT_FULL_SHA" "$RUST_VER" "$OS_INFO" "$CPU_MODEL" "$CPU_CORES" \
    "$DURATION_SECS" "$WARMUP_SECS" "$HTTP_CONCURRENCY" "$SSE_CONCURRENCY" "$SSE_CHUNKS" "$SSE_INTERVAL_MS" <<'PY'
import json
import sys
from pathlib import Path

(
    jsonl_path,
    output_path,
    run_utc,
    git_sha,
    git_full_sha,
    rust_ver,
    os_info,
    cpu_model,
    cpu_cores,
    duration_secs,
    warmup_secs,
    http_c,
    sse_c,
    sse_chunks,
    sse_interval_ms,
) = sys.argv[1:]

rows = [json.loads(line) for line in Path(jsonl_path).read_text().splitlines() if line.strip()]
http_rows = [r for r in rows if r["workload"] == "http"]
sse_rows = [r for r in rows if r["workload"] == "sse"]

def fmt_us(us: int) -> str:
    if us >= 1000:
        return f"{us / 1000.0:.2f} ms"
    return f"{us} µs"

lines = [
    "# Shunt Nightly Benchmark Report",
    "",
    "> Automatically generated by `benches/scripts/nightly_report.sh` via the Nightly Benchmarks workflow.",
    "",
    "## Environment",
    "",
    "| Field | Value |",
    "| --- | --- |",
    f"| **Timestamp** | {run_utc} |",
    f"| **Commit** | `{git_sha}` (`{git_full_sha}`) |",
    f"| **Toolchain** | `{rust_ver}` |",
    f"| **OS / Kernel** | `{os_info}` |",
    f"| **CPU** | {cpu_model} ({cpu_cores} cores) |",
    f"| **HTTP Params** | `c={http_c}`, `duration={duration_secs}s`, `warmup={warmup_secs}s` |",
    f"| **SSE Params** | `c={sse_c}`, `chunks={sse_chunks}`, `interval={sse_interval_ms}ms` |",
    "",
    "## HTTP/1.1 Workloads",
    "",
    "| Workload | Throughput | p50 | p95 | p99 | Max | Post-Run RSS | Errors |",
    "| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |",
]

has_failure = False
for r in http_rows:
    errs = int(r["errors"])
    if errs > 0:
        has_failure = True
    lines.append(
        f"| {r['label']} | **{r['rps']:,.1f} req/s** | {fmt_us(r['p50_us'])} | "
        f"{fmt_us(r['p95_us'])} | {fmt_us(r['p99_us'])} | {fmt_us(r['max_us'])} | "
        f"{r['rss_mb']:.1f} MB | {errs} |"
    )

lines += [
    "",
    "## High-Concurrency SSE Streaming Workloads",
    "",
    "| Workload | Completed / Failed | Chunks/s | TTFC p50 / p99 | Duration p50 / p99 | Wall Time | Post-Run RSS |",
    "| --- | :---: | ---: | ---: | ---: | ---: | ---: |",
]

for r in sse_rows:
    failed = int(r["failed"])
    if failed > 0:
        has_failure = True
    lines.append(
        f"| {r['label']} | **{r['completed']} / {failed}** | {r['chunks_per_sec']:,.1f}/s | "
        f"{fmt_us(r['ttfc_p50_us'])} / {fmt_us(r['ttfc_p99_us'])} | "
        f"{fmt_us(r['dur_p50_us'])} / {fmt_us(r['dur_p99_us'])} | "
        f"{r['wall_s']:.2f}s | {r['rss_mb']:.1f} MB |"
    )

lines.append("")
report = "\n".join(lines)
Path(output_path).write_text(report, encoding="utf-8")
print(report)

if has_failure:
    print("error: one or more benchmark workloads reported errors/failed streams!", file=sys.stderr)
    sys.exit(1)
PY
