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
MAX_RSS_GROWTH_MB="${MAX_RSS_GROWTH_MB:-20.0}"

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

# Deterministic HS256 JWT (iss=https://bench.shunt.dev, aud=shunt-api, scope="read write", exp=2100)
BENCH_JWT="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImJlbmNoLWhzMSJ9.eyJpc3MiOiJodHRwczovL2JlbmNoLnNodW50LmRldiIsImF1ZCI6InNodW50LWFwaSIsInN1YiI6ImJlbmNoLXVzZXIiLCJzY29wZSI6InJlYWQgd3JpdGUiLCJvcmciOnsiaWQiOiJhY21lIn0sImV4cCI6NDEwMjQ0NDgwMH0.oNwB3NTg0O9xnqR3IhQ9CqJfbgpiN597a1vthqYA7G0"

run_case \
    "security_jwt_http" \
    "Shunt JWT & Security Chain (\`ip-filter\` + \`jwt-auth\` HS256 + \`body-limit\`)" \
    "$CONFIG_DIR/shunt-security-compression.toml" \
    http \
    --url "http://127.0.0.1:$GATEWAY_PORT/ping" \
    -c "$HTTP_CONCURRENCY" \
    -d "$DURATION_SECS" \
    --warmup-secs "$WARMUP_SECS" \
    -H "Authorization: Bearer $BENCH_JWT"

run_case \
    "security_jwt_zstd_http" \
    "Shunt JWT + Security + Streaming \`zstd\` (~4KB JSON)" \
    "$CONFIG_DIR/shunt-security-compression.toml" \
    http \
    --url "http://127.0.0.1:$GATEWAY_PORT/json" \
    -c "$HTTP_CONCURRENCY" \
    -d "$DURATION_SECS" \
    --warmup-secs "$WARMUP_SECS" \
    -H "Authorization: Bearer $BENCH_JWT" \
    -H "Accept-Encoding: zstd"

run_case \
    "ai_json_translate" \
    "Shunt-AI Non-Streaming Translate (\`Anthropic <-> OpenAI\` + usage)" \
    "$CONFIG_DIR/shunt-ai-bench.toml" \
    http \
    --url "http://127.0.0.1:$GATEWAY_PORT/v1/chat/completions" \
    --method POST \
    --body '{"model":"claude-bench","stream":false,"messages":[{"role":"user","content":"hi"}]}' \
    -c "$HTTP_CONCURRENCY" \
    -d "$DURATION_SECS" \
    --warmup-secs "$WARMUP_SECS"

run_case \
    "ai_governed_json" \
    "Shunt-AI 8-Plugin Governed Chain (\`vkeys\` + \`router\` + \`rpm/tpm\` + \`budget\` + \`adapter\` + \`failover\` + \`usage\`)" \
    "$CONFIG_DIR/shunt-ai-governed.toml" \
    http \
    --url "http://127.0.0.1:$GATEWAY_PORT/v1/chat/completions" \
    --method POST \
    --body '{"model":"gpt-bench","stream":false,"messages":[{"role":"user","content":"hi"}]}' \
    -c "$HTTP_CONCURRENCY" \
    -d "$DURATION_SECS" \
    --warmup-secs "$WARMUP_SECS" \
    -H "Authorization: Bearer sk-bench-virtual-key"

run_case \
    "ai_guardrails_json" \
    "Shunt-AI Inline Guardrails (\`pii\` + \`secrets\` + \`prompt_injection\` + regex/keywords)" \
    "$CONFIG_DIR/shunt-ai-guardrails.toml" \
    http \
    --url "http://127.0.0.1:$GATEWAY_PORT/v1/chat/completions" \
    --method POST \
    --body '{"model":"gpt-bench","stream":false,"messages":[{"role":"user","content":"hi"}]}' \
    -c "$HTTP_CONCURRENCY" \
    -d "$DURATION_SECS" \
    --warmup-secs "$WARMUP_SECS"

run_case \
    "ai_cache_hit_json" \
    "Shunt-AI Exact-Match Cache Hit (\`ai-cache\`, zero upstream I/O)" \
    "$CONFIG_DIR/shunt-ai-cache.toml" \
    http \
    --url "http://127.0.0.1:$GATEWAY_PORT/v1/chat/completions" \
    --method POST \
    --body '{"model":"gpt-bench","temperature":0,"stream":false,"messages":[{"role":"user","content":"hi"}]}' \
    -c "$HTTP_CONCURRENCY" \
    -d "$DURATION_SECS" \
    --warmup-secs "$WARMUP_SECS" \
    -H "Authorization: Bearer sk-bench-virtual-key"

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

run_case \
    "sse_ai_guardrails" \
    "Shunt-AI Guardrailed SSE (\`Anthropic -> OpenAI\` + streaming holdback PII/secrets scan)" \
    "$CONFIG_DIR/shunt-ai-guardrails.toml" \
    sse \
    --url "http://127.0.0.1:$GATEWAY_PORT/v1/chat/completions" \
    -c "$SSE_CONCURRENCY" \
    --waves 1 \
    --method POST \
    --body '{"model":"claude-bench","stream":true,"messages":[{"role":"user","content":"hi"}]}'

# Primed streaming SSE cache replay workload.
echo "==> Running [sse_ai_cache_hit] Shunt-AI Streaming SSE Cache Replay Hit..." >&2
wait_for_port_free "$GATEWAY_PORT"
: >"$GW_LOG"
RUST_LOG=error "$SHUNT_BIN" run --no-watch -c "$CONFIG_DIR/shunt-ai-cache.toml" >"$GW_LOG" 2>&1 &
GW_PID=$!
wait_for_port_and_pid "$GATEWAY_PORT" "$GW_PID" "$GW_LOG"
"$BENCH_BIN" sse \
    --url "http://127.0.0.1:$GATEWAY_PORT/v1/chat/completions" \
    -c 1 --waves 1 --method POST \
    --body '{"model":"claude-bench","temperature":0,"stream":true,"messages":[{"role":"user","content":"hi"}]}' \
    -H "Authorization: Bearer sk-bench-virtual-key" >/dev/null
raw_json="$("$BENCH_BIN" sse \
    --url "http://127.0.0.1:$GATEWAY_PORT/v1/chat/completions" \
    -c "$SSE_CONCURRENCY" --waves 1 --method POST \
    --body '{"model":"claude-bench","temperature":0,"stream":true,"messages":[{"role":"user","content":"hi"}]}' \
    -H "Authorization: Bearer sk-bench-virtual-key" --json)"
rss="$(rss_mb "$GW_PID")"
stop_gw
python3 -c '
import json, sys
row = json.loads(sys.argv[1])
row["id"] = sys.argv[2]
row["label"] = sys.argv[3]
row["rss_mb"] = float(sys.argv[4])
print(json.dumps(row))
' "$raw_json" "sse_ai_cache_hit" "Shunt-AI Streaming SSE Cache Replay Hit (\`ai-cache\`, zero upstream I/O)" "$rss" >>"$RESULTS_JSONL"

# Steady-state memory growth soak check: run two consecutive identical bursts on the SAME
# 8-plugin governed Shunt process and verify post-warmup RSS delta stays bounded.
echo "==> Running [rss_soak] Shunt-AI Governed Steady-State RSS Guardrail..." >&2
wait_for_port_free "$GATEWAY_PORT"
: >"$GW_LOG"
RUST_LOG=error "$SHUNT_BIN" run --no-watch -c "$CONFIG_DIR/shunt-ai-governed.toml" >"$GW_LOG" 2>&1 &
GW_PID=$!
wait_for_port_and_pid "$GATEWAY_PORT" "$GW_PID" "$GW_LOG"
soak_b1_json="$("$BENCH_BIN" http \
    --url "http://127.0.0.1:$GATEWAY_PORT/v1/chat/completions" \
    --method POST \
    --body '{"model":"gpt-bench","stream":false,"messages":[{"role":"user","content":"hi"}]}' \
    -c "$HTTP_CONCURRENCY" -d "$DURATION_SECS" --warmup-secs "$WARMUP_SECS" \
    -H "Authorization: Bearer sk-bench-virtual-key" --json)"
rss_burst1="$(rss_mb "$GW_PID")"
soak_b2_json="$("$BENCH_BIN" http \
    --url "http://127.0.0.1:$GATEWAY_PORT/v1/chat/completions" \
    --method POST \
    --body '{"model":"claude-bench","stream":false,"messages":[{"role":"user","content":"hi"}]}' \
    -c "$HTTP_CONCURRENCY" -d "$DURATION_SECS" --warmup-secs 0 \
    -H "Authorization: Bearer sk-bench-virtual-key" --json)"
rss_burst2="$(rss_mb "$GW_PID")"
stop_gw
python3 -c '
import json, sys
b1 = json.loads(sys.argv[1])
b2 = json.loads(sys.argv[2])
r1 = float(sys.argv[3])
r2 = float(sys.argv[4])
row = {
    "workload": "rss_soak",
    "id": "ai_governed_rss_soak",
    "label": "Shunt-AI 8-Plugin Governed (Burst 1 OpenAI -> Burst 2 Anthropic on same PID)",
    "requests_burst1": int(b1["ok"]),
    "requests_burst2": int(b2["ok"]),
    "errors": int(b1["errors"]) + int(b2["errors"]),
    "rss_burst1_mb": r1,
    "rss_burst2_mb": r2,
    "rss_delta_mb": round(r2 - r1, 1),
}
print(json.dumps(row))
' "$soak_b1_json" "$soak_b2_json" "$rss_burst1" "$rss_burst2" >>"$RESULTS_JSONL"

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
    "$DURATION_SECS" "$WARMUP_SECS" "$HTTP_CONCURRENCY" "$SSE_CONCURRENCY" "$SSE_CHUNKS" "$SSE_INTERVAL_MS" "$MAX_RSS_GROWTH_MB" <<'PY'
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
    max_rss_growth_mb_s,
) = sys.argv[1:]

max_rss_growth_mb = float(max_rss_growth_mb_s)
rows = [json.loads(line) for line in Path(jsonl_path).read_text().splitlines() if line.strip()]
http_rows = [r for r in rows if r["workload"] == "http"]
sse_rows = [r for r in rows if r["workload"] == "sse"]
soak_rows = [r for r in rows if r["workload"] == "rss_soak"]

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

if soak_rows:
    lines += [
        "",
        f"## Memory Stability (Steady-State RSS Guardrail: delta <= {max_rss_growth_mb:.1f} MB)",
        "",
        "| Workload | Burst 1 Reqs / RSS | Burst 2 Reqs / RSS | RSS Delta | Status |",
        "| --- | ---: | ---: | ---: | :---: |",
    ]
    for r in soak_rows:
        errs = int(r["errors"])
        delta = float(r["rss_delta_mb"])
        passed = errs == 0 and delta <= max_rss_growth_mb
        if not passed:
            has_failure = True
        status = "PASS" if passed else "FAIL"
        lines.append(
            f"| {r['label']} | {r['requests_burst1']:,} / {r['rss_burst1_mb']:.1f} MB | "
            f"{r['requests_burst2']:,} / {r['rss_burst2_mb']:.1f} MB | "
            f"{delta:+.1f} MB | **{status}** |"
        )

lines.append("")
report = "\n".join(lines)
Path(output_path).write_text(report, encoding="utf-8")
print(report)

if has_failure:
    print("error: one or more benchmark workloads or RSS stability checks failed!", file=sys.stderr)
    sys.exit(1)
PY
