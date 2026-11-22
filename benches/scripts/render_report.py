#!/usr/bin/env python3
"""Render unified Shunt benchmark JSONL results into sectioned Markdown reports."""

import argparse
import json
import sys
from collections import OrderedDict
from pathlib import Path


def fmt_us(us: int) -> str:
    if us >= 1_000_000:
        return f"{us / 1_000_000.0:.2f} s"
    if us >= 1_000:
        return f"{us / 1_000.0:.2f} ms"
    return f"{us} µs"


def fmt_cpu(row: dict) -> str:
    val = row.get("cpu_ms_per_1k_req")
    if val is None or val <= 0:
        return "—"
    return f"{val:.1f} ms"


def fmt_rss(row: dict) -> str:
    rss = row.get("post_rss_mb")
    if rss is None:
        rss = row.get("rss_mb")
    if rss is None:
        return "—"
    procs = row.get("proc_count")
    if procs and int(procs) > 1:
        return f"{float(rss):.1f} MB ({int(procs)}p)"
    return f"{float(rss):.1f} MB"


def render_http_table(rows: list[dict], open_loop: bool = False) -> tuple[list[str], bool]:
    has_failure = False
    if not rows:
        return [], False

    if open_loop:
        lines = [
            "| Workload | Gateway | Target RPS | Achieved RPS | p50 | p99 | p99.9 | Max | CPU / 1k | RSS | Errors |",
            "| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |",
        ]
    else:
        lines = [
            "| Workload | Gateway | Throughput | p50 | p99 | p99.9 | CPU / 1k | RSS | Errors |",
            "| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |",
        ]

    # Preserve first-seen workload ID ordering so competitors sit right next to Shunt.
    grouped: OrderedDict[str, list[dict]] = OrderedDict()
    for r in rows:
        grouped.setdefault(r["id"], []).append(r)

    for _wid, group in grouped.items():
        for idx, r in enumerate(group):
            errs = int(r.get("errors", 0))
            if errs > 0:
                has_failure = True
            w_label = r["label"] if idx == 0 else "↳"
            gw_label = r.get("gateway_label", r.get("gateway", "Shunt"))
            if open_loop:
                target = int(r.get("target_rps", 0))
                lines.append(
                    f"| {w_label} | {gw_label} | {target:,} | **{r['rps']:,.1f} req/s** | "
                    f"{fmt_us(r['p50_us'])} | {fmt_us(r['p99_us'])} | {fmt_us(r.get('p999_us', r['p99_us']))} | "
                    f"{fmt_us(r['max_us'])} | {fmt_cpu(r)} | {fmt_rss(r)} | {errs} |"
                )
            else:
                lines.append(
                    f"| {w_label} | {gw_label} | **{r['rps']:,.1f} req/s** | "
                    f"{fmt_us(r['p50_us'])} | {fmt_us(r['p99_us'])} | {fmt_us(r.get('p999_us', r['p99_us']))} | "
                    f"{fmt_cpu(r)} | {fmt_rss(r)} | {errs} |"
                )
    return lines, has_failure


def render_single_wave_table(rows: list[dict]) -> tuple[list[str], bool]:
    has_failure = False
    if not rows:
        return [], False
    lines = [
        "| Workload | Gateway | Concurrency | Ok / Errors | p50 | p99 | Wall Time | RSS |",
        "| --- | --- | ---: | :---: | ---: | ---: | ---: | ---: |",
    ]
    for r in rows:
        errs = int(r.get("errors", 0))
        if errs > 0:
            has_failure = True
        gw_label = r.get("gateway_label", r.get("gateway", "Shunt"))
        lines.append(
            f"| {r['label']} | {gw_label} | {r['concurrency']} | **{r['ok']} / {errs}** | "
            f"{fmt_us(r['p50_us'])} | {fmt_us(r['p99_us'])} | {r['duration_s']:.3f}s | {fmt_rss(r)} |"
        )
    return lines, has_failure


def render_sse_table(rows: list[dict]) -> tuple[list[str], bool]:
    has_failure = False
    if not rows:
        return [], False
    lines = [
        "| Workload | Gateway | Concurrency | Completed / Failed | Chunks/s | TTFC p50 / p99 | Wall Time | RSS |",
        "| --- | --- | ---: | :---: | ---: | ---: | ---: | ---: |",
    ]
    grouped: OrderedDict[tuple[str, int], list[dict]] = OrderedDict()
    for r in rows:
        grouped.setdefault((r["id"], int(r["concurrency"])), []).append(r)

    for _key, group in grouped.items():
        for idx, r in enumerate(group):
            failed = int(r.get("failed", 0))
            if failed > 0:
                has_failure = True
            w_label = r["label"] if idx == 0 else "↳"
            gw_label = r.get("gateway_label", r.get("gateway", "Shunt"))
            wall_s = float(r["wall_s"])
            wall_str = f"{wall_s * 1000.0:.1f} ms" if wall_s < 0.1 else f"{wall_s:.2f}s"
            lines.append(
                f"| {w_label} | {gw_label} | {int(r['concurrency']):,} | "
                f"**{int(r['completed']):,} / {failed}** | {r['chunks_per_sec']:,.1f}/s | "
                f"{fmt_us(r['ttfc_p50_us'])} / {fmt_us(r['ttfc_p99_us'])} | "
                f"{wall_str} | {fmt_rss(r)} |"
            )
    return lines, has_failure


def main() -> None:
    parser = argparse.ArgumentParser(description="Render Shunt benchmark JSONL to Markdown.")
    parser.add_argument("--jsonl", required=True, help="Path to benchmark JSONL results")
    parser.add_argument("--env-json", required=True, help="Path to environment metadata JSON")
    parser.add_argument("--output-md", help="Optional path to write Markdown report")
    parser.add_argument("--title", default="Shunt Benchmark Report", help="Report H1 title")
    args = parser.parse_args()

    env = json.loads(Path(args.env_json).read_text(encoding="utf-8"))
    rows = [
        json.loads(line)
        for line in Path(args.jsonl).read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    max_rss_growth_mb = float(env.get("max_rss_growth_mb", 20.0))

    lines: list[str] = [
        f"# {args.title}",
        "",
        "> Automatically generated by `benches/scripts/bench.sh` + `benches/scripts/render_report.py` (RFC 0020).",
        "",
        "## Environment",
        "",
        "| Field | Value |",
        "| --- | --- |",
        f"| **Timestamp** | {env.get('run_utc', 'unknown')} |",
        f"| **Commit** | `{env.get('git_sha', 'unknown')}` (`{env.get('git_full_sha', 'unknown')}`) |",
        f"| **Profile / Suites** | `{env.get('profile', 'unknown')}` · suites: `{env.get('suites', 'all')}` · competitors: `{env.get('competitors', 'none')}` |",
        f"| **Toolchain** | `{env.get('rust_ver', 'unknown')}` |",
        f"| **OS / Kernel** | `{env.get('os_info', 'unknown')}` |",
        f"| **CPU** | {env.get('cpu_model', 'unknown')} ({env.get('cpu_cores', '?')} cores) |",
        f"| **HTTP Params** | `c={env.get('http_concurrency')}`, `duration={env.get('duration_secs')}s`, `warmup={env.get('warmup_secs')}s` |",
        f"| **SSE Params** | `c={env.get('sse_concurrency')}` (med `{env.get('sse_med_concurrency')}`), `chunks={env.get('sse_chunks')}`, `interval={env.get('sse_interval_ms')}ms` |",
    ]
    if env.get("versions"):
        lines.append(f"| **Gateway Versions** | {env['versions']} |")

    # Footprint & Cold Start summary (deduplicated per gateway_label)
    footprints: OrderedDict[str, dict] = OrderedDict()
    for r in rows:
        gw_label = r.get("gateway_label")
        if gw_label and "cold_start_ms" in r and gw_label not in footprints:
            footprints[gw_label] = r

    if footprints:
        lines += [
            "",
            "## Footprint & Cold Start",
            "",
            "| Gateway / Profile | Cold Start | Idle RSS | Processes |",
            "| --- | ---: | ---: | ---: |",
        ]
        for gw_label, r in footprints.items():
            idle_rss = r.get("idle_rss_mb")
            idle_str = f"{float(idle_rss):.1f} MB" if idle_rss is not None else "—"
            procs = int(r.get("idle_proc_count", r.get("proc_count", 1)))
            lines.append(
                f"| {gw_label} | **{int(r['cold_start_ms']):,} ms** | {idle_str} | {procs} |"
            )

    has_failure = False

    # 1. API Gateway Suite
    api_rows = [r for r in rows if r.get("suite") == "api"]
    if api_rows:
        lines += ["", "## 1. API Gateway Suite"]
        api_http = [
            r for r in api_rows if r.get("workload") == "http" and r.get("mode") != "open_loop"
        ]
        api_open = [
            r for r in api_rows if r.get("workload") == "http" and r.get("mode") == "open_loop"
        ]
        api_sse = [r for r in api_rows if r.get("workload") == "sse"]

        if api_http:
            lines += ["", "### HTTP Throughput & Latency", ""]
            tbl, fail = render_http_table(api_http, open_loop=False)
            lines += tbl
            has_failure = has_failure or fail

        if api_open:
            lines += ["", "### Open-Loop Tail Latency (Coordinated-Omission Free)", ""]
            tbl, fail = render_http_table(api_open, open_loop=True)
            lines += tbl
            has_failure = has_failure or fail

        if api_sse:
            lines += ["", "### High-Concurrency SSE Passthrough", ""]
            tbl, fail = render_sse_table(api_sse)
            lines += tbl
            has_failure = has_failure or fail

    # 2. AI Gateway Suite
    ai_rows = [r for r in rows if r.get("suite") == "ai"]
    if ai_rows:
        lines += ["", "## 2. AI Gateway Suite"]
        ai_http = [
            r
            for r in ai_rows
            if r.get("workload") == "http" and r.get("mode") not in ("single_wave", "open_loop")
        ]
        ai_wave = [
            r for r in ai_rows if r.get("workload") == "http" and r.get("mode") == "single_wave"
        ]
        ai_sse = [r for r in ai_rows if r.get("workload") == "sse"]

        if ai_http:
            lines += [
                "",
                "### Non-Streaming Chat, Translation, Guardrails, Cache, Multi-Protocol & Failover",
                "",
            ]
            tbl, fail = render_http_table(ai_http, open_loop=False)
            lines += tbl
            has_failure = has_failure or fail

        if ai_wave:
            lines += ["", "### Singleflight Thundering-Herd Coalescing", ""]
            tbl, fail = render_single_wave_table(ai_wave)
            lines += tbl
            has_failure = has_failure or fail

        if ai_sse:
            lines += ["", "### High-Concurrency AI SSE Streaming", ""]
            tbl, fail = render_sse_table(ai_sse)
            lines += tbl
            has_failure = has_failure or fail

    # 3. MCP & Agentic Gateway Suite
    mcp_rows = [r for r in rows if r.get("suite") == "mcp"]
    if mcp_rows:
        lines += ["", "## 3. MCP & Agentic Gateway Suite"]
        mcp_http = [r for r in mcp_rows if r.get("workload") == "http"]
        mcp_sse = [r for r in mcp_rows if r.get("workload") == "sse"]

        if mcp_http:
            lines += ["", "### JSON-RPC 2.0 Governance & Guardrails", ""]
            tbl, fail = render_http_table(mcp_http, open_loop=False)
            lines += tbl
            has_failure = has_failure or fail

        if mcp_sse:
            lines += ["", "### Streamable HTTP SSE Tool Calls", ""]
            tbl, fail = render_sse_table(mcp_sse)
            lines += tbl
            has_failure = has_failure or fail

    # 4. Stability, Hot-Reload & Memory Guardrails
    soak_rows = [r for r in rows if r.get("suite") == "soak"]
    if soak_rows:
        lines += ["", "## 4. Stability, Hot-Reload & Memory Guardrails"]
        reload_rows = [r for r in soak_rows if r.get("workload") == "reload"]
        rss_rows = [r for r in soak_rows if r.get("workload") == "rss_soak"]

        if reload_rows:
            lines += [
                "",
                "### Live Hot-Reload Under Load (`POST /reload`)",
                "",
                "| Workload | Throughput | p50 | p99 | Reloads Ok / Fail | Request Errors | RSS | Status |",
                "| --- | ---: | ---: | ---: | :---: | ---: | ---: | :---: |",
            ]
            for r in reload_rows:
                errs = int(r.get("errors", 0))
                r_ok = int(r.get("reloads_ok", 0))
                r_fail = int(r.get("reloads_failed", 0))
                passed = errs == 0 and r_fail == 0 and r_ok > 0
                if not passed:
                    has_failure = True
                status = "PASS" if passed else "FAIL"
                lines.append(
                    f"| {r['label']} | **{r['rps']:,.1f} req/s** | {fmt_us(r['p50_us'])} | "
                    f"{fmt_us(r['p99_us'])} | {r_ok} / {r_fail} | {errs} | {fmt_rss(r)} | **{status}** |"
                )

        if rss_rows:
            lines += [
                "",
                f"### Steady-State Memory Stability (Guardrail: delta <= {max_rss_growth_mb:.1f} MB)",
                "",
                "| Workload | Burst 1 Reqs / RSS | Burst 2 Reqs / RSS | RSS Delta | Status |",
                "| --- | ---: | ---: | ---: | :---: |",
            ]
            for r in rss_rows:
                errs = int(r.get("errors", 0))
                delta = float(r["rss_delta_mb"])
                passed = errs == 0 and delta <= max_rss_growth_mb
                if not passed:
                    has_failure = True
                status = "PASS" if passed else "FAIL"
                lines.append(
                    f"| {r['label']} | {int(r['requests_burst1']):,} / {float(r['rss_burst1_mb']):.1f} MB | "
                    f"{int(r['requests_burst2']):,} / {float(r['rss_burst2_mb']):.1f} MB | "
                    f"{delta:+.1f} MB | **{status}** |"
                )

    lines.append("")
    report = "\n".join(lines)

    if args.output_md:
        out_path = Path(args.output_md)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(report, encoding="utf-8")

    print(report)

    if has_failure:
        print(
            "error: one or more benchmark workloads or stability guardrails failed!",
            file=sys.stderr,
        )
        sys.exit(1)


if __name__ == "__main__":
    main()
