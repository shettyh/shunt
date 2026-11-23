---
title: Observability & Inspector UI
description: Monitor Shunt with the built-in read-only Admin Inspector UI, live µs waterfalls, Prometheus metrics, and zero-dependency OTLP/HTTP GenAI traces.
---

Shunt gives you deep visibility out of the box without databases, external agents, or hot-path overhead.

## 1. Read-Only Admin Inspector Web UI (`--ui`)

Enable the embedded Inspector UI with `--ui` or `[admin] ui = true`:

```bash
shunt dev --ui -c shunt.toml
# or in production:
shunt run --ui -c shunt.toml
```

Open **`http://127.0.0.1:9090/ui`** in your browser to inspect:
- **Live Trace Waterfalls (SSE):** Per-request, per-hook microsecond timing breakdowns streamed from `/api/traces/stream` (backed by a bounded in-memory ring buffer).
- **Compiled Snapshot Graph:** Active routes, attached plugins, and exact `HookMask` bitmasks with all secrets automatically redacted.
- **Upstream Health:** Per-endpoint weights, active HTTP/TCP probe status, and passive circuit ejection state.
- **AI & MCP Runtime Diagnostics:** Live token usage, spend, provider cooldowns, cache hit rates, and MCP catalog/session/guardrail stats from `/api/status`.

:::note[Strictly Read-Only & Isolated]
The Inspector UI never mutates config and always binds to `[admin]` (`127.0.0.1:9090` by default)—never the public proxy listener. When `--ui` is off, zero trace capture hooks are attached.
:::

## 2. Live Terminal Waterfalls (`shunt dev`)

Running `shunt dev -c shunt.toml` automatically attaches `dev-waterfall`, printing per-hook microsecond timings to `stderr` for every request so you can immediately spot slow upstreams or plugins during local development.

## 3. Prometheus Metrics (`GET /metrics`)

Attach the global `metrics` plugin and scrape `http://127.0.0.1:9090/metrics`:

- **HTTP Gateway:** Request counters, status classes, latency histograms, upstream active/passive health gauges, traffic mirror counters.
- **AI Gateway (`shunt_ai_*`):** Prompt/cached/reasoning/completion tokens, TTFT histograms, nano-USD cost (`shunt_ai_cost_usd_total`), cache hits/misses, failover attempts, guardrail triggers.
- **MCP Gateway (`shunt_mcp_*`):** JSON-RPC calls by method/server/tool, ACL denials, guardrail blocks, loop-breaker rejections, active sessions.
- **OTLP Exporter:** Exported batches, dropped spans, export errors.

## 4. Zero-Dependency OTLP/HTTP Tracing

Configure `[telemetry]` and attach `otel-trace` to export standard W3C traces (`traceparent`/`tracestate`) with **OpenTelemetry GenAI** (`gen_ai.*`) and **MCP** (`mcp.*`) semantic attributes directly over OTLP/HTTP JSON—compatible with **Jaeger**, **Grafana Tempo**, **Langfuse**, **Arize Phoenix**, **Datadog**, and **Honeycomb**:

```toml
[telemetry]
enabled = true
backend = "otlp_http"
endpoint = "http://127.0.0.1:4318/v1/traces"
service_name = "shunt-ai-gateway"
resource_attributes = { "deployment.environment" = "prod" }
headers = { Authorization = "env:OTLP_AUTH_HEADER" }

[[plugins]]
name = "otel-trace"
[plugins.config]
sample_rate = 1.0
respect_parent_sampling = true
propagate_headers = true
emit_response_header = true
```

Exporting happens on a dedicated background task with a bounded queue (`queue_capacity = 4096`), so a slow or unreachable collector **never blocks** live proxy traffic.
