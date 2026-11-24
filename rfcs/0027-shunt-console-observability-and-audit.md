# RFC 0027: `shunt-console` — Unified Fleet Observability, Trace Explorer & Audit Center

- **Status:** Draft
- **Crates / Directories:** `console/crates/shunt-console-core`, `console/crates/shunt-console-api`, `console/web`, `shunt-config`
- **Depends On:** [RFC 0023](./0023-shunt-console-architecture-and-control-plane.md), [RFC 0011](./0011-otlp-observability-and-ai-cache.md), [RFC 0012](./0012-admin-inspector-ui.md), [RFC 0015](./0015-guardrails-audit-and-webhooks.md)

## 1. Summary

This RFC specifies **Pillar E (Unified Fleet Observability, Trace Explorer & Audit Center)** of `shunt-console`. It graduates Shunt's single-node in-memory Admin Inspector UI ([RFC 0012](./0012-admin-inspector-ui.md)) into a **fleet-wide, persistent, cross-pillar observability and compliance hub** spanning HTTP API, AI Gateway, and MCP Agentic traffic—without adding a single custom telemetry protocol to `shunt-engine`.

`shunt-console` embeds native **OTLP/HTTP JSON (`/ingest/v1/traces`)** and **Structured Audit (`/ingest/v1/audit`)** receivers, stores bounded recent traces + pre-aggregated metrics rollups in SQLite/Postgres out of the box, supports **optional ClickHouse / upstream OTLP forwarding** for high-volume fleets, correlates multi-step **AI + MCP agent sessions** via W3C `traceparent`, and maintains a **hash-chained immutable Admin Audit Log** with SIEM export.

## 2. Motivation

During production incidents, security audits, or agent debugging, teams running multi-node Shunt fleets hit four visibility limits when relying solely on per-node `--ui` or disconnected tools:
1. **Single-node ephemeral visibility:** Layer 1's `TraceRingBuffer` holds 256–10,000 recent requests per node in memory; once evicted or spread across 10 replicas, debugging a customer's failed request requires hunting across nodes.
2. **Fragmented AI + MCP agent timelines:** A single autonomous agent run makes 6 LLM calls through `shunt-ai` and 14 tool calls through `shunt-mcp`. Seeing both in one correlated waterfall with per-hook µs timings, guardrail actions, and cumulative cost is essential for debugging agent latency and runaway spend.
3. **Compliance & security auditability:** Enterprise security teams require searchable, retention-controlled logs of every PII redaction, prompt-injection block, MCP tool approval, and control-plane mutation (who published Revision #42, who revoked key `vk_...`, who lifted a kill-switch).
4. **Coexistence with existing observability stacks:** Larger teams already run Grafana/Tempo/Jaeger/Langfuse/Datadog and want `shunt-console` to complement—not trap—their OTLP telemetry.

## 3. Goals & Non-Goals

### Goals
- **Zero new data-plane telemetry protocols:** Reuse Shunt's existing non-blocking `otel-trace` OTLP/HTTP JSON exporter ([RFC 0011](./0011-otlp-observability-and-ai-cache.md)), `ai-audit` webhook sink ([RFC 0015](./0015-guardrails-audit-and-webhooks.md)), and `mcp-telemetry` structured audit events.
- **Batteries-included default + scale-out escape hatch:** Works zero-config with SQLite/Postgres (bounded retention + automatic TTL pruning + hourly/daily rollups), with pluggable **ClickHouse** storage and **OTLP Tee/Forwarding** to external collectors (Langfuse, Arize Phoenix, Jaeger, Tempo, Datadog).
- **Fleet-wide Trace Waterfall Explorer:** Filterable search + live tail across HTTP API, AI, and MCP requests, preserving Shunt's signature per-hook microsecond waterfall (matching [RFC 0012](./0012-admin-inspector-ui.md)).
- **Cross-pillar Agent Session Correlation:** Stitch `shunt-ai` LLM turns and `shunt-mcp` tool calls sharing a W3C `trace_id` or `x-shunt-session-id` / `Mcp-Session-Id` into one end-to-end execution timeline.
- **Tamper-evident Admin Audit Log & Security Audit Center:** Hash-chained immutable record of all control-plane writes + searchable data-plane security events + SIEM webhook/JSONL export.
- **Privacy-by-default:** Store redacted metadata, token counts, costs, and SHA-256 argument/prompt fingerprints by default; full payload capture is strictly opt-in, cluster-scoped, and encrypted at rest.

### Non-Goals
- **Building a general-purpose APM or log-aggregation platform (Datadog/Splunk clone):** Observability in `shunt-console` is purpose-built for gateway requests, hooks, AI inference, MCP tool calls, and control-plane governance.
- **Blocking proxy traffic if ingestion slows down:** Shunt's OTLP and audit exporters are already bounded and drop-on-full; `shunt-console` ingestion enforces backpressure/sampling policies independently so a telemetry burst never degrades proxy throughput or control-plane Channel 1/2 delivery.

## 4. Design

### 4.1 Ingestion Pipeline & Isolation

`ConsoleCompiler` optionally wires `otel-trace`, `ai-audit`, and `mcp-telemetry` on managed clusters to point at `shunt-console`'s authenticated ingestion endpoints:

```text
  shunt Fleet
    ├── otel-trace (OTLP/HTTP JSON)  ──▶ POST /ingest/v1/traces
    ├── ai-audit / mcp-telemetry     ──▶ POST /ingest/v1/audit
    └── Node Heartbeats (15s)        ──▶ POST /cp/v1/nodes/{id}/heartbeat
                                                │
                                                ▼
                                   Bounded Async Ingest Queue
                                   (isolated tokio worker pool;
                                    separate from Channel 1/2!)
                                    ├──▶ Storage Backend (SQLite / Postgres / ClickHouse)
                                    ├──▶ Live Tail Fanout (filtered browser SSE)
                                    ├──▶ Rollup & Alert Evaluator
                                    └──▶ Optional OTLP / SIEM Forwarders
```

**Critical Isolation Invariant:** Ingestion runs on a bounded channel with dedicated worker tasks and separate DB connection pool limits so a 50k RPS trace spike can shed/sample ingest load (`429`/adaptive tail-sampling) without ever starving Channel 1 topology sync, Channel 2 key revocations, or Channel 3 MCP approvals.

### 4.2 Tiered Storage & Adaptive Retention

To stay fast on SQLite/Postgres without unbounded disk growth, `shunt-console` uses a clean `TelemetryStore` trait with two implementations:

1. **Embedded SQL Backend (`SqliteTelemetryStore` / `PostgresTelemetryStore`, default):**
   - **`trace_records` (hot ring, configurable max rows / TTL, default 7 days or 500k rows):**
     Indexed on `(cluster_id, ts)`, `trace_id`, `session_id`, `pillar` (`http` | `ai` | `mcp`), `route_id`, `status_code`, `key_id`, `model`, `mcp_tool`, `guardrail_triggered`. Stores compact JSON of per-hook µs timings and canonical attributes (`http.*`, `gen_ai.*`, `mcp.*`).
   - **`security_audit_events` (default 90 days):**
     Indexed on `(cluster_id, ts, category, severity, principal_id)` covering PII redactions, prompt-injection blocks, indirect MCP injection detections, budget/rate-limit denials, approval decisions, and kill-switch blocks.
   - **`metrics_rollups_1m` / `1h` / `1d` (long-term retention):**
     Exact counts, latency histogram buckets (for accurate fleet-wide p50/p95/p99 across nodes), error rates, token/cost totals, cache hit rates, and MCP tool counts.
   - Background compactor prunes expired partitions/rows incrementally (zero long table locks).

2. **Scale-Out Backend (`ClickHouseTelemetryStore`, optional):**
   - Enabled via `--telemetry-clickhouse-url https://...` for high-throughput production fleets (>1,000 req/s sustained trace capture) requiring 30–365 day raw trace search.

3. **Upstream OTLP Forwarding (Tee):**
   - Configurable per cluster: forward raw OTLP/HTTP spans asynchronously to external endpoints (e.g., Langfuse, Arize Phoenix, Grafana Tempo, Jaeger, Honeycomb, Datadog) with optional head/tail sampling rules (e.g., store 100% of errors, guardrail hits, and slow requests in `shunt-console`, forward 100% to Tempo).

### 4.3 Unified Fleet Trace Explorer & Agent Timeline (`console/web`)

- **Faceted Search & Live Tail:**
  - Filter bar supporting instant facets: `cluster`, `node`, `pillar:(http|ai|mcp)`, `status:>=400`, `duration:>500ms`, `key:<id>`, `org:<slug>`, `team:<slug>`, `model:<name>`, `provider:<id>`, `mcp.tool:<name>`, `guardrail:blocked|redacted`, `cache:hit`, and exact `trace_id` / `request_id`.
  - **Live Tail Toggle:** Streams matching newly-ingested traces over `GET /api/v1/clusters/{cluster}/traces/stream?<filters>` (SSE with `event: lagged` backpressure notification, reusing the exact UX discipline of [RFC 0012](./0012-admin-inspector-ui.md)).
- **Per-Hook µs Waterfall Drawer:**
  - Visualizes each request's exact hook execution (`request-id: 2µs` → `ai-virtual-keys: 5µs` → `ai-budget: 9µs` → `ai-model-router: 14µs` → `upstream TTFB: 284ms` → `ai-provider-adapter: 2µs/chunk × 48 chunks` → `total: 612ms`), compiled `HookMask`, node ID, snapshot revision, and structured attributes.
- **Cross-Pillar Agent Session View:**
  - Clicking any `trace_id` or `session_id` renders a hierarchical timeline correlating all `shunt-ai` LLM turns and `shunt-mcp` tool invocations in chronological order—showing total agent wall-clock time, cumulative token spend, tool calls executed, guardrail interventions, and human approvals granted in one unified view.

### 4.4 Security Audit & Tamper-Evident Admin Audit Center

#### 1. Data-Plane Security Audit (`security_audit_events`)
- Unified searchable feed for all defensive actions across the fleet:
  - HTTP: `jwt-auth`/`mtls-auth` rejections, `ip-filter` blocks, `body-limit` overflows, `rate-limit` 429s.
  - AI: `ai-guardrails` PII redactions & prompt-injection blocks, `ai-budget` hard/soft trips, `ai-virtual-keys` expired/revoked attempts.
  - MCP: `mcp-guardrails` argument violations, indirect prompt-injection detections, human approval requests/decisions, `mcp-rate-limit` loop-breaker trips, and `mcp.kill_switch` blocks.

#### 2. Tamper-Evident Control-Plane Admin Audit Log (`admin_audit_log`)
Every write endpoint in `shunt-console` atomically appends an immutable audit row within the same DB transaction:

```sql
CREATE TABLE admin_audit_log (
    seq            INTEGER PRIMARY KEY, -- monotonic per deployment
    ts             TEXT NOT NULL,
    actor_type     TEXT NOT NULL,       -- 'user' | 'api_token' | 'system'
    actor_id       TEXT NOT NULL,
    actor_ip       TEXT,
    org_id         TEXT,
    cluster_id     TEXT,
    action         TEXT NOT NULL,       -- e.g. 'revision.publish', 'virtual_key.revoke', 'mcp.approval.approve'
    resource_type  TEXT NOT NULL,
    resource_id    TEXT NOT NULL,
    diff_json      TEXT,                -- secret-redacted before/after summary
    prev_hash      TEXT NOT NULL,       -- SHA-256 of previous row (genesis = 64 zeros)
    entry_hash     TEXT NOT NULL        -- SHA-256(seq || ts || actor || action || resource || diff || prev_hash)
);
```

- **Integrity Verification:** `GET /api/v1/audit/admin:verify` (and `shunt-console audit verify`) walks the hash chain and confirms zero tampering or gaps.
- **SIEM Export:** Real-time webhook / Splunk HEC / Datadog Logs streaming + scheduled S3-compatible JSONL archival.

### 4.5 Golden-Signal Dashboards & Alerting

- **Unified Overview Dashboard:** Filterable by cluster & time range (`15m`, `1h`, `24h`, `7d`, `30d`), displaying:
  - **HTTP API:** RPS, p50/p95/p99 latency, upstream TTFB, 4xx/5xx error rate, top slow routes.
  - **AI Gateway:** Token throughput (input/output/cached), TTFT p95, provider failover & cooldown rate, `ai-cache` hit ratio & cost saved, active spend vs. budgets.
  - **MCP Gateway:** `tools/call` RPS, tool error rate, pending/approved/denied human approvals, loop-breaker trips, active kill-switches.
- **Built-in Alert Rules:** Declarative rules evaluated against 1-minute rollups and security events (e.g., cluster 5xx > 2%, node drifted > 5m, budget burn > 80%, MCP loop-breaker spike, pending approval waiting > 2m), dispatched to Slack, PagerDuty, or generic webhooks with deduplication and cooldown windows.

### 4.6 REST API Endpoints (Summary)

- **Ingestion (Node-Authenticated):**
  - `POST /ingest/v1/traces` (standard OTLP/HTTP JSON `ExportTraceServiceRequest`)
  - `POST /ingest/v1/audit` (batched redacted `ai-audit` / `mcp-telemetry` JSON events)
- **Query & Streaming (RBAC-Protected):**
  - `GET /api/v1/clusters/{cluster}/traces` (faceted search + cursor pagination)
  - `GET /api/v1/clusters/{cluster}/traces/{trace_id}` (full trace + cross-pillar session correlation)
  - `GET /api/v1/clusters/{cluster}/traces/stream` (live filtered SSE tail)
  - `GET /api/v1/clusters/{cluster}/metrics/summary` & `/timeseries`
  - `GET /api/v1/audit/security`, `GET /api/v1/audit/admin`, `GET /api/v1/audit/admin:verify`
  - `GET|PUT|DELETE /api/v1/orgs/{org}/alert-rules/{slug}`
  - `GET|PUT|DELETE /api/v1/orgs/{org}/siem-sinks/{slug}`

## 5. Alternatives Considered & Rejected

1. **Pulling `/api/traces` and `/metrics` from every `shunt` node's `:9090` Admin API:**
   - *Rejected:* Breaks outbound-only network topology (NAT/private subnets), loses traces whenever a node restarts or rolls its ring buffer, and scales poorly across large autoscaling fleets. Outbound OTLP/HTTP + audit push works seamlessly behind firewalls.
2. **Making ClickHouse or Elasticsearch a mandatory dependency for `shunt-console`:**
   - *Rejected:* Violates Shunt's zero-friction single-binary ethos. Bounded SQLite/Postgres storage handles solo/SMB/staging fleets out of the box while `TelemetryStore` lets high-volume enterprises plug in ClickHouse cleanly.
3. **Inventing a bespoke binary telemetry protocol in `shunt-engine`:**
   - *Rejected:* Unnecessary maintenance and lock-in. Consuming standard OTLP/HTTP JSON means zero engine changes and instant interoperability with existing OTel collectors, Jaeger, Tempo, Langfuse, and Arize Phoenix.

## 6. Verification Strategy

- **Ingest Isolation Load Tests:** Flood `/ingest/v1/traces` at 10× capacity while asserting Channel 1 topology publish and Channel 2 virtual-key revocation p99 latency stay under 50 ms with zero dropped control-plane events.
- **OTLP & Cross-Pillar Correlation Tests:** Send real OTLP spans from `shunt` running both `shunt-ai` and `shunt-mcp` sharing a `traceparent` header; verify `GET /traces/{trace_id}` stitches both LLM turns and MCP tool calls with exact combined latency and `cost_nano_usd`.
- **Admin Audit Hash-Chain Tests:** Verify every mutating API endpoint writes an audit row, `audit:verify` succeeds across sequences of mutations, and mutating or deleting any single row in SQLite/Postgres causes `audit:verify` to report the exact tampered `seq`.
- **Retention & Compaction Tests:** Verify bounded ring pruning keeps SQLite/Postgres storage within configured row/TTL limits while preserving long-term `metrics_rollups_1h`/`1d` accuracy.

## 7. Future Work

- **Prometheus Remote-Write Receiver:** Optional ingestion of full `shunt_*` Prometheus metric series for deployments without a standalone Prometheus server.
- **Anomaly Detection on Latency & Token Spend:** Automated seasonal baseline alerting per route, model, and MCP server.
- **Compliance Evidence Packs:** One-click signed ZIP/PDF export bundling active policies, RBAC bindings, MCP approval histories, and verified admin audit hash-chains for SOC 2 / ISO 27001 audits.
