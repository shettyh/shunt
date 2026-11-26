# RFC 0024: `shunt-console` — Fleet Operations & Visual Config Studio

- **Status:** Draft
- **Crates / Directories:** `shunt-config`, `console/crates/shunt-console-core`, `console/crates/shunt-console-api`, `console/web`
- **Depends On:** [RFC 0023](./0023-shunt-console-architecture-and-control-plane.md)

## 1. Summary

This RFC specifies **Pillar A (Fleet & Release Operations)** and **Pillar B (Visual Config Studio)** of `shunt-console`. Building on Channel 1 (Topology Revisions) from [RFC 0023](./0023-shunt-console-architecture-and-control-plane.md), it provides multi-cluster node inventory, real-time config drift detection, label-targeted staged/canary rollouts with one-click rollback, a schema-driven visual editor for Shunt's full HTTP/AI/MCP topology (Listeners, TLS/mTLS, Upstreams, Route Groups, Path Templates/Regex, and Plugin Chains with live `HookMask` fast-path transparency), lossless `shunt.toml` import/export, and an in-console **Route & Policy Simulator**.

## 2. Motivation

Managing a fleet of `shunt` gateways across dev, staging, and production introduces operational risks that raw text files cannot easily eliminate:
- **Invisible fleet drift:** Operators need immediate visibility into whether 19 of 20 nodes picked up Revision #42 while 1 node failed TLS reload and stayed on Revision #41.
- **Risky all-at-once pushes:** Pushing a regex route change or upstream weight update directly to 100% of production nodes risks global outages; teams need ring-based canary rollouts and instant rollback without touching virtual keys or kill-switches.
- **Plugin ordering & `HookMask` opacity:** Shunt's speed relies on `HookMask` gating and valid plugin ordering (e.g., `jwt-auth` before `rate-limit`, `ai-virtual-keys` before `ai-budget`, `mcp-auth` before `mcp-router`). Operators editing configs need immediate visual feedback showing compiled `HookMask`s, fast-path eligibility, and `shunt verify` warnings *before* publishing.
- **Onboarding friction for existing `shunt.toml` users:** Teams migrating from standalone `shunt.toml` files need one-click import and full TOML export for disaster recovery and local `shunt test` runs.

## 3. Goals & Non-Goals

### Goals
- **Unified multi-cluster fleet view:** Real-time node inventory, active vs. target revision drift status, aggregated `/upstreams` active/passive health, provider failover cooldowns, EWMA latency tables, and `ai-cache` utilization.
- **Safe staged/canary rollouts:** Label-based rollout rings (`ring=canary` → `ring=stable`), immutable revision diffs (structured + canonical TOML), pre-publish `GatewayConfig::validate()` + `shunt verify` gating, and one-click rollback.
- **Schema-driven Visual Config Studio:** Typed forms generated from a canonical `PluginSchemaRegistry` in `shunt-config`, covering Listeners, TLS/mTLS certs, Upstreams, Route Groups ([RFC 0021](./0021-route-groups.md)), ordered Routes with `path_template`/`path_regex` ([RFC 0022](./0022-path-templates-and-regex-routing.md)), and Plugin Chains across `shunt-plugins`, `shunt-ai`, and `shunt-mcp`.
- **Live `HookMask` & fast-path transparency:** Display per-plugin and effective route `HookMask` bitmasks and explicitly highlight whether a route stays on Shunt's zero-allocation sync fast path (`HookResult::Ready`) vs. buffered/async hooks.
- **In-console Route & Policy Simulator:** Dry-run any synthetic request (host, method, path, headers) against draft or published revisions using `shunt-config`'s exact route matcher and verifier.
- **Unified multi-purpose surface & jargon-free UX:** Following [RFC 0023 §4.8](./0023-shunt-console-architecture-and-control-plane.md#48-web-console-ux-principles), Config Studio treats HTTP API, AI, and MCP topology entities as composable on the same cluster (no per-cluster gateway-type lock-in) and presents **Config & Releases** vs. **Live Policies** rather than exposing internal "Channel 1 / Channel 2" terminology.
- **Lossless `shunt.toml` import & export:** Import an existing `shunt.toml` into a cluster draft and export any revision as a standalone `shunt.toml` (secrets redacted or mapped to `env:` refs).

### Non-Goals
- **Container/VM orchestration:** `shunt-console` manages Shunt configurations and fleet state, not Kubernetes Pod scheduling or EC2 autoscaling.
- **Runtime per-request traffic splitting inside `shunt-console`:** Weighted traffic splitting between upstreams is compiled into `shunt-engine`'s native weighted upstream pools; canary *config* rollouts target subsets of `shunt` nodes by label.
- **Hand-maintained duplicate frontend schemas for 30+ plugins:** Plugin UI forms must be driven from Rust-defined metadata/JSON Schemas exposed by `shunt-config` so the UI never drifts from the gateway.

## 4. Design

### 4.1 Fleet Inventory, Heartbeats & Drift Detection

Each enrolled `shunt` node sends a heartbeat every 15s (configurable) to `POST /cp/v1/nodes/{node_id}/heartbeat`:

```json
{
  "node_id": "node_01J...",
  "shunt_version": "0.1.3",
  "labels": { "ring": "canary", "region": "us-east-1", "az": "use1-a" },
  "active_revision": 42,
  "active_digest": "sha256:9f86d0...",
  "last_reload_error": null,
  "synced_seqs": {
    "ai.virtual_keys": 1842,
    "ai.budgets": 310,
    "mcp.agent_acls": 94,
    "mcp.kill_switch": 7
  },
  "status": {
    "upstreams": [
      { "id": "openai", "healthy_endpoints": 2, "total_endpoints": 2, "active_probe_ms": 48.2 }
    ],
    "extensions": { "ai": { "...": "..." }, "mcp": { "...": "..." } }
  }
}
```

**Derived Node States:**
- **`Synced`:** Heartbeat < `3 × interval`, `active_digest == assigned_target_digest`, `last_reload_error == null`, and all Channel 2 `synced_seqs` within lag budget.
- **`Converging`:** Target revision changed < 30s ago and node is pulling/reloading.
- **`Drifted`:** Heartbeat healthy, `active_digest != assigned_target_digest` past convergence window, or `last_reload_error != null` (surfaces exact `ConfigError` diagnostic in UI!).
- **`Lagging`:** Channel 2 `synced_seq` behind cluster head beyond threshold (e.g., >5s).
- **`Offline`:** Missed heartbeats beyond TTL (default 60s); retained in inventory until pruned or deregistered.

### 4.2 Revision Lifecycle, Canary Rollouts & Rollback

```text
  Draft Edits (UI / REST / Terraform)
        │
        ▼
  Validate & Verify (GatewayConfig::validate() + shunt verify + dry-run SnapshotCompiler)
        │  [Blocks publish on Errors; displays Warnings with explicit ack]
        ▼
  Create Immutable Revision #N  (compiled_toml, digest, verify_report, diff vs #N-1)
        │
        ├──▶ Assign to Canary Ring   (selector: `ring=canary`)
        │       └─ Monitor fleet error rate / p99 / node reload health
        │
        ├──▶ Promote to All Nodes    (selector: `*`)
        │
        └──▶ One-Click Rollback      (reassign ring target back to Revision #N-1)
                └─ Channel 2 (virtual keys, budgets, MCP ACLs, kill-switch) UNTOUCHED!
```

**Invariants:**
1. **Immutability:** Once created, a `TopologyRevision` is immutable; rollback creates a new deployment pointer referencing an earlier revision number (recorded in `admin_audit_log`).
2. **Pre-flight compilation parity:** `shunt-console` runs `GatewayConfig::validate()` and `shunt_config::verify::verify_config()` before persisting a revision—catching route shadowing (`route.shadowed`), invalid path templates/regexes, unknown upstreams, and bad plugin orderings (`ai.plugin_order`, `mcp.plugin_order`) *before* any node sees the revision.
3. **Channel 2 isolation:** Topology rollback strictly changes Channel 1 pointers; Channel 2 state tables are never rolled back.

### 4.3 `PluginSchemaRegistry` (`shunt-config`) & Schema-Driven Config Studio

To guarantee zero drift between Shunt plugins and `shunt-console`'s visual editor (and simultaneously power `shunt schema` / IDE autocomplete from [docs/vision.md](../docs/vision.md)), `shunt-config` exposes a lightweight `PluginDescriptor` catalog:

```rust
pub struct PluginDescriptor {
    pub name: &'static str,           // e.g. "jwt-auth", "ai-model-router", "mcp-guardrails"
    pub pack: PluginPack,             // Core | Ai | Mcp
    pub summary: &'static str,
    pub hook_mask: HookMask,          // Static worst-case or conditional HookMask description
    pub fast_path_sync: bool,         // Whether common path returns HookResult::Ready
    pub config_schema: serde_json::Value, // JSON Schema 2020-12 for plugin config block
    pub secret_fields: &'static [&'static str], // Fields rendered as Vault secret pickers
    pub recommended_before: &'static [&'static str],
    pub recommended_after: &'static [&'static str],
}
```

**Visual Config Studio Views (`console/web`):**
1. **Topology Graph Canvas:** Interactive visual flow `Listeners (TLS/mTLS) → Route Groups → Routes → Plugin Pipeline → Upstreams / AI Providers / MCP Servers`, clickable into detail drawers.
2. **Listeners & TLS Manager:** Bind addresses, HTTP/1.1 & HTTP/2 settings, TLS cert/key selection from Secrets Vault with parsed X.509 expiry badges (warning at <30 days), SNI hostnames, and mTLS CA bundles.
3. **Upstreams & Health Studio:** Endpoint list with weights, TLS verification, split timeouts (`connect`, `response_headers`, `idle_chunk`), active HTTP/TCP health probe settings, passive outlier eviction, and live per-endpoint health sparklines from fleet heartbeats.
4. **Route Groups & Ordered Route Table:**
   - Drag-and-drop route ordering reflecting Shunt's explicit first-match-wins precedence.
   - Inline visual badges for `Exact`, `Prefix`, `Template` (`/orders/{id}`), and `Regex` (`^/orders/[0-9]+$`), plus live `shunt verify` inline squiggles for shadowed routes (`route.shadowed`) or narrowed group escapes.
5. **Plugin Chain Builder:**
   - Displays effective layered execution order (`Global → Route Group → Route`) with automatic ordering validation against `recommended_before`/`recommended_after`.
   - Renders each plugin's `HookMask` bits (`REQ_HDR`, `REQ_BODY`, `UPSTREAM`, `RESP_HDR`, `CHUNK`, `COMPLETE`) and a route-level **Fast-Path Badge** (e.g. `Sync Zero-Alloc` vs `Buffered Body` vs `Async Hook`).
   - Secret fields render as Vault pickers (`secret:<slug>` or `env:<VAR>`) rather than plaintext textboxes.
6. **Raw TOML / Diff View & Import/Export:**
   - Split-pane live preview of the compiled canonical `shunt.toml` and unified diff against the currently active revision.
   - **Import Wizard (`POST /api/v1/clusters/{cluster}/import-toml`):** Parses an uploaded `shunt.toml`, extracts inline secrets into Secrets Vault references (prompting confirmation), decomposes entities into relational draft resources, and verifies round-trip equivalence.

### 4.4 Interactive Route & Policy Simulator

Operators can test routing and policy decisions directly against any `draft` or published `revision` via `POST /api/v1/clusters/{cluster}/simulate`:

```json
// Request
{
  "target": "draft",
  "method": "GET",
  "host": "api.example.com",
  "path": "/v2/orders/94821/status",
  "headers": { "x-env": "beta" }
}

// Response
{
  "matched_route_id": "api_v2_order_status",
  "route_group_id": "api_v2",
  "match_kind": "path_template",
  "captured_path_params": { "order_id": "94821" },
  "effective_upstream": "orders_svc",
  "compiled_hook_mask": "ON_REQUEST_HEADERS | ON_COMPLETE",
  "fast_path_eligible": true,
  "plugin_chain": [
    { "layer": "global", "name": "request-id", "hook_mask": "ON_REQUEST_HEADERS" },
    { "layer": "group", "name": "jwt-auth", "hook_mask": "ON_REQUEST_HEADERS" },
    { "layer": "route", "name": "header-rewrite", "hook_mask": "ON_REQUEST_HEADERS" }
  ],
  "shadowing_warnings": []
}
```

Because `shunt-console` links `shunt-config` and `shunt-engine`'s matcher directly, the simulator executes the **exact** production route-matching algorithm (`Exact`, `Prefix`, `CompiledPathTemplate`, `RegexSet`)—zero JavaScript reimplementation drift.

### 4.5 REST API Endpoints (Summary)

- `GET /api/v1/clusters`, `PUT /api/v1/clusters/{cluster}`
- `GET /api/v1/clusters/{cluster}/nodes`, `DELETE /api/v1/clusters/{cluster}/nodes/{node_id}`, `PATCH /api/v1/clusters/{cluster}/nodes/{node_id}/labels`
- `GET|PUT|DELETE /api/v1/clusters/{cluster}/{listeners|upstreams|route-groups|routes|global-plugins}/{slug}`
- `PUT /api/v1/clusters/{cluster}/routes:reorder` (atomic precedence reorder)
- `POST /api/v1/clusters/{cluster}/validate` (runs `GatewayConfig::validate()` + `shunt verify`)
- `POST /api/v1/clusters/{cluster}/simulate` (Route & Policy Simulator)
- `POST /api/v1/clusters/{cluster}/revisions:publish` (creates revision + assigns target ring)
- `POST /api/v1/clusters/{cluster}/revisions/{rev}:promote` / `:rollback`
- `GET /api/v1/clusters/{cluster}/revisions/{rev}/diff?against={prev}`
- `POST /api/v1/clusters/{cluster}/import-toml`, `GET /api/v1/clusters/{cluster}/revisions/{rev}/export.toml`

## 5. Alternatives Considered & Rejected

1. **Storing raw `shunt.toml` blobs in DB with a Monaco text editor only:**
   - *Rejected:* Makes granular RBAC (e.g., letting a team edit its route group without touching TLS or global auth), structured Terraform CRUD, and visual plugin/hook guidance impossible. Normalized relational entities compiled into canonical `shunt.toml` give both structured UI/API *and* full TOML diff/export.
2. **Reimplementing route matching and validation in TypeScript for instant browser feedback:**
   - *Rejected:* Guaranteed to drift from Rust `CompiledPathTemplate`, `RegexSet`, and `shunt verify` rules. Sub-5ms server-side `/validate` and `/simulate` endpoints running real `shunt-config` code stay 100% authoritative.
3. **Auto-publishing every individual UI click immediately to production:**
   - *Rejected:* Causes half-configured intermediate states (e.g. creating a route before its upstream or auth plugin) and noisy reload storms. Explicit `Draft → Validate → Publish/Canary` makes production changes intentional and reviewable while still supporting `?auto_publish=true` for dev clusters.

## 6. Verification Strategy

- **Round-Trip Compilation Property Tests:** Arbitrary valid `GatewayConfig` → `import-toml` → relational DB entities → `ConsoleCompiler` → `GatewayConfig` produces semantically identical compiled routes, `HookMask`s, and upstreams.
- **Fleet Rollout Integration Tests:** Multi-node harness (3 simulated `shunt` nodes: 1 `ring=canary`, 2 `ring=stable`) verifying targeted canary assignment, intentional bad-TLS drift reporting, promotion, and rollback while verifying Channel 2 key revocations remain intact.
- **Simulator Equivalence Tests:** Property tests asserting `POST /simulate` matches `shunt_engine::GatewaySnapshot::match_route` across `Exact`, `Prefix`, `Template`, and `Regex` routes.

## 7. Future Work

- **Automated Canary Analysis (ACA):** Automatically pause or roll back a canary ring if ingested 5xx rate or p99 latency exceeds configured SLO thresholds compared to the stable ring.
- **Change Approval Workflows (4-Eyes Review):** Optional pull-request-style approval gate requiring a second `ClusterOperator` sign-off before publishing to production clusters.
- **Kubernetes Gateway API Visualization:** Read-only visualization of `--k8s-gateway` clusters synchronized from Kubernetes CRDs.
