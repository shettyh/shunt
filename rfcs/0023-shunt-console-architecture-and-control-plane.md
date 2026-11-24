# RFC 0023: `shunt-console` — Core Architecture, Control-Plane Protocol & Dynamic State Sync

- **Status:** Draft
- **Crates / Directories:** `shunt-plugin-sdk`, `shunt-config`, `shunt-cli`, `console/` (`shunt-console-core`, `shunt-console-server`, `console/web`)

## 1. Summary

This RFC defines the foundational architecture of **`shunt-console`**, Shunt's optional, full-fledged companion Admin Console and Control Plane (Layer 3 in [docs/vision.md](../docs/vision.md)). `shunt-console` provides unified, DB-backed management across all three Shunt pillars—**HTTP API Gateway**, **AI Gateway (`shunt-ai`)**, and **MCP Agentic Governance (`shunt-mcp`)**—packaged as a single Rust binary (`axum` + `sqlx` + `shunt-config` + embedded React/TypeScript SPA) supporting **SQLite out of the box** and **PostgreSQL for HA deployments**.

To eliminate the classic rollback, canary, and scale pitfalls of monolithic config pushes without compromising Shunt's zero-allocation data plane, this RFC introduces a **3-Channel Control Plane Protocol**:
1. **Channel 1 — Topology Revisions:** Reviewed, diffable, canary-rollable, and rollback-able `GatewayConfig` snapshots delivered over `ControlPlaneConfigProvider`.
2. **Channel 2 — Synced State Tables (`SyncedTable`):** A generic, strictly AI/MCP-agnostic SDK primitive syncing fast-changing identity and policy tables (`ai.virtual_keys`, `ai.budgets`, `ai.pricing`, `mcp.agent_acls`, `mcp.kill_switch`) fleet-wide in ~20–50 ms via monotonic SSE deltas into lock-free in-memory `ArcSwap` maps—completely decoupled from topology rollbacks.
3. **Channel 3 — Interactive Off-Hot-Path RPC:** Authenticated HTTPS callbacks over Shunt's existing `HttpClient` primitive ([RFC 0014](./0014-cloud-iam-and-http-client.md)) for per-invocation interactive decisions such as MCP human-in-the-loop tool approvals ([RFC 0026](./0026-shunt-console-mcp-governance-and-approvals.md)).

## 2. Motivation

Shunt's core data plane (`shunt`) intentionally stays a ~20 MB stateless binary driven by `shunt.toml` with an opt-in read-only Admin Inspector UI ([RFC 0012](./0012-admin-inspector-ui.md)). As organizations move from a single developer instance to multi-team production fleets, five operational gaps emerge that belong in a companion control plane rather than the proxy binary:

1. **Multi-node fleet management:** Coordinating config rollouts, detecting snapshot drift, and rolling back broken changes safely across dozens of stateless `shunt` instances.
2. **Self-service governance & FinOps:** Letting teams mint/rotate/revoke virtual API keys, track org/team spend budgets, and govern MCP agent tool permissions without editing TOML files or redeploying proxies.
3. **Separation of topology vs. identity lifecycles:** Rolling back a faulty route change must **never** un-revoke a compromised virtual key or undo an emergency MCP kill-switch; conversely, minting a developer key must not recompile routes/TLS certs or pollute release history.
4. **Centralized secrets & RBAC:** Managing provider API keys, TLS certificates, OIDC/SSO login, role-based access control, and immutable admin audit trails in one auditable place.
5. **Automation & future GitOps:** Starting DB-managed for rapid adoption while designing every API resource declaratively so a Terraform provider and CI tooling can cleanly wrap `shunt-console` later.

## 3. Goals & Non-Goals

### Goals
- **Strict architectural isolation:** Zero DB drivers, UI assets, or control-plane server code inside `shunt-engine`, `shunt-ai`, `shunt-mcp`, or the default `shunt` binary build. Zero AI/MCP concepts inside `shunt-engine` or `shunt-plugin-sdk`.
- **Single-binary zero-friction default:** `shunt-console serve` starts immediately with embedded SPA assets and an embedded SQLite database—upgrading seamlessly to PostgreSQL (`--database-url postgres://...`) for HA clusters.
- **Exact config parity:** `shunt-console` imports `shunt-config` directly in Rust, compiling normalized DB state into canonical `GatewayConfig` IR and running `GatewayConfig::validate()` + `shunt verify` before any revision can be published.
- **Outbound-only data-plane connectivity:** `shunt` nodes initiate outbound HTTPS connections to `shunt-console` (`shunt run --control-plane <url>`), working cleanly across NATs, firewalls, and private Kubernetes namespaces without exposing data-plane `:9090`.
- **Data-plane outage resilience:** Every `shunt` node caches its last-known-good Channel 1 snapshot and compacted Channel 2 state locally (`--cache-dir`), continuing to serve traffic at full speed if `shunt-console` restarts or becomes unreachable.
- **Zero-allocation hot path preserved:** All Channel 2 lookups read lock-free in-memory `ArcSwap` snapshots (nanosecond latency, zero network/Redis dependency required on the hot path).
- **Terraform-ready REST/OpenAPI 3.1 API:** Declarative slug-addressed resources, optimistic concurrency (`ETag`), atomic draft/publish workflows, and write-only secret fields from Day 1.

### Non-Goals
- **Embedding write/CRUD UI inside `shunt --ui`:** Layer 1 (`--ui`) remains strictly read-only and zero-DB.
- **Mandatory external message brokers (Kafka/NATS/Redis):** `shunt-console` achieves HA delta fanout using an append-only SQL `control_events` table (+ PostgreSQL `LISTEN/NOTIFY`). Redis (`DistributedStore`) remains strictly opt-in for cross-node rate-limit/spend counters.
- **Two-way Git ↔ DB sync in v1:** `shunt-console` is DB-authoritative first; declarative GitOps is layered cleanly via `Export shunt.toml`, OpenAPI SDKs, and a Terraform provider targeting the REST API.
- **Replacing dedicated APM/log warehouses at petabyte scale:** Embedded SQLite/Postgres handles rollups and recent trace/audit retention; massive historical retention delegates to optional ClickHouse or upstream OTLP forwarding ([RFC 0027](./0027-shunt-console-observability-and-audit.md)).

## 4. Design

### 4.1 Monorepo Layout & Build Isolation

`shunt-console` lives in the same monorepo under `console/`, intentionally **excluded** from the root `[workspace].members` so core `cargo build` / `cargo test` for `shunt` remain 100% pure-Rust, fast, and free of Node/npm or SQL dependencies:

```text
shunt/
├── Cargo.toml                        # Root workspace (shunt-engine, shunt-config, shunt-cli, ...)
├── crates/                           # Core data-plane & plugin packs (unchanged pure Rust)
└── console/
    ├── Cargo.toml                    # Dedicated workspace for shunt-console (path-deps on ../crates/shunt-config)
    ├── crates/
    │   ├── shunt-console-core/       # Domain models, SQL migrations, SecretsVault, ConsoleCompiler, RBAC
    │   ├── shunt-console-api/        # Axum REST/OpenAPI (utoipa), Control-Plane SSE/pull, OTLP/Audit ingest
    │   └── shunt-console-bin/        # Single binary CLI (`shunt-console serve|migrate|bootstrap|export`)
    └── web/                          # React + TypeScript + Vite + Tailwind SPA (embedded via rust-embed)
```

**Why same monorepo, separate workspace:**
- Changes to `GatewayConfig` IR or `shunt verify` rules immediately type-check against `ConsoleCompiler` in CI (`console` workflow job).
- Contributors hacking on `shunt-engine`, `shunt-ai`, or `shunt-mcp` never install Node, `sqlx`, or frontend dependencies.

### 4.2 Unified Control-Plane Domain Model

All three pillars share a single canonical hierarchy rather than siloed data models:

```text
Organization
 ├── Console Users, OIDC Mappings & RBAC Role Bindings
 ├── Service API Tokens (CI / Terraform)
 ├── Secrets Vault (envelope-encrypted DEKs; scoped to Org or Cluster)
 ├── Teams & Principals (Virtual Keys [sha256 only], Agent Identities, Quotas, Budgets)
 └── Clusters (e.g. prod-us, staging, dev)
      ├── Enrolled Nodes (node_id, labels, version, active_digest, last_heartbeat, status)
      ├── Channel 1: Topology Entities (Listeners, TLS Certs, Upstreams, Route Groups, Routes,
      │              Plugins, AI Providers/Models/Routing, MCP Servers)
      │              ──▶ compiled into immutable `TopologyRevision` (version, digest, toml, verify_report)
      ├── Channel 2: Synced State Tables (`control_events` append-only log per cluster/namespace)
      │              ──▶ `ai.virtual_keys`, `ai.budgets`, `ai.pricing`, `mcp.agent_acls`, `mcp.kill_switch`, `mcp.approvals`
      └── Telemetry & Audit (OTLP trace rollups, spend ledger, guardrail/MCP audit, admin audit chain)
```

### 4.3 The 3-Channel Control Plane Protocol

```text
┌────────────────────────────────────────────────────────────────────────────┐
│                               shunt-console                                │
│  REST/UI API ──▶ DB (SQLite / Postgres) ──▶ ConsoleCompiler (shunt-config) │
│                     │                                    │                 │
│                     ▼                                    ▼                 │
│          control_events (monotonic seq)         TopologyRevision           │
└──────────────┬───────────────┬───────────────────────────┬─────────────────┘
               │               │                           │
   Channel 3   │   Channel 2   │               Channel 1   │
   (HTTPS RPC) │   (SSE Delta) │               (SSE + Pull)│
               │               ▼                           ▼
               │   ┌────────────────────────────────────────────────────────┐
               │   │             shunt Data-Plane Node                      │
               │   │  `shunt run --control-plane https://console --token …` │
               │   │                                                        │
               │   │  ControlPlaneConfigProvider ──▶ ReloadController       │
               │   │    (Channel 1: ArcSwap<GatewaySnapshot>)               │
               │   │                                                        │
               │   │  ControlPlaneFeed ──▶ SyncedTableRegistry              │
               │   │    (Channel 2: lock-free ArcSwap tables per namespace) │
               │   │                                                        │
               │   │  HttpClient ◀──────────────────────────────────────────┤
               │   │    (Channel 3: off-hot-path MCP approval RPCs)         │
               │   │                                                        │
               │   │  Local Cache (`--cache-dir`): last-known-good LKG      │
               │   └────────────────────────────────────────────────────────┘
```

#### Channel 1: Topology Revisions (`ControlPlaneConfigProvider`)
- **Purpose:** Authoritative gateway topology (`GatewayConfig` IR): listeners, TLS/mTLS certs, upstreams, route groups, routes, plugins, AI provider/model routing tables, guardrail rules, and MCP server definitions.
- **Lifecycle:** Explicitly versioned (`rev_1`, `rev_2`, ...), validated by `GatewayConfig::validate()` + `shunt verify`, targetable to node label rings (`canary`, `stable`), and safely rollback-able.
- **Wire endpoints (`/cp/v1/...`, authenticated via node bearer token or mTLS client cert):**
  - `POST /cp/v1/nodes/register` — Enroll node using a cluster bootstrap token; receives long-lived node credential (`node_id`, rotatable `node_token` or mTLS cert).
  - `GET /cp/v1/clusters/{cluster}/topology/watch?node_id=...` — SSE stream emitting `event: revision` (`{ "revision": 42, "digest": "sha256:...", "url": "..." }`) whenever the node's assigned target revision changes.
  - `GET /cp/v1/clusters/{cluster}/topology/revisions/{rev}` — Returns compiled canonical `GatewayConfig` bundle (JSON/TOML + inline resolved TLS/secret payload over TLS + Ed25519 signature + `ETag: "<digest>"`, supporting `304 Not Modified`).
  - `POST /cp/v1/nodes/{node_id}/heartbeat` — Periodic (default 15s) lightweight report carrying `active_revision`, `active_digest`, `synced_seqs` (per Channel 2 namespace), build version, and redacted `/api/status` summary (upstream health, provider cooldowns, cache stats).
- **Data-plane integration (`shunt-config`):**
  - `ControlPlaneConfigProvider` implements existing `ConfigProvider` ([provider.rs](../crates/shunt-config/src/provider.rs)) by reading from an in-memory `ArcSwap<LoadedConfig>` updated by the background Channel 1 watcher, triggering the exact same `ReloadController::reload()` path as `FileConfigProvider`.
  - Before swapping, the node verifies the bundle digest (and optional console public key signature) and writes the last-known-good bundle atomically to `--cache-dir/topology.lkg` (optionally encrypted at rest with `--cache-key-env`).

#### Channel 2: Synced State Tables (`SyncedTable` in `shunt-plugin-sdk`)
- **Purpose:** High-churn, fleet-wide identity & policy state that must propagate in milliseconds to **100% of cluster nodes** regardless of topology revision or canary ring, and must **never** be reverted by a topology rollback.
- **Strictly AI/MCP-agnostic SDK primitive (`shunt-plugin-sdk::sync`):**

```rust
/// Monotonic versioned key-value snapshot for a single logical namespace
/// (e.g. `"ai.virtual_keys"`, `"ai.budgets"`, `"mcp.agent_acls"`, `"mcp.kill_switch"`).
pub struct SyncedTable {
    namespace: Arc<str>,
    state: ArcSwap<SyncedTableSnapshot>,
    on_update: RwLock<Vec<Arc<dyn Fn(&SyncedTableSnapshot) + Send + Sync>>>,
}

#[derive(Debug, Clone)]
pub struct SyncedTableSnapshot {
    pub seq: u64,
    pub entries: BTreeMap<Arc<str>, Arc<serde_json::Value>>,
}

impl SyncedTable {
    /// Lock-free O(1) snapshot load for hot-path reads (zero allocation).
    pub fn load(&self) -> Arc<SyncedTableSnapshot>;

    /// Registers a derived-view builder (e.g. compiling `serde_json::Value` into a
    /// pre-indexed `HashMap<Sha256Key, AiKeyPolicy>` stored in a plugin's own `ArcSwap`).
    pub fn subscribe(&self, cb: Arc<dyn Fn(&SyncedTableSnapshot) + Send + Sync>);
}
```

- **Why `subscribe()` + derived `ArcSwap<T>`:** Domain plugins (`ai-virtual-keys`, `ai-budget`, `mcp-auth`, `mcp-guardrails`) subscribe once during `PluginFactory::build()` via `BuildContext::synced_table(namespace)`. Whenever a delta arrives off the hot path, the plugin rebuilds or patches its typed, pre-indexed in-memory lookup table (`ArcSwap<CompiledKeyIndex>`) in microseconds—keeping request-path lookups **100% typed, zero-JSON-parsing, and zero-allocation**.
- **Wire protocol (`/cp/v1/clusters/{cluster}/state/stream`):**
  - Client connects with `?namespaces=ai.virtual_keys,ai.budgets,...&cursors=ai.virtual_keys:1042,mcp.kill_switch:18`.
  - Server replays deltas from the append-only SQL `control_events(seq, cluster_id, namespace, item_key, op, payload_json, created_at)` table:
    - `event: delta` → `{ "seq": 1043, "ns": "ai.virtual_keys", "op": "upsert"|"delete", "key": "vk_01J...", "value": { ... } }`
    - `event: full_sync` → sent automatically on cold start (`seq == 0`) or if `last_seq` was compacted past retention; atomically replaces the namespace map at `seq = N` and transitions cleanly into live deltas.
    - `: keep-alive` every 15s; automatic jittered exponential reconnect with `Last-Event-ID`.
  - **HA Console Fanout without Kafka/NATS:** On PostgreSQL, committing a transaction to `control_events` executes `NOTIFY shunt_control_events, '<cluster_id>:<seq>'`, waking all `shunt-console` replicas in <5 ms. On SQLite (single-node), an in-process `tokio::sync::broadcast` wakes connected SSE streams immediately.
  - **Outage Resilience:** `shunt` periodically checkpoints compacted Channel 2 snapshots to `--cache-dir/state.<ns>.lkg` so cold restarts during a console outage still boot with valid keys and policies.
  - **Standalone `shunt.toml` Invariant:** When `--control-plane` is not enabled, `BuildContext::synced_table()` returns `None` and plugins run purely from static TOML config with zero overhead.

#### Channel 3: Interactive Off-Hot-Path RPC
- Used exclusively for per-invocation interactive events that cannot be precomputed into static tables (primarily MCP Human-in-the-Loop Tool Approvals in [RFC 0026](./0026-shunt-console-mcp-governance-and-approvals.md)).
- Executes strictly via `BuildContext::http_client()` ([RFC 0014](./0014-cloud-iam-and-http-client.md)) using the node's authenticated control-plane credentials and strict bounded timeouts. Never runs on ordinary HTTP/AI/non-gated MCP requests.

### 4.4 Storage Schema & Database Abstraction (`shunt-console-core`)

`shunt-console-core` uses `sqlx` with portable SQL migrations supporting:
- **SQLite (`sqlite://./shunt-console.db`, WAL mode, default):** Zero external services; ideal for single-node deployments, small teams, and local demos.
- **PostgreSQL (`postgres://...`):** Recommended for multi-replica HA `shunt-console` deployments, using `LISTEN/NOTIFY` for multi-instance Channel 1/2 event fanout and advisory locks for background compaction/rollups.

Core tables:
- `organizations`, `teams`, `users`, `role_bindings`, `api_tokens`
- `clusters`, `nodes`, `node_bootstrap_tokens`
- `secrets` (ciphertext, wrapped DEK, key version, provider metadata—never plaintext)
- `topology_resources` (`cluster_id`, `kind`, `slug`, `version`, `spec_json`, `draft_state`)
- `topology_revisions` (`cluster_id`, `revision`, `digest`, `compiled_toml`, `verify_report_json`, `ring_assignments`, `published_by`, `created_at`)
- `control_events` (`seq` BIGSERIAL/AUTOINCREMENT, `cluster_id`, `namespace`, `item_key`, `op`, `payload_json`, `created_at`)
- `control_state_current` (materialized current KV state per `(cluster_id, namespace, item_key)` for instant `FULL_SYNC` without replaying full history)
- `admin_audit_log` (hash-chained immutable mutation log; [RFC 0027](./0027-shunt-console-observability-and-audit.md))

### 4.5 Secrets Vault & Delivery Security

1. **Virtual keys (`ai.virtual_keys`, `mcp.agent_acls`):** Plaintext secret is generated once at creation, returned once to the caller, and **never persisted**. Only `sha256:<64-hex>` + safe display prefix (`shunt_vk_ab12...`) is stored in DB and synced over Channel 2—leveraging `shunt-ai` and `shunt-mcp`'s native `sha256:` support.
2. **Upstream provider keys & TLS private keys:** Stored in `secrets` using **envelope encryption** (per-secret random 256-bit `AES-256-GCM` DEK wrapped by a Master KEK supplied via `SHUNT_CONSOLE_MASTER_KEY`, AWS KMS, GCP Cloud KMS, or HashiCorp Vault).
3. **Two secret delivery modes per secret:**
   - **`vault` (managed):** `shunt-console` decrypts at bundle-build time and delivers over TLS/mTLS into `shunt` memory only (local disk cache encrypted with node-local key if enabled).
   - **`env_ref` (zero-trust passthrough):** `shunt-console` compiles `"env:OPENAI_API_KEY"` directly into the IR so sensitive provider keys never enter `shunt-console`'s database at all.
4. **Secret redaction by construction:** All Console API responses, revision diffs, TOML exports, and audit logs reuse `shunt-config`'s secret redaction policy (`[REDACTED]` / `secret_ref:<slug>`).

### 4.6 Console AuthN, RBAC & Terraform-Ready REST/OpenAPI API

- **Authentication:**
  - Local bootstrap admin (`shunt-console bootstrap`) with Argon2id password hashing for zero-dependency startup.
  - Native **OIDC/SSO** (Authorization Code + PKCE: Okta, Google Workspace, GitHub, Microsoft Entra ID, Keycloak) with group-to-role claim mapping.
  - Scoped **Service API Tokens** (`shunt_ct_...`, stored as SHA-256 hash) for CI/CD and Terraform.
- **Built-in RBAC Roles (Org- and Cluster-scoped):**
  - `SuperAdmin` — Full platform, OIDC, and cross-org management.
  - `ClusterOperator` — Topology edits, revision publish/canary/rollback, node enrollment, secrets management.
  - `OrgAdmin` — Org/team structure, budgets, provider policies, RBAC within org.
  - `TeamLead` — Team virtual keys, team MCP ACLs, MCP approval inbox decisions, team spend visibility.
  - `Developer` — Self-service personal virtual keys (within team ceilings), AI Playground, read-only routes/traces for own keys.
  - `Auditor` — Read-only access to revisions, spend ledger, traces, and security/admin audit logs.
- **Terraform-Ready REST/OpenAPI 3.1 Conventions (`/api/v1/...`):**
  - Auto-generated OpenAPI 3.1 spec (`GET /api/v1/openapi.json`) via `utoipa`.
  - **Idempotent slug-addressed resources:** `PUT /api/v1/clusters/{cluster}/routes/{slug}`, `PUT /api/v1/clusters/{cluster}/upstreams/{slug}`, `PUT /api/v1/orgs/{org}/virtual-keys/{slug}`.
  - **Optimistic concurrency:** `ETag` + `If-Match` headers on every mutable resource (`412 Precondition Failed` on conflict).
  - **Atomic draft/publish:** Topology edits update `draft` resources without triggering fleet reloads until `POST /api/v1/clusters/{cluster}/revisions:publish` (or `?auto_publish=true` for simple workflows), enabling clean multi-resource `terraform apply` batches.
  - **Standard error envelope:** RFC 9457 `application/problem+json` including structured `shunt verify` diagnostic codes when validation fails.

### 4.7 `shunt-cli` Integration

```bash
# Start shunt connected to shunt-console (outbound-only, zero local shunt.toml needed)
shunt run \
  --control-plane https://console.internal:8443 \
  --cluster prod-us \
  --token-env SHUNT_NODE_TOKEN \
  --cache-dir /var/lib/shunt/cache \
  --node-labels ring=stable,region=us-east-1

# Start shunt-console (single binary, SQLite default)
shunt-console serve --listen 0.0.0.0:8443 --db sqlite://./shunt-console.db
```

## 5. Alternatives Considered & Rejected

1. **Embedding `shunt-console` inside the `shunt` data-plane binary:**
   - *Rejected:* Violates Shunt's single-binary zero-dependency guardrail, bloats the ~20 MB proxy with SQL drivers and frontend bundles, and couples data-plane scaling/security posture to control-plane database availability.
2. **Baking virtual keys, budgets, and MCP ACLs into monolithic `GatewayConfig` topology snapshots:**
   - *Rejected:* Creates three severe operational bugs: (a) rolling back a faulty route revision accidentally un-revokes compromised virtual keys; (b) revocations and kill-switches fail to reach all nodes uniformly during staged canary topology rollouts; (c) minting/revoking keys at scale (10k+ keys) forces expensive full-snapshot recompilation and clutters release history. Splitting into Channel 1 (Topology) and Channel 2 (`SyncedTable`) solves all three cleanly.
3. **Synchronous hot-path lookups against `shunt-console` or mandatory Redis for keys/ACLs:**
   - *Rejected:* Adds network latency and failure coupling onto Shunt's sub-millisecond hot path and breaks outage resilience. Lock-free local `ArcSwap` tables synced via Channel 2 preserve identical hot-path performance to static `shunt.toml`.
4. **Console pushing into data-plane Admin API (`:9090`):**
   - *Rejected:* Requires opening inbound network paths to every proxy pod/VM (breaking NAT/private-subnet deployments) and violates [RFC 0003](./0003-config-ir-and-admin-plane.md)'s defense-in-depth loopback admin default.
5. **Requiring Kafka/NATS/etcd for control-plane sync:**
   - *Rejected:* Destroys single-binary ergonomics. An append-only `control_events` SQL table (+ PostgreSQL `LISTEN/NOTIFY`) handles thousands of state mutations/sec with zero extra infrastructure.

## 6. Verification Strategy

- **Unit & Integration Tests (`console/crates/*`):** End-to-end tests spinning up `shunt-console-server` (against both SQLite and Postgres) alongside real `shunt` data-plane instances covering node enrollment, Channel 1 publish/rollback, Channel 2 delta replay + `FULL_SYNC` gap recovery, console-outage LKG cache boot, envelope encryption, RBAC enforcement, and `ETag` concurrency conflicts.
- **Property Tests (`proptest`):** `SyncedTable` state-machine equivalence (`apply_deltas(initial, events) == full_sync_state`) across arbitrary interleavings of upserts, deletes, reconnects, and log compactions.
- **Security & Isolation Checks:** CI check verifying root `cargo check --workspace` has zero dependency edges on `console/`, `sqlx`, or `axum`, and `shunt-engine` has zero AI/MCP/console symbols.
- **Performance Regression:** Benchmark verifying `SyncedTable`-backed `ai-virtual-keys` and `mcp-auth` match static `shunt.toml` throughput and p99 latency within noise (<1%).

## 7. Future Work

- **Official Terraform Provider (`terraform-provider-shunt`):** Thin declarative provider generated from `shunt-console`'s OpenAPI 3.1 spec.
- **Hybrid GitOps Overlay Mode:** Allow a cluster's Channel 1 topology to be locked read-only from Git while Channel 2 dynamic governance remains Console-managed.
- **Mutual TLS Node Identity & Short-Lived Automated Cert Rotation:** Built-in internal CA issuing short-lived SPIFFE/X.509 node certificates for Channel 1/2/3 links.
- **External Secret Manager Live Sync:** Native sync adapters for AWS Secrets Manager, GCP Secret Manager, and HashiCorp Vault KV.
