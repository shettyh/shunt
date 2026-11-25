# RFC 0026: `shunt-console` — MCP Governance, Tool ACLs & Human-in-the-Loop Approvals

- **Status:** Draft
- **Crates / Directories:** `shunt-mcp`, `shunt-plugin-sdk`, `console/crates/shunt-console-core`, `console/crates/shunt-console-api`, `console/web`
- **Depends On:** [RFC 0023](./0023-shunt-console-architecture-and-control-plane.md), [RFC 0019](./0019-mcp-and-agentic-gateway.md)

## 1. Summary

This RFC specifies **Pillar D (MCP & Agentic Governance)** of `shunt-console`. Building on `shunt-mcp` ([RFC 0019](./0019-mcp-and-agentic-gateway.md)) and the 3-Channel Control Plane ([RFC 0023](./0023-shunt-console-architecture-and-control-plane.md)), it adds:
1. An **MCP Server & Live Tool Catalog** surfacing discovered tools, resources, prompts, and JSON argument schemas across multiplexed upstream MCP servers.
2. A visual **Agent Identity & Least-Privilege ACL Matrix** + JSON argument rule builder synced fleet-wide in ~20–50 ms over **Channel 2 (`mcp.agent_acls`)**.
3. A **Human-in-the-Loop Approval Inbox** powered by **Channel 3 (Interactive RPC)** and **Channel 2 (`mcp.approvals`)**, binding every approval cryptographically to `(principal, server, tool, canonical_args_sha256)` with both **Async/Deferred** and **Synchronous Hold/Wait** execution modes.
4. A real-time **Agent Kill-Switch & Loop-Breaker Operations Center** over **Channel 2 (`mcp.kill_switch`)** to halt runaway or compromised agents fleet-wide in milliseconds.

## 2. Motivation

Autonomous coding, DevOps, and enterprise agents calling MCP tools (`github__merge_pr`, `postgres__execute_sql`, `aws__delete_stack`, `slack__post_message`) represent a far higher-impact security boundary than read-only LLM text generation. While [RFC 0019](./0019-mcp-and-agentic-gateway.md) built the data-plane enforcement primitives (`mcp-auth`, `mcp-router`, `mcp-guardrails`, `mcp-rate-limit`, `mcp-telemetry`), operating them at organizational scale requires a dedicated governance workflow:
- **Managing hundreds of tools across dozens of agents:** Hand-editing glob lists and per-tool JSON argument regexes in `shunt.toml` does not scale when security teams need to audit "which agents can invoke `postgres__*`?" at a glance.
- **Turning approval gates into a real human workflow:** Today `mcp-guardrails` checks a static `x-shunt-approved: true` header or external OPA webhook. Teams need an out-of-the-box **Approval Inbox** (Web UI + Slack/Teams/Webhook notifications) where a human reviews the exact agent, tool, and JSON arguments and clicks **Approve** or **Deny** with an auditable rationale.
- **Emergency containment:** When an agent suffers indirect prompt injection or enters a destructive loop, security operators need a **one-click Kill-Switch** that immediately terminates the agent's tool access across every `shunt` node without waiting for a topology rollout.

## 3. Goals & Non-Goals

### Goals
- **Live MCP Catalog Discovery:** Inspect tools, resources, prompts, and JSON input schemas exposed by every registered upstream MCP server without leaving `shunt-console`.
- **Fast Fleet-Wide Agent ACLs (Channel 2):** Update per-agent server/tool/resource/prompt permissions and JSON argument constraints via `mcp.agent_acls` in ~20–50 ms with zero topology reload and zero hot-path overhead. Following [RFC 0023 §4.8](./0023-shunt-console-architecture-and-control-plane.md#48-web-console-ux-principles), Agent Permissions, Approval Inbox, and Kill-Switch appear as first-class **MCP & Agents** views with `Instant Sync` indicators rather than exposing Channel 2/3 transport terms in the UI.
- **Tamper-Proof Human-in-the-Loop Approvals (Channel 3 + Channel 2):**
  - Bind every approval grant to `canonical_args_sha256` (reusing `shunt-mcp`'s deterministic canonical JSON serializer) so an approved safe call cannot be replayed with malicious arguments.
  - Support both **Async/Deferred Mode** (immediate `-32004` with `approval_id`, agent retries once approved) and **Hold/Wait Mode** (data plane holds the MCP call open up to a bounded timeout until a human clicks Approve/Deny).
  - Support **one-time grants** (default) and **time-boxed session grants** (e.g., "allow `github__create_issue` for this agent for 15 minutes").
- **Instant Agent / Session / Tool Kill-Switch (Channel 2):** Propagate emergency blocks (`mcp.kill_switch`) to 100% of nodes in <50 ms, immediately halting rogue agents or compromised upstream tools.
- **Zero MCP leakage into `shunt-engine` or `shunt-plugin-sdk`:** Every capability rides strictly on Channel 2 `SyncedTable` and Channel 3 `HttpClient`.

### Non-Goals
- **Running agent loops or hosting `stdio` MCP subprocesses inside `shunt-console`:** `shunt-console` governs Streamable HTTP MCP traffic through `shunt` data planes; it does not host LLM agent runtimes.
- **Replacing enterprise IAM/IdPs:** `shunt-console` integrates with existing OIDC/JWT/mTLS agent identities (and supports Shunt virtual agent keys) rather than replacing corporate identity providers.

## 4. Design

### 4.1 MCP Server Registry & Live Tool Discovery

- **Server Registration (Channel 1 Topology):** Operators register upstream MCP servers (`github`, `postgres`, `jira`, `internal-k8s`) with upstream pool, transport mode (`stateless` vs `stateful` lazy `initialize`), credential reference from Secrets Vault, and namespace prefix (`<server>__<tool>`).
- **Schema Discovery:** Connected `shunt` nodes report cached `tools/list`, `resources/list`, and `prompts/list` metadata summaries (tool name, description, JSON Schema `inputSchema`) via a dedicated catalog sync endpoint `POST /cp/v1/nodes/{node_id}/mcp-catalog` (hash-deduplicated so unchanged catalogs send zero bytes).
- **Risk Tagging:** Operators (or automated heuristics on schema keywords like `delete`, `drop`, `write`, `exec`, `transfer`) tag tools in the catalog as `read-only`, `write`, or `destructive`, visually highlighting ungoverned destructive tools.

### 4.2 Agent Identity & Visual ACL Matrix (Channel 2: `mcp.agent_acls`)

`mcp-auth` and `mcp-guardrails` opt into Channel 2 via `sync_namespace = "mcp.agent_acls"`:

```json
// Channel 2 entry in namespace `mcp.agent_acls`, key = "agent_01J..."
{
  "id": "agent_01J...",
  "name": "ci-triage-bot",
  "auth": {
    "kind": "api_key_sha256",
    "hashes": ["sha256:88a1..."]
  },
  // Or: { "kind": "jwt_subject", "issuer": "...", "subject": "spiffe://..." }
  "enabled": true,
  "allowed_servers": ["github", "jira"],
  "allowed_tools": ["github__get_*", "github__list_*", "github__create_issue", "jira__*"],
  "denied_tools": ["github__delete_*", "github__merge_*"],
  "allowed_resources": ["github://org/my-repo/*"],
  "allowed_prompts": ["triage_*"],
  "require_approval_tools": [
    {
      "tool": "github__create_issue",
      "mode": "hold_wait",
      "wait_timeout_secs": 45,
      "approver_roles": ["TeamLead", "ClusterOperator"],
      "allow_session_grant": true
    }
  ],
  "tool_arg_rules": {
    "github__create_issue": {
      "required_args": ["repo", "title"],
      "forbidden_args": ["admin_override"],
      "allow_patterns": { "repo": "^acme-org/[a-z0-9-]+$" },
      "max_arg_bytes": 16384
    }
  },
  "rate_limits": {
    "rpm": 60,
    "tools_call_rpm": 30,
    "max_calls_per_session": 100,
    "max_parallel_calls": 4
  }
}
```

**Visual UX (`console/web`):**
- **Permission Matrix:** Rows = Agent Principals (or Agent Roles), Columns = MCP Servers / Tools; toggle cells between `Allow`, `Require Approval`, `Deny`, and `Hidden from tools/list` (least-privilege disclosure).
- **Schema-Aware Argument Rule Builder:** Because `shunt-console` has each tool's live `inputSchema`, operators pick argument fields from a dropdown rather than typing raw JSON property names by hand, and test sample `tools/call` JSON payloads in-browser via `POST /api/v1/clusters/{cluster}/mcp/policy:test`.

### 4.3 Human-in-the-Loop Approval Workflow (Channel 3 + Channel 2)

```text
  Agent            shunt (`mcp-guardrails`)                  shunt-console              Human Approver
    │                        │                                     │                          │
    │─ tools/call(args) ────▶│                                     │                          │
    │                        │ 1. Compute canonical_args_sha256    │                          │
    │                        │ 2. Check Channel 2 `mcp.approvals`  │                          │
    │                        │    (cache hit? → forward upstream!) │                          │
    │                        │                                     │                          │
    │                        │ 3. Cache miss → Channel 3 RPC       │                          │
    │                        │─── POST /cp/v1/mcp/approvals ──────▶│                          │
    │                        │    (agent, tool, args_redacted,     │─── Slack / UI Inbox ────▶│
    │                        │     canonical_args_sha256, mode)    │                          │
    │                        │                                     │                          │
    │   [Mode A: Async]      │◀── { status: "pending", id } ───────│                          │
    │◀─ JSON-RPC -32004 ─────│                                     │                          │
    │   { approval_id }      │                                     │◀── Click "Approve" ──────│
    │                        │                                     │    (rationale + scope)   │
    │                        │◀══ Channel 2 UPSERT mcp.approvals ══│                          │
    │─ Retry tools/call ────▶│ 4. Match grant + consume single-use │                          │
    │  (forwards upstream)   │                                     │                          │
    │                        │                                     │                          │
    │   [Mode B: Hold/Wait]  │    (holds Channel 3 HTTP open ≤60s) │◀── Click "Approve" ──────│
    │                        │◀── { status: "approved", grant } ───│                          │
    │  (forwards upstream    │                                     │                          │
    │   in same HTTP call!)  │                                     │                          │
```

#### Cryptographic & Safety Invariants
1. **Strict Argument Binding:** Every approval request and grant carries `args_sha256 = sha256(canonical_json_bytes(params.arguments))`. On retry (Mode A), `mcp-guardrails` recomputes `args_sha256` from the incoming request and rejects any mismatch (`-32003`)—preventing TOCTOU argument tampering.
2. **Single-Use Consumption & Expiry:**
   - Default grants are **single-use** (`max_uses = 1`, `expires_at = now + 5m`). Once `mcp-guardrails` executes the call, it reports consumption asynchronously (`POST /cp/v1/mcp/approvals/{id}/consume`) and Console emits a Channel 2 `DELETE` for `mcp.approvals/<id>` (and locally marks the grant consumed immediately in `StateStore` / `DistributedStore` to prevent race replays).
   - **Time-boxed session grants** (`scope = "session_tool"`, e.g. 15 min for a specific `(principal_id, mcp_session_id, tool)`) omit argument pinning only when explicitly allowed by the tool's policy (`allow_session_grant = true`).
3. **Zero Upstream Leakage:** `mcp-router` continues to strip all internal approval headers (`x-shunt-approved`, `x-shunt-approval-id`) before forwarding to upstream MCP servers.
4. **Fail-Closed Default:** If `shunt-console` is unreachable during a Channel 3 approval call, `mcp-guardrails` **always fails closed** (`-32004` approval unavailable) and never silently allows a gated destructive tool.
5. **Notification Connectors:** Console pushes interactive approval cards to **Web UI Inbox** (live SSE updates), **Slack** (Block Kit Approve/Deny buttons calling signed webhook callbacks), **Microsoft Teams**, and **generic webhooks**.

### 4.4 Emergency Kill-Switch & Loop-Breaker Operations (Channel 2: `mcp.kill_switch`)

`mcp-auth` and `mcp-guardrails` subscribe to Channel 2 namespace `mcp.kill_switch`:

```json
// Keyed by rule ID; checked in O(1) lock-free ArcSwap map before routing any MCP request
{
  "id": "ks_01J...",
  "scope": "principal" | "session" | "server" | "tool",
  "target": "agent_01J..." ,     // or session_id, server name, or "postgres__execute_sql"
  "reason": "Suspected prompt injection via external GitHub issue #441",
  "created_by": "secops@acme.com",
  "expires_at": null             // null = until manually lifted
}
```

- **Sub-50 ms Containment:** Triggering a Kill-Switch in the Console UI or via `POST /api/v1/clusters/{cluster}/mcp/kill-switch` pushes a ~200-byte Channel 2 delta to 100% of cluster nodes immediately. Affected requests receive JSON-RPC `-32003` (`blocked by security kill-switch`) and emit high-priority audit events.
- **Loop-Breaker Live Feed:** `shunt-console` ingests `mcp-rate-limit` loop-breaker trips and `mcp-guardrails` indirect prompt-injection detections via `/ingest/v1/audit`, surfacing an **Active Incidents Banner** with a one-click **"Kill Agent"** or **"Kill Session"** button right next to the offending event.

### 4.5 REST API Endpoints (Summary)

- `GET|PUT|DELETE /api/v1/clusters/{cluster}/mcp/servers/{slug}`
- `GET /api/v1/clusters/{cluster}/mcp/catalog` (aggregated discovered tools/resources/prompts + schemas)
- `GET|PUT|DELETE /api/v1/clusters/{cluster}/mcp/agents/{agent_id}` (writes Channel 2 `mcp.agent_acls`)
- `POST /api/v1/clusters/{cluster}/mcp/policy:test` (dry-run ACL + JSON arg rule evaluation)
- `GET /api/v1/clusters/{cluster}/mcp/approvals?status=pending|approved|denied|expired`
- `POST /api/v1/clusters/{cluster}/mcp/approvals/{id}:approve` / `:deny`
- `GET|POST|DELETE /api/v1/clusters/{cluster}/mcp/kill-switch` (writes Channel 2 `mcp.kill_switch`)
- **Control-Plane Channel 3 Endpoints:**
  - `POST /cp/v1/mcp/approvals` (request approval; supports `mode = "async" | "hold_wait"`)
  - `POST /cp/v1/mcp/approvals/{id}/consume` (mark single-use grant consumed)

## 5. Alternatives Considered & Rejected

1. **Baking MCP approvals into Channel 1 topology snapshots:**
   - *Rejected:* Triggering a full gateway snapshot reload to approve one tool invocation is slow, pollutes release history, and risks unintended side effects on unrelated routes.
2. **Allowing agents to supply `x-shunt-approved: true` directly in Console-managed mode:**
   - *Rejected:* In Console-managed clusters, client-asserted approval headers are disabled by default; approvals must be backed by a Console-issued grant verified against `canonical_args_sha256`.
3. **Only supporting synchronous Hold/Wait approval mode:**
   - *Rejected:* Many MCP clients enforce short HTTP timeouts (15–30s), whereas human approvals often take minutes. Supporting both **Async/Deferred** (default) and **Hold/Wait** (configurable per tool) works across every MCP client and agent framework.

## 6. Verification Strategy

- **End-to-End Approval Integration Tests:** Spin up `shunt-console` + `shunt` (`mcp-router` + `mcp-guardrails`) + mock MCP server testing:
  - Mode A (Async): denied with `approval_id` → approved in Console → retry with identical args succeeds → replay fails (single-use) → retry with mutated args fails (`args_sha256` mismatch).
  - Mode B (Hold/Wait): concurrent `tools/call` held open → Console approves after 200ms → upstream receives call transparently; timeout expiry returns `-32004`.
  - Fail-closed test: `shunt-console` killed mid-request → gated tool is strictly rejected.
- **Kill-Switch Latency & Isolation Tests:** Verify `mcp.kill_switch` blocks active agent sessions across all nodes within <100 ms locally and survives Channel 1 topology rollbacks.
- **Least-Privilege Disclosure Tests:** Verify revoking a tool in `mcp.agent_acls` immediately hides it from subsequent `tools/list` responses as well as blocking `tools/call`.

## 7. Future Work

- **Risk-Adaptive Auto-Approval Rules:** Policy expressions (e.g., auto-approve `postgres__query` when SQL AST is read-only `SELECT` with `LIMIT <= 100`, escalate writes to human inbox).
- **Per-User Downstream OAuth Delegation UI:** Manage OAuth app registrations and token-exchange flows so upstream MCP servers act on behalf of the invoking human user rather than a shared service token.
- **Cross-Agent Blast-Radius Graph:** Visual map showing which LLM virtual keys, MCP agents, and backend MCP servers interact inside shared agent sessions.
