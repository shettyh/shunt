# Shunt RFCs

This directory contains Request for Comments (RFC) design documents for **Shunt**. Each RFC captures the motivation, concrete design, invariants, and **rejected alternatives** for a major architectural seam so users and contributors can understand *why* Shunt is built the way it is—not just *how* it works.

## Index

| RFC | Title | Status | Crates |
| --- | --- | --- | --- |
| [0001](./0001-plugin-sdk-and-lifecycle.md) | Plugin SDK & Request Lifecycle | Implemented | `shunt-plugin-sdk`, `shunt-engine` |
| [0002](./0002-atomic-snapshots-and-state-lifecycle.md) | Atomic Snapshots, Pool Reuse & State Lifecycle | Implemented | `shunt-engine`, `shunt-plugin-sdk` |
| [0003](./0003-config-ir-and-admin-plane.md) | Config IR, Hot Reload, Admin API & Dev Ergonomics | Implemented | `shunt-config`, `shunt-plugins`, `shunt-cli` |
| [0004](./0004-shunt-ai-plugin-pack.md) | `shunt-ai`: Multi-Provider AI Gateway as a Pure Plugin Pack | Implemented | `shunt-ai` |
| [0005](./0005-benchmarks-and-hardening.md) | Benchmark Harness vs. Envoy & Caddy & Hardening | Implemented | `benches/`, `shunt-engine`, `shunt-config` |
| [0006](./0006-verification-and-spec-testing.md) | Layered Verification, Property Testing & Spec-Driven TOML Testing | Implemented | `shunt-plugin-sdk`, `shunt-engine`, `shunt-config`, `shunt-plugins`, `shunt-ai`, `shunt-test`, `shunt-cli`, `specs/`, `fuzz/` |
| [0007](./0007-generalized-ai-providers-and-endpoints.md) | Generalized AI Providers & Expanded OpenAI Endpoints | Implemented | `shunt-ai`, `shunt-plugin-sdk`, `shunt-engine`, `shunt-test`, `fuzz` |
| [0008](./0008-multi-protocol-ai-ingress.md) | Multi-Protocol AI Ingress (`/v1/messages` & `/v1/responses`) | Implemented | `shunt-ai`, `shunt-test`, `fuzz` |
| [0009](./0009-virtual-keys-budgets-and-distributed-state.md) | Virtual Keys, Token Rate Limits, Cost Budgets & Distributed `StateStore` | Implemented | `shunt-plugin-sdk`, `shunt-engine`, `shunt-config`, `shunt-plugins`, `shunt-ai`, `shunt-cli`, `shunt-test`, `fuzz` |
| [0010](./0010-smart-routing-and-active-health-checks.md) | Smart Routing & Active Upstream Health Checks | Implemented | `shunt-engine`, `shunt-config`, `shunt-ai`, `shunt-cli`, `shunt-test` |
| [0011](./0011-otlp-observability-and-ai-cache.md) | OTLP/HTTP Observability & Exact-Match AI Response Cache | Implemented | `shunt-plugin-sdk`, `shunt-engine`, `shunt-plugins`, `shunt-ai`, `shunt-config`, `shunt-cli`, `shunt-test`, `fuzz` |
| [0012](./0012-admin-inspector-ui.md) | Admin Read-Only Inspector UI (`--ui`) | Implemented | `shunt-plugin-sdk`, `shunt-config`, `shunt-ai`, `shunt-cli`, `shunt-test` |
| [0013](./0013-protocol-parity-and-provider-presets.md) | Deep Protocol Parity, Provider Presets & Multi-Key Pools | Implemented | `shunt-ai`, `specs/`, `examples/`, `fuzz/` |
| [0014](./0014-cloud-iam-and-http-client.md) | Dynamic Cloud IAM Auth & Outbound `HttpClient` Primitive | Implemented | `shunt-plugin-sdk`, `shunt-engine`, `shunt-ai`, `shunt-test`, `specs/`, `examples/`, `fuzz/` |
| [0015](./0015-guardrails-audit-and-webhooks.md) | Pluggable AI Guardrails (`ai-guardrails`), Audit Sinks (`ai-audit`) & Alert Webhooks (`ai-alerts`) | Implemented | `shunt-plugin-sdk`, `shunt-engine`, `shunt-config`, `shunt-ai`, `specs/`, `examples/`, `fuzz/` |
| [0016](./0016-multimodal-endpoints-and-streaming-cache.md) | Multimodal Endpoints, Generation Lookup & Streaming/Singleflight/Semantic AI Cache | Implemented | `shunt-ai`, `shunt-config`, `specs/`, `examples/`, `fuzz/` |
| [0017](./0017-per-request-routing-quotas-and-advanced-failover.md) | Per-Request Routing, Concurrency Quotas & Advanced Failover | Implemented | `shunt-plugin-sdk`, `shunt-engine`, `shunt-config`, `shunt-ai`, `specs/`, `examples/`, `fuzz/` |
| [0018](./0018-jwt-http-security-compression-and-k8s-gateway.md) | JWT/OIDC Auth, HTTP Gateway Security, Response Compression & Kubernetes Gateway API | Implemented | `shunt-plugin-sdk`, `shunt-engine`, `shunt-plugins`, `shunt-config`, `shunt-cli`, `specs/`, `examples/`, `fuzz/` |
| [0019](./0019-mcp-and-agentic-gateway.md) | `shunt-mcp`: Model Context Protocol (MCP) & Agentic Governance Plugin Pack | Implemented | `shunt-mcp`, `shunt-config`, `shunt-cli`, `shunt-test`, `specs/`, `examples/`, `fuzz/` |
| [0020](./0020-unified-comprehensive-benchmarks.md) | Unified & Comprehensive Gateway Benchmark Suite (API, AI & MCP) | Implemented | `benches/shunt-bench`, `benches/configs/`, `benches/scripts/`, `benches/results/` |
| [0021](./0021-route-groups.md) | Route Groups & Shared Plugin Chains | Implemented | `shunt-config`, `shunt-cli`, `shunt-test`, `specs/`, `examples/` |
| [0022](./0022-path-templates-and-regex-routing.md) | Path Templates, Regex Routing & Captured Path Parameters | Implemented | `shunt-plugin-sdk`, `shunt-engine`, `shunt-plugins`, `shunt-config`, `specs/`, `examples/`, `fuzz/` |
| [0023](./0023-shunt-console-architecture-and-control-plane.md) | `shunt-console`: Core Architecture, Control-Plane Protocol & Dynamic State Sync | Implemented | `shunt-plugin-sdk`, `shunt-engine`, `shunt-config`, `shunt-cli`, `console/` |
| [0024](./0024-shunt-console-fleet-and-config-studio.md) | `shunt-console`: Fleet Operations & Visual Config Studio | Draft | `shunt-config`, `console/` |
| [0025](./0025-shunt-console-ai-governance-and-finops.md) | `shunt-console`: AI Gateway Governance, Virtual Keys & FinOps Ledger | Draft | `shunt-ai`, `console/` |
| [0026](./0026-shunt-console-mcp-governance-and-approvals.md) | `shunt-console`: MCP Governance, Tool ACLs & Human-in-the-Loop Approvals | Draft | `shunt-mcp`, `shunt-plugin-sdk`, `console/` |
| [0027](./0027-shunt-console-observability-and-audit.md) | `shunt-console`: Unified Fleet Observability, Trace Explorer & Audit Center | Draft | `shunt-config`, `console/` |

## Status Definitions

- **Draft**: Under active design or pending implementation.
- **Accepted**: Design agreed upon; ready for implementation.
- **Implemented**: Shipped in the codebase and verified by tests.
- **Superseded**: Replaced by a newer RFC (linked in the header).
- **Rejected**: Explored and intentionally not pursued (kept for historical context).

## Writing a New RFC

Keep RFCs concise, concrete, and focused on a single architectural seam. Use the following sections:

1. **Header**: Title, Status, Crates
2. **Summary**: 2–4 sentences describing what this RFC introduces.
3. **Motivation**: The problem or tension that drove the design.
4. **Goals & Non-Goals**: Clear scope boundaries.
5. **Design**: Core types, lifecycle/diagrams, and invariants.
6. **Alternatives Considered & Rejected**: Other viable designs and why they were not chosen.
7. **Future Work**: Known v2+ extensions enabled by the design.
