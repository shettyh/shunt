# Shunt RFCs

This directory contains Request for Comments (RFC) design documents for **Shunt**. Each RFC captures the motivation, concrete design, invariants, and **rejected alternatives** for a major architectural seam so users and contributors can understand *why* Shunt is built the way it is—not just *how* it works.

## Index

| RFC | Title | Status | Crates |
| --- | --- | --- | --- |
| [0001](./0001-plugin-sdk-and-lifecycle.md) | Plugin SDK & Request Lifecycle | Implemented | `shunt-plugin-sdk`, `shunt-core` |
| [0002](./0002-atomic-snapshots-and-state-lifecycle.md) | Atomic Snapshots, Pool Reuse & State Lifecycle | Implemented | `shunt-core`, `shunt-plugin-sdk` |
| [0003](./0003-config-ir-and-admin-plane.md) | Config IR, Hot Reload, Admin API & Dev Ergonomics | Implemented | `shunt-config`, `shunt-plugins`, `shunt-cli` |
| [0004](./0004-shunt-ai-plugin-pack.md) | `shunt-ai`: Multi-Provider AI Gateway as a Pure Plugin Pack | Implemented | `shunt-ai` |
| [0005](./0005-benchmarks-and-hardening.md) | Benchmark Harness vs. Envoy & Caddy & Hardening | Implemented | `benches/`, `shunt-core`, `shunt-config` |
| [0006](./0006-verification-and-spec-testing.md) | Layered Verification, Property Testing & Spec-Driven TOML Testing | Implemented | `shunt-plugin-sdk`, `shunt-core`, `shunt-config`, `shunt-plugins`, `shunt-ai`, `shunt-test`, `shunt-cli`, `specs/`, `fuzz/` |
| [0007](./0007-generalized-ai-providers-and-endpoints.md) | Generalized AI Providers & Expanded OpenAI Endpoints | Implemented | `shunt-ai`, `shunt-plugin-sdk`, `shunt-core`, `shunt-test`, `fuzz` |
| [0008](./0008-multi-protocol-ai-ingress.md) | Multi-Protocol AI Ingress (`/v1/messages` & `/v1/responses`) | Implemented | `shunt-ai`, `shunt-test`, `fuzz` |
| [0009](./0009-virtual-keys-budgets-and-distributed-state.md) | Virtual Keys, Token Rate Limits, Cost Budgets & Distributed `StateStore` | Implemented | `shunt-plugin-sdk`, `shunt-core`, `shunt-config`, `shunt-plugins`, `shunt-ai`, `shunt-cli`, `shunt-test`, `fuzz` |
| [0010](./0010-smart-routing-and-active-health-checks.md) | Smart Routing & Active Upstream Health Checks | Implemented | `shunt-core`, `shunt-config`, `shunt-ai`, `shunt-cli`, `shunt-test` |
| [0011](./0011-otlp-observability-and-ai-cache.md) | OTLP/HTTP Observability & Exact-Match AI Response Cache | Implemented | `shunt-plugin-sdk`, `shunt-core`, `shunt-plugins`, `shunt-ai`, `shunt-config`, `shunt-cli`, `shunt-test`, `fuzz` |
| [0012](./0012-admin-inspector-ui.md) | Admin Read-Only Inspector UI (`--ui`) | Implemented | `shunt-plugin-sdk`, `shunt-config`, `shunt-ai`, `shunt-cli`, `shunt-test` |

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
