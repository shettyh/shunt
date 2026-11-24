# Changelog

## 0.3.0 (2026-11-24)

## What's Changed
* feat(routing): add path templates, regex routing, and captured path parameters (RFC 0022) by @shettyh in https://github.com/shettyh/shunt/pull/44
* perf(routing): add internal RouteIndex (Exact map + Segment Trie + RegexSet) for RFC 0022 Stage 2 by @shettyh in https://github.com/shettyh/shunt/pull/46
* ci(bench): pin nightly benchmarks to ubuntu-24.04-arm by @shettyh in https://github.com/shettyh/shunt/pull/47


**Full Changelog**: https://github.com/shettyh/shunt/compare/v0.2.0...v0.3.0

## 0.2.0 (2026-11-23)

## What's Changed
* docs: add documentation website and update product vision by @shettyh in https://github.com/shettyh/shunt/pull/38
* docs: improve config mental model, route-group patterns, plugin matrices & production guide by @shettyh in https://github.com/shettyh/shunt/pull/41
* feat(config): add route groups and shared plugin chains (RFC 0021) by @shettyh in https://github.com/shettyh/shunt/pull/40


**Full Changelog**: https://github.com/shettyh/shunt/compare/v0.1.2...v0.2.0

## 0.1.2 (2026-11-23)

## What's Changed
* fix(crates): rename shunt-core to shunt-engine by @shettyh in https://github.com/shettyh/shunt/pull/36


**Full Changelog**: https://github.com/shettyh/shunt/compare/v0.1.1...v0.1.2

## 0.1.1 (2026-11-23)

## What's Changed
* chore(release): fix multi-arch Docker build, workflow_dispatch publish, and crates.io publish cycle by @shettyh in https://github.com/shettyh/shunt/pull/33


**Full Changelog**: https://github.com/shettyh/shunt/compare/v0.1.0...v0.1.1

## 0.1.0 (2026-11-23)

## What's Changed
* feat(verify): implement RFC 0006 layered verification, proptest, shunt verify/test, TLA+, Kani & fuzzing by @shettyh in https://github.com/shettyh/shunt/pull/8
* feat(ai): implement RFC 0007 generalized AI providers, cloud dialects, /v1/models & /v1/embeddings by @shettyh in https://github.com/shettyh/shunt/pull/9
* feat(ai): implement RFC 0008 multi-protocol AI ingress (/v1/messages & /v1/responses) by @shettyh in https://github.com/shettyh/shunt/pull/10
* feat(ai): implement RFC 0009 virtual keys, TPM limits, cost budgets & distributed StateStore by @shettyh in https://github.com/shettyh/shunt/pull/11
* feat(routing): implement RFC 0010 smart routing, weighted pools & active health checks by @shettyh in https://github.com/shettyh/shunt/pull/12
* feat(observability): implement RFC 0011 OTLP/HTTP tracing & exact-match ai-cache by @shettyh in https://github.com/shettyh/shunt/pull/13
* feat(admin): implement RFC 0012 read-only Admin Inspector UI (--ui) by @shettyh in https://github.com/shettyh/shunt/pull/14
* perf(bench): update nightly benchmark report by @github-actions[bot] in https://github.com/shettyh/shunt/pull/15
* perf(bench): add Shunt vs. LiteLLM AI gateway benchmarks & Phase A4 vision update by @shettyh in https://github.com/shettyh/shunt/pull/16
* feat(ai): implement RFC 0013 deep protocol parity, provider presets & multi-key pools by @shettyh in https://github.com/shettyh/shunt/pull/17
* feat(ai): implement RFC 0014 dynamic cloud IAM auth & outbound HttpClient primitive by @shettyh in https://github.com/shettyh/shunt/pull/18
* feat(ai): implement RFC 0015 pluggable AI guardrails, redacted audit sinks & alert webhooks by @shettyh in https://github.com/shettyh/shunt/pull/19
* feat(ai): implement RFC 0016 multimodal endpoints, generation lookup & streaming/singleflight/semantic AI cache by @shettyh in https://github.com/shettyh/shunt/pull/20
* feat(ai): implement RFC 0017 per-request routing, concurrency quotas & advanced failover by @shettyh in https://github.com/shettyh/shunt/pull/21
* feat(gateway): implement RFC 0018 JWT/OIDC auth, HTTP security, compression & Kubernetes Gateway API by @shettyh in https://github.com/shettyh/shunt/pull/22
* perf(bench): expand gateway & AI benchmarks for RFC 0015–0018 and fix AiGenerationStore leak by @shettyh in https://github.com/shettyh/shunt/pull/24
* test(verify): bounded-store invariants, core TLA+/proptest updates, RSS soak guardrail & full nightly fuzzing by @shettyh in https://github.com/shettyh/shunt/pull/25
* feat(mcp): implement RFC 0019 MCP & agentic governance plugin pack by @shettyh in https://github.com/shettyh/shunt/pull/26
* docs: streamline README and extract plugin/admin/examples reference by @shettyh in https://github.com/shettyh/shunt/pull/27
* perf(bench): implement RFC 0020 unified API, AI & MCP benchmark suite by @shettyh in https://github.com/shettyh/shunt/pull/28
* docs(readme): make Benchmarks at a Glance scannable by @shettyh in https://github.com/shettyh/shunt/pull/30
* perf(bench): update nightly benchmark report by @github-actions[bot] in https://github.com/shettyh/shunt/pull/31
* chore(release): add shunt-mcp to release-please, Dockerfile, and crates-publish by @shettyh in https://github.com/shettyh/shunt/pull/32


**Full Changelog**: https://github.com/shettyh/shunt/compare/v0.0.1...v0.1.0

## 0.0.1 (2026-11-21)

## What's Changed
* ci: add PR checks, security audit, multi-platform releases, Docker, and nightly benchmarks by @shettyh in https://github.com/shettyh/shunt/pull/1
* ci: adopt Release Please semantic release PR workflow by @shettyh in https://github.com/shettyh/shunt/pull/4

## New Contributors
* @shettyh made their first contribution in https://github.com/shettyh/shunt/pull/1

**Full Changelog**: https://github.com/shettyh/shunt/commits/v0.0.1
