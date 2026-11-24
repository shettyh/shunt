---
title: Verification & Testing
description: Catch misconfigurations, shadowed routes, broken plugin chains, and regressions before deployment with shunt check, shunt verify, and shunt test.
---

Shunt treats gateway configuration like code—shipping three built-in CLI verification layers that run in milliseconds in CI with zero external services.

## 1. Structural & Compilation Check (`shunt check`)

Parses TOML/YAML or Kubernetes manifests, validates every field and `env:VAR` reference, builds every plugin factory, and prints the compiled route table + active `HookMask`s:

```bash
shunt check -c shunt.toml
shunt check --k8s-manifest examples/k8s-gateway-api.yaml
```

## 2. Static Policy Verification (`shunt verify`)

Runs deep static analysis over the compiled `GatewaySnapshot` to catch subtle production bugs before deployment:

- **Route shadowing** (e.g., a broad `path_prefix = "/"` placed before `/api`, or `/orders/{id}/{action}` placed before `/orders/{id}/status`, including across paths lowered from `[[route_groups]]`, `path_template`, and `path_regex`)
- **Unused route groups** (`route_group.unused` warnings when a declared `[[route_groups]]` entry has no routes attached)
- **Plugin ordering bugs** across the effective `group + route` chain (e.g., `ai-provider-adapter` placed before `ai-model-router`, or `ai-cache` placed after `ai-budget`)
- **Missing upstream or provider definitions** referenced by model aliases
- **Security & reliability policy rules** targeting routes or route groups (`match_route` and `match_group` via `[verify]` in `shunt.toml` or `--policy policy.toml`)

```toml
[verify]
[[verify.route_policies]]
match_group = "api_*"
require_plugins = ["jwt-auth", "rate-limit"]
forbid_hooks = ["REQUEST_BODY_BUFFERED"]
```

```bash
# Human-readable output
shunt verify -c shunt.toml

# CI mode: fail on warnings and emit machine-readable JSON
shunt verify -c shunt.toml --strict --format json
```

## 3. Declarative Contract Tests (`shunt test`)

Write end-to-end gateway contract tests in TOML (`*.spec.toml`) and execute them against in-process mock upstreams—testing auth, rate limits, failover, SSE translation, guardrails, and MCP policies in milliseconds without Docker or live API keys:

```bash
shunt test -s specs/conformance/01-core-routing-and-plugins.spec.toml
shunt test -s my-gateway.spec.toml -c shunt.toml --filter "failover" --format json
```

A minimal contract spec:

```toml
[spec]
name = "api-gateway-contract"
config = "shunt.toml"

[[mocks]]
name = "api_backend"
[[mocks.routes]]
path = "/hello"
status = 200
body = '{"ok":true}'

[[cases]]
name = "adds powered-by header and forwards request"
method = "GET"
path = "/api/hello"
[cases.expect]
status = 200
headers = { "x-powered-by" = "shunt" }
body_contains = '"ok":true'
```

## 4. Formal & Fuzz Verification (Repo Level)

Shunt itself is verified with:
- **19 TOML conformance suites** covering HTTP, route groups, path templates/regex, AI, and MCP specs (`specs/conformance/`)
- **TLA+ models** (`specs/tla/`) verifying `AtomicReload`, `PassiveHealth`, and `RequestPipeline` invariants
- **18 `cargo-fuzz` targets** (`fuzz/fuzz_targets/`) covering untrusted parsers (SSE, AWS binary EventStream, Gemini SSE, JWT/JWKS, X.509 mTLS certs, RESP/Redis, MCP JSON-RPC, K8s manifests, guardrails, and config parsing)
- **Property tests (`proptest`)** across routing, token accounting, and translation layers
