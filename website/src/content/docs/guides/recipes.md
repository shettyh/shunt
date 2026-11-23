---
title: Which Plugins Do I Need?
description: Task-oriented recipe selector mapping real-world API, AI, and MCP gateway goals directly to exact Shunt plugin chains.
---

Shunt ships **31 built-in plugins**, but you only attach the ones your route actually needs—unused hooks cost **zero** CPU or memory thanks to `HookMask`.

Use this matrix to pick the minimal plugin chain for your goal.

## HTTP API Gateway Recipes

| Goal | Recommended Plugin Chain | Starter Example |
| --- | --- | --- |
| **Minimal reverse proxy + metrics** | `request-id` → `metrics` → `access-log` | `examples/shunt.toml` |
| **Public REST API with auth & limits** | `ip-filter` → `jwt-auth` → `rate-limit` → `body-limit` → `compression` → `cors` | `examples/shunt-api-gateway.toml` |
| **Zero-trust service-to-service (mTLS)** | `[server.tls]` (`client_ca`) + `mtls-auth` → `otel-trace` → `metrics` | `examples/shunt-api-gateway.toml` |
| **Legacy URL migration** | `redirect` (on legacy route) + `header-rewrite` (on v2 route) | `examples/shunt-api-gateway.toml` |
| **Kubernetes Gateway API ingress** | `shunt run --k8s-gateway` + `shunt.io/plugins` annotations | `examples/k8s-gateway-api.yaml` |

## AI Gateway Recipes (`shunt-ai`)

| Goal | Recommended Plugin Chain | Starter Example |
| --- | --- | --- |
| **Multi-provider failover (OpenAI + Anthropic)** | `ai-model-router` → `ai-provider-adapter` → `ai-failover` → `ai-usage-tracker` | `examples/shunt-ai.toml` |
| **Claude Code / Codex + local Ollama** | `ai-model-router` → `ai-provider-adapter` (`preset = "ollama"` + cloud) → `ai-failover` → `ai-usage-tracker` | [Coding Agents Guide](/shunt/guides/coding-agents/) |
| **Team virtual keys, RPM/TPM & USD budgets** | `ai-virtual-keys` → `ai-model-router` → `ai-token-rate-limit` → `ai-budget` → `ai-provider-adapter` → `ai-failover` → `ai-usage-tracker` | `examples/shunt-ai-governance.toml` |
| **Zero-latency AI caching + OTLP traces** | `otel-trace` (global) + `ai-model-router` → `ai-cache` → `ai-provider-adapter` → `ai-usage-tracker` | `examples/shunt-ai-observability-cache.toml` |
| **PII redaction, guardrails, audit & Slack alerts** | `ai-model-router` → `ai-guardrails` → `ai-budget` → `ai-provider-adapter` → `ai-failover` → `ai-usage-tracker` → `ai-audit` → `ai-alerts` | `examples/shunt-ai-guardrails-audit-alerts.toml` |
| **AWS Bedrock + Vertex AI + Azure Cloud IAM** | `ai-model-router` → `ai-provider-adapter` (`aws_iam` / `gcp_iam` / `azure_ad`) → `ai-failover` → `ai-usage-tracker` | `examples/shunt-ai-cloud-iam.toml` |
| **Smart canary / latency / cost / headroom routing** | `ai-model-router` (`strategy = "weighted" | "latency" | "cost" | "headroom"`) → `ai-provider-adapter` → `ai-failover` | `examples/shunt-ai-smart-routing.toml` |
| **Multimodal (images, audio, rerank, realtime WS)** | `allow_websockets = true` + `ai-model-router` → `ai-provider-adapter` → `ai-cache` (`cache_streaming = true`) → `ai-usage-tracker` | `examples/shunt-ai-multimodal-cache.toml` |

## MCP & Agentic Gateway Recipes (`shunt-mcp`)

| Goal | Recommended Plugin Chain | Starter Example |
| --- | --- | --- |
| **Virtual MCP multiplexer with tool ACLs** | `mcp-auth` → `mcp-router` → `mcp-telemetry` | `examples/shunt-mcp-gateway.toml` |
| **Full agentic governance (SQL rules, approvals, loop breaker)** | `mcp-auth` → `mcp-router` → `mcp-guardrails` → `mcp-rate-limit` → `mcp-telemetry` | `examples/shunt-mcp-gateway.toml` |
| **Enterprise OAuth + JWT / mTLS MCP** | `jwt-auth` (or `mtls-auth`) → `mcp-auth` (with RFC 9728 metadata) → `mcp-router` → `mcp-guardrails` → `mcp-rate-limit` → `mcp-telemetry` | [MCP Overview](/shunt/mcp-gateway/overview/) |

:::tip[Verify Your Plugin Order Automatically]
Whenever you compose a custom chain, run `shunt verify -c shunt.toml`. Shunt statically checks plugin ordering, missing providers, and shadowed routes before you deploy.
:::
