---
title: AI Gateway Overview & Protocols
description: Multi-protocol AI ingress, bidirectional JSON and live SSE translation, multimodal endpoints, and canonical plugin ordering in shunt-ai.
---

`shunt-ai` is a pure-plugin multi-provider AI gateway built strictly on `shunt-plugin-sdk`. A single `/v1` route can serve OpenAI SDKs, Anthropic SDKs (Claude Code), OpenAI Responses clients (Codex CLI), and multimodal workloads across cloud and local inference backends.

## Supported Ingress Endpoints

| Endpoint | Protocol / Purpose |
| --- | --- |
| `POST /v1/chat/completions` | OpenAI Chat Completions (JSON + live SSE streaming, tools, vision, `json_schema`, reasoning) |
| `POST /v1/messages` | Anthropic Messages API (native passthrough to Anthropic, or live bidirectional translation to OpenAI, Azure, Gemini, Bedrock, Ollama/vLLM) |
| `POST /v1/messages/count_tokens` | Local token estimation endpoint for Anthropic clients |
| `POST /v1/responses` | OpenAI Responses API (native or translated across Chat / Anthropic / Gemini / Bedrock) |
| `POST /v1/embeddings` | Embeddings across OpenAI-compatible, Gemini, and AWS Bedrock (Titan/Cohere) |
| `GET /v1/models` & `/v1/models/{id}` | Synthesized model catalog with optional `context_length`, `pricing`, and capability metadata |
| `POST /v1/rerank` | Reranking across Cohere, Jina, Voyage, Bedrock, and vLLM |
| `POST /v1/images/*` | Image generation/edits (OpenAI, Gemini Imagen, etc.) |
| `POST /v1/audio/*` | Speech TTS & Whisper transcription/translation (multipart uploads up to `max_body_bytes`) |
| `GET /v1/realtime` | WebSocket voice/live realtime proxy (`allow_websockets = true`) |
| `POST /v1/completions` | Legacy completions / Fill-in-the-Middle (FIM) |
| `POST /v1/moderations` | Content moderation |
| `POST /v1/batches` & `/v1/files` | Batch & File APIs |
| `GET /v1/generation?id=...` | Reload-persistent generation metadata & cost lookup (zero DB) |

## Recommended Plugin Ordering

Plugins execute in the order listed under `[[routes.plugins]]`. Follow this canonical order for a full governed AI route (`shunt verify` warns if required dependencies are out of order):

```text
1. ai-virtual-keys       Authenticate client key & attach team/model/quota policy
2. ai-model-router       Parse request, enforce model ACLs & capabilities, select fallback chain
3. ai-guardrails         Scan/redact prompts before cache/budget/upstream (and responses/SSE on return)
4. ai-cache              Short-circuit exact/streaming/semantic cache hits with zero spend or quota
5. ai-token-rate-limit   Enforce RPM, TPM (pre-flight + reconciled), and max_parallel_requests
6. ai-budget             Enforce nano-USD budgets (with optional pre-flight reservations)
7. ai-provider-adapter   Inject provider auth / Cloud IAM & translate request/response/SSE dialects
8. ai-failover           Retry next target on 429/5xx/529, TTFT timeout, or context overflow
9. ai-usage-tracker      Extract tokens + TTFT, serve /v1/generation, feed metrics & OTLP GenAI spans
10. ai-audit             Emit redacted prompt/completion audit records (JSONL / OTLP / webhook)
11. ai-alerts            Send deduplicated Slack / PagerDuty / HTTP operational alerts
```

Every plugin is optional—start with just `ai-model-router`, `ai-provider-adapter`, `ai-failover`, and `ai-usage-tracker` and add governance or caching plugins as needed.
