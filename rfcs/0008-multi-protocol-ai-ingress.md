# RFC 0008: Multi-Protocol AI Ingress (`/v1/messages` & `/v1/responses`)

- **Status:** Implemented
- **Crates:** `shunt-ai`, `shunt-test`, `fuzz`

## Summary

RFC 0008 completes Phase A1 of [docs/vision.md](../docs/vision.md) by turning `shunt-ai` into a **multi-protocol AI gateway** that accepts **three** client-facing AI ingress protocols on the same unified `/v1` route and translates bidirectionally across all five configured upstream provider dialects (`openai_compatible`, `anthropic`, `azure_openai`, `gemini`, `bedrock`):

1. **OpenAI Chat Completions** (`POST /v1/chat/completions`) — existing canonical frontend.
2. **Anthropic Messages** (`POST /v1/messages`) — lets Claude Code, Anthropic SDKs, and Anthropic-native agents point directly at Shunt and route seamlessly to Anthropic (zero-loss native passthrough), OpenAI, Ollama, Groq, Azure OpenAI, Google Gemini / Vertex AI, or AWS Bedrock with live bidirectional JSON & SSE translation and cross-cloud failover.
3. **OpenAI Responses** (`POST /v1/responses`) — lets modern OpenAI SDKs, Codex CLI, and OpenAI Agents SDK route to native Responses-capable endpoints (zero-loss passthrough when `responses_path` is configured) OR transparently translate across Anthropic, Gemini, Bedrock, Ollama, Groq, and Azure Chat Completions with full streaming SSE lifecycle translation.

All multi-protocol ingress logic lives **100% inside `shunt-ai`** with zero changes to `shunt-core` or `shunt-plugin-sdk`.

## Motivation

In RFC 0007, Shunt expanded its **egress** breadth to cover arbitrary OpenAI-compatible servers plus Anthropic, Azure OpenAI, Google Gemini/Vertex, and AWS Bedrock—but its **ingress** remained OpenAI Chat Completions only. Real developer environments increasingly mix clients speaking three wire protocols:

- **Claude Code & Anthropic SDKs** speak `POST /v1/messages` exclusively (including `system` block arrays, `tool_use`/`tool_result` blocks, `anthropic-beta` headers, and named SSE events `message_start` -> `content_block_*` -> `message_delta` -> `message_stop`).
- **Codex CLI & modern OpenAI SDKs** adopt `POST /v1/responses` (`instructions`, typed `input` items, `function_call`/`function_call_output`, `text.format`, and sequenced `response.*` SSE events).
- **Existing apps & SDKs** continue using `POST /v1/chat/completions`, `POST /v1/embeddings`, and `GET /v1/models`.

Without multi-protocol ingress, teams must deploy separate proxies per SDK or lose automatic cross-cloud failover (for example, failing over a Claude Code `POST /v1/messages` request from an overloaded Anthropic endpoint to AWS Bedrock ConverseStream or Gemini).

## Goals & Non-Goals

### Goals
- **Unified single-route ergonomics:** A single `path_prefix = "/v1"` route serves `/v1/models`, `/v1/chat/completions`, `/v1/messages`, `/v1/responses`, and `/v1/embeddings` using one model catalog, one provider registry, one failover circuit breaker, and one token tracker.
- **Zero-translation native fast paths:**
  - `POST /v1/messages` -> `anthropic` upstream passes through natively (rewriting `"model"` only when aliased, preserving `anthropic-beta`, `anthropic-version`, `thinking`, `cache_control`, citations, and streaming chunks untouched).
  - `POST /v1/responses` -> `openai_compatible` / `azure_openai` with `responses_path` configured passes through natively (rewriting `"model"` only when aliased).
- **Hub-and-spoke translation (no N x M explosion):** Cross-protocol requests normalize once into Shunt's canonical OpenAI Chat Completions JSON IR and responses compose two orthogonal streaming/JSON stages (`Upstream -> Canonical OpenAI -> Ingress`).
- **Protocol-native gateway errors:** Gateway-generated errors (`400`, `404`, `500`) match the ingress protocol (`{"type":"error","error":{...}}` on `/v1/messages`; `{"error":{...}}` on OpenAI endpoints).
- **Accurate token & TTFT tracking across every combination:** Extend `ai-usage-tracker` to recognize OpenAI Responses streaming (`response.output_text.delta`, `response.function_call_arguments.delta`, `response.completed.response.usage`) alongside OpenAI Chat, Anthropic Messages, Gemini, and Bedrock.
- **Layered verification (RFC 0006):** Back both new ingress translators and composed cross-cloud pipelines with TOML conformance specs (`06-multi-protocol-ingress.spec.toml`), property tests, and fuzz targets.

### Non-Goals
- **Stateful Responses API server-side conversation storage (`previous_response_id` / `GET /v1/responses/{id}` / `DELETE /v1/responses/{id}`):** Shunt is a stateless data plane. Native passthrough (`responses_path = "/v1/responses"`) preserves `previous_response_id` transparently when talking to OpenAI directly; cross-provider translation targets stateless multi-turn `input` item arrays.
- **Anthropic `/v1/messages/count_tokens`:** Deferred to a lightweight follow-up once local token estimation lands in RFC 0009 (TPM rate limiting).
- **Server-side built-in provider tools (`web_search_preview`, `file_search`, `computer_use`) across different vendors:** Preserved transparently on native passthrough paths; cross-provider translation focuses on portable function tools, text, structured outputs, and vision inputs.

---

## Design

### 1. Hub-and-Spoke Architecture with Native Fast Paths

```text
                       ┌──────────────────────┐
                       │   Ingress Frontend   │
                       └──────────┬───────────┘
         ┌────────────────────────┼────────────────────────┐
         ▼                        ▼                        ▼
  POST /v1/chat/completions  POST /v1/messages     POST /v1/responses
         │                        │                        │
         │                        ├──[native fast path]───► Anthropic
         │                        │                        │
         │                        │   ┌─[native fast path]─┴──► OpenAI/Azure (responses_path)
         │                        │   │
         ▼                        ▼   ▼
  ┌──────────────────────────────────────────────────────┐
  │     Canonical Chat Completions Wire IR (JSON/SSE)    │
  └──────────────────────────┬───────────────────────────┘
                             │
         ┌───────────┬───────┼───────┬──────────┐
         ▼           ▼       ▼       ▼          ▼
    OpenAI-Comp    Azure  Anthropic Gemini   Bedrock
```

Because `shunt-core` passes a fresh O(1) refcount clone of the original buffered request body into `on_upstream_request` on **every retry attempt**, failover seamlessly mixes native fast paths and translated fallback paths within a single request:
- Attempt 1 on `POST /v1/messages` hits Anthropic natively -> `529 Overloaded` -> `ai-failover` retries.
- Attempt 2 translates the original Anthropic request -> Canonical IR -> AWS Bedrock ConverseStream (with pure-Rust SigV4) and live-streams `Bedrock EventStream -> Canonical OpenAI SSE -> Anthropic Messages SSE` back to the client.

### 2. Endpoint Classification & Native Error Responses

`AiEndpointKind` in `crates/shunt-ai/src/types.rs` adds:
- `AnthropicMessages` (matched on `POST .../messages`)
- `OpenAiResponses` (matched on `POST .../responses`)

Both require `AiCapability::Chat` during target capability filtering in `ai-model-router`.

`endpoint_error_response(endpoint, status, error_type, code, message)` emits:
- Anthropic `{"type":"error","error":{"type":"...","message":"..."}}` for `AnthropicMessages` (mapping HTTP status codes `400/401/403/404/413/429/529` to canonical Anthropic error types such as `not_found_error`, `rate_limit_error`, `overloaded_error`).
- OpenAI `{"error":{"message":"...","type":"...","param":null,"code":...}}` for all OpenAI endpoints.

### 3. Provider Configuration (`responses_path`)

`ProviderInstanceConfig` adds one optional field:

```toml
[routes.plugins.config.providers.openai]
dialect = "openai_compatible"
responses_path = "/v1/responses"
auth = { type = "bearer", api_key = "env:OPENAI_API_KEY" }
```

- When `responses_path` is set on `openai_compatible` or `azure_openai`, `POST /v1/responses` takes the native zero-translation fast path (`rewrite_openai_responses_request` + `AdapterResponseState::Passthrough`).
- When omitted (e.g., Ollama, Groq, older vLLM, or Azure Chat Completions deployments), `POST /v1/responses` translates transparently via Canonical Chat Completions.

### 4. Anthropic Messages Ingress (`crates/shunt-ai/src/ingress/anthropic.rs`)

- **Native Passthrough:** `rewrite_anthropic_request` mutates `"model"` only when aliased (`Ok(None)` = zero-copy), while `ai-provider-adapter` preserves client `anthropic-beta` and `anthropic-version` headers on Anthropic targets (and strips them on non-Anthropic targets).
- **Request Translation (`anthropic_to_openai_request`):**
  - `system` string or `[{type: "text", text}]` array -> `{role: "system"}`.
  - `user` content blocks: `tool_result` blocks split into `{role: "tool", tool_call_id, content}` messages; `text` & `image` (`base64` -> `data:` URI, `url` -> HTTPS URL) map to user content parts.
  - `assistant` content blocks: `text` -> `content`, `tool_use` -> `tool_calls`, Anthropic-only `thinking` blocks ignored cleanly on non-Anthropic backends.
  - `tools`, `tool_choice` (`auto`/`any`/`none`/`tool`), `stop_sequences`, `max_tokens`, `temperature`, `top_p`, `stream`, `metadata.user_id`.
- **Response Translation:**
  - Non-streaming (`openai_to_anthropic_response`): maps `choices[0].message` (`content` + `tool_calls`) -> Anthropic `content[]` (`text` + `tool_use`), maps `finish_reason` -> `stop_reason` (`stop`->`end_turn`, `length`->`max_tokens`, `tool_calls`->`tool_use`), and maps upstream errors into Anthropic `{"type":"error",...}`.
  - Streaming (`OpenAiToAnthropicSseTranslator`): emits strictly ordered `message_start`, monotonically indexed `content_block_start` / `content_block_delta` (`text_delta`, `input_json_delta`) / `content_block_stop`, defers `message_delta` until `[DONE]`/EOF so OpenAI's trailing `stream_options.include_usage` chunk populates both `input_tokens` and `output_tokens`, and terminates with `message_stop`.

### 5. OpenAI Responses Ingress (`crates/shunt-ai/src/ingress/responses.rs`)

- **Native Passthrough:** `rewrite_openai_responses_request` rewrites `"model"` only when aliased.
- **Request Translation (`responses_to_chat_request`):**
  - `instructions` -> `{role: "system"}`.
  - `input` string -> single user message; `input` array -> `message` items (`input_text`/`output_text`/`text`/`refusal`/`input_image`), `function_call` items (merged into assistant `tool_calls`), and `function_call_output` items (`role: "tool"`).
  - `max_output_tokens` -> `max_tokens`, flat `tools` -> Chat Completions `tools[].function`, `tool_choice`, `text.format` (`json_object` / `json_schema`) -> `response_format`, `temperature`, `top_p`, `stream`, `user`, `parallel_tool_calls`.
- **Response Translation:**
  - Non-streaming (`chat_to_responses_response`): produces `object: "response"` with `status` (`completed` / `incomplete` on `length`), `output` (`message` with `output_text` + `function_call` items), and `usage.{input_tokens, output_tokens, total_tokens}`.
  - Streaming (`ChatToResponsesSseTranslator`): maintains strictly monotonic `sequence_number` (`0, 1, 2, ...`) across `response.created`, `response.in_progress`, `response.output_item.added`, `response.content_part.added`, `response.output_text.delta` / `done`, `response.content_part.done`, `response.function_call_arguments.delta` / `done`, `response.output_item.done`, and terminal `response.completed` / `response.incomplete` containing the assembled `output[]` and `usage`.

### 6. Composable Two-Stage `AdapterResponseState`

`AdapterResponseState` in `crates/shunt-ai/src/provider_adapter.rs` collapses all upstream × ingress combinations into three clean variants:
- `Passthrough` (native same-protocol zero-copy fast path)
- `Streaming { upstream: UpstreamStreamStage, ingress: IngressStreamStage }` (chunks flow `Upstream -> Canonical OpenAI SSE -> Ingress SSE`, flushing both stages in order at `end_of_stream`)
- `BufferedJson { upstream: UpstreamJsonKind, ingress: IngressResponseFormat, ... }` (buffers up to `max_non_stream_response_bytes`, converts `Upstream JSON -> Canonical OpenAI JSON -> Ingress JSON`)

---

## Alternatives Considered & Rejected

### 1. Direct N x M Pairwise Translators (`Anthropic <-> Bedrock`, `Responses <-> Gemini`, etc.)
- **Why considered:** Avoids an intermediate JSON serialization hop on cross-provider requests/responses.
- **Why rejected:** Requires maintaining 15+ bidirectional JSON and SSE/EventStream translators (30+ state machines), multiplying subtle edge-case bugs and maintenance cost. Native passthrough already eliminates translation for the two highest-volume paths (`Anthropic -> Anthropic` and `Responses -> OpenAI`), and cross-protocol translation adds only ~10–30 µs of JSON overhead against multi-hundred-millisecond LLM latencies.

### 2. Separate Plugins per Ingress Protocol (`ai-anthropic-ingress`, `ai-responses-ingress`)
- **Why considered:** Isolates each frontend in its own plugin.
- **Why rejected:** Duplicates model routing, failover state, header sanitization, and provider credentials across multiple plugin blocks in `shunt.toml`, and breaks single-route `/v1` deployment. Handling endpoint dispatch inside `ai-model-router` + `ai-provider-adapter` keeps configuration single-source-of-truth.

### 3. Stateful In-Gateway Storage for Responses `previous_response_id`
- **Why considered:** Enables server-side thread continuation even against providers like Gemini or Bedrock.
- **Why rejected:** Violates Shunt's stateless, bounded-memory data-plane guardrail (unbounded conversation storage in RAM would risk OOM). Once optional Redis/Valkey `StateStore` lands in RFC 0009, an opt-in conversation store plugin can layer cleanly on top.

---

## Verification

- **Unit tests:** Comprehensive translation, tool-call, image, structured output, error-mapping, and fragmented SSE tests in `crates/shunt-ai/src/ingress/{anthropic,responses}.rs`.
- **Conformance spec (`specs/conformance/06-multi-protocol-ingress.spec.toml`):** Verifies native passthrough, cross-provider translation (OpenAI, Ollama, Anthropic, Gemini, AWS Bedrock binary EventStream), tool calls, native error schemas, usage metrics, and cross-cloud failover for both `POST /v1/messages` and `POST /v1/responses`.
- **Property tests (`crates/shunt-ai/tests/proptest_ai.rs`):** Chunk-split invariance, Anthropic SSE lifecycle invariants, Responses SSE monotonic `sequence_number` & lifecycle invariants, composed 2-stage pipeline (`Bedrock -> Anthropic`, `Gemini -> Responses`) chunk-split invariance, and panic-freedom on arbitrary JSON/bytes.
- **Fuzz targets (`fuzz/`):** `fuzz_openai_to_anthropic_sse` and `fuzz_chat_to_responses_sse`.

---

## Future Work

- **RFC 0009:** Virtual API keys, TPM/RPM token-aware rate limiting, cost attribution & budgets, and optional distributed Redis/Valkey `StateStore`.
- **Optional `/v1/messages/count_tokens` endpoint:** Can reuse RFC 0009's token estimator when configured.
