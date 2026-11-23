# RFC 0004: `shunt-ai` — Multi-Provider AI Gateway as a Pure Plugin Pack

- **Status:** Implemented
- **Crates:** `shunt-ai`

## Summary

`shunt-ai` implements an OpenAI-compatible multi-provider AI gateway (supporting OpenAI and Anthropic backends, non-streaming JSON and live SSE streaming, automatic `429`/`5xx` failover, stateful cooldowns, and token/TTFT accounting) **strictly as a plugin pack on top of `shunt-plugin-sdk`**, with zero AI concepts or dependencies inside `shunt-engine`.

## Motivation

AI gateways exercise the hardest primitives in an HTTP proxy simultaneously:
- Routing based on a JSON body field (`"model"`), not just URL paths.
- Per-attempt request translation across incompatible upstream APIs (OpenAI `/v1/chat/completions` ↔ Anthropic `/v1/messages`).
- Failover across providers on `429` / `5xx` / `529` / transport errors without corrupting the canonical request.
- Live chunk-by-chunk SSE protocol translation across arbitrary TCP packet boundaries.
- Long-lived streams requiring split TTFB vs. idle-chunk timeouts and accurate Time-To-First-Token (TTFT) + token usage accounting.

Building `shunt-ai` strictly through `shunt-plugin-sdk` serves a dual purpose: delivering a genuinely useful AI router *and* proving that `shunt-engine`'s general-purpose primitives are complete without special-casing AI.

## Goals & Non-Goals

### Goals
- Zero dependency on `shunt-engine` or `hyper` in `crates/shunt-ai/Cargo.toml`'s `[dependencies]`.
- Unified OpenAI-compatible frontend: `POST /v1/chat/completions` (both JSON and `text/event-stream`).
- Clean composable 4-plugin split (`ai-model-router`, `ai-provider-adapter`, `ai-failover`, `ai-usage-tracker`) communicating via typed `RequestCtx::extensions`.
- Support OpenAI and Anthropic (text, system/developer prompts, images, tool calls / `tool_use` / `tool_result`, stop sequences, error schema mapping).
- Order-independent usage tracking (works whether `ai-usage-tracker` runs before or after `ai-provider-adapter`).
- Reload-safe provider cooldowns via `StateStore` and Prometheus metrics via `GET /metrics`.

### Non-Goals
- Full provider catalog (Bedrock, Vertex, Gemini, Cohere) in v1—the adapter pattern makes adding providers straightforward in follow-up work.
- Semantic caching, prompt guardrails, or billing/cost ledger persistence (these fit cleanly as additional plugins on the same `AiRequestMeta` / `AiUsage` extensions).

## Design

### 1. Plugin Composition & Extension Flow

```text
Client: POST /v1/chat/completions (OpenAI JSON)
  │
  ├─ [ai-model-router]
  │    • on_request_body_buffered: parse `model` + `stream`, resolve fallback chain
  │      -> insert AiRequestMeta into ctx.extensions (400/404 OpenAI error on failure)
  │    • on_route: set decision.upstream & raise decision.max_attempts >= targets.len()
  │    • on_upstream_select: select targets[(attempt - 1) % len], set upstream
  │
  ├─ [ai-failover] (when cooldown_ms > 0)
  │    • on_upstream_select: skip targets currently in StateStore cooldown
  │
  ├─ [ai-provider-adapter]
  │    • on_upstream_request:
  │        - strip client auth headers; set Accept-Encoding: identity
  │        - OpenAI: inject Bearer key, rewrite model, inject stream_options.include_usage
  │        - Anthropic: inject x-api-key + anthropic-version, rewrite URI -> /v1/messages,
  │          translate OpenAI JSON -> Anthropic Messages JSON
  │    • on_response_headers: attach x-shunt-{provider,model,attempt}; init SSE/JSON state
  │
  ├─ [ai-failover]
  │    • on_response_headers: on 429/5xx/529, record FailoverEvent (+ optional cooldown),
  │      return Flow::RetryUpstream if ctx.attempt < max_attempts
  │      -> shunt-engine replays canonical OpenAI body on next attempt!
  │
  ├─ [ai-provider-adapter]
  │    • on_response_body_chunk:
  │        - OpenAI: zero-work Passthrough
  │        - Anthropic SSE: live AnthropicSseTranslator -> OpenAI chat.completion.chunk SSE
  │          (incl. tool_calls deltas, finish_reason, final usage chunk, data: [DONE])
  │        - Anthropic JSON: bounded buffer -> translate to OpenAI JSON on end_of_stream
  │
  └─ [ai-usage-tracker]
       • on_response_body_chunk (read-only): parse OpenAI OR Anthropic JSON/SSE frames,
         record first_token_at (true TTFT) + prompt/completion/total tokens in AiUsage
       • on_complete: emit AiUsageReport -> AiMetrics (Prometheus) + structured tracing log
```

### 2. Subtle Protocol Invariants Solved

- **Disabling upstream compression (`Accept-Encoding: identity`):** If a downstream client sends `Accept-Encoding: gzip`, an upstream returning compressed bytes would break both SSE translation and JSON usage inspection. `ai-provider-adapter` normalizes `Accept-Encoding` to `identity` on every upstream attempt.
- **Arbitrary chunk-boundary SSE framing (`SseParser`):** HTTP chunks can split mid-line, mid-JSON, or use `\r\n` vs. `\n`. `SseParser` maintains a per-request byte buffer and flushes trailing frames on `end_of_stream = true`.
- **Anthropic strict schema requirements:**
  - `max_tokens` is mandatory in Anthropic's API (optional in OpenAI) → falls back to `max_completion_tokens`, then configurable `default_max_tokens` (4096).
  - Consecutive same-role messages (e.g., multiple `role: "tool"` responses) are merged into a single Anthropic `user` message with multiple `tool_result` blocks.
  - Non-2xx Anthropic error payloads (`{"type":"error","error":{...}}`) are translated into OpenAI error JSON (`{"error":{...}}`).
- **True TTFT vs. TTFB:** For SSE streams, `ai-usage-tracker` records `first_token_at` on the first non-empty content or tool-call delta chunk rather than HTTP header arrival, falling back to `summary.ttfb` for non-streaming requests.
- **No warning spam on exhausted retries:** `ai-model-router` records `selection.max_attempts` on `AiRequestMeta`, so `ai-failover` only returns `Flow::RetryUpstream` while `ctx.attempt < max_attempts` and otherwise lets the final upstream error return cleanly to the caller.

### 3. Prometheus Metrics Exposed via `GET /metrics`

- `shunt_ai_requests_total{provider,model,stream,status}` (counter)
- `shunt_ai_tokens_total{provider,model,kind="prompt"|"completion"}` (counter)
- `shunt_ai_failovers_total{from_provider,to_provider,model}` (counter)
- `shunt_ai_ttft_seconds{provider,model,stream}` (histogram)
- `shunt_ai_request_duration_seconds{provider,model,stream}` (histogram)

## Alternatives Considered & Rejected

### 1. Single Monolithic `shunt-ai` Plugin
- **Why considered:** Fewer config blocks in `shunt.toml`; no need to share state through `ctx.extensions`.
- **Why rejected:** Prevents mixing and matching (e.g., using `ai-usage-tracker` without `ai-failover`, or plugging in a custom third-party router or token-rate-limiter between `ai-model-router` and `ai-provider-adapter`). Splitting into 4 focused plugins proves `ctx.extensions` composability and gives clear per-plugin timings in `shunt dev`.

### 2. Adding a Dedicated `RESPONSE_BODY_BUFFERED` Hook to `shunt-engine`
- **Why considered:** Would simplify non-streaming Anthropic JSON translation.
- **Why rejected:** Non-streaming vs. streaming is only known dynamically per request (via JSON `"stream"` and response `Content-Type`), not statically at route-compilation time. Handling bounded non-streaming buffering inside `ai-provider-adapter::on_response_body_chunk` (returning empty `Bytes` until `end_of_stream = true`) keeps `shunt-engine` smaller and lets a single route serve both JSON and SSE seamlessly.

### 3. Passing Client API Keys Directly to Upstreams
- **Why considered:** Zero secret config in `shunt.toml`.
- **Why rejected:** Breaks multi-provider failover (an OpenAI client key cannot authenticate against Anthropic) and violates gateway key-isolation best practices. Gateway auth (`bearer-auth`) is cleanly separated from upstream provider credentials (`env:OPENAI_API_KEY`, `env:ANTHROPIC_API_KEY`), and `GET /snapshot` automatically redacts all `api_key` fields.

## Future Work

- Additional provider adapters (Google Gemini, AWS Bedrock, Azure OpenAI, local Ollama/vLLM).
- Token-per-minute (TPM) rate-limiting plugin built on `StateStore` + `AiUsage`.
- Responses API (`/v1/responses`) and Embeddings (`/v1/embeddings`) translation support.
