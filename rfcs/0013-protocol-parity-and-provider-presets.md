# RFC 0013: Deep Protocol Parity, Provider Presets & Multi-Key Pools

- **Status:** Implemented
- **Crates:** `shunt-ai`, `specs/`, `examples/`, `fuzz/`

## 1. Summary

This RFC deepens Shunt's pure-plugin AI gateway (`shunt-ai`) to close the highest-impact protocol translation, cost accounting, and provider ergonomics gaps compared to LiteLLM and OpenRouter—with **zero changes to `shunt-engine` or `shunt-plugin-sdk`** and **zero new external dependencies**:

1. **Cross-Provider Reasoning & Thinking Translation:** Bidirectional mapping across OpenAI `reasoning_effort` / Responses `reasoning.effort`, Anthropic `thinking`, Gemini `generationConfig.thinkingConfig`, and Bedrock Converse `additionalModelRequestFields`, plus streaming/non-streaming `reasoning_content` / `thinking_delta` / `reasoning` item translation and `reasoning_tokens` accounting.
2. **Prompt-Cache Writes, Tiered Pricing & `cachePoint` Translation:** Tracks `cache_creation_input_tokens` / `cacheWriteInputTokens`, translates Anthropic `cache_control` ↔ Bedrock `cachePoint`, and extends `ModelPricing` with `cache_write_per_million_usd` and long-context tiered rates (`>200k` tokens).
3. **Structured Outputs, `drop_params` & Parameter Overrides:** Native `response_format` (`json_schema` / `json_object`) translation for Anthropic (`output_config.format`) and Bedrock (`outputConfig.textFormat`), LiteLLM-style `drop_params` (boolean dialect-aware stripping or explicit allow/strip lists), and per-provider / per-target `default_params` & `override_params`.
4. **Claude-on-Vertex & Bedrock Embeddings:** Supports Claude models hosted on Google Cloud Vertex AI (`dialect = "anthropic"` + `vertex_project`/`vertex_location` -> `rawPredict` / `streamRawPredict`) and `POST /v1/embeddings` on AWS Bedrock (Amazon Titan Embed & Cohere Embed).
5. **Built-in Provider Presets, Multi-Key Pools & BYOK Passthrough:** Built-in presets inside `ai-provider-adapter` (`openai`, `anthropic`, `gemini`, `azure_openai`, `bedrock`, `groq`, `deepseek`, `fireworks`, `together`, `mistral`, `cohere`, `xai`, `openrouter`, `ollama`, `vllm`), `StateStore`-backed multi-key upstream pools with automatic `429`/`401`/`403` rotation and `Clock`-driven cooldowns, and optional `client_passthrough` (BYOK) auth.

## 2. Motivation

Teams migrating production workloads from LiteLLM or OpenRouter to Shunt encounter five practical friction points beyond basic chat/streaming translation:

- **Reasoning models are now ubiquitous:** OpenAI (`o3`/`o4`), Anthropic (`thinking`), Gemini 2.5 (`thinkingConfig` + `thought: true`), DeepSeek (`reasoning_content`), and Bedrock all expose distinct wire formats for reasoning effort, thought deltas, and reasoning token counts.
- **Prompt caching dominates production cost:** Anthropic and Bedrock charge a separate write premium (`cache_creation_input_tokens` / `cacheWriteInputTokens`) and large-context models (Claude 4, Gemini 2.5 Pro) switch to higher tiered pricing above 200k prompt tokens. Without write and tier tracking, `ai-budget` under-reports spend.
- **Cross-provider quirks cause avoidable `400`s:** Clients sending OpenAI-specific parameters (`logprobs`, `seed`, `frequency_penalty`) or `response_format: json_schema` to Anthropic/Bedrock—or `cache_control` to OpenAI—fail unless the gateway normalizes or drops unsupported fields cleanly.
- **Cloud hosting breadth:** Enterprise GCP teams run Claude on Vertex AI alongside Gemini, and AWS shops use Bedrock Titan/Cohere embeddings on the same gateway.
- **Config boilerplate & rate-limit resilience:** Repeating `dialect`, `chat_path`, `embeddings_path`, and auth headers for Groq/DeepSeek/OpenRouter/Together is tedious, and high-throughput deployments pool multiple upstream API keys per provider to absorb `429` rate limits before failing over to a secondary provider.

## 3. Goals & Non-Goals

### Goals
- **Strictly pure-plugin:** Keep `shunt-engine` and `shunt-plugin-sdk` 100% AI-free and untouched.
- **Zero-copy fast path preserved:** Same-protocol passthrough with no parameter overrides, `drop_params = false`, and matching model name continues to skip JSON re-serialization (`Ok(None)`).
- **Pay only for what you use:** `ai-provider-adapter` enables `HookMask::ON_ROUTE` only when at least one provider configures a multi-key pool (`api_keys.len() > 1`).
- **Deterministic & reload-safe state:** Multi-key pool cursors and per-key cooldowns live in `StateStore` (`KeyPoolTable`) and use `BuildContext::clock()` so they survive hot reloads and test deterministically with `ManualClock`.
- **Automatic secret redaction:** All new credential fields (`api_key`, `api_keys`) match `shunt-config::redact_secrets` patterns automatically.

### Non-Goals
- **Dynamic cloud IAM token refresh (AWS IMDS/IRSA/STS, GCP ADC/WI, Azure Entra ID):** Intentionally split into RFC 0014 so the general-purpose `HttpClient` SDK primitive and cloud identity flows receive dedicated design and verification.
- **Implicit upstream URL generation in `shunt-config`:** Provider presets stay strictly inside `ai-provider-adapter`; `[upstreams.*]` entries remain explicit in `shunt.toml` so `shunt-config` stays AI-agnostic and network egress endpoints remain auditable.

## 4. Design

### 4.1 Cross-Provider Reasoning & Thinking Translation

Canonical OpenAI Chat Completions carries `reasoning_effort` (`"none" | "minimal" | "low" | "medium" | "high" | "xhigh"`) and optional `thinking: { type, budget_tokens }`:

- **Ingress normalization:**
  - `anthropic_to_openai_request` preserves `thinking` and derives `reasoning_effort` (`<= 2048 -> "low"`, `<= 10_000 -> "medium"`, `> 10_000 -> "high"`, `disabled -> "none"`).
  - `responses_to_chat_request` maps `reasoning.effort` -> `reasoning_effort`.
- **Upstream request translation:**
  - **Anthropic:** Maps `reasoning_effort` (`minimal`/`low` = 1024, `medium` = 4096, `high` = 16384, `xhigh` = 32768) or explicit `thinking.budget_tokens` to `thinking: { type: "enabled", budget_tokens }`, guarantees `max_tokens > budget_tokens`, and omits `temperature`/`top_p` (which Anthropic rejects with thinking enabled).
  - **Gemini:** Maps to `generationConfig.thinkingConfig = { thinkingBudget, includeThoughts: true }` (or `thinkingBudget: 0` for `"none"`).
  - **Bedrock Converse:** Emits `additionalModelRequestFields.thinking` for Claude models (with `maxTokens` bump and `temperature`/`topP` omission) and `additionalModelRequestFields.reasoning_effort` for non-Claude reasoning models.
- **Response & streaming translation:**
  - Anthropic `thinking` blocks / `thinking_delta`, Gemini `part.thought == true`, and Bedrock `reasoningContent.reasoningText.text` / `delta.reasoningContent.text` normalize into canonical OpenAI `message.reasoning_content` / `delta.reasoning_content`.
  - Anthropic ingress (`openai_to_anthropic_response` / `OpenAiToAnthropicSseTranslator`) converts `reasoning_content` back into `{ type: "thinking" }` blocks and `thinking_delta` SSE events.
  - OpenAI Responses ingress (`chat_to_responses_response` / `ChatToResponsesSseTranslator`) converts `reasoning_content` into `type: "reasoning"` output items and `response.reasoning_summary_text.delta` SSE events.
- **Usage & telemetry:** `AiUsage` and `AiUsageReport` gain `reasoning_tokens` and `cache_creation_prompt_tokens`, surfaced in Prometheus (`shunt_ai_tokens_total{kind="reasoning"|"cache_write"|"cache_read"}`) and OTel/Inspector annotations (`gen_ai.usage.reasoning_tokens`, `gen_ai.usage.cache_creation.input_tokens`).

### 4.2 Prompt-Cache Writes, Tiered Pricing & `cachePoint`

- **Token normalization:** Anthropic and Bedrock report `input_tokens` excluding cache reads/writes; translators and `ai-usage-tracker` normalize `prompt_tokens = input + cache_read + cache_creation` while retaining `cached_prompt_tokens` (`cache_read`) and `cache_creation_prompt_tokens` (`cache_write`), and populate `prompt_tokens_details.{cached_tokens, cache_creation_tokens}`.
- **`ModelPricing` extensions:** Adds `cache_write_per_million_usd` and optional long-context tier fields (`long_context_threshold_tokens`, `long_context_input_per_million_usd`, `long_context_output_per_million_usd`, `long_context_cached_input_per_million_usd`, `long_context_cache_write_per_million_usd`). `cost_nano_usd_detailed` switches to long-context rates whenever `prompt_tokens > threshold` and computes exact `u128` nano-USD across uncached input, cache-read, cache-write, and output tokens.
- **`cache_control` ↔ Bedrock `cachePoint`:** `anthropic_to_openai_request` preserves `cache_control` on system blocks, message parts, and tools; `openai_to_anthropic_request` preserves `cache_control` (keeping `system` as a block array when cached); `openai_to_bedrock_converse_request` emits `{ "cachePoint": { "type": "default" } }` immediately after any cached system block, content block, or tool spec; `rewrite_openai_request` strips `cache_control` so OpenAI-compatible upstreams never reject it.

### 4.3 Structured Outputs, `drop_params` & Parameter Overrides

- **Structured outputs:**
  - `openai_to_anthropic_request` translates `response_format: { type: "json_schema", json_schema: { schema, ... } }` into Anthropic's `output_config: { format: { type: "json_schema", schema } }` (and `json_object` into a JSON-only system instruction). `anthropic_to_openai_request` performs the inverse mapping for cross-provider routing.
  - `openai_to_bedrock_converse_request` translates `response_format: json_schema` into Bedrock's `outputConfig.textFormat = { type: "json_schema", structure: { jsonSchema: { name, description?, schema: "<json-string>" } } }`.
- **Parameter normalization:**
  - `default_params` and `override_params` are supported both per provider (`providers.<name>`) and per router target (`models.<alias>[]` / `rules[].targets[]`), applied in deterministic precedence: client body < provider defaults < target defaults < provider overrides < target overrides < `drop_params`.
  - `drop_params` accepts `true` (dialect-aware stripping of unsupported cross-provider keys, including `reasoning`-model `max_tokens -> max_completion_tokens` normalization on OpenAI `o1`/`o3`/`o4`/`gpt-5` models) or an explicit `Vec<String>` of top-level keys to remove.

### 4.4 Claude-on-Vertex & Bedrock Embeddings

- **Claude on Vertex AI:** Configuring `dialect = "anthropic"` (or `preset = "anthropic"`) together with `vertex_project` and `vertex_location` routes to `/v1/projects/{project}/locations/{location}/publishers/anthropic/models/{model}:{rawPredict|streamRawPredict}`, strips `"model"` from the JSON body, injects `"anthropic_version": "vertex-2023-10-16"` (or configured `anthropic_version`) into the body instead of an HTTP header, and supports both OpenAI/Responses translation and native `/v1/messages` ingress.
- **Bedrock Embeddings:** `POST /v1/embeddings` targeting `ProviderDialect::Bedrock` routes to `/model/{model}/invoke`, adapting Amazon Titan Embed (`inputText` + optional `dimensions`/`normalize`) and Cohere Embed (`texts`, `input_type`, v3/v4 float embeddings) cleanly to/from OpenAI `/v1/embeddings` JSON.

### 4.5 Built-in Provider Presets, Multi-Key Pools & BYOK Passthrough

- **Presets:** `preset = "groq" | "deepseek" | "fireworks" | "together" | "mistral" | "cohere" | "xai" | "openrouter" | "ollama" | "vllm" | "openai" | "anthropic" | "gemini" | "azure_openai" | "bedrock"` supplies canonical `dialect`, `chat_path`, `embeddings_path`, `responses_path`, and default auth header mapping, while allowing `api_key` / `api_keys` shorthand directly on `providers.<name>`. Explicit fields always override preset defaults.
- **Multi-Key Pools (`KeyPoolTable`):** When `api_keys` has >1 key, `ai-provider-adapter` stores per-provider round-robin cursors and cooldown timestamps in `StateStore`. On a `key_rotate_statuses` response (default `[429, 401, 403]`), the active key enters cooldown (honoring numeric `Retry-After`) and—if another uncooled key exists in the pool—`ai-provider-adapter` marks `IntraProviderKeyRetry` in `RequestCtx::extensions` and returns `Flow::RetryUpstream` before `ai-failover` runs. `ai-model-router` keeps the active target fixed for `IntraProviderKeyRetry`, and only advances to the next provider target once the pool is exhausted.
- **BYOK (`auth = { type = "client_passthrough" }`):** Extracts the caller's credential (from an optional explicit `source_header`, or standard `x-api-key` / `x-goog-api-key` / `api-key` / `Authorization: Bearer ...`), caches it in `RequestCtx::extensions` across retries, and maps it to the upstream provider's native auth header.

## 5. Alternatives Considered & Rejected

1. **Adding `ProviderDialect::VertexAnthropic` as a separate enum variant:** Rejected because Gemini on Vertex already uses `dialect = "gemini"` + `vertex_project` + `vertex_location`; using the identical pattern for `dialect = "anthropic"` keeps config orthogonal and reuses validation cleanly.
2. **Auto-generating `[upstreams.*]` from provider presets inside `shunt-config`:** Rejected to keep `shunt-config` strictly AI-agnostic and preserve explicit, auditable egress URLs and TLS/timeout settings in `[upstreams.*]`.
3. **Treating multi-key rotation as synthetic duplicate targets in `ai-model-router`:** Rejected because `ai-failover` cooldowns are keyed by `(upstream, model)`, which would erroneously cool down the whole provider when a single API key hits `429`. Handling key rotation directly inside `ai-provider-adapter` with `IntraProviderKeyRetry` isolates per-key health cleanly from provider health.

## 6. Verification

- **Unit & Integration Tests:** Reasoning/thinking request + non-stream + streaming translators (Anthropic, Gemini, Bedrock, OpenAI Responses), prompt-cache write & tiered pricing math, `cache_control` ↔ `cachePoint`, `json_schema` on Anthropic/Bedrock, `drop_params` + param overrides, Claude-on-Vertex, Bedrock Titan/Cohere embeddings, provider presets, multi-key pool rotation/cooldowns, and BYOK passthrough.
- **Property Tests (`proptest`):** Tiered/cache-write pricing invariants (monotonicity, non-overflow, clamping) and `KeyPoolTable` round-robin/cooldown invariants.
- **Conformance Spec:** `specs/conformance/11-protocol-parity-and-presets.spec.toml` exercising end-to-end reasoning translation, cache-write & tiered cost attribution, `drop_params`/`override_params`, Anthropic/Bedrock `json_schema`, Claude-on-Vertex, Bedrock embeddings, presets, multi-key `429` rotation + `ManualClock` recovery, and BYOK passthrough.
