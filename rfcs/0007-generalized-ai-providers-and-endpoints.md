# RFC 0007: Generalized AI Providers & Expanded OpenAI Endpoints

- **Status:** Implemented
- **Crates:** `shunt-ai`, `shunt-plugin-sdk`, `shunt-engine`, `shunt-test`, `fuzz`

## Summary

RFC 0007 evolves `shunt-ai` from its initial two-provider (`OpenAi` | `Anthropic`) vertical slice (RFC 0004) into a **generalized, named-provider AI gateway** supporting:
1. Arbitrary **OpenAI-compatible providers** (Ollama, vLLM, SGLang, Groq, DeepSeek, Fireworks, Together, Mistral, xAI, OpenRouter, etc.) via declarative provider instances.
2. First-class cloud & frontier protocol dialects: **Google Gemini** (AI Studio & Vertex AI), **Azure OpenAI**, and **AWS Bedrock** (Converse & ConverseStream with pure-Rust SigV4 signing and binary AWS EventStream decoding).
3. Expanded OpenAI-compatible API surface: **`GET /v1/models`** (synthesized from configured aliases/rules) and **`POST /v1/embeddings`**.

All AI concepts remain strictly isolated inside `shunt-ai`; the only transport-level addition to `shunt-plugin-sdk` / `shunt-engine` is exposing the resolved upstream endpoint URI on `UpstreamRequest` so request-signing plugins (such as AWS SigV4) can sign against the exact target authority.

## Motivation

In `v0.0.1`, `shunt-ai` has two structural limitations that block real-world adoption as a self-hosted LiteLLM / OpenRouter alternative:

1. **Closed 2-variant provider model:** `AiProvider` is a hardcoded enum (`OpenAi | Anthropic`) and `ai-provider-adapter` only accepts a single `openai` block and a single `anthropic` block. Teams cannot configure multiple OpenAI-compatible backends with distinct credentials (e.g., OpenAI + Groq + local Ollama + internal vLLM), nor route to Gemini, Azure OpenAI, or AWS Bedrock.
2. **Chat-only API surface:** Real SDKs, coding agents, and RAG pipelines routinely call `GET /v1/models` (for model discovery in IDE/agent UIs) and `POST /v1/embeddings` alongside `POST /v1/chat/completions`.

Addressing both in RFC 0007 delivers Phase A1 of [docs/vision.md](../docs/vision.md) with a single, clean provider schema—taking advantage of `v0.0.x` to make a clean break instead of carrying legacy config shims.

## Goals & Non-Goals

### Goals
- **Named provider registry:** Decouple *provider instance name* (e.g., `"ollama"`, `"groq"`, `"openai-prod"`, `"gemini-us"`, `"bedrock-east"`) from *wire protocol dialect* (`openai_compatible`, `anthropic`, `azure_openai`, `gemini`, `bedrock`).
- **Single canonical config schema:** Use one unified `providers.<name>` map in `ai-provider-adapter` (no legacy top-level `openai`/`anthropic` shims), migrating repo examples, tests, and conformance specs cleanly.
- **Zero AI leakage into `shunt-engine`:** Keep `shunt-engine` and `shunt-plugin-sdk` strictly AI-agnostic.
- **Zero heavy cloud SDK dependencies:** Implement AWS SigV4 signing and binary AWS EventStream framing in small, pure-Rust modules so the `shunt` release binary stays ~20 MB and compiles fast.
- **Expanded endpoints:** Support `GET /v1/models` (and `GET /v1/models/{id}`) and `POST /v1/embeddings` seamlessly on either a unified `/v1` route or dedicated per-endpoint routes.
- **Order-independent usage accounting:** Extend `ai-usage-tracker` to recognize OpenAI, Anthropic, Gemini, Bedrock, and Embeddings usage fields regardless of plugin ordering.
- **Layered verification (RFC 0006):** Back every new protocol translator and binary/SSE framer with declarative TOML conformance specs (`shunt test`), property tests, and fuzz targets.

### Non-Goals
- **Anthropic `/v1/messages` ingress & OpenAI `/v1/responses`** — deferred to **RFC 0008 (Multi-Protocol AI Ingress)** so bidirectional frontends are designed cleanly on top of this provider registry.
- **Virtual API keys, TPM rate limits, spend budgets, and Redis `StateStore`** — deferred to **RFC 0009**.
- **Weighted / TTFT / cost-aware routing** — deferred to **RFC 0010** (though this RFC introduces lightweight endpoint capability tagging that RFC 0010 builds on).
- **GCP Service Account JWT token exchange / AWS STS IMDS credential chains:** In v1 of the cloud adapters, credentials are supplied via `env:` secrets (static/rotated bearer tokens or AWS SigV4 env credentials) to avoid adding blocking background network refreshers to the zero-dependency default path. Async credential refreshers can plug into the same `ProviderAuth` seam later.

---

## Design

### 1. General-Purpose SDK Primitive (`shunt-plugin-sdk` + `shunt-engine`)

AWS SigV4 signing requires computing the canonical `host` header (and any endpoint base path) from the exact upstream endpoint selected for the current attempt—including when testing against a local mock (`http://127.0.0.1:<port>`) or failing over across multi-endpoint pools.

Today, `shunt-engine` resolves `base_uri` in Stage 4 right before invoking `on_upstream_request`, but `UpstreamRequest` does not carry it. RFC 0007 adds one AI-agnostic field to `UpstreamRequest`:

```rust
pub struct UpstreamRequest {
    pub method: Method,
    pub uri: Uri,
    pub headers: HeaderMap,
    pub body: Option<Bytes>,
    /// Resolved base URI of the selected upstream endpoint for this attempt
    /// (e.g., `https://bedrock-runtime.us-east-1.amazonaws.com` or `http://127.0.0.1:18080`).
    /// Populated by `shunt-engine` prior to `on_upstream_request` so signing/auth plugins
    /// can inspect the exact target scheme, authority, and base path.
    pub endpoint_uri: Option<Uri>,
}
```

**Why this belongs in `shunt-plugin-sdk`:** Any request-signing plugin (AWS SigV4 for S3/Bedrock/API Gateway, HMAC signing, audience-scoped JWT minting) needs the exact resolved upstream authority. Keeping it `Option<Uri>` preserves ergonomics in unit tests and adds zero allocation overhead to routes that do not opt into `ON_UPSTREAM_REQUEST`.

---

### 2. Core Data Model Changes (`crates/shunt-ai/src/types.rs`)

#### Replacing the Closed `AiProvider` Enum

Instead of a closed two-variant enum:

```rust
/// Wire protocol dialect spoken by an upstream provider instance.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderDialect {
    #[serde(alias = "openai")]
    OpenAiCompatible,
    Anthropic,
    #[serde(alias = "azure")]
    AzureOpenAi,
    Gemini,
    Bedrock,
}

/// Logical AI API operation parsed from the incoming request path/method.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AiEndpointKind {
    ChatCompletions,
    Embeddings,
    ModelsList,
    ModelRetrieve,
}

/// Optional capability flags declared per provider/target so incompatible targets
/// are filtered out cleanly (e.g., skipping Anthropic on `/v1/embeddings`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AiCapability {
    Chat,
    Streaming,
    Tools,
    Vision,
    Embeddings,
}
```

`AiTarget`, `FailoverEvent`, and `AiUsage` switch from `provider: AiProvider` to `provider: String` (the named provider ID such as `"openai"`, `"ollama"`, `"groq"`, `"gemini"`, `"bedrock"`):

```rust
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AiTarget {
    /// Named provider ID matching an entry in `ai-provider-adapter`'s `providers` map.
    pub provider: String,
    pub upstream: String,
    pub model: String,
    pub endpoint_override: Option<String>,
    /// Optional capability override; when empty, defaults apply per endpoint/dialect.
    pub capabilities: Vec<AiCapability>,
}

#[derive(Debug, Clone)]
pub struct AiRequestMeta {
    pub endpoint: AiEndpointKind,
    pub requested_model: String,
    pub stream: bool,
    pub targets: Vec<AiTarget>,
    pub active_target_index: usize,
    pub max_attempts: usize,
}
```

Prometheus labels (`provider="..."`, `from_provider="..."`, `to_provider="..."`) and response headers (`x-shunt-provider`) automatically emit the named provider ID (e.g., `groq`, `ollama`, `bedrock-east`), giving operators clear per-backend visibility out of the box.

---

### 3. Provider Configuration & Secret Redaction

#### Declarative `providers` Map in `ai-provider-adapter`

```toml
[[routes.plugins]]
name = "ai-provider-adapter"
[routes.plugins.config]
response_headers = true

# Standard OpenAI
[routes.plugins.config.providers.openai]
dialect = "openai_compatible"
auth = { type = "bearer", api_key = "env:OPENAI_API_KEY" }
organization = "org-..."
include_stream_usage = true

# Local Ollama / vLLM / SGLang (no auth required)
[routes.plugins.config.providers.ollama]
dialect = "openai_compatible"
chat_path = "/v1/chat/completions"
embeddings_path = "/v1/embeddings"
auth = { type = "none" }
include_stream_usage = false

# Groq / DeepSeek / Fireworks / OpenRouter (OpenAI-compatible)
[routes.plugins.config.providers.groq]
dialect = "openai_compatible"
chat_path = "/openai/v1/chat/completions"
auth = { type = "bearer", api_key = "env:GROQ_API_KEY" }

# Anthropic
[routes.plugins.config.providers.anthropic]
dialect = "anthropic"
auth = { type = "header", header = "x-api-key", api_key = "env:ANTHROPIC_API_KEY" }
anthropic_version = "2023-06-01"
default_max_tokens = 4096

# Azure OpenAI
[routes.plugins.config.providers.azure]
dialect = "azure_openai"
api_version = "2024-10-21"
auth = { type = "header", header = "api-key", api_key = "env:AZURE_OPENAI_API_KEY" }
# Or Microsoft Entra ID:
# auth = { type = "bearer", api_key = "env:AZURE_ENTRA_TOKEN" }

# Google Gemini (AI Studio)
[routes.plugins.config.providers.gemini]
dialect = "gemini"
auth = { type = "header", header = "x-goog-api-key", api_key = "env:GEMINI_API_KEY" }

# Google Gemini (Vertex AI)
[routes.plugins.config.providers.vertex]
dialect = "gemini"
vertex_project = "my-gcp-project"
vertex_location = "us-central1"
auth = { type = "bearer", api_key = "env:VERTEX_ACCESS_TOKEN" }

# AWS Bedrock (Converse / ConverseStream)
[routes.plugins.config.providers.bedrock]
dialect = "bedrock"
region = "us-east-1"
auth = { type = "aws_sigv4", access_key_id = "env:AWS_ACCESS_KEY_ID", secret_access_key = "env:AWS_SECRET_ACCESS_KEY", session_token = "env:AWS_SESSION_TOKEN" }
# Or Bedrock API Key:
# auth = { type = "bearer", api_key = "env:AWS_BEARER_TOKEN_BEDROCK" }
```

#### Clean Schema (No Legacy Shims)
At `v0.0.x`, `shunt-ai` has no external production configs to preserve. Top-level `openai` and `anthropic` blocks in `ai-provider-adapter` are removed in favor of the single `providers.<name>` map, keeping config parsing, validation, and documentation unambiguous. Existing repo examples (`examples/shunt-ai.toml`), tests, and conformance specs (`specs/conformance/03-ai-gateway-contract.spec.toml`) are updated directly to the canonical schema.

#### Automatic Secret Redaction Invariant
Notice that every secret field in `ProviderAuthConfig` is named `api_key`, `secret_access_key`, or `session_token`—all of which match `shunt-config::ir::redact_secrets` (`api_key`, `secret`, `token`). As a result, `GET /snapshot` automatically redacts **every** provider credential across all dialects with zero changes required to `shunt-config`.

---

### 4. Protocol Dialect Specifications

Each dialect is encapsulated behind a clean internal adapter interface inside `crates/shunt-ai/src/dialects/`:

| Dialect | Chat Path | Embeddings Path | Auth | Streaming Wire Format |
| --- | --- | --- | --- | --- |
| `openai_compatible` | `/v1/chat/completions` (configurable) | `/v1/embeddings` (configurable) | `None` / `Bearer` / custom header | OpenAI SSE (passthrough) |
| `anthropic` | `/v1/messages` (configurable) | *Unsupported* (400/501) | `x-api-key` + `anthropic-version` | Anthropic SSE -> OpenAI SSE |
| `azure_openai` | `/openai/deployments/{model}/chat/completions?api-version={ver}` | `/openai/deployments/{model}/embeddings?api-version={ver}` | `api-key` header or `Bearer` (Entra) | OpenAI SSE (passthrough) |
| `gemini` (AI Studio) | `/v1beta/models/{model}:generateContent` / `:streamGenerateContent?alt=sse` | `/v1beta/models/{model}:embedContent` / `:batchEmbedContents` | `x-goog-api-key` header (never query param) | Gemini SSE -> OpenAI SSE |
| `gemini` (Vertex AI) | `/v1/projects/{proj}/locations/{loc}/publishers/google/models/{model}:generateContent` (or `:streamGenerateContent?alt=sse`) | `/v1/projects/{proj}/locations/{loc}/publishers/google/models/{model}:predict` | `Authorization: Bearer` | Gemini SSE -> OpenAI SSE |
| `bedrock` | `/model/{url_encoded_model}/converse` / `/converse-stream` | *Optional / Titan/Cohere follow-up; returns structured 501 in v1* | AWS SigV4 (`AWS4-HMAC-SHA256`) or Bedrock `Bearer` | Binary AWS EventStream -> OpenAI SSE |

#### 4.1 `openai_compatible` Dialect
- Supports `chat_path` (default `/v1/chat/completions`), `embeddings_path` (default `/v1/embeddings`), `include_stream_usage` (default `true`, can be disabled for servers like older Ollama/vLLM that reject `stream_options`), optional `organization`/`project`, and `extra_headers`.
- Rewrites `"model"` in the JSON body to `target.model` for both chat and embeddings requests.
- Zero-copy passthrough on responses (both JSON and SSE).

#### 4.2 `azure_openai` Dialect
- Uses `target.model` as the Azure `{deployment}` name (percent-encoded for URI safety) and appends `?api-version={api_version}` (default `"2024-10-21"`).
- Reuses `openai_compatible` request rewriting and zero-copy response passthrough.
- Strips `"model"` optionally or keeps it (Azure ignores or accepts it depending on API version; rewriting to `target.model` is safe and consistent).

#### 4.3 `gemini` Dialect (`crates/shunt-ai/src/dialects/gemini.rs`)
- **Chat Request Translation (OpenAI -> Gemini `generateContent`):**
  - `system` / `developer` messages -> top-level `systemInstruction.parts`.
  - `user` / `assistant` messages -> `contents[]` with roles `"user"` / `"model"`; supports text parts and `image_url` (base64 data URIs -> `inlineData`, HTTPS URLs -> `fileData`).
  - `tools` (`type: "function"`) -> `tools[0].functionDeclarations[]` (recursively stripping unsupported JSON Schema fields like `$schema` / `additionalProperties` when needed).
  - `tool_calls` (assistant) -> `functionCall` parts; `role: "tool"` messages -> `user` message with `functionResponse` parts matched by `tool_call_id` -> function name map.
  - Generation parameters: `temperature`, `top_p`, `max_tokens` / `max_completion_tokens` -> `maxOutputTokens`, `stop` -> `stopSequences`, `response_format` (`json_object` / `json_schema`) -> `responseMimeType` + `responseSchema`.
- **Chat Response Translation (Gemini -> OpenAI):**
  - Non-streaming JSON: maps `candidates[0].content.parts` (`text`, `functionCall`) to `choices[0].message`, maps `finishReason` (`STOP` -> `"stop"`, `MAX_TOKENS` -> `"length"`, `SAFETY`/`RECITATION` -> `"content_filter"`, tool call presence -> `"tool_calls"`), and maps `usageMetadata` (`promptTokenCount`, `candidatesTokenCount`, `totalTokenCount`) to OpenAI `usage`.
  - Streaming SSE (`?alt=sse`): `GeminiSseTranslator` parses standard SSE frames via `SseParser`, emits OpenAI `chat.completion.chunk` deltas incrementally (including `tool_calls` deltas with synthetic call IDs), emits final `finish_reason` + `usage` chunk, and terminates with `data: [DONE]\n\n`.
  - Error mapping: Gemini `{"error":{"code":...,"message":...,"status":...}}` -> standard OpenAI error JSON.
- **Embeddings Translation:**
  - Single string/token input -> `:embedContent` (`content.parts[{text}]`), or array of inputs -> `:batchEmbedContents` (`requests[]`), mapping `embedding.values` / `embeddings[].values` into OpenAI `{"object":"list","data":[{"object":"embedding","index":i,"embedding":[...]}],"model":...,"usage":{...}}`.
  - Vertex AI embeddings use `:predict` (`{"instances":[{"content":...}]}`) -> `predictions[].embeddings.values`.

#### 4.4 `bedrock` Dialect (`crates/shunt-ai/src/dialects/bedrock.rs`, `aws_sigv4.rs`, `aws_eventstream.rs`)
- **Why Converse API:** Bedrock's `Converse` / `ConverseStream` API provides a single uniform schema across Claude, Llama, Nova, Mistral, and Titan models hosted on Bedrock—avoiding per-model payload sprawl.
- **Chat Request Translation (OpenAI -> Bedrock Converse):**
  - `system` / `developer` messages -> top-level `system: [{"text": ...}]`.
  - `user` / `assistant` messages -> `messages[]` with `content` blocks (`text`, `image` for base64 data URIs, `toolUse`, `toolResult`).
  - `tools` -> `toolConfig.tools[].toolSpec` (`name`, `description`, `inputSchema.json`).
  - `temperature`, `top_p`, `max_tokens` / `max_completion_tokens` -> `inferenceConfig` (`temperature`, `topP`, `maxTokens`, `stopSequences`).
- **Chat Response Translation:**
  - Non-streaming JSON: maps `output.message.content` (`text`, `toolUse`), `stopReason` (`end_turn` -> `"stop"`, `max_tokens` -> `"length"`, `tool_use` -> `"tool_calls"`, `content_filtered`/`guardrail_intervened` -> `"content_filter"`), and `usage` (`inputTokens`, `outputTokens`, `totalTokens`).
  - Streaming (`ConverseStream`): Bedrock returns `Content-Type: application/vnd.amazon.eventstream` binary frames rather than SSE.
    - `AwsEventStreamDecoder` incrementally buffers arbitrary TCP chunks, validates the 4-byte prelude CRC32 and trailing 4-byte message CRC32 (IEEE polynomial `0xEDB88320`), parses typed event headers (`:message-type`, `:event-type`, `:exception-type`), and yields decoded JSON payloads.
    - `BedrockStreamTranslator` converts `messageStart`, `contentBlockStart` (`toolUse`), `contentBlockDelta` (`text`, `toolUse.input`), `contentBlockStop`, `messageStop`, and `metadata` (usage) into live OpenAI `chat.completion.chunk` SSE frames and terminates with `data: [DONE]\n\n`, while rewriting downstream `Content-Type` to `text/event-stream; charset=utf-8`.
- **Pure-Rust AWS SigV4 Signer (`aws_sigv4.rs`):**
  - Uses `sha2` (already in workspace) + `hmac` (zero AWS SDK bloat).
  - Derives `host` from `UpstreamRequest.endpoint_uri` (respecting non-default ports for local mock tests!), URI-encodes Bedrock model IDs (which contain `:`, e.g., `anthropic.claude-3-5-sonnet-20241022-v2:0`) according to AWS SigV4 double-encoding rules for non-S3 services, computes `x-amz-content-sha256`, `x-amz-date`, optional `x-amz-security-token`, and attaches `Authorization: AWS4-HMAC-SHA256 ...`.
  - Uses `Clock` (or `SystemTime` with injectable timestamp for deterministic tests) and is verified against official AWS SigV4 test suite vectors.

---

### 5. Expanded OpenAI Endpoints (`GET /v1/models` & `POST /v1/embeddings`)

#### Unified Route OR Per-Endpoint Routes

`ai-model-router` adds `HookMask::ON_REQUEST_HEADERS` to inspect `(req.method, req.uri.path())`:

```text
Incoming Request
  │
  ├─ GET /v1/models
  │    └─ [ai-model-router::on_request_headers]
  │         short-circuit Flow::Respond(200 JSON {"object":"list","data":[...]})
  │         (zero body buffering, zero upstream hop!)
  │
  ├─ GET /v1/models/{model_id}
  │    └─ [ai-model-router::on_request_headers]
  │         if configured -> 200 JSON {"id":...,"object":"model",...}
  │         else          -> 404 OpenAI error JSON (`model_not_found`)
  │
  ├─ POST /v1/embeddings
  │    └─ [ai-model-router::on_request_headers] -> tag AiEndpointKind::Embeddings
  │       [ai-model-router::on_request_body_buffered] -> parse `model` (stream = false),
  │         resolve targets (excluding targets explicitly lacking `embeddings`)
  │       [ai-provider-adapter] -> rewrite path/body for embeddings dialect
  │       [ai-usage-tracker] -> record prompt_tokens / total_tokens
  │
  └─ POST /v1/chat/completions (default)
       └─ [ai-model-router::on_request_headers] -> tag AiEndpointKind::ChatCompletions
          [ai-model-router::on_request_body_buffered] -> parse `model` + `stream`
          ... existing chat pipeline ...
```

This design supports **both** deployment styles:
- **Single ergonomic route** in `shunt.toml`: `path_prefix = "/v1"`, `methods = ["GET", "POST"]` — one plugin chain serves `/v1/models`, `/v1/chat/completions`, and `/v1/embeddings` with a single model catalog.
- **Granular per-endpoint routes**: `path_exact = "/v1/chat/completions"`, `path_exact = "/v1/embeddings"`, `path_exact = "/v1/models"` — allowing independent timeouts (e.g., 5s timeout for embeddings vs. 60s for chat).

#### Synthesizing `GET /v1/models`
- Built deterministically at snapshot compilation time (sorted by `id`, zero per-request sorting/allocation beyond cloning pre-serialized `Bytes`!).
- Sources model entries from:
  1. Every explicit key in `models` (aliases like `"smart"`, `"fast"`, `"embed-default"`), with `owned_by` set to the primary target's provider name (or `"shunt"`).
  2. Any explicit concrete `model` names referenced inside `rules` targets (wildcard patterns themselves like `"claude-*"` are not emitted as literal model IDs unless explicitly listed in an optional `exposed_models` list).
  3. Optional `exposed_models` array in `ai-model-router` config for advertising wildcard-routed models (e.g., `["gpt-4o", "claude-3-5-sonnet-20241022", "gemini-2.5-flash"]`).
- Returns standard OpenAI `{"object": "list", "data": [{"id": "...", "object": "model", "created": 0, "owned_by": "..."}]}`.

#### Handling `POST /v1/embeddings`
- `ai-model-router` extracts `"model"` (does not require `"messages"` and forces `stream = false`).
- If a model resolves to targets where a dialect does not support embeddings (e.g., Anthropic), `ai-provider-adapter` returns a clear OpenAI-formatted `400 invalid_request_error` (`code: "unsupported_endpoint"`)—or if capability filtering is configured on targets, `ai-model-router` selects only embedding-capable targets up front.
- `ai-usage-tracker` records `prompt_tokens` and `total_tokens` (with `completion_tokens = None`) and logs/exports metrics identically.

---

### 6. Order-Independent `ai-usage-tracker` Updates

`extract_usage_from_json` and `contains_first_token` in `crates/shunt-ai/src/usage_tracker.rs` are extended to recognize:
- **OpenAI** (chat & embeddings): `usage.{prompt_tokens, completion_tokens, total_tokens}`
- **Anthropic**: `usage.{input_tokens, output_tokens}`, `message.usage.{input_tokens, output_tokens}`
- **Gemini**: `usageMetadata.{promptTokenCount, candidatesTokenCount, totalTokenCount}`, first token on `candidates[].content.parts[]` (`text` / `functionCall`)
- **Bedrock Converse**: `usage.{inputTokens, outputTokens, totalTokens}` (and translated OpenAI SSE chunks when `ai-usage-tracker` runs after `ai-provider-adapter`).

---

## Alternatives Considered & Rejected

### 1. Using Official Cloud SDKs (`aws-sdk-bedrockruntime`, `google-cloud-*`)
- **Why considered:** Offloads SigV4 signing, EventStream framing, and cloud auth chains.
- **Why rejected:** Pulls in 100+ transitive crates, adds tens of megabytes to the binary, slows builds dramatically, and bypasses `shunt-engine`'s warm connection pool, passive health tracking, split TTFB/idle-chunk timeouts, and `shunt test` mock transport. Keeping all upstream HTTP I/O flowing through `shunt-engine` preserves Shunt's sub-ms overhead, 20 MB binary footprint, and full testability.

### 2. Hardcoding a Giant Enum for Every Vendor (`OpenAi | Anthropic | Groq | Ollama | DeepSeek | ...`)
- **Why considered:** Simple match statements and compile-time exhaustive checks.
- **Why rejected:** Every new OpenAI-compatible vendor or self-hosted cluster would require modifying Rust code and cutting a Shunt release, and users still couldn't configure two separate OpenAI/vLLM clusters with different keys or headers. Separating **named provider instances** from **5 wire protocol dialects** solves both permanently.

### 3. Passing Gemini API Keys via `?key=...` Query Parameters
- **Why considered:** Commonly shown in Gemini quickstart examples.
- **Why rejected:** Query strings frequently leak into proxy access logs, error diagnostics, and upstream URLs. Using the officially supported `x-goog-api-key` header keeps secrets strictly out of URIs and protected by header sanitization and `GET /snapshot` redaction.

### 4. Separate Plugin for `GET /v1/models` (`ai-models-endpoint`)
- **Why considered:** Smaller single-purpose plugin.
- **Why rejected:** Would force users to duplicate their model alias list across two plugin configs in `shunt.toml` and risk drift between `/v1/models` and what `ai-model-router` actually accepts. Synthesizing `/v1/models` directly from `ai-model-router`'s compiled catalog guarantees single-source-of-truth accuracy (and can be disabled via `serve_models_endpoint = false`).

---

## Verification & Implementation Plan

To keep PRs reviewable, fast, and continuously verified under RFC 0006, RFC 0007 is split into **two implementation slices**:

### Slice 1 — Generalized Provider Registry, `openai_compatible`, `/v1/models` & `/v1/embeddings`
1. **`shunt-plugin-sdk` & `shunt-engine`:** Add `UpstreamRequest.endpoint_uri: Option<Uri>` populated from `base_uri` in `pipeline.rs`.
2. **`shunt-ai` core refactor:**
   - Replace closed `AiProvider` enum with `ProviderDialect` + named `String` provider IDs on `AiTarget`, `FailoverEvent`, and `AiUsage`.
   - Replace top-level `openai`/`anthropic` config blocks with the unified `providers` map + `ProviderAuthConfig` (`none`, `bearer`, `header`) in `ai-provider-adapter`.
   - Add `AiEndpointKind`, `GET /v1/models` + `GET /v1/models/{id}` pre-serialized synthesis, and `POST /v1/embeddings` routing & adapter support.
3. **Verification:**
   - Migrate `examples/shunt-ai.toml`, `specs/conformance/03-ai-gateway-contract.spec.toml`, and existing unit/integration/`proptest_ai` tests to the canonical `providers.<name>` schema.
   - Add `specs/conformance/05-ai-providers-and-endpoints.spec.toml` covering custom OpenAI-compatible providers (Ollama/Groq-style), cross-provider failover, `GET /v1/models`, and `POST /v1/embeddings`.

### Slice 2 — Cloud & Frontier Adapters (Azure OpenAI, Google Gemini, AWS Bedrock)
1. **Azure OpenAI dialect:** Deployment URI construction + `?api-version=` + `api-key`/Entra auth for chat (JSON & SSE) and embeddings.
2. **Google Gemini dialect (AI Studio & Vertex AI):** Request/response/SSE/embeddings translators (`dialects/gemini.rs`), `usageMetadata` extraction, property tests for arbitrary SSE chunk splits, and `fuzz/fuzz_targets/fuzz_gemini_sse.rs`.
3. **AWS Bedrock dialect:**
   - `aws_sigv4.rs` (verified against official AWS SigV4 test vectors).
   - `aws_eventstream.rs` (incremental binary decoder with CRC32 validation, arbitrary chunk-split property tests, and `fuzz/fuzz_targets/fuzz_aws_eventstream.rs`).
   - `dialects/bedrock.rs` (Converse JSON + ConverseStream binary -> OpenAI SSE translation).
4. **Verification & Docs:**
   - Expand `specs/conformance/05-ai-providers-and-endpoints.spec.toml` with mock Azure, Gemini (JSON + SSE + embeddings), and Bedrock (Converse JSON + binary ConverseStream + SigV4 header assertions + cross-cloud failover).
   - Add multi-provider example config in `examples/shunt-ai-multi-provider.toml`.
   - Run `cargo fmt`, `cargo clippy --workspace --all-targets --locked -- -D warnings`, `cargo test --workspace --locked`, and `shunt verify` / `shunt test`.

---

## Future Work

- **RFC 0008 (Multi-Protocol AI Ingress):** Expose Anthropic `POST /v1/messages` and OpenAI `POST /v1/responses` frontends backed by the exact same `ProviderDialect` registry introduced here.
- **Dynamic cloud credential refreshers:** Optional async GCP service-account JWT / AWS STS token refreshers plugged into `ProviderAuth`.
- **Bedrock Embeddings:** Model-specific embeddings payloads (Titan Text Embeddings v2, Cohere Embed) once Converse-style unified embeddings or per-model Bedrock adapters are requested.
