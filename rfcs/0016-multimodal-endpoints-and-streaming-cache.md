# RFC 0016: Multimodal Endpoints, Generation Lookup & Streaming/Singleflight/Semantic AI Cache

- **Status:** Implemented
- **Crates:** `shunt-ai`, `shunt-config`, `specs/`, `examples/`, `fuzz/`

## 1. Summary

This RFC completes Shunt's endpoint breadth and AI caching layer strictly inside `shunt-ai`—with **zero changes to `shunt-engine` or `shunt-plugin-sdk`**. It adds first-class support for **`POST /v1/rerank`**, **`POST /v1/completions`**, **`POST /v1/moderations`**, **`POST /v1/images/*`**, **`POST /v1/audio/*`**, **`GET /v1/realtime` (WebSocket)**, **`/v1/files`**, **`/v1/batches`**, and **`GET /v1/generation?id=...`**, alongside **streaming SSE response caching & instant replay**, **singleflight request coalescing**, and an **opt-in semantic vector cache seam** in `ai-cache`.

## 2. Motivation

Teams migrating production workloads from LiteLLM or OpenRouter need more than chat and embeddings:

- **Multimodal & RAG pipelines:** Production AI apps depend on rerankers (`/v1/rerank` across Cohere, Jina, Voyage, vLLM, and AWS Bedrock), speech/audio (`/v1/audio/speech`, `/transcriptions`, `/translations`), image generation & editing (`/v1/images/*` including Gemini Imagen), legacy FIM (`/v1/completions`), moderation (`/v1/moderations`), asynchronous batch/file workflows (`/v1/files`, `/v1/batches`), and real-time voice WebSockets (`/v1/realtime`)—all governed by the same virtual keys, budgets, failover, and metrics.
- **Per-request generation metadata (`GET /v1/generation?id=...`):** OpenRouter-compatible clients frequently query exact token counts, latency, provider, and USD cost after a streaming or non-streaming generation completes, without standing up an external SQL database.
- **High-leverage AI caching:** Exact-match non-streaming caching misses three major production savings opportunities:
  1. **Streaming SSE responses** (`stream: true` accounts for the vast majority of interactive LLM traffic).
  2. **Thundering-herd stampedes** (concurrent identical cache misses firing duplicate expensive upstream calls).
  3. **Paraphrased / semantically equivalent prompts** where cosine similarity over embeddings can safely serve cached responses when opted in.

## 3. Goals & Non-Goals

### Goals
- **Strictly zero AI in `shunt-engine` and `shunt-plugin-sdk`:** Reuse `shunt-engine`'s existing WebSocket upgrade tunnel (`allow_websockets = true`), `StateStore`, `DistributedStore`, and RFC 0014's pooled `HttpClient`.
- **Binary-safe multipart handling:** Pure-Rust, zero-dependency RFC 7578 `multipart/form-data` parser & `model`-field rewriter so `/v1/audio/transcriptions`, `/v1/audio/translations`, `/v1/images/edits`, `/v1/images/variations`, and `/v1/files` route by model alias and enforce virtual-key ACLs without corrupting binary payloads.
- **Cross-dialect multimodal translation:**
  - `POST /v1/rerank`: native passthrough for `openai_compatible`/Cohere/Jina/vLLM, Voyage response normalization (`data[]` → `results[]`), and full AWS Bedrock Agent Runtime `/rerank` + SigV4 translation.
  - `POST /v1/images/generations`: native passthrough for OpenAI/Azure + Google Gemini / Vertex AI Imagen `:predict` translation.
  - `GET /v1/realtime`: WebSocket proxy supporting `?model=...`, `Sec-WebSocket-Protocol` (`openai-insecure-api-key.<key>`) virtual-key auth & stripping, and OpenAI / Azure Realtime upstream URI & header rewriting.
- **Zero-DB `GET /v1/generation?id=...`:** Served in `on_request_headers` by `ai-usage-tracker` from a bounded, reload-persistent `AiGenerationStore` in `StateStore` with strict virtual-key tenant isolation and `x-shunt-generation-id` response headers.
- **Lossless streaming SSE cache & instant replay:** Capture the final translated, guardrail-scrubbed `text/event-stream` wire bytes (with `stream: true` in the cache key) and replay immediately via `Flow::Respond(BufferedResponse)` with `Content-Type: text/event-stream; charset=utf-8`, `Cache-Control: no-cache`, and `x-shunt-cache: hit`.
- **Deadlock-free singleflight coalescing:** `StateStore`-backed `AiSingleflightTable` with an RAII leader drop guard so leader failures, aborts, overflows, or cancellations always wake followers cleanly.
- **Zero-bloat semantic cache seam:** Opt-in `SemanticCacheBackend` trait plus built-in `HttpClient`-backed embedding + bounded in-memory cosine-similarity LRU index (`SemanticCacheTable`) and optional external vector HTTP webhook backend—zero ONNX/FAISS dependencies and zero overhead when unconfigured.

### Non-Goals
- **Artificial SSE chunk pacing / typing-speed delays on cache hits:** Production gateways (Cloudflare AI Gateway, Portkey, Helicone) flush cached SSE streams immediately so clients get sub-ms latency while remaining 100% compliant with WHATWG EventSource and official OpenAI/Anthropic SDKs.
- **Bundling local embedding model weights into `shunt`:** Semantic caching calls an external/local embedding API (OpenAI, Ollama, vLLM) or vector sidecar over `HttpClient`, preserving the ~20 MB single binary.
- **WebSocket frame-level JSON rewriting on `/v1/realtime`:** The WebSocket upgrade handshake performs full virtual-key auth, model routing, and upstream URI/auth translation, then hands off to `shunt-engine`'s zero-copy bidirectional tunnel.

## 4. Design

### 4.1 Expanded `AiEndpointKind` & `AiCapability`
`AiEndpointKind` adds:
- `Completions` (`POST /v1/completions`)
- `Rerank` (`POST /v1/rerank`)
- `Moderations` (`POST /v1/moderations`)
- `ImagesGenerations`, `ImagesEdits`, `ImagesVariations` (`POST /v1/images/*`)
- `AudioSpeech`, `AudioTranscriptions`, `AudioTranslations` (`POST /v1/audio/*`)
- `Realtime` (`GET /v1/realtime` WebSocket upgrade)
- `Files` (`/v1/files`, `/v1/files/{id}`, `/v1/files/{id}/content`)
- `Batches` (`/v1/batches`, `/v1/batches/{id}`, `/v1/batches/{id}/cancel`)
- `GenerationRetrieve` (`GET /v1/generation?id=...`)

`AiCapability` adds `Completions`, `Rerank`, `Moderations`, `Images`, `Audio`, `Realtime`, `Files`, and `Batches` so capability guards automatically exclude incompatible fallback targets.

### 4.2 Multipart & Non-Model Endpoint Routing
- Multipart endpoints (`/v1/audio/transcriptions`, `/v1/audio/translations`, `/v1/images/edits`, `/v1/images/variations`) extract `model` via `multipart::extract_multipart_text_field` during `on_request_body_buffered`, enforce virtual-key model ACLs, and rewrite only the `model` part in `on_upstream_request` while preserving binary parts byte-for-byte.
- File & Batch CRUD endpoints (`/v1/files*`, `/v1/batches*`) have no `model` body field. `ai-model-router` resolves targets in deterministic precedence:
  1. Explicit `x-shunt-provider` header (validated against virtual-key `allowed_providers` and configured `files_targets` / `batches_targets` / `default_targets`),
  2. Configured `files_targets` or `batches_targets` on `ai-model-router`,
  3. Fallback to `default_targets`.
- `GET /v1/realtime` extracts `?model=` in `on_request_headers` (since WebSocket upgrades skip `on_request_body_buffered`), enforces virtual-key auth (including `Sec-WebSocket-Protocol: openai-insecure-api-key.<key>`) and model ACLs, strips the client key token from `Sec-WebSocket-Protocol`, and rewrites upstream path/query/auth in `on_upstream_request`.

### 4.3 `GET /v1/generation?id=...` (`AiGenerationStore`)
- `ai-usage-tracker` maintains a bounded, reload-persistent `AiGenerationStore` (default capacity: `4096` entries, configurable via `generation_store_capacity`, `0` to disable) in `StateStore`.
- On every upstream AI invocation, `ai-usage-tracker` assigns a deterministic `x-shunt-generation-id` (`gen-<request_id>`) in `on_response_headers` (when `emit_generation_id_header = true`), captures any upstream JSON/SSE `"id"` and `"finish_reason"`, reads attributed cost from `AiRecordedCost` (shared interior-mutable slot written by `ai-budget`, with optional built-in pricing fallback), and records an `AiGenerationRecord` in `on_complete` indexed by both the upstream ID (when present) and `gen-<request_id>`.
- `GET /v1/generation?id=<id>` is served directly in `ai-usage-tracker::on_request_headers` (after `ai-virtual-keys`), enforcing strict tenant isolation (`record.key_id == policy.key_id` when virtual keys are active) and returning `{ "data": { ... } }`.

### 4.4 Streaming Cache, Singleflight & Semantic Cache Seam (`ai-cache`)
- **Streaming SSE caching (`cache_streaming: bool`, default `false`):**
  - When enabled, `stream: true` requests on configured conversational/completions endpoints participate in exact-match lookup and capture.
  - Because `stream: true` is present in the canonicalized JSON body, streaming and non-streaming cache keys never collide.
  - In `on_response_body_chunk`, `ai-cache` captures the final translated, guardrail-scrubbed `text/event-stream` wire bytes (bounded by `max_entry_bytes`). If `ai-guardrails` aborts the stream or the upstream fails, the partial capture is discarded.
  - Cache hits return `Flow::Respond(BufferedResponse)` with `Content-Type: text/event-stream; charset=utf-8`, `Cache-Control: no-cache`, and `x-shunt-cache: hit`.
- **Singleflight coalescing (`singleflight: bool`, default `false`; `singleflight_timeout_ms`, default `30_000`):**
  - `AiSingleflightTable` in `StateStore` tracks in-flight cache keys using `tokio::sync::watch::channel<Option<SingleflightOutcome>>`.
  - First cache miss becomes leader and inserts an RAII `SingleflightLeaderGuard` into `ctx.extensions`; concurrent identical misses subscribe and await completion (bounded by `singleflight_timeout_ms`).
  - Leader completion in `on_complete` publishes `SingleflightOutcome::Cached(entry)` and wakes all followers immediately (`x-shunt-cache: coalesced`); dropping the guard on any error, non-200, abort, or timeout publishes `SingleflightOutcome::Failed` so followers fall through to upstream cleanly.
- **Semantic vector cache seam (`[semantic]`):**
  - Public async trait `SemanticCacheBackend` (`lookup`, `store`) with two built-in zero-bloat backends powered by `HttpClient`:
    1. `embedding_http`: extracts canonical prompt text from the request, calls a configured OpenAI/Ollama-compatible `/v1/embeddings` endpoint via `HttpClient`, and searches a bounded, reload-persistent `SemanticCacheTable` (scoped by tenant/endpoint/model/target) using pure-Rust cosine similarity against `similarity_threshold` (default `0.95`).
    2. `webhook`: delegates vector lookup and store to an external HTTP service (e.g., Qdrant/Redis VSS sidecar).
  - Semantic hits emit `x-shunt-cache: semantic_hit` and `x-shunt-cache-similarity: <score>`.

## 5. Alternatives Considered & Rejected
1. **Adding WebSocket frame rewriting or multipart parsing to `shunt-engine`:** Rejected—violates the zero-AI core invariant; `shunt-engine`'s generic `allow_websockets` tunnel and `REQUEST_BODY_BUFFERED` hook already provide everything `shunt-ai` needs.
2. **Artificial timer delays when replaying cached SSE streams:** Rejected—adds latency and holds open tasks/sockets without improving SDK compatibility.
3. **Embedding ONNX/BERT weights for local semantic caching:** Rejected—would bloat the ~20 MB binary by hundreds of megabytes; calling an existing embedding endpoint via `HttpClient` keeps `shunt` tiny and composable.

## 6. Verification
- **Unit tests:** Multipart parser/rewriter, Bedrock/Voyage rerank translators, Gemini Imagen translator, Realtime WS URI/subprotocol helpers, `AiGenerationStore` eviction & tenant isolation, cosine similarity math, and singleflight drop-guard release.
- **Integration E2E tests:** `crates/shunt-ai/tests/multimodal_and_cache_e2e.rs` covering `/v1/rerank` (Cohere + Bedrock SigV4), `/v1/completions`, `/v1/moderations`, `/v1/images/*` (OpenAI + Gemini Imagen), `/v1/audio/*` (TTS + multipart STT), live WebSocket `/v1/realtime` proxying, `/v1/files` & `/v1/batches`, `GET /v1/generation?id=...`, streaming SSE cache capture & replay, concurrent singleflight coalescing & failure release, and semantic vector cache hits via mock embeddings.
- **Property tests (`proptest`):** Multipart field-rewrite binary preservation, cosine similarity `[-1, 1]` and self-similarity invariants, and panic-freedom across rerank/Imagen/multipart parsers.
- **Fuzz target:** `fuzz_multimodal` fuzzing multipart parsing/rewriting, rerank/Imagen translators, and query/subprotocol parsers.
- **Conformance spec:** `specs/conformance/14-multimodal-and-streaming-cache.spec.toml` runnable via `shunt test`.
