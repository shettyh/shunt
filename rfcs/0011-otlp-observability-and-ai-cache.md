# RFC 0011: OTLP/HTTP Observability & Exact-Match AI Response Cache

- **Status:** Implemented
- **Crates:** `shunt-plugin-sdk`, `shunt-core`, `shunt-plugins`, `shunt-ai`, `shunt-config`, `shunt-cli`, `shunt-test`, `fuzz`

## 1. Summary

This RFC introduces two high-leverage production capabilities while keeping Shunt's single-binary, zero-bloat architecture intact:

1. **Zero-Dependency OTLP/HTTP JSON Tracing (`[telemetry]` + `otel-trace` + GenAI semantic attributes):** W3C `traceparent`/`tracestate` propagation and a bounded async batching OTLP/HTTP JSON trace exporter (`POST /v1/traces`) built directly on Shunt's existing `hyper` + `rustls` stack—supporting Jaeger, Grafana Tempo, Langfuse, Arize Phoenix, Honeycomb, and Datadog without pulling in heavy `opentelemetry-sdk`/`tonic`/`prost` dependencies.
2. **Exact-Match AI Response Cache (`ai-cache`):** Canonicalized JSON SHA-256 response caching for deterministic non-streaming AI workloads (`POST /v1/embeddings` and `temperature == 0` calls on `/v1/chat/completions`, `/v1/messages`, `/v1/responses`), backed by a bounded, reload-persistent in-memory LRU+TTL table with optional multi-replica Redis/Valkey sharing via `DistributedStore`.

## 2. Motivation

Teams deploying Shunt in front of LLMs and HTTP APIs face two immediate production needs:

- **End-to-end trace visibility across HTTP & GenAI stacks:** Prometheus metrics tell operators *that* latency or spend spiked, but debugging slow prompts, provider failovers, or downstream API hops requires distributed traces (`traceparent`) with OpenTelemetry HTTP and GenAI semantic attributes (`gen_ai.provider.name`, `gen_ai.request.model`, `gen_ai.usage.input_tokens`, `gen_ai.usage.output_tokens`, TTFT, cost, cache status).
- **Eliminating redundant deterministic LLM/embedding calls:** Embeddings pipelines, CI eval suites, classifiers, and agentic tool loops repeatedly send identical deterministic (`temperature = 0`) prompts. Serving exact-match hits directly from Shunt saves upstream latency, token quotas, and provider spend.

At the same time, Shunt must preserve its core guardrails: zero AI types in `shunt-core` or `shunt-plugin-sdk`, zero heavy SDK dependencies, zero hot-path blocking, and zero external sidecars required by default.

## 3. Goals & Non-Goals

### Goals
- **AI-free SDK telemetry seam:** Define `TraceContext`, `SpanRecord`, `SpanHandle`, and `TelemetrySink` in `shunt-plugin-sdk` with zero AI concepts.
- **Non-blocking OTLP/HTTP JSON exporter:** Bounded `tokio::sync::mpsc` batching exporter in `shunt-core` (`OtlpHttpExporter`) that drops excess spans under backpressure (counted via `shunt_telemetry_spans_total`) rather than stalling proxy requests, and flushes cleanly on graceful shutdown.
- **Order-independent span enrichment:** Allow `shunt-ai` plugins (`ai-usage-tracker`, `ai-budget`, `ai-cache`) to attach OpenTelemetry GenAI attributes from immutable `&RequestCtx` `on_complete` hooks regardless of whether `otel-trace` is global or per-route.
- **Safe exact-match `ai-cache`:** Cache only deterministic non-streaming `200 OK` JSON responses by default (`embeddings` always; conversational endpoints when `temperature == 0`), honor `Cache-Control: no-store`/`no-cache`, isolate tenants via `scope = "virtual_key"` by default, work across translated provider dialects (Anthropic/Gemini/Bedrock), and skip upstream token/budget charging on cache hit.
- **Multi-replica cache sharing:** Extend `DistributedStore` with `get_bytes` / `set_bytes` (`GET` / `SET ... PX` on `RedisStateStore`) and perform distributed cache writes off the hot path in `on_complete`.

### Non-Goals (Intentionally Cut)
- **Heavy OpenTelemetry gRPC/Protobuf SDK crates:** Avoid pulling `opentelemetry-sdk`, `tonic`, and `prost` (~100+ crates) when standard OTLP/HTTP JSON over `hyper` + `rustls` works with every major collector and AI observability platform.
- **Semantic / vector similarity caching:** Requires embedding stores/vector indices and introduces false-positive response risks; out of scope for the lean single binary.
- **Streaming SSE replay caching:** Interactive streaming calls are typically non-deterministic; caching non-streaming JSON + embeddings captures the vast majority of real-world value safely.
- **Hand-crafted Grafana dashboard JSON files:** Static dashboard JSON blobs rot rapidly during `v0.0.x` and cannot be meaningfully verified in CI; clean `/metrics` naming and PromQL examples are preferred.
- **Bespoke vendor sinks & file-based JSONL audit writers:** Langfuse, Arize Phoenix, Tempo, Jaeger, and ClickHouse all ingest standard OTLP/HTTP natively, and `access-log` / `ai-usage-tracker` already emit structured stdout logs.

## 4. Design

### 4.1 AI-Free Telemetry Seam (`shunt-plugin-sdk`)

- `TraceContext`: Strictly validates W3C Trace Context `traceparent` headers (`00-<32-hex>-<16-hex>-<2-hex>`), rejecting version `ff`, uppercase/invalid hex, and all-zero `trace-id`/`parent-id`. Generates guaranteed non-zero IDs with zero extra dependencies and supports deterministic `TraceIdRatioBased` sampling (`should_sample_trace_id`).
- `TelemetrySink`: Non-blocking trait (`emit_span(&self, span: SpanRecord) -> bool`) injected into plugins via `BuildContext::telemetry_sink()`.
- `SpanHandle` (RAII emission): Inserted into `RequestCtx::extensions` by `otel-trace` **only when `[telemetry]` is enabled and the request is sampled** (zero allocation on unsampled requests). `SpanHandle` wraps an interior-mutable `Arc<SpanState>` so any plugin can attach attributes from immutable `&RequestCtx` `on_complete` hooks. When `RequestCtx` drops after **all** `on_complete` hooks finish, `SpanState::drop` emits the single enriched `SpanRecord` to the `TelemetrySink`—eliminating ordering fragility between global `otel-trace` and route-scoped `ai-*` plugins.

### 4.2 Bounded Async OTLP/HTTP JSON Exporter (`shunt-core`)

`OtlpHttpExporter` accepts `SpanRecord`s via non-blocking `mpsc::Sender::try_send`, spawns its background batching worker lazily on the active Tokio runtime (so synchronous `shunt check` / `shunt verify` never spawn stray tasks), and exports standard Protobuf-JSON `ExportTraceServiceRequest` batches (`POST /v1/traces`) when `batch_size` is reached, `flush_interval` ticks, or `flush(timeout)` is called on graceful shutdown. `RuntimeRegistry` caches warm exporters across hot reloads and garbage-collects removed exporters after snapshot commit.

Exposed Prometheus counters:
- `shunt_telemetry_spans_total{backend="otlp_http",result="exported"|"dropped"|"failed"}`
- `shunt_telemetry_export_errors_total{backend="otlp_http"}`

### 4.3 `otel-trace` Plugin & GenAI Semantic Attributes

- `otel-trace` (`shunt-plugins`): Parses incoming `traceparent`/`tracestate`, propagates child `traceparent` to upstreams in `on_upstream_request`, optionally emits `x-trace-id` (`ON_RESPONSE_HEADERS` gated behind `emit_response_header`), and records OTel HTTP semantic attributes (`http.request.method`, `url.path`, `http.route`, `http.response.status_code`, `server.address`, `network.peer.address`, `shunt.*`).
- `shunt-ai` enrichment:
  - `ai-usage-tracker` attaches canonical OTel GenAI metadata (`gen_ai.operation.name`, `gen_ai.provider.name`, `gen_ai.request.model`, `gen_ai.response.model`, `gen_ai.usage.input_tokens`, `gen_ai.usage.output_tokens`, `gen_ai.usage.cache_read.input_tokens`, `shunt.ai.stream`, `shunt.ai.ttft_ms`, `shunt.ai.failovers`, `shunt.ai.routing_strategy`, `shunt.ai.key_id`, `shunt.ai.team`, `shunt.ai.cache_status`) and refines the span name to `"{op} {requested_model}"`. Prompt/completion contents are **never** exported by default.
  - `ai-budget` attaches `shunt.ai.cost_usd`.

### 4.4 Exact-Match AI Response Cache (`ai-cache`)

Recommended plugin chain placement:
```text
ai-virtual-keys -> ai-model-router -> ai-cache -> ai-token-rate-limit -> ai-budget -> ai-provider-adapter -> ai-failover -> ai-usage-tracker
```

- **Canonical cache key:** SHA-256 over `(version, tenant_scope, endpoint, requested_model, optional primary (provider, model), canonical_json_bytes(body))` where JSON object keys are recursively sorted and `-0.0`/`0.0` normalize to `0`.
- **Cacheability rules:**
  - `POST /v1/embeddings`: always deterministic.
  - `POST /v1/chat/completions`, `/v1/messages`, `/v1/responses`: non-streaming only; requires explicit `temperature == 0` when `require_deterministic = true` (default).
  - Honors client `Cache-Control: no-store` / `no-cache` / `max-age=0`, `x-shunt-cache-bypass: true`, and upstream `Cache-Control: no-store`.
- **Cross-dialect support:** When `ai-provider-adapter` translates a non-streaming Anthropic/Gemini/Bedrock response into the client's ingress schema and `AiCachePending` is active, it attaches the translated `Bytes` (zero-copy refcount clone) via `AiTranslatedResponseBody`. `ai-cache::on_complete` prefers that translated body so cached hits return the exact client schema regardless of upstream dialect.
- **Storage & eviction:** Bounded in-memory `AiCacheTable` (enforcing both `max_entries` and `max_total_bytes` via LRU + `Clock`-driven TTL) stored in `StateStore` so cache entries survive hot reloads; when `[state] backend = "redis"` is enabled and `distributed = true`, reads use `DistributedStore::get_bytes` and writes run off-hot-path via `DistributedStore::set_bytes` in `on_complete`.
- **Headers & metrics:** Emits `x-shunt-cache: hit | miss | bypass` and exports `shunt_ai_cache_requests_total{status,endpoint,model}`. On cache hit, `Flow::Respond` short-circuits before `ai-token-rate-limit`, `ai-budget`, and upstream—consuming zero quota, spend, or upstream latency.

### 4.5 Configuration & Static Verification

- `[telemetry]` section in `shunt.toml` with `env:VAR` resolution for `endpoint` and `headers`, plus header redaction in debug output and `GET /snapshot`.
- `shunt verify` adds:
  - `ai.plugin_order` (`Error`): rejects `ai-cache` placed before `ai-model-router`.
  - `ai.cache_order` (`Warning`): advises placing `ai-cache` before `ai-token-rate-limit` / `ai-budget`.
  - `telemetry.no_trace_plugin` (`Warning`): warns when `[telemetry] enabled = true` without any `otel-trace` plugin attached.

## 5. Alternatives Considered & Rejected

1. **Pulling in `opentelemetry-sdk` + `opentelemetry-otlp` + `tonic`:** Rejected because it adds 100+ transitive crates, inflates compile times and binary size, and introduces gRPC runtime complexity when OTLP/HTTP JSON over our existing `hyper` + `rustls` stack is ~400 LOC and universally supported.
2. **Emitting spans inside `otel-trace::on_complete` directly:** Rejected because global plugins run before route plugins in `on_complete`, which would cause `otel-trace` to export spans before `ai-usage-tracker` and `ai-budget` could attach token counts and cost. RAII drop on `SpanHandle` guarantees every `on_complete` plugin enriches the span cleanly regardless of placement.
3. **Synchronous Redis cache writes inside `on_response_body_chunk`:** Rejected because blocking client response completion on a Redis write adds unnecessary tail latency and risks caching aborted streams; performing writes in `on_complete` keeps client latency untouched and ensures only complete `200 OK` responses are cached.

## 6. Verification

- **Unit & E2E tests:** W3C `traceparent` parsing/formatting, `OtlpHttpExporter` JSON encoding, batch export, backpressure drop counting, multi-replica distributed `ai-cache` sharing, `verify` rules, and header redaction.
- **Conformance specs:** `specs/conformance/09-observability-and-ai-cache.spec.toml` verifying real OTLP/HTTP JSON export to an in-process mock collector (`mock://otlp_collector/v1/traces`), GenAI attributes, cache miss/hit/bypass, embeddings, translated Anthropic caching, tenant isolation, and deterministic TTL expiry via `ManualClock`.
- **Property tests (`proptest`):** W3C `traceparent` parser crash-freedom & round-trip invariants, ratio sampler monotonicity, canonical JSON key permutation invariance, and `AiCacheTable` strict entry/byte capacity bounds.
- **Fuzz target:** `fuzz/fuzz_targets/fuzz_traceparent.rs` targeting untrusted HTTP `traceparent` parsing.
