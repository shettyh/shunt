# RFC 0015: Pluggable AI Guardrails (`ai-guardrails`), Redacted Audit Sinks (`ai-audit`) & Alert Webhooks (`ai-alerts`)

- **Status:** Implemented
- **Crates:** `shunt-plugin-sdk`, `shunt-core`, `shunt-config`, `shunt-ai`, `specs/`, `examples/`, `fuzz/`

## 1. Summary

This RFC adds production AI safety, compliance auditing, and operational alerting to Shunt as three composable, strictly SDK-based plugins inside `shunt-ai`—**`ai-guardrails`**, **`ai-audit`**, and **`ai-alerts`**—plus a minimal, strictly AI-free **OTLP `SpanEvent`** primitive in `shunt-plugin-sdk` and `shunt-core`. Every external callout (guardrail APIs, audit webhooks, and Slack/PagerDuty/HTTP alerts) reuses RFC 0014's pooled `HttpClient`, preserving Shunt's zero-AI core and single-binary leanness.

## 2. Motivation

Enterprise AI gateway deployments cannot ship to production on routing and cost controls alone:

- **Sensitive data leakage & prompt safety:** Teams need fast inline PII & credential detection/redaction (emails, SSNs, Luhn-validated credit cards, AWS/OpenAI/Anthropic/GitHub/Stripe/Slack/GCP keys, JWTs, private keys), custom regex/keyword/policy rules, and async callouts to dedicated safety services (OPA, Microsoft Presidio, Lakera Guard, AWS Bedrock Guardrails, Llama Guard, or internal webhooks) on requests, non-streaming responses, and live SSE streams.
- **Compliance & audit trails:** Regulated teams need redacted prompt/completion audit logs written off the hot path to JSONL files, OpenTelemetry GenAI span events (`gen_ai.content.prompt` / `gen_ai.content.completion`), or HMAC-signed webhooks—without risking raw secret exposure or blocking inference latency.
- **Operational alerting:** Platform engineers need deduplicated real-time alerts in Slack, PagerDuty, or HTTP webhooks when virtual-key/team budgets cross soft/hard thresholds, upstream circuit breakers open, failover chains exhaust, or guardrails block traffic.

## 3. Goals & Non-Goals

### Goals
- **Strictly AI-free SDK/core addition:** Add only general-purpose `SpanEvent` support to `shunt-plugin-sdk` (`SpanRecord::events`, `SpanHandle::add_event`, `RequestCtx::add_span_event`) and OTLP JSON serialization in `shunt-core::otlp`.
- **Zero-allocation sync fast path & pay-only-for-what-you-use:**
  - `ai-guardrails` stays synchronous (`HookResult::Ready`) whenever no external callouts apply to a stage, and omits `HookMask::RESPONSE_BODY_STREAM` for request-only configurations.
  - `ai-audit` adapts its `HookMask` to `include_prompt` / `include_completion` / `include_headers`, and performs all disk/HTTP sink I/O off the hot path over bounded non-blocking queues.
  - `ai-alerts` hooks **only** `HookMask::ON_COMPLETE` and dispatches over a bounded non-blocking queue.
- **Cross-protocol & streaming parity:** Protocol-aware text extraction and in-place redaction across OpenAI `/v1/chat/completions`, Anthropic `/v1/messages`, OpenAI `/v1/responses`, and `/v1/embeddings`—including rolling-window & holdback SSE streaming inspection to catch secrets split across consecutive SSE chunks.
- **Zero external guardrail/alert SDK bloat:** All 6 external guardrail adapters (Webhook, OPA, Presidio, Lakera, Bedrock Guardrails with pure-Rust AWS SigV4, Llama Guard) and 3 alert formatters (Slack, PagerDuty Events v2, HMAC-SHA256-signed HTTP) run directly over `BuildContext::http_client()` and `ring`.
- **Reload-persistent stats, dedup & secret redaction:** Runtime counters (`guardrails`, `audit_sinks`, `alert_sinks`) and `AlertDedupTable` live in `StateStore`, test deterministically with `ManualClock`, expose read-only snapshots on `GET /api/status` and Prometheus `/metrics`, and redact all secrets (`api_key`, `signing_secret`, `routing_key`, `aws_secret_access_key`) on `GET /snapshot`.

### Non-Goals
- **Bundling local ML/NLP inference weights (ONNX/BERT) into `shunt`:** Rejected to keep the single binary tiny (~20 MB) and startup sub-50 ms; semantic/ML classifiers plug in cleanly via `ai-guardrails` external callouts (`presidio`, `lakera`, `bedrock_guardrails`, `llama_guard`, `webhook`).
- **Synchronous blocking audit writes:** Audit sinks are strictly bounded non-blocking queues that drop excess events under extreme backpressure rather than stalling user traffic.

## 4. Design

### 4.1 AI-Free OTLP Span Events (`shunt-plugin-sdk` + `shunt-core`)
- `SpanEvent { name, time_unix_nanos, attributes }` is appended to `SpanRecord::events`.
- `RequestCtx::add_span_event(name, attributes)` is a zero-cost no-op when no sampled `SpanHandle` is attached.
- `shunt-core::otlp::encode_single_span` emits `"events": [...]` per OTLP/HTTP JSON spec only when non-empty.

### 4.2 `ai-guardrails`
- **Built-in detectors & presets:** `pii` (`email`, `ssn` with SSA range checks, `credit_card` with Luhn validation, `phone`, `ip_address` with IPv4 octet validation), `secrets` (`private_key`, `aws_access_key`, `anthropic_api_key`, `openai_api_key`, `github_token`, `stripe_key`, `slack_token`, `gcp_api_key`, `jwt`, `bearer_token`), and `prompt_injection`.
- **Custom rules & policies:** Linear-time ReDoS-safe `regex_rules` (compiled with bounded `size_limit`), `keyword_rules`, and `policy` (`max_prompt_chars`, `max_messages`, `blocked_roles`, `skip_roles`, `allowed_models`, `skip_models`).
- **Actions & redaction modes:** `allow` | `warn` | `redact` (`mask`, `hash`, `partial`) | `block` (formatted natively for OpenAI or Anthropic ingress).
- **Streaming SSE protection:** Bounded `stream_holdback_chars` catches and redacts secrets split across SSE chunks; rolling `stream_overlap_chars` and periodic `stream_window_chars` drive local and external `stream` callouts; `on_stream_violation` supports `redact_and_stop` (protocol-native content-filter terminator) or `abort` (`StreamFlow::Abort`).
- **Cache safety:** Non-streaming response blocks clear `AiCachePending` / `AiTranslatedResponseBody` so blocked outputs are never cached; redactions update `AiTranslatedResponseBody` so only scrubbed outputs enter `ai-cache`.

### 4.3 `ai-audit`
- Captures bounded prompt & completion text (JSON and SSE), scrubs PII/secrets via `LocalRedactor` prior to emission, filters forbidden auth headers (`Authorization`, `x-api-key`, `cookie`, etc.), and emits structured `AuditRecord`s in `on_complete` to:
  1. `jsonl`: bounded non-blocking background writer with optional `max_file_bytes` rotation (`<path>.1`).
  2. `otlp_events`: emits `gen_ai.content.prompt` and `gen_ai.content.completion` span events onto the active OTLP span.
  3. `webhook`: bounded batching background worker over `HttpClient` with optional `X-Shunt-Signature-256: sha256=<hex>` HMAC-SHA256 signing.

### 4.4 `ai-alerts` & Interior-Mutable `AiAlertBus`
- `ai-budget` (pre-flight soft/hard rejections AND post-response threshold crossings in `on_complete`), `ai-failover` (`circuit_breaker_open` on cooldown activation and `failover_exhausted`), and `ai-guardrails` (`guardrail_block`) push typed `AiAlertEvent`s onto a per-request `AiAlertBus` (`Arc<Mutex<Vec<AiAlertEvent>>>`).
- `ai-alerts::on_complete` deduplicates per `(target, kind, dedup_key)` via `StateStore`-backed `AlertDedupTable` + `Clock::now()` and dispatches asynchronously to **Slack**, **PagerDuty Events API v2**, and **HMAC-SHA256-signed HTTP** webhooks.

### 4.5 Recommended Plugin Order & Static Verification
`shunt verify` (`crates/shunt-config/src/verify.rs`) validates ordering with `ai.guardrails_order`, `ai.audit_order`, and `ai.alerts_order` warnings. Recommended chain:
`otel-trace` → `ai-virtual-keys` → `ai-model-router` → `ai-provider-adapter` → `ai-guardrails` → `ai-cache` → `ai-token-rate-limit` → `ai-budget` → `ai-failover` → `ai-usage-tracker` → `ai-audit` → `ai-alerts`.

## 5. Alternatives Considered & Rejected
1. **Embedding a single monolithic "governance" plugin:** Rejected—splitting `ai-guardrails`, `ai-audit`, and `ai-alerts` lets routes pay only for the hooks they need (e.g., `ai-alerts` adds zero request/response body hooks).
2. **Blocking `on_complete` on webhook/file I/O:** Rejected—would couple client tail latency and connection teardown to external Slack/SIEM latency; bounded non-blocking queues isolate failures cleanly.

## 6. Verification
- **Unit tests:** Luhn/SSN/IPv4 validators, PII/secret redactors (`mask`/`hash`/`partial`), prompt-injection rules, all 6 external guardrail response parsers, HMAC-SHA256 RFC 4231 test vector, Slack/PagerDuty/HTTP alert formatters, `AlertDedupTable`, UTF-8 audit truncation, and OTLP `SpanEvent` JSON encoding.
- **Integration E2E tests:** `crates/shunt-ai/tests/guardrails_audit_alerts_e2e.rs` verifying inline & SSE split-chunk redaction, prompt-injection blocking, Bedrock Guardrails AWS SigV4 signing, JSONL file output, OTLP GenAI span events on a mock collector, HMAC-signed audit & alert webhooks, Slack/PagerDuty payloads, and `ManualClock` alert deduplication.
- **Property tests (`proptest`):** Luhn generator/single-digit corruption invariants, redactor non-leakage & idempotence, and panic-freedom across all external guardrail parsers & text extractors.
- **Fuzz target:** `fuzz_guardrails` fuzzing detectors, validators, redactors, extractors, and all 6 external guardrail response parsers.
- **Conformance spec:** `specs/conformance/13-guardrails-audit-and-alerts.spec.toml` runnable via `shunt test`.
