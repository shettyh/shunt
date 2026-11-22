# RFC 0014: Dynamic Cloud IAM Auth & Outbound `HttpClient` Primitive

- **Status:** Implemented
- **Crates:** `shunt-plugin-sdk`, `shunt-core`, `shunt-ai`, `shunt-test`, `specs/`, `examples/`, `fuzz/`

## 1. Summary

This RFC introduces a general-purpose, strictly AI-free outbound [`HttpClient`] primitive in `shunt-plugin-sdk` backed by `shunt-core`'s pooled `hyper` + `rustls` stack, and uses it inside `shunt-ai` (`ai-provider-adapter`) to deliver zero-SDK, auto-refreshing cloud IAM authentication across **AWS** (EC2 IMDSv2, ECS Task Role, EKS IRSA / `AssumeRoleWithWebIdentity`, STS `AssumeRole`), **Google Cloud** (GCE/GKE Metadata Server / Workload Identity, Service Account RS256 JWT OAuth2, ADC Authorized User), and **Azure Entra ID** (Managed Identity IMDS, `client_credentials`, AKS Workload Identity).

## 2. Motivation

Production VPC and Kubernetes deployments rarely permit static long-lived API keys or static AWS IAM user keys:

- **AWS Bedrock** workloads run on EC2 (IMDSv2), ECS (Task Role), or EKS (IRSA projected OIDC token files), often chaining into a cross-account IAM role via STS `AssumeRole`.
- **Google Cloud Vertex AI** (Gemini and Claude-on-Vertex) expects short-lived OAuth2 Bearer tokens obtained from the GCE/GKE metadata server (Workload Identity), a Service Account JSON private key (RS256 JWT assertion), or Application Default Credentials (`authorized_user`).
- **Azure OpenAI / Azure AI Foundry** enterprises authenticate with Microsoft Entra ID Bearer tokens (`https://cognitiveservices.azure.com/.default`) via Managed Identity, AKS Workload Identity, or Service Principal `client_credentials`.

At the same time, upcoming Shunt capabilities (RFC 0015 external guardrails/webhooks and RFC 0018 JWKS/OIDC verification) also need a clean, bounded, reload-persistent sideband HTTP client without pulling `reqwest` or leaking `hyper` into `shunt-plugin-sdk`.

## 3. Goals & Non-Goals

### Goals
- **AI-free SDK primitive:** Add `HttpClient`, `HttpRequest`, `HttpResponse`, and `HttpClientError` to `shunt-plugin-sdk` with zero AI concepts and zero `hyper` types exposed.
- **Zero new external SDK bloat:** Implement `CoreHttpClient` on `shunt-core`'s existing `ShuntConnector` (`hyper` + `rustls` + `webpki-roots`), and implement AWS STS XML parsing, GCP RS256 PKCS#8 JWT signing (reusing `ring` already compiled by `rustls`), and Azure Entra ID exchanges directly in `shunt-ai`—zero cloud SDK dependencies.
- **Zero-allocation warm fast path:** Static auth and **warm cached dynamic cloud tokens** execute synchronously via `HookResult::Ready`; only cache misses and proactive/reactive refreshes return `HookResult::Pending`.
- **Singleflight coalescing & stale-while-valid resilience:** Concurrent requests hitting an expiring token coalesce onto one outbound refresh via a cancellation-safe gate. If a proactive refresh fails transiently while the cached token is still valid, Shunt continues serving with the valid token rather than failing traffic.
- **Reload-persistent & deterministic:** `CloudTokenCache` lives in `StateStore`, keyed by `(provider_name, config_fingerprint)`, and uses `BuildContext::clock()` so tokens survive hot reloads of unchanged configs, invalidate immediately when auth config changes, and test deterministically with `ManualClock`.
- **Reactive revocation recovery:** If an upstream rejects a cached dynamic token with `401` (or `403` on AWS SigV4), `ai-provider-adapter` invalidates the cached credential and performs at most one automatic re-fetch retry per request.
- **Automatic secret redaction:** All credential fields (`credentials_json`, `credentials_file`, `client_secret`, `ecs_auth_token`, `web_identity_token_file`, `federated_token_file`) match `shunt-config::redact_secrets` patterns automatically.

### Non-Goals
- **Cloud-provider SDK embedding (`aws-sdk-*`, `google-cloud-*`, `azure_identity`):** Rejected to preserve Shunt's tiny binary size, fast compile times, and auditable dependency tree.
- **Streaming outbound responses on `HttpClient`:** Sideband calls (IAM token exchange, JWKS, policy webhooks) use bounded buffered bodies (`max_response_bytes`, default 4 MiB). Streaming can be added separately if ever required.

## 4. Design

### 4.1 Outbound `HttpClient` Primitive (`shunt-plugin-sdk` + `shunt-core`)

`shunt-plugin-sdk` defines:

```rust
pub trait HttpClient: fmt::Debug + Send + Sync + 'static {
    fn send<'a>(
        &'a self,
        request: HttpRequest,
    ) -> BoxFuture<'a, Result<HttpResponse, HttpClientError>>;
}
```

- `HttpRequest` carries `method`, `uri`, `headers`, `body: Bytes`, optional per-request `timeout`, and optional `max_response_bytes`.
- `BuildContext::http_client(&self) -> Option<Arc<dyn HttpClient>>` exposes the shared client to plugins during `PluginFactory::build`.
- `shunt-core::CoreHttpClient` implements `HttpClient` on top of `hyper_util::client::legacy::Client<ShuntConnector, Full<Bytes>>`, enforcing absolute `http://`/`https://` URIs, end-to-end timeouts, and incremental frame-by-frame response size caps (`ResponseTooLarge`).
- `RuntimeRegistry` lazily creates and retains a single warm `CoreHttpClient` (with `with_http_client(...)` override for tests) and attaches it to every `BuildSession`.

### 4.2 Reload-Persistent `CloudTokenCache` & Singleflight Gate (`shunt-ai`)

`CloudTokenCache` is stored in `StateStore` under `"ai_cloud_tokens"`:

- **Key:** `"{provider_name}::{sha256_config_fingerprint}"` — hot reloads with identical auth config reuse warm cached credentials; changing `role_arn`, `scope`, `tenant_id`, or endpoints immediately starts fresh.
- **Expiration & margin:** Each entry records monotonic `fetched_at` and `ttl` relative to `Clock::now()`.
  - `effective_margin = configured_margin.min(ttl / 2)` (so short-lived tokens still cache cleanly)
  - `now < fetched_at + ttl - effective_margin` → **Fresh** (sync `HookResult::Ready`)
  - `now < fetched_at + ttl` → **Stale-while-valid** (async refresh; falls back to cached credential if refresh fails)
  - `now >= fetched_at + ttl` → **Expired** (async refresh required; returns `503 cloud_auth_failed` on error)
- **Cancellation-safe singleflight:** A zero-dependency per-key `SingleflightGate` ensures only one coroutine refreshes a given provider's token at a time; waiting callers wake and re-check the cache immediately upon completion or cancellation.
- **Observability:** `inspect_ai_runtime` exposes non-secret `cloud_tokens` entries (`provider`, `auth_kind`, `cached`, `expires_in_ms`, `refresh_count`, `error_count`, `last_error`) on `GET /api/status`.

### 4.3 Cloud Provider Auth Variants (`ai-provider-adapter`)

`ProviderAuthConfig` gains three variants:

1. **`auth.type = "aws_iam"`** (produces `AwsSigV4Credentials` with `session_token` for `sign_upstream_request`):
   - `mode`: `"auto"` (default) | `"env"` | `"web_identity"` | `"ecs"` | `"imds"`
   - **IMDSv2:** `PUT /latest/api/token` → `GET /latest/meta-data/iam/security-credentials/` → `GET /latest/meta-data/iam/security-credentials/{role}`
   - **ECS Task Role:** `GET {ecs_credentials_uri}` (resolving `AWS_CONTAINER_CREDENTIALS_FULL_URI` or `AWS_CONTAINER_CREDENTIALS_RELATIVE_URI` + optional `AWS_CONTAINER_AUTHORIZATION_TOKEN(_FILE)`)
   - **EKS IRSA (`web_identity`):** Re-reads `web_identity_token_file` (`AWS_WEB_IDENTITY_TOKEN_FILE`) on every refresh and calls unsigned `POST {sts_endpoint}/` with `Action=AssumeRoleWithWebIdentity`
   - **STS `AssumeRole` chaining:** When `role_arn` is set on `env`/`ecs`/`imds` (or `auto` resolving via those), signs `POST {sts_endpoint}/` (`Action=AssumeRole`, optional `ExternalId`/`DurationSeconds`) using `shunt-ai`'s existing `aws_sigv4::sign_canonical` with `service = "sts"`.
   - `auto` chain order: `env` → `web_identity` → `ecs` → `imds` (+ optional `AssumeRole`).
   - `providers.<name>.region` also supports `env:VAR` expansion (e.g., `region = "env:AWS_REGION"`).

2. **`auth.type = "gcp_iam"`** (injects `Authorization: Bearer <access_token>`):
   - `mode`: `"auto"` (default) | `"metadata"` | `"service_account"` | `"authorized_user"`
   - **Metadata Server / GKE Workload Identity:** `GET {metadata_endpoint}/computeMetadata/v1/instance/service-accounts/{email}/token?scopes=...` with `Metadata-Flavor: Google`
   - **Service Account JSON (`RS256` JWT):** Pure-Rust PKCS#8 PEM decoder + `ring::signature::RsaKeyPair::from_pkcs8` (`RSA_PKCS1_SHA256`) signing a 1-hour JWT assertion exchanged at `token_uri` (`grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer`)
   - **ADC Authorized User:** OAuth2 `grant_type=refresh_token` exchange for `gcloud auth application-default login` credentials
   - `auto` chain order: `credentials_json` → `credentials_file` / `GOOGLE_APPLICATION_CREDENTIALS` → `metadata`.

3. **`auth.type = "azure_ad"`** (injects `Authorization: Bearer <access_token>`):
   - `mode`: `"auto"` (default) | `"managed_identity"` | `"client_credentials"` | `"workload_identity"`
   - Default `scope = "https://cognitiveservices.azure.com/.default"` (and IMDS `resource` derived automatically by stripping `/.default`)
   - **Managed Identity (IMDS):** `GET {imds_endpoint}/metadata/identity/oauth2/token?api-version=2018-02-01&resource=...[&client_id=...]` with `Metadata: true` (handles both integer and stringified `expires_in`)
   - **Service Principal (`client_credentials`):** `POST {authority_host}/{tenant_id}/oauth2/v2.0/token`
   - **AKS Workload Identity (`workload_identity`):** Re-reads `federated_token_file` (`AZURE_FEDERATED_TOKEN_FILE`) on each refresh and posts `client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer`
   - `auto` chain order: `workload_identity` → `client_credentials` → `managed_identity`.

## 5. Alternatives Considered & Rejected

1. **Pulling `aws-config` / `gcp_auth` / `azure_identity` crates:** Rejected—would add dozens of transitive dependencies, pull in `reqwest`/`openssl`/heavy proc macros, break single-binary leanness, and duplicate TLS stacks alongside `shunt-core`.
2. **Spawning background refresh timers inside `ai-provider-adapter`:** Rejected—background tasks complicate hot-reload lifecycle, leak across `shunt check` / ephemeral snapshots, and break deterministic `ManualClock` testing. On-demand singleflight refresh with stale-while-valid fallback achieves equal resilience with zero background threads.
3. **Making `ai-provider-adapter` construct its own `hyper` client:** Rejected—violates Shunt's crate isolation rule (`shunt-ai` must depend strictly on `shunt-plugin-sdk`, never on `shunt-core` or `hyper`).

## 6. Verification

- **Unit tests:** `CoreHttpClient` (HTTP GET/POST, timeouts, body cap, URI validation), every AWS/GCP/Azure flow, RS256 JWT cryptographic signature verification, singleflight concurrency coalescing, stale-while-valid fallback, clock-driven expiry, reactive `401` invalidation, and `ManualClock` determinism.
- **Property tests (`proptest`):** RFC 3339 UTC timestamp parser invariants, STS XML parser safety/round-trips, and `CloudTokenCache` TTL/margin state invariants.
- **Fuzz target:** `fuzz_cloud_auth_parsers` fuzzing STS XML parsing, RFC 3339 timestamp parsing, PKCS#8 PEM decoding, and cloud token JSON parsing.
- **Conformance spec:** `specs/conformance/12-cloud-iam-auth.spec.toml` verifying AWS IMDSv2, ECS + STS `AssumeRole`, EKS IRSA, GCP Metadata, GCP Service Account RS256 JWT, Azure Managed Identity, Azure `client_credentials`, caching, `ManualClock` expiry refresh, reload persistence, reactive `401` refresh retry, and secret redaction end-to-end against in-process mocks.
