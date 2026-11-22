# RFC 0018: JWT/OIDC Auth, HTTP Gateway Security, Response Compression & Kubernetes Gateway API

- **Status:** Implemented
- **Crates:** `shunt-plugin-sdk`, `shunt-core`, `shunt-plugins`, `shunt-config`, `shunt-cli`, `specs/`, `examples/`, `fuzz/`

## 1. Summary

This RFC inaugurates **Path B (Phases B1–B2)**—turning Shunt into a full-featured, developer-first modern HTTP API Gateway on the exact same lean data plane and plugin SDK that power `shunt-ai`. It introduces:

1. **Pure-Rust JWT / JWKS / OIDC Authentication (`jwt-auth`):** Zero external JWT/transport crates; verifies `HS256/384/512`, `RS256/384/512`, `PS256/384/512`, `ES256/384`, and `EdDSA` via `ring`, with `HttpClient`-backed OIDC Discovery (`/.well-known/openid-configuration`) & `StateStore`-cached JWKS refresh (singleflight coalesced, unknown-`kid` rotation with anti-DoS cooldown, sync zero-alloc warm fast path), RFC 7519 claim/scope/audience/issuer/skew checks, and anti-spoofing claim header forwarding.
2. **HTTP Security & Traffic Plugins (`ip-filter`, `mtls-auth`, `body-limit`, `redirect`):**
   - `ip-filter`: IPv4/IPv6 CIDR allow/deny rules (`deny_first` / `allow_first`), IPv4-mapped IPv6 normalization, and secure right-to-left `X-Forwarded-For` traversal with `trusted_proxies`.
   - Mutual TLS (`ClientAuthMode::Optional | Required`) in `shunt-core` with zero-downtime Client CA hot reloads (`ArcSwap<TlsAcceptor>`), panic-free pure-Rust X.509 DER metadata extraction (`ClientCertInfo` on `RequestCtx`), and the `mtls-auth` authorization plugin (CN, SAN DNS, SPIFFE SAN URI, SHA-256 fingerprint).
   - Zero-copy streaming request body size enforcement (`LimitedIncomingBody` in `shunt-core`) paired with the `body-limit` plugin for fast `413` rejection on both `Content-Length` and chunked/HTTP2 streams.
   - `redirect` plugin and `header-rewrite` URL/Host rewrite extensions (`upstream_host`, `path_replace_full`, `path_replace_prefix`).
3. **Streaming-Safe Response Compression (`compression`):** Negotiates `zstd`, `br`, `gzip`, and `deflate` via RFC 9110 `Accept-Encoding` q-values, compresses incrementally chunk-by-chunk, weakens strong `ETag`s (`W/"..."`), appends `Vary: Accept-Encoding`, and unconditionally skips `text/event-stream` (SSE), `Cache-Control: no-transform`, already-encoded responses, media/archives, and bodies below `min_size_bytes`.
4. **Zero-Bloat Kubernetes Gateway API v1 `ConfigProvider` (`shunt-config::k8s`):** Compiles `GatewayClass`, `Gateway`, `HTTPRoute`, `Service`, `Endpoints`, `EndpointSlice`, and TLS `Secret` resources (including exact/prefix/header/method matching, Gateway API precedence sorting, hostname intersection, `allowedRoutes` namespace policy, canary weight LCM scaling, filters, and in-memory TLS Secrets) into Shunt's canonical `GatewayConfig`—supporting both static manifest files (`--k8s-manifest`) and live Kubernetes API sync/hot-reloads (`--k8s-gateway`) using `HttpClient` with zero `kube-rs` bloat.

## 2. Motivation

With Path A (RFCs 0007–0017) achieving production AI gateway parity, teams deploying Shunt in front of both LLM endpoints and standard microservices need core API gateway capabilities—OIDC/JWT auth, CIDR IP filtering, mTLS workload identity, streaming body caps, response compression, and native Kubernetes Gateway API ingress—without sacrificing Shunt's single-binary ~20 MB footprint or sub-millisecond fast path.

## 3. Goals & Non-Goals

### Goals
- **Zero-bloat cryptography & Kubernetes integration:** Reuse `ring` for all 12 JWS algorithms and `HttpClient` + `serde_json`/`serde_yaml` for Kubernetes Gateway API—avoiding `kube-rs`, `k8s-openapi`, and heavy JWT crate trees.
- **Pay only for what you use:** `client_cert` is `None` on non-mTLS listeners (`Arc`-cloned per request on mTLS); `RouteMatch.headers` and `LimitedIncomingBody` incur zero cost when unconfigured; `jwt-auth` runs synchronously (`HookResult::Ready`) whenever the JWKS cache is warm.
- **Atomic hot reloads everywhere:** Server SNI certs, mTLS client CAs, K8s TLS Secrets, and K8s `HTTPRoute`/`Service`/`Endpoints` updates swap atomically with zero downtime.
- **SSE & streaming safety by default:** `compression` never buffers full responses and never compresses `text/event-stream` or `multipart/*`.

### Non-Goals
- **Writing Kubernetes status subresources back to the API server:** Read-only data-plane compilation keeps RBAC strictly read-only (`get`/`list`), minimizing cluster blast radius; controller status reporting can layer on later without changing the compiler.
- **L4 `TCPRoute` / `UDPRoute` / `TLSRoute` passthrough:** Scoped cleanly to HTTP/HTTPS `Gateway` + `HTTPRoute` v1 resources.

## 4. Design

### 4.1 Core & SDK Primitives
- **`ClientCertInfo` (`shunt-plugin-sdk`):** Added `pub client_cert: Option<Arc<ClientCertInfo>>` to `RequestCtx` carrying `subject_cn`, `subject_dn`, `issuer_dn`, `san_dns`, `san_uris`, `san_emails`, `serial_hex`, and `sha256_fingerprint`.
- **mTLS & Hot CA Rotation (`shunt-core::tls` & `server.rs`):** `TlsListenerConfig` accepts `Option<ClientAuthConfig>` (`ClientAuthMode::None | Optional | Required` + PEM CA bundle). `GatewayServer` wraps `TlsAcceptor` in `ArcSwap<TlsAcceptor>` so `ServerReloader::reload_client_auth` atomically swaps client CA roots for all subsequent handshakes without dropping active connections. Leaf peer DER certificates are parsed once per TLS connection via a panic-free pure-Rust ASN.1 DER extractor (`parse_client_cert_info`).
- **Streaming Body Caps (`shunt-core::body` & `pipeline.rs`):** `CompiledRoute::explicit_max_body_bytes` enforces explicit route or plugin `max_request_body_bytes()` caps upfront via `Content-Length` AND on unbuffered streaming request bodies via zero-copy `LimitedIncomingBody` (mapping overflow to HTTP `413 Payload Too Large`).
- **Header Route Matching (`shunt-core::snapshot` & `shunt-config::ir`):** `RouteMatch::headers` (`RouteIr::headers`) adds optional exact header matching, integrated into `shunt verify`'s `route_subsumes` shadowing checker.
- **Custom CA Support on `CoreHttpClientConfig`:** Added `extra_ca_pem: Option<Vec<u8>>` so `K8sApiConfigProvider` verifies in-cluster `https://kubernetes.default.svc` against `/var/run/secrets/kubernetes.io/serviceaccount/ca.crt`.

### 4.2 General HTTP Plugins (`shunt-plugins`)
- **`jwt-auth`:** Validates JWTs using `ring` (`HS256/384/512`, `RS256/384/512`, `PS256/384/512`, `ES256/384`, `EdDSA`), strictly matching key material type to `alg` and rejecting `alg: "none"` and unsupported `crit` headers. Caches JWKS in `StateStore` with pure-`std` singleflight coalescing and anti-DoS minimum refresh cooldown (`jwks_min_refresh_secs`) for unknown `kid` lookups. Strips configured `forward_claims` headers before auth to prevent spoofing.
- **`ip-filter`:** Pure-Rust `IpNet` CIDR matcher with IPv4-mapped IPv6 normalization, `deny_first` / `allow_first` precedence, and right-to-left `X-Forwarded-For` hop peeling constrained by `trusted_proxies`.
- **`mtls-auth`:** Authorizes `ctx.client_cert` against `allowed_cns`, `allowed_san_dns`, `allowed_san_uris` (SPIFFE globs), and `allowed_fingerprints`; strips spoofed identity headers and injects verified subject/DN/SPIFFE/fingerprint headers.
- **`body-limit`:** Synchronous `Content-Length` `413` check in `on_request_headers` + `max_request_body_bytes()` delegation to `shunt-core`'s zero-copy `LimitedIncomingBody`.
- **`compression`:** RFC 9110 `Accept-Encoding` negotiation (`zstd`, `br`, `gzip`, `deflate`) with chunked streaming encoders in `on_response_body_chunk`, SSE/`no-transform`/already-encoded/min-size guards, `Vary: Accept-Encoding`, and RFC 9110 `ETag` weakening.
- **`redirect` & `header-rewrite` URL rewrites:** Standalone HTTP redirect and upstream host/path rewrite plugins that also serve as direct compilation targets for Kubernetes Gateway API filters.

### 4.3 Kubernetes Gateway API `ConfigProvider` (`shunt-config::k8s`)
- `K8sClusterSnapshot` ingests multi-document YAML or Kubernetes API JSON lists (`GatewayClass`, `Gateway`, `HTTPRoute`, `Service`, `Endpoints`, `EndpointSlice`, `Secret`).
- `compile_k8s_gateway_snapshot` enforces GatewayClass `controllerName` matching, `allowedRoutes.namespaces.from` (`Same`/`All`/`Selector`), Gateway API hostname intersection, exact canary split weighting across unequal pod counts via LCM scaling, filter translation (`RequestHeaderModifier`, `ResponseHeaderModifier`, `URLRewrite`, `RequestRedirect`, `RequestMirror`), in-memory base64 TLS `Secret` decoding (`ServerTlsConfig.cert_pem`/`key_pem`), Shunt extension annotations (`shunt.io/plugins`, `shunt.io/max-attempts`, `shunt.io/max-body-bytes`, `shunt.io/client-ca-secret`), and Gateway API route precedence ordering.
- Exposed through both `K8sManifestConfigProvider` (`--k8s-manifest <path>`) and live `K8sApiConfigProvider` + `start_k8s_sync_loop` (`--k8s-gateway`) with SHA-256 digest deduplication.

## 5. Alternatives Considered & Rejected

1. **Depending on `kube` + `k8s-openapi` for Kubernetes Gateway API:** Rejected—adds >150 transitive crates, heavy compile times, and binary bloat for what is cleanly expressed in ~700 lines of typed serde structs over Shunt's existing `HttpClient` + `rustls`.
2. **Pulling in `jsonwebtoken` + `x509-parser` crates:** Rejected—`ring` is already in `Cargo.lock`, supports all 12 JWS algorithms natively without duplicate crypto primitives, and a minimal bounds-checked DER extractor (~150 lines, fuzzed) covers all mTLS identity fields cleanly.
3. **Buffering full HTTP responses in `compression` before compressing:** Rejected—breaks memory efficiency on large responses and violates Shunt's streaming-first design; incremental streaming encoders in `on_response_body_chunk` keep memory bounded while preserving full `gzip`/`br`/`zstd`/`deflate` framing.

## 6. Future Work

- **RFC 0019 — Wasm Component Model Plugin Host:** Tier 2 hot-reloadable Wasm plugins on `shunt-plugin-sdk`.
- **RFC 0020 — Companion Control Plane (`shunt-console`):** Optional DB-backed management UI & runtime CRUD plane driving `shunt` via `ConfigProvider`.
- **Kubernetes Watch Streams & ReferenceGrant:** Upgrade polling sync to chunked HTTP watch streams with `resourceVersion` resume and explicit cross-namespace `ReferenceGrant` authorization.
