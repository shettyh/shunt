# Shunt — Security & Hardening Audit

**Status:** Audit Complete (Ready for Remediation Planning)  
**Scope:** Line-by-line security and hardening audit of all production Rust crates (`shunt-engine`, `shunt-plugin-sdk`, `shunt-plugins`, `shunt-config`, `shunt-cli`, `shunt-ai`, `shunt-mcp`), plus CI workflows (`.github/workflows/{ci,security,verify}.yml`), `deny.toml`, `Dockerfile`, 18 `cargo-fuzz` targets, `proptest` suites, TLA+ specs, Kani bounded proofs, and soak/reload tests. Includes pre-merge security findings for in-progress RFC 0023 Control Plane files (`control_plane.rs`, `sync.rs`), explicitly tagged below.  
**Related Docs:** [Product Vision](vision.md) · [Core Design](design.md) · [Reference](reference.md) · [RFC Index](../rfcs/README.md)

> **Policy Alignment:** All remediation recommendations follow Shunt's pre-release and architectural guardrails: clean breaks (no backwards-compatibility shims while pre-release), zero AI/MCP concepts in `shunt-engine` or `shunt-plugin-sdk`, zero-allocation `HookMask` fast paths preserved, and single-binary zero-dependency defaults.

---

## 1. Executive Summary & Strong Foundations

### What Is Already Strong
- **Zero `unsafe` in production crates** across the entire Rust workspace (only `std::env::set_var` in tests).
- **Strong crypto & HTTP/2 baselines:** `rustls 0.23.46` / `ring 0.17.14` (TLS 1.2/1.3 AEAD defaults), `hyper 1.12.0` HTTP/1.1 framing checks, `h2 0.4.20` Rapid Reset protections, `jwt-auth` strict `alg: none` & algorithm-confusion prevention + RSA `2048..=8192`-bit modulus checks, and `ring` AES-256-GCM / Ed25519 in Control Plane sync.
- **ReDoS immunity:** All route and guardrail regexes use Rust's linear-time `regex` crate with explicit NFA/DFA memory budgets; `shunt-mcp` globbing is iterative.
- **Panic isolation & error hygiene:** Both sync and async plugin panics are caught across every lifecycle stage (`catch.rs`, `hardening_soak.rs`), and engine error bodies use static messages without leaking stack traces or internal upstream errors.
- **Verification culture:** 19 TOML conformance specs, 4 `proptest` suites, 3 TLA+ specs checked in CI, 6 Kani bounded proofs, 18 nightly `cargo-fuzz` targets, `cargo-deny` weekly audits, and distroless non-root Docker runtime.

### Risk Heatmap (Confirmed Findings)

| Subsystem | Critical | High | Medium | Low / Hardening | Top Themes |
| --- | :---: | :---: | :---: | :---: | --- |
| **Core Engine & SDK** (`shunt-engine`, `shunt-plugin-sdk`) | — | **5** | **8** | **4 (+6)** | `Connection:` header strips `XFF` & auth headers; `InspectResponseBody` fail-open on abort/panic; raw unnormalized path matching; Hyper timers silently disabled (Slowloris); default-on unvalidated WebSockets |
| **Core & Auth Plugins** (`shunt-plugins`) | — | **8*** | **9** | **5** | Open redirects (`redirect.rs`); `{param}` path traversal (`header_rewrite.rs`); `rate_limit` O(N) lock scan + distributed panic; OIDC `jwks_uri` SSRF/downgrade & JWT base64url malleability; multi-`Authorization` desync; mTLS SPIFFE/DNS wildcard & multi-SAN mismatch; compression RAM DoS/BREACH; chunked body-limit early-response bypass |
| **Config, Admin, K8s, Control Plane & CLI** (`shunt-config`, `shunt-cli`) | **4** | **8** | **6** | **4** | K8s missing `ReferenceGrant`, `Selector` checking `HTTPRoute` labels, untrusted `shunt.io/plugins` annotation; Control Plane WIP LKG plaintext downgrade & unverified Ed25519 sig + SSRF token leak; unauthenticated Admin CSRF/DNS rebinding; blocking `reload()` on Tokio workers; incomplete secret redaction & env-var error leaks |
| **AI Gateway** (`shunt-ai`) | **3** | **6** | **7** | **4** | `/v1/files/*` & `/v1/batches/*` path traversal bypassing models/budget/guardrails; cross-tenant cache & translated-SSE guardrail cache leak; shared-key cross-tenant Files/Batches/Responses; Vertex `gs://` exfiltration; `models[]` override quota bypass; missing-`usage`/abort 100% refund & Redis `1e+14` Lua break; streaming guardrail holdback/OOM bugs; duplicate JSON/multipart key smuggling; BYOK failover leak |
| **MCP Gateway** (`shunt-mcp`) | **3** | **6** | **3** | **2** | JSON-RPC batch smuggling (`[1..N]` dropped from policy); disabled principal escalating to wildcard access; client self-approval (`_meta.approved` / `x-shunt-approved`); session-binding eviction hijack & predictable IDs; non-`POST/GET/DELETE` full bypass; FIFO eviction wiping rate limits; resource URI traversal; guardrail/auth credential leaks |

*\*Hop-by-hop `Connection:` header stripping of gateway-injected headers spans `shunt-engine` and `shunt-plugins` and is counted once under Core Engine.*

---

## 2. Core Engine & Plugin SDK (`shunt-engine`, `shunt-plugin-sdk`)

### High Findings

1. **`Connection:` hop-by-hop stripping runs *after* auth plugins and `append_forwarded_for`**
   - **Code:** [pipeline.rs](../crates/shunt-engine/src/pipeline.rs#L71-L114), [pipeline.rs](../crates/shunt-engine/src/pipeline.rs#L336-L352), [pipeline.rs](../crates/shunt-engine/src/pipeline.rs#L1529-L1567)
   - **Issue:** Stage 1 (`on_request_headers`) injects trusted headers (`x-jwt-*`, `x-client-cn`, `x-request-id`, `header-rewrite` sets), then line 336 appends `X-Forwarded-For`, and **only at line 352** does `strip_hop_by_hop_headers` delete every header nominated in the client's `Connection:` header. Additionally, `headers.get(header::TE)` inspects only the *first* `TE` header.
   - **Impact:** An untrusted client sending `Connection: x-forwarded-for, x-jwt-roles, x-client-cn, content-length` deletes gateway-injected identity/IP headers before reaching upstream.
   - **Fix:** Strip client hop-by-hop and `Connection:`-nominated headers **before** Stage 1 and `append_forwarded_for` (never permitting `Connection:` to strip `Content-Length` or protected gateway headers), and normalize `TE` across `get_all(header::TE)`.

2. **Fail-open bypass when `RESPONSE_BODY_STREAM` returns `Abort` or panics under `Flow::InspectResponseBody`**
   - **Code:** [pipeline.rs](../crates/shunt-engine/src/pipeline.rs#L907-L998)
   - **Issue:** When a plugin triggers `Flow::InspectResponseBody`, lines 909–970 run `RESPONSE_BODY_STREAM` plugins and set `aborted_mid_stream = true` on `StreamFlow::Abort` or panic—**then lines 972–997 never check `aborted_mid_stream` and emit `inspected_body` verbatim with `200 OK`**.
   - **Impact:** Any output guardrail or DLP plugin aborting or panicking on an inspected response fails open and delivers blocked content to the client.
   - **Fix:** Check `if aborted_mid_stream` before line 972 and return `finish_error` (`502`/`500`) without emitting `inspected_body`.

3. **Raw unnormalized path matching enables route/auth boundary bypass & upstream base-path escape**
   - **Code:** [snapshot.rs](../crates/shunt-engine/src/snapshot.rs#L162-L166), [route_index.rs](../crates/shunt-engine/src/route_index.rs#L317), [path_match.rs](../crates/shunt-engine/src/path_match.rs#L188-L234), [pipeline.rs](../crates/shunt-engine/src/pipeline.rs#L1655-L1673), [upstream.rs](../crates/shunt-engine/src/upstream.rs#L1001-L1038)
   - **Issue:** Route matching runs directly on raw `req.uri().path()` without dot-segment resolution (`..`, `.`), `//` collapsing, or percent-encoding validation (`%2e%2e`, `%2f`, `%5c`, `%00`), and `build_target_uri` forwards raw paths verbatim. In `strip_uri_prefix`, if `new_pq.parse::<Uri>()` fails (e.g. `//evil.com`), `.unwrap_or_else` silently skips stripping.
   - **Impact:** Requests like `/public/../admin`, `//admin`, or `/%61dmin` miss auth-protected `/admin` routes, match a fallback route, and get normalized by the backend; upstream base paths (`http://be/api/v1`) can be escaped via `/../../internal`.
   - **Fix:** Canonicalize or reject ambiguous/traversal paths (`..`, `.`, `//`, `%2e`, `%2f`, `%5c`, `%00`) with `400 Bad Request` by default before routing, and use that exact canonical path for route matching, parameter extraction, `strip_prefix`, and `build_target_uri`.

4. **Hyper timers silently disabled + missing connection, TLS handshake, idle, and body-read timeouts (Slowloris / FD exhaustion)**
   - **Code:** [server.rs](../crates/shunt-engine/src/server.rs#L102-L185), [server.rs](../crates/shunt-engine/src/server.rs#L232-L255), [body.rs](../crates/shunt-engine/src/body.rs#L373-L396), [pipeline.rs](../crates/shunt-engine/src/pipeline.rs#L169), [pipeline.rs](../crates/shunt-engine/src/pipeline.rs#L795), [pipeline.rs](../crates/shunt-engine/src/pipeline.rs#L1114-L1210)
   - **Issue:**
     - `AutoServerBuilder::new(...)` omits `.http1().timer(TokioTimer::new())`, which **silently disables** Hyper's 30s default `header_read_timeout` (`Time::Empty`).
     - No `tls_handshake_timeout` and `acceptor.accept()` ignores graceful shutdown.
     - No `max_connections` semaphore; `EMFILE` accept errors tight-loop at 100% CPU without backoff.
     - No HTTP/1.1 idle keep-alive timeout; HTTP/2 sets no timer, keep-alive, `max_concurrent_streams`, or `max_header_list_size`.
     - `collect_body_limited` has no read timeout on slow-POST buffered requests (`pipeline.rs:169`), and `InspectResponseBody` (`pipeline.rs:795`) bypasses `idle_chunk_timeout`.
     - `spawn_request_body_stream_pump` doesn't `select!` on `tx.closed()`, leaking tasks if upstream drops early.
   - **Fix:** Wire `TokioTimer::new()` to both H1 & H2 server builders, add `max_connections` + accept backoff + `tls_handshake_timeout` + idle/body read timeouts + H2 stream/header limits, wrap `InspectResponseBody` in `IdleTimeoutBody`, and `select!` on `tx.closed()`.

5. **WebSocket upgrades enabled by default with unvalidated handshake, raw headers, stale hook state, and untracked tunnels**
   - **Code:** [snapshot.rs](../crates/shunt-engine/src/snapshot.rs#L329), [pipeline.rs](../crates/shunt-engine/src/pipeline.rs#L53-L58), [ws.rs](../crates/shunt-engine/src/ws.rs#L21-L43), [ws.rs](../crates/shunt-engine/src/ws.rs#L316-L335), [ws.rs](../crates/shunt-engine/src/ws.rs#L438-L573)
   - **Issue:** `allow_websockets` defaults to `true`. `is_websocket_upgrade` never validates `HTTP/1.1`, `Sec-WebSocket-Key`, `Sec-WebSocket-Version: 13`, or upstream `101`'s `Upgrade: websocket` + `Sec-WebSocket-Accept`. Branches before `strip_hop_by_hop_headers`, ignores `on_request_headers` stripping `Upgrade` or `on_response_headers` changing `101` to `403`, and spawns `copy_bidirectional` after dropping `ActiveConnGuard` with no idle/max timeout or shutdown cancellation.
   - **Fix:** Default `allow_websockets: false`; enforce full RFC 6455 request & `101` accept validation; strip non-WS hop-by-hop/framing headers; honor post-hook mutations; keep `ActiveConnGuard` + idle/max-lifetime/shutdown bounds on tunnels.

### Medium & Low Findings (`shunt-engine` & `shunt-plugin-sdk`)

| ID | Severity | Area & File | Summary & Fix |
| --- | --- | --- | --- |
| E-M1 | Medium | `SyncedTable::subscribe` *(RFC 0023 WIP: `crates/shunt-plugin-sdk/src/sync.rs`)* | Subscriptions never unsubscribe (permanent closure/memory/CPU leak on every reload & failed reload); callbacks run under `write_lock` without `catch_unwind` (poisoning kills future Control Plane revocations); `replace_full` skips `seq` monotonicity check (rollback risk). Fix: RAII guard/`Weak`, invoke outside lock with `catch_unwind`, enforce `seq >= current.seq`. |
| E-M2 | Medium | `endpoint_override` & `connect_uri` ([pipeline.rs](../crates/shunt-engine/src/pipeline.rs#L471-L496), [upstream.rs](../crates/shunt-engine/src/upstream.rs#L1178-L1230), [http_client.rs](../crates/shunt-engine/src/http_client.rs#L89-L175)) | `endpoint_override` skips `http`/`https` scheme validation; `connect_uri` has no configurable egress CIDR blocklist (metadata/RFC1918/loopback) or DNS-pinned `SocketAddr` connect (DNS rebinding). |
| E-M3 | Medium | `append_forwarded_for` ([pipeline.rs](../crates/shunt-engine/src/pipeline.rs#L336), [pipeline.rs](../crates/shunt-engine/src/pipeline.rs#L1569-L1579)) | Unconditionally preserves spoofed `X-Forwarded-*` / `Forwarded` with no `trusted_proxies`; drops 2nd+ `XFF` headers instead of folding `get_all`; runs after Stage 1. |
| E-M4 | Medium | `Host` / `:authority` / SNI ([snapshot.rs](../crates/shunt-engine/src/snapshot.rs#L197-L223), [tls.rs](../crates/shunt-engine/src/tls.rs#L73-L88)) | No rejection on `:authority` vs `Host` conflict or duplicate/malformed `Host` (`admin:80@evil`); trailing dot (`admin.example.com.`) bypasses host route; `..example.com` matches `*.example.com`; no optional SNI-vs-Host `421` check. |
| E-M5 | Medium | Redis RESP2 client ([redis.rs](../crates/shunt-engine/src/redis.rs#L117-L119), [redis.rs](../crates/shunt-engine/src/redis.rs#L188-L206), [redis.rs](../crates/shunt-engine/src/redis.rs#L311-L447), [redis.rs](../crates/shunt-engine/src/redis.rs#L521-L630)) | No total byte/element cap on `read_buf`/nested arrays + O(N²) re-parse; IPv6 broken (`::1:6379`); URL parse error echoes raw password; public `encode_resp_value` allows CRLF in SimpleString/Error; Lua `tostring(nxt)` breaks `INCRBY` at `>= 1e14` (see §5 H-3). |
| E-M6 | Medium | Pool timer & OTLP exporter ([upstream.rs](../crates/shunt-engine/src/upstream.rs#L680-L688), [http_client.rs](../crates/shunt-engine/src/http_client.rs#L75-L78), [otlp.rs](../crates/shunt-engine/src/otlp.rs#L175-L380)) | Missing `.pool_timer(TokioTimer::new())` silently disables idle pool eviction; OTLP collector response body drain is uncapped; `flush()` blocks outside timeout & ignores `batch_size`; raw endpoint URL logged on warn. |
| E-M7 | Medium | Retries, mirrors & streaming ctx ([pipeline.rs](../crates/shunt-engine/src/pipeline.rs#L367-L372), [pipeline.rs](../crates/shunt-engine/src/pipeline.rs#L682-L684), [pipeline.rs](../crates/shunt-engine/src/pipeline.rs#L1115-L1118), [pipeline.rs](../crates/shunt-engine/src/pipeline.rs#L1583-L1651)) | Automatic post-connect retries fire on non-idempotent `POST`/`DELETE` with no engine cap on `decision.max_attempts`; traffic mirrors clone `Authorization`/`Cookie` and drop response bodies (breaking keep-alive); `REQUEST_BODY_STREAM` pump uses a blank `RequestCtx` (losing auth extensions). |
| E-M8 | Medium | TLS / X.509 ([tls.rs](../crates/shunt-engine/src/tls.rs#L26-L49), [tls.rs](../crates/shunt-engine/src/tls.rs#L214-L220), [tls.rs](../crates/shunt-engine/src/tls.rs#L397-L496), [tls.rs](../crates/shunt-engine/src/tls.rs#L522-L556)) | `parse_x509_name` omits RFC 4514 escaping (`O="Evil,CN=admin"` spoofs `CN=admin`); SANs allow `\0`; no CRL support in `WebPkiClientVerifier`; upstream `extra_ca_pem` always merges public `webpki_roots` (cannot pin private CA) & lacks upstream mTLS; `load_certified_key_pem` doesn't check `keys_match()`; `insecure_skip_verify` logs no warning. |
| E-L1–L4 | Low | `StateStore` `"::"` delimiter collision ([state.rs](../crates/shunt-plugin-sdk/src/state.rs#L96-L150)), `CompiledPathRegex` unbalanced group anchoring escape ([path_match.rs](../crates/shunt-engine/src/path_match.rs#L335-L344)), `ON_RESPONSE_HEADERS` skipped on synthetic/error responses + `Content-Length` on 204/304 ([pipeline.rs](../crates/shunt-engine/src/pipeline.rs#L1508-L1517)), sequential active probes & unchecked `Instant::now() + dur` deadline math ([body.rs](../crates/shunt-engine/src/body.rs#L219), [upstream.rs](../crates/shunt-engine/src/upstream.rs#L861-L907)). |

---

## 3. Core & Auth Plugins (`shunt-plugins`)

### High Findings

1. **Multiple Open Redirects in `redirect.rs`**
   - **Code:** [redirect.rs](../crates/shunt-plugins/src/redirect.rs#L53-L196)
   - **Issue:** (a) Relative redirects emit `//evil.example/x` and `/\evil.example/x` verbatim (and `path_match_prefix = "/old"` -> `"/"` turns `/old//evil.example/x` into `Location: //evil.example/x`); (b) `strip_host_port` reflects unvalidated `Host` headers (including `trusted.example@evil.example`); (c) `req.uri.scheme_str()` fallback reflects arbitrary schemes; (d) `replace_path_prefix` lacks segment-boundary checking (`/old-admin` matches `/old`).
   - **Fix:** Normalize/reject relative paths starting with `//` or `/\`, strictly validate `Host` syntax (reject `@`, `/`, `?`, `#`, `\`, whitespace) + add optional `allowed_hosts`, restrict scheme fallback to `http`/`https`, and enforce segment boundaries in `replace_path_prefix`.

2. **Path Traversal via Unsanitized `{param}` / `{*wildcard}` in `header_rewrite.rs`**
   - **Code:** [header_rewrite.rs](../crates/shunt-plugins/src/header_rewrite.rs#L85-L111), [header_rewrite.rs](../crates/shunt-plugins/src/header_rewrite.rs#L267-L290)
   - **Issue:** `path_replace_full` interpolates raw `{param}` / `{*wildcard}` captures (`..`, `../../admin`, `%2e%2e`, `%2f`) into upstream paths; failed URI parse silently forwards the unrewritten URI; also inherits `replace_path_prefix`'s missing segment boundary.
   - **Fix:** Reject dot-segments, encoded dots/slashes, and control chars in path params (or canonicalize before routing per §2 H-3) and fail closed with `400 Bad Request` on invalid rewritten URIs.

3. **`rate_limit.rs`: O(N) blocking mutex scans, unbounded key size, ignored `ResolvedClientIp`, and distributed `Duration::from_secs_f64` panic**
   - **Code:** [rate_limit.rs](../crates/shunt-plugins/src/rate_limit.rs#L215-L324), [rate_limit.rs](../crates/shunt-plugins/src/rate_limit.rs#L452-L499)
   - **Issue:**
     - Every cache miss runs full-shard `retain()` + `min_by_key()` (~12.5k entries) under a blocking `std::sync::Mutex` on Tokio workers; evicting exhausted buckets resets rate limits; slot-race fallback uses an untracked ephemeral bucket.
     - `KeyStrategy::Header` has no key-length cap (memory & Redis key amplification).
     - `KeyStrategy::ClientIp` uses raw `ctx.client_addr.ip()`—ignoring `ResolvedClientIp` from `ip-filter` (all proxied users collapse to the LB's IP!) and failing to normalize `::ffff:` IPv4-mapped IPv6.
     - Distributed mode computes `Duration::from_secs_f64((burst / rps).max(1.0))`—tiny finite `rps` overflows to `inf` and **panics at runtime**; when `burst < rps`, `.max(1.0)` collapses a 1000 rps limiter to 10 rps.
   - **Fix:** Use O(1) LRU/sampled eviction, hash keys (keyed 128/256-bit digest) or strictly cap length, consult `ResolvedClientIp` + `normalize_ip`, bound `window_secs` in `build()`, and add a distributed GCRA/token-bucket Lua script in `RedisStateStore`.

4. **`jwt_auth.rs`: Unvalidated OIDC Discovery `jwks_uri` (TLS Downgrade, SSRF, Missing `issuer` Verification)**
   - **Code:** [jwt_auth.rs](../crates/shunt-plugins/src/jwt_auth.rs#L575-L588), [jwt_auth.rs](../crates/shunt-plugins/src/jwt_auth.rs#L1067-L1114)
   - **Issue:** `resolve_jwks_uri` trusts `doc["jwks_uri"]` permanently without checking `doc["issuer"] == configured_issuer` (OIDC Discovery §4.3), enforcing `https://` when discovery is `https://`, or blocking private/metadata IPs. Plaintext `http://` is also allowed by default in `validate_http_url`.
   - **Fix:** Verify exact `doc["issuer"]` match, require `https://` by default (behind explicit `allow_insecure_http = false`), apply `CoreHttpClient` egress IP filtering, and expire `discovered_jwks_uri` with TTL / clear on error.

5. **Multi-Header `Authorization` Credential Desync in `bearer_auth.rs` & `jwt_auth.rs`**
   - **Code:** [bearer_auth.rs](../crates/shunt-plugins/src/bearer_auth.rs#L33), [bearer_auth.rs](../crates/shunt-plugins/src/bearer_auth.rs#L137-L145), [jwt_auth.rs](../crates/shunt-plugins/src/jwt_auth.rs#L296), [jwt_auth.rs](../crates/shunt-plugins/src/jwt_auth.rs#L771-L826), [jwt_auth.rs](../crates/shunt-plugins/src/jwt_auth.rs#L997-L1003)
   - **Issue:** Both read only the first `Authorization` (or custom/cookie/query) occurrence via `.get()` and default `strip_header: false`. Sending two `Authorization` headers passes Shunt on the first while forwarding both to upstreams that use last-wins parsing. `jwt_auth` also doesn't strip `cookie_name`/`query_param` when `strip_header = true`.
   - **Fix:** Reject duplicate `Authorization`/`header_name`/matching cookie/query tokens with `400`/`401`; default `strip_header = true` on `bearer-auth`; strip extracted cookie/query tokens when configured.

6. **`mtls_auth.rs`: Overbroad `*` Wildcards Crossing `.`/`/` Boundaries & Multi-SAN Identity Mismatch**
   - **Code:** [mtls_auth.rs](../crates/shunt-plugins/src/mtls_auth.rs#L163-L291), [tls.rs](../crates/shunt-engine/src/tls.rs#L398-L495)
   - **Issue:** (a) `wildcard_match_bytes` lets `*` cross `.` in DNS (`*.svc.internal` matches `evil.other.svc.internal`) and `/` in SPIFFE URIs (`spiffe://prod/ns/*/sa/frontend` matches `spiffe://prod/ns/other/sa/admin/sa/frontend`); (b) `allowed_san_uris` checks `.any()`, but `san_uri_header` & `subject` emit `cert.san_uris.first()`—so a multi-SAN cert can pass allowlist on SAN #2 and forward privileged SAN #1; (c) inherits `tls.rs` unescaped DN injection, NUL bytes in CN/SAN, and lack of CRL/fingerprint deny list.
   - **Fix:** Single-label DNS matching (`*` excludes `.`, leftmost label only), path-segment URI matching (`*` excludes `/`, `?`, `#`), forward the *matched* SAN URI, reject `\0`/control chars and RFC 4514-escape DN in `tls.rs`, and add CRL + `denied_fingerprints`.

7. **`compression.rs`: Per-Stream Memory DoS, Sync Tokio Starvation, BREACH Risk, and `206 Partial Content` Corruption**
   - **Code:** [compression.rs](../crates/shunt-plugins/src/compression.rs#L158-L180), [compression.rs](../crates/shunt-plugins/src/compression.rs#L243-L326), [compression.rs](../crates/shunt-plugins/src/compression.rs#L471-L550)
   - **Issue:** Brotli uses `lgwin = 22` (~4+ MiB/stream) and Zstd allows level `19` (up to ~128 MiB/stream), enabling multi-GiB RAM exhaustion via slow-reading H2 streams; sync compression runs inline on Tokio workers; compresses authenticated/`Set-Cookie`/`no-store` TLS responses without BREACH guard; compresses `206 Partial Content` / `Content-Range`, corrupting byte-range reassembly.
   - **Fix:** Cap Brotli `lgwin` (16–18), Zstd level/window, and concurrent active compressors; skip `206` & `Content-Range`; add BREACH protection toggle (skipping `Set-Cookie`/`Cache-Control: no-store`/authenticated responses when enabled).

8. **`body_limit.rs` + Engine: Chunked Streaming Reaches Upstream & Early-Response Bypass + Fail-Open `Content-Length`**
   - **Code:** [body_limit.rs](../crates/shunt-plugins/src/body_limit.rs#L72-L98), [pipeline.rs](../crates/shunt-engine/src/pipeline.rs#L144-L166), [pipeline.rs](../crates/shunt-engine/src/pipeline.rs#L610-L669)
   - **Issue:** On unbuffered chunked uploads, up to `max_bytes` streams to upstream immediately, and if upstream responds early `pool.send_request` returns `Ok(res)` bypassing the `exceeded_flag` `413` check. Non-numeric/negative/overflowing/duplicate `Content-Length` fails open in `.parse::<usize>().ok()`. Custom `status_code` is ignored on chunked/buffered rejections.
   - **Fix:** Validate all `Content-Length` headers via `get_all` (reject invalid/conflicting with `400`), check `exceeded_flag` even on `Ok(res)` (or add strict `buffer_chunked` option), and optionally reject `Content-Encoding` compressed request bodies.

### Medium & Low Findings (`shunt-plugins`)

| ID | Severity | Plugin & File | Summary & Fix |
| --- | --- | --- | --- |
| P-M1 | Medium | `jwt-auth` ([jwt_auth.rs](../crates/shunt-plugins/src/jwt_auth.rs#L1557-L1591)) | Non-canonical `base64url_decode` accepts arbitrary trailing `=` and ignores trailing non-zero bits (token/signature malleability bypassing replay/revocation/rate-limit keys). Fix: strict RFC 7515 unpadded canonical decoder. |
| P-M2 | Medium | `jwt-auth` ([jwt_auth.rs](../crates/shunt-plugins/src/jwt_auth.rs#L703-L762), [jwt_auth.rs](../crates/shunt-plugins/src/jwt_auth.rs#L872-L879), [jwt_auth.rs](../crates/shunt-plugins/src/jwt_auth.rs#L1170-L1215)) | Unbounded JWT length before signature check; no-`kid` tokens verify against every JWK (uncapped key count); `jwks_min_refresh` skipped when cache is cold/expired (outage thundering herd). |
| P-M3 | Medium | `jwt-auth` ([jwt_auth.rs](../crates/shunt-plugins/src/jwt_auth.rs#L717-L745), [jwt_auth.rs](../crates/shunt-plugins/src/jwt_auth.rs#L889-L935), [jwt_auth.rs](../crates/shunt-plugins/src/jwt_auth.rs#L1315-L1408)) | Accepts `crit: []`, `exp == now`, duplicate JSON keys (last-wins differential), wrong-typed JWK `use`/`alg`/`key_ops` (silently bypassed!), remote `"oct"` symmetric JWKs, non-string `aud` array elements, and 1-byte static HMAC secrets. |
| P-M4 | Medium | `bearer-auth` ([bearer_auth.rs](../crates/shunt-plugins/src/bearer_auth.rs#L86-L145)) | Length-leaking hand-rolled XOR loop (use per-instance keyed `ring::hmac::verify`), rejects `"BEARER "` uppercase scheme, unescaped `realm` in `WWW-Authenticate`. |
| P-M5 | Medium | `cors` ([cors.rs](../crates/shunt-plugins/src/cors.rs#L14-L209)) | Omits `Vary: Origin` on absent/disallowed `Origin` (CDN cache poisoning); disallowed preflights fall through to upstream; upstream `Access-Control-*` not stripped on disallowed origin; only checks first `Origin` header; misses `*` check on methods/headers with `allow_credentials`. |
| P-M6 | Medium | `ip-filter` ([ip_filter.rs](../crates/shunt-plugins/src/ip_filter.rs#L283-L364)) | `client_ip_header` reads first header (spoofable if proxy appends); unparseable XFF entries are skipped instead of stopping right-to-left walk; `[::1]garbage` parses as `::1`. |
| P-M7 | Medium | `otel-trace` ([otel_trace.rs](../crates/shunt-plugins/src/otel_trace.rs#L27-L220)) | `respect_parent_sampling: true` default allows unauthenticated trace-volume DoS or audit suppression; unbounded/unvalidated `tracestate`; ignores duplicate `traceparent`; raw path in span name causes high cardinality. |
| P-M8 | Medium | `request-id`, `access-log`, `dev-waterfall` ([request_id.rs](../crates/shunt-plugins/src/request_id.rs#L27-L99), [access_log.rs](../crates/shunt-plugins/src/access_log.rs#L92-L128), [dev_waterfall.rs](../crates/shunt-plugins/src/dev_waterfall.rs#L71-L126)) | `trust_incoming: true` allows spaces/`=` in `X-Request-Id` -> structured log forging in `access-log`; `dev-waterfall` prints raw path/error -> ANSI terminal escape injection. |
| P-M9 | Medium | Missing `#[serde(deny_unknown_fields)]` | 7 plugin configs (`cors`, `bearer-auth`, `rate-limit`, `header-rewrite`, `otel-trace`, `request-id`, `access-log`) silently ignore config typos (e.g. `allow_origin` silently opens CORS to `*`). |
| P-L1–L5 | Low | `header_rewrite` `HashMap` case nondeterminism & unstripped spoofed header when template resolves `None`; `compression` first-only `Accept-Encoding` & invalid `q=` defaulting to `1.0`; `jwt_auth` non-minimal DER & plaintext secrets in `#[derive(Debug)]`; predictable sequential `request-id`; `as i64`/`as u32` narrowing casts. |

---

## 4. Config, Admin Plane, Kubernetes Gateway API, Control Plane & CLI (`shunt-config`, `shunt-cli`)

### Critical Findings

1. **K8s Gateway API: Zero `ReferenceGrant` enforcement (cross-namespace Service, Mirror & TLS Secret access + `--k8s-namespace` bypass)**
   - **Code:** [k8s.rs](../crates/shunt-config/src/k8s.rs#L782-L830), [k8s.rs](../crates/shunt-config/src/k8s.rs#L1054-L1100), [k8s.rs](../crates/shunt-config/src/k8s.rs#L1516-L1607), [k8s.rs](../crates/shunt-config/src/k8s.rs#L1953-L1977)
   - **Issue:** `ReferenceGrant` is never fetched or checked. Any `HTTPRoute` can route/mirror to Services in arbitrary namespaces (even when `--k8s-namespace` is set, via DNS fallback `{name}.{ns}.svc.{cluster_domain}:{port}`), and any `Gateway` can load TLS Secrets from any namespace (`sync_once` even collects `needed_secrets` across *all* Gateways before filtering by controller/gateway name).
   - **Fix:** Model/ingest `ReferenceGrant`, deny all cross-namespace `HTTPRoute -> Service` and `Gateway -> Secret` references without an explicit matching grant, and filter Gateways before collecting secrets.

2. **K8s Gateway API: `allowedRoutes.namespaces.from: Selector` checks untrusted `HTTPRoute` labels instead of `Namespace` labels**
   - **Code:** [k8s.rs](../crates/shunt-config/src/k8s.rs#L1116-L1144)
   - **Issue:** Matches `sel.match_labels` against `route.metadata.labels` instead of the `Namespace` object's labels—letting any tenant self-label their `HTTPRoute` to attach to admin-restricted listeners.
   - **Fix:** Ingest `Namespace` objects and evaluate selectors strictly against `namespace.metadata.labels` (fail closed if unknown).

3. **K8s Gateway API: Untrusted `HTTPRoute` `shunt.io/plugins` annotation enables arbitrary plugin execution (env/file read, file write, IAM/IMDS SSRF) & Gateway policy override**
   - **Code:** [k8s.rs](../crates/shunt-config/src/k8s.rs#L702-L725), [k8s.rs](../crates/shunt-config/src/k8s.rs#L1235-L1267)
   - **Issue:** Any `HTTPRoute` author can instantiate `ai-provider-adapter` (exfiltrating `env:` secrets or pod AWS/GCP/Azure IAM/IMDS), `ai-audit` (arbitrary pod file writes / webhook SSRF), `jwt-auth` (`jwks_file` / `public_key_file` local file reads), raise `max_body_bytes` above the Gateway's cap, or bypass Gateway annotations by ordering a weaker Gateway first in `parentRefs` (`attached_listeners.first()`).
   - **Fix:** Disable `shunt.io/plugins` on `HTTPRoute` by default (require explicit admin opt-in + safe plugin allowlist), cap `max_body_bytes` via `min` with Gateway & bound `max_attempts`, and apply annotations across *all* attached Gateways.

4. **Control Plane LKG Cache: AES-256-GCM plaintext downgrade bypass & unverified Ed25519 signatures on `topology.lkg`** *(RFC 0023 WIP: `crates/shunt-config/src/control_plane.rs`)*
   - **Issue:** (a) In `read_cache_file`, when `key` (`--cache-key-env`) is configured, any file NOT starting with `SHUNT_ENC_V1:` is accepted verbatim as plaintext! (b) `CachedTopologyLkg` omits `signature_b64` and `load_cached_topology` calls only `verify_digest()`, skipping Ed25519 signature verification even when `--control-plane-public-key` is pinned.
   - **Fix:** Fail closed in `read_cache_file` whenever `key.is_some()` and the `SHUNT_ENC_V1:` envelope is absent; persist `signature_b64` in `CachedTopologyLkg` and call `verify_bundle_integrity()` on load.

### High Findings (`shunt-config`, `shunt-cli`)

1. **Unauthenticated Admin API + Localhost CSRF (`POST /reload`) & DNS Rebinding** ([admin.rs](../crates/shunt-config/src/admin.rs#L107-L169), [admin.rs](../crates/shunt-config/src/admin.rs#L257-L395)): Zero auth, zero `Host` validation (DNS rebinding), zero `Origin`/`Sec-Fetch-Site` CSRF protection on `POST /reload`, and no startup block/warning if `admin.listen` is non-loopback in `shunt run`.
2. **Control Plane SSRF & `node_token` exfiltration via unvalidated `TopologyRevisionEvent.url`** *(RFC 0023 WIP: `crates/shunt-config/src/control_plane.rs`)*: Follows any absolute `http://`/`https://` URL (or `@`/`//` relative trick) from SSE events and attaches `Authorization: Bearer <node_token>`. Restrict strictly to same-origin `/cp/v1/...` paths.
3. **K8s URL authority injection (SSRF) & K8s API Secret path traversal** ([k8s.rs](../crates/shunt-config/src/k8s.rs#L1599-L1602), [k8s.rs](../crates/shunt-config/src/k8s.rs#L1670-L1676), [k8s.rs](../crates/shunt-config/src/k8s.rs#L1957-L1975)): Unvalidated `bref.name`/`ns`/`cluster_ip` allow URI authority injection; unvalidated `shunt.io/client-ca-secret` annotation (`../...`) traverses K8s API Secret paths. Validate RFC 1123 DNS labels, `IpAddr`, and percent-encode API path segments.
4. **K8s fail-open drop of `queryParams` & `ExtensionRef` filters + inverted hostname precedence** ([k8s.rs](../crates/shunt-config/src/k8s.rs#L205-L209), [k8s.rs](../crates/shunt-config/src/k8s.rs#L982-L998), [k8s.rs](../crates/shunt-config/src/k8s.rs#L1444-L1457)): Silently drops `queryParams` matchers and `ExtensionRef` auth/WAF filters; sorts path length before hostname specificity. Fail closed on unsupported matchers/filters and sort hostname specificity first per Gateway API v1.
5. **Incomplete secret redaction in `/snapshot` + resolved `env:` secret values leaked in error messages** ([ir.rs](../crates/shunt-config/src/ir.rs#L1298-L1337), [compiler.rs](../crates/shunt-config/src/compiler.rs#L422-L467)): `is_secret_key` misses hyphenated `x-api-key`/`api-key`/`x-goog-api-key`/`x-mcp-api-key`, `cookie`, Slack webhook `url`, `jwks_inline`, AWS `external_id`, and URLs with userinfo/query tokens. `compile_telemetry_config` and `compile_redis_state_config` echo resolved `env:` URLs (with passwords/tokens) into error strings exposed via `POST /reload`, `/api/status`, and heartbeats.
6. **Blocking sync `ReloadController::reload()` on Tokio async workers + unbounded Admin server** ([admin.rs](../crates/shunt-config/src/admin.rs#L127-L162), [admin.rs](../crates/shunt-config/src/admin.rs#L356-L383), [reloader.rs](../crates/shunt-config/src/reloader.rs#L57-L84)): Concurrent `POST /reload` calls block Tokio data-plane workers on `std::sync::Mutex` + sync `std::fs`; Admin server lacks `Semaphore` connection cap, `header_read_timeout`, reload rate-limit, and SSE subscriber cap.
7. **Broken atomic reload rollback** ([reloader.rs](../crates/shunt-config/src/reloader.rs#L66-L73), [compiler.rs](../crates/shunt-config/src/compiler.rs#L158-L182), plus *RFC 0023 WIP `control_plane.rs`*): `reload_tls` mutates live certs before `reload_client_auth` succeeds; `get_or_create_redis_store`/`get_or_create_otlp_exporter` leak instances into `RuntimeRegistry` on compile failure; Control Plane WIP overwrites `topology.lkg` and `active_revision` *before* `controller.reload()` succeeds.
8. **Control Plane `SseParser` OOM / O(N²) / split-UTF-8 corruption + sync per-delta disk writes** *(RFC 0023 WIP: `crates/shunt-config/src/control_plane.rs`)*: Unbounded `buf`/`cur_data`, per-line `drain`, `from_utf8_lossy` corrupting split multi-byte UTF-8, and blocking full-namespace disk checkpoints on every delta event.

### Medium & Low Findings (`shunt-config`, `shunt-cli`)

| ID | Severity | Area & File | Summary & Fix |
| --- | --- | --- | --- |
| C-M1 | Medium | Cache perms & Ed25519 scope *(RFC 0023 WIP: `control_plane.rs`)* | Cache dir/files (`node_credentials.json`) created with default `0644` (use `0700`/`0600`); Ed25519 signature omits `cluster` (cross-cluster bundle replay -> sign `v2:<cluster>:<revision>:<digest>`). |
| C-M2 | Medium | Deprecated `serde_yaml` & file/symlink limits ([Cargo.toml](../crates/shunt-config/Cargo.toml#L29), [provider.rs](../crates/shunt-config/src/provider.rs#L44-L66), [k8s.rs](../crates/shunt-config/src/k8s.rs#L420-L537)) | `serde_yaml 0.9` is deprecated (`RUSTSEC-2024-0320`) with 100x+ alias memory amplification; no max config/manifest file size; `collect_yaml_files` follows directory symlinks infinitely. |
| C-M3 | Medium | Config bounds & validation gaps ([ir.rs](../crates/shunt-config/src/ir.rs#L752-L1254), [compiler.rs](../crates/shunt-config/src/compiler.rs#L193-L307)) | Unbounded `state.pool_size` (`Vec::with_capacity` OOM panic), `telemetry.queue_capacity`, `max_attempts`, `max_in_flight`; timeouts accept `0` (and K8s `"0s"` sets 0ms instead of disabled); standalone `path_prefix = ""` matches everything; duplicate `(scope, plugin_id)` collides in `StateStore`; wildcard/loopback port collision missed. |
| C-M4 | Medium | `verify.rs` & plugin ordering ([verify.rs](../crates/shunt-config/src/verify.rs#L284-L407), [compiler.rs](../crates/shunt-config/src/compiler.rs#L192-L212)) | Zero ordering checks for core security plugins (`ip-filter`, `body-limit`, `rate-limit`, auth, `header-rewrite`) or `ai-guardrails` vs `ai-provider-adapter` (unused `adapter_pos`); no warnings on `insecure_skip_verify` or cleartext creds; `InspectorCapturePlugin` runs *after* global plugins (blind to global auth/rate-limit rejections). |
| C-M5 | Medium | Inspector UI & `TraceRingBuffer` ([admin.rs](../crates/shunt-config/src/admin.rs#L407-L410), [inspector.html](../crates/shunt-config/assets/inspector.html#L587-L730), [inspector.rs](../crates/shunt-config/src/inspector.rs#L130-L158)) | CSP uses `'unsafe-inline'`; `location.hash` injected into `querySelector`; uncapped trace `path`/`host`/`error` strings; `next_seq` incremented outside mutex causing SSE drop of out-of-order traces; full DOM rebuild on every SSE event. |
| C-M6 | Medium | CLI defaults & warnings ([main.rs](../crates/shunt-cli/src/main.rs#L115-L150), [main.rs](../crates/shunt-cli/src/main.rs#L791-L810)) | Missing `--k8s-ca-cert` (and `--control-plane-ca-cert` on RFC 0023 WIP, pushing users to `--control-plane-insecure`); no warnings on cleartext `http://` K8s/CP servers, `--token` in argv, or unencrypted `--cache-dir`; `SIGHUP` blocks signal loop with sync `controller.reload()`; `shunt dev --k8s-manifest` defaults to `0.0.0.0:8080` instead of `127.0.0.1:8080`. |
| C-L1–L4 | Low | K8s projected SA token never rotated ([k8s.rs](../crates/shunt-config/src/k8s.rs#L1845-L1853)); K8s multi-Gateway merging & ignored `group`; file watcher misses `upstreams[].tls.ca_cert`, dynamic post-reload cert paths & K8s `..data` symlinks; poisoned-lock panics & 16 MiB error strings. |

---

## 5. AI Gateway Plugins (`shunt-ai`)

### Critical Findings

1. **Path traversal & upstream endpoint hijack on `/v1/files/*` and `/v1/batches/*`**
   - **Code:** [model_router.rs](../crates/shunt-ai/src/model_router.rs#L1461-L1474), [model_router.rs](../crates/shunt-ai/src/model_router.rs#L1743-L1801), [provider_adapter.rs](../crates/shunt-ai/src/provider_adapter.rs#L1462-L1534)
   - **Issue:** Resource routes skip `allowed_models`, label `requested_model = "files"`/`"batches"` (unpriced -> `$0.00`), and concatenate raw unnormalized path suffixes onto upstream bases (including Azure `/openai/files`) using the gateway's master API key.
   - **Impact:** Virtual-key holders can traverse out of `/v1/files/` to hit `/v1/chat/completions`, restricted Azure deployments, or admin APIs while bypassing `allowed_models`, `model_limits`, `ai-budget`, and `ai-guardrails`.
   - **Fix:** Strictly allowlist canonical subpaths (`""`, `"/<id>"`, `"/<id>/content"`, `"/<id>/cancel"` with `[A-Za-z0-9_-]+`) and reject client-supplied `api-version=` query params on Azure.

2. **Cross-tenant cache leakage, semantic cache poisoning & translated-SSE guardrail bypass via cache**
   - **Code:** [cache.rs](../crates/shunt-ai/src/cache.rs#L1064-L1132), [cache.rs](../crates/shunt-ai/src/cache.rs#L1392-L1403), [cache.rs](../crates/shunt-ai/src/cache.rs#L1582-L1597), [cache.rs](../crates/shunt-ai/src/cache.rs#L1983-L1998), [guardrails.rs](../crates/shunt-ai/src/guardrails.rs#L3647-L3834)
   - **Issue:** (a) `CacheScope::Team` collapses all keys with `team: None` into `"team:default"`; `CacheScope::VirtualKey` without `ai-virtual-keys` collapses everyone into `"key:anonymous"`; (b) semantic cache ignores multimodal attachments (`image_url`/audio/PDF), `/v1/rerank` `documents`, `tools`, `response_format`, and `max_tokens`; (c) streaming `ai-guardrails` redaction/`RedactAndStop` never invalidates `AiTranslatedResponseBody`/`AiCachePending`, so `ai-cache::on_complete` caches and serves the **unredacted, unblocked** translated SSE stream.
   - **Fix:** Fall back to `key:{key_id}` for `team: None` and disable caching when unauthenticated under tenant scopes; hash or exclude multimodal/rerank-docs/tools/schema in `semantic_partition`; invalidate `AiCachePending` & `AiTranslatedResponseBody` on any streaming guardrail block or redaction.

3. **Cross-tenant upstream File, Batch & Stored `/v1/responses` exposure on shared provider keys**
   - **Code:** [model_router.rs](../crates/shunt-ai/src/model_router.rs#L1743-L1801), [provider_adapter.rs](../crates/shunt-ai/src/provider_adapter.rs#L1461-L1548), [provider_adapter.rs](../crates/shunt-ai/src/provider_adapter.rs#L1712-L1752)
   - **Issue:** All virtual keys sharing an upstream OpenAI/Azure account can list/download/delete each other's `/v1/files`, `/v1/batches`, and attach to each other's stored `/v1/responses` threads via `previous_response_id` (where OpenAI defaults `store: true`).
   - **Fix:** Track tenant resource ownership (distributed-aware) or gate shared-account resource APIs behind explicit opt-in and default `store: false` on `/v1/responses` unless per-key credentials are used.

### High Findings (`shunt-ai`)

1. **Confused-deputy Vertex AI GCS exfiltration via `fileData.fileUri`** ([gemini.rs](../crates/shunt-ai/src/dialects/gemini.rs#L358-L383)): Forwards client `gs://bucket/object` URIs verbatim into Gemini `fileData.fileUri`, allowing virtual-key holders to read private GCS buckets via Vertex's IAM. Fix: reject `gs://`/`file://`/`http://` by default (opt-in bucket prefix allowlist).
2. **Per-request `models[]` + `provider` overrides bypass per-model quotas, budgets & guardrail exclusions** ([model_router.rs](../crates/shunt-ai/src/model_router.rs#L1165-L1421), [token_rate_limit.rs](../crates/shunt-ai/src/token_rate_limit.rs#L808-L811), [budget.rs](../crates/shunt-ai/src/budget.rs#L644-L648), [guardrails.rs](../crates/shunt-ai/src/guardrails.rs#L2796-L2802)): Filtering out primary `"cheap"` leaving fallback `"expensive"` still records `requested_model = "cheap"`, evaluating cheap-model limits/skip rules. Also **unbounded `models[]`** enables N-attempt retry amplification & O(N²) dedup CPU ([model_router.rs](../crates/shunt-ai/src/model_router.rs#L1875-L1981)).
3. **Budget & TPM bypass via missing-`usage` / mid-stream abort + 100% preflight refund + default TOCTOU + Redis `1e+14` Lua break** ([usage_tracker.rs](../crates/shunt-ai/src/usage_tracker.rs#L955-L1007), [budget.rs](../crates/shunt-ai/src/budget.rs#L145), [budget.rs](../crates/shunt-ai/src/budget.rs#L1266-L1336), [token_rate_limit.rs](../crates/shunt-ai/src/token_rate_limit.rs#L102), [redis.rs](../crates/shunt-engine/src/redis.rs#L50-L63)): Aborting before the final usage chunk bills `$0.00` and refunds 100% of `preflight_reserve`; `preflight_reserve` defaults `false` and `reserve_output_tokens_cap` defaults `0`; Redis `tostring(nxt)` writes `"1e+14"` at `$100k` nano-dollars, breaking `INCRBY` and failing open.
4. **`ai-guardrails` multiple bypasses & unbounded SSE memory leak** ([guardrails.rs](../crates/shunt-ai/src/guardrails.rs#L1460-L1508), [guardrails.rs](../crates/shunt-ai/src/guardrails.rs#L1905-L2168), [guardrails.rs](../crates/shunt-ai/src/guardrails.rs#L2690-L3856)): Misses tool-call args, thinking blocks, completions/images/rerank/count_tokens/multipart, `choices[1..]`; 64-char holdback leaks JWTs / `sk-proj-` / `sk-ant-` / PEM bodies; `pending_external` buffers entire SSE stream even when no external stream guardrail is configured (OOM); external redaction writes combined text into only one message; Bedrock SigV4 omits `x-amz-date`/`x-amz-content-sha256` from `sign_headers`; missing `verify.rs` check for `ai-guardrails` before `ai-provider-adapter`.
5. **JSON duplicate-key smuggling & multipart duplicate `model` smuggling** ([multipart.rs](../crates/shunt-ai/src/multipart.rs#L50-L231), [provider_adapter.rs](../crates/shunt-ai/src/provider_adapter.rs#L1699-L1832)): Raw un-reserialized JSON forwarded on pass-through enables first-vs-last-key parser differentials; multipart inspects/rewrites only the first `name="model"` part.
6. **`ai-token-rate-limit` empty-shard bypass, `EndUser` `::` key collision, `AnthropicCountTokens` exemption & BYOK failover leak** ([token_rate_limit.rs](../crates/shunt-ai/src/token_rate_limit.rs#L433-L444), [token_rate_limit.rs](../crates/shunt-ai/src/token_rate_limit.rs#L668-L678), [types.rs](../crates/shunt-ai/src/types.rs#L107), [provider_adapter.rs](../crates/shunt-ai/src/provider_adapter.rs#L1258-L1341)): Full global table with empty target shard admits requests untracked; `"user": "victim::model:gpt-4o"` collides buckets; `AnthropicCountTokens` skips rate limits/guardrails; `ClientByokCredential` leaks Provider A's BYOK key onto failover Provider B (and custom `source_header`s aren't stripped).

### Medium & Low Findings (`shunt-ai`)

- **M1:** Unbounded `SseParser` (`line_buf`/`data_lines`), `ChatToResponsesSseTranslator`, and `BedrockStreamTranslator` buffers + O(N²) `drain` in `AwsEventStreamDecoder` ([sse.rs](../crates/shunt-ai/src/sse.rs#L18-L165), [responses.rs](../crates/shunt-ai/src/ingress/responses.rs#L575-L871), [aws_eventstream.rs](../crates/shunt-ai/src/aws_eventstream.rs#L234)).
- **M2:** Cloud IAM refresh storms without backoff, unvalidated ECS full URI / GCP `token_uri`, blocking `std::fs` on Tokio workers, O(N²) `xml_unescape`, Bedrock 403 triggering shared cache invalidation, and 503 responses leaking internal IAM paths/ARNs ([cloud_auth.rs](../crates/shunt-ai/src/cloud_auth.rs#L781-L2011), [provider_adapter.rs](../crates/shunt-ai/src/provider_adapter.rs#L2080), [provider_adapter.rs](../crates/shunt-ai/src/provider_adapter.rs#L2854)).
- **M3:** AWS SigV4 path canonicalization, stale `x-amz-security-token` retention, and unsigned extra `x-amz-*` headers ([aws_sigv4.rs](../crates/shunt-ai/src/aws_sigv4.rs#L126-L386)).
- **M4:** Shadow traffic dispatched *before* guardrails/rate-limit/budget, exfiltrating unredacted PII and blocked prompts ([model_router.rs](../crates/shunt-ai/src/model_router.rs#L1407)).
- **M5:** `/v1/generation` sequential ID enumeration & cross-tenant `response_id` overwrite ([usage_tracker.rs](../crates/shunt-ai/src/usage_tracker.rs#L885-L897), [generation.rs](../crates/shunt-ai/src/generation.rs#L114-L154)).
- **M6:** Unbounded Prometheus `AiMetrics` and routing/failover `HashMap` cardinality under wildcard models ([usage_tracker.rs](../crates/shunt-ai/src/usage_tracker.rs#L65-L88), [routing.rs](../crates/shunt-ai/src/routing.rs)).
- **M7:** Audit log truncates *before* redaction (splitting secrets), misses `sec-websocket-protocol`, skips redacting headers/errors, and creates JSONL files as `0644` ([audit.rs](../crates/shunt-ai/src/audit.rs#L321-L984)); custom budget windows collide in Redis (`"custom"`) and distributed `preflight_reserve` omits alerts ([budget.rs](../crates/shunt-ai/src/budget.rs#L627-L830)).
- **L1–L4:** Replace custom `constant_time_eq_32` in `virtual_keys.rs` with `ring::constant_time::verify_slices_are_equal`; require `https://` by default for alert/audit/guardrail webhooks; redact secrets in `cloud_auth` `Debug` impls; filter `/v1/models` by `allowed_providers`; gate `x-shunt-cache-bypass`.

---

## 6. MCP Gateway Plugins (`shunt-mcp`)

### Critical Findings

1. **JSON-RPC batch smuggling completely bypasses Auth ACLs, Guardrails, Rate Limits & Rewriting**
   - **Code:** [types.rs](../crates/shunt-mcp/src/types.rs#L72-L122), [router.rs](../crates/shunt-mcp/src/router.rs#L1004-L1020), [guardrails.rs](../crates/shunt-mcp/src/guardrails.rs#L474-L480), [rate_limit.rs](../crates/shunt-mcp/src/rate_limit.rs#L385-L493)
   - **Issue:** When `allow_batch = true`, `parse_mcp_jsonrpc_request` accepts an uncapped array, then `router.rs:1017` evaluates only `parsed_list.into_iter().next()` and discards elements `[1..N]` while forwarding the raw array unchanged.
   - **Fix:** Either cleanly remove `allow_batch` (aligned with MCP 2025-06-18, which dropped JSON-RPC batching) or enforce `max_batch_size` and validate/charge/redact/rewrite *every* item in request and response batches.

2. **Revoked/disabled MCP principal escalates to unrestricted wildcard access**
   - **Code:** [auth.rs](../crates/shunt-mcp/src/auth.rs#L338-L340), [auth.rs](../crates/shunt-mcp/src/auth.rs#L540-L575)
   - **Issue:** Disabled principals (`enabled = false`) are omitted from `by_id`. Under `identity_header` + `allow_unlisted_identities = true`, a disabled user misses `by_id` and falls into the unlisted fallback—receiving an unrestricted `McpPrincipal` with no `allowed_tools`/`denied_tools`/quotas.
   - **Fix:** Store all configured principals in `by_id` with their `enabled` flag and return `403 Forbidden` immediately when `enabled == false`. Prefer consuming `ctx.get_ext::<AuthSubject>()` directly rather than trusting raw headers.

3. **Client self-approval bypass of `require_approval_tools`**
   - **Code:** [types.rs](../crates/shunt-mcp/src/types.rs#L200-L205), [router.rs](../crates/shunt-mcp/src/router.rs#L872-L873), [guardrails.rs](../crates/shunt-mcp/src/guardrails.rs#L526-L548)
   - **Issue:** Trusting client-supplied `x-shunt-approved: true` or `params._meta.approved: true` (and advertising both in the denial message) lets any prompt-injected agent self-approve destructive tools.
   - **Fix:** Require cryptographically signed short-lived approval tokens bound to `(principal_id, tool_name, args_sha256, exp, nonce)` or an authoritative `policy_webhook` verdict.

### High, Medium & Low Findings (`shunt-mcp`)

| ID | Severity | Area & File | Summary & Fix |
| --- | --- | --- | --- |
| M-H1 | High | Session hijacking & predictable IDs ([auth.rs](../crates/shunt-mcp/src/auth.rs#L177-L216), [auth.rs](../crates/shunt-mcp/src/auth.rs#L601-L664), [router.rs](../crates/shunt-mcp/src/router.rs#L222-L286), [router.rs](../crates/shunt-mcp/src/router.rs#L1142-L1190)) | 16k bogus `Mcp-Session-Id` values evict victims' bindings and allow re-bind hijacking; local `initialize` skips `on_response_headers` binding; session IDs use predictable timestamps + seq (no CSPRNG); `owner.is_some()` + `caller.is_none()` passes `touch_and_verify`; response binding conflict ignored. |
| M-H2 | High | `mcp-guardrails` bypasses ([guardrails.rs](../crates/shunt-mcp/src/guardrails.rs#L474-L1210)) | Skips `resources/read`, `prompts/get`, `tools/list` (tool-poisoning descriptions), and `error.data`; zero-holdback SSE chunk scanning misses split secrets; PEM regex leaves key body intact; compressed upstream responses fail open (`mcp-router` doesn't force `Accept-Encoding: identity`); object keys & array `params` skipped. |
| M-H3 | High | `mcp-rate-limit` bypass & FIFO wipeout ([rate_limit.rs](../crates/shunt-mcp/src/rate_limit.rs#L148-L205), [rate_limit.rs](../crates/shunt-mcp/src/rate_limit.rs#L388-L492)) | `initialize` & fan-out `*/list` short-circuit before rate limiting; rotating `Mcp-Session-Id` bypasses `max_calls_per_session` & `loop_breaker`; shared FIFO table lets 32k `loop`/`sess` keys evict and reset everyone's `rpm`/`tool_rpm` buckets; `mcp:sess:` omits `scope`. |
| M-H4 | High | HTTP method & backend path bypass ([router.rs](../crates/shunt-mcp/src/router.rs#L864-L1003), [router.rs](../crates/shunt-mcp/src/router.rs#L1724-L1750)) | `PUT`/`PATCH`/`HEAD`/`OPTIONS` skip `McpRequestMeta` and pass straight through to upstream bypassing guardrails, rate limits, telemetry, and `x-shunt-approved` stripping; single-server `GET` forwards arbitrary paths with injected `upstream_auth`. |
| M-H5 | High | Resource URI traversal & implicit `<server>://` ([router.rs](../crates/shunt-mcp/src/router.rs#L587-L610), [types.rs](../crates/shunt-mcp/src/types.rs#L289-L295)) | Raw `starts_with`/`glob_match` permits `..`/`%2e%2e` URI traversal; empty `resource_prefixes` implicitly grants `<srv.name>://` ownership. |
| M-H6 | High | Credential leakage in `mcp-auth` ([auth.rs](../crates/shunt-mcp/src/auth.rs#L426-L476), [auth.rs](../crates/shunt-mcp/src/auth.rs#L540-L599)) | `identity_header` path skips stripping `Authorization`/`x-mcp-api-key`; `extract_api_key` strips only the first matched header, leaking secondary auth headers upstream. |
| M-M1–M3 | Medium | Plaintext `Mcp-Session-Id` logged in audit & OTLP ([telemetry.rs](../crates/shunt-mcp/src/telemetry.rs#L458-L484)); unbounded `McpMetricsData` method/tool cardinality ([telemetry.rs](../crates/shunt-mcp/src/telemetry.rs#L56-L135)); global cross-route `McpSessionTable`/`McpCatalogTable` collisions, unfiltered single-server `*/list` catalogs, and cold-discovery storms ([router.rs](../crates/shunt-mcp/src/router.rs#L491-L1838)). |

---

## 7. Testing, Fuzzing & Verification Gap Analysis

Shunt's **layering** (conformance specs + `proptest` + TLA+ + Kani + 18 nightly fuzz targets) is already unusually mature—the main gap is that **current tests mostly verify happy paths and non-panic parsing rather than adversarial security invariants**:

### A. Adversarial Security Integration Tests (Highest ROI — Immediate Need)
Currently, 8 of 15 plugins in `shunt-plugins` have zero inline unit tests, `shunt-cli` has 0 tests, `control_plane.rs` has 0 integration tests, and `shunt-mcp` has only a single integration test file. High-priority additions:
- **Core Engine:** `Connection: x-forwarded-for, x-jwt-sub` stripping attack; `InspectResponseBody` + `StreamFlow::Abort`/panic fail-closed test; Slowloris suite (slow H1 headers, stalled TLS handshake, slow POST body, stalled `InspectResponseBody`, `max_connections` cap); path traversal (`//admin`, `/public/../admin`, `/%61dmin`) & `Host`/`:authority` mismatch; WebSocket RFC 6455 & `101` rejection; `SyncedTable` multi-reload non-leak & panic non-poisoning.
- **Core & Auth Plugins:** Open redirect matrix (`redirect.rs`); `{param}` traversal (`header_rewrite.rs`); JWT base64url malleability, `crit: []`, duplicate JSON keys, multi-`Authorization`, OIDC discovery `issuer`/downgrade/SSRF, cold-cache outage cooldown; mTLS single-label DNS & slash-bounded SPIFFE wildcards, multi-SAN header binding, DN escaping, NUL bytes; `rate_limit` `ResolvedClientIp` & `1e-308` distributed window; `cors` `Vary: Origin` & upstream `ACAO` strip; `compression` `206` & memory caps.
- **Config / Admin / K8s / Control Plane:** K8s `ReferenceGrant` denial, `Selector` vs `Namespace` labels (not `HTTPRoute` labels), `shunt.io/plugins` confinement, `queryParams`/`ExtensionRef` fail-closed, hostname precedence, secret-path traversal; Control Plane LKG plaintext downgrade rejection, Ed25519 signature check on LKG load, same-origin bundle URL check, `0600` perms, failed-reload LKG rollback; Admin CSRF/DNS-rebinding `Host` check & full real-plugin secret redaction matrix (`x-api-key`, Slack `url`, `jwks_inline`, env-var errors).
- **AI & MCP:** `/v1/files/../chat/completions` traversal; `models[]` override vs `model_limits`; mid-stream abort + missing `usage` budget test + Redis `>= 1e14` Lua round-trip; cross-tenant cache & translated-SSE guardrail cache test; streaming >64-char secret holdback; Vertex `gs://` rejection; BYOK failover isolation; MCP batch smuggling, disabled-principal escalation, self-approval rejection, session eviction hijack, FIFO rate-limit eviction resistance, `PUT`/`PATCH` rejection, resource URI traversal.
- **Static Security Checks in `shunt verify` ([verify.rs](../crates/shunt-config/src/verify.rs)):** Warn/error on `insecure_skip_verify = true`, cleartext `redis://` with password, cleartext `http://` OTLP/webhooks with auth headers, non-loopback `admin.listen` without auth, `ai-guardrails` placed before `ai-provider-adapter`, `header-rewrite` after auth plugins mutating identity headers, and `mcp-auth` with `identity_header` lacking an upstream auth plugin.

### B. Targeted Fuzzing Additions & CI Upgrades
Existing 18 fuzz targets run 30s each nightly and already cover most raw byte parsers. Highest-ROI fuzzing improvements:
1. **`fuzz_http_sanitization`** *(New — High ROI)*: Fuzz `strip_hop_by_hop_headers`, `append_forwarded_for`, `build_target_uri`, `strip_uri_prefix`, and path canonicalization on hostile URIs/headers, asserting security invariants (no `..` escape, protected headers preserved, single `TE: trailers`).
2. **`fuzz_redirect_and_rewrite`** *(New — High ROI)*: Fuzz `RedirectPlugin::compute_location`, `replace_path_prefix`, `strip_host_port`, and `header_rewrite::expand_path_params`, asserting relative `Location` never starts with `//` or `/\` and rewritten paths never contain `..`.
3. **`fuzz_control_plane`** *(New — High ROI, for RFC 0023)*: Fuzz `control_plane::SseParser` (asserting bounded memory & chunk-split UTF-8 invariance), `decrypt_cache_bytes`, `decode_base64`, and `verify_bundle_integrity`.
4. **`fuzz_aws_sigv4` & `fuzz_multipart`** *(New — Medium-High ROI)*: Fuzz SigV4 canonicalization/signing and multipart boundary/duplicate-field extraction & rewriting.
5. **`fuzz_ip_filter_and_mtls_match`** *(New — Medium ROI)*: Fuzz XFF right-to-left parsing, `parse_forwarded_ip`, and DNS/SPIFFE wildcard matching asserting `.` and `/` boundary invariants.
6. **Upgrade existing fuzz targets with security assertions & CI limits ([verify.yml](../.github/workflows/verify.yml)):**
   - Assert canonical unpadded base64url round-trip & duplicate-key rejection in `fuzz_jwt_and_jwks.rs`.
   - Assert bounded total memory/element budgets on nested arrays & CRLF safety in `fuzz_resp_parser.rs`.
   - Assert bounded memory on newline-free inputs in `fuzz_sse_parser.rs`.
   - Fuzz streaming holdback chunk-split invariance for long secrets (JWT/PEM/API keys) in `fuzz_guardrails.rs`.
   - Fuzz `redact_secrets` & YAML alias-expansion memory ceilings in `fuzz_config_parse.rs`.
   - Persist fuzz corpus across nightly runs and pass `-rss_limit_mb=512` so OOM amplification bugs fail CI immediately.

### C. Formal Extensions (Kani & TLA+)
- **Kani:** Add bounded proofs for canonical path normalization (never contains `..` or `//`), single-label DNS & slash-bounded SPIFFE wildcard matching, and `base64url_decode_unpadded` canonical round-trip.
- **TLA+:** Extend `AtomicReload.tla` to cover Control Plane LKG write-after-commit and TLS+ClientAuth paired swap; extend `RequestPipeline.tla` to cover `InspectResponseBody` abort semantics (which would have caught §2 H-2 formally).

---

## 8. Phased Remediation Roadmap & Open Design Decisions

### Phased Waves
- **Wave 1 — Core Data-Plane & Auth Foundations:** Fix §2 H-1–H-5 (`Connection:` strip order, `InspectResponseBody` fail-closed, path canonicalization, Hyper timers + Slowloris/body/TLS/connection limits, WebSockets opt-in + RFC 6455 + tracked tunnels, `pool_timer`, `SyncedTable` leak/poisoning) and §3 H-1–H-8 (`redirect`, `header-rewrite`, `rate-limit`, `jwt-auth`, `bearer-auth`, `mtls-auth` + `tls.rs`, `cors`, `compression`, `body-limit`, `#[serde(deny_unknown_fields)]`).
- **Wave 2 — Control Plane, Admin API & Kubernetes Isolation:** Fix §4 C-1–C-4 and H-1–H-8 (`ReferenceGrant`, `Namespace` selectors, `shunt.io/plugins` confinement, LKG plaintext downgrade & Ed25519 sig check, Admin CSRF/DNS-rebinding/auth/non-blocking reload, complete secret redaction & env-var error sanitization, `shunt verify` security rules).
- **Wave 3 — AI & MCP Gateway Hardening:** Fix §5 C-1–C-3 & H-1–H-6 (`/v1/files/*` traversal, cross-tenant & translated-SSE guardrail cache, shared-key resource isolation, Vertex `gs://`, `models[]` override/cap, missing-`usage`/abort accounting + Redis `1e+14`, guardrail holdback/OOM/coverage/Bedrock SigV4, duplicate JSON/multipart keys, BYOK failover) and §6 C-1–C-3 & H-1–H-6 (MCP batch smuggling, disabled principal escalation, signed approval tokens, CSPRNG/non-evictable sessions, guardrails/rate-limit/method/URI/auth fixes).
- **Wave 4 — Adversarial Test Suite, Upgraded Fuzzers & Dependency Hygiene:** Add per-crate adversarial security suites, 5 new fuzz targets + upgraded CI assertions with `-rss_limit_mb=512` + corpus caching, and migrate off deprecated `serde_yaml`.

### Open Design Decisions
1. **Path canonicalization default (`shunt-engine`):** Reject ambiguous paths (`..`, `//`, `%2e`, `%2f`, `%5c`, `%00`) with `400 Bad Request` by default (strict/Envoy-style, opt-in raw path mode) vs. normalize-and-forward?
2. **Secure defaults:** Flip `allow_websockets` to `false` (opt-in per route) and `bearer-auth.strip_header` to `true`?
3. **Outbound SSRF policy (`CoreHttpClient` / `connect_uri`):** Block private/loopback/cloud-metadata CIDRs by default with an explicit `allow_private_egress = true` opt-in for local dev/in-cluster webhooks?
4. **Admin API hardening:** Loopback `Host`-header validation + CSRF guard + optional `auth_token` (required for non-loopback), or also split read-only `/metrics` onto its own listener?
5. **K8s `shunt.io/plugins` trust model:** Disable on `HTTPRoute` by default (admin-owned `Gateway` only, or behind an explicit CLI flag + safe plugin allowlist)?
6. **MCP batching & approvals:** Remove `allow_batch` cleanly (per MCP `2025-06-18`) vs. full per-item batch policy enforcement; replace self-asserted `x-shunt-approved`/`_meta.approved` with HMAC/JWT signed approval tokens?
