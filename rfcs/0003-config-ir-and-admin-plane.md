# RFC 0003: Config IR, Hot Reload, Admin API & Dev Ergonomics

- **Status:** Implemented
- **Crates:** `shunt-config`, `shunt-plugins`, `shunt-cli`

## Summary

This RFC describes Shunt's configuration pipeline (`ConfigProvider` → canonical `GatewayConfig` IR → `SnapshotCompiler`), automatic file-watcher and signal/API hot reloads, the isolated read-only Admin listener, secret redaction, and the developer-first CLI (`shunt check`, `shunt run`, `shunt dev` with per-hook microsecond waterfalls).

## Motivation

A gateway that is fast in benchmarks still fails developers if it is painful to configure, debug, or operate safely:
- Config errors during a live reload must **never** take down running traffic, and must report *all* actionable validation errors at once.
- Admin/observability endpoints (`/metrics`, `/snapshot`, `/reload`) must never accidentally leak onto public proxy ports or expose bearer tokens / API keys.
- Debugging latency across a 5-plugin chain in local development should be immediate—not require spinning up Jaeger/OpenTelemetry just to see which hook took 12ms.

## Goals & Non-Goals

### Goals
- Support `shunt.toml` (primary) and optional YAML (`.yaml`/`.yml`) behind a pluggable `ConfigProvider` trait.
- Validate structure, TLS files, and every plugin's typed config atomically before swapping snapshots.
- Isolate the Admin API on a dedicated listener (`127.0.0.1:9090` by default) and redact secret fields in `GET /snapshot`.
- Dogfood `shunt-plugin-sdk` for all built-in plugins—including `dev-waterfall` for `shunt dev`.

### Non-Goals
- Mutating config via the Admin API (`PUT /config`) in v1—`shunt.toml` is the single authoritative source of truth.
- Distributed control planes (xDS / Kubernetes Gateway API CRDs) in v1 (enabled cleanly in v2 via `ConfigProvider`).

## Design

### 1. Configuration Pipeline & `ConfigProvider` Seam

```text
  shunt.toml / .yaml (FileConfigProvider)  ──┐
  [v2+: HTTP API / K8s CRD ConfigProvider] ──┼─▶ LoadedConfig (IR + SHA-256 digest)
                                             │
                                             ▼
                                     SnapshotCompiler
                              1. GatewayConfig::validate()   (collects ALL errors)
                              2. Load & verify TLS PEMs
                              3. Build global + route plugins via PluginRegistry
                              4. Build GatewaySnapshot (reusing warm pools)
                              5. Commit pool + StateStore GC (ONLY after success)
                                             │
                                             ▼
                                     CompiledBundle
                              (Arc<GatewaySnapshot>, CertStore, SnapshotInspect)
```

- `GatewayConfig::validate()` collects all structural errors (invalid socket addresses, admin/server port collisions, duplicate upstream/route IDs, invalid URIs/HTTP methods, unknown upstream references) into a single `ConfigError::Validation(Vec<String>)`.
- Relative TLS paths (`cert`, `key`, `ca_cert`) are resolved relative to the config file's parent directory.
- `ReloadController` serializes reloads with a mutex, compiles the new bundle, atomically swaps both TLS certs and the `GatewaySnapshot`, and updates `ArcSwap<SnapshotInspect>`. If any step fails, the last-known-good snapshot keeps serving untouched.

### 2. Automatic & Explicit Hot Reloads

Three reload triggers feed the exact same `ReloadController::reload()` path:
1. **File watcher (`start_file_watcher`):** Uses `notify` watching the config file's parent directory (handling atomic editor renames like vim/VSCode) and all referenced TLS cert/key files, with a 150ms debounce window.
2. **Admin API:** `POST /reload` triggers synchronous validation/reload and returns `200 OK` with the new `SnapshotInspect`, or `422 Unprocessable Entity` with actionable compilation diagnostics.
3. **Unix signal:** `SIGHUP` triggers a reload in `shunt run` and `shunt dev`.

### 3. Isolated Read-Only Admin Listener (`AdminServer`)

- Always bound to its own `TcpListener` (`127.0.0.1:9090` by default); validation explicitly rejects binding `admin.listen` to the same address/port as `server.listen`.
- Endpoints:
  - `GET /health` — liveness/readiness JSON with active snapshot `version`, `digest`, route count, and upstream count.
  - `GET /metrics` — Prometheus text exposition format (`v0.0.4`), combining core HTTP metrics (`shunt-plugins::PrometheusMetrics`) and AI gateway metrics (`shunt-ai::AiMetrics`).
  - `GET /snapshot` — active `SnapshotInspect` JSON showing compiled routes, `HookMask` bitmasks, upstream `pool_id`s, and plugin configs with **recursive secret redaction** (`redact_secrets` masks any key matching `token`, `secret`, `password`, `passwd`, `api_key`, `apikey`, `authorization`, `private_key`, `credential`).
  - `POST /reload` — explicit synchronous reload.

### 4. Dogfooded Built-in Plugins (`shunt-plugins`)

Every built-in plugin depends strictly on `shunt-plugin-sdk` (never `shunt-core`):
- `request-id` — propagates or generates `x-request-id` and attaches `RequestId` to `ctx.extensions`.
- `bearer-auth` — constant-time token comparison with `env:VAR` secret indirection and `AuthSubject` extension.
- `rate-limit` — token-bucket limiter keyed by `client_ip`, `header` (`key_header`), or `global`, backed by `StateStore` so buckets survive reloads.
- `cors` — preflight `OPTIONS` short-circuiting and origin/credential header injection.
- `header-rewrite` — declarative request/response header set/add/remove.
- `metrics` — Prometheus request counters, latency/TTFB histograms, byte counters, and stream-abort counters.
- `access-log` — structured completion logging.
- `dev-waterfall` — injected automatically as an extra global plugin in `shunt dev`!

### 5. Developer Experience (`shunt-cli`)

- `shunt check -c shunt.toml`: Compiles the snapshot offline, prints a table of global plugins, upstream pool IDs, routes, and compiled `HookMask`s, and exits non-zero on error.
- `shunt run -c shunt.toml`: Production server with hot reload (`--no-watch` optional) and graceful `SIGTERM`/`Ctrl-C` draining.
- `shunt dev -c shunt.toml`: Enables `ctx.trace_enabled = true`, attaches `DevWaterfallPlugin`, auto-watches config/certs, and prints a live per-request waterfall to stderr:

```text
200 POST /v1/chat/completions │ bearer-auth: 4µs │ ai-model-router: 18µs │ upstream TTFB: 312.0ms │ ai-provider-adapter: 2µs/chunk (42 chunks) │ total: 680.4ms
```

## Alternatives Considered & Rejected

### 1. Exposing Admin Endpoints on the Main Proxy Listener Under `/__admin`
- **Why considered:** One fewer port to configure.
- **Why rejected:** High operational risk of accidentally exposing `/snapshot` or `/reload` to the public internet via misconfigured reverse proxies or ingress rules. A dedicated loopback listener enforces defense-in-depth by default.

### 2. Building `shunt dev` Timing Output Directly Inside `shunt-core`
- **Why considered:** Direct access to pipeline internals.
- **Why rejected:** Violates "everything above transport is a plugin." Recording opt-in `HookTiming` entries in `RequestCtx` (gated by a single `ctx.trace_enabled` boolean) lets `DevWaterfallPlugin` render waterfalls purely through `on_request_headers` + `on_complete`.

### 3. Watching Only the Exact `shunt.toml` File Path with `notify`
- **Why considered:** Slightly simpler watcher setup.
- **Why rejected:** Editors and Kubernetes ConfigMap mounts routinely update files via atomic rename (`write tmp -> rename`), which breaks inode-based single-file watches on macOS/Linux. Watching parent directories and filtering by canonical filename handles atomic renames reliably.

## Future Work

- Remote control-plane `ConfigProvider` (HTTP polling / watch stream / Kubernetes Gateway API CRDs).
- `shunt build --with <crate>` helper to assemble custom static binaries with third-party Rust plugins.
