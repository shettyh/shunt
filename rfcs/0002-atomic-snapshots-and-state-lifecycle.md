# RFC 0002: Atomic Snapshots, Pool Reuse & State Lifecycle

- **Status:** Implemented
- **Crates:** `shunt-core`, `shunt-plugin-sdk`

## Summary

This RFC defines how Shunt performs zero-downtime configuration reloads and graceful shutdowns using immutable `GatewaySnapshot`s swapped via `ArcSwap`, while preserving warm upstream TCP/TLS connection pools and stateful plugin counters (rate limiters, circuit breakers) inside a shared `RuntimeRegistry`.

## Motivation

Naive hot-reload implementations in proxies frequently break in subtle production ways:

1. **Cold-pool thundering herds:** Tearing down and recreating upstream HTTP clients on every config reload drops keep-alive pools and triggers simultaneous TLS handshakes across all backends.
2. **State amnesia & leaks:** Rebuilding plugins on reload either wipes active rate-limit windows / circuit-breaker cooldowns, or leaks memory forever in global maps when routes are removed.
3. **Half-applied reloads:** Mutating shared routing tables in place leaves the proxy in an inconsistent state if validation fails partway through or if an in-flight request observes two different configs mid-flight.

## Goals & Non-Goals

### Goals
- Lock-free, single-load snapshot lookup per incoming request (`ArcSwap<GatewaySnapshot>`).
- Zero dropped requests during live config reloads and `SIGTERM` shutdowns.
- Automatic reuse of warm upstream connection pools and passive health state when an upstream's network/TLS identity is unchanged.
- Scoped persistent state for stateful plugins (`StateStore` / `StateHandle`) with automatic garbage collection of orphaned scopes on successful reload.
- Hot-reloadable SNI TLS certificates (`DynamicCertResolver`) without restarting listeners.

### Non-Goals
- Distributed/clustered state synchronization (e.g., Redis-backed rate limits)—v1 provides in-process `StateStore`; distributed stores can be added inside async plugins via `HookResult::Pending`.

## Design

### 1. Immutable `GatewaySnapshot` + `ArcSwap`

Every compiled configuration produces a self-contained, immutable `Arc<GatewaySnapshot>`:

```rust
pub struct GatewaySnapshot {
    pub version: u64,
    pub routes: Vec<Arc<CompiledRoute>>,
    pub upstreams: HashMap<String, Arc<UpstreamPool>>,
}
```

- `GatewayServer` holds `Arc<ArcSwap<GatewaySnapshot>>`.
- Each incoming request loads `snapshot.load_full()` **once** at entry and runs its entire lifecycle (including streaming responses and retries) against that exact snapshot.
- Swapping in a new snapshot via `ServerReloader::swap_snapshot(next)` is atomic and lock-free. Old snapshots and their plugin chains are automatically dropped as soon as their last in-flight request completes.

### 2. Warm Pool Reuse (`RuntimeRegistry` & `UpstreamPoolKey`)

`RuntimeRegistry` persists across snapshot compilations and caches `UpstreamPool` instances keyed by `UpstreamPoolKey`:

```rust
pub struct UpstreamPoolKey {
    pub endpoints: Vec<String>,
    pub http2_only: bool,
    pub tls: UpstreamTlsConfig,
    pub connect_timeout: Duration,
    pub pool_idle_timeout: Duration,
    pub pool_max_idle_per_host: usize,
    pub unhealthy_threshold: usize,
    pub unhealthy_cooldown: Duration,
}
```

During compilation:
1. For each upstream in the new config, `RuntimeRegistry::get_or_create_pool` looks up `config.pool_key()`.
2. If unchanged, it returns a clone of the existing `Arc<UpstreamPool>` (same `pool_id`, same warm HTTP/1.1 + H2 keep-alive connections, same passive health counters).
3. If changed (e.g., endpoint list or CA cert rotated), a fresh `UpstreamPool` is constructed.
4. **Only after the entire snapshot compiles cleanly**, `gc_unused_pools(&active_keys)` removes unreferenced pools from the registry cache. In-flight requests on older snapshots keep holding their `Arc<UpstreamPool>` until they finish draining.

### 3. Stateful Plugin Persistence & Orphan GC (`StateStore`)

Plugins are stateless per snapshot by default. Stateful plugins (e.g., `rate-limit`, `ai-failover` cooldown circuit breakers) request a scoped `StateHandle` during `PluginFactory::build`:

```text
SnapshotCompiler::compile()
  │
  ├─ session = runtime_registry.begin_build_session()
  ├─ for each plugin attachment (scope_id = "route:<route_id>:<plugin_id>"):
  │    ├─ build_ctx = session.context_for(scope_id)
  │    └─ factory.build(config, &build_ctx)
  │         └─ handle = build_ctx.state_handle()   // marks scope_id as live
  │         └─ handle.get_or_init("buckets", ...)  // survives reload!
  │
  ├─ if ANY error occurs -> abort compile; session is dropped WITHOUT GC
  │    (live snapshot & existing state remain completely untouched)
  │
  └─ if ALL stages succeed -> session.commit_gc()
       └─ StateStore::retain_scopes(&live_scopes)  // GCs removed routes/plugins
```

- Keys are namespaced as `"{scope_id}::{key}"` inside `StateStore`.
- Authors can assign an explicit `id = "..."` on a plugin attachment in `shunt.toml` so its `scope_id` remains stable even if plugin array ordering changes.
- Type safety: `StateStore::get_or_init<T>` downcasts stored `Arc<dyn Any + Send + Sync>` and replaces the entry cleanly if a plugin's state type changes.

### 4. Hot-Reloadable TLS (`DynamicCertResolver`)

`TlsListenerConfig` wraps a `DynamicCertResolver` backed by `ArcSwap<CertStore>` (supporting a default certificate, exact SNI hostnames, and `*.suffix` wildcard SNI lookup). On reload, `ServerReloader::reload_tls(next_store)` atomically swaps certificates for all new TLS handshakes while existing TLS sessions continue undisturbed.

### 5. Split Timeouts & Graceful Draining

- **Split Timeouts:** Every route configures independent `connect_timeout` (per upstream), `response_headers_timeout` (TTFB/TTFT), and `idle_chunk_timeout` (max silence between streaming body chunks), allowing long-lived SSE/LLM streams without disabling stall detection.
- **Graceful Shutdown:** `GatewayServer` tracks active connections via `ActiveConnGuard` + `Notify`. On `SIGTERM`/`Ctrl-C`, the accept loop stops, Hyper signals graceful shutdown (`Connection: close` / HTTP/2 `GOAWAY`), and `ServerHandle::shutdown()` waits until active connections reach zero or `drain_timeout` elapses.

## Alternatives Considered & Rejected

### 1. Mutating Live Routes/Plugins Behind a Global `RwLock`
- **Why considered:** Simple mental model for incremental updates.
- **Why rejected:** Causes read/write lock contention on every request, risks partial updates on reload failure, and breaks consistency when a request spans a reload boundary. `ArcSwap` gives lock-free reads and atomic all-or-nothing swaps.

### 2. Rebuilding Everything from Scratch on Reload (No `RuntimeRegistry`)
- **Why considered:** Simpler code; zero state management.
- **Why rejected:** Destroys warm upstream keep-alive/TLS pools on every route edit and resets rate-limiters and provider circuit breakers, causing traffic spikes and broken limits on every config deploy.

### 3. Requiring Plugins to Implement Custom `on_reload` / `shutdown` Hooks
- **Why considered:** Gives plugins manual control over state migration.
- **Why rejected:** Shifts boilerplate and leak-prone lifecycle bookkeeping onto every plugin author. The `BuildSession` + `StateHandle` pattern makes state persistence a 2-line opt-in with automatic, fail-safe orphan GC.

## Future Work

- Active background health probes per `UpstreamPool` (complementing v1's passive consecutive-failure health tracking).
- Exposing pool connection & health telemetry via the Admin API.
