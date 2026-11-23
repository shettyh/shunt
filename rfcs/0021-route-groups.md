# RFC 0021: Route Groups & Shared Plugin Chains

- **Status:** Implemented
- **Crates:** `shunt-config`, `shunt-cli`, `shunt-test`, `specs/`, `examples/`

## 1. Summary

This RFC introduces **Route Groups (`[[route_groups]]`)** as a first-class, compile-time primitive in Shunt's canonical configuration IR (`shunt-config`). A route group defines shared route match defaults (`hosts`, `path_prefix`, `methods`, `headers`), shared route execution defaults (`upstream`, `strip_prefix`, `max_body_bytes`, `max_attempts`, timeouts, `allow_websockets`, `mirrors`), and a **shared plugin chain** instantiated **once per group** under a reload-persistent `group:<group_id>:<plugin_id>` `StateStore` scope.

Individual `[[routes]]` entries remain in a single flat, ordered list and opt into a group via `group = "<group_id>"`. During `SnapshotCompiler::compile()`, grouped routes are lowered into standard immutable `CompiledRoute` structs with `global → group → route` plugin chains (`Arc`-cloned group plugins) and precomputed `HookMask`s—incurring **zero changes and zero runtime overhead in `shunt-engine`**.

## 2. Motivation

Shunt already supports both global (`[[plugins]]`) and route-level (`[[routes.plugins]]`) plugins. As users consolidate HTTP APIs, AI `/v1/*` endpoints, and MCP `/mcp` endpoints into a single gateway binary, two concrete limitations emerge:

1. **Configuration repetition across logical API surfaces:**
   A gateway serving `/public/*`, `/api/v2/users`, `/api/v2/orders`, `/api/v2/billing`, `/admin/*`, and `/v1/*` cannot rely on global `[[plugins]]` without applying auth, IP filters, CORS, or body caps to the wrong routes. Repeating `hosts`, `path_prefix`, timeouts, and 3–5 plugin blocks on every `[[routes]]` entry makes `shunt.toml` verbose and error-prone.
2. **Duplicated plugin instances and fragmented state:**
   Today, attaching `rate-limit` or `jwt-auth` to five routes via `[[routes.plugins]]` compiles **five independent plugin instances** with five separate `StateStore` scopes (`route:r1:...` through `route:r5:...`):
   - A `100 req/s` rate limit becomes `100 req/s` *per route* (`500 req/s` total) instead of a shared API-group budget.
   - `jwt-auth` runs five redundant JWKS HTTP caches and background refresh cycles instead of sharing one warm cache.
   - `ai-virtual-keys`, `ai-budget`, `ai-cache`, or `ai-failover` cannot easily share state across multiple sibling routes.

Solving both problems at the `shunt-config` IR level also establishes the right foundation for `shunt-console` (which manages logical APIs/route groups over the `ConfigProvider` seam) without touching `shunt-engine` or disrupting Kubernetes Gateway API compilation.

## 3. Goals & Non-Goals

### Goals
- **Zero data-plane overhead (`shunt-engine` untouched):** Route groups lower completely in `SnapshotCompiler` into flat `CompiledRoute` chains with precomputed `HookMask`s.
- **Shared plugin instances & reload-persistent group state:** Group plugins are constructed once per group (`scope_id = "group:<group_id>:<plugin_id>"`) and shared via `Arc::clone` across all member routes, giving shared rate-limit buckets, shared JWKS caches, and atomic GC on reload.
- **Unambiguous first-match-wins route precedence:** Keep all routes in a single ordered `[[routes]]` array so match priority and `shunt verify` route-shadowing analysis stay explicit and immediately readable.
- **Safe narrowing semantics:** Prevent a grouped route from accidentally escaping its group's `hosts`, `methods`, or `headers` security boundary.
- **Full verification & inspection support:** Surface groups in `GET /snapshot`, `shunt check`, and `shunt verify` (effective merged plugin-order checks, `route_group.unused`, and `match_group` policy selectors).
- **Zero breaking impact on Kubernetes Gateway API (`shunt-config::k8s`)** and clean 1:1 alignment with future `shunt-console`.

### Non-Goals
- **Nested / multi-level group inheritance (`group` referencing another `group`) or multi-group composition (`groups = [...]`):** Adds cycle detection, diamond merge ambiguity, and opaque plugin ordering for marginal real-world gain. Single-level `RouteIr.group: Option<String>` keeps effective config trivially inspectable.
- **Runtime route-group dispatch inside `shunt-engine`:** The engine continues to match flat `CompiledRoute` entries with zero extra indirection.
- **Backwards-compatibility aliases or alternate syntaxes** (e.g., nested `[[route_groups.routes]]` alongside `group = "..."`): Per Shunt's pre-release policy, expose one canonical representation.

## 4. Design

### 4.1 Canonical Config IR (`shunt-config::ir`)

```toml
[[plugins]]
name = "request-id"

[[plugins]]
name = "metrics"

[[route_groups]]
id = "api_v2"
hosts = ["api.example.com"]
path_prefix = "/v2"
strip_prefix = "/v2"
max_body_bytes = 1048576
max_attempts = 2
response_headers_timeout_ms = 10000
idle_chunk_timeout_ms = 30000
allow_websockets = false

[[route_groups.plugins]]
name = "ip-filter"
[route_groups.plugins.config]
allow = ["10.0.0.0/8", "127.0.0.0/8"]

[[route_groups.plugins]]
name = "jwt-auth"
id = "api-v2-jwt"
[route_groups.plugins.config]
jwks_uri = "https://auth.example.com/.well-known/jwks.json"
issuer = "https://auth.example.com"
audience = "shunt-api"

[[route_groups.plugins]]
name = "rate-limit"
id = "api-v2-rl"
[route_groups.plugins.config]
requests_per_second = 100.0
burst = 200
key = "client_ip"

# Routes stay in one top-to-bottom ordered list (explicit first-match-wins precedence).
[[routes]]
id = "api_v2_users"
group = "api_v2"
path_prefix = "/users"          # lowered to "/v2/users"
upstream = "users_svc"

[[routes]]
id = "api_v2_orders"
group = "api_v2"
path_prefix = "/orders"         # lowered to "/v2/orders"
upstream = "orders_svc"
max_attempts = 3                # overrides group default (2)

[[routes.plugins]]
name = "header-rewrite"         # runs after global + group plugins
[routes.plugins.config]
response_set = { "x-service" = "orders" }
```

#### IR Struct Changes

- **`GatewayConfig`** adds:
  ```rust
  #[serde(default)]
  pub route_groups: Vec<RouteGroupIr>,
  ```
- **`RouteGroupIr`** (new):
  ```rust
  #[derive(Debug, Clone, Default, Deserialize, Serialize)]
  #[serde(default)]
  pub struct RouteGroupIr {
      pub id: String,
      pub hosts: Vec<String>,
      pub path_prefix: Option<String>,
      pub methods: Vec<String>,
      pub headers: BTreeMap<String, String>,
      pub upstream: Option<String>,
      pub strip_prefix: Option<String>,
      pub max_body_bytes: Option<usize>,
      pub max_attempts: Option<usize>,
      pub response_headers_timeout_ms: Option<u64>,
      pub idle_chunk_timeout_ms: Option<u64>,
      pub allow_websockets: Option<bool>,
      pub mirrors: Vec<RouteMirrorIr>,
      pub plugins: Vec<PluginAttachment>,
  }
  ```
- **`RouteIr`** updates:
  - Add `#[serde(default)] pub group: Option<String>`.
  - Make `upstream`, `max_attempts`, `response_headers_timeout_ms`, `idle_chunk_timeout_ms`, and `allow_websockets` optional (`Option<T>` with `#[serde(default)]`) so `SnapshotCompiler` can distinguish "explicitly set on route" from "omitted (inherit from group, else gateway default)".
  - Existing TOML/YAML files remain syntactically identical because `upstream = "foo"`, `max_attempts = 2`, etc. deserialize seamlessly into `Some(...)`.

### 4.2 Validation Rules (`GatewayConfig::validate`)

All errors are collected together in `ConfigError::Validation(Vec<String>)`:

1. **Group identity:** `group.id` must be non-empty and unique across `route_groups`.
2. **Group fields:** Validate `path_prefix` (if set, must start with `/`), `methods`, `headers`, `upstream` (if set, must exist in `upstreams`), `max_attempts` (if set, must be `>= 1`), and `mirrors` (same rules as `RouteIr::mirrors`).
3. **Route group reference:** If `route.group = Some(gid)`, `gid` must exist in `route_groups`.
4. **Effective upstream:** `route.upstream.as_deref().or(group.and_then(|g| g.upstream.as_deref()))` must be `Some(name)` and exist in `upstreams`.
5. **Safe matcher narrowing:**
   - **`hosts`:** If both `group.hosts` and `route.hosts` are non-empty, every host pattern in `route.hosts` must be subsumed by at least one pattern in `group.hosts` (e.g., group `["*.example.com"]` narrowed to route `["api.example.com"]` is valid; widening to `["other.com"]` is a validation error).
   - **`methods`:** If both `group.methods` and `route.methods` are non-empty, every method in `route.methods` must be present in `group.methods`.
   - **`headers`:** If both `group.headers` and `route.headers` specify the same header name (case-insensitive) with *different* exact values, report a validation error (contradictory exact matchers can never match).

### 4.3 Lowering & Merge Semantics (`SnapshotCompiler`)

For each route (with optional resolved `group: Option<&RouteGroupIr>`), lowering produces a single effective route specification before calling `SnapshotBuilder::route`:

| Field | Lowering Rule |
| --- | --- |
| **`path`** | If `group.path_prefix = Some(gp)`: join with `route.path_exact` (`Exact(join_paths(gp, re))`), join with `route.path_prefix` (`Prefix(join_paths(gp, rp))`), or use `Prefix(gp)` if route specifies neither. Otherwise use route's path rule unchanged. |
| **`hosts`** | `route.hosts` if non-empty, else `group.hosts`. |
| **`methods`** | `route.methods` if non-empty, else `group.methods`. |
| **`headers`** | Union of `group.headers` and `route.headers`. |
| **`upstream`** | `route.upstream` → `group.upstream` (guaranteed `Some` by validation). |
| **`strip_prefix`** | `route.strip_prefix` → `group.strip_prefix`. |
| **`max_body_bytes`** | `route.max_body_bytes` → `group.max_body_bytes` (then further capped by `min` with any plugin `max_request_body_bytes()` in `SnapshotBuilder`). |
| **`max_attempts`** | `route.max_attempts` → `group.max_attempts` → `1`. |
| **`response_headers_timeout_ms`** | `route.response_headers_timeout_ms` → `group.response_headers_timeout_ms` → `Some(30_000)`. |
| **`idle_chunk_timeout_ms`** | `route.idle_chunk_timeout_ms` → `group.idle_chunk_timeout_ms` → `Some(60_000)`. |
| **`allow_websockets`** | `route.allow_websockets` → `group.allow_websockets` → `true`. |
| **`mirrors`** | `group.mirrors` followed by `route.mirrors`. |
| **`plugins`** | `global_plugins` → `group_plugins` (`Arc::clone`) → `route_plugins`. |

#### Canonical `join_paths(group_prefix, route_path)` Rules
- Leading/trailing slash normalization guarantees clean boundary joins without double slashes:
  - `join_paths("/v2", "/users")` → `"/v2/users"`
  - `join_paths("/v2/", "/users")` → `"/v2/users"`
  - `join_paths("/v2", "/")` → `"/v2"`
  - `join_paths("/", "/users")` → `"/users"`
  - `join_paths("/", "/")` → `"/"`
- Route `path_prefix` and `path_exact` (when set) must start with `/`.

### 4.4 Plugin Compilation, Shared Instances & Reload State Lifecycle

```text
  SnapshotCompiler::compile()
    ├── 1. Build global plugins:  scope = "global:<id_or_name:idx>"
    ├── 2. Build group plugins:   scope = "group:<group_id>:<id_or_name:idx>"   (ONCE per group)
    └── 3. For each route in GatewayConfig.routes (in exact declaration order):
             ├── Lower matchers & scalar defaults (route over group over defaults)
             ├── Build route plugins: scope = "route:<route_id>:<id_or_name:idx>"
             ├── Assemble RouteSpec plugins: [group_plugins (Arc::clone)..., route_plugins...]
             └── SnapshotBuilder prepends global_plugins -> computes HookMask -> CompiledRoute
```

Key invariants:
- **Shared state across member routes:** Because every route in group `api_v2` receives an `Arc::clone` of the exact same `HttpPlugin` instance built under `group:api_v2:api-v2-rl`, token-bucket counters (`rate-limit`), JWKS caches (`jwt-auth`), quota windows (`ai-token-rate-limit`), and circuit breakers (`ai-failover`) are shared across all routes in `api_v2`.
- **Reload persistence & transactional GC:** Adding, removing, or modifying routes inside `api_v2` keeps `group:api_v2:api-v2-rl` alive in `RuntimeRegistry::state_store` across atomic reloads. Removing the group (or removing a plugin from the group) garbage-collects its `StateStore` scope automatically on `build_session.commit_gc()`.
- **Fail-fast compilation for empty groups:** Declared groups with zero attached routes still compile their plugins during `compile()` so `shunt check` catches invalid plugin configs immediately; `shunt verify` flags them with a `route_group.unused` warning.
- **Zero `shunt-engine` changes:** `GatewaySnapshot`, `CompiledRoute`, `SnapshotBuilder`, and `pipeline.rs` remain completely unchanged.

### 4.5 Inspection, Admin API & Static Verification

#### `SnapshotInspect` (`GET /snapshot` & `shunt check`)
- Add `pub route_groups: Vec<RouteGroupInspect>` to `SnapshotInspect`:
  - `id`, `hosts`, `path_prefix`, `methods`, `upstream`, `plugins: Vec<PluginInspect>` (with redacted config, `scope_id`, `hook_mask`), and `routes: Vec<String>` (member route IDs).
- Add `#[serde(skip_serializing_if = "Option::is_none")] pub group: Option<String>` to `RouteInspect`.
- `RouteInspect.plugin_details` lists the route's full non-global chain (group plugins first with `group:...` `scope_id`, then route plugins with `route:...` `scope_id`), matching `CompiledRoute.plugins` after `global_plugins`.

#### `shunt verify` (`crates/shunt-config/src/verify.rs`)
- **Effective chain verification:** All per-route static rules (`route.timeout_order`, `ai.plugin_order`, `ai.cache_order`, `ai.guardrails_order`, `ai.audit_order`, `ai.alerts_order`, `ai.unknown_upstream`, `ai.unknown_provider`, `ai.attempts_insufficient`, `mcp.plugin_order`, `mcp.unknown_upstream`, `mcp.auth_recommended`, `telemetry.no_trace_plugin`) inspect the **effective merged plugin list** (`group.plugins` + `route.plugins`) and resolved upstream/timeouts. This catches cross-boundary ordering errors (e.g., `ai-model-router` in a group while `ai-virtual-keys` is on a member route).
- **New diagnostic rule `route_group.unused` (`Severity::Warning`):** Emitted when a declared `[[route_groups]]` entry is not referenced by any route.
- **Policy matching by group:** Extend `RoutePolicy` with:
  ```rust
  #[serde(default)]
  pub match_group: Option<String>,
  ```
  - When `match_group` is set (glob pattern, e.g., `"api_*"`), the policy matches routes belonging to a matching group.
  - When both `match_route` (non-empty) and `match_group` are set, both must match.

### 4.6 Compatibility with Kubernetes Gateway API & `shunt-console`

#### Kubernetes Gateway API (`shunt-config::k8s`)
- **Zero breaking impact:** `compile_k8s_gateway_snapshot` continues compiling `GatewayClass`, `Gateway`, `HTTPRoute`, `Service`, `Endpoints`, `EndpointSlice`, and TLS `Secret` resources into `GatewayConfig` with `route_groups: Vec::new()` and `group: None` on emitted routes. No K8s manifest syntax, precedence sorting, or CLI flags change.
- **Future synergy:** Today, `k8s.rs` clones `Gateway`/`HTTPRoute`-level `shunt.io/plugins` annotations onto each compiled `(rule, match)` route—creating duplicate plugin instances per match. Once RFC 0021 is implemented, `k8s.rs` can optionally emit one `RouteGroupIr` per `HTTPRoute` carrying its `shunt.io/plugins`, enabling shared rate-limit buckets and JWKS caches across all rules of a single `HTTPRoute`.

#### Companion Control Plane (`shunt-console`)
- Per [docs/vision.md](../docs/vision.md), `shunt-console` drives stateless `shunt` data-plane nodes strictly through the `ConfigProvider` seam (pushing/serving canonical `GatewayConfig` IR) and reads `GET /snapshot` and `GET /api/status`.
- Making `RouteGroupIr` a first-class IR entity gives `shunt-console` a direct 1:1 representation for logical **APIs / Services / Route Groups** in its database and UI:
  - Operators configure shared auth, CORS, IP filtering, or rate limits once on a group and attach routes to it—preserving shared `StateStore` / Redis quota buckets without duplicating plugin payloads across every route.
  - `GET /snapshot` exposes both `route_groups` and each route's `group` membership so `shunt-console` can render effective vs. inherited plugins accurately.

## 5. Alternatives Considered & Rejected

1. **Nested `[[route_groups.routes]]` ownership instead of flat `[[routes]]` with `group = "..."`:**
   - *Why considered:* Familiar to web frameworks (Axum `nest`, Gin `Group`, Caddy `handle_path`).
   - *Why rejected:* In TOML, nested arrays-of-tables rapidly degrade readability (`[[route_groups.routes.plugins]]` + `[route_groups.routes.plugins.config]`). More critically, interleaving route-match precedence between nested group routes and top-level `[[routes]]` becomes non-obvious under Shunt's first-match-wins router. Flat `[[routes]]` referencing `group = "..."` keeps precedence 100% linear and TOML clean.
2. **Named `[[plugin_chains]]` / `[[presets]]` only (without route matchers or defaults):**
   - *Why considered:* Reusable plugin lists without touching route matching.
   - *Why rejected:* Misses half the real-world duplication (`hosts`, `path_prefix`, `strip_prefix`, `max_body_bytes`, timeouts) and doesn't map cleanly to logical APIs/services in `shunt-console` or `shunt verify` (`match_group`).
3. **Multi-group composition (`groups = ["cors", "auth", "api_v2"]`) or nested group inheritance:**
   - *Why considered:* Mixin-style composition across orthogonal concerns.
   - *Why rejected:* Introduces cycle validation, ambiguous precedence for conflicting scalar defaults (`upstream`, `path_prefix`, `max_body_bytes`, timeouts), and fragile cross-mixin plugin ordering. Single-level `group = "..."` covers the vast majority of real gateway topologies cleanly; orthogonal gateway-wide concerns already belong in global `[[plugins]]`.
4. **Implementing route-group dispatch at runtime inside `shunt-engine`:**
   - *Why considered:* Avoids flattening routes during compilation.
   - *Why rejected:* Adds branching, extra `Arc` dereferences, and two-level `HookMask` combination on every HTTP request, violating Shunt's "tiny core, zero hot-path overhead" guardrail.

## 6. Verification & Testing Plan

1. **Unit & reload tests (`crates/shunt-config`):**
   - Structural validation: duplicate group IDs, unknown group references, missing effective upstream, invalid host/method widening, contradictory exact header matchers.
   - Lowering & inheritance: `join_paths` edge cases, scalar override precedence (`route > group > default`), mirror concatenation, and `global → group → route` plugin order.
   - Shared state & reload persistence: verify two routes in the same group share a single `rate-limit` bucket and survive a hot reload adding/removing a sibling route without resetting counters, and that removing the group GCs its `StateStore` scope.
2. **Static verifier tests (`crates/shunt-config/src/verify.rs`):**
   - Route shadowing on lowered group+route paths.
   - Cross-boundary `ai.plugin_order` and `mcp.plugin_order` diagnostics (group plugin vs. route plugin).
   - `route_group.unused` warning and `RoutePolicy.match_group` enforcement.
3. **Property tests (`crates/shunt-config/tests/proptest_config.rs`):**
   - `join_paths` normalization invariants (always starts with `/`, never contains `//`, never has a trailing `/` unless `"/"`).
   - Host/method narrowing soundness (every request matching a lowered grouped route also matches the group's matcher).
4. **Declarative TOML conformance spec (`specs/route-groups.spec.toml` via `shunt test`):**
   - End-to-end test covering prefix/host lowering, shared group `rate-limit` quota across two distinct routes, group `jwt-auth` / `header-rewrite` + route-level overrides, and `GET /snapshot` inspection output.

## 7. Future Work

- **Kubernetes Gateway API `HTTPRoute` group lowering:** Emit a `RouteGroupIr` per `HTTPRoute` carrying `shunt.io/plugins` annotations so multi-rule `HTTPRoute` resources share stateful plugin instances automatically.
- **Admin Inspector UI group view:** Add group badges and group-level filtering to the opt-in Read-Only Admin Inspector Web UI (`--ui`).
- **`shunt-console` integration:** Map Console "API Groups / Services" directly onto `GatewayConfig.route_groups`.
