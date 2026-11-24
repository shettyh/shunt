# RFC 0022: Path Templates, Regex Routing & Captured Path Parameters

- **Status:** Implemented (Stage 1)
- **Crates:** `shunt-plugin-sdk`, `shunt-engine`, `shunt-plugins`, `shunt-config`, `specs/`, `examples/`, `fuzz/`

## 1. Summary

This RFC extends Shunt's path routing with two first-class precompiled path matchers—**parameterized path templates (`path_template`)** and **linear-time regular expressions (`path_regex`)**—alongside **single-pass `RegexSet` acceleration**, **pay-only-for-what-you-use captured path parameters (`RequestCtx::path_params`)**, **Kubernetes Gateway API v1 `RegularExpression` parity**, and **sound static route-shadowing analysis (`shunt verify`)**.

All existing `Exact`, `Prefix`, and `Any` routes preserve their exact zero-allocation hot path and explicit first-match-wins declaration order.

## 2. Motivation

Previously, `PathMatch` only supported `Any`, `Exact`, and segment-boundary `Prefix` matching. This created two concrete gaps for modern HTTP API gateways and Kubernetes Gateway API deployments:

1. **Parameterized REST endpoints:** Routing `/orders/{order_id}/status` to a different upstream, method policy, rate limit, or rewrite rule than `/orders/{order_id}/cancel` or `/orders/{order_id}` was impossible without falling back to a coarse `path_prefix = "/orders"` route.
2. **Constrained patterns & Kubernetes Gateway API v1 parity:** Constrained patterns (such as numeric-only IDs `^/orders/[0-9]+/status$` or file-extension matching) and Kubernetes Gateway API v1 `HTTPRoute` `PathMatchType::RegularExpression` rules were unsupported and rejected during compilation.

At the same time, any solution must uphold Shunt's core architectural guardrails:
- **Zero bloat:** Reuse the workspace's existing linear-time, ReDoS-safe `regex` crate (already compiled into the binary for `shunt-ai` and `shunt-mcp`) rather than adding backtracking regex engines or opinionated router crates.
- **Pay only for what you use:** Zero heap allocation during route matching, zero parameter extraction on static or `HookMask::EMPTY` routes, and zero regex overhead on snapshots with no regex routes.
- **Explicit first-match-wins precedence:** Preserve Shunt's deterministic top-to-bottom route evaluation across `(hosts, path, methods, headers)` and exact `route.shadowed` verification.

## 3. Goals & Non-Goals

### Goals
- **Zero-allocation `path_template` matching:** Precompile segment templates (`/orders/{order_id}/status`, `/files/{*filepath}`) with a SIMD-friendly `static_prefix` fast-reject and slice-based segment matching.
- **Safe, linear-time `path_regex` matching with `RegexSet` acceleration:** Precompile regexes with explicit memory/DFA limits, anchor full-path matches (`\A(?:...)\z`), and scan all regex routes in a snapshot in a single `O(path_len)` `RegexSet` pass—short-circuiting completely when an earlier non-regex route matches.
- **Opt-in captured path parameters on `RequestCtx`:** Expose `ctx.path_params` / `ctx.path_param("order_id")` for both `path_template` parameters and named `path_regex` capture groups `(?P<name>...)`, allocated **only** when a parameterized route wins and `!route.hook_mask.is_empty()`.
- **First-party `header-rewrite` interpolation:** Allow `{param}` placeholders in `header-rewrite` headers and `path_replace_full` with zero overhead for static configs.
- **Route Groups & Static Verification:** Lower `group.path_prefix + route.path_template` seamlessly, prevent unsafe `group.path_prefix + route.path_regex` combinations, and extend `shunt verify`'s `path_subsumes` algebra soundly.
- **Kubernetes Gateway API v1 `RegularExpression`:** Support `HTTPPathMatch.type = "RegularExpression"` with Gateway API v1 precedence (`Exact > PathPrefix (longest) > RegularExpression`).

### Non-Goals
- **Replacing declaration order with fixed router specificity (e.g., `matchit`):** Shunt routes match multi-dimensionally on `(hosts, path, methods, headers)` where overlapping paths with distinct methods/headers/hosts are normal and first-match-wins order must stay explicit.
- **Intra-segment template expressions (e.g., `/orders/ord-{id:[0-9]+}`):** Keeps `path_template` simple, fast, and statically decidable for subsumption checks; use `path_regex` for intra-segment or character-class constraints.
- **Backtracking / PCRE regex features (lookahead, backreferences):** Disallowed intentionally so untrusted paths can never trigger ReDoS.

## 4. Design

### 4.1 Path Template Syntax & Execution (`shunt-engine::path_match`)

A `path_template` is compiled once into `CompiledPathTemplate`:

```rust
pub enum TemplateSegment {
    Literal(Arc<str>),
    Param(Arc<str>),    // `{order_id}` — matches one non-empty slash-free segment
    Wildcard(Arc<str>), // `{*filepath}` — final segment only; matches 1+ remaining chars (may include `/`)
}

pub struct CompiledPathTemplate {
    raw: Arc<str>,
    static_prefix: Arc<str>, // literal prefix before first `{...}` (e.g. "/orders/")
    segments: Arc<[TemplateSegment]>,
    param_count: usize,
    has_wildcard: bool,
}
```

**Validation rules:**
- Must start with `/`, contain no `?` or `#`, no `//`, and no trailing `/` (except root `"/"`).
- Parameter names must match `[A-Za-z_][A-Za-z0-9_]*` and be unique within the template.
- `{*name}` wildcard segments must appear in the final segment position only.
- Partial-segment or unbalanced braces (e.g., `/orders/ord-{id}`) are rejected with an actionable hint pointing to `path_regex`.

**Hot-path execution:**
1. Fast-reject with `!path.starts_with(self.static_prefix.as_ref())` (single `memcmp`).
2. Walk `segments` against `&path[1..]` using pure `&str` slicing (`strip_prefix`, `find('/')`) with **zero allocations**.
3. Parameter extraction runs **only after** a route wins and only when `!route.hook_mask.is_empty() && route.matcher.path.has_params()`.

### 4.2 Regex Routing & `RegexSet` Acceleration (`shunt-engine`)

A `path_regex` is compiled once into `CompiledPathRegex`:
- Anchored internally as `\A(?:<raw>)\z` for full-path matching (matching Envoy `safe_regex` semantics and preventing accidental partial/substring hijacking).
- Built via `RegexBuilder` with `size_limit = 1 MiB` and `dfa_size_limit = 1 MiB` to guard against pathological patterns during config reload or untrusted manifest parsing.
- Named capture groups (`(?P<order_id>[0-9]+)`) are collected at compile time; during route matching, no capture vectors are allocated.

**Single-pass `RegexSet` dispatch in `GatewaySnapshot::match_route`:**
- When a snapshot contains **zero** regex routes, `GatewaySnapshot::regex_table` is `None` and dispatch runs the unchanged linear scan with zero overhead.
- When a snapshot contains `>= 1` regex route, `SnapshotBuilder::build()` compiles all anchored regex patterns into a single `regex::RegexSet`, records each regex route's `regex_set_slot: Option<usize>`, and stores `min_route_idx` (the lowest route index using `PathMatch::Regex`).
- On each request:
  1. Scan `routes[..min_route_idx]` first. If any earlier static/template route matches, return immediately—**`RegexSet` never runs**.
  2. Otherwise, execute `regex_table.set.matches(path)` **once** (`O(path_len)` across all regex routes combined).
  3. Scan `routes[min_route_idx..]`: regex routes check `regex_matches.matched(slot)` in `O(1)` before checking `methods`/`hosts`/`headers`.

This guarantees **exact behavioral equivalence** to naive first-match-wins linear scanning (`indexed_match(req) == linear_match(req)`), which is verified via property tests.

### 4.3 Captured Path Parameters (`shunt-plugin-sdk`)

```rust
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PathParams {
    entries: Option<Box<[(Arc<str>, String)]>>,
}
```

- Stored directly on `RequestCtx::path_params` with convenience accessor `ctx.path_param("order_id") -> Option<&str>`.
- `Option<Box<[...]>>` occupies 16 bytes (fat pointer niche) and performs **zero heap allocation** for every `Any`, `Exact`, `Prefix`, unnamed `Regex`, or `HookMask::EMPTY` route.
- `header-rewrite` detects `{...}` placeholders at plugin build time (`has_templates: bool`) so static rewrites stay on the precompiled zero-overhead path, while parameterized rewrites expand `{name}` from `ctx.path_params` in `request_set`/`request_add`/`upstream_set`/`response_set`/`response_add` and `path_replace_full`.

### 4.4 Config IR, Route Groups, Verifier & Kubernetes Gateway API (`shunt-config`)

#### Canonical IR (`shunt.toml`)
```toml
[[routes]]
id = "order_status"
group = "api_v2"
path_template = "/orders/{order_id}/status"  # lowered to "/v2/orders/{order_id}/status"
methods = ["GET"]
upstream = "orders_svc"

[[routes.plugins]]
name = "header-rewrite"
[routes.plugins.config]
upstream_set = { "x-order-id" = "{order_id}" }
path_replace_full = "/internal/orders/{order_id}/state"

[[routes]]
id = "legacy_invoice_pdf"
path_regex = "/invoices/(?P<year>[0-9]{4})/(?P<id>[0-9]+)\\.pdf"
methods = ["GET"]
upstream = "billing_svc"
```

- At most one of `path_prefix`, `path_exact`, `path_template`, or `path_regex` may be specified per route.
- **Route Groups:**
  - `group.path_prefix` + `route.path_template` lowers via `join_route_paths(gp, tpl)` and preserves group narrowing soundness.
  - `group.path_prefix` + `route.path_regex` is rejected during validation because prepending a prefix to an arbitrary regex breaks anchors/alternations and could violate RFC 0021's group boundary guarantee; groups without `path_prefix` may freely contain `path_regex` routes.

#### Static Verification (`shunt verify`)
`path_subsumes(earlier, later)` is extended soundly:
- `Prefix` vs `Template`: exact check that `Template`'s leading literal segments match the prefix segments.
- `Template` vs `Exact`: `earlier.matches(exact)`.
- `Template` vs `Template`: exact segment-by-segment subsumption (`Param` subsumes `Literal` and `Param` but not `Wildcard`; `Wildcard` subsumes any non-empty suffix of segments).
- `Template` vs `Prefix`: sound check when `Template` ends with a `Wildcard` strictly before the prefix's last segment and leading segments subsume.
- `Regex` vs `Exact`: `earlier.matches(exact)`.
- `Regex` vs `Regex`: exact raw-pattern equality (`er.raw() == lr.raw()`); conservative `false` otherwise to prevent false-positive shadowing errors.

#### Kubernetes Gateway API v1 (`shunt-config::k8s`)
- `HTTPPathMatch.type = "RegularExpression"` compiles to `RouteIr.path_regex`.
- `RoutePrecedenceKey.path_kind_rank` implements Gateway API v1 precedence:
  - `3` = `Exact`
  - `2` = `PathPrefix` (ranked by descending character length)
  - `1` = `RegularExpression` (ranked by headers, method, creationTimestamp, namespace/name, rule/match index)
  - `0` = `Any`
- `URLRewrite` / `RequestRedirect` with `ReplacePrefixMatch` is rejected on `RegularExpression` routes per Gateway API v1 rules (`ReplaceFullPath` remains supported).

## 5. Alternatives Considered & Rejected

1. **Adopting a third-party radix router (`matchit`) as the primary dispatcher:**
   - *Why rejected:* `matchit` enforces fixed specificity precedence and rejects overlapping patterns, conflicting with Shunt's multi-dimensional `(hosts, path, methods, headers)` first-match-wins routing model and `path_regex` support.
2. **Expressing `path_template` purely by lowering to `path_regex`:**
   - *Why rejected:* Loses decidable static route-shadowing checks (`path_subsumes`) in `shunt verify`, makes `group.path_prefix` lowering harder to verify, and is slower than direct `static_prefix` + segment slice walking.
3. **Unanchored `path_regex` matching:**
   - *Why rejected:* Unanchored regexes (e.g., `/orders/[0-9]+`) silently match unintended prefixes/suffixes (`/evil/orders/123/admin`), creating security surprises. Full-path anchoring (`\A(?:...)\z`) matches Envoy's `safe_regex` semantics and still allows prefix/suffix wildcards explicitly via `.*`.

## 6. Future Work (Stage 2)

- **Internal `Exact` hash map + Segment Trie candidate index inside `GatewaySnapshot`:** If future benchmarks target 1,000–10,000+ routes, add an internal candidate index returning route indices pruned by `best_idx`—preserving the exact same `PathMatch` API, `shunt.toml` schema, and first-match-wins equivalence.
- **Low-cardinality `http.route` metric/trace option:** Optionally expose the matched template pattern (e.g. `"/orders/{order_id}/status"`) to `otel-trace` and `metrics` plugins alongside `route_id`.
