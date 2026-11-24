use std::collections::HashMap;
use std::collections::hash_map::RandomState;
use std::hash::{BuildHasher, Hasher};
use std::sync::Arc;

use http::Request;
use regex::{RegexSet, RegexSetBuilder};

use crate::path_match::{DEFAULT_PATH_REGEX_SIZE_LIMIT, PathMatch, TemplateSegment};
use crate::snapshot::{CompiledRoute, MAX_REGEX_SET_SIZE_LIMIT};

/// Minimum route count at which [`GatewaySnapshot`](crate::GatewaySnapshot) activates
/// [`RouteIndex`] instead of flat linear scanning.
///
/// Below this threshold, linear scanning over a contiguous slice is L1-cache resident and
/// faster than hashing + trie traversal. Above it, `O(1)` exact lookup and `O(segments)`
/// trie dispatch scale cleanly to thousands of routes and 404 traffic.
pub const ROUTE_INDEX_MIN_ROUTES: usize = 16;

/// Fanout threshold for switching a trie node's literal children from a small inline slice
/// (zero hashing) to a hash map (`O(1)` lookup).
const SMALL_LITERAL_CHILDREN_MAX: usize = 8;

/// Sentinel node index indicating the absence of a parameter child in [`TrieNode`].
const NONE_NODE: u32 = u32::MAX;

/// Fast non-cryptographic multiplier for per-snapshot seeded hashing.
const FX_K: u64 = 0x517c_c1b7_2722_0a95;

/// Per-snapshot randomly seeded fast hasher for immutable config lookup tables.
///
/// Seeding from [`RandomState`] prevents static offline collision crafting while avoiding
/// SipHash overhead on every hot-path exact/trie lookup.
#[derive(Debug, Clone, Copy)]
struct FastBuildHasher {
    seed: u64,
}

impl FastBuildHasher {
    fn new() -> Self {
        let seed = RandomState::new().hash_one(FX_K);
        Self { seed }
    }
}

impl BuildHasher for FastBuildHasher {
    type Hasher = FastHasher;

    #[inline]
    fn build_hasher(&self) -> Self::Hasher {
        FastHasher { hash: self.seed }
    }
}

struct FastHasher {
    hash: u64,
}

impl FastHasher {
    #[inline]
    fn mix(&mut self, word: u64) {
        self.hash = (self.hash.rotate_left(5) ^ word).wrapping_mul(FX_K);
    }
}

impl Hasher for FastHasher {
    #[inline]
    fn finish(&self) -> u64 {
        // Avalanche mix so both low bits (bucket) and high 7 bits (SwissTable H2 tag) are well distributed.
        let mut h = self.hash;
        h ^= h >> 33;
        h = h.wrapping_mul(0xff51_afd7_ed55_8ccd);
        h ^= h >> 33;
        h
    }

    #[inline]
    fn write(&mut self, bytes: &[u8]) {
        let (chunks8, rem) = bytes.as_chunks::<8>();
        for chunk in chunks8 {
            self.mix(u64::from_ne_bytes(*chunk));
        }
        let (chunks4, rem) = rem.as_chunks::<4>();
        if let Some(chunk) = chunks4.first() {
            self.mix(u32::from_ne_bytes(*chunk) as u64);
        }
        for &b in rem {
            self.mix(b as u64);
        }
    }

    #[inline]
    fn write_u8(&mut self, i: u8) {
        self.mix(i as u64);
    }
}

enum LiteralChildren {
    Empty,
    Small(Box<[(Box<str>, u32)]>),
    Map(HashMap<Box<str>, u32, FastBuildHasher>),
}

impl std::fmt::Debug for LiteralChildren {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LiteralChildren::Empty => f.write_str("Empty"),
            LiteralChildren::Small(items) => f.debug_tuple("Small").field(&items.len()).finish(),
            LiteralChildren::Map(map) => f.debug_tuple("Map").field(&map.len()).finish(),
        }
    }
}

impl LiteralChildren {
    #[inline]
    fn get(&self, seg: &str) -> Option<u32> {
        match self {
            LiteralChildren::Empty => None,
            LiteralChildren::Small(items) => {
                for (k, id) in items.iter() {
                    if k.as_ref() == seg {
                        return Some(*id);
                    }
                }
                None
            }
            LiteralChildren::Map(map) => map.get(seg).copied(),
        }
    }
}

#[derive(Debug)]
struct TrieNode {
    /// Minimum declaration index of any route stored in this node or its subtree.
    min_subtree_idx: u32,
    /// Index of the single-segment parameter child node (`{param}`), or [`NONE_NODE`].
    param_child: u32,
    /// Exact-depth template routes terminating at this node (sorted ascending by route index).
    exact_routes: Box<[u32]>,
    /// Canonical `PathMatch::Prefix` routes terminating at this node (sorted ascending).
    prefix_routes: Box<[u32]>,
    /// Trailing `{*wildcard}` template routes branching from this node (sorted ascending).
    wildcard_routes: Box<[u32]>,
    /// Literal segment child edges.
    literal_children: LiteralChildren,
}

#[derive(Default)]
struct BuilderTrieNode {
    min_subtree_idx: u32,
    param_child: u32,
    exact_routes: Vec<u32>,
    prefix_routes: Vec<u32>,
    wildcard_routes: Vec<u32>,
    literal_children: HashMap<String, u32>,
}

impl BuilderTrieNode {
    fn new() -> Self {
        Self {
            min_subtree_idx: u32::MAX,
            param_child: NONE_NODE,
            exact_routes: Vec::new(),
            prefix_routes: Vec::new(),
            wildcard_routes: Vec::new(),
            literal_children: HashMap::new(),
        }
    }
}

struct IndexedRegexBucket {
    route_indices: Box<[u32]>,
    set: Option<RegexSet>,
}

impl std::fmt::Debug for IndexedRegexBucket {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IndexedRegexBucket")
            .field("route_count", &self.route_indices.len())
            .field("has_regex_set", &self.set.is_some())
            .finish()
    }
}

/// Internal candidate index baked into [`GatewaySnapshot`](crate::GatewaySnapshot) for
/// `O(1)` exact, `O(segments)` prefix/template, and single-pass `RegexSet` route dispatch.
///
/// Strictly preserves first-match-wins declaration order across `(hosts, path, methods, headers)`
/// by tracking the winning `best_idx` and pruning any bucket or trie subtree whose minimum
/// declaration index is `>= best_idx`.
#[derive(Debug)]
pub struct RouteIndex {
    exact_map: HashMap<Box<str>, Box<[u32]>, FastBuildHasher>,
    min_exact_idx: u32,
    trie_nodes: Box<[TrieNode]>,
    any_routes: Box<[u32]>,
    min_any_idx: u32,
    /// Non-canonical `PathMatch::Prefix` routes (e.g. `""`, `"//"`, `"/a//b"`, relative prefixes)
    /// that cannot be lowered into the canonical segment trie. Always empty for `shunt-config` inputs.
    fallback_routes: Box<[u32]>,
    min_fallback_idx: u32,
    regex_bucket: Option<IndexedRegexBucket>,
    min_regex_idx: u32,
}

impl RouteIndex {
    /// Builds an immutable [`RouteIndex`] over `routes`.
    ///
    /// # Panics
    /// Panics if `routes.len() >= u32::MAX as usize`.
    pub fn build(routes: &[Arc<CompiledRoute>]) -> Self {
        assert!(
            routes.len() < u32::MAX as usize,
            "RouteIndex supports at most u32::MAX - 1 routes"
        );

        let hasher = FastBuildHasher::new();
        let mut exact_builder: HashMap<String, Vec<u32>> = HashMap::new();
        let mut min_exact_idx = u32::MAX;

        let mut trie_builder: Vec<BuilderTrieNode> = vec![BuilderTrieNode::new()];
        let mut any_routes: Vec<u32> = Vec::new();
        let mut fallback_routes: Vec<u32> = Vec::new();

        let mut regex_indices: Vec<u32> = Vec::new();
        let mut regex_patterns: Vec<String> = Vec::new();

        for (raw_idx, route) in routes.iter().enumerate() {
            let idx = raw_idx as u32;
            match &route.matcher.path {
                PathMatch::Any => {
                    any_routes.push(idx);
                }
                PathMatch::Exact(path) => {
                    min_exact_idx = min_exact_idx.min(idx);
                    exact_builder.entry(path.clone()).or_default().push(idx);
                }
                PathMatch::Prefix(prefix) => {
                    if prefix == "/" {
                        any_routes.push(idx);
                    } else if let Some(trimmed) = canonical_prefix_trimmed(prefix) {
                        insert_prefix_into_trie(&mut trie_builder, trimmed, idx);
                    } else {
                        fallback_routes.push(idx);
                    }
                }
                PathMatch::Template(tpl) => {
                    if !tpl.has_params() {
                        // Parameterless template matches identically to Exact(raw).
                        min_exact_idx = min_exact_idx.min(idx);
                        exact_builder
                            .entry(tpl.raw().to_owned())
                            .or_default()
                            .push(idx);
                    } else {
                        insert_template_into_trie(&mut trie_builder, tpl.segments(), idx);
                    }
                }
                PathMatch::Regex(re) => {
                    regex_indices.push(idx);
                    regex_patterns.push(re.anchored_pattern().to_owned());
                }
            }
        }

        let mut exact_map = HashMap::with_capacity_and_hasher(exact_builder.len(), hasher);
        for (path, ids) in exact_builder {
            exact_map.insert(path.into_boxed_str(), ids.into_boxed_slice());
        }

        let trie_nodes = freeze_trie(trie_builder, hasher);
        let min_any_idx = any_routes.first().copied().unwrap_or(u32::MAX);
        let min_fallback_idx = fallback_routes.first().copied().unwrap_or(u32::MAX);
        let min_regex_idx = regex_indices.first().copied().unwrap_or(u32::MAX);

        let regex_bucket = if !regex_indices.is_empty() {
            let budget = DEFAULT_PATH_REGEX_SIZE_LIMIT
                .saturating_mul(regex_patterns.len().max(1))
                .min(MAX_REGEX_SET_SIZE_LIMIT);
            let set = RegexSetBuilder::new(&regex_patterns)
                .size_limit(budget)
                .dfa_size_limit(budget)
                .build()
                .ok();
            Some(IndexedRegexBucket {
                route_indices: regex_indices.into_boxed_slice(),
                set,
            })
        } else {
            None
        };

        Self {
            exact_map,
            min_exact_idx,
            trie_nodes,
            any_routes: any_routes.into_boxed_slice(),
            min_any_idx,
            fallback_routes: fallback_routes.into_boxed_slice(),
            min_fallback_idx,
            regex_bucket,
            min_regex_idx,
        }
    }

    #[inline]
    fn min_trie_idx(&self) -> u32 {
        self.trie_nodes[0].min_subtree_idx
    }

    /// Finds the first matching route in declaration order (`0..routes.len()`).
    pub fn match_route<'a, B>(
        &self,
        routes: &'a [Arc<CompiledRoute>],
        req: &Request<B>,
    ) -> Option<&'a Arc<CompiledRoute>> {
        let path = req.uri().path();
        let mut best_idx: u32 = u32::MAX;
        let mut cached_host: Option<Option<&str>> = None;

        // 1. O(1) exact path lookup.
        if self.min_exact_idx < best_idx
            && let Some(ids) = self.exact_map.get(path)
        {
            consider_sorted_ids(ids, routes, req, &mut cached_host, &mut best_idx);
        }

        let min_trie = self.min_trie_idx();

        // 2a. If an `Any` (or `Prefix("/")`) route precedes the trie (e.g. top-of-table host catch-all),
        // check `Any` first so a match prunes the entire trie walk.
        let mut any_checked = false;
        if self.min_any_idx < best_idx && self.min_any_idx < min_trie {
            consider_sorted_ids(
                &self.any_routes,
                routes,
                req,
                &mut cached_host,
                &mut best_idx,
            );
            any_checked = true;
        }

        // 2b. O(segments) Segment Trie lookup for canonical Prefix + Template + Wildcard routes.
        if min_trie < best_idx && path.starts_with('/') {
            let tail = &path[1..];
            if !tail.is_empty() {
                let root = &self.trie_nodes[0];
                if !root.wildcard_routes.is_empty() {
                    consider_sorted_ids(
                        &root.wildcard_routes,
                        routes,
                        req,
                        &mut cached_host,
                        &mut best_idx,
                    );
                }
                if min_trie < best_idx {
                    let (seg, next_rest) = split_first_segment(tail);
                    if !seg.is_empty() {
                        self.descend_children(
                            root,
                            seg,
                            next_rest,
                            routes,
                            req,
                            &mut cached_host,
                            &mut best_idx,
                        );
                    }
                }
            }
        }

        // 3. Remaining `Any` routes (typical bottom-of-table fallback — skipped when an earlier route won).
        if !any_checked && self.min_any_idx < best_idx {
            consider_sorted_ids(
                &self.any_routes,
                routes,
                req,
                &mut cached_host,
                &mut best_idx,
            );
        }

        // 4. Non-canonical `Prefix` fallback routes (always empty for standard configs).
        if self.min_fallback_idx < best_idx {
            for &idx in self.fallback_routes.iter() {
                if idx >= best_idx {
                    break;
                }
                let route = &routes[idx as usize];
                if route.matcher.path.matches(path)
                    && route.matcher.matches_non_path_cached(req, &mut cached_host)
                {
                    best_idx = idx;
                    break;
                }
            }
        }

        // 5. Single-pass `RegexSet` bucket (skipped completely if any earlier route matched).
        if self.min_regex_idx < best_idx
            && let Some(bucket) = &self.regex_bucket
        {
            if let Some(set) = &bucket.set {
                let matches = set.matches(path);
                for slot in matches.iter() {
                    let idx = bucket.route_indices[slot];
                    if idx >= best_idx {
                        break;
                    }
                    if routes[idx as usize]
                        .matcher
                        .matches_non_path_cached(req, &mut cached_host)
                    {
                        best_idx = idx;
                        break;
                    }
                }
            } else {
                for &idx in bucket.route_indices.iter() {
                    if idx >= best_idx {
                        break;
                    }
                    let route = &routes[idx as usize];
                    if route.matcher.path.matches(path)
                        && route.matcher.matches_non_path_cached(req, &mut cached_host)
                    {
                        best_idx = idx;
                        break;
                    }
                }
            }
        }

        (best_idx != u32::MAX).then(|| &routes[best_idx as usize])
    }

    #[allow(clippy::too_many_arguments)]
    #[inline]
    fn descend_children<'r, B>(
        &self,
        parent: &TrieNode,
        seg: &str,
        next_rest: Option<&str>,
        routes: &[Arc<CompiledRoute>],
        req: &'r Request<B>,
        cached_host: &mut Option<Option<&'r str>>,
        best_idx: &mut u32,
    ) {
        let lit_id = parent.literal_children.get(seg);
        let param_id = (parent.param_child != NONE_NODE).then_some(parent.param_child);

        match (lit_id, param_id) {
            (Some(l), Some(p)) => {
                let l_min = self.trie_nodes[l as usize].min_subtree_idx;
                let p_min = self.trie_nodes[p as usize].min_subtree_idx;
                // Visit the branch with the lower minimum declaration index first to maximize pruning.
                let (first_id, first_min, second_id, second_min) = if l_min <= p_min {
                    (l, l_min, p, p_min)
                } else {
                    (p, p_min, l, l_min)
                };
                if first_min < *best_idx {
                    self.visit_node(first_id, next_rest, routes, req, cached_host, best_idx);
                }
                if second_min < *best_idx {
                    self.visit_node(second_id, next_rest, routes, req, cached_host, best_idx);
                }
            }
            (Some(l), None) => {
                if self.trie_nodes[l as usize].min_subtree_idx < *best_idx {
                    self.visit_node(l, next_rest, routes, req, cached_host, best_idx);
                }
            }
            (None, Some(p)) => {
                if self.trie_nodes[p as usize].min_subtree_idx < *best_idx {
                    self.visit_node(p, next_rest, routes, req, cached_host, best_idx);
                }
            }
            (None, None) => {}
        }
    }

    fn visit_node<'r, B>(
        &self,
        node_id: u32,
        rest: Option<&str>,
        routes: &[Arc<CompiledRoute>],
        req: &'r Request<B>,
        cached_host: &mut Option<Option<&'r str>>,
        best_idx: &mut u32,
    ) {
        let node = &self.trie_nodes[node_id as usize];
        if node.min_subtree_idx >= *best_idx {
            return;
        }

        // Canonical `PathMatch::Prefix` matches whether the path ends here, has a trailing `/`, or continues.
        if !node.prefix_routes.is_empty() {
            consider_sorted_ids(&node.prefix_routes, routes, req, cached_host, best_idx);
        }

        match rest {
            None => {
                // Path ended at this exact segment depth: exact-depth templates match.
                if !node.exact_routes.is_empty() {
                    consider_sorted_ids(&node.exact_routes, routes, req, cached_host, best_idx);
                }
            }
            Some(tail) => {
                if tail.is_empty() {
                    // Trailing `/` cannot match exact-depth templates or `{*wildcard}` (which requires 1+ chars).
                    return;
                }
                if !node.wildcard_routes.is_empty() {
                    consider_sorted_ids(&node.wildcard_routes, routes, req, cached_host, best_idx);
                }
                if node.min_subtree_idx >= *best_idx {
                    return;
                }
                let (next_seg, next_rest) = split_first_segment(tail);
                if !next_seg.is_empty() {
                    self.descend_children(
                        node,
                        next_seg,
                        next_rest,
                        routes,
                        req,
                        cached_host,
                        best_idx,
                    );
                }
            }
        }
    }
}

#[inline]
fn split_first_segment(tail: &str) -> (&str, Option<&str>) {
    match tail.find('/') {
        Some(pos) => (&tail[..pos], Some(&tail[pos + 1..])),
        None => (tail, None),
    }
}

#[inline]
fn consider_sorted_ids<'r, B>(
    ids: &[u32],
    routes: &[Arc<CompiledRoute>],
    req: &'r Request<B>,
    cached_host: &mut Option<Option<&'r str>>,
    best_idx: &mut u32,
) {
    for &idx in ids {
        if idx >= *best_idx {
            break;
        }
        if routes[idx as usize]
            .matcher
            .matches_non_path_cached(req, cached_host)
        {
            *best_idx = idx;
            break;
        }
    }
}

/// Returns the trimmed prefix if it can be represented cleanly in the canonical segment trie
/// (starts with `/`, has at least one segment after trimming trailing `/`, and contains no empty `//` segments).
fn canonical_prefix_trimmed(prefix: &str) -> Option<&str> {
    let trimmed = prefix.trim_end_matches('/');
    if trimmed.len() <= 1 || !trimmed.starts_with('/') {
        return None;
    }
    if trimmed[1..].split('/').any(|seg| seg.is_empty()) {
        return None;
    }
    Some(trimmed)
}

fn insert_prefix_into_trie(nodes: &mut Vec<BuilderTrieNode>, trimmed_prefix: &str, route_idx: u32) {
    let mut cur = 0usize;
    nodes[cur].min_subtree_idx = nodes[cur].min_subtree_idx.min(route_idx);

    for seg in trimmed_prefix[1..].split('/') {
        let next = if let Some(&existing) = nodes[cur].literal_children.get(seg) {
            existing as usize
        } else {
            let new_id = nodes.len() as u32;
            nodes.push(BuilderTrieNode::new());
            nodes[cur].literal_children.insert(seg.to_owned(), new_id);
            new_id as usize
        };
        cur = next;
        nodes[cur].min_subtree_idx = nodes[cur].min_subtree_idx.min(route_idx);
    }

    nodes[cur].prefix_routes.push(route_idx);
}

fn insert_template_into_trie(
    nodes: &mut Vec<BuilderTrieNode>,
    segments: &[TemplateSegment],
    route_idx: u32,
) {
    let mut cur = 0usize;
    nodes[cur].min_subtree_idx = nodes[cur].min_subtree_idx.min(route_idx);

    for seg in segments {
        match seg {
            TemplateSegment::Literal(lit) => {
                let next = if let Some(&existing) = nodes[cur].literal_children.get(lit.as_ref()) {
                    existing as usize
                } else {
                    let new_id = nodes.len() as u32;
                    nodes.push(BuilderTrieNode::new());
                    nodes[cur]
                        .literal_children
                        .insert(lit.as_ref().to_owned(), new_id);
                    new_id as usize
                };
                cur = next;
                nodes[cur].min_subtree_idx = nodes[cur].min_subtree_idx.min(route_idx);
            }
            TemplateSegment::Param(_) => {
                let next = if nodes[cur].param_child != NONE_NODE {
                    nodes[cur].param_child as usize
                } else {
                    let new_id = nodes.len() as u32;
                    nodes.push(BuilderTrieNode::new());
                    nodes[cur].param_child = new_id;
                    new_id as usize
                };
                cur = next;
                nodes[cur].min_subtree_idx = nodes[cur].min_subtree_idx.min(route_idx);
            }
            TemplateSegment::Wildcard(_) => {
                nodes[cur].wildcard_routes.push(route_idx);
                return;
            }
        }
    }

    nodes[cur].exact_routes.push(route_idx);
}

fn freeze_trie(builder_nodes: Vec<BuilderTrieNode>, hasher: FastBuildHasher) -> Box<[TrieNode]> {
    let subtree_mins: Vec<u32> = builder_nodes.iter().map(|n| n.min_subtree_idx).collect();

    builder_nodes
        .into_iter()
        .map(|node| {
            let literal_children = if node.literal_children.is_empty() {
                LiteralChildren::Empty
            } else if node.literal_children.len() <= SMALL_LITERAL_CHILDREN_MAX {
                let mut items: Vec<(Box<str>, u32)> = node
                    .literal_children
                    .into_iter()
                    .map(|(k, id)| (k.into_boxed_str(), id))
                    .collect();
                items.sort_by_key(|(_, id)| subtree_mins[*id as usize]);
                LiteralChildren::Small(items.into_boxed_slice())
            } else {
                let mut map =
                    HashMap::with_capacity_and_hasher(node.literal_children.len(), hasher);
                for (k, id) in node.literal_children {
                    map.insert(k.into_boxed_str(), id);
                }
                LiteralChildren::Map(map)
            };

            TrieNode {
                min_subtree_idx: node.min_subtree_idx,
                param_child: node.param_child,
                exact_routes: node.exact_routes.into_boxed_slice(),
                prefix_routes: node.prefix_routes.into_boxed_slice(),
                wildcard_routes: node.wildcard_routes.into_boxed_slice(),
                literal_children,
            }
        })
        .collect::<Vec<_>>()
        .into_boxed_slice()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{RouteMatch, RouteSpec, RuntimeRegistry, SnapshotBuilder, UpstreamConfig};
    use http::{Method, header::HeaderName};

    fn make_routes(specs: Vec<(&str, RouteMatch)>) -> Vec<Arc<CompiledRoute>> {
        let reg = RuntimeRegistry::new();
        let mut builder = SnapshotBuilder::new(1).upstream(UpstreamConfig::new(
            "be",
            vec!["http://127.0.0.1:8081".to_owned()],
        ));
        for (id, matcher) in specs {
            builder = builder.route(RouteSpec::new(id, matcher, "be"));
        }
        builder.build(&reg, false).unwrap().routes.clone()
    }

    fn assert_equiv(routes: &[Arc<CompiledRoute>], index: &RouteIndex, req: &Request<()>) {
        let expected = routes
            .iter()
            .find(|r| r.matcher.matches(req))
            .map(|r| r.id.as_str());
        let actual = index.match_route(routes, req).map(|r| r.id.as_str());
        assert_eq!(
            actual,
            expected,
            "mismatch for {} {} (host={:?})",
            req.method(),
            req.uri().path(),
            req.headers().get(http::header::HOST)
        );
    }

    #[test]
    fn empty_index_matches_nothing() {
        let routes = make_routes(vec![]);
        let index = RouteIndex::build(&routes);
        let req = Request::builder().uri("/anything").body(()).unwrap();
        assert_equiv(&routes, &index, &req);
    }

    #[test]
    fn tricky_paths_slashes_wildcards_and_non_canonical_prefixes() {
        let routes = make_routes(vec![
            ("exact_root", RouteMatch::exact("/")),
            (
                "tpl_root_wild",
                RouteMatch::template("/{*all}")
                    .unwrap()
                    .with_method(Method::POST),
            ),
            (
                "tpl_files_wild",
                RouteMatch::template("/files/{*fp}").unwrap(),
            ),
            (
                "tpl_order_status",
                RouteMatch::template("/orders/{id}/status").unwrap(),
            ),
            (
                "tpl_param_then_lit",
                RouteMatch::template("/{tenant}/status").unwrap(),
            ),
            ("prefix_orders_slash", RouteMatch::prefix("/orders/")),
            ("prefix_noncanon_empty", RouteMatch::prefix("//")),
            ("prefix_noncanon_double", RouteMatch::prefix("/a//b")),
            ("prefix_noncanon_rel", RouteMatch::prefix("rel")),
            (
                "tpl_static_only",
                RouteMatch::template("/static/health").unwrap(),
            ),
            ("re_numeric", RouteMatch::regex(r"/items/[0-9]+").unwrap()),
            (
                "prefix_root",
                RouteMatch::prefix("/").with_host("fallback.example.com"),
            ),
            (
                "any_last",
                RouteMatch::any().with_header(HeaderName::from_static("x-catch"), "1"),
            ),
        ]);
        let index = RouteIndex::build(&routes);

        let paths = [
            "/",
            "//",
            "///",
            "/orders",
            "/orders/",
            "/orders//status",
            "/orders/123/status",
            "/orders/123/status/",
            "/orders/status",
            "/acme/status",
            "/acme/status/",
            "/files",
            "/files/",
            "/files/a",
            "/files//a",
            "/files/a/b/c/",
            "/a//b",
            "/a//b/c",
            "/static/health",
            "/static/health/",
            "/items/42",
            "/items/abc",
            "/unknown",
        ];

        for path in paths {
            for method in [Method::GET, Method::POST] {
                for host in ["api.example.com", "fallback.example.com"] {
                    for catch in [false, true] {
                        let mut b = Request::builder()
                            .method(method.clone())
                            .uri(path)
                            .header(http::header::HOST, host);
                        if catch {
                            b = b.header("x-catch", "1");
                        }
                        let req = b.body(()).unwrap();
                        assert_equiv(&routes, &index, &req);
                    }
                }
            }
        }
    }

    #[test]
    fn high_fanout_trie_map_and_first_match_wins_precedence() {
        let mut specs = Vec::new();
        // Top-of-table host-scoped `Any` route to exercise early-any pruning.
        specs.push(("admin_any", RouteMatch::any().with_host("admin.local")));
        // 30 literal children under `/svc` to force `LiteralChildren::Map`.
        for i in 0..30 {
            let id = Box::leak(format!("svc_{i}").into_boxed_str());
            specs.push((
                id,
                RouteMatch::template(&format!("/svc/item_{i}/{{id}}")).unwrap(),
            ));
        }
        // Overlapping param route at higher index.
        specs.push((
            "svc_fallback_param",
            RouteMatch::template("/svc/{name}/{id}").unwrap(),
        ));
        // Bottom-of-table regex.
        specs.push((
            "re_tail",
            RouteMatch::regex(r"/svc/special-[0-9]+").unwrap(),
        ));

        let routes = make_routes(specs);
        let index = RouteIndex::build(&routes);

        for path in [
            "/svc/item_0/42",
            "/svc/item_29/99",
            "/svc/unknown/99",
            "/svc/special-123",
            "/nowhere",
        ] {
            for host in ["api.local", "admin.local"] {
                let req = Request::builder()
                    .uri(path)
                    .header(http::header::HOST, host)
                    .body(())
                    .unwrap();
                assert_equiv(&routes, &index, &req);
            }
        }
    }

    #[test]
    fn snapshot_activates_route_index_at_threshold() {
        let reg = RuntimeRegistry::new();
        let build_n = |n: usize| {
            let mut b = SnapshotBuilder::new(1).upstream(UpstreamConfig::new(
                "be",
                vec!["http://127.0.0.1:8081".to_owned()],
            ));
            for i in 0..n {
                b = b.route(RouteSpec::new(
                    format!("r_{i}"),
                    RouteMatch::prefix(format!("/svc-{i}")),
                    "be",
                ));
            }
            b.build(&reg, false).unwrap()
        };

        let small = build_n(ROUTE_INDEX_MIN_ROUTES - 1);
        assert!(!small.is_indexed());

        let indexed = build_n(ROUTE_INDEX_MIN_ROUTES);
        assert!(indexed.is_indexed());

        let req = Request::builder()
            .uri(format!("/svc-{}/ping", ROUTE_INDEX_MIN_ROUTES - 1))
            .body(())
            .unwrap();
        assert_eq!(
            indexed.match_route(&req).map(|r| r.id.as_str()),
            indexed.match_route_linear(&req).map(|r| r.id.as_str())
        );
    }

    /// Release-mode routing microbenchmark matrix comparing `match_route_linear` vs `RouteIndex`
    /// vs `GatewaySnapshot::match_route`.
    ///
    /// Run with: `cargo test -p shunt-engine --release route_index_perf_matrix -- --ignored --nocapture`
    #[test]
    #[ignore]
    fn route_index_perf_matrix() {
        use std::hint::black_box;
        use std::time::Instant;

        fn bench_ns<F: FnMut()>(iters: u64, mut f: F) -> f64 {
            // Warmup
            for _ in 0..(iters / 10).max(1000) {
                f();
            }
            let start = Instant::now();
            for _ in 0..iters {
                f();
            }
            start.elapsed().as_nanos() as f64 / iters as f64
        }

        let reg = RuntimeRegistry::new();
        println!(
            "\n{:>6} | {:<14} | {:>10} | {:>10} | {:>10} | {:>8}",
            "routes", "case", "linear ns", "index ns", "snap ns", "speedup"
        );
        println!("{}", "-".repeat(72));

        for &n in &[4usize, 10, 16, 24, 32, 64, 200, 1000, 5000] {
            let mut builder = SnapshotBuilder::new(1).upstream(UpstreamConfig::new(
                "be",
                vec!["http://127.0.0.1:8081".to_owned()],
            ));
            for i in 0..n {
                let matcher = match i % 4 {
                    0 => RouteMatch::exact(format!("/api/v1/svc-{i}/health")),
                    1 => RouteMatch::prefix(format!("/api/v1/svc-{i}")),
                    2 => {
                        RouteMatch::template(&format!("/api/v1/svc-{i}/orders/{{order_id}}/status"))
                            .unwrap()
                            .with_method(Method::GET)
                    }
                    _ => RouteMatch::template(&format!("/api/v1/svc-{i}/files/{{*filepath}}"))
                        .unwrap(),
                };
                builder = builder.route(RouteSpec::new(format!("r_{i}"), matcher, "be"));
            }
            let snap = builder.build(&reg, false).unwrap();
            let index = RouteIndex::build(&snap.routes);

            let first_req = Request::builder()
                .method(Method::GET)
                .uri("/api/v1/svc-0/health")
                .body(())
                .unwrap();
            let mid = n / 2;
            let mid_uri = match mid % 4 {
                0 => format!("/api/v1/svc-{mid}/health"),
                1 => format!("/api/v1/svc-{mid}/items"),
                2 => format!("/api/v1/svc-{mid}/orders/ord-42/status"),
                _ => format!("/api/v1/svc-{mid}/files/a/b/c.txt"),
            };
            let mid_req = Request::builder()
                .method(Method::GET)
                .uri(&mid_uri)
                .body(())
                .unwrap();
            let last = n - 1;
            let last_uri = match last % 4 {
                0 => format!("/api/v1/svc-{last}/health"),
                1 => format!("/api/v1/svc-{last}/items"),
                2 => format!("/api/v1/svc-{last}/orders/ord-42/status"),
                _ => format!("/api/v1/svc-{last}/files/a/b/c.txt"),
            };
            let last_req = Request::builder()
                .method(Method::GET)
                .uri(&last_uri)
                .body(())
                .unwrap();
            let miss_req = Request::builder()
                .method(Method::GET)
                .uri("/api/v1/nonexistent-service/orders/999/status")
                .body(())
                .unwrap();

            let iters = if n >= 1000 { 20_000 } else { 200_000 };
            for (label, req) in [
                ("hit_first", &first_req),
                ("hit_mid", &mid_req),
                ("hit_last", &last_req),
                ("miss_404", &miss_req),
            ] {
                assert_eq!(
                    snap.match_route(req).map(|r| r.id.as_str()),
                    snap.match_route_linear(req).map(|r| r.id.as_str())
                );
                assert_eq!(
                    index.match_route(&snap.routes, req).map(|r| r.id.as_str()),
                    snap.match_route_linear(req).map(|r| r.id.as_str())
                );

                let lin_ns = bench_ns(iters, || {
                    black_box(snap.match_route_linear(black_box(req)));
                });
                let idx_ns = bench_ns(iters, || {
                    black_box(index.match_route(&snap.routes, black_box(req)));
                });
                let snap_ns = bench_ns(iters, || {
                    black_box(snap.match_route(black_box(req)));
                });
                println!(
                    "{:>6} | {:<14} | {:>10.1} | {:>10.1} | {:>10.1} | {:>7.2}x",
                    n,
                    label,
                    lin_ns,
                    idx_ns,
                    snap_ns,
                    lin_ns / snap_ns
                );
            }
        }
    }
}
