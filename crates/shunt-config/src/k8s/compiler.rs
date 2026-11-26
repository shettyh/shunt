//! Pure, deterministic, fault-isolated Kubernetes Gateway API v1 compiler.
//!
//! Compiles a [`K8sClusterSnapshot`] into:
//! - Per-listener [`CompiledK8sListener`] bundles (one per active `(Gateway, port)`),
//! - Desired per-`Gateway` [`DesiredK8sService`] port-mapped Service definitions,
//! - Complete Gateway API v1 [`K8sStatusPlan`] (`GatewayClass`, `Gateway`, `HTTPRoute`).

use std::collections::{BTreeMap, HashMap, HashSet};
use std::time::SystemTime;

use serde_json::{Map as JsonMap, Value as JsonValue};
use shunt_engine::{CompiledPathRegex, load_certified_key_pem};

use crate::error::ConfigError;
use crate::ir::{
    AdminConfig, ClientAuthModeIr, GatewayConfig, PluginAttachment, RouteIr, RouteMirrorIr,
    ServerConfig, ServerTlsConfig, SniCertConfig, UpstreamEndpointIr, UpstreamIr,
};
use crate::provider::sha256_hex;

use super::K8sGatewayOptions;
use super::status::{
    K8sCondition, K8sGatewayAddress, K8sGatewayClassStatus, K8sGatewayStatus, K8sHttpRouteStatus,
    K8sListenerStatus, K8sRouteParentStatus, K8sStatusPlan, K8sSupportedFeature,
    SUPPORTED_GATEWAY_FEATURES, format_rfc3339_utc,
};
use super::types::{
    K8sClusterSnapshot, K8sEndpointPort, K8sEndpointSlice, K8sEndpoints, K8sGateway,
    K8sHttpBackendRef, K8sHttpPathMatch, K8sHttpRoute, K8sHttpRouteFilter, K8sHttpRouteMatch,
    K8sListener, K8sNamespace, K8sParentRef, K8sReferenceGrant, K8sRouteGroupKind, K8sSecret,
    K8sService, K8sServicePort,
};

pub(crate) const REDIRECT_NOOP_UPSTREAM: &str = "_k8s_redirect_noop";
pub(crate) const SPLIT_PLACEHOLDER_UPSTREAM: &str = "_k8s_split_placeholder";
const GATEWAY_API_GROUP: &str = "gateway.networking.k8s.io";

/// Stable, deterministic internal pod port allocator for shared-Deployment multi-Gateway isolation.
///
/// Maps each active `(gateway_namespace, gateway_name, external_port)` tuple to a unique internal
/// port within `[range_start..=range_end]` and preserves existing mappings across hot reloads so
/// active listeners never drop connections when unrelated Gateways appear or disappear.
#[derive(Debug, Clone)]
pub struct PortAllocator {
    range_start: u16,
    range_end: u16,
    allocated: BTreeMap<(String, String, u16), u16>,
    used: HashSet<u16>,
}

impl PortAllocator {
    pub fn new(range_start: u16, range_end: u16) -> Self {
        let (start, end) = if range_start <= range_end {
            (range_start, range_end)
        } else {
            (range_end, range_start)
        };
        Self {
            range_start: start,
            range_end: end,
            allocated: BTreeMap::new(),
            used: HashSet::new(),
        }
    }

    /// Allocates (or returns the existing) internal port for `(gw_ns, gw_name, external_port)`.
    pub fn allocate(&mut self, gw_ns: &str, gw_name: &str, external_port: u16) -> Option<u16> {
        let key = (gw_ns.to_owned(), gw_name.to_owned(), external_port);
        if let Some(&existing) = self.allocated.get(&key) {
            return Some(existing);
        }
        let span = u32::from(self.range_end) - u32::from(self.range_start) + 1;
        // Deterministic FNV-1a 32-bit hash for reproducible initial port assignment.
        let mut h: u32 = 2_166_136_261;
        for b in gw_ns
            .bytes()
            .chain(std::iter::once(b'/'))
            .chain(gw_name.bytes())
            .chain(std::iter::once(b':'))
            .chain(external_port.to_be_bytes())
        {
            h ^= u32::from(b);
            h = h.wrapping_mul(16_777_619);
        }
        let start_offset = h % span;
        for step in 0..span {
            let candidate = self.range_start + ((start_offset + step) % span) as u16;
            if self.used.insert(candidate) {
                self.allocated.insert(key, candidate);
                return Some(candidate);
            }
        }
        None
    }

    /// Releases port assignments for `(gw_ns, gw_name, external_port)` keys no longer active.
    pub fn prune(&mut self, active: &HashSet<(String, String, u16)>) {
        self.allocated.retain(|k, port| {
            if active.contains(k) {
                true
            } else {
                self.used.remove(port);
                false
            }
        });
    }
}

/// Desired port entry on a Shunt-managed per-`Gateway` Kubernetes `Service`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DesiredK8sServicePort {
    pub name: String,
    pub external_port: u16,
    pub target_port: u16,
}

/// Desired per-`Gateway` Kubernetes `Service` that routes external traffic to the shared Shunt pods.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DesiredK8sService {
    pub namespace: String,
    pub name: String,
    pub gateway_namespace: String,
    pub gateway_name: String,
    pub service_type: String,
    pub selector: BTreeMap<String, String>,
    pub ports: Vec<DesiredK8sServicePort>,
}

/// One compiled listener socket for a `(Gateway, external_port)` tuple.
#[derive(Debug, Clone)]
pub struct CompiledK8sListener {
    pub gateway_namespace: String,
    pub gateway_name: String,
    pub external_port: u16,
    pub internal_port: u16,
    pub is_tls: bool,
    pub config: GatewayConfig,
    pub digest: String,
}

/// Complete output of pure multi-Gateway cluster compilation.
#[derive(Debug, Clone)]
pub struct CompiledK8sCluster {
    pub listeners: Vec<CompiledK8sListener>,
    pub desired_services: Vec<DesiredK8sService>,
    pub status_plan: K8sStatusPlan,
}

/// Computes the canonical Kubernetes Service name managed by Shunt for a `Gateway`.
pub fn gateway_service_name(gateway_name: &str) -> String {
    let raw = format!("shunt-gw-{gateway_name}");
    if raw.len() <= 63 {
        raw
    } else {
        let mut s = raw[..63].trim_end_matches('-').to_owned();
        if s.is_empty() {
            s = "shunt-gw".to_owned();
        }
        s
    }
}

/// Evaluates Kubernetes Gateway API `ReferenceGrant` authorization.
///
/// Same-namespace references are always permitted. Cross-namespace references require an
/// explicit `ReferenceGrant` in `to_ns` matching `(from_group, from_kind, from_ns)` and
/// `(to_group, to_kind, to_name | None)`.
#[allow(clippy::too_many_arguments)]
pub fn is_reference_permitted(
    grants: &[K8sReferenceGrant],
    from_group: &str,
    from_kind: &str,
    from_ns: &str,
    to_group: &str,
    to_kind: &str,
    to_ns: &str,
    to_name: &str,
) -> bool {
    if from_ns == to_ns {
        return true;
    }
    let norm_from_group = normalize_group(from_group);
    let norm_to_group = normalize_group(to_group);

    grants.iter().any(|rg| {
        if rg.metadata.effective_namespace() != to_ns {
            return false;
        }
        let from_ok = rg.spec.from.iter().any(|f| {
            normalize_group(&f.group) == norm_from_group
                && f.kind == from_kind
                && f.namespace == from_ns
        });
        if !from_ok {
            return false;
        }
        rg.spec.to.iter().any(|t| {
            normalize_group(&t.group) == norm_to_group
                && t.kind == to_kind
                && match t.name.as_deref() {
                    None | Some("") => true,
                    Some(n) => n == to_name,
                }
        })
    })
}

#[inline]
fn normalize_group(group: &str) -> &str {
    if group.is_empty() || group.eq_ignore_ascii_case("core") {
        ""
    } else {
        group
    }
}

#[inline]
fn normalize_listener_hostname(hostname: Option<&str>) -> String {
    match hostname.map(str::trim) {
        None | Some("") | Some("*") => "*".to_owned(),
        Some(h) => h.to_ascii_lowercase(),
    }
}

#[derive(Debug, Clone)]
struct ListenerEval {
    index: usize,
    name: String,
    port: u16,
    is_tls: bool,
    accepted: bool,
    accepted_reason: &'static str,
    accepted_msg: String,
    conflicted: bool,
    conflicted_reason: &'static str,
    conflicted_msg: String,
    resolved_refs: bool,
    resolved_refs_reason: &'static str,
    resolved_refs_msg: String,
    supported_kinds: Vec<K8sRouteGroupKind>,
    allows_http_route: bool,
    certs: Vec<(Option<String>, String, String)>,
    attached_routes: i32,
}

impl ListenerEval {
    fn is_programmable(&self) -> bool {
        self.accepted && !self.conflicted && self.resolved_refs
    }
}

struct SnapshotIndexes<'a> {
    namespaces: HashMap<&'a str, &'a K8sNamespace>,
    services: HashMap<(&'a str, &'a str), &'a K8sService>,
    endpoints: HashMap<(&'a str, &'a str), &'a K8sEndpoints>,
    slices: HashMap<(&'a str, &'a str), Vec<&'a K8sEndpointSlice>>,
    secrets: HashMap<(&'a str, &'a str), &'a K8sSecret>,
    grants: &'a [K8sReferenceGrant],
}

impl<'a> SnapshotIndexes<'a> {
    fn build(snap: &'a K8sClusterSnapshot) -> Self {
        let namespaces = snap
            .namespaces
            .iter()
            .map(|n| (n.metadata.name.as_str(), n))
            .collect();
        let services = snap
            .services
            .iter()
            .map(|s| {
                (
                    (s.metadata.effective_namespace(), s.metadata.name.as_str()),
                    s,
                )
            })
            .collect();
        let endpoints = snap
            .endpoints
            .iter()
            .map(|e| {
                (
                    (e.metadata.effective_namespace(), e.metadata.name.as_str()),
                    e,
                )
            })
            .collect();
        let mut slices: HashMap<(&'a str, &'a str), Vec<&'a K8sEndpointSlice>> = HashMap::new();
        for slice in &snap.endpoint_slices {
            if let Some(svc_name) = slice.metadata.labels.get("kubernetes.io/service-name") {
                slices
                    .entry((slice.metadata.effective_namespace(), svc_name.as_str()))
                    .or_default()
                    .push(slice);
            }
        }
        let secrets = snap
            .secrets
            .iter()
            .map(|s| {
                (
                    (s.metadata.effective_namespace(), s.metadata.name.as_str()),
                    s,
                )
            })
            .collect();
        Self {
            namespaces,
            services,
            endpoints,
            slices,
            secrets,
            grants: &snap.reference_grants,
        }
    }
}

fn evaluate_gateway_listeners(gw: &K8sGateway, idx: &SnapshotIndexes<'_>) -> Vec<ListenerEval> {
    let gw_ns = gw.metadata.effective_namespace();

    // Detect protocol & hostname conflicts on the same port.
    let mut protocols_by_port: HashMap<u16, HashSet<String>> = HashMap::new();
    let mut host_counts_by_port: HashMap<(u16, String), usize> = HashMap::new();
    for l in &gw.spec.listeners {
        protocols_by_port
            .entry(l.port)
            .or_default()
            .insert(l.protocol.to_ascii_uppercase());
        *host_counts_by_port
            .entry((l.port, normalize_listener_hostname(l.hostname.as_deref())))
            .or_insert(0) += 1;
    }

    let mut evals = Vec::with_capacity(gw.spec.listeners.len());
    for (i, l) in gw.spec.listeners.iter().enumerate() {
        let proto_upper = l.protocol.to_ascii_uppercase();
        let is_http = proto_upper == "HTTP";
        let is_https = proto_upper == "HTTPS";

        let mut accepted = true;
        let mut accepted_reason = "Accepted";
        let mut accepted_msg = "Listener accepted".to_owned();

        let mut conflicted = false;
        let mut conflicted_reason = "NoConflicts";
        let mut conflicted_msg = "No listener conflicts".to_owned();

        let mut resolved_refs = true;
        let mut resolved_refs_reason = "ResolvedRefs";
        let mut resolved_refs_msg = "All references resolved".to_owned();

        // 1. Protocol support check
        if !is_http && !is_https {
            accepted = false;
            accepted_reason = "UnsupportedProtocol";
            accepted_msg = format!("Protocol `{}` is not supported by Shunt", l.protocol);
        }

        // 2. Port conflict checks
        if let Some(protos) = protocols_by_port.get(&l.port)
            && protos.len() > 1
        {
            conflicted = true;
            conflicted_reason = "ProtocolConflict";
            conflicted_msg = format!("Multiple protocols configured on port {}", l.port);
            accepted = false;
            accepted_reason = "ProtocolConflict";
            accepted_msg = conflicted_msg.clone();
        } else if host_counts_by_port
            .get(&(l.port, normalize_listener_hostname(l.hostname.as_deref())))
            .copied()
            .unwrap_or(0)
            > 1
        {
            conflicted = true;
            conflicted_reason = "HostnameConflict";
            conflicted_msg = format!(
                "Duplicate hostname `{}` on port {}",
                normalize_listener_hostname(l.hostname.as_deref()),
                l.port
            );
            accepted = false;
            accepted_reason = "HostnameConflict";
            accepted_msg = conflicted_msg.clone();
        }

        // 3. Allowed route kinds check
        let mut supported_kinds = Vec::new();
        let mut allows_http_route = false;
        if is_http || is_https {
            let explicit_kinds = l
                .allowed_routes
                .as_ref()
                .map(|ar| ar.kinds.as_slice())
                .unwrap_or(&[]);
            if explicit_kinds.is_empty() {
                supported_kinds.push(K8sRouteGroupKind {
                    group: Some(GATEWAY_API_GROUP.to_owned()),
                    kind: "HTTPRoute".to_owned(),
                });
                allows_http_route = true;
            } else {
                let mut has_invalid_kind = false;
                for gk in explicit_kinds {
                    let grp = gk.group.as_deref().unwrap_or(GATEWAY_API_GROUP);
                    if grp == GATEWAY_API_GROUP && gk.kind == "HTTPRoute" {
                        supported_kinds.push(K8sRouteGroupKind {
                            group: Some(GATEWAY_API_GROUP.to_owned()),
                            kind: "HTTPRoute".to_owned(),
                        });
                        allows_http_route = true;
                    } else {
                        has_invalid_kind = true;
                    }
                }
                if has_invalid_kind {
                    resolved_refs = false;
                    resolved_refs_reason = "InvalidRouteKinds";
                    resolved_refs_msg =
                        "One or more allowedRoutes.kinds are unsupported (only HTTPRoute is supported)"
                            .to_owned();
                }
            }
        }

        // 4. HTTPS TLS validation (per-listener fault isolation!)
        let mut certs = Vec::new();
        if is_https {
            match &l.tls {
                None => {
                    accepted = false;
                    accepted_reason = "InvalidParameters";
                    accepted_msg = "HTTPS listener requires `tls` configuration".to_owned();
                }
                Some(ltls) => {
                    let mode = ltls.mode.as_deref().unwrap_or("Terminate");
                    if !mode.eq_ignore_ascii_case("Terminate") {
                        accepted = false;
                        accepted_reason = "UnsupportedValue";
                        accepted_msg =
                            format!("TLS mode `{mode}` is not supported (only `Terminate`)");
                    } else if ltls.certificate_refs.is_empty() {
                        resolved_refs = false;
                        resolved_refs_reason = "InvalidCertificateRef";
                        resolved_refs_msg =
                            "HTTPS Terminate listener requires at least one certificateRef"
                                .to_owned();
                    } else {
                        for cref in &ltls.certificate_refs {
                            let grp = cref.group.as_deref().unwrap_or("");
                            let kind = cref.kind.as_deref().unwrap_or("Secret");
                            if !normalize_group(grp).is_empty() || kind != "Secret" {
                                resolved_refs = false;
                                resolved_refs_reason = "InvalidCertificateRef";
                                resolved_refs_msg = format!(
                                    "Unsupported certificateRef group=`{grp}` kind=`{kind}`"
                                );
                                continue;
                            }
                            let sec_ns = cref.namespace.as_deref().unwrap_or(gw_ns);
                            if !is_reference_permitted(
                                idx.grants,
                                GATEWAY_API_GROUP,
                                "Gateway",
                                gw_ns,
                                "",
                                "Secret",
                                sec_ns,
                                &cref.name,
                            ) {
                                resolved_refs = false;
                                resolved_refs_reason = "RefNotPermitted";
                                resolved_refs_msg = format!(
                                    "Cross-namespace Secret `{sec_ns}/{}` requires a ReferenceGrant",
                                    cref.name
                                );
                                continue;
                            }
                            let Some(secret) = idx.secrets.get(&(sec_ns, cref.name.as_str()))
                            else {
                                resolved_refs = false;
                                resolved_refs_reason = "InvalidCertificateRef";
                                resolved_refs_msg =
                                    format!("TLS Secret `{sec_ns}/{}` not found", cref.name);
                                continue;
                            };
                            let Some(cert_pem) = extract_secret_key(secret, "tls.crt") else {
                                resolved_refs = false;
                                resolved_refs_reason = "InvalidCertificateRef";
                                resolved_refs_msg = format!(
                                    "TLS Secret `{sec_ns}/{}` missing valid `tls.crt`",
                                    cref.name
                                );
                                continue;
                            };
                            let Some(key_pem) = extract_secret_key(secret, "tls.key") else {
                                resolved_refs = false;
                                resolved_refs_reason = "InvalidCertificateRef";
                                resolved_refs_msg = format!(
                                    "TLS Secret `{sec_ns}/{}` missing valid `tls.key`",
                                    cref.name
                                );
                                continue;
                            };
                            // Cryptographically validate the PEM cert/key pair via ring/rustls.
                            if let Err(e) =
                                load_certified_key_pem(cert_pem.as_bytes(), key_pem.as_bytes())
                            {
                                resolved_refs = false;
                                resolved_refs_reason = "InvalidCertificateRef";
                                resolved_refs_msg = format!(
                                    "TLS Secret `{sec_ns}/{}` has invalid PEM keypair: {e}",
                                    cref.name
                                );
                                continue;
                            }
                            certs.push((l.hostname.clone(), cert_pem, key_pem));
                        }
                    }
                }
            }
        }

        evals.push(ListenerEval {
            index: i,
            name: l.name.clone(),
            port: l.port,
            is_tls: is_https,
            accepted,
            accepted_reason,
            accepted_msg,
            conflicted,
            conflicted_reason,
            conflicted_msg,
            resolved_refs,
            resolved_refs_reason,
            resolved_refs_msg,
            supported_kinds,
            allows_http_route,
            certs,
            attached_routes: 0,
        });
    }
    evals
}

#[derive(Debug, Clone)]
struct RoutePrecedenceKey {
    /// 2 = exact host, 1 = wildcard host, 0 = any host
    host_specificity: u8,
    /// Descending length of hostname (longer wildcard suffix `*.sub.example.com` > `*.example.com`).
    host_len: usize,
    /// 3 = Exact, 2 = PathPrefix, 1 = RegularExpression, 0 = Any
    path_kind_rank: u8,
    path_len: usize,
    header_count: usize,
    query_param_count: usize,
    has_method: bool,
    creation_timestamp: String,
    namespace: String,
    name: String,
    rule_idx: usize,
    match_idx: usize,
}

impl RoutePrecedenceKey {
    fn cmp_precedence(&self, other: &Self) -> std::cmp::Ordering {
        // Per Kubernetes Gateway API v1 precedence:
        // 1. Hostname specificity (exact > longest wildcard > any)
        // 2. Path match type & length (Exact > longest PathPrefix > RegularExpression > Any)
        // 3. Header match count (desc), Query param count (desc), Method match (true > false)
        // 4. Tie-breakers: oldest creationTimestamp, then namespace/name/rule/match ascending.
        other
            .host_specificity
            .cmp(&self.host_specificity)
            .then_with(|| other.host_len.cmp(&self.host_len))
            .then_with(|| other.path_kind_rank.cmp(&self.path_kind_rank))
            .then_with(|| other.path_len.cmp(&self.path_len))
            .then_with(|| other.header_count.cmp(&self.header_count))
            .then_with(|| other.query_param_count.cmp(&self.query_param_count))
            .then_with(|| other.has_method.cmp(&self.has_method))
            .then_with(|| cmp_creation_ts(&self.creation_timestamp, &other.creation_timestamp))
            .then_with(|| self.namespace.cmp(&other.namespace))
            .then_with(|| self.name.cmp(&other.name))
            .then_with(|| self.rule_idx.cmp(&other.rule_idx))
            .then_with(|| self.match_idx.cmp(&other.match_idx))
    }
}

fn cmp_creation_ts(a: &str, b: &str) -> std::cmp::Ordering {
    match (a.is_empty(), b.is_empty()) {
        (true, true) => std::cmp::Ordering::Equal,
        (true, false) => std::cmp::Ordering::Greater,
        (false, true) => std::cmp::Ordering::Less,
        (false, false) => a.cmp(b),
    }
}

struct RankedRoute {
    precedence: RoutePrecedenceKey,
    route: RouteIr,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BackendRefError {
    InvalidKind,
    RefNotPermitted,
    BackendNotFound,
}

impl BackendRefError {
    fn reason(self) -> &'static str {
        match self {
            BackendRefError::InvalidKind => "InvalidKind",
            BackendRefError::RefNotPermitted => "RefNotPermitted",
            BackendRefError::BackendNotFound => "BackendNotFound",
        }
    }
}

/// Pure, fault-isolated multi-Gateway cluster compiler (Phase 1 & Phase 2 core).
///
/// Never fails the entire cluster due to one invalid Secret, denied `ReferenceGrant`,
/// conflicting listener, or unknown `backendRef`: instead, isolates the failure in
/// `status_plan` and compiles unresolved backends into synthetic HTTP `500` targets.
pub fn compile_k8s_gateway_cluster(
    snap: &K8sClusterSnapshot,
    opts: &K8sGatewayOptions,
    allocator: &mut PortAllocator,
) -> CompiledK8sCluster {
    let now_ts = format_rfc3339_utc(SystemTime::now());
    let idx = SnapshotIndexes::build(snap);
    let mut status_plan = K8sStatusPlan::default();

    // 1. Managed GatewayClasses + GatewayClass.status
    let mut managed_classes: HashSet<&str> = HashSet::new();
    for gc in &snap.gateway_classes {
        if gc.spec.controller_name == opts.controller_name {
            managed_classes.insert(gc.metadata.name.as_str());
            let features = SUPPORTED_GATEWAY_FEATURES
                .iter()
                .map(|&name| K8sSupportedFeature {
                    name: name.to_owned(),
                })
                .collect();
            status_plan.gateway_classes.insert(
                gc.metadata.name.clone(),
                K8sGatewayClassStatus {
                    conditions: vec![K8sCondition::new(
                        "Accepted",
                        true,
                        gc.metadata.effective_generation(),
                        "Accepted",
                        "GatewayClass is accepted by Shunt",
                        &now_ts,
                    )],
                    supported_features: features,
                },
            );
        }
    }

    // 2. Filter managed Gateways and evaluate all listeners per Gateway
    let mut matching_gateways: Vec<&K8sGateway> = snap
        .gateways
        .iter()
        .filter(|gw| {
            if let Some(ns) = &opts.namespace
                && gw.metadata.effective_namespace() != ns
            {
                return false;
            }
            if let Some(name) = &opts.gateway_name
                && gw.metadata.name != *name
            {
                return false;
            }
            if snap.gateway_classes.is_empty() {
                true
            } else {
                managed_classes.contains(gw.spec.gateway_class_name.as_str())
            }
        })
        .collect();
    matching_gateways.sort_by(|a, b| {
        (a.metadata.effective_namespace(), a.metadata.name.as_str())
            .cmp(&(b.metadata.effective_namespace(), b.metadata.name.as_str()))
    });

    let mut gw_evals: BTreeMap<(String, String), (&K8sGateway, Vec<ListenerEval>)> =
        BTreeMap::new();
    for gw in &matching_gateways {
        let key = (
            gw.metadata.effective_namespace().to_owned(),
            gw.metadata.name.clone(),
        );
        let evals = evaluate_gateway_listeners(gw, &idx);
        gw_evals.insert(key, (gw, evals));
    }

    // 3. Allocate internal pod ports per active (Gateway, external_port)
    let mut active_port_keys: HashSet<(String, String, u16)> = HashSet::new();
    let mut port_map: BTreeMap<(String, String, u16), u16> = BTreeMap::new();
    for ((gw_ns, gw_name), (_, evals)) in &gw_evals {
        for ev in evals {
            if ev.accepted && !ev.conflicted {
                let pkey = (gw_ns.clone(), gw_name.clone(), ev.port);
                if active_port_keys.insert(pkey.clone())
                    && let Some(internal) = allocator.allocate(gw_ns, gw_name, ev.port)
                {
                    port_map.insert(pkey, internal);
                }
            }
        }
    }
    allocator.prune(&active_port_keys);

    // Per (gw_ns, gw_name, external_port) route & upstream accumulators
    struct PortAccumulator {
        upstreams: BTreeMap<String, UpstreamIr>,
        ranked_routes: Vec<RankedRoute>,
        needs_redirect_noop: bool,
        needs_split_placeholder: bool,
    }
    let mut port_accum: BTreeMap<(String, String, u16), PortAccumulator> = BTreeMap::new();

    // 4. Evaluate HTTPRoutes, attach to listeners, compile rules, compute HTTPRoute.status
    let mut sorted_routes: Vec<&K8sHttpRoute> = snap.http_routes.iter().collect();
    sorted_routes.sort_by(|a, b| {
        (a.metadata.effective_namespace(), a.metadata.name.as_str())
            .cmp(&(b.metadata.effective_namespace(), b.metadata.name.as_str()))
    });

    for http_route in sorted_routes {
        let route_ns = http_route.metadata.effective_namespace();
        let route_name = &http_route.metadata.name;
        if let Some(ns_filter) = &opts.namespace
            && route_ns != ns_filter
        {
            continue;
        }
        let route_gen = http_route.metadata.effective_generation();

        // Preserve parent statuses from foreign controllers if present in snapshot.
        if let Some(existing_status) = &http_route.status {
            let foreign: Vec<JsonValue> = existing_status
                .parents
                .iter()
                .filter(|p| {
                    p.get("controllerName").and_then(JsonValue::as_str)
                        != Some(opts.controller_name.as_str())
                })
                .cloned()
                .collect();
            if !foreign.is_empty() {
                status_plan
                    .foreign_route_parents
                    .insert((route_ns.to_owned(), route_name.clone()), foreign);
            }
        }

        // Pre-validate all backendRefs & mirrors in this HTTPRoute once for `ResolvedRefs` status.
        let (resolved_refs_ok, resolved_refs_reason, resolved_refs_msg) =
            check_route_backend_refs(http_route, &idx, true);

        let mut parent_statuses: Vec<K8sRouteParentStatus> = Vec::new();

        for pref in &http_route.spec.parent_refs {
            let pref_group = pref.group.as_deref().unwrap_or(GATEWAY_API_GROUP);
            let pref_kind = pref.kind.as_deref().unwrap_or("Gateway");
            if pref_group != GATEWAY_API_GROUP || pref_kind != "Gateway" {
                continue;
            }
            let target_ns = pref.namespace.as_deref().unwrap_or(route_ns);
            let gw_key = (target_ns.to_owned(), pref.name.clone());
            let Some((gw, evals)) = gw_evals.get_mut(&gw_key) else {
                // Not a Gateway managed by Shunt; ignore per Gateway API spec.
                continue;
            };
            let gw = *gw;

            // Match listeners by sectionName and port.
            let candidate_indices: Vec<usize> = evals
                .iter()
                .enumerate()
                .filter(|(_, ev)| {
                    if let Some(sec) = &pref.section_name
                        && ev.name != *sec
                    {
                        return false;
                    }
                    if let Some(p) = pref.port
                        && ev.port != p
                    {
                        return false;
                    }
                    true
                })
                .map(|(i, _)| i)
                .collect();

            if candidate_indices.is_empty() {
                parent_statuses.push(build_route_parent_status(
                    pref,
                    &opts.controller_name,
                    route_gen,
                    false,
                    "NoMatchingParent",
                    "No listener on parent Gateway matched parentRef sectionName/port",
                    resolved_refs_ok,
                    resolved_refs_reason,
                    &resolved_refs_msg,
                    &now_ts,
                ));
                continue;
            }

            // Filter by allowedRoutes (namespaces + kinds)
            let allowed_indices: Vec<usize> = candidate_indices
                .into_iter()
                .filter(|&li| {
                    let ev = &evals[li];
                    let listener = &gw.spec.listeners[ev.index];
                    ev.allows_http_route
                        && listener_allows_route_ns(gw, listener, http_route, &idx.namespaces)
                })
                .collect();

            if allowed_indices.is_empty() {
                parent_statuses.push(build_route_parent_status(
                    pref,
                    &opts.controller_name,
                    route_gen,
                    false,
                    "NotAllowedByListeners",
                    "Parent Gateway listeners do not allow this HTTPRoute",
                    resolved_refs_ok,
                    resolved_refs_reason,
                    &resolved_refs_msg,
                    &now_ts,
                ));
                continue;
            }

            // Filter by hostname intersection per listener
            let mut attached_by_port: BTreeMap<u16, Vec<String>> = BTreeMap::new();
            let mut matched_any_hostname = false;
            let mut matched_any_wildcard_all_by_port: HashSet<u16> = HashSet::new();

            for &li in &allowed_indices {
                let ev = &mut evals[li];
                let listener = &gw.spec.listeners[ev.index];
                let Some(hosts) =
                    compute_effective_hostnames(&[(gw, listener)], &http_route.spec.hostnames)
                else {
                    continue;
                };
                matched_any_hostname = true;
                ev.attached_routes += 1;

                if ev.accepted && !ev.conflicted {
                    if hosts.is_empty() {
                        matched_any_wildcard_all_by_port.insert(ev.port);
                    } else {
                        let entry = attached_by_port.entry(ev.port).or_default();
                        for h in hosts {
                            push_unique(entry, h);
                        }
                    }
                }
            }

            if !matched_any_hostname {
                parent_statuses.push(build_route_parent_status(
                    pref,
                    &opts.controller_name,
                    route_gen,
                    false,
                    "NoMatchingListenerHostname",
                    "No listener hostname intersected with HTTPRoute hostnames",
                    resolved_refs_ok,
                    resolved_refs_reason,
                    &resolved_refs_msg,
                    &now_ts,
                ));
                continue;
            }

            // Compile rules onto each active external_port for this Gateway.
            let mut route_compile_err: Option<String> = None;
            let mut ports_to_emit: HashSet<u16> = attached_by_port.keys().copied().collect();
            ports_to_emit.extend(matched_any_wildcard_all_by_port.iter().copied());

            for ext_port in ports_to_emit {
                let pkey = (target_ns.to_owned(), pref.name.clone(), ext_port);
                let accum = port_accum.entry(pkey).or_insert_with(|| PortAccumulator {
                    upstreams: BTreeMap::new(),
                    ranked_routes: Vec::new(),
                    needs_redirect_noop: false,
                    needs_split_placeholder: false,
                });
                let hosts = if matched_any_wildcard_all_by_port.contains(&ext_port) {
                    Vec::new()
                } else {
                    attached_by_port.remove(&ext_port).unwrap_or_default()
                };
                if let Err(err) = compile_http_route_into_accum(
                    gw,
                    http_route,
                    &hosts,
                    &idx,
                    opts,
                    true,
                    &mut accum.upstreams,
                    &mut accum.ranked_routes,
                    &mut accum.needs_redirect_noop,
                    &mut accum.needs_split_placeholder,
                ) {
                    route_compile_err = Some(err.to_string());
                }
            }

            if let Some(err_msg) = route_compile_err {
                parent_statuses.push(build_route_parent_status(
                    pref,
                    &opts.controller_name,
                    route_gen,
                    false,
                    "UnsupportedValue",
                    &err_msg,
                    resolved_refs_ok,
                    resolved_refs_reason,
                    &resolved_refs_msg,
                    &now_ts,
                ));
            } else {
                parent_statuses.push(build_route_parent_status(
                    pref,
                    &opts.controller_name,
                    route_gen,
                    true,
                    "Accepted",
                    "HTTPRoute accepted by Shunt",
                    resolved_refs_ok,
                    resolved_refs_reason,
                    &resolved_refs_msg,
                    &now_ts,
                ));
            }
        }

        if !parent_statuses.is_empty() {
            status_plan.http_routes.insert(
                (route_ns.to_owned(), route_name.clone()),
                K8sHttpRouteStatus {
                    parents: parent_statuses,
                },
            );
        }
    }

    // 5. Build DesiredK8sService, CompiledK8sListener, and Gateway.status for every managed Gateway
    let mut desired_services = Vec::new();
    let mut listeners = Vec::new();

    for ((gw_ns, gw_name), (gw, evals)) in gw_evals {
        let gw_gen = gw.metadata.effective_generation();
        let svc_name = gateway_service_name(&gw_name);

        // Collect unique active external ports on this Gateway.
        let mut by_port: BTreeMap<u16, Vec<&ListenerEval>> = BTreeMap::new();
        for ev in &evals {
            if ev.accepted && !ev.conflicted {
                by_port.entry(ev.port).or_default().push(ev);
            }
        }

        let mut svc_ports = Vec::new();
        for (&ext_port, port_evals) in &by_port {
            let pkey = (gw_ns.clone(), gw_name.clone(), ext_port);
            let Some(&internal_port) = port_map.get(&pkey) else {
                continue;
            };
            svc_ports.push(DesiredK8sServicePort {
                name: format!("p-{ext_port}"),
                external_port: ext_port,
                target_port: internal_port,
            });

            // Compile listener TLS config (only from programmable HTTPS listeners on this port).
            let is_tls = port_evals.iter().any(|e| e.is_tls);
            let mut server_tls = if is_tls {
                build_port_tls_config(gw, port_evals, &idx)
            } else {
                None
            };
            // If every HTTPS listener on this port failed cert resolution, skip binding an invalid TLS socket.
            if is_tls && server_tls.is_none() {
                continue;
            }
            if !is_tls {
                server_tls = None;
            }

            let mut global_plugins = opts.global_plugins.clone();
            if let Some(raw_json) = gw.metadata.annotations.get("shunt.io/global-plugins")
                && let Ok(parsed) = serde_json::from_str::<Vec<PluginAttachment>>(raw_json)
            {
                global_plugins.extend(parsed);
            }

            let mut accum = port_accum.remove(&pkey).unwrap_or_else(|| PortAccumulator {
                upstreams: BTreeMap::new(),
                ranked_routes: Vec::new(),
                needs_redirect_noop: false,
                needs_split_placeholder: false,
            });
            insert_sentinel_upstreams(
                &mut accum.upstreams,
                accum.needs_redirect_noop,
                accum.needs_split_placeholder,
            );
            accum
                .ranked_routes
                .sort_by(|a, b| a.precedence.cmp_precedence(&b.precedence));

            let cfg = GatewayConfig {
                server: ServerConfig {
                    listen: format!("0.0.0.0:{internal_port}"),
                    drain_timeout_ms: 30_000,
                    tls: server_tls,
                },
                admin: AdminConfig {
                    enabled: false,
                    ..AdminConfig::default()
                },
                state: Default::default(),
                telemetry: Default::default(),
                plugins: global_plugins,
                upstreams: accum.upstreams.into_values().collect(),
                route_groups: Vec::new(),
                routes: accum.ranked_routes.into_iter().map(|r| r.route).collect(),
                verify: Default::default(),
            };

            if cfg.validate().is_ok() {
                let canonical = serde_json::to_vec(&cfg).unwrap_or_default();
                let digest = sha256_hex(&canonical);
                listeners.push(CompiledK8sListener {
                    gateway_namespace: gw_ns.clone(),
                    gateway_name: gw_name.clone(),
                    external_port: ext_port,
                    internal_port,
                    is_tls,
                    config: cfg,
                    digest,
                });
            }
        }

        if !svc_ports.is_empty() {
            desired_services.push(DesiredK8sService {
                namespace: gw_ns.clone(),
                name: svc_name.clone(),
                gateway_namespace: gw_ns.clone(),
                gateway_name: gw_name.clone(),
                service_type: opts.service_type.clone(),
                selector: opts.pod_selector.clone(),
                ports: svc_ports,
            });
        }

        // Resolve Gateway.status.addresses from the reconciled Service (or fallback address).
        let addresses = resolve_gateway_addresses(
            idx.services
                .get(&(gw_ns.as_str(), svc_name.as_str()))
                .copied(),
            opts,
        );
        let any_accepted = evals.iter().any(|e| e.accepted);
        let all_accepted = !evals.is_empty() && evals.iter().all(|e| e.accepted);
        let any_programmable = evals.iter().any(ListenerEval::is_programmable);
        let has_address = !addresses.is_empty();

        let gw_accepted_reason = if all_accepted {
            "Accepted"
        } else {
            "ListenersNotValid"
        };
        let (gw_programmed, gw_programmed_reason, gw_programmed_msg) = if !any_programmable {
            (
                false,
                "ListenersNotValid",
                "No valid programmable listeners on Gateway",
            )
        } else if !has_address {
            (
                false,
                "AddressNotAssigned",
                "Waiting for Gateway Service address assignment",
            )
        } else {
            (true, "Programmed", "Gateway is programmed in Shunt")
        };

        let listener_statuses: Vec<K8sListenerStatus> = evals
            .into_iter()
            .map(|ev| {
                let programmed = ev.is_programmable() && has_address;
                let (prog_reason, prog_msg) = if !ev.is_programmable() {
                    (
                        "Invalid",
                        "Listener has unresolved or conflicted configuration",
                    )
                } else if !has_address {
                    ("AddressNotAssigned", "Waiting for Gateway Service address")
                } else {
                    ("Programmed", "Listener is programmed in Shunt")
                };
                K8sListenerStatus {
                    name: ev.name,
                    supported_kinds: ev.supported_kinds,
                    attached_routes: ev.attached_routes,
                    conditions: vec![
                        K8sCondition::new(
                            "Accepted",
                            ev.accepted,
                            gw_gen,
                            ev.accepted_reason,
                            ev.accepted_msg,
                            &now_ts,
                        ),
                        K8sCondition::new(
                            "Conflicted",
                            ev.conflicted,
                            gw_gen,
                            ev.conflicted_reason,
                            ev.conflicted_msg,
                            &now_ts,
                        ),
                        K8sCondition::new(
                            "ResolvedRefs",
                            ev.resolved_refs,
                            gw_gen,
                            ev.resolved_refs_reason,
                            ev.resolved_refs_msg,
                            &now_ts,
                        ),
                        K8sCondition::new(
                            "Programmed",
                            programmed,
                            gw_gen,
                            prog_reason,
                            prog_msg,
                            &now_ts,
                        ),
                    ],
                }
            })
            .collect();

        status_plan.gateways.insert(
            (gw_ns, gw_name),
            K8sGatewayStatus {
                addresses,
                conditions: vec![
                    K8sCondition::new(
                        "Accepted",
                        any_accepted,
                        gw_gen,
                        gw_accepted_reason,
                        if any_accepted {
                            "Gateway accepted by Shunt"
                        } else {
                            "No valid listeners accepted on Gateway"
                        },
                        &now_ts,
                    ),
                    K8sCondition::new(
                        "Programmed",
                        gw_programmed,
                        gw_gen,
                        gw_programmed_reason,
                        gw_programmed_msg,
                        &now_ts,
                    ),
                ],
                listeners: listener_statuses,
            },
        );
    }

    CompiledK8sCluster {
        listeners,
        desired_services,
        status_plan,
    }
}

fn resolve_gateway_addresses(
    svc: Option<&K8sService>,
    opts: &K8sGatewayOptions,
) -> Vec<K8sGatewayAddress> {
    let mut out = Vec::new();
    if let Some(s) = svc {
        if let Some(lb) = s.status.as_ref().and_then(|st| st.load_balancer.as_ref()) {
            for ing in &lb.ingress {
                if let Some(ip) = &ing.ip
                    && !ip.is_empty()
                {
                    out.push(K8sGatewayAddress {
                        address_type: "IPAddress".to_owned(),
                        value: ip.clone(),
                    });
                } else if let Some(host) = &ing.hostname
                    && !host.is_empty()
                {
                    out.push(K8sGatewayAddress {
                        address_type: "Hostname".to_owned(),
                        value: host.clone(),
                    });
                }
            }
        }
        if out.is_empty()
            && let Some(cip) = s.spec.cluster_ip.as_deref()
            && !cip.is_empty()
            && !cip.eq_ignore_ascii_case("None")
        {
            out.push(K8sGatewayAddress {
                address_type: "IPAddress".to_owned(),
                value: cip.to_owned(),
            });
        }
    }
    if out.is_empty()
        && let Some(addr) = &opts.default_gateway_address
        && !addr.is_empty()
    {
        let addr_type = if addr.parse::<std::net::IpAddr>().is_ok() {
            "IPAddress"
        } else {
            "Hostname"
        };
        out.push(K8sGatewayAddress {
            address_type: addr_type.to_owned(),
            value: addr.clone(),
        });
    }
    out
}

fn build_port_tls_config(
    gw: &K8sGateway,
    port_evals: &[&ListenerEval],
    idx: &SnapshotIndexes<'_>,
) -> Option<ServerTlsConfig> {
    let mut tls_cfg = ServerTlsConfig::default();
    let mut has_any_cert = false;

    let gw_ns = gw.metadata.effective_namespace();
    if let Some(ca_secret_name) = gw.metadata.annotations.get("shunt.io/client-ca-secret")
        && let Some(secret) = idx.secrets.get(&(gw_ns, ca_secret_name.as_str()))
        && let Some(ca_pem) =
            extract_secret_key(secret, "ca.crt").or_else(|| extract_secret_key(secret, "tls.crt"))
    {
        tls_cfg.client_ca_pem = Some(ca_pem);
        tls_cfg.client_auth = match gw
            .metadata
            .annotations
            .get("shunt.io/client-auth")
            .map(String::as_str)
        {
            Some("optional") => Some(ClientAuthModeIr::Optional),
            Some("none") => Some(ClientAuthModeIr::None),
            _ => Some(ClientAuthModeIr::Required),
        };
    }

    for ev in port_evals {
        if !ev.is_tls || !ev.is_programmable() {
            continue;
        }
        for (hostname, cert_pem, key_pem) in &ev.certs {
            has_any_cert = true;
            match hostname.as_deref().map(str::trim) {
                Some(host) if !host.is_empty() && host != "*" => {
                    tls_cfg.sni.push(SniCertConfig {
                        host: host.to_ascii_lowercase(),
                        cert: None,
                        key: None,
                        cert_pem: Some(cert_pem.clone()),
                        key_pem: Some(key_pem.clone()),
                    });
                    if tls_cfg.cert_pem.is_none() {
                        tls_cfg.cert_pem = Some(cert_pem.clone());
                        tls_cfg.key_pem = Some(key_pem.clone());
                    }
                }
                _ => {
                    tls_cfg.cert_pem = Some(cert_pem.clone());
                    tls_cfg.key_pem = Some(key_pem.clone());
                }
            }
        }
    }

    has_any_cert.then_some(tls_cfg)
}

#[allow(clippy::too_many_arguments)]
fn build_route_parent_status(
    pref: &K8sParentRef,
    controller_name: &str,
    generation: i64,
    accepted: bool,
    accepted_reason: &str,
    accepted_msg: &str,
    resolved_refs: bool,
    resolved_refs_reason: &str,
    resolved_refs_msg: &str,
    now_ts: &str,
) -> K8sRouteParentStatus {
    K8sRouteParentStatus {
        parent_ref: pref.clone(),
        controller_name: controller_name.to_owned(),
        conditions: vec![
            K8sCondition::new(
                "Accepted",
                accepted,
                generation,
                accepted_reason,
                accepted_msg,
                now_ts,
            ),
            K8sCondition::new(
                "ResolvedRefs",
                resolved_refs,
                generation,
                resolved_refs_reason,
                resolved_refs_msg,
                now_ts,
            ),
        ],
    }
}

fn check_route_backend_refs(
    http_route: &K8sHttpRoute,
    idx: &SnapshotIndexes<'_>,
    strict_service_lookup: bool,
) -> (bool, &'static str, String) {
    let route_ns = http_route.metadata.effective_namespace();
    for rule in &http_route.spec.rules {
        for bref in &rule.backend_refs {
            if let Err((err, msg)) = validate_backend_ref(
                route_ns,
                bref.group.as_deref(),
                bref.kind.as_deref(),
                bref.namespace.as_deref(),
                &bref.name,
                idx,
                strict_service_lookup,
            ) {
                return (false, err.reason(), msg);
            }
        }
        for filter in &rule.filters {
            if filter.filter_type == "RequestMirror"
                && let Some(mirror) = &filter.request_mirror
                && let Err((err, msg)) = validate_backend_ref(
                    route_ns,
                    mirror.backend_ref.group.as_deref(),
                    mirror.backend_ref.kind.as_deref(),
                    mirror.backend_ref.namespace.as_deref(),
                    &mirror.backend_ref.name,
                    idx,
                    strict_service_lookup,
                )
            {
                return (false, err.reason(), msg);
            }
        }
    }
    (
        true,
        "ResolvedRefs",
        "All backend references resolved".to_owned(),
    )
}

fn validate_backend_ref(
    route_ns: &str,
    group: Option<&str>,
    kind: Option<&str>,
    namespace: Option<&str>,
    name: &str,
    idx: &SnapshotIndexes<'_>,
    strict_service_lookup: bool,
) -> Result<(), (BackendRefError, String)> {
    let grp = group.unwrap_or("");
    let knd = kind.unwrap_or("Service");
    if !normalize_group(grp).is_empty() || knd != "Service" {
        return Err((
            BackendRefError::InvalidKind,
            format!("Unsupported backendRef group=`{grp}` kind=`{knd}`"),
        ));
    }
    let target_ns = namespace.unwrap_or(route_ns);
    if !is_reference_permitted(
        idx.grants,
        GATEWAY_API_GROUP,
        "HTTPRoute",
        route_ns,
        "",
        "Service",
        target_ns,
        name,
    ) {
        return Err((
            BackendRefError::RefNotPermitted,
            format!("Cross-namespace Service `{target_ns}/{name}` requires a ReferenceGrant"),
        ));
    }
    if strict_service_lookup && !idx.services.contains_key(&(target_ns, name)) {
        return Err((
            BackendRefError::BackendNotFound,
            format!("Service `{target_ns}/{name}` not found"),
        ));
    }
    Ok(())
}

/// Compiles a [`K8sClusterSnapshot`] into a single canonical [`GatewayConfig`] IR
/// (used by `--k8s-manifest`, `shunt check`, `shunt verify`, `shunt dev`, and single-port `--k8s-gateway`).
pub fn compile_k8s_gateway_snapshot(
    snap: &K8sClusterSnapshot,
    opts: &K8sGatewayOptions,
) -> Result<GatewayConfig, ConfigError> {
    let idx = SnapshotIndexes::build(snap);
    let managed_classes: HashSet<&str> = snap
        .gateway_classes
        .iter()
        .filter(|gc| gc.spec.controller_name == opts.controller_name)
        .map(|gc| gc.metadata.name.as_str())
        .collect();

    let matching_gateways: Vec<&K8sGateway> = snap
        .gateways
        .iter()
        .filter(|gw| {
            if let Some(ns) = &opts.namespace
                && gw.metadata.effective_namespace() != ns
            {
                return false;
            }
            if let Some(name) = &opts.gateway_name
                && gw.metadata.name != *name
            {
                return false;
            }
            if snap.gateway_classes.is_empty() {
                true
            } else {
                managed_classes.contains(gw.spec.gateway_class_name.as_str())
            }
        })
        .collect();

    // Compile TLS certificates from HTTPS Terminate listeners & optional client-CA annotation.
    let server_tls = compile_gateway_tls(&matching_gateways, &idx)?;

    let mut global_plugins = opts.global_plugins.clone();
    for gw in &matching_gateways {
        if let Some(raw_json) = gw.metadata.annotations.get("shunt.io/global-plugins") {
            let parsed: Vec<PluginAttachment> = serde_json::from_str(raw_json).map_err(|e| {
                ConfigError::K8s(format!(
                    "Gateway `{}/{}` invalid `shunt.io/global-plugins` JSON: {e}",
                    gw.metadata.effective_namespace(),
                    gw.metadata.name
                ))
            })?;
            global_plugins.extend(parsed);
        }
    }

    let mut upstreams_map: BTreeMap<String, UpstreamIr> = BTreeMap::new();
    let mut ranked_routes: Vec<RankedRoute> = Vec::new();
    let mut needs_redirect_noop = false;
    let mut needs_split_placeholder = false;

    let strict_service_lookup = !snap.services.is_empty();

    for http_route in &snap.http_routes {
        let route_ns = http_route.metadata.effective_namespace();
        if let Some(ns_filter) = &opts.namespace
            && route_ns != ns_filter
        {
            continue;
        }

        let mut attached_listeners: Vec<(&K8sGateway, &K8sListener)> = Vec::new();
        for pref in &http_route.spec.parent_refs {
            let pref_group = pref.group.as_deref().unwrap_or(GATEWAY_API_GROUP);
            if pref_group != GATEWAY_API_GROUP {
                continue;
            }
            if let Some(kind) = &pref.kind
                && kind != "Gateway"
            {
                continue;
            }
            let target_ns = pref.namespace.as_deref().unwrap_or(route_ns);
            for &gw in &matching_gateways {
                if gw.metadata.name != pref.name || gw.metadata.effective_namespace() != target_ns {
                    continue;
                }
                for listener in &gw.spec.listeners {
                    if let Some(sec) = &pref.section_name
                        && listener.name != *sec
                    {
                        continue;
                    }
                    if let Some(p) = pref.port
                        && listener.port != p
                    {
                        continue;
                    }
                    if !listener_allows_http_route_kind(listener)
                        || !listener_allows_route_ns(gw, listener, http_route, &idx.namespaces)
                    {
                        continue;
                    }
                    attached_listeners.push((gw, listener));
                }
            }
        }

        if attached_listeners.is_empty() {
            continue;
        }

        let Some(hosts) =
            compute_effective_hostnames(&attached_listeners, &http_route.spec.hostnames)
        else {
            continue;
        };

        let primary_gw = attached_listeners[0].0;
        compile_http_route_into_accum(
            primary_gw,
            http_route,
            &hosts,
            &idx,
            opts,
            strict_service_lookup,
            &mut upstreams_map,
            &mut ranked_routes,
            &mut needs_redirect_noop,
            &mut needs_split_placeholder,
        )?;
    }

    insert_sentinel_upstreams(
        &mut upstreams_map,
        needs_redirect_noop,
        needs_split_placeholder,
    );

    ranked_routes.sort_by(|a, b| a.precedence.cmp_precedence(&b.precedence));

    let config = GatewayConfig {
        server: ServerConfig {
            listen: opts.listen.clone(),
            drain_timeout_ms: 30_000,
            tls: server_tls,
        },
        admin: AdminConfig {
            enabled: opts.admin_enabled,
            listen: opts.admin_listen.clone(),
            ui: opts.admin_ui,
            ..AdminConfig::default()
        },
        state: Default::default(),
        telemetry: Default::default(),
        plugins: global_plugins,
        upstreams: upstreams_map.into_values().collect(),
        route_groups: Vec::new(),
        routes: ranked_routes.into_iter().map(|r| r.route).collect(),
        verify: Default::default(),
    };

    config.validate()?;
    Ok(config)
}

fn insert_sentinel_upstreams(
    upstreams_map: &mut BTreeMap<String, UpstreamIr>,
    needs_redirect_noop: bool,
    needs_split_placeholder: bool,
) {
    for (needed, name) in [
        (needs_redirect_noop, REDIRECT_NOOP_UPSTREAM),
        (needs_split_placeholder, SPLIT_PLACEHOLDER_UPSTREAM),
    ] {
        if needed {
            upstreams_map.insert(
                name.to_owned(),
                UpstreamIr {
                    name: name.to_owned(),
                    endpoints: vec![UpstreamEndpointIr::Url("http://127.0.0.1:1".to_owned())],
                    http2_only: false,
                    connect_timeout_ms: 1_000,
                    pool_idle_timeout_ms: 60_000,
                    pool_max_idle_per_host: 1,
                    unhealthy_threshold: 3,
                    unhealthy_cooldown_ms: 10_000,
                    tls: Default::default(),
                    health_check: None,
                },
            );
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn compile_http_route_into_accum(
    gw: &K8sGateway,
    http_route: &K8sHttpRoute,
    hosts: &[String],
    idx: &SnapshotIndexes<'_>,
    opts: &K8sGatewayOptions,
    strict_service_lookup: bool,
    upstreams_map: &mut BTreeMap<String, UpstreamIr>,
    ranked_routes: &mut Vec<RankedRoute>,
    needs_redirect_noop: &mut bool,
    needs_split_placeholder: &mut bool,
) -> Result<(), ConfigError> {
    let route_ns = http_route.metadata.effective_namespace();
    let route_name = &http_route.metadata.name;

    let mut extra_plugins: Vec<PluginAttachment> = Vec::new();
    let mut max_attempts = 1usize;
    let mut max_body_bytes: Option<usize> = None;

    apply_shunt_annotations(
        &gw.metadata.annotations,
        &format!(
            "Gateway `{}/{}`",
            gw.metadata.effective_namespace(),
            gw.metadata.name
        ),
        &mut extra_plugins,
        &mut max_attempts,
        &mut max_body_bytes,
    )?;
    apply_shunt_annotations(
        &http_route.metadata.annotations,
        &format!("HTTPRoute `{route_ns}/{route_name}`"),
        &mut extra_plugins,
        &mut max_attempts,
        &mut max_body_bytes,
    )?;

    // Partition hostnames by specificity bucket so an HTTPRoute with both exact and wildcard
    // hostnames (e.g. `["api.example.com", "*.example.com"]`) ranks each host accurately.
    let host_buckets: Vec<(Vec<String>, u8, usize)> = partition_host_buckets(hosts);

    for (rule_idx, rule) in http_route.spec.rules.iter().enumerate() {
        let matches: Vec<K8sHttpRouteMatch> = if rule.matches.is_empty() {
            vec![K8sHttpRouteMatch {
                path: Some(K8sHttpPathMatch {
                    match_type: Some("PathPrefix".to_owned()),
                    value: Some("/".to_owned()),
                }),
                headers: Vec::new(),
                query_params: Vec::new(),
                method: None,
            }]
        } else {
            rule.matches.clone()
        };

        let has_redirect = rule
            .filters
            .iter()
            .any(|f| f.filter_type == "RequestRedirect" && f.request_redirect.is_some());

        // Compile rule backends:
        // - Redirect-only rule -> REDIRECT_NOOP_UPSTREAM
        // - Single valid backend with weight > 0 and no per-backend filters -> direct upstream (zero-overhead!)
        // - Multi-backend, zero-weight, invalid/unpermitted backend, or per-backend filters -> `traffic-split` plugin
        let (upstream_name, split_plugin): (String, Option<PluginAttachment>) =
            if has_redirect && rule.backend_refs.is_empty() {
                *needs_redirect_noop = true;
                (REDIRECT_NOOP_UPSTREAM.to_owned(), None)
            } else if rule.backend_refs.is_empty() {
                *needs_split_placeholder = true;
                (
                    SPLIT_PLACEHOLDER_UPSTREAM.to_owned(),
                    Some(make_synthetic_500_split("no backendRefs configured")),
                )
            } else {
                compile_rule_backends(
                    route_ns,
                    route_name,
                    rule_idx,
                    &rule.backend_refs,
                    idx,
                    &opts.cluster_domain,
                    strict_service_lookup,
                    upstreams_map,
                    needs_split_placeholder,
                )?
            };

        // Compile RequestMirror filters into RouteMirrorIr entries (enforcing ReferenceGrant!).
        let mut mirrors = Vec::new();
        for (f_idx, filter) in rule.filters.iter().enumerate() {
            if filter.filter_type == "RequestMirror"
                && let Some(mirror) = &filter.request_mirror
            {
                if validate_backend_ref(
                    route_ns,
                    mirror.backend_ref.group.as_deref(),
                    mirror.backend_ref.kind.as_deref(),
                    mirror.backend_ref.namespace.as_deref(),
                    &mirror.backend_ref.name,
                    idx,
                    strict_service_lookup,
                )
                .is_err()
                {
                    continue;
                }
                let m_up_name = format!("k8s_mirror_{route_ns}_{route_name}_r{rule_idx}_f{f_idx}");
                let m_ref = K8sHttpBackendRef {
                    group: mirror.backend_ref.group.clone(),
                    kind: mirror.backend_ref.kind.clone(),
                    name: mirror.backend_ref.name.clone(),
                    namespace: mirror.backend_ref.namespace.clone(),
                    port: mirror.backend_ref.port,
                    weight: Some(1),
                    filters: Vec::new(),
                };
                let m_eps =
                    resolve_single_backend_endpoints(route_ns, &m_ref, idx, &opts.cluster_domain);
                if !m_eps.is_empty() {
                    upstreams_map.insert(
                        m_up_name.clone(),
                        UpstreamIr {
                            name: m_up_name.clone(),
                            endpoints: m_eps,
                            http2_only: false,
                            connect_timeout_ms: 5_000,
                            pool_idle_timeout_ms: 90_000,
                            pool_max_idle_per_host: 64,
                            unhealthy_threshold: 3,
                            unhealthy_cooldown_ms: 10_000,
                            tls: Default::default(),
                            health_check: None,
                        },
                    );
                    mirrors.push(RouteMirrorIr {
                        upstream: m_up_name,
                        sample_rate: 1.0,
                        timeout_ms: 5_000,
                        max_in_flight: 128,
                        headers: BTreeMap::new(),
                    });
                }
            }
        }

        // Compile rule timeouts (backendRequest or request).
        let response_headers_timeout_ms = rule
            .timeouts
            .as_ref()
            .and_then(|t| t.backend_request.as_deref().or(t.request.as_deref()))
            .and_then(parse_k8s_duration_ms)
            .or(Some(30_000));

        for (match_idx, m) in matches.iter().enumerate() {
            let compiled_path = compile_path_match(m.path.as_ref())?;
            let matched_prefix = compiled_path
                .path_prefix
                .as_deref()
                .or(compiled_path.path_exact.as_deref());

            // Gateway API v1: duplicate header matchers keep the FIRST entry (case-insensitive).
            let mut headers = BTreeMap::new();
            let mut seen_header_lower = HashSet::new();
            for hm in &m.headers {
                if hm.match_type.as_deref().unwrap_or("Exact") != "Exact" {
                    return Err(ConfigError::K8s(format!(
                        "HTTPRoute `{route_ns}/{route_name}`: unsupported header match type `{}` (only `Exact` is supported)",
                        hm.match_type.as_deref().unwrap_or("")
                    )));
                }
                let lower = hm.name.to_ascii_lowercase();
                if seen_header_lower.insert(lower) {
                    headers.insert(hm.name.clone(), hm.value.clone());
                }
            }

            // Gateway API v1: duplicate query-param matchers keep the FIRST entry (case-sensitive).
            let mut query_params = BTreeMap::new();
            for qm in &m.query_params {
                if qm.match_type.as_deref().unwrap_or("Exact") != "Exact" {
                    return Err(ConfigError::K8s(format!(
                        "HTTPRoute `{route_ns}/{route_name}`: unsupported queryParam match type `{}` (only `Exact` is supported)",
                        qm.match_type.as_deref().unwrap_or("")
                    )));
                }
                query_params
                    .entry(qm.name.clone())
                    .or_insert_with(|| qm.value.clone());
            }

            let methods: Vec<String> = m
                .method
                .as_ref()
                .map(|meth| vec![meth.to_ascii_uppercase()])
                .unwrap_or_default();

            let mut route_plugins = extra_plugins.clone();
            compile_rule_filters(&rule.filters, matched_prefix, &mut route_plugins)?;
            if let Some(sp) = &split_plugin {
                route_plugins.push(sp.clone());
            }

            for (hb_idx, (bucket_hosts, host_specificity, host_len)) in
                host_buckets.iter().enumerate()
            {
                let route_id = if host_buckets.len() == 1 {
                    format!("k8s:{route_ns}/{route_name}:r{rule_idx}:m{match_idx}")
                } else {
                    format!("k8s:{route_ns}/{route_name}:r{rule_idx}:m{match_idx}:h{hb_idx}")
                };

                let prec = RoutePrecedenceKey {
                    host_specificity: *host_specificity,
                    host_len: *host_len,
                    path_kind_rank: compiled_path.kind_rank,
                    path_len: compiled_path.path_len,
                    header_count: headers.len(),
                    query_param_count: query_params.len(),
                    has_method: !methods.is_empty(),
                    creation_timestamp: http_route
                        .metadata
                        .creation_timestamp
                        .clone()
                        .unwrap_or_default(),
                    namespace: route_ns.to_owned(),
                    name: route_name.clone(),
                    rule_idx,
                    match_idx,
                };

                ranked_routes.push(RankedRoute {
                    precedence: prec,
                    route: RouteIr {
                        id: route_id,
                        group: None,
                        hosts: bucket_hosts.clone(),
                        path_prefix: compiled_path.path_prefix.clone(),
                        path_exact: compiled_path.path_exact.clone(),
                        path_template: None,
                        path_regex: compiled_path.path_regex.clone(),
                        methods: methods.clone(),
                        headers: headers.clone(),
                        query_params: query_params.clone(),
                        upstream: Some(upstream_name.clone()),
                        strip_prefix: None,
                        max_body_bytes,
                        max_attempts: Some(max_attempts),
                        response_headers_timeout_ms,
                        idle_chunk_timeout_ms: Some(60_000),
                        allow_websockets: Some(true),
                        mirrors: mirrors.clone(),
                        plugins: route_plugins.clone(),
                    },
                });
            }
        }
    }

    Ok(())
}

fn partition_host_buckets(hosts: &[String]) -> Vec<(Vec<String>, u8, usize)> {
    if hosts.is_empty() {
        return vec![(Vec::new(), 0, 0)];
    }
    let mut exact = Vec::new();
    let mut wildcards_by_len: BTreeMap<usize, Vec<String>> = BTreeMap::new();
    for h in hosts {
        if h.starts_with("*.") {
            wildcards_by_len.entry(h.len()).or_default().push(h.clone());
        } else {
            exact.push(h.clone());
        }
    }
    let mut out = Vec::new();
    if !exact.is_empty() {
        out.push((exact, 2, 0));
    }
    for (len, list) in wildcards_by_len.into_iter().rev() {
        out.push((list, 1, len));
    }
    out
}

fn make_synthetic_500_split(reason: &str) -> PluginAttachment {
    PluginAttachment {
        name: "traffic-split".to_owned(),
        id: None,
        config: serde_json::json!({
            "targets": [
                { "weight": 1, "status": 500, "body": reason }
            ]
        }),
    }
}

#[allow(clippy::too_many_arguments)]
fn compile_rule_backends(
    route_ns: &str,
    route_name: &str,
    rule_idx: usize,
    backend_refs: &[K8sHttpBackendRef],
    idx: &SnapshotIndexes<'_>,
    cluster_domain: &str,
    strict_service_lookup: bool,
    upstreams_map: &mut BTreeMap<String, UpstreamIr>,
    needs_split_placeholder: &mut bool,
) -> Result<(String, Option<PluginAttachment>), ConfigError> {
    // Fast path: exactly 1 valid backend with weight > 0 and no per-backend filters -> direct upstream!
    if backend_refs.len() == 1 {
        let bref = &backend_refs[0];
        let weight = bref.weight.unwrap_or(1);
        if weight > 0
            && bref.filters.is_empty()
            && validate_backend_ref(
                route_ns,
                bref.group.as_deref(),
                bref.kind.as_deref(),
                bref.namespace.as_deref(),
                &bref.name,
                idx,
                strict_service_lookup,
            )
            .is_ok()
        {
            let eps = resolve_single_backend_endpoints(route_ns, bref, idx, cluster_domain);
            if !eps.is_empty() {
                let up_name = format!("k8s_{route_ns}_{route_name}_r{rule_idx}");
                upstreams_map.insert(
                    up_name.clone(),
                    UpstreamIr {
                        name: up_name.clone(),
                        endpoints: eps,
                        http2_only: false,
                        connect_timeout_ms: 5_000,
                        pool_idle_timeout_ms: 90_000,
                        pool_max_idle_per_host: 64,
                        unhealthy_threshold: 3,
                        unhealthy_cooldown_ms: 10_000,
                        tls: Default::default(),
                        health_check: None,
                    },
                );
                return Ok((up_name, None));
            }
        }
    }

    // General path: weighted split / synthetic 500 for invalid or zero-weight refs / per-backend filters.
    let mut targets_json: Vec<JsonValue> = Vec::with_capacity(backend_refs.len());
    let mut default_upstream: Option<String> = None;

    for (b_idx, bref) in backend_refs.iter().enumerate() {
        let weight = bref.weight.unwrap_or(1);
        let validation = validate_backend_ref(
            route_ns,
            bref.group.as_deref(),
            bref.kind.as_deref(),
            bref.namespace.as_deref(),
            &bref.name,
            idx,
            strict_service_lookup,
        );

        let mut target_obj = JsonMap::new();
        target_obj.insert("weight".to_owned(), JsonValue::from(weight));

        match validation {
            Ok(()) => {
                let eps = resolve_single_backend_endpoints(route_ns, bref, idx, cluster_domain);
                if eps.is_empty() {
                    target_obj.insert("status".to_owned(), JsonValue::from(500));
                    target_obj.insert(
                        "body".to_owned(),
                        JsonValue::String("no backend endpoints".to_owned()),
                    );
                } else {
                    let up_name = format!("k8s_{route_ns}_{route_name}_r{rule_idx}_b{b_idx}");
                    upstreams_map.insert(
                        up_name.clone(),
                        UpstreamIr {
                            name: up_name.clone(),
                            endpoints: eps,
                            http2_only: false,
                            connect_timeout_ms: 5_000,
                            pool_idle_timeout_ms: 90_000,
                            pool_max_idle_per_host: 64,
                            unhealthy_threshold: 3,
                            unhealthy_cooldown_ms: 10_000,
                            tls: Default::default(),
                            health_check: None,
                        },
                    );
                    if default_upstream.is_none() {
                        default_upstream = Some(up_name.clone());
                    }
                    target_obj.insert("upstream".to_owned(), JsonValue::String(up_name));
                    apply_backend_header_filters(&bref.filters, &mut target_obj);
                }
            }
            Err((_, msg)) => {
                target_obj.insert("status".to_owned(), JsonValue::from(500));
                target_obj.insert("body".to_owned(), JsonValue::String(msg));
            }
        }

        targets_json.push(JsonValue::Object(target_obj));
    }

    let base_upstream = match default_upstream {
        Some(u) => u,
        None => {
            *needs_split_placeholder = true;
            SPLIT_PLACEHOLDER_UPSTREAM.to_owned()
        }
    };

    let split_plugin = PluginAttachment {
        name: "traffic-split".to_owned(),
        id: None,
        config: serde_json::json!({ "targets": targets_json }),
    };

    Ok((base_upstream, Some(split_plugin)))
}

fn apply_backend_header_filters(
    filters: &[K8sHttpRouteFilter],
    target_obj: &mut JsonMap<String, JsonValue>,
) {
    let mut req_set = JsonMap::new();
    let mut req_add: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut req_remove: Vec<JsonValue> = Vec::new();
    let mut res_set = JsonMap::new();
    let mut res_add: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut res_remove: Vec<JsonValue> = Vec::new();

    for filter in filters {
        match filter.filter_type.as_str() {
            "RequestHeaderModifier" => {
                if let Some(m) = &filter.request_header_modifier {
                    for h in &m.set {
                        req_set.insert(h.name.clone(), JsonValue::String(h.value.clone()));
                    }
                    for h in &m.add {
                        req_add
                            .entry(h.name.clone())
                            .or_default()
                            .push(h.value.clone());
                    }
                    for r in &m.remove {
                        req_remove.push(JsonValue::String(r.clone()));
                    }
                }
            }
            "ResponseHeaderModifier" => {
                if let Some(m) = &filter.response_header_modifier {
                    for h in &m.set {
                        res_set.insert(h.name.clone(), JsonValue::String(h.value.clone()));
                    }
                    for h in &m.add {
                        res_add
                            .entry(h.name.clone())
                            .or_default()
                            .push(h.value.clone());
                    }
                    for r in &m.remove {
                        res_remove.push(JsonValue::String(r.clone()));
                    }
                }
            }
            _ => {}
        }
    }

    if !req_set.is_empty() {
        target_obj.insert("request_set".to_owned(), JsonValue::Object(req_set));
    }
    if !req_add.is_empty() {
        target_obj.insert("request_add".to_owned(), encode_multi_header_map(req_add));
    }
    if !req_remove.is_empty() {
        target_obj.insert("request_remove".to_owned(), JsonValue::Array(req_remove));
    }
    if !res_set.is_empty() {
        target_obj.insert("response_set".to_owned(), JsonValue::Object(res_set));
    }
    if !res_add.is_empty() {
        target_obj.insert("response_add".to_owned(), encode_multi_header_map(res_add));
    }
    if !res_remove.is_empty() {
        target_obj.insert("response_remove".to_owned(), JsonValue::Array(res_remove));
    }
}

fn encode_multi_header_map(map: BTreeMap<String, Vec<String>>) -> JsonValue {
    let mut out = JsonMap::new();
    for (k, vals) in map {
        if vals.len() == 1 {
            out.insert(k, JsonValue::String(vals.into_iter().next().unwrap()));
        } else {
            out.insert(
                k,
                JsonValue::Array(vals.into_iter().map(JsonValue::String).collect()),
            );
        }
    }
    JsonValue::Object(out)
}

fn compile_gateway_tls(
    gateways: &[&K8sGateway],
    idx: &SnapshotIndexes<'_>,
) -> Result<Option<ServerTlsConfig>, ConfigError> {
    let mut tls_cfg = ServerTlsConfig::default();
    let mut has_any_cert = false;

    for &gw in gateways {
        let gw_ns = gw.metadata.effective_namespace();

        if let Some(ca_secret_name) = gw.metadata.annotations.get("shunt.io/client-ca-secret") {
            let secret = idx
                .secrets
                .get(&(gw_ns, ca_secret_name.as_str()))
                .ok_or_else(|| {
                    ConfigError::K8s(format!(
                        "Gateway `{gw_ns}/{}` references missing client CA Secret `{gw_ns}/{ca_secret_name}`",
                        gw.metadata.name
                    ))
                })?;
            let ca_pem = extract_secret_key(secret, "ca.crt")
                .or_else(|| extract_secret_key(secret, "tls.crt"))
                .ok_or_else(|| {
                    ConfigError::K8s(format!(
                        "Secret `{gw_ns}/{ca_secret_name}` missing `ca.crt` or `tls.crt`"
                    ))
                })?;
            tls_cfg.client_ca_pem = Some(ca_pem);
            tls_cfg.client_auth = match gw
                .metadata
                .annotations
                .get("shunt.io/client-auth")
                .map(String::as_str)
            {
                Some("optional") => Some(ClientAuthModeIr::Optional),
                Some("none") => Some(ClientAuthModeIr::None),
                _ => Some(ClientAuthModeIr::Required),
            };
        }

        for listener in &gw.spec.listeners {
            if !listener.protocol.eq_ignore_ascii_case("HTTPS") {
                continue;
            }
            let Some(ltls) = &listener.tls else {
                continue;
            };
            if ltls
                .mode
                .as_deref()
                .map(|m| !m.eq_ignore_ascii_case("Terminate"))
                .unwrap_or(false)
            {
                continue;
            }

            for cert_ref in &ltls.certificate_refs {
                if let Some(kind) = &cert_ref.kind
                    && kind != "Secret"
                {
                    continue;
                }
                let sec_ns = cert_ref.namespace.as_deref().unwrap_or(gw_ns);
                if !is_reference_permitted(
                    idx.grants,
                    GATEWAY_API_GROUP,
                    "Gateway",
                    gw_ns,
                    "",
                    "Secret",
                    sec_ns,
                    &cert_ref.name,
                ) {
                    return Err(ConfigError::K8s(format!(
                        "Gateway `{gw_ns}/{}` listener `{}` cross-namespace TLS Secret `{sec_ns}/{}` is not permitted by ReferenceGrant",
                        gw.metadata.name, listener.name, cert_ref.name
                    )));
                }
                let secret = idx
                    .secrets
                    .get(&(sec_ns, cert_ref.name.as_str()))
                    .ok_or_else(|| {
                        ConfigError::K8s(format!(
                            "Gateway `{gw_ns}/{}` listener `{}` references missing TLS Secret `{sec_ns}/{}`",
                            gw.metadata.name, listener.name, cert_ref.name
                        ))
                    })?;
                let cert_pem = extract_secret_key(secret, "tls.crt").ok_or_else(|| {
                    ConfigError::K8s(format!(
                        "TLS Secret `{sec_ns}/{}` missing `tls.crt`",
                        cert_ref.name
                    ))
                })?;
                let key_pem = extract_secret_key(secret, "tls.key").ok_or_else(|| {
                    ConfigError::K8s(format!(
                        "TLS Secret `{sec_ns}/{}` missing `tls.key`",
                        cert_ref.name
                    ))
                })?;

                has_any_cert = true;
                match listener.hostname.as_deref().map(str::trim) {
                    Some(host) if !host.is_empty() && host != "*" => {
                        tls_cfg.sni.push(SniCertConfig {
                            host: host.to_ascii_lowercase(),
                            cert: None,
                            key: None,
                            cert_pem: Some(cert_pem.clone()),
                            key_pem: Some(key_pem.clone()),
                        });
                        if tls_cfg.cert_pem.is_none() {
                            tls_cfg.cert_pem = Some(cert_pem);
                            tls_cfg.key_pem = Some(key_pem);
                        }
                    }
                    _ => {
                        tls_cfg.cert_pem = Some(cert_pem);
                        tls_cfg.key_pem = Some(key_pem);
                    }
                }
            }
        }
    }

    Ok(if has_any_cert { Some(tls_cfg) } else { None })
}

pub(crate) fn extract_secret_key(secret: &K8sSecret, key: &str) -> Option<String> {
    if let Some(plain) = secret.string_data.get(key) {
        return Some(plain.clone());
    }
    let b64 = secret.data.get(key)?;
    let decoded = base64_decode_std(b64).ok()?;
    String::from_utf8(decoded).ok()
}

fn listener_allows_http_route_kind(listener: &K8sListener) -> bool {
    let explicit_kinds = listener
        .allowed_routes
        .as_ref()
        .map(|ar| ar.kinds.as_slice())
        .unwrap_or(&[]);
    if explicit_kinds.is_empty() {
        return true;
    }
    explicit_kinds.iter().any(|gk| {
        let grp = gk.group.as_deref().unwrap_or(GATEWAY_API_GROUP);
        grp == GATEWAY_API_GROUP && gk.kind == "HTTPRoute"
    })
}

fn listener_allows_route_ns(
    gw: &K8sGateway,
    listener: &K8sListener,
    route: &K8sHttpRoute,
    namespaces: &HashMap<&str, &K8sNamespace>,
) -> bool {
    let gw_ns = gw.metadata.effective_namespace();
    let route_ns = route.metadata.effective_namespace();
    let from = listener
        .allowed_routes
        .as_ref()
        .and_then(|ar| ar.namespaces.as_ref())
        .and_then(|ns| ns.from.as_deref())
        .unwrap_or("Same");
    match from {
        "All" => true,
        "Same" => gw_ns == route_ns,
        "Selector" => {
            if let Some(sel) = listener
                .allowed_routes
                .as_ref()
                .and_then(|ar| ar.namespaces.as_ref())
                .and_then(|ns| ns.selector.as_ref())
            {
                if let Some(ns_obj) = namespaces.get(route_ns) {
                    sel.matches(&ns_obj.metadata.labels)
                } else {
                    false
                }
            } else {
                gw_ns == route_ns
            }
        }
        _ => gw_ns == route_ns,
    }
}

/// Computes Gateway API hostname intersection across attached listeners and route hostnames.
fn compute_effective_hostnames(
    listeners: &[(&K8sGateway, &K8sListener)],
    route_hosts: &[String],
) -> Option<Vec<String>> {
    let mut result: Vec<String> = Vec::new();
    let mut matches_any = false;

    for (_, listener) in listeners {
        let l_host = listener
            .hostname
            .as_deref()
            .map(str::trim)
            .filter(|h| !h.is_empty() && *h != "*");

        match (l_host, route_hosts.is_empty()) {
            (None, true) => {
                matches_any = true;
            }
            (None, false) => {
                for rh in route_hosts {
                    push_unique(&mut result, rh.to_ascii_lowercase());
                }
            }
            (Some(lh), true) => {
                push_unique(&mut result, lh.to_ascii_lowercase());
            }
            (Some(lh), false) => {
                let lh_low = lh.to_ascii_lowercase();
                for rh in route_hosts {
                    let rh_low = rh.to_ascii_lowercase();
                    if let Some(inter) = intersect_two_hostnames(&lh_low, &rh_low) {
                        push_unique(&mut result, inter);
                    }
                }
            }
        }
    }

    if matches_any {
        Some(Vec::new())
    } else if result.is_empty() {
        None
    } else {
        Some(result)
    }
}

fn push_unique(vec: &mut Vec<String>, item: String) {
    if !vec.contains(&item) {
        vec.push(item);
    }
}

/// Intersects two Gateway API hostnames (exact or `*.suffix` wildcard), returning the more specific one.
pub fn intersect_two_hostnames(a: &str, b: &str) -> Option<String> {
    if a == b {
        return Some(a.to_owned());
    }
    if let Some(a_suf) = a.strip_prefix("*.") {
        if let Some(b_suf) = b.strip_prefix("*.") {
            if b_suf.len() > a_suf.len()
                && b_suf.ends_with(a_suf)
                && b_suf.as_bytes()[b_suf.len() - a_suf.len() - 1] == b'.'
            {
                return Some(b.to_owned());
            }
            if a_suf.len() > b_suf.len()
                && a_suf.ends_with(b_suf)
                && a_suf.as_bytes()[a_suf.len() - b_suf.len() - 1] == b'.'
            {
                return Some(a.to_owned());
            }
            return None;
        }
        if shunt_engine::host_matches(a, b) {
            return Some(b.to_owned());
        }
        return None;
    }
    if b.starts_with("*.") && shunt_engine::host_matches(b, a) {
        return Some(a.to_owned());
    }
    None
}

fn apply_shunt_annotations(
    annotations: &BTreeMap<String, String>,
    owner_label: &str,
    plugins: &mut Vec<PluginAttachment>,
    max_attempts: &mut usize,
    max_body_bytes: &mut Option<usize>,
) -> Result<(), ConfigError> {
    if let Some(raw_plugins) = annotations.get("shunt.io/plugins") {
        let parsed: Vec<PluginAttachment> = serde_json::from_str(raw_plugins).map_err(|e| {
            ConfigError::K8s(format!(
                "{owner_label}: invalid `shunt.io/plugins` JSON annotation: {e}"
            ))
        })?;
        plugins.extend(parsed);
    }
    if let Some(raw_att) = annotations.get("shunt.io/max-attempts") {
        let parsed: usize = raw_att.trim().parse().map_err(|e| {
            ConfigError::K8s(format!(
                "{owner_label}: invalid `shunt.io/max-attempts`: {e}"
            ))
        })?;
        *max_attempts = parsed.max(1);
    }
    if let Some(raw_body) = annotations.get("shunt.io/max-body-bytes") {
        let parsed: usize = raw_body.trim().parse().map_err(|e| {
            ConfigError::K8s(format!(
                "{owner_label}: invalid `shunt.io/max-body-bytes`: {e}"
            ))
        })?;
        *max_body_bytes = Some(parsed);
    }
    Ok(())
}

struct CompiledK8sPathMatch {
    path_exact: Option<String>,
    path_prefix: Option<String>,
    path_regex: Option<String>,
    kind_rank: u8,
    path_len: usize,
}

fn compile_path_match(pm: Option<&K8sHttpPathMatch>) -> Result<CompiledK8sPathMatch, ConfigError> {
    let Some(pm) = pm else {
        return Ok(CompiledK8sPathMatch {
            path_exact: None,
            path_prefix: Some("/".to_owned()),
            path_regex: None,
            kind_rank: 2,
            path_len: 1,
        });
    };
    let kind = pm.match_type.as_deref().unwrap_or("PathPrefix");
    let val = pm.value.clone().unwrap_or_else(|| "/".to_owned());
    match kind {
        "Exact" => {
            let len = val.len();
            Ok(CompiledK8sPathMatch {
                path_exact: Some(val),
                path_prefix: None,
                path_regex: None,
                kind_rank: 3,
                path_len: len,
            })
        }
        "PathPrefix" => {
            let len = val.len();
            Ok(CompiledK8sPathMatch {
                path_exact: None,
                path_prefix: Some(val),
                path_regex: None,
                kind_rank: 2,
                path_len: len,
            })
        }
        "RegularExpression" => {
            CompiledPathRegex::compile(&val).map_err(|e| {
                ConfigError::K8s(format!(
                    "invalid HTTPRoute RegularExpression path `{val}`: {e}"
                ))
            })?;
            Ok(CompiledK8sPathMatch {
                path_exact: None,
                path_prefix: None,
                path_regex: Some(val),
                kind_rank: 1,
                path_len: 0,
            })
        }
        other => Err(ConfigError::K8s(format!(
            "unsupported HTTPRoute path match type `{other}` (supported: `Exact`, `PathPrefix`, `RegularExpression`)"
        ))),
    }
}

fn compile_rule_filters(
    filters: &[K8sHttpRouteFilter],
    matched_prefix: Option<&str>,
    out_plugins: &mut Vec<PluginAttachment>,
) -> Result<(), ConfigError> {
    let mut req_set = JsonMap::new();
    let mut req_add: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut req_remove: Vec<JsonValue> = Vec::new();
    let mut res_set = JsonMap::new();
    let mut res_add: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut res_remove: Vec<JsonValue> = Vec::new();
    let mut upstream_host: Option<String> = None;
    let mut path_replace_full: Option<String> = None;
    let mut path_replace_prefix: Option<String> = None;

    for filter in filters {
        match filter.filter_type.as_str() {
            "RequestHeaderModifier" => {
                if let Some(m) = &filter.request_header_modifier {
                    for h in &m.set {
                        req_set.insert(h.name.clone(), JsonValue::String(h.value.clone()));
                    }
                    for h in &m.add {
                        req_add
                            .entry(h.name.clone())
                            .or_default()
                            .push(h.value.clone());
                    }
                    for r in &m.remove {
                        req_remove.push(JsonValue::String(r.clone()));
                    }
                }
            }
            "ResponseHeaderModifier" => {
                if let Some(m) = &filter.response_header_modifier {
                    for h in &m.set {
                        res_set.insert(h.name.clone(), JsonValue::String(h.value.clone()));
                    }
                    for h in &m.add {
                        res_add
                            .entry(h.name.clone())
                            .or_default()
                            .push(h.value.clone());
                    }
                    for r in &m.remove {
                        res_remove.push(JsonValue::String(r.clone()));
                    }
                }
            }
            "URLRewrite" => {
                if let Some(rw) = &filter.url_rewrite {
                    if let Some(host) = &rw.hostname {
                        upstream_host = Some(host.clone());
                    }
                    if let Some(pm) = &rw.path {
                        match pm.modifier_type.as_str() {
                            "ReplaceFullPath" => {
                                path_replace_full = pm.replace_full_path.clone();
                            }
                            "ReplacePrefixMatch" => {
                                if matched_prefix.is_none() {
                                    return Err(ConfigError::K8s(
                                        "URLRewrite `ReplacePrefixMatch` is not compatible with `RegularExpression` path matches; use `ReplaceFullPath`".to_owned(),
                                    ));
                                }
                                path_replace_prefix = pm.replace_prefix_match.clone();
                            }
                            other => {
                                return Err(ConfigError::K8s(format!(
                                    "unsupported URLRewrite path modifier `{other}`"
                                )));
                            }
                        }
                    }
                }
            }
            "RequestRedirect" => {
                if let Some(rd) = &filter.request_redirect {
                    let mut cfg = JsonMap::new();
                    if let Some(sc) = rd.status_code {
                        cfg.insert("status_code".to_owned(), JsonValue::from(sc));
                    }
                    if let Some(scheme) = &rd.scheme {
                        cfg.insert("scheme".to_owned(), JsonValue::String(scheme.clone()));
                    }
                    if let Some(host) = &rd.hostname {
                        cfg.insert("hostname".to_owned(), JsonValue::String(host.clone()));
                    }
                    if let Some(port) = rd.port {
                        cfg.insert("port".to_owned(), JsonValue::from(port));
                    }
                    if let Some(pm) = &rd.path {
                        match pm.modifier_type.as_str() {
                            "ReplaceFullPath" => {
                                if let Some(p) = &pm.replace_full_path {
                                    cfg.insert(
                                        "path_replace_full".to_owned(),
                                        JsonValue::String(p.clone()),
                                    );
                                }
                            }
                            "ReplacePrefixMatch" => {
                                if let Some(p) = &pm.replace_prefix_match {
                                    let Some(mp) = matched_prefix else {
                                        return Err(ConfigError::K8s(
                                            "RequestRedirect `ReplacePrefixMatch` is not compatible with `RegularExpression` path matches; use `ReplaceFullPath`".to_owned(),
                                        ));
                                    };
                                    cfg.insert(
                                        "path_match_prefix".to_owned(),
                                        JsonValue::String(mp.to_owned()),
                                    );
                                    cfg.insert(
                                        "path_replace_prefix".to_owned(),
                                        JsonValue::String(p.clone()),
                                    );
                                }
                            }
                            _ => {}
                        }
                    }
                    out_plugins.push(PluginAttachment {
                        name: "redirect".to_owned(),
                        id: None,
                        config: JsonValue::Object(cfg),
                    });
                }
            }
            "RequestMirror" => {}
            _ => {}
        }
    }

    let has_rewrite = !req_set.is_empty()
        || !req_add.is_empty()
        || !req_remove.is_empty()
        || !res_set.is_empty()
        || !res_add.is_empty()
        || !res_remove.is_empty()
        || upstream_host.is_some()
        || path_replace_full.is_some()
        || path_replace_prefix.is_some();

    if has_rewrite {
        let mut cfg = JsonMap::new();
        if !req_set.is_empty() {
            cfg.insert("request_set".to_owned(), JsonValue::Object(req_set));
        }
        if !req_add.is_empty() {
            cfg.insert("request_add".to_owned(), encode_multi_header_map(req_add));
        }
        if !req_remove.is_empty() {
            cfg.insert("request_remove".to_owned(), JsonValue::Array(req_remove));
        }
        if !res_set.is_empty() {
            cfg.insert("response_set".to_owned(), JsonValue::Object(res_set));
        }
        if !res_add.is_empty() {
            cfg.insert("response_add".to_owned(), encode_multi_header_map(res_add));
        }
        if !res_remove.is_empty() {
            cfg.insert("response_remove".to_owned(), JsonValue::Array(res_remove));
        }
        if let Some(h) = upstream_host {
            cfg.insert("upstream_host".to_owned(), JsonValue::String(h));
        }
        if let Some(full) = path_replace_full {
            cfg.insert("path_replace_full".to_owned(), JsonValue::String(full));
        }
        if let Some(rep) = path_replace_prefix {
            if let Some(mp) = matched_prefix {
                cfg.insert(
                    "path_match_prefix".to_owned(),
                    JsonValue::String(mp.to_owned()),
                );
            }
            cfg.insert("path_replace_prefix".to_owned(), JsonValue::String(rep));
        }
        out_plugins.push(PluginAttachment {
            name: "header-rewrite".to_owned(),
            id: None,
            config: JsonValue::Object(cfg),
        });
    }

    Ok(())
}

fn resolve_single_backend_endpoints(
    default_ns: &str,
    bref: &K8sHttpBackendRef,
    idx: &SnapshotIndexes<'_>,
    cluster_domain: &str,
) -> Vec<UpstreamEndpointIr> {
    let ns = bref.namespace.as_deref().unwrap_or(default_ns);
    let svc = idx.services.get(&(ns, bref.name.as_str())).copied();
    let req_port = bref
        .port
        .or_else(|| svc.and_then(|s| s.spec.ports.first().map(|p| p.port)))
        .unwrap_or(80);

    let matched_svc_port = svc.and_then(|s| {
        s.spec
            .ports
            .iter()
            .find(|p| p.port == req_port)
            .or_else(|| s.spec.ports.first())
    });

    let scheme = matched_svc_port
        .and_then(|p| p.app_protocol.as_deref())
        .map(|ap| {
            if ap.eq_ignore_ascii_case("https") || ap.eq_ignore_ascii_case("tls") {
                "https"
            } else {
                "http"
            }
        })
        .unwrap_or("http");

    let mut urls: Vec<String> = Vec::new();

    // 1. Prefer EndpointSlices (modern K8s API)
    if let Some(svc_slices) = idx.slices.get(&(ns, bref.name.as_str())) {
        for slice in svc_slices {
            let target_port = resolve_endpoint_port(&slice.ports, matched_svc_port, req_port);
            for ep in &slice.endpoints {
                if ep.conditions.as_ref().and_then(|c| c.ready).unwrap_or(true) {
                    for addr in &ep.addresses {
                        urls.push(format_host_port_url(scheme, addr, target_port));
                    }
                }
            }
        }
    }

    // 2. Fallback to Endpoints (v1)
    if urls.is_empty()
        && let Some(ep_obj) = idx.endpoints.get(&(ns, bref.name.as_str()))
    {
        for subset in &ep_obj.subsets {
            let target_port = resolve_endpoint_port(&subset.ports, matched_svc_port, req_port);
            for addr in &subset.addresses {
                urls.push(format_host_port_url(scheme, &addr.ip, target_port));
            }
        }
    }

    // 3. Fallback to Service ClusterIP or Kubernetes DNS FQDN
    if urls.is_empty() {
        if let Some(cip) = svc
            .and_then(|s| s.spec.cluster_ip.as_deref())
            .filter(|ip| !ip.is_empty() && !ip.eq_ignore_ascii_case("None"))
        {
            urls.push(format_host_port_url(scheme, cip, req_port));
        } else {
            urls.push(format!(
                "{scheme}://{}.{}.svc.{cluster_domain}:{req_port}",
                bref.name, ns
            ));
        }
    }

    urls.into_iter().map(UpstreamEndpointIr::Url).collect()
}

fn resolve_endpoint_port(
    ports: &[K8sEndpointPort],
    svc_port: Option<&K8sServicePort>,
    fallback: u16,
) -> u16 {
    if let Some(sp) = svc_port {
        if let Some(ref name) = sp.name
            && let Some(found) = ports
                .iter()
                .find(|p| p.name.as_deref() == Some(name.as_str()))
        {
            return found.port;
        }
        if let Some(tp) = &sp.target_port {
            if let Some(num) = tp.as_u64()
                && let Ok(p) = u16::try_from(num)
            {
                return p;
            }
            if let Some(name) = tp.as_str()
                && let Some(found) = ports.iter().find(|p| p.name.as_deref() == Some(name))
            {
                return found.port;
            }
        }
    }
    ports.first().map(|p| p.port).unwrap_or(fallback)
}

fn format_host_port_url(scheme: &str, host: &str, port: u16) -> String {
    if host.contains(':') && !host.starts_with('[') {
        format!("{scheme}://[{host}]:{port}")
    } else {
        format!("{scheme}://{host}:{port}")
    }
}

/// Parses Gateway API GEP-1742 duration strings (e.g. `"500ms"`, `"10s"`, `"1m30s"`).
pub fn parse_k8s_duration_ms(raw: &str) -> Option<u64> {
    let s = raw.trim();
    if s.is_empty() {
        return None;
    }
    let bytes = s.as_bytes();
    let mut idx = 0usize;
    let mut total_ms = 0u64;
    let mut matched_any = false;

    while idx < bytes.len() {
        let num_start = idx;
        while idx < bytes.len() && bytes[idx].is_ascii_digit() {
            idx += 1;
        }
        if idx == num_start {
            return None;
        }
        let val: u64 = s[num_start..idx].parse().ok()?;
        let unit_start = idx;
        while idx < bytes.len() && bytes[idx].is_ascii_alphabetic() {
            idx += 1;
        }
        let unit = &s[unit_start..idx];
        let mult = match unit {
            "ms" => 1u64,
            "s" => 1_000,
            "m" => 60_000,
            "h" => 3_600_000,
            _ => return None,
        };
        total_ms = total_ms.checked_add(val.checked_mul(mult)?)?;
        matched_any = true;
    }

    matched_any.then_some(total_ms)
}

fn base64_decode_std(input: &str) -> Result<Vec<u8>, &'static str> {
    let cleaned: Vec<u8> = input.bytes().filter(|b| !b.is_ascii_whitespace()).collect();
    let trimmed = match cleaned.iter().rposition(|&b| b != b'=') {
        Some(end) => &cleaned[..=end],
        None => &[],
    };
    if trimmed.len() % 4 == 1 {
        return Err("invalid base64 length");
    }
    let val = |b: u8| -> Result<u8, &'static str> {
        match b {
            b'A'..=b'Z' => Ok(b - b'A'),
            b'a'..=b'z' => Ok(b - b'a' + 26),
            b'0'..=b'9' => Ok(b - b'0' + 52),
            b'+' | b'-' => Ok(62),
            b'/' | b'_' => Ok(63),
            _ => Err("invalid base64 character"),
        }
    };
    let mut out = Vec::with_capacity((trimmed.len() * 3) / 4);
    let (chunks, rem) = trimmed.as_chunks::<4>();
    for c in chunks {
        let (a, b, c2, d) = (val(c[0])?, val(c[1])?, val(c[2])?, val(c[3])?);
        out.push((a << 2) | (b >> 4));
        out.push((b << 4) | (c2 >> 2));
        out.push((c2 << 6) | d);
    }
    match rem {
        [] => {}
        [x, y] => {
            let (a, b) = (val(*x)?, val(*y)?);
            out.push((a << 2) | (b >> 4));
        }
        [x, y, z] => {
            let (a, b, c2) = (val(*x)?, val(*y)?, val(*z)?);
            out.push((a << 2) | (b >> 4));
            out.push((b << 4) | (c2 >> 2));
        }
        _ => return Err("invalid base64 remainder"),
    }
    Ok(out)
}
