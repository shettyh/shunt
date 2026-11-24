//! Zero-bloat Kubernetes Gateway API v1 compiler and [`ConfigProvider`].
//!
//! Compiles standard `GatewayClass`, `Gateway`, `HTTPRoute`, `Service`, `Endpoints`,
//! `EndpointSlice`, and TLS `Secret` resources directly into Shunt's canonical
//! [`GatewayConfig`] IR—supporting both static multi-document YAML manifests
//! ([`K8sManifestConfigProvider`]) and live Kubernetes API polling/reloads
//! ([`K8sApiConfigProvider`]) built strictly on [`shunt_plugin_sdk::HttpClient`]
//! with zero `kube-rs` / `k8s-openapi` dependency bloat.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use arc_swap::ArcSwap;
use serde::{Deserialize, Serialize};
use serde_json::{Map as JsonMap, Value as JsonValue};
use shunt_engine::{CompiledPathRegex, CoreHttpClient, CoreHttpClientConfig};
use shunt_plugin_sdk::{HeaderValue, HttpClient, HttpRequest, Uri, header};
use tokio::sync::watch;
use tracing::{info, warn};

use crate::error::ConfigError;
use crate::ir::{
    AdminConfig, ClientAuthModeIr, GatewayConfig, PluginAttachment, RouteIr, RouteMirrorIr,
    ServerConfig, ServerTlsConfig, SniCertConfig, UpstreamEndpointIr, UpstreamIr,
};
use crate::provider::{ConfigProvider, LoadedConfig, sha256_hex};
use crate::reloader::ReloadController;

/// Default Kubernetes Gateway API `GatewayClass.spec.controllerName` managed by Shunt.
pub const DEFAULT_K8S_CONTROLLER_NAME: &str = "shunt.io/gateway-controller";
const REDIRECT_NOOP_UPSTREAM: &str = "_k8s_redirect_noop";

/// Options controlling how Kubernetes Gateway API resources compile into [`GatewayConfig`].
#[derive(Debug, Clone)]
pub struct K8sGatewayOptions {
    pub controller_name: String,
    pub namespace: Option<String>,
    pub gateway_name: Option<String>,
    pub listen: String,
    pub admin_listen: String,
    pub admin_enabled: bool,
    pub admin_ui: bool,
    pub cluster_domain: String,
    pub global_plugins: Vec<PluginAttachment>,
}

impl Default for K8sGatewayOptions {
    fn default() -> Self {
        Self {
            controller_name: DEFAULT_K8S_CONTROLLER_NAME.to_owned(),
            namespace: None,
            gateway_name: None,
            listen: "0.0.0.0:8080".to_owned(),
            admin_listen: "127.0.0.1:9090".to_owned(),
            admin_enabled: true,
            admin_ui: false,
            cluster_domain: "cluster.local".to_owned(),
            global_plugins: Vec::new(),
        }
    }
}

// =============================================================================
// Kubernetes Gateway API v1 & Core v1 Resource Schemas
// =============================================================================

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", default)]
pub struct K8sObjectMeta {
    pub name: String,
    pub namespace: Option<String>,
    pub creation_timestamp: Option<String>,
    pub labels: BTreeMap<String, String>,
    pub annotations: BTreeMap<String, String>,
}

impl K8sObjectMeta {
    pub fn effective_namespace(&self) -> &str {
        self.namespace.as_deref().unwrap_or("default")
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct K8sGatewayClass {
    #[serde(default)]
    pub metadata: K8sObjectMeta,
    pub spec: K8sGatewayClassSpec,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", default)]
pub struct K8sGatewayClassSpec {
    pub controller_name: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct K8sGateway {
    #[serde(default)]
    pub metadata: K8sObjectMeta,
    pub spec: K8sGatewaySpec,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", default)]
pub struct K8sGatewaySpec {
    pub gateway_class_name: String,
    pub listeners: Vec<K8sListener>,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", default)]
pub struct K8sListener {
    pub name: String,
    pub hostname: Option<String>,
    pub port: u16,
    pub protocol: String,
    pub tls: Option<K8sGatewayTlsConfig>,
    pub allowed_routes: Option<K8sAllowedRoutes>,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", default)]
pub struct K8sGatewayTlsConfig {
    pub mode: Option<String>,
    pub certificate_refs: Vec<K8sSecretObjectRef>,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", default)]
pub struct K8sSecretObjectRef {
    pub group: Option<String>,
    pub kind: Option<String>,
    pub name: String,
    pub namespace: Option<String>,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", default)]
pub struct K8sAllowedRoutes {
    pub namespaces: Option<K8sRouteNamespaces>,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", default)]
pub struct K8sRouteNamespaces {
    pub from: Option<String>,
    pub selector: Option<K8sLabelSelector>,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", default)]
pub struct K8sLabelSelector {
    pub match_labels: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct K8sHttpRoute {
    #[serde(default)]
    pub metadata: K8sObjectMeta,
    pub spec: K8sHttpRouteSpec,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", default)]
pub struct K8sHttpRouteSpec {
    pub parent_refs: Vec<K8sParentRef>,
    pub hostnames: Vec<String>,
    pub rules: Vec<K8sHttpRouteRule>,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", default)]
pub struct K8sParentRef {
    pub group: Option<String>,
    pub kind: Option<String>,
    pub namespace: Option<String>,
    pub name: String,
    pub section_name: Option<String>,
    pub port: Option<u16>,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", default)]
pub struct K8sHttpRouteRule {
    pub matches: Vec<K8sHttpRouteMatch>,
    pub filters: Vec<K8sHttpRouteFilter>,
    pub backend_refs: Vec<K8sHttpBackendRef>,
    pub timeouts: Option<K8sHttpRouteTimeouts>,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", default)]
pub struct K8sHttpRouteTimeouts {
    pub request: Option<String>,
    pub backend_request: Option<String>,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", default)]
pub struct K8sHttpRouteMatch {
    pub path: Option<K8sHttpPathMatch>,
    pub headers: Vec<K8sHttpHeaderMatch>,
    pub method: Option<String>,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", default)]
pub struct K8sHttpPathMatch {
    #[serde(rename = "type")]
    pub match_type: Option<String>,
    pub value: Option<String>,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", default)]
pub struct K8sHttpHeaderMatch {
    #[serde(rename = "type")]
    pub match_type: Option<String>,
    pub name: String,
    pub value: String,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", default)]
pub struct K8sHttpRouteFilter {
    #[serde(rename = "type")]
    pub filter_type: String,
    pub request_header_modifier: Option<K8sHttpHeaderFilter>,
    pub response_header_modifier: Option<K8sHttpHeaderFilter>,
    pub request_redirect: Option<K8sHttpRequestRedirectFilter>,
    pub url_rewrite: Option<K8sHttpUrlRewriteFilter>,
    pub request_mirror: Option<K8sHttpRequestMirrorFilter>,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", default)]
pub struct K8sHttpHeaderFilter {
    pub set: Vec<K8sHttpHeader>,
    pub add: Vec<K8sHttpHeader>,
    pub remove: Vec<String>,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", default)]
pub struct K8sHttpHeader {
    pub name: String,
    pub value: String,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", default)]
pub struct K8sHttpRequestRedirectFilter {
    pub scheme: Option<String>,
    pub hostname: Option<String>,
    pub path: Option<K8sHttpPathModifier>,
    pub port: Option<u16>,
    pub status_code: Option<u16>,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", default)]
pub struct K8sHttpUrlRewriteFilter {
    pub hostname: Option<String>,
    pub path: Option<K8sHttpPathModifier>,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", default)]
pub struct K8sHttpPathModifier {
    #[serde(rename = "type")]
    pub modifier_type: String,
    pub replace_full_path: Option<String>,
    pub replace_prefix_match: Option<String>,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", default)]
pub struct K8sHttpRequestMirrorFilter {
    pub backend_ref: K8sBackendObjectRef,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", default)]
pub struct K8sBackendObjectRef {
    pub group: Option<String>,
    pub kind: Option<String>,
    pub name: String,
    pub namespace: Option<String>,
    pub port: Option<u16>,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", default)]
pub struct K8sHttpBackendRef {
    pub group: Option<String>,
    pub kind: Option<String>,
    pub name: String,
    pub namespace: Option<String>,
    pub port: Option<u16>,
    pub weight: Option<u32>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct K8sService {
    #[serde(default)]
    pub metadata: K8sObjectMeta,
    #[serde(default)]
    pub spec: K8sServiceSpec,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", default)]
pub struct K8sServiceSpec {
    #[serde(rename = "clusterIP")]
    pub cluster_ip: Option<String>,
    pub ports: Vec<K8sServicePort>,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", default)]
pub struct K8sServicePort {
    pub name: Option<String>,
    pub port: u16,
    pub target_port: Option<JsonValue>,
    pub app_protocol: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct K8sEndpoints {
    #[serde(default)]
    pub metadata: K8sObjectMeta,
    #[serde(default)]
    pub subsets: Vec<K8sEndpointSubset>,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", default)]
pub struct K8sEndpointSubset {
    pub addresses: Vec<K8sEndpointAddress>,
    pub ports: Vec<K8sEndpointPort>,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", default)]
pub struct K8sEndpointAddress {
    pub ip: String,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", default)]
pub struct K8sEndpointPort {
    pub name: Option<String>,
    pub port: u16,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct K8sEndpointSlice {
    #[serde(default)]
    pub metadata: K8sObjectMeta,
    #[serde(default)]
    pub endpoints: Vec<K8sEndpointSliceEntry>,
    #[serde(default)]
    pub ports: Vec<K8sEndpointPort>,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", default)]
pub struct K8sEndpointSliceEntry {
    pub addresses: Vec<String>,
    pub conditions: Option<K8sEndpointConditions>,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", default)]
pub struct K8sEndpointConditions {
    pub ready: Option<bool>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct K8sSecret {
    #[serde(default)]
    pub metadata: K8sObjectMeta,
    #[serde(rename = "type")]
    pub secret_type: Option<String>,
    #[serde(default)]
    pub data: BTreeMap<String, String>,
    #[serde(default)]
    pub string_data: BTreeMap<String, String>,
}

#[derive(Debug, Deserialize)]
struct K8sListEnvelope<T> {
    #[serde(default = "Vec::new")]
    items: Vec<T>,
}

/// Complete point-in-time snapshot of Kubernetes Gateway API and backing Service/Endpoint/Secret objects.
#[derive(Debug, Clone, Default)]
pub struct K8sClusterSnapshot {
    pub gateway_classes: Vec<K8sGatewayClass>,
    pub gateways: Vec<K8sGateway>,
    pub http_routes: Vec<K8sHttpRoute>,
    pub services: Vec<K8sService>,
    pub endpoints: Vec<K8sEndpoints>,
    pub endpoint_slices: Vec<K8sEndpointSlice>,
    pub secrets: Vec<K8sSecret>,
}

impl K8sClusterSnapshot {
    /// Parses a multi-document Kubernetes YAML manifest (`---` separated).
    pub fn from_yaml_str(raw: &str) -> Result<Self, ConfigError> {
        let mut snap = Self::default();
        for doc in serde_yaml::Deserializer::from_str(raw) {
            let val = serde_yaml::Value::deserialize(doc).map_err(|e| {
                ConfigError::K8s(format!("failed to parse Kubernetes YAML document: {e}"))
            })?;
            if val.is_null() {
                continue;
            }
            snap.ingest_yaml_value(val)?;
        }
        Ok(snap)
    }

    /// Loads one YAML file or all `.yaml`/`.yml` files inside a directory (sorted deterministically).
    pub fn from_path(path: &Path) -> Result<(Self, String), ConfigError> {
        let mut combined = String::new();
        if path.is_dir() {
            let mut files = Vec::new();
            collect_yaml_files(path, &mut files)?;
            files.sort();
            for f in files {
                let content = std::fs::read_to_string(&f)
                    .map_err(|source| ConfigError::ReadFile { path: f, source })?;
                combined.push_str("\n---\n");
                combined.push_str(&content);
            }
        } else {
            combined = std::fs::read_to_string(path).map_err(|source| ConfigError::ReadFile {
                path: path.to_path_buf(),
                source,
            })?;
        }
        let digest = sha256_hex(combined.as_bytes());
        let snap = Self::from_yaml_str(&combined)?;
        Ok((snap, digest))
    }

    fn ingest_yaml_value(&mut self, val: serde_yaml::Value) -> Result<(), ConfigError> {
        let kind = val
            .get("kind")
            .and_then(|k| k.as_str())
            .unwrap_or_default()
            .to_owned();
        if kind.is_empty() {
            return Ok(());
        }
        match kind.as_str() {
            "List" => {
                if let Some(items) = val.get("items").and_then(|i| i.as_sequence()) {
                    for item in items.clone() {
                        self.ingest_yaml_value(item)?;
                    }
                }
            }
            "GatewayClass" => {
                let obj: K8sGatewayClass = serde_yaml::from_value(val)
                    .map_err(|e| ConfigError::K8s(format!("invalid GatewayClass: {e}")))?;
                self.gateway_classes.push(obj);
            }
            "Gateway" => {
                let obj: K8sGateway = serde_yaml::from_value(val)
                    .map_err(|e| ConfigError::K8s(format!("invalid Gateway: {e}")))?;
                self.gateways.push(obj);
            }
            "HTTPRoute" => {
                let obj: K8sHttpRoute = serde_yaml::from_value(val)
                    .map_err(|e| ConfigError::K8s(format!("invalid HTTPRoute: {e}")))?;
                self.http_routes.push(obj);
            }
            "Service" => {
                let obj: K8sService = serde_yaml::from_value(val)
                    .map_err(|e| ConfigError::K8s(format!("invalid Service: {e}")))?;
                self.services.push(obj);
            }
            "Endpoints" => {
                let obj: K8sEndpoints = serde_yaml::from_value(val)
                    .map_err(|e| ConfigError::K8s(format!("invalid Endpoints: {e}")))?;
                self.endpoints.push(obj);
            }
            "EndpointSlice" => {
                let obj: K8sEndpointSlice = serde_yaml::from_value(val)
                    .map_err(|e| ConfigError::K8s(format!("invalid EndpointSlice: {e}")))?;
                self.endpoint_slices.push(obj);
            }
            "Secret" => {
                let obj: K8sSecret = serde_yaml::from_value(val)
                    .map_err(|e| ConfigError::K8s(format!("invalid Secret: {e}")))?;
                self.secrets.push(obj);
            }
            _ => {}
        }
        Ok(())
    }
}

fn collect_yaml_files(dir: &Path, out: &mut Vec<PathBuf>) -> Result<(), ConfigError> {
    let entries = std::fs::read_dir(dir).map_err(|source| ConfigError::ReadFile {
        path: dir.to_path_buf(),
        source,
    })?;
    for entry in entries {
        let entry = entry.map_err(|source| ConfigError::ReadFile {
            path: dir.to_path_buf(),
            source,
        })?;
        let p = entry.path();
        if p.is_dir() {
            collect_yaml_files(&p, out)?;
        } else if matches!(
            p.extension().and_then(|e| e.to_str()),
            Some("yaml" | "yml" | "YAML" | "YML")
        ) {
            out.push(p);
        }
    }
    Ok(())
}

// =============================================================================
// Compiler: K8sClusterSnapshot -> GatewayConfig
// =============================================================================

/// Compiles a [`K8sClusterSnapshot`] into a canonical [`GatewayConfig`] IR.
pub fn compile_k8s_gateway_snapshot(
    snap: &K8sClusterSnapshot,
    opts: &K8sGatewayOptions,
) -> Result<GatewayConfig, ConfigError> {
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

    let services_by_key: HashMap<(&str, &str), &K8sService> = snap
        .services
        .iter()
        .map(|s| {
            (
                (s.metadata.effective_namespace(), s.metadata.name.as_str()),
                s,
            )
        })
        .collect();

    let endpoints_by_key: HashMap<(&str, &str), &K8sEndpoints> = snap
        .endpoints
        .iter()
        .map(|e| {
            (
                (e.metadata.effective_namespace(), e.metadata.name.as_str()),
                e,
            )
        })
        .collect();

    let mut slices_by_svc: HashMap<(&str, &str), Vec<&K8sEndpointSlice>> = HashMap::new();
    for slice in &snap.endpoint_slices {
        if let Some(svc_name) = slice.metadata.labels.get("kubernetes.io/service-name") {
            slices_by_svc
                .entry((slice.metadata.effective_namespace(), svc_name.as_str()))
                .or_default()
                .push(slice);
        }
    }

    let secrets_by_key: HashMap<(&str, &str), &K8sSecret> = snap
        .secrets
        .iter()
        .map(|s| {
            (
                (s.metadata.effective_namespace(), s.metadata.name.as_str()),
                s,
            )
        })
        .collect();

    // Compile TLS certificates from HTTPS Terminate listeners & optional client-CA annotation.
    let server_tls = compile_gateway_tls(&matching_gateways, &secrets_by_key)?;

    // Global plugins from options + any Gateway-level `shunt.io/global-plugins` annotations.
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
    let mut needs_redirect_noop = false;

    struct RankedRoute {
        precedence: RoutePrecedenceKey,
        route: RouteIr,
    }
    let mut ranked_routes: Vec<RankedRoute> = Vec::new();

    for http_route in &snap.http_routes {
        let route_ns = http_route.metadata.effective_namespace();
        let route_name = &http_route.metadata.name;
        if let Some(ns_filter) = &opts.namespace
            && route_ns != ns_filter
        {
            continue;
        }

        // Collect all (Gateway, Listener) pairs this HTTPRoute attaches to.
        let mut attached_listeners: Vec<(&K8sGateway, &K8sListener)> = Vec::new();
        for pref in &http_route.spec.parent_refs {
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
                    if !listener_allows_route(gw, listener, http_route) {
                        continue;
                    }
                    attached_listeners.push((gw, listener));
                }
            }
        }

        if attached_listeners.is_empty() {
            continue;
        }

        // Compute effective intersected hostnames across attached listeners.
        let effective_hosts =
            compute_effective_hostnames(&attached_listeners, &http_route.spec.hostnames);
        if effective_hosts.is_none() {
            // Hostname intersection was disjoint -> route does not match any host on these listeners.
            continue;
        }
        let hosts = effective_hosts.unwrap_or_default();

        // Parse optional Shunt annotations on parent Gateway & HTTPRoute.
        let mut extra_plugins: Vec<PluginAttachment> = Vec::new();
        let mut max_attempts = 1usize;
        let mut max_body_bytes: Option<usize> = None;

        if let Some((gw, _)) = attached_listeners.first() {
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
        }
        apply_shunt_annotations(
            &http_route.metadata.annotations,
            &format!("HTTPRoute `{route_ns}/{route_name}`"),
            &mut extra_plugins,
            &mut max_attempts,
            &mut max_body_bytes,
        )?;

        for (rule_idx, rule) in http_route.spec.rules.iter().enumerate() {
            let matches: Vec<K8sHttpRouteMatch> = if rule.matches.is_empty() {
                vec![K8sHttpRouteMatch {
                    path: Some(K8sHttpPathMatch {
                        match_type: Some("PathPrefix".to_owned()),
                        value: Some("/".to_owned()),
                    }),
                    headers: Vec::new(),
                    method: None,
                }]
            } else {
                rule.matches.clone()
            };

            let has_redirect = rule
                .filters
                .iter()
                .any(|f| f.filter_type == "RequestRedirect" && f.request_redirect.is_some());

            // Compile rule backends into a weighted UpstreamIr (unless redirect-only).
            let upstream_name = if has_redirect && rule.backend_refs.is_empty() {
                needs_redirect_noop = true;
                REDIRECT_NOOP_UPSTREAM.to_owned()
            } else {
                let up_name = format!("k8s_{route_ns}_{route_name}_r{rule_idx}");
                let endpoints = resolve_backend_refs_to_endpoints(
                    route_ns,
                    &rule.backend_refs,
                    &services_by_key,
                    &endpoints_by_key,
                    &slices_by_svc,
                    &opts.cluster_domain,
                )?;
                if endpoints.is_empty() {
                    continue;
                }
                upstreams_map.insert(
                    up_name.clone(),
                    UpstreamIr {
                        name: up_name.clone(),
                        endpoints,
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
                up_name
            };

            // Compile RequestMirror filters into RouteMirrorIr entries.
            let mut mirrors = Vec::new();
            for (f_idx, filter) in rule.filters.iter().enumerate() {
                if filter.filter_type == "RequestMirror"
                    && let Some(mirror) = &filter.request_mirror
                {
                    let m_up_name =
                        format!("k8s_mirror_{route_ns}_{route_name}_r{rule_idx}_f{f_idx}");
                    let m_ref = K8sHttpBackendRef {
                        group: mirror.backend_ref.group.clone(),
                        kind: mirror.backend_ref.kind.clone(),
                        name: mirror.backend_ref.name.clone(),
                        namespace: mirror.backend_ref.namespace.clone(),
                        port: mirror.backend_ref.port,
                        weight: Some(1),
                    };
                    let m_eps = resolve_backend_refs_to_endpoints(
                        route_ns,
                        &[m_ref],
                        &services_by_key,
                        &endpoints_by_key,
                        &slices_by_svc,
                        &opts.cluster_domain,
                    )?;
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

                let mut headers = BTreeMap::new();
                for hm in &m.headers {
                    if hm.match_type.as_deref().unwrap_or("Exact") != "Exact" {
                        return Err(ConfigError::K8s(format!(
                            "HTTPRoute `{route_ns}/{route_name}`: unsupported header match type `{}` (only `Exact` is supported)",
                            hm.match_type.as_deref().unwrap_or("")
                        )));
                    }
                    headers.insert(hm.name.clone(), hm.value.clone());
                }

                let methods: Vec<String> = m
                    .method
                    .as_ref()
                    .map(|meth| vec![meth.to_ascii_uppercase()])
                    .unwrap_or_default();

                let mut route_plugins = extra_plugins.clone();
                compile_rule_filters(&rule.filters, matched_prefix, &mut route_plugins)?;

                let route_id = format!("k8s:{route_ns}/{route_name}:r{rule_idx}:m{match_idx}");
                let host_specificity = if hosts.is_empty() {
                    0u8
                } else if hosts.iter().any(|h| !h.starts_with("*.")) {
                    2u8
                } else {
                    1u8
                };

                let prec = RoutePrecedenceKey {
                    path_kind_rank: compiled_path.kind_rank,
                    path_len: compiled_path.path_len,
                    header_count: headers.len(),
                    has_method: !methods.is_empty(),
                    host_specificity,
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
                        hosts: hosts.clone(),
                        path_prefix: compiled_path.path_prefix,
                        path_exact: compiled_path.path_exact,
                        path_template: None,
                        path_regex: compiled_path.path_regex,
                        methods,
                        headers,
                        upstream: Some(upstream_name.clone()),
                        strip_prefix: None,
                        max_body_bytes,
                        max_attempts: Some(max_attempts),
                        response_headers_timeout_ms,
                        idle_chunk_timeout_ms: Some(60_000),
                        allow_websockets: Some(true),
                        mirrors: mirrors.clone(),
                        plugins: route_plugins,
                    },
                });
            }
        }
    }

    if needs_redirect_noop {
        upstreams_map.insert(
            REDIRECT_NOOP_UPSTREAM.to_owned(),
            UpstreamIr {
                name: REDIRECT_NOOP_UPSTREAM.to_owned(),
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

    // Sort routes per Kubernetes Gateway API precedence rules.
    ranked_routes.sort_by(|a, b| a.precedence.cmp_precedence(&b.precedence));

    let config = GatewayConfig {
        server: ServerConfig {
            listen: opts.listen.clone(),
            drain_timeout_ms: 30_000,
            tls: server_tls,
            ..ServerConfig::default()
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

#[derive(Debug, Clone)]
struct RoutePrecedenceKey {
    /// 3 = Exact, 2 = PathPrefix, 1 = RegularExpression, 0 = Any
    path_kind_rank: u8,
    path_len: usize,
    header_count: usize,
    has_method: bool,
    /// 2 = exact host, 1 = wildcard host, 0 = any host
    host_specificity: u8,
    creation_timestamp: String,
    namespace: String,
    name: String,
    rule_idx: usize,
    match_idx: usize,
}

impl RoutePrecedenceKey {
    fn cmp_precedence(&self, other: &Self) -> std::cmp::Ordering {
        // Higher precedence comes FIRST (descending for rank/length/counts, ascending for tie-breakers).
        other
            .path_kind_rank
            .cmp(&self.path_kind_rank)
            .then_with(|| other.path_len.cmp(&self.path_len))
            .then_with(|| other.header_count.cmp(&self.header_count))
            .then_with(|| other.has_method.cmp(&self.has_method))
            .then_with(|| other.host_specificity.cmp(&self.host_specificity))
            .then_with(|| self.creation_timestamp.cmp(&other.creation_timestamp))
            .then_with(|| self.namespace.cmp(&other.namespace))
            .then_with(|| self.name.cmp(&other.name))
            .then_with(|| self.rule_idx.cmp(&other.rule_idx))
            .then_with(|| self.match_idx.cmp(&other.match_idx))
    }
}

fn compile_gateway_tls(
    gateways: &[&K8sGateway],
    secrets: &HashMap<(&str, &str), &K8sSecret>,
) -> Result<Option<ServerTlsConfig>, ConfigError> {
    let mut tls_cfg = ServerTlsConfig::default();
    let mut has_any_cert = false;

    for &gw in gateways {
        let gw_ns = gw.metadata.effective_namespace();

        // Optional mTLS client CA secret annotation (`shunt.io/client-ca-secret = "ca-secret-name"`).
        if let Some(ca_secret_name) = gw.metadata.annotations.get("shunt.io/client-ca-secret") {
            let secret = secrets.get(&(gw_ns, ca_secret_name.as_str())).ok_or_else(|| {
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
                let secret = secrets.get(&(sec_ns, cert_ref.name.as_str())).ok_or_else(|| {
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

fn extract_secret_key(secret: &K8sSecret, key: &str) -> Option<String> {
    if let Some(plain) = secret.string_data.get(key) {
        return Some(plain.clone());
    }
    let b64 = secret.data.get(key)?;
    let decoded = base64_decode_std(b64).ok()?;
    String::from_utf8(decoded).ok()
}

fn listener_allows_route(gw: &K8sGateway, listener: &K8sListener, route: &K8sHttpRoute) -> bool {
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
                sel.match_labels
                    .iter()
                    .all(|(k, v)| route.metadata.labels.get(k) == Some(v))
            } else {
                gw_ns == route_ns
            }
        }
        _ => gw_ns == route_ns,
    }
}

/// Computes Gateway API hostname intersection across attached listeners and route hostnames.
///
/// Returns `None` when listeners and route have disjoint hostnames (route should not bind),
/// `Some(vec![])` when any hostname is matched, or `Some(hosts)` for restricted hosts.
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
                // Per Gateway API v1 precedence, RegularExpression tie-breaking uses headers/method/
                // creationTimestamp/name rather than regex string length.
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
    let mut req_add = JsonMap::new();
    let mut req_remove: Vec<JsonValue> = Vec::new();
    let mut res_set = JsonMap::new();
    let mut res_add = JsonMap::new();
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
                        req_add.insert(h.name.clone(), JsonValue::String(h.value.clone()));
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
                        res_add.insert(h.name.clone(), JsonValue::String(h.value.clone()));
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
            "RequestMirror" => {
                // Compiled directly into `RouteIr.mirrors`.
            }
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
            cfg.insert("request_add".to_owned(), JsonValue::Object(req_add));
        }
        if !req_remove.is_empty() {
            cfg.insert("request_remove".to_owned(), JsonValue::Array(req_remove));
        }
        if !res_set.is_empty() {
            cfg.insert("response_set".to_owned(), JsonValue::Object(res_set));
        }
        if !res_add.is_empty() {
            cfg.insert("response_add".to_owned(), JsonValue::Object(res_add));
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

fn resolve_backend_refs_to_endpoints(
    default_ns: &str,
    backend_refs: &[K8sHttpBackendRef],
    services: &HashMap<(&str, &str), &K8sService>,
    endpoints: &HashMap<(&str, &str), &K8sEndpoints>,
    slices: &HashMap<(&str, &str), Vec<&K8sEndpointSlice>>,
    cluster_domain: &str,
) -> Result<Vec<UpstreamEndpointIr>, ConfigError> {
    let mut resolved_groups: Vec<(u32, Vec<String>)> = Vec::new();

    for bref in backend_refs {
        let weight = bref.weight.unwrap_or(1);
        if weight == 0 {
            continue;
        }
        if let Some(kind) = &bref.kind
            && kind != "Service"
        {
            continue;
        }

        let ns = bref.namespace.as_deref().unwrap_or(default_ns);
        let svc = services.get(&(ns, bref.name.as_str())).copied();
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
        if let Some(svc_slices) = slices.get(&(ns, bref.name.as_str())) {
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
            && let Some(ep_obj) = endpoints.get(&(ns, bref.name.as_str()))
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

        resolved_groups.push((weight, urls));
    }

    if resolved_groups.is_empty() {
        return Ok(Vec::new());
    }

    // Scale per-endpoint weights by LCM of group sizes so backend canary splits are exact
    // even when services have unequal replica counts (e.g., 3 pods vs 1 pod).
    let mut scale: u64 = 1;
    for (_, urls) in &resolved_groups {
        let len = urls.len().max(1) as u64;
        scale = lcm(scale, len).min(10_000);
    }

    let mut out = Vec::new();
    for (group_weight, urls) in resolved_groups {
        let count = urls.len().max(1) as u64;
        let per_ep_weight =
            ((u64::from(group_weight) * scale) / count).clamp(1, u64::from(u32::MAX)) as u32;
        for url in urls {
            if per_ep_weight == 1 {
                out.push(UpstreamEndpointIr::Url(url));
            } else {
                out.push(UpstreamEndpointIr::Weighted {
                    url,
                    weight: per_ep_weight,
                });
            }
        }
    }

    Ok(out)
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

fn gcd(mut a: u64, mut b: u64) -> u64 {
    while b != 0 {
        let t = b;
        b = a % b;
        a = t;
    }
    a.max(1)
}

fn lcm(a: u64, b: u64) -> u64 {
    (a / gcd(a, b)).saturating_mul(b)
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

// =============================================================================
// ConfigProvider #1: Local Kubernetes Gateway API YAML Manifest(s)
// =============================================================================

/// File/directory [`ConfigProvider`] that compiles Kubernetes Gateway API YAML manifests
/// into Shunt's [`GatewayConfig`] IR (supports live hot reloads via `start_file_watcher`).
#[derive(Debug, Clone)]
pub struct K8sManifestConfigProvider {
    path: PathBuf,
    options: K8sGatewayOptions,
}

impl K8sManifestConfigProvider {
    pub fn new(path: impl Into<PathBuf>, options: K8sGatewayOptions) -> Self {
        Self {
            path: path.into(),
            options,
        }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl ConfigProvider for K8sManifestConfigProvider {
    fn source_name(&self) -> String {
        format!("k8s-manifest:{}", self.path.display())
    }

    fn load(&self) -> Result<LoadedConfig, ConfigError> {
        let (snap, digest) = K8sClusterSnapshot::from_path(&self.path)?;
        let config = compile_k8s_gateway_snapshot(&snap, &self.options)?;
        Ok(LoadedConfig {
            source_name: self.source_name(),
            config,
            digest,
        })
    }
}

// =============================================================================
// ConfigProvider #2: Live Kubernetes API Server Provider
// =============================================================================

/// Connection configuration for talking to a Kubernetes API server.
#[derive(Debug, Clone)]
pub struct K8sClientConfig {
    pub api_server: String,
    pub bearer_token: Option<String>,
    pub ca_cert_pem: Option<Vec<u8>>,
    pub insecure_skip_verify: bool,
    pub request_timeout: Duration,
    pub poll_interval: Duration,
}

impl K8sClientConfig {
    /// Discovers in-cluster Kubernetes API credentials from standard ServiceAccount mount paths
    /// (`KUBERNETES_SERVICE_HOST`, `KUBERNETES_SERVICE_PORT`, and `/var/run/secrets/kubernetes.io/serviceaccount/*`).
    pub fn from_in_cluster() -> Result<Self, ConfigError> {
        let host = std::env::var("KUBERNETES_SERVICE_HOST").map_err(|_| {
            ConfigError::K8s(
                "KUBERNETES_SERVICE_HOST is not set (pass `--k8s-api-server` outside a cluster)"
                    .to_owned(),
            )
        })?;
        let port = std::env::var("KUBERNETES_SERVICE_PORT").unwrap_or_else(|_| "443".to_owned());
        let api_server = if host.contains(':') && !host.starts_with('[') {
            format!("https://[{host}]:{port}")
        } else {
            format!("https://{host}:{port}")
        };
        let token_path = Path::new("/var/run/secrets/kubernetes.io/serviceaccount/token");
        let bearer_token = std::fs::read_to_string(token_path)
            .map(|s| s.trim().to_owned())
            .map_err(|e| {
                ConfigError::K8s(format!(
                    "failed to read ServiceAccount token `{}`: {e}",
                    token_path.display()
                ))
            })?;
        let ca_path = Path::new("/var/run/secrets/kubernetes.io/serviceaccount/ca.crt");
        let ca_cert_pem = std::fs::read(ca_path).ok();

        Ok(Self {
            api_server,
            bearer_token: Some(bearer_token),
            ca_cert_pem,
            insecure_skip_verify: false,
            request_timeout: Duration::from_secs(10),
            poll_interval: Duration::from_secs(5),
        })
    }
}

/// Live Kubernetes Gateway API [`ConfigProvider`] backed by [`HttpClient`].
///
/// [`K8sApiConfigProvider::sync_once`] fetches `GatewayClass`, `Gateway`, `HTTPRoute`,
/// `Service`, `Endpoints`, `EndpointSlice`, and referenced TLS `Secret` resources from the
/// Kubernetes API server, compiles them into [`GatewayConfig`], and stores the latest
/// [`LoadedConfig`] lock-free in an [`ArcSwap`] so synchronous [`ConfigProvider::load`] calls
/// never block a Tokio worker thread.
pub struct K8sApiConfigProvider {
    client_cfg: K8sClientConfig,
    options: K8sGatewayOptions,
    http_client: Arc<dyn HttpClient>,
    latest: ArcSwap<Option<LoadedConfig>>,
}

impl K8sApiConfigProvider {
    /// Creates a provider using Shunt's built-in pooled [`CoreHttpClient`].
    pub fn new(
        client_cfg: K8sClientConfig,
        options: K8sGatewayOptions,
    ) -> Result<Self, ConfigError> {
        let http_cfg = CoreHttpClientConfig {
            default_timeout: client_cfg.request_timeout,
            extra_ca_pem: client_cfg.ca_cert_pem.clone(),
            insecure_skip_verify: client_cfg.insecure_skip_verify,
            ..CoreHttpClientConfig::default()
        };
        let client = CoreHttpClient::new(http_cfg)?;
        Ok(Self::with_http_client(
            client_cfg,
            options,
            Arc::new(client),
        ))
    }

    /// Creates a provider using a custom [`HttpClient`] (ideal for mock/unit tests).
    pub fn with_http_client(
        client_cfg: K8sClientConfig,
        options: K8sGatewayOptions,
        http_client: Arc<dyn HttpClient>,
    ) -> Self {
        Self {
            client_cfg,
            options,
            http_client,
            latest: ArcSwap::from_pointee(None),
        }
    }

    pub fn poll_interval(&self) -> Duration {
        self.client_cfg.poll_interval
    }

    /// Synchronizes once against the Kubernetes API server.
    ///
    /// Returns `Ok(true)` if the compiled configuration digest changed since the last sync,
    /// or `Ok(false)` if unchanged.
    pub async fn sync_once(&self) -> Result<bool, ConfigError> {
        let ns_seg = match &self.options.namespace {
            Some(ns) => format!("namespaces/{ns}/"),
            None => String::new(),
        };

        let gateway_classes: Vec<K8sGatewayClass> = self
            .fetch_list("/apis/gateway.networking.k8s.io/v1/gatewayclasses")
            .await?;
        let gateways: Vec<K8sGateway> = self
            .fetch_list(&format!(
                "/apis/gateway.networking.k8s.io/v1/{ns_seg}gateways"
            ))
            .await?;
        let http_routes: Vec<K8sHttpRoute> = self
            .fetch_list(&format!(
                "/apis/gateway.networking.k8s.io/v1/{ns_seg}httproutes"
            ))
            .await?;
        let services: Vec<K8sService> = self
            .fetch_list(&format!("/api/v1/{ns_seg}services"))
            .await?;
        let endpoints: Vec<K8sEndpoints> = self
            .fetch_list_optional(&format!("/api/v1/{ns_seg}endpoints"))
            .await?;
        let endpoint_slices: Vec<K8sEndpointSlice> = self
            .fetch_list_optional(&format!("/apis/discovery.k8s.io/v1/{ns_seg}endpointslices"))
            .await?;

        // Only fetch Secrets actually referenced by Gateway TLS listeners or client-CA annotations.
        let mut needed_secrets: HashSet<(String, String)> = HashSet::new();
        for gw in &gateways {
            let gw_ns = gw.metadata.effective_namespace().to_owned();
            if let Some(ca_sec) = gw.metadata.annotations.get("shunt.io/client-ca-secret") {
                needed_secrets.insert((gw_ns.clone(), ca_sec.clone()));
            }
            for listener in &gw.spec.listeners {
                if let Some(tls) = &listener.tls {
                    for cref in &tls.certificate_refs {
                        let s_ns = cref.namespace.clone().unwrap_or_else(|| gw_ns.clone());
                        needed_secrets.insert((s_ns, cref.name.clone()));
                    }
                }
            }
        }
        let mut secrets = Vec::with_capacity(needed_secrets.len());
        let mut sorted_secret_keys: Vec<(String, String)> = needed_secrets.into_iter().collect();
        sorted_secret_keys.sort();
        for (s_ns, s_name) in sorted_secret_keys {
            let sec: K8sSecret = self
                .fetch_single(&format!("/api/v1/namespaces/{s_ns}/secrets/{s_name}"))
                .await?;
            secrets.push(sec);
        }

        let snap = K8sClusterSnapshot {
            gateway_classes,
            gateways,
            http_routes,
            services,
            endpoints,
            endpoint_slices,
            secrets,
        };
        let config = compile_k8s_gateway_snapshot(&snap, &self.options)?;
        let canonical = serde_json::to_vec(&config)
            .map_err(|e| ConfigError::K8s(format!("failed to hash compiled config: {e}")))?;
        let digest = sha256_hex(&canonical);

        let prev_digest = self
            .latest
            .load()
            .as_ref()
            .as_ref()
            .map(|l| l.digest.clone());
        let changed = prev_digest.as_deref() != Some(digest.as_str());

        let loaded = LoadedConfig {
            source_name: self.source_name(),
            config,
            digest,
        };
        self.latest.store(Arc::new(Some(loaded)));
        Ok(changed)
    }

    async fn fetch_list<T: for<'de> Deserialize<'de>>(
        &self,
        path: &str,
    ) -> Result<Vec<T>, ConfigError> {
        let body = self.get_json(path).await?;
        let list: K8sListEnvelope<T> = serde_json::from_slice(&body).map_err(|e| {
            ConfigError::K8s(format!(
                "failed to decode Kubernetes list from `{path}`: {e}"
            ))
        })?;
        Ok(list.items)
    }

    async fn fetch_list_optional<T: for<'de> Deserialize<'de>>(
        &self,
        path: &str,
    ) -> Result<Vec<T>, ConfigError> {
        match self.get_json_status(path).await? {
            (http::StatusCode::NOT_FOUND, _) => Ok(Vec::new()),
            (status, body) if status.is_success() => {
                let list: K8sListEnvelope<T> = serde_json::from_slice(&body).map_err(|e| {
                    ConfigError::K8s(format!(
                        "failed to decode Kubernetes list from `{path}`: {e}"
                    ))
                })?;
                Ok(list.items)
            }
            (status, _) => Err(ConfigError::K8s(format!(
                "Kubernetes API `{path}` returned HTTP {status}"
            ))),
        }
    }

    async fn fetch_single<T: for<'de> Deserialize<'de>>(
        &self,
        path: &str,
    ) -> Result<T, ConfigError> {
        let body = self.get_json(path).await?;
        serde_json::from_slice(&body).map_err(|e| {
            ConfigError::K8s(format!(
                "failed to decode Kubernetes object from `{path}`: {e}"
            ))
        })
    }

    async fn get_json(&self, path: &str) -> Result<bytes::Bytes, ConfigError> {
        let (status, body) = self.get_json_status(path).await?;
        if !status.is_success() {
            return Err(ConfigError::K8s(format!(
                "Kubernetes API `{path}` returned HTTP {status}"
            )));
        }
        Ok(body)
    }

    async fn get_json_status(
        &self,
        path: &str,
    ) -> Result<(http::StatusCode, bytes::Bytes), ConfigError> {
        let base = self.client_cfg.api_server.trim_end_matches('/');
        let full_url = format!("{base}{path}");
        let uri: Uri = full_url.parse().map_err(|e| {
            ConfigError::K8s(format!("invalid Kubernetes API URL `{full_url}`: {e}"))
        })?;
        let mut req = HttpRequest::get(uri)
            .with_header(header::ACCEPT, HeaderValue::from_static("application/json"))
            .with_timeout(self.client_cfg.request_timeout);
        if let Some(tok) = &self.client_cfg.bearer_token {
            let val = HeaderValue::from_str(&format!("Bearer {tok}")).map_err(|e| {
                ConfigError::K8s(format!("invalid Kubernetes bearer token header: {e}"))
            })?;
            req = req.with_header(header::AUTHORIZATION, val);
        }
        let resp = self.http_client.send(req).await.map_err(|e| {
            ConfigError::K8s(format!("Kubernetes API request `{path}` failed: {e}"))
        })?;
        Ok((resp.status, resp.body))
    }
}

impl ConfigProvider for K8sApiConfigProvider {
    fn source_name(&self) -> String {
        format!("k8s-api:{}", self.client_cfg.api_server)
    }

    fn load(&self) -> Result<LoadedConfig, ConfigError> {
        self.latest.load().as_ref().clone().ok_or_else(|| {
            ConfigError::K8s(
                "K8sApiConfigProvider has not completed initial sync_once() yet".to_owned(),
            )
        })
    }
}

/// Handle for the background Kubernetes Gateway API synchronization task.
pub struct K8sSyncHandle {
    shutdown_tx: watch::Sender<bool>,
    task: tokio::task::JoinHandle<()>,
}

impl K8sSyncHandle {
    pub fn stop(self) {
        let _ = self.shutdown_tx.send(true);
        self.task.abort();
    }
}

/// Spawns a background polling loop that syncs Kubernetes Gateway API resources into
/// `provider` and triggers atomic [`ReloadController::reload`] whenever the compiled digest changes.
pub fn start_k8s_sync_loop(
    provider: Arc<K8sApiConfigProvider>,
    controller: Arc<ReloadController>,
) -> K8sSyncHandle {
    let (shutdown_tx, mut shutdown_rx) = watch::channel(false);
    let interval = provider.poll_interval().max(Duration::from_millis(200));
    let task = tokio::spawn(async move {
        let mut ticker = tokio::time::interval(interval);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        // Skip immediate first tick since caller already ran initial `sync_once()`.
        ticker.tick().await;
        loop {
            tokio::select! {
                _ = shutdown_rx.changed() => {
                    if *shutdown_rx.borrow() {
                        break;
                    }
                }
                _ = ticker.tick() => {
                    match provider.sync_once().await {
                        Ok(true) => {
                            match controller.reload() {
                                Ok(inspect) => {
                                    info!(
                                        version = inspect.version,
                                        routes = inspect.routes.len(),
                                        upstreams = inspect.upstreams.len(),
                                        "reloaded gateway snapshot from Kubernetes Gateway API"
                                    );
                                }
                                Err(err) => {
                                    warn!(
                                        error = %err,
                                        "Kubernetes Gateway API reload failed; keeping last-known-good snapshot"
                                    );
                                }
                            }
                        }
                        Ok(false) => {}
                        Err(err) => {
                            warn!(
                                error = %err,
                                "Kubernetes Gateway API sync error; retrying on next poll"
                            );
                        }
                    }
                }
            }
        }
    });
    K8sSyncHandle { shutdown_tx, task }
}
