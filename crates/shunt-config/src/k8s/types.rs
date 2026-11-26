//! Typed Kubernetes Gateway API v1 & Core v1 resource schemas (zero `k8s-openapi` bloat).

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;

use crate::error::ConfigError;
use crate::provider::sha256_hex;

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", default)]
pub struct K8sObjectMeta {
    pub name: String,
    pub namespace: Option<String>,
    pub uid: Option<String>,
    pub generation: Option<i64>,
    pub creation_timestamp: Option<String>,
    pub labels: BTreeMap<String, String>,
    pub annotations: BTreeMap<String, String>,
}

impl K8sObjectMeta {
    pub fn effective_namespace(&self) -> &str {
        self.namespace.as_deref().unwrap_or("default")
    }

    pub fn effective_generation(&self) -> i64 {
        self.generation.unwrap_or(1)
    }
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", default)]
pub struct K8sNamespace {
    pub metadata: K8sObjectMeta,
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
    pub kinds: Vec<K8sRouteGroupKind>,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", default)]
pub struct K8sRouteGroupKind {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub group: Option<String>,
    pub kind: String,
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
    pub match_expressions: Vec<K8sLabelSelectorRequirement>,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", default)]
pub struct K8sLabelSelectorRequirement {
    pub key: String,
    pub operator: String,
    pub values: Vec<String>,
}

impl K8sLabelSelector {
    /// Evaluates Kubernetes `metav1.LabelSelector` (`matchLabels` + `matchExpressions`).
    pub fn matches(&self, labels: &BTreeMap<String, String>) -> bool {
        if !self
            .match_labels
            .iter()
            .all(|(k, v)| labels.get(k) == Some(v))
        {
            return false;
        }
        for expr in &self.match_expressions {
            let val = labels.get(&expr.key);
            let ok = match expr.operator.as_str() {
                "In" => val.is_some_and(|v| expr.values.iter().any(|cand| cand == v)),
                "NotIn" => val.is_none_or(|v| !expr.values.iter().any(|cand| cand == v)),
                "Exists" => val.is_some(),
                "DoesNotExist" => val.is_none(),
                _ => false,
            };
            if !ok {
                return false;
            }
        }
        true
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct K8sHttpRoute {
    #[serde(default)]
    pub metadata: K8sObjectMeta,
    pub spec: K8sHttpRouteSpec,
    #[serde(default)]
    pub status: Option<K8sHttpRouteStatusSnapshot>,
}

/// Minimal snapshot of existing `HTTPRoute.status.parents` read from the API server so
/// controller status patches preserve entries written by other controllers.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", default)]
pub struct K8sHttpRouteStatusSnapshot {
    pub parents: Vec<JsonValue>,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", default)]
pub struct K8sHttpRouteSpec {
    pub parent_refs: Vec<K8sParentRef>,
    pub hostnames: Vec<String>,
    pub rules: Vec<K8sHttpRouteRule>,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", default)]
pub struct K8sParentRef {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub group: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub namespace: Option<String>,
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub section_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
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
    pub query_params: Vec<K8sHttpQueryParamMatch>,
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
pub struct K8sHttpQueryParamMatch {
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
    pub filters: Vec<K8sHttpRouteFilter>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct K8sReferenceGrant {
    #[serde(default)]
    pub metadata: K8sObjectMeta,
    pub spec: K8sReferenceGrantSpec,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", default)]
pub struct K8sReferenceGrantSpec {
    pub from: Vec<K8sReferenceGrantFrom>,
    pub to: Vec<K8sReferenceGrantTo>,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", default)]
pub struct K8sReferenceGrantFrom {
    pub group: String,
    pub kind: String,
    pub namespace: String,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", default)]
pub struct K8sReferenceGrantTo {
    pub group: String,
    pub kind: String,
    pub name: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct K8sService {
    #[serde(default)]
    pub metadata: K8sObjectMeta,
    #[serde(default)]
    pub spec: K8sServiceSpec,
    #[serde(default)]
    pub status: Option<K8sServiceStatus>,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", default)]
pub struct K8sServiceSpec {
    #[serde(rename = "type")]
    pub service_type: Option<String>,
    #[serde(rename = "clusterIP")]
    pub cluster_ip: Option<String>,
    pub selector: BTreeMap<String, String>,
    pub ports: Vec<K8sServicePort>,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", default)]
pub struct K8sServiceStatus {
    pub load_balancer: Option<K8sLoadBalancerStatus>,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", default)]
pub struct K8sLoadBalancerStatus {
    pub ingress: Vec<K8sLoadBalancerIngress>,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", default)]
pub struct K8sLoadBalancerIngress {
    pub ip: Option<String>,
    pub hostname: Option<String>,
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
pub(crate) struct K8sListEnvelope<T> {
    #[serde(default = "Vec::new")]
    pub(crate) items: Vec<T>,
}

/// Complete point-in-time snapshot of Kubernetes Gateway API and backing objects.
#[derive(Debug, Clone, Default)]
pub struct K8sClusterSnapshot {
    pub namespaces: Vec<K8sNamespace>,
    pub gateway_classes: Vec<K8sGatewayClass>,
    pub gateways: Vec<K8sGateway>,
    pub http_routes: Vec<K8sHttpRoute>,
    pub reference_grants: Vec<K8sReferenceGrant>,
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
            "Namespace" => {
                let obj: K8sNamespace = serde_yaml::from_value(val)
                    .map_err(|e| ConfigError::K8s(format!("invalid Namespace: {e}")))?;
                self.namespaces.push(obj);
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
            "ReferenceGrant" => {
                let obj: K8sReferenceGrant = serde_yaml::from_value(val)
                    .map_err(|e| ConfigError::K8s(format!("invalid ReferenceGrant: {e}")))?;
                self.reference_grants.push(obj);
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
