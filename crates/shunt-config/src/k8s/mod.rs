//! Zero-bloat Kubernetes Gateway API v1 compiler, `ConfigProvider`, and controller runtime.
//!
//! Compiles standard `GatewayClass`, `Gateway`, `HTTPRoute`, `ReferenceGrant`, `Namespace`,
//! `Service`, `Endpoints`, `EndpointSlice`, and TLS `Secret` resources directly into Shunt's
//! canonical [`crate::GatewayConfig`] IR—supporting:
//! - Static multi-document YAML manifests ([`K8sManifestConfigProvider`]),
//! - Read-only live Kubernetes API polling/reloads ([`K8sApiConfigProvider`] + [`start_k8s_sync_loop`]),
//! - Full multi-Gateway `GATEWAY-HTTP` controller mode ([`MultiListenerSupervisor`] +
//!   [`start_k8s_controller_loop`]) with `.status` PATCH reconciliation and per-Gateway `Service`
//!   port mapping—built strictly on [`shunt_plugin_sdk::HttpClient`] with zero `kube-rs` bloat.

pub mod client;
pub mod compiler;
pub mod status;
pub mod supervisor;
pub mod types;

use std::collections::BTreeMap;

use crate::ir::PluginAttachment;

pub use client::{
    K8sApiConfigProvider, K8sClientConfig, K8sManifestConfigProvider, K8sSyncHandle,
    start_k8s_sync_loop,
};
pub use compiler::{
    CompiledK8sCluster, CompiledK8sListener, DesiredK8sService, DesiredK8sServicePort,
    PortAllocator, compile_k8s_gateway_cluster, compile_k8s_gateway_snapshot, gateway_service_name,
    intersect_two_hostnames, is_reference_permitted, parse_k8s_duration_ms,
};
pub use status::{
    K8sCondition, K8sGatewayAddress, K8sGatewayClassStatus, K8sGatewayStatus, K8sHttpRouteStatus,
    K8sListenerStatus, K8sRouteParentStatus, K8sStatusPlan, K8sSupportedFeature,
    SUPPORTED_GATEWAY_FEATURES, format_rfc3339_utc,
};
pub use supervisor::{
    K8sControllerHandle, MultiListenerSupervisor, reconcile_k8s_controller_once,
    start_k8s_controller_loop,
};
pub use types::{
    K8sAllowedRoutes, K8sBackendObjectRef, K8sClusterSnapshot, K8sEndpointAddress,
    K8sEndpointConditions, K8sEndpointPort, K8sEndpointSlice, K8sEndpointSliceEntry,
    K8sEndpointSubset, K8sEndpoints, K8sGateway, K8sGatewayClass, K8sGatewayClassSpec,
    K8sGatewaySpec, K8sGatewayTlsConfig, K8sHttpBackendRef, K8sHttpHeader, K8sHttpHeaderFilter,
    K8sHttpHeaderMatch, K8sHttpPathMatch, K8sHttpPathModifier, K8sHttpQueryParamMatch,
    K8sHttpRequestMirrorFilter, K8sHttpRequestRedirectFilter, K8sHttpRoute, K8sHttpRouteFilter,
    K8sHttpRouteMatch, K8sHttpRouteRule, K8sHttpRouteSpec, K8sHttpRouteStatusSnapshot,
    K8sHttpRouteTimeouts, K8sHttpUrlRewriteFilter, K8sLabelSelector, K8sLabelSelectorRequirement,
    K8sListener, K8sLoadBalancerIngress, K8sLoadBalancerStatus, K8sNamespace, K8sObjectMeta,
    K8sParentRef, K8sReferenceGrant, K8sReferenceGrantFrom, K8sReferenceGrantSpec,
    K8sReferenceGrantTo, K8sRouteGroupKind, K8sRouteNamespaces, K8sSecret, K8sSecretObjectRef,
    K8sService, K8sServicePort, K8sServiceSpec, K8sServiceStatus,
};

/// Default Kubernetes Gateway API `GatewayClass.spec.controllerName` managed by Shunt.
pub const DEFAULT_K8S_CONTROLLER_NAME: &str = "shunt.io/gateway-controller";

/// Options controlling how Kubernetes Gateway API resources compile and reconcile.
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
    /// Enable PATCHing `.status` subresources (`GatewayClass`, `Gateway`, `HTTPRoute`).
    pub write_status: bool,
    /// Enable creating/patching/deleting one Kubernetes `Service` per managed `Gateway`.
    pub manage_services: bool,
    /// Kubernetes `Service.spec.type` used when `manage_services = true` (`ClusterIP`, `LoadBalancer`, `NodePort`).
    pub service_type: String,
    /// Pod label selector applied to managed per-`Gateway` `Service` manifests.
    pub pod_selector: BTreeMap<String, String>,
    /// Start of internal pod port range for multi-Gateway listener isolation.
    pub port_range_start: u16,
    /// End of internal pod port range (inclusive).
    pub port_range_end: u16,
    /// Optional fallback address written to `Gateway.status.addresses` when no Service IP is present yet.
    pub default_gateway_address: Option<String>,
}

impl Default for K8sGatewayOptions {
    fn default() -> Self {
        let mut pod_selector = BTreeMap::new();
        pod_selector.insert("app.kubernetes.io/name".to_owned(), "shunt".to_owned());
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
            write_status: false,
            manage_services: false,
            service_type: "ClusterIP".to_owned(),
            pod_selector,
            port_range_start: 10_080,
            port_range_end: 19_999,
            default_gateway_address: None,
        }
    }
}
