//! Configuration IR, `shunt.toml` / YAML loader, file watcher, `SnapshotCompiler`,
//! and read-only Admin API + optional Inspector UI for Shunt.

pub mod admin;
pub mod compiler;
pub mod error;
pub mod inspector;
pub mod ir;
pub mod k8s;
pub mod provider;
pub mod reloader;
#[cfg(feature = "admin-ui")]
pub mod ui;
pub mod verify;

pub use admin::{AdminHandle, AdminServer, MetricsRenderer, StatusProvider, ui_feature_compiled};
pub use compiler::{
    CompiledBundle, PluginInspect, RouteGroupInspect, RouteInspect, RoutePluginInspect,
    SnapshotCompiler, SnapshotInspect, UpstreamInspect,
};
pub use error::ConfigError;
pub use inspector::{
    INSPECTOR_PLUGIN_NAME, InspectorCapturePlugin, InspectorChunkSummary, InspectorHookSpan,
    InspectorTrace, TraceRingBuffer, TraceRingSummary, format_sse_lagged_event,
    format_sse_trace_event,
};
pub use ir::{
    ActiveHealthCheckIr, ActiveProbeKindIr, AdminConfig, ClientAuthModeIr,
    DEFAULT_ROUTE_ALLOW_WEBSOCKETS, DEFAULT_ROUTE_IDLE_CHUNK_TIMEOUT_MS,
    DEFAULT_ROUTE_MAX_ATTEMPTS, DEFAULT_ROUTE_RESPONSE_HEADERS_TIMEOUT_MS,
    DEFAULT_UI_TRACE_CAPACITY, GatewayConfig, MAX_UI_TRACE_CAPACITY, PluginAttachment,
    ResolvedRoute, RouteGroupIr, RouteIr, ServerConfig, ServerTlsConfig, SniCertConfig,
    StateBackendKind, StateConfig, TelemetryBackendKind, TelemetryConfig, UpstreamEndpointIr,
    UpstreamIr, UpstreamTlsIr, host_pattern_subsumes, join_route_paths, redact_secrets,
};
pub use k8s::{
    CompiledK8sCluster, CompiledK8sListener, DEFAULT_K8S_CONTROLLER_NAME, DesiredK8sService,
    DesiredK8sServicePort, K8sApiConfigProvider, K8sClientConfig, K8sClusterSnapshot,
    K8sControllerHandle, K8sGatewayOptions, K8sManifestConfigProvider, K8sStatusPlan,
    K8sSyncHandle, MultiListenerSupervisor, PortAllocator, SUPPORTED_GATEWAY_FEATURES,
    compile_k8s_gateway_cluster, compile_k8s_gateway_snapshot, gateway_service_name,
    intersect_two_hostnames, is_reference_permitted, parse_k8s_duration_ms,
    reconcile_k8s_controller_once, start_k8s_controller_loop, start_k8s_sync_loop,
};
pub use provider::{ConfigProvider, FileConfigProvider, InlineConfigProvider, LoadedConfig};
pub use reloader::{ConfigWatcherHandle, ReloadController, start_file_watcher};
pub use verify::{
    RoutePolicy, Severity, VerifyDiagnostic, VerifyPolicy, VerifyReport, load_policy_file,
    route_subsumes, verify_bundle,
};
