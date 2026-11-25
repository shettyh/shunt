//! Configuration IR, `shunt.toml` / YAML loader, file watcher, `SnapshotCompiler`,
//! and read-only Admin API + optional Inspector UI for Shunt.

pub mod admin;
pub mod compiler;
pub mod control_plane;
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
pub use control_plane::{
    ControlPlaneClientConfig, ControlPlaneConfigProvider, ControlPlaneSyncHandle,
    HeartbeatStatusProvider, NodeHeartbeatRequest, NodeRegisterRequest, NodeRegisterResponse,
    SseFrame, SseParser, StateDeltaEvent, StateFullSyncEvent, TopologyBundleResponse,
    TopologyRevisionEvent, parse_cache_key_32, parse_node_labels, start_control_plane_sync,
    verify_bundle_integrity,
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
    DEFAULT_K8S_CONTROLLER_NAME, K8sApiConfigProvider, K8sClientConfig, K8sClusterSnapshot,
    K8sGatewayOptions, K8sManifestConfigProvider, K8sSyncHandle, compile_k8s_gateway_snapshot,
    intersect_two_hostnames, parse_k8s_duration_ms, start_k8s_sync_loop,
};
pub use provider::{ConfigProvider, FileConfigProvider, InlineConfigProvider, LoadedConfig};
pub use reloader::{ConfigWatcherHandle, ReloadController, start_file_watcher};
pub use verify::{
    RoutePolicy, Severity, VerifyDiagnostic, VerifyPolicy, VerifyReport, load_policy_file,
    route_subsumes, verify_bundle,
};
