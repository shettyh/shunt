//! Ultra-lean, pluggable Rust HTTP gateway core engine.
//!
//! Built on `tokio`, `hyper` v1, `rustls`, and `arc-swap`.

pub mod body;
pub mod catch;
pub mod error;
pub mod http_client;
pub mod otlp;
pub mod pipeline;
pub mod probe;
pub mod redis;
pub mod registry;
pub mod server;
pub mod snapshot;
pub mod tls;
pub mod upstream;
pub mod ws;

pub use body::ShuntBody;
pub use error::CoreError;
pub use http_client::{
    CoreHttpClient, CoreHttpClientConfig, DEFAULT_HTTP_CLIENT_CONNECT_TIMEOUT,
    DEFAULT_HTTP_CLIENT_MAX_RESPONSE_BYTES, DEFAULT_HTTP_CLIENT_TIMEOUT,
};
pub use otlp::{OtlpExporterConfig, OtlpExporterStats, OtlpHttpExporter, encode_otlp_traces_json};
pub use probe::ProbeSupervisor;
pub use redis::{
    RedisStateStore, RedisStoreConfig, RespError, RespValue, decode_resp_frame,
    encode_resp_command, encode_resp_value,
};
pub use registry::{BuildSession, RuntimeRegistry};
pub use server::{GatewayServer, ServerHandle, ServerReloader};
pub use snapshot::{
    CompiledMirror, CompiledRoute, DEFAULT_MAX_BODY_BYTES, GatewaySnapshot, PathMatch, RouteMatch,
    RouteSpec, SnapshotBuilder, TimeoutConfig, TrafficMirrorSpec, UpstreamHealthReport,
    host_matches,
};
pub use tls::{
    CertStore, DynamicCertResolver, TlsListenerConfig, UpstreamTlsConfig, ensure_crypto_provider,
    load_certified_key_pem,
};
pub use upstream::{
    ActiveHealthCheckConfig, ActiveProbeKind, EndpointHealthSnapshot, EndpointState,
    MAX_SWRR_SCHEDULE_LEN, UpstreamConfig, UpstreamEndpoint, UpstreamPool, UpstreamPoolKey,
    build_swrr_schedule, select_endpoint_index, select_weighted_endpoint_index,
};
