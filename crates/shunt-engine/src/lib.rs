//! Ultra-lean, pluggable Rust HTTP gateway core engine.
//!
//! Built on `tokio`, `hyper` v1, `rustls`, and `arc-swap`.

pub mod body;
pub mod catch;
pub mod error;
pub mod http_client;
pub mod otlp;
pub mod path_match;
pub mod pipeline;
pub mod probe;
pub mod redis;
pub mod registry;
pub mod route_index;
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
pub use path_match::{
    CompiledPathRegex, CompiledPathTemplate, DEFAULT_PATH_REGEX_SIZE_LIMIT, PathMatch,
    TemplateSegment, validate_request_path, validate_request_path_allow_encoded_slashes,
};
pub use pipeline::{DEFAULT_REQUEST_BODY_TIMEOUT, RequestMeta};
pub use probe::ProbeSupervisor;
pub use redis::{
    RedisStateStore, RedisStoreConfig, RespError, RespValue, decode_resp_frame,
    encode_resp_command, encode_resp_value,
};
pub use registry::{BuildSession, RuntimeRegistry};
pub use route_index::{ROUTE_INDEX_MIN_ROUTES, RouteIndex};
pub use server::{
    DEFAULT_HEADER_READ_TIMEOUT, DEFAULT_HTTP2_KEEP_ALIVE_INTERVAL,
    DEFAULT_HTTP2_KEEP_ALIVE_TIMEOUT, DEFAULT_HTTP2_MAX_CONCURRENT_STREAMS,
    DEFAULT_HTTP2_MAX_HEADER_LIST_SIZE, DEFAULT_MAX_CONNECTIONS, DEFAULT_TLS_HANDSHAKE_TIMEOUT,
    GatewayServer, ServerHandle, ServerLimits, ServerReloader,
};
pub use snapshot::{
    CompiledMirror, CompiledRoute, DEFAULT_MAX_BODY_BYTES, GatewaySnapshot, RouteMatch, RouteSpec,
    SnapshotBuilder, TimeoutConfig, TrafficMirrorSpec, UpstreamHealthReport, host_matches,
};
pub use tls::{
    CertStore, ClientAuthConfig, ClientAuthMode, DynamicCertResolver, TlsListenerConfig,
    UpstreamTlsConfig, ensure_crypto_provider, load_certified_key_pem, parse_client_cert_info,
};
pub use upstream::{
    ActiveHealthCheckConfig, ActiveProbeKind, EndpointHealthSnapshot, EndpointState,
    MAX_SWRR_SCHEDULE_LEN, UpstreamConfig, UpstreamEndpoint, UpstreamPool, UpstreamPoolKey,
    build_swrr_schedule, select_endpoint_index, select_weighted_endpoint_index,
};
