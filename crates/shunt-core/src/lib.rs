//! Ultra-lean, pluggable Rust HTTP gateway core engine.
//!
//! Built on `tokio`, `hyper` v1, `rustls`, and `arc-swap`.

pub mod body;
pub mod catch;
pub mod error;
pub mod pipeline;
pub mod registry;
pub mod server;
pub mod snapshot;
pub mod tls;
pub mod upstream;
pub mod ws;

pub use body::ShuntBody;
pub use error::CoreError;
pub use registry::{BuildSession, RuntimeRegistry};
pub use server::{GatewayServer, ServerHandle, ServerReloader};
pub use snapshot::{
    CompiledRoute, DEFAULT_MAX_BODY_BYTES, GatewaySnapshot, PathMatch, RouteMatch, RouteSpec,
    SnapshotBuilder, TimeoutConfig, host_matches,
};
pub use tls::{
    CertStore, DynamicCertResolver, TlsListenerConfig, UpstreamTlsConfig, ensure_crypto_provider,
    load_certified_key_pem,
};
pub use upstream::{
    EndpointState, UpstreamConfig, UpstreamPool, UpstreamPoolKey, select_endpoint_index,
};
