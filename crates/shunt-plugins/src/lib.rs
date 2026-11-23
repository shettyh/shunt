//! First-party general HTTP plugins for Shunt.
//!
//! Every plugin in this crate depends **strictly** on `shunt-plugin-sdk` (never
//! on `shunt-engine`), proving that first-party and third-party plugins use the
//! exact same public contract.

pub mod access_log;
pub mod bearer_auth;
pub mod body_limit;
pub mod compression;
pub mod cors;
pub mod dev_waterfall;
pub mod header_rewrite;
pub mod ip_filter;
pub mod jwt_auth;
pub mod metrics;
pub mod mtls_auth;
pub mod otel_trace;
pub mod rate_limit;
pub mod redirect;
pub mod request_id;

use std::sync::Arc;

use shunt_plugin_sdk::PluginRegistry;

pub use access_log::{AccessLogFactory, AccessLogPlugin};
pub use bearer_auth::{AuthSubject, BearerAuthFactory, BearerAuthPlugin};
pub use body_limit::{BodyLimitFactory, BodyLimitPlugin};
pub use compression::{
    CompressionFactory, CompressionPlugin, ContentEncoding, negotiate_accept_encoding,
};
pub use cors::{CorsFactory, CorsPlugin};
pub use dev_waterfall::{DevWaterfallPlugin, WaterfallSink, format_waterfall};
pub use header_rewrite::{HeaderRewriteFactory, HeaderRewritePlugin};
pub use ip_filter::{IpFilterFactory, IpFilterPlugin, IpNet, IpPrecedence, ResolvedClientIp};
pub use jwt_auth::{
    JwtAlgorithm, JwtAuthFactory, JwtAuthPlugin, JwtClaims, ParsedJwt, VerificationKey,
    VerificationKeyMaterial, base64url_decode, base64url_encode, parse_jwks_json,
    parse_jwt_unverified, parse_spki_pem_public_key,
};
pub use metrics::{MetricsFactory, MetricsPlugin, PrometheusMetrics};
pub use mtls_auth::{MtlsAuthFactory, MtlsAuthPlugin};
pub use otel_trace::{OtelTraceFactory, OtelTracePlugin};
pub use rate_limit::{RateLimitFactory, RateLimitPlugin};
pub use redirect::{RedirectFactory, RedirectPlugin};
pub use request_id::{RequestId, RequestIdFactory, RequestIdPlugin};

/// Registers all first-party Shunt plugins into `registry`.
pub fn register_builtin_plugins(registry: &mut PluginRegistry, metrics: Arc<PrometheusMetrics>) {
    registry
        .register(RequestIdFactory)
        .register(AccessLogFactory)
        .register(BearerAuthFactory)
        .register(JwtAuthFactory)
        .register(MtlsAuthFactory)
        .register(IpFilterFactory)
        .register(BodyLimitFactory)
        .register(CompressionFactory)
        .register(RedirectFactory)
        .register(RateLimitFactory)
        .register(HeaderRewriteFactory)
        .register(CorsFactory)
        .register(OtelTraceFactory)
        .register(MetricsFactory::new(metrics));
}
