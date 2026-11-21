//! First-party general HTTP plugins for Shunt.
//!
//! Every plugin in this crate depends **strictly** on `shunt-plugin-sdk` (never
//! on `shunt-core`), proving that first-party and third-party plugins use the
//! exact same public contract.

pub mod access_log;
pub mod bearer_auth;
pub mod cors;
pub mod dev_waterfall;
pub mod header_rewrite;
pub mod metrics;
pub mod rate_limit;
pub mod request_id;

use std::sync::Arc;

use shunt_plugin_sdk::PluginRegistry;

pub use access_log::{AccessLogFactory, AccessLogPlugin};
pub use bearer_auth::{AuthSubject, BearerAuthFactory, BearerAuthPlugin};
pub use cors::{CorsFactory, CorsPlugin};
pub use dev_waterfall::{DevWaterfallPlugin, WaterfallSink, format_waterfall};
pub use header_rewrite::{HeaderRewriteFactory, HeaderRewritePlugin};
pub use metrics::{MetricsFactory, MetricsPlugin, PrometheusMetrics};
pub use rate_limit::{RateLimitFactory, RateLimitPlugin};
pub use request_id::{RequestId, RequestIdFactory, RequestIdPlugin};

/// Registers all first-party Shunt plugins into `registry`.
pub fn register_builtin_plugins(registry: &mut PluginRegistry, metrics: Arc<PrometheusMetrics>) {
    registry
        .register(RequestIdFactory)
        .register(AccessLogFactory)
        .register(BearerAuthFactory)
        .register(RateLimitFactory)
        .register(HeaderRewriteFactory)
        .register(CorsFactory)
        .register(MetricsFactory::new(metrics));
}
