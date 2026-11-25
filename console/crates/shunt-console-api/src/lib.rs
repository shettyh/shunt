//! Axum HTTP router for `shunt-console`:
//! - `/cp/v1/...`: Outbound data-plane protocol (Node registration, Channel 1 topology SSE/pull,
//!   Channel 2 `SyncedTable` SSE deltas/full_sync, Heartbeats).
//! - `/api/v1/...`: Terraform-ready REST/OpenAPI 3.1 management API with RBAC, `ETag` concurrency,
//!   and RFC 9457 `application/problem+json` error envelopes.
//! - `/*`: Embedded React SPA assets via `rust-embed`.

pub mod api;
pub mod auth;
pub mod cp;
pub mod problem;
pub mod spa;

use std::sync::Arc;

use axum::Router;
use axum::http::Method;
use axum::routing::{delete, get, patch, post, put};
use shunt_console_core::ConsoleStore;
use shunt_engine::CoreHttpClient;
use tower_http::cors::{Any, CorsLayer};
use tower_http::limit::RequestBodyLimitLayer;
use tower_http::trace::TraceLayer;

#[derive(Clone)]
pub struct AppState {
    pub store: Arc<ConsoleStore>,
    pub http_client: Arc<CoreHttpClient>,
    pub public_url: String,
    pub secure_cookies: bool,
}

impl AppState {
    pub fn new(store: Arc<ConsoleStore>, public_url: String, secure_cookies: bool) -> Self {
        let http_client =
            Arc::new(CoreHttpClient::new_default().expect("failed to initialize CoreHttpClient"));
        Self {
            store,
            http_client,
            public_url,
            secure_cookies,
        }
    }
}

/// Builds the complete `shunt-console` Axum [`Router`].
pub fn build_router(state: AppState, allow_dev_cors: bool) -> Router {
    let cp_routes = Router::new()
        .route("/cp/v1/nodes/register", post(cp::register_node))
        .route("/cp/v1/nodes/{node_id}/heartbeat", post(cp::node_heartbeat))
        .route(
            "/cp/v1/clusters/{cluster}/topology/watch",
            get(cp::watch_topology),
        )
        .route(
            "/cp/v1/clusters/{cluster}/topology/revisions/assigned",
            get(cp::get_assigned_revision_bundle),
        )
        .route(
            "/cp/v1/clusters/{cluster}/topology/revisions/{rev}",
            get(cp::get_revision_bundle),
        )
        .route(
            "/cp/v1/clusters/{cluster}/state/stream",
            get(cp::stream_synced_state),
        );

    let api_routes = Router::new()
        // OpenAPI & System
        .route("/api/v1/openapi.json", get(api::get_openapi_json))
        .route("/api/v1/system/status", get(api::get_system_status))
        .route("/api/v1/setup/bootstrap", post(api::setup_bootstrap))
        // Auth & OIDC
        .route("/api/v1/auth/login", post(api::login))
        .route("/api/v1/auth/logout", post(api::logout))
        .route("/api/v1/auth/me", get(api::get_me))
        .route("/api/v1/auth/oidc/{slug}/start", get(api::oidc_start))
        .route("/api/v1/auth/oidc/{slug}/callback", get(api::oidc_callback))
        // Orgs & Teams
        .route("/api/v1/orgs", get(api::list_orgs).post(api::create_org))
        .route("/api/v1/orgs/{org}/teams", get(api::list_teams))
        .route("/api/v1/orgs/{org}/teams/{team}", put(api::upsert_team))
        // Clusters, Nodes & Bootstrap Tokens
        .route(
            "/api/v1/orgs/{org}/clusters",
            get(api::list_org_clusters).post(api::create_cluster),
        )
        .route("/api/v1/clusters/{cluster}", get(api::get_cluster))
        .route(
            "/api/v1/clusters/{cluster}/nodes",
            get(api::list_cluster_nodes),
        )
        .route(
            "/api/v1/clusters/{cluster}/nodes/{node_id}",
            delete(api::delete_node),
        )
        .route(
            "/api/v1/clusters/{cluster}/nodes/{node_id}/labels",
            patch(api::update_node_labels),
        )
        .route(
            "/api/v1/clusters/{cluster}/bootstrap-tokens",
            get(api::list_bootstrap_tokens).post(api::create_bootstrap_token),
        )
        .route(
            "/api/v1/clusters/{cluster}/bootstrap-tokens/{id}",
            delete(api::revoke_bootstrap_token),
        )
        // Channel 1 Topology Resources & Revisions
        .route(
            "/api/v1/clusters/{cluster}/resources",
            get(api::list_topology_resources),
        )
        .route(
            "/api/v1/clusters/{cluster}/resources/{kind}/{slug}",
            put(api::upsert_topology_resource).delete(api::delete_topology_resource),
        )
        .route(
            "/api/v1/clusters/{cluster}/validate",
            post(api::validate_cluster_draft),
        )
        .route(
            "/api/v1/clusters/{cluster}/import-toml",
            post(api::import_cluster_toml),
        )
        .route(
            "/api/v1/clusters/{cluster}/revisions",
            get(api::list_revisions),
        )
        .route(
            "/api/v1/clusters/{cluster}/revisions:publish",
            post(api::publish_revision),
        )
        .route(
            "/api/v1/clusters/{cluster}/revisions/{rev}",
            get(api::get_revision),
        )
        .route(
            "/api/v1/clusters/{cluster}/revisions/{rev}/rollback",
            post(api::rollback_revision),
        )
        .route(
            "/api/v1/clusters/{cluster}/revisions/{rev}/promote",
            post(api::promote_revision),
        )
        .route(
            "/api/v1/clusters/{cluster}/revisions/{rev}/export.toml",
            get(api::export_revision_toml),
        )
        // Channel 2 Synced State Management
        .route(
            "/api/v1/clusters/{cluster}/state",
            get(api::list_state_namespaces),
        )
        .route(
            "/api/v1/clusters/{cluster}/state/{namespace}",
            get(api::get_namespace_state),
        )
        .route(
            "/api/v1/clusters/{cluster}/state/{namespace}/{key}",
            put(api::upsert_state_item).delete(api::delete_state_item),
        )
        // Secrets Vault
        .route("/api/v1/orgs/{org}/secrets", get(api::list_secrets))
        .route(
            "/api/v1/orgs/{org}/secrets/{slug}",
            put(api::upsert_secret).delete(api::delete_secret),
        )
        // Users, RBAC, API Tokens & OIDC
        .route(
            "/api/v1/orgs/{org}/users",
            get(api::list_org_users).post(api::create_org_user),
        )
        .route(
            "/api/v1/orgs/{org}/role-bindings",
            post(api::create_role_binding),
        )
        .route(
            "/api/v1/orgs/{org}/role-bindings/{id}",
            delete(api::delete_role_binding),
        )
        .route(
            "/api/v1/orgs/{org}/api-tokens",
            get(api::list_api_tokens).post(api::create_api_token),
        )
        .route(
            "/api/v1/orgs/{org}/api-tokens/{id}",
            delete(api::revoke_api_token),
        )
        .route(
            "/api/v1/orgs/{org}/oidc-providers",
            get(api::list_oidc_providers),
        )
        .route(
            "/api/v1/orgs/{org}/oidc-providers/{slug}",
            put(api::upsert_oidc_provider).delete(api::delete_oidc_provider),
        )
        // Tamper-Evident Admin Audit Log
        .route("/api/v1/audit/admin", get(api::list_admin_audit))
        .route("/api/v1/audit/admin:verify", get(api::verify_admin_audit));

    let mut router = Router::new()
        .merge(cp_routes)
        .merge(api_routes)
        .fallback(spa::serve_spa)
        .layer(RequestBodyLimitLayer::new(8 * 1024 * 1024))
        .layer(TraceLayer::new_for_http())
        .with_state(state);

    if allow_dev_cors {
        router = router.layer(
            CorsLayer::new()
                .allow_origin(Any)
                .allow_methods([
                    Method::GET,
                    Method::POST,
                    Method::PUT,
                    Method::PATCH,
                    Method::DELETE,
                    Method::OPTIONS,
                ])
                .allow_headers(Any),
        );
    }

    router
}
