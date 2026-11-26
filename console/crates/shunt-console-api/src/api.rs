use std::collections::BTreeMap;

use axum::Json;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, Uri, header};
use axum::response::{IntoResponse, Redirect, Response};
use axum_extra::extract::cookie::CookieJar;
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use shunt_console_core::{
    AdminAuditEntry, ApiTokenMeta, AuditChainVerification, BootstrapTokenMeta, Cluster,
    ConsoleError, ControlEvent, ControlStateItem, CreateApiTokenInput, CreateBootstrapTokenInput,
    CreateClusterInput, CreateOidcProviderInput, CreateOrgInput, CreateUserInput, CreatedApiToken,
    CreatedBootstrapToken, DiagnosticItem, InitialBootstrapInput, InitialBootstrapResult,
    NamespaceStateSummary, NodeRecord, OidcProviderRecord, Organization, Permission,
    PublishRevisionInput, Role, RoleBinding, SecretMeta, SystemStatus, Team, TopologyResource,
    TopologyResourceKind, TopologyRevision, UpsertResourceInput, UpsertSecretInput, UserSummary,
    ValidateDraftResult, authorize, generate_secret_token, sha256_hex,
};
use shunt_plugin_sdk::{HttpClient, HttpRequest};
use utoipa::{OpenApi, ToSchema};

use crate::AppState;
use crate::auth::{
    AuthPrincipal, SESSION_COOKIE_NAME, build_session_cookie, clear_session_cookie,
    extract_if_match,
};
use crate::problem::{ApiError, ProblemDetails};

#[derive(OpenApi)]
#[openapi(
    info(
        title = "shunt-console Control Plane API",
        version = "0.3.0",
        description = "Terraform-ready REST/OpenAPI 3.1 management API for Shunt fleets (HTTP API, AI, and MCP gateways)."
    ),
    paths(
        get_system_status,
        setup_bootstrap,
        login,
        logout,
        get_me,
        list_orgs,
        create_org,
        list_org_clusters,
        create_cluster,
        get_cluster,
        list_cluster_nodes,
        update_node_labels,
        delete_node,
        list_bootstrap_tokens,
        create_bootstrap_token,
        revoke_bootstrap_token,
        list_topology_resources,
        upsert_topology_resource,
        delete_topology_resource,
        validate_cluster_draft,
        import_cluster_toml,
        list_revisions,
        get_revision,
        publish_revision,
        rollback_revision,
        export_revision_toml,
        list_state_namespaces,
        get_namespace_state,
        upsert_state_item,
        delete_state_item,
        list_secrets,
        upsert_secret,
        delete_secret,
        list_org_users,
        create_org_user,
        create_role_binding,
        delete_role_binding,
        list_api_tokens,
        create_api_token,
        revoke_api_token,
        list_oidc_providers,
        upsert_oidc_provider,
        delete_oidc_provider,
        list_admin_audit,
        verify_admin_audit,
    ),
    components(schemas(
        ProblemDetails,
        DiagnosticItem,
        SystemStatus,
        InitialBootstrapInput,
        InitialBootstrapResult,
        LoginRequest,
        MeResponse,
        Organization,
        CreateOrgInput,
        Team,
        UserSummary,
        UserWithRoles,
        CreateUserInput,
        Role,
        RoleBinding,
        CreateRoleBindingRequest,
        ApiTokenMeta,
        CreatedApiToken,
        CreateApiTokenInput,
        OidcProviderRecord,
        CreateOidcProviderInput,
        Cluster,
        CreateClusterInput,
        NodeRecord,
        UpdateNodeLabelsRequest,
        BootstrapTokenMeta,
        CreatedBootstrapToken,
        CreateBootstrapTokenInput,
        TopologyResourceKind,
        TopologyResource,
        UpsertResourceInput,
        ValidateDraftResult,
        ImportTomlRequest,
        TopologyRevision,
        PublishRevisionInput,
        RollbackRevisionRequest,
        NamespaceStateSummary,
        NamespaceStateResponse,
        UpsertStateItemRequest,
        ControlStateItem,
        ControlEvent,
        SecretMeta,
        UpsertSecretInput,
        AdminAuditEntry,
        AuditChainVerification,
    ))
)]
pub struct ConsoleOpenApi;

/// `GET /api/v1/openapi.json` — Serves the auto-generated OpenAPI 3.1 specification.
pub async fn get_openapi_json() -> Json<utoipa::openapi::OpenApi> {
    Json(ConsoleOpenApi::openapi())
}

// =============================================================================
// System Status, First-Run Bootstrap & Authentication
// =============================================================================

#[utoipa::path(
    get,
    path = "/api/v1/system/status",
    responses((status = 200, body = SystemStatus))
)]
pub async fn get_system_status(
    State(state): State<AppState>,
) -> Result<Json<SystemStatus>, ApiError> {
    Ok(Json(state.store.system_status().await?))
}

#[utoipa::path(
    post,
    path = "/api/v1/setup/bootstrap",
    request_body = InitialBootstrapInput,
    responses(
        (status = 201, body = InitialBootstrapResult),
        (status = 409, body = ProblemDetails)
    )
)]
pub async fn setup_bootstrap(
    State(state): State<AppState>,
    jar: CookieJar,
    Json(input): Json<InitialBootstrapInput>,
) -> Result<(StatusCode, CookieJar, Json<InitialBootstrapResult>), ApiError> {
    let result = state.store.initial_bootstrap(input).await?;
    let cookie = build_session_cookie(result.session_token.clone(), state.secure_cookies);
    Ok((StatusCode::CREATED, jar.add(cookie), Json(result)))
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct LoginRequest {
    pub email: String,
    pub password: String,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct MeResponse {
    pub actor_type: String,
    pub actor_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user: Option<UserSummary>,
    pub bindings: Vec<RoleBinding>,
    pub roles_catalog: Vec<RoleCatalogItem>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct RoleCatalogItem {
    pub role: Role,
    pub description: String,
}

#[utoipa::path(
    post,
    path = "/api/v1/auth/login",
    request_body = LoginRequest,
    responses((status = 200, body = UserSummary), (status = 401, body = ProblemDetails))
)]
pub async fn login(
    State(state): State<AppState>,
    jar: CookieJar,
    Json(req): Json<LoginRequest>,
) -> Result<(CookieJar, Json<UserSummary>), ApiError> {
    let (user, session_token) = state
        .store
        .authenticate_local(&req.email, &req.password)
        .await?;
    let cookie = build_session_cookie(session_token, state.secure_cookies);
    Ok((jar.add(cookie), Json(user)))
}

#[utoipa::path(
    post,
    path = "/api/v1/auth/logout",
    responses((status = 204))
)]
pub async fn logout(State(state): State<AppState>, jar: CookieJar) -> (CookieJar, StatusCode) {
    if let Some(cookie) = jar.get(SESSION_COOKIE_NAME) {
        let _ = state.store.revoke_session(cookie.value()).await;
    }
    (jar.add(clear_session_cookie()), StatusCode::NO_CONTENT)
}

#[utoipa::path(
    get,
    path = "/api/v1/auth/me",
    responses((status = 200, body = MeResponse), (status = 401, body = ProblemDetails))
)]
pub async fn get_me(AuthPrincipal(p): AuthPrincipal) -> Json<MeResponse> {
    let all_roles = [
        Role::SuperAdmin,
        Role::ClusterOperator,
        Role::OrgAdmin,
        Role::TeamLead,
        Role::Developer,
        Role::Auditor,
    ];
    Json(MeResponse {
        actor_type: p.actor.actor_type,
        actor_id: p.actor.actor_id,
        user: p.user,
        bindings: p.bindings,
        roles_catalog: all_roles
            .into_iter()
            .map(|r| RoleCatalogItem {
                role: r,
                description: r.description().to_owned(),
            })
            .collect(),
    })
}

/// `GET /api/v1/auth/oidc/{slug}/start` — Starts Authorization Code + PKCE OIDC sign-in flow.
pub async fn oidc_start(
    State(state): State<AppState>,
    Path(slug): Path<String>,
) -> Result<Response, ApiError> {
    let provider = state.store.get_oidc_provider_by_slug(&slug).await?;
    let discovery_url = format!(
        "{}/.well-known/openid-configuration",
        provider.issuer_url.trim_end_matches('/')
    );
    let uri: Uri = discovery_url.parse().map_err(|e| {
        ApiError(ConsoleError::BadRequest(format!(
            "invalid OIDC issuer URL: {e}"
        )))
    })?;
    let resp = state
        .http_client
        .send(HttpRequest::get(uri))
        .await
        .map_err(|e| {
            ApiError(ConsoleError::BadRequest(format!(
                "OIDC discovery failed: {e}"
            )))
        })?;
    let doc: Value = serde_json::from_slice(&resp.body).map_err(|e| {
        ApiError(ConsoleError::BadRequest(format!(
            "invalid OIDC discovery document: {e}"
        )))
    })?;
    let auth_endpoint = doc
        .get("authorization_endpoint")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            ApiError(ConsoleError::BadRequest(
                "OIDC discovery missing authorization_endpoint".to_owned(),
            ))
        })?;

    let (oidc_state, _, _) = generate_secret_token("st_")?;
    let (pkce_verifier, _, _) = generate_secret_token("pkce_")?;
    let (nonce, _, _) = generate_secret_token("nc_")?;
    let challenge_hash = hex_to_bytes(&sha256_hex(pkce_verifier.as_bytes()));
    let code_challenge = URL_SAFE_NO_PAD.encode(challenge_hash);

    state
        .store
        .store_oidc_auth_state(&provider.id, &oidc_state, &pkce_verifier, &nonce, "/")
        .await?;

    let callback_url = format!(
        "{}/api/v1/auth/oidc/{}/callback",
        state.public_url.trim_end_matches('/'),
        provider.slug
    );
    let authorize_url = format!(
        "{}?response_type=code&client_id={}&redirect_uri={}&scope={}&state={}&nonce={}&code_challenge={}&code_challenge_method=S256",
        auth_endpoint,
        url_encode(&provider.client_id),
        url_encode(&callback_url),
        url_encode(&provider.scopes),
        url_encode(&oidc_state),
        url_encode(&nonce),
        url_encode(&code_challenge),
    );

    Ok(Redirect::temporary(&authorize_url).into_response())
}

#[derive(Debug, Deserialize)]
pub struct OidcCallbackQuery {
    pub code: String,
    pub state: String,
}

/// `GET /api/v1/auth/oidc/{slug}/callback` — Completes PKCE exchange and issues session cookie.
pub async fn oidc_callback(
    State(state): State<AppState>,
    Path(slug): Path<String>,
    Query(q): Query<OidcCallbackQuery>,
) -> Result<Response, ApiError> {
    let provider = state.store.get_oidc_provider_by_slug(&slug).await?;
    let (provider_id, _pkce_verifier, _nonce, _redirect_to) =
        state.store.consume_oidc_auth_state(&q.state).await?;
    if provider_id != provider.id {
        return Err(ApiError(ConsoleError::BadRequest(
            "OIDC state provider mismatch".to_owned(),
        )));
    }
    if q.code.is_empty() {
        return Err(ApiError(ConsoleError::BadRequest(
            "missing OIDC authorization code".to_owned(),
        )));
    }
    Err(ApiError(ConsoleError::BadRequest(
        "OIDC provider token exchange requires reachable external IdP token_endpoint; configure a valid issuer_url and client_secret_ref".to_owned(),
    )))
}

// =============================================================================
// Organizations & Teams
// =============================================================================

#[utoipa::path(
    get,
    path = "/api/v1/orgs",
    responses((status = 200, body = [Organization]))
)]
pub async fn list_orgs(
    State(state): State<AppState>,
    AuthPrincipal(p): AuthPrincipal,
) -> Result<Json<Vec<Organization>>, ApiError> {
    let all = state.store.list_orgs().await?;
    let visible: Vec<Organization> = all
        .into_iter()
        .filter(|o| authorize(&p.bindings, Some(&o.id), None, Permission::OrgRead).is_ok())
        .collect();
    Ok(Json(visible))
}

#[utoipa::path(
    post,
    path = "/api/v1/orgs",
    request_body = CreateOrgInput,
    responses((status = 201, body = Organization))
)]
pub async fn create_org(
    State(state): State<AppState>,
    AuthPrincipal(p): AuthPrincipal,
    Json(input): Json<CreateOrgInput>,
) -> Result<(StatusCode, HeaderMap, Json<Organization>), ApiError> {
    authorize(&p.bindings, None, None, Permission::OrgWrite)?;
    let org = state.store.create_org(input, &p.actor).await?;
    Ok((StatusCode::CREATED, etag_headers(&org.etag), Json(org)))
}

pub async fn list_teams(
    State(state): State<AppState>,
    AuthPrincipal(p): AuthPrincipal,
    Path(org_slug): Path<String>,
) -> Result<Json<Vec<Team>>, ApiError> {
    let org = state.store.get_org_by_slug(&org_slug).await?;
    authorize(&p.bindings, Some(&org.id), None, Permission::OrgRead)?;
    Ok(Json(state.store.list_teams(&org.id).await?))
}

#[derive(Debug, Deserialize)]
pub struct UpsertTeamRequest {
    pub name: String,
}

pub async fn upsert_team(
    State(state): State<AppState>,
    AuthPrincipal(p): AuthPrincipal,
    headers: HeaderMap,
    Path((org_slug, team_slug)): Path<(String, String)>,
    Json(req): Json<UpsertTeamRequest>,
) -> Result<(HeaderMap, Json<Team>), ApiError> {
    let org = state.store.get_org_by_slug(&org_slug).await?;
    authorize(&p.bindings, Some(&org.id), None, Permission::OrgWrite)?;
    let team = state
        .store
        .upsert_team(
            &org.id,
            &team_slug,
            &req.name,
            extract_if_match(&headers).as_deref(),
            &p.actor,
        )
        .await?;
    Ok((etag_headers(&team.etag), Json(team)))
}

// =============================================================================
// Clusters, Nodes & Bootstrap Enrollment Tokens
// =============================================================================

#[utoipa::path(
    get,
    path = "/api/v1/orgs/{org}/clusters",
    params(("org" = String, Path, description = "Organization slug")),
    responses((status = 200, body = [Cluster]))
)]
pub async fn list_org_clusters(
    State(state): State<AppState>,
    AuthPrincipal(p): AuthPrincipal,
    Path(org_slug): Path<String>,
) -> Result<Json<Vec<Cluster>>, ApiError> {
    let org = state.store.get_org_by_slug(&org_slug).await?;
    let clusters = state.store.list_clusters(Some(&org.id)).await?;
    let visible = clusters
        .into_iter()
        .filter(|c| {
            authorize(
                &p.bindings,
                Some(&org.id),
                Some(&c.id),
                Permission::ClusterRead,
            )
            .is_ok()
        })
        .collect();
    Ok(Json(visible))
}

#[utoipa::path(
    post,
    path = "/api/v1/orgs/{org}/clusters",
    params(("org" = String, Path, description = "Organization slug")),
    request_body = CreateClusterInput,
    responses((status = 201, body = Cluster))
)]
pub async fn create_cluster(
    State(state): State<AppState>,
    AuthPrincipal(p): AuthPrincipal,
    Path(org_slug): Path<String>,
    Json(input): Json<CreateClusterInput>,
) -> Result<(StatusCode, HeaderMap, Json<Cluster>), ApiError> {
    let org = state.store.get_org_by_slug(&org_slug).await?;
    authorize(&p.bindings, Some(&org.id), None, Permission::ClusterManage)?;
    let cluster = state.store.create_cluster(&org.id, input, &p.actor).await?;
    Ok((
        StatusCode::CREATED,
        etag_headers(&cluster.etag),
        Json(cluster),
    ))
}

#[utoipa::path(
    get,
    path = "/api/v1/clusters/{cluster}",
    params(("cluster" = String, Path, description = "Cluster slug")),
    responses((status = 200, body = Cluster))
)]
pub async fn get_cluster(
    State(state): State<AppState>,
    AuthPrincipal(p): AuthPrincipal,
    Path(cluster_slug): Path<String>,
) -> Result<(HeaderMap, Json<Cluster>), ApiError> {
    let cluster = state.store.get_cluster_by_slug(&cluster_slug).await?;
    authorize(
        &p.bindings,
        Some(&cluster.org_id),
        Some(&cluster.id),
        Permission::ClusterRead,
    )?;
    Ok((etag_headers(&cluster.etag), Json(cluster)))
}

#[utoipa::path(
    get,
    path = "/api/v1/clusters/{cluster}/nodes",
    params(("cluster" = String, Path, description = "Cluster slug")),
    responses((status = 200, body = [NodeRecord]))
)]
pub async fn list_cluster_nodes(
    State(state): State<AppState>,
    AuthPrincipal(p): AuthPrincipal,
    Path(cluster_slug): Path<String>,
) -> Result<Json<Vec<NodeRecord>>, ApiError> {
    let cluster = state.store.get_cluster_by_slug(&cluster_slug).await?;
    authorize(
        &p.bindings,
        Some(&cluster.org_id),
        Some(&cluster.id),
        Permission::ClusterRead,
    )?;
    Ok(Json(state.store.list_cluster_nodes(&cluster.id).await?))
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct UpdateNodeLabelsRequest {
    pub labels: BTreeMap<String, String>,
}

#[utoipa::path(
    patch,
    path = "/api/v1/clusters/{cluster}/nodes/{node_id}/labels",
    request_body = UpdateNodeLabelsRequest,
    responses((status = 204))
)]
pub async fn update_node_labels(
    State(state): State<AppState>,
    AuthPrincipal(p): AuthPrincipal,
    Path((cluster_slug, node_id)): Path<(String, String)>,
    Json(req): Json<UpdateNodeLabelsRequest>,
) -> Result<StatusCode, ApiError> {
    let cluster = state.store.get_cluster_by_slug(&cluster_slug).await?;
    authorize(
        &p.bindings,
        Some(&cluster.org_id),
        Some(&cluster.id),
        Permission::NodeManage,
    )?;
    state
        .store
        .update_node_labels(&cluster.id, &node_id, req.labels, &p.actor)
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

#[utoipa::path(
    delete,
    path = "/api/v1/clusters/{cluster}/nodes/{node_id}",
    responses((status = 204))
)]
pub async fn delete_node(
    State(state): State<AppState>,
    AuthPrincipal(p): AuthPrincipal,
    Path((cluster_slug, node_id)): Path<(String, String)>,
) -> Result<StatusCode, ApiError> {
    let cluster = state.store.get_cluster_by_slug(&cluster_slug).await?;
    authorize(
        &p.bindings,
        Some(&cluster.org_id),
        Some(&cluster.id),
        Permission::NodeManage,
    )?;
    state
        .store
        .delete_node(&cluster.id, &node_id, &p.actor)
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

#[utoipa::path(
    get,
    path = "/api/v1/clusters/{cluster}/bootstrap-tokens",
    responses((status = 200, body = [BootstrapTokenMeta]))
)]
pub async fn list_bootstrap_tokens(
    State(state): State<AppState>,
    AuthPrincipal(p): AuthPrincipal,
    Path(cluster_slug): Path<String>,
) -> Result<Json<Vec<BootstrapTokenMeta>>, ApiError> {
    let cluster = state.store.get_cluster_by_slug(&cluster_slug).await?;
    authorize(
        &p.bindings,
        Some(&cluster.org_id),
        Some(&cluster.id),
        Permission::NodeManage,
    )?;
    Ok(Json(state.store.list_bootstrap_tokens(&cluster.id).await?))
}

#[utoipa::path(
    post,
    path = "/api/v1/clusters/{cluster}/bootstrap-tokens",
    request_body = CreateBootstrapTokenInput,
    responses((status = 201, body = CreatedBootstrapToken))
)]
pub async fn create_bootstrap_token(
    State(state): State<AppState>,
    AuthPrincipal(p): AuthPrincipal,
    Path(cluster_slug): Path<String>,
    Json(input): Json<CreateBootstrapTokenInput>,
) -> Result<(StatusCode, Json<CreatedBootstrapToken>), ApiError> {
    let cluster = state.store.get_cluster_by_slug(&cluster_slug).await?;
    authorize(
        &p.bindings,
        Some(&cluster.org_id),
        Some(&cluster.id),
        Permission::NodeManage,
    )?;
    let created = state
        .store
        .create_bootstrap_token(&cluster.id, input, &p.actor)
        .await?;
    Ok((StatusCode::CREATED, Json(created)))
}

#[utoipa::path(
    delete,
    path = "/api/v1/clusters/{cluster}/bootstrap-tokens/{id}",
    responses((status = 204))
)]
pub async fn revoke_bootstrap_token(
    State(state): State<AppState>,
    AuthPrincipal(p): AuthPrincipal,
    Path((cluster_slug, token_id)): Path<(String, String)>,
) -> Result<StatusCode, ApiError> {
    let cluster = state.store.get_cluster_by_slug(&cluster_slug).await?;
    authorize(
        &p.bindings,
        Some(&cluster.org_id),
        Some(&cluster.id),
        Permission::NodeManage,
    )?;
    state
        .store
        .revoke_bootstrap_token(&cluster.id, &token_id, &p.actor)
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

// =============================================================================
// Channel 1: Topology Resources, Validation, Publish, Rollback & Export
// =============================================================================

#[derive(Debug, Deserialize)]
pub struct ResourceListQuery {
    #[serde(default)]
    pub kind: Option<String>,
}

#[utoipa::path(
    get,
    path = "/api/v1/clusters/{cluster}/resources",
    responses((status = 200, body = [TopologyResource]))
)]
pub async fn list_topology_resources(
    State(state): State<AppState>,
    AuthPrincipal(p): AuthPrincipal,
    Path(cluster_slug): Path<String>,
    Query(q): Query<ResourceListQuery>,
) -> Result<Json<Vec<TopologyResource>>, ApiError> {
    let cluster = state.store.get_cluster_by_slug(&cluster_slug).await?;
    authorize(
        &p.bindings,
        Some(&cluster.org_id),
        Some(&cluster.id),
        Permission::TopologyRead,
    )?;
    let kind_filter = match q.kind.as_deref() {
        Some(k) => Some(TopologyResourceKind::parse(k).ok_or_else(|| {
            ApiError(ConsoleError::BadRequest(format!(
                "unknown resource kind `{k}`"
            )))
        })?),
        None => None,
    };
    Ok(Json(
        state
            .store
            .list_topology_resources(&cluster.id, kind_filter)
            .await?,
    ))
}

#[derive(Debug, Deserialize)]
pub struct AutoPublishQuery {
    #[serde(default)]
    pub auto_publish: bool,
}

#[utoipa::path(
    put,
    path = "/api/v1/clusters/{cluster}/resources/{kind}/{slug}",
    request_body = UpsertResourceInput,
    responses(
        (status = 200, body = TopologyResource),
        (status = 412, body = ProblemDetails)
    )
)]
pub async fn upsert_topology_resource(
    State(state): State<AppState>,
    AuthPrincipal(p): AuthPrincipal,
    headers: HeaderMap,
    Path((cluster_slug, kind_str, slug)): Path<(String, String, String)>,
    Query(q): Query<AutoPublishQuery>,
    Json(input): Json<UpsertResourceInput>,
) -> Result<(HeaderMap, Json<TopologyResource>), ApiError> {
    let cluster = state.store.get_cluster_by_slug(&cluster_slug).await?;
    authorize(
        &p.bindings,
        Some(&cluster.org_id),
        Some(&cluster.id),
        Permission::TopologyWrite,
    )?;
    let kind = TopologyResourceKind::parse(&kind_str).ok_or_else(|| {
        ApiError(ConsoleError::BadRequest(format!(
            "unknown resource kind `{kind_str}`"
        )))
    })?;
    let res = state
        .store
        .upsert_topology_resource(
            &cluster.id,
            kind,
            &slug,
            input,
            extract_if_match(&headers).as_deref(),
            &p.actor,
        )
        .await?;
    if q.auto_publish {
        authorize(
            &p.bindings,
            Some(&cluster.org_id),
            Some(&cluster.id),
            Permission::TopologyPublish,
        )?;
        let _ = state
            .store
            .publish_revision(
                &cluster.id,
                PublishRevisionInput {
                    ring_selector: "*".to_owned(),
                    notes: format!("Auto-published after updating {kind_str}/{slug}"),
                    strict: false,
                },
                &p.actor,
            )
            .await?;
    }
    Ok((etag_headers(&res.etag), Json(res)))
}

#[utoipa::path(
    delete,
    path = "/api/v1/clusters/{cluster}/resources/{kind}/{slug}",
    responses((status = 204), (status = 412, body = ProblemDetails))
)]
pub async fn delete_topology_resource(
    State(state): State<AppState>,
    AuthPrincipal(p): AuthPrincipal,
    headers: HeaderMap,
    Path((cluster_slug, kind_str, slug)): Path<(String, String, String)>,
) -> Result<StatusCode, ApiError> {
    let cluster = state.store.get_cluster_by_slug(&cluster_slug).await?;
    authorize(
        &p.bindings,
        Some(&cluster.org_id),
        Some(&cluster.id),
        Permission::TopologyWrite,
    )?;
    let kind = TopologyResourceKind::parse(&kind_str).ok_or_else(|| {
        ApiError(ConsoleError::BadRequest(format!(
            "unknown resource kind `{kind_str}`"
        )))
    })?;
    state
        .store
        .delete_topology_resource(
            &cluster.id,
            kind,
            &slug,
            extract_if_match(&headers).as_deref(),
            &p.actor,
        )
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

#[utoipa::path(
    post,
    path = "/api/v1/clusters/{cluster}/validate",
    responses((status = 200, body = ValidateDraftResult))
)]
pub async fn validate_cluster_draft(
    State(state): State<AppState>,
    AuthPrincipal(p): AuthPrincipal,
    Path(cluster_slug): Path<String>,
) -> Result<Json<ValidateDraftResult>, ApiError> {
    let cluster = state.store.get_cluster_by_slug(&cluster_slug).await?;
    authorize(
        &p.bindings,
        Some(&cluster.org_id),
        Some(&cluster.id),
        Permission::TopologyRead,
    )?;
    Ok(Json(state.store.validate_cluster_draft(&cluster.id).await?))
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct ImportTomlRequest {
    pub toml: String,
}

#[utoipa::path(
    post,
    path = "/api/v1/clusters/{cluster}/import-toml",
    request_body = ImportTomlRequest,
    responses((status = 200, body = ValidateDraftResult))
)]
pub async fn import_cluster_toml(
    State(state): State<AppState>,
    AuthPrincipal(p): AuthPrincipal,
    Path(cluster_slug): Path<String>,
    Json(req): Json<ImportTomlRequest>,
) -> Result<Json<ValidateDraftResult>, ApiError> {
    let cluster = state.store.get_cluster_by_slug(&cluster_slug).await?;
    authorize(
        &p.bindings,
        Some(&cluster.org_id),
        Some(&cluster.id),
        Permission::TopologyWrite,
    )?;
    Ok(Json(
        state
            .store
            .import_toml_into_cluster(&cluster.id, &req.toml, &p.actor)
            .await?,
    ))
}

#[utoipa::path(
    get,
    path = "/api/v1/clusters/{cluster}/revisions",
    responses((status = 200, body = [TopologyRevision]))
)]
pub async fn list_revisions(
    State(state): State<AppState>,
    AuthPrincipal(p): AuthPrincipal,
    Path(cluster_slug): Path<String>,
) -> Result<Json<Vec<TopologyRevision>>, ApiError> {
    let cluster = state.store.get_cluster_by_slug(&cluster_slug).await?;
    authorize(
        &p.bindings,
        Some(&cluster.org_id),
        Some(&cluster.id),
        Permission::TopologyRead,
    )?;
    Ok(Json(state.store.list_revisions(&cluster.id).await?))
}

#[utoipa::path(
    get,
    path = "/api/v1/clusters/{cluster}/revisions/{rev}",
    responses((status = 200, body = TopologyRevision))
)]
pub async fn get_revision(
    State(state): State<AppState>,
    AuthPrincipal(p): AuthPrincipal,
    Path((cluster_slug, rev)): Path<(String, u64)>,
) -> Result<Json<TopologyRevision>, ApiError> {
    let cluster = state.store.get_cluster_by_slug(&cluster_slug).await?;
    authorize(
        &p.bindings,
        Some(&cluster.org_id),
        Some(&cluster.id),
        Permission::TopologyRead,
    )?;
    Ok(Json(state.store.get_revision(&cluster.id, rev).await?))
}

#[utoipa::path(
    post,
    path = "/api/v1/clusters/{cluster}/revisions:publish",
    request_body = PublishRevisionInput,
    responses((status = 201, body = TopologyRevision), (status = 422, body = ProblemDetails))
)]
pub async fn publish_revision(
    State(state): State<AppState>,
    AuthPrincipal(p): AuthPrincipal,
    Path(cluster_slug): Path<String>,
    Json(input): Json<PublishRevisionInput>,
) -> Result<(StatusCode, Json<TopologyRevision>), ApiError> {
    let cluster = state.store.get_cluster_by_slug(&cluster_slug).await?;
    authorize(
        &p.bindings,
        Some(&cluster.org_id),
        Some(&cluster.id),
        Permission::TopologyPublish,
    )?;
    let rev = state
        .store
        .publish_revision(&cluster.id, input, &p.actor)
        .await?;
    Ok((StatusCode::CREATED, Json(rev)))
}

#[derive(Debug, Default, Deserialize, ToSchema)]
pub struct RollbackRevisionRequest {
    #[serde(default)]
    pub ring_selector: Option<String>,
}

#[utoipa::path(
    post,
    path = "/api/v1/clusters/{cluster}/revisions/{rev}/rollback",
    request_body = RollbackRevisionRequest,
    responses((status = 200, body = Cluster))
)]
pub async fn rollback_revision(
    State(state): State<AppState>,
    AuthPrincipal(p): AuthPrincipal,
    Path((cluster_slug, rev)): Path<(String, u64)>,
    body: Option<Json<RollbackRevisionRequest>>,
) -> Result<Json<Cluster>, ApiError> {
    let cluster = state.store.get_cluster_by_slug(&cluster_slug).await?;
    authorize(
        &p.bindings,
        Some(&cluster.org_id),
        Some(&cluster.id),
        Permission::TopologyPublish,
    )?;
    let selector = body
        .and_then(|b| b.0.ring_selector)
        .unwrap_or_else(|| "*".to_owned());
    let updated = state
        .store
        .rollback_or_promote_revision(&cluster.id, rev, &selector, "revision.rollback", &p.actor)
        .await?;
    Ok(Json(updated))
}

pub async fn promote_revision(
    State(state): State<AppState>,
    AuthPrincipal(p): AuthPrincipal,
    Path((cluster_slug, rev)): Path<(String, u64)>,
    body: Option<Json<RollbackRevisionRequest>>,
) -> Result<Json<Cluster>, ApiError> {
    let cluster = state.store.get_cluster_by_slug(&cluster_slug).await?;
    authorize(
        &p.bindings,
        Some(&cluster.org_id),
        Some(&cluster.id),
        Permission::TopologyPublish,
    )?;
    let selector = body
        .and_then(|b| b.0.ring_selector)
        .unwrap_or_else(|| "*".to_owned());
    let updated = state
        .store
        .rollback_or_promote_revision(&cluster.id, rev, &selector, "revision.promote", &p.actor)
        .await?;
    Ok(Json(updated))
}

#[utoipa::path(
    get,
    path = "/api/v1/clusters/{cluster}/revisions/{rev}/export.toml",
    responses((status = 200, content_type = "text/plain"))
)]
pub async fn export_revision_toml(
    State(state): State<AppState>,
    AuthPrincipal(p): AuthPrincipal,
    Path((cluster_slug, rev)): Path<(String, u64)>,
) -> Result<Response, ApiError> {
    let cluster = state.store.get_cluster_by_slug(&cluster_slug).await?;
    authorize(
        &p.bindings,
        Some(&cluster.org_id),
        Some(&cluster.id),
        Permission::TopologyRead,
    )?;
    let revision = state.store.get_revision(&cluster.id, rev).await?;
    Ok((
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, "application/toml; charset=utf-8"),
            (
                header::CONTENT_DISPOSITION,
                "attachment; filename=\"shunt.toml\"",
            ),
        ],
        revision.compiled_toml,
    )
        .into_response())
}

// =============================================================================
// Channel 2: Synced State Table Management
// =============================================================================

#[utoipa::path(
    get,
    path = "/api/v1/clusters/{cluster}/state",
    responses((status = 200, body = [NamespaceStateSummary]))
)]
pub async fn list_state_namespaces(
    State(state): State<AppState>,
    AuthPrincipal(p): AuthPrincipal,
    Path(cluster_slug): Path<String>,
) -> Result<Json<Vec<NamespaceStateSummary>>, ApiError> {
    let cluster = state.store.get_cluster_by_slug(&cluster_slug).await?;
    authorize(
        &p.bindings,
        Some(&cluster.org_id),
        Some(&cluster.id),
        Permission::SyncedStateRead,
    )?;
    Ok(Json(
        state.store.list_namespace_summaries(&cluster.id).await?,
    ))
}

#[derive(Debug, Serialize, ToSchema)]
pub struct NamespaceStateResponse {
    pub namespace: String,
    pub head_seq: u64,
    pub items: Vec<ControlStateItem>,
    pub recent_events: Vec<ControlEvent>,
}

#[utoipa::path(
    get,
    path = "/api/v1/clusters/{cluster}/state/{namespace}",
    responses((status = 200, body = NamespaceStateResponse))
)]
pub async fn get_namespace_state(
    State(state): State<AppState>,
    AuthPrincipal(p): AuthPrincipal,
    Path((cluster_slug, namespace)): Path<(String, String)>,
) -> Result<Json<NamespaceStateResponse>, ApiError> {
    let cluster = state.store.get_cluster_by_slug(&cluster_slug).await?;
    authorize(
        &p.bindings,
        Some(&cluster.org_id),
        Some(&cluster.id),
        Permission::SyncedStateRead,
    )?;
    let (head_seq, items, recent_events) = state
        .store
        .list_namespace_items_and_events(&cluster.id, &namespace)
        .await?;
    Ok(Json(NamespaceStateResponse {
        namespace,
        head_seq,
        items,
        recent_events,
    }))
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct UpsertStateItemRequest {
    pub value: Value,
}

#[utoipa::path(
    put,
    path = "/api/v1/clusters/{cluster}/state/{namespace}/{key}",
    request_body = UpsertStateItemRequest,
    responses((status = 200, body = ControlEvent))
)]
pub async fn upsert_state_item(
    State(state): State<AppState>,
    AuthPrincipal(p): AuthPrincipal,
    Path((cluster_slug, namespace, key)): Path<(String, String, String)>,
    Json(req): Json<UpsertStateItemRequest>,
) -> Result<Json<ControlEvent>, ApiError> {
    let cluster = state.store.get_cluster_by_slug(&cluster_slug).await?;
    authorize(
        &p.bindings,
        Some(&cluster.org_id),
        Some(&cluster.id),
        Permission::SyncedStateWrite,
    )?;
    let ev = state
        .store
        .upsert_synced_state(&cluster.id, &namespace, &key, req.value, &p.actor)
        .await?;
    Ok(Json(ev))
}

#[utoipa::path(
    delete,
    path = "/api/v1/clusters/{cluster}/state/{namespace}/{key}",
    responses((status = 200, body = ControlEvent))
)]
pub async fn delete_state_item(
    State(state): State<AppState>,
    AuthPrincipal(p): AuthPrincipal,
    Path((cluster_slug, namespace, key)): Path<(String, String, String)>,
) -> Result<Json<ControlEvent>, ApiError> {
    let cluster = state.store.get_cluster_by_slug(&cluster_slug).await?;
    authorize(
        &p.bindings,
        Some(&cluster.org_id),
        Some(&cluster.id),
        Permission::SyncedStateWrite,
    )?;
    let ev = state
        .store
        .delete_synced_state(&cluster.id, &namespace, &key, &p.actor)
        .await?;
    Ok(Json(ev))
}

// =============================================================================
// Secrets Vault
// =============================================================================

#[utoipa::path(
    get,
    path = "/api/v1/orgs/{org}/secrets",
    responses((status = 200, body = [SecretMeta]))
)]
pub async fn list_secrets(
    State(state): State<AppState>,
    AuthPrincipal(p): AuthPrincipal,
    Path(org_slug): Path<String>,
) -> Result<Json<Vec<SecretMeta>>, ApiError> {
    let org = state.store.get_org_by_slug(&org_slug).await?;
    authorize(&p.bindings, Some(&org.id), None, Permission::SecretsRead)?;
    Ok(Json(state.store.list_secrets(&org.id).await?))
}

#[utoipa::path(
    put,
    path = "/api/v1/orgs/{org}/secrets/{slug}",
    request_body = UpsertSecretInput,
    responses((status = 200, body = SecretMeta), (status = 412, body = ProblemDetails))
)]
pub async fn upsert_secret(
    State(state): State<AppState>,
    AuthPrincipal(p): AuthPrincipal,
    headers: HeaderMap,
    Path((org_slug, slug)): Path<(String, String)>,
    Json(input): Json<UpsertSecretInput>,
) -> Result<(HeaderMap, Json<SecretMeta>), ApiError> {
    let org = state.store.get_org_by_slug(&org_slug).await?;
    authorize(&p.bindings, Some(&org.id), None, Permission::SecretsWrite)?;
    let meta = state
        .store
        .upsert_secret(
            &org.id,
            &slug,
            input,
            extract_if_match(&headers).as_deref(),
            &p.actor,
        )
        .await?;
    Ok((etag_headers(&meta.etag), Json(meta)))
}

#[utoipa::path(
    delete,
    path = "/api/v1/orgs/{org}/secrets/{slug}",
    responses((status = 204))
)]
pub async fn delete_secret(
    State(state): State<AppState>,
    AuthPrincipal(p): AuthPrincipal,
    Path((org_slug, slug)): Path<(String, String)>,
) -> Result<StatusCode, ApiError> {
    let org = state.store.get_org_by_slug(&org_slug).await?;
    authorize(&p.bindings, Some(&org.id), None, Permission::SecretsWrite)?;
    state.store.delete_secret(&org.id, &slug, &p.actor).await?;
    Ok(StatusCode::NO_CONTENT)
}

// =============================================================================
// Users, RBAC, API Tokens & OIDC Providers
// =============================================================================

#[derive(Debug, Serialize, ToSchema)]
pub struct UserWithRoles {
    pub user: UserSummary,
    pub bindings: Vec<RoleBinding>,
}

#[utoipa::path(
    get,
    path = "/api/v1/orgs/{org}/users",
    responses((status = 200, body = [UserWithRoles]))
)]
pub async fn list_org_users(
    State(state): State<AppState>,
    AuthPrincipal(p): AuthPrincipal,
    Path(org_slug): Path<String>,
) -> Result<Json<Vec<UserWithRoles>>, ApiError> {
    let org = state.store.get_org_by_slug(&org_slug).await?;
    authorize(&p.bindings, Some(&org.id), None, Permission::RbacManage)?;
    let users = state.store.list_org_users(&org.id).await?;
    Ok(Json(
        users
            .into_iter()
            .map(|(user, bindings)| UserWithRoles { user, bindings })
            .collect(),
    ))
}

#[utoipa::path(
    post,
    path = "/api/v1/orgs/{org}/users",
    request_body = CreateUserInput,
    responses((status = 201, body = UserWithRoles))
)]
pub async fn create_org_user(
    State(state): State<AppState>,
    AuthPrincipal(p): AuthPrincipal,
    Path(org_slug): Path<String>,
    Json(input): Json<CreateUserInput>,
) -> Result<(StatusCode, Json<UserWithRoles>), ApiError> {
    let org = state.store.get_org_by_slug(&org_slug).await?;
    authorize(&p.bindings, Some(&org.id), None, Permission::RbacManage)?;
    let (user, binding) = state
        .store
        .create_user_in_org(&org.id, input, &p.actor)
        .await?;
    Ok((
        StatusCode::CREATED,
        Json(UserWithRoles {
            user,
            bindings: vec![binding],
        }),
    ))
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct CreateRoleBindingRequest {
    pub user_id: String,
    pub role: Role,
    #[serde(default)]
    pub cluster_id: Option<String>,
}

#[utoipa::path(
    post,
    path = "/api/v1/orgs/{org}/role-bindings",
    request_body = CreateRoleBindingRequest,
    responses((status = 201, body = RoleBinding))
)]
pub async fn create_role_binding(
    State(state): State<AppState>,
    AuthPrincipal(p): AuthPrincipal,
    Path(org_slug): Path<String>,
    Json(req): Json<CreateRoleBindingRequest>,
) -> Result<(StatusCode, Json<RoleBinding>), ApiError> {
    let org = state.store.get_org_by_slug(&org_slug).await?;
    authorize(&p.bindings, Some(&org.id), None, Permission::RbacManage)?;
    let rb = state
        .store
        .create_role_binding(&org.id, &req.user_id, req.role, req.cluster_id, &p.actor)
        .await?;
    Ok((StatusCode::CREATED, Json(rb)))
}

#[utoipa::path(
    delete,
    path = "/api/v1/orgs/{org}/role-bindings/{id}",
    responses((status = 204))
)]
pub async fn delete_role_binding(
    State(state): State<AppState>,
    AuthPrincipal(p): AuthPrincipal,
    Path((org_slug, id)): Path<(String, String)>,
) -> Result<StatusCode, ApiError> {
    let org = state.store.get_org_by_slug(&org_slug).await?;
    authorize(&p.bindings, Some(&org.id), None, Permission::RbacManage)?;
    state
        .store
        .delete_role_binding(&org.id, &id, &p.actor)
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

#[utoipa::path(
    get,
    path = "/api/v1/orgs/{org}/api-tokens",
    responses((status = 200, body = [ApiTokenMeta]))
)]
pub async fn list_api_tokens(
    State(state): State<AppState>,
    AuthPrincipal(p): AuthPrincipal,
    Path(org_slug): Path<String>,
) -> Result<Json<Vec<ApiTokenMeta>>, ApiError> {
    let org = state.store.get_org_by_slug(&org_slug).await?;
    authorize(&p.bindings, Some(&org.id), None, Permission::ApiTokenManage)?;
    Ok(Json(state.store.list_api_tokens(&org.id).await?))
}

#[utoipa::path(
    post,
    path = "/api/v1/orgs/{org}/api-tokens",
    request_body = CreateApiTokenInput,
    responses((status = 201, body = CreatedApiToken))
)]
pub async fn create_api_token(
    State(state): State<AppState>,
    AuthPrincipal(p): AuthPrincipal,
    Path(org_slug): Path<String>,
    Json(input): Json<CreateApiTokenInput>,
) -> Result<(StatusCode, Json<CreatedApiToken>), ApiError> {
    let org = state.store.get_org_by_slug(&org_slug).await?;
    authorize(&p.bindings, Some(&org.id), None, Permission::ApiTokenManage)?;
    let tok = state
        .store
        .create_api_token(&org.id, input, &p.actor)
        .await?;
    Ok((StatusCode::CREATED, Json(tok)))
}

#[utoipa::path(
    delete,
    path = "/api/v1/orgs/{org}/api-tokens/{id}",
    responses((status = 204))
)]
pub async fn revoke_api_token(
    State(state): State<AppState>,
    AuthPrincipal(p): AuthPrincipal,
    Path((org_slug, id)): Path<(String, String)>,
) -> Result<StatusCode, ApiError> {
    let org = state.store.get_org_by_slug(&org_slug).await?;
    authorize(&p.bindings, Some(&org.id), None, Permission::ApiTokenManage)?;
    state.store.revoke_api_token(&org.id, &id, &p.actor).await?;
    Ok(StatusCode::NO_CONTENT)
}

#[utoipa::path(
    get,
    path = "/api/v1/orgs/{org}/oidc-providers",
    responses((status = 200, body = [OidcProviderRecord]))
)]
pub async fn list_oidc_providers(
    State(state): State<AppState>,
    AuthPrincipal(p): AuthPrincipal,
    Path(org_slug): Path<String>,
) -> Result<Json<Vec<OidcProviderRecord>>, ApiError> {
    let org = state.store.get_org_by_slug(&org_slug).await?;
    authorize(&p.bindings, Some(&org.id), None, Permission::RbacManage)?;
    Ok(Json(state.store.list_oidc_providers(&org.id).await?))
}

#[utoipa::path(
    put,
    path = "/api/v1/orgs/{org}/oidc-providers/{slug}",
    request_body = CreateOidcProviderInput,
    responses((status = 200, body = OidcProviderRecord))
)]
pub async fn upsert_oidc_provider(
    State(state): State<AppState>,
    AuthPrincipal(p): AuthPrincipal,
    headers: HeaderMap,
    Path((org_slug, slug)): Path<(String, String)>,
    Json(input): Json<CreateOidcProviderInput>,
) -> Result<(HeaderMap, Json<OidcProviderRecord>), ApiError> {
    let org = state.store.get_org_by_slug(&org_slug).await?;
    authorize(&p.bindings, Some(&org.id), None, Permission::RbacManage)?;
    let rec = state
        .store
        .upsert_oidc_provider(
            &org.id,
            &slug,
            input,
            extract_if_match(&headers).as_deref(),
            &p.actor,
        )
        .await?;
    Ok((etag_headers(&rec.etag), Json(rec)))
}

#[utoipa::path(
    delete,
    path = "/api/v1/orgs/{org}/oidc-providers/{slug}",
    responses((status = 204))
)]
pub async fn delete_oidc_provider(
    State(state): State<AppState>,
    AuthPrincipal(p): AuthPrincipal,
    Path((org_slug, slug)): Path<(String, String)>,
) -> Result<StatusCode, ApiError> {
    let org = state.store.get_org_by_slug(&org_slug).await?;
    authorize(&p.bindings, Some(&org.id), None, Permission::RbacManage)?;
    state
        .store
        .delete_oidc_provider(&org.id, &slug, &p.actor)
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

// =============================================================================
// Tamper-Evident Admin Audit Log
// =============================================================================

#[derive(Debug, Deserialize)]
pub struct AuditListQuery {
    #[serde(default = "default_audit_limit")]
    pub limit: i64,
}

fn default_audit_limit() -> i64 {
    100
}

#[utoipa::path(
    get,
    path = "/api/v1/audit/admin",
    responses((status = 200, body = [AdminAuditEntry]))
)]
pub async fn list_admin_audit(
    State(state): State<AppState>,
    AuthPrincipal(p): AuthPrincipal,
    Query(q): Query<AuditListQuery>,
) -> Result<Json<Vec<AdminAuditEntry>>, ApiError> {
    // Allow any principal with AuditRead on at least one scope.
    let can_read = p
        .bindings
        .iter()
        .any(|b| shunt_console_core::role_allows(b.role, Permission::AuditRead));
    if !can_read {
        return Err(ApiError(ConsoleError::Forbidden(
            "AuditRead permission required".to_owned(),
        )));
    }
    Ok(Json(state.store.list_admin_audit(q.limit).await?))
}

#[utoipa::path(
    get,
    path = "/api/v1/audit/admin:verify",
    responses((status = 200, body = AuditChainVerification))
)]
pub async fn verify_admin_audit(
    State(state): State<AppState>,
    AuthPrincipal(p): AuthPrincipal,
) -> Result<Json<AuditChainVerification>, ApiError> {
    let can_read = p
        .bindings
        .iter()
        .any(|b| shunt_console_core::role_allows(b.role, Permission::AuditRead));
    if !can_read {
        return Err(ApiError(ConsoleError::Forbidden(
            "AuditRead permission required".to_owned(),
        )));
    }
    Ok(Json(state.store.verify_admin_audit_chain().await?))
}

// =============================================================================
// Helpers
// =============================================================================

fn etag_headers(etag: &str) -> HeaderMap {
    let mut map = HeaderMap::new();
    if let Ok(val) = HeaderValue::from_str(etag) {
        map.insert(header::ETAG, val);
    }
    map
}

fn url_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~') {
            out.push(b as char);
        } else {
            use std::fmt::Write as _;
            let _ = write!(out, "%{b:02X}");
        }
    }
    out
}

fn hex_to_bytes(hex: &str) -> Vec<u8> {
    (0..hex.len())
        .step_by(2)
        .filter_map(|i| u8::from_str_radix(&hex[i..i + 2], 16).ok())
        .collect()
}
