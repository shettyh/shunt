use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::error::DiagnosticItem;
use crate::rbac::Role;

/// High-level deployment & initialization status returned by `GET /api/v1/system/status`.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct SystemStatus {
    pub initialized: bool,
    pub version: String,
    pub db_kind: String,
    pub public_key_b64: String,
    pub ephemeral_dev_key: bool,
    pub oidc_providers: Vec<PublicOidcProvider>,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct PublicOidcProvider {
    pub slug: String,
    pub display_name: String,
    pub org_slug: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct Organization {
    pub id: String,
    pub slug: String,
    pub name: String,
    pub etag: String,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct Team {
    pub id: String,
    pub org_id: String,
    pub slug: String,
    pub name: String,
    pub etag: String,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct UserSummary {
    pub id: String,
    pub email: String,
    pub display_name: String,
    pub auth_provider: String,
    pub active: bool,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct ApiTokenMeta {
    pub id: String,
    pub org_id: String,
    pub name: String,
    pub prefix: String,
    pub role: Role,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cluster_id: Option<String>,
    pub created_by: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_used_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub revoked_at: Option<String>,
    pub created_at: String,
}

/// Returned once at API token creation time; plaintext secret is never stored.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct CreatedApiToken {
    pub token: ApiTokenMeta,
    pub plaintext_token: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct OidcProviderRecord {
    pub id: String,
    pub org_id: String,
    pub slug: String,
    pub display_name: String,
    pub issuer_url: String,
    pub client_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_secret_ref: Option<String>,
    pub scopes: String,
    pub group_claim: String,
    pub role_mappings: BTreeMap<String, Role>,
    pub enabled: bool,
    pub etag: String,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct Cluster {
    pub id: String,
    pub org_id: String,
    pub slug: String,
    pub name: String,
    pub description: String,
    pub environment: String,
    /// Map of label selector (e.g. `"ring=canary"`, `"*"`) -> assigned revision number.
    pub ring_assignments: BTreeMap<String, u64>,
    pub etag: String,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct BootstrapTokenMeta {
    pub id: String,
    pub cluster_id: String,
    pub name: String,
    pub prefix: String,
    pub default_labels: BTreeMap<String, String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_uses: Option<i64>,
    pub uses_count: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub revoked_at: Option<String>,
    pub created_by: String,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct CreatedBootstrapToken {
    pub token: BootstrapTokenMeta,
    pub plaintext_token: String,
}

/// Derived fleet convergence status for an enrolled `shunt` node.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum NodeStatus {
    Synced,
    Converging,
    Drifted,
    Lagging,
    Offline,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct NodeRecord {
    pub id: String,
    pub cluster_id: String,
    pub name: String,
    pub shunt_version: String,
    pub labels: BTreeMap<String, String>,
    pub active_revision: u64,
    pub target_revision: Option<u64>,
    pub active_digest: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_reload_error: Option<String>,
    pub synced_seqs: BTreeMap<String, u64>,
    pub status: NodeStatus,
    pub runtime_status: serde_json::Value,
    pub last_heartbeat_at: String,
    pub created_at: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum SecretDeliveryMode {
    Vault,
    EnvRef,
}

impl SecretDeliveryMode {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Vault => "vault",
            Self::EnvRef => "env_ref",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "vault" => Some(Self::Vault),
            "env_ref" => Some(Self::EnvRef),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum SecretScopeType {
    Org,
    Cluster,
}

impl SecretScopeType {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Org => "org",
            Self::Cluster => "cluster",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "org" => Some(Self::Org),
            "cluster" => Some(Self::Cluster),
            _ => None,
        }
    }
}

/// Redacted secret metadata (never exposes plaintext secret values).
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct SecretMeta {
    pub id: String,
    pub org_id: String,
    pub scope_type: SecretScopeType,
    pub scope_id: String,
    pub slug: String,
    pub description: String,
    pub delivery_mode: SecretDeliveryMode,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub env_var_name: Option<String>,
    pub key_version: i64,
    pub metadata: serde_json::Value,
    pub etag: String,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum TopologyResourceKind {
    Server,
    Admin,
    State,
    Telemetry,
    GlobalPlugin,
    Upstream,
    RouteGroup,
    Route,
}

impl TopologyResourceKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Server => "server",
            Self::Admin => "admin",
            Self::State => "state",
            Self::Telemetry => "telemetry",
            Self::GlobalPlugin => "global_plugin",
            Self::Upstream => "upstream",
            Self::RouteGroup => "route_group",
            Self::Route => "route",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "server" | "listeners" | "listener" => Some(Self::Server),
            "admin" => Some(Self::Admin),
            "state" => Some(Self::State),
            "telemetry" => Some(Self::Telemetry),
            "global_plugin" | "global-plugins" | "global_plugins" => Some(Self::GlobalPlugin),
            "upstream" | "upstreams" => Some(Self::Upstream),
            "route_group" | "route-groups" | "route_groups" => Some(Self::RouteGroup),
            "route" | "routes" => Some(Self::Route),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct TopologyResource {
    pub id: String,
    pub cluster_id: String,
    pub kind: TopologyResourceKind,
    pub slug: String,
    pub sort_order: i64,
    pub version: i64,
    pub etag: String,
    pub spec: serde_json::Value,
    pub draft_state: String,
    pub updated_by: String,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct TopologyRevision {
    pub id: String,
    pub cluster_id: String,
    pub revision: u64,
    pub digest: String,
    /// Redacted canonical `shunt.toml` (secrets replaced with `secret:<slug>` or `env:<VAR>`).
    pub compiled_toml: String,
    pub verify_report: serde_json::Value,
    pub signature_b64: String,
    pub ring_assignments: BTreeMap<String, u64>,
    pub notes: String,
    pub published_by: String,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct ValidateDraftResult {
    pub valid: bool,
    pub errors: usize,
    pub warnings: usize,
    pub infos: usize,
    pub digest: String,
    pub compiled_toml: String,
    pub diagnostics: Vec<DiagnosticItem>,
    pub route_count: usize,
    pub upstream_count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct ControlEvent {
    pub seq: u64,
    pub cluster_id: String,
    pub namespace: String,
    pub item_key: String,
    pub op: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payload: Option<serde_json::Value>,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct ControlStateItem {
    pub cluster_id: String,
    pub namespace: String,
    pub item_key: String,
    pub seq: u64,
    pub payload: serde_json::Value,
    pub updated_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct NamespaceStateSummary {
    pub namespace: String,
    pub head_seq: u64,
    pub item_count: usize,
    pub converged_nodes: usize,
    pub total_online_nodes: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct AdminAuditEntry {
    pub seq: u64,
    pub ts: String,
    pub actor_type: String,
    pub actor_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub actor_ip: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub org_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cluster_id: Option<String>,
    pub action: String,
    pub resource_type: String,
    pub resource_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub diff: Option<serde_json::Value>,
    pub prev_hash: String,
    pub entry_hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct AuditChainVerification {
    pub valid: bool,
    pub checked_entries: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub first_tampered_seq: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

/// Actor metadata captured on every authenticated request for RBAC & audit logging.
#[derive(Debug, Clone)]
pub struct AuditActor {
    pub actor_type: String,
    pub actor_id: String,
    pub actor_ip: Option<String>,
}

impl AuditActor {
    pub fn system(id: impl Into<String>) -> Self {
        Self {
            actor_type: "system".to_owned(),
            actor_id: id.into(),
            actor_ip: None,
        }
    }
}

/// Real-time cluster notification broadcast across in-process SSE subscribers (and Postgres NOTIFY).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ClusterBusEvent {
    TopologyChanged {
        cluster_id: String,
        revision: u64,
        digest: String,
    },
    StateDelta {
        cluster_id: String,
        seq: u64,
        namespace: String,
        item_key: String,
        op: String,
        payload: Option<serde_json::Value>,
    },
}
