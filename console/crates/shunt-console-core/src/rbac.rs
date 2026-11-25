use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::error::ConsoleError;

/// Built-in RBAC roles defined by RFC 0023 §4.6.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum Role {
    SuperAdmin,
    ClusterOperator,
    OrgAdmin,
    TeamLead,
    Developer,
    Auditor,
}

impl Role {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::SuperAdmin => "super_admin",
            Self::ClusterOperator => "cluster_operator",
            Self::OrgAdmin => "org_admin",
            Self::TeamLead => "team_lead",
            Self::Developer => "developer",
            Self::Auditor => "auditor",
        }
    }

    pub fn parse(s: &str) -> Result<Self, ConsoleError> {
        match s {
            "super_admin" | "SuperAdmin" => Ok(Self::SuperAdmin),
            "cluster_operator" | "ClusterOperator" => Ok(Self::ClusterOperator),
            "org_admin" | "OrgAdmin" => Ok(Self::OrgAdmin),
            "team_lead" | "TeamLead" => Ok(Self::TeamLead),
            "developer" | "Developer" => Ok(Self::Developer),
            "auditor" | "Auditor" => Ok(Self::Auditor),
            other => Err(ConsoleError::BadRequest(format!(
                "unknown RBAC role `{other}`"
            ))),
        }
    }

    /// Plain-English description shown in Console RBAC UI.
    pub fn description(&self) -> &'static str {
        match self {
            Self::SuperAdmin => "Full platform, OIDC, and cross-organization administration.",
            Self::ClusterOperator => {
                "Topology edits, revision publish/canary/rollback, node enrollment, and secrets."
            }
            Self::OrgAdmin => "Org/team management, clusters, budgets, policies, and org RBAC.",
            Self::TeamLead => {
                "Team virtual keys, MCP ACLs, approval inbox decisions, and team visibility."
            }
            Self::Developer => {
                "Self-service personal keys, read-only topology/state, and playground access."
            }
            Self::Auditor => {
                "Read-only access to topology revisions, fleet state, and tamper-evident audit logs."
            }
        }
    }
}

/// Scoped permission evaluated against an authenticated actor's role bindings.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Permission {
    OrgRead,
    OrgWrite,
    RbacManage,
    ApiTokenManage,
    ClusterRead,
    ClusterManage,
    NodeManage,
    TopologyRead,
    TopologyWrite,
    TopologyPublish,
    SyncedStateRead,
    SyncedStateWrite,
    SecretsRead,
    SecretsWrite,
    AuditRead,
}

/// A single role assignment attached to a user or API token.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct RoleBinding {
    pub id: String,
    pub user_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub org_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cluster_id: Option<String>,
    pub role: Role,
    pub created_at: String,
}

/// Checks whether a given [`Role`] grants `perm`.
pub fn role_allows(role: Role, perm: Permission) -> bool {
    match role {
        Role::SuperAdmin => true,
        Role::OrgAdmin => matches!(
            perm,
            Permission::OrgRead
                | Permission::OrgWrite
                | Permission::RbacManage
                | Permission::ApiTokenManage
                | Permission::ClusterRead
                | Permission::ClusterManage
                | Permission::NodeManage
                | Permission::TopologyRead
                | Permission::TopologyWrite
                | Permission::TopologyPublish
                | Permission::SyncedStateRead
                | Permission::SyncedStateWrite
                | Permission::SecretsRead
                | Permission::SecretsWrite
                | Permission::AuditRead
        ),
        Role::ClusterOperator => matches!(
            perm,
            Permission::OrgRead
                | Permission::ClusterRead
                | Permission::ClusterManage
                | Permission::NodeManage
                | Permission::TopologyRead
                | Permission::TopologyWrite
                | Permission::TopologyPublish
                | Permission::SyncedStateRead
                | Permission::SyncedStateWrite
                | Permission::SecretsRead
                | Permission::SecretsWrite
                | Permission::AuditRead
        ),
        Role::TeamLead => matches!(
            perm,
            Permission::OrgRead
                | Permission::ClusterRead
                | Permission::TopologyRead
                | Permission::SyncedStateRead
                | Permission::SyncedStateWrite
                | Permission::SecretsRead
        ),
        Role::Developer => matches!(
            perm,
            Permission::OrgRead
                | Permission::ClusterRead
                | Permission::TopologyRead
                | Permission::SyncedStateRead
        ),
        Role::Auditor => matches!(
            perm,
            Permission::OrgRead
                | Permission::ClusterRead
                | Permission::TopologyRead
                | Permission::SyncedStateRead
                | Permission::SecretsRead
                | Permission::AuditRead
        ),
    }
}

/// Evaluates whether any binding in `bindings` authorizes `perm` within `(org_id, cluster_id)`.
pub fn authorize(
    bindings: &[RoleBinding],
    org_id: Option<&str>,
    cluster_id: Option<&str>,
    perm: Permission,
) -> Result<(), ConsoleError> {
    let allowed = bindings.iter().any(|b| {
        if !role_allows(b.role, perm) {
            return false;
        }
        if b.role == Role::SuperAdmin {
            return true;
        }
        let org_ok = match (&b.org_id, org_id) {
            (None, _) => true,
            (Some(bound), Some(req)) => bound == req,
            (Some(_), None) => false,
        };
        let cluster_ok = match (&b.cluster_id, cluster_id) {
            (None, _) => true,
            (Some(bound), Some(req)) => bound == req,
            (Some(_), None) => false,
        };
        org_ok && cluster_ok
    });

    if allowed {
        Ok(())
    } else {
        Err(ConsoleError::Forbidden(format!(
            "missing required permission `{perm:?}` for this scope"
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn binding(role: Role, org_id: Option<&str>, cluster_id: Option<&str>) -> RoleBinding {
        RoleBinding {
            id: "rb_1".to_owned(),
            user_id: "u_1".to_owned(),
            org_id: org_id.map(ToOwned::to_owned),
            cluster_id: cluster_id.map(ToOwned::to_owned),
            role,
            created_at: String::new(),
        }
    }

    #[test]
    fn rbac_enforces_roles_and_scope_boundaries() {
        let dev = vec![binding(Role::Developer, Some("org_a"), None)];
        assert!(authorize(&dev, Some("org_a"), Some("cls_1"), Permission::TopologyRead).is_ok());
        assert!(
            authorize(
                &dev,
                Some("org_a"),
                Some("cls_1"),
                Permission::TopologyPublish
            )
            .is_err()
        );
        assert!(authorize(&dev, Some("org_b"), Some("cls_1"), Permission::TopologyRead).is_err());

        let auditor = vec![binding(Role::Auditor, Some("org_a"), None)];
        assert!(authorize(&auditor, Some("org_a"), None, Permission::AuditRead).is_ok());
        assert!(authorize(&auditor, Some("org_a"), None, Permission::SecretsWrite).is_err());

        let op = vec![binding(Role::ClusterOperator, Some("org_a"), Some("cls_1"))];
        assert!(
            authorize(
                &op,
                Some("org_a"),
                Some("cls_1"),
                Permission::TopologyPublish
            )
            .is_ok()
        );
        assert!(
            authorize(
                &op,
                Some("org_a"),
                Some("cls_2"),
                Permission::TopologyPublish
            )
            .is_err()
        );

        let super_admin = vec![binding(Role::SuperAdmin, None, None)];
        assert!(
            authorize(
                &super_admin,
                Some("org_z"),
                Some("cls_9"),
                Permission::RbacManage
            )
            .is_ok()
        );
    }
}
