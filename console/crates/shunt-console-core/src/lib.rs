//! Core domain models, SQLite/PostgreSQL storage, envelope-encrypted Secrets Vault,
//! RBAC, OIDC, hash-chained Admin Audit Log, and `ConsoleCompiler` for `shunt-console`.

pub mod compiler;
pub mod crypto;
pub mod db;
pub mod error;
pub mod models;
pub mod rbac;
pub mod vault;

pub use compiler::{
    CompiledTopology, ConsoleCompiler, resolve_target_revision, selector_matches_labels,
};
pub use crypto::{
    compute_etag, constant_time_eq, generate_secret_token, hash_password, new_id, sha256_hex,
    sha256_prefixed, validate_slug, verify_password,
};
pub use db::{
    AuthenticatedPrincipal, ConsoleStore, ConsoleStoreConfig, CreateApiTokenInput,
    CreateBootstrapTokenInput, CreateClusterInput, CreateOidcProviderInput, CreateOrgInput,
    CreateUserInput, DbKind, InitialBootstrapInput, InitialBootstrapResult, PublishRevisionInput,
    UpsertResourceInput, UpsertSecretInput,
};
pub use error::{ConsoleError, DiagnosticItem};
pub use models::{
    AdminAuditEntry, ApiTokenMeta, AuditActor, AuditChainVerification, BootstrapTokenMeta, Cluster,
    ClusterBusEvent, ControlEvent, ControlStateItem, CreatedApiToken, CreatedBootstrapToken,
    NamespaceStateSummary, NodeRecord, NodeStatus, OidcProviderRecord, Organization,
    PublicOidcProvider, SecretDeliveryMode, SecretMeta, SecretScopeType, SystemStatus, Team,
    TopologyResource, TopologyResourceKind, TopologyRevision, UserSummary, ValidateDraftResult,
};
pub use rbac::{Permission, Role, RoleBinding, authorize, role_allows};
pub use vault::{BundleSigner, EncryptedEnvelope, SecretsVault};
