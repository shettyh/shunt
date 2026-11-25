use std::collections::BTreeMap;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use chrono::{DateTime, Duration as ChronoDuration, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sqlx::postgres::{PgListener, PgPoolOptions};
use sqlx::sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions, SqliteSynchronous};
use sqlx::{PgPool, Row, SqlitePool};
use tokio::sync::broadcast;
use tracing::{debug, info, warn};
use utoipa::ToSchema;

use crate::compiler::{ConsoleCompiler, resolve_target_revision};
use crate::crypto::{
    compute_etag, generate_secret_token, hash_password, new_id, sha256_hex, sha256_prefixed,
    validate_slug, verify_password,
};
use crate::error::ConsoleError;
use crate::models::{
    AdminAuditEntry, ApiTokenMeta, AuditActor, AuditChainVerification, BootstrapTokenMeta, Cluster,
    ClusterBusEvent, ControlEvent, ControlStateItem, CreatedApiToken, CreatedBootstrapToken,
    NamespaceStateSummary, NodeRecord, NodeStatus, OidcProviderRecord, Organization,
    PublicOidcProvider, SecretDeliveryMode, SecretMeta, SecretScopeType, SystemStatus, Team,
    TopologyResource, TopologyResourceKind, TopologyRevision, UserSummary, ValidateDraftResult,
};
use crate::rbac::{Role, RoleBinding};
use crate::vault::{BundleSigner, EncryptedEnvelope, SecretsVault};

const GENESIS_AUDIT_HASH: &str = "0000000000000000000000000000000000000000000000000000000000000000";
const PG_NOTIFY_CHANNEL: &str = "shunt_control_events";
const DEFAULT_HEARTBEAT_INTERVAL_SECS: u64 = 15;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DbKind {
    Sqlite,
    Postgres,
}

impl DbKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Sqlite => "sqlite",
            Self::Postgres => "postgres",
        }
    }
}

#[derive(Clone)]
enum DbPool {
    Sqlite(SqlitePool),
    Postgres(PgPool),
}

macro_rules! on_db {
    ($pool:expr, |$p:ident| $body:expr) => {
        match $pool {
            DbPool::Sqlite($p) => $body,
            DbPool::Postgres($p) => $body,
        }
    };
}

/// Configuration for initializing [`ConsoleStore`].
#[derive(Debug, Clone)]
pub struct ConsoleStoreConfig {
    pub database_url: String,
    pub master_key_encoded: Option<String>,
}

/// Authenticated user or service API token principal attached to request context.
#[derive(Debug, Clone)]
pub struct AuthenticatedPrincipal {
    pub actor: AuditActor,
    pub user: Option<UserSummary>,
    pub bindings: Vec<RoleBinding>,
}

#[derive(Debug, Clone, Deserialize, ToSchema)]
pub struct InitialBootstrapInput {
    pub admin_email: String,
    pub admin_name: String,
    pub admin_password: String,
    pub org_slug: String,
    pub org_name: String,
    pub cluster_slug: String,
    pub cluster_name: String,
    #[serde(default = "default_env_prod")]
    pub environment: String,
    /// Optional existing `shunt.toml` to import into the initial cluster draft.
    /// When omitted, seeds the clean default unified gateway skeleton.
    #[serde(default)]
    pub import_toml: Option<String>,
    #[serde(default = "default_true")]
    pub auto_publish: bool,
}

fn default_env_prod() -> String {
    "production".to_owned()
}
fn default_true() -> bool {
    true
}

#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct InitialBootstrapResult {
    pub user: UserSummary,
    pub organization: Organization,
    pub cluster: Cluster,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub initial_revision: Option<TopologyRevision>,
    pub bootstrap_token: CreatedBootstrapToken,
    pub session_token: String,
}

#[derive(Debug, Clone, Deserialize, ToSchema)]
pub struct CreateOrgInput {
    pub slug: String,
    pub name: String,
}

#[derive(Debug, Clone, Deserialize, ToSchema)]
pub struct CreateClusterInput {
    pub slug: String,
    pub name: String,
    #[serde(default)]
    pub description: String,
    #[serde(default = "default_env_prod")]
    pub environment: String,
    /// Optional `shunt.toml` to import into the cluster's initial draft.
    /// When omitted, seeds the clean default unified gateway skeleton.
    #[serde(default)]
    pub import_toml: Option<String>,
}

#[derive(Debug, Clone, Deserialize, ToSchema)]
pub struct CreateBootstrapTokenInput {
    pub name: String,
    #[serde(default)]
    pub default_labels: BTreeMap<String, String>,
    #[serde(default)]
    pub max_uses: Option<i64>,
    #[serde(default)]
    pub expires_in_hours: Option<i64>,
}

#[derive(Debug, Clone, Deserialize, ToSchema)]
pub struct UpsertResourceInput {
    pub spec: Value,
    #[serde(default)]
    pub sort_order: Option<i64>,
}

#[derive(Debug, Clone, Deserialize, ToSchema)]
pub struct PublishRevisionInput {
    #[serde(default = "default_wildcard_ring")]
    pub ring_selector: String,
    #[serde(default)]
    pub notes: String,
    #[serde(default)]
    pub strict: bool,
}

fn default_wildcard_ring() -> String {
    "*".to_owned()
}

#[derive(Debug, Clone, Deserialize, ToSchema)]
pub struct UpsertSecretInput {
    #[serde(default)]
    pub description: String,
    pub scope_type: SecretScopeType,
    pub scope_id: String,
    pub delivery_mode: SecretDeliveryMode,
    /// Plaintext secret value (write-only; required for `vault` mode on create or rotation).
    #[serde(default)]
    pub value: Option<String>,
    /// Environment variable name on data-plane nodes (required for `env_ref` mode).
    #[serde(default)]
    pub env_var_name: Option<String>,
    #[serde(default)]
    pub metadata: Option<Value>,
}

#[derive(Debug, Clone, Deserialize, ToSchema)]
pub struct CreateUserInput {
    pub email: String,
    pub display_name: String,
    pub password: String,
    pub role: Role,
    #[serde(default)]
    pub cluster_id: Option<String>,
}

#[derive(Debug, Clone, Deserialize, ToSchema)]
pub struct CreateApiTokenInput {
    pub name: String,
    pub role: Role,
    #[serde(default)]
    pub cluster_id: Option<String>,
    #[serde(default)]
    pub expires_in_days: Option<i64>,
}

#[derive(Debug, Clone, Deserialize, ToSchema)]
pub struct CreateOidcProviderInput {
    pub display_name: String,
    pub issuer_url: String,
    pub client_id: String,
    #[serde(default)]
    pub client_secret_ref: Option<String>,
    #[serde(default = "default_oidc_scopes")]
    pub scopes: String,
    #[serde(default = "default_group_claim")]
    pub group_claim: String,
    #[serde(default)]
    pub role_mappings: BTreeMap<String, Role>,
    #[serde(default = "default_true")]
    pub enabled: bool,
}

fn default_oidc_scopes() -> String {
    "openid email profile".to_owned()
}
fn default_group_claim() -> String {
    "groups".to_owned()
}

/// Primary control-plane persistence & event-fanout engine supporting SQLite and PostgreSQL.
pub struct ConsoleStore {
    pool: DbPool,
    db_kind: DbKind,
    vault: Arc<SecretsVault>,
    signer: Arc<BundleSigner>,
    bus: broadcast::Sender<ClusterBusEvent>,
    _pg_listener_task: Option<tokio::task::JoinHandle<()>>,
}

impl ConsoleStore {
    /// Connects to SQLite (`sqlite://...`) or PostgreSQL (`postgres://...`), runs migrations,
    /// initializes envelope-encryption [`SecretsVault`] and Ed25519 [`BundleSigner`], and starts
    /// the PostgreSQL `LISTEN/NOTIFY` bridge when running on Postgres.
    pub async fn connect(cfg: ConsoleStoreConfig) -> Result<Self, ConsoleError> {
        let url = cfg.database_url.trim();
        let (pool, db_kind) = if url.starts_with("postgres://") || url.starts_with("postgresql://")
        {
            let pg = PgPoolOptions::new()
                .max_connections(16)
                .acquire_timeout(Duration::from_secs(10))
                .connect(url)
                .await?;
            sqlx::migrate!("./migrations/postgres")
                .run(&pg)
                .await
                .map_err(|e| ConsoleError::Database(format!("postgres migration failed: {e}")))?;
            (DbPool::Postgres(pg), DbKind::Postgres)
        } else {
            let sqlite_url = if url.starts_with("sqlite:") {
                url.to_owned()
            } else {
                format!("sqlite://{url}")
            };
            let opts = SqliteConnectOptions::from_str(&sqlite_url)?
                .create_if_missing(true)
                .journal_mode(SqliteJournalMode::Wal)
                .synchronous(SqliteSynchronous::Normal)
                .foreign_keys(true)
                .busy_timeout(Duration::from_secs(5));
            let max_conns = if sqlite_url.contains(":memory:") {
                1
            } else {
                8
            };
            let sq = SqlitePoolOptions::new()
                .max_connections(max_conns)
                .connect_with(opts)
                .await?;
            sqlx::migrate!("./migrations/sqlite")
                .run(&sq)
                .await
                .map_err(|e| ConsoleError::Database(format!("sqlite migration failed: {e}")))?;
            (DbPool::Sqlite(sq), DbKind::Sqlite)
        };

        // Initialize or load Master KEK for SecretsVault.
        let vault = match cfg.master_key_encoded.as_deref() {
            Some(raw) if !raw.trim().is_empty() => Arc::new(SecretsVault::from_encoded_key(raw)?),
            _ => {
                let existing = get_metadata(&pool, "dev_master_key_b64").await?;
                let key = match existing {
                    Some(b64) => crate::vault::parse_key_32(&b64)?,
                    None => {
                        let (k, b64) = SecretsVault::generate_dev_key()?;
                        set_metadata(&pool, "dev_master_key_b64", &b64).await?;
                        k
                    }
                };
                Arc::new(SecretsVault::new(key, true))
            }
        };

        // Initialize or load Ed25519 BundleSigner (stored encrypted via SecretsVault).
        let signer = match get_metadata(&pool, "bundle_signer_pkcs8_env").await? {
            Some(raw) => {
                let env: EncryptedEnvelopeSer = serde_json::from_str(&raw)
                    .map_err(|e| ConsoleError::Vault(format!("corrupt signer metadata: {e}")))?;
                let plain = vault.decrypt(&env.into(), "console_metadata|bundle_signer")?;
                let b64 = String::from_utf8(plain)
                    .map_err(|e| ConsoleError::Vault(format!("invalid signer UTF-8: {e}")))?;
                Arc::new(BundleSigner::from_pkcs8_b64(&b64)?)
            }
            None => {
                let (signer, pkcs8_b64) = BundleSigner::generate()?;
                let env = vault.encrypt(pkcs8_b64.as_bytes(), "console_metadata|bundle_signer")?;
                let serialized = serde_json::to_string(&EncryptedEnvelopeSer::from(env))
                    .map_err(|e| ConsoleError::Internal(e.to_string()))?;
                set_metadata(&pool, "bundle_signer_pkcs8_env", &serialized).await?;
                Arc::new(signer)
            }
        };

        let (bus, _) = broadcast::channel::<ClusterBusEvent>(1024);

        let pg_listener_task = if let DbPool::Postgres(ref pg) = pool {
            let pg_clone = pg.clone();
            let bus_clone = bus.clone();
            Some(tokio::spawn(async move {
                run_pg_notify_bridge(pg_clone, bus_clone).await;
            }))
        } else {
            None
        };

        info!(
            db_kind = db_kind.as_str(),
            ephemeral_dev_key = vault.is_ephemeral_dev_key(),
            "shunt-console store initialized"
        );

        Ok(Self {
            pool,
            db_kind,
            vault,
            signer,
            bus,
            _pg_listener_task: pg_listener_task,
        })
    }

    pub fn db_kind(&self) -> DbKind {
        self.db_kind
    }

    pub fn vault(&self) -> &SecretsVault {
        &self.vault
    }

    pub fn signer(&self) -> &BundleSigner {
        &self.signer
    }

    pub fn subscribe_events(&self) -> broadcast::Receiver<ClusterBusEvent> {
        self.bus.subscribe()
    }

    async fn emit_event(&self, event: ClusterBusEvent) {
        let _ = self.bus.send(event.clone());
        if let DbPool::Postgres(ref pg) = self.pool
            && let Ok(payload) = serde_json::to_string(&event)
        {
            let _ = sqlx::query("SELECT pg_notify($1, $2)")
                .bind(PG_NOTIFY_CHANNEL)
                .bind(payload)
                .execute(pg)
                .await;
        }
    }

    // =========================================================================
    // System Status & First-Run Bootstrap
    // =========================================================================

    pub async fn system_status(&self) -> Result<SystemStatus, ConsoleError> {
        let user_count: i64 = on_db!(&self.pool, |p| {
            sqlx::query_scalar("SELECT COUNT(*) FROM users")
                .fetch_one(p)
                .await?
        });
        let oidc_providers = self.list_public_oidc_providers().await?;

        Ok(SystemStatus {
            initialized: user_count > 0,
            version: env!("CARGO_PKG_VERSION").to_owned(),
            db_kind: self.db_kind.as_str().to_owned(),
            public_key_b64: self.signer.public_key_b64().to_owned(),
            ephemeral_dev_key: self.vault.is_ephemeral_dev_key(),
            oidc_providers,
        })
    }

    pub async fn initial_bootstrap(
        &self,
        input: InitialBootstrapInput,
    ) -> Result<InitialBootstrapResult, ConsoleError> {
        let user_count: i64 = on_db!(&self.pool, |p| {
            sqlx::query_scalar("SELECT COUNT(*) FROM users")
                .fetch_one(p)
                .await?
        });
        if user_count > 0 {
            return Err(ConsoleError::Conflict(
                "shunt-console is already initialized".to_owned(),
            ));
        }

        validate_slug(&input.org_slug, "org_slug")?;
        validate_slug(&input.cluster_slug, "cluster_slug")?;
        let email = input.admin_email.trim().to_lowercase();
        if !email.contains('@') || email.len() < 5 {
            return Err(ConsoleError::BadRequest(
                "please provide a valid admin email address".to_owned(),
            ));
        }

        let pw_hash = hash_password(&input.admin_password)?;
        let now = now_rfc3339();
        let user_id = new_id("usr");
        let org_id = new_id("org");
        let org_etag = compute_etag(format!("{org_id}:{}:{now}", input.org_name).as_bytes());
        let rb_id = new_id("rb");

        on_db!(&self.pool, |p| {
            sqlx::query(
                "INSERT INTO users (id, email, display_name, password_hash, auth_provider, active, created_at, updated_at)
                 VALUES ($1, $2, $3, $4, 'local', 1, $5, $5)",
            )
            .bind(&user_id)
            .bind(&email)
            .bind(input.admin_name.trim())
            .bind(&pw_hash)
            .bind(&now)
            .execute(p)
            .await?;

            sqlx::query(
                "INSERT INTO organizations (id, slug, name, etag, created_at, updated_at)
                 VALUES ($1, $2, $3, $4, $5, $5)",
            )
            .bind(&org_id)
            .bind(&input.org_slug)
            .bind(input.org_name.trim())
            .bind(&org_etag)
            .bind(&now)
            .execute(p)
            .await?;

            sqlx::query(
                "INSERT INTO role_bindings (id, user_id, org_id, cluster_id, role, created_at)
                 VALUES ($1, $2, NULL, NULL, $3, $4)",
            )
            .bind(&rb_id)
            .bind(&user_id)
            .bind(Role::SuperAdmin.as_str())
            .bind(&now)
            .execute(p)
            .await?;
        });

        let actor = AuditActor {
            actor_type: "user".to_owned(),
            actor_id: email.clone(),
            actor_ip: None,
        };
        self.append_audit(
            &actor,
            Some(&org_id),
            None,
            "system.bootstrap",
            "organization",
            &input.org_slug,
            Some(serde_json::json!({ "admin_email": email, "cluster": input.cluster_slug })),
        )
        .await?;

        let cluster = self
            .create_cluster(
                &org_id,
                CreateClusterInput {
                    slug: input.cluster_slug.clone(),
                    name: input.cluster_name.clone(),
                    description: "Initial cluster created during setup".to_owned(),
                    environment: input.environment.clone(),
                    import_toml: input.import_toml.clone(),
                },
                &actor,
            )
            .await?;

        let initial_revision = if input.auto_publish {
            Some(
                self.publish_revision(
                    &cluster.id,
                    PublishRevisionInput {
                        ring_selector: "*".to_owned(),
                        notes: "Initial revision from setup".to_owned(),
                        strict: false,
                    },
                    &actor,
                )
                .await?,
            )
        } else {
            None
        };

        let bootstrap_token = self
            .create_bootstrap_token(
                &cluster.id,
                CreateBootstrapTokenInput {
                    name: "initial-node-enrollment".to_owned(),
                    default_labels: BTreeMap::from([("ring".to_owned(), "stable".to_owned())]),
                    max_uses: None,
                    expires_in_hours: Some(24 * 30),
                },
                &actor,
            )
            .await?;

        let session_token = self.create_session(&user_id).await?;
        let user = UserSummary {
            id: user_id,
            email,
            display_name: input.admin_name.trim().to_owned(),
            auth_provider: "local".to_owned(),
            active: true,
            created_at: now.clone(),
        };
        let organization = Organization {
            id: org_id,
            slug: input.org_slug,
            name: input.org_name.trim().to_owned(),
            etag: org_etag,
            created_at: now.clone(),
            updated_at: now,
        };
        let cluster = self.get_cluster_by_id(&cluster.id).await?;

        Ok(InitialBootstrapResult {
            user,
            organization,
            cluster,
            initial_revision,
            bootstrap_token,
            session_token,
        })
    }

    // =========================================================================
    // Authentication, Sessions, Users, RBAC, API Tokens & OIDC
    // =========================================================================

    pub async fn authenticate_local(
        &self,
        email: &str,
        password: &str,
    ) -> Result<(UserSummary, String), ConsoleError> {
        let email_norm = email.trim().to_lowercase();
        let rec: Option<(UserSummary, Option<String>)> = on_db!(&self.pool, |p| {
            let row = sqlx::query(
                "SELECT id, email, display_name, password_hash, auth_provider, active, created_at
                 FROM users WHERE email = $1",
            )
            .bind(&email_norm)
            .fetch_optional(p)
            .await?;
            row.map(|r| {
                let u = UserSummary {
                    id: r.get("id"),
                    email: r.get("email"),
                    display_name: r.get("display_name"),
                    auth_provider: r.get("auth_provider"),
                    active: r.get::<i64, _>("active") != 0,
                    created_at: r.get("created_at"),
                };
                let pw: Option<String> = r.get("password_hash");
                (u, pw)
            })
        });

        let Some((user, pw_hash)) = rec else {
            return Err(ConsoleError::Unauthorized(
                "invalid email or password".to_owned(),
            ));
        };
        if !user.active {
            return Err(ConsoleError::Unauthorized("account is disabled".to_owned()));
        }
        let Some(hash) = pw_hash else {
            return Err(ConsoleError::Unauthorized(
                "this account uses SSO/OIDC sign-in".to_owned(),
            ));
        };
        if !verify_password(password, &hash) {
            return Err(ConsoleError::Unauthorized(
                "invalid email or password".to_owned(),
            ));
        }

        let session_token = self.create_session(&user.id).await?;
        Ok((user, session_token))
    }

    pub async fn create_session(&self, user_id: &str) -> Result<String, ConsoleError> {
        let (plaintext, hash, _) = generate_secret_token("shunt_sess_")?;
        let id = new_id("sess");
        let now = Utc::now();
        let expires = (now + ChronoDuration::days(7)).to_rfc3339();
        let now_str = now.to_rfc3339();

        on_db!(&self.pool, |p| {
            sqlx::query(
                "INSERT INTO sessions (id, token_hash, user_id, expires_at, created_at)
                 VALUES ($1, $2, $3, $4, $5)",
            )
            .bind(&id)
            .bind(&hash)
            .bind(user_id)
            .bind(&expires)
            .bind(&now_str)
            .execute(p)
            .await?;
        });
        Ok(plaintext)
    }

    pub async fn revoke_session(&self, token: &str) -> Result<(), ConsoleError> {
        let hash = sha256_prefixed(token.as_bytes());
        on_db!(&self.pool, |p| {
            sqlx::query("DELETE FROM sessions WHERE token_hash = $1")
                .bind(&hash)
                .execute(p)
                .await?;
        });
        Ok(())
    }

    pub async fn authenticate_token(
        &self,
        token: &str,
        actor_ip: Option<String>,
    ) -> Result<AuthenticatedPrincipal, ConsoleError> {
        let hash = sha256_prefixed(token.as_bytes());
        let now = Utc::now();

        if token.starts_with("shunt_ct_") {
            #[allow(clippy::type_complexity)]
            let rec: Option<(
                String,
                String,
                String,
                String,
                Option<String>,
                Option<String>,
                Option<String>,
                String,
            )> = on_db!(&self.pool, |p| {
                let row = sqlx::query(
                    "SELECT id, org_id, name, role, cluster_id, expires_at, revoked_at, created_at
                     FROM api_tokens WHERE token_hash = $1",
                )
                .bind(&hash)
                .fetch_optional(p)
                .await?;
                row.map(|r| {
                    (
                        r.get("id"),
                        r.get("org_id"),
                        r.get("name"),
                        r.get("role"),
                        r.get("cluster_id"),
                        r.get("expires_at"),
                        r.get("revoked_at"),
                        r.get("created_at"),
                    )
                })
            });
            let Some((
                tok_id,
                org_id,
                name,
                role_s,
                cluster_id,
                expires_at,
                revoked_at,
                created_at,
            )) = rec
            else {
                return Err(ConsoleError::Unauthorized("invalid API token".to_owned()));
            };
            if revoked_at.is_some() {
                return Err(ConsoleError::Unauthorized(
                    "API token was revoked".to_owned(),
                ));
            }
            if let Some(exp) = expires_at
                && let Ok(dt) = DateTime::parse_from_rfc3339(&exp)
                && dt < now
            {
                return Err(ConsoleError::Unauthorized("API token expired".to_owned()));
            }
            let role = Role::parse(&role_s)?;
            let now_str = now.to_rfc3339();
            on_db!(&self.pool, |p| {
                let _ = sqlx::query("UPDATE api_tokens SET last_used_at = $1 WHERE id = $2")
                    .bind(&now_str)
                    .bind(&tok_id)
                    .execute(p)
                    .await;
            });
            return Ok(AuthenticatedPrincipal {
                actor: AuditActor {
                    actor_type: "api_token".to_owned(),
                    actor_id: format!("token:{name}"),
                    actor_ip,
                },
                user: None,
                bindings: vec![RoleBinding {
                    id: tok_id.clone(),
                    user_id: tok_id,
                    org_id: Some(org_id),
                    cluster_id,
                    role,
                    created_at,
                }],
            });
        }

        let rec: Option<(String, UserSummary)> = on_db!(&self.pool, |p| {
            let row = sqlx::query(
                "SELECT s.expires_at, u.id, u.email, u.display_name, u.auth_provider, u.active, u.created_at
                 FROM sessions s JOIN users u ON s.user_id = u.id
                 WHERE s.token_hash = $1",
            )
            .bind(&hash)
            .fetch_optional(p)
            .await?;
            row.map(|r| {
                (
                    r.get::<String, _>("expires_at"),
                    UserSummary {
                        id: r.get("id"),
                        email: r.get("email"),
                        display_name: r.get("display_name"),
                        auth_provider: r.get("auth_provider"),
                        active: r.get::<i64, _>("active") != 0,
                        created_at: r.get("created_at"),
                    },
                )
            })
        });
        let Some((exp, user)) = rec else {
            return Err(ConsoleError::Unauthorized(
                "invalid or expired session".to_owned(),
            ));
        };
        if let Ok(dt) = DateTime::parse_from_rfc3339(&exp)
            && dt < now
        {
            return Err(ConsoleError::Unauthorized("session expired".to_owned()));
        }
        if !user.active {
            return Err(ConsoleError::Unauthorized("user disabled".to_owned()));
        }
        let bindings = self.list_user_role_bindings(&user.id).await?;
        Ok(AuthenticatedPrincipal {
            actor: AuditActor {
                actor_type: "user".to_owned(),
                actor_id: user.email.clone(),
                actor_ip,
            },
            user: Some(user),
            bindings,
        })
    }

    pub async fn list_user_role_bindings(
        &self,
        user_id: &str,
    ) -> Result<Vec<RoleBinding>, ConsoleError> {
        #[allow(clippy::type_complexity)]
        let raw: Vec<(
            String,
            String,
            Option<String>,
            Option<String>,
            String,
            String,
        )> = on_db!(&self.pool, |p| {
            let rows = sqlx::query(
                "SELECT id, user_id, org_id, cluster_id, role, created_at
                     FROM role_bindings WHERE user_id = $1 ORDER BY created_at ASC",
            )
            .bind(user_id)
            .fetch_all(p)
            .await?;
            rows.into_iter()
                .map(|r| {
                    (
                        r.get("id"),
                        r.get("user_id"),
                        r.get("org_id"),
                        r.get("cluster_id"),
                        r.get("role"),
                        r.get("created_at"),
                    )
                })
                .collect()
        });
        let mut out = Vec::with_capacity(raw.len());
        for (id, uid, org_id, cluster_id, role_s, created_at) in raw {
            out.push(RoleBinding {
                id,
                user_id: uid,
                org_id,
                cluster_id,
                role: Role::parse(&role_s)?,
                created_at,
            });
        }
        Ok(out)
    }

    pub async fn list_org_users(
        &self,
        org_id: &str,
    ) -> Result<Vec<(UserSummary, Vec<RoleBinding>)>, ConsoleError> {
        let users: Vec<UserSummary> = on_db!(&self.pool, |p| {
            let rows = sqlx::query(
                "SELECT DISTINCT u.id, u.email, u.display_name, u.auth_provider, u.active, u.created_at
                 FROM users u
                 LEFT JOIN role_bindings rb ON rb.user_id = u.id
                 WHERE rb.org_id = $1 OR rb.org_id IS NULL
                 ORDER BY u.created_at ASC",
            )
            .bind(org_id)
            .fetch_all(p)
            .await?;
            rows.into_iter()
                .map(|r| UserSummary {
                    id: r.get("id"),
                    email: r.get("email"),
                    display_name: r.get("display_name"),
                    auth_provider: r.get("auth_provider"),
                    active: r.get::<i64, _>("active") != 0,
                    created_at: r.get("created_at"),
                })
                .collect()
        });
        let mut out = Vec::with_capacity(users.len());
        for u in users {
            let bindings = self.list_user_role_bindings(&u.id).await?;
            out.push((u, bindings));
        }
        Ok(out)
    }

    pub async fn create_user_in_org(
        &self,
        org_id: &str,
        input: CreateUserInput,
        actor: &AuditActor,
    ) -> Result<(UserSummary, RoleBinding), ConsoleError> {
        let email = input.email.trim().to_lowercase();
        if !email.contains('@') {
            return Err(ConsoleError::BadRequest("invalid email address".to_owned()));
        }
        let pw_hash = hash_password(&input.password)?;
        let now = now_rfc3339();
        let user_id = new_id("usr");
        let rb_id = new_id("rb");
        let bound_org = if input.role == Role::SuperAdmin {
            None
        } else {
            Some(org_id.to_owned())
        };

        on_db!(&self.pool, |p| {
            sqlx::query(
                "INSERT INTO users (id, email, display_name, password_hash, auth_provider, active, created_at, updated_at)
                 VALUES ($1, $2, $3, $4, 'local', 1, $5, $5)",
            )
            .bind(&user_id)
            .bind(&email)
            .bind(input.display_name.trim())
            .bind(&pw_hash)
            .bind(&now)
            .execute(p)
            .await?;

            sqlx::query(
                "INSERT INTO role_bindings (id, user_id, org_id, cluster_id, role, created_at)
                 VALUES ($1, $2, $3, $4, $5, $6)",
            )
            .bind(&rb_id)
            .bind(&user_id)
            .bind(&bound_org)
            .bind(&input.cluster_id)
            .bind(input.role.as_str())
            .bind(&now)
            .execute(p)
            .await?;
        });

        self.append_audit(
            actor,
            Some(org_id),
            input.cluster_id.as_deref(),
            "user.create",
            "user",
            &email,
            Some(serde_json::json!({ "role": input.role.as_str() })),
        )
        .await?;

        Ok((
            UserSummary {
                id: user_id.clone(),
                email,
                display_name: input.display_name.trim().to_owned(),
                auth_provider: "local".to_owned(),
                active: true,
                created_at: now.clone(),
            },
            RoleBinding {
                id: rb_id,
                user_id,
                org_id: bound_org,
                cluster_id: input.cluster_id,
                role: input.role,
                created_at: now,
            },
        ))
    }

    pub async fn create_role_binding(
        &self,
        org_id: &str,
        user_id: &str,
        role: Role,
        cluster_id: Option<String>,
        actor: &AuditActor,
    ) -> Result<RoleBinding, ConsoleError> {
        let id = new_id("rb");
        let now = now_rfc3339();
        let bound_org = if role == Role::SuperAdmin {
            None
        } else {
            Some(org_id.to_owned())
        };
        on_db!(&self.pool, |p| {
            sqlx::query(
                "INSERT INTO role_bindings (id, user_id, org_id, cluster_id, role, created_at)
                 VALUES ($1, $2, $3, $4, $5, $6)",
            )
            .bind(&id)
            .bind(user_id)
            .bind(&bound_org)
            .bind(&cluster_id)
            .bind(role.as_str())
            .bind(&now)
            .execute(p)
            .await?;
        });
        self.append_audit(
            actor,
            Some(org_id),
            cluster_id.as_deref(),
            "rbac.binding.create",
            "role_binding",
            &id,
            Some(serde_json::json!({ "user_id": user_id, "role": role.as_str() })),
        )
        .await?;
        Ok(RoleBinding {
            id,
            user_id: user_id.to_owned(),
            org_id: bound_org,
            cluster_id,
            role,
            created_at: now,
        })
    }

    pub async fn delete_role_binding(
        &self,
        org_id: &str,
        binding_id: &str,
        actor: &AuditActor,
    ) -> Result<(), ConsoleError> {
        let affected = on_db!(&self.pool, |p| {
            sqlx::query("DELETE FROM role_bindings WHERE id = $1")
                .bind(binding_id)
                .execute(p)
                .await?
                .rows_affected()
        });
        if affected == 0 {
            return Err(ConsoleError::NotFound(format!(
                "role binding `{binding_id}` not found"
            )));
        }
        self.append_audit(
            actor,
            Some(org_id),
            None,
            "rbac.binding.delete",
            "role_binding",
            binding_id,
            None,
        )
        .await?;
        Ok(())
    }

    pub async fn create_api_token(
        &self,
        org_id: &str,
        input: CreateApiTokenInput,
        actor: &AuditActor,
    ) -> Result<CreatedApiToken, ConsoleError> {
        let name = input.name.trim();
        if name.is_empty() {
            return Err(ConsoleError::BadRequest(
                "token name is required".to_owned(),
            ));
        }
        let (plaintext, hash, prefix) = generate_secret_token("shunt_ct_")?;
        let id = new_id("tok");
        let now = Utc::now();
        let now_str = now.to_rfc3339();
        let expires_at = input
            .expires_in_days
            .filter(|d| *d > 0)
            .map(|d| (now + ChronoDuration::days(d)).to_rfc3339());

        on_db!(&self.pool, |p| {
            sqlx::query(
                "INSERT INTO api_tokens (id, org_id, name, token_hash, prefix, role, cluster_id, created_by, expires_at, created_at)
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)",
            )
            .bind(&id)
            .bind(org_id)
            .bind(name)
            .bind(&hash)
            .bind(&prefix)
            .bind(input.role.as_str())
            .bind(&input.cluster_id)
            .bind(&actor.actor_id)
            .bind(&expires_at)
            .bind(&now_str)
            .execute(p)
            .await?;
        });

        self.append_audit(
            actor,
            Some(org_id),
            input.cluster_id.as_deref(),
            "api_token.create",
            "api_token",
            &id,
            Some(
                serde_json::json!({ "name": name, "role": input.role.as_str(), "prefix": prefix }),
            ),
        )
        .await?;

        Ok(CreatedApiToken {
            token: ApiTokenMeta {
                id,
                org_id: org_id.to_owned(),
                name: name.to_owned(),
                prefix,
                role: input.role,
                cluster_id: input.cluster_id,
                created_by: actor.actor_id.clone(),
                expires_at,
                last_used_at: None,
                revoked_at: None,
                created_at: now_str,
            },
            plaintext_token: plaintext,
        })
    }

    pub async fn list_api_tokens(&self, org_id: &str) -> Result<Vec<ApiTokenMeta>, ConsoleError> {
        #[allow(clippy::type_complexity)]
        let raw: Vec<(
            String,
            String,
            String,
            String,
            String,
            Option<String>,
            String,
            Option<String>,
            Option<String>,
            Option<String>,
            String,
        )> = on_db!(&self.pool, |p| {
            let rows = sqlx::query(
                "SELECT id, org_id, name, prefix, role, cluster_id, created_by, expires_at, last_used_at, revoked_at, created_at
                 FROM api_tokens WHERE org_id = $1 ORDER BY created_at DESC",
            )
            .bind(org_id)
            .fetch_all(p)
            .await?;
            rows.into_iter()
                .map(|r| {
                    (
                        r.get("id"),
                        r.get("org_id"),
                        r.get("name"),
                        r.get("prefix"),
                        r.get("role"),
                        r.get("cluster_id"),
                        r.get("created_by"),
                        r.get("expires_at"),
                        r.get("last_used_at"),
                        r.get("revoked_at"),
                        r.get("created_at"),
                    )
                })
                .collect()
        });
        let mut out = Vec::with_capacity(raw.len());
        for (
            id,
            org_id,
            name,
            prefix,
            role_s,
            cluster_id,
            created_by,
            expires_at,
            last_used_at,
            revoked_at,
            created_at,
        ) in raw
        {
            out.push(ApiTokenMeta {
                id,
                org_id,
                name,
                prefix,
                role: Role::parse(&role_s)?,
                cluster_id,
                created_by,
                expires_at,
                last_used_at,
                revoked_at,
                created_at,
            });
        }
        Ok(out)
    }

    pub async fn revoke_api_token(
        &self,
        org_id: &str,
        token_id: &str,
        actor: &AuditActor,
    ) -> Result<(), ConsoleError> {
        let now = now_rfc3339();
        let affected = on_db!(&self.pool, |p| {
            sqlx::query("UPDATE api_tokens SET revoked_at = $1 WHERE id = $2 AND org_id = $3")
                .bind(&now)
                .bind(token_id)
                .bind(org_id)
                .execute(p)
                .await?
                .rows_affected()
        });
        if affected == 0 {
            return Err(ConsoleError::NotFound(format!(
                "API token `{token_id}` not found"
            )));
        }
        self.append_audit(
            actor,
            Some(org_id),
            None,
            "api_token.revoke",
            "api_token",
            token_id,
            None,
        )
        .await?;
        Ok(())
    }

    // OIDC Providers
    pub async fn list_public_oidc_providers(
        &self,
    ) -> Result<Vec<PublicOidcProvider>, ConsoleError> {
        let items = on_db!(&self.pool, |p| {
            let rows = sqlx::query(
                "SELECT o.slug, o.display_name, org.slug AS org_slug
                 FROM oidc_providers o JOIN organizations org ON o.org_id = org.id
                 WHERE o.enabled = 1 ORDER BY o.display_name ASC",
            )
            .fetch_all(p)
            .await?;
            rows.into_iter()
                .map(|r| PublicOidcProvider {
                    slug: r.get("slug"),
                    display_name: r.get("display_name"),
                    org_slug: r.get("org_slug"),
                })
                .collect()
        });
        Ok(items)
    }

    pub async fn list_oidc_providers(
        &self,
        org_id: &str,
    ) -> Result<Vec<OidcProviderRecord>, ConsoleError> {
        let items = on_db!(&self.pool, |p| {
            let rows = sqlx::query(
                "SELECT id, org_id, slug, display_name, issuer_url, client_id, client_secret_ref,
                        scopes, group_claim, role_mappings_json, enabled, etag, created_at, updated_at
                 FROM oidc_providers WHERE org_id = $1 ORDER BY slug ASC",
            )
            .bind(org_id)
            .fetch_all(p)
            .await?;
            rows.into_iter().map(row_to_oidc_provider).collect()
        });
        Ok(items)
    }

    pub async fn upsert_oidc_provider(
        &self,
        org_id: &str,
        slug: &str,
        input: CreateOidcProviderInput,
        if_match: Option<&str>,
        actor: &AuditActor,
    ) -> Result<OidcProviderRecord, ConsoleError> {
        validate_slug(slug, "slug")?;
        let now = now_rfc3339();
        let mappings_json = serde_json::to_string(&input.role_mappings)
            .map_err(|e| ConsoleError::Internal(e.to_string()))?;
        let etag = compute_etag(
            format!(
                "{org_id}:{slug}:{}:{}:{}:{now}",
                input.issuer_url, input.client_id, mappings_json
            )
            .as_bytes(),
        );
        let enabled_int: i64 = if input.enabled { 1 } else { 0 };

        let existing: Option<(String, String, String)> = on_db!(&self.pool, |p| {
            sqlx::query(
                "SELECT id, etag, created_at FROM oidc_providers WHERE org_id = $1 AND slug = $2",
            )
            .bind(org_id)
            .bind(slug)
            .fetch_optional(p)
            .await?
            .map(|r| (r.get("id"), r.get("etag"), r.get("created_at")))
        });

        let (id, created_at) = if let Some((id, current_etag, created_at)) = existing {
            check_if_match(if_match, &current_etag)?;
            on_db!(&self.pool, |p| {
                sqlx::query(
                    "UPDATE oidc_providers
                     SET display_name = $1, issuer_url = $2, client_id = $3, client_secret_ref = $4,
                         scopes = $5, group_claim = $6, role_mappings_json = $7, enabled = $8,
                         etag = $9, updated_at = $10
                     WHERE id = $11",
                )
                .bind(input.display_name.trim())
                .bind(input.issuer_url.trim())
                .bind(input.client_id.trim())
                .bind(&input.client_secret_ref)
                .bind(&input.scopes)
                .bind(&input.group_claim)
                .bind(&mappings_json)
                .bind(enabled_int)
                .bind(&etag)
                .bind(&now)
                .bind(&id)
                .execute(p)
                .await?;
            });
            (id, created_at)
        } else {
            let id = new_id("oidc");
            on_db!(&self.pool, |p| {
                sqlx::query(
                    "INSERT INTO oidc_providers
                     (id, org_id, slug, display_name, issuer_url, client_id, client_secret_ref,
                      scopes, group_claim, role_mappings_json, enabled, etag, created_at, updated_at)
                     VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $13)",
                )
                .bind(&id)
                .bind(org_id)
                .bind(slug)
                .bind(input.display_name.trim())
                .bind(input.issuer_url.trim())
                .bind(input.client_id.trim())
                .bind(&input.client_secret_ref)
                .bind(&input.scopes)
                .bind(&input.group_claim)
                .bind(&mappings_json)
                .bind(enabled_int)
                .bind(&etag)
                .bind(&now)
                .execute(p)
                .await?;
            });
            (id, now.clone())
        };

        self.append_audit(
            actor,
            Some(org_id),
            None,
            "oidc_provider.upsert",
            "oidc_provider",
            slug,
            Some(serde_json::json!({ "issuer_url": input.issuer_url, "enabled": input.enabled })),
        )
        .await?;

        Ok(OidcProviderRecord {
            id,
            org_id: org_id.to_owned(),
            slug: slug.to_owned(),
            display_name: input.display_name.trim().to_owned(),
            issuer_url: input.issuer_url.trim().to_owned(),
            client_id: input.client_id.trim().to_owned(),
            client_secret_ref: input.client_secret_ref,
            scopes: input.scopes,
            group_claim: input.group_claim,
            role_mappings: input.role_mappings,
            enabled: input.enabled,
            etag,
            created_at,
            updated_at: now,
        })
    }

    pub async fn delete_oidc_provider(
        &self,
        org_id: &str,
        slug: &str,
        actor: &AuditActor,
    ) -> Result<(), ConsoleError> {
        let affected = on_db!(&self.pool, |p| {
            sqlx::query("DELETE FROM oidc_providers WHERE org_id = $1 AND slug = $2")
                .bind(org_id)
                .bind(slug)
                .execute(p)
                .await?
                .rows_affected()
        });
        if affected == 0 {
            return Err(ConsoleError::NotFound(format!(
                "OIDC provider `{slug}` not found"
            )));
        }
        self.append_audit(
            actor,
            Some(org_id),
            None,
            "oidc_provider.delete",
            "oidc_provider",
            slug,
            None,
        )
        .await?;
        Ok(())
    }

    pub async fn get_oidc_provider_by_slug(
        &self,
        slug: &str,
    ) -> Result<OidcProviderRecord, ConsoleError> {
        let item = on_db!(&self.pool, |p| {
            sqlx::query(
                "SELECT id, org_id, slug, display_name, issuer_url, client_id, client_secret_ref,
                        scopes, group_claim, role_mappings_json, enabled, etag, created_at, updated_at
                 FROM oidc_providers WHERE slug = $1 AND enabled = 1",
            )
            .bind(slug)
            .fetch_optional(p)
            .await?
            .map(row_to_oidc_provider)
        });
        item.ok_or_else(|| {
            ConsoleError::NotFound(format!("enabled OIDC provider `{slug}` not found"))
        })
    }

    pub async fn store_oidc_auth_state(
        &self,
        provider_id: &str,
        state: &str,
        pkce_verifier: &str,
        nonce: &str,
        redirect_to: &str,
    ) -> Result<(), ConsoleError> {
        let expires = (Utc::now() + ChronoDuration::minutes(10)).to_rfc3339();
        on_db!(&self.pool, |p| {
            sqlx::query(
                "INSERT INTO oidc_auth_states (state, provider_id, pkce_verifier, nonce, redirect_to, expires_at)
                 VALUES ($1, $2, $3, $4, $5, $6)",
            )
            .bind(state)
            .bind(provider_id)
            .bind(pkce_verifier)
            .bind(nonce)
            .bind(redirect_to)
            .bind(&expires)
            .execute(p)
            .await?;
        });
        Ok(())
    }

    pub async fn consume_oidc_auth_state(
        &self,
        state: &str,
    ) -> Result<(String, String, String, String), ConsoleError> {
        let rec: Option<(String, String, String, String, String)> = on_db!(&self.pool, |p| {
            let row = sqlx::query(
                "SELECT provider_id, pkce_verifier, nonce, redirect_to, expires_at
                 FROM oidc_auth_states WHERE state = $1",
            )
            .bind(state)
            .fetch_optional(p)
            .await?;
            let _ = sqlx::query("DELETE FROM oidc_auth_states WHERE state = $1")
                .bind(state)
                .execute(p)
                .await;
            row.map(|r| {
                (
                    r.get("provider_id"),
                    r.get("pkce_verifier"),
                    r.get("nonce"),
                    r.get("redirect_to"),
                    r.get("expires_at"),
                )
            })
        });
        let Some((provider_id, pkce_verifier, nonce, redirect_to, exp)) = rec else {
            return Err(ConsoleError::BadRequest(
                "invalid or expired OIDC state".to_owned(),
            ));
        };
        if let Ok(dt) = DateTime::parse_from_rfc3339(&exp)
            && dt < Utc::now()
        {
            return Err(ConsoleError::BadRequest(
                "OIDC login state expired".to_owned(),
            ));
        }
        Ok((provider_id, pkce_verifier, nonce, redirect_to))
    }

    // =========================================================================
    // Organizations, Teams & Clusters
    // =========================================================================

    pub async fn list_orgs(&self) -> Result<Vec<Organization>, ConsoleError> {
        let items = on_db!(&self.pool, |p| {
            let rows = sqlx::query(
                "SELECT id, slug, name, etag, created_at, updated_at FROM organizations ORDER BY created_at ASC",
            )
            .fetch_all(p)
            .await?;
            rows.into_iter()
                .map(|r| Organization {
                    id: r.get("id"),
                    slug: r.get("slug"),
                    name: r.get("name"),
                    etag: r.get("etag"),
                    created_at: r.get("created_at"),
                    updated_at: r.get("updated_at"),
                })
                .collect()
        });
        Ok(items)
    }

    pub async fn get_org_by_slug(&self, slug: &str) -> Result<Organization, ConsoleError> {
        let item = on_db!(&self.pool, |p| {
            sqlx::query(
                "SELECT id, slug, name, etag, created_at, updated_at FROM organizations WHERE slug = $1",
            )
            .bind(slug)
            .fetch_optional(p)
            .await?
            .map(|r| Organization {
                id: r.get("id"),
                slug: r.get("slug"),
                name: r.get("name"),
                etag: r.get("etag"),
                created_at: r.get("created_at"),
                updated_at: r.get("updated_at"),
            })
        });
        item.ok_or_else(|| ConsoleError::NotFound(format!("organization `{slug}` not found")))
    }

    pub async fn create_org(
        &self,
        input: CreateOrgInput,
        actor: &AuditActor,
    ) -> Result<Organization, ConsoleError> {
        validate_slug(&input.slug, "slug")?;
        let id = new_id("org");
        let now = now_rfc3339();
        let etag = compute_etag(format!("{id}:{}:{now}", input.name).as_bytes());
        on_db!(&self.pool, |p| {
            sqlx::query(
                "INSERT INTO organizations (id, slug, name, etag, created_at, updated_at)
                 VALUES ($1, $2, $3, $4, $5, $5)",
            )
            .bind(&id)
            .bind(&input.slug)
            .bind(input.name.trim())
            .bind(&etag)
            .bind(&now)
            .execute(p)
            .await?;
        });
        self.append_audit(
            actor,
            Some(&id),
            None,
            "org.create",
            "organization",
            &input.slug,
            Some(serde_json::json!({ "name": input.name })),
        )
        .await?;
        Ok(Organization {
            id,
            slug: input.slug,
            name: input.name.trim().to_owned(),
            etag,
            created_at: now.clone(),
            updated_at: now,
        })
    }

    pub async fn list_teams(&self, org_id: &str) -> Result<Vec<Team>, ConsoleError> {
        let items = on_db!(&self.pool, |p| {
            let rows = sqlx::query(
                "SELECT id, org_id, slug, name, etag, created_at, updated_at
                 FROM teams WHERE org_id = $1 ORDER BY slug ASC",
            )
            .bind(org_id)
            .fetch_all(p)
            .await?;
            rows.into_iter()
                .map(|r| Team {
                    id: r.get("id"),
                    org_id: r.get("org_id"),
                    slug: r.get("slug"),
                    name: r.get("name"),
                    etag: r.get("etag"),
                    created_at: r.get("created_at"),
                    updated_at: r.get("updated_at"),
                })
                .collect()
        });
        Ok(items)
    }

    pub async fn upsert_team(
        &self,
        org_id: &str,
        slug: &str,
        name: &str,
        if_match: Option<&str>,
        actor: &AuditActor,
    ) -> Result<Team, ConsoleError> {
        validate_slug(slug, "team")?;
        let now = now_rfc3339();
        let etag = compute_etag(format!("{org_id}:{slug}:{name}:{now}").as_bytes());
        let existing: Option<(String, String, String)> = on_db!(&self.pool, |p| {
            sqlx::query("SELECT id, etag, created_at FROM teams WHERE org_id = $1 AND slug = $2")
                .bind(org_id)
                .bind(slug)
                .fetch_optional(p)
                .await?
                .map(|r| (r.get("id"), r.get("etag"), r.get("created_at")))
        });
        let (id, created_at) = if let Some((id, cur_etag, created_at)) = existing {
            check_if_match(if_match, &cur_etag)?;
            on_db!(&self.pool, |p| {
                sqlx::query("UPDATE teams SET name = $1, etag = $2, updated_at = $3 WHERE id = $4")
                    .bind(name.trim())
                    .bind(&etag)
                    .bind(&now)
                    .bind(&id)
                    .execute(p)
                    .await?;
            });
            (id, created_at)
        } else {
            let id = new_id("team");
            on_db!(&self.pool, |p| {
                sqlx::query(
                    "INSERT INTO teams (id, org_id, slug, name, etag, created_at, updated_at)
                     VALUES ($1, $2, $3, $4, $5, $6, $6)",
                )
                .bind(&id)
                .bind(org_id)
                .bind(slug)
                .bind(name.trim())
                .bind(&etag)
                .bind(&now)
                .execute(p)
                .await?;
            });
            (id, now.clone())
        };
        self.append_audit(
            actor,
            Some(org_id),
            None,
            "team.upsert",
            "team",
            slug,
            Some(serde_json::json!({ "name": name })),
        )
        .await?;
        Ok(Team {
            id,
            org_id: org_id.to_owned(),
            slug: slug.to_owned(),
            name: name.trim().to_owned(),
            etag,
            created_at,
            updated_at: now,
        })
    }

    pub async fn list_clusters(&self, org_id: Option<&str>) -> Result<Vec<Cluster>, ConsoleError> {
        let items = match org_id {
            Some(oid) => on_db!(&self.pool, |p| {
                let rows = sqlx::query(
                    "SELECT id, org_id, slug, name, description, environment, ring_assignments_json, etag, created_at, updated_at
                     FROM clusters WHERE org_id = $1 ORDER BY created_at ASC",
                )
                .bind(oid)
                .fetch_all(p)
                .await?;
                rows.into_iter().map(row_to_cluster).collect()
            }),
            None => on_db!(&self.pool, |p| {
                let rows = sqlx::query(
                    "SELECT id, org_id, slug, name, description, environment, ring_assignments_json, etag, created_at, updated_at
                     FROM clusters ORDER BY created_at ASC",
                )
                .fetch_all(p)
                .await?;
                rows.into_iter().map(row_to_cluster).collect()
            }),
        };
        Ok(items)
    }

    pub async fn get_cluster_by_slug(&self, slug: &str) -> Result<Cluster, ConsoleError> {
        let item = on_db!(&self.pool, |p| {
            sqlx::query(
                "SELECT id, org_id, slug, name, description, environment, ring_assignments_json, etag, created_at, updated_at
                 FROM clusters WHERE slug = $1",
            )
            .bind(slug)
            .fetch_optional(p)
            .await?
            .map(row_to_cluster)
        });
        item.ok_or_else(|| ConsoleError::NotFound(format!("cluster `{slug}` not found")))
    }

    pub async fn get_cluster_by_id(&self, id: &str) -> Result<Cluster, ConsoleError> {
        let item = on_db!(&self.pool, |p| {
            sqlx::query(
                "SELECT id, org_id, slug, name, description, environment, ring_assignments_json, etag, created_at, updated_at
                 FROM clusters WHERE id = $1",
            )
            .bind(id)
            .fetch_optional(p)
            .await?
            .map(row_to_cluster)
        });
        item.ok_or_else(|| ConsoleError::NotFound(format!("cluster `{id}` not found")))
    }

    pub async fn create_cluster(
        &self,
        org_id: &str,
        input: CreateClusterInput,
        actor: &AuditActor,
    ) -> Result<Cluster, ConsoleError> {
        validate_slug(&input.slug, "cluster_slug")?;
        let id = new_id("cls");
        let now = now_rfc3339();
        let etag = compute_etag(format!("{id}:{}:{now}", input.name).as_bytes());
        on_db!(&self.pool, |p| {
            sqlx::query(
                "INSERT INTO clusters (id, org_id, slug, name, description, environment, ring_assignments_json, etag, created_at, updated_at)
                 VALUES ($1, $2, $3, $4, $5, $6, '{}', $7, $8, $8)",
            )
            .bind(&id)
            .bind(org_id)
            .bind(&input.slug)
            .bind(input.name.trim())
            .bind(input.description.trim())
            .bind(input.environment.trim())
            .bind(&etag)
            .bind(&now)
            .execute(p)
            .await?;
        });

        let initial_toml = input
            .import_toml
            .as_deref()
            .filter(|s| !s.trim().is_empty())
            .unwrap_or_else(|| ConsoleCompiler::default_cluster_toml());
        self.import_toml_into_cluster(&id, initial_toml, actor)
            .await?;

        self.append_audit(
            actor,
            Some(org_id),
            Some(&id),
            "cluster.create",
            "cluster",
            &input.slug,
            Some(serde_json::json!({ "name": input.name, "environment": input.environment })),
        )
        .await?;

        Ok(Cluster {
            id,
            org_id: org_id.to_owned(),
            slug: input.slug,
            name: input.name.trim().to_owned(),
            description: input.description.trim().to_owned(),
            environment: input.environment.trim().to_owned(),
            ring_assignments: BTreeMap::new(),
            etag,
            created_at: now.clone(),
            updated_at: now,
        })
    }

    // =========================================================================
    // Bootstrap Tokens & Fleet Nodes
    // =========================================================================

    pub async fn create_bootstrap_token(
        &self,
        cluster_id: &str,
        input: CreateBootstrapTokenInput,
        actor: &AuditActor,
    ) -> Result<CreatedBootstrapToken, ConsoleError> {
        let cluster = self.get_cluster_by_id(cluster_id).await?;
        let name = input.name.trim();
        if name.is_empty() {
            return Err(ConsoleError::BadRequest(
                "token name is required".to_owned(),
            ));
        }
        let (plaintext, hash, prefix) = generate_secret_token("shunt_bt_")?;
        let id = new_id("bt");
        let now = Utc::now();
        let now_str = now.to_rfc3339();
        let expires_at = input
            .expires_in_hours
            .filter(|h| *h > 0)
            .map(|h| (now + ChronoDuration::hours(h)).to_rfc3339());
        let labels_json = serde_json::to_string(&input.default_labels)
            .map_err(|e| ConsoleError::Internal(e.to_string()))?;

        on_db!(&self.pool, |p| {
            sqlx::query(
                "INSERT INTO node_bootstrap_tokens
                 (id, cluster_id, name, token_hash, prefix, default_labels_json, max_uses, uses_count, expires_at, created_by, created_at)
                 VALUES ($1, $2, $3, $4, $5, $6, $7, 0, $8, $9, $10)",
            )
            .bind(&id)
            .bind(cluster_id)
            .bind(name)
            .bind(&hash)
            .bind(&prefix)
            .bind(&labels_json)
            .bind(input.max_uses)
            .bind(&expires_at)
            .bind(&actor.actor_id)
            .bind(&now_str)
            .execute(p)
            .await?;
        });

        self.append_audit(
            actor,
            Some(&cluster.org_id),
            Some(cluster_id),
            "bootstrap_token.create",
            "node_bootstrap_token",
            &id,
            Some(serde_json::json!({ "name": name, "prefix": prefix })),
        )
        .await?;

        Ok(CreatedBootstrapToken {
            token: BootstrapTokenMeta {
                id,
                cluster_id: cluster_id.to_owned(),
                name: name.to_owned(),
                prefix,
                default_labels: input.default_labels,
                max_uses: input.max_uses,
                uses_count: 0,
                expires_at,
                revoked_at: None,
                created_by: actor.actor_id.clone(),
                created_at: now_str,
            },
            plaintext_token: plaintext,
        })
    }

    pub async fn list_bootstrap_tokens(
        &self,
        cluster_id: &str,
    ) -> Result<Vec<BootstrapTokenMeta>, ConsoleError> {
        let items = on_db!(&self.pool, |p| {
            let rows = sqlx::query(
                "SELECT id, cluster_id, name, prefix, default_labels_json, max_uses, uses_count, expires_at, revoked_at, created_by, created_at
                 FROM node_bootstrap_tokens WHERE cluster_id = $1 ORDER BY created_at DESC",
            )
            .bind(cluster_id)
            .fetch_all(p)
            .await?;
            rows.into_iter()
                .map(|r| BootstrapTokenMeta {
                    id: r.get("id"),
                    cluster_id: r.get("cluster_id"),
                    name: r.get("name"),
                    prefix: r.get("prefix"),
                    default_labels: serde_json::from_str(
                        &r.get::<String, _>("default_labels_json"),
                    )
                    .unwrap_or_default(),
                    max_uses: r.get("max_uses"),
                    uses_count: r.get("uses_count"),
                    expires_at: r.get("expires_at"),
                    revoked_at: r.get("revoked_at"),
                    created_by: r.get("created_by"),
                    created_at: r.get("created_at"),
                })
                .collect()
        });
        Ok(items)
    }

    pub async fn revoke_bootstrap_token(
        &self,
        cluster_id: &str,
        token_id: &str,
        actor: &AuditActor,
    ) -> Result<(), ConsoleError> {
        let cluster = self.get_cluster_by_id(cluster_id).await?;
        let now = now_rfc3339();
        let affected = on_db!(&self.pool, |p| {
            sqlx::query(
                "UPDATE node_bootstrap_tokens SET revoked_at = $1 WHERE id = $2 AND cluster_id = $3",
            )
            .bind(&now)
            .bind(token_id)
            .bind(cluster_id)
            .execute(p)
            .await?
            .rows_affected()
        });
        if affected == 0 {
            return Err(ConsoleError::NotFound(format!(
                "bootstrap token `{token_id}` not found"
            )));
        }
        self.append_audit(
            actor,
            Some(&cluster.org_id),
            Some(cluster_id),
            "bootstrap_token.revoke",
            "node_bootstrap_token",
            token_id,
            None,
        )
        .await?;
        Ok(())
    }

    pub async fn register_node_with_bootstrap_token(
        &self,
        bootstrap_token: &str,
        cluster_slug: &str,
        node_name: Option<String>,
        shunt_version: String,
        mut labels: BTreeMap<String, String>,
    ) -> Result<(NodeRecord, String, u64), ConsoleError> {
        let cluster = self.get_cluster_by_slug(cluster_slug).await?;
        let bt_hash = sha256_prefixed(bootstrap_token.as_bytes());
        #[allow(clippy::type_complexity)]
        let rec: Option<(
            String,
            String,
            String,
            Option<i64>,
            i64,
            Option<String>,
            Option<String>,
        )> = on_db!(&self.pool, |p| {
            sqlx::query(
                "SELECT id, cluster_id, default_labels_json, max_uses, uses_count, expires_at, revoked_at
                 FROM node_bootstrap_tokens WHERE token_hash = $1",
            )
            .bind(&bt_hash)
            .fetch_optional(p)
            .await?
            .map(|r| {
                (
                    r.get("id"),
                    r.get("cluster_id"),
                    r.get("default_labels_json"),
                    r.get("max_uses"),
                    r.get("uses_count"),
                    r.get("expires_at"),
                    r.get("revoked_at"),
                )
            })
        });
        let Some((
            bt_id,
            bt_cluster_id,
            default_labels_json,
            max_uses,
            uses_count,
            expires_at,
            revoked_at,
        )) = rec
        else {
            return Err(ConsoleError::Unauthorized(
                "invalid cluster bootstrap token".to_owned(),
            ));
        };
        if bt_cluster_id != cluster.id {
            return Err(ConsoleError::Forbidden(
                "bootstrap token does not belong to requested cluster".to_owned(),
            ));
        }
        if revoked_at.is_some() {
            return Err(ConsoleError::Unauthorized(
                "bootstrap token has been revoked".to_owned(),
            ));
        }
        if let Some(exp) = expires_at
            && let Ok(dt) = DateTime::parse_from_rfc3339(&exp)
            && dt < Utc::now()
        {
            return Err(ConsoleError::Unauthorized(
                "bootstrap token expired".to_owned(),
            ));
        }
        if let Some(max) = max_uses
            && uses_count >= max
        {
            return Err(ConsoleError::Unauthorized(
                "bootstrap token reached max_uses".to_owned(),
            ));
        }

        let default_labels: BTreeMap<String, String> =
            serde_json::from_str(&default_labels_json).unwrap_or_default();
        for (k, v) in default_labels {
            labels.entry(k).or_insert(v);
        }

        let node_id = new_id("node");
        let resolved_name = node_name
            .filter(|n| !n.trim().is_empty())
            .unwrap_or_else(|| format!("shunt-{}", &node_id[node_id.len().saturating_sub(6)..]));
        let (node_token, node_token_hash, _) = generate_secret_token("shunt_nt_")?;
        let now = now_rfc3339();
        let labels_json =
            serde_json::to_string(&labels).map_err(|e| ConsoleError::Internal(e.to_string()))?;

        on_db!(&self.pool, |p| {
            sqlx::query(
                "UPDATE node_bootstrap_tokens SET uses_count = uses_count + 1 WHERE id = $1",
            )
            .bind(&bt_id)
            .execute(p)
            .await?;

            sqlx::query(
                "INSERT INTO nodes
                 (id, cluster_id, name, token_hash, shunt_version, labels_json, active_revision, active_digest,
                  synced_seqs_json, status_json, last_heartbeat_at, created_at)
                 VALUES ($1, $2, $3, $4, $5, $6, 0, '', '{}', '{}', $7, $7)",
            )
            .bind(&node_id)
            .bind(&cluster.id)
            .bind(&resolved_name)
            .bind(&node_token_hash)
            .bind(&shunt_version)
            .bind(&labels_json)
            .bind(&now)
            .execute(p)
            .await?;
        });

        let target_revision = resolve_target_revision(&cluster.ring_assignments, &labels);
        let record = NodeRecord {
            id: node_id,
            cluster_id: cluster.id,
            name: resolved_name,
            shunt_version,
            labels,
            active_revision: 0,
            target_revision,
            active_digest: String::new(),
            last_reload_error: None,
            synced_seqs: BTreeMap::new(),
            status: if target_revision.is_none() {
                NodeStatus::Synced
            } else {
                NodeStatus::Converging
            },
            runtime_status: serde_json::json!({}),
            last_heartbeat_at: now.clone(),
            created_at: now,
        };
        Ok((record, node_token, DEFAULT_HEARTBEAT_INTERVAL_SECS))
    }

    pub async fn authenticate_node_token(
        &self,
        node_token: &str,
    ) -> Result<(String, String, BTreeMap<String, String>), ConsoleError> {
        let hash = sha256_prefixed(node_token.as_bytes());
        let rec: Option<(String, String, String)> = on_db!(&self.pool, |p| {
            sqlx::query("SELECT id, cluster_id, labels_json FROM nodes WHERE token_hash = $1")
                .bind(&hash)
                .fetch_optional(p)
                .await?
                .map(|r| (r.get("id"), r.get("cluster_id"), r.get("labels_json")))
        });
        let Some((id, cluster_id, labels_json)) = rec else {
            return Err(ConsoleError::Unauthorized("invalid node token".to_owned()));
        };
        let labels: BTreeMap<String, String> =
            serde_json::from_str(&labels_json).unwrap_or_default();
        Ok((id, cluster_id, labels))
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn record_node_heartbeat(
        &self,
        node_id: &str,
        shunt_version: &str,
        labels: &BTreeMap<String, String>,
        active_revision: u64,
        active_digest: &str,
        last_reload_error: Option<&str>,
        synced_seqs: &BTreeMap<String, u64>,
        runtime_status: &Value,
    ) -> Result<(), ConsoleError> {
        let now = now_rfc3339();
        let labels_json =
            serde_json::to_string(labels).map_err(|e| ConsoleError::Internal(e.to_string()))?;
        let seqs_json = serde_json::to_string(synced_seqs)
            .map_err(|e| ConsoleError::Internal(e.to_string()))?;
        let status_json = serde_json::to_string(runtime_status)
            .map_err(|e| ConsoleError::Internal(e.to_string()))?;

        let affected = on_db!(&self.pool, |p| {
            sqlx::query(
                "UPDATE nodes
                 SET shunt_version = $1, labels_json = $2, active_revision = $3, active_digest = $4,
                     last_reload_error = $5, synced_seqs_json = $6, status_json = $7, last_heartbeat_at = $8
                 WHERE id = $9",
            )
            .bind(shunt_version)
            .bind(&labels_json)
            .bind(active_revision as i64)
            .bind(active_digest)
            .bind(last_reload_error)
            .bind(&seqs_json)
            .bind(&status_json)
            .bind(&now)
            .bind(node_id)
            .execute(p)
            .await?
            .rows_affected()
        });
        if affected == 0 {
            return Err(ConsoleError::NotFound(format!(
                "node `{node_id}` not found"
            )));
        }
        Ok(())
    }

    pub async fn list_cluster_nodes(
        &self,
        cluster_id: &str,
    ) -> Result<Vec<NodeRecord>, ConsoleError> {
        let cluster = self.get_cluster_by_id(cluster_id).await?;
        let head_seqs = self.get_namespace_head_seqs(cluster_id).await?;
        let rev_digests = self.get_revision_digests_map(cluster_id).await?;
        let now = Utc::now();

        struct RawNode {
            id: String,
            cluster_id: String,
            name: String,
            shunt_version: String,
            labels_json: String,
            active_revision: i64,
            active_digest: String,
            last_reload_error: Option<String>,
            synced_seqs_json: String,
            status_json: String,
            last_heartbeat_at: String,
            created_at: String,
        }

        let raw_nodes: Vec<RawNode> = on_db!(&self.pool, |p| {
            let rows = sqlx::query(
                "SELECT id, cluster_id, name, shunt_version, labels_json, active_revision, active_digest,
                        last_reload_error, synced_seqs_json, status_json, last_heartbeat_at, created_at
                 FROM nodes WHERE cluster_id = $1 ORDER BY created_at DESC",
            )
            .bind(cluster_id)
            .fetch_all(p)
            .await?;
            rows.into_iter()
                .map(|r| RawNode {
                    id: r.get("id"),
                    cluster_id: r.get("cluster_id"),
                    name: r.get("name"),
                    shunt_version: r.get("shunt_version"),
                    labels_json: r.get("labels_json"),
                    active_revision: r.get("active_revision"),
                    active_digest: r.get("active_digest"),
                    last_reload_error: r.get("last_reload_error"),
                    synced_seqs_json: r.get("synced_seqs_json"),
                    status_json: r.get("status_json"),
                    last_heartbeat_at: r.get("last_heartbeat_at"),
                    created_at: r.get("created_at"),
                })
                .collect()
        });

        let mut out = Vec::with_capacity(raw_nodes.len());
        for r in raw_nodes {
            let labels: BTreeMap<String, String> =
                serde_json::from_str(&r.labels_json).unwrap_or_default();
            let synced_seqs: BTreeMap<String, u64> =
                serde_json::from_str(&r.synced_seqs_json).unwrap_or_default();
            let runtime_status: Value = serde_json::from_str(&r.status_json).unwrap_or_default();
            let active_revision = r.active_revision.max(0) as u64;
            let target_revision = resolve_target_revision(&cluster.ring_assignments, &labels);

            let status = derive_node_status(
                &r.last_heartbeat_at,
                &cluster.updated_at,
                now,
                active_revision,
                &r.active_digest,
                target_revision,
                target_revision.and_then(|rev| rev_digests.get(&rev).map(String::as_str)),
                r.last_reload_error.as_deref(),
                &synced_seqs,
                &head_seqs,
            );

            out.push(NodeRecord {
                id: r.id,
                cluster_id: r.cluster_id,
                name: r.name,
                shunt_version: r.shunt_version,
                labels,
                active_revision,
                target_revision,
                active_digest: r.active_digest,
                last_reload_error: r.last_reload_error,
                synced_seqs,
                status,
                runtime_status,
                last_heartbeat_at: r.last_heartbeat_at,
                created_at: r.created_at,
            });
        }
        Ok(out)
    }

    pub async fn update_node_labels(
        &self,
        cluster_id: &str,
        node_id: &str,
        labels: BTreeMap<String, String>,
        actor: &AuditActor,
    ) -> Result<(), ConsoleError> {
        let cluster = self.get_cluster_by_id(cluster_id).await?;
        let labels_json =
            serde_json::to_string(&labels).map_err(|e| ConsoleError::Internal(e.to_string()))?;
        let affected = on_db!(&self.pool, |p| {
            sqlx::query("UPDATE nodes SET labels_json = $1 WHERE id = $2 AND cluster_id = $3")
                .bind(&labels_json)
                .bind(node_id)
                .bind(cluster_id)
                .execute(p)
                .await?
                .rows_affected()
        });
        if affected == 0 {
            return Err(ConsoleError::NotFound(format!(
                "node `{node_id}` not found"
            )));
        }

        if let Some(target_rev) = resolve_target_revision(&cluster.ring_assignments, &labels)
            && let Ok(rev) = self.get_revision(cluster_id, target_rev).await
        {
            self.emit_event(ClusterBusEvent::TopologyChanged {
                cluster_id: cluster_id.to_owned(),
                revision: rev.revision,
                digest: rev.digest,
            })
            .await;
        }

        self.append_audit(
            actor,
            Some(&cluster.org_id),
            Some(cluster_id),
            "node.labels.update",
            "node",
            node_id,
            Some(serde_json::json!({ "labels": labels })),
        )
        .await?;
        Ok(())
    }

    pub async fn delete_node(
        &self,
        cluster_id: &str,
        node_id: &str,
        actor: &AuditActor,
    ) -> Result<(), ConsoleError> {
        let cluster = self.get_cluster_by_id(cluster_id).await?;
        let affected = on_db!(&self.pool, |p| {
            sqlx::query("DELETE FROM nodes WHERE id = $1 AND cluster_id = $2")
                .bind(node_id)
                .bind(cluster_id)
                .execute(p)
                .await?
                .rows_affected()
        });
        if affected == 0 {
            return Err(ConsoleError::NotFound(format!(
                "node `{node_id}` not found"
            )));
        }
        self.append_audit(
            actor,
            Some(&cluster.org_id),
            Some(cluster_id),
            "node.delete",
            "node",
            node_id,
            None,
        )
        .await?;
        Ok(())
    }

    // =========================================================================
    // Secrets Vault CRUD (Envelope-Encrypted or Env Passthrough)
    // =========================================================================

    pub async fn list_secrets(&self, org_id: &str) -> Result<Vec<SecretMeta>, ConsoleError> {
        let items = on_db!(&self.pool, |p| {
            let rows = sqlx::query(
                "SELECT id, org_id, scope_type, scope_id, slug, description, delivery_mode, env_var_name,
                        key_version, metadata_json, etag, created_at, updated_at
                 FROM secrets WHERE org_id = $1 ORDER BY slug ASC",
            )
            .bind(org_id)
            .fetch_all(p)
            .await?;
            rows.into_iter().map(row_to_secret_meta).collect()
        });
        Ok(items)
    }

    pub async fn upsert_secret(
        &self,
        org_id: &str,
        slug: &str,
        input: UpsertSecretInput,
        if_match: Option<&str>,
        actor: &AuditActor,
    ) -> Result<SecretMeta, ConsoleError> {
        validate_slug(slug, "secret")?;
        let now = now_rfc3339();
        let meta_val = input.metadata.unwrap_or_else(|| serde_json::json!({}));
        let meta_json =
            serde_json::to_string(&meta_val).map_err(|e| ConsoleError::Internal(e.to_string()))?;

        let existing: Option<(String, i64, String, String)> = on_db!(&self.pool, |p| {
            sqlx::query(
                "SELECT id, key_version, etag, created_at FROM secrets
                 WHERE org_id = $1 AND scope_type = $2 AND scope_id = $3 AND slug = $4",
            )
            .bind(org_id)
            .bind(input.scope_type.as_str())
            .bind(&input.scope_id)
            .bind(slug)
            .fetch_optional(p)
            .await?
            .map(|r| {
                (
                    r.get("id"),
                    r.get("key_version"),
                    r.get("etag"),
                    r.get("created_at"),
                )
            })
        });

        let (id, key_version, created_at) =
            if let Some((id, prev_ver, cur_etag, created_at)) = existing {
                check_if_match(if_match, &cur_etag)?;
                (id, prev_ver + 1, created_at)
            } else {
                (new_id("sec"), 1, now.clone())
            };

        let (env_var_name, ciphertext, nonce, wrapped_dek, dek_nonce) = match input.delivery_mode {
            SecretDeliveryMode::EnvRef => {
                let var = input
                    .env_var_name
                    .as_deref()
                    .map(str::trim)
                    .filter(|v| !v.is_empty())
                    .ok_or_else(|| {
                        ConsoleError::BadRequest(
                            "env_var_name is required when delivery_mode is `env_ref`".to_owned(),
                        )
                    })?
                    .to_owned();
                (Some(var), None, None, None, None)
            }
            SecretDeliveryMode::Vault => {
                let plaintext = input
                    .value
                    .as_deref()
                    .filter(|v| !v.is_empty())
                    .ok_or_else(|| {
                        ConsoleError::BadRequest(
                            "secret `value` is required when delivery_mode is `vault`".to_owned(),
                        )
                    })?;
                let aad = format!("{org_id}|{}|{slug}|{key_version}", input.scope_id);
                let env = self.vault.encrypt(plaintext.as_bytes(), &aad)?;
                (
                    None,
                    Some(env.ciphertext_b64),
                    Some(env.nonce_b64),
                    Some(env.wrapped_dek_b64),
                    Some(env.dek_nonce_b64),
                )
            }
        };

        let etag = compute_etag(
            format!(
                "{id}:{key_version}:{}:{}:{now}",
                input.delivery_mode.as_str(),
                input.description
            )
            .as_bytes(),
        );

        if key_version > 1 {
            on_db!(&self.pool, |p| {
                sqlx::query(
                    "UPDATE secrets
                     SET description = $1, delivery_mode = $2, env_var_name = $3,
                         ciphertext = $4, nonce = $5, wrapped_dek = $6, dek_nonce = $7,
                         key_version = $8, metadata_json = $9, etag = $10, updated_at = $11
                     WHERE id = $12",
                )
                .bind(input.description.trim())
                .bind(input.delivery_mode.as_str())
                .bind(&env_var_name)
                .bind(&ciphertext)
                .bind(&nonce)
                .bind(&wrapped_dek)
                .bind(&dek_nonce)
                .bind(key_version)
                .bind(&meta_json)
                .bind(&etag)
                .bind(&now)
                .bind(&id)
                .execute(p)
                .await?;
            });
        } else {
            on_db!(&self.pool, |p| {
                sqlx::query(
                    "INSERT INTO secrets
                     (id, org_id, scope_type, scope_id, slug, description, delivery_mode, env_var_name,
                      ciphertext, nonce, wrapped_dek, dek_nonce, key_version, metadata_json, etag, created_at, updated_at)
                     VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $16)",
                )
                .bind(&id)
                .bind(org_id)
                .bind(input.scope_type.as_str())
                .bind(&input.scope_id)
                .bind(slug)
                .bind(input.description.trim())
                .bind(input.delivery_mode.as_str())
                .bind(&env_var_name)
                .bind(&ciphertext)
                .bind(&nonce)
                .bind(&wrapped_dek)
                .bind(&dek_nonce)
                .bind(key_version)
                .bind(&meta_json)
                .bind(&etag)
                .bind(&now)
                .execute(p)
                .await?;
            });
        }

        self.append_audit(
            actor,
            Some(org_id),
            if input.scope_type == SecretScopeType::Cluster {
                Some(input.scope_id.as_str())
            } else {
                None
            },
            if key_version > 1 {
                "secret.rotate"
            } else {
                "secret.create"
            },
            "secret",
            slug,
            Some(serde_json::json!({
                "delivery_mode": input.delivery_mode.as_str(),
                "key_version": key_version,
                "env_var_name": env_var_name,
                "value": "[REDACTED]"
            })),
        )
        .await?;

        Ok(SecretMeta {
            id,
            org_id: org_id.to_owned(),
            scope_type: input.scope_type,
            scope_id: input.scope_id,
            slug: slug.to_owned(),
            description: input.description.trim().to_owned(),
            delivery_mode: input.delivery_mode,
            env_var_name,
            key_version,
            metadata: meta_val,
            etag,
            created_at,
            updated_at: now,
        })
    }

    pub async fn delete_secret(
        &self,
        org_id: &str,
        slug: &str,
        actor: &AuditActor,
    ) -> Result<(), ConsoleError> {
        let affected = on_db!(&self.pool, |p| {
            sqlx::query("DELETE FROM secrets WHERE org_id = $1 AND slug = $2")
                .bind(org_id)
                .bind(slug)
                .execute(p)
                .await?
                .rows_affected()
        });
        if affected == 0 {
            return Err(ConsoleError::NotFound(format!("secret `{slug}` not found")));
        }
        self.append_audit(
            actor,
            Some(org_id),
            None,
            "secret.delete",
            "secret",
            slug,
            None,
        )
        .await?;
        Ok(())
    }

    pub async fn resolve_secret_for_cluster(
        &self,
        org_id: &str,
        cluster_id: &str,
        slug: &str,
    ) -> Result<String, ConsoleError> {
        struct RawSecret {
            scope_id: String,
            delivery_mode: String,
            env_var_name: Option<String>,
            ciphertext: Option<String>,
            nonce: Option<String>,
            wrapped_dek: Option<String>,
            dek_nonce: Option<String>,
            key_version: i64,
        }

        let rec: Option<RawSecret> = on_db!(&self.pool, |p| {
            let cluster_row = sqlx::query(
                "SELECT scope_id, delivery_mode, env_var_name, ciphertext, nonce, wrapped_dek, dek_nonce, key_version
                 FROM secrets WHERE org_id = $1 AND scope_type = 'cluster' AND scope_id = $2 AND slug = $3",
            )
            .bind(org_id)
            .bind(cluster_id)
            .bind(slug)
            .fetch_optional(p)
            .await?;
            let chosen = if cluster_row.is_some() {
                cluster_row
            } else {
                sqlx::query(
                    "SELECT scope_id, delivery_mode, env_var_name, ciphertext, nonce, wrapped_dek, dek_nonce, key_version
                     FROM secrets WHERE org_id = $1 AND scope_type = 'org' AND slug = $2",
                )
                .bind(org_id)
                .bind(slug)
                .fetch_optional(p)
                .await?
            };
            chosen.map(|r| RawSecret {
                scope_id: r.get("scope_id"),
                delivery_mode: r.get("delivery_mode"),
                env_var_name: r.get("env_var_name"),
                ciphertext: r.get("ciphertext"),
                nonce: r.get("nonce"),
                wrapped_dek: r.get("wrapped_dek"),
                dek_nonce: r.get("dek_nonce"),
                key_version: r.get("key_version"),
            })
        });
        let Some(row) = rec else {
            return Err(ConsoleError::NotFound(format!(
                "referenced secret `secret:{slug}` not found in vault"
            )));
        };
        if row.delivery_mode == "env_ref" {
            let var = row.env_var_name.unwrap_or_default();
            return Ok(format!("env:{var}"));
        }
        let aad = format!("{org_id}|{}|{slug}|{}", row.scope_id, row.key_version);
        let env = EncryptedEnvelope {
            ciphertext_b64: row.ciphertext.unwrap_or_default(),
            nonce_b64: row.nonce.unwrap_or_default(),
            wrapped_dek_b64: row.wrapped_dek.unwrap_or_default(),
            dek_nonce_b64: row.dek_nonce.unwrap_or_default(),
        };
        let plain = self.vault.decrypt(&env, &aad)?;
        String::from_utf8(plain)
            .map_err(|e| ConsoleError::Vault(format!("decrypted secret is not valid UTF-8: {e}")))
    }

    // =========================================================================
    // Channel 1: Topology Resources, Validation, Publish & Rollback
    // =========================================================================

    pub async fn list_topology_resources(
        &self,
        cluster_id: &str,
        kind_filter: Option<TopologyResourceKind>,
    ) -> Result<Vec<TopologyResource>, ConsoleError> {
        let items = match kind_filter {
            Some(kind) => on_db!(&self.pool, |p| {
                let rows = sqlx::query(
                    "SELECT id, cluster_id, kind, slug, sort_order, version, etag, spec_json, draft_state, updated_by, created_at, updated_at
                     FROM topology_resources WHERE cluster_id = $1 AND kind = $2
                     ORDER BY sort_order ASC, slug ASC",
                )
                .bind(cluster_id)
                .bind(kind.as_str())
                .fetch_all(p)
                .await?;
                rows.into_iter().map(row_to_topology_resource).collect()
            }),
            None => on_db!(&self.pool, |p| {
                let rows = sqlx::query(
                    "SELECT id, cluster_id, kind, slug, sort_order, version, etag, spec_json, draft_state, updated_by, created_at, updated_at
                     FROM topology_resources WHERE cluster_id = $1
                     ORDER BY kind ASC, sort_order ASC, slug ASC",
                )
                .bind(cluster_id)
                .fetch_all(p)
                .await?;
                rows.into_iter().map(row_to_topology_resource).collect()
            }),
        };
        Ok(items)
    }

    pub async fn get_topology_resource(
        &self,
        cluster_id: &str,
        kind: TopologyResourceKind,
        slug: &str,
    ) -> Result<TopologyResource, ConsoleError> {
        let item = on_db!(&self.pool, |p| {
            sqlx::query(
                "SELECT id, cluster_id, kind, slug, sort_order, version, etag, spec_json, draft_state, updated_by, created_at, updated_at
                 FROM topology_resources WHERE cluster_id = $1 AND kind = $2 AND slug = $3",
            )
            .bind(cluster_id)
            .bind(kind.as_str())
            .bind(slug)
            .fetch_optional(p)
            .await?
            .map(row_to_topology_resource)
        });
        item.ok_or_else(|| ConsoleError::NotFound(format!("{} `{slug}` not found", kind.as_str())))
    }

    pub async fn upsert_topology_resource(
        &self,
        cluster_id: &str,
        kind: TopologyResourceKind,
        slug: &str,
        input: UpsertResourceInput,
        if_match: Option<&str>,
        actor: &AuditActor,
    ) -> Result<TopologyResource, ConsoleError> {
        validate_slug(slug, "slug")?;
        let cluster = self.get_cluster_by_id(cluster_id).await?;
        let now = now_rfc3339();
        let spec_json = serde_json::to_string(&input.spec)
            .map_err(|e| ConsoleError::Internal(e.to_string()))?;

        let existing: Option<(String, i64, i64, String, String)> = on_db!(&self.pool, |p| {
            sqlx::query(
                "SELECT id, sort_order, version, etag, created_at FROM topology_resources
                 WHERE cluster_id = $1 AND kind = $2 AND slug = $3",
            )
            .bind(cluster_id)
            .bind(kind.as_str())
            .bind(slug)
            .fetch_optional(p)
            .await?
            .map(|r| {
                (
                    r.get("id"),
                    r.get("sort_order"),
                    r.get("version"),
                    r.get("etag"),
                    r.get("created_at"),
                )
            })
        });

        let (id, sort_order, version, etag, created_at) = if let Some((
            id,
            prev_sort,
            prev_ver,
            cur_etag,
            created_at,
        )) = existing
        {
            check_if_match(if_match, &cur_etag)?;
            let sort_order = input.sort_order.unwrap_or(prev_sort);
            let version = prev_ver + 1;
            let etag = compute_etag(format!("{id}:{version}:{spec_json}").as_bytes());
            on_db!(&self.pool, |p| {
                sqlx::query(
                        "UPDATE topology_resources
                         SET sort_order = $1, version = $2, etag = $3, spec_json = $4, draft_state = 'active',
                             updated_by = $5, updated_at = $6
                         WHERE id = $7",
                    )
                    .bind(sort_order)
                    .bind(version)
                    .bind(&etag)
                    .bind(&spec_json)
                    .bind(&actor.actor_id)
                    .bind(&now)
                    .bind(&id)
                    .execute(p)
                    .await?;
            });
            (id, sort_order, version, etag, created_at)
        } else {
            let id = new_id("res");
            let sort_order = input.sort_order.unwrap_or(0);
            let etag = compute_etag(format!("{id}:1:{spec_json}").as_bytes());
            on_db!(&self.pool, |p| {
                sqlx::query(
                        "INSERT INTO topology_resources
                         (id, cluster_id, kind, slug, sort_order, version, etag, spec_json, draft_state, updated_by, created_at, updated_at)
                         VALUES ($1, $2, $3, $4, $5, 1, $6, $7, 'active', $8, $9, $9)",
                    )
                    .bind(&id)
                    .bind(cluster_id)
                    .bind(kind.as_str())
                    .bind(slug)
                    .bind(sort_order)
                    .bind(&etag)
                    .bind(&spec_json)
                    .bind(&actor.actor_id)
                    .bind(&now)
                    .execute(p)
                    .await?;
            });
            (id, sort_order, 1, etag, now.clone())
        };

        self.append_audit(
            actor,
            Some(&cluster.org_id),
            Some(cluster_id),
            "topology_resource.upsert",
            kind.as_str(),
            slug,
            Some(serde_json::json!({ "version": version })),
        )
        .await?;

        Ok(TopologyResource {
            id,
            cluster_id: cluster_id.to_owned(),
            kind,
            slug: slug.to_owned(),
            sort_order,
            version,
            etag,
            spec: input.spec,
            draft_state: "active".to_owned(),
            updated_by: actor.actor_id.clone(),
            created_at,
            updated_at: now,
        })
    }

    pub async fn delete_topology_resource(
        &self,
        cluster_id: &str,
        kind: TopologyResourceKind,
        slug: &str,
        if_match: Option<&str>,
        actor: &AuditActor,
    ) -> Result<(), ConsoleError> {
        let cluster = self.get_cluster_by_id(cluster_id).await?;
        let existing = self.get_topology_resource(cluster_id, kind, slug).await?;
        check_if_match(if_match, &existing.etag)?;
        on_db!(&self.pool, |p| {
            sqlx::query("DELETE FROM topology_resources WHERE id = $1")
                .bind(&existing.id)
                .execute(p)
                .await?;
        });
        self.append_audit(
            actor,
            Some(&cluster.org_id),
            Some(cluster_id),
            "topology_resource.delete",
            kind.as_str(),
            slug,
            None,
        )
        .await?;
        Ok(())
    }

    pub async fn import_toml_into_cluster(
        &self,
        cluster_id: &str,
        toml_src: &str,
        actor: &AuditActor,
    ) -> Result<ValidateDraftResult, ConsoleError> {
        let cluster = self.get_cluster_by_id(cluster_id).await?;
        let items = ConsoleCompiler::decompose_toml(toml_src)?;
        let now = now_rfc3339();

        on_db!(&self.pool, |p| {
            sqlx::query("DELETE FROM topology_resources WHERE cluster_id = $1")
                .bind(cluster_id)
                .execute(p)
                .await?;
        });

        for (kind, slug, sort_order, spec) in items {
            let id = new_id("res");
            let spec_json =
                serde_json::to_string(&spec).map_err(|e| ConsoleError::Internal(e.to_string()))?;
            let etag = compute_etag(format!("{id}:1:{spec_json}").as_bytes());
            on_db!(&self.pool, |p| {
                sqlx::query(
                    "INSERT INTO topology_resources
                     (id, cluster_id, kind, slug, sort_order, version, etag, spec_json, draft_state, updated_by, created_at, updated_at)
                     VALUES ($1, $2, $3, $4, $5, 1, $6, $7, 'active', $8, $9, $9)",
                )
                .bind(&id)
                .bind(cluster_id)
                .bind(kind.as_str())
                .bind(&slug)
                .bind(sort_order)
                .bind(&etag)
                .bind(&spec_json)
                .bind(&actor.actor_id)
                .bind(&now)
                .execute(p)
                .await?;
            });
        }

        self.append_audit(
            actor,
            Some(&cluster.org_id),
            Some(cluster_id),
            "topology.import_toml",
            "cluster",
            &cluster.slug,
            None,
        )
        .await?;

        self.validate_cluster_draft(cluster_id).await
    }

    pub async fn validate_cluster_draft(
        &self,
        cluster_id: &str,
    ) -> Result<ValidateDraftResult, ConsoleError> {
        let cluster = self.get_cluster_by_id(cluster_id).await?;
        let resources = self.list_topology_resources(cluster_id, None).await?;
        ConsoleCompiler::validate_preview(&cluster.slug, &resources)
    }

    pub async fn publish_revision(
        &self,
        cluster_id: &str,
        input: PublishRevisionInput,
        actor: &AuditActor,
    ) -> Result<TopologyRevision, ConsoleError> {
        let cluster = self.get_cluster_by_id(cluster_id).await?;
        let resources = self.list_topology_resources(cluster_id, None).await?;
        let compiled =
            ConsoleCompiler::compile_and_verify(&cluster.slug, &resources, input.strict)?;
        if !compiled.verify_report.passed {
            return Err(ConsoleError::Validation {
                message: format!(
                    "shunt verify failed with {} error(s), {} warning(s)",
                    compiled.verify_report.errors, compiled.verify_report.warnings
                ),
                diagnostics: compiled.diagnostics,
            });
        }

        let max_rev: i64 = on_db!(&self.pool, |p| {
            sqlx::query_scalar(
                "SELECT COALESCE(MAX(revision), 0) FROM topology_revisions WHERE cluster_id = $1",
            )
            .bind(cluster_id)
            .fetch_one(p)
            .await?
        });
        let revision = (max_rev as u64) + 1;
        let signature_b64 = self.signer.sign_revision(revision, &compiled.digest);
        let verify_json = serde_json::to_string(&compiled.verify_report)
            .map_err(|e| ConsoleError::Internal(e.to_string()))?;

        let mut next_rings = cluster.ring_assignments.clone();
        let selector = if input.ring_selector.trim().is_empty() {
            "*".to_owned()
        } else {
            input.ring_selector.trim().to_owned()
        };
        next_rings.insert(selector.clone(), revision);
        let rings_json = serde_json::to_string(&next_rings)
            .map_err(|e| ConsoleError::Internal(e.to_string()))?;

        let rev_id = new_id("rev");
        let now = now_rfc3339();
        let new_cluster_etag = compute_etag(format!("{}:{revision}:{now}", cluster.id).as_bytes());

        on_db!(&self.pool, |p| {
            sqlx::query(
                "INSERT INTO topology_revisions
                 (id, cluster_id, revision, digest, compiled_toml, verify_report_json, signature_b64,
                  ring_assignments_json, notes, published_by, created_at)
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)",
            )
            .bind(&rev_id)
            .bind(cluster_id)
            .bind(revision as i64)
            .bind(&compiled.digest)
            .bind(&compiled.redacted_toml)
            .bind(&verify_json)
            .bind(&signature_b64)
            .bind(&rings_json)
            .bind(input.notes.trim())
            .bind(&actor.actor_id)
            .bind(&now)
            .execute(p)
            .await?;

            sqlx::query(
                "UPDATE clusters SET ring_assignments_json = $1, etag = $2, updated_at = $3 WHERE id = $4",
            )
            .bind(&rings_json)
            .bind(&new_cluster_etag)
            .bind(&now)
            .bind(cluster_id)
            .execute(p)
            .await?;
        });

        self.append_audit(
            actor,
            Some(&cluster.org_id),
            Some(cluster_id),
            "revision.publish",
            "topology_revision",
            &format!("rev-{revision}"),
            Some(serde_json::json!({
                "revision": revision,
                "digest": compiled.digest,
                "ring_selector": selector,
                "notes": input.notes
            })),
        )
        .await?;

        self.emit_event(ClusterBusEvent::TopologyChanged {
            cluster_id: cluster_id.to_owned(),
            revision,
            digest: compiled.digest.clone(),
        })
        .await;

        Ok(TopologyRevision {
            id: rev_id,
            cluster_id: cluster_id.to_owned(),
            revision,
            digest: compiled.digest,
            compiled_toml: compiled.redacted_toml,
            verify_report: serde_json::from_str(&verify_json).unwrap_or_default(),
            signature_b64,
            ring_assignments: next_rings,
            notes: input.notes.trim().to_owned(),
            published_by: actor.actor_id.clone(),
            created_at: now,
        })
    }

    pub async fn rollback_or_promote_revision(
        &self,
        cluster_id: &str,
        target_revision: u64,
        ring_selector: &str,
        action_name: &str,
        actor: &AuditActor,
    ) -> Result<Cluster, ConsoleError> {
        let cluster = self.get_cluster_by_id(cluster_id).await?;
        let rev = self.get_revision(cluster_id, target_revision).await?;

        let mut next_rings = cluster.ring_assignments.clone();
        let selector = if ring_selector.trim().is_empty() {
            "*"
        } else {
            ring_selector.trim()
        };
        if selector == "*" && action_name == "revision.rollback" {
            next_rings.clear();
        }
        next_rings.insert(selector.to_owned(), target_revision);
        let rings_json = serde_json::to_string(&next_rings)
            .map_err(|e| ConsoleError::Internal(e.to_string()))?;
        let now = now_rfc3339();
        let etag = compute_etag(format!("{}:{rings_json}:{now}", cluster.id).as_bytes());

        on_db!(&self.pool, |p| {
            sqlx::query(
                "UPDATE clusters SET ring_assignments_json = $1, etag = $2, updated_at = $3 WHERE id = $4",
            )
            .bind(&rings_json)
            .bind(&etag)
            .bind(&now)
            .bind(cluster_id)
            .execute(p)
            .await?;
        });

        self.append_audit(
            actor,
            Some(&cluster.org_id),
            Some(cluster_id),
            action_name,
            "topology_revision",
            &format!("rev-{target_revision}"),
            Some(serde_json::json!({
                "target_revision": target_revision,
                "ring_selector": selector,
                "channel2_untouched": true
            })),
        )
        .await?;

        self.emit_event(ClusterBusEvent::TopologyChanged {
            cluster_id: cluster_id.to_owned(),
            revision: rev.revision,
            digest: rev.digest,
        })
        .await;

        self.get_cluster_by_id(cluster_id).await
    }

    pub async fn list_revisions(
        &self,
        cluster_id: &str,
    ) -> Result<Vec<TopologyRevision>, ConsoleError> {
        let items = on_db!(&self.pool, |p| {
            let rows = sqlx::query(
                "SELECT id, cluster_id, revision, digest, compiled_toml, verify_report_json,
                        signature_b64, ring_assignments_json, notes, published_by, created_at
                 FROM topology_revisions WHERE cluster_id = $1 ORDER BY revision DESC",
            )
            .bind(cluster_id)
            .fetch_all(p)
            .await?;
            rows.into_iter().map(row_to_topology_revision).collect()
        });
        Ok(items)
    }

    pub async fn get_revision(
        &self,
        cluster_id: &str,
        revision: u64,
    ) -> Result<TopologyRevision, ConsoleError> {
        let item = on_db!(&self.pool, |p| {
            sqlx::query(
                "SELECT id, cluster_id, revision, digest, compiled_toml, verify_report_json,
                        signature_b64, ring_assignments_json, notes, published_by, created_at
                 FROM topology_revisions WHERE cluster_id = $1 AND revision = $2",
            )
            .bind(cluster_id)
            .bind(revision as i64)
            .fetch_optional(p)
            .await?
            .map(row_to_topology_revision)
        });
        item.ok_or_else(|| {
            ConsoleError::NotFound(format!("topology revision #{revision} not found"))
        })
    }

    pub async fn build_node_delivery_bundle(
        &self,
        cluster_id: &str,
        revision: u64,
    ) -> Result<shunt_config::TopologyBundleResponse, ConsoleError> {
        let cluster = self.get_cluster_by_id(cluster_id).await?;
        let rev = self.get_revision(cluster_id, revision).await?;

        let mut needed_slugs = Vec::new();
        collect_secret_slugs_in_toml(&rev.compiled_toml, &mut needed_slugs);
        let mut resolved_map = BTreeMap::new();
        for slug in needed_slugs {
            if let std::collections::btree_map::Entry::Vacant(e) = resolved_map.entry(slug) {
                let val = self
                    .resolve_secret_for_cluster(&cluster.org_id, cluster_id, e.key())
                    .await?;
                e.insert(val);
            }
        }

        let delivered_toml = if resolved_map.is_empty() {
            rev.compiled_toml.clone()
        } else {
            ConsoleCompiler::resolve_secrets_for_delivery(&rev.compiled_toml, |slug| {
                resolved_map
                    .get(slug)
                    .cloned()
                    .ok_or_else(|| ConsoleError::NotFound(format!("secret `{slug}` not resolved")))
            })?
        };

        let digest = sha256_prefixed(delivered_toml.as_bytes());
        let signature_b64 = self.signer.sign_revision(rev.revision, &digest);

        Ok(shunt_config::TopologyBundleResponse {
            revision: rev.revision,
            digest,
            compiled_toml: delivered_toml,
            signature_b64: Some(signature_b64),
        })
    }

    async fn get_revision_digests_map(
        &self,
        cluster_id: &str,
    ) -> Result<BTreeMap<u64, String>, ConsoleError> {
        let pairs: Vec<(u64, String)> = on_db!(&self.pool, |p| {
            let rows = sqlx::query(
                "SELECT revision, digest FROM topology_revisions WHERE cluster_id = $1",
            )
            .bind(cluster_id)
            .fetch_all(p)
            .await?;
            rows.into_iter()
                .map(|r| (r.get::<i64, _>("revision") as u64, r.get("digest")))
                .collect()
        });
        Ok(pairs.into_iter().collect())
    }

    // =========================================================================
    // Channel 2: Synced State Tables (`control_events` + `control_state_current`)
    // =========================================================================

    pub async fn upsert_synced_state(
        &self,
        cluster_id: &str,
        namespace: &str,
        item_key: &str,
        payload: Value,
        actor: &AuditActor,
    ) -> Result<ControlEvent, ConsoleError> {
        let cluster = self.get_cluster_by_id(cluster_id).await?;
        validate_namespace(namespace)?;
        if item_key.trim().is_empty() {
            return Err(ConsoleError::BadRequest(
                "item_key cannot be empty".to_owned(),
            ));
        }
        let now = now_rfc3339();
        let payload_json =
            serde_json::to_string(&payload).map_err(|e| ConsoleError::Internal(e.to_string()))?;

        let seq: i64 = on_db!(&self.pool, |p| {
            let mut tx = p.begin().await?;
            let seq: i64 = sqlx::query_scalar(
                "INSERT INTO control_events (cluster_id, namespace, item_key, op, payload_json, created_at)
                 VALUES ($1, $2, $3, 'upsert', $4, $5)
                 RETURNING seq",
            )
            .bind(cluster_id)
            .bind(namespace)
            .bind(item_key)
            .bind(&payload_json)
            .bind(&now)
            .fetch_one(&mut *tx)
            .await?;

            sqlx::query(
                "INSERT INTO control_state_current (cluster_id, namespace, item_key, seq, payload_json, updated_at)
                 VALUES ($1, $2, $3, $4, $5, $6)
                 ON CONFLICT (cluster_id, namespace, item_key)
                 DO UPDATE SET seq = excluded.seq, payload_json = excluded.payload_json, updated_at = excluded.updated_at",
            )
            .bind(cluster_id)
            .bind(namespace)
            .bind(item_key)
            .bind(seq)
            .bind(&payload_json)
            .bind(&now)
            .execute(&mut *tx)
            .await?;

            tx.commit().await?;
            seq
        });

        let seq_u64 = seq as u64;
        self.append_audit(
            actor,
            Some(&cluster.org_id),
            Some(cluster_id),
            "synced_state.upsert",
            namespace,
            item_key,
            Some(serde_json::json!({ "seq": seq_u64 })),
        )
        .await?;

        self.emit_event(ClusterBusEvent::StateDelta {
            cluster_id: cluster_id.to_owned(),
            seq: seq_u64,
            namespace: namespace.to_owned(),
            item_key: item_key.to_owned(),
            op: "upsert".to_owned(),
            payload: Some(payload.clone()),
        })
        .await;

        Ok(ControlEvent {
            seq: seq_u64,
            cluster_id: cluster_id.to_owned(),
            namespace: namespace.to_owned(),
            item_key: item_key.to_owned(),
            op: "upsert".to_owned(),
            payload: Some(payload),
            created_at: now,
        })
    }

    pub async fn delete_synced_state(
        &self,
        cluster_id: &str,
        namespace: &str,
        item_key: &str,
        actor: &AuditActor,
    ) -> Result<ControlEvent, ConsoleError> {
        let cluster = self.get_cluster_by_id(cluster_id).await?;
        validate_namespace(namespace)?;
        let now = now_rfc3339();

        let seq: i64 = on_db!(&self.pool, |p| {
            let mut tx = p.begin().await?;
            let seq: i64 = sqlx::query_scalar(
                "INSERT INTO control_events (cluster_id, namespace, item_key, op, payload_json, created_at)
                 VALUES ($1, $2, $3, 'delete', NULL, $4)
                 RETURNING seq",
            )
            .bind(cluster_id)
            .bind(namespace)
            .bind(item_key)
            .bind(&now)
            .fetch_one(&mut *tx)
            .await?;

            sqlx::query(
                "DELETE FROM control_state_current
                 WHERE cluster_id = $1 AND namespace = $2 AND item_key = $3",
            )
            .bind(cluster_id)
            .bind(namespace)
            .bind(item_key)
            .execute(&mut *tx)
            .await?;

            tx.commit().await?;
            seq
        });

        let seq_u64 = seq as u64;
        self.append_audit(
            actor,
            Some(&cluster.org_id),
            Some(cluster_id),
            "synced_state.delete",
            namespace,
            item_key,
            Some(serde_json::json!({ "seq": seq_u64 })),
        )
        .await?;

        self.emit_event(ClusterBusEvent::StateDelta {
            cluster_id: cluster_id.to_owned(),
            seq: seq_u64,
            namespace: namespace.to_owned(),
            item_key: item_key.to_owned(),
            op: "delete".to_owned(),
            payload: None,
        })
        .await;

        Ok(ControlEvent {
            seq: seq_u64,
            cluster_id: cluster_id.to_owned(),
            namespace: namespace.to_owned(),
            item_key: item_key.to_owned(),
            op: "delete".to_owned(),
            payload: None,
            created_at: now,
        })
    }

    pub async fn get_namespace_full_sync(
        &self,
        cluster_id: &str,
        namespace: &str,
    ) -> Result<(u64, BTreeMap<String, Value>), ConsoleError> {
        let head_seq: i64 = on_db!(&self.pool, |p| {
            sqlx::query_scalar(
                "SELECT COALESCE(MAX(seq), 0) FROM control_events WHERE cluster_id = $1 AND namespace = $2",
            )
            .bind(cluster_id)
            .bind(namespace)
            .fetch_one(p)
            .await?
        });

        let pairs: Vec<(String, String)> = on_db!(&self.pool, |p| {
            let rows = sqlx::query(
                "SELECT item_key, payload_json FROM control_state_current
                 WHERE cluster_id = $1 AND namespace = $2 ORDER BY item_key ASC",
            )
            .bind(cluster_id)
            .bind(namespace)
            .fetch_all(p)
            .await?;
            rows.into_iter()
                .map(|r| (r.get("item_key"), r.get("payload_json")))
                .collect()
        });

        let mut entries = BTreeMap::new();
        for (key, json_s) in pairs {
            let val: Value = serde_json::from_str(&json_s).unwrap_or(Value::Null);
            entries.insert(key, val);
        }
        Ok((head_seq as u64, entries))
    }

    pub async fn replay_namespace_deltas(
        &self,
        cluster_id: &str,
        namespace: &str,
        after_seq: u64,
    ) -> Result<Option<Vec<ControlEvent>>, ConsoleError> {
        if after_seq == 0 {
            return Ok(None);
        }
        let min_seq: Option<i64> = on_db!(&self.pool, |p| {
            sqlx::query_scalar(
                "SELECT MIN(seq) FROM control_events WHERE cluster_id = $1 AND namespace = $2",
            )
            .bind(cluster_id)
            .bind(namespace)
            .fetch_one(p)
            .await?
        });
        if let Some(min) = min_seq
            && (after_seq as i64) + 1 < min
        {
            return Ok(None);
        }

        let events = on_db!(&self.pool, |p| {
            let rows = sqlx::query(
                "SELECT seq, cluster_id, namespace, item_key, op, payload_json, created_at
                 FROM control_events
                 WHERE cluster_id = $1 AND namespace = $2 AND seq > $3
                 ORDER BY seq ASC",
            )
            .bind(cluster_id)
            .bind(namespace)
            .bind(after_seq as i64)
            .fetch_all(p)
            .await?;
            rows.into_iter().map(row_to_control_event).collect()
        });

        Ok(Some(events))
    }

    pub async fn compact_control_events(
        &self,
        cluster_id: &str,
        namespace: &str,
        keep_after_seq: u64,
    ) -> Result<u64, ConsoleError> {
        let removed = on_db!(&self.pool, |p| {
            sqlx::query(
                "DELETE FROM control_events
                 WHERE cluster_id = $1 AND namespace = $2 AND seq <= $3",
            )
            .bind(cluster_id)
            .bind(namespace)
            .bind(keep_after_seq as i64)
            .execute(p)
            .await?
            .rows_affected()
        });
        Ok(removed)
    }

    pub async fn list_namespace_summaries(
        &self,
        cluster_id: &str,
    ) -> Result<Vec<NamespaceStateSummary>, ConsoleError> {
        let head_seqs = self.get_namespace_head_seqs(cluster_id).await?;
        let count_pairs: Vec<(String, usize)> = on_db!(&self.pool, |p| {
            let rows = sqlx::query(
                "SELECT namespace, COUNT(*) AS cnt FROM control_state_current
                 WHERE cluster_id = $1 GROUP BY namespace",
            )
            .bind(cluster_id)
            .fetch_all(p)
            .await?;
            rows.into_iter()
                .map(|r| (r.get("namespace"), r.get::<i64, _>("cnt") as usize))
                .collect()
        });
        let counts: BTreeMap<String, usize> = count_pairs.into_iter().collect();

        let nodes = self.list_cluster_nodes(cluster_id).await?;
        let online_nodes: Vec<&NodeRecord> = nodes
            .iter()
            .filter(|n| n.status != NodeStatus::Offline)
            .collect();

        let mut namespaces: BTreeMap<String, u64> = BTreeMap::from([
            ("ai.virtual_keys".to_owned(), 0),
            ("ai.budgets".to_owned(), 0),
            ("ai.pricing".to_owned(), 0),
            ("mcp.agent_acls".to_owned(), 0),
            ("mcp.kill_switch".to_owned(), 0),
            ("mcp.approvals".to_owned(), 0),
        ]);
        for (ns, seq) in head_seqs {
            namespaces.insert(ns, seq);
        }

        let mut out = Vec::with_capacity(namespaces.len());
        for (ns, head_seq) in namespaces {
            let converged = online_nodes
                .iter()
                .filter(|n| n.synced_seqs.get(&ns).copied().unwrap_or(0) >= head_seq)
                .count();
            out.push(NamespaceStateSummary {
                item_count: counts.get(&ns).copied().unwrap_or(0),
                converged_nodes: converged,
                total_online_nodes: online_nodes.len(),
                namespace: ns,
                head_seq,
            });
        }
        Ok(out)
    }

    pub async fn list_namespace_items_and_events(
        &self,
        cluster_id: &str,
        namespace: &str,
    ) -> Result<(u64, Vec<ControlStateItem>, Vec<ControlEvent>), ConsoleError> {
        let head_seq: i64 = on_db!(&self.pool, |p| {
            sqlx::query_scalar(
                "SELECT COALESCE(MAX(seq), 0) FROM control_events WHERE cluster_id = $1 AND namespace = $2",
            )
            .bind(cluster_id)
            .bind(namespace)
            .fetch_one(p)
            .await?
        });
        let items = on_db!(&self.pool, |p| {
            let rows = sqlx::query(
                "SELECT cluster_id, namespace, item_key, seq, payload_json, updated_at
                 FROM control_state_current
                 WHERE cluster_id = $1 AND namespace = $2 ORDER BY item_key ASC",
            )
            .bind(cluster_id)
            .bind(namespace)
            .fetch_all(p)
            .await?;
            rows.into_iter()
                .map(|r| ControlStateItem {
                    cluster_id: r.get("cluster_id"),
                    namespace: r.get("namespace"),
                    item_key: r.get("item_key"),
                    seq: r.get::<i64, _>("seq") as u64,
                    payload: serde_json::from_str(&r.get::<String, _>("payload_json"))
                        .unwrap_or(Value::Null),
                    updated_at: r.get("updated_at"),
                })
                .collect()
        });

        let events = on_db!(&self.pool, |p| {
            let rows = sqlx::query(
                "SELECT seq, cluster_id, namespace, item_key, op, payload_json, created_at
                 FROM control_events
                 WHERE cluster_id = $1 AND namespace = $2
                 ORDER BY seq DESC LIMIT 50",
            )
            .bind(cluster_id)
            .bind(namespace)
            .fetch_all(p)
            .await?;
            rows.into_iter().map(row_to_control_event).collect()
        });

        Ok((head_seq as u64, items, events))
    }

    async fn get_namespace_head_seqs(
        &self,
        cluster_id: &str,
    ) -> Result<BTreeMap<String, u64>, ConsoleError> {
        let pairs: Vec<(String, u64)> = on_db!(&self.pool, |p| {
            let rows = sqlx::query(
                "SELECT namespace, MAX(seq) AS max_seq FROM control_events
                 WHERE cluster_id = $1 GROUP BY namespace",
            )
            .bind(cluster_id)
            .fetch_all(p)
            .await?;
            rows.into_iter()
                .map(|r| (r.get("namespace"), r.get::<i64, _>("max_seq") as u64))
                .collect()
        });
        Ok(pairs.into_iter().collect())
    }

    // =========================================================================
    // Hash-Chained Immutable Admin Audit Log
    // =========================================================================

    #[allow(clippy::too_many_arguments)]
    pub async fn append_audit(
        &self,
        actor: &AuditActor,
        org_id: Option<&str>,
        cluster_id: Option<&str>,
        action: &str,
        resource_type: &str,
        resource_id: &str,
        diff: Option<Value>,
    ) -> Result<u64, ConsoleError> {
        let ts = now_rfc3339();
        let diff_json = diff
            .as_ref()
            .map(serde_json::to_string)
            .transpose()
            .map_err(|e| ConsoleError::Internal(e.to_string()))?;

        let seq: i64 = on_db!(&self.pool, |p| {
            let mut tx = p.begin().await?;
            let prev: Option<(i64, String)> = sqlx::query_as(
                "SELECT seq, entry_hash FROM admin_audit_log ORDER BY seq DESC LIMIT 1",
            )
            .fetch_optional(&mut *tx)
            .await?;

            let (next_seq, prev_hash) = match prev {
                Some((s, h)) => (s + 1, h),
                None => (1, GENESIS_AUDIT_HASH.to_owned()),
            };

            let entry_hash = compute_audit_hash(
                next_seq as u64,
                &ts,
                &actor.actor_type,
                &actor.actor_id,
                action,
                resource_type,
                resource_id,
                diff_json.as_deref(),
                &prev_hash,
            );

            sqlx::query(
                "INSERT INTO admin_audit_log
                 (seq, ts, actor_type, actor_id, actor_ip, org_id, cluster_id, action, resource_type, resource_id, diff_json, prev_hash, entry_hash)
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)",
            )
            .bind(next_seq)
            .bind(&ts)
            .bind(&actor.actor_type)
            .bind(&actor.actor_id)
            .bind(&actor.actor_ip)
            .bind(org_id)
            .bind(cluster_id)
            .bind(action)
            .bind(resource_type)
            .bind(resource_id)
            .bind(&diff_json)
            .bind(&prev_hash)
            .bind(&entry_hash)
            .execute(&mut *tx)
            .await?;

            tx.commit().await?;
            next_seq
        });

        Ok(seq as u64)
    }

    pub async fn list_admin_audit(&self, limit: i64) -> Result<Vec<AdminAuditEntry>, ConsoleError> {
        let clamped = limit.clamp(1, 500);
        let items = on_db!(&self.pool, |p| {
            let rows = sqlx::query(
                "SELECT seq, ts, actor_type, actor_id, actor_ip, org_id, cluster_id,
                        action, resource_type, resource_id, diff_json, prev_hash, entry_hash
                 FROM admin_audit_log ORDER BY seq DESC LIMIT $1",
            )
            .bind(clamped)
            .fetch_all(p)
            .await?;
            rows.into_iter()
                .map(|r| {
                    let diff_opt: Option<String> = r.get("diff_json");
                    AdminAuditEntry {
                        seq: r.get::<i64, _>("seq") as u64,
                        ts: r.get("ts"),
                        actor_type: r.get("actor_type"),
                        actor_id: r.get("actor_id"),
                        actor_ip: r.get("actor_ip"),
                        org_id: r.get("org_id"),
                        cluster_id: r.get("cluster_id"),
                        action: r.get("action"),
                        resource_type: r.get("resource_type"),
                        resource_id: r.get("resource_id"),
                        diff: diff_opt.and_then(|s| serde_json::from_str(&s).ok()),
                        prev_hash: r.get("prev_hash"),
                        entry_hash: r.get("entry_hash"),
                    }
                })
                .collect()
        });
        Ok(items)
    }

    pub async fn verify_admin_audit_chain(&self) -> Result<AuditChainVerification, ConsoleError> {
        struct RawAudit {
            seq: u64,
            ts: String,
            actor_type: String,
            actor_id: String,
            action: String,
            resource_type: String,
            resource_id: String,
            diff_json: Option<String>,
            prev_hash: String,
            entry_hash: String,
        }

        let rows: Vec<RawAudit> = on_db!(&self.pool, |p| {
            let rs = sqlx::query(
                "SELECT seq, ts, actor_type, actor_id, action, resource_type, resource_id, diff_json, prev_hash, entry_hash
                 FROM admin_audit_log ORDER BY seq ASC",
            )
            .fetch_all(p)
            .await?;
            rs.into_iter()
                .map(|r| RawAudit {
                    seq: r.get::<i64, _>("seq") as u64,
                    ts: r.get("ts"),
                    actor_type: r.get("actor_type"),
                    actor_id: r.get("actor_id"),
                    action: r.get("action"),
                    resource_type: r.get("resource_type"),
                    resource_id: r.get("resource_id"),
                    diff_json: r.get("diff_json"),
                    prev_hash: r.get("prev_hash"),
                    entry_hash: r.get("entry_hash"),
                })
                .collect()
        });

        let mut expected_prev = GENESIS_AUDIT_HASH.to_owned();
        for (expected_seq, r) in (1u64..).zip(rows.iter()) {
            if r.seq != expected_seq {
                return Ok(AuditChainVerification {
                    valid: false,
                    checked_entries: rows.len(),
                    first_tampered_seq: Some(expected_seq),
                    message: Some(format!(
                        "gap detected: expected seq {expected_seq}, found {}",
                        r.seq
                    )),
                });
            }
            if r.prev_hash != expected_prev {
                return Ok(AuditChainVerification {
                    valid: false,
                    checked_entries: rows.len(),
                    first_tampered_seq: Some(r.seq),
                    message: Some(format!("prev_hash mismatch at seq {}", r.seq)),
                });
            }
            let recomputed = compute_audit_hash(
                r.seq,
                &r.ts,
                &r.actor_type,
                &r.actor_id,
                &r.action,
                &r.resource_type,
                &r.resource_id,
                r.diff_json.as_deref(),
                &r.prev_hash,
            );
            if recomputed != r.entry_hash {
                return Ok(AuditChainVerification {
                    valid: false,
                    checked_entries: rows.len(),
                    first_tampered_seq: Some(r.seq),
                    message: Some(format!("entry_hash tampered at seq {}", r.seq)),
                });
            }
            expected_prev = r.entry_hash.clone();
        }

        Ok(AuditChainVerification {
            valid: true,
            checked_entries: rows.len(),
            first_tampered_seq: None,
            message: Some(format!(
                "verified {} hash-chained audit record(s) with zero tampering",
                rows.len()
            )),
        })
    }
}

// =============================================================================
// Internal Helpers
// =============================================================================

#[derive(Serialize, Deserialize)]
struct EncryptedEnvelopeSer {
    ciphertext_b64: String,
    nonce_b64: String,
    wrapped_dek_b64: String,
    dek_nonce_b64: String,
}

impl From<EncryptedEnvelope> for EncryptedEnvelopeSer {
    fn from(e: EncryptedEnvelope) -> Self {
        Self {
            ciphertext_b64: e.ciphertext_b64,
            nonce_b64: e.nonce_b64,
            wrapped_dek_b64: e.wrapped_dek_b64,
            dek_nonce_b64: e.dek_nonce_b64,
        }
    }
}

impl From<EncryptedEnvelopeSer> for EncryptedEnvelope {
    fn from(e: EncryptedEnvelopeSer) -> Self {
        Self {
            ciphertext_b64: e.ciphertext_b64,
            nonce_b64: e.nonce_b64,
            wrapped_dek_b64: e.wrapped_dek_b64,
            dek_nonce_b64: e.dek_nonce_b64,
        }
    }
}

async fn get_metadata(pool: &DbPool, key: &str) -> Result<Option<String>, ConsoleError> {
    let val = on_db!(pool, |p| {
        sqlx::query_scalar("SELECT value FROM console_metadata WHERE key = $1")
            .bind(key)
            .fetch_optional(p)
            .await?
    });
    Ok(val)
}

async fn set_metadata(pool: &DbPool, key: &str, value: &str) -> Result<(), ConsoleError> {
    let now = now_rfc3339();
    on_db!(pool, |p| {
        sqlx::query(
            "INSERT INTO console_metadata (key, value, updated_at) VALUES ($1, $2, $3)
             ON CONFLICT (key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at",
        )
        .bind(key)
        .bind(value)
        .bind(&now)
        .execute(p)
        .await?;
    });
    Ok(())
}

async fn run_pg_notify_bridge(pool: PgPool, bus: broadcast::Sender<ClusterBusEvent>) {
    loop {
        match PgListener::connect_with(&pool).await {
            Ok(mut listener) => {
                if let Err(err) = listener.listen(PG_NOTIFY_CHANNEL).await {
                    warn!(error = %err, "Postgres LISTEN failed; retrying");
                    tokio::time::sleep(Duration::from_secs(2)).await;
                    continue;
                }
                debug!("PostgreSQL LISTEN/NOTIFY control-event fanout active");
                while let Ok(notif) = listener.recv().await {
                    if let Ok(ev) = serde_json::from_str::<ClusterBusEvent>(notif.payload()) {
                        let _ = bus.send(ev);
                    }
                }
            }
            Err(err) => {
                warn!(error = %err, "Postgres listener connect failed; retrying");
            }
        }
        tokio::time::sleep(Duration::from_secs(2)).await;
    }
}

fn now_rfc3339() -> String {
    Utc::now().to_rfc3339()
}

fn check_if_match(if_match: Option<&str>, current_etag: &str) -> Result<(), ConsoleError> {
    let Some(expected) = if_match else {
        return Ok(());
    };
    let trimmed = expected.trim();
    if trimmed == "*" || trimmed == current_etag {
        return Ok(());
    }
    Err(ConsoleError::PreconditionFailed {
        expected: trimmed.to_owned(),
        actual: current_etag.to_owned(),
    })
}

fn validate_namespace(ns: &str) -> Result<(), ConsoleError> {
    if ns.is_empty()
        || ns.len() > 64
        || !ns.bytes().all(|b| {
            b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'.' | b'-' | b'_')
        })
    {
        return Err(ConsoleError::BadRequest(format!(
            "invalid Channel 2 namespace `{ns}`"
        )));
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn compute_audit_hash(
    seq: u64,
    ts: &str,
    actor_type: &str,
    actor_id: &str,
    action: &str,
    resource_type: &str,
    resource_id: &str,
    diff_json: Option<&str>,
    prev_hash: &str,
) -> String {
    let material = format!(
        "{seq}|{ts}|{actor_type}:{actor_id}|{action}|{resource_type}|{resource_id}|{}|{prev_hash}",
        diff_json.unwrap_or("")
    );
    sha256_hex(material.as_bytes())
}

#[allow(clippy::too_many_arguments)]
fn derive_node_status(
    last_hb_str: &str,
    cluster_updated_str: &str,
    now: DateTime<Utc>,
    active_revision: u64,
    active_digest: &str,
    target_revision: Option<u64>,
    target_digest: Option<&str>,
    last_reload_error: Option<&str>,
    synced_seqs: &BTreeMap<String, u64>,
    head_seqs: &BTreeMap<String, u64>,
) -> NodeStatus {
    let hb_age_secs = DateTime::parse_from_rfc3339(last_hb_str)
        .map(|dt| (now - dt.with_timezone(&Utc)).num_seconds())
        .unwrap_or(9999);
    if hb_age_secs > 60 {
        return NodeStatus::Offline;
    }
    if last_reload_error.is_some() {
        return NodeStatus::Drifted;
    }
    if let Some(target_rev) = target_revision {
        let digest_ok = match target_digest {
            Some(td) if !td.is_empty() && !active_digest.is_empty() => {
                active_digest
                    .strip_prefix("sha256:")
                    .unwrap_or(active_digest)
                    == td.strip_prefix("sha256:").unwrap_or(td)
            }
            _ => true,
        };
        if active_revision != target_rev || !digest_ok {
            let cluster_age = DateTime::parse_from_rfc3339(cluster_updated_str)
                .map(|dt| (now - dt.with_timezone(&Utc)).num_seconds())
                .unwrap_or(999);
            if cluster_age <= 30 {
                return NodeStatus::Converging;
            }
            return NodeStatus::Drifted;
        }
    }
    for (ns, head) in head_seqs {
        if *head > 0 && synced_seqs.get(ns).copied().unwrap_or(0) < *head {
            return NodeStatus::Lagging;
        }
    }
    NodeStatus::Synced
}

fn collect_secret_slugs_in_toml(toml_src: &str, out: &mut Vec<String>) {
    if let Ok(val) = toml::from_str::<toml::Value>(toml_src) {
        collect_secret_slugs_in_toml_val(&val, out);
    }
}

fn collect_secret_slugs_in_toml_val(val: &toml::Value, out: &mut Vec<String>) {
    match val {
        toml::Value::String(s) => {
            if let Some(slug) = s.strip_prefix("secret:") {
                out.push(slug.trim().to_owned());
            }
        }
        toml::Value::Array(arr) => {
            for item in arr {
                collect_secret_slugs_in_toml_val(item, out);
            }
        }
        toml::Value::Table(tbl) => {
            for (_, v) in tbl {
                collect_secret_slugs_in_toml_val(v, out);
            }
        }
        _ => {}
    }
}

fn row_to_cluster<R: Row>(r: R) -> Cluster
where
    for<'a> &'a str: sqlx::ColumnIndex<R>,
    for<'a> String: sqlx::Decode<'a, R::Database> + sqlx::Type<R::Database>,
{
    let rings_json: String = r.get("ring_assignments_json");
    Cluster {
        id: r.get("id"),
        org_id: r.get("org_id"),
        slug: r.get("slug"),
        name: r.get("name"),
        description: r.get("description"),
        environment: r.get("environment"),
        ring_assignments: serde_json::from_str(&rings_json).unwrap_or_default(),
        etag: r.get("etag"),
        created_at: r.get("created_at"),
        updated_at: r.get("updated_at"),
    }
}

fn row_to_secret_meta<R: Row>(r: R) -> SecretMeta
where
    for<'a> &'a str: sqlx::ColumnIndex<R>,
    for<'a> String: sqlx::Decode<'a, R::Database> + sqlx::Type<R::Database>,
    for<'a> Option<String>: sqlx::Decode<'a, R::Database> + sqlx::Type<R::Database>,
    for<'a> i64: sqlx::Decode<'a, R::Database> + sqlx::Type<R::Database>,
{
    SecretMeta {
        id: r.get("id"),
        org_id: r.get("org_id"),
        scope_type: SecretScopeType::parse(&r.get::<String, _>("scope_type"))
            .unwrap_or(SecretScopeType::Org),
        scope_id: r.get("scope_id"),
        slug: r.get("slug"),
        description: r.get("description"),
        delivery_mode: SecretDeliveryMode::parse(&r.get::<String, _>("delivery_mode"))
            .unwrap_or(SecretDeliveryMode::Vault),
        env_var_name: r.get("env_var_name"),
        key_version: r.get("key_version"),
        metadata: serde_json::from_str(&r.get::<String, _>("metadata_json")).unwrap_or_default(),
        etag: r.get("etag"),
        created_at: r.get("created_at"),
        updated_at: r.get("updated_at"),
    }
}

fn row_to_topology_resource<R: Row>(r: R) -> TopologyResource
where
    for<'a> &'a str: sqlx::ColumnIndex<R>,
    for<'a> String: sqlx::Decode<'a, R::Database> + sqlx::Type<R::Database>,
    for<'a> i64: sqlx::Decode<'a, R::Database> + sqlx::Type<R::Database>,
{
    TopologyResource {
        id: r.get("id"),
        cluster_id: r.get("cluster_id"),
        kind: TopologyResourceKind::parse(&r.get::<String, _>("kind"))
            .unwrap_or(TopologyResourceKind::Route),
        slug: r.get("slug"),
        sort_order: r.get("sort_order"),
        version: r.get("version"),
        etag: r.get("etag"),
        spec: serde_json::from_str(&r.get::<String, _>("spec_json")).unwrap_or(Value::Null),
        draft_state: r.get("draft_state"),
        updated_by: r.get("updated_by"),
        created_at: r.get("created_at"),
        updated_at: r.get("updated_at"),
    }
}

fn row_to_topology_revision<R: Row>(r: R) -> TopologyRevision
where
    for<'a> &'a str: sqlx::ColumnIndex<R>,
    for<'a> String: sqlx::Decode<'a, R::Database> + sqlx::Type<R::Database>,
    for<'a> i64: sqlx::Decode<'a, R::Database> + sqlx::Type<R::Database>,
{
    TopologyRevision {
        id: r.get("id"),
        cluster_id: r.get("cluster_id"),
        revision: r.get::<i64, _>("revision") as u64,
        digest: r.get("digest"),
        compiled_toml: r.get("compiled_toml"),
        verify_report: serde_json::from_str(&r.get::<String, _>("verify_report_json"))
            .unwrap_or_default(),
        signature_b64: r.get("signature_b64"),
        ring_assignments: serde_json::from_str(&r.get::<String, _>("ring_assignments_json"))
            .unwrap_or_default(),
        notes: r.get("notes"),
        published_by: r.get("published_by"),
        created_at: r.get("created_at"),
    }
}

fn row_to_control_event<R: Row>(r: R) -> ControlEvent
where
    for<'a> &'a str: sqlx::ColumnIndex<R>,
    for<'a> String: sqlx::Decode<'a, R::Database> + sqlx::Type<R::Database>,
    for<'a> Option<String>: sqlx::Decode<'a, R::Database> + sqlx::Type<R::Database>,
    for<'a> i64: sqlx::Decode<'a, R::Database> + sqlx::Type<R::Database>,
{
    let payload_opt: Option<String> = r.get("payload_json");
    ControlEvent {
        seq: r.get::<i64, _>("seq") as u64,
        cluster_id: r.get("cluster_id"),
        namespace: r.get("namespace"),
        item_key: r.get("item_key"),
        op: r.get("op"),
        payload: payload_opt.and_then(|s| serde_json::from_str(&s).ok()),
        created_at: r.get("created_at"),
    }
}

fn row_to_oidc_provider<R: Row>(r: R) -> OidcProviderRecord
where
    for<'a> &'a str: sqlx::ColumnIndex<R>,
    for<'a> String: sqlx::Decode<'a, R::Database> + sqlx::Type<R::Database>,
    for<'a> Option<String>: sqlx::Decode<'a, R::Database> + sqlx::Type<R::Database>,
    for<'a> i64: sqlx::Decode<'a, R::Database> + sqlx::Type<R::Database>,
{
    OidcProviderRecord {
        id: r.get("id"),
        org_id: r.get("org_id"),
        slug: r.get("slug"),
        display_name: r.get("display_name"),
        issuer_url: r.get("issuer_url"),
        client_id: r.get("client_id"),
        client_secret_ref: r.get("client_secret_ref"),
        scopes: r.get("scopes"),
        group_claim: r.get("group_claim"),
        role_mappings: serde_json::from_str(&r.get::<String, _>("role_mappings_json"))
            .unwrap_or_default(),
        enabled: r.get::<i64, _>("enabled") != 0,
        etag: r.get("etag"),
        created_at: r.get("created_at"),
        updated_at: r.get("updated_at"),
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    async fn memory_store() -> ConsoleStore {
        ConsoleStore::connect(ConsoleStoreConfig {
            database_url: "sqlite::memory:".to_owned(),
            master_key_encoded: None,
        })
        .await
        .unwrap()
    }

    #[tokio::test]
    async fn sqlite_bootstrap_vault_channel2_and_audit_chain_verify() {
        let store = memory_store().await;
        assert!(!store.system_status().await.unwrap().initialized);

        let boot = store
            .initial_bootstrap(InitialBootstrapInput {
                admin_email: "admin@acme.dev".to_owned(),
                admin_name: "Alice Admin".to_owned(),
                admin_password: "correct-horse-battery".to_owned(),
                org_slug: "acme".to_owned(),
                org_name: "Acme Corp".to_owned(),
                cluster_slug: "prod-us".to_owned(),
                cluster_name: "Prod US".to_owned(),
                environment: "production".to_owned(),
                import_toml: None,
                auto_publish: true,
            })
            .await
            .unwrap();

        assert!(store.system_status().await.unwrap().initialized);
        assert_eq!(boot.initial_revision.as_ref().unwrap().revision, 1);

        let dup = store
            .initial_bootstrap(InitialBootstrapInput {
                admin_email: "other@acme.dev".to_owned(),
                admin_name: "Bob".to_owned(),
                admin_password: "correct-horse-battery".to_owned(),
                org_slug: "other".to_owned(),
                org_name: "Other".to_owned(),
                cluster_slug: "dev".to_owned(),
                cluster_name: "Dev".to_owned(),
                environment: "dev".to_owned(),
                import_toml: None,
                auto_publish: false,
            })
            .await;
        assert!(matches!(dup, Err(ConsoleError::Conflict(_))));

        let actor = AuditActor::system("test");
        let sec = store
            .upsert_secret(
                &boot.organization.id,
                "openai-key",
                UpsertSecretInput {
                    description: "OpenAI prod key".to_owned(),
                    scope_type: SecretScopeType::Org,
                    scope_id: boot.organization.id.clone(),
                    delivery_mode: SecretDeliveryMode::Vault,
                    value: Some("sk-super-secret".to_owned()),
                    env_var_name: None,
                    metadata: None,
                },
                None,
                &actor,
            )
            .await
            .unwrap();
        assert_eq!(sec.key_version, 1);
        let resolved = store
            .resolve_secret_for_cluster(&boot.organization.id, &boot.cluster.id, "openai-key")
            .await
            .unwrap();
        assert_eq!(resolved, "sk-super-secret");

        let conflict = store
            .upsert_secret(
                &boot.organization.id,
                "openai-key",
                UpsertSecretInput {
                    description: "updated".to_owned(),
                    scope_type: SecretScopeType::Org,
                    scope_id: boot.organization.id.clone(),
                    delivery_mode: SecretDeliveryMode::Vault,
                    value: Some("sk-rotated".to_owned()),
                    env_var_name: None,
                    metadata: None,
                },
                Some("\"stale-etag\""),
                &actor,
            )
            .await;
        assert!(matches!(
            conflict,
            Err(ConsoleError::PreconditionFailed { .. })
        ));

        let ev1 = store
            .upsert_synced_state(
                &boot.cluster.id,
                "ai.virtual_keys",
                "vk_1",
                json!({"enabled": true}),
                &actor,
            )
            .await
            .unwrap();
        let ev2 = store
            .upsert_synced_state(
                &boot.cluster.id,
                "ai.virtual_keys",
                "vk_2",
                json!({"enabled": true}),
                &actor,
            )
            .await
            .unwrap();
        assert!(ev2.seq > ev1.seq);

        let deltas = store
            .replay_namespace_deltas(&boot.cluster.id, "ai.virtual_keys", ev1.seq)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(deltas.len(), 1);
        assert_eq!(deltas[0].item_key, "vk_2");

        store
            .compact_control_events(&boot.cluster.id, "ai.virtual_keys", ev2.seq)
            .await
            .unwrap();
        let ev3 = store
            .upsert_synced_state(
                &boot.cluster.id,
                "ai.virtual_keys",
                "vk_3",
                json!({"enabled": true}),
                &actor,
            )
            .await
            .unwrap();
        assert!(ev3.seq > ev2.seq);
        let gap = store
            .replay_namespace_deltas(&boot.cluster.id, "ai.virtual_keys", ev1.seq)
            .await
            .unwrap();
        assert!(gap.is_none());
        let (head, full) = store
            .get_namespace_full_sync(&boot.cluster.id, "ai.virtual_keys")
            .await
            .unwrap();
        assert_eq!(head, ev3.seq);
        assert_eq!(full.len(), 3);

        let verification = store.verify_admin_audit_chain().await.unwrap();
        assert!(verification.valid, "{verification:?}");
        assert!(verification.checked_entries >= 5);
    }
}
