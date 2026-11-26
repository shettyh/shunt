-- shunt-console initial schema (PostgreSQL)

CREATE TABLE IF NOT EXISTS console_metadata (
    key        TEXT PRIMARY KEY NOT NULL,
    value      TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS organizations (
    id         TEXT PRIMARY KEY NOT NULL,
    slug       TEXT NOT NULL UNIQUE,
    name       TEXT NOT NULL,
    etag       TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS teams (
    id         TEXT PRIMARY KEY NOT NULL,
    org_id     TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    slug       TEXT NOT NULL,
    name       TEXT NOT NULL,
    etag       TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    UNIQUE(org_id, slug)
);

CREATE TABLE IF NOT EXISTS users (
    id            TEXT PRIMARY KEY NOT NULL,
    email         TEXT NOT NULL UNIQUE,
    display_name  TEXT NOT NULL,
    password_hash TEXT,
    auth_provider TEXT NOT NULL DEFAULT 'local',
    oidc_subject  TEXT,
    active        BIGINT NOT NULL DEFAULT 1,
    created_at    TEXT NOT NULL,
    updated_at    TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS sessions (
    id         TEXT PRIMARY KEY NOT NULL,
    token_hash TEXT NOT NULL UNIQUE,
    user_id    TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    expires_at TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_sessions_expires ON sessions(expires_at);

CREATE TABLE IF NOT EXISTS oidc_providers (
    id                 TEXT PRIMARY KEY NOT NULL,
    org_id             TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    slug               TEXT NOT NULL,
    display_name       TEXT NOT NULL,
    issuer_url         TEXT NOT NULL,
    client_id          TEXT NOT NULL,
    client_secret_ref  TEXT,
    scopes             TEXT NOT NULL DEFAULT 'openid email profile',
    group_claim        TEXT NOT NULL DEFAULT 'groups',
    role_mappings_json TEXT NOT NULL DEFAULT '{}',
    enabled            BIGINT NOT NULL DEFAULT 1,
    etag               TEXT NOT NULL,
    created_at         TEXT NOT NULL,
    updated_at         TEXT NOT NULL,
    UNIQUE(org_id, slug)
);

CREATE TABLE IF NOT EXISTS oidc_auth_states (
    state         TEXT PRIMARY KEY NOT NULL,
    provider_id   TEXT NOT NULL REFERENCES oidc_providers(id) ON DELETE CASCADE,
    pkce_verifier TEXT NOT NULL,
    nonce         TEXT NOT NULL,
    redirect_to   TEXT NOT NULL,
    expires_at    TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS role_bindings (
    id         TEXT PRIMARY KEY NOT NULL,
    user_id    TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    org_id     TEXT REFERENCES organizations(id) ON DELETE CASCADE,
    cluster_id TEXT,
    role       TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_role_bindings_user ON role_bindings(user_id);

CREATE TABLE IF NOT EXISTS api_tokens (
    id           TEXT PRIMARY KEY NOT NULL,
    org_id       TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    name         TEXT NOT NULL,
    token_hash   TEXT NOT NULL UNIQUE,
    prefix       TEXT NOT NULL,
    role         TEXT NOT NULL,
    cluster_id   TEXT,
    created_by   TEXT NOT NULL,
    expires_at   TEXT,
    last_used_at TEXT,
    revoked_at   TEXT,
    created_at   TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS clusters (
    id                    TEXT PRIMARY KEY NOT NULL,
    org_id                TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    slug                  TEXT NOT NULL UNIQUE,
    name                  TEXT NOT NULL,
    description           TEXT NOT NULL DEFAULT '',
    environment           TEXT NOT NULL DEFAULT 'production',
    ring_assignments_json TEXT NOT NULL DEFAULT '{}',
    etag                  TEXT NOT NULL,
    created_at            TEXT NOT NULL,
    updated_at            TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS node_bootstrap_tokens (
    id                  TEXT PRIMARY KEY NOT NULL,
    cluster_id          TEXT NOT NULL REFERENCES clusters(id) ON DELETE CASCADE,
    name                TEXT NOT NULL,
    token_hash          TEXT NOT NULL UNIQUE,
    prefix              TEXT NOT NULL,
    default_labels_json TEXT NOT NULL DEFAULT '{}',
    max_uses            BIGINT,
    uses_count          BIGINT NOT NULL DEFAULT 0,
    expires_at          TEXT,
    revoked_at          TEXT,
    created_by          TEXT NOT NULL,
    created_at          TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS nodes (
    id                TEXT PRIMARY KEY NOT NULL,
    cluster_id        TEXT NOT NULL REFERENCES clusters(id) ON DELETE CASCADE,
    name              TEXT NOT NULL,
    token_hash        TEXT NOT NULL UNIQUE,
    shunt_version     TEXT NOT NULL,
    labels_json       TEXT NOT NULL DEFAULT '{}',
    active_revision   BIGINT NOT NULL DEFAULT 0,
    active_digest     TEXT NOT NULL DEFAULT '',
    last_reload_error TEXT,
    synced_seqs_json  TEXT NOT NULL DEFAULT '{}',
    status_json       TEXT NOT NULL DEFAULT '{}',
    last_heartbeat_at TEXT NOT NULL,
    created_at        TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_nodes_cluster ON nodes(cluster_id);

CREATE TABLE IF NOT EXISTS secrets (
    id            TEXT PRIMARY KEY NOT NULL,
    org_id        TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    scope_type    TEXT NOT NULL,
    scope_id      TEXT NOT NULL,
    slug          TEXT NOT NULL,
    description   TEXT NOT NULL DEFAULT '',
    delivery_mode TEXT NOT NULL,
    env_var_name  TEXT,
    ciphertext    TEXT,
    nonce         TEXT,
    wrapped_dek   TEXT,
    dek_nonce     TEXT,
    key_version   BIGINT NOT NULL DEFAULT 1,
    metadata_json TEXT NOT NULL DEFAULT '{}',
    etag          TEXT NOT NULL,
    created_at    TEXT NOT NULL,
    updated_at    TEXT NOT NULL,
    UNIQUE(org_id, scope_type, scope_id, slug)
);

CREATE TABLE IF NOT EXISTS topology_resources (
    id          TEXT PRIMARY KEY NOT NULL,
    cluster_id  TEXT NOT NULL REFERENCES clusters(id) ON DELETE CASCADE,
    kind        TEXT NOT NULL,
    slug        TEXT NOT NULL,
    sort_order  BIGINT NOT NULL DEFAULT 0,
    version     BIGINT NOT NULL DEFAULT 1,
    etag        TEXT NOT NULL,
    spec_json   TEXT NOT NULL,
    draft_state TEXT NOT NULL DEFAULT 'active',
    updated_by  TEXT NOT NULL,
    created_at  TEXT NOT NULL,
    updated_at  TEXT NOT NULL,
    UNIQUE(cluster_id, kind, slug)
);
CREATE INDEX IF NOT EXISTS idx_topology_resources_cluster ON topology_resources(cluster_id, kind, sort_order);

CREATE TABLE IF NOT EXISTS topology_revisions (
    id                    TEXT PRIMARY KEY NOT NULL,
    cluster_id            TEXT NOT NULL REFERENCES clusters(id) ON DELETE CASCADE,
    revision              BIGINT NOT NULL,
    digest                TEXT NOT NULL,
    compiled_toml         TEXT NOT NULL,
    verify_report_json    TEXT NOT NULL,
    signature_b64         TEXT NOT NULL,
    ring_assignments_json TEXT NOT NULL DEFAULT '{}',
    notes                 TEXT NOT NULL DEFAULT '',
    published_by          TEXT NOT NULL,
    created_at            TEXT NOT NULL,
    UNIQUE(cluster_id, revision)
);
CREATE INDEX IF NOT EXISTS idx_topology_revisions_cluster ON topology_revisions(cluster_id, revision DESC);

CREATE TABLE IF NOT EXISTS control_events (
    seq          BIGSERIAL PRIMARY KEY,
    cluster_id   TEXT NOT NULL REFERENCES clusters(id) ON DELETE CASCADE,
    namespace    TEXT NOT NULL,
    item_key     TEXT NOT NULL,
    op           TEXT NOT NULL,
    payload_json TEXT,
    created_at   TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_control_events_cluster_ns_seq ON control_events(cluster_id, namespace, seq);

CREATE TABLE IF NOT EXISTS control_state_current (
    cluster_id   TEXT NOT NULL REFERENCES clusters(id) ON DELETE CASCADE,
    namespace    TEXT NOT NULL,
    item_key     TEXT NOT NULL,
    seq          BIGINT NOT NULL,
    payload_json TEXT NOT NULL,
    updated_at   TEXT NOT NULL,
    PRIMARY KEY (cluster_id, namespace, item_key)
);

CREATE TABLE IF NOT EXISTS admin_audit_log (
    seq           BIGSERIAL PRIMARY KEY,
    ts            TEXT NOT NULL,
    actor_type    TEXT NOT NULL,
    actor_id      TEXT NOT NULL,
    actor_ip      TEXT,
    org_id        TEXT,
    cluster_id    TEXT,
    action        TEXT NOT NULL,
    resource_type TEXT NOT NULL,
    resource_id   TEXT NOT NULL,
    diff_json     TEXT,
    prev_hash     TEXT NOT NULL,
    entry_hash    TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_admin_audit_ts ON admin_audit_log(seq DESC);
