use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use arc_swap::ArcSwap;
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};
use shunt_plugin_sdk::{
    BufferedResponse, BuildContext, Clock, Flow, HeaderName, HeaderValue, HookMask, HookResult,
    HttpPlugin, Method, PluginBuildError, PluginConfig, PluginFactory, RequestCtx, RequestHead,
    ResponseHead, StatusCode, SyncedTableSnapshot, header,
};
use tracing::warn;

use crate::types::{
    MCP_ERR_FORBIDDEN, MCP_ERR_UNAUTHORIZED, MCP_SESSION_HEADER, McpPrincipal, get_header_str,
    jsonrpc_error_response, resolve_env_secret,
};

const DEFAULT_SESSION_BIND_TTL_SECS: u64 = 3_600;
const DEFAULT_MAX_SESSION_BINDINGS: usize = 16_384;

fn default_true() -> bool {
    true
}

fn default_session_bind_ttl_secs() -> u64 {
    DEFAULT_SESSION_BIND_TTL_SECS
}

fn default_max_session_bindings() -> usize {
    DEFAULT_MAX_SESSION_BINDINGS
}

fn default_oauth_metadata_path() -> String {
    "/.well-known/oauth-protected-resource".to_owned()
}

/// Optional RFC 9728 OAuth 2.0 Protected Resource Metadata served by `mcp-auth`
/// (required by MCP 2025-06+ OAuth discovery flows).
#[derive(Debug, Clone, Deserialize)]
struct OAuthProtectedResourceConfig {
    /// Path to serve metadata on (default: `"/.well-known/oauth-protected-resource"`).
    #[serde(default = "default_oauth_metadata_path")]
    path: String,
    /// Canonical resource identifier URL (e.g., `"https://mcp.example.com/mcp"`).
    resource: String,
    /// Authorization server issuer URLs.
    #[serde(default)]
    authorization_servers: Vec<String>,
    /// Supported OAuth scopes.
    #[serde(default)]
    scopes_supported: Vec<String>,
    /// Supported bearer token methods (default: `["header"]`).
    #[serde(default)]
    bearer_methods_supported: Vec<String>,
}

/// Configured MCP virtual key or principal policy entry.
#[derive(Debug, Deserialize)]
struct McpPrincipalEntryConfig {
    /// Stable principal identifier (matches virtual key ID or forwarded `identity_header` value).
    id: String,
    /// Optional secret key: plaintext, `"env:VAR_NAME"`, or `"sha256:<64-hex>"`.
    /// Named `api_key` so `GET /snapshot` automatically redacts it.
    /// May be omitted when authenticating via `identity_header` (e.g. `jwt-auth` / `mtls-auth`).
    #[serde(default)]
    api_key: Option<String>,
    #[serde(default)]
    team: Option<String>,
    #[serde(default)]
    agent_id: Option<String>,
    #[serde(default = "default_true")]
    enabled: bool,
    #[serde(default)]
    allowed_servers: Vec<String>,
    #[serde(default)]
    allowed_tools: Vec<String>,
    #[serde(default)]
    denied_tools: Vec<String>,
    #[serde(default)]
    allowed_resources: Vec<String>,
    #[serde(default)]
    allowed_prompts: Vec<String>,
    #[serde(default)]
    allowed_methods: Vec<String>,
    #[serde(default)]
    rpm: Option<u64>,
    #[serde(default)]
    tool_rpm: Option<u64>,
    #[serde(default)]
    max_calls_per_session: Option<u64>,
    #[serde(default)]
    max_parallel_calls: Option<u64>,
    #[serde(default)]
    metadata: BTreeMap<String, String>,
}

#[derive(Debug, Deserialize)]
#[serde(default)]
struct McpAuthConfig {
    /// Strip client key headers after verification so upstream MCP servers never see them.
    #[serde(default = "default_true")]
    strip_key_header: bool,
    /// Accept `Authorization: Bearer <key>`.
    #[serde(default = "default_true")]
    accept_bearer: bool,
    /// Accept `x-mcp-api-key: <key>`.
    #[serde(default = "default_true")]
    accept_x_mcp_api_key: bool,
    /// Optional custom header to extract API key from.
    #[serde(default)]
    custom_header: Option<String>,
    /// Optional trusted identity header populated by an earlier auth plugin
    /// (e.g., `"x-shunt-jwt-sub"` from `jwt-auth` or `"x-shunt-mtls-cn"` from `mtls-auth`).
    #[serde(default)]
    identity_header: Option<String>,
    /// Optional fallback policy applied to authenticated identities not explicitly listed in `keys`
    /// when `identity_header` is used.
    #[serde(default)]
    allow_unlisted_identities: bool,
    /// Bind every observed `Mcp-Session-Id` to the authenticated principal ID to prevent
    /// cross-agent / cross-tenant session hijacking (default: true).
    #[serde(default = "default_true")]
    bind_session_to_principal: bool,
    /// TTL in seconds for session-to-principal bindings (default: 3600).
    #[serde(default = "default_session_bind_ttl_secs")]
    session_bind_ttl_secs: u64,
    /// Maximum tracked session bindings in memory (bounded against cardinality DoS).
    #[serde(default = "default_max_session_bindings")]
    max_session_bindings: usize,
    /// Optional RFC 9728 OAuth Protected Resource Metadata endpoint.
    #[serde(default)]
    oauth_protected_resource: Option<OAuthProtectedResourceConfig>,
    /// Optional Channel 2 `SyncedTable` namespace (e.g. `"mcp.agent_acls"`) supplying live
    /// fleet-wide agent keys & ACLs without reloading topology.
    #[serde(default)]
    sync_namespace: Option<String>,
    /// Optional Channel 2 `SyncedTable` namespace (e.g. `"mcp.kill_switch"`) supplying instant
    /// fleet-wide principal/session emergency blocks.
    #[serde(default)]
    kill_switch_namespace: Option<String>,
    /// Configured virtual keys / principal policies.
    #[serde(default)]
    keys: Vec<McpPrincipalEntryConfig>,
}

impl Default for McpAuthConfig {
    fn default() -> Self {
        Self {
            strip_key_header: true,
            accept_bearer: true,
            accept_x_mcp_api_key: true,
            custom_header: None,
            identity_header: None,
            allow_unlisted_identities: false,
            bind_session_to_principal: true,
            session_bind_ttl_secs: DEFAULT_SESSION_BIND_TTL_SECS,
            max_session_bindings: DEFAULT_MAX_SESSION_BINDINGS,
            oauth_protected_resource: None,
            sync_namespace: None,
            kill_switch_namespace: None,
            keys: Vec::new(),
        }
    }
}

#[derive(Debug, Deserialize)]
struct SyncedMcpAgentPayload {
    #[serde(default)]
    id: Option<String>,
    #[serde(default)]
    api_key: Option<String>,
    #[serde(default)]
    key_hashes: Vec<String>,
    #[serde(default)]
    team: Option<String>,
    #[serde(default)]
    agent_id: Option<String>,
    #[serde(default = "default_true")]
    enabled: bool,
    #[serde(default)]
    allowed_servers: Vec<String>,
    #[serde(default)]
    allowed_tools: Vec<String>,
    #[serde(default)]
    denied_tools: Vec<String>,
    #[serde(default)]
    allowed_resources: Vec<String>,
    #[serde(default)]
    allowed_prompts: Vec<String>,
    #[serde(default)]
    allowed_methods: Vec<String>,
    #[serde(default)]
    rpm: Option<u64>,
    #[serde(default)]
    tool_rpm: Option<u64>,
    #[serde(default)]
    max_calls_per_session: Option<u64>,
    #[serde(default)]
    max_parallel_calls: Option<u64>,
    #[serde(default)]
    metadata: BTreeMap<String, String>,
}

#[derive(Debug, Default)]
struct SyncedMcpAuthIndex {
    keys: Vec<CompiledKey>,
    by_id: HashMap<String, McpPrincipal>,
}

#[derive(Debug, Clone, Deserialize)]
struct KillSwitchRule {
    scope: String,
    target: String,
    #[serde(default)]
    reason: Option<String>,
}

fn compile_synced_mcp_agents(snapshot: &SyncedTableSnapshot) -> SyncedMcpAuthIndex {
    let mut index = SyncedMcpAuthIndex::default();
    for (item_key, raw_val) in snapshot.iter() {
        let entry: SyncedMcpAgentPayload = match serde_json::from_value((**raw_val).clone()) {
            Ok(e) => e,
            Err(err) => {
                warn!(key = %item_key, error = %err, "ignoring malformed synced mcp.agent_acls entry");
                continue;
            }
        };
        let id = entry
            .id
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .unwrap_or(item_key.as_ref())
            .to_owned();
        let principal = McpPrincipal {
            id: id.clone(),
            team: entry.team,
            agent_id: entry.agent_id,
            allowed_servers: entry.allowed_servers,
            allowed_tools: entry.allowed_tools,
            denied_tools: entry.denied_tools,
            allowed_resources: entry.allowed_resources,
            allowed_prompts: entry.allowed_prompts,
            allowed_methods: entry.allowed_methods,
            rpm: entry.rpm,
            tool_rpm: entry.tool_rpm,
            max_calls_per_session: entry.max_calls_per_session,
            max_parallel_calls: entry.max_parallel_calls,
            metadata: entry.metadata,
        };
        for raw in &entry.key_hashes {
            if let Ok(hash) = compile_key_hash(raw) {
                index.keys.push(CompiledKey {
                    hash,
                    enabled: entry.enabled,
                    principal: principal.clone(),
                });
            }
        }
        if let Some(ref single) = entry.api_key
            && let Ok(hash) = compile_key_hash(single)
        {
            index.keys.push(CompiledKey {
                hash,
                enabled: entry.enabled,
                principal: principal.clone(),
            });
        }
        if entry.enabled {
            index.by_id.insert(id, principal);
        }
    }
    index
}

fn compile_kill_switches(snapshot: &SyncedTableSnapshot) -> Vec<KillSwitchRule> {
    let mut rules = Vec::with_capacity(snapshot.len());
    for (item_key, raw_val) in snapshot.iter() {
        match serde_json::from_value::<KillSwitchRule>((**raw_val).clone()) {
            Ok(rule) if !rule.scope.trim().is_empty() && !rule.target.trim().is_empty() => {
                rules.push(rule);
            }
            Ok(_) => {}
            Err(err) => {
                warn!(key = %item_key, error = %err, "ignoring malformed synced mcp.kill_switch entry");
            }
        }
    }
    rules
}

#[derive(Debug, Clone)]
struct BoundSessionEntry {
    principal_id: String,
    expires_at: Duration,
}

/// Reload-persistent, bounded table binding `Mcp-Session-Id` values to authenticated principals
/// to prevent session hijacking across tenants or agents.
#[derive(Debug, Default)]
pub struct McpSessionBindingTable {
    entries: Mutex<HashMap<String, BoundSessionEntry>>,
}

/// Read-only snapshot of active session bindings for Admin Inspector `/api/status`.
#[derive(Debug, Clone, Serialize)]
pub struct SessionBindingStatsSnapshot {
    pub active_bindings: usize,
}

impl McpSessionBindingTable {
    pub fn check_or_bind(
        &self,
        session_id: &str,
        principal_id: &str,
        now: Duration,
        ttl: Duration,
        max_entries: usize,
    ) -> bool {
        let mut guard = self
            .entries
            .lock()
            .expect("McpSessionBindingTable poisoned");
        guard.retain(|_, v| v.expires_at > now);

        if let Some(existing) = guard.get_mut(session_id) {
            if existing.principal_id != principal_id {
                return false;
            }
            existing.expires_at = now.saturating_add(ttl);
            return true;
        }

        if guard.len() >= max_entries.max(1)
            && let Some(oldest_key) = guard
                .iter()
                .min_by_key(|(_, v)| v.expires_at)
                .map(|(k, _)| k.clone())
        {
            guard.remove(&oldest_key);
        }

        guard.insert(
            session_id.to_owned(),
            BoundSessionEntry {
                principal_id: principal_id.to_owned(),
                expires_at: now.saturating_add(ttl),
            },
        );
        true
    }

    pub fn remove(&self, session_id: &str) {
        let mut guard = self
            .entries
            .lock()
            .expect("McpSessionBindingTable poisoned");
        guard.remove(session_id);
    }

    pub fn active_count(&self, now: Duration) -> usize {
        let guard = self
            .entries
            .lock()
            .expect("McpSessionBindingTable poisoned");
        guard.values().filter(|v| v.expires_at > now).count()
    }
}

#[derive(Debug)]
struct CompiledKey {
    hash: [u8; 32],
    enabled: bool,
    principal: McpPrincipal,
}

struct CompiledOAuthMetadata {
    path: String,
    body: Vec<u8>,
    www_authenticate: HeaderValue,
}

/// Plugin factory for `mcp-auth`.
pub struct McpAuthFactory;

impl PluginFactory for McpAuthFactory {
    fn name(&self) -> &str {
        "mcp-auth"
    }

    fn build(
        &self,
        config: &PluginConfig,
        ctx: &BuildContext,
    ) -> Result<Arc<dyn HttpPlugin>, PluginBuildError> {
        let cfg: McpAuthConfig = config.deserialize(self.name())?;
        let sync_namespace = cfg
            .sync_namespace
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_owned);
        let kill_switch_namespace = cfg
            .kill_switch_namespace
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_owned);

        if cfg.keys.is_empty() && cfg.identity_header.is_none() && sync_namespace.is_none() {
            return Err(PluginBuildError::BuildFailed {
                plugin: self.name().to_owned(),
                message: "mcp-auth requires at least one entry in `keys`, an `identity_header`, or a `sync_namespace`"
                    .to_owned(),
            });
        }

        let custom_header = match cfg.custom_header {
            Some(ref h) => Some(HeaderName::from_bytes(h.as_bytes()).map_err(|e| {
                PluginBuildError::BuildFailed {
                    plugin: self.name().to_owned(),
                    message: format!("invalid custom_header `{h}`: {e}"),
                }
            })?),
            None => None,
        };

        let identity_header = match cfg.identity_header {
            Some(ref h) => Some(HeaderName::from_bytes(h.as_bytes()).map_err(|e| {
                PluginBuildError::BuildFailed {
                    plugin: self.name().to_owned(),
                    message: format!("invalid identity_header `{h}`: {e}"),
                }
            })?),
            None => None,
        };

        let mut compiled_keys = Vec::new();
        let mut by_id = HashMap::new();

        for entry in cfg.keys {
            if entry.id.trim().is_empty() {
                return Err(PluginBuildError::BuildFailed {
                    plugin: self.name().to_owned(),
                    message: "mcp-auth key entry `id` must not be empty".to_owned(),
                });
            }
            let principal = McpPrincipal {
                id: entry.id.clone(),
                team: entry.team,
                agent_id: entry.agent_id,
                allowed_servers: entry.allowed_servers,
                allowed_tools: entry.allowed_tools,
                denied_tools: entry.denied_tools,
                allowed_resources: entry.allowed_resources,
                allowed_prompts: entry.allowed_prompts,
                allowed_methods: entry.allowed_methods,
                rpm: entry.rpm,
                tool_rpm: entry.tool_rpm,
                max_calls_per_session: entry.max_calls_per_session,
                max_parallel_calls: entry.max_parallel_calls,
                metadata: entry.metadata,
            };

            if let Some(raw_key) = entry.api_key {
                let hash =
                    compile_key_hash(&raw_key).map_err(|msg| PluginBuildError::BuildFailed {
                        plugin: self.name().to_owned(),
                        message: format!("key `{}`: {msg}", entry.id),
                    })?;
                compiled_keys.push(CompiledKey {
                    hash,
                    enabled: entry.enabled,
                    principal: principal.clone(),
                });
            } else if identity_header.is_none() {
                return Err(PluginBuildError::BuildFailed {
                    plugin: self.name().to_owned(),
                    message: format!(
                        "key `{}` omits `api_key`, which is only allowed when `identity_header` is configured",
                        entry.id
                    ),
                });
            }

            if entry.enabled {
                by_id.insert(entry.id, principal);
            }
        }

        let oauth_metadata = match cfg.oauth_protected_resource {
            Some(meta) => {
                let bearer_methods = if meta.bearer_methods_supported.is_empty() {
                    vec!["header".to_owned()]
                } else {
                    meta.bearer_methods_supported
                };
                let doc = json!({
                    "resource": meta.resource,
                    "authorization_servers": meta.authorization_servers,
                    "scopes_supported": meta.scopes_supported,
                    "bearer_methods_supported": bearer_methods,
                });
                let body = serde_json::to_vec(&doc).map_err(|e| PluginBuildError::BuildFailed {
                    plugin: self.name().to_owned(),
                    message: format!("failed to serialize oauth_protected_resource: {e}"),
                })?;
                let resource_metadata_url = format!(
                    "{}{}",
                    meta.resource.trim_end_matches('/'),
                    if meta.path.starts_with('/') {
                        meta.path.clone()
                    } else {
                        format!("/{}", meta.path)
                    }
                );
                let www_val = format!("Bearer resource_metadata=\"{resource_metadata_url}\"");
                let www_authenticate =
                    HeaderValue::from_str(&www_val).map_err(|e| PluginBuildError::BuildFailed {
                        plugin: self.name().to_owned(),
                        message: format!("invalid WWW-Authenticate header: {e}"),
                    })?;
                Some(CompiledOAuthMetadata {
                    path: meta.path,
                    body,
                    www_authenticate,
                })
            }
            None => None,
        };

        let bindings = ctx
            .state_handle()
            .get_or_init("mcp-session-bindings", McpSessionBindingTable::default);

        let synced_index = sync_namespace.and_then(|ns| {
            ctx.synced_table(&ns).map(|table| {
                let store = Arc::new(ArcSwap::from_pointee(SyncedMcpAuthIndex::default()));
                let store_sub = Arc::clone(&store);
                table.subscribe(Arc::new(move |snap| {
                    store_sub.store(Arc::new(compile_synced_mcp_agents(snap)));
                }));
                store
            })
        });

        let kill_switches = kill_switch_namespace.and_then(|ns| {
            ctx.synced_table(&ns).map(|table| {
                let store = Arc::new(ArcSwap::from_pointee(Vec::<KillSwitchRule>::new()));
                let store_sub = Arc::clone(&store);
                table.subscribe(Arc::new(move |snap| {
                    store_sub.store(Arc::new(compile_kill_switches(snap)));
                }));
                store
            })
        });

        Ok(Arc::new(McpAuthPlugin {
            strip_key_header: cfg.strip_key_header,
            accept_bearer: cfg.accept_bearer,
            accept_x_mcp_api_key: cfg.accept_x_mcp_api_key,
            custom_header,
            identity_header,
            allow_unlisted_identities: cfg.allow_unlisted_identities,
            bind_session_to_principal: cfg.bind_session_to_principal,
            session_bind_ttl: Duration::from_secs(cfg.session_bind_ttl_secs.max(1)),
            max_session_bindings: cfg.max_session_bindings.max(1),
            oauth_metadata,
            keys: compiled_keys,
            by_id,
            synced_index,
            kill_switches,
            bindings,
            clock: ctx.clock(),
        }))
    }
}

/// MCP authentication, per-agent tool/resource/prompt ACL policy attachment, and session binding.
pub struct McpAuthPlugin {
    strip_key_header: bool,
    accept_bearer: bool,
    accept_x_mcp_api_key: bool,
    custom_header: Option<HeaderName>,
    identity_header: Option<HeaderName>,
    allow_unlisted_identities: bool,
    bind_session_to_principal: bool,
    session_bind_ttl: Duration,
    max_session_bindings: usize,
    oauth_metadata: Option<CompiledOAuthMetadata>,
    keys: Vec<CompiledKey>,
    by_id: HashMap<String, McpPrincipal>,
    synced_index: Option<Arc<ArcSwap<SyncedMcpAuthIndex>>>,
    kill_switches: Option<Arc<ArcSwap<Vec<KillSwitchRule>>>>,
    bindings: Arc<McpSessionBindingTable>,
    clock: Arc<dyn Clock>,
}

impl McpAuthPlugin {
    fn extract_api_key(&self, req: &mut RequestHead) -> Option<String> {
        if let Some(ref custom) = self.custom_header
            && let Some(val) = req
                .headers
                .get(custom)
                .and_then(|v| v.to_str().ok())
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(str::to_owned)
        {
            if self.strip_key_header {
                req.headers.remove(custom);
            }
            return Some(val);
        }

        if self.accept_x_mcp_api_key
            && let Some(val) = req
                .headers
                .get("x-mcp-api-key")
                .and_then(|v| v.to_str().ok())
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(str::to_owned)
        {
            if self.strip_key_header {
                req.headers.remove("x-mcp-api-key");
            }
            return Some(val);
        }

        if self.accept_bearer
            && let Some(auth) = req
                .headers
                .get(header::AUTHORIZATION)
                .and_then(|v| v.to_str().ok())
            && let Some(token) = auth
                .strip_prefix("Bearer ")
                .or_else(|| auth.strip_prefix("bearer "))
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(str::to_owned)
        {
            if self.strip_key_header {
                req.headers.remove(header::AUTHORIZATION);
            }
            return Some(token);
        }

        None
    }

    fn verify_key(&self, presented: &str) -> Option<(bool, McpPrincipal)> {
        let digest: [u8; 32] = Sha256::digest(presented.as_bytes()).into();
        let mut matched: Option<(bool, McpPrincipal)> = None;
        for entry in &self.keys {
            if constant_time_eq_32(&digest, &entry.hash) {
                matched = Some((entry.enabled, entry.principal.clone()));
            }
        }
        if let Some(ref synced) = self.synced_index {
            let guard = synced.load();
            for entry in &guard.keys {
                if constant_time_eq_32(&digest, &entry.hash) {
                    matched = Some((entry.enabled, entry.principal.clone()));
                }
            }
        }
        matched
    }

    fn lookup_by_id(&self, subject: &str) -> Option<McpPrincipal> {
        if let Some(ref synced) = self.synced_index
            && let Some(policy) = synced.load().by_id.get(subject)
        {
            return Some(policy.clone());
        }
        self.by_id.get(subject).cloned()
    }

    fn check_kill_switch(&self, principal_id: &str, session_id: Option<&str>) -> Option<String> {
        let ks = self.kill_switches.as_ref()?;
        let rules = ks.load();
        for rule in rules.iter() {
            let hit = match rule.scope.as_str() {
                "principal" => rule.target == "*" || rule.target == principal_id,
                "session" => session_id.is_some_and(|sid| rule.target == "*" || rule.target == sid),
                _ => false,
            };
            if hit {
                return Some(
                    rule.reason
                        .clone()
                        .unwrap_or_else(|| "blocked by security kill-switch".to_owned()),
                );
            }
        }
        None
    }

    fn unauthorized(&self, msg: &str) -> BufferedResponse {
        let mut resp = jsonrpc_error_response(
            StatusCode::UNAUTHORIZED,
            None,
            MCP_ERR_UNAUTHORIZED,
            msg,
            None,
        );
        if let Some(ref meta) = self.oauth_metadata {
            resp.headers
                .insert(header::WWW_AUTHENTICATE, meta.www_authenticate.clone());
        } else {
            resp.headers.insert(
                header::WWW_AUTHENTICATE,
                HeaderValue::from_static("Bearer realm=\"shunt-mcp\""),
            );
        }
        resp
    }
}

impl HttpPlugin for McpAuthPlugin {
    fn name(&self) -> &str {
        "mcp-auth"
    }

    fn hook_mask(&self) -> HookMask {
        let mut mask = HookMask::ON_REQUEST_HEADERS;
        if self.bind_session_to_principal {
            mask |= HookMask::ON_RESPONSE_HEADERS;
        }
        mask
    }

    fn on_request_headers<'a>(
        &'a self,
        ctx: &'a mut RequestCtx,
        req: &'a mut RequestHead,
    ) -> HookResult<'a, Flow> {
        // 1. Optional RFC 9728 OAuth Protected Resource Metadata endpoint (unauthenticated discovery)
        if let Some(ref meta) = self.oauth_metadata
            && req.method == Method::GET
            && req.uri.path() == meta.path
        {
            return HookResult::Ready(Flow::Respond(BufferedResponse::json(
                StatusCode::OK,
                meta.body.clone(),
            )));
        }

        // 2. Authenticate via trusted identity header (from jwt-auth / mtls-auth) OR virtual API key
        let principal = if let Some(ref id_hdr) = self.identity_header
            && let Some(subject) = req
                .headers
                .get(id_hdr)
                .and_then(|v| v.to_str().ok())
                .map(str::trim)
                .filter(|s| !s.is_empty())
        {
            if let Some(policy) = self.lookup_by_id(subject) {
                policy
            } else if self.allow_unlisted_identities {
                McpPrincipal {
                    id: subject.to_owned(),
                    team: None,
                    agent_id: None,
                    allowed_servers: Vec::new(),
                    allowed_tools: Vec::new(),
                    denied_tools: Vec::new(),
                    allowed_resources: Vec::new(),
                    allowed_prompts: Vec::new(),
                    allowed_methods: Vec::new(),
                    rpm: None,
                    tool_rpm: None,
                    max_calls_per_session: None,
                    max_parallel_calls: None,
                    metadata: BTreeMap::new(),
                }
            } else {
                return HookResult::Ready(Flow::Respond(jsonrpc_error_response(
                    StatusCode::FORBIDDEN,
                    None,
                    MCP_ERR_FORBIDDEN,
                    format!("authenticated identity `{subject}` is not authorized for MCP access"),
                    None,
                )));
            }
        } else {
            let Some(presented) = self.extract_api_key(req) else {
                return HookResult::Ready(Flow::Respond(
                    self.unauthorized("missing MCP authentication credentials"),
                ));
            };
            match self.verify_key(&presented) {
                Some((true, p)) => p,
                Some((false, _)) => {
                    return HookResult::Ready(Flow::Respond(jsonrpc_error_response(
                        StatusCode::FORBIDDEN,
                        None,
                        MCP_ERR_FORBIDDEN,
                        "MCP virtual key is disabled",
                        None,
                    )));
                }
                None => {
                    return HookResult::Ready(Flow::Respond(
                        self.unauthorized("invalid MCP authentication credentials"),
                    ));
                }
            }
        };

        // 2b. Check instant Channel 2 kill-switch rules for principal or session
        let incoming_session = get_header_str(&req.headers, MCP_SESSION_HEADER);
        if let Some(reason) = self.check_kill_switch(&principal.id, incoming_session) {
            return HookResult::Ready(Flow::Respond(jsonrpc_error_response(
                StatusCode::FORBIDDEN,
                None,
                MCP_ERR_FORBIDDEN,
                format!("MCP access halted by kill-switch: {reason}"),
                None,
            )));
        }

        // 3. Enforce session-to-principal binding on incoming `Mcp-Session-Id`
        if self.bind_session_to_principal
            && let Some(session_id) = get_header_str(&req.headers, MCP_SESSION_HEADER)
        {
            let now = self.clock.now();
            if req.method == Method::DELETE {
                let allowed = self.bindings.check_or_bind(
                    session_id,
                    &principal.id,
                    now,
                    self.session_bind_ttl,
                    self.max_session_bindings,
                );
                if !allowed {
                    return HookResult::Ready(Flow::Respond(jsonrpc_error_response(
                        StatusCode::FORBIDDEN,
                        None,
                        MCP_ERR_FORBIDDEN,
                        "Mcp-Session-Id belongs to a different authenticated principal",
                        None,
                    )));
                }
                self.bindings.remove(session_id);
            } else if !self.bindings.check_or_bind(
                session_id,
                &principal.id,
                now,
                self.session_bind_ttl,
                self.max_session_bindings,
            ) {
                return HookResult::Ready(Flow::Respond(jsonrpc_error_response(
                    StatusCode::FORBIDDEN,
                    None,
                    MCP_ERR_FORBIDDEN,
                    "Mcp-Session-Id belongs to a different authenticated principal",
                    None,
                )));
            }
        }

        ctx.insert_ext(principal);
        HookResult::Ready(Flow::Continue)
    }

    fn on_response_headers<'a>(
        &'a self,
        ctx: &'a mut RequestCtx,
        res: &'a mut ResponseHead,
    ) -> HookResult<'a, Flow> {
        if self.bind_session_to_principal
            && let Some(principal) = ctx.get_ext::<McpPrincipal>()
            && let Some(session_id) = get_header_str(&res.headers, MCP_SESSION_HEADER)
        {
            let now = self.clock.now();
            let _ = self.bindings.check_or_bind(
                session_id,
                &principal.id,
                now,
                self.session_bind_ttl,
                self.max_session_bindings,
            );
        }
        HookResult::Ready(Flow::Continue)
    }
}

fn compile_key_hash(raw: &str) -> Result<[u8; 32], String> {
    if let Some(hex_digest) = raw.strip_prefix("sha256:") {
        let bytes = hex_decode_32(hex_digest.trim())?;
        Ok(bytes)
    } else {
        let secret = resolve_env_secret(raw)?;
        if secret.is_empty() {
            return Err("api_key must not be empty".to_owned());
        }
        Ok(Sha256::digest(secret.as_bytes()).into())
    }
}

fn hex_decode_32(hex: &str) -> Result<[u8; 32], String> {
    if hex.len() != 64 {
        return Err(format!(
            "expected 64 hex chars for sha256 digest, got {}",
            hex.len()
        ));
    }
    let mut out = [0u8; 32];
    let b = hex.as_bytes();
    for i in 0..32 {
        let hi = hex_nibble(b[2 * i])
            .ok_or_else(|| "invalid hex character in sha256 digest".to_owned())?;
        let lo = hex_nibble(b[2 * i + 1])
            .ok_or_else(|| "invalid hex character in sha256 digest".to_owned())?;
        out[i] = (hi << 4) | lo;
    }
    Ok(out)
}

fn hex_nibble(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

fn constant_time_eq_32(a: &[u8; 32], b: &[u8; 32]) -> bool {
    let mut diff = 0u8;
    for i in 0..32 {
        diff |= a[i] ^ b[i];
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;
    use std::net::SocketAddr;
    use std::sync::RwLock;

    use shunt_plugin_sdk::{
        HeaderMap, StateStore, SyncedDeltaOp, SyncedTableRegistry, Uri, Version,
    };

    fn sha256_prefixed(raw: &str) -> String {
        let digest: [u8; 32] = Sha256::digest(raw.as_bytes()).into();
        let hex: String = digest.iter().map(|b| format!("{b:02x}")).collect();
        format!("sha256:{hex}")
    }

    fn mcp_req(token: &str) -> RequestHead {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::AUTHORIZATION,
            HeaderValue::from_str(&format!("Bearer {token}")).unwrap(),
        );
        RequestHead {
            method: Method::POST,
            uri: Uri::from_static("/mcp"),
            version: Version::HTTP_11,
            headers,
        }
    }

    fn test_ctx(id: u64) -> RequestCtx {
        let addr: SocketAddr = "127.0.0.1:12345".parse().unwrap();
        RequestCtx::new(id, addr, None)
    }

    #[test]
    fn synced_mcp_agents_and_kill_switch_apply_live() {
        let state = Arc::new(StateStore::new());
        let touched = Arc::new(RwLock::new(HashSet::new()));
        let synced = Arc::new(SyncedTableRegistry::new());
        let ctx = BuildContext::new("mcp-gateway", state, touched)
            .with_synced_tables(Some(Arc::clone(&synced)));
        let cfg = PluginConfig::new(json!({
            "sync_namespace": "mcp.agent_acls",
            "kill_switch_namespace": "mcp.kill_switch"
        }));
        let plugin = McpAuthFactory.build(&cfg, &ctx).unwrap();

        let agents = synced.get_or_create("mcp.agent_acls");
        let kill = synced.get_or_create("mcp.kill_switch");
        let token = "sk-mcp-live-agent-1";

        // Live agent upsert
        agents.apply_delta(
            1,
            "agent_ci",
            SyncedDeltaOp::Upsert(json!({
                "enabled": true,
                "team": "platform",
                "key_hashes": [sha256_prefixed(token)],
                "allowed_servers": ["github"],
                "allowed_tools": ["github__list_*"],
                "denied_tools": ["github__delete_*"]
            })),
        );

        let mut rctx = test_ctx(1);
        let mut req = mcp_req(token);
        let ok = matches!(
            plugin.on_request_headers(&mut rctx, &mut req),
            HookResult::Ready(Flow::Continue)
        );
        assert!(ok, "expected Continue for synced agent");
        let p = rctx.get_ext::<McpPrincipal>().expect("principal attached");
        assert_eq!(p.id, "agent_ci");
        assert_eq!(p.allowed_servers, vec!["github"]);

        // Trigger instant kill-switch for principal
        kill.apply_delta(
            1,
            "ks_1",
            SyncedDeltaOp::Upsert(json!({
                "scope": "principal",
                "target": "agent_ci",
                "reason": "runaway tool loop"
            })),
        );

        let mut rctx = test_ctx(2);
        let mut req = mcp_req(token);
        match plugin.on_request_headers(&mut rctx, &mut req) {
            HookResult::Ready(Flow::Respond(resp)) => {
                assert_eq!(resp.status, StatusCode::FORBIDDEN)
            }
            _ => panic!("expected 403 from kill-switch"),
        }

        // Lift kill-switch -> access restored immediately
        kill.apply_delta(2, "ks_1", SyncedDeltaOp::Delete);
        let mut rctx = test_ctx(3);
        let mut req = mcp_req(token);
        assert!(matches!(
            plugin.on_request_headers(&mut rctx, &mut req),
            HookResult::Ready(Flow::Continue)
        ));
    }
}
