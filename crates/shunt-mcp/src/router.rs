use std::collections::{BTreeMap, HashMap};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use shunt_plugin_sdk::{
    BufferedResponse, BuildContext, Bytes, Clock, Flow, HeaderName, HeaderValue, HookMask,
    HookResult, HttpClient, HttpPlugin, HttpRequest, Method, PluginBuildError, PluginConfig,
    PluginFactory, RequestCtx, RequestHead, ResponseHead, RouteDecision, StatusCode,
    UpstreamRequest, UpstreamSelection, Uri, header,
};
use tracing::warn;

use crate::types::{
    DEFAULT_PROTOCOL_VERSION, JSONRPC_INVALID_PARAMS, JSONRPC_INVALID_REQUEST,
    JSONRPC_METHOD_NOT_FOUND, MCP_ERR_FORBIDDEN, MCP_ERR_UPSTREAM_ERROR, MCP_NAME_HEADER,
    MCP_PROTOCOL_VERSION_HEADER, MCP_SESSION_HEADER, McpPrincipal, McpRequestMeta, McpUpstreamAuth,
    ResolvedUpstreamAuth, SUPPORTED_PROTOCOL_VERSIONS, extract_mcp_response_payloads,
    get_header_str, join_namespaced, jsonrpc_error_response, jsonrpc_result_response,
    parse_mcp_jsonrpc_request, serialize_json_bytes, sha256_hex, split_namespaced,
};

const DEFAULT_MAX_BODY_BYTES: usize = 2 * 1024 * 1024; // 2 MiB
const DEFAULT_CATALOG_TTL_SECS: u64 = 60;
const DEFAULT_SESSION_TTL_SECS: u64 = 3_600;
const DEFAULT_MAX_SESSIONS: usize = 16_384;
const DEFAULT_DISCOVERY_TIMEOUT_MS: u64 = 5_000;

fn default_true() -> bool {
    true
}

fn default_namespace_separator() -> String {
    "__".to_owned()
}

fn default_server_name() -> String {
    "shunt-mcp-gateway".to_owned()
}

fn default_server_version() -> String {
    env!("CARGO_PKG_VERSION").to_owned()
}

fn default_max_body_bytes() -> usize {
    DEFAULT_MAX_BODY_BYTES
}

fn default_catalog_ttl_secs() -> u64 {
    DEFAULT_CATALOG_TTL_SECS
}

fn default_session_ttl_secs() -> u64 {
    DEFAULT_SESSION_TTL_SECS
}

fn default_max_sessions() -> usize {
    DEFAULT_MAX_SESSIONS
}

fn default_discovery_timeout_ms() -> u64 {
    DEFAULT_DISCOVERY_TIMEOUT_MS
}

#[derive(Debug, Clone, Deserialize)]
struct McpServerConfig {
    /// Target Shunt upstream pool name (from `[[upstreams]]`) used for proxied calls.
    upstream: String,
    /// Optional HTTP(S) endpoint URL used for sideband `HttpClient` fan-out discovery
    /// (`tools/list`, `resources/list`, `prompts/list`) and stateful session initialization.
    /// Supports `"mock://<upstream>/mcp"` in `shunt test`.
    #[serde(default)]
    endpoint: Option<String>,
    /// Optional HTTP request path override when forwarding to this backend server (e.g., `"/mcp"`).
    #[serde(default)]
    path: Option<String>,
    /// Optional authentication injected on requests to this backend MCP server.
    #[serde(default)]
    auth: McpUpstreamAuth,
    /// Resource URI prefixes owned by this server (used to route `resources/read`).
    #[serde(default)]
    resource_prefixes: Vec<String>,
    /// Whether this backend MCP server requires an upstream `initialize` handshake &
    /// `Mcp-Session-Id` before `tools/call` or `tools/list` (default: false).
    #[serde(default)]
    stateful: bool,
    /// Optional static tool catalog override (avoids upstream discovery calls when set).
    #[serde(default)]
    static_tools: Vec<Value>,
    /// Optional human-readable description.
    #[serde(default)]
    description: Option<String>,
    /// Enable/disable this server without removing it from config (default: true).
    #[serde(default = "default_true")]
    enabled: bool,
}

#[derive(Debug, Deserialize)]
#[serde(default)]
struct McpRouterConfig {
    /// Maximum buffered JSON-RPC POST request body size in bytes (default: 2 MiB).
    #[serde(default = "default_max_body_bytes")]
    max_body_bytes: usize,
    /// Namespace separator joining `<server><sep><tool>` in multi-server mode (default: `"__"`).
    #[serde(default = "default_namespace_separator")]
    namespace_separator: String,
    /// Virtual MCP server name advertised in synthesized `initialize` responses.
    #[serde(default = "default_server_name")]
    server_name: String,
    /// Virtual MCP server version advertised in synthesized `initialize` responses.
    #[serde(default = "default_server_version")]
    server_version: String,
    /// Allow JSON-RPC batch arrays (default: false — safer for per-call governance).
    #[serde(default)]
    allow_batch: bool,
    /// Attach diagnostic `x-shunt-mcp-*` response headers (default: true).
    #[serde(default = "default_true")]
    response_headers: bool,
    /// Mirror resolved tool/resource/prompt name into `Mcp-Name` upstream header (default: true).
    #[serde(default = "default_true")]
    mirror_mcp_name_header: bool,
    /// Catalog cache TTL in seconds for fan-out `tools/list` / `resources/list` / `prompts/list`.
    #[serde(default = "default_catalog_ttl_secs")]
    catalog_ttl_secs: u64,
    /// Gateway virtual session TTL in seconds (default: 3600).
    #[serde(default = "default_session_ttl_secs")]
    session_ttl_secs: u64,
    /// Maximum tracked gateway sessions in memory (bounded against cardinality DoS).
    #[serde(default = "default_max_sessions")]
    max_sessions: usize,
    /// Timeout in milliseconds for sideband discovery / upstream session init calls.
    #[serde(default = "default_discovery_timeout_ms")]
    discovery_timeout_ms: u64,
    /// If `true`, skip unreachable servers during `tools/list` fan-out instead of failing
    /// the entire aggregation (default: true).
    #[serde(default = "default_true")]
    partial_discovery_ok: bool,
    /// Single-server passthrough path override (used only when `servers` is empty).
    #[serde(default)]
    upstream_path: Option<String>,
    /// Single-server passthrough upstream auth (used only when `servers` is empty).
    #[serde(default)]
    upstream_auth: McpUpstreamAuth,
    /// Optional logical server label in single-server passthrough mode (default: `"default"`).
    #[serde(default)]
    default_server_label: Option<String>,
    /// Optional server name to proxy `GET` SSE streams to in multiplexer mode.
    #[serde(default)]
    default_sse_server: Option<String>,
    /// Named backend MCP servers for virtual multiplexer mode.
    /// When empty, `mcp-router` runs in single-server passthrough governance mode.
    #[serde(default)]
    servers: BTreeMap<String, McpServerConfig>,
}

impl Default for McpRouterConfig {
    fn default() -> Self {
        Self {
            max_body_bytes: DEFAULT_MAX_BODY_BYTES,
            namespace_separator: default_namespace_separator(),
            server_name: default_server_name(),
            server_version: default_server_version(),
            allow_batch: false,
            response_headers: true,
            mirror_mcp_name_header: true,
            catalog_ttl_secs: DEFAULT_CATALOG_TTL_SECS,
            session_ttl_secs: DEFAULT_SESSION_TTL_SECS,
            max_sessions: DEFAULT_MAX_SESSIONS,
            discovery_timeout_ms: DEFAULT_DISCOVERY_TIMEOUT_MS,
            partial_discovery_ok: true,
            upstream_path: None,
            upstream_auth: McpUpstreamAuth::None,
            default_server_label: None,
            default_sse_server: None,
            servers: BTreeMap::new(),
        }
    }
}

struct CompiledServer {
    name: String,
    upstream: String,
    endpoint: Option<Uri>,
    path: Option<String>,
    auth: ResolvedUpstreamAuth,
    resource_prefixes: Vec<String>,
    stateful: bool,
    static_tools: Vec<Value>,
    enabled: bool,
}

#[derive(Debug, Clone)]
struct GatewaySession {
    owner_principal: Option<String>,
    protocol_version: String,
    /// Maps backend server name -> backend `Mcp-Session-Id` for stateful upstreams.
    upstream_sessions: HashMap<String, String>,
    expires_at: Duration,
}

/// Error returned when an `Mcp-Session-Id` is presented by a different authenticated principal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SessionOwnershipError;

/// Reload-persistent, bounded virtual MCP session table stored in `StateStore`.
#[derive(Debug, Default)]
pub struct McpSessionTable {
    sessions: Mutex<HashMap<String, GatewaySession>>,
    seq: AtomicU64,
}

/// Read-only snapshot of MCP sessions for Admin Inspector `/api/status`.
#[derive(Debug, Clone, Serialize)]
pub struct McpSessionStatsSnapshot {
    pub active_sessions: usize,
    pub upstream_session_links: usize,
}

impl McpSessionTable {
    pub fn create_session(
        &self,
        owner_principal: Option<String>,
        protocol_version: String,
        now: Duration,
        ttl: Duration,
        max_sessions: usize,
    ) -> String {
        let seq = self.seq.fetch_add(1, Ordering::Relaxed);
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let seed = format!(
            "shunt-mcp-{seq}-{nanos}-{:?}-{}",
            now,
            owner_principal.as_deref().unwrap_or("anon")
        );
        let sid = format!("mcp_{}", &sha256_hex(seed.as_bytes())[..32]);

        let mut guard = self.sessions.lock().expect("McpSessionTable poisoned");
        guard.retain(|_, v| v.expires_at > now);
        if guard.len() >= max_sessions.max(1)
            && let Some(oldest) = guard
                .iter()
                .min_by_key(|(_, v)| v.expires_at)
                .map(|(k, _)| k.clone())
        {
            guard.remove(&oldest);
        }
        guard.insert(
            sid.clone(),
            GatewaySession {
                owner_principal,
                protocol_version,
                upstream_sessions: HashMap::new(),
                expires_at: now.saturating_add(ttl),
            },
        );
        sid
    }

    /// Validates an existing session (checking owner principal if bound) and refreshes TTL.
    /// Returns `Ok(Some(protocol_version))` if found and valid, `Ok(None)` if unknown,
    /// or `Err(SessionOwnershipError)` if owned by a different principal.
    pub fn touch_and_verify(
        &self,
        sid: &str,
        principal_id: Option<&str>,
        now: Duration,
        ttl: Duration,
    ) -> Result<Option<String>, SessionOwnershipError> {
        let mut guard = self.sessions.lock().expect("McpSessionTable poisoned");
        guard.retain(|_, v| v.expires_at > now);
        let Some(sess) = guard.get_mut(sid) else {
            return Ok(None);
        };
        if let (Some(owner), Some(caller)) = (sess.owner_principal.as_deref(), principal_id)
            && owner != caller
        {
            return Err(SessionOwnershipError);
        }
        sess.expires_at = now.saturating_add(ttl);
        Ok(Some(sess.protocol_version.clone()))
    }

    pub fn get_upstream_session(&self, sid: &str, server: &str, now: Duration) -> Option<String> {
        let guard = self.sessions.lock().expect("McpSessionTable poisoned");
        let sess = guard.get(sid)?;
        if sess.expires_at <= now {
            return None;
        }
        sess.upstream_sessions.get(server).cloned()
    }

    pub fn set_upstream_session(&self, sid: &str, server: &str, upstream_sid: String) {
        let mut guard = self.sessions.lock().expect("McpSessionTable poisoned");
        if let Some(sess) = guard.get_mut(sid) {
            sess.upstream_sessions
                .insert(server.to_owned(), upstream_sid);
        }
    }

    pub fn remove_session(&self, sid: &str) -> Option<HashMap<String, String>> {
        let mut guard = self.sessions.lock().expect("McpSessionTable poisoned");
        guard.remove(sid).map(|s| s.upstream_sessions)
    }

    pub fn snapshot(&self, now: Duration) -> McpSessionStatsSnapshot {
        let guard = self.sessions.lock().expect("McpSessionTable poisoned");
        let mut active = 0usize;
        let mut links = 0usize;
        for sess in guard.values() {
            if sess.expires_at > now {
                active += 1;
                links += sess.upstream_sessions.len();
            }
        }
        McpSessionStatsSnapshot {
            active_sessions: active,
            upstream_session_links: links,
        }
    }
}

#[derive(Debug, Clone)]
struct CachedCatalogEntry {
    items: Vec<Value>,
    expires_at: Duration,
}

/// Reload-persistent, TTL-bounded cache for aggregated MCP server catalogs
/// (`tools/list`, `resources/list`, `resources/templates/list`, `prompts/list`).
#[derive(Debug, Default)]
pub struct McpCatalogTable {
    entries: Mutex<HashMap<String, CachedCatalogEntry>>,
}

/// Read-only snapshot of cached MCP discovery catalogs for Admin Inspector `/api/status`.
#[derive(Debug, Clone, Serialize)]
pub struct McpCatalogStatsSnapshot {
    pub cached_catalogs: usize,
    pub cached_items: usize,
}

impl McpCatalogTable {
    pub fn get(&self, key: &str, now: Duration) -> Option<Vec<Value>> {
        let guard = self.entries.lock().expect("McpCatalogTable poisoned");
        let entry = guard.get(key)?;
        if entry.expires_at > now {
            Some(entry.items.clone())
        } else {
            None
        }
    }

    pub fn insert(&self, key: String, items: Vec<Value>, now: Duration, ttl: Duration) {
        let mut guard = self.entries.lock().expect("McpCatalogTable poisoned");
        guard.retain(|_, v| v.expires_at > now);
        guard.insert(
            key,
            CachedCatalogEntry {
                items,
                expires_at: now.saturating_add(ttl),
            },
        );
    }

    pub fn snapshot(&self, now: Duration) -> McpCatalogStatsSnapshot {
        let guard = self.entries.lock().expect("McpCatalogTable poisoned");
        let mut catalogs = 0usize;
        let mut items = 0usize;
        for entry in guard.values() {
            if entry.expires_at > now {
                catalogs += 1;
                items += entry.items.len();
            }
        }
        McpCatalogStatsSnapshot {
            cached_catalogs: catalogs,
            cached_items: items,
        }
    }
}

/// Per-request HTTP metadata captured in `on_request_headers` for `on_request_body_buffered`.
#[derive(Debug, Clone)]
struct IncomingMcpHeaders {
    method: Method,
    session_id: Option<String>,
    protocol_version: Option<String>,
    approved_header: bool,
}

/// Plugin factory for `mcp-router`.
pub struct McpRouterFactory;

impl PluginFactory for McpRouterFactory {
    fn name(&self) -> &str {
        "mcp-router"
    }

    fn build(
        &self,
        config: &PluginConfig,
        ctx: &BuildContext,
    ) -> Result<Arc<dyn HttpPlugin>, PluginBuildError> {
        let cfg: McpRouterConfig = config.deserialize(self.name())?;

        if cfg.max_body_bytes == 0 {
            return Err(PluginBuildError::BuildFailed {
                plugin: self.name().to_owned(),
                message: "mcp-router `max_body_bytes` must be > 0".to_owned(),
            });
        }

        let upstream_auth = cfg.upstream_auth.resolve(self.name()).map_err(|message| {
            PluginBuildError::BuildFailed {
                plugin: self.name().to_owned(),
                message,
            }
        })?;

        let mut servers = BTreeMap::new();
        for (name, scfg) in cfg.servers {
            if name.trim().is_empty() {
                return Err(PluginBuildError::BuildFailed {
                    plugin: self.name().to_owned(),
                    message: "mcp-router server name must not be empty".to_owned(),
                });
            }
            if !cfg.namespace_separator.is_empty() && name.contains(&cfg.namespace_separator) {
                return Err(PluginBuildError::BuildFailed {
                    plugin: self.name().to_owned(),
                    message: format!(
                        "mcp-router server name `{name}` must not contain namespace_separator `{}`",
                        cfg.namespace_separator
                    ),
                });
            }
            let endpoint = match scfg.endpoint {
                Some(ref raw) => {
                    Some(
                        raw.parse::<Uri>()
                            .map_err(|e| PluginBuildError::BuildFailed {
                                plugin: self.name().to_owned(),
                                message: format!(
                                    "server `{name}` invalid endpoint URI `{raw}`: {e}"
                                ),
                            })?,
                    )
                }
                None => None,
            };
            let auth = scfg.auth.resolve(self.name()).map_err(|message| {
                PluginBuildError::BuildFailed {
                    plugin: self.name().to_owned(),
                    message: format!("server `{name}`: {message}"),
                }
            })?;
            let _ = scfg.description;
            servers.insert(
                name.clone(),
                CompiledServer {
                    name,
                    upstream: scfg.upstream,
                    endpoint,
                    path: scfg.path,
                    auth,
                    resource_prefixes: scfg.resource_prefixes,
                    stateful: scfg.stateful,
                    static_tools: scfg.static_tools,
                    enabled: scfg.enabled,
                },
            );
        }

        if let Some(ref sse_srv) = cfg.default_sse_server
            && !servers.contains_key(sse_srv)
        {
            return Err(PluginBuildError::BuildFailed {
                plugin: self.name().to_owned(),
                message: format!(
                    "mcp-router `default_sse_server` references unknown server `{sse_srv}`"
                ),
            });
        }

        let state = ctx.state_handle();
        let sessions = state.get_or_init("mcp-sessions", McpSessionTable::default);
        let catalogs = state.get_or_init("mcp-catalogs", McpCatalogTable::default);

        Ok(Arc::new(McpRouterPlugin {
            max_body_bytes: cfg.max_body_bytes,
            namespace_separator: cfg.namespace_separator,
            server_name: cfg.server_name,
            server_version: cfg.server_version,
            allow_batch: cfg.allow_batch,
            response_headers: cfg.response_headers,
            mirror_mcp_name_header: cfg.mirror_mcp_name_header,
            catalog_ttl: Duration::from_secs(cfg.catalog_ttl_secs),
            session_ttl: Duration::from_secs(cfg.session_ttl_secs.max(1)),
            max_sessions: cfg.max_sessions.max(1),
            discovery_timeout: Duration::from_millis(cfg.discovery_timeout_ms.max(100)),
            partial_discovery_ok: cfg.partial_discovery_ok,
            upstream_path: cfg.upstream_path,
            upstream_auth,
            default_server_label: cfg
                .default_server_label
                .unwrap_or_else(|| "default".to_owned()),
            default_sse_server: cfg.default_sse_server,
            servers: Arc::new(servers),
            sessions,
            catalogs,
            http_client: ctx.http_client(),
            clock: ctx.clock(),
        }))
    }
}

/// MCP Streamable HTTP router & virtual multi-server multiplexer.
pub struct McpRouterPlugin {
    max_body_bytes: usize,
    namespace_separator: String,
    server_name: String,
    server_version: String,
    allow_batch: bool,
    response_headers: bool,
    mirror_mcp_name_header: bool,
    catalog_ttl: Duration,
    session_ttl: Duration,
    max_sessions: usize,
    discovery_timeout: Duration,
    partial_discovery_ok: bool,
    upstream_path: Option<String>,
    upstream_auth: ResolvedUpstreamAuth,
    default_server_label: String,
    default_sse_server: Option<String>,
    servers: Arc<BTreeMap<String, CompiledServer>>,
    sessions: Arc<McpSessionTable>,
    catalogs: Arc<McpCatalogTable>,
    http_client: Option<Arc<dyn HttpClient>>,
    clock: Arc<dyn Clock>,
}

impl McpRouterPlugin {
    fn is_multiplexer(&self) -> bool {
        !self.servers.is_empty()
    }

    fn apply_diag_headers(&self, meta: &McpRequestMeta, headers: &mut shunt_plugin_sdk::HeaderMap) {
        if !self.response_headers {
            return;
        }
        if let Ok(v) = HeaderValue::from_str(&meta.server) {
            headers.insert(HeaderName::from_static("x-shunt-mcp-server"), v);
        }
        if let Ok(v) = HeaderValue::from_str(&meta.method) {
            headers.insert(HeaderName::from_static("x-shunt-mcp-method"), v);
        }
        if let Some(ref tool) = meta.tool_name
            && let Ok(v) = HeaderValue::from_str(tool)
        {
            headers.insert(HeaderName::from_static("x-shunt-mcp-tool"), v);
        }
        if let Some(ref sid) = meta.session_id
            && let Ok(v) = HeaderValue::from_str(sid)
        {
            headers.insert(HeaderName::from_static("x-shunt-mcp-session"), v);
        }
    }

    fn negotiate_protocol_version(params: Option<&Value>, hdr: Option<&str>) -> String {
        let requested = params
            .and_then(|p| p.get("protocolVersion"))
            .and_then(Value::as_str)
            .or(hdr);
        if let Some(req_ver) = requested
            && SUPPORTED_PROTOCOL_VERSIONS.contains(&req_ver)
        {
            return req_ver.to_owned();
        }
        DEFAULT_PROTOCOL_VERSION.to_owned()
    }

    fn resolve_server_for_resource(&self, uri: &str) -> Option<&CompiledServer> {
        let mut best: Option<(&CompiledServer, usize)> = None;
        for srv in self.servers.values() {
            if !srv.enabled {
                continue;
            }
            for prefix in &srv.resource_prefixes {
                if uri.starts_with(prefix.as_str()) {
                    let len = prefix.len();
                    if best.is_none_or(|(_, best_len)| len > best_len) {
                        best = Some((srv, len));
                    }
                }
            }
            let scheme_prefix = format!("{}://", srv.name);
            if uri.starts_with(&scheme_prefix) {
                let len = scheme_prefix.len();
                if best.is_none_or(|(_, best_len)| len > best_len) {
                    best = Some((srv, len));
                }
            }
        }
        best.map(|(s, _)| s)
    }

    fn filter_tools_for_principal(
        items: &[Value],
        server_name: &str,
        sep: &str,
        principal: Option<&McpPrincipal>,
    ) -> Vec<Value> {
        let mut out = Vec::with_capacity(items.len());
        for item in items {
            let Some(mut obj) = item.as_object().cloned() else {
                continue;
            };
            let Some(raw_name) = obj.get("name").and_then(Value::as_str).map(str::to_owned) else {
                continue;
            };
            let namespaced = join_namespaced(server_name, sep, &raw_name);
            if let Some(p) = principal
                && !p.allows_tool(&namespaced, Some(&raw_name))
            {
                continue;
            }
            obj.insert("name".to_owned(), Value::String(namespaced));
            out.push(Value::Object(obj));
        }
        out
    }

    fn filter_resources_for_principal(
        items: &[Value],
        principal: Option<&McpPrincipal>,
    ) -> Vec<Value> {
        let mut out = Vec::with_capacity(items.len());
        for item in items {
            let uri = item
                .get("uri")
                .or_else(|| item.get("uriTemplate"))
                .and_then(Value::as_str);
            if let (Some(p), Some(u)) = (principal, uri)
                && !p.allows_resource(u)
            {
                continue;
            }
            out.push(item.clone());
        }
        out
    }

    fn filter_prompts_for_principal(
        items: &[Value],
        server_name: &str,
        sep: &str,
        principal: Option<&McpPrincipal>,
    ) -> Vec<Value> {
        let mut out = Vec::with_capacity(items.len());
        for item in items {
            let Some(mut obj) = item.as_object().cloned() else {
                continue;
            };
            let Some(raw_name) = obj.get("name").and_then(Value::as_str).map(str::to_owned) else {
                continue;
            };
            let namespaced = join_namespaced(server_name, sep, &raw_name);
            if let Some(p) = principal
                && !p.allows_prompt(&namespaced, Some(&raw_name))
            {
                continue;
            }
            obj.insert("name".to_owned(), Value::String(namespaced));
            out.push(Value::Object(obj));
        }
        out
    }

    async fn fetch_server_catalog(
        client: &dyn HttpClient,
        server: &CompiledServer,
        method: &str,
        result_field: &str,
        timeout: Duration,
    ) -> Result<Vec<Value>, String> {
        if method == "tools/list" && !server.static_tools.is_empty() {
            return Ok(server.static_tools.clone());
        }
        let Some(ref uri) = server.endpoint else {
            return Ok(Vec::new());
        };

        // If backend server is stateful, initialize an ephemeral discovery session first.
        let mut upstream_sid: Option<String> = None;
        if server.stateful {
            upstream_sid =
                Some(init_upstream_mcp_session(client, uri, &server.auth, timeout).await?);
        }

        let payload = json!({
            "jsonrpc": "2.0",
            "id": "shunt-discovery-1",
            "method": method,
            "params": {},
        });
        let body = serde_json::to_vec(&payload).map_err(|e| e.to_string())?;

        let mut req = HttpRequest::post(uri.clone())
            .with_header(
                header::CONTENT_TYPE,
                HeaderValue::from_static("application/json"),
            )
            .with_header(
                header::ACCEPT,
                HeaderValue::from_static("application/json, text/event-stream"),
            )
            .with_body(body)
            .with_timeout(timeout);
        apply_resolved_auth(&server.auth, &mut req.headers);
        if let Some(ref sid) = upstream_sid
            && let Ok(hv) = HeaderValue::from_str(sid)
        {
            req.headers
                .insert(HeaderName::from_static(MCP_SESSION_HEADER), hv);
        }

        let resp = client
            .send(req)
            .await
            .map_err(|e| format!("server `{}` {method} discovery failed: {e}", server.name))?;

        if !resp.status.is_success() {
            return Err(format!(
                "server `{}` {method} returned HTTP {}",
                server.name,
                resp.status.as_u16()
            ));
        }

        let ct = resp
            .headers
            .get(header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok());
        let events = extract_mcp_response_payloads(ct, &resp.body);
        for ev in events {
            if let Some(arr) = ev
                .get("result")
                .and_then(|r| r.get(result_field))
                .and_then(Value::as_array)
            {
                return Ok(arr.clone());
            }
        }
        Ok(Vec::new())
    }
}

async fn init_upstream_mcp_session(
    client: &dyn HttpClient,
    uri: &Uri,
    auth: &ResolvedUpstreamAuth,
    timeout: Duration,
) -> Result<String, String> {
    let init_payload = json!({
        "jsonrpc": "2.0",
        "id": "shunt-init-1",
        "method": "initialize",
        "params": {
            "protocolVersion": DEFAULT_PROTOCOL_VERSION,
            "capabilities": {},
            "clientInfo": {
                "name": "shunt-mcp-gateway",
                "version": env!("CARGO_PKG_VERSION"),
            }
        }
    });
    let init_body = serde_json::to_vec(&init_payload).map_err(|e| e.to_string())?;
    let mut init_req = HttpRequest::post(uri.clone())
        .with_header(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/json"),
        )
        .with_header(
            header::ACCEPT,
            HeaderValue::from_static("application/json, text/event-stream"),
        )
        .with_body(init_body)
        .with_timeout(timeout);
    apply_resolved_auth(auth, &mut init_req.headers);

    let resp = client
        .send(init_req)
        .await
        .map_err(|e| format!("upstream MCP initialize failed: {e}"))?;
    if !resp.status.is_success() {
        return Err(format!(
            "upstream MCP initialize returned HTTP {}",
            resp.status.as_u16()
        ));
    }

    let sid = get_header_str(&resp.headers, MCP_SESSION_HEADER)
        .map(str::to_owned)
        .unwrap_or_default();

    if !sid.is_empty() {
        let notif_payload = json!({
            "jsonrpc": "2.0",
            "method": "notifications/initialized"
        });
        if let Ok(notif_body) = serde_json::to_vec(&notif_payload) {
            let mut notif_req = HttpRequest::post(uri.clone())
                .with_header(
                    header::CONTENT_TYPE,
                    HeaderValue::from_static("application/json"),
                )
                .with_body(notif_body)
                .with_timeout(timeout);
            apply_resolved_auth(auth, &mut notif_req.headers);
            if let Ok(hv) = HeaderValue::from_str(&sid) {
                notif_req
                    .headers
                    .insert(HeaderName::from_static(MCP_SESSION_HEADER), hv);
            }
            let _ = client.send(notif_req).await;
        }
    }

    Ok(sid)
}

fn apply_resolved_auth(auth: &ResolvedUpstreamAuth, headers: &mut shunt_plugin_sdk::HeaderMap) {
    if let ResolvedUpstreamAuth::Header { name, value } = auth {
        headers.insert(name.clone(), value.clone());
    }
}

impl HttpPlugin for McpRouterPlugin {
    fn name(&self) -> &str {
        "mcp-router"
    }

    fn hook_mask(&self) -> HookMask {
        let mut mask = HookMask::ON_REQUEST_HEADERS
            | HookMask::REQUEST_BODY_BUFFERED
            | HookMask::ON_ROUTE
            | HookMask::ON_UPSTREAM_SELECT
            | HookMask::ON_UPSTREAM_REQUEST;
        if self.response_headers {
            mask |= HookMask::ON_RESPONSE_HEADERS;
        }
        mask
    }

    fn max_request_body_bytes(&self) -> Option<usize> {
        Some(self.max_body_bytes)
    }

    fn on_request_headers<'a>(
        &'a self,
        ctx: &'a mut RequestCtx,
        req: &'a mut RequestHead,
    ) -> HookResult<'a, Flow> {
        let session_id = get_header_str(&req.headers, MCP_SESSION_HEADER).map(str::to_owned);
        let protocol_version =
            get_header_str(&req.headers, MCP_PROTOCOL_VERSION_HEADER).map(str::to_owned);
        let approved_header = get_header_str(&req.headers, "x-shunt-approved")
            .is_some_and(|v| v.eq_ignore_ascii_case("true") || v == "1");

        // Handle DELETE session termination in multiplexer mode immediately.
        if req.method == Method::DELETE && self.is_multiplexer() {
            let principal_id = ctx.get_ext::<McpPrincipal>().map(|p| p.id.as_str());
            if let Some(ref sid) = session_id {
                let now = self.clock.now();
                if self
                    .sessions
                    .touch_and_verify(sid, principal_id, now, self.session_ttl)
                    .is_err()
                {
                    return HookResult::Ready(Flow::Respond(jsonrpc_error_response(
                        StatusCode::FORBIDDEN,
                        None,
                        MCP_ERR_FORBIDDEN,
                        "Mcp-Session-Id belongs to a different authenticated principal",
                        None,
                    )));
                }
                let _upstream_sids = self.sessions.remove_session(sid);
            }
            let meta = McpRequestMeta {
                jsonrpc_id: None,
                method: "_session_delete".to_owned(),
                is_notification: true,
                server: "gateway".to_owned(),
                upstream: None,
                tool_name: None,
                backend_tool_name: None,
                resource_uri: None,
                prompt_name: None,
                backend_prompt_name: None,
                arguments: None,
                session_id,
                protocol_version,
                approved: approved_header,
                handled_locally: true,
            };
            let mut resp = BufferedResponse::new(StatusCode::NO_CONTENT, Bytes::new());
            self.apply_diag_headers(&meta, &mut resp.headers);
            ctx.insert_ext(meta);
            return HookResult::Ready(Flow::Respond(resp));
        }

        // Handle GET SSE stream
        if req.method == Method::GET {
            if self.is_multiplexer() {
                if let Some(ref sse_srv_name) = self.default_sse_server
                    && let Some(srv) = self.servers.get(sse_srv_name)
                {
                    if let Some(p) = ctx.get_ext::<McpPrincipal>()
                        && !p.allows_server(&srv.name)
                    {
                        return HookResult::Ready(Flow::Respond(jsonrpc_error_response(
                            StatusCode::FORBIDDEN,
                            None,
                            MCP_ERR_FORBIDDEN,
                            format!(
                                "principal `{}` is not allowed to access server `{}`",
                                p.id, srv.name
                            ),
                            None,
                        )));
                    }
                    ctx.insert_ext(McpRequestMeta {
                        jsonrpc_id: None,
                        method: "_sse_stream".to_owned(),
                        is_notification: true,
                        server: srv.name.clone(),
                        upstream: Some(srv.upstream.clone()),
                        tool_name: None,
                        backend_tool_name: None,
                        resource_uri: None,
                        prompt_name: None,
                        backend_prompt_name: None,
                        arguments: None,
                        session_id,
                        protocol_version,
                        approved: approved_header,
                        handled_locally: false,
                    });
                    return HookResult::Ready(Flow::Continue);
                }
                return HookResult::Ready(Flow::Respond(BufferedResponse::text(
                    StatusCode::METHOD_NOT_ALLOWED,
                    "GET SSE stream is not configured on this virtual MCP multiplexer route",
                )));
            }
            ctx.insert_ext(McpRequestMeta {
                jsonrpc_id: None,
                method: "_sse_stream".to_owned(),
                is_notification: true,
                server: self.default_server_label.clone(),
                upstream: None,
                tool_name: None,
                backend_tool_name: None,
                resource_uri: None,
                prompt_name: None,
                backend_prompt_name: None,
                arguments: None,
                session_id,
                protocol_version,
                approved: approved_header,
                handled_locally: false,
            });
            return HookResult::Ready(Flow::Continue);
        }

        ctx.insert_ext(IncomingMcpHeaders {
            method: req.method.clone(),
            session_id,
            protocol_version,
            approved_header,
        });
        HookResult::Ready(Flow::Continue)
    }

    fn on_request_body_buffered<'a>(
        &'a self,
        ctx: &'a mut RequestCtx,
        body: &'a mut Bytes,
    ) -> HookResult<'a, Flow> {
        let Some(hdrs) = ctx.get_ext::<IncomingMcpHeaders>().cloned() else {
            return HookResult::Ready(Flow::Continue);
        };

        if hdrs.method != Method::POST {
            return HookResult::Ready(Flow::Continue);
        }

        let parsed_list = match parse_mcp_jsonrpc_request(body, self.allow_batch) {
            Ok(v) => v,
            Err(err) => {
                return HookResult::Ready(Flow::Respond(jsonrpc_error_response(
                    StatusCode::BAD_REQUEST,
                    None,
                    err.code,
                    err.message,
                    None,
                )));
            }
        };

        let req = parsed_list
            .into_iter()
            .next()
            .expect("non-empty parsed list");
        let principal = ctx.get_ext::<McpPrincipal>().cloned();
        let now = self.clock.now();

        // Check principal method ACL first
        if let Some(ref p) = principal
            && !p.allows_method(&req.method)
        {
            return HookResult::Ready(Flow::Respond(jsonrpc_error_response(
                StatusCode::FORBIDDEN,
                req.id.as_ref(),
                MCP_ERR_FORBIDDEN,
                format!(
                    "principal `{}` is not permitted to invoke `{}`",
                    p.id, req.method
                ),
                None,
            )));
        }

        // Validate virtual gateway session ownership if session header present
        if self.is_multiplexer()
            && let Some(ref sid) = hdrs.session_id
            && self
                .sessions
                .touch_and_verify(
                    sid,
                    principal.as_ref().map(|p| p.id.as_str()),
                    now,
                    self.session_ttl,
                )
                .is_err()
        {
            return HookResult::Ready(Flow::Respond(jsonrpc_error_response(
                StatusCode::FORBIDDEN,
                req.id.as_ref(),
                MCP_ERR_FORBIDDEN,
                "Mcp-Session-Id belongs to a different authenticated principal",
                None,
            )));
        }

        let approved = hdrs.approved_header || req.meta_approved;

        // -----------------------------------------------------------------
        // Mode 1: Single-server passthrough governance mode
        // -----------------------------------------------------------------
        if !self.is_multiplexer() {
            if let Some(ref p) = principal {
                if let Some(ref tool) = req.tool_name
                    && !p.allows_tool(tool, Some(tool))
                {
                    return HookResult::Ready(Flow::Respond(jsonrpc_error_response(
                        StatusCode::FORBIDDEN,
                        req.id.as_ref(),
                        MCP_ERR_FORBIDDEN,
                        format!(
                            "principal `{}` is not permitted to call tool `{tool}`",
                            p.id
                        ),
                        None,
                    )));
                }
                if let Some(ref uri) = req.resource_uri
                    && !p.allows_resource(uri)
                {
                    return HookResult::Ready(Flow::Respond(jsonrpc_error_response(
                        StatusCode::FORBIDDEN,
                        req.id.as_ref(),
                        MCP_ERR_FORBIDDEN,
                        format!(
                            "principal `{}` is not permitted to access resource `{uri}`",
                            p.id
                        ),
                        None,
                    )));
                }
                if let Some(ref prompt) = req.prompt_name
                    && !p.allows_prompt(prompt, Some(prompt))
                {
                    return HookResult::Ready(Flow::Respond(jsonrpc_error_response(
                        StatusCode::FORBIDDEN,
                        req.id.as_ref(),
                        MCP_ERR_FORBIDDEN,
                        format!(
                            "principal `{}` is not permitted to get prompt `{prompt}`",
                            p.id
                        ),
                        None,
                    )));
                }
            }

            ctx.insert_ext(McpRequestMeta {
                jsonrpc_id: req.id,
                method: req.method,
                is_notification: req.is_notification,
                server: self.default_server_label.clone(),
                upstream: None,
                backend_tool_name: req.tool_name.clone(),
                tool_name: req.tool_name,
                resource_uri: req.resource_uri,
                backend_prompt_name: req.prompt_name.clone(),
                prompt_name: req.prompt_name,
                arguments: req.arguments,
                session_id: hdrs.session_id,
                protocol_version: hdrs.protocol_version,
                approved,
                handled_locally: false,
            });
            return HookResult::Ready(Flow::Continue);
        }

        // -----------------------------------------------------------------
        // Mode 2: Multi-server Virtual MCP Multiplexer
        // -----------------------------------------------------------------
        match req.method.as_str() {
            "initialize" => {
                let negotiated = Self::negotiate_protocol_version(
                    req.params.as_ref(),
                    hdrs.protocol_version.as_deref(),
                );
                let sid = self.sessions.create_session(
                    principal.as_ref().map(|p| p.id.clone()),
                    negotiated.clone(),
                    now,
                    self.session_ttl,
                    self.max_sessions,
                );
                let result = json!({
                    "protocolVersion": negotiated,
                    "capabilities": {
                        "tools": { "listChanged": false },
                        "resources": { "subscribe": false, "listChanged": false },
                        "prompts": { "listChanged": false },
                    },
                    "serverInfo": {
                        "name": self.server_name,
                        "version": self.server_version,
                    },
                });
                let mut resp = jsonrpc_result_response(StatusCode::OK, req.id.as_ref(), result);
                if let Ok(hv) = HeaderValue::from_str(&sid) {
                    resp.headers
                        .insert(HeaderName::from_static(MCP_SESSION_HEADER), hv);
                }
                if let Ok(hv) = HeaderValue::from_str(&negotiated) {
                    resp.headers
                        .insert(HeaderName::from_static(MCP_PROTOCOL_VERSION_HEADER), hv);
                }
                let meta = McpRequestMeta {
                    jsonrpc_id: req.id,
                    method: req.method,
                    is_notification: false,
                    server: "gateway".to_owned(),
                    upstream: None,
                    tool_name: None,
                    backend_tool_name: None,
                    resource_uri: None,
                    prompt_name: None,
                    backend_prompt_name: None,
                    arguments: None,
                    session_id: Some(sid),
                    protocol_version: Some(negotiated),
                    approved,
                    handled_locally: true,
                };
                self.apply_diag_headers(&meta, &mut resp.headers);
                ctx.insert_ext(meta);
                HookResult::Ready(Flow::Respond(resp))
            }
            "notifications/initialized" | "notifications/cancelled" => {
                let meta = McpRequestMeta {
                    jsonrpc_id: None,
                    method: req.method,
                    is_notification: true,
                    server: "gateway".to_owned(),
                    upstream: None,
                    tool_name: None,
                    backend_tool_name: None,
                    resource_uri: None,
                    prompt_name: None,
                    backend_prompt_name: None,
                    arguments: None,
                    session_id: hdrs.session_id,
                    protocol_version: hdrs.protocol_version,
                    approved,
                    handled_locally: true,
                };
                let mut resp = BufferedResponse::new(StatusCode::ACCEPTED, Bytes::new());
                self.apply_diag_headers(&meta, &mut resp.headers);
                ctx.insert_ext(meta);
                HookResult::Ready(Flow::Respond(resp))
            }
            "ping" => {
                let meta = McpRequestMeta {
                    jsonrpc_id: req.id.clone(),
                    method: req.method,
                    is_notification: req.is_notification,
                    server: "gateway".to_owned(),
                    upstream: None,
                    tool_name: None,
                    backend_tool_name: None,
                    resource_uri: None,
                    prompt_name: None,
                    backend_prompt_name: None,
                    arguments: None,
                    session_id: hdrs.session_id,
                    protocol_version: hdrs.protocol_version,
                    approved,
                    handled_locally: true,
                };
                let mut resp = jsonrpc_result_response(StatusCode::OK, req.id.as_ref(), json!({}));
                self.apply_diag_headers(&meta, &mut resp.headers);
                ctx.insert_ext(meta);
                HookResult::Ready(Flow::Respond(resp))
            }
            "tools/list" | "resources/list" | "resources/templates/list" | "prompts/list" => {
                let result_field = match req.method.as_str() {
                    "tools/list" => "tools",
                    "resources/list" => "resources",
                    "resources/templates/list" => "resourceTemplates",
                    _ => "prompts",
                };

                // Fast-path: check if every permitted server has a warm cache entry (or static tools)
                let permitted_servers: Vec<&CompiledServer> = self
                    .servers
                    .values()
                    .filter(|s| {
                        s.enabled && principal.as_ref().is_none_or(|p| p.allows_server(&s.name))
                    })
                    .collect();

                let mut all_warm = true;
                let mut per_server_items: Vec<(&str, Vec<Value>)> =
                    Vec::with_capacity(permitted_servers.len());
                for srv in &permitted_servers {
                    if req.method == "tools/list" && !srv.static_tools.is_empty() {
                        per_server_items.push((srv.name.as_str(), srv.static_tools.clone()));
                        continue;
                    }
                    let cache_key = format!("{}::{}", srv.name, req.method);
                    if self.catalog_ttl > Duration::ZERO
                        && let Some(cached) = self.catalogs.get(&cache_key, now)
                    {
                        per_server_items.push((srv.name.as_str(), cached));
                    } else if srv.endpoint.is_none() {
                        per_server_items.push((srv.name.as_str(), Vec::new()));
                    } else {
                        all_warm = false;
                        break;
                    }
                }

                let meta = McpRequestMeta {
                    jsonrpc_id: req.id.clone(),
                    method: req.method.clone(),
                    is_notification: req.is_notification,
                    server: "gateway".to_owned(),
                    upstream: None,
                    tool_name: None,
                    backend_tool_name: None,
                    resource_uri: None,
                    prompt_name: None,
                    backend_prompt_name: None,
                    arguments: None,
                    session_id: hdrs.session_id.clone(),
                    protocol_version: hdrs.protocol_version.clone(),
                    approved,
                    handled_locally: true,
                };

                if all_warm {
                    let mut aggregated = Vec::new();
                    for (srv_name, items) in per_server_items {
                        match req.method.as_str() {
                            "tools/list" => aggregated.extend(Self::filter_tools_for_principal(
                                &items,
                                srv_name,
                                &self.namespace_separator,
                                principal.as_ref(),
                            )),
                            "prompts/list" => {
                                aggregated.extend(Self::filter_prompts_for_principal(
                                    &items,
                                    srv_name,
                                    &self.namespace_separator,
                                    principal.as_ref(),
                                ))
                            }
                            _ => aggregated.extend(Self::filter_resources_for_principal(
                                &items,
                                principal.as_ref(),
                            )),
                        }
                    }
                    let mut result_map = Map::new();
                    result_map.insert(result_field.to_owned(), Value::Array(aggregated));
                    let mut resp = jsonrpc_result_response(
                        StatusCode::OK,
                        req.id.as_ref(),
                        Value::Object(result_map),
                    );
                    self.apply_diag_headers(&meta, &mut resp.headers);
                    ctx.insert_ext(meta);
                    return HookResult::Ready(Flow::Respond(resp));
                }

                // Cold path: async concurrent fan-out via HttpClient
                let Some(client) = self.http_client.clone() else {
                    ctx.insert_ext(meta);
                    return HookResult::Ready(Flow::Respond(jsonrpc_error_response(
                        StatusCode::BAD_GATEWAY,
                        req.id.as_ref(),
                        MCP_ERR_UPSTREAM_ERROR,
                        "outbound HttpClient is unavailable for MCP catalog discovery",
                        None,
                    )));
                };

                let method = req.method.clone();
                let req_id = req.id.clone();
                let servers = Arc::clone(&self.servers);
                let catalogs = self.catalogs.clone();
                let clock = Arc::clone(&self.clock);
                let sep = self.namespace_separator.clone();
                let timeout = self.discovery_timeout;
                let ttl = self.catalog_ttl;
                let partial_ok = self.partial_discovery_ok;
                let response_headers = self.response_headers;

                ctx.insert_ext(meta.clone());

                HookResult::pending(async move {
                    let permitted_names: Vec<String> = servers
                        .values()
                        .filter(|s| {
                            s.enabled && principal.as_ref().is_none_or(|p| p.allows_server(&s.name))
                        })
                        .map(|s| s.name.clone())
                        .collect();

                    let mut join_set = tokio::task::JoinSet::new();
                    for srv_name in permitted_names {
                        let servers_c = Arc::clone(&servers);
                        let client_c = Arc::clone(&client);
                        let catalogs_c = catalogs.clone();
                        let clock_c = Arc::clone(&clock);
                        let method_c = method.clone();
                        join_set.spawn(async move {
                            let Some(srv) = servers_c.get(&srv_name) else {
                                return (srv_name, Ok(Vec::new()));
                            };
                            let now_inner = clock_c.now();
                            let cache_key = format!("{}::{}", srv.name, method_c);
                            if ttl > Duration::ZERO
                                && let Some(cached) = catalogs_c.get(&cache_key, now_inner)
                            {
                                return (srv_name, Ok(cached));
                            }
                            let res = Self::fetch_server_catalog(
                                client_c.as_ref(),
                                srv,
                                &method_c,
                                result_field,
                                timeout,
                            )
                            .await;
                            if let Ok(ref items) = res
                                && ttl > Duration::ZERO
                            {
                                catalogs_c.insert(cache_key, items.clone(), clock_c.now(), ttl);
                            }
                            (srv_name, res)
                        });
                    }

                    let mut by_server: BTreeMap<String, Vec<Value>> = BTreeMap::new();
                    while let Some(joined) = join_set.join_next().await {
                        match joined {
                            Ok((srv_name, Ok(items))) => {
                                by_server.insert(srv_name, items);
                            }
                            Ok((srv_name, Err(err))) => {
                                if !partial_ok {
                                    return Flow::Respond(jsonrpc_error_response(
                                        StatusCode::BAD_GATEWAY,
                                        req_id.as_ref(),
                                        MCP_ERR_UPSTREAM_ERROR,
                                        err,
                                        None,
                                    ));
                                }
                                warn!(server = %srv_name, error = %err, "MCP discovery failed for server; skipping");
                            }
                            Err(join_err) => {
                                if !partial_ok {
                                    return Flow::Respond(jsonrpc_error_response(
                                        StatusCode::INTERNAL_SERVER_ERROR,
                                        req_id.as_ref(),
                                        MCP_ERR_UPSTREAM_ERROR,
                                        format!("discovery task failed: {join_err}"),
                                        None,
                                    ));
                                }
                            }
                        }
                    }

                    let mut aggregated = Vec::new();
                    for (srv_name, items) in by_server {
                        match method.as_str() {
                            "tools/list" => aggregated.extend(Self::filter_tools_for_principal(
                                &items,
                                &srv_name,
                                &sep,
                                principal.as_ref(),
                            )),
                            "prompts/list" => {
                                aggregated.extend(Self::filter_prompts_for_principal(
                                    &items,
                                    &srv_name,
                                    &sep,
                                    principal.as_ref(),
                                ))
                            }
                            _ => aggregated.extend(Self::filter_resources_for_principal(
                                &items,
                                principal.as_ref(),
                            )),
                        }
                    }

                    let mut result_map = Map::new();
                    result_map.insert(result_field.to_owned(), Value::Array(aggregated));
                    let mut resp = jsonrpc_result_response(
                        StatusCode::OK,
                        req_id.as_ref(),
                        Value::Object(result_map),
                    );
                    if response_headers {
                        if let Ok(v) = HeaderValue::from_str(&meta.server) {
                            resp.headers
                                .insert(HeaderName::from_static("x-shunt-mcp-server"), v);
                        }
                        if let Ok(v) = HeaderValue::from_str(&meta.method) {
                            resp.headers
                                .insert(HeaderName::from_static("x-shunt-mcp-method"), v);
                        }
                    }
                    Flow::Respond(resp)
                })
            }
            "tools/call" => {
                let Some(full_tool) = req.tool_name.clone() else {
                    return HookResult::Ready(Flow::Respond(jsonrpc_error_response(
                        StatusCode::BAD_REQUEST,
                        req.id.as_ref(),
                        JSONRPC_INVALID_PARAMS,
                        "tools/call requires string `params.name`",
                        None,
                    )));
                };

                let Some((srv_name, raw_tool)) =
                    split_namespaced(&full_tool, &self.namespace_separator)
                else {
                    return HookResult::Ready(Flow::Respond(jsonrpc_error_response(
                        StatusCode::BAD_REQUEST,
                        req.id.as_ref(),
                        JSONRPC_INVALID_PARAMS,
                        format!(
                            "tool `{full_tool}` must be namespaced as `<server>{}<tool>`",
                            self.namespace_separator
                        ),
                        None,
                    )));
                };

                let Some(srv) = self.servers.get(srv_name).filter(|s| s.enabled) else {
                    return HookResult::Ready(Flow::Respond(jsonrpc_error_response(
                        StatusCode::NOT_FOUND,
                        req.id.as_ref(),
                        JSONRPC_METHOD_NOT_FOUND,
                        format!("unknown or disabled MCP server `{srv_name}`"),
                        None,
                    )));
                };

                if let Some(ref p) = principal {
                    if !p.allows_server(&srv.name) {
                        return HookResult::Ready(Flow::Respond(jsonrpc_error_response(
                            StatusCode::FORBIDDEN,
                            req.id.as_ref(),
                            MCP_ERR_FORBIDDEN,
                            format!(
                                "principal `{}` is not permitted to access MCP server `{}`",
                                p.id, srv.name
                            ),
                            None,
                        )));
                    }
                    if !p.allows_tool(&full_tool, Some(raw_tool)) {
                        return HookResult::Ready(Flow::Respond(jsonrpc_error_response(
                            StatusCode::FORBIDDEN,
                            req.id.as_ref(),
                            MCP_ERR_FORBIDDEN,
                            format!(
                                "principal `{}` is not permitted to call tool `{full_tool}`",
                                p.id
                            ),
                            None,
                        )));
                    }
                }

                ctx.insert_ext(McpRequestMeta {
                    jsonrpc_id: req.id,
                    method: req.method,
                    is_notification: req.is_notification,
                    server: srv.name.clone(),
                    upstream: Some(srv.upstream.clone()),
                    tool_name: Some(full_tool.clone()),
                    backend_tool_name: Some(raw_tool.to_owned()),
                    resource_uri: None,
                    prompt_name: None,
                    backend_prompt_name: None,
                    arguments: req.arguments,
                    session_id: hdrs.session_id,
                    protocol_version: hdrs.protocol_version,
                    approved,
                    handled_locally: false,
                });
                HookResult::Ready(Flow::Continue)
            }
            "resources/read" | "resources/subscribe" | "resources/unsubscribe" => {
                let Some(uri) = req.resource_uri.clone() else {
                    return HookResult::Ready(Flow::Respond(jsonrpc_error_response(
                        StatusCode::BAD_REQUEST,
                        req.id.as_ref(),
                        JSONRPC_INVALID_PARAMS,
                        format!("{} requires string `params.uri`", req.method),
                        None,
                    )));
                };

                let Some(srv) = self.resolve_server_for_resource(&uri) else {
                    return HookResult::Ready(Flow::Respond(jsonrpc_error_response(
                        StatusCode::NOT_FOUND,
                        req.id.as_ref(),
                        JSONRPC_INVALID_PARAMS,
                        format!("no MCP server owns resource URI `{uri}`"),
                        None,
                    )));
                };

                if let Some(ref p) = principal
                    && (!p.allows_server(&srv.name) || !p.allows_resource(&uri))
                {
                    return HookResult::Ready(Flow::Respond(jsonrpc_error_response(
                        StatusCode::FORBIDDEN,
                        req.id.as_ref(),
                        MCP_ERR_FORBIDDEN,
                        format!(
                            "principal `{}` is not permitted to access resource `{uri}`",
                            p.id
                        ),
                        None,
                    )));
                }

                ctx.insert_ext(McpRequestMeta {
                    jsonrpc_id: req.id,
                    method: req.method,
                    is_notification: req.is_notification,
                    server: srv.name.clone(),
                    upstream: Some(srv.upstream.clone()),
                    tool_name: None,
                    backend_tool_name: None,
                    resource_uri: Some(uri),
                    prompt_name: None,
                    backend_prompt_name: None,
                    arguments: None,
                    session_id: hdrs.session_id,
                    protocol_version: hdrs.protocol_version,
                    approved,
                    handled_locally: false,
                });
                HookResult::Ready(Flow::Continue)
            }
            "prompts/get" => {
                let Some(full_prompt) = req.prompt_name.clone() else {
                    return HookResult::Ready(Flow::Respond(jsonrpc_error_response(
                        StatusCode::BAD_REQUEST,
                        req.id.as_ref(),
                        JSONRPC_INVALID_PARAMS,
                        "prompts/get requires string `params.name`",
                        None,
                    )));
                };

                let Some((srv_name, raw_prompt)) =
                    split_namespaced(&full_prompt, &self.namespace_separator)
                else {
                    return HookResult::Ready(Flow::Respond(jsonrpc_error_response(
                        StatusCode::BAD_REQUEST,
                        req.id.as_ref(),
                        JSONRPC_INVALID_PARAMS,
                        format!(
                            "prompt `{full_prompt}` must be namespaced as `<server>{}<prompt>`",
                            self.namespace_separator
                        ),
                        None,
                    )));
                };

                let Some(srv) = self.servers.get(srv_name).filter(|s| s.enabled) else {
                    return HookResult::Ready(Flow::Respond(jsonrpc_error_response(
                        StatusCode::NOT_FOUND,
                        req.id.as_ref(),
                        JSONRPC_METHOD_NOT_FOUND,
                        format!("unknown or disabled MCP server `{srv_name}`"),
                        None,
                    )));
                };

                if let Some(ref p) = principal
                    && (!p.allows_server(&srv.name)
                        || !p.allows_prompt(&full_prompt, Some(raw_prompt)))
                {
                    return HookResult::Ready(Flow::Respond(jsonrpc_error_response(
                        StatusCode::FORBIDDEN,
                        req.id.as_ref(),
                        MCP_ERR_FORBIDDEN,
                        format!(
                            "principal `{}` is not permitted to get prompt `{full_prompt}`",
                            p.id
                        ),
                        None,
                    )));
                }

                let backend_prompt = raw_prompt.to_owned();
                ctx.insert_ext(McpRequestMeta {
                    jsonrpc_id: req.id,
                    method: req.method,
                    is_notification: req.is_notification,
                    server: srv.name.clone(),
                    upstream: Some(srv.upstream.clone()),
                    tool_name: None,
                    backend_tool_name: None,
                    resource_uri: None,
                    prompt_name: Some(full_prompt),
                    backend_prompt_name: Some(backend_prompt),
                    arguments: req.arguments,
                    session_id: hdrs.session_id,
                    protocol_version: hdrs.protocol_version,
                    approved,
                    handled_locally: false,
                });
                HookResult::Ready(Flow::Continue)
            }
            other => HookResult::Ready(Flow::Respond(jsonrpc_error_response(
                StatusCode::BAD_REQUEST,
                req.id.as_ref(),
                JSONRPC_METHOD_NOT_FOUND,
                format!("unsupported MCP multiplexer method `{other}`"),
                None,
            ))),
        }
    }

    fn on_route<'a>(
        &'a self,
        ctx: &'a mut RequestCtx,
        decision: &'a mut RouteDecision,
    ) -> HookResult<'a, Flow> {
        if let Some(meta) = ctx.get_ext::<McpRequestMeta>()
            && let Some(ref upstream) = meta.upstream
        {
            decision.upstream = upstream.clone();
        }
        HookResult::Ready(Flow::Continue)
    }

    fn on_upstream_select<'a>(
        &'a self,
        ctx: &'a mut RequestCtx,
        selection: &'a mut UpstreamSelection,
    ) -> HookResult<'a, Flow> {
        if let Some(meta) = ctx.get_ext::<McpRequestMeta>()
            && let Some(ref upstream) = meta.upstream
        {
            selection.upstream = upstream.clone();
        }
        HookResult::Ready(Flow::Continue)
    }

    fn on_upstream_request<'a>(
        &'a self,
        ctx: &'a mut RequestCtx,
        req: &'a mut UpstreamRequest,
    ) -> HookResult<'a, Flow> {
        let Some(meta) = ctx.get_ext::<McpRequestMeta>().cloned() else {
            return HookResult::Ready(Flow::Continue);
        };

        // Always strip internal approval header before forwarding upstream
        req.headers.remove("x-shunt-approved");

        if !self.is_multiplexer() {
            if let Some(ref path) = self.upstream_path
                && let Ok(uri) = path.parse::<Uri>()
            {
                req.uri = uri;
            }
            apply_resolved_auth(&self.upstream_auth, &mut req.headers);
            if self.mirror_mcp_name_header
                && let Some(name) = meta
                    .backend_tool_name
                    .as_deref()
                    .or(meta.backend_prompt_name.as_deref())
                    .or(meta.resource_uri.as_deref())
                && let Ok(hv) = HeaderValue::from_str(name)
            {
                req.headers
                    .insert(HeaderName::from_static(MCP_NAME_HEADER), hv);
            }
            return HookResult::Ready(Flow::Continue);
        }

        let Some(srv) = self.servers.get(&meta.server) else {
            return HookResult::Ready(Flow::Continue);
        };

        if let Some(ref path) = srv.path
            && let Ok(uri) = path.parse::<Uri>()
        {
            req.uri = uri;
        }
        apply_resolved_auth(&srv.auth, &mut req.headers);

        if self.mirror_mcp_name_header
            && let Some(name) = meta
                .backend_tool_name
                .as_deref()
                .or(meta.backend_prompt_name.as_deref())
                .or(meta.resource_uri.as_deref())
            && let Ok(hv) = HeaderValue::from_str(name)
        {
            req.headers
                .insert(HeaderName::from_static(MCP_NAME_HEADER), hv);
        }

        // Rewrite namespaced `params.name` to raw backend tool/prompt name on the
        // (potentially guardrail-redacted) buffered body.
        let rewrite_name = meta
            .backend_tool_name
            .as_deref()
            .or(meta.backend_prompt_name.as_deref());
        if let (Some(raw_name), Some(body_bytes)) = (rewrite_name, req.body.as_ref())
            && let Ok(mut doc) = serde_json::from_slice::<Value>(body_bytes)
        {
            if let Some(params) = doc.get_mut("params").and_then(Value::as_object_mut) {
                params.insert("name".to_owned(), Value::String(raw_name.to_owned()));
            }
            if let Ok(rewritten) = serialize_json_bytes(&doc) {
                req.body = Some(rewritten);
                req.headers.remove(header::CONTENT_LENGTH);
            }
        }

        // Remove gateway virtual session ID before forwarding unless mapped to backend session.
        req.headers.remove(MCP_SESSION_HEADER);

        if !srv.stateful {
            return HookResult::Ready(Flow::Continue);
        }

        let now = self.clock.now();
        if let Some(ref gw_sid) = meta.session_id
            && let Some(up_sid) = self.sessions.get_upstream_session(gw_sid, &srv.name, now)
        {
            if let Ok(hv) = HeaderValue::from_str(&up_sid) {
                req.headers
                    .insert(HeaderName::from_static(MCP_SESSION_HEADER), hv);
            }
            return HookResult::Ready(Flow::Continue);
        }

        // Lazy upstream MCP session handshake via HttpClient
        let Some(client) = self.http_client.clone() else {
            return HookResult::Ready(Flow::Continue);
        };
        let Some(endpoint_uri) = srv.endpoint.clone().or_else(|| req.endpoint_uri.clone()) else {
            return HookResult::Ready(Flow::Continue);
        };
        let auth = srv.auth.clone();
        let timeout = self.discovery_timeout;
        let sessions = Arc::clone(&self.sessions);
        let gw_sid = meta.session_id.clone();
        let srv_name = srv.name.clone();
        let req_id = meta.jsonrpc_id.clone();

        HookResult::pending(async move {
            match init_upstream_mcp_session(client.as_ref(), &endpoint_uri, &auth, timeout).await {
                Ok(up_sid) => {
                    if !up_sid.is_empty() {
                        if let Some(ref gsid) = gw_sid {
                            sessions.set_upstream_session(gsid, &srv_name, up_sid.clone());
                        }
                        if let Ok(hv) = HeaderValue::from_str(&up_sid) {
                            req.headers
                                .insert(HeaderName::from_static(MCP_SESSION_HEADER), hv);
                        }
                    }
                    Flow::Continue
                }
                Err(err) => Flow::Respond(jsonrpc_error_response(
                    StatusCode::BAD_GATEWAY,
                    req_id.as_ref(),
                    MCP_ERR_UPSTREAM_ERROR,
                    format!("failed to initialize stateful MCP server `{srv_name}`: {err}"),
                    None,
                )),
            }
        })
    }

    fn on_response_headers<'a>(
        &'a self,
        ctx: &'a mut RequestCtx,
        res: &'a mut ResponseHead,
    ) -> HookResult<'a, Flow> {
        if let Some(meta) = ctx.get_ext::<McpRequestMeta>() {
            self.apply_diag_headers(meta, &mut res.headers);
        }
        HookResult::Ready(Flow::Continue)
    }
}

#[allow(dead_code)]
fn _assert_invalid_request_const_used() -> i64 {
    JSONRPC_INVALID_REQUEST
}
