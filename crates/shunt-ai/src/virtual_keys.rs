use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::Arc;

use arc_swap::ArcSwap;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use shunt_plugin_sdk::{
    BuildContext, Clock, Flow, HeaderName, HookMask, HookResult, HttpPlugin, PluginBuildError,
    PluginConfig, PluginFactory, RequestCtx, RequestHead, StatusCode, SyncedTableSnapshot, header,
};
use tracing::warn;

use crate::cloud_auth::parse_rfc3339_utc_secs;
use crate::model_router::TargetSpec;
use crate::multimodal::{extract_realtime_ws_subprotocol_key, strip_realtime_ws_key_subprotocol};
use crate::types::{
    AiEndpointKind, AiKeyPolicy, AiTarget, BudgetWindow, ModelLimitOverride,
    endpoint_error_response, resolve_env_secret,
};

fn default_true() -> bool {
    true
}

/// Virtual key expiration timestamp accepting either an RFC 3339 UTC string
/// (e.g., `"2027-01-01T00:00:00Z"`) or a Unix epoch seconds integer.
#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
enum ExpiresAtConfig {
    UnixSecs(u64),
    Rfc3339(String),
}

impl ExpiresAtConfig {
    fn to_unix_secs(&self) -> Result<u64, String> {
        match self {
            ExpiresAtConfig::UnixSecs(s) => Ok(*s),
            ExpiresAtConfig::Rfc3339(raw) => parse_rfc3339_utc_secs(raw)
                .map_err(|e| format!("invalid `expires_at` timestamp `{raw}`: {e}")),
        }
    }
}

#[derive(Debug, Deserialize)]
struct VirtualKeyEntryConfig {
    /// Stable virtual key identifier (used in logs, metrics, rate-limit & budget keys).
    id: String,
    /// Client secret key: plaintext, `"env:VAR_NAME"`, or `"sha256:<64-hex-chars>"`.
    /// Named `api_key` so `GET /snapshot` redacts it automatically.
    api_key: String,
    /// Optional organization name for org-level attribution & budgets.
    #[serde(default)]
    org: Option<String>,
    /// Optional team / project name for team-level attribution & budgets.
    #[serde(default)]
    team: Option<String>,
    /// Set to `false` to disable a key without removing it from config (default: true).
    #[serde(default = "default_true")]
    enabled: bool,
    /// Optional UTC expiration timestamp (RFC 3339 string or Unix epoch seconds).
    #[serde(default)]
    expires_at: Option<ExpiresAtConfig>,
    /// Optional glob list of allowed model aliases/names (empty = all allowed).
    #[serde(default)]
    allowed_models: Vec<String>,
    /// Optional glob list of allowed provider IDs (empty = all allowed).
    #[serde(default)]
    allowed_providers: Vec<String>,
    /// Optional per-model target override chains (`model_or_glob -> [TargetSpec]`).
    #[serde(default)]
    provider_overrides: HashMap<String, Vec<TargetSpec>>,
    /// Optional per-key RPM override consumed by `ai-token-rate-limit`.
    #[serde(default)]
    rpm: Option<u64>,
    /// Optional per-key TPM override consumed by `ai-token-rate-limit`.
    #[serde(default)]
    tpm: Option<u64>,
    /// Optional per-key max concurrent in-flight requests consumed by `ai-token-rate-limit`.
    #[serde(default)]
    max_parallel_requests: Option<u64>,
    /// Optional per-key hard spend budget (USD) consumed by `ai-budget`.
    #[serde(default)]
    budget_usd: Option<f64>,
    /// Optional per-key soft warning spend threshold (USD) consumed by `ai-budget`.
    #[serde(default)]
    budget_soft_limit_usd: Option<f64>,
    /// Optional per-key budget window override consumed by `ai-budget`.
    #[serde(default)]
    budget_window: Option<BudgetWindow>,
    /// Optional per-model quota/budget overrides (`model_or_glob -> ModelLimitOverride`).
    #[serde(default)]
    model_limits: HashMap<String, ModelLimitOverride>,
    /// Optional key metadata tags.
    #[serde(default)]
    metadata: BTreeMap<String, String>,
}

#[derive(Debug, Deserialize)]
#[serde(default)]
struct AiVirtualKeysConfig {
    /// Strip client key headers after verification so upstream providers never see virtual keys (default: true).
    #[serde(default = "default_true")]
    strip_key_header: bool,
    /// Accept virtual key via `Authorization: Bearer <key>` (default: true).
    #[serde(default = "default_true")]
    accept_bearer: bool,
    /// Accept virtual key via `x-api-key: <key>` (Anthropic SDKs, default: true).
    #[serde(default = "default_true")]
    accept_x_api_key: bool,
    /// Accept virtual key via OpenAI Realtime WebSocket subprotocol
    /// (`Sec-WebSocket-Protocol: openai-insecure-api-key.<key>`, default: true).
    #[serde(default = "default_true")]
    accept_ws_subprotocol: bool,
    /// Optional custom header name to extract the virtual key from (e.g., `"x-shunt-key"`).
    #[serde(default)]
    custom_header: Option<String>,
    /// Optional Channel 2 `SyncedTable` namespace (e.g., `"ai.virtual_keys"`) supplying live
    /// fleet-wide virtual keys without reloading topology snapshots.
    #[serde(default)]
    sync_namespace: Option<String>,
    /// Configured static virtual keys (merged with `sync_namespace` when both are set).
    #[serde(default)]
    keys: Vec<VirtualKeyEntryConfig>,
}

impl Default for AiVirtualKeysConfig {
    fn default() -> Self {
        Self {
            strip_key_header: true,
            accept_bearer: true,
            accept_x_api_key: true,
            accept_ws_subprotocol: true,
            custom_header: None,
            sync_namespace: None,
            keys: Vec::new(),
        }
    }
}

#[derive(Debug, Deserialize)]
struct SyncedVirtualKeyPayload {
    #[serde(default)]
    id: Option<String>,
    #[serde(default)]
    api_key: Option<String>,
    #[serde(default)]
    key_hashes: Vec<String>,
    #[serde(default)]
    org: Option<String>,
    #[serde(default)]
    team: Option<String>,
    #[serde(default = "default_true")]
    enabled: bool,
    #[serde(default)]
    expires_at: Option<ExpiresAtConfig>,
    #[serde(default)]
    allowed_models: Vec<String>,
    #[serde(default)]
    allowed_providers: Vec<String>,
    #[serde(default)]
    provider_overrides: HashMap<String, Vec<TargetSpec>>,
    #[serde(default)]
    rpm: Option<u64>,
    #[serde(default)]
    tpm: Option<u64>,
    #[serde(default)]
    max_parallel_requests: Option<u64>,
    #[serde(default)]
    budget_usd: Option<f64>,
    #[serde(default)]
    budget_soft_limit_usd: Option<f64>,
    #[serde(default)]
    budget_window: Option<BudgetWindow>,
    #[serde(default)]
    model_limits: HashMap<String, ModelLimitOverride>,
    #[serde(default)]
    metadata: BTreeMap<String, String>,
}

fn compile_synced_virtual_keys(snapshot: &SyncedTableSnapshot) -> Vec<CompiledVirtualKey> {
    let mut compiled = Vec::with_capacity(snapshot.len());
    for (item_key, raw_val) in snapshot.iter() {
        let entry: SyncedVirtualKeyPayload = match serde_json::from_value((**raw_val).clone()) {
            Ok(e) => e,
            Err(err) => {
                warn!(
                    key = %item_key,
                    error = %err,
                    "ignoring malformed synced ai.virtual_keys entry"
                );
                continue;
            }
        };

        let key_id = entry
            .id
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .unwrap_or(item_key.as_ref())
            .to_owned();

        let expires_at_unix_secs = match &entry.expires_at {
            Some(exp) => match exp.to_unix_secs() {
                Ok(ts) => Some(ts),
                Err(msg) => {
                    warn!(key = %key_id, error = %msg, "ignoring synced virtual key with invalid expires_at");
                    continue;
                }
            },
            None => None,
        };

        let mut digests = Vec::new();
        for hash_spec in &entry.key_hashes {
            match compile_key_digest(hash_spec) {
                Ok(d) => digests.push(d),
                Err(msg) => {
                    warn!(key = %key_id, error = %msg, "skipping invalid hash in synced virtual key");
                }
            }
        }
        if let Some(ref single) = entry.api_key {
            match compile_key_digest(single) {
                Ok(d) => digests.push(d),
                Err(msg) => {
                    warn!(key = %key_id, error = %msg, "skipping invalid api_key in synced virtual key");
                }
            }
        }
        if digests.is_empty() {
            continue;
        }

        let mut overrides = HashMap::with_capacity(entry.provider_overrides.len());
        for (model_pat, specs) in entry.provider_overrides {
            if specs.is_empty() {
                continue;
            }
            let targets: Vec<AiTarget> = specs.into_iter().map(|s| s.resolve(&model_pat)).collect();
            overrides.insert(model_pat, targets);
        }

        let policy = AiKeyPolicy {
            key_id,
            org: entry.org,
            team: entry.team,
            allowed_models: entry.allowed_models,
            allowed_providers: entry.allowed_providers,
            provider_overrides: overrides,
            rpm: entry.rpm.filter(|&v| v > 0),
            tpm: entry.tpm.filter(|&v| v > 0),
            max_parallel_requests: entry.max_parallel_requests.filter(|&v| v > 0),
            budget_usd: entry.budget_usd.filter(|b| b.is_finite() && *b >= 0.0),
            budget_soft_limit_usd: entry
                .budget_soft_limit_usd
                .filter(|b| b.is_finite() && *b >= 0.0),
            budget_window: entry.budget_window,
            model_limits: entry.model_limits,
            metadata: entry.metadata,
        };

        for digest in digests {
            compiled.push(CompiledVirtualKey {
                digest,
                enabled: entry.enabled,
                expires_at_unix_secs,
                policy: policy.clone(),
            });
        }
    }
    compiled
}

struct CompiledVirtualKey {
    digest: [u8; 32],
    enabled: bool,
    expires_at_unix_secs: Option<u64>,
    policy: AiKeyPolicy,
}

/// Factory for the `ai-virtual-keys` plugin.
pub struct AiVirtualKeysFactory;

impl PluginFactory for AiVirtualKeysFactory {
    fn name(&self) -> &str {
        "ai-virtual-keys"
    }

    fn build(
        &self,
        config: &PluginConfig,
        ctx: &BuildContext,
    ) -> Result<Arc<dyn HttpPlugin>, PluginBuildError> {
        let cfg: AiVirtualKeysConfig = config.deserialize(self.name())?;
        let sync_namespace = cfg
            .sync_namespace
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_owned);
        if cfg.keys.is_empty() && sync_namespace.is_none() {
            return Err(PluginBuildError::BuildFailed {
                plugin: self.name().to_owned(),
                message:
                    "ai-virtual-keys requires at least one entry in `keys` or a `sync_namespace`"
                        .to_owned(),
            });
        }
        if !cfg.accept_bearer
            && !cfg.accept_x_api_key
            && !cfg.accept_ws_subprotocol
            && cfg.custom_header.is_none()
        {
            return Err(PluginBuildError::BuildFailed {
                plugin: self.name().to_owned(),
                message: "enable at least one key source (`accept_bearer`, `accept_x_api_key`, `accept_ws_subprotocol`, or `custom_header`)".to_owned(),
            });
        }

        let custom_header = match &cfg.custom_header {
            Some(raw) => Some(HeaderName::from_bytes(raw.as_bytes()).map_err(|e| {
                PluginBuildError::BuildFailed {
                    plugin: self.name().to_owned(),
                    message: format!("invalid `custom_header` `{raw}`: {e}"),
                }
            })?),
            None => None,
        };

        let mut seen_ids = HashSet::new();
        let mut compiled = Vec::with_capacity(cfg.keys.len());

        for entry in cfg.keys {
            if entry.id.trim().is_empty() {
                return Err(PluginBuildError::BuildFailed {
                    plugin: self.name().to_owned(),
                    message: "virtual key `id` cannot be empty".to_owned(),
                });
            }
            if !seen_ids.insert(entry.id.clone()) {
                return Err(PluginBuildError::BuildFailed {
                    plugin: self.name().to_owned(),
                    message: format!("duplicate virtual key id `{}`", entry.id),
                });
            }
            if let Some(rpm) = entry.rpm
                && rpm == 0
            {
                return Err(PluginBuildError::BuildFailed {
                    plugin: self.name().to_owned(),
                    message: format!("virtual key `{}`: `rpm` must be >= 1", entry.id),
                });
            }
            if let Some(tpm) = entry.tpm
                && tpm == 0
            {
                return Err(PluginBuildError::BuildFailed {
                    plugin: self.name().to_owned(),
                    message: format!("virtual key `{}`: `tpm` must be >= 1", entry.id),
                });
            }
            if let Some(b) = entry.budget_usd
                && (!b.is_finite() || b < 0.0)
            {
                return Err(PluginBuildError::BuildFailed {
                    plugin: self.name().to_owned(),
                    message: format!(
                        "virtual key `{}`: `budget_usd` must be a non-negative finite number",
                        entry.id
                    ),
                });
            }
            if let Some(sb) = entry.budget_soft_limit_usd
                && (!sb.is_finite() || sb < 0.0)
            {
                return Err(PluginBuildError::BuildFailed {
                    plugin: self.name().to_owned(),
                    message: format!(
                        "virtual key `{}`: `budget_soft_limit_usd` must be a non-negative finite number",
                        entry.id
                    ),
                });
            }

            if let Some(mpr) = entry.max_parallel_requests
                && mpr == 0
            {
                return Err(PluginBuildError::BuildFailed {
                    plugin: self.name().to_owned(),
                    message: format!(
                        "virtual key `{}`: `max_parallel_requests` must be >= 1",
                        entry.id
                    ),
                });
            }
            let expires_at_unix_secs = match &entry.expires_at {
                Some(exp) => {
                    Some(
                        exp.to_unix_secs()
                            .map_err(|msg| PluginBuildError::BuildFailed {
                                plugin: self.name().to_owned(),
                                message: format!("virtual key `{}`: {msg}", entry.id),
                            })?,
                    )
                }
                None => None,
            };
            for (pat, ml) in &entry.model_limits {
                if pat.trim().is_empty() {
                    return Err(PluginBuildError::BuildFailed {
                        plugin: self.name().to_owned(),
                        message: format!(
                            "virtual key `{}`: `model_limits` pattern cannot be empty",
                            entry.id
                        ),
                    });
                }
                if ml.rpm == Some(0) || ml.tpm == Some(0) || ml.max_parallel_requests == Some(0) {
                    return Err(PluginBuildError::BuildFailed {
                        plugin: self.name().to_owned(),
                        message: format!(
                            "virtual key `{}`: `model_limits.{pat}` rpm/tpm/max_parallel_requests must be >= 1",
                            entry.id
                        ),
                    });
                }
                if let Some(b) = ml.budget_usd
                    && (!b.is_finite() || b < 0.0)
                {
                    return Err(PluginBuildError::BuildFailed {
                        plugin: self.name().to_owned(),
                        message: format!(
                            "virtual key `{}`: `model_limits.{pat}.budget_usd` must be non-negative finite",
                            entry.id
                        ),
                    });
                }
                if let Some(sb) = ml.budget_soft_limit_usd
                    && (!sb.is_finite() || sb < 0.0)
                {
                    return Err(PluginBuildError::BuildFailed {
                        plugin: self.name().to_owned(),
                        message: format!(
                            "virtual key `{}`: `model_limits.{pat}.budget_soft_limit_usd` must be non-negative finite",
                            entry.id
                        ),
                    });
                }
            }

            let digest = compile_key_digest(&entry.api_key).map_err(|msg| {
                PluginBuildError::BuildFailed {
                    plugin: self.name().to_owned(),
                    message: format!("virtual key `{}`: {msg}", entry.id),
                }
            })?;

            let mut overrides = HashMap::with_capacity(entry.provider_overrides.len());
            for (model_pat, specs) in entry.provider_overrides {
                if specs.is_empty() {
                    return Err(PluginBuildError::BuildFailed {
                        plugin: self.name().to_owned(),
                        message: format!(
                            "virtual key `{}`: `provider_overrides.{model_pat}` cannot be empty",
                            entry.id
                        ),
                    });
                }
                let targets: Vec<AiTarget> =
                    specs.into_iter().map(|s| s.resolve(&model_pat)).collect();
                overrides.insert(model_pat, targets);
            }

            compiled.push(CompiledVirtualKey {
                digest,
                enabled: entry.enabled,
                expires_at_unix_secs,
                policy: AiKeyPolicy {
                    key_id: entry.id,
                    org: entry.org,
                    team: entry.team,
                    allowed_models: entry.allowed_models,
                    allowed_providers: entry.allowed_providers,
                    provider_overrides: overrides,
                    rpm: entry.rpm,
                    tpm: entry.tpm,
                    max_parallel_requests: entry.max_parallel_requests,
                    budget_usd: entry.budget_usd,
                    budget_soft_limit_usd: entry.budget_soft_limit_usd,
                    budget_window: entry.budget_window,
                    model_limits: entry.model_limits,
                    metadata: entry.metadata,
                },
            });
        }

        let synced_keys = sync_namespace.and_then(|ns| {
            ctx.synced_table(&ns).map(|table| {
                let store = Arc::new(ArcSwap::from_pointee(Vec::<CompiledVirtualKey>::new()));
                let store_sub = Arc::clone(&store);
                table.subscribe(Arc::new(move |snap| {
                    store_sub.store(Arc::new(compile_synced_virtual_keys(snap)));
                }));
                store
            })
        });

        Ok(Arc::new(AiVirtualKeysPlugin {
            strip_key_header: cfg.strip_key_header,
            accept_bearer: cfg.accept_bearer,
            accept_x_api_key: cfg.accept_x_api_key,
            accept_ws_subprotocol: cfg.accept_ws_subprotocol,
            custom_header,
            clock: ctx.clock(),
            keys: compiled,
            synced_keys,
        }))
    }
}

fn compile_key_digest(raw_spec: &str) -> Result<[u8; 32], String> {
    if let Some(hex_str) = raw_spec.strip_prefix("sha256:") {
        decode_hex_32(hex_str.trim())
    } else {
        let resolved = resolve_env_secret(raw_spec)?;
        if resolved.trim().is_empty() {
            return Err("`api_key` resolved to an empty string".to_owned());
        }
        Ok(sha256_bytes(resolved.as_bytes()))
    }
}

fn sha256_bytes(input: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(input);
    let out = hasher.finalize();
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&out);
    arr
}

fn decode_hex_32(hex: &str) -> Result<[u8; 32], String> {
    if hex.len() != 64 {
        return Err(format!(
            "expected 64 hex characters after `sha256:`, got {}",
            hex.len()
        ));
    }
    let bytes = hex.as_bytes();
    let mut out = [0u8; 32];
    for i in 0..32 {
        let hi = hex_nibble(bytes[i * 2])
            .ok_or_else(|| format!("invalid hex character in sha256 digest at index {}", i * 2))?;
        let lo = hex_nibble(bytes[i * 2 + 1]).ok_or_else(|| {
            format!(
                "invalid hex character in sha256 digest at index {}",
                i * 2 + 1
            )
        })?;
        out[i] = (hi << 4) | lo;
    }
    Ok(out)
}

const fn hex_nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// Constant-time 32-byte digest comparison (prevents timing side-channels).
fn constant_time_eq_32(a: &[u8; 32], b: &[u8; 32]) -> bool {
    let mut diff = 0u8;
    for i in 0..32 {
        diff |= a[i] ^ b[i];
    }
    diff == 0
}

fn detect_error_endpoint(path: &str) -> AiEndpointKind {
    let trimmed = if path.len() > 1 {
        path.trim_end_matches('/')
    } else {
        path
    };
    if trimmed.ends_with("/messages/count_tokens") {
        AiEndpointKind::AnthropicCountTokens
    } else if trimmed.ends_with("/messages") {
        AiEndpointKind::AnthropicMessages
    } else if trimmed.ends_with("/responses") {
        AiEndpointKind::OpenAiResponses
    } else if trimmed.ends_with("/embeddings") {
        AiEndpointKind::Embeddings
    } else {
        AiEndpointKind::ChatCompletions
    }
}

/// Virtual API key authentication & multi-tenant policy plugin (`ai-virtual-keys`).
///
/// Runs synchronously (`HookResult::Ready`) in `on_request_headers` against the immutable
/// snapshot's pre-hashed keys with zero heap allocations on mismatch or key lookup.
pub struct AiVirtualKeysPlugin {
    strip_key_header: bool,
    accept_bearer: bool,
    accept_x_api_key: bool,
    accept_ws_subprotocol: bool,
    custom_header: Option<HeaderName>,
    clock: Arc<dyn Clock>,
    keys: Vec<CompiledVirtualKey>,
    synced_keys: Option<Arc<ArcSwap<Vec<CompiledVirtualKey>>>>,
}

impl AiVirtualKeysPlugin {
    fn extract_presented_key(&self, req: &RequestHead) -> Option<String> {
        if let Some(hdr) = &self.custom_header
            && let Some(val) = req
                .headers
                .get(hdr)
                .and_then(|v| v.to_str().ok())
                .map(str::trim)
                .filter(|s| !s.is_empty())
        {
            return Some(val.to_owned());
        }
        if self.accept_bearer
            && let Some(val) = req
                .headers
                .get(header::AUTHORIZATION)
                .and_then(|v| v.to_str().ok())
                .and_then(|s| {
                    s.strip_prefix("Bearer ")
                        .or_else(|| s.strip_prefix("bearer "))
                })
                .map(str::trim)
                .filter(|s| !s.is_empty())
        {
            return Some(val.to_owned());
        }
        if self.accept_x_api_key
            && let Some(val) = req
                .headers
                .get("x-api-key")
                .and_then(|v| v.to_str().ok())
                .map(str::trim)
                .filter(|s| !s.is_empty())
        {
            return Some(val.to_owned());
        }
        if self.accept_ws_subprotocol
            && let Some(val) = extract_realtime_ws_subprotocol_key(&req.headers)
        {
            return Some(val);
        }
        None
    }
}

impl HttpPlugin for AiVirtualKeysPlugin {
    fn name(&self) -> &str {
        "ai-virtual-keys"
    }

    fn hook_mask(&self) -> HookMask {
        HookMask::ON_REQUEST_HEADERS
    }

    fn on_request_headers<'a>(
        &'a self,
        ctx: &'a mut RequestCtx,
        req: &'a mut RequestHead,
    ) -> HookResult<'a, Flow> {
        let endpoint = detect_error_endpoint(req.uri.path());

        let Some(presented) = self.extract_presented_key(req) else {
            let resp = endpoint_error_response(
                endpoint,
                StatusCode::UNAUTHORIZED,
                "authentication_error",
                Some("missing_api_key"),
                "Missing virtual API key",
            );
            return HookResult::Ready(Flow::Respond(resp));
        };

        let presented_digest = sha256_bytes(presented.as_bytes());
        let mut matched: Option<&CompiledVirtualKey> = None;
        for candidate in &self.keys {
            if constant_time_eq_32(&presented_digest, &candidate.digest) {
                matched = Some(candidate);
            }
        }
        let synced_guard = self.synced_keys.as_ref().map(|s| s.load());
        if let Some(ref synced) = synced_guard {
            for candidate in synced.iter() {
                if constant_time_eq_32(&presented_digest, &candidate.digest) {
                    matched = Some(candidate);
                }
            }
        }

        match matched {
            Some(key) if !key.enabled => {
                let resp = endpoint_error_response(
                    endpoint,
                    StatusCode::FORBIDDEN,
                    "permission_error",
                    Some("api_key_disabled"),
                    "Virtual API key is disabled",
                );
                HookResult::Ready(Flow::Respond(resp))
            }
            Some(key)
                if key
                    .expires_at_unix_secs
                    .is_some_and(|exp| self.clock.unix_timestamp_secs() >= exp) =>
            {
                let resp = endpoint_error_response(
                    endpoint,
                    StatusCode::UNAUTHORIZED,
                    "authentication_error",
                    Some("api_key_expired"),
                    "Virtual API key has expired",
                );
                HookResult::Ready(Flow::Respond(resp))
            }
            Some(key) => {
                ctx.insert_ext(key.policy.clone());
                if self.strip_key_header {
                    if self.accept_bearer {
                        req.headers.remove(header::AUTHORIZATION);
                    }
                    if self.accept_x_api_key {
                        req.headers.remove("x-api-key");
                    }
                    if self.accept_ws_subprotocol {
                        strip_realtime_ws_key_subprotocol(&mut req.headers);
                    }
                    if let Some(hdr) = &self.custom_header {
                        req.headers.remove(hdr);
                    }
                }
                HookResult::Ready(Flow::Continue)
            }
            None => {
                let resp = endpoint_error_response(
                    endpoint,
                    StatusCode::UNAUTHORIZED,
                    "authentication_error",
                    Some("invalid_api_key"),
                    "Invalid virtual API key",
                );
                HookResult::Ready(Flow::Respond(resp))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::SocketAddr;
    use std::sync::RwLock;

    use serde_json::json;
    use shunt_plugin_sdk::{
        HeaderMap, HeaderValue, Method, StateStore, SyncedDeltaOp, SyncedTableRegistry, Uri,
        Version,
    };

    #[test]
    fn sha256_digest_parsing_and_matching() {
        let raw = "sk-shunt-alice-12345";
        let d1 = compile_key_digest(raw).unwrap();
        let hex: String = d1.iter().map(|b| format!("{b:02x}")).collect();
        let d2 = compile_key_digest(&format!("sha256:{hex}")).unwrap();
        assert!(constant_time_eq_32(&d1, &d2));
        assert!(compile_key_digest("sha256:short").is_err());
    }

    fn test_req(bearer: &str) -> RequestHead {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::AUTHORIZATION,
            HeaderValue::from_str(&format!("Bearer {bearer}")).unwrap(),
        );
        RequestHead {
            method: Method::POST,
            uri: Uri::from_static("/v1/chat/completions"),
            version: Version::HTTP_11,
            headers,
        }
    }

    fn test_ctx(id: u64) -> RequestCtx {
        let addr: SocketAddr = "127.0.0.1:12345".parse().unwrap();
        RequestCtx::new(id, addr, None)
    }

    fn sha256_prefixed(raw: &str) -> String {
        let d = sha256_bytes(raw.as_bytes());
        let hex: String = d.iter().map(|b| format!("{b:02x}")).collect();
        format!("sha256:{hex}")
    }

    #[test]
    fn sync_namespace_builds_without_registry_for_dry_run_validation() {
        let state = Arc::new(StateStore::new());
        let touched = Arc::new(RwLock::new(HashSet::new()));
        let ctx = BuildContext::new("ai-gateway", state, touched);
        let cfg = PluginConfig::new(json!({ "sync_namespace": "ai.virtual_keys" }));
        let plugin = AiVirtualKeysFactory.build(&cfg, &ctx).unwrap();
        assert_eq!(plugin.hook_mask(), HookMask::ON_REQUEST_HEADERS);
    }

    #[test]
    fn synced_virtual_keys_upsert_rotate_disable_and_revoke_live() {
        let state = Arc::new(StateStore::new());
        let touched = Arc::new(RwLock::new(HashSet::new()));
        let synced = Arc::new(SyncedTableRegistry::new());
        let ctx = BuildContext::new("ai-gateway", state, touched)
            .with_synced_tables(Some(Arc::clone(&synced)));
        let cfg = PluginConfig::new(json!({ "sync_namespace": "ai.virtual_keys" }));
        let plugin = AiVirtualKeysFactory.build(&cfg, &ctx).unwrap();

        let table = synced.get_or_create("ai.virtual_keys");
        let k1 = "sk-shunt-live-primary-1";
        let k2 = "sk-shunt-live-rotated-2";

        // Before upsert, key is rejected.
        let mut rctx = test_ctx(1);
        let mut req = test_req(k1);
        match plugin.on_request_headers(&mut rctx, &mut req) {
            HookResult::Ready(Flow::Respond(resp)) => {
                assert_eq!(resp.status, StatusCode::UNAUTHORIZED)
            }
            _ => panic!("expected 401 before upsert"),
        }

        // Live Channel 2 upsert with dual hashes (rotation grace window).
        table.apply_delta(
            1,
            "vk_search",
            SyncedDeltaOp::Upsert(json!({
                "enabled": true,
                "org": "acme",
                "team": "search",
                "key_hashes": [sha256_prefixed(k1), sha256_prefixed(k2)],
                "allowed_models": ["smart", "gpt-4o*"],
                "rpm": 120,
                "budget_usd": 250.0
            })),
        );

        for (i, candidate) in [k1, k2].into_iter().enumerate() {
            let mut rctx = test_ctx(10 + i as u64);
            let mut req = test_req(candidate);
            let ok = matches!(
                plugin.on_request_headers(&mut rctx, &mut req),
                HookResult::Ready(Flow::Continue)
            );
            assert!(ok, "expected Continue for synced key");
            let pol = rctx.get_ext::<AiKeyPolicy>().expect("policy attached");
            assert_eq!(pol.key_id, "vk_search");
            assert_eq!(pol.team.as_deref(), Some("search"));
            assert_eq!(pol.rpm, Some(120));
            assert_eq!(pol.budget_usd, Some(250.0));
            assert!(req.headers.get(header::AUTHORIZATION).is_none());
        }

        // Disable via delta -> 403 Forbidden.
        table.apply_delta(
            2,
            "vk_search",
            SyncedDeltaOp::Upsert(json!({
                "enabled": false,
                "key_hashes": [sha256_prefixed(k1)]
            })),
        );
        let mut rctx = test_ctx(20);
        let mut req = test_req(k1);
        match plugin.on_request_headers(&mut rctx, &mut req) {
            HookResult::Ready(Flow::Respond(resp)) => {
                assert_eq!(resp.status, StatusCode::FORBIDDEN)
            }
            _ => panic!("expected 403 for disabled synced key"),
        }

        // Delete via delta -> immediate 401 revocation.
        table.apply_delta(3, "vk_search", SyncedDeltaOp::Delete);
        let mut rctx = test_ctx(30);
        let mut req = test_req(k1);
        match plugin.on_request_headers(&mut rctx, &mut req) {
            HookResult::Ready(Flow::Respond(resp)) => {
                assert_eq!(resp.status, StatusCode::UNAUTHORIZED)
            }
            _ => panic!("expected 401 after revocation"),
        }
    }
}
