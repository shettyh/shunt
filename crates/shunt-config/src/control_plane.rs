//! Data-plane Control Plane client (RFC 0023 Channels 1 & 2 + LKG local cache).
//!
//! Connects outbound-only over HTTP/HTTPS to `shunt-console`, keeping `shunt` fully functional
//! behind NATs, firewalls, and private subnets with zero inbound admin ports required:
//! - **Channel 1 (`ControlPlaneConfigProvider`)**: Watches assigned topology revisions over SSE,
//!   fetches signed `GatewayConfig` bundles with `ETag` caching, verifies SHA-256 digest and
//!   optional Ed25519 signature, writes an atomic last-known-good (`topology.lkg`) cache, and
//!   triggers [`ReloadController::reload`].
//! - **Channel 2 (`SyncedTableRegistry`)**: Streams monotonic `full_sync` + `delta` SSE updates
//!   into lock-free in-memory `ArcSwap` tables and checkpoints `state.<ns>.lkg` files so cold
//!   restarts during a console outage continue operating smoothly.
//! - **Heartbeats**: Periodically reports active revision, digest, reload errors, Channel 2
//!   sequence cursors, and redacted runtime status back to `shunt-console`.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use arc_swap::ArcSwap;
use http::{HeaderName, HeaderValue, StatusCode, Uri, header};
use http_body_util::BodyExt;
use ring::aead::{AES_256_GCM, Aad, LessSafeKey, Nonce, UnboundKey};
use ring::rand::{SecureRandom, SystemRandom};
use ring::signature::{ED25519, UnparsedPublicKey};
use serde::{Deserialize, Serialize};
use shunt_engine::{CoreHttpClient, CoreHttpClientConfig};
use shunt_plugin_sdk::{HttpClient, HttpRequest, SyncedDelta, SyncedDeltaOp, SyncedTableRegistry};
use tokio::sync::watch;
use tracing::{debug, info, warn};

use crate::error::ConfigError;
use crate::ir::GatewayConfig;
use crate::provider::{ConfigProvider, LoadedConfig, sha256_hex};
use crate::reloader::ReloadController;

const CACHE_ENVELOPE_PREFIX: &str = "SHUNT_ENC_V1:";

/// Callback supplying redacted runtime status JSON for periodic node heartbeats.
pub type HeartbeatStatusProvider = Arc<dyn Fn() -> serde_json::Value + Send + Sync>;

/// Client configuration for connecting a `shunt` node to `shunt-console`.
#[derive(Debug, Clone)]
pub struct ControlPlaneClientConfig {
    /// Base URL of `shunt-console` (e.g. `https://console.internal:8443`).
    pub base_url: String,
    /// Target cluster slug (e.g. `prod-us`).
    pub cluster: String,
    /// Cluster bootstrap token (for initial enrollment) or persisted node token.
    pub token: String,
    /// Optional human-friendly node name (defaults to hostname or generated ID).
    pub node_name: Option<String>,
    /// Shunt binary version reported in registration & heartbeats.
    pub shunt_version: String,
    /// Key-value node labels used for canary ring targeting (e.g. `ring=canary,region=us-east-1`).
    pub labels: BTreeMap<String, String>,
    /// Optional local cache directory for credentials, `topology.lkg`, and `state.<ns>.lkg`.
    pub cache_dir: Option<PathBuf>,
    /// Optional 32-byte AES-256-GCM key encrypting LKG cache files at rest.
    pub cache_key: Option<[u8; 32]>,
    /// Optional base64-encoded Ed25519 public key for verifying topology bundle signatures.
    pub public_key_b64: Option<String>,
    /// Optional extra PEM root CA bundle for verifying `shunt-console`'s TLS certificate.
    pub ca_cert_pem: Option<Vec<u8>>,
    /// Skip TLS certificate verification (local development only; `false` by default).
    pub insecure_skip_verify: bool,
    /// Heartbeat reporting interval (default: 15s; server may override on registration).
    pub heartbeat_interval: Duration,
    /// Request timeout for control-plane RPCs (default: 10s).
    pub request_timeout: Duration,
    /// Default fallback listen address used only in standby mode before Revision #1 is published.
    pub standby_listen: String,
    /// Default admin UI flag in standby mode before Revision #1 is published.
    pub standby_admin_ui: bool,
    /// Channel 2 namespaces to subscribe to in addition to any registered dynamically.
    pub namespaces: Vec<String>,
}

impl Default for ControlPlaneClientConfig {
    fn default() -> Self {
        Self {
            base_url: "http://127.0.0.1:8443".to_owned(),
            cluster: "default".to_owned(),
            token: String::new(),
            node_name: None,
            shunt_version: env!("CARGO_PKG_VERSION").to_owned(),
            labels: BTreeMap::new(),
            cache_dir: None,
            cache_key: None,
            public_key_b64: None,
            ca_cert_pem: None,
            insecure_skip_verify: false,
            heartbeat_interval: Duration::from_secs(15),
            request_timeout: Duration::from_secs(10),
            standby_listen: "0.0.0.0:8080".to_owned(),
            standby_admin_ui: false,
            namespaces: Vec::new(),
        }
    }
}

// =============================================================================
// Wire Protocol DTOs (`/cp/v1/...`)
// =============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeRegisterRequest {
    pub cluster: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub node_name: Option<String>,
    pub shunt_version: String,
    #[serde(default)]
    pub labels: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeRegisterResponse {
    pub node_id: String,
    pub node_token: String,
    pub cluster: String,
    pub heartbeat_interval_secs: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub public_key_b64: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_revision: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TopologyRevisionEvent {
    pub revision: u64,
    pub digest: String,
    pub url: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TopologyBundleResponse {
    pub revision: u64,
    pub digest: String,
    pub compiled_toml: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature_b64: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeHeartbeatRequest {
    pub node_id: String,
    pub shunt_version: String,
    pub labels: BTreeMap<String, String>,
    pub active_revision: u64,
    pub active_digest: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_reload_error: Option<String>,
    #[serde(default)]
    pub synced_seqs: BTreeMap<String, u64>,
    #[serde(default)]
    pub status: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateDeltaEvent {
    pub seq: u64,
    pub ns: String,
    pub op: String,
    pub key: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateFullSyncEvent {
    pub seq: u64,
    pub ns: String,
    #[serde(default)]
    pub entries: BTreeMap<String, serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PersistedNodeCredentials {
    node_id: String,
    node_token: String,
    cluster: String,
    #[serde(default)]
    public_key_b64: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct CachedTopologyLkg {
    revision: u64,
    digest: String,
    compiled_toml: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct CachedStateLkg {
    namespace: String,
    seq: u64,
    entries: BTreeMap<String, serde_json::Value>,
}

// =============================================================================
// ControlPlaneConfigProvider (Channel 1)
// =============================================================================

#[derive(Debug, Clone)]
struct ActiveCredentials {
    node_id: String,
    node_token: String,
    public_key_b64: Option<String>,
    heartbeat_interval: Duration,
}

/// [`ConfigProvider`] driven by `shunt-console` Channel 1 topology revisions with local LKG
/// cache fallback for outage resilience.
pub struct ControlPlaneConfigProvider {
    config: ControlPlaneClientConfig,
    http: Arc<CoreHttpClient>,
    credentials: RwLock<Option<ActiveCredentials>>,
    current: ArcSwap<LoadedConfig>,
    active_revision: AtomicU64,
    last_reload_error: RwLock<Option<String>>,
    synced_tables: Arc<SyncedTableRegistry>,
}

impl ControlPlaneConfigProvider {
    /// Creates a new [`ControlPlaneConfigProvider`] bound to `synced_tables`.
    ///
    /// Call [`ControlPlaneConfigProvider::bootstrap`] before passing to [`ReloadController`] to
    /// enroll with `shunt-console` (or boot from `--cache-dir` LKG files during an outage).
    pub fn new(
        config: ControlPlaneClientConfig,
        synced_tables: Arc<SyncedTableRegistry>,
    ) -> Result<Self, ConfigError> {
        let http = CoreHttpClient::new(CoreHttpClientConfig {
            connect_timeout: Duration::from_secs(5),
            default_timeout: config.request_timeout,
            default_max_response_bytes: 16 * 1024 * 1024,
            extra_ca_pem: config.ca_cert_pem.clone(),
            insecure_skip_verify: config.insecure_skip_verify,
            ..CoreHttpClientConfig::default()
        })
        .map_err(|e| ConfigError::ControlPlane(format!("HTTP client init failed: {e}")))?;

        for ns in &config.namespaces {
            let _ = synced_tables.get_or_create(ns);
        }

        let standby = build_standby_loaded_config(&config);
        Ok(Self {
            config,
            http: Arc::new(http),
            credentials: RwLock::new(None),
            current: ArcSwap::from_pointee(standby),
            active_revision: AtomicU64::new(0),
            last_reload_error: RwLock::new(None),
            synced_tables,
        })
    }

    /// Returns the attached [`SyncedTableRegistry`].
    pub fn synced_tables(&self) -> &Arc<SyncedTableRegistry> {
        &self.synced_tables
    }

    /// Returns the currently active topology revision number (`0` when in standby).
    pub fn active_revision(&self) -> u64 {
        self.active_revision.load(Ordering::Acquire)
    }

    /// Returns the currently active configuration digest.
    pub fn active_digest(&self) -> String {
        self.current.load().digest.clone()
    }

    /// Returns the enrolled `node_id`, if registered or restored from LKG cache.
    pub fn node_id(&self) -> Option<String> {
        self.credentials
            .read()
            .expect("credentials lock poisoned")
            .as_ref()
            .map(|c| c.node_id.clone())
    }

    /// Returns the last reload error, if the most recent snapshot reload failed.
    pub fn last_reload_error(&self) -> Option<String> {
        self.last_reload_error
            .read()
            .expect("last_reload_error lock poisoned")
            .clone()
    }

    /// Records a reload error (or clears it when `None`) for reporting in subsequent heartbeats.
    pub fn set_reload_error(&self, err: Option<String>) {
        *self
            .last_reload_error
            .write()
            .expect("last_reload_error lock poisoned") = err;
    }

    /// Performs startup bootstrap:
    /// 1. Restores any cached Channel 2 `state.*.lkg` files from `--cache-dir`.
    /// 2. Restores persisted node credentials (or registers with `shunt-console` via `/cp/v1/nodes/register`).
    /// 3. Pulls the assigned topology revision (falling back to `topology.lkg` if the console is
    ///    unreachable, or standby mode if the cluster has no published revisions yet).
    pub async fn bootstrap(&self) -> Result<(), ConfigError> {
        // 1. Pre-load any Channel 2 LKG state checkpoints before opening listeners.
        self.load_cached_state_tables();

        // 2. Load cached credentials or enroll via bootstrap token.
        let mut target_revision: Option<u64> = None;
        if let Some(cached) = self.read_cached_credentials()
            && cached.cluster == self.config.cluster
        {
            debug!(node_id = %cached.node_id, "restored persisted control-plane node credentials");
            *self.credentials.write().expect("credentials lock poisoned") =
                Some(ActiveCredentials {
                    node_id: cached.node_id,
                    node_token: cached.node_token,
                    public_key_b64: self.config.public_key_b64.clone().or(cached.public_key_b64),
                    heartbeat_interval: self.config.heartbeat_interval,
                });
        }

        if self.credentials.read().expect("credentials lock").is_none() {
            match self.register_node().await {
                Ok(resp) => {
                    target_revision = resp.target_revision;
                    let creds = ActiveCredentials {
                        node_id: resp.node_id.clone(),
                        node_token: resp.node_token.clone(),
                        public_key_b64: self
                            .config
                            .public_key_b64
                            .clone()
                            .or(resp.public_key_b64.clone()),
                        heartbeat_interval: Duration::from_secs(
                            resp.heartbeat_interval_secs.max(1),
                        ),
                    };
                    self.write_cached_credentials(&PersistedNodeCredentials {
                        node_id: resp.node_id,
                        node_token: resp.node_token,
                        cluster: resp.cluster,
                        public_key_b64: resp.public_key_b64,
                    });
                    *self.credentials.write().expect("credentials lock poisoned") = Some(creds);
                }
                Err(err) => {
                    // Console unreachable at cold start: allow booting from LKG cache if available.
                    if self.load_cached_topology()? {
                        warn!(
                            error = %err,
                            revision = self.active_revision(),
                            "control plane unreachable on startup; booted from local LKG cache"
                        );
                        return Ok(());
                    }
                    return Err(err);
                }
            }
        }

        // 3. Pull latest assigned revision if known, else query `/revisions/latest`.
        let fetch_res = match target_revision {
            Some(rev) => self.fetch_and_stage_revision(rev, None).await,
            None => self.fetch_latest_assigned_revision().await,
        };

        match fetch_res {
            Ok(Some(rev)) => {
                info!(
                    cluster = %self.config.cluster,
                    revision = rev,
                    digest = %self.active_digest(),
                    "bootstrapped topology from control plane"
                );
                Ok(())
            }
            Ok(None) => {
                // Cluster exists & node is enrolled, but no revision has been published yet.
                if self.load_cached_topology()? {
                    info!(
                        revision = self.active_revision(),
                        "using cached LKG topology while waiting for published revisions"
                    );
                } else {
                    info!(
                        cluster = %self.config.cluster,
                        standby_listen = %self.config.standby_listen,
                        "node enrolled in standby mode; waiting for first published topology revision"
                    );
                }
                Ok(())
            }
            Err(err) => {
                if self.load_cached_topology()? {
                    warn!(
                        error = %err,
                        revision = self.active_revision(),
                        "failed to fetch topology from control plane; booted from local LKG cache"
                    );
                    Ok(())
                } else {
                    Err(err)
                }
            }
        }
    }

    async fn register_node(&self) -> Result<NodeRegisterResponse, ConfigError> {
        let url = format!("{}/cp/v1/nodes/register", self.base_url());
        let uri: Uri = url
            .parse()
            .map_err(|e| ConfigError::ControlPlane(format!("invalid register URL `{url}`: {e}")))?;

        let payload = serde_json::to_vec(&NodeRegisterRequest {
            cluster: self.config.cluster.clone(),
            node_name: self.config.node_name.clone(),
            shunt_version: self.config.shunt_version.clone(),
            labels: self.config.labels.clone(),
        })
        .map_err(|e| ConfigError::ControlPlane(format!("serialize register request: {e}")))?;

        let mut req = HttpRequest::post(uri)
            .with_timeout(self.config.request_timeout)
            .with_header(
                header::CONTENT_TYPE,
                HeaderValue::from_static("application/json"),
            )
            .with_body(payload);
        if !self.config.token.is_empty() {
            req = req.with_header(header::AUTHORIZATION, bearer_header(&self.config.token)?);
        }

        let resp =
            self.http.send(req).await.map_err(|e| {
                ConfigError::ControlPlane(format!("node register request failed: {e}"))
            })?;
        if resp.status != StatusCode::OK && resp.status != StatusCode::CREATED {
            let body = String::from_utf8_lossy(&resp.body);
            return Err(ConfigError::ControlPlane(format!(
                "node registration rejected ({}): {}",
                resp.status, body
            )));
        }

        serde_json::from_slice::<NodeRegisterResponse>(&resp.body)
            .map_err(|e| ConfigError::ControlPlane(format!("invalid register response JSON: {e}")))
    }

    async fn fetch_latest_assigned_revision(&self) -> Result<Option<u64>, ConfigError> {
        let creds = self.require_credentials()?;
        let url = format!(
            "{}/cp/v1/clusters/{}/topology/revisions/assigned?node_id={}",
            self.base_url(),
            url_encode_segment(&self.config.cluster),
            url_encode_segment(&creds.node_id)
        );
        self.fetch_bundle_from_url(&url, None).await
    }

    /// Fetches a specific revision bundle (respecting `If-None-Match`), verifies digest +
    /// optional Ed25519 signature, writes `topology.lkg`, and stages it into `self.current`.
    /// Returns `Ok(Some(rev))` if a new bundle was staged, or `Ok(None)` on `304 Not Modified` / `404`.
    pub async fn fetch_and_stage_revision(
        &self,
        revision: u64,
        explicit_url: Option<&str>,
    ) -> Result<Option<u64>, ConfigError> {
        let url = match explicit_url {
            Some(u) if u.starts_with("http://") || u.starts_with("https://") => u.to_owned(),
            Some(rel) => format!("{}{}", self.base_url(), rel),
            None => format!(
                "{}/cp/v1/clusters/{}/topology/revisions/{}",
                self.base_url(),
                url_encode_segment(&self.config.cluster),
                revision
            ),
        };
        self.fetch_bundle_from_url(&url, Some(self.active_digest()))
            .await
    }

    async fn fetch_bundle_from_url(
        &self,
        url: &str,
        if_none_match: Option<String>,
    ) -> Result<Option<u64>, ConfigError> {
        let creds = self.require_credentials()?;
        let uri: Uri = url
            .parse()
            .map_err(|e| ConfigError::ControlPlane(format!("invalid bundle URL `{url}`: {e}")))?;

        let mut req = HttpRequest::get(uri)
            .with_timeout(self.config.request_timeout)
            .with_header(header::AUTHORIZATION, bearer_header(&creds.node_token)?);
        if let Some(etag) = if_none_match
            && !etag.is_empty()
            && let Ok(val) = HeaderValue::from_str(&format!("\"{etag}\""))
        {
            req = req.with_header(header::IF_NONE_MATCH, val);
        }

        let resp =
            self.http.send(req).await.map_err(|e| {
                ConfigError::ControlPlane(format!("fetch topology bundle failed: {e}"))
            })?;

        if resp.status == StatusCode::NOT_MODIFIED || resp.status == StatusCode::NOT_FOUND {
            return Ok(None);
        }
        if !resp.status.is_success() {
            let body = String::from_utf8_lossy(&resp.body);
            return Err(ConfigError::ControlPlane(format!(
                "fetch topology bundle returned {}: {}",
                resp.status, body
            )));
        }

        let bundle: TopologyBundleResponse = serde_json::from_slice(&resp.body)
            .map_err(|e| ConfigError::ControlPlane(format!("invalid topology bundle JSON: {e}")))?;

        verify_bundle_integrity(&bundle, creds.public_key_b64.as_deref())?;

        let loaded = parse_topology_toml(
            &self.config.cluster,
            bundle.revision,
            &bundle.digest,
            &bundle.compiled_toml,
        )?;

        self.write_cached_topology(&CachedTopologyLkg {
            revision: bundle.revision,
            digest: bundle.digest.clone(),
            compiled_toml: bundle.compiled_toml,
        });

        self.current.store(Arc::new(loaded));
        self.active_revision
            .store(bundle.revision, Ordering::Release);
        Ok(Some(bundle.revision))
    }

    fn base_url(&self) -> &str {
        self.config.base_url.trim_end_matches('/')
    }

    fn require_credentials(&self) -> Result<ActiveCredentials, ConfigError> {
        self.credentials
            .read()
            .expect("credentials lock poisoned")
            .clone()
            .ok_or_else(|| ConfigError::ControlPlane("node is not enrolled yet".to_owned()))
    }

    fn read_cached_credentials(&self) -> Option<PersistedNodeCredentials> {
        let dir = self.config.cache_dir.as_ref()?;
        let path = dir.join("node_credentials.json");
        let bytes = read_cache_file(&path, self.config.cache_key.as_ref()).ok()??;
        serde_json::from_slice(&bytes).ok()
    }

    fn write_cached_credentials(&self, creds: &PersistedNodeCredentials) {
        let Some(dir) = self.config.cache_dir.as_ref() else {
            return;
        };
        if let Ok(bytes) = serde_json::to_vec_pretty(creds)
            && let Err(err) = write_cache_file_atomic(
                &dir.join("node_credentials.json"),
                &bytes,
                self.config.cache_key.as_ref(),
            )
        {
            warn!(error = %err, "failed to persist node credentials to cache-dir");
        }
    }

    fn load_cached_topology(&self) -> Result<bool, ConfigError> {
        let Some(dir) = self.config.cache_dir.as_ref() else {
            return Ok(false);
        };
        let path = dir.join("topology.lkg");
        let Some(bytes) = read_cache_file(&path, self.config.cache_key.as_ref())? else {
            return Ok(false);
        };
        let cached: CachedTopologyLkg = serde_json::from_slice(&bytes).map_err(|e| {
            ConfigError::ControlPlane(format!("corrupt topology.lkg cache file: {e}"))
        })?;
        verify_digest(&cached.compiled_toml, &cached.digest)?;
        let loaded = parse_topology_toml(
            &self.config.cluster,
            cached.revision,
            &cached.digest,
            &cached.compiled_toml,
        )?;
        self.current.store(Arc::new(loaded));
        self.active_revision
            .store(cached.revision, Ordering::Release);
        Ok(true)
    }

    fn write_cached_topology(&self, cached: &CachedTopologyLkg) {
        let Some(dir) = self.config.cache_dir.as_ref() else {
            return;
        };
        if let Ok(bytes) = serde_json::to_vec(cached)
            && let Err(err) = write_cache_file_atomic(
                &dir.join("topology.lkg"),
                &bytes,
                self.config.cache_key.as_ref(),
            )
        {
            warn!(error = %err, "failed to write topology.lkg cache");
        }
    }

    fn load_cached_state_tables(&self) {
        let Some(dir) = self.config.cache_dir.as_ref() else {
            return;
        };
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
                continue;
            };
            if !name.starts_with("state.") || !name.ends_with(".lkg") {
                continue;
            }
            if let Ok(Some(bytes)) = read_cache_file(&path, self.config.cache_key.as_ref())
                && let Ok(cached) = serde_json::from_slice::<CachedStateLkg>(&bytes)
            {
                debug!(
                    namespace = %cached.namespace,
                    seq = cached.seq,
                    entries = cached.entries.len(),
                    "restored Channel 2 state from LKG cache"
                );
                self.synced_tables
                    .replace_full_json(&cached.namespace, cached.seq, cached.entries);
            }
        }
    }

    fn checkpoint_state_namespace(&self, namespace: &str) {
        let Some(dir) = self.config.cache_dir.as_ref() else {
            return;
        };
        let Some(table) = self.synced_tables.get(namespace) else {
            return;
        };
        let snap = table.load();
        let entries: BTreeMap<String, serde_json::Value> = snap
            .iter()
            .map(|(k, v)| (k.to_string(), (**v).clone()))
            .collect();
        let payload = CachedStateLkg {
            namespace: namespace.to_owned(),
            seq: snap.seq,
            entries,
        };
        let sanitized = sanitize_filename_component(namespace);
        let path = dir.join(format!("state.{sanitized}.lkg"));
        if let Ok(bytes) = serde_json::to_vec(&payload)
            && let Err(err) = write_cache_file_atomic(&path, &bytes, self.config.cache_key.as_ref())
        {
            warn!(namespace = %namespace, error = %err, "failed to write state LKG checkpoint");
        }
    }
}

impl ConfigProvider for ControlPlaneConfigProvider {
    fn source_name(&self) -> String {
        format!("control-plane:{}@{}", self.config.cluster, self.base_url())
    }

    fn load(&self) -> Result<LoadedConfig, ConfigError> {
        Ok((**self.current.load()).clone())
    }
}

// =============================================================================
// Background Control-Plane Sync Loops (Channel 1, Channel 2, Heartbeats)
// =============================================================================

/// Handle controlling background Channel 1 topology watch, Channel 2 state sync, and heartbeat
/// reporting tasks.
pub struct ControlPlaneSyncHandle {
    shutdown_tx: watch::Sender<bool>,
    tasks: Vec<tokio::task::JoinHandle<()>>,
}

impl ControlPlaneSyncHandle {
    /// Signals all control-plane background tasks to stop cleanly.
    pub fn stop(self) {
        let _ = self.shutdown_tx.send(true);
        for t in self.tasks {
            t.abort();
        }
    }
}

/// Starts background Channel 1 (topology SSE watch), Channel 2 (`SyncedTable` SSE delta stream),
/// and periodic heartbeat tasks.
pub fn start_control_plane_sync(
    provider: Arc<ControlPlaneConfigProvider>,
    controller: Arc<ReloadController>,
    status_provider: Option<HeartbeatStatusProvider>,
) -> ControlPlaneSyncHandle {
    let (shutdown_tx, shutdown_rx) = watch::channel(false);

    let t1 = tokio::spawn(run_topology_watch_loop(
        Arc::clone(&provider),
        Arc::clone(&controller),
        shutdown_rx.clone(),
    ));
    let t2 = tokio::spawn(run_state_sync_loop(
        Arc::clone(&provider),
        shutdown_rx.clone(),
    ));
    let t3 = tokio::spawn(run_heartbeat_loop(
        provider,
        controller,
        status_provider,
        shutdown_rx,
    ));

    ControlPlaneSyncHandle {
        shutdown_tx,
        tasks: vec![t1, t2, t3],
    }
}

async fn ensure_enrolled(provider: &ControlPlaneConfigProvider) -> Option<ActiveCredentials> {
    if let Ok(creds) = provider.require_credentials() {
        return Some(creds);
    }
    match provider.register_node().await {
        Ok(resp) => {
            let creds = ActiveCredentials {
                node_id: resp.node_id.clone(),
                node_token: resp.node_token.clone(),
                public_key_b64: provider
                    .config
                    .public_key_b64
                    .clone()
                    .or(resp.public_key_b64.clone()),
                heartbeat_interval: Duration::from_secs(resp.heartbeat_interval_secs.max(1)),
            };
            provider.write_cached_credentials(&PersistedNodeCredentials {
                node_id: resp.node_id,
                node_token: resp.node_token,
                cluster: resp.cluster,
                public_key_b64: resp.public_key_b64,
            });
            *provider
                .credentials
                .write()
                .expect("credentials lock poisoned") = Some(creds.clone());
            Some(creds)
        }
        Err(err) => {
            warn!(error = %err, "control-plane re-enrollment attempt failed; will retry");
            None
        }
    }
}

async fn run_topology_watch_loop(
    provider: Arc<ControlPlaneConfigProvider>,
    controller: Arc<ReloadController>,
    mut shutdown: watch::Receiver<bool>,
) {
    let mut backoff = Duration::from_millis(250);
    loop {
        if *shutdown.borrow() {
            break;
        }
        let Some(creds) = ensure_enrolled(&provider).await else {
            if wait_or_shutdown(&mut shutdown, backoff).await {
                break;
            }
            backoff = (backoff * 2).min(Duration::from_secs(15));
            continue;
        };

        let url = format!(
            "{}/cp/v1/clusters/{}/topology/watch?node_id={}",
            provider.base_url(),
            url_encode_segment(&provider.config.cluster),
            url_encode_segment(&creds.node_id)
        );
        let Ok(uri) = url.parse::<Uri>() else {
            warn!(url = %url, "invalid topology watch URL");
            break;
        };
        let Ok(auth) = bearer_header(&creds.node_token) else {
            break;
        };
        let req = HttpRequest::get(uri)
            .with_timeout(provider.config.request_timeout)
            .with_header(header::AUTHORIZATION, auth)
            .with_header(
                header::ACCEPT,
                HeaderValue::from_static("text/event-stream"),
            );

        match provider.http.send_streaming(req).await {
            Ok(resp) if resp.status().is_success() => {
                backoff = Duration::from_millis(250);
                debug!(cluster = %provider.config.cluster, "connected Channel 1 topology SSE stream");
                let mut body = resp.into_body();
                let mut parser = SseParser::default();
                loop {
                    tokio::select! {
                        _ = shutdown.changed() => {
                            if *shutdown.borrow() {
                                return;
                            }
                        }
                        frame = body.frame() => {
                            match frame {
                                Some(Ok(f)) => {
                                    if let Ok(data) = f.into_data() {
                                        for ev in parser.push(&data) {
                                            if ev.event.as_deref() == Some("revision") {
                                                handle_topology_event(&provider, &controller, &ev.data).await;
                                            }
                                        }
                                    }
                                }
                                Some(Err(err)) => {
                                    warn!(error = %err, "Channel 1 topology stream error; reconnecting");
                                    break;
                                }
                                None => {
                                    debug!("Channel 1 topology stream closed by server; reconnecting");
                                    break;
                                }
                            }
                        }
                    }
                }
            }
            Ok(resp) => {
                warn!(status = %resp.status(), "Channel 1 topology watch rejected; backing off");
            }
            Err(err) => {
                warn!(error = %err, "Channel 1 topology watch connect failed; backing off");
            }
        }

        if wait_or_shutdown(&mut shutdown, jittered(backoff)).await {
            break;
        }
        backoff = (backoff * 2).min(Duration::from_secs(15));
    }
}

async fn handle_topology_event(
    provider: &ControlPlaneConfigProvider,
    controller: &ReloadController,
    data: &str,
) {
    let ev: TopologyRevisionEvent = match serde_json::from_str(data) {
        Ok(e) => e,
        Err(err) => {
            warn!(error = %err, "ignoring malformed Channel 1 revision event");
            return;
        }
    };

    if ev.revision == provider.active_revision()
        && digests_match(&ev.digest, &provider.active_digest())
    {
        return;
    }

    match provider
        .fetch_and_stage_revision(ev.revision, Some(&ev.url))
        .await
    {
        Ok(Some(rev)) => match controller.reload() {
            Ok(inspect) => {
                provider.set_reload_error(None);
                info!(
                    revision = rev,
                    snapshot_version = inspect.version,
                    digest = %inspect.digest,
                    "applied Channel 1 topology revision"
                );
            }
            Err(err) => {
                let msg = err.to_string();
                warn!(revision = rev, error = %msg, "Channel 1 snapshot reload failed; retaining previous snapshot");
                provider.set_reload_error(Some(msg));
            }
        },
        Ok(None) => {}
        Err(err) => {
            let msg = err.to_string();
            warn!(revision = ev.revision, error = %msg, "failed to fetch Channel 1 revision bundle");
            provider.set_reload_error(Some(msg));
        }
    }
}

async fn run_state_sync_loop(
    provider: Arc<ControlPlaneConfigProvider>,
    mut shutdown: watch::Receiver<bool>,
) {
    let mut backoff = Duration::from_millis(250);
    let mut last_event_id: Option<String> = None;

    loop {
        if *shutdown.borrow() {
            break;
        }
        let Some(creds) = ensure_enrolled(&provider).await else {
            if wait_or_shutdown(&mut shutdown, backoff).await {
                break;
            }
            backoff = (backoff * 2).min(Duration::from_secs(15));
            continue;
        };

        let mut ns_set = provider.synced_tables.namespaces();
        for ns in &provider.config.namespaces {
            if !ns_set.contains(ns) {
                ns_set.push(ns.clone());
            }
        }
        ns_set.sort();
        ns_set.dedup();

        let cursors = provider.synced_tables.cursors();
        let namespaces_q = ns_set.join(",");
        let cursors_q: String = ns_set
            .iter()
            .map(|ns| format!("{ns}:{}", cursors.get(ns).copied().unwrap_or(0)))
            .collect::<Vec<_>>()
            .join(",");

        let url = format!(
            "{}/cp/v1/clusters/{}/state/stream?namespaces={}&cursors={}",
            provider.base_url(),
            url_encode_segment(&provider.config.cluster),
            url_encode_query_val(&namespaces_q),
            url_encode_query_val(&cursors_q),
        );
        let Ok(uri) = url.parse::<Uri>() else {
            warn!(url = %url, "invalid Channel 2 state stream URL");
            break;
        };
        let Ok(auth) = bearer_header(&creds.node_token) else {
            break;
        };

        let mut req = HttpRequest::get(uri)
            .with_timeout(provider.config.request_timeout)
            .with_header(header::AUTHORIZATION, auth)
            .with_header(
                header::ACCEPT,
                HeaderValue::from_static("text/event-stream"),
            );
        if let Some(ref id) = last_event_id
            && let Ok(val) = HeaderValue::from_str(id)
        {
            req = req.with_header(HeaderName::from_static("last-event-id"), val);
        }

        match provider.http.send_streaming(req).await {
            Ok(resp) if resp.status().is_success() => {
                backoff = Duration::from_millis(250);
                debug!(cluster = %provider.config.cluster, "connected Channel 2 state SSE stream");
                let mut body = resp.into_body();
                let mut parser = SseParser::default();
                loop {
                    tokio::select! {
                        _ = shutdown.changed() => {
                            if *shutdown.borrow() {
                                return;
                            }
                        }
                        frame = body.frame() => {
                            match frame {
                                Some(Ok(f)) => {
                                    if let Ok(data) = f.into_data() {
                                        for ev in parser.push(&data) {
                                            if let Some(id) = ev.id {
                                                last_event_id = Some(id);
                                            }
                                            match ev.event.as_deref() {
                                                Some("full_sync") => {
                                                    if let Ok(fs) = serde_json::from_str::<StateFullSyncEvent>(&ev.data) {
                                                        provider.synced_tables.replace_full_json(&fs.ns, fs.seq, fs.entries);
                                                        provider.checkpoint_state_namespace(&fs.ns);
                                                    }
                                                }
                                                Some("delta") => {
                                                    if let Ok(d) = serde_json::from_str::<StateDeltaEvent>(&ev.data) {
                                                        let op = match d.op.as_str() {
                                                            "delete" => SyncedDeltaOp::Delete,
                                                            _ => SyncedDeltaOp::Upsert(d.value.unwrap_or(serde_json::Value::Null)),
                                                        };
                                                        let ns = d.ns.clone();
                                                        if provider.synced_tables.apply_delta(SyncedDelta {
                                                            seq: d.seq,
                                                            namespace: d.ns,
                                                            key: d.key,
                                                            op,
                                                        }) {
                                                            provider.checkpoint_state_namespace(&ns);
                                                        }
                                                    }
                                                }
                                                _ => {}
                                            }
                                        }
                                    }
                                }
                                Some(Err(err)) => {
                                    warn!(error = %err, "Channel 2 state stream error; reconnecting");
                                    break;
                                }
                                None => {
                                    debug!("Channel 2 state stream closed by server; reconnecting");
                                    break;
                                }
                            }
                        }
                    }
                }
            }
            Ok(resp) => {
                warn!(status = %resp.status(), "Channel 2 state stream rejected; backing off");
            }
            Err(err) => {
                warn!(error = %err, "Channel 2 state stream connect failed; backing off");
            }
        }

        if wait_or_shutdown(&mut shutdown, jittered(backoff)).await {
            break;
        }
        backoff = (backoff * 2).min(Duration::from_secs(15));
    }
}

async fn run_heartbeat_loop(
    provider: Arc<ControlPlaneConfigProvider>,
    controller: Arc<ReloadController>,
    status_provider: Option<HeartbeatStatusProvider>,
    mut shutdown: watch::Receiver<bool>,
) {
    // Send an initial heartbeat shortly after startup so Fleet UI marks the node Synced quickly.
    let mut initial_delay = Duration::from_millis(200);
    loop {
        if wait_or_shutdown(&mut shutdown, initial_delay).await {
            break;
        }

        let Some(creds) = ensure_enrolled(&provider).await else {
            initial_delay = Duration::from_secs(5);
            continue;
        };
        initial_delay = creds.heartbeat_interval.max(Duration::from_secs(1));

        let snap = controller.current_snapshot();
        let upstreams_json: Vec<serde_json::Value> = snap
            .upstream_health_reports()
            .into_iter()
            .map(|r| {
                let total = r.endpoints.len();
                let healthy = r.endpoints.iter().filter(|e| e.healthy).count();
                let avg_probe_ms = {
                    let mut sum_us = 0u64;
                    let mut count = 0u64;
                    for ep in &r.endpoints {
                        if ep.last_probe_latency_us > 0 {
                            sum_us += ep.last_probe_latency_us;
                            count += 1;
                        }
                    }
                    if count > 0 {
                        Some((sum_us as f64 / count as f64) / 1000.0)
                    } else {
                        None
                    }
                };
                serde_json::json!({
                    "id": r.name,
                    "healthy_endpoints": healthy,
                    "total_endpoints": total,
                    "active_probe_ms": avg_probe_ms,
                })
            })
            .collect();
        let extensions = status_provider
            .as_ref()
            .map(|cb| cb())
            .unwrap_or_else(|| serde_json::json!({}));

        let payload = NodeHeartbeatRequest {
            node_id: creds.node_id.clone(),
            shunt_version: provider.config.shunt_version.clone(),
            labels: provider.config.labels.clone(),
            active_revision: provider.active_revision(),
            active_digest: provider.active_digest(),
            last_reload_error: provider.last_reload_error(),
            synced_seqs: provider.synced_tables.cursors(),
            status: serde_json::json!({
                "upstreams": upstreams_json,
                "extensions": extensions,
            }),
        };

        let url = format!(
            "{}/cp/v1/nodes/{}/heartbeat",
            provider.base_url(),
            url_encode_segment(&creds.node_id)
        );
        if let (Ok(uri), Ok(auth), Ok(body)) = (
            url.parse::<Uri>(),
            bearer_header(&creds.node_token),
            serde_json::to_vec(&payload),
        ) {
            let req = HttpRequest::post(uri)
                .with_timeout(provider.config.request_timeout)
                .with_header(header::AUTHORIZATION, auth)
                .with_header(
                    header::CONTENT_TYPE,
                    HeaderValue::from_static("application/json"),
                )
                .with_body(body);
            if let Err(err) = provider.http.send(req).await {
                debug!(error = %err, "control-plane heartbeat failed");
            }
        }
    }
}

async fn wait_or_shutdown(shutdown: &mut watch::Receiver<bool>, dur: Duration) -> bool {
    if *shutdown.borrow() {
        return true;
    }
    tokio::select! {
        _ = shutdown.changed() => *shutdown.borrow(),
        _ = tokio::time::sleep(dur) => false,
    }
}

fn jittered(base: Duration) -> Duration {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.subsec_nanos() as u64)
        .unwrap_or(0);
    let jitter_ms = nanos % 250;
    base + Duration::from_millis(jitter_ms)
}

// =============================================================================
// Integrity, SSE Parser, LKG Cache & Helpers
// =============================================================================

fn build_standby_loaded_config(cfg: &ControlPlaneClientConfig) -> LoadedConfig {
    let mut gw = GatewayConfig::default();
    gw.server.listen = cfg.standby_listen.clone();
    gw.admin.ui = cfg.standby_admin_ui;
    LoadedConfig {
        source_name: format!("control-plane:{}:standby", cfg.cluster),
        config: gw,
        digest: "sha256:0000000000000000000000000000000000000000000000000000000000000000"
            .to_owned(),
    }
}

fn parse_topology_toml(
    cluster: &str,
    revision: u64,
    digest: &str,
    compiled_toml: &str,
) -> Result<LoadedConfig, ConfigError> {
    let source_name = format!("control-plane:{cluster}:rev-{revision}");
    let config: GatewayConfig =
        toml::from_str(compiled_toml).map_err(|source| ConfigError::TomlParse {
            source_name: source_name.clone(),
            source,
        })?;
    Ok(LoadedConfig {
        source_name,
        config,
        digest: normalize_digest(digest),
    })
}

fn normalize_digest(digest: &str) -> String {
    if digest.starts_with("sha256:") {
        digest.to_owned()
    } else {
        format!("sha256:{digest}")
    }
}

fn digests_match(a: &str, b: &str) -> bool {
    a.strip_prefix("sha256:")
        .unwrap_or(a)
        .eq_ignore_ascii_case(b.strip_prefix("sha256:").unwrap_or(b))
}

fn verify_digest(compiled_toml: &str, expected_digest: &str) -> Result<(), ConfigError> {
    let actual = sha256_hex(compiled_toml.as_bytes());
    if !digests_match(&actual, expected_digest) {
        return Err(ConfigError::ControlPlane(format!(
            "topology bundle digest mismatch: expected `{expected_digest}`, got `sha256:{actual}`"
        )));
    }
    Ok(())
}

/// Verifies bundle SHA-256 digest and (when `public_key_b64` is provided) Ed25519 signature over
/// `v1:<revision>:<normalized_digest>`.
pub fn verify_bundle_integrity(
    bundle: &TopologyBundleResponse,
    public_key_b64: Option<&str>,
) -> Result<(), ConfigError> {
    verify_digest(&bundle.compiled_toml, &bundle.digest)?;

    if let Some(pk_b64) = public_key_b64 {
        let sig_b64 = bundle.signature_b64.as_deref().ok_or_else(|| {
            ConfigError::ControlPlane(
                "control-plane public key is pinned, but topology bundle has no signature"
                    .to_owned(),
            )
        })?;
        let pk_bytes = decode_base64(pk_b64).map_err(|e| {
            ConfigError::ControlPlane(format!("invalid Ed25519 public key base64: {e}"))
        })?;
        let sig_bytes = decode_base64(sig_b64).map_err(|e| {
            ConfigError::ControlPlane(format!("invalid Ed25519 signature base64: {e}"))
        })?;
        let msg = format!(
            "v1:{}:{}",
            bundle.revision,
            normalize_digest(&bundle.digest)
        );
        UnparsedPublicKey::new(&ED25519, pk_bytes)
            .verify(msg.as_bytes(), &sig_bytes)
            .map_err(|_| {
                ConfigError::ControlPlane("Ed25519 signature verification failed".to_owned())
            })?;
    }

    Ok(())
}

/// Parses a 32-byte cache encryption key from hex (64 chars) or base64.
pub fn parse_cache_key_32(raw: &str) -> Result<[u8; 32], ConfigError> {
    let trimmed = raw.trim();
    if trimmed.len() == 64 && trimmed.bytes().all(|b| b.is_ascii_hexdigit()) {
        let mut out = [0u8; 32];
        for i in 0..32 {
            out[i] = u8::from_str_radix(&trimmed[i * 2..i * 2 + 2], 16)
                .map_err(|e| ConfigError::ControlPlane(format!("invalid hex cache key: {e}")))?;
        }
        return Ok(out);
    }
    let decoded = decode_base64(trimmed)
        .map_err(|e| ConfigError::ControlPlane(format!("invalid base64 cache key: {e}")))?;
    let arr: [u8; 32] = decoded.try_into().map_err(|_| {
        ConfigError::ControlPlane("cache encryption key must decode to exactly 32 bytes".to_owned())
    })?;
    Ok(arr)
}

fn write_cache_file_atomic(
    path: &Path,
    plaintext: &[u8],
    key: Option<&[u8; 32]>,
) -> Result<(), ConfigError> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| {
            ConfigError::ControlPlane(format!("create cache dir `{}`: {e}", parent.display()))
        })?;
    }
    let payload: Vec<u8> = match key {
        Some(k) => encrypt_cache_bytes(plaintext, k)?,
        None => plaintext.to_vec(),
    };
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let tmp = path.with_extension(format!("tmp.{}.{nonce}", std::process::id()));
    std::fs::write(&tmp, &payload)
        .map_err(|e| ConfigError::ControlPlane(format!("write cache temp file: {e}")))?;
    std::fs::rename(&tmp, path).map_err(|e| {
        let _ = std::fs::remove_file(&tmp);
        ConfigError::ControlPlane(format!("rename cache file `{}`: {e}", path.display()))
    })?;
    Ok(())
}

fn read_cache_file(path: &Path, key: Option<&[u8; 32]>) -> Result<Option<Vec<u8>>, ConfigError> {
    match std::fs::read(path) {
        Ok(raw) => {
            if raw.starts_with(CACHE_ENVELOPE_PREFIX.as_bytes()) {
                let k = key.ok_or_else(|| {
                    ConfigError::ControlPlane(format!(
                        "cache file `{}` is encrypted; set --cache-key-env",
                        path.display()
                    ))
                })?;
                Ok(Some(decrypt_cache_bytes(&raw, k)?))
            } else {
                Ok(Some(raw))
            }
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(err) => Err(ConfigError::ControlPlane(format!(
            "read cache file `{}`: {err}",
            path.display()
        ))),
    }
}

fn encrypt_cache_bytes(plaintext: &[u8], key: &[u8; 32]) -> Result<Vec<u8>, ConfigError> {
    let rng = SystemRandom::new();
    let mut nonce_bytes = [0u8; 12];
    rng.fill(&mut nonce_bytes)
        .map_err(|_| ConfigError::ControlPlane("failed to generate AES-GCM nonce".to_owned()))?;

    let unbound = UnboundKey::new(&AES_256_GCM, key)
        .map_err(|_| ConfigError::ControlPlane("invalid AES-256-GCM cache key".to_owned()))?;
    let sealing = LessSafeKey::new(unbound);
    let mut in_out = plaintext.to_vec();
    sealing
        .seal_in_place_append_tag(
            Nonce::assume_unique_for_key(nonce_bytes),
            Aad::from(CACHE_ENVELOPE_PREFIX.as_bytes()),
            &mut in_out,
        )
        .map_err(|_| ConfigError::ControlPlane("AES-256-GCM encryption failed".to_owned()))?;

    let mut combined = Vec::with_capacity(12 + in_out.len());
    combined.extend_from_slice(&nonce_bytes);
    combined.extend_from_slice(&in_out);
    let mut out = CACHE_ENVELOPE_PREFIX.as_bytes().to_vec();
    out.extend_from_slice(encode_base64(&combined).as_bytes());
    Ok(out)
}

fn decrypt_cache_bytes(raw: &[u8], key: &[u8; 32]) -> Result<Vec<u8>, ConfigError> {
    let encoded = std::str::from_utf8(
        raw.strip_prefix(CACHE_ENVELOPE_PREFIX.as_bytes())
            .ok_or_else(|| {
                ConfigError::ControlPlane("missing encrypted cache prefix".to_owned())
            })?,
    )
    .map_err(|e| ConfigError::ControlPlane(format!("invalid UTF-8 in encrypted cache: {e}")))?;
    let combined = decode_base64(encoded.trim()).map_err(|e| {
        ConfigError::ControlPlane(format!("invalid base64 in encrypted cache: {e}"))
    })?;
    if combined.len() < 12 + 16 {
        return Err(ConfigError::ControlPlane(
            "encrypted cache payload truncated".to_owned(),
        ));
    }
    let (nonce_slice, cipher) = combined.split_at(12);
    let mut nonce_bytes = [0u8; 12];
    nonce_bytes.copy_from_slice(nonce_slice);

    let unbound = UnboundKey::new(&AES_256_GCM, key)
        .map_err(|_| ConfigError::ControlPlane("invalid AES-256-GCM cache key".to_owned()))?;
    let opening = LessSafeKey::new(unbound);
    let mut buf = cipher.to_vec();
    let plain = opening
        .open_in_place(
            Nonce::assume_unique_for_key(nonce_bytes),
            Aad::from(CACHE_ENVELOPE_PREFIX.as_bytes()),
            &mut buf,
        )
        .map_err(|_| {
            ConfigError::ControlPlane(
                "failed to decrypt LKG cache file (wrong key or tampered file)".to_owned(),
            )
        })?;
    Ok(plain.to_vec())
}

fn sanitize_filename_component(s: &str) -> String {
    s.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect()
}

fn bearer_header(token: &str) -> Result<HeaderValue, ConfigError> {
    HeaderValue::from_str(&format!("Bearer {token}"))
        .map_err(|e| ConfigError::ControlPlane(format!("invalid bearer token header: {e}")))
}

fn url_encode_segment(s: &str) -> String {
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

fn url_encode_query_val(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~' | b',' | b':') {
            out.push(b as char);
        } else {
            use std::fmt::Write as _;
            let _ = write!(out, "%{b:02X}");
        }
    }
    out
}

/// Parsed Server-Sent Event frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SseFrame {
    pub event: Option<String>,
    pub id: Option<String>,
    pub data: String,
}

/// Incremental Server-Sent Events (SSE) parser resilient to arbitrary TCP chunk splits.
#[derive(Debug, Default)]
pub struct SseParser {
    buf: String,
    cur_event: Option<String>,
    cur_id: Option<String>,
    cur_data: Vec<String>,
}

impl SseParser {
    /// Feeds raw bytes from an HTTP streaming body and returns all complete SSE frames.
    pub fn push(&mut self, bytes: &[u8]) -> Vec<SseFrame> {
        let text = String::from_utf8_lossy(bytes);
        self.buf.push_str(&text);
        let mut out = Vec::new();

        while let Some(pos) = self.buf.find('\n') {
            let mut line = self.buf[..pos].to_owned();
            self.buf.drain(..=pos);
            if line.ends_with('\r') {
                line.pop();
            }

            if line.is_empty() {
                if !self.cur_data.is_empty() || self.cur_event.is_some() {
                    out.push(SseFrame {
                        event: self.cur_event.take(),
                        id: self.cur_id.take(),
                        data: self.cur_data.join("\n"),
                    });
                    self.cur_data.clear();
                }
                continue;
            }

            if line.starts_with(':') {
                continue;
            }

            let (field, val) = match line.split_once(':') {
                Some((f, v)) => (f, v.strip_prefix(' ').unwrap_or(v)),
                None => (line.as_str(), ""),
            };
            match field {
                "event" => self.cur_event = Some(val.to_owned()),
                "id" => self.cur_id = Some(val.to_owned()),
                "data" => self.cur_data.push(val.to_owned()),
                _ => {}
            }
        }
        out
    }
}

/// Parses comma-separated `k=v,k2=v2` node labels passed via `--node-labels`.
pub fn parse_node_labels(raw: &str) -> Result<BTreeMap<String, String>, ConfigError> {
    let mut map = BTreeMap::new();
    for part in raw.split(',').map(str::trim).filter(|s| !s.is_empty()) {
        let Some((k, v)) = part.split_once('=') else {
            return Err(ConfigError::ControlPlane(format!(
                "invalid --node-labels entry `{part}`: expected `key=value`"
            )));
        };
        let key = k.trim();
        let val = v.trim();
        if key.is_empty() || val.is_empty() {
            return Err(ConfigError::ControlPlane(format!(
                "invalid --node-labels entry `{part}`: empty key or value"
            )));
        }
        map.insert(key.to_owned(), val.to_owned());
    }
    Ok(map)
}

fn encode_base64(input: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
    for chunk in input.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = chunk.get(1).copied().unwrap_or(0) as u32;
        let b2 = chunk.get(2).copied().unwrap_or(0) as u32;
        let n = (b0 << 16) | (b1 << 8) | b2;
        out.push(TABLE[((n >> 18) & 0x3f) as usize] as char);
        out.push(TABLE[((n >> 12) & 0x3f) as usize] as char);
        if chunk.len() > 1 {
            out.push(TABLE[((n >> 6) & 0x3f) as usize] as char);
        } else {
            out.push('=');
        }
        if chunk.len() > 2 {
            out.push(TABLE[(n & 0x3f) as usize] as char);
        } else {
            out.push('=');
        }
    }
    out
}

fn decode_base64(input: &str) -> Result<Vec<u8>, String> {
    let cleaned: Vec<u8> = input.bytes().filter(|b| !b.is_ascii_whitespace()).collect();
    if !cleaned.len().is_multiple_of(4) {
        return Err("base64 length must be a multiple of 4".to_owned());
    }
    let val = |c: u8| -> Result<u8, String> {
        match c {
            b'A'..=b'Z' => Ok(c - b'A'),
            b'a'..=b'z' => Ok(c - b'a' + 26),
            b'0'..=b'9' => Ok(c - b'0' + 52),
            b'+' | b'-' => Ok(62),
            b'/' | b'_' => Ok(63),
            _ => Err(format!("invalid base64 byte `{}`", c as char)),
        }
    };
    let mut out = Vec::with_capacity(cleaned.len() / 4 * 3);
    for chunk in cleaned.chunks_exact(4) {
        let a = val(chunk[0])?;
        let b = val(chunk[1])?;
        out.push((a << 2) | (b >> 4));
        if chunk[2] != b'=' {
            let c = val(chunk[2])?;
            out.push((b << 4) | (c >> 2));
            if chunk[3] != b'=' {
                let d = val(chunk[3])?;
                out.push((c << 6) | d);
            }
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use ring::signature::{Ed25519KeyPair, KeyPair};

    use super::*;

    #[test]
    fn sse_parser_handles_split_chunks_and_comments() {
        let mut parser = SseParser::default();
        assert!(parser.push(b": keep-alive\n\nevent: del").is_empty());
        let frames = parser.push(b"ta\nid: 42\ndata: {\"seq\":42}\n\n");
        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0].event.as_deref(), Some("delta"));
        assert_eq!(frames[0].id.as_deref(), Some("42"));
        assert_eq!(frames[0].data, "{\"seq\":42}");
    }

    #[test]
    fn cache_encryption_roundtrip_and_tamper_detection() {
        let key = [7u8; 32];
        let secret = b"secret topology payload";
        let encrypted = encrypt_cache_bytes(secret, &key).unwrap();
        assert!(encrypted.starts_with(CACHE_ENVELOPE_PREFIX.as_bytes()));
        assert!(!String::from_utf8_lossy(&encrypted).contains("secret topology"));

        let decrypted = decrypt_cache_bytes(&encrypted, &key).unwrap();
        assert_eq!(decrypted, secret);

        // Wrong key fails cleanly.
        let wrong_key = [8u8; 32];
        assert!(decrypt_cache_bytes(&encrypted, &wrong_key).is_err());
    }

    #[test]
    fn bundle_ed25519_signature_and_digest_verification() {
        let rng = SystemRandom::new();
        let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
        let kp = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap();
        let pk_b64 = encode_base64(kp.public_key().as_ref());

        let toml_src = "[server]\nlisten = \"127.0.0.1:8080\"\n";
        let digest = format!("sha256:{}", sha256_hex(toml_src.as_bytes()));
        let msg = format!("v1:3:{digest}");
        let sig = kp.sign(msg.as_bytes());
        let bundle = TopologyBundleResponse {
            revision: 3,
            digest,
            compiled_toml: toml_src.to_owned(),
            signature_b64: Some(encode_base64(sig.as_ref())),
        };

        verify_bundle_integrity(&bundle, Some(&pk_b64)).unwrap();

        let mut tampered = bundle.clone();
        tampered.compiled_toml.push_str("# tampered\n");
        assert!(verify_bundle_integrity(&tampered, Some(&pk_b64)).is_err());
    }

    #[test]
    fn parse_node_labels_parses_pairs_and_rejects_malformed() {
        let labels = parse_node_labels("ring=canary, region=us-east-1").unwrap();
        assert_eq!(labels.get("ring").map(String::as_str), Some("canary"));
        assert_eq!(labels.get("region").map(String::as_str), Some("us-east-1"));
        assert!(parse_node_labels("broken").is_err());
        assert!(parse_node_labels("key=").is_err());
    }
}
