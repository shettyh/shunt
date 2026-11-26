//! Kubernetes Gateway API `ConfigProvider` implementations and zero-`kube-rs`
//! API client (built strictly on [`shunt_plugin_sdk::HttpClient`]).

use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use arc_swap::ArcSwap;
use serde::Deserialize;
use serde_json::{Value as JsonValue, json};
use shunt_engine::{CoreHttpClient, CoreHttpClientConfig};
use shunt_plugin_sdk::{HeaderValue, HttpClient, HttpRequest, Method, Uri, header};
use tokio::sync::watch;
use tracing::{debug, info, warn};

use crate::error::ConfigError;
use crate::provider::{ConfigProvider, LoadedConfig, sha256_hex};
use crate::reloader::ReloadController;

use super::K8sGatewayOptions;
use super::compiler::{
    CompiledK8sCluster, DesiredK8sService, PortAllocator, compile_k8s_gateway_cluster,
    compile_k8s_gateway_snapshot,
};
use super::status::{K8sGatewayAddress, K8sStatusPlan};
use super::types::{
    K8sClusterSnapshot, K8sEndpointSlice, K8sEndpoints, K8sGateway, K8sGatewayClass, K8sHttpRoute,
    K8sListEnvelope, K8sNamespace, K8sReferenceGrant, K8sSecret, K8sService,
};

const MANAGED_BY_LABEL: &str = "app.kubernetes.io/managed-by";
const MANAGED_BY_VALUE: &str = "shunt";
const GATEWAY_NS_LABEL: &str = "shunt.io/gateway-namespace";
const GATEWAY_NAME_LABEL: &str = "shunt.io/gateway-name";
const TOKEN_REFRESH_INTERVAL: Duration = Duration::from_secs(60);

// =============================================================================
// ConfigProvider #1: Local Kubernetes Gateway API YAML Manifest(s)
// =============================================================================

/// File/directory [`ConfigProvider`] that compiles Kubernetes Gateway API YAML manifests
/// into Shunt's [`crate::GatewayConfig`] IR (supports live hot reloads via `start_file_watcher`).
#[derive(Debug, Clone)]
pub struct K8sManifestConfigProvider {
    path: PathBuf,
    options: K8sGatewayOptions,
}

impl K8sManifestConfigProvider {
    pub fn new(path: impl Into<PathBuf>, options: K8sGatewayOptions) -> Self {
        Self {
            path: path.into(),
            options,
        }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl ConfigProvider for K8sManifestConfigProvider {
    fn source_name(&self) -> String {
        format!("k8s-manifest:{}", self.path.display())
    }

    fn load(&self) -> Result<LoadedConfig, ConfigError> {
        let (snap, digest) = K8sClusterSnapshot::from_path(&self.path)?;
        let config = compile_k8s_gateway_snapshot(&snap, &self.options)?;
        Ok(LoadedConfig {
            source_name: self.source_name(),
            config,
            digest,
        })
    }
}

// =============================================================================
// ConfigProvider #2: Live Kubernetes API Server Client & Controller Transport
// =============================================================================

/// Connection configuration for talking to a Kubernetes API server.
#[derive(Debug, Clone)]
pub struct K8sClientConfig {
    pub api_server: String,
    pub bearer_token: Option<String>,
    /// Optional path to a projected ServiceAccount token file (reloaded periodically and on 401).
    pub token_path: Option<PathBuf>,
    pub ca_cert_pem: Option<Vec<u8>>,
    pub insecure_skip_verify: bool,
    pub request_timeout: Duration,
    pub poll_interval: Duration,
}

impl Default for K8sClientConfig {
    fn default() -> Self {
        Self {
            api_server: "https://kubernetes.default.svc:443".to_owned(),
            bearer_token: None,
            token_path: None,
            ca_cert_pem: None,
            insecure_skip_verify: false,
            request_timeout: Duration::from_secs(10),
            poll_interval: Duration::from_secs(5),
        }
    }
}

impl K8sClientConfig {
    /// Discovers in-cluster Kubernetes API credentials from standard ServiceAccount mount paths
    /// (`KUBERNETES_SERVICE_HOST`, `KUBERNETES_SERVICE_PORT`, and `/var/run/secrets/kubernetes.io/serviceaccount/*`).
    pub fn from_in_cluster() -> Result<Self, ConfigError> {
        let host = std::env::var("KUBERNETES_SERVICE_HOST").map_err(|_| {
            ConfigError::K8s(
                "KUBERNETES_SERVICE_HOST is not set (pass `--k8s-api-server` outside a cluster)"
                    .to_owned(),
            )
        })?;
        let port = std::env::var("KUBERNETES_SERVICE_PORT").unwrap_or_else(|_| "443".to_owned());
        let api_server = if host.contains(':') && !host.starts_with('[') {
            format!("https://[{host}]:{port}")
        } else {
            format!("https://{host}:{port}")
        };
        let token_path = PathBuf::from("/var/run/secrets/kubernetes.io/serviceaccount/token");
        let bearer_token = std::fs::read_to_string(&token_path)
            .map(|s| s.trim().to_owned())
            .map_err(|e| {
                ConfigError::K8s(format!(
                    "failed to read ServiceAccount token `{}`: {e}",
                    token_path.display()
                ))
            })?;
        let ca_path = Path::new("/var/run/secrets/kubernetes.io/serviceaccount/ca.crt");
        let ca_cert_pem = std::fs::read(ca_path).ok();

        Ok(Self {
            api_server,
            bearer_token: Some(bearer_token),
            token_path: Some(token_path),
            ca_cert_pem,
            insecure_skip_verify: false,
            request_timeout: Duration::from_secs(10),
            poll_interval: Duration::from_secs(5),
        })
    }
}

struct TokenState {
    token: Option<String>,
    loaded_at: Instant,
}

/// Live Kubernetes Gateway API [`ConfigProvider`] and controller API client backed by [`HttpClient`].
pub struct K8sApiConfigProvider {
    client_cfg: K8sClientConfig,
    options: K8sGatewayOptions,
    http_client: Arc<dyn HttpClient>,
    latest: ArcSwap<Option<LoadedConfig>>,
    token_state: Mutex<TokenState>,
    /// Last-patched canonical status digest per `(resource_path)` (ignoring `lastTransitionTime`)
    /// so unchanged statuses emit zero PATCH calls and keep `lastTransitionTime` stable.
    status_digests: Mutex<HashMap<String, String>>,
}

impl K8sApiConfigProvider {
    /// Creates a provider using Shunt's built-in pooled [`CoreHttpClient`].
    pub fn new(
        client_cfg: K8sClientConfig,
        options: K8sGatewayOptions,
    ) -> Result<Self, ConfigError> {
        let http_cfg = CoreHttpClientConfig {
            default_timeout: client_cfg.request_timeout,
            extra_ca_pem: client_cfg.ca_cert_pem.clone(),
            insecure_skip_verify: client_cfg.insecure_skip_verify,
            ..CoreHttpClientConfig::default()
        };
        let client = CoreHttpClient::new(http_cfg)?;
        Ok(Self::with_http_client(
            client_cfg,
            options,
            Arc::new(client),
        ))
    }

    /// Creates a provider using a custom [`HttpClient`] (ideal for mock/unit tests).
    pub fn with_http_client(
        client_cfg: K8sClientConfig,
        options: K8sGatewayOptions,
        http_client: Arc<dyn HttpClient>,
    ) -> Self {
        let initial_token = client_cfg.bearer_token.clone();
        Self {
            client_cfg,
            options,
            http_client,
            latest: ArcSwap::from_pointee(None),
            token_state: Mutex::new(TokenState {
                token: initial_token,
                loaded_at: Instant::now(),
            }),
            status_digests: Mutex::new(HashMap::new()),
        }
    }

    pub fn poll_interval(&self) -> Duration {
        self.client_cfg.poll_interval
    }

    pub fn options(&self) -> &K8sGatewayOptions {
        &self.options
    }

    /// Fetches a complete point-in-time [`K8sClusterSnapshot`] from the Kubernetes API server.
    pub async fn fetch_snapshot(&self) -> Result<K8sClusterSnapshot, ConfigError> {
        let ns_seg = match &self.options.namespace {
            Some(ns) => format!("namespaces/{ns}/"),
            None => String::new(),
        };

        let namespaces: Vec<K8sNamespace> = self.fetch_list_optional("/api/v1/namespaces").await?;
        let gateway_classes: Vec<K8sGatewayClass> = self
            .fetch_list("/apis/gateway.networking.k8s.io/v1/gatewayclasses")
            .await?;
        let gateways: Vec<K8sGateway> = self
            .fetch_list(&format!(
                "/apis/gateway.networking.k8s.io/v1/{ns_seg}gateways"
            ))
            .await?;
        let http_routes: Vec<K8sHttpRoute> = self
            .fetch_list(&format!(
                "/apis/gateway.networking.k8s.io/v1/{ns_seg}httproutes"
            ))
            .await?;

        // Gateway API ReferenceGrant lives in v1beta1 (v1.0-v1.3) and v1 (v1.4+); try v1beta1 then v1.
        let mut reference_grants: Vec<K8sReferenceGrant> = self
            .fetch_list_optional(&format!(
                "/apis/gateway.networking.k8s.io/v1beta1/{ns_seg}referencegrants"
            ))
            .await?;
        if reference_grants.is_empty() {
            reference_grants = self
                .fetch_list_optional(&format!(
                    "/apis/gateway.networking.k8s.io/v1/{ns_seg}referencegrants"
                ))
                .await?;
        }

        let services: Vec<K8sService> = self
            .fetch_list(&format!("/api/v1/{ns_seg}services"))
            .await?;
        let endpoints: Vec<K8sEndpoints> = self
            .fetch_list_optional(&format!("/api/v1/{ns_seg}endpoints"))
            .await?;
        let endpoint_slices: Vec<K8sEndpointSlice> = self
            .fetch_list_optional(&format!("/apis/discovery.k8s.io/v1/{ns_seg}endpointslices"))
            .await?;

        // Only fetch Secrets actually referenced by Gateway TLS listeners or client-CA annotations.
        // Missing/forbidden Secrets are skipped cleanly so fault isolation sets ResolvedRefs=False.
        let mut needed_secrets: HashSet<(String, String)> = HashSet::new();
        for gw in &gateways {
            let gw_ns = gw.metadata.effective_namespace().to_owned();
            if let Some(ca_sec) = gw.metadata.annotations.get("shunt.io/client-ca-secret") {
                needed_secrets.insert((gw_ns.clone(), ca_sec.clone()));
            }
            for listener in &gw.spec.listeners {
                if let Some(tls) = &listener.tls {
                    for cref in &tls.certificate_refs {
                        let s_ns = cref.namespace.clone().unwrap_or_else(|| gw_ns.clone());
                        needed_secrets.insert((s_ns, cref.name.clone()));
                    }
                }
            }
        }
        let mut secrets = Vec::with_capacity(needed_secrets.len());
        let mut sorted_secret_keys: Vec<(String, String)> = needed_secrets.into_iter().collect();
        sorted_secret_keys.sort();
        for (s_ns, s_name) in sorted_secret_keys {
            if let Some(sec) = self
                .fetch_single_optional::<K8sSecret>(&format!(
                    "/api/v1/namespaces/{s_ns}/secrets/{s_name}"
                ))
                .await?
            {
                secrets.push(sec);
            }
        }

        Ok(K8sClusterSnapshot {
            namespaces,
            gateway_classes,
            gateways,
            http_routes,
            reference_grants,
            services,
            endpoints,
            endpoint_slices,
            secrets,
        })
    }

    /// Synchronizes once against the Kubernetes API server into a single [`LoadedConfig`]
    /// (read-only `--k8s-gateway` mode).
    pub async fn sync_once(&self) -> Result<bool, ConfigError> {
        let snap = self.fetch_snapshot().await?;
        let config = compile_k8s_gateway_snapshot(&snap, &self.options)?;
        let canonical = serde_json::to_vec(&config)
            .map_err(|e| ConfigError::K8s(format!("failed to hash compiled config: {e}")))?;
        let digest = sha256_hex(&canonical);

        let prev_digest = self
            .latest
            .load()
            .as_ref()
            .as_ref()
            .map(|l| l.digest.clone());
        let changed = prev_digest.as_deref() != Some(digest.as_str());

        let loaded = LoadedConfig {
            source_name: self.source_name(),
            config,
            digest,
        };
        self.latest.store(Arc::new(Some(loaded)));
        Ok(changed)
    }

    /// Full controller reconciliation cycle:
    /// 1. Fetch cluster snapshot.
    /// 2. Compile multi-Gateway listeners, desired Services, and status plan.
    /// 3. If `manage_services` is enabled, reconcile per-Gateway Kubernetes Services and
    ///    refresh `Gateway.status.addresses` immediately from created/updated Services.
    pub async fn sync_cluster_once(
        &self,
        allocator: &mut PortAllocator,
    ) -> Result<CompiledK8sCluster, ConfigError> {
        let snap = self.fetch_snapshot().await?;
        let mut compiled = compile_k8s_gateway_cluster(&snap, &self.options, allocator);

        if self.options.manage_services {
            let reconciled_svcs = self
                .reconcile_services(&compiled.desired_services, &snap.services)
                .await?;
            // Immediately fold newly created/updated Service addresses into Gateway.status
            // so conformance tests see `Gateway.status.addresses` on the very first sync!
            for svc in reconciled_svcs {
                if let Some(gw_ns) = svc.metadata.labels.get(GATEWAY_NS_LABEL)
                    && let Some(gw_name) = svc.metadata.labels.get(GATEWAY_NAME_LABEL)
                    && let Some(gw_status) = compiled
                        .status_plan
                        .gateways
                        .get_mut(&(gw_ns.clone(), gw_name.clone()))
                    && gw_status.addresses.is_empty()
                {
                    let addrs = extract_service_addresses(&svc);
                    if !addrs.is_empty() {
                        gw_status.addresses = addrs;
                        // Promote Programmed=True if at least one listener is accepted/resolved.
                        let any_listener_ready = gw_status.listeners.iter().any(|l| {
                            l.conditions
                                .iter()
                                .any(|c| c.condition_type == "Accepted" && c.status == "True")
                                && l.conditions.iter().any(|c| {
                                    c.condition_type == "Conflicted" && c.status == "False"
                                })
                                && l.conditions.iter().any(|c| {
                                    c.condition_type == "ResolvedRefs" && c.status == "True"
                                })
                        });
                        if any_listener_ready {
                            for cond in &mut gw_status.conditions {
                                if cond.condition_type == "Programmed" {
                                    cond.status = "True".to_owned();
                                    cond.reason = "Programmed".to_owned();
                                    cond.message = "Gateway is programmed in Shunt".to_owned();
                                }
                            }
                            for l in &mut gw_status.listeners {
                                let ok =
                                    l.conditions.iter().any(|c| {
                                        c.condition_type == "Accepted" && c.status == "True"
                                    }) && l.conditions.iter().any(|c| {
                                        c.condition_type == "Conflicted" && c.status == "False"
                                    }) && l.conditions.iter().any(|c| {
                                        c.condition_type == "ResolvedRefs" && c.status == "True"
                                    });
                                if ok {
                                    for cond in &mut l.conditions {
                                        if cond.condition_type == "Programmed" {
                                            cond.status = "True".to_owned();
                                            cond.reason = "Programmed".to_owned();
                                            cond.message =
                                                "Listener is programmed in Shunt".to_owned();
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        Ok(compiled)
    }

    /// Reconciles Shunt-managed per-`Gateway` Kubernetes `Service` resources idempotently.
    pub async fn reconcile_services(
        &self,
        desired: &[DesiredK8sService],
        existing: &[K8sService],
    ) -> Result<Vec<K8sService>, ConfigError> {
        let mut existing_by_key: HashMap<(&str, &str), &K8sService> = HashMap::new();
        for svc in existing {
            existing_by_key.insert(
                (
                    svc.metadata.effective_namespace(),
                    svc.metadata.name.as_str(),
                ),
                svc,
            );
        }

        let mut desired_keys: HashSet<(&str, &str)> = HashSet::new();
        let mut upserted = Vec::new();

        for d in desired {
            desired_keys.insert((d.namespace.as_str(), d.name.as_str()));
            let body = build_service_manifest(d);
            match existing_by_key.get(&(d.namespace.as_str(), d.name.as_str())) {
                None => {
                    let path = format!("/api/v1/namespaces/{}/services", d.namespace);
                    let (status, resp_body) = self
                        .send_json(Method::POST, &path, "application/json", &body)
                        .await?;
                    if status.is_success() {
                        if let Ok(created) = serde_json::from_slice::<K8sService>(&resp_body) {
                            upserted.push(created);
                        }
                    } else if status != http::StatusCode::CONFLICT {
                        warn!(
                            namespace = %d.namespace,
                            service = %d.name,
                            %status,
                            "failed to create Gateway Service"
                        );
                    }
                }
                Some(cur) => {
                    if service_needs_update(cur, d) {
                        let path =
                            format!("/api/v1/namespaces/{}/services/{}", d.namespace, d.name);
                        let (status, resp_body) = self
                            .send_json(Method::PATCH, &path, "application/merge-patch+json", &body)
                            .await?;
                        if status.is_success() {
                            if let Ok(patched) = serde_json::from_slice::<K8sService>(&resp_body) {
                                upserted.push(patched);
                            }
                        } else {
                            warn!(
                                namespace = %d.namespace,
                                service = %d.name,
                                %status,
                                "failed to patch Gateway Service"
                            );
                        }
                    }
                }
            }
        }

        // Delete orphaned Shunt-managed Services whose Gateway was deleted.
        for svc in existing {
            if svc
                .metadata
                .labels
                .get(MANAGED_BY_LABEL)
                .map(String::as_str)
                == Some(MANAGED_BY_VALUE)
                && svc.metadata.labels.contains_key(GATEWAY_NAME_LABEL)
            {
                let key = (
                    svc.metadata.effective_namespace(),
                    svc.metadata.name.as_str(),
                );
                if !desired_keys.contains(&key) {
                    let path = format!("/api/v1/namespaces/{}/services/{}", key.0, key.1);
                    let (status, _) = self
                        .send_raw(Method::DELETE, &path, None, bytes::Bytes::new())
                        .await?;
                    if !status.is_success() && status != http::StatusCode::NOT_FOUND {
                        warn!(
                            namespace = %key.0,
                            service = %key.1,
                            %status,
                            "failed to delete orphaned Gateway Service"
                        );
                    }
                }
            }
        }

        Ok(upserted)
    }

    /// Patches `.status` subresources for `GatewayClass`, `Gateway`, and `HTTPRoute`,
    /// deduplicating unchanged logical statuses (ignoring `lastTransitionTime`).
    pub async fn reconcile_statuses(&self, plan: &K8sStatusPlan) -> Result<usize, ConfigError> {
        let mut patched_count = 0usize;

        for (name, status) in &plan.gateway_classes {
            let path = format!("/apis/gateway.networking.k8s.io/v1/gatewayclasses/{name}/status");
            let payload = json!({ "status": status });
            if self.patch_status_if_changed(&path, &payload).await? {
                patched_count += 1;
            }
        }

        for ((ns, name), status) in &plan.gateways {
            let path = format!(
                "/apis/gateway.networking.k8s.io/v1/namespaces/{ns}/gateways/{name}/status"
            );
            let payload = json!({ "status": status });
            if self.patch_status_if_changed(&path, &payload).await? {
                patched_count += 1;
            }
        }

        for ((ns, name), status) in &plan.http_routes {
            let path = format!(
                "/apis/gateway.networking.k8s.io/v1/namespaces/{ns}/httproutes/{name}/status"
            );
            let mut parents_json: Vec<JsonValue> = plan
                .foreign_route_parents
                .get(&(ns.clone(), name.clone()))
                .cloned()
                .unwrap_or_default();
            for p in &status.parents {
                if let Ok(v) = serde_json::to_value(p) {
                    parents_json.push(v);
                }
            }
            let payload = json!({ "status": { "parents": parents_json } });
            if self.patch_status_if_changed(&path, &payload).await? {
                patched_count += 1;
            }
        }

        Ok(patched_count)
    }

    async fn patch_status_if_changed(
        &self,
        path: &str,
        payload: &JsonValue,
    ) -> Result<bool, ConfigError> {
        let mut normalized = payload.clone();
        strip_transition_times(&mut normalized);
        let digest = sha256_hex(&serde_json::to_vec(&normalized).unwrap_or_default());

        {
            let cache = self
                .status_digests
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            if cache.get(path).map(String::as_str) == Some(digest.as_str()) {
                return Ok(false);
            }
        }

        let (status, body) = self
            .send_json(Method::PATCH, path, "application/merge-patch+json", payload)
            .await?;
        if status.is_success() {
            let mut cache = self
                .status_digests
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            cache.insert(path.to_owned(), digest);
            debug!(path, "patched Kubernetes Gateway API status");
            Ok(true)
        } else {
            let body_preview = String::from_utf8_lossy(&body);
            warn!(
                path,
                %status,
                body = %body_preview.chars().take(256).collect::<String>(),
                "Kubernetes status PATCH failed"
            );
            Ok(false)
        }
    }

    fn current_bearer_token(&self, force_reload: bool) -> Option<String> {
        let mut guard = self.token_state.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(ref token_path) = self.client_cfg.token_path
            && (force_reload || guard.loaded_at.elapsed() >= TOKEN_REFRESH_INTERVAL)
            && let Ok(fresh) = std::fs::read_to_string(token_path)
        {
            let trimmed = fresh.trim().to_owned();
            if !trimmed.is_empty() {
                guard.token = Some(trimmed);
                guard.loaded_at = Instant::now();
            }
        }
        guard.token.clone()
    }

    async fn fetch_list<T: for<'de> Deserialize<'de>>(
        &self,
        path: &str,
    ) -> Result<Vec<T>, ConfigError> {
        let body = self.get_json(path).await?;
        let list: K8sListEnvelope<T> = serde_json::from_slice(&body).map_err(|e| {
            ConfigError::K8s(format!(
                "failed to decode Kubernetes list from `{path}`: {e}"
            ))
        })?;
        Ok(list.items)
    }

    async fn fetch_list_optional<T: for<'de> Deserialize<'de>>(
        &self,
        path: &str,
    ) -> Result<Vec<T>, ConfigError> {
        match self
            .send_raw(Method::GET, path, None, bytes::Bytes::new())
            .await?
        {
            (http::StatusCode::NOT_FOUND | http::StatusCode::FORBIDDEN, _) => Ok(Vec::new()),
            (status, body) if status.is_success() => {
                let list: K8sListEnvelope<T> = serde_json::from_slice(&body).map_err(|e| {
                    ConfigError::K8s(format!(
                        "failed to decode Kubernetes list from `{path}`: {e}"
                    ))
                })?;
                Ok(list.items)
            }
            (status, _) => Err(ConfigError::K8s(format!(
                "Kubernetes API `{path}` returned HTTP {status}"
            ))),
        }
    }

    async fn fetch_single_optional<T: for<'de> Deserialize<'de>>(
        &self,
        path: &str,
    ) -> Result<Option<T>, ConfigError> {
        match self
            .send_raw(Method::GET, path, None, bytes::Bytes::new())
            .await?
        {
            (http::StatusCode::NOT_FOUND | http::StatusCode::FORBIDDEN, _) => Ok(None),
            (status, body) if status.is_success() => {
                let obj = serde_json::from_slice(&body).map_err(|e| {
                    ConfigError::K8s(format!(
                        "failed to decode Kubernetes object from `{path}`: {e}"
                    ))
                })?;
                Ok(Some(obj))
            }
            (status, _) => Err(ConfigError::K8s(format!(
                "Kubernetes API `{path}` returned HTTP {status}"
            ))),
        }
    }

    async fn get_json(&self, path: &str) -> Result<bytes::Bytes, ConfigError> {
        let (status, body) = self
            .send_raw(Method::GET, path, None, bytes::Bytes::new())
            .await?;
        if !status.is_success() {
            return Err(ConfigError::K8s(format!(
                "Kubernetes API `{path}` returned HTTP {status}"
            )));
        }
        Ok(body)
    }

    async fn send_json(
        &self,
        method: Method,
        path: &str,
        content_type: &str,
        payload: &JsonValue,
    ) -> Result<(http::StatusCode, bytes::Bytes), ConfigError> {
        let bytes = serde_json::to_vec(payload)
            .map_err(|e| ConfigError::K8s(format!("failed to serialize Kubernetes JSON: {e}")))?;
        self.send_raw(method, path, Some(content_type), bytes::Bytes::from(bytes))
            .await
    }

    async fn send_raw(
        &self,
        method: Method,
        path: &str,
        content_type: Option<&str>,
        body: bytes::Bytes,
    ) -> Result<(http::StatusCode, bytes::Bytes), ConfigError> {
        let base = self.client_cfg.api_server.trim_end_matches('/');
        let full_url = format!("{base}{path}");
        let uri: Uri = full_url.parse().map_err(|e| {
            ConfigError::K8s(format!("invalid Kubernetes API URL `{full_url}`: {e}"))
        })?;

        for attempt in 0..2 {
            let token = self.current_bearer_token(attempt > 0);
            let mut req = HttpRequest::new(method.clone(), uri.clone())
                .with_header(header::ACCEPT, HeaderValue::from_static("application/json"))
                .with_timeout(self.client_cfg.request_timeout)
                .with_body(body.clone());
            if let Some(ct) = content_type {
                let ct_val = HeaderValue::from_str(ct)
                    .map_err(|e| ConfigError::K8s(format!("invalid Content-Type `{ct}`: {e}")))?;
                req = req.with_header(header::CONTENT_TYPE, ct_val);
            }
            if let Some(tok) = &token {
                let val = HeaderValue::from_str(&format!("Bearer {tok}")).map_err(|e| {
                    ConfigError::K8s(format!("invalid Kubernetes bearer token header: {e}"))
                })?;
                req = req.with_header(header::AUTHORIZATION, val);
            }

            let resp = self.http_client.send(req).await.map_err(|e| {
                ConfigError::K8s(format!(
                    "Kubernetes API request `{method} {path}` failed: {e}"
                ))
            })?;

            // Retry once with freshly reloaded projected ServiceAccount token on 401 Unauthorized.
            if resp.status == http::StatusCode::UNAUTHORIZED
                && attempt == 0
                && self.client_cfg.token_path.is_some()
            {
                debug!("Kubernetes API returned 401; reloading projected ServiceAccount token");
                continue;
            }
            return Ok((resp.status, resp.body));
        }

        unreachable!("loop executes at most twice and always returns on attempt 1")
    }
}

fn strip_transition_times(val: &mut JsonValue) {
    match val {
        JsonValue::Object(map) => {
            map.remove("lastTransitionTime");
            for v in map.values_mut() {
                strip_transition_times(v);
            }
        }
        JsonValue::Array(arr) => {
            for v in arr.iter_mut() {
                strip_transition_times(v);
            }
        }
        _ => {}
    }
}

fn build_service_manifest(d: &DesiredK8sService) -> JsonValue {
    let mut labels = BTreeMap::new();
    labels.insert(MANAGED_BY_LABEL.to_owned(), MANAGED_BY_VALUE.to_owned());
    labels.insert(GATEWAY_NS_LABEL.to_owned(), d.gateway_namespace.clone());
    labels.insert(GATEWAY_NAME_LABEL.to_owned(), d.gateway_name.clone());

    let ports: Vec<JsonValue> = d
        .ports
        .iter()
        .map(|p| {
            json!({
                "name": p.name,
                "protocol": "TCP",
                "port": p.external_port,
                "targetPort": p.target_port,
            })
        })
        .collect();

    json!({
        "apiVersion": "v1",
        "kind": "Service",
        "metadata": {
            "name": d.name,
            "namespace": d.namespace,
            "labels": labels,
        },
        "spec": {
            "type": d.service_type,
            "selector": d.selector,
            "ports": ports,
        }
    })
}

fn service_needs_update(cur: &K8sService, desired: &DesiredK8sService) -> bool {
    if cur.spec.service_type.as_deref().unwrap_or("ClusterIP") != desired.service_type {
        return true;
    }
    if cur.spec.selector != desired.selector {
        return true;
    }
    if cur.spec.ports.len() != desired.ports.len() {
        return true;
    }
    for dp in &desired.ports {
        let matched = cur.spec.ports.iter().any(|cp| {
            cp.port == dp.external_port
                && cp
                    .target_port
                    .as_ref()
                    .and_then(JsonValue::as_u64)
                    .map(|p| p == u64::from(dp.target_port))
                    .unwrap_or(false)
        });
        if !matched {
            return true;
        }
    }
    false
}

fn extract_service_addresses(svc: &K8sService) -> Vec<K8sGatewayAddress> {
    let mut out = Vec::new();
    if let Some(lb) = svc.status.as_ref().and_then(|st| st.load_balancer.as_ref()) {
        for ing in &lb.ingress {
            if let Some(ip) = &ing.ip
                && !ip.is_empty()
            {
                out.push(K8sGatewayAddress {
                    address_type: "IPAddress".to_owned(),
                    value: ip.clone(),
                });
            } else if let Some(host) = &ing.hostname
                && !host.is_empty()
            {
                out.push(K8sGatewayAddress {
                    address_type: "Hostname".to_owned(),
                    value: host.clone(),
                });
            }
        }
    }
    if out.is_empty()
        && let Some(cip) = svc.spec.cluster_ip.as_deref()
        && !cip.is_empty()
        && !cip.eq_ignore_ascii_case("None")
    {
        out.push(K8sGatewayAddress {
            address_type: "IPAddress".to_owned(),
            value: cip.to_owned(),
        });
    }
    out
}

impl ConfigProvider for K8sApiConfigProvider {
    fn source_name(&self) -> String {
        format!("k8s-api:{}", self.client_cfg.api_server)
    }

    fn load(&self) -> Result<LoadedConfig, ConfigError> {
        self.latest.load().as_ref().clone().ok_or_else(|| {
            ConfigError::K8s(
                "K8sApiConfigProvider has not completed initial sync_once() yet".to_owned(),
            )
        })
    }
}

/// Handle for the background read-only Kubernetes Gateway API synchronization task.
pub struct K8sSyncHandle {
    shutdown_tx: watch::Sender<bool>,
    task: tokio::task::JoinHandle<()>,
}

impl K8sSyncHandle {
    pub fn stop(self) {
        let _ = self.shutdown_tx.send(true);
        self.task.abort();
    }
}

/// Spawns a background polling loop that syncs Kubernetes Gateway API resources into
/// `provider` and triggers atomic [`ReloadController::reload`] whenever the compiled digest changes.
pub fn start_k8s_sync_loop(
    provider: Arc<K8sApiConfigProvider>,
    controller: Arc<ReloadController>,
) -> K8sSyncHandle {
    let (shutdown_tx, mut shutdown_rx) = watch::channel(false);
    let interval = provider.poll_interval().max(Duration::from_millis(200));
    let task = tokio::spawn(async move {
        let mut ticker = tokio::time::interval(interval);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        ticker.tick().await;
        loop {
            tokio::select! {
                _ = shutdown_rx.changed() => {
                    if *shutdown_rx.borrow() {
                        break;
                    }
                }
                _ = ticker.tick() => {
                    match provider.sync_once().await {
                        Ok(true) => {
                            match controller.reload() {
                                Ok(inspect) => {
                                    info!(
                                        version = inspect.version,
                                        routes = inspect.routes.len(),
                                        upstreams = inspect.upstreams.len(),
                                        "reloaded gateway snapshot from Kubernetes Gateway API"
                                    );
                                }
                                Err(err) => {
                                    warn!(
                                        error = %err,
                                        "Kubernetes Gateway API reload failed; keeping last-known-good snapshot"
                                    );
                                }
                            }
                        }
                        Ok(false) => {}
                        Err(err) => {
                            warn!(
                                error = %err,
                                "Kubernetes Gateway API sync error; retrying on next poll"
                            );
                        }
                    }
                }
            }
        }
    });
    K8sSyncHandle { shutdown_tx, task }
}
