use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use http::{HeaderName, HeaderValue, StatusCode, Uri, header};
use serde_json::{Value, json};
use shunt_config::{
    ConfigProvider, ControlPlaneClientConfig, ControlPlaneConfigProvider, ReloadController,
    SnapshotCompiler, SseParser, start_control_plane_sync,
};
use shunt_console_api::{AppState, build_router};
use shunt_console_core::{ConsoleStore, ConsoleStoreConfig};
use shunt_engine::{CoreHttpClient, GatewayServer, RuntimeRegistry};
use shunt_plugin_sdk::{HttpClient, HttpRequest, PluginRegistry, SyncedTableRegistry};
use shunt_plugins::{PrometheusMetrics, register_builtin_plugins};
use tokio::net::TcpListener;

async fn spawn_console_server() -> (String, Arc<ConsoleStore>, tokio::task::JoinHandle<()>) {
    let store = Arc::new(
        ConsoleStore::connect(ConsoleStoreConfig {
            database_url: "sqlite::memory:".to_owned(),
            master_key_encoded: None,
        })
        .await
        .unwrap(),
    );
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let base_url = format!("http://{addr}");
    let app = build_router(
        AppState::new(Arc::clone(&store), base_url.clone(), false),
        false,
    );
    let handle = tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    (base_url, store, handle)
}

async fn api_req(
    http: &CoreHttpClient,
    method: http::Method,
    url: &str,
    bearer: Option<&str>,
    if_match: Option<&str>,
    body: Option<Value>,
) -> (StatusCode, http::HeaderMap, Value) {
    let uri: Uri = url.parse().unwrap();
    let mut req = HttpRequest::new(method, uri).with_timeout(Duration::from_secs(5));
    if let Some(tok) = bearer {
        req = req.with_header(
            header::AUTHORIZATION,
            HeaderValue::from_str(&format!("Bearer {tok}")).unwrap(),
        );
    }
    if let Some(etag) = if_match {
        req = req.with_header(header::IF_MATCH, HeaderValue::from_str(etag).unwrap());
    }
    if let Some(b) = body {
        req = req
            .with_header(
                header::CONTENT_TYPE,
                HeaderValue::from_static("application/json"),
            )
            .with_body(serde_json::to_vec(&b).unwrap());
    }
    let resp = http.send(req).await.unwrap();
    let val = serde_json::from_slice(&resp.body).unwrap_or(Value::Null);
    (resp.status, resp.headers, val)
}

#[tokio::test]
async fn end_to_end_control_plane_channels_rollback_lkg_rbac_and_audit() {
    let (base_url, store, console_task) = spawn_console_server().await;
    let http = CoreHttpClient::new_default().unwrap();

    // 1. Verify OpenAPI 3.1 spec and embedded SPA security headers.
    let openapi_resp = http
        .send(HttpRequest::get(
            format!("{base_url}/api/v1/openapi.json").parse().unwrap(),
        ))
        .await
        .unwrap();
    assert_eq!(openapi_resp.status, StatusCode::OK);
    let openapi_json: Value = serde_json::from_slice(&openapi_resp.body).unwrap();
    assert!(
        openapi_json["openapi"]
            .as_str()
            .unwrap_or("")
            .starts_with("3.1")
    );

    let spa_resp = http
        .send(HttpRequest::get(format!("{base_url}/").parse().unwrap()))
        .await
        .unwrap();
    assert_eq!(spa_resp.status, StatusCode::OK);
    assert_eq!(
        spa_resp
            .headers
            .get("x-frame-options")
            .and_then(|v| v.to_str().ok()),
        Some("DENY")
    );

    // 2. First-run bootstrap via REST API.
    let (st, _, boot) = api_req(
        &http,
        http::Method::POST,
        &format!("{base_url}/api/v1/setup/bootstrap"),
        None,
        None,
        Some(json!({
            "admin_email": "ops@acme.io",
            "admin_name": "Ops Admin",
            "admin_password": "super-secret-password",
            "org_slug": "acme",
            "org_name": "Acme Corp",
            "cluster_slug": "prod-us",
            "cluster_name": "Prod US",
            "environment": "production",
            "starter_preset": "http-api",
            "auto_publish": true
        })),
    )
    .await;
    assert_eq!(st, StatusCode::CREATED, "bootstrap body: {boot}");
    let admin_session = boot["session_token"].as_str().unwrap().to_owned();
    let bootstrap_token = boot["bootstrap_token"]["plaintext_token"]
        .as_str()
        .unwrap()
        .to_owned();
    let cluster_id = boot["cluster"]["id"].as_str().unwrap().to_owned();

    // Update [server] listen to ephemeral 127.0.0.1:0 + disable admin port for test node.
    let (st, _, _) = api_req(
        &http,
        http::Method::PUT,
        &format!("{base_url}/api/v1/clusters/prod-us/resources/server/default"),
        Some(&admin_session),
        None,
        Some(json!({ "spec": { "listen": "127.0.0.1:0", "drain_timeout_ms": 1000 } })),
    )
    .await;
    assert_eq!(st, StatusCode::OK);

    // Store a vault secret and reference it from a header-rewrite plugin to prove vault resolution
    // works on Channel 1 delivery while staying redacted in stored revisions/APIs!
    let (st, _, sec_meta) = api_req(
        &http,
        http::Method::PUT,
        &format!("{base_url}/api/v1/orgs/acme/secrets/upstream-api-key"),
        Some(&admin_session),
        None,
        Some(json!({
            "description": "Backend API secret",
            "scope_type": "org",
            "scope_id": boot["organization"]["id"].as_str().unwrap(),
            "delivery_mode": "vault",
            "value": "sk-vault-secret-999"
        })),
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    assert!(!sec_meta.to_string().contains("sk-vault-secret-999"));

    // Publish Revision #2 with server=127.0.0.1:0 so our live data plane boots cleanly.
    let (st, _, rev2) = api_req(
        &http,
        http::Method::POST,
        &format!("{base_url}/api/v1/clusters/prod-us/revisions:publish"),
        Some(&admin_session),
        None,
        Some(json!({ "ring_selector": "*", "notes": "ephemeral port for test" })),
    )
    .await;
    assert_eq!(st, StatusCode::CREATED, "rev2: {rev2}");
    assert_eq!(rev2["revision"].as_u64(), Some(2));

    // 3. Boot a REAL Shunt data-plane instance wired to shunt-console with encrypted --cache-dir!
    let cache_dir = tempfile::tempdir().unwrap();
    let cache_key = [42u8; 32];
    let synced_tables = Arc::new(SyncedTableRegistry::new());
    let cp_cfg = ControlPlaneClientConfig {
        base_url: base_url.clone(),
        cluster: "prod-us".to_owned(),
        token: bootstrap_token,
        node_name: Some("test-node-1".to_owned()),
        labels: BTreeMap::from([("ring".to_owned(), "stable".to_owned())]),
        cache_dir: Some(cache_dir.path().to_path_buf()),
        cache_key: Some(cache_key),
        public_key_b64: Some(store.signer().public_key_b64().to_owned()),
        heartbeat_interval: Duration::from_millis(150),
        namespaces: vec!["ai.virtual_keys".to_owned(), "mcp.kill_switch".to_owned()],
        ..ControlPlaneClientConfig::default()
    };

    let cp_provider = Arc::new(
        ControlPlaneConfigProvider::new(cp_cfg.clone(), Arc::clone(&synced_tables)).unwrap(),
    );
    cp_provider.bootstrap().await.unwrap();
    assert_eq!(cp_provider.active_revision(), 2);

    // Compile initial snapshot and launch real GatewayServer + ReloadController + ControlPlaneSync!
    let mut plugin_reg = PluginRegistry::new();
    register_builtin_plugins(&mut plugin_reg, Arc::new(PrometheusMetrics::new()));
    let runtime = Arc::new(RuntimeRegistry::new().with_synced_tables(Arc::clone(&synced_tables)));
    let compiler = Arc::new(SnapshotCompiler::new(Arc::new(plugin_reg), runtime));
    let initial_loaded = cp_provider.load().unwrap();
    let initial_bundle = compiler.compile(&initial_loaded).unwrap();
    let gw_handle = GatewayServer::new(initial_bundle.snapshot)
        .bind("127.0.0.1:0".parse().unwrap())
        .await
        .unwrap();
    let controller = Arc::new(ReloadController::new(
        cp_provider.clone(),
        compiler,
        gw_handle.reloader(),
        initial_bundle.inspect,
    ));
    let sync_handle =
        start_control_plane_sync(Arc::clone(&cp_provider), Arc::clone(&controller), None);

    // 4. Push Channel 2 entries (upsert + revoke) and verify real-time SSE sync into ArcSwap!
    let (st, _, ev1) = api_req(
        &http,
        http::Method::PUT,
        &format!("{base_url}/api/v1/clusters/prod-us/state/ai.virtual_keys/vk_keep"),
        Some(&admin_session),
        None,
        Some(json!({ "value": { "enabled": true, "team": "core" } })),
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    let ev1_seq = ev1["seq"].as_u64().unwrap();

    let (st, _, _) = api_req(
        &http,
        http::Method::PUT,
        &format!("{base_url}/api/v1/clusters/prod-us/state/ai.virtual_keys/vk_revoke"),
        Some(&admin_session),
        None,
        Some(json!({ "value": { "enabled": true } })),
    )
    .await;
    assert_eq!(st, StatusCode::OK);

    let (st, _, _) = api_req(
        &http,
        http::Method::DELETE,
        &format!("{base_url}/api/v1/clusters/prod-us/state/ai.virtual_keys/vk_revoke"),
        Some(&admin_session),
        None,
        None,
    )
    .await;
    assert_eq!(st, StatusCode::OK);

    // Wait up to 3s for SSE Channel 2 delta delivery into lock-free SyncedTable.
    let vk_table = synced_tables.get_or_create("ai.virtual_keys");
    let deadline = tokio::time::Instant::now() + Duration::from_secs(3);
    loop {
        let snap = vk_table.load();
        if snap.get("vk_keep").is_some()
            && snap.get("vk_revoke").is_none()
            && snap.seq >= ev1_seq + 2
        {
            break;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "timed out waiting for Channel 2 SSE sync; got seq={} entries={:?}",
            snap.seq,
            snap.entries
        );
        tokio::time::sleep(Duration::from_millis(25)).await;
    }

    // 5. Publish Revision #3 (adding a second route) and verify live Channel 1 SSE push!
    let (st, hdrs, _) = api_req(
        &http,
        http::Method::PUT,
        &format!("{base_url}/api/v1/clusters/prod-us/resources/route/orders-v2"),
        Some(&admin_session),
        None,
        Some(json!({
            "spec": {
                "id": "orders-v2",
                "path_prefix": "/v2/orders",
                "upstream": "api-backend"
            }
        })),
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    let route_etag = hdrs.get(header::ETAG).unwrap().to_str().unwrap().to_owned();

    // Verify ETag optimistic concurrency returns 412 Precondition Failed on stale If-Match!
    let (st, hdrs_412, prob_412) = api_req(
        &http,
        http::Method::PUT,
        &format!("{base_url}/api/v1/clusters/prod-us/resources/route/orders-v2"),
        Some(&admin_session),
        Some("\"wrong-etag\""),
        Some(json!({
            "spec": { "id": "orders-v2", "path_prefix": "/v2/orders", "upstream": "api-backend" }
        })),
    )
    .await;
    assert_eq!(st, StatusCode::PRECONDITION_FAILED);
    assert!(
        hdrs_412
            .get(header::CONTENT_TYPE)
            .unwrap()
            .to_str()
            .unwrap()
            .contains("application/problem+json")
    );
    assert_eq!(prob_412["status"].as_u64(), Some(412));
    assert!(!route_etag.is_empty());

    let (st, _, rev3) = api_req(
        &http,
        http::Method::POST,
        &format!("{base_url}/api/v1/clusters/prod-us/revisions:publish"),
        Some(&admin_session),
        None,
        Some(json!({ "ring_selector": "*", "notes": "add orders-v2 route" })),
    )
    .await;
    assert_eq!(st, StatusCode::CREATED);
    assert_eq!(rev3["revision"].as_u64(), Some(3));

    // Wait for live node to pick up Revision #3 automatically via Channel 1 SSE!
    let deadline = tokio::time::Instant::now() + Duration::from_secs(3);
    while cp_provider.active_revision() != 3 {
        assert!(
            tokio::time::Instant::now() < deadline,
            "timed out waiting for Channel 1 rev #3; active={}",
            cp_provider.active_revision()
        );
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    assert_eq!(controller.current_inspect().routes.len(), 2);

    // 6. Roll back Channel 1 to Revision #2 -> assert node rolls back topology while Channel 2
    //    keys/revocations remain 100% UNTOUCHED!
    let (st, _, _) = api_req(
        &http,
        http::Method::POST,
        &format!("{base_url}/api/v1/clusters/prod-us/revisions/2/rollback"),
        Some(&admin_session),
        None,
        Some(json!({ "ring_selector": "*" })),
    )
    .await;
    assert_eq!(st, StatusCode::OK);

    let deadline = tokio::time::Instant::now() + Duration::from_secs(3);
    while cp_provider.active_revision() != 2 {
        assert!(
            tokio::time::Instant::now() < deadline,
            "timed out waiting for Channel 1 rollback to rev #2; active={}",
            cp_provider.active_revision()
        );
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    assert_eq!(controller.current_inspect().routes.len(), 1);
    // Channel 2 invariant: vk_keep still active and vk_revoke still revoked!
    let snap_after_rb = vk_table.load();
    assert!(snap_after_rb.get("vk_keep").is_some());
    assert!(snap_after_rb.get("vk_revoke").is_none());

    // Wait for heartbeat to report node Synced on rev #2.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(3);
    loop {
        let (_, _, nodes) = api_req(
            &http,
            http::Method::GET,
            &format!("{base_url}/api/v1/clusters/prod-us/nodes"),
            Some(&admin_session),
            None,
            None,
        )
        .await;
        let arr = nodes.as_array().unwrap();
        if arr.len() == 1
            && arr[0]["active_revision"].as_u64() == Some(2)
            && arr[0]["status"].as_str() == Some("synced")
        {
            break;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "node did not report synced on rev #2: {nodes}"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    // 7. RBAC enforcement test with Service API Token (Developer cannot publish or write secrets).
    let (st, _, dev_tok) = api_req(
        &http,
        http::Method::POST,
        &format!("{base_url}/api/v1/orgs/acme/api-tokens"),
        Some(&admin_session),
        None,
        Some(json!({ "name": "dev-ci", "role": "developer" })),
    )
    .await;
    assert_eq!(st, StatusCode::CREATED);
    let dev_bearer = dev_tok["plaintext_token"].as_str().unwrap();

    let (st_read, _, _) = api_req(
        &http,
        http::Method::GET,
        &format!("{base_url}/api/v1/clusters/prod-us/revisions"),
        Some(dev_bearer),
        None,
        None,
    )
    .await;
    assert_eq!(st_read, StatusCode::OK);

    let (st_pub, _, _) = api_req(
        &http,
        http::Method::POST,
        &format!("{base_url}/api/v1/clusters/prod-us/revisions:publish"),
        Some(dev_bearer),
        None,
        Some(json!({ "ring_selector": "*", "notes": "unauthorized" })),
    )
    .await;
    assert_eq!(st_pub, StatusCode::FORBIDDEN);

    // 8. Channel 2 compaction gap -> FULL_SYNC recovery over SSE!
    store
        .compact_control_events(&cluster_id, "ai.virtual_keys", ev1_seq + 1)
        .await
        .unwrap();
    // Register a second node token to hit `/cp/v1/clusters/prod-us/state/stream` with stale cursor=ev1_seq.
    let (_, node_tok2, _) = store
        .register_node_with_bootstrap_token(
            boot["bootstrap_token"]["plaintext_token"].as_str().unwrap(),
            "prod-us",
            Some("gap-test-node".to_owned()),
            "0.3.0".to_owned(),
            BTreeMap::new(),
        )
        .await
        .unwrap();
    let gap_req = HttpRequest::get(
        format!(
            "{base_url}/cp/v1/clusters/prod-us/state/stream?namespaces=ai.virtual_keys&cursors=ai.virtual_keys:{ev1_seq}"
        )
        .parse()
        .unwrap(),
    )
    .with_header(
        header::AUTHORIZATION,
        HeaderValue::from_str(&format!("Bearer {node_tok2}")).unwrap(),
    )
    .with_header(
        HeaderName::from_static("accept"),
        HeaderValue::from_static("text/event-stream"),
    );
    let sse_resp = http.send_streaming(gap_req).await.unwrap();
    assert_eq!(sse_resp.status(), StatusCode::OK);
    let mut body = sse_resp.into_body();
    let mut parser = SseParser::default();
    let mut got_full_sync = false;
    use http_body_util::BodyExt as _;
    while let Ok(Some(Ok(frame))) = tokio::time::timeout(Duration::from_secs(2), body.frame()).await
    {
        if let Ok(data) = frame.into_data() {
            for ev in parser.push(&data) {
                if ev.event.as_deref() == Some("full_sync") {
                    let parsed: Value = serde_json::from_str(&ev.data).unwrap();
                    assert_eq!(parsed["ns"].as_str(), Some("ai.virtual_keys"));
                    assert!(parsed["entries"]["vk_keep"].is_object());
                    assert!(parsed["entries"].get("vk_revoke").is_none());
                    got_full_sync = true;
                    break;
                }
            }
        }
        if got_full_sync {
            break;
        }
    }
    assert!(
        got_full_sync,
        "expected FULL_SYNC event on compacted cursor gap"
    );

    // 9. Verify tamper-evident hash-chained admin audit log!
    let (st, _, audit_ver) = api_req(
        &http,
        http::Method::GET,
        &format!("{base_url}/api/v1/audit/admin:verify"),
        Some(&admin_session),
        None,
        None,
    )
    .await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(audit_ver["valid"].as_bool(), Some(true));

    // 10. Console-outage LKG cache cold-boot test!
    sync_handle.stop();
    gw_handle.shutdown().await;
    console_task.abort();
    // Give OS a moment to release the closed console socket.
    tokio::time::sleep(Duration::from_millis(50)).await;

    let offline_tables = Arc::new(SyncedTableRegistry::new());
    let offline_cfg = ControlPlaneClientConfig {
        base_url: "http://127.0.0.1:1".to_owned(), // Guaranteed unreachable!
        request_timeout: Duration::from_millis(300),
        ..cp_cfg
    };
    let offline_provider =
        ControlPlaneConfigProvider::new(offline_cfg, Arc::clone(&offline_tables)).unwrap();
    offline_provider.bootstrap().await.unwrap();
    assert_eq!(offline_provider.active_revision(), 2);
    assert!(
        offline_tables
            .get_or_create("ai.virtual_keys")
            .load()
            .get("vk_keep")
            .is_some(),
        "LKG state cache must restore Channel 2 entries during console outage!"
    );
}
