use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::{Arc, RwLock};
use std::time::Duration;

use bytes::Bytes;
use http::{Request, Response, StatusCode, header};
use http_body_util::{BodyExt, Full};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::client::legacy::Client;
use hyper_util::rt::{TokioExecutor, TokioIo};
use rcgen::{CertificateParams, KeyPair};
use serde_json::json;
use shunt_config::{
    ConfigProvider, K8sApiConfigProvider, K8sClientConfig, K8sClusterSnapshot, K8sGatewayOptions,
    MultiListenerSupervisor, PortAllocator, ReloadController, SUPPORTED_GATEWAY_FEATURES,
    SnapshotCompiler, compile_k8s_gateway_cluster, compile_k8s_gateway_snapshot,
    intersect_two_hostnames, parse_k8s_duration_ms, reconcile_k8s_controller_once,
    start_k8s_sync_loop,
};
use shunt_engine::{GatewayServer, RuntimeRegistry};
use shunt_plugin_sdk::PluginRegistry;
use shunt_plugins::{PrometheusMetrics, register_builtin_plugins};
use tokio::net::TcpListener;

fn b64_std(data: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    let (chunks, rem) = data.as_chunks::<3>();
    for c in chunks {
        let n = ((c[0] as u32) << 16) | ((c[1] as u32) << 8) | (c[2] as u32);
        out.push(TABLE[((n >> 18) & 63) as usize] as char);
        out.push(TABLE[((n >> 12) & 63) as usize] as char);
        out.push(TABLE[((n >> 6) & 63) as usize] as char);
        out.push(TABLE[(n & 63) as usize] as char);
    }
    match rem {
        [a] => {
            let n = (*a as u32) << 16;
            out.push(TABLE[((n >> 18) & 63) as usize] as char);
            out.push(TABLE[((n >> 12) & 63) as usize] as char);
            out.push_str("==");
        }
        [a, b] => {
            let n = ((*a as u32) << 16) | ((*b as u32) << 8);
            out.push(TABLE[((n >> 18) & 63) as usize] as char);
            out.push(TABLE[((n >> 12) & 63) as usize] as char);
            out.push(TABLE[((n >> 6) & 63) as usize] as char);
            out.push('=');
        }
        _ => {}
    }
    out
}

#[test]
fn k8s_gateway_api_manifest_compiles_routes_precedence_canary_filters_and_tls() {
    let params = CertificateParams::new(vec!["api.example.com".to_owned()]).unwrap();
    let key = KeyPair::generate().unwrap();
    let cert = params.self_signed(&key).unwrap();
    let cert_b64 = b64_std(cert.pem().as_bytes());
    let key_b64 = b64_std(key.serialize_pem().as_bytes());

    let yaml = format!(
        r#"
apiVersion: gateway.networking.k8s.io/v1
kind: GatewayClass
metadata:
  name: shunt
spec:
  controllerName: shunt.io/gateway-controller
---
apiVersion: v1
kind: Secret
metadata:
  name: api-tls
  namespace: prod
type: kubernetes.io/tls
data:
  tls.crt: "{cert_b64}"
  tls.key: "{key_b64}"
---
apiVersion: gateway.networking.k8s.io/v1
kind: Gateway
metadata:
  name: edge
  namespace: prod
spec:
  gatewayClassName: shunt
  listeners:
    - name: https
      hostname: "*.example.com"
      port: 443
      protocol: HTTPS
      tls:
        mode: Terminate
        certificateRefs:
          - name: api-tls
      allowedRoutes:
        namespaces:
          from: Same
---
apiVersion: v1
kind: Service
metadata:
  name: app-v1
  namespace: prod
spec:
  ports:
    - name: http
      port: 80
      targetPort: 8080
---
apiVersion: v1
kind: Endpoints
metadata:
  name: app-v1
  namespace: prod
subsets:
  - addresses:
      - ip: 10.0.1.1
      - ip: 10.0.1.2
    ports:
      - name: http
        port: 8080
---
apiVersion: v1
kind: Service
metadata:
  name: app-v2
  namespace: prod
spec:
  ports:
    - name: http
      port: 80
      targetPort: 8080
---
apiVersion: discovery.k8s.io/v1
kind: EndpointSlice
metadata:
  name: app-v2-slice
  namespace: prod
  labels:
    kubernetes.io/service-name: app-v2
ports:
  - name: http
    port: 8080
endpoints:
  - addresses: ["10.0.2.1"]
    conditions:
      ready: true
  - addresses: ["10.0.2.2"]
    conditions:
      ready: false
---
apiVersion: gateway.networking.k8s.io/v1
kind: HTTPRoute
metadata:
  name: app-routes
  namespace: prod
  annotations:
    shunt.io/max-attempts: "2"
spec:
  parentRefs:
    - name: edge
  hostnames:
    - "api.example.com"
    - "other.unrelated.io"
  rules:
    - matches:
        - path:
            type: PathPrefix
            value: /api
      filters:
        - type: RequestHeaderModifier
          requestHeaderModifier:
            set:
              - name: x-env
                value: prod
        - type: ResponseHeaderModifier
          responseHeaderModifier:
            add:
              - name: x-served-by
                value: shunt-k8s
        - type: RequestMirror
          requestMirror:
            backendRef:
              name: app-v2
              port: 80
      timeouts:
        backendRequest: 2s500ms
      backendRefs:
        - name: app-v1
          port: 80
          weight: 80
        - name: app-v2
          port: 80
          weight: 20
    - matches:
        - path:
            type: Exact
            value: /api/health
          method: GET
          headers:
            - name: x-probe
              value: "1"
      filters:
        - type: RequestRedirect
          requestRedirect:
            statusCode: 302
            scheme: https
            path:
              type: ReplaceFullPath
              replaceFullPath: /healthz
---
apiVersion: gateway.networking.k8s.io/v1
kind: HTTPRoute
metadata:
  name: cross-ns-blocked
  namespace: other-ns
spec:
  parentRefs:
    - name: edge
      namespace: prod
  rules:
    - backendRefs:
        - name: app-v1
          port: 80
"#
    );

    let snap = K8sClusterSnapshot::from_yaml_str(&yaml).unwrap();
    let cfg = compile_k8s_gateway_snapshot(&snap, &K8sGatewayOptions::default()).unwrap();

    // 1. TLS Secret decoded cleanly into inline PEM SNI config
    let tls = cfg.server.tls.as_ref().expect("TLS config compiled");
    assert!(tls.cert_pem.is_some());
    assert_eq!(tls.sni.len(), 1);
    assert_eq!(tls.sni[0].host, "*.example.com");

    // 2. Cross-namespace HTTPRoute blocked by `allowedRoutes.namespaces.from = Same`
    assert_eq!(cfg.routes.len(), 2);

    // 3. Gateway API Precedence: Exact `/api/health` comes BEFORE PathPrefix `/api`!
    assert_eq!(cfg.routes[0].path_exact.as_deref(), Some("/api/health"));
    assert_eq!(cfg.routes[0].methods, vec!["GET"]);
    assert_eq!(
        cfg.routes[0].headers.get("x-probe").map(String::as_str),
        Some("1")
    );
    assert!(cfg.routes[0].plugins.iter().any(|p| p.name == "redirect"));

    let api_route = &cfg.routes[1];
    assert_eq!(api_route.path_prefix.as_deref(), Some("/api"));
    // Hostname intersection keeps `api.example.com`, drops `other.unrelated.io`!
    assert_eq!(api_route.hosts, vec!["api.example.com"]);
    assert_eq!(api_route.max_attempts, Some(2));
    assert_eq!(api_route.response_headers_timeout_ms, Some(2_500));
    assert_eq!(api_route.mirrors.len(), 1);
    assert!(api_route.plugins.iter().any(|p| p.name == "header-rewrite"));

    // 4. Canary weight split via `traffic-split`: app-v1 (2 ready pods, weight 80) and
    // app-v2 (1 ready pod, unready 10.0.2.2 skipped!, weight 20) get distinct upstreams + exact 80:20 split.
    let split = api_route
        .plugins
        .iter()
        .find(|p| p.name == "traffic-split")
        .expect("traffic-split plugin attached for weighted canary");
    let targets = split.config["targets"].as_array().unwrap();
    assert_eq!(targets.len(), 2);
    assert_eq!(targets[0]["weight"].as_u64(), Some(80));
    assert_eq!(targets[1]["weight"].as_u64(), Some(20));

    let up_v1_name = targets[0]["upstream"].as_str().unwrap();
    let up_v2_name = targets[1]["upstream"].as_str().unwrap();
    let up_v1 = cfg.upstreams.iter().find(|u| u.name == up_v1_name).unwrap();
    let up_v2 = cfg.upstreams.iter().find(|u| u.name == up_v2_name).unwrap();
    assert_eq!(up_v1.endpoints.len(), 2); // 2 ready pods in app-v1
    assert_eq!(up_v2.endpoints.len(), 1); // 1 ready pod in app-v2 (unready 10.0.2.2 excluded!)

    // 5. Compiles cleanly through full SnapshotCompiler + verifies with zero errors!
    let mut reg = PluginRegistry::new();
    register_builtin_plugins(&mut reg, Arc::new(PrometheusMetrics::new()));
    let compiler = SnapshotCompiler::new(Arc::new(reg), Arc::new(RuntimeRegistry::new()));
    let loaded = shunt_config::LoadedConfig {
        source_name: "k8s-test".to_owned(),
        config: cfg,
        digest: "abc".to_owned(),
    };
    let bundle = compiler.compile(&loaded).unwrap();
    let report = shunt_config::verify_bundle(&bundle, None, false);
    assert!(report.passed, "verify failed: {:?}", report.diagnostics);
}

#[test]
fn hostname_intersection_and_duration_parser_unit() {
    assert_eq!(
        intersect_two_hostnames("*.example.com", "api.example.com").as_deref(),
        Some("api.example.com")
    );
    assert_eq!(
        intersect_two_hostnames("*.example.com", "*.eu.example.com").as_deref(),
        Some("*.eu.example.com")
    );
    assert_eq!(intersect_two_hostnames("*.example.com", "other.org"), None);

    assert_eq!(parse_k8s_duration_ms("500ms"), Some(500));
    assert_eq!(parse_k8s_duration_ms("10s"), Some(10_000));
    assert_eq!(parse_k8s_duration_ms("1m30s"), Some(90_000));
    assert_eq!(parse_k8s_duration_ms("bad"), None);
}

async fn spawn_simple_backend(tag: &'static str) -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let task = tokio::spawn(async move {
        loop {
            let Ok((tcp, _)) = listener.accept().await else {
                break;
            };
            tokio::spawn(async move {
                let svc = service_fn(move |_req: Request<hyper::body::Incoming>| async move {
                    Ok::<_, Infallible>(
                        Response::builder()
                            .status(StatusCode::OK)
                            .body(Full::new(Bytes::from_static(tag.as_bytes())))
                            .unwrap(),
                    )
                });
                let _ = http1::Builder::new()
                    .serve_connection(TokioIo::new(tcp), svc)
                    .await;
            });
        }
    });
    (addr, task)
}

#[tokio::test]
async fn k8s_api_provider_live_sync_and_atomic_hot_reload() {
    let (v1_addr, v1_task) = spawn_simple_backend("backend-v1").await;
    let (v2_addr, v2_task) = spawn_simple_backend("backend-v2").await;

    let active_target = Arc::new(RwLock::new(v1_addr));
    let target_clone = Arc::clone(&active_target);

    // Spawn mock Kubernetes API server
    let api_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let api_addr = api_listener.local_addr().unwrap();
    let api_task = tokio::spawn(async move {
        loop {
            let Ok((tcp, _)) = api_listener.accept().await else {
                break;
            };
            let target_ref = Arc::clone(&target_clone);
            tokio::spawn(async move {
                let svc = service_fn(move |req: Request<hyper::body::Incoming>| {
                    let target = *target_ref.read().unwrap();
                    async move {
                        let body = match req.uri().path() {
                            "/apis/gateway.networking.k8s.io/v1/gatewayclasses" => json!({
                                "items": [{
                                    "metadata": {"name": "shunt"},
                                    "spec": {"controllerName": "shunt.io/gateway-controller"}
                                }]
                            }),
                            "/apis/gateway.networking.k8s.io/v1/namespaces/default/gateways" => {
                                json!({
                                    "items": [{
                                        "metadata": {"name": "gw", "namespace": "default"},
                                        "spec": {
                                            "gatewayClassName": "shunt",
                                            "listeners": [{"name": "http", "port": 80, "protocol": "HTTP"}]
                                        }
                                    }]
                                })
                            }
                            "/apis/gateway.networking.k8s.io/v1/namespaces/default/httproutes" => {
                                json!({
                                    "items": [{
                                        "metadata": {"name": "rt", "namespace": "default"},
                                        "spec": {
                                            "parentRefs": [{"name": "gw"}],
                                            "rules": [{
                                                "matches": [{"path": {"type": "PathPrefix", "value": "/"}}],
                                                "backendRefs": [{"name": "app", "port": 80}]
                                            }]
                                        }
                                    }]
                                })
                            }
                            "/api/v1/namespaces/default/services" => json!({
                                "items": [{
                                    "metadata": {"name": "app", "namespace": "default"},
                                    "spec": {"ports": [{"name": "http", "port": 80, "targetPort": target.port()}]}
                                }]
                            }),
                            "/api/v1/namespaces/default/endpoints" => json!({
                                "items": [{
                                    "metadata": {"name": "app", "namespace": "default"},
                                    "subsets": [{
                                        "addresses": [{"ip": target.ip().to_string()}],
                                        "ports": [{"name": "http", "port": target.port()}]
                                    }]
                                }]
                            }),
                            _ => {
                                return Ok::<_, Infallible>(
                                    Response::builder()
                                        .status(StatusCode::NOT_FOUND)
                                        .body(Full::new(Bytes::new()))
                                        .unwrap(),
                                );
                            }
                        };
                        Ok::<_, Infallible>(
                            Response::builder()
                                .status(StatusCode::OK)
                                .header(header::CONTENT_TYPE, "application/json")
                                .body(Full::new(Bytes::from(body.to_string())))
                                .unwrap(),
                        )
                    }
                });
                let _ = http1::Builder::new()
                    .serve_connection(TokioIo::new(tcp), svc)
                    .await;
            });
        }
    });

    let client_cfg = K8sClientConfig {
        api_server: format!("http://{api_addr}"),
        bearer_token: Some("test-sa-token".to_owned()),
        token_path: None,
        ca_cert_pem: None,
        insecure_skip_verify: false,
        request_timeout: Duration::from_secs(3),
        poll_interval: Duration::from_millis(200),
    };
    let opts = K8sGatewayOptions {
        namespace: Some("default".to_owned()),
        listen: "127.0.0.1:0".to_owned(),
        admin_enabled: false,
        ..K8sGatewayOptions::default()
    };

    let provider = Arc::new(K8sApiConfigProvider::new(client_cfg, opts).unwrap());
    assert!(provider.sync_once().await.unwrap());
    // Second sync with unchanged cluster state reports changed = false
    assert!(!provider.sync_once().await.unwrap());

    let mut reg = PluginRegistry::new();
    register_builtin_plugins(&mut reg, Arc::new(PrometheusMetrics::new()));
    let compiler = Arc::new(SnapshotCompiler::new(
        Arc::new(reg),
        Arc::new(RuntimeRegistry::new()),
    ));
    let loaded = provider.load().unwrap();
    let bundle = compiler.compile(&loaded).unwrap();
    let gw = GatewayServer::new(bundle.snapshot)
        .with_drain_timeout(Duration::from_secs(2))
        .bind("127.0.0.1:0".parse().unwrap())
        .await
        .unwrap();

    let controller = Arc::new(ReloadController::new(
        provider.clone(),
        Arc::clone(&compiler),
        gw.reloader(),
        bundle.inspect,
    ));
    let sync_handle = start_k8s_sync_loop(Arc::clone(&provider), Arc::clone(&controller));

    let http_client = Client::builder(TokioExecutor::new()).build_http::<Full<Bytes>>();

    // Initial request hits backend-v1
    let r1 = http_client
        .request(
            Request::builder()
                .uri(format!("http://{}/hello", gw.local_addr()))
                .body(Full::new(Bytes::new()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(r1.status(), StatusCode::OK);
    let b1 = r1.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(b1, Bytes::from_static(b"backend-v1"));

    // Update Kubernetes Service/Endpoints to point at backend-v2 -> wait for live atomic reload!
    *active_target.write().unwrap() = v2_addr;
    let mut switched = false;
    for _ in 0..25 {
        tokio::time::sleep(Duration::from_millis(80)).await;
        let r = http_client
            .request(
                Request::builder()
                    .uri(format!("http://{}/hello", gw.local_addr()))
                    .body(Full::new(Bytes::new()))
                    .unwrap(),
            )
            .await
            .unwrap();
        let b = r.into_body().collect().await.unwrap().to_bytes();
        if b == Bytes::from_static(b"backend-v2") {
            switched = true;
            break;
        }
    }
    assert!(
        switched,
        "gateway did not hot-reload to backend-v2 from K8s API"
    );

    sync_handle.stop();
    gw.shutdown().await;
    api_task.abort();
    v1_task.abort();
    v2_task.abort();
}

#[test]
fn k8s_gateway_api_supports_regular_expression_paths_and_precedence() {
    let yaml = r#"
apiVersion: gateway.networking.k8s.io/v1
kind: GatewayClass
metadata:
  name: shunt
spec:
  controllerName: shunt.io/gateway-controller
---
apiVersion: gateway.networking.k8s.io/v1
kind: Gateway
metadata:
  name: edge
  namespace: prod
spec:
  gatewayClassName: shunt
  listeners:
    - name: http
      port: 80
      protocol: HTTP
---
apiVersion: v1
kind: Service
metadata:
  name: orders-svc
  namespace: prod
spec:
  ports:
    - port: 80
---
apiVersion: v1
kind: Endpoints
metadata:
  name: orders-svc
  namespace: prod
subsets:
  - addresses:
      - ip: 10.0.2.1
    ports:
      - port: 8080
---
apiVersion: gateway.networking.k8s.io/v1
kind: HTTPRoute
metadata:
  name: orders
  namespace: prod
spec:
  parentRefs:
    - name: edge
  rules:
    - matches:
        - path:
            type: RegularExpression
            value: /orders/[0-9]+/status
      filters:
        - type: URLRewrite
          urlRewrite:
            path:
              type: ReplaceFullPath
              replaceFullPath: /internal/order-status
      backendRefs:
        - name: orders-svc
          port: 80
    - matches:
        - path:
            type: PathPrefix
            value: /orders/special
      backendRefs:
        - name: orders-svc
          port: 80
    - matches:
        - path:
            type: Exact
            value: /orders/0/status
      backendRefs:
        - name: orders-svc
          port: 80
"#;

    let snap = K8sClusterSnapshot::from_yaml_str(yaml).unwrap();
    let cfg = compile_k8s_gateway_snapshot(&snap, &K8sGatewayOptions::default()).unwrap();

    // Gateway API v1 precedence: Exact (r2) > PathPrefix (r1) > RegularExpression (r0).
    assert_eq!(cfg.routes.len(), 3);
    assert_eq!(
        cfg.routes[0].path_exact.as_deref(),
        Some("/orders/0/status")
    );
    assert_eq!(
        cfg.routes[1].path_prefix.as_deref(),
        Some("/orders/special")
    );
    assert_eq!(
        cfg.routes[2].path_regex.as_deref(),
        Some("/orders/[0-9]+/status")
    );

    // Compile into an immutable GatewaySnapshot and verify live route dispatch.
    let metrics = Arc::new(PrometheusMetrics::new());
    let mut reg = PluginRegistry::new();
    register_builtin_plugins(&mut reg, metrics);
    let runtime = Arc::new(RuntimeRegistry::new());
    let compiler = SnapshotCompiler::new(Arc::new(reg), runtime);
    let loaded = shunt_config::LoadedConfig {
        config: cfg,
        digest: "k8s-regex-test".to_owned(),
        source_name: "k8s".to_owned(),
    };
    let bundle = compiler.compile(&loaded).unwrap();

    let req_exact = Request::builder().uri("/orders/0/status").body(()).unwrap();
    assert_eq!(
        bundle.snapshot.match_route(&req_exact).unwrap().id,
        "k8s:prod/orders:r2:m0"
    );

    let req_regex = Request::builder()
        .uri("/orders/9876/status")
        .body(())
        .unwrap();
    assert_eq!(
        bundle.snapshot.match_route(&req_regex).unwrap().id,
        "k8s:prod/orders:r0:m0"
    );

    let req_non_numeric = Request::builder()
        .uri("/orders/abc/status")
        .body(())
        .unwrap();
    assert!(bundle.snapshot.match_route(&req_non_numeric).is_none());

    // Invalid regex is rejected cleanly.
    let bad_re_yaml = yaml.replace("/orders/[0-9]+/status", "/orders/[unclosed");
    let bad_snap = K8sClusterSnapshot::from_yaml_str(&bad_re_yaml).unwrap();
    let err = compile_k8s_gateway_snapshot(&bad_snap, &K8sGatewayOptions::default())
        .unwrap_err()
        .to_string();
    assert!(err.contains("RegularExpression"));

    // ReplacePrefixMatch on a RegularExpression route is rejected per Gateway API v1.
    let bad_rewrite_yaml = yaml.replace(
        "type: ReplaceFullPath\n              replaceFullPath: /internal/order-status",
        "type: ReplacePrefixMatch\n              replacePrefixMatch: /v2",
    );
    let bad_rw_snap = K8sClusterSnapshot::from_yaml_str(&bad_rewrite_yaml).unwrap();
    let rw_err = compile_k8s_gateway_snapshot(&bad_rw_snap, &K8sGatewayOptions::default())
        .unwrap_err()
        .to_string();
    assert!(rw_err.contains("ReplacePrefixMatch"));
}

#[tokio::test]
async fn gateway_http_core_reference_grant_namespace_selector_and_fault_isolation() {
    let (ok_addr, ok_task) = spawn_simple_backend("cross-ns-ok").await;

    let base_yaml = format!(
        r#"
apiVersion: v1
kind: Namespace
metadata:
  name: infra
  labels:
    env: infra
---
apiVersion: v1
kind: Namespace
metadata:
  name: team-allowed
  labels:
    shared-gateway-access: "true"
    tier: gold
---
apiVersion: v1
kind: Namespace
metadata:
  name: team-denied
  labels:
    shared-gateway-access: "false"
---
apiVersion: v1
kind: Namespace
metadata:
  name: backend-ns
---
apiVersion: gateway.networking.k8s.io/v1
kind: GatewayClass
metadata:
  name: shunt
  generation: 2
spec:
  controllerName: shunt.io/gateway-controller
---
apiVersion: gateway.networking.k8s.io/v1
kind: Gateway
metadata:
  name: shared-gw
  namespace: infra
  generation: 3
spec:
  gatewayClassName: shunt
  listeners:
    - name: http
      port: 80
      protocol: HTTP
      allowedRoutes:
        namespaces:
          from: Selector
          selector:
            matchLabels:
              shared-gateway-access: "true"
            matchExpressions:
              - key: tier
                operator: In
                values: ["gold", "silver"]
    - name: bad-tls
      port: 443
      protocol: HTTPS
      tls:
        mode: Terminate
        certificateRefs:
          - name: nonexistent-secret
---
apiVersion: v1
kind: Service
metadata:
  name: shunt-gw-shared-gw
  namespace: infra
spec:
  clusterIP: 10.96.0.10
  ports:
    - port: 80
      targetPort: 10080
---
apiVersion: v1
kind: Service
metadata:
  name: remote-svc
  namespace: backend-ns
spec:
  ports:
    - port: 80
      targetPort: {port}
---
apiVersion: v1
kind: Endpoints
metadata:
  name: remote-svc
  namespace: backend-ns
subsets:
  - addresses:
      - ip: {ip}
    ports:
      - port: {port}
---
apiVersion: gateway.networking.k8s.io/v1
kind: HTTPRoute
metadata:
  name: allowed-route
  namespace: team-allowed
  generation: 4
spec:
  parentRefs:
    - name: shared-gw
      namespace: infra
      sectionName: http
  rules:
    - matches:
        - path:
            type: PathPrefix
            value: /remote
      backendRefs:
        - name: remote-svc
          namespace: backend-ns
          port: 80
    - matches:
        - path:
            type: PathPrefix
            value: /bad-kind
      backendRefs:
        - group: example.com
          kind: Widget
          name: w1
          port: 80
    - matches:
        - path:
            type: PathPrefix
            value: /zero-weight
      backendRefs:
        - name: remote-svc
          namespace: backend-ns
          port: 80
          weight: 0
---
apiVersion: gateway.networking.k8s.io/v1
kind: HTTPRoute
metadata:
  name: denied-ns-route
  namespace: team-denied
  generation: 1
spec:
  parentRefs:
    - name: shared-gw
      namespace: infra
  rules:
    - backendRefs:
        - name: remote-svc
          namespace: backend-ns
          port: 80
"#,
        ip = ok_addr.ip(),
        port = ok_addr.port()
    );

    // 1. Without ReferenceGrant: cross-namespace backend returns 500 & ResolvedRefs=False (RefNotPermitted),
    // while broken HTTPS listener is isolated without failing the HTTP listener!
    let snap_no_grant = K8sClusterSnapshot::from_yaml_str(&base_yaml).unwrap();
    let mut alloc = PortAllocator::new(20_000, 21_000);
    let cluster1 =
        compile_k8s_gateway_cluster(&snap_no_grant, &K8sGatewayOptions::default(), &mut alloc);

    // GatewayClass status has Accepted=True + supportedFeatures
    let gc_status = cluster1.status_plan.gateway_classes.get("shunt").unwrap();
    assert_eq!(gc_status.conditions[0].status, "True");
    assert_eq!(gc_status.conditions[0].observed_generation, 2);
    assert_eq!(
        gc_status.supported_features.len(),
        SUPPORTED_GATEWAY_FEATURES.len()
    );

    // Gateway status: http listener is Programmed=True with attachedRoutes=1; bad-tls is ResolvedRefs=False!
    let gw_status = cluster1
        .status_plan
        .gateways
        .get(&("infra".to_owned(), "shared-gw".to_owned()))
        .unwrap();
    assert_eq!(gw_status.addresses[0].value, "10.96.0.10");
    let http_l = gw_status
        .listeners
        .iter()
        .find(|l| l.name == "http")
        .unwrap();
    assert_eq!(http_l.attached_routes, 1);
    assert!(
        http_l
            .conditions
            .iter()
            .any(|c| c.condition_type == "Programmed" && c.status == "True")
    );
    let tls_l = gw_status
        .listeners
        .iter()
        .find(|l| l.name == "bad-tls")
        .unwrap();
    assert!(
        tls_l
            .conditions
            .iter()
            .any(|c| c.condition_type == "ResolvedRefs"
                && c.status == "False"
                && c.reason == "InvalidCertificateRef")
    );

    // team-denied route was rejected by Namespace selector -> Accepted=False (NotAllowedByListeners)
    let denied_st = cluster1
        .status_plan
        .http_routes
        .get(&("team-denied".to_owned(), "denied-ns-route".to_owned()))
        .unwrap();
    assert!(
        denied_st.parents[0]
            .conditions
            .iter()
            .any(|c| c.condition_type == "Accepted"
                && c.status == "False"
                && c.reason == "NotAllowedByListeners")
    );

    // team-allowed route attached (Accepted=True) but ResolvedRefs=False (RefNotPermitted)
    let allowed_st = cluster1
        .status_plan
        .http_routes
        .get(&("team-allowed".to_owned(), "allowed-route".to_owned()))
        .unwrap();
    assert!(
        allowed_st.parents[0]
            .conditions
            .iter()
            .any(|c| c.condition_type == "Accepted" && c.status == "True")
    );
    assert!(
        allowed_st.parents[0]
            .conditions
            .iter()
            .any(|c| c.condition_type == "ResolvedRefs"
                && c.status == "False"
                && c.reason == "RefNotPermitted")
    );

    // Boot real GatewayServer on the compiled HTTP listener and verify live HTTP 500s!
    assert_eq!(cluster1.listeners.len(), 1);
    let mut reg = PluginRegistry::new();
    register_builtin_plugins(&mut reg, Arc::new(PrometheusMetrics::new()));
    let compiler = Arc::new(SnapshotCompiler::new(
        Arc::new(reg),
        Arc::new(RuntimeRegistry::new()),
    ));
    let mut sup = MultiListenerSupervisor::new(Arc::clone(&compiler))
        .with_bind_ip("127.0.0.1".parse().unwrap())
        .with_drain_timeout(Duration::from_secs(1));
    sup.apply_cluster(&cluster1).await.unwrap();
    let gw_addr = sup.addr_for_gateway_port("infra", "shared-gw", 80).unwrap();
    let http_client = Client::builder(TokioExecutor::new()).build_http::<Full<Bytes>>();

    for path in ["/remote", "/bad-kind", "/zero-weight"] {
        let resp = http_client
            .request(
                Request::builder()
                    .uri(format!("http://{gw_addr}{path}"))
                    .body(Full::new(Bytes::new()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::INTERNAL_SERVER_ERROR,
            "expected HTTP 500 for `{path}` without ReferenceGrant"
        );
    }

    // 2. Add ReferenceGrant in `backend-ns` permitting `team-allowed` HTTPRoute -> Service `remote-svc`!
    let with_grant_yaml = format!(
        "{base_yaml}
---
apiVersion: gateway.networking.k8s.io/v1beta1
kind: ReferenceGrant
metadata:
  name: allow-team-allowed
  namespace: backend-ns
spec:
  from:
    - group: gateway.networking.k8s.io
      kind: HTTPRoute
      namespace: team-allowed
  to:
    - group: \"\"
      kind: Service
      name: remote-svc
"
    );
    let snap_with_grant = K8sClusterSnapshot::from_yaml_str(&with_grant_yaml).unwrap();
    let cluster2 =
        compile_k8s_gateway_cluster(&snap_with_grant, &K8sGatewayOptions::default(), &mut alloc);
    sup.apply_cluster(&cluster2).await.unwrap();

    // `/remote` now hot-reloaded to 200 OK while `/bad-kind` and `/zero-weight` stay 500!
    let ok_resp = http_client
        .request(
            Request::builder()
                .uri(format!("http://{gw_addr}/remote"))
                .body(Full::new(Bytes::new()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(ok_resp.status(), StatusCode::OK);
    let body = ok_resp.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(body, Bytes::from_static(b"cross-ns-ok"));

    let bad_resp = http_client
        .request(
            Request::builder()
                .uri(format!("http://{gw_addr}/bad-kind"))
                .body(Full::new(Bytes::new()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(bad_resp.status(), StatusCode::INTERNAL_SERVER_ERROR);

    sup.shutdown_all().await;
    ok_task.abort();
}

#[test]
fn gateway_http_hostname_precedence_query_params_and_per_backend_headers() {
    let yaml = r#"
apiVersion: gateway.networking.k8s.io/v1
kind: GatewayClass
metadata:
  name: shunt
spec:
  controllerName: shunt.io/gateway-controller
---
apiVersion: gateway.networking.k8s.io/v1
kind: Gateway
metadata:
  name: edge
  namespace: default
spec:
  gatewayClassName: shunt
  listeners:
    - name: http
      port: 80
      protocol: HTTP
---
apiVersion: v1
kind: Service
metadata:
  name: svc-exact-host
  namespace: default
spec:
  ports: [{ port: 80 }]
---
apiVersion: v1
kind: Service
metadata:
  name: svc-wild-host
  namespace: default
spec:
  ports: [{ port: 80 }]
---
apiVersion: gateway.networking.k8s.io/v1
kind: HTTPRoute
metadata:
  name: wild-route
  namespace: default
spec:
  parentRefs: [{ name: edge }]
  hostnames: ["*.example.com"]
  rules:
    - matches:
        - path: { type: Exact, value: /v2 }
      backendRefs:
        - name: svc-wild-host
          port: 80
---
apiVersion: gateway.networking.k8s.io/v1
kind: HTTPRoute
metadata:
  name: exact-route
  namespace: default
spec:
  parentRefs: [{ name: edge }]
  hostnames: ["foo.example.com"]
  rules:
    - matches:
        - path: { type: PathPrefix, value: / }
          queryParams:
            - name: animal
              value: whale
      backendRefs:
        - name: svc-exact-host
          port: 80
          filters:
            - type: RequestHeaderModifier
              requestHeaderModifier:
                add:
                  - name: x-multi
                    value: one
                  - name: x-multi
                    value: two
"#;

    let snap = K8sClusterSnapshot::from_yaml_str(yaml).unwrap();
    let cfg = compile_k8s_gateway_snapshot(&snap, &K8sGatewayOptions::default()).unwrap();

    // Exact hostname (`foo.example.com` PathPrefix `/`) MUST precede wildcard (`*.example.com` Exact `/v2`).
    assert_eq!(cfg.routes.len(), 2);
    assert_eq!(cfg.routes[0].hosts, vec!["foo.example.com"]);
    assert_eq!(
        cfg.routes[0].query_params.get("animal").map(String::as_str),
        Some("whale")
    );
    assert_eq!(cfg.routes[1].hosts, vec!["*.example.com"]);

    // Per-backend multi-value header add compiles cleanly through SnapshotCompiler!
    let mut reg = PluginRegistry::new();
    register_builtin_plugins(&mut reg, Arc::new(PrometheusMetrics::new()));
    let compiler = SnapshotCompiler::new(Arc::new(reg), Arc::new(RuntimeRegistry::new()));
    let loaded = shunt_config::LoadedConfig {
        source_name: "k8s-prec".to_owned(),
        config: cfg,
        digest: "prec".to_owned(),
    };
    let bundle = compiler.compile(&loaded).unwrap();

    let req_exact_host = Request::builder()
        .uri("/v2?animal=whale&animal=dolphin")
        .header(header::HOST, "foo.example.com")
        .body(())
        .unwrap();
    assert_eq!(
        bundle.snapshot.match_route(&req_exact_host).unwrap().id,
        "k8s:default/exact-route:r0:m0"
    );

    // Wrong first query param falls through to wildcard Exact `/v2` route!
    let req_wrong_qp = Request::builder()
        .uri("/v2?animal=dolphin&animal=whale")
        .header(header::HOST, "foo.example.com")
        .body(())
        .unwrap();
    assert_eq!(
        bundle.snapshot.match_route(&req_wrong_qp).unwrap().id,
        "k8s:default/wild-route:r0:m0"
    );
}

#[tokio::test]
async fn k8s_controller_mode_isolates_two_gateways_on_port_80_patches_status_and_rotates_token() {
    let (alpha_addr, alpha_task) = spawn_simple_backend("from-alpha").await;
    let (beta_addr, beta_task) = spawn_simple_backend("from-beta").await;

    // Temporary ServiceAccount token file to test transparent HTTP 401 token reload!
    let token_file =
        std::env::temp_dir().join(format!("shunt-k8s-sa-token-{}", std::process::id()));
    std::fs::write(&token_file, "token-v2").unwrap();

    #[derive(Default)]
    struct MockClusterState {
        expected_token: String,
        created_services: Vec<serde_json::Value>,
        status_patches: Vec<(String, serde_json::Value)>,
    }

    let state = Arc::new(RwLock::new(MockClusterState {
        expected_token: "token-v2".to_owned(),
        created_services: Vec::new(),
        status_patches: Vec::new(),
    }));
    let state_srv = Arc::clone(&state);

    let api_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let api_addr = api_listener.local_addr().unwrap();
    let api_task = tokio::spawn(async move {
        loop {
            let Ok((tcp, _)) = api_listener.accept().await else {
                break;
            };
            let st = Arc::clone(&state_srv);
            tokio::spawn(async move {
                let svc = service_fn(move |req: Request<hyper::body::Incoming>| {
                    let st = Arc::clone(&st);
                    async move {
                        let method = req.method().clone();
                        let path = req.uri().path().to_owned();
                        let auth = req
                            .headers()
                            .get(header::AUTHORIZATION)
                            .and_then(|v| v.to_str().ok())
                            .unwrap_or("")
                            .to_owned();
                        let body_bytes = req.into_body().collect().await.unwrap().to_bytes();

                        let expected = format!("Bearer {}", st.read().unwrap().expected_token);
                        if auth != expected {
                            return Ok::<_, Infallible>(
                                Response::builder()
                                    .status(StatusCode::UNAUTHORIZED)
                                    .body(Full::new(Bytes::from_static(b"expired token")))
                                    .unwrap(),
                            );
                        }

                        if method == http::Method::PATCH && path.ends_with("/status") {
                            let val: serde_json::Value =
                                serde_json::from_slice(&body_bytes).unwrap();
                            st.write().unwrap().status_patches.push((path, val));
                            return Ok(Response::builder()
                                .status(StatusCode::OK)
                                .header(header::CONTENT_TYPE, "application/json")
                                .body(Full::new(Bytes::from_static(b"{}")))
                                .unwrap());
                        }

                        if method == http::Method::POST && path.ends_with("/services") {
                            let mut val: serde_json::Value =
                                serde_json::from_slice(&body_bytes).unwrap();
                            let name = val["metadata"]["name"].as_str().unwrap_or("");
                            let cip = if name.contains("alpha") {
                                "10.96.1.1"
                            } else {
                                "10.96.1.2"
                            };
                            val["spec"]["clusterIP"] = json!(cip);
                            st.write().unwrap().created_services.push(val.clone());
                            return Ok(Response::builder()
                                .status(StatusCode::CREATED)
                                .header(header::CONTENT_TYPE, "application/json")
                                .body(Full::new(Bytes::from(val.to_string())))
                                .unwrap());
                        }

                        let resp_json = match path.as_str() {
                            "/api/v1/namespaces" => json!({
                                "items": [{"metadata": {"name": "default"}}]
                            }),
                            "/apis/gateway.networking.k8s.io/v1/gatewayclasses" => json!({
                                "items": [{
                                    "metadata": {"name": "shunt", "generation": 1},
                                    "spec": {"controllerName": "shunt.io/gateway-controller"}
                                }]
                            }),
                            "/apis/gateway.networking.k8s.io/v1/gateways" => json!({
                                "items": [
                                    {
                                        "metadata": {"name": "gw-alpha", "namespace": "default", "generation": 1},
                                        "spec": {
                                            "gatewayClassName": "shunt",
                                            "listeners": [{"name": "http", "port": 80, "protocol": "HTTP"}]
                                        }
                                    },
                                    {
                                        "metadata": {"name": "gw-beta", "namespace": "default", "generation": 1},
                                        "spec": {
                                            "gatewayClassName": "shunt",
                                            "listeners": [{"name": "http", "port": 80, "protocol": "HTTP"}]
                                        }
                                    }
                                ]
                            }),
                            "/apis/gateway.networking.k8s.io/v1/httproutes" => json!({
                                "items": [
                                    {
                                        "metadata": {"name": "rt-alpha", "namespace": "default", "generation": 1},
                                        "spec": {
                                            "parentRefs": [{"name": "gw-alpha"}],
                                            "rules": [{"backendRefs": [{"name": "svc-alpha", "port": 80}]}]
                                        },
                                        "status": {
                                            "parents": [{
                                                "parentRef": {"name": "other-gw"},
                                                "controllerName": "other.io/controller",
                                                "conditions": []
                                            }]
                                        }
                                    },
                                    {
                                        "metadata": {"name": "rt-beta", "namespace": "default", "generation": 1},
                                        "spec": {
                                            "parentRefs": [{"name": "gw-beta"}],
                                            "rules": [{"backendRefs": [{"name": "svc-beta", "port": 80}]}]
                                        }
                                    }
                                ]
                            }),
                            "/apis/gateway.networking.k8s.io/v1beta1/referencegrants" => {
                                json!({"items": []})
                            }
                            "/api/v1/services" => {
                                let mut items = vec![
                                    json!({
                                        "metadata": {"name": "svc-alpha", "namespace": "default"},
                                        "spec": {"ports": [{"port": 80, "targetPort": alpha_addr.port()}]}
                                    }),
                                    json!({
                                        "metadata": {"name": "svc-beta", "namespace": "default"},
                                        "spec": {"ports": [{"port": 80, "targetPort": beta_addr.port()}]}
                                    }),
                                ];
                                items.extend(st.read().unwrap().created_services.clone());
                                json!({"items": items})
                            }
                            "/api/v1/endpoints" => json!({
                                "items": [
                                    {
                                        "metadata": {"name": "svc-alpha", "namespace": "default"},
                                        "subsets": [{"addresses": [{"ip": alpha_addr.ip().to_string()}], "ports": [{"port": alpha_addr.port()}]}]
                                    },
                                    {
                                        "metadata": {"name": "svc-beta", "namespace": "default"},
                                        "subsets": [{"addresses": [{"ip": beta_addr.ip().to_string()}], "ports": [{"port": beta_addr.port()}]}]
                                    }
                                ]
                            }),
                            "/apis/discovery.k8s.io/v1/endpointslices" => json!({"items": []}),
                            _ => {
                                return Ok(Response::builder()
                                    .status(StatusCode::NOT_FOUND)
                                    .body(Full::new(Bytes::new()))
                                    .unwrap());
                            }
                        };

                        Ok::<_, Infallible>(
                            Response::builder()
                                .status(StatusCode::OK)
                                .header(header::CONTENT_TYPE, "application/json")
                                .body(Full::new(Bytes::from(resp_json.to_string())))
                                .unwrap(),
                        )
                    }
                });
                let _ = http1::Builder::new()
                    .serve_connection(TokioIo::new(tcp), svc)
                    .await;
            });
        }
    });

    // Start provider with stale initial bearer token `"token-v1"` — client must reload `token-v2` on 401!
    let client_cfg = K8sClientConfig {
        api_server: format!("http://{api_addr}"),
        bearer_token: Some("token-v1".to_owned()),
        token_path: Some(token_file.clone()),
        ca_cert_pem: None,
        insecure_skip_verify: false,
        request_timeout: Duration::from_secs(3),
        poll_interval: Duration::from_millis(500),
    };
    let opts = K8sGatewayOptions {
        write_status: true,
        manage_services: true,
        port_range_start: 22_000,
        port_range_end: 23_000,
        ..K8sGatewayOptions::default()
    };

    let provider = K8sApiConfigProvider::new(client_cfg, opts).unwrap();
    let mut reg = PluginRegistry::new();
    register_builtin_plugins(&mut reg, Arc::new(PrometheusMetrics::new()));
    let compiler = Arc::new(SnapshotCompiler::new(
        Arc::new(reg),
        Arc::new(RuntimeRegistry::new()),
    ));
    let mut allocator = PortAllocator::new(22_000, 23_000);
    let mut sup = MultiListenerSupervisor::new(compiler)
        .with_bind_ip("127.0.0.1".parse().unwrap())
        .with_drain_timeout(Duration::from_secs(1));

    // Reconcile #1: recovers from 401 via token file reload, creates 2 Services, binds 2 isolated ports, PATCHes 5 statuses!
    reconcile_k8s_controller_once(&provider, &mut allocator, &mut sup)
        .await
        .unwrap();

    let addr_alpha = sup
        .addr_for_gateway_port("default", "gw-alpha", 80)
        .unwrap();
    let addr_beta = sup.addr_for_gateway_port("default", "gw-beta", 80).unwrap();
    assert_ne!(addr_alpha.port(), addr_beta.port());

    let http_client = Client::builder(TokioExecutor::new()).build_http::<Full<Bytes>>();
    let r_a = http_client
        .request(
            Request::builder()
                .uri(format!("http://{addr_alpha}/"))
                .body(Full::new(Bytes::new()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        r_a.into_body().collect().await.unwrap().to_bytes(),
        Bytes::from_static(b"from-alpha")
    );

    let r_b = http_client
        .request(
            Request::builder()
                .uri(format!("http://{addr_beta}/"))
                .body(Full::new(Bytes::new()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        r_b.into_body().collect().await.unwrap().to_bytes(),
        Bytes::from_static(b"from-beta")
    );

    // Verify 2 managed Services created & 5 status PATCHes (1 GatewayClass + 2 Gateways + 2 HTTPRoutes)
    let first_patch_count = {
        let st = state.read().unwrap();
        assert_eq!(st.created_services.len(), 2);
        assert_eq!(st.status_patches.len(), 5);
        // Verify foreign controller parent status was preserved on rt-alpha!
        let rt_alpha_patch = st
            .status_patches
            .iter()
            .find(|(p, _)| p.contains("httproutes/rt-alpha/status"))
            .unwrap();
        let parents = rt_alpha_patch.1["status"]["parents"].as_array().unwrap();
        assert_eq!(parents.len(), 2);
        assert!(
            parents
                .iter()
                .any(|p| p["controllerName"] == "other.io/controller")
        );
        assert!(
            parents
                .iter()
                .any(|p| p["controllerName"] == "shunt.io/gateway-controller")
        );
        st.status_patches.len()
    };

    // Reconcile #2 (unchanged cluster): status digest deduplication must emit ZERO extra PATCH calls!
    reconcile_k8s_controller_once(&provider, &mut allocator, &mut sup)
        .await
        .unwrap();
    assert_eq!(
        state.read().unwrap().status_patches.len(),
        first_patch_count
    );

    sup.shutdown_all().await;
    let _ = std::fs::remove_file(&token_file);
    api_task.abort();
    alpha_task.abort();
    beta_task.abort();
}
