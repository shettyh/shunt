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
    ReloadController, SnapshotCompiler, compile_k8s_gateway_snapshot, intersect_two_hostnames,
    parse_k8s_duration_ms, start_k8s_sync_loop,
};
use shunt_core::{GatewayServer, RuntimeRegistry};
use shunt_plugin_sdk::PluginRegistry;
use shunt_plugins::{PrometheusMetrics, register_builtin_plugins};
use tokio::net::TcpListener;

fn b64_std(data: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    let mut chunks = data.chunks_exact(3);
    for c in &mut chunks {
        let n = ((c[0] as u32) << 16) | ((c[1] as u32) << 8) | (c[2] as u32);
        out.push(TABLE[((n >> 18) & 63) as usize] as char);
        out.push(TABLE[((n >> 12) & 63) as usize] as char);
        out.push(TABLE[((n >> 6) & 63) as usize] as char);
        out.push(TABLE[(n & 63) as usize] as char);
    }
    match chunks.remainder() {
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
    assert_eq!(api_route.max_attempts, 2);
    assert_eq!(api_route.response_headers_timeout_ms, Some(2_500));
    assert_eq!(api_route.mirrors.len(), 1);
    assert!(api_route.plugins.iter().any(|p| p.name == "header-rewrite"));

    // 4. Canary weight scaling: app-v1 (2 ready pods, weight 80) -> 80 each? Wait: LCM(2,1)=2 ->
    // app-v1 gets 80*2/2 = 80 per pod (total 160), app-v2 (1 ready pod, unready skipped!, weight 20)
    // gets 20*2/1 = 40 -> 160:40 == exact 80:20 split!
    let up = cfg
        .upstreams
        .iter()
        .find(|u| u.name == api_route.upstream)
        .unwrap();
    assert_eq!(up.endpoints.len(), 3); // 2 ready pods in v1 + 1 ready pod in v2 (unready 10.0.2.2 excluded!)
    let v1_weight: u32 = up
        .endpoints
        .iter()
        .filter(|e| e.url().contains("10.0.1."))
        .map(|e| e.weight())
        .sum();
    let v2_weight: u32 = up
        .endpoints
        .iter()
        .filter(|e| e.url().contains("10.0.2."))
        .map(|e| e.weight())
        .sum();
    assert_eq!(v1_weight * 20, v2_weight * 80);

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
