---
title: Kubernetes Gateway API
description: Run Shunt directly from Kubernetes Gateway API v1 manifests or live in-cluster API sync without sidecars or heavy controllers.
---

Shunt includes a zero-bloat **Kubernetes Gateway API v1** `ConfigProvider` that compiles `GatewayClass`, `Gateway`, `HTTPRoute`, `Service`, `Endpoints`, and TLS `Secret` resources directly into immutable `GatewaySnapshot`s.

## Two Operating Modes

### 1. Local / GitOps Manifest Mode (`--k8s-manifest`)

Validate, verify, or run directly from a YAML file or directory (with automatic file-watch hot reload):

```bash
shunt check  --k8s-manifest examples/k8s-gateway-api.yaml
shunt verify --k8s-manifest examples/k8s-gateway-api.yaml
shunt dev --ui --k8s-manifest examples/k8s-gateway-api.yaml
shunt run    --k8s-manifest ./k8s-manifests/ --listen 0.0.0.0:8080
```

### 2. Live Cluster Sync Mode (`--k8s-gateway`)

Poll the Kubernetes API server directly (using in-cluster ServiceAccount credentials or `--k8s-api-server` + `K8S_BEARER_TOKEN`) and atomically hot-reload on every change:

```bash
shunt run --k8s-gateway \
  --k8s-controller-name shunt.io/gateway-controller \
  --k8s-namespace prod \
  --k8s-poll-interval-ms 5000 \
  --listen 0.0.0.0:8080
```

## Supported Resources & Features

| Resource | Supported Capabilities |
| --- | --- |
| `GatewayClass` | Filtered by `spec.controllerName` (default: `shunt.io/gateway-controller`) |
| `Gateway` | Listeners (`HTTP`/`HTTPS`), `hostname` globs, `tls.certificateRefs` (`Secret` PEM certs with SNI), `allowedRoutes`, global plugin annotations |
| `HTTPRoute` | `parentRefs`, `hostnames`, `PathPrefix`/`Exact` path matches, HTTP `method` & `headers` exact matches, `timeouts.backendRequest`, weighted `backendRefs` |
| `HTTPRoute` Filters | `RequestHeaderModifier`, `ResponseHeaderModifier`, `RequestRedirect`, `URLRewrite` (`ReplaceFullPath`, `ReplacePrefixMatch`, `hostname`), `RequestMirror` |
| `Service` & `Endpoints` | Resolves backend service ports and pod endpoint IPs into weighted Shunt upstream pools |
| `Secret` | Inline PEM TLS certs & private keys (redacted in `/snapshot`) |

## Shunt Annotations

Attach any first-party HTTP, AI, or MCP plugin to Kubernetes resources using JSON annotations:

| Annotation | Target | Example |
| --- | --- | --- |
| `shunt.io/global-plugins` | `Gateway` | `'[{"name":"request-id"},{"name":"metrics"}]'` |
| `shunt.io/plugins` | `HTTPRoute` | `'[{"name":"compression","config":{"encodings":["zstd","br","gzip"]}}]'` |
| `shunt.io/max-attempts` | `HTTPRoute` | `"2"` |
| `shunt.io/max-body-bytes` | `HTTPRoute` | `"1048576"` |

## Example Manifest

```yaml
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
  name: edge-gateway
  namespace: default
  annotations:
    shunt.io/global-plugins: '[{"name":"request-id"},{"name":"metrics"}]'
spec:
  gatewayClassName: shunt
  listeners:
    - name: http
      hostname: "*.example.com"
      port: 80
      protocol: HTTP
---
apiVersion: gateway.networking.k8s.io/v1
kind: HTTPRoute
metadata:
  name: payments-route
  namespace: default
  annotations:
    shunt.io/max-attempts: "2"
    shunt.io/plugins: '[{"name":"compression","config":{"encodings":["zstd","br","gzip"]}}]'
spec:
  parentRefs:
    - name: edge-gateway
  hostnames:
    - "api.example.com"
  rules:
    - matches:
        - path:
            type: PathPrefix
            value: /v2/payments
      backendRefs:
        - name: payments-v1
          port: 80
          weight: 90
        - name: payments-v2
          port: 80
          weight: 10
```
