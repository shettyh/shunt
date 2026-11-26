---
title: Kubernetes Gateway API
description: Run Shunt directly from Kubernetes Gateway API v1 manifests or live in-cluster API sync without sidecars or heavy controllers.
---

Shunt includes a zero-bloat **Kubernetes Gateway API v1** compiler and controller (`GATEWAY-HTTP` profile, RFC 0028) that compiles `GatewayClass`, `Gateway`, `HTTPRoute`, `ReferenceGrant`, `Namespace`, `Service`, `Endpoints`/`EndpointSlice`, and TLS `Secret` resources directly into immutable `GatewaySnapshot`s — with zero `kube-rs` / `k8s-openapi` dependency bloat.

## Three Operating Modes

### 1. Local / GitOps Manifest Mode (`--k8s-manifest`)

Validate, verify, or run directly from a YAML file or directory (with automatic file-watch hot reload):

```bash
shunt check  --k8s-manifest examples/k8s-gateway-api.yaml
shunt verify --k8s-manifest examples/k8s-gateway-api.yaml
shunt dev --ui --k8s-manifest examples/k8s-gateway-api.yaml
shunt run    --k8s-manifest ./k8s-manifests/ --listen 0.0.0.0:8080
```

### 2. Read-Only Live Cluster Sync (`--k8s-gateway`)

Poll the Kubernetes API server with strictly read-only RBAC (in-cluster ServiceAccount with automatic projected-token rotation, or `--k8s-api-server` + `K8S_BEARER_TOKEN`) and atomically hot-reload on every change:

```bash
shunt run --k8s-gateway \
  --k8s-controller-name shunt.io/gateway-controller \
  --k8s-namespace prod \
  --k8s-poll-interval-ms 5000 \
  --listen 0.0.0.0:8080
```

### 3. Full `GATEWAY-HTTP` Controller Mode (`--k8s-controller`)

Run Shunt as a multi-Gateway Kubernetes Gateway API controller using a shared non-root Shunt Deployment + per-`Gateway` port-mapped `Service`:

```bash
kubectl apply -f https://github.com/kubernetes-sigs/gateway-api/releases/download/v1.2.1/standard-install.yaml
kubectl apply -f deploy/k8s/shunt-gateway-controller.yaml
```

In `--k8s-controller` mode Shunt automatically:
- Isolates multiple `Gateway` objects (including overlapping `:80`/`:443` listeners) via `MultiListenerSupervisor` on `--k8s-port-range` (default `10080-19999`),
- Reconciles one Kubernetes `Service` per `Gateway` (`--k8s-service-type ClusterIP|LoadBalancer|NodePort`) mapping each listener port to its isolated pod port,
- Reconciles `.status` subresources (`GatewayClass`, `Gateway`, `HTTPRoute`) including `supportedFeatures`, `addresses`, `attachedRoutes`, `observedGeneration`, and per-object fault isolation.

## Supported Resources & Features

| Resource | Supported Capabilities |
| --- | --- |
| `GatewayClass` | Filtered by `spec.controllerName` (default: `shunt.io/gateway-controller`); publishes `Accepted` + `supportedFeatures` |
| `Gateway` | Multi-port `HTTP`/`HTTPS` listeners, conflict detection (`ProtocolConflict`/`HostnameConflict`), `hostname` globs, `tls.certificateRefs` (with PEM validation & `ReferenceGrant` checks), `allowedRoutes` (`Same`/`All`/`Selector` on `Namespace` labels + `kinds`), `attachedRoutes` & `addresses` status |
| `HTTPRoute` | `parentRefs`, `hostnames` (hostname-first precedence), `Exact` / `PathPrefix` / `RegularExpression` path matches, `headers` & `queryParams` exact matches, HTTP `method`, `timeouts.backendRequest`/`request`, weighted `backendRefs` (with synthetic `500` on invalid/unpermitted/zero-weight refs), per-backend filters |
| `HTTPRoute` Filters | `RequestHeaderModifier`, `ResponseHeaderModifier` (multi-value `add`), `RequestRedirect` (scheme/port-preserving), `URLRewrite` (`ReplaceFullPath`, `ReplacePrefixMatch`, `hostname`), `RequestMirror` |
| `ReferenceGrant` | Enforces cross-namespace `HTTPRoute -> Service` and `Gateway -> Secret` authorization |
| `Service`, `Endpoints` & `EndpointSlice` | Resolves backend service ports and ready pod IPs into upstream pools |
| `Secret` | Inline PEM TLS certs & private keys (validated via `ring`/`rustls`, redacted in `/snapshot`) |

## Official SIG-Network Conformance Suite

Shunt ships a Go conformance test harness under `tests/k8s-conformance/` targeting the official `sigs.k8s.io/gateway-api/conformance` `GATEWAY-HTTP` profile (executed automatically in `.github/workflows/k8s-conformance.yml`):

```bash
cd tests/k8s-conformance
go test -v -timeout 20m ./... --gateway-class=shunt --conformance-profiles=GATEWAY-HTTP
```

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
