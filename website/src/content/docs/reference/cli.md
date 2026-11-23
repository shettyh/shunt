---
title: CLI Commands
description: Reference for every shunt CLI subcommand and flag (check, verify, test, dev, run).
---

The `shunt` binary provides five subcommands covering validation, static policy verification, contract testing, local development, and production serving.

## `shunt check`

Validate configuration, compile the snapshot, and print compiled routes alongside active `HookMask` bitmasks.

```bash
shunt check [-c FILE] [--k8s-manifest PATH] [--k8s-controller-name NAME] [--k8s-namespace NS]
```

| Flag | Default | Description |
| --- | --- | --- |
| `-c, --config <FILE>` | `shunt.toml` | Path to TOML or YAML config file |
| `--k8s-manifest <PATH>` | — | Kubernetes Gateway API YAML manifest file or directory |
| `--k8s-controller-name <NAME>` | `shunt.io/gateway-controller` | `GatewayClass.spec.controllerName` filter |
| `--k8s-namespace <NS>` | — | Optional Kubernetes namespace filter |

**Example output (`shunt check -c examples/shunt-route-groups.toml`):**

```text
Configuration valid: examples/shunt-route-groups.toml
Snapshot v1 (digest: fd1970ac5990, state: memory, telemetry: disabled)

Global Plugins:
  - request-id         mask=[on_request_headers | on_response_headers]
  - metrics            mask=[on_complete]

Route Groups (2):
  - api_v2           [*.example.com /v2] routes=2 plugins=[ip-filter -> jwt-auth -> rate-limit]
  - billing_api      [api.example.com /billing] routes=2 plugins=[jwt-auth -> rate-limit]

Upstreams (4):
  - billing_svc        pool=#3 [h1/h2] -> http://127.0.0.1:18084
  - orders_svc         pool=#2 [h1/h2] -> http://127.0.0.1:18082
  - public_svc         pool=#4 [h1/h2] -> http://127.0.0.1:18083
  - users_svc          pool=#1 [h1/h2] -> http://127.0.0.1:18081

Routes (5):
  - api_v2_users     [GET,POST api.example.com /v2/users*] -> users_svc (attempts=2 group=api_v2, plugins=[request-id -> metrics -> ip-filter -> jwt-auth -> rate-limit])
    HookMask: on_request_headers | on_response_headers | on_complete
  - api_v2_orders    [ANY *.example.com /v2/orders*] -> orders_svc (attempts=3 group=api_v2, plugins=[request-id -> metrics -> ip-filter -> jwt-auth -> rate-limit -> header-rewrite])
    HookMask: on_request_headers | on_response_headers | on_complete
  - billing_invoices [GET,POST api.example.com /billing/invoices*] -> billing_svc (attempts=1 group=billing_api, plugins=[request-id -> metrics -> jwt-auth -> rate-limit])
    HookMask: on_request_headers | on_response_headers | on_complete
  - billing_subscriptions [ANY api.example.com /billing/subscriptions*] -> billing_svc (attempts=1 group=billing_api, plugins=[request-id -> metrics -> jwt-auth -> rate-limit])
    HookMask: on_request_headers | on_response_headers | on_complete
  - public_health    [GET * =/health] -> public_svc (attempts=1, plugins=[request-id -> metrics])
    HookMask: on_request_headers | on_response_headers | on_complete
```

---

## `shunt verify`

Run static IR, route-shadowing, plugin-chain ordering, and declarative policy checks.

```bash
shunt verify [-c FILE | --k8s-manifest PATH] [--policy FILE] [--strict] [--format text|json]
```

| Flag | Default | Description |
| --- | --- | --- |
| `-c, --config <FILE>` | `shunt.toml` | Path to TOML or YAML config file |
| `--k8s-manifest <PATH>` | — | Kubernetes Gateway API manifest file or directory |
| `--policy <FILE>` | — | External policy TOML file overriding `[verify]` |
| `--format <text\|json>` | `text` | Output format |
| `--strict` | `false` | Treat warnings as errors (non-zero exit code) |

**Example output:**

```text
Verification passed: examples/shunt-route-groups.toml (0 errors, 0 warnings)
```

---

## `shunt test`

Execute declarative TOML contract tests (`*.spec.toml`) against in-process mock upstreams.

```bash
shunt test -s SPEC.toml [-c FILE] [--filter SUBSTR] [--format text|json]
```

| Flag | Default | Description |
| --- | --- | --- |
| `-s, --spec <SPEC>` | *(required)* | Path to `*.spec.toml` contract test suite |
| `-c, --config <FILE>` | `spec.config` | Optional override path to `shunt.toml` |
| `--filter <SUBSTR>` | — | Only run cases whose name contains this substring (case-insensitive) |
| `--format <text\|json>` | `text` | Output format |

---

## `shunt dev`

Run in developer mode with automatic file-watch hot reloads, live per-hook µs trace waterfalls on `stderr`, and optional browser Inspector UI.

```bash
shunt dev [-c FILE | --k8s-manifest PATH] [--ui]
```

| Flag | Default | Description |
| --- | --- | --- |
| `-c, --config <FILE>` | `shunt.toml` | Path to TOML or YAML config file |
| `--ui` | `false` | Enable read-only Admin Inspector Web UI (`http://127.0.0.1:9090/ui`) and live SSE traces |
| `--k8s-manifest <PATH>` | — | Watch and serve Kubernetes Gateway API manifests |
| `--k8s-controller-name <NAME>` | `shunt.io/gateway-controller` | `GatewayClass` filter |
| `--k8s-namespace <NS>` | — | Optional namespace filter |

---

## `shunt run`

Run the production gateway with atomic hot reloads (file watch, `POST /reload`, `SIGHUP`, or live Kubernetes Gateway API sync) and graceful connection draining (`SIGTERM` / `SIGINT`).

```bash
shunt run [-c FILE | --k8s-manifest PATH | --k8s-gateway] [--no-watch] [--ui]
```

| Flag | Default | Description |
| --- | --- | --- |
| `-c, --config <FILE>` | `shunt.toml` | Path to TOML or YAML config file |
| `--no-watch` | `false` | Disable automatic file watcher (`POST /reload` and `SIGHUP` still work) |
| `--ui` | `false` | Enable opt-in read-only Admin Inspector Web UI on the Admin listener |
| `--k8s-manifest <PATH>` | — | Load & watch Kubernetes Gateway API YAML manifests |
| `--k8s-gateway` | `false` | Enable live Kubernetes Gateway API sync from the cluster API server |
| `--k8s-api-server <URL>` | in-cluster | Explicit K8s API server URL (reads `K8S_BEARER_TOKEN` if set) |
| `--k8s-namespace <NS>` | — | Optional K8s namespace filter |
| `--k8s-controller-name <NAME>` | `shunt.io/gateway-controller` | `GatewayClass` filter |
| `--k8s-poll-interval-ms <MS>` | `5000` | Poll interval for `--k8s-gateway` |
| `--listen <ADDR>` | `0.0.0.0:8080` | Listener override when using `--k8s-manifest` or `--k8s-gateway` |
