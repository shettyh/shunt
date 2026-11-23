---
title: Security, TLS & Auth
description: Configure hot-reloadable SNI TLS, mutual TLS (mTLS) client certificate auth, pure-Rust JWT/JWKS/OIDC verification, CIDR IP filtering, and rate limiting.
---

Shunt ships pure-Rust security primitives with zero OpenSSL or external auth-service dependencies—all hot-reloadable without dropping active connections.

## Hot-Reloadable SNI TLS & mTLS

Configure TLS termination and mutual TLS under `[server.tls]`. Shunt watches all referenced certificate, private key, and client CA files automatically and reloads the `rustls` resolver atomically whenever certs rotate on disk:

```toml
[server]
listen = "0.0.0.0:8443"

[server.tls]
cert = "certs/default.crt"
key = "certs/default.key"
client_ca = "certs/client-ca.crt"
client_auth = "required" # "none" | "optional" | "required"

[[server.tls.sni]]
host = "payments.example.com"
cert = "certs/payments.crt"
key = "certs/payments.key"
```

Pair `[server.tls]` with [`mtls-auth`](/shunt/plugins/http-plugins/#mtls-auth) to enforce CN, SAN DNS, SPIFFE URI, or SHA-256 fingerprint allowlists and inject verified identity headers upstream (incoming headers with the same names are always stripped first to prevent spoofing).

## Pure-Rust JWT / JWKS / OIDC (`jwt-auth`)

Supports `HS256`/`HS384`/`HS512`, `RS256`/`RS384`/`RS512`, `PS256`/`PS384`/`PS512`, `ES256`/`ES384`, and `EdDSA`, with automatic OIDC discovery, cached JWKS background refresh, anti-DoS refresh throttling on unknown `kid`s, and claim forwarding:

```toml
[[routes.plugins]]
name = "jwt-auth"
[routes.plugins.config]
oidc_discovery = true
issuer = "https://auth.example.com"
audience = "payments-api"
algorithms = ["RS256", "ES256", "EdDSA"]
required_scopes = ["orders:read"]
forward_claims = { "sub" = "x-user-id", "org.id" = "x-org-id" }
strip_header = true
```

## CIDR IP Filtering, Body Limits & Rate Limiting

Combine edge protection plugins in order so invalid traffic is shed synchronously before hitting upstreams:

```toml
[[routes.plugins]]
name = "ip-filter"
[routes.plugins.config]
allow = ["10.0.0.0/8", "127.0.0.0/8"]
deny = ["10.99.0.0/16"]
trusted_proxies = ["10.0.0.1/32"]
use_forwarded_for = true

[[routes.plugins]]
name = "rate-limit"
id = "api-rl" # preserves bucket state across hot reloads
[routes.plugins.config]
requests_per_second = 100.0
burst = 200
key = "subject" # uses authenticated JWT/mTLS/bearer subject
distributed = true # shares limits across replicas when [state] backend = "redis"

[[routes.plugins]]
name = "body-limit"
[routes.plugins.config]
max_bytes = 1048576 # 1 MiB across both Content-Length and chunked streams
```
