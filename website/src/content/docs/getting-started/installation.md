---
title: Installation
description: Install the Shunt single-binary gateway via crates.io, GitHub Releases, Docker, or from source.
---

Shunt ships as a **single statically linked binary** (`shunt`) with all first-party plugin packs (`shunt-plugins`, `shunt-ai`, `shunt-mcp`) and the optional read-only Admin Inspector UI compiled in—zero runtime dependencies, no database, and no sidecars required.

## Prebuilt Binaries (GitHub Releases)

Download the latest archive for your platform from [GitHub Releases](https://github.com/shettyh/shunt/releases). Available targets:

| Platform | Architecture | Archive |
| --- | --- | --- |
| Linux (static `musl`) | `x86_64`, `aarch64` | `shunt-vX.Y.Z-*-unknown-linux-musl.tar.gz` |
| Linux (`glibc`) | `x86_64`, `aarch64` | `shunt-vX.Y.Z-*-unknown-linux-gnu.tar.gz` |
| macOS | Apple Silicon (`aarch64`), Intel (`x86_64`) | `shunt-vX.Y.Z-*-apple-darwin.tar.gz` |
| Windows | `x86_64` | `shunt-vX.Y.Z-x86_64-pc-windows-msvc.zip` |

Every release includes `SHA256SUMS.txt` and GitHub build provenance attestations.

```bash
# Example: macOS Apple Silicon
tar -xzf shunt-v0.1.2-aarch64-apple-darwin.tar.gz
sudo mv shunt-v0.1.2-aarch64-apple-darwin/shunt /usr/local/bin/shunt
shunt --version
```

## Cargo (`crates.io`)

Requires Rust **1.91+** (edition 2024):

```bash
cargo install shunt-cli
shunt --version
```

:::note[Optional minimal build without embedded Inspector UI]
The embedded Admin Inspector UI (`--ui`) is enabled by default via the `admin-ui` Cargo feature. To compile a stripped binary without UI assets:
```bash
cargo install shunt-cli --no-default-features
```
:::

## Docker (`ghcr.io`)

Multi-arch images (`linux/amd64`, `linux/arm64`) are published to GitHub Container Registry:

```bash
docker run --rm \
  -p 8080:8080 \
  -p 9090:9090 \
  -v "$PWD/shunt.toml:/etc/shunt/shunt.toml:ro" \
  ghcr.io/shettyh/shunt:latest
```

To enable the read-only Admin Inspector UI in Docker, pass `run --ui -c /etc/shunt/shunt.toml` and bind `[admin] listen = "0.0.0.0:9090"` inside the container (keeping port `9090` mapped only to localhost on the host: `-p 127.0.0.1:9090:9090`).

## Build from Source

```bash
git clone https://github.com/shettyh/shunt.git
cd shunt
cargo install --path crates/shunt-cli
```

## Verify Your Install

```bash
shunt --version
shunt --help
```

Next, pick a 2-minute quickstart for your use case:
- [Quickstart: HTTP API Gateway](/shunt/getting-started/quickstart-api/)
- [Quickstart: Multi-Provider AI Gateway](/shunt/getting-started/quickstart-ai/)
- [Quickstart: Virtual MCP Gateway](/shunt/getting-started/quickstart-mcp/)
