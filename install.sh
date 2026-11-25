#!/bin/sh
# Shunt installer — downloads a verified prebuilt release binary for macOS or Linux.
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/shettyh/shunt/main/install.sh | sh
#
# Optional environment variables / flags:
#   SHUNT_VERSION / --version <tag>   Install a specific release (e.g. v0.3.0 or 0.3.0)
#   SHUNT_INSTALL_DIR / --dir <path>  Installation directory (default: $HOME/.local/bin)
#   SHUNT_LIBC                        Linux libc variant: musl (default) or gnu
#   SHUNT_REPO                        GitHub repository (default: shettyh/shunt)
set -eu

REPO="${SHUNT_REPO:-shettyh/shunt}"
INSTALL_DIR="${SHUNT_INSTALL_DIR:-$HOME/.local/bin}"
VERSION="${SHUNT_VERSION:-}"
LIBC="${SHUNT_LIBC:-musl}"

err()  { printf 'error: %s\n' "$1" >&2; exit 1; }
info() { printf '%s\n' "$1" >&2; }

need_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    err "required command not found: $1"
  fi
}

usage() {
  cat <<'EOF'
Install Shunt (https://github.com/shettyh/shunt)

Usage:
  install.sh [OPTIONS]

Options:
  -v, --version <VER>   Install a specific version (e.g. v0.3.0 or 0.3.0)
  -d, --dir <DIR>       Directory to install `shunt` into (default: ~/.local/bin)
  -h, --help            Show this help message

Environment variables:
  SHUNT_VERSION         Same as --version
  SHUNT_INSTALL_DIR     Same as --dir
  SHUNT_LIBC            Linux libc variant: musl (default) or gnu
EOF
}

parse_args() {
  while [ $# -gt 0 ]; do
    case "$1" in
      -v|--version)
        [ $# -ge 2 ] || err "missing value for $1"
        VERSION="$2"
        shift 2
        ;;
      -d|--dir)
        [ $# -ge 2 ] || err "missing value for $1"
        INSTALL_DIR="$2"
        shift 2
        ;;
      -h|--help)
        usage
        exit 0
        ;;
      *)
        err "unknown option: $1 (use --help for usage)"
        ;;
    esac
  done
}

normalize_tag() {
  case "$1" in
    v*) printf '%s\n' "$1" ;;
    *)  printf 'v%s\n' "$1" ;;
  esac
}

detect_target() {
  _os="${1:-$(uname -s)}"
  _arch="${2:-$(uname -m)}"
  _libc="${3:-$LIBC}"

  case "$_os" in
    Darwin)
      case "$_arch" in
        arm64|aarch64) printf '%s\n' "aarch64-apple-darwin" ;;
        x86_64|amd64)  printf '%s\n' "x86_64-apple-darwin" ;;
        *) err "unsupported macOS architecture: $_arch" ;;
      esac
      ;;
    Linux)
      case "$_libc" in
        musl|gnu) : ;;
        *) err "unsupported SHUNT_LIBC value: $_libc (expected 'musl' or 'gnu')" ;;
      esac
      case "$_arch" in
        x86_64|amd64)  printf '%s\n' "x86_64-unknown-linux-${_libc}" ;;
        aarch64|arm64) printf '%s\n' "aarch64-unknown-linux-${_libc}" ;;
        *) err "unsupported Linux architecture: $_arch" ;;
      esac
      ;;
    MINGW*|MSYS*|CYGWIN*)
      err "Windows is not supported by install.sh; download the .zip from https://github.com/${REPO}/releases or run: cargo install shunt-cli"
      ;;
    *)
      err "unsupported OS: $_os (see https://github.com/${REPO}/releases)"
      ;;
  esac
}

resolve_latest_tag() {
  _latest_url="https://github.com/${REPO}/releases/latest"
  _effective=$(curl -fsSL -o /dev/null -w '%{url_effective}' "$_latest_url") \
    || err "failed to resolve latest release from $_latest_url"
  _tag="${_effective##*/}"
  case "$_tag" in
    v[0-9]*)
      printf '%s\n' "$_tag"
      ;;
    *)
      err "could not determine latest release tag (resolved '$_effective')"
      ;;
  esac
}

sha256_file() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
  elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$1" | awk '{print $1}'
  elif command -v openssl >/dev/null 2>&1; then
    openssl dgst -sha256 "$1" | awk '{print $NF}'
  else
    err "no SHA-256 tool found (need sha256sum, shasum, or openssl)"
  fi
}

verify_checksum() {
  _archive_path="$1"
  _archive_name="$2"
  _sums_path="$3"

  _expected=$(awk -v f="$_archive_name" '$2 == f { print $1; exit }' "$_sums_path")
  [ -n "$_expected" ] || err "checksum entry for $_archive_name not found in SHA256SUMS.txt"

  _actual=$(sha256_file "$_archive_path")
  if [ "$_actual" != "$_expected" ]; then
    err "SHA-256 checksum mismatch for $_archive_name (expected $_expected, got $_actual)"
  fi
}

print_path_hint() {
  _dir="$1"
  case ":${PATH:-}:" in
    *":$_dir:"*) return 0 ;;
  esac

  info ""
  info "Note: $_dir is not on your PATH."
  _shell_name=$(basename "${SHELL:-sh}")
  case "$_shell_name" in
    zsh)
      info "Add it with:"
      info "  echo 'export PATH=\"$_dir:\$PATH\"' >> ~/.zshrc && source ~/.zshrc"
      ;;
    bash)
      info "Add it with:"
      info "  echo 'export PATH=\"$_dir:\$PATH\"' >> ~/.bashrc && source ~/.bashrc"
      ;;
    fish)
      info "Add it with:"
      info "  fish_add_path \"$_dir\""
      ;;
    *)
      info "Add it to your shell profile:"
      info "  export PATH=\"$_dir:\$PATH\""
      ;;
  esac
}

main() {
  parse_args "$@"

  need_cmd curl
  need_cmd tar
  need_cmd awk
  need_cmd mktemp

  target=$(detect_target)
  if [ -n "$VERSION" ]; then
    tag=$(normalize_tag "$VERSION")
  else
    tag=$(resolve_latest_tag)
  fi

  pkg="shunt-${tag}-${target}"
  archive="${pkg}.tar.gz"
  base_url="https://github.com/${REPO}/releases/download/${tag}"
  archive_url="${base_url}/${archive}"
  sums_url="${base_url}/SHA256SUMS.txt"

  tmp=$(mktemp -d)
  trap 'rm -rf "$tmp"' EXIT

  info "Downloading Shunt ${tag} (${target})..."
  curl -fL --progress-bar -o "${tmp}/${archive}" "$archive_url" \
    || err "failed to download ${archive_url}"

  curl -fsSL -o "${tmp}/SHA256SUMS.txt" "$sums_url" \
    || err "failed to download ${sums_url}"

  verify_checksum "${tmp}/${archive}" "$archive" "${tmp}/SHA256SUMS.txt"
  info "Verified SHA-256 checksum."

  tar -xzf "${tmp}/${archive}" -C "$tmp" \
    || err "failed to extract ${archive}"

  bin_src="${tmp}/${pkg}/shunt"
  [ -f "$bin_src" ] || err "expected binary not found in archive: ${pkg}/shunt"

  mkdir -p "$INSTALL_DIR"
  chmod 0755 "$bin_src"
  mv "$bin_src" "${INSTALL_DIR}/shunt"

  info "Installed shunt to ${INSTALL_DIR}/shunt"
  if installed_ver=$("${INSTALL_DIR}/shunt" --version 2>/dev/null); then
    info "Verified: ${installed_ver}"
  fi

  print_path_hint "$INSTALL_DIR"
  info ""
  info "Get started: shunt --help"
}

# Allow sourcing in tests without executing.
if [ "${SHUNT_INSTALL_LIB:-0}" != "1" ]; then
  main "$@"
fi
