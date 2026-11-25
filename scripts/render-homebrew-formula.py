#!/usr/bin/env python3
"""Render the Homebrew Formula (Formula/shunt.rb) for a Shunt release."""

from __future__ import annotations

import argparse
import pathlib
import sys

TARGETS = {
    "macos_arm": "aarch64-apple-darwin",
    "macos_intel": "x86_64-apple-darwin",
    "linux_arm": "aarch64-unknown-linux-musl",
    "linux_intel": "x86_64-unknown-linux-musl",
}


def parse_checksums(path: pathlib.Path) -> dict[str, str]:
    checksums: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        parts = line.split()
        if len(parts) < 2:
            continue
        digest, filename = parts[0], parts[1].lstrip("*")
        checksums[filename] = digest
    return checksums


def render_formula(version: str, repo: str, checksums: dict[str, str]) -> str:
    tag = f"v{version}"
    shas: dict[str, str] = {}
    for key, target in TARGETS.items():
        archive = f"shunt-{tag}-{target}.tar.gz"
        if archive not in checksums:
            raise KeyError(f"missing checksum for {archive}")
        shas[key] = checksums[archive]

    base = f"https://github.com/{repo}/releases/download/v#{{version}}"
    return f'''class Shunt < Formula
  desc "Ultra-lean, pluggable Rust gateway for HTTP APIs, AI, and MCP"
  homepage "https://github.com/{repo}"
  version "{version}"
  license "Apache-2.0"

  on_macos do
    on_arm do
      url "{base}/shunt-v#{{version}}-aarch64-apple-darwin.tar.gz"
      sha256 "{shas["macos_arm"]}"
    end

    on_intel do
      url "{base}/shunt-v#{{version}}-x86_64-apple-darwin.tar.gz"
      sha256 "{shas["macos_intel"]}"
    end
  end

  on_linux do
    on_arm do
      url "{base}/shunt-v#{{version}}-aarch64-unknown-linux-musl.tar.gz"
      sha256 "{shas["linux_arm"]}"
    end

    on_intel do
      url "{base}/shunt-v#{{version}}-x86_64-unknown-linux-musl.tar.gz"
      sha256 "{shas["linux_intel"]}"
    end
  end

  def install
    bin.install "shunt"
    pkgshare.install "examples"
  end

  test do
    assert_match version.to_s, shell_output("#{{bin}}/shunt --version")
  end
end
'''


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tag", required=True, help="Release tag (e.g. v0.3.0)")
    parser.add_argument(
        "--checksums",
        required=True,
        type=pathlib.Path,
        help="Path to SHA256SUMS.txt from the GitHub Release",
    )
    parser.add_argument(
        "--repo",
        default="shettyh/shunt",
        help="GitHub repository slug (default: shettyh/shunt)",
    )
    parser.add_argument(
        "--output",
        default="-",
        help="Output file path, or '-' for stdout (default: '-')",
    )
    args = parser.parse_args()

    version = args.tag.removeprefix("v")
    checksums = parse_checksums(args.checksums)
    formula = render_formula(version=version, repo=args.repo, checksums=checksums)

    if args.output == "-":
        sys.stdout.write(formula)
    else:
        out = pathlib.Path(args.output)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(formula, encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
