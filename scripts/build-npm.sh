#!/usr/bin/env bash
# Build per-platform npm packages from cross-compiled Go binaries.
#
# Usage: scripts/build-npm.sh <version>
# Example: scripts/build-npm.sh 0.1.0
#
# Output layout:
#   dist/npm/mcp-gate/                     (wrapper, version stamped)
#   dist/npm/mcp-gate-darwin-arm64/        (binary + package.json)
#   dist/npm/mcp-gate-darwin-x64/
#   dist/npm/mcp-gate-linux-x64/
#   dist/npm/mcp-gate-linux-arm64/
#
# Each platform package can then be published with `npm publish dist/npm/<name>`.
#
# Windows is not yet supported — internal/wrapper uses syscall.SIGUSR1 (Unix-only).
# Add darwin/linux ports first; once wrapper is portable, add "win32-x64:windows/amd64".

set -euo pipefail

VERSION="${1:-}"
if [[ -z "$VERSION" ]]; then
  echo "usage: $0 <version>  (e.g. 0.1.0)" >&2
  exit 2
fi

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
OUT_DIR="$ROOT_DIR/dist/npm"
SRC_PKG="$ROOT_DIR/npm/mcp-gate"

# Map: <npm-platform>-<npm-arch> => <GOOS>/<GOARCH>
TARGETS=(
  "darwin-arm64:darwin/arm64"
  "darwin-x64:darwin/amd64"
  "linux-x64:linux/amd64"
  "linux-arm64:linux/arm64"
)

rm -rf "$OUT_DIR"
mkdir -p "$OUT_DIR"

# 1. Wrapper package — copy and stamp version.
cp -R "$SRC_PKG" "$OUT_DIR/mcp-gate"
node -e "
  const fs = require('fs');
  const p = '$OUT_DIR/mcp-gate/package.json';
  const j = JSON.parse(fs.readFileSync(p, 'utf8'));
  j.version = '$VERSION';
  for (const k of Object.keys(j.optionalDependencies || {})) {
    j.optionalDependencies[k] = '$VERSION';
  }
  fs.writeFileSync(p, JSON.stringify(j, null, 2) + '\n');
"
chmod +x "$OUT_DIR/mcp-gate/bin/cli.js"

# 2. Per-platform packages.
for entry in "${TARGETS[@]}"; do
  npm_id="${entry%%:*}"
  go_target="${entry##*:}"
  goos="${go_target%%/*}"
  goarch="${go_target##*/}"

  pkg_dir="$OUT_DIR/mcp-gate-$npm_id"
  bin_dir="$pkg_dir/bin"
  mkdir -p "$bin_dir"

  bin_name="mcp-gate"
  [[ "$goos" == "windows" ]] && bin_name="mcp-gate.exe"

  # Parse npm-style npm_id back into node platform/arch fields.
  node_platform="${npm_id%-*}"
  node_arch="${npm_id##*-}"

  echo "==> building $npm_id ($goos/$goarch)"
  GOOS="$goos" GOARCH="$goarch" CGO_ENABLED=0 \
    go build -trimpath -ldflags="-s -w -X main.version=$VERSION" \
    -o "$bin_dir/$bin_name" \
    "$ROOT_DIR/cmd/mcp-gate"

  cat > "$pkg_dir/package.json" <<EOF
{
  "name": "mcp-gate-$npm_id",
  "version": "$VERSION",
  "description": "mcp-gate prebuilt binary for $npm_id.",
  "homepage": "https://github.com/seoo2001/mcp-gate",
  "repository": {
    "type": "git",
    "url": "git+https://github.com/seoo2001/mcp-gate.git"
  },
  "license": "MIT",
  "files": ["bin/"],
  "os": ["$node_platform"],
  "cpu": ["$node_arch"]
}
EOF
done

echo
echo "Built packages in $OUT_DIR:"
ls -1 "$OUT_DIR"
