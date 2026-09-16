#!/bin/bash
# Build standalone AgentShield binaries for every supported platform and write
# a SHA256SUMS file next to them.
#
# AgentShield depends only on Node builtins, so each target compiles to a single
# self-contained executable that needs no Node install on the user's machine.
#
#   ./scripts/build-release.sh            build every target
#   ./scripts/build-release.sh darwin-arm64   build one
#
# Requires bun (https://bun.sh) for --compile. Output lands in dist/release/.

set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
ENTRY="$REPO/packages/cli/src/index.js"
OUT="$REPO/dist/release"
VERSION="$(node -p "require('$REPO/package.json').version")"

# bun --target => the artifact suffix users download
TARGETS=(
  "bun-darwin-arm64:darwin-arm64"
  "bun-darwin-x64:darwin-x64"
  "bun-linux-x64:linux-x64"
  "bun-linux-arm64:linux-arm64"
)

if ! command -v bun >/dev/null 2>&1; then
  echo "error: bun is required to build binaries — see https://bun.sh" >&2
  exit 1
fi

only="${1:-}"

rm -rf "$OUT"
mkdir -p "$OUT"

echo "AgentShield $VERSION → $OUT"
echo

for entry in "${TARGETS[@]}"; do
  target="${entry%%:*}"
  suffix="${entry##*:}"
  [ -n "$only" ] && [ "$only" != "$suffix" ] && continue

  artifact="agentshield-$suffix"
  printf '  %-16s ' "$suffix"

  # --define must be space-separated. bun silently ignores the esbuild-style
  # --define:NAME=VALUE form, which builds fine but bakes in no version.
  bun build "$ENTRY" \
    --compile \
    --minify \
    --sourcemap=none \
    --target="$target" \
    --define __AGENTSHIELD_VERSION__="\"$VERSION\"" \
    --outfile "$OUT/$artifact" >/dev/null 2>&1

  # bun appends .exe on Windows targets; we ship none, but stay defensive.
  [ -f "$OUT/$artifact.exe" ] && mv "$OUT/$artifact.exe" "$OUT/$artifact"
  chmod +x "$OUT/$artifact"

  size="$(du -h "$OUT/$artifact" | cut -f1 | tr -d ' ')"
  echo "ok  ($size)"
done

# Checksums are what the installer verifies before it runs anything.
cd "$OUT"
if command -v sha256sum >/dev/null 2>&1; then
  sha256sum agentshield-* > SHA256SUMS
else
  shasum -a 256 agentshield-* > SHA256SUMS
fi

echo
echo "SHA256SUMS"
sed 's/^/  /' SHA256SUMS
