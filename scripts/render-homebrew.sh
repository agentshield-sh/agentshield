#!/bin/bash
# Render the Homebrew formula for the built release.
#
# Reads dist/release/SHA256SUMS and substitutes the version and the four
# per-platform checksums into packaging/homebrew/agentshield.rb.
#
#   ./scripts/build-release.sh && ./scripts/render-homebrew.sh
#
# Writes dist/release/agentshield.rb, ready to commit to the tap repository.

set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
TEMPLATE="$REPO/packaging/homebrew/agentshield.rb"
SUMS="$REPO/dist/release/SHA256SUMS"
OUT="$REPO/dist/release/agentshield.rb"
VERSION="$(node -p "require('$REPO/package.json').version")"

[ -f "$SUMS" ] || { echo "error: $SUMS not found — run ./scripts/build-release.sh first" >&2; exit 1; }

sum_for() {
  local value
  value="$(grep " agentshield-$1\$" "$SUMS" | cut -d' ' -f1 | head -n 1)"
  [ -n "$value" ] || { echo "error: no checksum for agentshield-$1 in SHA256SUMS" >&2; exit 1; }
  echo "$value"
}

sed \
  -e "s|VERSION|$VERSION|g" \
  -e "s|SHA256_DARWIN_ARM64|$(sum_for darwin-arm64)|" \
  -e "s|SHA256_DARWIN_X64|$(sum_for darwin-x64)|" \
  -e "s|SHA256_LINUX_ARM64|$(sum_for linux-arm64)|" \
  -e "s|SHA256_LINUX_X64|$(sum_for linux-x64)|" \
  "$TEMPLATE" > "$OUT"

# A leftover placeholder means a silent, broken formula — fail loudly instead.
if grep -q "SHA256_\|\"VERSION\"" "$OUT"; then
  echo "error: unsubstituted placeholders remain in $OUT" >&2
  grep -n "SHA256_\|\"VERSION\"" "$OUT" >&2
  exit 1
fi

echo "wrote $OUT (version $VERSION)"
