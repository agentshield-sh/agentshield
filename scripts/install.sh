#!/bin/sh
# AgentShield installer.
#
# This script downloads a released binary and verifies its SHA256 checksum
# against the signed SHA256SUMS file BEFORE putting anything on your PATH.
# Nothing is executed until that check passes.
#
# You are encouraged to read this file before running it:
#
#   curl -fsSL https://agentshield.sh/install.sh -o install.sh
#   less install.sh
#   sh install.sh
#
# Options (environment variables):
#   AGENTSHIELD_VERSION   pin a version, e.g. 0.1.0   (default: latest release)
#   AGENTSHIELD_PREFIX    install directory           (default: ~/.local/bin)

set -eu

REPO="agentshield-sh/agentshield"
PREFIX="${AGENTSHIELD_PREFIX:-$HOME/.local/bin}"

die() { printf '\033[31merror\033[0m %s\n' "$1" >&2; exit 1; }
info() { printf '  %s\n' "$1"; }

# ---------------------------------------------------------------- requirements
if command -v curl >/dev/null 2>&1; then
  fetch() { curl -fsSL "$1" -o "$2"; }
  fetch_stdout() { curl -fsSL "$1"; }
elif command -v wget >/dev/null 2>&1; then
  fetch() { wget -qO "$2" "$1"; }
  fetch_stdout() { wget -qO- "$1"; }
else
  die "curl or wget is required."
fi

if command -v sha256sum >/dev/null 2>&1; then
  checksum() { sha256sum "$1" | cut -d' ' -f1; }
elif command -v shasum >/dev/null 2>&1; then
  checksum() { shasum -a 256 "$1" | cut -d' ' -f1; }
else
  die "sha256sum or shasum is required to verify the download."
fi

# ------------------------------------------------------------------- platform
os="$(uname -s)"
arch="$(uname -m)"

case "$os" in
  Darwin) os="darwin" ;;
  Linux)  os="linux" ;;
  *) die "unsupported operating system: $os. AgentShield supports macOS and Linux." ;;
esac

case "$arch" in
  arm64|aarch64) arch="arm64" ;;
  x86_64|amd64)  arch="x64" ;;
  *) die "unsupported architecture: $arch" ;;
esac

artifact="agentshield-$os-$arch"

# -------------------------------------------------------------------- version
version="${AGENTSHIELD_VERSION:-}"
if [ -z "$version" ]; then
  version="$(fetch_stdout "https://api.github.com/repos/$REPO/releases/latest" \
    | sed -n 's/.*"tag_name"[[:space:]]*:[[:space:]]*"v\{0,1\}\([^"]*\)".*/\1/p' \
    | head -n 1)"
  [ -n "$version" ] || die "could not determine the latest version. Set AGENTSHIELD_VERSION to pin one."
fi

base="https://github.com/$REPO/releases/download/v$version"

echo
echo "AgentShield $version ($os-$arch)"
echo

# ------------------------------------------------------------------- download
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT INT TERM

info "downloading $artifact"
fetch "$base/$artifact" "$tmp/$artifact" || die "download failed: $base/$artifact"

info "downloading SHA256SUMS"
fetch "$base/SHA256SUMS" "$tmp/SHA256SUMS" || die "could not fetch SHA256SUMS — refusing to install unverified."

# --------------------------------------------------------------------- verify
expected="$(grep " $artifact\$" "$tmp/SHA256SUMS" | cut -d' ' -f1 | head -n 1)"
[ -n "$expected" ] || die "no checksum published for $artifact — refusing to install."

actual="$(checksum "$tmp/$artifact")"

if [ "$expected" != "$actual" ]; then
  printf '\033[31m\n  CHECKSUM MISMATCH — NOTHING WAS INSTALLED\033[0m\n\n' >&2
  printf '    expected  %s\n' "$expected" >&2
  printf '    actual    %s\n\n' "$actual" >&2
  die "the download does not match the published checksum. Do not run it."
fi

info "checksum verified  ${actual}"

# -------------------------------------------------------------------- install
mkdir -p "$PREFIX" || die "could not create $PREFIX"
chmod +x "$tmp/$artifact"
mv "$tmp/$artifact" "$PREFIX/agentshield" || die "could not install to $PREFIX"

echo
printf '\033[32m  installed\033[0m  %s\n' "$PREFIX/agentshield"
echo

case ":$PATH:" in
  *":$PREFIX:"*) ;;
  *)
    printf '  %s is not on your PATH. Add it:\n\n' "$PREFIX"
    printf '    export PATH="%s:$PATH"\n\n' "$PREFIX"
    ;;
esac

echo "  Get started:"
echo
echo "    agentshield scan"
echo
