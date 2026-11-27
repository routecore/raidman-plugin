#!/usr/bin/env bash
#
# Download the pinned noVNC release archive and verify its SHA-256.
# The version and hash are pinned in .github/workflows/build-plugin.yml
# (NOVNC_VERSION / NOVNC_SHA256); pass them in the environment.
#
# Usage: NOVNC_VERSION=1.6.0 NOVNC_SHA256=<sha256> scripts/fetch-novnc.sh <output.tar.gz>
set -euo pipefail

OUT=${1:?usage: scripts/fetch-novnc.sh <output.tar.gz>}
: "${NOVNC_VERSION:?NOVNC_VERSION is not set (see .github/workflows/build-plugin.yml)}"
: "${NOVNC_SHA256:?NOVNC_SHA256 is not set (see .github/workflows/build-plugin.yml)}"
[[ $NOVNC_VERSION =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || { echo "fetch-novnc: invalid NOVNC_VERSION" >&2; exit 1; }
[[ $NOVNC_SHA256 =~ ^[0-9a-f]{64}$ ]] || { echo "fetch-novnc: invalid NOVNC_SHA256" >&2; exit 1; }

sha256_of() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
  else
    shasum -a 256 "$1" | awk '{print $1}'
  fi
}

mkdir -p "$(dirname "$OUT")"
curl -fsSL --retry 3 --proto '=https' -o "$OUT.part" \
  "https://github.com/novnc/noVNC/archive/refs/tags/v${NOVNC_VERSION}.tar.gz"
got=$(sha256_of "$OUT.part")
if [ "$got" != "$NOVNC_SHA256" ]; then
  rm -f "$OUT.part"
  echo "fetch-novnc: noVNC v$NOVNC_VERSION has SHA-256 $got, expected $NOVNC_SHA256" >&2
  exit 1
fi
mv "$OUT.part" "$OUT"
echo "fetch-novnc: noVNC v$NOVNC_VERSION OK"
