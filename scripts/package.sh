#!/usr/bin/env bash
#
# Assemble the plugin package raidman-<version>.tgz reproducibly: fixed mtime
# (the last commit's time, or SOURCE_DATE_EPOCH), sorted entries, owner 0:0,
# normalised modes and gzip -n. The same inputs always give the same SHA-256.
#
# Contents (what the plg install script expects):
#   raidman, rc.raidman (0755); raidman.page, raidman.conf, icon.png (0644);
#   web/novnc/ (runtime part of the pinned noVNC release, with its licence).
#
# Usage: scripts/package.sh <version> <binary> <outdir>
#   NOVNC_TARBALL  verified noVNC archive (from scripts/fetch-novnc.sh);
#                  downloaded when unset (needs NOVNC_VERSION/NOVNC_SHA256)
# Needs GNU tar. Prints the package's SHA-256 on the last line.
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
VERSION=${1:?usage: scripts/package.sh <version> <binary> <outdir>}
BINARY=${2:?usage: scripts/package.sh <version> <binary> <outdir>}
OUTDIR=${3:?usage: scripts/package.sh <version> <binary> <outdir>}
[[ $VERSION =~ ^[A-Za-z0-9._-]+$ ]] || { echo "package: invalid version '$VERSION'" >&2; exit 1; }
[ -f "$BINARY" ] || { echo "package: binary $BINARY not found" >&2; exit 1; }

TAR=tar
if ! tar --version 2>/dev/null | grep -q 'GNU tar'; then
  if command -v gtar >/dev/null 2>&1; then
    TAR=gtar
  else
    echo "package: GNU tar is required (macOS: brew install gnu-tar)" >&2
    exit 1
  fi
fi

EPOCH=${SOURCE_DATE_EPOCH:-$(git -C "$ROOT" log -1 --format=%ct)}
[[ $EPOCH =~ ^[0-9]+$ ]] || { echo "package: invalid SOURCE_DATE_EPOCH" >&2; exit 1; }

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
STAGE="$WORK/pkg"
mkdir -p "$STAGE/web"

install -m 0755 "$BINARY" "$STAGE/raidman"
install -m 0755 "$ROOT/src/rc.raidman" "$STAGE/rc.raidman"
install -m 0644 "$ROOT/src/raidman.page" "$STAGE/raidman.page"
install -m 0644 "$ROOT/raidman.conf" "$STAGE/raidman.conf"
install -m 0644 "$ROOT/icon.png" "$STAGE/icon.png"

# noVNC: only what vnc.html loads at runtime (it fetches defaults.json,
# mandatory.json and package.json), plus the licence files (MPL-2.0; vendored
# pako is MIT, its licence is inside vendor/).
TARBALL=${NOVNC_TARBALL:-}
if [ -z "$TARBALL" ]; then
  TARBALL="$WORK/novnc.tar.gz"
  bash "$ROOT/scripts/fetch-novnc.sh" "$TARBALL"
fi
mkdir -p "$WORK/novnc"
tar -xzf "$TARBALL" -C "$WORK/novnc"
SRC=$(find "$WORK/novnc" -mindepth 1 -maxdepth 1 -type d -name 'noVNC-*' | head -n 1)
[ -n "$SRC" ] && [ -f "$SRC/vnc.html" ] || { echo "package: $TARBALL is not a noVNC release" >&2; exit 1; }
mkdir -p "$STAGE/web/novnc"
for item in vnc.html vnc_lite.html defaults.json mandatory.json package.json LICENSE.txt AUTHORS README.md app core vendor; do
  [ -e "$SRC/$item" ] || { echo "package: noVNC is missing $item" >&2; exit 1; }
  cp -R "$SRC/$item" "$STAGE/web/novnc/"
done
find "$STAGE/web" -type d -exec chmod 0755 {} +
find "$STAGE/web" -type f -exec chmod 0644 {} +
chmod 0755 "$STAGE" "$STAGE/web"
if find "$STAGE" -type l | grep -q .; then
  echo "package: symlinks are not allowed in the package" >&2
  exit 1
fi

mkdir -p "$OUTDIR"
PKG="$OUTDIR/raidman-$VERSION.tgz"
LC_ALL=C "$TAR" --sort=name --mtime="@$EPOCH" --owner=0 --group=0 --numeric-owner \
  --format=gnu -cf - -C "$STAGE" . | gzip -n -9 > "$PKG"

if command -v sha256sum >/dev/null 2>&1; then
  SHA256=$(sha256sum "$PKG" | awk '{print $1}')
else
  SHA256=$(shasum -a 256 "$PKG" | awk '{print $1}')
fi
echo "$SHA256  raidman-$VERSION.tgz" > "$PKG.sha256"
echo "package: $PKG"
echo "$SHA256"
