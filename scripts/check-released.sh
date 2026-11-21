#!/usr/bin/env bash
#
# Check that raidman.plg's install script still fits the released package it
# points to. stamp-main.sh only changes the version and SHA-256 on main, so a
# later change on main that makes the install script need a new file would
# break every install of the current release. This downloads the package
# named by the plg, checks its SHA-256 against the plg's, and runs
# check-package.sh on it with this plg.
#
# Usage: scripts/check-released.sh [path/to/raidman.plg]
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
PLG=${1:-$ROOT/raidman.plg}

fail() {
  echo "check-released: $*" >&2
  exit 1
}

command -v xmllint >/dev/null 2>&1 || fail "xmllint not found (Debian/Ubuntu: apt-get install libxml2-utils)"
xpath() {
  xmllint --noent --nonet --xpath "$1" "$PLG"
}
[ "$(xpath 'count(//FILE[URL])')" = 1 ] || fail "expected exactly one <FILE> with a <URL> in $PLG"
URL=$(xpath 'normalize-space(//FILE[URL]/URL)')
WANT=$(xpath 'normalize-space(//FILE[URL]/SHA256)')
[[ $WANT =~ ^[0-9a-f]{64}$ ]] || fail "<SHA256> for $URL is '$WANT', not a SHA-256"
case $URL in
  https://github.com/*/releases/download/*) ;;
  *) fail "unexpected package URL: $URL" ;;
esac

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
PKG="$TMP/$(basename "$URL")"
curl -fsSL --proto '=https' --retry 3 -o "$PKG" "$URL" || fail "cannot download $URL"
GOT=$(sha256sum "$PKG" 2>/dev/null | cut -d' ' -f1 || shasum -a 256 "$PKG" | cut -d' ' -f1)
[ "$GOT" = "$WANT" ] || fail "$URL has SHA-256 $GOT, the plg says $WANT"
bash "$ROOT/scripts/check-package.sh" "$PKG" "$PLG"
echo "check-released: $URL fits the install script in $PLG"
