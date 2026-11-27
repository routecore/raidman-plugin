#!/usr/bin/env bash
#
# Set <!ENTITY version> and <!ENTITY sha256> in a raidman.plg (in place).
# Used by the release job only: humans never edit these two lines.
#
# Usage: scripts/stamp-plg.sh <raidman.plg> <version> <sha256>
set -euo pipefail

PLG=${1:?usage: scripts/stamp-plg.sh <raidman.plg> <version> <sha256>}
VERSION=${2:?usage: scripts/stamp-plg.sh <raidman.plg> <version> <sha256>}
SHA256=${3:?usage: scripts/stamp-plg.sh <raidman.plg> <version> <sha256>}
[[ $VERSION =~ ^[0-9]{4}\.[0-9]{2}\.[0-9]{2}[a-z]?$ ]] || { echo "stamp-plg: invalid version '$VERSION'" >&2; exit 1; }
[[ $SHA256 =~ ^[0-9a-f]{64}$ ]] || { echo "stamp-plg: invalid sha256 '$SHA256'" >&2; exit 1; }

for entity in version sha256; do
  n=$(grep -cE "^<!ENTITY ${entity} +\"[^\"]*\">\$" "$PLG" || true)
  [ "$n" = 1 ] || { echo "stamp-plg: expected one <!ENTITY $entity \"...\"> line in $PLG, found $n" >&2; exit 1; }
done

TMP=$(mktemp "$PLG.XXXXXX")
trap 'rm -f "$TMP"' EXIT
sed -E \
  -e "s|^<!ENTITY version +\"[^\"]*\">\$|<!ENTITY version   \"$VERSION\">|" \
  -e "s|^<!ENTITY sha256 +\"[^\"]*\">\$|<!ENTITY sha256    \"$SHA256\">|" \
  "$PLG" > "$TMP"
grep -qx "<!ENTITY version   \"$VERSION\">" "$TMP" || { echo "stamp-plg: version not stamped" >&2; exit 1; }
grep -qx "<!ENTITY sha256    \"$SHA256\">" "$TMP" || { echo "stamp-plg: sha256 not stamped" >&2; exit 1; }
cat "$TMP" > "$PLG"
echo "stamp-plg: $PLG -> $VERSION / $SHA256"
