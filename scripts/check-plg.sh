#!/usr/bin/env bash
#
# Lint raidman.plg and the Community Applications XML files:
#   - raidman.plg, raidman.xml and ca_profile.xml are well-formed XML and the
#     plg's entities resolve (a broken CDATA/entity split fails here);
#   - the plugin version has the release format and has a <CHANGE> entry;
#   - every <FILE> that downloads something has an https <URL> and a 64-hex
#     <SHA256> (the Community Applications requirement);
#   - every inline script parses with bash -n, the install script carries the
#     resolved VERSION, and no inline script downloads anything itself;
#   - src/rc.raidman and scripts/*.sh parse with bash -n.
# When installed, shellcheck also runs (errors only).
#
# Usage: scripts/check-plg.sh [--allow-unstamped] [path/to/raidman.plg]
#   --allow-unstamped  accept an empty <SHA256> (a plg that was never released)
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
ALLOW_UNSTAMPED=0
if [ "${1:-}" = "--allow-unstamped" ]; then
  ALLOW_UNSTAMPED=1
  shift
fi
PLG=${1:-$ROOT/raidman.plg}
VERSION_RE='^[0-9]{4}\.[0-9]{2}\.[0-9]{2}[a-z]?$'

fail() {
  echo "check-plg: $*" >&2
  exit 1
}

command -v xmllint >/dev/null 2>&1 || fail "xmllint not found (Debian/Ubuntu: apt-get install libxml2-utils)"
HAVE_SHELLCHECK=0
if command -v shellcheck >/dev/null 2>&1; then
  HAVE_SHELLCHECK=1
fi

xpath() {
  xmllint --noent --nonet --xpath "$1" "$PLG"
}

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

# Well-formed XML; --noent also resolves every entity of the plg.
xmllint --noout --nonet "$PLG" "$ROOT/raidman.xml" "$ROOT/ca_profile.xml" || fail "XML is not well-formed"
xmllint --noout --noent --nonet "$PLG" || fail "$PLG: entities do not resolve"

VERSION=$(xpath 'string(/PLUGIN/@version)')
[[ $VERSION =~ $VERSION_RE ]] || fail "plugin version '$VERSION' is not YYYY.MM.DD[a-z]"
grep -qF "<CHANGE>$VERSION - " "$PLG" || fail "no <CHANGE>$VERSION - ...</CHANGE> entry for the plugin version"

# Every downloaded file is pinned by SHA-256.
[ "$(xpath 'count(//FILE[URL][not(SHA256)])')" = 0 ] || fail "a <FILE> with a <URL> has no <SHA256>"
NURL=$(xpath 'count(//FILE[URL])')
for ((i = 1; i <= NURL; i++)); do
  url=$(xpath "normalize-space((//FILE[URL])[$i]/URL)")
  sha=$(xpath "normalize-space((//FILE[URL])[$i]/SHA256)")
  [[ $url == https://* ]] || fail "<URL> '$url' is not https"
  if [ -z "$sha" ] && [ "$ALLOW_UNSTAMPED" = 1 ]; then
    echo "check-plg: note: $url has no SHA-256 yet (unstamped plg)"
    continue
  fi
  [[ $sha =~ ^[0-9a-f]{64}$ ]] || fail "<SHA256> for $url is '$sha', not a SHA-256 (the release workflow stamps it)"
done

# Inline scripts.
NINLINE=$(xpath 'count(//FILE[INLINE])')
[ "$NINLINE" -ge 1 ] || fail "no inline scripts found"
for ((i = 1; i <= NINLINE; i++)); do
  method=$(xpath "string((//FILE[INLINE])[$i]/@Method)")
  run=$(xpath "string((//FILE[INLINE])[$i]/@Run)")
  script="$WORK/inline-$i-${method:-file}.sh"
  xpath "string((//FILE[INLINE])[$i]/INLINE)" > "$script"
  case "$run" in
    /bin/bash | bash) ;;
    *) fail "inline script $i (${method:-no method}) has Run='$run'; only /bin/bash is checked" ;;
  esac
  bash -n "$script" || fail "inline script $i (${method:-no method}) has a syntax error"
  if grep -nE '(^|[^[:alnum:]_-])(wget|curl)([^[:alnum:]_-]|$)' "$script"; then
    fail "inline script $i (${method:-no method}) downloads something; use a <FILE> with <SHA256> or the package"
  fi
  if [ "$method" = install ]; then
    grep -qx "VERSION=\"$VERSION\"" "$script" || fail "install script does not resolve VERSION=\"$VERSION\""
  fi
  if [ "$HAVE_SHELLCHECK" = 1 ]; then
    shellcheck -s bash -S error "$script" || fail "shellcheck: inline script $i (${method:-no method})"
  fi
done

# Shell scripts shipped in the package and used by CI.
for f in "$ROOT/src/rc.raidman" "$ROOT"/scripts/*.sh; do
  bash -n "$f" || fail "$f has a syntax error"
  if [ "$HAVE_SHELLCHECK" = 1 ]; then
    shellcheck -S error "$f" || fail "shellcheck: $f"
  fi
done

if [ "$HAVE_SHELLCHECK" = 0 ]; then
  echo "check-plg: note: shellcheck not installed; only bash -n was run"
fi
echo "check-plg: $PLG OK (version $VERSION, $NURL download(s), $NINLINE inline script(s))"
