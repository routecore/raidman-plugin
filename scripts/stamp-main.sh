#!/usr/bin/env bash
#
# Release job only: commit the released version and package SHA-256 into
# raidman.plg on main (installed servers poll that file for updates).
#
# Only main's own raidman.plg is edited (two lines), so later edits on main
# are kept. Refuses unless the tagged commit is an ancestor of main or main
# differs from it only in raidman.plg. Never stamps an older version over a
# newer one. Retries on push races.
#
# Usage: GH_TOKEN=... scripts/stamp-main.sh <version> <sha256> <tagged-commit>
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
VERSION=${1:?usage: scripts/stamp-main.sh <version> <sha256> <tagged-commit>}
SHA256=${2:?usage: scripts/stamp-main.sh <version> <sha256> <tagged-commit>}
TAG_COMMIT=${3:?usage: scripts/stamp-main.sh <version> <sha256> <tagged-commit>}
[[ $VERSION =~ ^[0-9]{4}\.[0-9]{2}\.[0-9]{2}[a-z]?$ ]] || { echo "stamp-main: invalid version" >&2; exit 1; }
[[ $SHA256 =~ ^[0-9a-f]{64}$ ]] || { echo "stamp-main: invalid sha256" >&2; exit 1; }
[[ $TAG_COMMIT =~ ^[0-9a-f]{40}$ ]] || { echo "stamp-main: invalid commit" >&2; exit 1; }

git_auth=()
if [ -n "${GH_TOKEN:-}" ]; then
  basic=$(printf 'x-access-token:%s' "$GH_TOKEN" | base64 | tr -d '\n')
  git_auth=(-c "http.https://github.com/.extraheader=AUTHORIZATION: basic $basic")
fi

WT=$(mktemp -d)/main
cleanup() {
  git -C "$ROOT" worktree remove --force "$WT" >/dev/null 2>&1 || true
}
trap cleanup EXIT

plg_version() {
  sed -n 's/^<!ENTITY version *"\([^"]*\)">$/\1/p' "$1"
}

git -C "$ROOT" fetch --quiet --no-tags origin +refs/heads/main:refs/remotes/origin/main
git -C "$ROOT" worktree add --quiet --detach "$WT" origin/main

for attempt in 1 2 3 4 5; do
  if [ "$attempt" -gt 1 ]; then
    sleep $((attempt * 5))
    git -C "$ROOT" fetch --quiet --no-tags origin +refs/heads/main:refs/remotes/origin/main
  fi
  git -C "$WT" checkout --quiet --force --detach origin/main

  if ! git -C "$WT" merge-base --is-ancestor "$TAG_COMMIT" HEAD &&
    ! git -C "$WT" diff --quiet "$TAG_COMMIT" HEAD -- . ':(exclude)raidman.plg'; then
    echo "stamp-main: $TAG_COMMIT is not on main and main differs from it outside raidman.plg; not stamping." >&2
    exit 1
  fi

  MAIN_VERSION=$(plg_version "$WT/raidman.plg")
  if [ "$MAIN_VERSION" != "$VERSION" ] &&
    [ "$(printf '%s\n%s\n' "$MAIN_VERSION" "$VERSION" | sort -V | tail -n 1)" = "$MAIN_VERSION" ]; then
    echo "stamp-main: main already carries the newer version $MAIN_VERSION; leaving it."
    exit 0
  fi

  bash "$ROOT/scripts/stamp-plg.sh" "$WT/raidman.plg" "$VERSION" "$SHA256"
  bash "$ROOT/scripts/check-plg.sh" "$WT/raidman.plg"
  if git -C "$WT" diff --quiet; then
    echo "stamp-main: main's raidman.plg already carries $VERSION / $SHA256."
    exit 0
  fi
  git -C "$WT" -c user.name="github-actions[bot]" \
    -c user.email="41898282+github-actions[bot]@users.noreply.github.com" \
    commit --quiet -m "chore(release): raidman.plg $VERSION" \
    -m "Package SHA-256: $SHA256" -- raidman.plg
  if git -C "$WT" ${git_auth[@]+"${git_auth[@]}"} push --quiet origin HEAD:refs/heads/main; then
    echo "stamp-main: pushed $(git -C "$WT" rev-parse HEAD) to main."
    exit 0
  fi
  echo "stamp-main: push attempt $attempt failed; retrying." >&2
done
echo "stamp-main: could not push to main; re-run the release job (it reuses the published package)." >&2
exit 1
