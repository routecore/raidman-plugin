#!/usr/bin/env bash
#
# Build the release binary exactly as the release job does (linux/amd64,
# static, version stamped through -ldflags) and smoke-test it with -version
# when the host can run it.
#
# Usage: scripts/build.sh <version> [output]   (output defaults to ./raidman)
# In CI (CI=true) the smoke test is mandatory.
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
VERSION=${1:?usage: scripts/build.sh <version> [output]}
OUT=${2:-$ROOT/raidman}
[[ $VERSION =~ ^[A-Za-z0-9._-]+$ ]] || { echo "build: invalid version '$VERSION'" >&2; exit 1; }

mkdir -p "$(dirname "$OUT")"
# -buildvcs=false: the binary must not depend on the state of the work tree
# (the release job edits raidman.plg before and after building).
(cd "$ROOT" && CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
  go build -trimpath -buildvcs=false -ldflags "-s -w -X main.Version=${VERSION}" -o "$OUT" ./src/cmd/app)

if [ "$(go env GOHOSTOS)/$(go env GOHOSTARCH)" = linux/amd64 ]; then
  got=$("$OUT" -version)
  if [ "$got" != "$VERSION" ]; then
    echo "build: $OUT -version printed '$got', expected '$VERSION' (is main.Version still the -X target?)" >&2
    exit 1
  fi
  echo "build: $OUT OK (version $got)"
elif [ "${CI:-}" = true ]; then
  echo "build: CI must run on linux/amd64 to smoke-test the release binary" >&2
  exit 1
else
  echo "build: $OUT built (not linux/amd64: -version smoke test skipped)"
fi
