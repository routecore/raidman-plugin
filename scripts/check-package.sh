#!/usr/bin/env bash
#
# Check that a package contains exactly what the raidman.plg install script
# expects: every file in its REQUIRED_FILES line, nothing outside the known
# top-level files and web/novnc/, raidman and rc.raidman 0755, only plain
# files and directories, owner 0:0, and no absolute or ".." paths.
#
# Usage: scripts/check-package.sh <raidman-<version>.tgz> [path/to/raidman.plg]
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
PKG=${1:?usage: scripts/check-package.sh <package.tgz> [raidman.plg]}
PLG=${2:-$ROOT/raidman.plg}

fail() {
  echo "check-package: $*" >&2
  exit 1
}

command -v xmllint >/dev/null 2>&1 || fail "xmllint not found (Debian/Ubuntu: apt-get install libxml2-utils)"
command -v python3 >/dev/null 2>&1 || fail "python3 not found"
INSTALL=$(xmllint --noent --nonet --xpath 'string(//FILE[@Method="install"]/INLINE)' "$PLG")
REQUIRED=$(printf '%s\n' "$INSTALL" | sed -n 's/^REQUIRED_FILES="\([^"]*\)"$/\1/p')
[ -n "$REQUIRED" ] || fail "no REQUIRED_FILES=\"...\" line in the install script of $PLG"

python3 -I - "$PKG" "$REQUIRED" <<'PY'
import sys, tarfile

pkg, required = sys.argv[1], sys.argv[2].split()
top_expected = {".", "icon.png", "raidman", "raidman.conf", "raidman.page", "rc.raidman", "web", "web/novnc"}
executables = {"raidman", "rc.raidman"}
errors = []

with tarfile.open(pkg, "r:gz") as tf:
    members = tf.getmembers()
names = {}
for m in members:
    name = m.name[2:] if m.name.startswith("./") else m.name
    name = name.rstrip("/") or "."
    if m.name.startswith("/") or ".." in name.split("/"):
        errors.append(f"unsafe path {m.name!r}")
    if not (m.isfile() or m.isdir()):
        errors.append(f"{m.name}: only plain files and directories are allowed")
    if m.uid != 0 or m.gid != 0:
        errors.append(f"{m.name}: owner {m.uid}:{m.gid}, want 0:0")
    names[name] = m

for f in required:
    if f not in names or not names[f].isfile():
        errors.append(f"missing {f} (required by the install script)")
for name in sorted(names):
    if name not in top_expected and not name.startswith("web/novnc/"):
        errors.append(f"unexpected entry {name}")
for f in executables:
    if f in names and names[f].mode & 0o777 != 0o755:
        errors.append(f"{f}: mode {names[f].mode & 0o777:o}, want 755")
if "web/novnc/LICENSE.txt" not in names:
    errors.append("noVNC licence (web/novnc/LICENSE.txt) missing")

if errors:
    print("check-package: " + pkg + ":\n  " + "\n  ".join(errors), file=sys.stderr)
    sys.exit(1)
print(f"check-package: {pkg} OK ({len(members)} entries)")
PY
