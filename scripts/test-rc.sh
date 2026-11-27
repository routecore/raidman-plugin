#!/usr/bin/env bash
#
# Exercise src/rc.raidman (Linux only; needs /proc, setsid and flock) with a
# real daemon binary in a scratch directory:
#   start reports success only when our pid listens; cwd is / and HOME=/root;
#   a second start or a second supervisor never double-starts;
#   kill -9 of the daemon is restarted by the supervisor;
#   stop ends supervisor and daemon and nothing respawns;
#   a clean daemon exit (SIGTERM) is not restarted;
#   start does not claim success when another process owns the port.
#
# Usage: scripts/test-rc.sh <linux raidman binary>
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
SRC_BIN=${1:?usage: scripts/test-rc.sh <raidman binary>}
[ "$(uname -s)" = Linux ] || { echo "test-rc: Linux only" >&2; exit 1; }

T=$(mktemp -d)
mkdir -p "$T/bin" "$T/run" "$T/cwd"
install -m 0755 "$SRC_BIN" "$T/bin/raidman" # comm must be "raidman"
install -m 0755 "$ROOT/src/rc.raidman" "$T/rc.raidman" # git may store it without +x
RC="$T/rc.raidman"
export RAIDMAN_BIN="$T/bin/raidman" RAIDMAN_RUN_DIR="$T/run" RAIDMAN_LOG="$T/raidman.log" RAIDMAN_BACKOFF_MIN=1
RAIDMAN_PORT=$((20000 + RANDOM % 20000))
export RAIDMAN_PORT
FOREIGN=0

cleanup() {
  "$RC" stop >/dev/null 2>&1 || true
  [ "$FOREIGN" -gt 0 ] && kill "$FOREIGN" 2>/dev/null
  rm -rf "$T"
}
trap cleanup EXIT

fail() {
  echo "test-rc: FAIL: $*" >&2
  echo "--- log ---" >&2
  tail -n 40 "$RAIDMAN_LOG" >&2 || true
  exit 1
}

daemon_pid() { cat "$T/run/raidman.pid" 2>/dev/null; }
supervisors() { pgrep -fc "rc.raidman supervise" || true; }
alive() { [ -n "$1" ] && kill -0 "$1" 2>/dev/null; }
gone() { ! kill -0 "$1" 2>/dev/null; }
no_supervisor() { [ "$(supervisors)" = 0 ]; }
port_open() { (exec 3<>"/dev/tcp/127.0.0.1/$RAIDMAN_PORT") 2>/dev/null; }

wait_for() { # wait_for <seconds> <command...>
  local n=$(($1 * 4))
  shift
  while [ "$n" -gt 0 ]; do
    "$@" && return 0
    sleep 0.25
    n=$((n - 1))
  done
  return 1
}

cd "$T/cwd"

echo "test-rc: start"
out=$("$RC" start) || fail "start returned non-zero: $out"
[[ $out == "RaidMan started (pid "* ]] || fail "unexpected start output: $out"
pid=$(daemon_pid)
alive "$pid" || fail "daemon not running after start"
[ "$(readlink "/proc/$pid/cwd")" = / ] || fail "daemon cwd is $(readlink "/proc/$pid/cwd"), want /"
tr '\0' '\n' <"/proc/$pid/environ" | grep -qx 'HOME=/root' || fail "daemon HOME is not /root"
[ "$(supervisors)" = 1 ] || fail "expected one supervisor, found $(supervisors)"

echo "test-rc: double start"
out=$("$RC" start) || fail "second start returned non-zero"
[[ $out == *"already running"* ]] || fail "second start: $out"
"$RC" supervise </dev/null >>"$RAIDMAN_LOG" 2>&1 &
extra=$!
wait_for 5 gone "$extra" || fail "a second supervisor did not exit"
[ "$(daemon_pid)" = "$pid" ] || fail "daemon pid changed after a second supervisor"
[ "$(supervisors)" = 1 ] || fail "expected one supervisor, found $(supervisors)"

echo "test-rc: crash restart"
kill -KILL "$pid"
restarted() {
  local p
  p=$(daemon_pid)
  [ -n "$p" ] && [ "$p" != "$pid" ] && alive "$p" && "$RC" status >/dev/null
}
wait_for 15 restarted || fail "daemon was not restarted after kill -9"
grep -q '\[SUPERVISOR\] RaidMan exited with status' "$RAIDMAN_LOG" || fail "restart not logged"
pid=$(daemon_pid)

echo "test-rc: stop"
"$RC" stop >/dev/null
alive "$pid" && fail "daemon still running after stop"
[ "$(supervisors)" = 0 ] || fail "supervisor still running after stop"
sleep 3
[ -z "$(pgrep -x raidman || true)" ] || fail "daemon respawned after stop"
if "$RC" status >/dev/null; then fail "status reports running after stop"; fi

echo "test-rc: clean exit is not restarted"
"$RC" start >/dev/null || fail "start after stop failed"
pid=$(daemon_pid)
kill -TERM "$pid"
wait_for 10 gone "$pid" || fail "daemon ignored SIGTERM"
wait_for 5 no_supervisor || fail "supervisor kept running after a clean exit"
sleep 2
[ -z "$(pgrep -x raidman || true)" ] || fail "daemon restarted after a clean exit"

echo "test-rc: port owned by another process"
python3 -c 'import socket,sys,time
s=socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("127.0.0.1", int(sys.argv[1]))); s.listen(); time.sleep(120)' "$RAIDMAN_PORT" &
FOREIGN=$!
wait_for 5 port_open || fail "foreign listener did not start"
if out=$("$RC" start); then fail "start claimed success while another process owns the port: $out"; fi
[[ $out != "RaidMan started (pid "* ]] || fail "start printed success: $out"
"$RC" stop >/dev/null

echo "test-rc: OK"
