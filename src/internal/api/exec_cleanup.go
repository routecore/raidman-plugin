package api

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// Ending a container console must end what runs inside the container.
// Killing the docker CLI (the PTY's child) does not: dockerd keeps the
// exec'd shell and everything it started running until the container stops.
// So every docker exec session gets a random tag in its environment
// (docker exec -e RAIDMAN_EXEC=<tag>); container processes are host
// processes too, so on session end the plugin finds them through
// /proc/<pid>/environ, hangs them up and kills what is left after a grace
// period.
//
// Only these processes are signalled:
//   - a process whose environment holds the exact entry RAIDMAN_EXEC=<tag>;
//   - a process in a session or process group whose leader holds it (docker
//     exec -t makes the shell a session leader; this reaches what dropped
//     the variable, e.g. su - or env -i, but nothing outside the session).
//
// Never pid 1, the daemon itself or its own process group. Each process is
// identified by pid and start time, so a pid reused during the grace period
// is not signalled.
const execTagEnv = "RAIDMAN_EXEC"

// Overridable in tests.
var (
	procRoot      = "/proc"
	signalProcess = func(pid int, sig syscall.Signal) error { return syscall.Kill(pid, sig) }
	execHupGrace  = 3 * time.Second
	execPollEvery = 100 * time.Millisecond
)

// newExecTag returns a random session tag (128 bits, hex).
func newExecTag() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// procInfo is what the cleanup needs from /proc/<pid>.
type procInfo struct {
	pid, pgid, sid int
	start          string // starttime (field 22), the pid's identity
	zombie         bool
	tagged         bool
}

// readProc reads /proc/<pid>/stat and environ. ok is false when the process
// is gone or unreadable.
func readProc(root string, pid int, entry []byte) (procInfo, bool) {
	dir := filepath.Join(root, strconv.Itoa(pid))
	stat, err := os.ReadFile(filepath.Join(dir, "stat"))
	if err != nil {
		return procInfo{}, false
	}
	// "pid (comm) state ppid pgrp session ...": comm may hold spaces and
	// parentheses, so fields are counted after the last ')'.
	i := bytes.LastIndexByte(stat, ')')
	if i < 0 {
		return procInfo{}, false
	}
	f := strings.Fields(string(stat[i+1:]))
	if len(f) < 20 { // f[0] is field 3 (state), f[19] field 22 (starttime)
		return procInfo{}, false
	}
	pgid, err1 := strconv.Atoi(f[2])
	sid, err2 := strconv.Atoi(f[3])
	if err1 != nil || err2 != nil {
		return procInfo{}, false
	}
	p := procInfo{pid: pid, pgid: pgid, sid: sid, start: f[19], zombie: f[0] == "Z"}
	if env, err := os.ReadFile(filepath.Join(dir, "environ")); err == nil {
		for _, e := range bytes.Split(env, []byte{0}) {
			if bytes.Equal(e, entry) {
				p.tagged = true
				break
			}
		}
	}
	return p, true
}

// execTargets scans root and returns the live processes of the tagged
// session, plus the processes in known (pid -> start time, from an earlier
// scan) that still exist with the same start time.
func execTargets(root, tag string, known map[int]string) map[int]procInfo {
	des, err := os.ReadDir(root)
	if err != nil {
		return nil
	}
	entry := []byte(execTagEnv + "=" + tag)
	self, selfGroup := os.Getpid(), syscall.Getpgrp()
	excluded := func(p procInfo) bool {
		return p.pid <= 1 || p.pid == self || p.pgid == selfGroup || p.zombie
	}
	all := map[int]procInfo{}
	leaders := map[int]bool{} // tagged pids, as session / group ids
	for _, de := range des {
		pid, err := strconv.Atoi(de.Name())
		if err != nil || pid <= 0 {
			continue
		}
		if p, ok := readProc(root, pid, entry); ok {
			all[pid] = p
			if p.tagged && !excluded(p) {
				leaders[pid] = true
			}
		}
	}
	out := map[int]procInfo{}
	for pid, p := range all {
		if excluded(p) {
			continue
		}
		start, seen := known[pid]
		if p.tagged || leaders[p.sid] || leaders[p.pgid] || (seen && start == p.start) {
			out[pid] = p
		}
	}
	return out
}

// endExecSession hangs up the tagged session's processes (see execTagEnv),
// waits up to execHupGrace for them to exit and kills the rest. A rescan
// before the kill also catches a process that started late.
func endExecSession(tag string) {
	targets := execTargets(procRoot, tag, nil)
	if len(targets) == 0 {
		return
	}
	known := make(map[int]string, len(targets))
	for pid, p := range targets {
		known[pid] = p.start
		_ = signalProcess(pid, syscall.SIGHUP)
	}
	deadline := time.Now().Add(execHupGrace)
	for time.Now().Before(deadline) {
		time.Sleep(execPollEvery)
		if targets = execTargets(procRoot, tag, known); len(targets) == 0 {
			return
		}
	}
	for pid := range execTargets(procRoot, tag, known) {
		_ = signalProcess(pid, syscall.SIGKILL)
	}
}
