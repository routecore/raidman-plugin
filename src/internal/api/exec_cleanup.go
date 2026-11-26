package api

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/routecore/raidman-plugin/src/internal/service/docker"
)

// Ending a container console must end the shell it started inside the
// container. Killing the docker CLI (the PTY's child) does not: dockerd keeps
// the exec'd shell running until the container stops. The plugin ends it the
// way a terminal hang-up (ssh) does:
//
//  1. The exec'd shell is found: docker exec -t makes it a session leader,
//     and every session gets a random tag in its environment
//     (docker exec -e RAIDMAN_EXEC=<tag>). Only processes of the container
//     (whose /proc/<pid>/cgroup names the container's full id) are looked
//     at; only their environment is read.
//  2. The shell and the terminal's foreground process group get SIGHUP. The
//     shell passes it on to its jobs (bash does; so would ssh).
//  3. After execHupGrace, what is still in the shell's session is killed,
//     except processes that ignore SIGHUP (nohup). The shell itself is
//     always killed.
//
// So deliberately detached work survives, as it would an ssh disconnect:
// nohup jobs, and anything that left the session (setsid, daemons, the tmux
// or screen server). Interactive programs and plain background jobs end
// with the console.
//
// Never pid 1, the daemon itself or its own process group. Each process is
// identified by pid and start time and, on Linux, signalled through a pidfd
// opened during the scan, so a pid reused meanwhile is not signalled.
const execTagEnv = "RAIDMAN_EXEC"

// Overridable in tests.
var (
	procRoot      = "/proc"
	signalProcess = func(pid int, sig syscall.Signal) error { return syscall.Kill(pid, sig) }
	// openPidfd opens a pidfd (Linux); signals then go through it
	// (sendPidfdSignal) and it is closed with closePidfd.
	openPidfd       = pidfdOpen
	sendPidfdSignal = pidfdSignal
	closePidfd      = pidfdClose
	// readProcFile reads one /proc file. A read can block for good (a
	// process in D state, e.g. on a hung NFS mount, holds its memory map
	// lock, which reading environ needs), so it runs with execReadTimeout.
	readProcFile = os.ReadFile
	// containerFullID resolves a container reference to its full id.
	containerFullID = docker.ContainerFullID

	execHupGrace  = 3 * time.Second
	execPollEvery = 100 * time.Millisecond
	// execLateStart: when the shell is not found (the socket dropped before
	// runc started it), it is looked for once more this long after the
	// docker CLI exited.
	execLateStart = time.Second
	// execReadTimeout bounds one /proc read; execCleanupTimeout the whole
	// cleanup (no signal is sent after it).
	execReadTimeout    = time.Second
	execCleanupTimeout = 30 * time.Second
)

var fullIDRe = regexp.MustCompile(`^[0-9a-f]{64}$`)

// newExecTag returns a random session tag (128 bits, hex).
func newExecTag() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// procInfo is what the cleanup needs from /proc/<pid>/stat.
type procInfo struct {
	pid, pgid, sid int
	tpgid          int    // foreground process group of the terminal
	start          uint64 // starttime (field 22), the pid's identity
	zombie         bool
}

// readStat parses /proc/<pid>/stat. ok is false when the process is gone or
// unreadable.
func readStat(root string, pid int) (procInfo, bool) {
	stat, err := os.ReadFile(filepath.Join(root, strconv.Itoa(pid), "stat"))
	if err != nil {
		return procInfo{}, false
	}
	// "pid (comm) state ppid pgrp session tty_nr tpgid ...": comm may hold
	// spaces and parentheses, so fields are counted after the last ')'.
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
	tpgid, err3 := strconv.Atoi(f[5])
	start, err4 := strconv.ParseUint(f[19], 10, 64)
	if err1 != nil || err2 != nil || err3 != nil || err4 != nil {
		return procInfo{}, false
	}
	return procInfo{pid: pid, pgid: pgid, sid: sid, tpgid: tpgid, start: start, zombie: f[0] == "Z"}, true
}

// execSession is one cleanup run.
type execSession struct {
	root     string
	id       []byte // the container's full id
	entry    []byte // RAIDMAN_EXEC=<tag>
	deadline time.Time
	stuck    map[int]bool        // pids whose /proc read timed out
	handles  map[int]*procHandle // opened during scans, by pid
}

// procHandle is a process found by a scan: its identity and, when one could
// be opened, a pidfd.
type procHandle struct {
	procInfo
	fd int // -1 without a pidfd
}

// readTimeout reads a /proc file of pid with execReadTimeout. A read that
// does not finish is abandoned (its goroutine ends when the read does) and
// the pid is not read again in this cleanup.
func (s *execSession) readTimeout(pid int, name string) ([]byte, bool) {
	if s.stuck[pid] {
		return nil, false
	}
	type result struct {
		b   []byte
		err error
	}
	ch := make(chan result, 1)
	path := filepath.Join(s.root, strconv.Itoa(pid), name)
	go func() {
		b, err := readProcFile(path)
		ch <- result{b, err}
	}()
	select {
	case r := <-ch:
		return r.b, r.err == nil
	case <-time.After(execReadTimeout):
		s.stuck[pid] = true
		return nil, false
	}
}

// inContainer reports whether pid's cgroup is the container's (or below it).
// Unlike environ, reading it does not touch the process's memory.
func (s *execSession) inContainer(pid int) bool {
	b, err := readProcFile(filepath.Join(s.root, strconv.Itoa(pid), "cgroup"))
	return err == nil && bytes.Contains(b, s.id)
}

// tagged reports whether pid's environment holds the exact session tag.
func (s *execSession) tagged(pid int) bool {
	env, ok := s.readTimeout(pid, "environ")
	if !ok {
		return false
	}
	for _, e := range bytes.Split(env, []byte{0}) {
		if bytes.Equal(e, s.entry) {
			return true
		}
	}
	return false
}

// ignoresHup reports whether pid ignores SIGHUP (SigIgn in status), as a
// nohup'd process does.
func (s *execSession) ignoresHup(pid int) bool {
	b, ok := s.readTimeout(pid, "status")
	if !ok {
		return false
	}
	for _, line := range strings.Split(string(b), "\n") {
		if v, found := strings.CutPrefix(line, "SigIgn:"); found {
			mask, err := strconv.ParseUint(strings.TrimSpace(v), 16, 64)
			return err == nil && mask&(1<<(uint(syscall.SIGHUP)-1)) != 0
		}
	}
	return false
}

// scan returns the container's live processes (stat first, then cgroup:
// nothing else is read from other processes).
func (s *execSession) scan() []procInfo {
	des, err := os.ReadDir(s.root)
	if err != nil {
		return nil
	}
	self, selfGroup := os.Getpid(), syscall.Getpgrp()
	var out []procInfo
	for _, de := range des {
		pid, err := strconv.Atoi(de.Name())
		if err != nil || pid <= 1 || pid == self {
			continue
		}
		p, ok := readStat(s.root, pid)
		if !ok || p.zombie || p.pgid == selfGroup || !s.inContainer(pid) {
			continue
		}
		out = append(out, p)
	}
	return out
}

// findShell returns the exec'd shell: the oldest session leader of the
// container that carries the tag (everything else carrying it descends
// from the shell, e.g. a job moved to its own session with setsid).
func (s *execSession) findShell() (procInfo, bool) {
	var shell procInfo
	found := false
	for _, p := range s.scan() {
		if p.pid != p.sid || (found && p.start >= shell.start) || !s.tagged(p.pid) {
			continue
		}
		shell, found = p, true
	}
	return shell, found
}

// handle returns a handle for p, reusing the one opened for the same
// process by an earlier scan. With a pidfd, p is checked again after the
// open (same start time, still the container's), so the pidfd is known to
// refer to the process that was scanned. nil when p is gone.
func (s *execSession) handle(p procInfo) *procHandle {
	if h := s.handles[p.pid]; h != nil {
		if h.start == p.start {
			h.procInfo = p
			return h
		}
		h.close()
		delete(s.handles, p.pid)
	}
	h := &procHandle{procInfo: p, fd: -1}
	fd, err := openPidfd(p.pid)
	switch {
	case err == nil:
		h.fd = fd
		again, ok := readStat(s.root, p.pid)
		if !ok || again.start != p.start || !s.inContainer(p.pid) {
			h.close()
			return nil
		}
	case errors.Is(err, syscall.ESRCH):
		return nil
	}
	// Without pidfds (ENOSYS, other systems) signals go by pid.
	s.handles[p.pid] = h
	return h
}

func (h *procHandle) close() {
	if h.fd >= 0 {
		closePidfd(h.fd)
		h.fd = -1
	}
}

// signal sends sig unless the cleanup's deadline has passed.
func (s *execSession) signal(h *procHandle, sig syscall.Signal) {
	if !time.Now().Before(s.deadline) {
		return
	}
	if h.fd >= 0 {
		_ = sendPidfdSignal(h.fd, sig)
		return
	}
	_ = signalProcess(h.pid, sig)
}

// members returns handles for the live processes of the session sid.
func (s *execSession) members(sid int) []*procHandle {
	var out []*procHandle
	for _, p := range s.scan() {
		if p.sid != sid {
			continue
		}
		if h := s.handle(p); h != nil {
			out = append(out, h)
		}
	}
	return out
}

// endExecSession ends the console session tagged tag in container ref
// (fullID when it was resolved at start, else resolved now; nothing is
// signalled when it cannot be). It runs on its own goroutine, alongside the
// docker CLI's termination; cliExited is closed once the CLI has exited.
func endExecSession(ref, fullID, tag string, cliExited <-chan struct{}) {
	deadline := time.Now().Add(execCleanupTimeout)
	if !fullIDRe.MatchString(fullID) {
		ctx, cancel := context.WithDeadline(context.Background(), deadline)
		id, err := containerFullID(ctx, ref)
		cancel()
		if err != nil || !fullIDRe.MatchString(id) {
			return
		}
		fullID = id
	}
	s := &execSession{
		root:     procRoot,
		id:       []byte(fullID),
		entry:    []byte(execTagEnv + "=" + tag),
		deadline: deadline,
		stuck:    map[int]bool{},
		handles:  map[int]*procHandle{},
	}
	defer func() {
		for _, h := range s.handles {
			h.close()
		}
	}()

	shell, ok := s.findShell()
	if !ok {
		// The socket may have dropped before runc started the shell: look
		// once more after the CLI has exited.
		select {
		case <-cliExited:
		case <-time.After(time.Until(deadline)):
			return
		}
		time.Sleep(execLateStart)
		if shell, ok = s.findShell(); !ok {
			return
		}
	}

	// Hang up, as the kernel does on a terminal hang-up: the session leader
	// and the terminal's foreground process group.
	isShell := func(h *procHandle) bool { return h.pid == shell.pid && h.start == shell.start }
	for _, h := range s.members(shell.sid) {
		if isShell(h) || (shell.tpgid > 0 && h.pgid == shell.tpgid) {
			s.signal(h, syscall.SIGHUP)
		}
	}

	// Kill what is left in the session after the grace period, but not
	// what ignores SIGHUP (nohup); the shell itself always.
	graceEnd := time.Now().Add(execHupGrace)
	for {
		var left []*procHandle
		for _, h := range s.members(shell.sid) {
			if isShell(h) || !s.ignoresHup(h.pid) {
				left = append(left, h)
			}
		}
		if len(left) == 0 || !time.Now().Before(s.deadline) {
			return
		}
		if !time.Now().Before(graceEnd) {
			for _, h := range left {
				s.signal(h, syscall.SIGKILL)
			}
			return
		}
		time.Sleep(execPollEvery)
	}
}
