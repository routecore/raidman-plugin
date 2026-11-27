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
	"sync"
	"syscall"
	"time"

	"github.com/routecore/raidman-plugin/src/internal/service/docker"
)

// Ending a container console must end the shell it started inside the
// container. Killing the docker CLI (the PTY's child) does not: dockerd keeps
// the exec'd shell running until the container stops. The plugin ends it the
// way a terminal hang-up (ssh) does:
//
//  1. While the console is open, the exec'd shell is identified (execWatch)
//     and recorded by pid and start time. Every session gets a random tag in
//     its environment (docker exec -e RAIDMAN_EXEC=<tag>), and docker exec -t
//     makes the shell a session leader with the console's terminal as its
//     controlling terminal and the container runtime (outside the container)
//     as its parent. Exactly one live process of the container must match
//     all of that: tagged, session leader, a controlling terminal, a parent
//     that is not a process of the container. What the shell starts in a
//     new session (setsid, a tmux/screen server and its panes, a daemon) has
//     a parent inside the container or no terminal, so it never matches.
//     Only processes of the container (whose /proc/<pid>/cgroup names the
//     container's full id) are looked at; only their environment is read.
//  2. At the end, only the recorded shell's session is acted on. If the
//     shell is still running, it and the terminal's foreground process
//     group get SIGHUP (the shell passes it on to its jobs, as bash does on
//     an ssh hang-up). If it already exited (the user typed exit), the
//     processes left in its session get SIGHUP.
//  3. After execHupGrace, what is still in that session is killed, except
//     processes that ignore SIGHUP (nohup) or whose status cannot be read.
//     The shell itself is always killed.
//
// So deliberately detached work survives, as it would an ssh disconnect:
// nohup jobs, and anything that left the session (setsid, daemons, the tmux
// or screen server). Interactive programs and plain background jobs end with
// the console. Another session is never taken for the shell: when the shell
// was not recorded (the socket dropped before runc started it), the
// container is looked at once at the end and once after the CLI exited,
// with the same rule; when nothing or more than one process matches,
// nothing is signalled.
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
	// lock, which reading environ needs), so it runs with execReadTimeout
	// (see readTimeout).
	readProcFile = os.ReadFile
	// containerFullID resolves a container reference to its full id.
	containerFullID = docker.ContainerFullID

	execHupGrace  = 3 * time.Second
	execPollEvery = 100 * time.Millisecond
	// execLateStart: when the shell was not recorded, it is looked for once
	// more this long after the docker CLI exited.
	execLateStart = time.Second
	// execReadTimeout bounds one /proc read; execCleanupTimeout the whole
	// cleanup (no signal is sent after it).
	execReadTimeout    = time.Second
	execCleanupTimeout = 30 * time.Second
	// The watch scans the container every execWatchPoll at first, doubling
	// up to execWatchMaxPoll, for at most execWatchFor (a scan reads the
	// stat and cgroup of every process of the host).
	execWatchPoll    = 50 * time.Millisecond
	execWatchMaxPoll = 2 * time.Second
	execWatchFor     = 2 * time.Minute
	// maxProcReads caps the /proc reads in flight, process-wide (see
	// readTimeout).
	maxProcReads = 32
	// procReads is the process-wide state of /proc reads.
	procReads = newProcReadState()
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
	pid, ppid, pgid, sid int
	tty                  int    // controlling terminal (tty_nr), 0 for none
	tpgid                int    // foreground process group of the terminal
	start                uint64 // starttime (field 22), the pid's identity
	zombie               bool
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
	ppid, err0 := strconv.Atoi(f[1])
	pgid, err1 := strconv.Atoi(f[2])
	sid, err2 := strconv.Atoi(f[3])
	tty, err3 := strconv.Atoi(f[4])
	tpgid, err4 := strconv.Atoi(f[5])
	start, err5 := strconv.ParseUint(f[19], 10, 64)
	if err := errors.Join(err0, err1, err2, err3, err4, err5); err != nil {
		return procInfo{}, false
	}
	return procInfo{pid: pid, ppid: ppid, pgid: pgid, sid: sid, tty: tty, tpgid: tpgid, start: start, zombie: f[0] == "Z"}, true
}

// procKey identifies a process: a pid with its start time.
type procKey struct {
	pid   int
	start uint64
}

// procReadState is the process-wide bookkeeping of /proc reads (see
// readTimeout): how many are in flight, and which processes have a read
// that timed out and has not returned yet.
type procReadState struct {
	mu       sync.Mutex
	inFlight int
	stuck    map[procKey]int
}

func newProcReadState() *procReadState { return &procReadState{stuck: map[procKey]int{}} }

// execSession is one scan context: a watch or a cleanup run.
type execSession struct {
	root     string
	id       []byte // the container's full id
	entry    []byte // RAIDMAN_EXEC=<tag>
	deadline time.Time
	abort    <-chan struct{}     // ends waits early (nil: never)
	handles  map[int]*procHandle // opened during scans, by pid
}

func newExecSession(fullID, tag string, deadline time.Time, abort <-chan struct{}) *execSession {
	return &execSession{
		root:     procRoot,
		id:       []byte(fullID),
		entry:    []byte(execTagEnv + "=" + tag),
		deadline: deadline,
		abort:    abort,
		handles:  map[int]*procHandle{},
	}
}

func (s *execSession) aborted() bool {
	select {
	case <-s.abort:
		return true
	default:
		return false
	}
}

// procHandle is a process found by a scan: its identity and, when one could
// be opened, a pidfd.
type procHandle struct {
	procInfo
	fd int // -1 without a pidfd
}

// readTimeout reads a /proc file of p, waiting at most execReadTimeout. A
// read that does not finish is abandoned; its goroutine (and the thread
// blocked in the read) ends when the read does. The bookkeeping is
// process-wide (procReads), so a stuck process costs one goroutine, not one
// per cleanup: while a read of p that timed out is still blocked, p is not
// read again by any session, and no read starts while maxProcReads reads
// are in flight. A read that is skipped reports ok false.
func (s *execSession) readTimeout(p procInfo, name string) ([]byte, bool) {
	st := procReads
	k := procKey{p.pid, p.start}
	st.mu.Lock()
	if st.stuck[k] > 0 || st.inFlight >= maxProcReads {
		st.mu.Unlock()
		return nil, false
	}
	st.inFlight++
	st.mu.Unlock()

	type result struct {
		b   []byte
		err error
	}
	// done and timedOut are guarded by st.mu; the result is sent under it,
	// so the waiter below either finds it or marks the read stuck before
	// the reader looks.
	var done, timedOut bool
	ch := make(chan result, 1)
	path := filepath.Join(s.root, strconv.Itoa(p.pid), name)
	read := readProcFile
	go func() {
		b, err := read(path)
		st.mu.Lock()
		defer st.mu.Unlock()
		st.inFlight--
		done = true
		if timedOut {
			if st.stuck[k]--; st.stuck[k] <= 0 {
				delete(st.stuck, k)
			}
		}
		ch <- result{b, err}
	}()
	timer := time.NewTimer(execReadTimeout)
	defer timer.Stop()
	var expired bool
	select {
	case r := <-ch:
		return r.b, r.err == nil
	case <-timer.C:
		expired = true
	case <-s.abort:
	}
	st.mu.Lock()
	defer st.mu.Unlock()
	if done {
		r := <-ch
		return r.b, r.err == nil
	}
	if expired {
		timedOut = true
		st.stuck[k]++
	}
	return nil, false
}

// inContainer reports whether pid's cgroup is the container's (or below it).
// Unlike environ, reading it does not touch the process's memory.
func (s *execSession) inContainer(pid int) bool {
	if pid <= 0 {
		return false
	}
	b, err := readProcFile(filepath.Join(s.root, strconv.Itoa(pid), "cgroup"))
	return err == nil && bytes.Contains(b, s.id)
}

// tagged reports whether p's environment holds the exact session tag.
func (s *execSession) tagged(p procInfo) bool {
	env, ok := s.readTimeout(p, "environ")
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

// ignoresHup reports whether p ignores SIGHUP (SigIgn in status), as a
// nohup'd process does. ok is false when its status could not be read.
func (s *execSession) ignoresHup(p procInfo) (ignores, ok bool) {
	b, ok := s.readTimeout(p, "status")
	if !ok {
		return false, false
	}
	for _, line := range strings.Split(string(b), "\n") {
		if v, found := strings.CutPrefix(line, "SigIgn:"); found {
			mask, err := strconv.ParseUint(strings.TrimSpace(v), 16, 64)
			if err != nil {
				return false, false
			}
			return mask&(1<<(uint(syscall.SIGHUP)-1)) != 0, true
		}
	}
	return false, false
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
		if s.aborted() {
			return nil
		}
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

// findShell returns the exec'd shell: the one live process of the container
// that is a session leader with a controlling terminal, whose parent is not
// a process of the container (it is the container runtime) and that carries
// the tag. ok is false when none, or more than one, matches. The environ of
// a process is read last, only for candidates.
func (s *execSession) findShell() (procInfo, bool) {
	var shell procInfo
	n := 0
	for _, p := range s.scan() {
		if p.pid != p.sid || p.tty == 0 || s.inContainer(p.ppid) || !s.tagged(p) {
			continue
		}
		shell = p
		n++
	}
	return shell, n == 1
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

func (s *execSession) closeHandles() {
	for _, h := range s.handles {
		h.close()
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

// execWatch follows one container console: started once the docker CLI
// runs, it records the exec'd shell (see findShell) as soon as it appears,
// so that the end of the console acts on that session only, even when the
// shell has already exited by then.
type execWatch struct {
	ref, fullID, tag string
	stop, done       chan struct{}
	started          bool // set before the end runs (same goroutine)
	// Written by run before done is closed.
	shell procInfo
	found bool
}

// newExecWatch returns the watch for the session tagged tag in container ref
// (fullID when already resolved). Nothing runs until start.
func newExecWatch(ref, fullID, tag string) *execWatch {
	return &execWatch{ref: ref, fullID: fullID, tag: tag, stop: make(chan struct{}), done: make(chan struct{})}
}

// start starts watching for the shell, in the background, until it is
// found, end is called or execWatchFor has passed.
func (w *execWatch) start() {
	w.started = true
	go w.run()
}

func (w *execWatch) run() {
	defer close(w.done)
	until := time.Now().Add(execWatchFor)
	wait := execWatchPoll
	for {
		t := time.NewTimer(wait)
		select {
		case <-w.stop:
			t.Stop()
			return
		case <-t.C:
		}
		if !time.Now().Before(until) {
			return
		}
		wait = min(2*wait, execWatchMaxPoll)
		if !fullIDRe.MatchString(w.fullID) {
			// Never scan without the full id: an empty one would match
			// every process of the host.
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			id, err := containerFullID(ctx, w.ref)
			cancel()
			if err != nil || !fullIDRe.MatchString(id) {
				continue
			}
			w.fullID = id
		}
		s := newExecSession(w.fullID, w.tag, until, w.stop)
		if shell, ok := s.findShell(); ok {
			w.shell, w.found = shell, true
			return
		}
	}
}

// end ends the console session: it stops the watch and hangs up the
// recorded shell's session (see the top of this file). It runs on its own
// goroutine, alongside the docker CLI's termination; cliExited is closed
// once the CLI has exited. Nothing is signalled when the container cannot
// be resolved to its full id.
func (w *execWatch) end(cliExited <-chan struct{}) {
	deadline := time.Now().Add(execCleanupTimeout)
	if w.started {
		close(w.stop)
		<-w.done
	}
	fullID := w.fullID
	if !fullIDRe.MatchString(fullID) {
		ctx, cancel := context.WithDeadline(context.Background(), deadline)
		id, err := containerFullID(ctx, w.ref)
		cancel()
		if err != nil || !fullIDRe.MatchString(id) {
			return
		}
		fullID = id
	}
	s := newExecSession(fullID, w.tag, deadline, nil)
	defer s.closeHandles()

	shell, ok := w.shell, w.found
	if !ok {
		// Not recorded: the socket may have dropped before runc started
		// the shell. Look now, and once more after the CLI has exited.
		if shell, ok = s.findShell(); !ok {
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
	}
	s.hangUp(shell)
}

// hangUp ends the session led by shell, as the kernel does on a terminal
// hang-up: SIGHUP to the shell and the terminal's foreground process group,
// or, when the shell has exited, to what is left in its session; after
// execHupGrace SIGKILL to the shell and to the members that do not ignore
// SIGHUP. Only members of that session are ever signalled.
func (s *execSession) hangUp(shell procInfo) {
	sid := shell.pid
	cur, ok := readStat(s.root, shell.pid)
	if ok && cur.start != shell.start {
		// The pid was reused: the kernel frees a pid only once no
		// process is left in the session it led, so there is nothing
		// left to end (and sid is someone else's now).
		return
	}
	alive := ok && !cur.zombie
	isShell := func(h *procHandle) bool { return alive && h.pid == shell.pid && h.start == shell.start }
	for _, h := range s.members(sid) {
		// Without the shell the session has lost its terminal, so there
		// is no foreground group: every member is hung up.
		if !alive || isShell(h) || (cur.tpgid > 0 && h.pgid == cur.tpgid) {
			s.signal(h, syscall.SIGHUP)
		}
	}

	// Kill what is left in the session after the grace period, but not
	// what ignores SIGHUP (nohup) or cannot be checked; the shell always.
	graceEnd := time.Now().Add(execHupGrace)
	for {
		var left []*procHandle
		for _, h := range s.members(sid) {
			if isShell(h) {
				left = append(left, h)
			} else if ign, ok := s.ignoresHup(h.procInfo); ok && !ign {
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
