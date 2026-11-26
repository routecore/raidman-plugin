package api

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

// Container ids for the fake /proc.
var (
	ctrID    = strings.Repeat("c", 64)
	otherCtr = strings.Repeat("d", 64)
)

// fakeProc is a /proc tree: each process has stat, environ, cgroup and
// status files. Nothing in it is a real process: pidfds are never opened
// (openPidfd fails) and every test replaces signalProcess.
type fakeProc struct {
	t    *testing.T
	root string
	mu   sync.Mutex
}

func newFakeProc(t *testing.T) *fakeProc {
	t.Helper()
	fp := &fakeProc{t: t, root: t.TempDir()}
	oldRoot, oldSig, oldPidfd, oldRead, oldID := procRoot, signalProcess, openPidfd, readProcFile, containerFullID
	oldPidfdSig, oldPidfdClose := sendPidfdSignal, closePidfd
	oldGrace, oldPoll, oldLate, oldRT, oldCT := execHupGrace, execPollEvery, execLateStart, execReadTimeout, execCleanupTimeout
	t.Cleanup(func() {
		procRoot, signalProcess, openPidfd, readProcFile, containerFullID = oldRoot, oldSig, oldPidfd, oldRead, oldID
		sendPidfdSignal, closePidfd = oldPidfdSig, oldPidfdClose
		execHupGrace, execPollEvery, execLateStart, execReadTimeout, execCleanupTimeout = oldGrace, oldPoll, oldLate, oldRT, oldCT
	})
	procRoot = fp.root
	signalProcess = func(pid int, sig syscall.Signal) error {
		t.Errorf("unexpected signal %v to %d", sig, pid)
		return nil
	}
	openPidfd = func(int) (int, error) { return -1, errors.ErrUnsupported }
	sendPidfdSignal = func(fd int, sig syscall.Signal) error {
		t.Errorf("unexpected signal %v through fd %d", sig, fd)
		return nil
	}
	closePidfd = func(int) {}
	containerFullID = func(context.Context, string) (string, error) { return ctrID, nil }
	execHupGrace, execPollEvery, execLateStart = 300*time.Millisecond, 10*time.Millisecond, 20*time.Millisecond
	execReadTimeout, execCleanupTimeout = 200*time.Millisecond, 10*time.Second
	// Directories that are not processes, as in the real /proc.
	for _, d := range []string{"self", "sys", "net"} {
		os.MkdirAll(filepath.Join(fp.root, d), 0o755)
	}
	return fp
}

// fproc describes one fake process.
type fproc struct {
	pid              int
	comm, state      string
	pgid, sid, tpgid int
	start            string
	ctr              string // container id in its cgroup ("" = host)
	nohup            bool   // ignores SIGHUP
	env              []string
}

func (fp *fakeProc) add(p fproc) {
	fp.mu.Lock()
	defer fp.mu.Unlock()
	dir := filepath.Join(fp.root, fmt.Sprint(p.pid))
	if err := os.MkdirAll(dir, 0o755); err != nil {
		fp.t.Fatal(err)
	}
	if p.state == "" {
		p.state = "S"
	}
	// Fields 3..22 (state ppid pgrp session tty_nr tpgid flags minflt
	// cminflt majflt cmajflt utime stime cutime cstime priority nice
	// threads itrealvalue starttime), then a few more.
	stat := fmt.Sprintf("%d (%s) %s 1 %d %d 34816 %d 4194560 100 0 0 0 1 2 0 0 20 0 1 0 %s 1000 200 0 0",
		p.pid, p.comm, p.state, p.pgid, p.sid, p.tpgid, p.start)
	environ := ""
	if len(p.env) > 0 {
		environ = strings.Join(p.env, "\x00") + "\x00"
	}
	cgroup := "0::/\n"
	if p.ctr != "" {
		cgroup = "0::/docker/" + p.ctr + "\n"
	}
	sigIgn := "0000000000000000"
	if p.nohup {
		sigIgn = "0000000000000001"
	}
	status := "Name:\t" + p.comm + "\nSigQ:\t0/1\nSigPnd:\t0000000000000000\nSigBlk:\t0000000000000000\nSigIgn:\t" + sigIgn + "\nSigCgt:\t0000000000010002\n"
	for name, data := range map[string]string{"stat": stat, "environ": environ, "cgroup": cgroup, "status": status} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(data), 0o644); err != nil {
			fp.t.Fatal(err)
		}
	}
}

func (fp *fakeProc) remove(pid int) {
	fp.mu.Lock()
	defer fp.mu.Unlock()
	os.RemoveAll(filepath.Join(fp.root, fmt.Sprint(pid)))
}

type sent struct {
	pid int
	sig syscall.Signal
}

// recorder replaces signalProcess; onSignal (may be nil) runs for each.
func recorder(onSignal func(pid int, sig syscall.Signal)) (func() (hup, kill []int), func(int, syscall.Signal) error) {
	var mu sync.Mutex
	var got []sent
	return func() (hup, kill []int) {
			mu.Lock()
			defer mu.Unlock()
			hup, kill = []int{}, []int{}
			for _, s := range got {
				switch s.sig {
				case syscall.SIGHUP:
					hup = append(hup, s.pid)
				case syscall.SIGKILL:
					kill = append(kill, s.pid)
				}
			}
			sort.Ints(hup)
			sort.Ints(kill)
			return hup, kill
		}, func(pid int, sig syscall.Signal) error {
			mu.Lock()
			got = append(got, sent{pid, sig})
			mu.Unlock()
			if onSignal != nil {
				onSignal(pid, sig)
			}
			return nil
		}
}

func closedChan() <-chan struct{} {
	c := make(chan struct{})
	close(c)
	return c
}

const testTag = "0123456789abcdef0123456789abcdef"

// TestEndExecSession builds a console session in a container (the shell
// leads its session; a foreground job; background jobs, one nohup'd; jobs
// moved to their own sessions) among decoys, and checks the ssh-like
// semantics: the shell and the foreground group are hung up, what is left
// in the session after the grace period is killed except what ignores
// SIGHUP, and nothing outside the session or the container is touched.
func TestEndExecSession(t *testing.T) {
	fp := newFakeProc(t)
	mark := execTagEnv + "=" + testTag
	path := "PATH=/usr/bin"

	// The session: the shell (500) ignores SIGHUP; the foreground group
	// 510 is running top (exits on SIGHUP) and a nohup'd child.
	fp.add(fproc{pid: 500, comm: "sh", pgid: 500, sid: 500, tpgid: 510, start: "1000", ctr: ctrID, env: []string{path, mark}})
	fp.add(fproc{pid: 510, comm: "top", pgid: 510, sid: 500, tpgid: 510, start: "1010", ctr: ctrID, env: []string{"HOME=/x"}}) // env dropped (su -)
	fp.add(fproc{pid: 511, comm: "nohup fg", pgid: 510, sid: 500, tpgid: 510, start: "1011", ctr: ctrID, nohup: true, env: []string{mark}})
	fp.add(fproc{pid: 501, comm: "sleep", pgid: 501, sid: 500, start: "1001", ctr: ctrID, env: []string{mark}})                    // background job
	fp.add(fproc{pid: 502, comm: "nohup (x) y", pgid: 502, sid: 500, start: "1002", ctr: ctrID, nohup: true, env: []string{mark}}) // nohup &
	fp.add(fproc{pid: 503, comm: "dead", state: "Z", pgid: 500, sid: 500, start: "1003", ctr: ctrID})                              // zombie
	// Left the session: setsid'd (still tagged, a session leader itself,
	// but younger than the shell), and a tmux server.
	fp.add(fproc{pid: 504, comm: "setsid", pgid: 504, sid: 504, start: "1004", ctr: ctrID, env: []string{path, mark}})
	fp.add(fproc{pid: 505, comm: "tmux", pgid: 505, sid: 505, start: "1005", ctr: ctrID, env: []string{mark}})
	fp.add(fproc{pid: 506, comm: "child", pgid: 504, sid: 504, start: "1006", ctr: ctrID})
	// Decoys.
	fp.add(fproc{pid: 1, comm: "init", pgid: 1, sid: 1, start: "1", ctr: ctrID, env: []string{mark}}) // never pid 1
	fp.add(fproc{pid: 600, comm: "docker", pgid: 600, sid: 600, start: "2000", env: []string{path}})  // the CLI: tag only in argv
	fp.add(fproc{pid: 601, comm: "other", pgid: 601, sid: 601, start: "2001", ctr: ctrID, env: []string{mark + "0"}})
	fp.add(fproc{pid: 602, comm: "other", pgid: 602, sid: 602, start: "2002", ctr: ctrID, env: []string{"X_" + mark}})
	fp.add(fproc{pid: 603, comm: "other", pgid: 603, sid: 603, start: "2003", ctr: ctrID, env: []string{execTagEnv + "=ffffffffffffffffffffffffffffffff"}})
	fp.add(fproc{pid: 604, comm: "kthread", pgid: 0, sid: 0, start: "2004"})
	fp.add(fproc{pid: 605, comm: "other ctr", pgid: 605, sid: 605, start: "900", ctr: otherCtr, env: []string{mark}}) // tagged, older, another container
	fp.add(fproc{pid: 607, comm: "other ctr", pgid: 607, sid: 500, start: "2007", ctr: otherCtr})                     // same sid, another container
	fp.add(fproc{pid: 606, comm: "same group", pgid: syscall.Getpgrp(), sid: 500, start: "2006", ctr: ctrID, env: []string{mark}})
	os.WriteFile(filepath.Join(fp.root, "600", "cmdline"), []byte("docker\x00exec\x00-e\x00"+mark+"\x00"), 0o644)

	late := false
	signals, sig := recorder(func(pid int, sig syscall.Signal) {
		if sig == syscall.SIGHUP && pid != 500 && pid != 511 {
			fp.remove(pid) // exits on hang-up
		}
		if !late {
			// A process started in the session after the first scan.
			late = true
			fp.add(fproc{pid: 508, comm: "late", pgid: 500, sid: 500, start: "1008", ctr: ctrID})
		}
		if sig == syscall.SIGHUP && pid == 510 {
			// 510 reused by an unrelated process.
			fp.add(fproc{pid: 510, comm: "reused", pgid: 700, sid: 700, start: "3000", ctr: ctrID})
		}
	})
	signalProcess = sig
	endExecSession("plex", ctrID, testTag, closedChan())

	hup, kill := signals()
	if want := []int{500, 510, 511}; !reflect.DeepEqual(hup, want) {
		t.Errorf("SIGHUP sent to %v, want %v", hup, want)
	}
	// The shell ignored SIGHUP; the background job and the late process
	// were never hung up; the nohup'd processes are left alone.
	if want := []int{500, 501, 508}; !reflect.DeepEqual(kill, want) {
		t.Errorf("SIGKILL sent to %v, want %v", kill, want)
	}
}

// Only the container's processes are read beyond stat and cgroup: environ
// and status of host processes (which may be stuck in D state) are never
// opened.
func TestEndExecSessionReadsOnlyTheContainer(t *testing.T) {
	fp := newFakeProc(t)
	fp.add(fproc{pid: 500, comm: "sh", pgid: 500, sid: 500, start: "1", ctr: ctrID, env: []string{execTagEnv + "=" + testTag}})
	for pid := 600; pid < 620; pid++ {
		fp.add(fproc{pid: pid, comm: "host", pgid: pid, sid: pid, start: "2"})
	}
	var mu sync.Mutex
	var read []string
	readProcFile = func(p string) ([]byte, error) {
		mu.Lock()
		read = append(read, strings.TrimPrefix(p, fp.root))
		mu.Unlock()
		return os.ReadFile(p)
	}
	_, signalProcess = recorder(func(pid int, _ syscall.Signal) { fp.remove(pid) })
	endExecSession("plex", ctrID, testTag, closedChan())
	for _, p := range read {
		if !strings.HasPrefix(p, "/500/") && !strings.HasSuffix(p, "/cgroup") {
			t.Errorf("read %s", p)
		}
	}
}

// A process whose environ cannot be read (stuck) is skipped after
// execReadTimeout; the rest of the session is still ended, in bounded time.
func TestEndExecSessionStuckRead(t *testing.T) {
	fp := newFakeProc(t)
	fp.add(fproc{pid: 400, comm: "stuck", pgid: 400, sid: 400, start: "1", ctr: ctrID})
	fp.add(fproc{pid: 500, comm: "sh", pgid: 500, sid: 500, start: "2", ctr: ctrID, env: []string{execTagEnv + "=" + testTag}})
	block := make(chan struct{})
	t.Cleanup(func() { close(block) })
	readProcFile = func(p string) ([]byte, error) {
		if strings.HasSuffix(p, "/400/environ") {
			<-block
		}
		return os.ReadFile(p)
	}
	signals, sig := recorder(func(pid int, _ syscall.Signal) { fp.remove(pid) })
	signalProcess = sig
	start := time.Now()
	endExecSession("plex", ctrID, testTag, closedChan())
	if d := time.Since(start); d > 3*time.Second {
		t.Errorf("cleanup took %v", d)
	}
	if hup, _ := signals(); !reflect.DeepEqual(hup, []int{500}) {
		t.Errorf("SIGHUP sent to %v, want [500]", hup)
	}
}

// The socket dropped before runc started the shell: nothing is found at
// first, and the shell is found by the rescan after the CLI exited.
func TestEndExecSessionLateShell(t *testing.T) {
	fp := newFakeProc(t)
	cliExited := make(chan struct{})
	go func() {
		time.Sleep(50 * time.Millisecond)
		fp.add(fproc{pid: 500, comm: "sh", pgid: 500, sid: 500, start: "1", ctr: ctrID, env: []string{execTagEnv + "=" + testTag}})
		close(cliExited)
	}()
	signals, sig := recorder(func(pid int, _ syscall.Signal) { fp.remove(pid) })
	signalProcess = sig
	endExecSession("plex", ctrID, testTag, cliExited)
	if hup, _ := signals(); !reflect.DeepEqual(hup, []int{500}) {
		t.Errorf("SIGHUP sent to %v, want [500]", hup)
	}
}

// Nothing tagged: no signal, no grace period.
func TestEndExecSessionNothingLeft(t *testing.T) {
	fp := newFakeProc(t)
	fp.add(fproc{pid: 700, comm: "sh", pgid: 700, sid: 700, start: "1", ctr: ctrID, env: []string{"PATH=/bin"}})
	execHupGrace = time.Minute
	start := time.Now()
	endExecSession("plex", ctrID, testTag, closedChan())
	if time.Since(start) > 5*time.Second {
		t.Error("waited for a session that has no processes")
	}
}

// The container cannot be resolved (or resolves to something that is not a
// full id): nothing is signalled. A full id given at start is used as is.
func TestEndExecSessionNeedsContainerID(t *testing.T) {
	fp := newFakeProc(t)
	fp.add(fproc{pid: 500, comm: "sh", pgid: 500, sid: 500, start: "1", ctr: ctrID, env: []string{execTagEnv + "=" + testTag}})
	for _, resolve := range []func(context.Context, string) (string, error){
		func(context.Context, string) (string, error) { return "", errors.New("no such container") },
		func(context.Context, string) (string, error) { return "", nil }, // would match every cgroup
		func(context.Context, string) (string, error) { return "ccc", nil },
	} {
		containerFullID = resolve
		endExecSession("plex", "", testTag, closedChan())
	}
	// Resolved at the end when unknown at start.
	containerFullID = func(_ context.Context, ref string) (string, error) {
		if ref != "plex" {
			t.Errorf("resolved %q", ref)
		}
		return ctrID, nil
	}
	signals, sig := recorder(func(pid int, _ syscall.Signal) { fp.remove(pid) })
	signalProcess = sig
	endExecSession("plex", "", testTag, closedChan())
	if hup, _ := signals(); !reflect.DeepEqual(hup, []int{500}) {
		t.Errorf("SIGHUP sent to %v, want [500]", hup)
	}
}

// When every process exits on SIGHUP, nothing is killed and the grace
// period is not waited out.
func TestEndExecSessionCleanHangup(t *testing.T) {
	fp := newFakeProc(t)
	fp.add(fproc{pid: 800, comm: "bash", pgid: 800, sid: 800, tpgid: 800, start: "1", ctr: ctrID, env: []string{execTagEnv + "=" + testTag}})
	execHupGrace = time.Minute
	signals, sig := recorder(func(pid int, _ syscall.Signal) { fp.remove(pid) })
	signalProcess = sig
	start := time.Now()
	endExecSession("plex", ctrID, testTag, closedChan())
	if time.Since(start) > 5*time.Second {
		t.Error("waited the full grace period after every process exited")
	}
	if _, kill := signals(); len(kill) != 0 {
		t.Errorf("killed %v", kill)
	}
}

// Only nohup'd processes are left once the shell exits: the grace period is
// not waited out for them, and they are not killed.
func TestEndExecSessionNohupSurvives(t *testing.T) {
	fp := newFakeProc(t)
	fp.add(fproc{pid: 800, comm: "bash", pgid: 800, sid: 800, tpgid: 800, start: "1", ctr: ctrID, env: []string{execTagEnv + "=" + testTag}})
	fp.add(fproc{pid: 801, comm: "job", pgid: 801, sid: 800, tpgid: 800, start: "2", ctr: ctrID, nohup: true})
	execHupGrace = time.Minute
	signals, sig := recorder(func(pid int, _ syscall.Signal) {
		if pid == 800 {
			fp.remove(pid)
		}
	})
	signalProcess = sig
	start := time.Now()
	endExecSession("plex", ctrID, testTag, closedChan())
	if time.Since(start) > 5*time.Second {
		t.Error("waited the grace period for a nohup'd job")
	}
	if hup, kill := signals(); !reflect.DeepEqual(hup, []int{800}) || len(kill) != 0 {
		t.Errorf("SIGHUP %v, SIGKILL %v; want [800], []", hup, kill)
	}
}

// After the cleanup's deadline no signal is sent, even by a scan that
// finishes late.
func TestEndExecSessionDeadline(t *testing.T) {
	fp := newFakeProc(t)
	fp.add(fproc{pid: 500, comm: "sh", pgid: 500, sid: 500, start: "1", ctr: ctrID, env: []string{execTagEnv + "=" + testTag}})
	execCleanupTimeout = 100 * time.Millisecond
	readProcFile = func(p string) ([]byte, error) {
		if strings.HasSuffix(p, "/500/environ") {
			time.Sleep(150 * time.Millisecond) // the scan outlives the deadline
		}
		return os.ReadFile(p)
	}
	execReadTimeout = time.Second
	signals, sig := recorder(nil)
	signalProcess = sig
	endExecSession("plex", ctrID, testTag, closedChan())
	if hup, kill := signals(); len(hup)+len(kill) != 0 {
		t.Errorf("signals after the deadline: SIGHUP %v, SIGKILL %v", hup, kill)
	}
}

// With pidfds (Linux), signals go through the descriptor opened during the
// scan, never by pid; a pid whose start time changed between the scan and
// the open (reused) gets no signal; every descriptor is closed.
func TestEndExecSessionPidfds(t *testing.T) {
	fp := newFakeProc(t)
	mark := execTagEnv + "=" + testTag
	fp.add(fproc{pid: 500, comm: "sh", pgid: 500, sid: 500, tpgid: 510, start: "1", ctr: ctrID, env: []string{mark}})
	fp.add(fproc{pid: 510, comm: "top", pgid: 510, sid: 500, tpgid: 510, start: "2", ctr: ctrID})
	fp.add(fproc{pid: 520, comm: "bg", pgid: 520, sid: 500, start: "3", ctr: ctrID})
	var mu sync.Mutex
	open := map[int]int{} // fd -> pid
	opened, closed := 0, 0
	openPidfd = func(pid int) (int, error) {
		mu.Lock()
		defer mu.Unlock()
		if pid == 520 {
			// Exits and its pid is reused between the scan and the open.
			fp.add(fproc{pid: 520, comm: "reused", pgid: 520, sid: 500, start: "99", ctr: ctrID})
		}
		opened++
		open[1000+opened] = pid
		return 1000 + opened, nil
	}
	closePidfd = func(fd int) {
		mu.Lock()
		defer mu.Unlock()
		if _, ok := open[fd]; !ok {
			t.Errorf("closed fd %d twice or never opened", fd)
		}
		delete(open, fd)
		closed++
	}
	var got []sent
	sendPidfdSignal = func(fd int, sig syscall.Signal) error {
		mu.Lock()
		pid := open[fd]
		got = append(got, sent{pid, sig})
		mu.Unlock()
		if sig == syscall.SIGHUP && pid == 510 {
			fp.remove(510)
		}
		return nil
	}
	endExecSession("plex", ctrID, testTag, closedChan())
	// 500 ignores the hang-up and is killed; 520's first handle was
	// dropped (start time changed), the process now holding the pid is in
	// the session and killed through its own handle.
	want := []sent{{500, syscall.SIGHUP}, {510, syscall.SIGHUP}, {500, syscall.SIGKILL}, {520, syscall.SIGKILL}}
	sort.Slice(got, func(i, j int) bool {
		if got[i].sig != got[j].sig {
			return got[i].sig < got[j].sig
		}
		return got[i].pid < got[j].pid
	})
	if !reflect.DeepEqual(got, want) {
		t.Errorf("signals %v, want %v", got, want)
	}
	if len(open) != 0 || opened != closed {
		t.Errorf("opened %d, closed %d, still open %v", opened, closed, open)
	}
}
