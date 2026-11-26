package api

import (
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

// fakeProc is a /proc tree: each process has a stat line and an environ.
type fakeProc struct {
	t    *testing.T
	root string
	mu   sync.Mutex
}

func newFakeProc(t *testing.T) *fakeProc {
	t.Helper()
	fp := &fakeProc{t: t, root: t.TempDir()}
	oldRoot, oldSig, oldGrace, oldPoll := procRoot, signalProcess, execHupGrace, execPollEvery
	t.Cleanup(func() { procRoot, signalProcess, execHupGrace, execPollEvery = oldRoot, oldSig, oldGrace, oldPoll })
	procRoot = fp.root
	execHupGrace, execPollEvery = 300*time.Millisecond, 10*time.Millisecond
	// Directories that are not processes, as in the real /proc.
	for _, d := range []string{"self", "sys", "net"} {
		os.MkdirAll(filepath.Join(fp.root, d), 0o755)
	}
	return fp
}

// add creates /proc/<pid> with the given comm, state, process group,
// session, start time and environment entries.
func (fp *fakeProc) add(pid int, comm, state string, pgid, sid int, start string, env ...string) {
	fp.mu.Lock()
	defer fp.mu.Unlock()
	dir := filepath.Join(fp.root, fmt.Sprint(pid))
	if err := os.MkdirAll(dir, 0o755); err != nil {
		fp.t.Fatal(err)
	}
	// Fields 3..22 (state ppid pgrp session tty tpgid flags minflt cminflt
	// majflt cmajflt utime stime cutime cstime priority nice threads
	// itrealvalue starttime), then a few more.
	stat := fmt.Sprintf("%d (%s) %s 1 %d %d 34816 %d 4194560 100 0 0 0 1 2 0 0 20 0 1 0 %s 1000 200 0 0",
		pid, comm, state, pgid, sid, pgid, start)
	environ := ""
	if len(env) > 0 {
		environ = strings.Join(env, "\x00") + "\x00"
	}
	if err := os.WriteFile(filepath.Join(dir, "stat"), []byte(stat), 0o644); err != nil {
		fp.t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "environ"), []byte(environ), 0o644); err != nil {
		fp.t.Fatal(err)
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

// TestEndExecSession builds a container session (tagged shell leading its
// session, a job in its own group, a process that dropped the variable)
// among decoys, and checks that only the session is hung up, and that what
// ignores SIGHUP (or starts late) is killed.
func TestEndExecSession(t *testing.T) {
	fp := newFakeProc(t)
	const tag = "0123456789abcdef0123456789abcdef"
	mark := execTagEnv + "=" + tag
	path := "PATH=/usr/bin"

	// The session (the shell ignores SIGHUP, the others exit on it).
	fp.add(500, "sh", "S", 500, 500, "1000", path, mark)
	fp.add(501, "sleep", "S", 501, 500, "1001", mark, path)   // a job: own group
	fp.add(502, "su (x) y", "S", 501, 500, "1002", "HOME=/x") // env dropped, same session
	fp.add(503, "dead", "Z", 500, 500, "1003")                // zombie: nothing to signal
	fp.add(504, "nohup", "S", 504, 504, "1004", path, mark)   // setsid'd but still tagged
	fp.add(505, "child", "S", 504, 504, "1005", "TERM=xterm") // in the tagged process's session
	// Decoys.
	fp.add(1, "init", "S", 1, 1, "1", mark)                                                     // never pid 1
	fp.add(600, "docker", "S", 600, 600, "2000", path)                                          // the CLI: tag only in argv
	fp.add(601, "other", "S", 601, 601, "2001", mark+"0")                                       // tag + suffix
	fp.add(602, "other", "S", 602, 602, "2002", "X_"+mark)                                      // another variable
	fp.add(603, "other", "S", 603, 603, "2003", execTagEnv+"=ffffffffffffffffffffffffffffffff") // another session
	fp.add(604, "kthread", "S", 0, 0, "2004")                                                   // no environment
	fp.add(605, "other", "S", 605, 1, "2005", path)                                             // session of a tagged pid 1
	fp.add(606, "same group", "S", syscall.Getpgrp(), 500, "2006", mark)                        // the daemon's own group
	os.WriteFile(filepath.Join(fp.root, fmt.Sprint(600), "cmdline"), []byte("docker\x00exec\x00-e\x00"+mark+"\x00"), 0o644)

	var mu sync.Mutex
	var got []sent
	late := false
	signalProcess = func(pid int, sig syscall.Signal) error {
		mu.Lock()
		got = append(got, sent{pid, sig})
		mu.Unlock()
		if sig == syscall.SIGHUP && pid != 500 {
			fp.remove(pid) // exits on hang-up
		}
		if !late {
			// A process started after the first scan, and pid 502 reused
			// by an unrelated process (new start time, no tag).
			late = true
			fp.add(507, "late", "S", 500, 500, "1007", mark)
		}
		if sig == syscall.SIGHUP && pid == 502 {
			fp.add(502, "reused", "S", 700, 700, "3000", path)
		}
		return nil
	}
	endExecSession(tag)

	hup, kill := []int{}, []int{}
	for _, s := range got {
		switch s.sig {
		case syscall.SIGHUP:
			hup = append(hup, s.pid)
		case syscall.SIGKILL:
			kill = append(kill, s.pid)
		default:
			t.Errorf("unexpected signal %v to %d", s.sig, s.pid)
		}
	}
	sort.Ints(hup)
	sort.Ints(kill)
	if want := []int{500, 501, 502, 504, 505}; !reflect.DeepEqual(hup, want) {
		t.Errorf("SIGHUP sent to %v, want %v", hup, want)
	}
	// The shell ignored SIGHUP; the late process was never hung up; the
	// reused pid 502 is left alone.
	if want := []int{500, 507}; !reflect.DeepEqual(kill, want) {
		t.Errorf("SIGKILL sent to %v, want %v", kill, want)
	}
}

// Nothing tagged: no signal, no grace period.
func TestEndExecSessionNothingLeft(t *testing.T) {
	fp := newFakeProc(t)
	fp.add(700, "sh", "S", 700, 700, "1", "PATH=/bin")
	execHupGrace = time.Minute
	signalProcess = func(pid int, sig syscall.Signal) error {
		t.Errorf("signal %v sent to %d", sig, pid)
		return nil
	}
	start := time.Now()
	endExecSession("0123456789abcdef0123456789abcdef")
	if time.Since(start) > 5*time.Second {
		t.Error("waited for a session that has no processes")
	}
}

// When every process exits on SIGHUP, nothing is killed and the grace
// period is not waited out.
func TestEndExecSessionCleanHangup(t *testing.T) {
	fp := newFakeProc(t)
	const tag = "fedcba9876543210fedcba9876543210"
	fp.add(800, "bash", "S", 800, 800, "1", execTagEnv+"="+tag)
	execHupGrace = time.Minute
	signalProcess = func(pid int, sig syscall.Signal) error {
		if sig != syscall.SIGHUP {
			t.Errorf("signal %v sent to %d", sig, pid)
		}
		fp.remove(pid)
		return nil
	}
	start := time.Now()
	endExecSession(tag)
	if time.Since(start) > 5*time.Second {
		t.Error("waited the full grace period after every process exited")
	}
}
