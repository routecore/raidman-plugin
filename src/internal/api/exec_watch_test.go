package api

import (
	"context"
	"fmt"
	"os"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

// The shell exited before the console closed (the user typed exit or
// Ctrl-D). Tagged session leaders of other sessions are still running: a
// setsid -f job (nginx and its worker), a tmux server and one of its panes,
// a daemon restarted from the console, an orphan reparented outside the
// container (--pid=host). None is taken for the shell. With the shell
// recorded, only what is left in its session is hung up and, unless it
// ignores SIGHUP, killed; without a record, nothing is signalled.
func TestEndExecSessionShellExited(t *testing.T) {
	for _, recorded := range []bool{true, false} {
		t.Run(fmt.Sprintf("recorded=%v", recorded), func(t *testing.T) {
			fp := newFakeProc(t)
			mark := execTagEnv + "=" + testTag
			fp.add(fproc{pid: 1, comm: "init", pgid: 1, sid: 1, notty: true, start: "1", ctr: ctrID})
			if recorded {
				fp.add(fproc{pid: 500, comm: "sh", pgid: 500, sid: 500, tpgid: 500, start: "1000", ctr: ctrID, env: []string{mark}})
			}
			// Left in the shell's session (reparented to init).
			fp.add(fproc{pid: 501, comm: "sleep", ppid: 1, pgid: 501, sid: 500, notty: true, start: "1001", ctr: ctrID, env: []string{mark}})
			fp.add(fproc{pid: 502, comm: "nohup", ppid: 1, pgid: 502, sid: 500, notty: true, start: "1002", ctr: ctrID, nohup: true, env: []string{mark}})
			// Other sessions.
			fp.add(fproc{pid: 504, comm: "nginx", ppid: 1, pgid: 504, sid: 504, notty: true, start: "1004", ctr: ctrID, env: []string{mark}})
			fp.add(fproc{pid: 506, comm: "nginx worker", ppid: 504, pgid: 504, sid: 504, notty: true, start: "1006", ctr: ctrID, env: []string{mark}})
			fp.add(fproc{pid: 505, comm: "tmux", ppid: 1, pgid: 505, sid: 505, notty: true, start: "1005", ctr: ctrID, env: []string{mark}})
			fp.add(fproc{pid: 507, comm: "pane", ppid: 505, pgid: 507, sid: 507, tpgid: 507, start: "1007", ctr: ctrID, env: []string{mark}})
			fp.add(fproc{pid: 520, comm: "daemon", ppid: 1, pgid: 520, sid: 520, notty: true, start: "1020", ctr: ctrID, env: []string{mark}})
			fp.add(fproc{pid: 530, comm: "orphan", pgid: 530, sid: 530, notty: true, start: "1030", ctr: ctrID, env: []string{mark}})

			w := newExecWatch("plex", ctrID, testTag)
			if recorded {
				w = watchUntilRecorded(t, "plex", ctrID, testTag)
				fp.remove(500) // exit
			}
			signals, sig := recorder(nil) // nothing exits on SIGHUP
			signalProcess = sig
			w.end(closedChan())

			hup, kill := signals()
			wantHup, wantKill := []int{}, []int{}
			if recorded {
				wantHup, wantKill = []int{501, 502}, []int{501}
			}
			if !reflect.DeepEqual(hup, wantHup) || !reflect.DeepEqual(kill, wantKill) {
				t.Errorf("SIGHUP %v, SIGKILL %v; want %v, %v", hup, kill, wantHup, wantKill)
			}
		})
	}
}

// The watch records the exec'd shell when it appears, not a session the
// shell starts, even when both are first seen by the same scan; the full id
// is resolved by the watch when it was unknown at start.
func TestExecWatchRecordsTheShell(t *testing.T) {
	fp := newFakeProc(t)
	mark := execTagEnv + "=" + testTag
	w := newExecWatch("plex", "", testTag)
	w.start()
	time.Sleep(30 * time.Millisecond)
	// setsid -c: its own session, with a terminal, younger, child of the
	// shell; listed first.
	fp.add(fproc{pid: 400, comm: "setsid", ppid: 500, pgid: 400, sid: 400, tpgid: 400, start: "1001", ctr: ctrID, env: []string{mark}})
	fp.add(fproc{pid: 500, comm: "sh", pgid: 500, sid: 500, tpgid: 500, start: "1000", ctr: ctrID, env: []string{mark}})
	select {
	case <-w.done:
	case <-time.After(5 * time.Second):
		t.Fatal("the watch did not stop")
	}
	if !w.found || w.shell.pid != 500 || w.shell.start != 1000 {
		t.Fatalf("recorded %+v (found %v), want pid 500", w.shell, w.found)
	}
	signals, sig := recorder(func(pid int, _ syscall.Signal) { fp.remove(pid) })
	signalProcess = sig
	w.end(closedChan())
	if hup, kill := signals(); !reflect.DeepEqual(hup, []int{500}) || len(kill) != 0 {
		t.Errorf("SIGHUP %v, SIGKILL %v; want [500], []", hup, kill)
	}
}

// A watch that finds nothing stops by itself after execWatchFor; ending it
// then looks once more (an early disconnect, the shell started late).
func TestExecWatchGivesUp(t *testing.T) {
	fp := newFakeProc(t)
	execWatchFor = 50 * time.Millisecond
	w := newExecWatch("plex", ctrID, testTag)
	w.start()
	select {
	case <-w.done:
	case <-time.After(5 * time.Second):
		t.Fatal("the watch did not give up")
	}
	if w.found {
		t.Fatal("recorded a shell that does not exist")
	}
	fp.add(fproc{pid: 500, comm: "sh", pgid: 500, sid: 500, start: "1", ctr: ctrID, env: []string{execTagEnv + "=" + testTag}})
	signals, sig := recorder(func(pid int, _ syscall.Signal) { fp.remove(pid) })
	signalProcess = sig
	w.end(closedChan())
	if hup, _ := signals(); !reflect.DeepEqual(hup, []int{500}) {
		t.Errorf("SIGHUP sent to %v, want [500]", hup)
	}
}

// Early disconnect (nothing recorded) when two processes match the rule
// (only possible with --pid=host): nothing is signalled.
func TestEndExecSessionAmbiguous(t *testing.T) {
	fp := newFakeProc(t)
	mark := execTagEnv + "=" + testTag
	fp.add(fproc{pid: 500, comm: "sh", pgid: 500, sid: 500, start: "1", ctr: ctrID, env: []string{mark}})
	fp.add(fproc{pid: 520, comm: "sh", pgid: 520, sid: 520, start: "2", ctr: ctrID, env: []string{mark}})
	signals, sig := recorder(nil)
	signalProcess = sig
	endExecSession("plex", ctrID, testTag, closedChan())
	if hup, kill := signals(); len(hup)+len(kill) != 0 {
		t.Errorf("SIGHUP %v, SIGKILL %v; want none", hup, kill)
	}
}

// The recorded shell exited and its pid now leads another session: that
// session is not touched.
func TestEndExecSessionShellPidReused(t *testing.T) {
	fp := newFakeProc(t)
	mark := execTagEnv + "=" + testTag
	fp.add(fproc{pid: 500, comm: "sh", pgid: 500, sid: 500, start: "1000", ctr: ctrID, env: []string{mark}})
	w := watchUntilRecorded(t, "plex", ctrID, testTag)
	fp.add(fproc{pid: 500, comm: "new", ppid: 1, pgid: 500, sid: 500, notty: true, start: "5000", ctr: ctrID})
	fp.add(fproc{pid: 501, comm: "new child", ppid: 500, pgid: 500, sid: 500, notty: true, start: "5001", ctr: ctrID})
	signals, sig := recorder(nil)
	signalProcess = sig
	w.end(closedChan())
	if hup, kill := signals(); len(hup)+len(kill) != 0 {
		t.Errorf("SIGHUP %v, SIGKILL %v; want none", hup, kill)
	}
}

// A process whose status cannot be read (stuck) is not taken for one that
// does not ignore SIGHUP: it is left alone, the shell is still killed.
func TestEndExecSessionUnreadableStatusLeftAlone(t *testing.T) {
	fp := newFakeProc(t)
	mark := execTagEnv + "=" + testTag
	fp.add(fproc{pid: 500, comm: "sh", pgid: 500, sid: 500, start: "1", ctr: ctrID, env: []string{mark}})
	fp.add(fproc{pid: 501, comm: "job", ppid: 500, pgid: 501, sid: 500, start: "2", ctr: ctrID, env: []string{mark}})
	block := make(chan struct{})
	t.Cleanup(func() { close(block) })
	readProcFile = func(p string) ([]byte, error) {
		if strings.HasSuffix(p, "/501/status") {
			<-block
		}
		return os.ReadFile(p)
	}
	execReadTimeout = 20 * time.Millisecond
	signals, sig := recorder(nil)
	signalProcess = sig
	endExecSession("plex", ctrID, testTag, closedChan())
	if hup, kill := signals(); !reflect.DeepEqual(hup, []int{500}) || !reflect.DeepEqual(kill, []int{500}) {
		t.Errorf("SIGHUP %v, SIGKILL %v; want [500], [500]", hup, kill)
	}
}

// blockedReads makes environ reads of the given pids block until release;
// it counts the reads started and the most blocked at once.
type blockedReads struct {
	mu            sync.Mutex
	started, peak int
	now           atomic.Int32
	release       chan struct{}
	once          sync.Once
}

func (b *blockedReads) unblock() { b.once.Do(func() { close(b.release) }) }

func blockReads(t *testing.T, fp *fakeProc, pids ...int) *blockedReads {
	b := &blockedReads{release: make(chan struct{})}
	t.Cleanup(b.unblock)
	stuck := map[string]bool{}
	for _, pid := range pids {
		stuck[fmt.Sprintf("%s/%d/environ", fp.root, pid)] = true
	}
	readProcFile = func(p string) ([]byte, error) {
		if stuck[p] {
			n := b.now.Add(1)
			b.mu.Lock()
			b.started++
			b.peak = max(b.peak, int(n))
			b.mu.Unlock()
			<-b.release
			b.now.Add(-1)
		}
		return os.ReadFile(p)
	}
	return b
}

// settled waits until no /proc read is in flight and none is marked stuck.
func settled(t *testing.T, st *procReadState) {
	t.Helper()
	for deadline := time.Now().Add(5 * time.Second); ; time.Sleep(5 * time.Millisecond) {
		st.mu.Lock()
		n, s := st.inFlight, len(st.stuck)
		st.mu.Unlock()
		if n == 0 && s == 0 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("in flight %d, stuck %d", n, s)
		}
	}
}

// A read that timed out marks the process stuck for every later cleanup,
// not just the current one: one blocked read per stuck process in all, and
// the mark goes once the read returns.
func TestProcReadStuckIsProcessWide(t *testing.T) {
	fp := newFakeProc(t)
	fp.add(fproc{pid: 400, comm: "stuck", pgid: 400, sid: 400, start: "1", ctr: ctrID})
	fp.add(fproc{pid: 500, comm: "sh", pgid: 500, sid: 500, start: "2", ctr: ctrID, env: []string{execTagEnv + "=" + testTag}})
	b := blockReads(t, fp, 400)
	execReadTimeout = 20 * time.Millisecond
	for i := 0; i < 3; i++ {
		signals, sig := recorder(func(pid int, _ syscall.Signal) {})
		signalProcess = sig
		endExecSession("plex", ctrID, testTag, closedChan())
		if hup, _ := signals(); !reflect.DeepEqual(hup, []int{500}) {
			t.Errorf("cleanup %d: SIGHUP sent to %v, want [500]", i, hup)
		}
	}
	b.mu.Lock()
	started := b.started
	b.mu.Unlock()
	if started != 1 {
		t.Errorf("the stuck environ was read %d times, want 1", started)
	}
	b.unblock()
	settled(t, procReads)
}

// At most maxProcReads reads are in flight, process-wide: with more stuck
// processes than that, the rest are skipped, and cleanups stay bounded.
func TestProcReadCap(t *testing.T) {
	fp := newFakeProc(t)
	maxProcReads = 2
	var pids []int
	for pid := 400; pid < 406; pid++ {
		fp.add(fproc{pid: pid, comm: "stuck", pgid: pid, sid: pid, start: "1", ctr: ctrID})
		pids = append(pids, pid)
	}
	b := blockReads(t, fp, pids...)
	execReadTimeout = 20 * time.Millisecond
	execCleanupTimeout = 5 * time.Second
	start := time.Now()
	for i := 0; i < 3; i++ {
		endExecSession("plex", ctrID, testTag, closedChan())
	}
	if d := time.Since(start); d > 3*time.Second {
		t.Errorf("cleanups took %v", d)
	}
	b.mu.Lock()
	started, peak := b.started, b.peak
	b.mu.Unlock()
	if peak > 2 || started > 2 {
		t.Errorf("%d stuck reads started, %d at once; want at most 2", started, peak)
	}
	b.unblock()
	settled(t, procReads)
}

// Stopping a watch blocked on a /proc read does not wait for the read's
// timeout.
func TestExecWatchStopsDuringStuckRead(t *testing.T) {
	fp := newFakeProc(t)
	fp.add(fproc{pid: 400, comm: "stuck", pgid: 400, sid: 400, start: "1", ctr: ctrID})
	b := blockReads(t, fp, 400)
	execReadTimeout = time.Hour
	containerFullID = func(context.Context, string) (string, error) { return ctrID, nil }
	w := newExecWatch("plex", ctrID, testTag)
	w.start()
	for deadline := time.Now().Add(5 * time.Second); b.now.Load() == 0; time.Sleep(5 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatal("the watch never read 400")
		}
	}
	close(w.stop)
	select {
	case <-w.done:
	case <-time.After(2 * time.Second):
		t.Fatal("the watch waited for the stuck read")
	}
	b.unblock()
	settled(t, procReads)
}
