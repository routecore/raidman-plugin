package api

import (
	"context"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/gorilla/websocket"

	"github.com/routecore/raidman-plugin/src/internal/service/vm"
)

// readUntilClose reads frames until the server closes, and returns the text
// of the data frames and the close error.
func readUntilClose(t *testing.T, c *websocket.Conn, within time.Duration) (string, error) {
	t.Helper()
	var out strings.Builder
	c.SetReadDeadline(time.Now().Add(within))
	for {
		_, msg, err := c.ReadMessage()
		if err != nil {
			return out.String(), err
		}
		out.Write(msg)
	}
}

func wantNormalClose(t *testing.T, what string, err error) {
	t.Helper()
	var ce *websocket.CloseError
	if !errors.As(err, &ce) || ce.Code != websocket.CloseNormalClosure {
		t.Errorf("%s: want a 1000 close frame, got %v", what, err)
	}
}

// A terminal starts at 80x24, not 0x0, before the client sends a resize.
func TestPtyDefaultSize(t *testing.T) {
	a, _ := newTestApi(t)
	base := ptyTestServer(t, a)
	c, _ := startShell(t, base)
	if err := c.WriteMessage(websocket.TextMessage, []byte("echo SIZE=$(stty size)=\n")); err != nil {
		t.Fatal(err)
	}
	re := regexp.MustCompile(`SIZE=(\d+ \d+)=`)
	var out strings.Builder
	deadline := time.Now().Add(10 * time.Second)
	for {
		c.SetReadDeadline(deadline)
		_, msg, err := c.ReadMessage()
		if err != nil {
			t.Fatalf("waiting for stty: %v (output %q)", err, out.String())
		}
		out.Write(msg)
		if m := re.FindStringSubmatch(out.String()); m != nil {
			if m[1] != "24 80" {
				t.Fatalf("initial size %q, want \"24 80\"", m[1])
			}
			return
		}
	}
}

// Closing a container console runs the in-container cleanup for exactly
// that session's tag (a fake docker CLI records its arguments; the
// container's shell is a fake /proc entry).
func TestDockerExecCloseEndsContainerSession(t *testing.T) {
	a, _ := newTestApi(t)
	base := ptyTestServer(t, a)
	bin := t.TempDir()
	argsFile := filepath.Join(bin, "args")
	script := "#!/bin/sh\necho \"$@\" > \"$FAKE_DOCKER_ARGS\"\necho ready\nexec sleep 60\n"
	if err := os.WriteFile(filepath.Join(bin, "docker"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("FAKE_DOCKER_ARGS", argsFile)
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))

	fp := newFakeProc(t)
	var mu sync.Mutex
	var hup []int
	signalProcess = func(pid int, sig syscall.Signal) error {
		mu.Lock()
		defer mu.Unlock()
		if sig == syscall.SIGHUP {
			hup = append(hup, pid)
			fp.remove(pid)
		}
		return nil
	}

	c, _, err := websocket.DefaultDialer.Dial(base+"docker&container=plex", http.Header{"x-api-key": {keyAdmin}})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetReadDeadline(time.Now().Add(10 * time.Second))
	if _, msg, err := c.ReadMessage(); err != nil || !strings.Contains(string(msg), "ready") {
		t.Fatalf("first frame: %v %q", err, msg)
	}
	b, err := os.ReadFile(argsFile)
	if err != nil {
		t.Fatal(err)
	}
	m := regexp.MustCompile(`-e (RAIDMAN_EXEC=[0-9a-f]{32}) -- plex sh`).FindStringSubmatch(string(b))
	if m == nil {
		t.Fatalf("docker args %q", b)
	}
	fp.add(fproc{pid: 4242, comm: "sh", pgid: 4242, sid: 4242, start: "1", ctr: ctrID, env: []string{"PATH=/bin", m[1]}})
	fp.add(fproc{pid: 4243, comm: "sh", pgid: 4243, sid: 4243, start: "1", ctr: ctrID, env: []string{"PATH=/bin", "RAIDMAN_EXEC=00000000000000000000000000000000"}})

	_ = c.WriteMessage(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""))
	deadline := time.Now().Add(hangupGrace + 5*time.Second)
	for {
		mu.Lock()
		got := append([]int(nil), hup...)
		mu.Unlock()
		if len(got) > 0 {
			if len(got) != 1 || got[0] != 4242 {
				t.Fatalf("SIGHUP sent to %v, want [4242]", got)
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("closing the console did not hang up the container session")
		}
		time.Sleep(20 * time.Millisecond)
	}
	for deadline := time.Now().Add(hangupGrace + 3*time.Second); openStreams(a) != 0; time.Sleep(20 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatal("stream slot still held")
		}
	}
	waitCleanups(t, a)
}

// waitCleanups waits for the console cleanups still running (they use the
// hooks newFakeProc restores).
func waitCleanups(t *testing.T, a *Api) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	a.waitExecCleanups(ctx)
	if n := a.execCleanups.Load(); n != 0 {
		t.Fatalf("%d console cleanup(s) still running", n)
	}
}

// A cleanup stuck reading /proc (a process in D state) does not hold the
// docker CLI, the stream slot or the audit line: they no longer wait for it.
func TestDockerExecStuckCleanupReleasesSlot(t *testing.T) {
	a, _ := newTestApi(t)
	base := ptyTestServer(t, a)
	bin := t.TempDir()
	script := "#!/bin/sh\necho ready\nexec sleep 60\n"
	if err := os.WriteFile(filepath.Join(bin, "docker"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))

	fp := newFakeProc(t)
	fp.add(fproc{pid: 4242, comm: "sh", pgid: 4242, sid: 4242, start: "1", ctr: ctrID})
	block := make(chan struct{})
	var once sync.Once
	unblock := func() { once.Do(func() { close(block) }) }
	t.Cleanup(unblock)
	readProcFile = func(p string) ([]byte, error) {
		if strings.HasSuffix(p, "/environ") {
			<-block
		}
		return os.ReadFile(p)
	}
	execReadTimeout = time.Hour // only the goroutine bounds the wait now

	c, _, err := websocket.DefaultDialer.Dial(base+"docker&container=plex", http.Header{"x-api-key": {keyAdmin}})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetReadDeadline(time.Now().Add(10 * time.Second))
	if _, msg, err := c.ReadMessage(); err != nil || !strings.Contains(string(msg), "ready") {
		t.Fatalf("first frame: %v %q", err, msg)
	}
	if n := a.execCleanups.Load(); n != 1 {
		t.Fatalf("pending cleanups = %d, want 1", n)
	}
	c.UnderlyingConn().Close()
	for deadline := time.Now().Add(hangupGrace + 3*time.Second); openStreams(a) != 0; time.Sleep(20 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatal("stream slot held by a stuck cleanup")
		}
	}
	if n := a.execCleanups.Load(); n != 1 {
		t.Errorf("pending cleanups = %d, want the stuck one", n)
	}
	unblock()
	waitCleanups(t, a)
}

// vm-log for a VM libvirt does not know and that has no log is refused with
// a clean close and without the host path; a log without a domain (a
// deleted VM) is still served.
func TestVmLogUnknownVM(t *testing.T) {
	a, _ := newTestApi(t)
	base := ptyTestServer(t, a)
	dir := t.TempDir()
	oldDir, oldResolve := qemuLogDir, resolveDomain
	t.Cleanup(func() { qemuLogDir, resolveDomain = oldDir, oldResolve })
	qemuLogDir = dir
	resolveDomain = func(string) (*vm.Domain, error) { return nil, errors.New("Domain not found") }

	c, _, err := websocket.DefaultDialer.Dial(base+"vm-log&vm=ghost", http.Header{"x-api-key": {keyAdmin}})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	out, err := readUntilClose(t, c, 5*time.Second)
	wantNormalClose(t, "unknown VM", err)
	if !strings.HasPrefix(out, "Error:") || strings.Contains(out, dir) || strings.Contains(out, "/var/log") {
		t.Errorf("unknown VM output %q", out)
	}

	if err := os.WriteFile(filepath.Join(dir, "gone.log"), []byte("LOG-LINE\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	c2, _, err := websocket.DefaultDialer.Dial(base+"vm-log&vm=gone", http.Header{"x-api-key": {keyAdmin}})
	if err != nil {
		t.Fatal(err)
	}
	defer c2.Close()
	c2.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, msg, err := c2.ReadMessage(); err != nil || !strings.Contains(string(msg), "LOG-LINE") {
		t.Errorf("log of a deleted VM: %v %q", err, msg)
	}
}

// docker-stats with an invalid container id and vm-vnc errors end with a
// close frame, not a dropped connection (1006).
func TestStreamErrorsSendCloseFrame(t *testing.T) {
	a, _ := newTestApi(t)
	base := ptyTestServer(t, a)
	old := getVncPort
	t.Cleanup(func() { getVncPort = old })
	getVncPort = func(string) (string, error) { return "", vm.ErrNotRunning }

	for _, c := range []struct{ query, want string }{
		{"docker-stats&container=bad%3Bid", "Error: "},
		{"vm-vnc&vm=-x", "Error: "},
		{"vm-vnc&vm=Windows", "Error finding VNC port"},
	} {
		conn, _, err := websocket.DefaultDialer.Dial(base+c.query, http.Header{"x-api-key": {keyAdmin}})
		if err != nil {
			t.Fatalf("%s: %v", c.query, err)
		}
		out, err := readUntilClose(t, conn, 5*time.Second)
		conn.Close()
		if !strings.HasPrefix(out, c.want) {
			t.Errorf("%s: output %q", c.query, out)
		}
		wantNormalClose(t, c.query, err)
	}
}
