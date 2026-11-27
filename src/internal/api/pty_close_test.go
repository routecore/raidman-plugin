package api

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

// openStreams returns the number of stream slots currently held.
func openStreams(a *Api) int {
	a.streams.mu.Lock()
	defer a.streams.mu.Unlock()
	return a.streams.total
}

// ptyTestServer serves a with a real HTTP server and returns the base ws URL.
func ptyTestServer(t *testing.T, a *Api) string {
	t.Helper()
	if _, err := os.Stat("/bin/bash"); err != nil {
		t.Skip("no /bin/bash")
	}
	// Keep the login shell away from the developer's dotfiles.
	t.Setenv("HOME", t.TempDir())
	h, err := a.Handler()
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(h)
	t.Cleanup(func() {
		_ = a.Shutdown(t.Context()) // cancels every open stream
		srv.Close()
	})
	return "ws" + strings.TrimPrefix(srv.URL, "http") + "/raidman/connect?type="
}

var shellPIDRe = regexp.MustCompile(`PID:(\d+)`)

// startShell opens a host terminal and returns the socket and the shell's pid.
func startShell(t *testing.T, base string) (*websocket.Conn, int) {
	t.Helper()
	c, resp, err := websocket.DefaultDialer.Dial(base+"host", http.Header{"x-api-key": {keyAdmin}})
	if err != nil {
		t.Fatalf("dial: %v (resp %v)", err, resp)
	}
	t.Cleanup(func() { c.Close() })
	if err := c.WriteMessage(websocket.TextMessage, []byte("echo PID:$$\n")); err != nil {
		t.Fatal(err)
	}
	var out strings.Builder
	deadline := time.Now().Add(10 * time.Second)
	for {
		c.SetReadDeadline(deadline)
		_, msg, err := c.ReadMessage()
		if err != nil {
			t.Fatalf("waiting for shell pid: %v (output %q)", err, out.String())
		}
		out.Write(msg)
		if m := shellPIDRe.FindStringSubmatch(out.String()); m != nil {
			pid, _ := strconv.Atoi(m[1])
			return c, pid
		}
	}
}

// waitSessionGone waits until no stream slot is held and pid no longer exists
// (killed and reaped).
func waitSessionGone(t *testing.T, a *Api, pid int, within time.Duration) {
	t.Helper()
	deadline := time.Now().Add(within)
	for {
		n := openStreams(a)
		alive := syscall.Kill(pid, 0) == nil
		if n == 0 && !alive {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("after %v: %d stream slot(s) still held, shell %d alive=%v", within, n, pid, alive)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// An idle shell writes nothing after its prompt. When the client vanishes
// the session must still end: the shell is killed and the slot is freed
// (previously the PTY read stayed blocked until the shell printed something).
func TestPtyClientDropEndsIdleShell(t *testing.T) {
	a, _ := newTestApi(t)
	base := ptyTestServer(t, a)
	c, pid := startShell(t, base)
	if n := openStreams(a); n != 1 {
		t.Fatalf("open streams = %d, want 1", n)
	}
	// Drop the connection without a close handshake (network loss).
	c.UnderlyingConn().Close()
	waitSessionGone(t, a, pid, hangupGrace+3*time.Second)
}

// Demoting the key to non-ADMIN closes an open shell with 1008 and kills it.
func TestPtyKeyDemotionKillsShell(t *testing.T) {
	a, dir := newTestApi(t)
	base := ptyTestServer(t, a)
	c, pid := startShell(t, base)

	js := `{"id":"id-admin","key":"` + keyAdmin + `","name":"admin","roles":["VIEWER"],"permissions":[]}`
	if err := os.WriteFile(filepath.Join(dir, "admin.json"), []byte(js), 0o600); err != nil {
		t.Fatal(err)
	}
	a.keys.Reload()

	deadline := time.Now().Add(authRecheckPeriod + 5*time.Second)
	for {
		c.SetReadDeadline(deadline)
		_, _, err := c.ReadMessage()
		if err == nil {
			continue
		}
		var ce *websocket.CloseError
		if !errors.As(err, &ce) || ce.Code != websocket.ClosePolicyViolation {
			t.Fatalf("want close 1008 after demotion, got %v", err)
		}
		break
	}
	waitSessionGone(t, a, pid, hangupGrace+3*time.Second)
}

// When the process exits on its own the client gets all output and then a
// clean 1000 close carrying the exit status.
func TestPtyExitSendsNormalClose(t *testing.T) {
	a, _ := newTestApi(t)
	base := ptyTestServer(t, a)
	c, pid := startShell(t, base)
	if err := c.WriteMessage(websocket.TextMessage, []byte("echo BYE-$((40+2)); exit 3\n")); err != nil {
		t.Fatal(err)
	}
	var out strings.Builder
	deadline := time.Now().Add(10 * time.Second)
	for {
		c.SetReadDeadline(deadline)
		_, msg, err := c.ReadMessage()
		if err == nil {
			out.Write(msg)
			continue
		}
		var ce *websocket.CloseError
		if !errors.As(err, &ce) || ce.Code != websocket.CloseNormalClosure || ce.Text != "process exited (3)" {
			t.Fatalf("want close 1000 \"process exited (3)\", got %v", err)
		}
		break
	}
	if !strings.Contains(out.String(), "BYE-42") {
		t.Fatalf("output before close is missing: %q", out.String())
	}
	waitSessionGone(t, a, pid, 3*time.Second)
}

// A disabled host terminal answers with the error text and a 1008 close.
func TestPtyHostDisabledClosesWithPolicyViolation(t *testing.T) {
	a, _ := newTestApi(t)
	a.hostTerminalEnabled = func() bool { return false }
	base := ptyTestServer(t, a)
	c, _, err := websocket.DefaultDialer.Dial(base+"host", http.Header{"x-api-key": {keyAdmin}})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, msg, err := c.ReadMessage(); err != nil || string(msg) != errHostTerminalDisabled {
		t.Fatalf("first frame: %v %q", err, msg)
	}
	_, _, err = c.ReadMessage()
	var ce *websocket.CloseError
	if !errors.As(err, &ce) || ce.Code != websocket.ClosePolicyViolation {
		t.Fatalf("want close 1008, got %v", err)
	}
}

// Invalid parameters end with the error text and a 1000 close (no retry loop).
func TestPtyInvalidParamsCloseNormally(t *testing.T) {
	a, _ := newTestApi(t)
	base := ptyTestServer(t, a)
	c, _, err := websocket.DefaultDialer.Dial(base+"docker-log&container=bad%20name", http.Header{"x-api-key": {keyAdmin}})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, msg, err := c.ReadMessage(); err != nil || !strings.HasPrefix(string(msg), "Error:") {
		t.Fatalf("first frame: %v %q", err, msg)
	}
	_, _, err = c.ReadMessage()
	var ce *websocket.CloseError
	if !errors.As(err, &ce) || ce.Code != websocket.CloseNormalClosure || !strings.HasPrefix(ce.Text, "Error:") {
		t.Fatalf("want close 1000 with the error, got %v", err)
	}
	deadline := time.Now().Add(3 * time.Second)
	for openStreams(a) != 0 {
		if time.Now().After(deadline) {
			t.Fatal("stream slot not released")
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// docker exec and the VM serial console are ADMIN only: keys holding
// DOCKER:UPDATE_ANY or VMS:UPDATE_ANY (and VIEWER) get 403.
func TestShellStreamsAreAdminOnly(t *testing.T) {
	a, _ := newTestApi(t)
	h, err := a.Handler()
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		typ, key string
		want     int
	}{
		{"docker&container=plex", keyPermOnly, http.StatusForbidden}, // DOCKER:UPDATE_ANY
		{"docker&container=plex", keyViewer, http.StatusForbidden},
		{"vm&vm=win11", keyVMOps, http.StatusForbidden}, // VMS:UPDATE_ANY
		{"vm&vm=win11", keyViewer, http.StatusForbidden},
		{"vm-vnc&vm=win11", keyGuest, http.StatusForbidden},
	} {
		req := httptest.NewRequest(http.MethodGet, "/raidman/connect?type="+tc.typ, nil)
		req.Header.Set("x-api-key", tc.key)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != tc.want {
			t.Errorf("type=%s: got %d, want %d (%s)", tc.typ, rec.Code, tc.want, rec.Body.String())
		}
	}
	for _, typ := range []string{"docker", "vm"} {
		wr := a.wsRoutes()[typ]
		if wr.Req != AdminOnly() {
			t.Errorf("stream %s requires %s, want ADMIN", typ, wr.Req)
		}
	}
}
