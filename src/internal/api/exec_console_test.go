package api

import (
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

// Through a real console: the watch started with the session records the
// shell while it runs. The user then types exit (the shell is gone when the
// socket closes) with a background job left in its session and another
// tagged session (a setsid'd daemon) running: only the job is hung up.
// Without the record the end would find no shell and signal nothing.
func TestDockerExecExitEndsOnlyTheShellsSession(t *testing.T) {
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
	var hup, kill []int
	signalProcess = func(pid int, sig syscall.Signal) error {
		mu.Lock()
		defer mu.Unlock()
		switch sig {
		case syscall.SIGHUP:
			hup = append(hup, pid)
			fp.remove(pid)
		case syscall.SIGKILL:
			kill = append(kill, pid)
		}
		return nil
	}
	// Closed once the shell's environ has been read (the watch's check).
	shellRead := make(chan struct{})
	var once sync.Once
	readProcFile = func(p string) ([]byte, error) {
		b, err := os.ReadFile(p)
		if strings.HasSuffix(p, "/4242/environ") && err == nil {
			once.Do(func() { close(shellRead) })
		}
		return b, err
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
	mark := m[1]
	fp.add(fproc{pid: 1, comm: "init", pgid: 1, sid: 1, notty: true, start: "1", ctr: ctrID})
	fp.add(fproc{pid: 4242, comm: "sh", pgid: 4242, sid: 4242, tpgid: 4242, start: "100", ctr: ctrID, env: []string{mark}})
	fp.add(fproc{pid: 4250, comm: "job", ppid: 4242, pgid: 4250, sid: 4242, start: "101", ctr: ctrID, env: []string{mark}})
	fp.add(fproc{pid: 4260, comm: "daemon", ppid: 1, pgid: 4260, sid: 4260, notty: true, start: "102", ctr: ctrID, env: []string{mark}})
	select {
	case <-shellRead:
	case <-time.After(5 * time.Second):
		t.Fatal("the console's watch never looked at the shell")
	}

	fp.remove(4242) // exit
	_ = c.WriteMessage(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""))
	waitCleanups(t, a)
	mu.Lock()
	defer mu.Unlock()
	sort.Ints(hup)
	if !reflect.DeepEqual(hup, []int{4250}) || len(kill) != 0 {
		t.Errorf("SIGHUP %v, SIGKILL %v; want [4250], []", hup, kill)
	}
}
