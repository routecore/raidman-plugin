package docker

import (
	"context"
	"errors"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/moby/moby/client"
)

const longID = "29f44a84a5a5942e82f7ad3fd76b1cd72b5a3e6b9cb6e997512c0e0c652ce53e"

// actionDaemon answers lifecycle POSTs on /containers/<name>/<action> with
// the status and message in answers (keyed by "<name>/<action>").
func actionDaemon(t *testing.T, answers map[string]struct {
	status int
	msg    string
}) {
	t.Helper()
	dir, err := os.MkdirTemp("", "rmd")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	sock := filepath.Join(dir, "d.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, rest, _ := strings.Cut(r.URL.Path, "/containers/")
		a, ok := answers[rest]
		if !ok {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(a.status)
		_, _ = w.Write([]byte(`{"message":"` + a.msg + `"}`))
	})}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })
	cli, err := client.New(client.WithHost("unix://" + sock))
	if err != nil {
		t.Fatal(err)
	}
	cliMu.Lock()
	old := shared
	shared = cli
	cliMu.Unlock()
	t.Cleanup(func() {
		cliMu.Lock()
		shared = old
		cliMu.Unlock()
		_ = cli.Close()
	})
}

// Wrong-state answers (the evidence's double taps) become ErrWrongState
// with a short message and no container id; real failures and missing
// containers keep their own errors.
func TestContainerActionWrongState(t *testing.T) {
	type answer = struct {
		status int
		msg    string
	}
	actionDaemon(t, map[string]answer{
		"c/pause":   {409, "container " + longID + " is already paused"},
		"c/unpause": {409, "Container " + longID + " is not paused"},
		"c/kill":    {409, "cannot kill container: rt-ports: container " + longID + " is not running"},
		"d/pause":   {409, "container " + longID + " is not running"},
		"e/kill":    {500, "cannot kill container: e: container " + longID + " is not running"}, // unclassified, same words
		"f/start":   {409, "conflict: something else entirely"},
		"g/start":   {500, "OCI runtime create failed: the process is not running"},
		"h/stop":    {404, "No such container: h"},
	})
	ctx := context.Background()
	for _, c := range []struct{ id, action, want string }{
		{"c", "pause", "container is already paused"},
		{"c", "unpause", "container is not paused"},
		{"c", "kill", "container is not running"},
		{"d", "pause", "container is not running"},
		{"e", "kill", "container is not running"},
		{"f", "start", ErrWrongState.Error()},
	} {
		err := ExecuteContainerAction(ctx, c.id, c.action)
		if !errors.Is(err, ErrWrongState) || err.Error() != c.want {
			t.Errorf("%s %s: %v, want ErrWrongState %q", c.action, c.id, err, c.want)
		}
		if err != nil && strings.Contains(err.Error(), longID[:12]) {
			t.Errorf("%s %s: message carries the container id: %q", c.action, c.id, err)
		}
	}
	if err := ExecuteContainerAction(ctx, "g", "start"); err == nil || errors.Is(err, ErrWrongState) {
		t.Errorf("a runtime failure became a state conflict: %v", err)
	}
	if err := ExecuteContainerAction(ctx, "h", "stop"); !errors.Is(err, ErrNotFound) || errors.Is(err, ErrWrongState) {
		t.Errorf("missing container: %v, want ErrNotFound", err)
	}
	if err := ExecuteContainerAction(ctx, "ok", "pause"); err != nil {
		t.Errorf("successful pause: %v", err)
	}
}
