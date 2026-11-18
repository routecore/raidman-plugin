package api

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/websocket"

	"github.com/routecore/raidman-plugin/src/internal/service/array"
	"github.com/routecore/raidman-plugin/src/internal/service/docker"
	"github.com/routecore/raidman-plugin/src/internal/service/mover"
	"github.com/routecore/raidman-plugin/src/internal/service/system"
)

type fakeEmcmd struct {
	mu    sync.Mutex
	calls []url.Values
	err   error
}

func (f *fakeEmcmd) Cmd(_ context.Context, p url.Values) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, p)
	return f.err
}

const v2VarIni = `version="7.2.0"
mdState="STARTED"
mdResync="0"
mdResyncPos="0"
mdResyncDt="0"
fsState="Started"
shareUser="e"
shareMoverActive="no"
csrf_token="TEST"
`

// v2Fixtures points every v2 data source at fixtures and fakes. Nothing
// real is read, contacted or executed.
func v2Fixtures(t *testing.T) *fakeEmcmd {
	t.Helper()
	dir := t.TempDir()
	varIni := filepath.Join(dir, "var.ini")
	if err := os.WriteFile(varIni, []byte(v2VarIni), 0o644); err != nil {
		t.Fatal(err)
	}
	em := &fakeEmcmd{}

	oldArr := [4]string{array.VarIniPath, array.DisksIniPath, array.DevsIniPath, healthVarIni}
	oldArrEm := array.Emcmd
	oldMover := [3]string{mover.VarIniPath, mover.PidFile, mover.ProcDir}
	oldMoverEm, oldMoverRun := mover.Emcmd, mover.RunCommand
	oldDocker := [4]any{getDockerUpdates, getDockerMeta, triggerUpdateCheck, updateCheckRunning}
	oldSys := [3]string{system.RebootBinary, system.PoweroffBinary, system.SafeModeFlag}
	oldSysStart := system.StartDetached
	oldUV := healthUnraidVersion
	t.Cleanup(func() {
		array.VarIniPath, array.DisksIniPath, array.DevsIniPath, healthVarIni = oldArr[0], oldArr[1], oldArr[2], oldArr[3]
		array.Emcmd = oldArrEm
		mover.VarIniPath, mover.PidFile, mover.ProcDir = oldMover[0], oldMover[1], oldMover[2]
		mover.Emcmd, mover.RunCommand = oldMoverEm, oldMoverRun
		getDockerUpdates = oldDocker[0].(func(context.Context) ([]docker.ContainerUpdate, error))
		getDockerMeta = oldDocker[1].(func(context.Context) ([]docker.ContainerMeta, error))
		triggerUpdateCheck = oldDocker[2].(func(context.Context) (bool, error))
		updateCheckRunning = oldDocker[3].(func() bool)
		system.RebootBinary, system.PoweroffBinary, system.SafeModeFlag = oldSys[0], oldSys[1], oldSys[2]
		system.StartDetached = oldSysStart
		healthUnraidVersion = oldUV
	})

	array.VarIniPath = varIni
	array.DisksIniPath = "../service/array/testdata/disks_state.ini"
	array.DevsIniPath = "../service/array/testdata/devs.ini"
	array.Emcmd = em
	healthVarIni = varIni
	healthUnraidVersion = filepath.Join(dir, "unraid-version")

	mover.VarIniPath = varIni
	mover.PidFile = filepath.Join(dir, "mover.pid")
	mover.ProcDir = filepath.Join(dir, "proc")
	mover.Emcmd = em
	mover.RunCommand = func(context.Context, string, ...string) ([]byte, error) {
		return nil, errors.New("exec not allowed in tests")
	}

	tr := true
	getDockerUpdates = func(context.Context) ([]docker.ContainerUpdate, error) {
		return []docker.ContainerUpdate{{Name: "plex", Image: "lscr.io/linuxserver/plex", UpdateAvailable: &tr}}, nil
	}
	getDockerMeta = func(context.Context) ([]docker.ContainerMeta, error) {
		return []docker.ContainerMeta{{ID: "abc", Name: "plex", Shell: "bash"}}, nil
	}
	triggerUpdateCheck = func(context.Context) (bool, error) { return false, nil }
	updateCheckRunning = func() bool { return false }

	system.RebootBinary = filepath.Join(dir, "reboot")
	system.PoweroffBinary = filepath.Join(dir, "poweroff")
	system.SafeModeFlag = filepath.Join(dir, "unraidsafemode")
	os.WriteFile(system.RebootBinary, nil, 0o755)
	os.WriteFile(system.PoweroffBinary, nil, 0o755)
	system.StartDetached = func(string, ...string) error { return nil }
	return em
}

type v2Case struct {
	method, path, body string
	ok                 int
	// who may call it besides ADMIN
	viewer, dockerRO, guest bool
}

var v2Cases = []v2Case{
	{"GET", "/api/health", "", 200, true, true, true},
	{"GET", "/api/docker/updates", "", 200, true, true, false},
	{"POST", "/api/docker/updates/check", "", 200, false, false, false},
	{"GET", "/api/docker/meta", "", 200, true, true, false},
	{"GET", "/api/disks/state", "", 200, true, false, false},
	{"POST", "/api/disks/spin", `{"disk":"all","action":"down"}`, 200, false, false, false},
	{"GET", "/api/mover/status", "", 200, true, false, false},
	{"POST", "/api/mover/action", `{"action":"start"}`, 200, false, false, false},
	{"POST", "/api/parity/action", `{"action":"start","correct":false}`, 200, false, false, false},
}

func doReq(t *testing.T, h http.Handler, method, path, body, key string) (int, []byte) {
	t.Helper()
	var rd io.Reader
	if body != "" {
		rd = strings.NewReader(body)
	}
	req := httptest.NewRequest(method, "/raidman"+path, rd)
	if key != "" {
		req.Header.Set("x-api-key", key)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	b, _ := io.ReadAll(rec.Body)
	return rec.Code, b
}

// TestV2PermissionMatrix runs the real protocol-2 handlers (on fixtures) for
// ADMIN, VIEWER, a permission-only DOCKER:READ_ANY key, GUEST and no key.
func TestV2PermissionMatrix(t *testing.T) {
	v2Fixtures(t)
	a, _ := newTestApi(t)
	h, err := a.Handler()
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range v2Cases {
		for _, who := range []struct {
			name, key string
			allowed   bool
		}{
			{"admin", keyAdmin, true},
			{"viewer", keyViewer, c.viewer},
			{"dockerRO", keyDockerRO, c.dockerRO},
			{"guest", keyGuest, c.guest},
			{"none", "", false},
		} {
			code, body := doReq(t, h, c.method, c.path, c.body, who.key)
			want := c.ok
			switch {
			case who.key == "":
				want = http.StatusUnauthorized
			case !who.allowed:
				want = http.StatusForbidden
			}
			if code != want {
				t.Errorf("%s %s as %s: %d %s, want %d", c.method, c.path, who.name, code, body, want)
				continue
			}
			if !json.Valid(body) {
				t.Errorf("%s %s as %s: body is not JSON: %q", c.method, c.path, who.name, body)
			}
			if code >= 400 {
				var e struct{ Error string }
				if json.Unmarshal(body, &e) != nil || e.Error == "" {
					t.Errorf("%s %s as %s: error shape %q", c.method, c.path, who.name, body)
				}
			}
		}
	}
}

func TestV2ErrorShape(t *testing.T) {
	v2Fixtures(t)
	a, _ := newTestApi(t)
	h, _ := a.Handler()

	// 405 after auth, JSON.
	code, body := doReq(t, h, "GET", "/api/parity/action", "", keyAdmin)
	if code != http.StatusMethodNotAllowed || !strings.Contains(string(body), `"error"`) {
		t.Fatalf("405: %d %q", code, body)
	}
	// Bad JSON body / invalid values: 400 JSON.
	for _, c := range []struct{ path, body string }{
		{"/api/parity/action", `nope`},
		{"/api/parity/action", `{"action":"explode"}`},
		{"/api/disks/spin", `{"disk":"disk1","action":"sideways"}`},
		{"/api/disks/spin", `{"disk":"-x","action":"up"}`},
		{"/api/mover/action", `{"action":"pause"}`},
	} {
		code, body := doReq(t, h, "POST", c.path, c.body, keyAdmin)
		if code != http.StatusBadRequest || !strings.Contains(string(body), `"error"`) {
			t.Errorf("%s %s: %d %q", c.path, c.body, code, body)
		}
	}
	// Unknown disk: 404.
	if code, body := doReq(t, h, "POST", "/api/disks/spin", `{"disk":"disk42","action":"up"}`, keyAdmin); code != http.StatusNotFound {
		t.Errorf("unknown disk: %d %q", code, body)
	}
	// Wrong state: 409 (nothing to pause).
	if code, body := doReq(t, h, "POST", "/api/parity/action", `{"action":"pause"}`, keyAdmin); code != http.StatusConflict {
		t.Errorf("pause idle: %d %q", code, body)
	}
	// Protocol-1 routes keep plain-text errors.
	code, body = doReq(t, h, "GET", "/api/array/status", "", "")
	if code != http.StatusUnauthorized || json.Valid(body) {
		t.Errorf("protocol-1 401 must stay plain text: %d %q", code, body)
	}
}

func TestV2HandlersReportBackendFailure(t *testing.T) {
	em := v2Fixtures(t)
	a, _ := newTestApi(t)
	h, _ := a.Handler()
	em.err = errors.New("emhttpd: rejected")
	for _, c := range []struct{ path, body string }{
		{"/api/disks/spin", `{"disk":"all","action":"up"}`},
		{"/api/parity/action", `{"action":"start","correct":true}`},
		{"/api/mover/action", `{"action":"start"}`},
	} {
		code, body := doReq(t, h, "POST", c.path, c.body, keyAdmin)
		if code != http.StatusInternalServerError || strings.Contains(string(body), `"ok"`) {
			t.Errorf("%s: %d %q — a failed command must not report success", c.path, code, body)
		}
	}
	getDockerMeta = func(context.Context) ([]docker.ContainerMeta, error) { return nil, errors.New("daemon down") }
	if code, _ := doReq(t, h, "GET", "/api/docker/meta", "", keyAdmin); code != http.StatusInternalServerError {
		t.Errorf("docker failure: %d", code)
	}
	triggerUpdateCheck = func(context.Context) (bool, error) { return false, docker.ErrCheckUnavailable }
	if code, _ := doReq(t, h, "POST", "/api/docker/updates/check", "", keyAdmin); code != http.StatusNotImplemented {
		t.Errorf("missing dockerupdate: %d", code)
	}
}

func TestV2ResponseShapes(t *testing.T) {
	em := v2Fixtures(t)
	a, _ := newTestApi(t)
	a.ctx.Config.Version = "2026.11.18"
	h, _ := a.Handler()

	_, body := doReq(t, h, "GET", "/api/health", "", keyGuest)
	var health struct {
		Version  string   `json:"version"`
		Protocol int      `json:"protocol"`
		Features []string `json:"features"`
		Unraid   *string  `json:"unraid"`
	}
	if err := json.Unmarshal(body, &health); err != nil {
		t.Fatal(err)
	}
	if health.Version != "2026.11.18" || health.Protocol != 2 || health.Unraid == nil || *health.Unraid != "7.2.0" || len(health.Features) != 8 {
		t.Fatalf("health = %s", body)
	}
	for _, f := range []string{"docker.updates", "docker.meta", "disks.state", "disks.spin", "mover", "parity.v2", "power", "terminal.resize"} {
		if !strings.Contains(string(body), `"`+f+`"`) {
			t.Errorf("health missing feature %s", f)
		}
	}

	_, body = doReq(t, h, "GET", "/api/disks/state", "", keyViewer)
	var disks []map[string]any
	if err := json.Unmarshal(body, &disks); err != nil || len(disks) == 0 {
		t.Fatalf("disks: %v %s", err, body)
	}
	if disks[0]["name"] != "parity" || disks[0]["spundown"] != true || disks[0]["temp"] != nil || disks[0]["type"] != "Parity" {
		t.Errorf("disk[0] = %v", disks[0])
	}
	for _, k := range []string{"name", "device", "type", "spundown", "temp", "status"} {
		if _, ok := disks[0][k]; !ok {
			t.Errorf("disk missing %s", k)
		}
	}

	_, body = doReq(t, h, "GET", "/api/mover/status", "", keyViewer)
	if string(body) != "{\"running\":false}\n" {
		t.Errorf("mover status = %q", body)
	}

	_, body = doReq(t, h, "GET", "/api/docker/updates", "", keyDockerRO)
	if !strings.Contains(string(body), `"updateAvailable":true`) || !strings.Contains(string(body), `"localDigest":null`) {
		t.Errorf("updates = %s", body)
	}
	code, body := doReq(t, h, "POST", "/api/docker/updates/check", "", keyAdmin)
	if code != 200 || string(body) != "{\"started\":true}\n" {
		t.Errorf("check = %d %s", code, body)
	}

	em.calls = nil
	code, body = doReq(t, h, "POST", "/api/parity/action", `{"action":"start","correct":true}`, keyAdmin)
	if code != 200 || string(body) != "{\"ok\":true}\n" || len(em.calls) != 1 || em.calls[0].Get("optionCorrect") != "correct" {
		t.Errorf("parity start: %d %s %v", code, body, em.calls)
	}
}

func TestSystemActionCleanPath(t *testing.T) {
	v2Fixtures(t)
	var started []string
	system.StartDetached = func(name string, args ...string) error {
		started = append(started, strings.Join(append([]string{name}, args...), " "))
		return nil
	}
	a, _ := newTestApi(t)
	h, _ := a.Handler()
	code, body := doReq(t, h, "POST", "/api/system/action", `{"action":"reboot"}`, keyAdmin)
	if code != 200 || !strings.Contains(string(body), `"success":true`) {
		t.Fatalf("reboot: %d %s", code, body)
	}
	code, _ = doReq(t, h, "POST", "/api/system/action", `{"action":"shutdown"}`, keyAdmin)
	if code != 200 {
		t.Fatalf("shutdown: %d", code)
	}
	if len(started) != 2 || started[0] != system.RebootBinary || started[1] != system.PoweroffBinary {
		t.Fatalf("started = %v", started)
	}
	if code, _ := doReq(t, h, "POST", "/api/system/action", `{"action":"reboot"}`, keyViewer); code != http.StatusForbidden {
		t.Fatalf("viewer reboot: %d", code)
	}
}

func TestParseResize(t *testing.T) {
	ok := []struct {
		in         string
		cols, rows uint16
	}{
		{"\x1b[8;40;120t", 120, 40},
		{"\x1b[8;1;1t", 1, 1},
		{`{"type":"resize","cols":100,"rows":30}`, 100, 30},
		{`{"rows":24,"cols":80,"type":"resize"}`, 80, 24},
		{` {"type":"resize","cols":80,"rows":24}`, 0, 0}, // leading space: input
	}
	for _, c := range ok {
		cols, rows, got := parseResize([]byte(c.in))
		if want := c.cols != 0; got != want || cols != c.cols || rows != c.rows {
			t.Errorf("parseResize(%q) = %d,%d,%v", c.in, cols, rows, got)
		}
	}
	for _, in := range []string{
		"", "ls -la\r", "{", "{}", `{"type":"input","data":"x"}`,
		`{"type":"resize","cols":0,"rows":24}`, `{"type":"resize","cols":80}`,
		`{"type":"resize","cols":80,"rows":24,"extra":1}`, `{"type":"resize","cols":80,"rows":24}x`,
		`{"type":"resize","cols":5000,"rows":24}`, `{"type":"resize","cols":-1,"rows":24}`,
		"\x1b[8;40;120", "\x1b[8;40;120tls", "\x1b[8;0;80t", "\x1b[8;40;99999t", "\x1b[A",
	} {
		if _, _, got := parseResize([]byte(in)); got {
			t.Errorf("parseResize(%q) accepted", in)
		}
	}
}

func TestDockerExecShellParam(t *testing.T) {
	a, _ := newTestApi(t)
	build := func(q string) ([]string, string) {
		r := httptest.NewRequest("GET", "/connect?type=docker&"+q, nil)
		cmd, msg := a.buildPtyCommand("docker", r)
		if cmd == nil {
			return nil, msg
		}
		return cmd.Args, ""
	}
	want := func(shell string) string { return "docker exec -it -- plex " + shell }
	for q, shell := range map[string]string{
		"container=plex":                     "sh",
		"container=plex&shell=bash":          "bash",
		"container=srv:plex&shell=zsh":       "zsh",
		"container=plex&shell=ash":           "ash",
		"container=plex&shell=/bin/sh":       "sh",
		"container=plex&shell=%2Fbin%2Fbash": "bash",
	} {
		args, msg := build(q)
		if got := strings.Join(args, " "); got != want(shell) {
			t.Errorf("%s: %q %q, want %q", q, got, msg, want(shell))
		}
	}
	for _, q := range []string{"container=plex&shell=python3", "container=plex&shell=bash%20-c%20id", "container=plex&shell=-i", "container=plex&shell=fish"} {
		if args, msg := build(q); args != nil || !strings.HasPrefix(msg, "Error:") {
			t.Errorf("%s accepted: %v", q, args)
		}
	}
}

// TestHostTerminalResize runs a real PTY (host terminal, /bin/bash) and
// checks both resize frame formats with `stty size`.
func TestHostTerminalResize(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("no pty")
	}
	if _, err := os.Stat("/bin/bash"); err != nil {
		t.Skip("no /bin/bash")
	}
	t.Setenv("HOME", t.TempDir())
	a, _ := newTestApi(t)
	h, _ := a.Handler()
	srv := httptest.NewServer(h)
	defer srv.Close()
	defer a.Shutdown(t.Context())

	u := "ws" + strings.TrimPrefix(srv.URL, "http") + "/raidman/connect?type=host"
	c, _, err := websocket.DefaultDialer.Dial(u, http.Header{"x-api-key": {keyAdmin}})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	var out strings.Builder
	waitFor := func(s string) {
		t.Helper()
		deadline := time.Now().Add(10 * time.Second)
		for !strings.Contains(out.String(), s) {
			c.SetReadDeadline(deadline)
			_, b, err := c.ReadMessage()
			if err != nil {
				t.Fatalf("waiting for %q: %v (output %q)", s, err, out.String())
			}
			out.Write(b)
		}
	}
	send := func(s string) {
		if err := c.WriteMessage(websocket.TextMessage, []byte(s)); err != nil {
			t.Fatal(err)
		}
	}
	send(`{"type":"resize","cols":101,"rows":37}`)
	send("stty size; echo M1''ARK\n")
	waitFor("M1ARK")
	if !strings.Contains(out.String(), "37 101") {
		t.Fatalf("JSON resize not applied: %q", out.String())
	}
	out.Reset()
	send("\x1b[8;29;93t")
	send("stty size; echo M2''ARK\n")
	waitFor("M2ARK")
	if !strings.Contains(out.String(), "29 93") {
		t.Fatalf("escape resize not applied: %q", out.String())
	}
	send("exit\n")
}
