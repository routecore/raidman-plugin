package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/routecore/raidman-plugin/src/internal/service/docker"
	"github.com/routecore/raidman-plugin/src/internal/service/httperr"
)

func contractHandler(t *testing.T) http.Handler {
	t.Helper()
	v2Fixtures(t)
	a, _ := newTestApi(t)
	h, err := a.Handler()
	if err != nil {
		t.Fatal(err)
	}
	return h
}

func decodeErrBody(t *testing.T, body []byte) map[string]string {
	t.Helper()
	var m map[string]string
	if err := json.Unmarshal(body, &m); err != nil {
		t.Fatalf("error body is not JSON: %q", body)
	}
	return m
}

// TestMissingResourceIsNot404 drives the action routes with a container or
// disk that does not exist. The app reads any plugin 404 as "route missing,
// plugin outdated", so they must answer 422 + "code":"not_found".
func TestMissingResourceIsNot404(t *testing.T) {
	h := contractHandler(t)
	oldExec := executeContainerAction
	t.Cleanup(func() { executeContainerAction = oldExec })
	executeContainerAction = func(context.Context, string, string) error {
		return fmt.Errorf("%w: No such container: abc", docker.ErrNotFound)
	}

	for _, c := range []struct{ path, body string }{
		{"/api/docker/action", `{"container":"abc","action":"kill"}`},
		{"/api/disks/spin", `{"disk":"disk42","action":"up"}`},
	} {
		code, body := doReq(t, h, "POST", c.path, c.body, keyAdmin)
		if code != http.StatusUnprocessableEntity {
			t.Errorf("%s: status %d, want 422 (%q)", c.path, code, body)
			continue
		}
		m := decodeErrBody(t, body)
		if m["code"] != httperr.CodeNotFound || m["error"] == "" {
			t.Errorf("%s: body %q, want error + code not_found", c.path, body)
		}
	}

	// Other container action errors keep their status and plain text.
	executeContainerAction = func(context.Context, string, string) error { return docker.ErrInvalidAction }
	if code, body := doReq(t, h, "POST", "/api/docker/action", `{"container":"abc","action":"x"}`, keyAdmin); code != http.StatusBadRequest || strings.Contains(string(body), "not_found") {
		t.Errorf("invalid action: %d %q", code, body)
	}

	// A wrong state (pause twice, kill a stopped container) is a plain-text
	// 409 with the service's short message.
	executeContainerAction = func(context.Context, string, string) error {
		return fmt.Errorf("%w", docker.ErrWrongState)
	}
	if code, body := doReq(t, h, "POST", "/api/docker/action", `{"container":"abc","action":"pause"}`, keyAdmin); code != http.StatusConflict || json.Valid(body) || !strings.Contains(string(body), docker.ErrWrongState.Error()) {
		t.Errorf("wrong state: %d %q, want plain-text 409", code, body)
	}

	// Unknown routes stay 404 (that is what "plugin outdated" means).
	if code, _ := doReq(t, h, "GET", "/api/no/such/route", "", keyAdmin); code != http.StatusNotFound {
		t.Errorf("unknown route: %d, want 404", code)
	}
}

func TestWriteHTTPError(t *testing.T) {
	rec := httptest.NewRecorder()
	writeHTTPError(rec, httperr.NotFound("disk %q not found", "disk9"))
	if rec.Code != http.StatusUnprocessableEntity || rec.Body.String() != "{\"code\":\"not_found\",\"error\":\"disk \\\"disk9\\\" not found\"}\n" {
		t.Errorf("not found: %d %q", rec.Code, rec.Body.String())
	}
	rec = httptest.NewRecorder()
	writeHTTPError(rec, httperr.New(http.StatusConflict, "busy"))
	if rec.Code != http.StatusConflict || rec.Body.String() != "{\"error\":\"busy\"}\n" {
		t.Errorf("conflict: %d %q", rec.Code, rec.Body.String())
	}
	rec = httptest.NewRecorder()
	writeHTTPError(rec, fmt.Errorf("plain"))
	if rec.Code != http.StatusInternalServerError || rec.Body.String() != "{\"error\":\"plain\"}\n" {
		t.Errorf("plain: %d %q", rec.Code, rec.Body.String())
	}
}

// inspectFixture is a trimmed Docker inspect document as GetContainers
// returns it (decoded JSON plus AutoStart).
func inspectFixture() map[string]any {
	const js = `{
	  "Id": "abc123", "Name": "/plex", "Image": "sha256:img", "Created": "2026-01-02T03:04:05Z",
	  "Path": "/init", "Args": [], "RestartCount": 0, "Driver": "btrfs",
	  "State": {"Status": "running", "Running": true, "Paused": false, "Restarting": false,
	    "OOMKilled": false, "Dead": false, "Pid": 42, "ExitCode": 0, "Error": "",
	    "StartedAt": "2026-01-02T03:04:06.123456789Z", "FinishedAt": "0001-01-01T00:00:00Z",
	    "Health": {"Status": "healthy", "FailingStreak": 0, "Log": [{"Output": "big health output"}]}},
	  "Config": {"Image": "lscr.io/linuxserver/plex", "Cmd": ["/init"], "Labels": {"a": "b"},
	    "Env": ["PLEX_CLAIM=secret"], "ExposedPorts": {"32400/tcp": {}}},
	  "HostConfig": {"NetworkMode": "br0", "RestartPolicy": {"Name": "unless-stopped"},
	    "Binds": ["/mnt/user/appdata/plex:/config"], "Devices": []},
	  "GraphDriver": {"Name": "btrfs", "Data": {"x": "y"}},
	  "NetworkSettings": {"SandboxKey": "/var/run/docker/netns/x",
	    "Ports": {"32400/tcp": [{"HostIp": "0.0.0.0", "HostPort": "32400"}]},
	    "Networks": {"br0": {"IPAddress": "192.168.1.50", "IPPrefixLen": 24, "Gateway": "192.168.1.1",
	      "MacAddress": "02:42:c0:a8:01:32", "GlobalIPv6Address": "", "EndpointID": "e", "DNSNames": ["plex"]}}},
	  "Mounts": [{"Type": "bind", "Source": "/mnt/user/appdata/plex", "Destination": "/config",
	    "Mode": "", "RW": true, "Propagation": "rprivate"}],
	  "AutoStart": true
	}`
	var m map[string]any
	if err := json.Unmarshal([]byte(js), &m); err != nil {
		panic(err)
	}
	return m
}

func TestContainersSummaryMode(t *testing.T) {
	h := contractHandler(t)
	oldGet := getContainers
	t.Cleanup(func() { getContainers = oldGet })
	var gotSize atomic.Bool
	getContainers = func(_ context.Context, o docker.ContainerOptions) ([]map[string]any, error) {
		gotSize.Store(o.Size)
		m := inspectFixture()
		if o.Size {
			m["SizeRw"], m["SizeRootFs"] = int64(1), int64(2)
		}
		return []map[string]any{m}, nil
	}

	// Default: full inspect documents, Env stripped. A bare GET (protocol-1
	// apps) also gets the sizes, as protocol-1 plugins always sent them.
	code, body := doReq(t, h, "GET", "/api/docker/containers", "", keyAdmin)
	var full []map[string]any
	if err := json.Unmarshal(body, &full); code != 200 || err != nil || len(full) != 1 {
		t.Fatalf("default: %d %v %q", code, err, body)
	}
	if !gotSize.Load() {
		t.Error("bare GET did not compute sizes")
	}
	want := inspectFixture()
	want["SizeRw"], want["SizeRootFs"] = int64(1), int64(2)
	docker.StripEnv(want)
	wantJS, _ := json.Marshal(want)
	gotJS, _ := json.Marshal(full[0])
	if string(wantJS) != string(gotJS) {
		t.Errorf("default response changed:\n got %s\nwant %s", gotJS, wantJS)
	}

	// Summary: only the allowlisted fields, never Env (even with env=1).
	code, body = doReq(t, h, "GET", "/api/docker/containers?fields=summary&env=1&size=1", "", keyAdmin)
	var sum []map[string]any
	if err := json.Unmarshal(body, &sum); code != 200 || err != nil || len(sum) != 1 {
		t.Fatalf("summary: %d %v %q", code, err, body)
	}
	if !gotSize.Load() {
		t.Error("summary dropped size=1")
	}
	const wantSum = `{"AutoStart":true,"Config":{"Cmd":["/init"],"Image":"lscr.io/linuxserver/plex","Labels":{"a":"b"}},` +
		`"Created":"2026-01-02T03:04:05Z","HostConfig":{"NetworkMode":"br0","RestartPolicy":{"Name":"unless-stopped"}},` +
		`"Id":"abc123","Image":"sha256:img","Mounts":[{"Destination":"/config","Mode":"","RW":true,"Source":"/mnt/user/appdata/plex","Type":"bind"}],` +
		`"Name":"/plex","NetworkSettings":{"Networks":{"br0":{"Gateway":"192.168.1.1","GlobalIPv6Address":"","IPAddress":"192.168.1.50","IPPrefixLen":24,"MacAddress":"02:42:c0:a8:01:32"}},` +
		`"Ports":{"32400/tcp":[{"HostIp":"0.0.0.0","HostPort":"32400"}]}},"SizeRootFs":2,"SizeRw":1,` +
		`"State":{"Dead":false,"Error":"","ExitCode":0,"FinishedAt":"0001-01-01T00:00:00Z","Health":{"FailingStreak":0,"Status":"healthy"},` +
		`"OOMKilled":false,"Paused":false,"Restarting":false,"Running":true,"StartedAt":"2026-01-02T03:04:06.123456789Z","Status":"running"}}`
	gotSum, _ := json.Marshal(sum[0])
	if string(gotSum) != wantSum {
		t.Errorf("summary:\n got %s\nwant %s", gotSum, wantSum)
	}
	if strings.Contains(string(body), "secret") || strings.Contains(string(body), "GraphDriver") || strings.Contains(string(body), "big health output") {
		t.Errorf("summary leaks heavy or secret fields: %s", body)
	}

	// ?summary=1 is an alias.
	_, body = doReq(t, h, "GET", "/api/docker/containers?summary=1", "", keyAdmin)
	if strings.Contains(string(body), "GraphDriver") || !strings.Contains(string(body), `"AutoStart":true`) {
		t.Errorf("summary=1: %s", body)
	}

	// Unknown fields values fall back to the full documents.
	_, body = doReq(t, h, "GET", "/api/docker/containers?fields=bogus", "", keyAdmin)
	if !strings.Contains(string(body), "GraphDriver") {
		t.Errorf("fields=bogus should answer full documents: %s", body)
	}

	// Any of the protocol-2 parameters opts out of the legacy size default;
	// size=1 always asks for it.
	for q, want := range map[string]bool{
		"":                true,
		"?fields=summary": false,
		"?summary=1":      false,
		"?fields=bogus":   false,
		"?fields=":        false,
		"?env=1":          false,
		"?size=0":         false,
		"?size=1":         true,
		"?other=1":        true,
	} {
		gotSize.Store(!want)
		if code, body := doReq(t, h, "GET", "/api/docker/containers"+q, "", keyAdmin); code != 200 {
			t.Fatalf("%q: %d %s", q, code, body)
		}
		if gotSize.Load() != want {
			t.Errorf("%q: Size = %v, want %v", q, !want, want)
		}
	}
}

func TestContainerSummaryDoesNotAlias(t *testing.T) {
	c := inspectFixture()
	s := containerSummary(c)
	s["Config"].(map[string]any)["Image"] = "changed"
	s["State"].(map[string]any)["Status"] = "changed"
	if c["Config"].(map[string]any)["Image"] != "lscr.io/linuxserver/plex" || c["State"].(map[string]any)["Status"] != "running" {
		t.Error("containerSummary aliases the source maps")
	}
	// Missing sections are simply absent.
	if got := containerSummary(map[string]any{"Id": "x"}); len(got) != 1 || got["Id"] != "x" {
		t.Errorf("sparse input: %v", got)
	}
}

// updateCheckHeaders polls GET /api/docker/updates until the outcome header
// equals want (or fails after a deadline) and returns the response headers.
func updateCheckHeaders(t *testing.T, h http.Handler, want string) http.Header {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		req := httptest.NewRequest("GET", "/raidman/api/docker/updates", nil)
		req.Header.Set("x-api-key", keyAdmin)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != 200 {
			t.Fatalf("GET updates: %d %s", rec.Code, rec.Body.String())
		}
		if rec.Header().Get("X-Raidman-Update-Check") == want {
			return rec.Header()
		}
		if time.Now().After(deadline) {
			t.Fatalf("update check header = %q, want %q", rec.Header().Get("X-Raidman-Update-Check"), want)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func TestUpdateCheckOutcome(t *testing.T) {
	h := contractHandler(t)
	oldPoll, oldLimit := updateCheckPoll, docker.UpdateCheckTimeout
	t.Cleanup(func() { updateCheckPoll, docker.UpdateCheckTimeout = oldPoll, oldLimit })
	updateCheckPoll = 2 * time.Millisecond

	var running atomic.Bool
	triggerUpdateCheck = func(context.Context) (bool, error) {
		if running.Load() {
			return true, nil
		}
		running.Store(true)
		return false, nil
	}
	updateCheckRunning = running.Load

	// A finished check reads "done" with its start and finish times, and keeps
	// reading "done" on later polls (the app may poll late).
	docker.UpdateCheckTimeout = time.Hour
	before := time.Now().UTC().Truncate(time.Second)
	if code, body := doReq(t, h, "POST", "/api/docker/updates/check", "", keyAdmin); code != 200 || string(body) != "{\"started\":true}\n" {
		t.Fatalf("check: %d %s", code, body)
	}
	updateCheckHeaders(t, h, "running")
	running.Store(false)
	hdr := updateCheckHeaders(t, h, "done")
	started, err1 := time.Parse(time.RFC3339, hdr.Get("X-Raidman-Update-Check-Started"))
	finished, err2 := time.Parse(time.RFC3339, hdr.Get("X-Raidman-Update-Check-Finished"))
	if err1 != nil || err2 != nil || started.Before(before) || finished.Before(started) || hdr.Get("X-Raidman-Update-Check-Error") != "" {
		t.Errorf("done headers: %v", hdr)
	}
	time.Sleep(10 * time.Millisecond)
	updateCheckHeaders(t, h, "done")

	// A check that stops at the timeout reads "failed" + "timed out".
	docker.UpdateCheckTimeout = 0
	if code, _ := doReq(t, h, "POST", "/api/docker/updates/check", "", keyAdmin); code != 200 {
		t.Fatalf("second check: %d", code)
	}
	updateCheckHeaders(t, h, "running")
	running.Store(false)
	hdr = updateCheckHeaders(t, h, "failed")
	if hdr.Get("X-Raidman-Update-Check-Error") != updateCheckTimedOut || hdr.Get("X-Raidman-Update-Check-Finished") == "" {
		t.Errorf("failed headers: %v", hdr)
	}

	// A new check clears the previous outcome while it runs.
	docker.UpdateCheckTimeout = time.Hour
	if code, _ := doReq(t, h, "POST", "/api/docker/updates/check", "", keyAdmin); code != 200 {
		t.Fatalf("third check: %d", code)
	}
	hdr = updateCheckHeaders(t, h, "running")
	if hdr.Get("X-Raidman-Update-Check-Error") != "" || hdr.Get("X-Raidman-Update-Check-Finished") != "" {
		t.Errorf("running headers carry the old outcome: %v", hdr)
	}
	running.Store(false)
	updateCheckHeaders(t, h, "done")
}

// TestSettleUpdateCheckIgnoresSuperseded: a watcher of an older check must
// not settle the current one.
func TestSettleUpdateCheckIgnoresSuperseded(t *testing.T) {
	st := &updateCheckState
	st.mu.Lock()
	defer st.mu.Unlock()
	st.gen++
	cur := st.gen
	st.started, st.limit, st.finished, st.failed, st.msg = time.Now(), time.Hour, time.Time{}, false, ""
	notRunning := func() bool { return false }
	if !settleUpdateCheckLocked(cur-1, notRunning, time.Now()) || !st.finished.IsZero() {
		t.Fatal("stale generation settled the current check")
	}
	if settleUpdateCheckLocked(cur, func() bool { return true }, time.Now()) || !st.finished.IsZero() {
		t.Fatal("running check settled")
	}
	if !settleUpdateCheckLocked(cur, notRunning, time.Now()) || st.finished.IsZero() || st.failed {
		t.Fatalf("finished check not settled as done: %+v", st.finished)
	}
}
