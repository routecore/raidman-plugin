package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/routecore/raidman-plugin/src/internal/service/files"
	"github.com/routecore/raidman-plugin/src/internal/service/httperr"
	"github.com/routecore/raidman-plugin/src/internal/service/memory"
	"github.com/routecore/raidman-plugin/src/internal/service/nut"
	"github.com/routecore/raidman-plugin/src/internal/service/plugins"
	"github.com/routecore/raidman-plugin/src/internal/service/smart"
)

// extrasFixtures fakes every feature-wave data source and points the file
// browser at a temp tree. Returns the temp /mnt/user/share path.
func extrasFixtures(t *testing.T) string {
	t.Helper()
	old := [8]any{listPlugins, checkPlugins, updatePlugin, removePlugin, getSmart, getMemory, getNut, pluginUpdateTO}
	oldFiles := [3]string{files.MntDir, files.BootDir, files.PoolsDir}
	t.Cleanup(func() {
		listPlugins = old[0].(func() ([]plugins.Plugin, error))
		checkPlugins = old[1].(func(context.Context) ([]plugins.Plugin, error))
		updatePlugin = old[2].(func(context.Context, string) (plugins.OpResult, error))
		removePlugin = old[3].(func(context.Context, string) (plugins.OpResult, error))
		getSmart = old[4].(func(context.Context, string) (smart.Report, error))
		getMemory = old[5].(func() (memory.Breakdown, error))
		getNut = old[6].(func(context.Context) nut.Status)
		files.MntDir, files.BootDir, files.PoolsDir = oldFiles[0], oldFiles[1], oldFiles[2]
	})
	list := []plugins.Plugin{{Name: "ca", File: "ca.plg", Version: "2026.01.01", UpdateAvailable: true, LatestVersion: "2026.02.01"}}
	listPlugins = func() ([]plugins.Plugin, error) { return list, nil }
	checkPlugins = func(context.Context) ([]plugins.Plugin, error) { return list, nil }
	updatePlugin = func(ctx context.Context, name string) (plugins.OpResult, error) {
		if _, ok := ctx.Deadline(); !ok {
			return plugins.OpResult{}, errors.New("update needs a deadline")
		}
		if name == "broken" {
			return plugins.OpResult{OK: false, Output: "plugin: download failed"}, nil
		}
		return plugins.OpResult{OK: true, Output: "plugin: updated " + name}, nil
	}
	removePlugin = func(_ context.Context, name string) (plugins.OpResult, error) {
		if name == "dynamix.system.temp" {
			return plugins.OpResult{}, httperr.New(http.StatusUnprocessableEntity, "system plugins cannot be removed")
		}
		return plugins.OpResult{OK: true, Output: "removed"}, nil
	}
	getSmart = func(_ context.Context, device string) (smart.Report, error) {
		if !smart.DeviceRe.MatchString(device) {
			return smart.Report{}, httperr.New(http.StatusBadRequest, "invalid device %q", device)
		}
		return smart.Report{Device: device, Standby: true, Attributes: []smart.Attribute{}}, nil
	}
	getMemory = func() (memory.Breakdown, error) {
		return memory.Breakdown{TotalBytes: 100, UsedBytes: 40, CachedBytes: 30}, nil
	}
	getNut = func(context.Context) nut.Status { return nut.Status{Devices: []nut.Device{}} }

	root := t.TempDir()
	files.MntDir = filepath.Join(root, "mnt")
	files.BootDir = filepath.Join(root, "boot")
	files.PoolsDir = filepath.Join(root, "boot/config/pools")
	share := filepath.Join(root, "mnt/user/share")
	os.MkdirAll(share, 0o755)
	os.MkdirAll(filepath.Join(root, "etc"), 0o755)
	os.WriteFile(filepath.Join(share, "movie.mp4"), []byte("0123456789"), 0o644)
	os.WriteFile(filepath.Join(root, "etc/shadow"), []byte("secret"), 0o644)
	os.Symlink(filepath.Join(root, "etc/shadow"), filepath.Join(share, "shadow"))
	return share
}

func TestExtrasPermissionMatrix(t *testing.T) {
	share := extrasFixtures(t)
	a, _ := newTestApi(t)
	h, err := a.Handler()
	if err != nil {
		t.Fatal(err)
	}
	q := url.QueryEscape
	cases := []v2Case{
		{"GET", "/api/plugins", "", 200, true, false, false},
		{"POST", "/api/plugins/check", "", 200, false, false, false},
		{"POST", "/api/plugins/update", `{"name":"ca"}`, 200, false, false, false},
		{"POST", "/api/plugins/remove", `{"name":"ca"}`, 200, false, false, false},
		{"GET", "/api/disks/smart?device=sdb", "", 200, true, false, false},
		{"GET", "/api/files/list?path=" + q(share), "", 200, false, false, false},
		{"GET", "/api/system/memory", "", 200, true, false, false},
		{"GET", "/api/ups/nut", "", 200, true, false, false},
	}
	for _, c := range cases {
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
			if code != want || !json.Valid(body) {
				t.Errorf("%s %s as %s: %d %s, want %d", c.method, c.path, who.name, code, body, want)
			}
		}
	}
	// Download is ADMIN only (raw bytes for admin, JSON errors otherwise).
	path := "/api/files/download?path=" + q(share+"/movie.mp4")
	if code, _ := doReq(t, h, "GET", path, "", keyViewer); code != http.StatusForbidden {
		t.Errorf("viewer download: %d", code)
	}
	if code, body := doReq(t, h, "GET", path, "", keyAdmin); code != 200 || string(body) != "0123456789" {
		t.Errorf("admin download: %d %q", code, body)
	}
}

func TestExtrasResponses(t *testing.T) {
	share := extrasFixtures(t)
	a, _ := newTestApi(t)
	h, _ := a.Handler()
	q := url.QueryEscape

	_, body := doReq(t, h, "GET", "/api/plugins", "", keyAdmin)
	if !strings.HasPrefix(string(body), `{"plugins":[{"name":"ca","file":"ca.plg","version":"2026.01.01","updateAvailable":true,"latestVersion":"2026.02.01"}]}`) {
		t.Errorf("plugins = %s", body)
	}
	code, body := doReq(t, h, "POST", "/api/plugins/update", `{"name":"broken"}`, keyAdmin)
	if code != 200 || string(body) != `{"ok":false,"output":"plugin: download failed","message":"plugin: download failed"}`+"\n" {
		t.Errorf("failed update: %d %s", code, body)
	}
	code, body = doReq(t, h, "POST", "/api/plugins/update", `{"name":"ca"}`, keyAdmin)
	if code != 200 || string(body) != `{"ok":true,"output":"plugin: updated ca"}`+"\n" {
		t.Errorf("update: %d %s", code, body)
	}
	for _, b := range []string{`{}`, `{"name":"  "}`, `nope`} {
		if code, _ := doReq(t, h, "POST", "/api/plugins/update", b, keyAdmin); code != http.StatusBadRequest {
			t.Errorf("update body %q: %d", b, code)
		}
	}
	if code, body := doReq(t, h, "POST", "/api/plugins/remove", `{"name":"dynamix.system.temp"}`, keyAdmin); code != http.StatusUnprocessableEntity || !strings.Contains(string(body), `"error":"system plugins cannot be removed"`) {
		t.Errorf("refused remove: %d %s", code, body)
	}
	if code, _ := doReq(t, h, "GET", "/api/disks/smart?device="+q("sda;reboot"), "", keyAdmin); code != http.StatusBadRequest {
		t.Errorf("bad device: %d", code)
	}
	_, body = doReq(t, h, "GET", "/api/disks/smart?device=sdb", "", keyAdmin)
	if string(body) != `{"device":"sdb","standby":true,"passed":null,"temperature":null,"powerOnHours":null,"attributes":[]}`+"\n" {
		t.Errorf("smart = %s", body)
	}
	_, body = doReq(t, h, "GET", "/api/system/memory", "", keyAdmin)
	if string(body) != `{"totalBytes":100,"usedBytes":40,"cachedBytes":30,"zfsArcBytes":null,"vmBytes":null,"dockerBytes":null}`+"\n" {
		t.Errorf("memory = %s", body)
	}
	_, body = doReq(t, h, "GET", "/api/ups/nut", "", keyAdmin)
	if string(body) != `{"available":false,"devices":[]}`+"\n" {
		t.Errorf("nut = %s", body)
	}

	// Files: listing shape, escapes and missing paths.
	_, body = doReq(t, h, "GET", "/api/files/list?path="+q(share), "", keyAdmin)
	var l struct {
		Path    string
		Parent  *string
		Entries []map[string]any
	}
	if err := json.Unmarshal(body, &l); err != nil || len(l.Entries) != 2 || l.Parent == nil {
		t.Fatalf("list: %v %s", err, body)
	}
	for path, status := range map[string]int{
		share + "/shadow":       http.StatusForbidden,
		share + "/../../../etc": http.StatusForbidden,
		"/etc":                  http.StatusForbidden,
		"":                      http.StatusBadRequest,
		share + "/missing":      http.StatusUnprocessableEntity,
	} {
		for _, ep := range []string{"/api/files/list", "/api/files/download"} {
			code, body := doReq(t, h, "GET", ep+"?path="+q(path), "", keyAdmin)
			if code != status || !strings.Contains(string(body), `"error"`) {
				t.Errorf("%s %q: %d %s, want %d", ep, path, code, body, status)
			}
		}
	}

	// Download headers and ranges.
	req := httptest.NewRequest("GET", "/raidman/api/files/download?path="+q(share+"/movie.mp4"), nil)
	req.Header.Set("x-api-key", keyAdmin)
	req.Header.Set("Range", "bytes=2-4")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusPartialContent || rec.Body.String() != "234" ||
		rec.Header().Get("Content-Type") != "video/mp4" ||
		rec.Header().Get("Content-Disposition") != `attachment; filename=movie.mp4` ||
		rec.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Errorf("range download: %d %q %v", rec.Code, rec.Body.String(), rec.Header())
	}
}

// Service errors keep their machine-readable code (SMART 501
// smart_unsupported), and an over-long file path is a 400 JSON error that
// does not echo the path.
func TestExtrasErrorCodesAndLongPaths(t *testing.T) {
	share := extrasFixtures(t)
	a, _ := newTestApi(t)
	h, _ := a.Handler()

	getSmart = func(context.Context, string) (smart.Report, error) {
		return smart.Report{}, &httperr.Error{Status: http.StatusNotImplemented, Code: httperr.CodeSmartUnsupported,
			Msg: "SMART is not available for this device (Unknown USB bridge)"}
	}
	code, body := doReq(t, h, "GET", "/api/disks/smart?device=sdf", "", keyAdmin)
	var e struct{ Error, Code string }
	if code != http.StatusNotImplemented || json.Unmarshal(body, &e) != nil || e.Code != httperr.CodeSmartUnsupported || e.Error == "" {
		t.Errorf("unsupported SMART: %d %s, want 501 with code %q", code, body, httperr.CodeSmartUnsupported)
	}

	long := share + "/" + strings.Repeat("a", 300)
	for _, ep := range []string{"/api/files/list", "/api/files/download"} {
		code, body := doReq(t, h, "GET", ep+"?path="+url.QueryEscape(long), "", keyAdmin)
		if code != http.StatusBadRequest || !json.Valid(body) || strings.Contains(string(body), "aaaa") {
			t.Errorf("%s with a 300-byte name: %d %s, want a 400 JSON error without the path", ep, code, body)
		}
	}
}
