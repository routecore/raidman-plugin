package api

import (
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/routecore/raidman-plugin/src/internal/domain"
	"github.com/routecore/raidman-plugin/src/internal/service/auth"
)

const (
	keyAdmin    = "admin-secret-0001"
	keyViewer   = "viewer-secret-0001"
	keyGuest    = "guest-secret-0001"
	keyPermOnly = "perm-secret-0001"
	keyVMOps    = "vmops-secret-0001"
	keyDockerRO = "dockerro-secret-0001"
)

var testKeyFiles = map[string]string{
	"admin.json":  `{"id":"id-admin","key":"` + keyAdmin + `","name":"admin","roles":["ADMIN"],"permissions":[]}`,
	"viewer.json": `{"id":"id-viewer","key":"` + keyViewer + `","name":"viewer","roles":["VIEWER"],"permissions":[]}`,
	"guest.json":  `{"id":"id-guest","key":"` + keyGuest + `","name":"guest","roles":["GUEST"],"permissions":[]}`,
	"perm.json":   `{"id":"id-perm","key":"` + keyPermOnly + `","name":"perm","roles":[],"permissions":[{"resource":"DOCKER","actions":["READ_ANY","UPDATE_ANY"]},{"resource":"ARRAY","actions":["READ_ANY"]}]}`,
	"vmops.json":  `{"id":"id-vmops","key":"` + keyVMOps + `","name":"vmops","roles":[],"permissions":[{"resource":"VMS","actions":["update"]}]}`,
	// permission-only DOCKER:READ_ANY key
	"dockerro.json": `{"id":"id-dockerro","key":"` + keyDockerRO + `","name":"dockerro","roles":[],"permissions":[{"resource":"DOCKER","actions":["READ_ANY"]}]}`,
}

func newTestApi(t *testing.T) (*Api, string) {
	t.Helper()
	dir := t.TempDir()
	for name, js := range testKeyFiles {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(js), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	store := auth.NewStore(dir, nil)
	store.Reload()
	a := Create(&domain.Context{}, store)
	a.hostTerminalEnabled = func() bool { return true }
	return a, dir
}

// contractRoutes is contract §4 ("Existing routes" and "New routes"). Adding a route to the
// table without adding it here (or vice versa) fails the test.
var contractRoutes = map[string]Requirement{
	"/api/vm/info":           Perm(auth.ResourceVMs, auth.ActionReadAny),
	"/api/vms":               Perm(auth.ResourceVMs, auth.ActionReadAny),
	"/api/vm/autostart":      Perm(auth.ResourceVMs, auth.ActionUpdateAny),
	"/api/vm/action":         Perm(auth.ResourceVMs, auth.ActionUpdateAny),
	"/api/vm/icon":           AnyKey(),
	"/novnc/":                AnyKey(),
	"/api/array/status":      Perm(auth.ResourceArray, auth.ActionReadAny),
	"/api/array/history":     Perm(auth.ResourceArray, auth.ActionReadAny),
	"/api/array/action":      Perm(auth.ResourceArray, auth.ActionUpdateAny),
	"/api/docker/containers": Perm(auth.ResourceDocker, auth.ActionReadAny),
	"/api/docker/action":     Perm(auth.ResourceDocker, auth.ActionUpdateAny),
	"/api/system/action":     AdminOnly(),
	"/connect":               AnyKey(), // per-type checks below

	// protocol 2
	"/api/health":                          AnyKey(),
	"/api/docker/updates":                  Perm(auth.ResourceDocker, auth.ActionReadAny),
	"/api/docker/updates/check":            Perm(auth.ResourceDocker, auth.ActionUpdateAny),
	"/api/docker/meta":                     Perm(auth.ResourceDocker, auth.ActionReadAny),
	"/api/disks/state":                     Perm(auth.ResourceArray, auth.ActionReadAny),
	"/api/array/encryption":                Perm(auth.ResourceArray, auth.ActionReadAny),
	"/api/array/encryption/keyfile/delete": Perm(auth.ResourceArray, auth.ActionUpdateAny),
	"/api/disks/spin":                      Perm(auth.ResourceArray, auth.ActionUpdateAny),
	"/api/mover/status":                    Perm(auth.ResourceArray, auth.ActionReadAny),
	"/api/mover/action":                    Perm(auth.ResourceArray, auth.ActionUpdateAny),
	"/api/parity/action":                   Perm(auth.ResourceArray, auth.ActionUpdateAny),

	// feature wave
	"/api/plugins":        Perm(auth.ResourceConfig, auth.ActionReadAny),
	"/api/plugins/check":  Perm(auth.ResourceConfig, auth.ActionUpdateAny),
	"/api/plugins/update": Perm(auth.ResourceConfig, auth.ActionUpdateAny),
	"/api/plugins/remove": AdminOnly(),
	"/api/disks/smart":    Perm(resourceDisk, auth.ActionReadAny),
	"/api/files/list":     AdminOnly(),
	"/api/files/download": AdminOnly(),
	"/api/system/memory":  Perm(auth.ResourceInfo, auth.ActionReadAny),
	"/api/ups/nut":        Perm(auth.ResourceConfig, auth.ActionReadAny),
}

var contractStreams = map[string]Requirement{
	"vm-vnc":       Perm(auth.ResourceVMs, auth.ActionUpdateAny),
	"vm":           AdminOnly(), // serial console is a shell: ADMIN only
	"vm-log":       Perm(auth.ResourceVMs, auth.ActionReadAny),
	"array-status": Perm(auth.ResourceArray, auth.ActionReadAny),
	"docker-stats": Perm(auth.ResourceDocker, auth.ActionReadAny),
	"docker-log":   Perm(auth.ResourceDocker, auth.ActionReadAny),
	"docker":       AdminOnly(), // docker exec is a shell: ADMIN only
	"host":         AdminOnly(),
}

func TestRouteTableMatchesContract(t *testing.T) {
	a, _ := newTestApi(t)
	seen := map[string]bool{}
	for _, rt := range a.routes() {
		want, ok := contractRoutes[rt.Path]
		if !ok {
			t.Errorf("route %s is not in the contract table", rt.Path)
			continue
		}
		if seen[rt.Path] {
			t.Errorf("route %s registered twice", rt.Path)
		}
		seen[rt.Path] = true
		if rt.Req != want {
			t.Errorf("route %s requires %s, contract says %s", rt.Path, rt.Req, want)
		}
	}
	for p := range contractRoutes {
		if !seen[p] {
			t.Errorf("contract route %s missing from table", p)
		}
	}
	ws := a.wsRoutes()
	for typ, want := range contractStreams {
		got, ok := ws[typ]
		if !ok {
			t.Errorf("stream %s missing", typ)
			continue
		}
		if got.Req != want {
			t.Errorf("stream %s requires %s, contract says %s", typ, got.Req, want)
		}
		if got.ReadLimit < 64*1024 {
			t.Errorf("stream %s read limit %d < 64KiB", typ, got.ReadLimit)
		}
	}
	for typ := range ws {
		if _, ok := contractStreams[typ]; !ok {
			t.Errorf("stream %s is not in the contract table", typ)
		}
	}
}

func TestRegisterRejectsUndeclaredRequirement(t *testing.T) {
	a, _ := newTestApi(t)
	mux := http.NewServeMux()
	err := a.register(mux, []route{{Path: "/api/x", Handler: func(http.ResponseWriter, *http.Request, *auth.Key, authSource) {}}})
	if err == nil {
		t.Fatal("route without requirement must be rejected")
	}
	if (Requirement{}).Allows(&auth.Key{}) {
		t.Fatal("zero requirement must deny")
	}
	if Perm("", "").Valid() {
		t.Fatal("empty permission must be invalid")
	}
}

// stubRoutes replaces every handler with one that answers 204, so the matrix
// test exercises only authentication + authorization.
func stubRoutes(a *Api) []route {
	rts := a.routes()
	for i := range rts {
		rts[i].Handler = func(w http.ResponseWriter, _ *http.Request, _ *auth.Key, _ authSource) {
			w.WriteHeader(http.StatusNoContent)
		}
	}
	return rts
}

func TestAuthorizationMatrix(t *testing.T) {
	a, _ := newTestApi(t)
	mux := http.NewServeMux()
	if err := a.register(mux, stubRoutes(a)); err != nil {
		t.Fatal(err)
	}
	keys := map[string]string{
		"admin": keyAdmin, "viewer": keyViewer, "guest": keyGuest,
		"perm": keyPermOnly, "vmops": keyVMOps, "dockerro": keyDockerRO, "none": "", "bogus": "not-a-key",
	}
	// key name -> set of routes it may use
	allowed := map[string]map[string]bool{
		"admin": nil, // all
		"viewer": set("/api/vm/info", "/api/vms", "/api/vm/icon", "/novnc/", "/api/array/status",
			"/api/array/history", "/api/docker/containers", "/connect",
			"/api/health", "/api/docker/updates", "/api/docker/meta", "/api/disks/state", "/api/array/encryption", "/api/mover/status",
			"/api/plugins", "/api/disks/smart", "/api/system/memory", "/api/ups/nut"),
		"guest": set("/api/vm/icon", "/novnc/", "/connect", "/api/health"),
		"perm": set("/api/vm/icon", "/novnc/", "/api/array/status", "/api/array/history",
			"/api/docker/containers", "/api/docker/action", "/connect",
			"/api/health", "/api/docker/updates", "/api/docker/updates/check", "/api/docker/meta",
			"/api/disks/state", "/api/array/encryption", "/api/mover/status"),
		"vmops": set("/api/vm/icon", "/novnc/", "/api/vm/autostart", "/api/vm/action", "/connect", "/api/health"),
		"dockerro": set("/api/vm/icon", "/novnc/", "/connect", "/api/health",
			"/api/docker/containers", "/api/docker/updates", "/api/docker/meta"),
	}
	for name, secret := range keys {
		for _, rt := range a.routes() {
			method := http.MethodGet
			if rt.Methods != nil {
				method = rt.Methods[0]
			}
			req := httptest.NewRequest(method, "/raidman"+rt.Path, nil)
			if secret != "" {
				req.Header.Set("x-api-key", secret)
			}
			rec := httptest.NewRecorder()
			mux.ServeHTTP(rec, stripPrefix(req))
			var want int
			switch {
			case name == "none" || name == "bogus":
				want = http.StatusUnauthorized
			case name == "admin" || allowed[name][rt.Path]:
				want = http.StatusNoContent
			default:
				want = http.StatusForbidden
			}
			if rec.Code != want {
				t.Errorf("%s %s with %s key: got %d, want %d", method, rt.Path, name, rec.Code, want)
			}
		}
	}
}

func set(items ...string) map[string]bool {
	m := map[string]bool{}
	for _, i := range items {
		m[i] = true
	}
	return m
}

func stripPrefix(r *http.Request) *http.Request {
	r.URL.Path = strings.TrimPrefix(r.URL.Path, "/raidman")
	return r
}

func TestMethodCheckedAfterAuth(t *testing.T) {
	a, _ := newTestApi(t)
	h, err := a.Handler()
	if err != nil {
		t.Fatal(err)
	}
	// No key: 401 even with the wrong method.
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/raidman/api/system/action", nil))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("got %d", rec.Code)
	}
	// Admin with GET: 405.
	req := httptest.NewRequest(http.MethodGet, "/raidman/api/system/action", nil)
	req.Header.Set("x-api-key", keyAdmin)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("got %d", rec.Code)
	}
	// Admin POST with invalid action never reaches the system service.
	req = httptest.NewRequest(http.MethodPost, "/raidman/api/system/action", strings.NewReader(`{"action":"format"}`))
	req.Header.Set("x-api-key", keyAdmin)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("got %d", rec.Code)
	}
}

func TestConnectPerTypeAuthorization(t *testing.T) {
	a, _ := newTestApi(t)
	h, err := a.Handler()
	if err != nil {
		t.Fatal(err)
	}
	do := func(secret, typ string) (int, string) {
		req := httptest.NewRequest(http.MethodGet, "/raidman/connect?type="+typ, nil)
		if secret != "" {
			req.Header.Set("x-api-key", secret)
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		b, _ := io.ReadAll(rec.Body)
		return rec.Code, string(b)
	}

	// Protocol-1 probe semantics: no key -> 401, valid key + unknown type -> 400.
	if code, _ := do("", ""); code != http.StatusUnauthorized {
		t.Fatalf("probe without key: %d", code)
	}
	if code, body := do(keyGuest, ""); code != http.StatusBadRequest || !strings.Contains(body, "Unknown connection type") {
		t.Fatalf("probe with key: %d %q", code, body)
	}

	keys := map[string]string{"admin": keyAdmin, "viewer": keyViewer, "guest": keyGuest, "perm": keyPermOnly, "vmops": keyVMOps, "dockerro": keyDockerRO}
	allowed := map[string]map[string]bool{
		"admin":    nil,
		"viewer":   set("vm-log", "array-status", "docker-stats", "docker-log"),
		"guest":    set(),
		"perm":     set("array-status", "docker-stats", "docker-log"),
		"vmops":    set("vm-vnc"),
		"dockerro": set("docker-stats", "docker-log"),
	}
	for name, secret := range keys {
		for typ := range contractStreams {
			code, body := do(secret, typ)
			if name == "admin" || allowed[name][typ] {
				// Authorized: the request reaches the websocket upgrade,
				// which fails because this is not a websocket handshake.
				if code != http.StatusBadRequest || strings.Contains(body, "Unknown connection type") {
					t.Errorf("%s %s: got %d %q, want upgrade failure", name, typ, code, body)
				}
			} else if code != http.StatusForbidden {
				t.Errorf("%s %s: got %d, want 403", name, typ, code)
			}
		}
	}
}

func TestNoVNCSessionCookie(t *testing.T) {
	a, dir := newTestApi(t)
	h, err := a.Handler()
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodGet, "/raidman/novnc/vnc.html", nil)
	req.Header.Set("x-api-key", keyViewer)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code == http.StatusUnauthorized || rec.Code == http.StatusForbidden {
		t.Fatalf("header auth failed: %d", rec.Code)
	}
	var sess *http.Cookie
	for _, c := range rec.Result().Cookies() {
		if c.Name == sessionCookieName {
			sess = c
		}
	}
	if sess == nil {
		t.Fatal("no session cookie set")
	}
	if strings.Contains(sess.Value, keyViewer) || !sess.HttpOnly {
		t.Fatalf("session cookie must be opaque and HttpOnly: %+v", sess)
	}

	withCookie := func(origin string) int {
		r := httptest.NewRequest(http.MethodGet, "/raidman/novnc/core/rfb.js", nil)
		r.AddCookie(&http.Cookie{Name: sessionCookieName, Value: sess.Value})
		if origin != "" {
			r.Header.Set("Origin", origin)
		}
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, r)
		return rr.Code
	}
	if code := withCookie(""); code == http.StatusUnauthorized {
		t.Fatal("session cookie not accepted")
	}
	if code := withCookie("https://evil.example"); code != http.StatusUnauthorized {
		t.Fatalf("cross-origin cookie accepted: %d", code)
	}

	// A raw key in raidman_session (old plugin format) is not a session.
	r := httptest.NewRequest(http.MethodGet, "/raidman/novnc/vnc.html", nil)
	r.AddCookie(&http.Cookie{Name: sessionCookieName, Value: keyViewer})
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, r)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("raw key accepted as session: %d", rr.Code)
	}

	// Revoking the key kills the session.
	os.Remove(filepath.Join(dir, "viewer.json"))
	a.keys.Reload()
	if code := withCookie(""); code != http.StatusUnauthorized {
		t.Fatalf("session survived key revocation: %d", code)
	}
}

func TestSessionExpiry(t *testing.T) {
	s := newSessionStore()
	now := time.Now()
	s.now = func() time.Time { return now }
	id, err := s.create([32]byte{1})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := s.resolve(id); !ok {
		t.Fatal("fresh session not found")
	}
	now = now.Add(sessionTTL + time.Second)
	if _, ok := s.resolve(id); ok {
		t.Fatal("expired session resolved")
	}
	if _, ok := s.resolve("nope"); ok {
		t.Fatal("unknown session resolved")
	}
}

func TestNormalizeContainerRef(t *testing.T) {
	ok := map[string]string{
		"plex":                    "plex",
		"/plex":                   "plex",
		"binhex-qbittorrentvpn":   "binhex-qbittorrentvpn",
		"a1b2c3d4e5f6":            "a1b2c3d4e5f6",
		"srv123:abcdef0123456789": "abcdef0123456789",
		"1f2e3d:4c5b:deadbeef":    "deadbeef",
		"  my_app.1  ":            "my_app.1",
	}
	for in, want := range ok {
		got, err := normalizeContainerRef(in)
		if err != nil || got != want {
			t.Errorf("normalizeContainerRef(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	for _, in := range []string{"", "-it", "--privileged", "srv:-u0", "a b", "x;rm -rf /", "a/b", "srv:", "é"} {
		if got, err := normalizeContainerRef(in); err == nil {
			t.Errorf("normalizeContainerRef(%q) = %q, want error", in, got)
		}
	}
}

func TestValidateVMRef(t *testing.T) {
	for _, in := range []string{"Windows 11", "Ubuntu (dev)", "Home Assistant", "Ünïcødé VM 🚀", "vm-1", "0d5f0a7e-1c2b-4d3e-8f9a-0b1c2d3e4f5a"} {
		if err := validateVMRef(in); err != nil {
			t.Errorf("validateVMRef(%q) = %v", in, err)
		}
	}
	for _, in := range []string{"", "-c", "--help", "a/b", "../etc", "line\nbreak", "nul\x00", "bad\xff", strings.Repeat("x", 600)} {
		if err := validateVMRef(in); err == nil {
			t.Errorf("validateVMRef(%q) accepted", in)
		}
	}
}

func TestVMLogPath(t *testing.T) {
	if p, ok := vmLogPath("Windows 11"); !ok || p != "/var/log/libvirt/qemu/Windows 11.log" {
		t.Fatalf("got %q %v", p, ok)
	}
	for _, in := range []string{"", "..", ".", "a/b", "../../etc/passwd"} {
		if p, ok := vmLogPath(in); ok {
			t.Errorf("vmLogPath(%q) = %q accepted", in, p)
		}
	}
}

func TestIconName(t *testing.T) {
	for _, in := range []string{"windows11.png", "ubuntu.png", "default_icon.png"} {
		if !validIconName(in) {
			t.Errorf("%q rejected", in)
		}
	}
	for _, in := range []string{"", ".", "..", "../x.png", "a/b.png", "-x.png", "a..png"} {
		if validIconName(in) {
			t.Errorf("%q accepted", in)
		}
	}
}
