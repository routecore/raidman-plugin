package api

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

// Cookies (the app's raw-key cookie and the raidman_session cookie) exist only
// for the VNC web view. Every other route and stream must ignore them, so a
// same-site page cannot drive the host terminal, power or docker exec.
func TestCookieAuthOnlyForVNC(t *testing.T) {
	a, _ := newTestApi(t)
	h, err := a.Handler()
	if err != nil {
		t.Fatal(err)
	}
	serve := func(method, path string, cookie *http.Cookie) int {
		r := httptest.NewRequest(method, path, strings.NewReader(`{"action":"reboot"}`))
		r.AddCookie(cookie)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, r)
		return rec.Code
	}
	// Mint a session the way the web view does.
	req := httptest.NewRequest(http.MethodGet, "/raidman/novnc/vnc.html", nil)
	req.Header.Set("x-api-key", keyAdmin)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	var sess *http.Cookie
	for _, c := range rec.Result().Cookies() {
		if c.Name == sessionCookieName {
			sess = c
		}
	}
	if sess == nil {
		t.Fatal("no session cookie")
	}
	cookies := map[string]*http.Cookie{
		"raw-key": {Name: "x-api-key", Value: keyAdmin},
		"session": {Name: sessionCookieName, Value: sess.Value},
	}
	for name, c := range cookies {
		for _, tc := range []struct{ method, path string }{
			{http.MethodPost, "/raidman/api/system/action"},
			{http.MethodGet, "/raidman/api/vms"},
			{http.MethodGet, "/raidman/api/docker/containers"},
			{http.MethodGet, "/raidman/api/health"},
			{http.MethodGet, "/raidman/connect?type=host"},
			{http.MethodGet, "/raidman/connect?type=docker&container=x"},
			{http.MethodGet, "/raidman/connect?type=vm-vnc&type=host"},
		} {
			if code := serve(tc.method, tc.path, c); code != http.StatusUnauthorized {
				t.Errorf("%s cookie on %s %s: got %d, want 401", name, tc.method, tc.path, code)
			}
		}
		// Allowed: noVNC assets and the vm-vnc stream (auth passes; the
		// plain GET then fails the WebSocket handshake with 400).
		if code := serve(http.MethodGet, "/raidman/novnc/vnc.html", c); code == http.StatusUnauthorized || code == http.StatusForbidden {
			t.Errorf("%s cookie rejected on /novnc/: %d", name, code)
		}
		if code := serve(http.MethodGet, "/raidman/connect?type=vm-vnc&vm=x", c); code == http.StatusUnauthorized || code == http.StatusForbidden {
			t.Errorf("%s cookie rejected on vm-vnc: %d", name, code)
		}
	}
}

func TestIsSafeOrigin(t *testing.T) {
	cases := []struct {
		host, xfh, origin, referer string
		want                       bool
	}{
		{"tower", "", "", "", true}, // native client
		{"tower", "", "http://tower", "", true},
		{"tower", "", "https://tower", "", true},
		{"tower", "", "http://TOWER", "", true},
		{"tower", "", "http://tower:8081", "", false}, // other web UI on the same host
		{"tower", "tower", "http://tower:8081", "", false},
		{"tower", "tower:8080", "http://tower:8080", "", true},
		{"tower", "tower:8080", "http://tower", "", false},
		{"tower", "tower:8080", "http://tower:8081", "", false},
		{"tower", "tower:443", "https://tower", "", true},
		{"tower", "", "http://localhost", "", false}, // loopback no longer special
		{"tower", "", "http://127.0.0.1", "", false},
		{"localhost", "localhost:8080", "http://localhost:8080", "", true},
		{"tower", "", "null", "", false},
		{"tower", "", "file://tower", "", false},
		{"tower", "", "http://evil.example", "", false},
		{"tower", "", "http://tower.evil.example", "", false},
		{"tower", "", "", "http://tower/raidman/novnc/vnc.html", true},
		{"tower", "", "", "http://evil.example/x", false},
		{"[fe80::1]", "[fe80::1]:8443", "https://[fe80::1]:8443", "", true},
		{"[fe80::1]", "", "http://[fe80::1]", "", true},
	}
	for _, c := range cases {
		r := httptest.NewRequest(http.MethodGet, "/x", nil)
		r.Host = c.host
		if c.xfh != "" {
			r.Header.Set("X-Forwarded-Host", c.xfh)
		}
		if c.origin != "" {
			r.Header.Set("Origin", c.origin)
		}
		if c.referer != "" {
			r.Header.Set("Referer", c.referer)
		}
		if got := isSafeOrigin(r); got != c.want {
			t.Errorf("host=%q xfh=%q origin=%q referer=%q: got %v want %v", c.host, c.xfh, c.origin, c.referer, got, c.want)
		}
	}
}

func TestStreamLimiter(t *testing.T) {
	l := newStreamLimiter()
	k1, k2 := [32]byte{1}, [32]byte{2}
	var rels []func()
	for i := 0; i < maxStreamsPerKey; i++ {
		rel, ok := l.acquire(k1)
		if !ok {
			t.Fatalf("slot %d refused", i)
		}
		rels = append(rels, rel)
	}
	if _, ok := l.acquire(k1); ok {
		t.Fatal("per-key limit not enforced")
	}
	rel2, ok := l.acquire(k2)
	if !ok {
		t.Fatal("other key blocked by first key's limit")
	}
	rel2()
	rels[0]()
	rels[0]() // double release is harmless
	if _, ok := l.acquire(k1); !ok {
		t.Fatal("released slot not reusable")
	}
	if l.total != maxStreamsPerKey {
		t.Fatalf("total=%d", l.total)
	}
}

func TestSessionsPerKeyCap(t *testing.T) {
	s := newSessionStore()
	other, err := s.create([32]byte{9})
	if err != nil {
		t.Fatal(err)
	}
	var first string
	for i := 0; i < 5*maxSessionsPerKey; i++ {
		id, err := s.create([32]byte{1})
		if err != nil {
			t.Fatal(err)
		}
		if i == 0 {
			first = id
		}
	}
	if _, ok := s.resolve(other); !ok {
		t.Fatal("one key's churn evicted another key's session")
	}
	if _, ok := s.resolve(first); ok {
		t.Fatal("oldest session of the churning key not evicted")
	}
	n := 0
	for _, e := range s.m {
		if e.keyHash == ([32]byte{1}) {
			n++
		}
	}
	if n != maxSessionsPerKey {
		t.Fatalf("key holds %d sessions, want %d", n, maxSessionsPerKey)
	}
}

func TestRequestBodyLimit(t *testing.T) {
	a, _ := newTestApi(t)
	h, err := a.Handler()
	if err != nil {
		t.Fatal(err)
	}
	body := `{"action":"` + strings.Repeat("x", maxBodyBytes+10) + `"}`
	r := httptest.NewRequest(http.MethodPost, "/raidman/api/array/action", strings.NewReader(body))
	r.Header.Set("x-api-key", keyAdmin)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("oversized body: got %d want 400", rec.Code)
	}
}

func TestVmIconRejectsDirectory(t *testing.T) {
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "win.png"), []byte("png"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(dir, "sub"), filepath.Join(dir, "link.png")); err != nil {
		t.Fatal(err)
	}
	old := vmIconDir
	vmIconDir = dir
	t.Cleanup(func() { vmIconDir = old })

	a, _ := newTestApi(t)
	h, _ := a.Handler()
	get := func(icon string) int {
		r := httptest.NewRequest(http.MethodGet, "/raidman/api/vm/icon?icon="+icon, nil)
		r.Header.Set("x-api-key", keyViewer)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, r)
		return rec.Code
	}
	if code := get("win.png"); code != http.StatusOK {
		t.Fatalf("regular icon: %d", code)
	}
	for _, icon := range []string{"sub", "link.png", "missing.png"} {
		if code := get(icon); code != http.StatusNotFound {
			t.Errorf("%s: got %d want 404", icon, code)
		}
	}
	for _, icon := range []string{"..", "../x", "%2e%2e%2fetc%2fhosts", ".hidden"} {
		if code := get(icon); code != http.StatusBadRequest {
			t.Errorf("%s: got %d want 400", icon, code)
		}
	}
}

// A long key name used to push the close reason past the 123-byte control
// frame limit, so the 1008 close frame was never sent.
func TestDepermissionedKeyClosesWith1008(t *testing.T) {
	if _, err := os.Stat("/var/local/emhttp/var.ini"); err == nil {
		t.Skip("running on an Unraid host")
	}
	a, dir := newTestApi(t)
	h, err := a.Handler()
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(h)
	defer srv.Close()
	defer a.Shutdown(t.Context())

	url := "ws" + strings.TrimPrefix(srv.URL, "http") + "/raidman/connect?type=array-status"
	c, _, err := websocket.DefaultDialer.Dial(url, http.Header{"x-api-key": {keyViewer}})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	long := strings.Repeat("very-long-key-name-", 20)
	js := `{"id":"id-viewer","key":"` + keyViewer + `","name":"` + long + `","roles":["GUEST"],"permissions":[]}`
	if err := os.WriteFile(filepath.Join(dir, "viewer.json"), []byte(js), 0o600); err != nil {
		t.Fatal(err)
	}
	// Force a different mtime/size so Reload re-parses.
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
			t.Fatalf("want close 1008, got %v", err)
		}
		if len(ce.Text) > maxCloseReason {
			t.Fatalf("reason too long: %d", len(ce.Text))
		}
		return
	}
}

// Attacker-chosen Origins must not grow the log limiter without bound.
func TestLogLimiterBounded(t *testing.T) {
	l := &logLimiter{last: map[string]time.Time{}, window: time.Minute}
	for i := 0; i < 5*logLimiterMax; i++ {
		l.allow(strings.Repeat("o", 300) + string(rune('a'+i%26)) + strings.Repeat("x", i%977))
	}
	if len(l.last) > logLimiterMax {
		t.Fatalf("limiter grew to %d entries", len(l.last))
	}
	for k := range l.last {
		if len(k) > 256 {
			t.Fatalf("unbounded key length %d", len(k))
		}
	}

	// Many foreign Origins from one client: one log key.
	a, _ := newTestApi(t)
	h, _ := a.Handler()
	before := len(securityLog.last)
	for i := 0; i < 50; i++ {
		r := httptest.NewRequest(http.MethodGet, "/raidman/novnc/vnc.html", nil)
		r.Header.Set("Origin", "http://evil"+strings.Repeat("x", i)+".example")
		r.Header.Set("X-Real-IP", "198.51.100.7")
		r.AddCookie(&http.Cookie{Name: sessionCookieName, Value: "whatever"})
		h.ServeHTTP(httptest.NewRecorder(), r)
	}
	if grown := len(securityLog.last) - before; grown > 1 {
		t.Fatalf("one client with 50 Origins added %d limiter keys", grown)
	}
}

// Log streams only need READ_ANY: client input must never reach their PTY.
// With input forwarded, the PTY line discipline would echo it back.
func TestLogStreamIgnoresInput(t *testing.T) {
	if _, err := os.Stat("/var/log/libvirt/qemu"); err == nil {
		t.Skip("running on a libvirt host")
	}
	if _, err := os.Stat("/usr/bin/tail"); err != nil {
		t.Skip("no tail")
	}
	a, _ := newTestApi(t)
	h, err := a.Handler()
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(h)
	defer srv.Close()
	defer a.Shutdown(t.Context())

	url := "ws" + strings.TrimPrefix(srv.URL, "http") + "/raidman/connect?type=vm-log&vm=raidman-no-such-vm"
	c, _, err := websocket.DefaultDialer.Dial(url, http.Header{"x-api-key": {keyViewer}})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	const marker = "raidman-injected-input"
	if err := c.WriteMessage(websocket.TextMessage, []byte(marker+"\r")); err != nil {
		t.Fatal(err)
	}
	var got strings.Builder
	deadline := time.Now().Add(1500 * time.Millisecond)
	for time.Now().Before(deadline) {
		c.SetReadDeadline(deadline)
		_, msg, err := c.ReadMessage()
		if err != nil {
			break
		}
		got.Write(msg)
	}
	if strings.Contains(got.String(), marker) {
		t.Fatalf("input reached the log PTY: %q", got.String())
	}
}

// The session cookie is Secure when nginx or a proxy/tunnel in front of it
// was reached over HTTPS (X-Raidman-Client-Proto from raidman.conf).
func TestSessionCookieSecureBehindProxy(t *testing.T) {
	a, _ := newTestApi(t)
	h, err := a.Handler()
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		hdr, val string
		want     bool
	}{{"", "", false}, {"X-Forwarded-Proto", "https", true}, {"X-Raidman-Client-Proto", "HTTPS", true}, {"X-Raidman-Client-Proto", "http", false}} {
		req := httptest.NewRequest(http.MethodGet, "/raidman/novnc/vnc.html", nil)
		req.Header.Set("x-api-key", keyAdmin)
		if tc.hdr != "" {
			req.Header.Set(tc.hdr, tc.val)
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		var got *http.Cookie
		for _, c := range rec.Result().Cookies() {
			if c.Name == sessionCookieName {
				got = c
			}
		}
		if got == nil || got.Secure != tc.want {
			t.Errorf("%s=%q: cookie %+v, want Secure=%v", tc.hdr, tc.val, got, tc.want)
		}
	}
}
