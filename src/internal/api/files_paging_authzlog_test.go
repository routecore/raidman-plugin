package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestFilesListPagingParams(t *testing.T) {
	share := extrasFixtures(t)
	for i := 0; i < 5; i++ {
		os.WriteFile(filepath.Join(share, fmt.Sprintf("f%d.txt", i)), []byte("x"), 0o644)
	}
	a, _ := newTestApi(t)
	h, err := a.Handler()
	if err != nil {
		t.Fatal(err)
	}
	q := url.QueryEscape(share)

	// Without paging params: the old shape (entries, truncated omitted when
	// everything fits).
	code, body := doReq(t, h, "GET", "/api/files/list?path="+q, "", keyAdmin)
	var l struct {
		Entries   []map[string]any `json:"entries"`
		Truncated bool             `json:"truncated"`
		Total     int              `json:"total"`
		Next      *int             `json:"next"`
	}
	if code != http.StatusOK || json.Unmarshal(body, &l) != nil || len(l.Entries) != 7 || l.Truncated || l.Next != nil || l.Total != 7 {
		t.Fatalf("unpaged: %d %s", code, body)
	}

	code, body = doReq(t, h, "GET", "/api/files/list?path="+q+"&offset=2&limit=3", "", keyAdmin)
	l.Next, l.Truncated = nil, false
	if code != http.StatusOK || json.Unmarshal(body, &l) != nil || len(l.Entries) != 3 || !l.Truncated || l.Next == nil || *l.Next != 5 {
		t.Fatalf("paged: %d %s", code, body)
	}

	for _, bad := range []string{"&offset=-1", "&offset=x", "&limit=0", "&limit=5001", "&limit=abc"} {
		code, body := doReq(t, h, "GET", "/api/files/list?path="+q+bad, "", keyAdmin)
		if code != http.StatusBadRequest || !strings.Contains(string(body), `"error"`) {
			t.Errorf("%s: %d %s, want 400", bad, code, body)
		}
	}
}

func TestFilesSensitiveBootPathsForbidden(t *testing.T) {
	share := extrasFixtures(t)
	boot := filepath.Join(filepath.Dir(filepath.Dir(filepath.Dir(share))), "boot")
	os.MkdirAll(filepath.Join(boot, "config/ssh"), 0o755)
	os.WriteFile(filepath.Join(boot, "config/shadow"), []byte("root:$6$"), 0o600)
	os.WriteFile(filepath.Join(boot, "config/ssh/ssh_host_rsa_key"), []byte("PRIVATE"), 0o600)
	a, _ := newTestApi(t)
	h, err := a.Handler()
	if err != nil {
		t.Fatal(err)
	}
	for ep, p := range map[string]string{
		"/api/files/download": filepath.Join(boot, "config/shadow"),
		"/api/files/list":     filepath.Join(boot, "config/ssh"),
	} {
		code, body := doReq(t, h, "GET", ep+"?path="+url.QueryEscape(p), "", keyAdmin)
		if code != http.StatusForbidden || bytes.Contains(body, []byte("PRIVATE")) || bytes.Contains(body, []byte("$6$")) {
			t.Errorf("%s %s: %d %s, want 403", ep, p, code, body)
		}
	}
	code, _ := doReq(t, h, "GET", "/api/files/download?path="+url.QueryEscape(filepath.Join(boot, "config/ssh/ssh_host_rsa_key")), "", keyAdmin)
	if code != http.StatusForbidden {
		t.Errorf("file in denied dir: %d, want 403", code)
	}
}

// An attacker-chosen path under a prefix route cannot forge log lines and is
// truncated.
func TestAuthzLogsQuotedTruncatedPath(t *testing.T) {
	a, _ := newTestApi(t)
	h, err := a.Handler()
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	old := log.Writer()
	log.SetOutput(&buf)
	defer log.SetOutput(old)

	path := "/raidman/novnc/x%0A2026/11/21%2010:00:00%20[AUDIT]%20forged" + strings.Repeat("A", 1000)
	req := httptest.NewRequest("GET", path, nil)
	req.Header.Set("x-api-key", "bogus")
	req.Header.Set("X-Real-IP", "198.51.100.77") // unique: the log limiter is process-global
	h.ServeHTTP(httptest.NewRecorder(), req)

	out := buf.String()
	if !strings.Contains(out, "Invalid API key") {
		t.Fatalf("no security log line: %q", out)
	}
	if strings.Contains(out, "\n2026/11/21 10:00:00 [AUDIT]") || strings.Count(out, "\n") != 1 {
		t.Fatalf("forged line in log: %q", out)
	}
	if !strings.Contains(out, `\n2026/11/21`) || strings.Contains(out, strings.Repeat("A", logPathMax)) {
		t.Fatalf("path not quoted/truncated: %q", out)
	}
}
