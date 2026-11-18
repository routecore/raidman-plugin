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

// TestStreamLargeMessageAndRevocation dials a real array-status stream
// (served from the dev fallback data on machines without /var/local/emhttp),
// checks that a 60 KiB client message (paste/clipboard size) does not kill the
// socket, and that deleting the key closes the open socket with 1008.
func TestStreamLargeMessageAndRevocation(t *testing.T) {
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
	hdr := http.Header{"x-api-key": {keyViewer}}
	c, resp, err := websocket.DefaultDialer.Dial(url, hdr)
	if err != nil {
		t.Fatalf("dial: %v (resp %v)", err, resp)
	}
	defer c.Close()

	c.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, msg, err := c.ReadMessage(); err != nil || !strings.Contains(string(msg), `"array"`) {
		t.Fatalf("first frame: %v %q", err, msg)
	}

	big := strings.Repeat("x", 60*1024)
	if err := c.WriteMessage(websocket.TextMessage, []byte(big)); err != nil {
		t.Fatal(err)
	}
	c.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, _, err := c.ReadMessage(); err != nil {
		t.Fatalf("socket died after 60KiB message: %v", err)
	}

	// Revoke the key: the socket must be closed with a policy violation.
	if err := os.Remove(filepath.Join(dir, "viewer.json")); err != nil {
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
			t.Fatalf("want close 1008 after revocation, got %v", err)
		}
		return
	}
}
