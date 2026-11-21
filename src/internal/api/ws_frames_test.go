package api

import (
	"bytes"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/gorilla/websocket"
)

func TestUTF8SafeLen(t *testing.T) {
	euro := []byte("€")  // 3 bytes
	smile := []byte("😀") // 4 bytes
	for _, tc := range []struct {
		name string
		in   []byte
		want int
	}{
		{"empty", nil, 0},
		{"ascii", []byte("abc"), 3},
		{"complete 3-byte", append([]byte("a"), euro...), 4},
		{"complete 4-byte", append([]byte("a"), smile...), 5},
		{"1 of 3", append([]byte("a"), euro[:1]...), 1},
		{"2 of 3", append([]byte("a"), euro[:2]...), 1},
		{"3 of 4", append([]byte("ab"), smile[:3]...), 2},
		{"lone lead byte", euro[:1], 0},
		{"invalid continuation run", []byte{'a', 0x80, 0x80, 0x80}, 4},
		{"invalid lead", []byte{'a', 0xff}, 2},
		{"latin-1 é", []byte{'a', 0xe9}, 1}, // looks like a 3-byte lead: held until next read or EOF
	} {
		if got := utf8SafeLen(tc.in); got != tc.want {
			t.Errorf("%s: utf8SafeLen(% x) = %d, want %d", tc.name, tc.in, got, tc.want)
		}
	}
}

// Feeding any byte stream through utf8SafeLen in arbitrary chunks (as the PTY
// loop does) reassembles it exactly, and every frame of valid UTF-8 input is
// valid UTF-8 on its own.
func TestUTF8SafeLenChunking(t *testing.T) {
	src := []byte(strings.Repeat("aé€😀ğ中", 200))
	for chunk := 1; chunk <= 9; chunk++ {
		var out []byte
		buf := make([]byte, 64)
		pending := 0
		for off := 0; off < len(src) || pending > 0; {
			n := copy(buf[pending:pending+min(chunk, len(buf)-pending)], src[off:])
			off += n
			n += pending
			send := utf8SafeLen(buf[:n])
			if off >= len(src) {
				send = n // EOF flush
			}
			frame := buf[:send]
			if !utf8.Valid(frame) {
				t.Fatalf("chunk %d: invalid frame % x", chunk, frame)
			}
			out = append(out, frame...)
			pending = copy(buf, buf[send:n])
		}
		if !bytes.Equal(out, src) {
			t.Fatalf("chunk %d: output differs from input", chunk)
		}
	}
}

// End to end: heavy multi-byte output from a real shell arrives as frames
// that are each valid UTF-8.
func TestPtyFramesAreValidUTF8(t *testing.T) {
	a, _ := newTestApi(t)
	base := ptyTestServer(t, a)
	c, _ := startShell(t, base)
	// "é€😀ğ" written as octal escapes: the typed line stays ASCII (readline
	// in the C locale would mangle non-ASCII input) and short.
	cmd := `s=$(printf '\303\251\342\202\254\360\237\230\200\304\237%.0s' $(seq 1 4000)); printf '%s\nDONE-%s\n' "$s" $((6*7))` + "\n"
	if err := c.WriteMessage(websocket.TextMessage, []byte(cmd)); err != nil {
		t.Fatal(err)
	}
	var out strings.Builder
	frames := 0
	deadline := time.Now().Add(15 * time.Second)
	for !strings.Contains(out.String(), "DONE-42") {
		c.SetReadDeadline(deadline)
		_, msg, err := c.ReadMessage()
		if err != nil {
			t.Fatalf("read: %v (after %d frames) %q", err, frames, out.String()[max(0, out.Len()-600):])
		}
		frames++
		if !utf8.Valid(msg) {
			t.Fatalf("frame %d is not valid UTF-8 (% x ...)", frames, msg[:min(len(msg), 16)])
		}
		out.Write(msg)
	}
	if got := strings.Count(out.String(), "é€😀ğ"); got < 4000 {
		t.Fatalf("got %d repetitions in %d frames, want >= 4000", got, frames)
	}
}

// The session cookie slides while used and still ends at the absolute cap;
// an idle session expires after sessionIdleTTL.
func TestSessionSlidingExpiry(t *testing.T) {
	s := newSessionStore()
	start := time.Now()
	now := start
	s.now = func() time.Time { return now }
	id, err := s.create([32]byte{1})
	if err != nil {
		t.Fatal(err)
	}
	step := sessionIdleTTL - time.Minute
	for now.Add(step).Before(start.Add(sessionTTL)) {
		now = now.Add(step)
		if _, ok := s.resolve(id); !ok {
			t.Fatalf("session in use expired after %v", now.Sub(start))
		}
	}
	now = start.Add(sessionTTL + time.Second)
	if _, ok := s.resolve(id); ok {
		t.Fatal("session outlived its absolute lifetime")
	}

	idle, _ := s.create([32]byte{2})
	now = now.Add(sessionIdleTTL + time.Second)
	if _, ok := s.resolve(idle); ok {
		t.Fatal("idle session did not expire")
	}
}

// SMART follows upstream: DISK:READ_ANY, not ARRAY:READ_ANY.
func TestSmartRequiresDiskRead(t *testing.T) {
	a, dir := newTestApi(t)
	const keyDisk, keyArray = "disk-secret-0001", "array-secret-0001"
	files := map[string]string{
		"disk.json":  `{"id":"id-disk","key":"` + keyDisk + `","name":"disk","roles":[],"permissions":[{"resource":"DISK","actions":["READ_ANY"]}]}`,
		"array.json": `{"id":"id-array","key":"` + keyArray + `","name":"array","roles":[],"permissions":[{"resource":"ARRAY","actions":["READ_ANY"]}]}`,
	}
	for name, js := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(js), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	a.keys.Reload()
	mux := http.NewServeMux()
	if err := a.register(mux, stubRoutes(a)); err != nil {
		t.Fatal(err)
	}
	for key, want := range map[string]int{
		keyDisk:   http.StatusNoContent,
		keyViewer: http.StatusNoContent,
		keyArray:  http.StatusForbidden,
	} {
		req := httptest.NewRequest(http.MethodGet, "/api/disks/smart?device=sdb", nil)
		req.Header.Set("x-api-key", key)
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		if rec.Code != want {
			t.Errorf("key %s: got %d, want %d", key, rec.Code, want)
		}
	}
}

// closeWith delivers its close frame and waits for the peer's echo before
// dropping the TCP connection.
func TestCloseWithDeliversFrame(t *testing.T) {
	done := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer close(done)
		c, err := headerUpgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		ws := newWSConn(t.Context(), c, readLimitDefault, clientIP(r))
		ws.drain()
		_ = ws.WriteText("bye")
		ws.closeWith(websocket.CloseNormalClosure, strings.Repeat("é", 100)) // over-long reason
	}))
	defer srv.Close()
	c, _, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(srv.URL, "http"), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, msg, err := c.ReadMessage(); err != nil || string(msg) != "bye" {
		t.Fatalf("first frame: %v %q", err, msg)
	}
	start := time.Now()
	_, _, err = c.ReadMessage()
	var ce *websocket.CloseError
	if !errors.As(err, &ce) || ce.Code != websocket.CloseNormalClosure || !utf8.ValidString(ce.Text) || len(ce.Text) > maxCloseReason {
		t.Fatalf("want close 1000 with a truncated valid reason, got %v", err)
	}
	select {
	case <-done:
	case <-time.After(closeGrace):
		t.Fatal("server did not finish after the client echoed the close")
	}
	if time.Since(start) >= closeGrace {
		t.Fatal("closeWith waited the full grace period despite the echo")
	}
}
