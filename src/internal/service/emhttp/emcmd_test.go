package emhttp

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func startFakeEmhttpd(t *testing.T, handler http.HandlerFunc) (socket string) {
	t.Helper()
	// Short path: unix socket paths are limited to ~104 bytes on macOS.
	dir, err := os.MkdirTemp("", "em")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	socket = filepath.Join(dir, "s")
	ln, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: handler}
	go srv.Serve(ln)
	t.Cleanup(func() { srv.Close() })
	return socket
}

func writeVarIni(t *testing.T, token string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "var.ini")
	if err := os.WriteFile(p, []byte("mdState=\"STARTED\"\ncsrf_token=\""+token+"\"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestCmdSendsFormWithCsrf(t *testing.T) {
	var got url.Values
	var path string
	socket := startFakeEmhttpd(t, func(w http.ResponseWriter, r *http.Request) {
		path = r.URL.Path
		b, _ := io.ReadAll(r.Body)
		got, _ = url.ParseQuery(string(b))
	})
	c := &Client{SocketPath: socket, VarIniPath: writeVarIni(t, "ABC"), Timeout: 5 * time.Second}
	if err := c.Cmd(context.Background(), url.Values{"cmdSpinupAll": {"Apply"}}); err != nil {
		t.Fatal(err)
	}
	if path != "/update" || got.Get("cmdSpinupAll") != "Apply" || got.Get("csrf_token") != "ABC" {
		t.Fatalf("path=%s form=%v", path, got)
	}
}

func TestCmdReportsFailures(t *testing.T) {
	varIni := writeVarIni(t, "ABC")
	body := startFakeEmhttpd(t, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("Invalid command\n"))
	})
	c := &Client{SocketPath: body, VarIniPath: varIni, Timeout: 5 * time.Second}
	if err := c.Cmd(context.Background(), url.Values{"x": {"y"}}); err == nil {
		t.Fatal("non-empty body must be an error")
	}

	status := startFakeEmhttpd(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	})
	c = &Client{SocketPath: status, VarIniPath: varIni, Timeout: 5 * time.Second}
	if err := c.Cmd(context.Background(), url.Values{"x": {"y"}}); err == nil {
		t.Fatal("HTTP error must be an error")
	}

	c = &Client{SocketPath: "/nonexistent/emhttpd.socket", VarIniPath: varIni}
	if err := c.Cmd(context.Background(), url.Values{"x": {"y"}}); err == nil {
		t.Fatal("missing socket must be an error")
	}

	c = &Client{SocketPath: status, VarIniPath: writeVarIni(t, "")}
	if err := c.Cmd(context.Background(), url.Values{"x": {"y"}}); err == nil {
		t.Fatal("missing csrf token must be an error")
	}
}
