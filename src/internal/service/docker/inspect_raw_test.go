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

// An inspect document the moby API types cannot decode (port range key from an
// image config, a hostname in Dns) but the old string-typed client listed.
const oddInspect = `{"Id":"odd123","Name":"/torrent","State":{"Status":"running","Running":true},` +
	`"Config":{"Image":"example/torrent","ExposedPorts":{"6881-6889/tcp":{}}},` +
	`"HostConfig":{"Dns":["dns.local"],"NetworkMode":"bridge"},` +
	`"NetworkSettings":{"IPAddress":"172.17.0.5","Ports":{},"Networks":{"bridge":{"IPAddress":"172.17.0.5","MacAddress":"02:42:AC:11:00:05"}}}}`

// fakeDaemon serves /containers/{id}/json on a Unix socket.
func fakeDaemon(t *testing.T) *client.Client {
	t.Helper()
	dir, err := os.MkdirTemp("", "rmd") // short path: Unix socket names are limited
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
		switch r.URL.Path {
		case "/containers/odd123/json", "/containers/torrent/json":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(oddInspect))
		case "/containers/broken/json":
			http.Error(w, `{"message":"boom"}`, http.StatusInternalServerError)
		default:
			http.Error(w, `{"message":"No such container"}`, http.StatusNotFound)
		}
	})}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })
	cli, err := client.New(client.WithHost("unix://" + sock))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cli.Close() })
	return cli
}

func TestRawInspectKeepsDocumentsTheTypedClientRejects(t *testing.T) {
	cli := fakeDaemon(t)
	ctx := context.Background()

	b, err := rawInspect(ctx, cli, "odd123")
	if err != nil {
		t.Fatalf("odd document: %v", err)
	}
	if string(b) != oddInspect {
		t.Errorf("document changed:\n%s", b)
	}
	// The typed client fails on the same document: the reason for rawInspect.
	if _, err := cli.ContainerInspect(ctx, "odd123", client.ContainerInspectOptions{}); err == nil {
		t.Log("note: the typed client now decodes this document; rawInspect is still exact")
	}

	if _, err := rawInspect(ctx, cli, "gone"); !errors.Is(err, ErrNotFound) {
		t.Errorf("404: err = %v, want ErrNotFound", err)
	}
	if _, err := rawInspect(ctx, cli, "broken"); err == nil || errors.Is(err, ErrNotFound) || !strings.Contains(err.Error(), "500") {
		t.Errorf("500: err = %v", err)
	}
}

func TestStatsInspectReadsRunningFromRawDocument(t *testing.T) {
	src := dockerStatsSource{cli: fakeDaemon(t)}
	id, running, err := src.Inspect(context.Background(), "torrent")
	if err != nil || id != "odd123" || !running {
		t.Fatalf("Inspect = %q, %v, %v", id, running, err)
	}
	if _, _, err := src.Inspect(context.Background(), "gone"); !errors.Is(err, ErrNotFound) {
		t.Errorf("missing container: err = %v, want ErrNotFound", err)
	}
}
