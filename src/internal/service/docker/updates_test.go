package docker

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/docker/docker/api/types/container"
)

func TestEnsureImageTag(t *testing.T) {
	cases := map[string]string{
		"redis":                             "library/redis:latest",
		"redis:7":                           "library/redis:7",
		"library/redis":                     "library/redis:latest",
		"lscr.io/linuxserver/plex":          "lscr.io/linuxserver/plex:latest",
		"lscr.io/linuxserver/plex:1.40":     "lscr.io/linuxserver/plex:1.40",
		"registry.local:5000/team/app":      "registry.local:5000/team/app:latest",
		"registry.local:5000/team/app:1.2":  "registry.local:5000/team/app:1.2",
		"ghcr.io/a/b@sha256:0123":           "ghcr.io/a/b:latest",
		"sha256:0123456789abcdef0123456789": "sha256:0123456789abcdef0123456789",
		"":                                  "",
	}
	for in, want := range cases {
		if got := EnsureImageTag(in); got != want {
			t.Errorf("EnsureImageTag(%q) = %q, want %q", in, got, want)
		}
	}
}

func loadStatusFixture(t *testing.T) map[string]UpdateEntry {
	t.Helper()
	b, err := os.ReadFile("testdata/unraid-update-status.json")
	if err != nil {
		t.Fatal(err)
	}
	m, err := ParseUpdateStatus(b)
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func TestParseUpdateStatusTolerant(t *testing.T) {
	m := loadStatusFixture(t)
	if _, ok := m["broken/entry:latest"]; ok {
		t.Fatal("malformed entry must be skipped")
	}
	if len(m) != 5 {
		t.Fatalf("entries = %d, want 5", len(m))
	}
	if _, err := ParseUpdateStatus([]byte("[]")); err == nil {
		t.Fatal("non-object file must fail")
	}
}

func boolp(b bool) *bool { return &b }

func TestBuildUpdates(t *testing.T) {
	status := loadStatusFixture(t)
	checked := time.Date(2026, 11, 18, 3, 0, 0, 0, time.UTC)
	containers := []container.Summary{
		{Names: []string{"/redis"}, Image: "redis"},                                            // digests differ -> update
		{Names: []string{"/plex"}, Image: "lscr.io/linuxserver/plex"},                          // same digest (case) -> none
		{Names: []string{"/app"}, Image: "registry.local:5000/team/app:1.2"},                   // no digests, status "false" -> update
		{Names: []string{"/ha"}, Image: "ghcr.io/home-assistant/home-assistant:stable"},        // undef -> unknown
		{Names: []string{"/jellyfin"}, Image: "jellyfin/jellyfin"},                             // status "true" = up to date
		{Names: []string{"/local"}, Image: "my-local-build:dev"},                               // not in file
		{Names: []string{"/other/link", "/sidecar"}, Image: "lscr.io/linuxserver/plex:latest"}, // primary name skips links
	}
	got := BuildUpdates(containers, status, &checked)
	want := []struct {
		name  string
		avail *bool
		local bool
	}{
		{"redis", boolp(true), true},
		{"plex", boolp(false), true},
		{"app", boolp(true), false},
		{"ha", nil, true},
		{"jellyfin", boolp(false), false},
		{"local", nil, false},
		{"sidecar", boolp(false), true},
	}
	if len(got) != len(want) {
		t.Fatalf("got %d entries", len(got))
	}
	for i, w := range want {
		g := got[i]
		if g.Name != w.name {
			t.Errorf("%d: name %q want %q", i, g.Name, w.name)
		}
		if (g.UpdateAvailable == nil) != (w.avail == nil) || (g.UpdateAvailable != nil && *g.UpdateAvailable != *w.avail) {
			t.Errorf("%s: updateAvailable=%v want %v", g.Name, deref(g.UpdateAvailable), deref(w.avail))
		}
		if (g.LocalDigest != nil) != w.local {
			t.Errorf("%s: localDigest=%v", g.Name, g.LocalDigest)
		}
	}
	if got[0].CheckedAt == nil || *got[0].CheckedAt != "2026-11-18T03:00:00Z" {
		t.Errorf("checkedAt = %v", got[0].CheckedAt)
	}
	if got[5].CheckedAt != nil {
		t.Errorf("unknown image must have null checkedAt")
	}
	if got[0].RemoteDigest == nil || *got[0].RemoteDigest != "sha256:2222222222222222222222222222222222222222222222222222222222222222" {
		t.Errorf("remote digest = %v", got[0].RemoteDigest)
	}
	if got[3].RemoteDigest != nil {
		t.Errorf("null remote must stay null")
	}
}

func deref(b *bool) any {
	if b == nil {
		return nil
	}
	return *b
}

func TestTriggerUpdateCheck(t *testing.T) {
	oldScript, oldStart := DockerUpdateScript, startCommand
	t.Cleanup(func() { DockerUpdateScript, startCommand = oldScript, oldStart })

	DockerUpdateScript = filepath.Join(t.TempDir(), "missing")
	if _, err := TriggerUpdateCheck(context.Background()); !errors.Is(err, ErrCheckUnavailable) {
		t.Fatalf("missing script: %v", err)
	}

	script := filepath.Join(t.TempDir(), "dockerupdate")
	if err := os.WriteFile(script, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	DockerUpdateScript = script
	var gotArgs []string
	release := make(chan struct{})
	// Never exec anything: record argv and start a harmless blocking command
	// in place of the real script.
	startCommand = func(cmd *exec.Cmd) error {
		gotArgs = cmd.Args
		cmd.Path, cmd.Args = "/bin/sh", []string{"/bin/sh", "-c", "read x"}
		stdin, err := cmd.StdinPipe()
		if err != nil {
			return err
		}
		go func() { <-release; stdin.Close() }()
		return cmd.Start()
	}
	already, err := TriggerUpdateCheck(context.Background())
	if err != nil || already {
		t.Fatalf("first trigger: already=%v err=%v", already, err)
	}
	if len(gotArgs) != 3 || gotArgs[0] != script || gotArgs[1] != "check" || gotArgs[2] != "nonotify" {
		t.Fatalf("argv = %v", gotArgs)
	}
	if !UpdateCheckRunning() {
		t.Fatal("check should be running")
	}
	if already, err := TriggerUpdateCheck(context.Background()); err != nil || !already {
		t.Fatalf("second trigger must be single-flighted: already=%v err=%v", already, err)
	}
	close(release)
	deadline := time.Now().Add(5 * time.Second)
	for UpdateCheckRunning() && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if UpdateCheckRunning() {
		t.Fatal("check did not finish")
	}
}
