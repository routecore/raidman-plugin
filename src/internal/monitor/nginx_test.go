package monitor

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func newTestMonitor(t *testing.T, content string, validate func() error) (*NginxMonitor, string, *int) {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, LocationsConfFile)
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	reloads := 0
	m := &NginxMonitor{confDir: dir, validate: validate, reload: func() error { reloads++; return nil }}
	return m, path, &reloads
}

func TestInjectOnce(t *testing.T) {
	m, path, reloads := newTestMonitor(t, "location /x {}", func() error { return nil })
	m.checkAndInject()
	m.checkAndInject()
	b, _ := os.ReadFile(path)
	if strings.Count(string(b), RaidmanConfLine) != 1 || !strings.HasPrefix(string(b), "location /x {}\n") {
		t.Fatalf("content = %q", b)
	}
	if *reloads != 1 {
		t.Fatalf("reloads = %d", *reloads)
	}
	info, _ := os.Stat(path)
	if info.Mode().Perm() != 0o644 {
		t.Fatalf("mode = %v", info.Mode())
	}
	if entries, _ := os.ReadDir(filepath.Dir(path)); len(entries) != 1 {
		t.Fatalf("temp files left behind: %v", entries)
	}
}

func TestRollbackOnInvalidConfig(t *testing.T) {
	calls := 0
	validate := func() error {
		calls++
		if calls == 1 {
			return nil // pre-check ok
		}
		return errors.New("nginx: [emerg] bad")
	}
	m, path, reloads := newTestMonitor(t, "orig\n", validate)
	m.checkAndInject()
	b, _ := os.ReadFile(path)
	if string(b) != "orig\n" {
		t.Fatalf("not rolled back: %q", b)
	}
	if *reloads != 0 {
		t.Fatal("must not reload after rollback")
	}
	if m.lastFailure.IsZero() {
		t.Fatal("failure cooldown not armed")
	}
}

func TestReplaceIfUnchangedDetectsConcurrentWrite(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "f")
	os.WriteFile(path, []byte("new from rc.nginx"), 0o644)
	if err := replaceIfUnchanged(path, []byte("what we read earlier"), []byte("ours")); err == nil {
		t.Fatal("expected change detection")
	}
	b, _ := os.ReadFile(path)
	if string(b) != "new from rc.nginx" {
		t.Fatalf("clobbered: %q", b)
	}
}
