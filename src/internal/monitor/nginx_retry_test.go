package monitor

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/fsnotify/fsnotify"
)

// A failed pre-check must not be final: the next check (the periodic retry)
// injects once nginx -t passes, and the pre-check error is logged only once.
func TestPrecheckFailureThenRetryInjects(t *testing.T) {
	fail := true
	validate := func() error {
		if fail {
			return errors.New("nginx: [emerg] other plugin broke it")
		}
		return nil
	}
	m, path, reloads := newTestMonitor(t, "location /x {}\n", validate)

	m.checkAndInject()
	m.checkAndInject()
	if b, _ := os.ReadFile(path); strings.Contains(string(b), RaidmanConfLine) {
		t.Fatalf("injected while nginx -t fails: %q", b)
	}
	if m.lastPrecheckErr == "" {
		t.Fatal("pre-check error not remembered (would be logged on every retry)")
	}
	if !m.lastFailure.IsZero() {
		t.Fatal("a failed pre-check must not arm the injection cooldown")
	}

	fail = false
	m.checkAndInject()
	b, _ := os.ReadFile(path)
	if strings.Count(string(b), RaidmanConfLine) != 1 {
		t.Fatalf("not injected after nginx -t recovered: %q", b)
	}
	if *reloads != 1 {
		t.Fatalf("reloads = %d", *reloads)
	}
	if m.lastPrecheckErr != "" {
		t.Fatal("pre-check error not cleared after recovery")
	}
}

// Start's loop retries on its own, without any change to locations.conf.
func TestStartRetriesWithoutFileEvents(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, LocationsConfFile)
	if err := os.WriteFile(path, []byte("location /x {}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, RaidmanConfFile), []byte("location /raidman/ {}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	w, err := fsnotify.NewWatcher()
	if err != nil {
		t.Fatal(err)
	}
	var calls, reloads atomic.Int32
	m := &NginxMonitor{
		watcher: w,
		confDir: dir,
		validate: func() error {
			// The initial check and the first retries fail.
			if calls.Add(1) <= 3 {
				return errors.New("nginx: [emerg] broken")
			}
			return nil
		},
		reload:        func() error { reloads.Add(1); return nil },
		retryInterval: 10 * time.Millisecond,
	}
	m.Start()
	t.Cleanup(func() { w.Close() })

	deadline := time.Now().Add(5 * time.Second)
	for {
		b, _ := os.ReadFile(path)
		if strings.Contains(string(b), RaidmanConfLine) && reloads.Load() == 1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("include not added by the periodic retry (validate calls %d, reloads %d): %q", calls.Load(), reloads.Load(), b)
		}
		time.Sleep(5 * time.Millisecond)
	}
	if calls.Load() < 4 {
		t.Fatalf("validate calls = %d, want at least 4", calls.Load())
	}
}

func TestRetryIntervalDefault(t *testing.T) {
	if got := (&NginxMonitor{}).interval(); got != defaultRetryInterval {
		t.Fatalf("interval() = %s, want %s", got, defaultRetryInterval)
	}
}

func TestNoInjectionWithoutSnippet(t *testing.T) {
	validations := 0
	m, path, _ := newTestMonitor(t, "location /x {}\n", func() error { validations++; return nil })
	if err := os.Remove(filepath.Join(m.confDir, RaidmanConfFile)); err != nil {
		t.Fatal(err)
	}
	m.checkAndInject()
	m.retryInject()
	if got, _ := os.ReadFile(path); strings.Contains(string(got), RaidmanConfLine) {
		t.Fatal("include added while raidman.conf is missing")
	}
	if validations != 0 {
		t.Fatalf("nginx -t ran %d times, want 0", validations)
	}
}

func TestRejectedInjectionBacksOffUntilAFileChanges(t *testing.T) {
	calls := 0
	// The pre-check passes, the post-injection check fails.
	m, path, _ := newTestMonitor(t, "location /x {}\n", func() error {
		calls++
		if calls%2 == 0 {
			return errors.New("emerg")
		}
		return nil
	})
	m.checkAndInject()
	if m.failedCount != 1 || calls != 2 {
		t.Fatalf("after first try: failedCount=%d calls=%d", m.failedCount, calls)
	}
	// Past the plain cooldown but inside the backoff (2nd failure → 60 s).
	m.failedCount = 2
	m.lastFailure = time.Now().Add(-failureCooldown - time.Second)
	m.retryInject()
	if calls != 2 {
		t.Fatalf("periodic retry ran nginx -t with unchanged files (calls=%d)", calls)
	}
	// A change to raidman.conf retries at once.
	if err := os.WriteFile(filepath.Join(m.confDir, RaidmanConfFile), []byte("location /raidman/ { }\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	m.retryInject()
	if calls != 4 {
		t.Fatalf("retry after a file change: calls=%d, want 4", calls)
	}
	if m.failedCount != 1 {
		t.Fatalf("failedCount=%d after a changed file, want 1", m.failedCount)
	}
	if got, _ := os.ReadFile(path); strings.Contains(string(got), RaidmanConfLine) {
		t.Fatal("rejected include was not reverted")
	}
}
