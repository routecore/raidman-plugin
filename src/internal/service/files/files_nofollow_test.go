package files

import (
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/routecore/raidman-plugin/src/internal/service/httperr"
)

// A directory swapped for a symlink between Resolve and the open is not
// followed: its target (an over-long name, which shfs must never be handed)
// is never looked up. Following it would answer 400 (ENAMETOOLONG from the
// lookup of the long name); the walk stops at the link with 500 ELOOP.
func TestOpenDoesNotFollowSwappedComponents(t *testing.T) {
	_, real := fixture(t)
	share := real + "/mnt/user/share" // no link above it (macOS: /var)
	long := strings.Repeat("a", maxNameLen+1)
	if err := os.Symlink(share+"/"+long+"/x", filepath.Join(share, "swapped")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("sub", filepath.Join(share, "swapped-dir")); err != nil {
		t.Fatal(err)
	}
	orig := evalSymlinks
	t.Cleanup(func() { evalSymlinks = orig })
	// Resolve saw the paths before the swap: they come back as given.
	evalSymlinks = func(p string) (string, error) {
		if strings.Contains(p, "/swapped") {
			return p, nil
		}
		return orig(p)
	}
	isELOOP := func(what string, err error) {
		t.Helper()
		if httperr.StatusOf(err) != http.StatusInternalServerError || !strings.Contains(err.Error(), "symbolic links") {
			t.Errorf("%s: %v, want 500 ELOOP", what, err)
		}
	}
	f, _, err := Open(share + "/swapped/b.txt")
	if f != nil {
		f.Close()
	}
	isELOOP("Open below a swapped directory", err)
	_, err = List(share + "/swapped/sub")
	isELOOP("List below a swapped directory", err)
	_, err = List(share + "/swapped")
	isELOOP("List of a swapped directory", err)
	// A short, harmless link in the middle is not followed either.
	if err := os.WriteFile(filepath.Join(share, "sub", "s.txt"), []byte("s"), 0o644); err != nil {
		t.Fatal(err)
	}
	f, _, err = Open(share + "/swapped-dir/s.txt")
	if f != nil {
		f.Close()
	}
	isELOOP("Open through a swapped link", err)
}

// A FIFO (or any special file) is refused by type without being opened, so
// a request for it never blocks; a directory is not a file and a file is
// not a directory.
func TestOpenSpecialFilesByType(t *testing.T) {
	_, real := fixture(t)
	share := real + "/mnt/user/share"
	if err := syscall.Mkfifo(filepath.Join(share, "fifo"), 0o644); err != nil {
		t.Skip("mkfifo:", err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		f, _, err := Open(share + "/fifo")
		if f != nil {
			f.Close()
		}
		if httperr.StatusOf(err) != http.StatusBadRequest || err.Error() != "not a file" {
			t.Errorf("Open(fifo) = %v, want 400 not a file", err)
		}
		if _, err := List(share + "/fifo"); httperr.StatusOf(err) != http.StatusBadRequest || err.Error() != "not a directory" {
			t.Errorf("List(fifo) = %v, want 400 not a directory", err)
		}
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("opening a FIFO blocked")
	}
	wantOpen(t, share+"/sub", http.StatusBadRequest)
	wantList(t, share+"/b.txt", http.StatusBadRequest)
	wantOpen(t, share+"/missing.txt", http.StatusUnprocessableEntity)
	wantList(t, share+"/missing", http.StatusUnprocessableEntity)
}
