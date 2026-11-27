package files

import (
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/routecore/raidman-plugin/src/internal/service/httperr"
)

// Over-long paths are refused lexically: nothing is resolved or stat'ed (a
// 300-byte name under /mnt/user crashed Unraid's shfs), and the error does
// not echo the path.
func TestOverlongPathsRefusedBeforeFilesystem(t *testing.T) {
	root, _ := fixture(t)
	share := root + "/mnt/user/share"
	long := strings.Repeat("a", maxNameLen+1)
	deep := share + strings.Repeat("/"+strings.Repeat("b", 200), maxPathLen/201+1)

	calls := 0
	orig := evalSymlinks
	evalSymlinks = func(p string) (string, error) { calls++; return orig(p) }
	t.Cleanup(func() { evalSymlinks = orig })

	for _, p := range []string{
		root + "/mnt/user/" + long, // the shfs crash: an over-long share name
		share + "/" + long,
		share + "/" + long + "/x",
		root + "/boot/" + long,
		deep, // every component fits, the whole path does not
	} {
		for name, call := range map[string]func(string) error{
			"Resolve": func(p string) error { _, err := Resolve(p); return err },
			"List":    func(p string) error { _, err := List(p); return err },
			"Open": func(p string) error {
				f, _, err := Open(p)
				if f != nil {
					f.Close()
				}
				return err
			},
		} {
			err := call(p)
			if httperr.StatusOf(err) != http.StatusBadRequest {
				t.Errorf("%s(len %d) = %v, want 400", name, len(p), err)
			}
			if err != nil && (strings.Contains(err.Error(), "aaaa") || strings.Contains(err.Error(), "bbbb")) {
				t.Errorf("%s error echoes the path: %.80q", name, err.Error())
			}
		}
	}
	if calls != 0 {
		t.Errorf("over-long paths reached the filesystem (%d EvalSymlinks calls)", calls)
	}

	// The limits themselves are allowed: a 255-byte name is looked up
	// (and is simply missing here).
	wantStatus(t, share+"/"+strings.Repeat("c", maxNameLen), http.StatusUnprocessableEntity)
	if calls == 0 {
		t.Error("a 255-byte name was refused before the lookup")
	}
}

// Filesystem errors other than "missing" and "denied" (EIO, ENOTCONN from a
// dead shfs, ...) answer a short reason, never the raw error with the path.
func TestResolveFilesystemErrorsHidePath(t *testing.T) {
	root, _ := fixture(t)
	target := root + "/mnt/user/share/private-name"
	orig := evalSymlinks
	t.Cleanup(func() { evalSymlinks = orig })

	for errno, want := range map[syscall.Errno]int{
		syscall.ENOTCONN:     http.StatusInternalServerError,
		syscall.EIO:          http.StatusInternalServerError,
		syscall.ENAMETOOLONG: http.StatusBadRequest,
		syscall.ENOENT:       http.StatusUnprocessableEntity,
		syscall.EACCES:       http.StatusForbidden,
	} {
		evalSymlinks = func(p string) (string, error) {
			if p == target {
				return "", &fs.PathError{Op: "lstat", Path: p, Err: errno}
			}
			return orig(p)
		}
		_, err := Resolve(target)
		if got := httperr.StatusOf(err); got != want {
			t.Errorf("%v: status %d (%v), want %d", errno, got, err, want)
		}
		if err == nil || strings.Contains(err.Error(), "private-name") || strings.Contains(err.Error(), "lstat") {
			t.Errorf("%v: error %q leaks the raw error", errno, err)
		}
		if want == http.StatusInternalServerError && !strings.HasSuffix(err.Error(), errno.Error()) {
			t.Errorf("%v: error %q lost the reason", errno, err)
		}
	}
}

// The flash secrets added after the first deny list: the Wi-Fi password,
// Samba's machine secrets, the license key files (any case) and rclone's
// configuration.
func TestMoreBootSecretsDenied(t *testing.T) {
	root := denyFixture(t)
	b := root + "/boot/config"
	for _, d := range []string{b + "/rclone/root", b + "/plugins/rclone", b + "/plugins/dockerMan"} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	denied := []string{"wireless.cfg", "secrets.tdb", "Starter.key", "PRO.KEY", "rclone/root/rclone.conf", "plugins/rclone/.rclone.conf"}
	allowed := []string{"ident.cfg", "network.cfg", "keyfile.txt", "key.cfg", "plugins/dockerMan/x.key"}
	for _, rel := range append(append([]string{}, denied...), allowed...) {
		if err := os.WriteFile(filepath.Join(b, rel), []byte("secret"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	for _, rel := range denied {
		wantOpen(t, b+"/"+rel, http.StatusForbidden)
	}
	wantList(t, b+"/rclone", http.StatusForbidden)
	wantList(t, b+"/rclone/root", http.StatusForbidden)
	for _, rel := range allowed {
		wantOpen(t, b+"/"+rel, 0)
	}

	l, err := List(b)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]bool{"wireless.cfg": true, "secrets.tdb": true, "Starter.key": true, "PRO.KEY": true,
		"rclone": true, "ident.cfg": false, "keyfile.txt": false, "key.cfg": false, "go": false}
	got := map[string]bool{}
	for _, e := range l.Entries {
		got[e.Name] = e.Protected
	}
	for name, p := range want {
		if v, ok := got[name]; !ok || v != p {
			t.Errorf("%s: protected = %v (listed %v), want %v", name, v, ok, p)
		}
	}
}
