package files

import (
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/routecore/raidman-plugin/src/internal/service/httperr"
)

// watchLstat records every path resolveSymlinks looks up.
func watchLstat(t *testing.T) *[]string {
	t.Helper()
	var seen []string
	orig := lstat
	lstat = func(p string) (fs.FileInfo, error) { seen = append(seen, p); return orig(p) }
	t.Cleanup(func() { lstat = orig })
	return &seen
}

// lookedUpTooLong reports a looked-up path with a component over
// maxNameLen, or longer than max.
func lookedUpTooLong(seen []string, max int) string {
	for _, p := range seen {
		if len(p) > max {
			return p
		}
		for _, seg := range strings.Split(p, "/") {
			if len(seg) > maxNameLen {
				return p
			}
		}
	}
	return ""
}

// A symlink on disk whose target holds an over-long name is refused (400)
// without that name ever being looked up: the client's path is short, so
// only the walker can keep it away from shfs. In a listing the link is
// shown unresolved.
func TestSymlinkTargetLengthChecked(t *testing.T) {
	root, _ := fixture(t)
	share := root + "/mnt/user/share"
	long := strings.Repeat("a", maxNameLen+1)
	for name, target := range map[string]string{
		"abs-long": share + "/" + long,
		"rel-long": "sub/" + long + "/x",
		"two-hops": "abs-long", // a link to a link to the long name
	} {
		if err := os.Symlink(target, filepath.Join(share, name)); err != nil {
			t.Fatal(err)
		}
	}
	// deep-long: a chain of links, each short, whose expansion grows past
	// PATH_MAX (every hop prepends its target to what is left).
	pad := strings.Repeat("sub/../", 100)
	for i := 0; i < 8; i++ {
		name, next := "deep"+strings.Repeat("x", i), "deep"+strings.Repeat("x", i+1)
		if i == 0 {
			name = "deep-long"
		}
		if err := os.Symlink(next+"/"+pad, filepath.Join(share, name)); err != nil {
			t.Fatal(err)
		}
	}
	seen := watchLstat(t)
	for _, name := range []string{"abs-long", "rel-long", "two-hops", "deep-long"} {
		if _, err := Resolve(share + "/" + name); httperr.StatusOf(err) != http.StatusBadRequest || err.Error() != "path too long" {
			t.Errorf("Resolve(%s) = %v, want 400 path too long", name, err)
		}
		f, _, err := Open(share + "/" + name)
		if f != nil {
			f.Close()
		}
		if httperr.StatusOf(err) != http.StatusBadRequest {
			t.Errorf("Open(%s) = %v, want 400", name, err)
		}
	}
	l, err := List(share)
	if err != nil {
		t.Fatal(err)
	}
	listed := 0
	for _, e := range l.Entries {
		switch e.Name {
		case "abs-long", "rel-long", "two-hops", "deep-long":
			listed++
			if e.Type != "symlink" || e.TargetType != "" || e.Size != 0 {
				t.Errorf("%s listed as %+v, want an unresolved symlink", e.Name, e)
			}
		}
	}
	if listed != 4 {
		t.Errorf("%d of 4 links listed", listed)
	}
	if p := lookedUpTooLong(*seen, maxPathLen); p != "" {
		t.Errorf("over-long path looked up: %.120q", p)
	}
	// A link with a target of normal length still resolves.
	if err := os.Symlink("sub", filepath.Join(share, "short")); err != nil {
		t.Fatal(err)
	}
	if _, err := Resolve(share + "/short"); err != nil {
		t.Errorf("short link: %v", err)
	}
}

// Under /mnt/user and /mnt/user0 a path may not exceed maxUserPathLen
// (shfs rewrites the prefix to a longer one); elsewhere maxPathLen applies.
// Both the client's path and a link's expansion are checked.
func TestUserSharePathCap(t *testing.T) {
	root, real := fixture(t)
	// A path of n bytes below dir made of 200-byte components.
	pad := func(dir string, n int) string {
		p := dir
		for len(p)+201 <= n {
			p += "/" + strings.Repeat("d", 200)
		}
		if k := n - len(p) - 1; k > 0 {
			p += "/" + strings.Repeat("e", k)
		}
		return p
	}
	between := (maxUserPathLen + maxPathLen) / 2 // over the user cap, under PATH_MAX
	seen := watchLstat(t)
	for _, dir := range []string{root + "/mnt/user/share", root + "/mnt/user0"} {
		if _, err := Resolve(pad(dir, between)); httperr.StatusOf(err) != http.StatusBadRequest {
			t.Errorf("user share path of %d bytes: %v, want 400", between, err)
		}
	}
	for _, p := range *seen {
		if (under(p, real+"/mnt/user") || under(p, real+"/mnt/user0")) && len(p) > maxUserPathLen {
			t.Errorf("user share path of %d bytes looked up", len(p))
		}
	}
	// The same length on a disk is only missing.
	if _, err := Resolve(pad(root+"/mnt/disk1", between)); httperr.StatusOf(err) != http.StatusUnprocessableEntity {
		t.Errorf("disk path of %d bytes: %v, want 422", between, err)
	}
	// A chain of short links whose expansion is "between" bytes long: refused
	// in a user share, only missing on a disk.
	for dir, want := range map[string]int{
		real + "/mnt/user/share": http.StatusBadRequest,
		real + "/mnt/disk1":      http.StatusUnprocessableEntity,
	} {
		// far -> farx/<seg> -> farxx/<seg> ... -> <filler>: the expansion
		// is dir + "/" + filler + n*seg. Every target stays short
		// (macOS limits a link to 1023 bytes).
		seg := strings.Repeat("/"+strings.Repeat("d", 200), 3)
		n := (between - len(dir) - 1 - 1000 + len(seg) - 1) / len(seg)
		filler := pad("", between-len(dir)-1-n*len(seg)+1)[1:]
		for i := 0; i <= n; i++ {
			name, target := "far"+strings.Repeat("x", i), "far"+strings.Repeat("x", i+1)+seg
			if i == n {
				target = filler
			}
			if err := os.Symlink(target, filepath.Join(dir, name)); err != nil {
				t.Fatal(err)
			}
		}
		*seen = nil
		if _, err := Resolve(dir + "/far"); httperr.StatusOf(err) != want {
			t.Errorf("%s: link chain expanding to %d bytes: %v, want %d", dir, between, err, want)
		}
		if p := lookedUpTooLong(*seen, maxUserPathLen); p != "" {
			t.Errorf("looked up %d bytes", len(p))
		}
	}
}

// Link loops answer 500 with the system's reason (ELOOP), like the kernel.
func TestSymlinkLoop(t *testing.T) {
	_, real := fixture(t)
	share := real + "/mnt/user/share" // no link above it (macOS: /var)
	os.Symlink("loop-b", filepath.Join(share, "loop-a"))
	os.Symlink("loop-a", filepath.Join(share, "loop-b"))
	_, err := Resolve(share + "/loop-a")
	if httperr.StatusOf(err) != http.StatusInternalServerError || !strings.Contains(err.Error(), "too many levels of symbolic links") {
		t.Errorf("loop: %v, want 500 ELOOP", err)
	}
	// 40 hops are followed (the kernel's limit), 41 are not.
	prev := "sub"
	for i := 1; i <= maxSymlinks+1; i++ {
		name := "hop" + strings.Repeat("x", i)
		os.Symlink(prev, filepath.Join(share, name))
		prev = name
		_, err := Resolve(share + "/" + name)
		if ok := err == nil; ok != (i <= maxSymlinks) {
			t.Errorf("%d hops: %v", i, err)
		}
	}
}

// A path swapped for a symlink after Resolve fails the O_NOFOLLOW open with
// ELOOP: a filesystem failure (500 with the reason), not a policy refusal.
// Paths outside the roots stay 403.
func TestOpenErrorsMatchREADME(t *testing.T) {
	root, _ := fixture(t)
	share := root + "/mnt/user/share"
	os.Symlink("sub", filepath.Join(share, "dir-link"))
	os.Symlink("b.txt", filepath.Join(share, "file-link"))
	orig := evalSymlinks
	t.Cleanup(func() { evalSymlinks = orig })
	// Resolve sees the path before the swap: it comes back unresolved.
	evalSymlinks = func(p string) (string, error) {
		if strings.HasSuffix(p, "-link") {
			return p, nil
		}
		return orig(p)
	}
	// Linux answers ELOOP; macOS ENOTDIR (O_DIRECTORY wins there).
	_, err := List(share + "/dir-link")
	if httperr.StatusOf(err) != http.StatusInternalServerError || !strings.HasPrefix(err.Error(), "cannot access path: ") {
		t.Errorf("List of a swapped directory: %v, want 500 with the reason", err)
	}
	f, _, err := Open(share + "/file-link")
	if f != nil {
		f.Close()
	}
	if httperr.StatusOf(err) != http.StatusInternalServerError || !strings.Contains(err.Error(), "symbolic links") {
		t.Errorf("Open of a swapped file: %v, want 500 ELOOP", err)
	}
	if strings.Contains(err.Error(), share) {
		t.Errorf("error echoes the path: %v", err)
	}
	// Policy refusals are unchanged.
	wantOpen(t, share+"/secret.txt", http.StatusForbidden)
	wantList(t, share+"/esc", http.StatusForbidden)
}

// checkPathLength is what guards every lookup, including the lstat of each
// listed entry (a directory just under the cap holding a long name).
func TestCheckPathLength(t *testing.T) {
	roots := []string{"/mnt/user", "/mnt/user0", "/r/mnt/user", "/r/mnt/user0"}
	at := func(dir string, n int) string { // dir + "/" + n-len(dir)-1 bytes in 200-byte names
		p := dir
		for len(p)+201 <= n {
			p += "/" + strings.Repeat("d", 200)
		}
		if k := n - len(p) - 1; k > 0 {
			p += "/" + strings.Repeat("e", k)
		}
		return p
	}
	for _, c := range []struct {
		path string
		ok   bool
	}{
		{at("/mnt/user/share", maxUserPathLen), true},
		{at("/mnt/user/share", maxUserPathLen+1), false},
		{at("/mnt/user0", maxUserPathLen+1), false},
		{at("/r/mnt/user/s", maxUserPathLen+1), false}, // the resolved form of MntDir
		{at("/mnt/users", maxUserPathLen+1), true},     // not a user share
		{at("/mnt/disk1", maxPathLen), true},
		{at("/mnt/disk1", maxPathLen+1), false},
		{"/mnt/disk1/" + strings.Repeat("n", maxNameLen), true},
		{"/mnt/disk1/" + strings.Repeat("n", maxNameLen+1), false},
	} {
		if err := checkPathLength(c.path, roots); (err == nil) != c.ok {
			t.Errorf("%.30s... (%d bytes): %v, want ok=%v", c.path, len(c.path), err, c.ok)
		}
	}
}
