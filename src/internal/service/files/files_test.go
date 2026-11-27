package files

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"testing"

	"github.com/routecore/raidman-plugin/src/internal/service/httperr"
)

// fixture builds a fake /mnt and /boot under a temp dir and returns the
// (unresolved) temp root and its symlink-resolved form.
func fixture(t *testing.T) (string, string) {
	t.Helper()
	root := t.TempDir()
	real, err := filepath.EvalSymlinks(root)
	if err != nil {
		t.Fatal(err)
	}
	oldMnt, oldBoot, oldPools, oldMax := MntDir, BootDir, PoolsDir, MaxEntries
	t.Cleanup(func() { MntDir, BootDir, PoolsDir, MaxEntries = oldMnt, oldBoot, oldPools, oldMax })
	MntDir = filepath.Join(root, "mnt")
	BootDir = filepath.Join(root, "boot")
	PoolsDir = filepath.Join(root, "boot", "config", "pools")

	mk := func(rel string) {
		if err := os.MkdirAll(filepath.Join(root, rel), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	write := func(rel, data string) {
		if err := os.WriteFile(filepath.Join(root, rel), []byte(data), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	link := func(target, rel string) {
		if err := os.Symlink(target, filepath.Join(root, rel)); err != nil {
			t.Fatal(err)
		}
	}
	for _, d := range []string{"mnt/user/share/sub", "mnt/user/Share2", "mnt/user0", "mnt/disk1", "mnt/disk12", "mnt/cache/appdata",
		"mnt/fast", "mnt/disks/ud", "mnt/remotes", "mnt/other", "mnt/diskx", "boot/config/pools", "bootleg", "etc"} {
		mk(d)
	}
	write("mnt/user/share/b.txt", "bee")
	write("mnt/user/share/A.mkv", "video")
	write("mnt/cache/appdata/c.txt", "cache file")
	write("mnt/disks/ud/x.txt", "ud")
	write("mnt/other/o.txt", "other")
	write("bootleg/leak.txt", "leak")
	write("etc/secret.txt", "secret")
	write("boot/config/pools/fast.cfg", "")
	write("boot/config/pools/disks.cfg", "") // reserved name, never a pool
	write("boot/config/pools/Bad Name.cfg", "")
	// Escapes: absolute and relative links leaving the roots.
	link(filepath.Join(root, "etc"), "mnt/user/share/esc")
	link("../../../etc/secret.txt", "mnt/user/share/secret.txt")
	link(filepath.Join(root, "mnt/other"), "mnt/disk1/other")
	link(filepath.Join(root, "mnt/disks/ud"), "mnt/disk1/ud")
	// Link between two allowed roots.
	link(filepath.Join(root, "mnt/cache/appdata/c.txt"), "mnt/user/share/c-link.txt")
	link(filepath.Join(root, "mnt/cache/appdata"), "mnt/user/share/appdata")
	return root, real
}

func wantStatus(t *testing.T, raw string, status int) {
	t.Helper()
	_, err := Resolve(raw)
	if got := httperr.StatusOf(err); err == nil || got != status {
		t.Errorf("Resolve(%q) = %v (status %d), want status %d", raw, err, got, status)
	}
}

func TestResolveRejects(t *testing.T) {
	root, _ := fixture(t)
	wantStatus(t, "", http.StatusBadRequest)
	wantStatus(t, "mnt/user", http.StatusBadRequest)
	wantStatus(t, root+"/mnt/user/share\x00/b.txt", http.StatusBadRequest)
	for _, rel := range []string{
		"/mnt/user/../../etc",      // .. leaves the roots
		"/mnt/user/share/../share", // any .. segment, even one staying inside
		"/mnt/user/share/sub/..",   // trailing ..
		"/mnt",                     // the parent of the roots
		"/mnt/other/o.txt",         // not a share, disk or pool
		"/mnt/disks/ud/x.txt",      // Unassigned Devices
		"/mnt/remotes",             // remote mounts
		"/mnt/diskx",               // disk without a number
		"/mnt/Bad Name",            // invalid pool cfg name
		"/bootleg/leak.txt",        // prefix confusion with /boot
		"/etc/secret.txt",          // outside everything
		"/mnt/user/share/esc",      // symlink to outside (absolute)
		"/mnt/user/share/esc/secret.txt",
		"/mnt/user/share/secret.txt", // symlink to outside (relative)
		"/mnt/disk1/other/o.txt",     // symlink into a non-root /mnt dir
		"/mnt/disk1/ud",              // symlink into Unassigned Devices
	} {
		wantStatus(t, root+rel, http.StatusForbidden)
	}
	// Outside the roots is refused before anything is stat'ed: a missing
	// path outside answers 403, not "not found".
	wantStatus(t, root+"/nope/missing", http.StatusForbidden)
	wantStatus(t, root+"/mnt/user/share/missing", http.StatusUnprocessableEntity)
	wantStatus(t, "/etc/passwd", http.StatusForbidden)
}

func TestResolveAllows(t *testing.T) {
	root, real := fixture(t)
	cases := map[string]string{
		"/mnt/user":                     "/mnt/user",
		"/mnt/user/":                    "/mnt/user",
		"/mnt/user//share/./b.txt":      "/mnt/user/share/b.txt",
		"/mnt/user0":                    "/mnt/user0",
		"/mnt/disk1":                    "/mnt/disk1",
		"/mnt/disk12":                   "/mnt/disk12",
		"/mnt/cache/appdata":            "/mnt/cache/appdata",
		"/mnt/fast":                     "/mnt/fast",
		"/boot":                         "/boot",
		"/boot/config/pools/fast.cfg":   "/boot/config/pools/fast.cfg",
		"/mnt/user/share/c-link.txt":    "/mnt/cache/appdata/c.txt", // share -> pool link is fine
		"/mnt/user/share/appdata/c.txt": "/mnt/cache/appdata/c.txt",
	}
	for in, want := range cases {
		got, err := Resolve(root + in)
		if err != nil || got != real+want {
			t.Errorf("Resolve(%q) = %q, %v; want %q", in, got, err, real+want)
		}
	}
	// The resolved form of the temp dir (macOS /private/var) is accepted too.
	if _, err := Resolve(real + "/mnt/user/share"); err != nil {
		t.Errorf("resolved base: %v", err)
	}
}

func TestPools(t *testing.T) {
	fixture(t)
	p := pools()
	if !p["fast"] || p["disks"] || p["Bad Name"] || len(p) != 1 {
		t.Fatalf("pools = %v", p)
	}
}

func TestUnder(t *testing.T) {
	if !under("/boot", "/boot") || !under("/boot/x", "/boot") || under("/bootleg", "/boot") || under("/boo", "/boot") {
		t.Fatal("under")
	}
}

func TestList(t *testing.T) {
	root, real := fixture(t)
	l, err := List(root + "/mnt/user/share")
	if err != nil {
		t.Fatal(err)
	}
	if l.Path != real+"/mnt/user/share" || l.Parent == nil || *l.Parent != real+"/mnt/user" || l.Truncated {
		t.Fatalf("listing header: %+v", l)
	}
	var names []string
	for _, e := range l.Entries {
		names = append(names, e.Name+":"+e.Type)
	}
	// Directories first (sub), then case-insensitive names; symlinks keep
	// their own type (appdata is a link to a directory).
	want := "[sub:dir A.mkv:file appdata:symlink b.txt:file c-link.txt:symlink esc:symlink secret.txt:symlink]"
	if fmt.Sprint(names) != want {
		t.Fatalf("entries = %v\nwant      %v", names, want)
	}
	for _, e := range l.Entries {
		switch e.Name {
		case "b.txt":
			if e.Size != 3 || e.Path != real+"/mnt/user/share/b.txt" || e.Mtime < 1e9 || e.Mtime > 1e11 {
				t.Errorf("b.txt: %+v (mtime must be unix seconds)", e)
			}
		case "c-link.txt":
			if e.Size != int64(len("cache file")) || e.TargetType != "file" {
				t.Errorf("allowed link target size/type: %+v", e)
			}
		case "appdata":
			if e.TargetType != "dir" {
				t.Errorf("link to an allowed directory: %+v", e)
			}
		case "secret.txt":
			if e.Size != 0 || e.TargetType != "" {
				t.Errorf("link target outside the roots must not be stat'ed: %+v", e)
			}
		}
	}

	// A root has no parent.
	l, err = List(root + "/mnt/user")
	if err != nil || l.Parent != nil {
		t.Fatalf("root listing: %+v %v", l, err)
	}
	if _, err := List(root + "/mnt/user/share/b.txt"); httperr.StatusOf(err) != http.StatusBadRequest {
		t.Errorf("file as dir: %v", err)
	}
	if _, err := List(root + "/mnt/user/share/esc"); httperr.StatusOf(err) != http.StatusForbidden {
		t.Errorf("escaping dir link: %v", err)
	}
}

func TestListTruncated(t *testing.T) {
	root, _ := fixture(t)
	MaxEntries = 2
	l, err := List(root + "/mnt/user/share")
	if err != nil || !l.Truncated || len(l.Entries) != 2 || l.Entries[0].Name != "sub" {
		t.Fatalf("%+v %v", l, err)
	}
}

func TestOpen(t *testing.T) {
	root, _ := fixture(t)
	f, fi, err := Open(root + "/mnt/user/share/b.txt")
	if err != nil {
		t.Fatal(err)
	}
	data, _ := io.ReadAll(f)
	f.Close()
	if string(data) != "bee" || fi.Size() != 3 {
		t.Fatalf("%q %d", data, fi.Size())
	}
	// Link to an allowed file is served as its target.
	f, _, err = Open(root + "/mnt/user/share/c-link.txt")
	if err != nil {
		t.Fatal(err)
	}
	f.Close()
	for rel, status := range map[string]int{
		"/mnt/user/share/secret.txt":              http.StatusForbidden,
		"/mnt/user/share/esc/secret.txt":          http.StatusForbidden,
		"/mnt/user/share/../../../etc/secret.txt": http.StatusForbidden,
		"/mnt/user/share":                         http.StatusBadRequest,
		"/mnt/user/share/missing":                 http.StatusUnprocessableEntity,
	} {
		if f, _, err := Open(root + rel); httperr.StatusOf(err) != status {
			if f != nil {
				f.Close()
			}
			t.Errorf("Open(%q) = %v, want %d", rel, err, status)
		}
	}
}

func TestContentHeaders(t *testing.T) {
	if ContentType("Movie.MKV") != "video/x-matroska" || ContentType("x.unknownext") != "application/octet-stream" || ContentType("a.txt") != "text/plain; charset=utf-8" {
		t.Fatal("content type")
	}
	if got := ContentDisposition("a b.txt"); got != `attachment; filename="a b.txt"` {
		t.Fatalf("ascii: %s", got)
	}
	if got := ContentDisposition("résumé.pdf"); got != "attachment; filename*=utf-8''r%C3%A9sum%C3%A9.pdf" {
		t.Fatalf("utf-8: %s", got)
	}
}
