package files

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/routecore/raidman-plugin/src/internal/service/httperr"
)

// denyFixture adds the sensitive /boot files and directories to the fixture.
func denyFixture(t *testing.T) string {
	t.Helper()
	root, _ := fixture(t)
	for _, d := range []string{"boot/config/ssh", "boot/config/ssl/certs", "boot/config/wireguard",
		"boot/config/plugins/dynamix.my.servers/keys", "boot/config/plugins/raidman"} {
		if err := os.MkdirAll(filepath.Join(root, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	for rel, data := range map[string]string{
		"boot/config/shadow":                                   "root:$6$hash",
		"boot/config/passwd":                                   "root:x:0:0",
		"boot/config/smbpasswd":                                "root:0:hash",
		"boot/config/go":                                       "#!/bin/bash",
		"boot/config/ssh/ssh_host_ed25519_key":                 "PRIVATE",
		"boot/config/ssl/certs/tower_unraid_bundle.pem":        "PRIVATE",
		"boot/config/wireguard/wg0.conf":                       "PrivateKey = x",
		"boot/config/plugins/dynamix.my.servers/keys/k.json":   `{"key":"secret"}`,
		"boot/config/plugins/dynamix.my.servers/myservers.cfg": "apikey=x",
		"boot/config/plugins/raidman/settings.json":            `{"allowed":[]}`,
		"boot/config/plugins/raidman/raidman.cfg":              "x=1",
	} {
		if err := os.WriteFile(filepath.Join(root, rel), []byte(data), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

func wantOpen(t *testing.T, raw string, status int) {
	t.Helper()
	f, _, err := Open(raw)
	if f != nil {
		f.Close()
	}
	if status == 0 {
		if err != nil {
			t.Errorf("Open(%q) = %v, want success", raw, err)
		}
		return
	}
	if got := httperr.StatusOf(err); err == nil || got != status {
		t.Errorf("Open(%q) = %v (status %d), want %d", raw, err, got, status)
	}
}

func wantList(t *testing.T, raw string, status int) {
	t.Helper()
	_, err := List(raw)
	if status == 0 {
		if err != nil {
			t.Errorf("List(%q) = %v, want success", raw, err)
		}
		return
	}
	if got := httperr.StatusOf(err); err == nil || got != status {
		t.Errorf("List(%q) = %v (status %d), want %d", raw, err, got, status)
	}
}

func TestSensitiveBootPathsRefused(t *testing.T) {
	root := denyFixture(t)
	b := root + "/boot/config"
	for _, p := range []string{
		b + "/shadow", b + "/passwd", b + "/smbpasswd",
		b + "/ssh/ssh_host_ed25519_key",
		b + "/ssl/certs/tower_unraid_bundle.pem",
		b + "/wireguard/wg0.conf",
		b + "/plugins/dynamix.my.servers/keys/k.json",
		b + "/plugins/dynamix.my.servers/myservers.cfg",
		b + "/plugins/raidman/settings.json",
	} {
		wantOpen(t, p, http.StatusForbidden)
		wantStatus(t, p, http.StatusForbidden)
	}
	for _, p := range []string{b + "/ssh", b + "/ssl", b + "/ssl/certs", b + "/wireguard",
		b + "/plugins/dynamix.my.servers", b + "/plugins/dynamix.my.servers/keys"} {
		wantList(t, p, http.StatusForbidden)
	}
	// The rest of /boot stays browsable.
	wantList(t, root+"/boot", 0)
	wantList(t, b, 0)
	wantList(t, b+"/plugins/raidman", 0)
	wantOpen(t, b+"/go", 0)
	wantOpen(t, b+"/plugins/raidman/raidman.cfg", 0)
}

// Identity, not names: links that reach a denied file or directory are
// refused, and so is a differently-cased name on a case-insensitive
// filesystem (vfat on Unraid; probed here, so it only runs where the test
// filesystem is case-insensitive too).
func TestSensitiveBootPathsByIdentity(t *testing.T) {
	root := denyFixture(t)
	b := root + "/boot/config"
	share := root + "/mnt/user/share"

	if err := os.Symlink(b+"/shadow", share+"/shadow-link"); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(b+"/ssh", share+"/ssh-link"); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(b+"/shadow", b+"/shadow.bak"); err != nil {
		t.Fatal(err)
	}
	wantOpen(t, share+"/shadow-link", http.StatusForbidden)
	wantList(t, share+"/ssh-link", http.StatusForbidden)
	wantOpen(t, share+"/ssh-link/ssh_host_ed25519_key", http.StatusForbidden)
	wantOpen(t, b+"/shadow.bak", http.StatusForbidden) // hard link: same file

	// The listing shows such links but never stats their targets.
	l, err := List(share)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range l.Entries {
		if (e.Name == "shadow-link" || e.Name == "ssh-link") && (e.TargetType != "" || e.Size != 0) {
			t.Errorf("denied link target described: %+v", e)
		}
	}

	upper := root + "/boot/CONFIG/SHADOW"
	a, errA := os.Stat(upper)
	c, errC := os.Stat(b + "/shadow")
	if errA != nil || errC != nil || !os.SameFile(a, c) {
		t.Log("case-sensitive test filesystem: case-variant check skipped")
		return
	}
	wantOpen(t, upper, http.StatusForbidden)
	wantList(t, root+"/boot/Config/SSH", http.StatusForbidden)
}

// pagingFixture creates a directory with dirs and mixed-case files.
func pagingFixture(t *testing.T) (string, []string) {
	t.Helper()
	root, _ := fixture(t)
	dir := root + "/mnt/user/big"
	var want []string
	for i := 0; i < 3; i++ {
		name := fmt.Sprintf("Dir%02d", i)
		if err := os.MkdirAll(filepath.Join(dir, name), 0o755); err != nil {
			t.Fatal(err)
		}
		want = append(want, name)
	}
	var fileNames []string
	for i := 0; i < 25; i++ {
		name := fmt.Sprintf("img_%02d.jpg", i)
		if i%2 == 1 {
			name = strings.ToUpper(name)
		}
		if err := os.WriteFile(filepath.Join(dir, name), []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
		fileNames = append(fileNames, name)
	}
	sort.Slice(fileNames, func(i, j int) bool { return strings.ToLower(fileNames[i]) < strings.ToLower(fileNames[j]) })
	return dir, append(want, fileNames...)
}

func names(es []Entry) []string {
	out := make([]string, 0, len(es))
	for _, e := range es {
		out = append(out, e.Name)
	}
	return out
}

func TestListPaging(t *testing.T) {
	dir, want := pagingFixture(t)
	MaxEntries = 10

	// No options: the first MaxEntries, as before paging existed.
	l, err := List(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !l.Truncated || l.Total != len(want) || l.Next == nil || *l.Next != 10 || l.Offset != 0 {
		t.Fatalf("first page header: %+v", l)
	}
	if fmt.Sprint(names(l.Entries)) != fmt.Sprint(want[:10]) {
		t.Fatalf("first page = %v, want %v", names(l.Entries), want[:10])
	}

	// Walking next pages yields the full sorted directory exactly once.
	var got []string
	offset := 0
	for pages := 0; ; pages++ {
		if pages > 10 {
			t.Fatal("paging does not terminate")
		}
		l, err := ListContext(context.Background(), dir, ListOptions{Offset: offset, Limit: 7})
		if err != nil {
			t.Fatal(err)
		}
		got = append(got, names(l.Entries)...)
		if l.Next == nil {
			if l.Truncated {
				t.Fatalf("last page still truncated: %+v", l)
			}
			break
		}
		offset = *l.Next
	}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("paged = %v\nwant    %v", got, want)
	}

	// Past the end: empty page, nothing more.
	l, err = ListContext(context.Background(), dir, ListOptions{Offset: 1000})
	if err != nil || len(l.Entries) != 0 || l.Next != nil || l.Truncated || l.Total != len(want) {
		t.Fatalf("past the end: %+v %v", l, err)
	}
}

func TestListScanCap(t *testing.T) {
	dir, _ := pagingFixture(t)
	oldScan := MaxScan
	t.Cleanup(func() { MaxScan = oldScan })
	MaxScan = 12
	MaxEntries = 5

	seen := 0
	offset := 0
	for pages := 0; ; pages++ {
		if pages > 10 {
			t.Fatal("paging past the scan cap does not terminate")
		}
		l, err := ListContext(context.Background(), dir, ListOptions{Offset: offset})
		if err != nil {
			t.Fatal(err)
		}
		if !l.Incomplete || !l.Truncated || l.Total != 12 {
			t.Fatalf("scan cap not reported: %+v", l)
		}
		seen += len(l.Entries)
		if l.Next == nil {
			break
		}
		offset = *l.Next
	}
	if seen != 12 {
		t.Fatalf("saw %d entries, want the 12 that were read", seen)
	}
}

func TestListCancelled(t *testing.T) {
	dir, _ := pagingFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := ListContext(ctx, dir, ListOptions{}); !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want context.Canceled", err)
	}
}

func TestListMarksProtectedEntries(t *testing.T) {
	root := denyFixture(t)
	if err := os.Symlink(filepath.Join(root, "boot/config/shadow"), filepath.Join(root, "boot/config/shadow.link")); err != nil {
		t.Fatal(err)
	}
	l, err := List(filepath.Join(root, "boot/config"))
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]bool{"shadow": true, "passwd": true, "smbpasswd": true, "ssh": true, "ssl": true,
		"wireguard": true, "shadow.link": true, "go": false, "plugins": false}
	got := map[string]bool{}
	for _, e := range l.Entries {
		got[e.Name] = e.Protected
	}
	for name, p := range want {
		if v, ok := got[name]; !ok || v != p {
			t.Errorf("%s: protected = %v (listed %v), want %v", name, v, ok, p)
		}
	}
	l, err = List(filepath.Join(root, "boot/config/plugins/raidman"))
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range l.Entries {
		if want := e.Name == "settings.json"; e.Protected != want {
			t.Errorf("plugins/raidman/%s: protected = %v, want %v", e.Name, e.Protected, want)
		}
	}
}
