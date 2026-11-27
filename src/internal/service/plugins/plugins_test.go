package plugins

import (
	"context"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/routecore/raidman-plugin/src/internal/service/execx"
	"github.com/routecore/raidman-plugin/src/internal/service/httperr"
)

func TestParsePLG(t *testing.T) {
	data, _ := os.ReadFile("testdata/raidman.plg")
	a, err := ParsePLG(data)
	if err != nil {
		t.Fatal(err)
	}
	if a["name"] != "raidman" || a["author"] != "Routecore" || a["version"] == "" || a["version"][0] == '&' ||
		a["pluginURL"] != "https://raw.githubusercontent.com/routecore/raidman-plugin/main/raidman.plg" ||
		a["support"] != "https://github.com/routecore/raidman-plugin/issues" || a["icon"] != "icon.png" {
		t.Fatalf("raidman attrs = %v", a)
	}

	data, _ = os.ReadFile("testdata/ca.plg")
	a, err = ParsePLG(data)
	if err != nil {
		t.Fatal(err)
	}
	// Nested entities (&github; and &name; inside pluginURL) and single quotes.
	if a["pluginURL"] != "https://raw.githubusercontent.com/Squidly271/community.applications/master/plugins/community.applications.plg" ||
		a["support"] != "https://forums.unraid.net/topic/38582" || a["version"] != "2025.01.10" || a["icon"] != "users" {
		t.Fatalf("ca attrs = %v", a)
	}

	for _, bad := range []string{"not xml at all", "<root/>", `<!DOCTYPE PLUGIN [<!ENTITY a "&b;"><!ENTITY b "&a;">]><PLUGIN name="&a;">`} {
		a, err := ParsePLG([]byte(bad))
		if bad == "not xml at all" || bad == "<root/>" {
			if err == nil {
				t.Errorf("%q: want error, got %v", bad, a)
			}
			continue
		}
		// Cyclic entities terminate.
		if err != nil {
			t.Errorf("cyclic: %v", err)
		}
	}
}

func TestCompareVersions(t *testing.T) {
	for _, c := range []struct {
		a, b string
		want int
	}{
		{"2026.11.18", "2026.11.18", 0},
		{"2026.11.19", "2026.11.18", 1},
		{"2026.11.18a", "2026.11.18", 1},
		{"2026.11.18b", "2026.11.18a", 1},
		{"2026.11.18", "2026.11.18a", -1},
		{"2026.12.01", "2026.11.30a", 1},
		{"2026.1.5", "2026.01.05", 0},
		{"2026.10.01", "2026.9.30", 1},
		{"2025.01.10.1200", "2025.01.10", 1},
		{"7.2.1", "7.2.0", 1},
		{"7.2.0", "7.2.0-rc.1", 1},
		{"7.2.0-rc.2", "7.2.0-rc.1", 1},
		{"7.2.0-beta.1", "7.2.0-rc.1", -1},
		{"7.10.0", "7.9.9", 1},
		{"v1.2", "1.2", 0},
		{"", "1.0", -1},
	} {
		if got := CompareVersions(c.a, c.b); got != c.want {
			t.Errorf("CompareVersions(%q, %q) = %d, want %d", c.a, c.b, got, c.want)
		}
		if got := CompareVersions(c.b, c.a); got != -c.want {
			t.Errorf("CompareVersions(%q, %q) = %d, want %d (antisymmetry)", c.b, c.a, got, -c.want)
		}
	}
}

type call struct {
	name string
	args []string
}

// setup builds installed/boot/tmp plugin dirs from fixtures and fakes the
// plugin binary; nothing is executed.
func setup(t *testing.T) *[]call {
	t.Helper()
	dir := t.TempDir()
	old := []string{InstalledDir, BootDir, TmpDir, PluginBinary, SelfUpdateLog}
	oldRun, oldStart := Run, StartDetached
	t.Cleanup(func() {
		InstalledDir, BootDir, TmpDir, PluginBinary, SelfUpdateLog = old[0], old[1], old[2], old[3], old[4]
		Run, StartDetached = oldRun, oldStart
	})
	InstalledDir = filepath.Join(dir, "log")
	BootDir = filepath.Join(dir, "boot")
	TmpDir = filepath.Join(dir, "tmp")
	PluginBinary = filepath.Join(dir, "plugin")
	SelfUpdateLog = filepath.Join(dir, "update.log")
	for _, d := range []string{InstalledDir, BootDir, TmpDir} {
		os.MkdirAll(d, 0o755)
	}
	os.WriteFile(PluginBinary, nil, 0o755)
	cp := func(src, dst string) {
		b, err := os.ReadFile(filepath.Join("testdata", src))
		if err != nil {
			t.Fatal(err)
		}
		os.WriteFile(dst, b, 0o644)
	}
	for _, f := range []string{"raidman.plg", "ca.plg", "dynamix.system.temp.plg", "unRAIDServer.plg", "broken.plg"} {
		cp(f, filepath.Join(InstalledDir, f))
	}
	// Flash-only copy (not installed yet) and a duplicate of an installed one.
	cp("ca.plg", filepath.Join(BootDir, "ca.plg"))
	os.WriteFile(filepath.Join(BootDir, "extra.plg"), []byte(`<!DOCTYPE PLUGIN [<!ENTITY version "1.0">]><PLUGIN name="extra" version="&version;"></PLUGIN>`), 0o644)

	// "plugin checkall" left a newer CA (named after its pluginURL) and an
	// older dynamix copy (named after the installed file).
	ca, _ := os.ReadFile("testdata/ca.plg")
	os.WriteFile(filepath.Join(TmpDir, "community.applications.plg"), []byte(strings.Replace(string(ca), `"2025.01.10"`, `"2025.01.10a"`, 1)), 0o644)
	dt, _ := os.ReadFile("testdata/dynamix.system.temp.plg")
	os.WriteFile(filepath.Join(TmpDir, "dynamix.system.temp.plg"), []byte(strings.Replace(string(dt), `"2024.12.01"`, `"2024.11.01"`, 1)), 0o644)

	calls := &[]call{}
	Run = func(_ context.Context, name string, args ...string) (execx.Result, error) {
		*calls = append(*calls, call{name, args})
		return execx.Result{Stdout: []byte("plugin: ok\n"), ExitCode: 0}, nil
	}
	StartDetached = func(_ string, name string, args ...string) error {
		*calls = append(*calls, call{"detached:" + name, args})
		return nil
	}
	return calls
}

func TestList(t *testing.T) {
	setup(t)
	list, err := List()
	if err != nil {
		t.Fatal(err)
	}
	byFile := map[string]Plugin{}
	for _, p := range list {
		if _, dup := byFile[p.File]; dup {
			t.Errorf("duplicate %s", p.File)
		}
		byFile[p.File] = p
	}
	if len(list) != 5 || byFile["broken.plg"].File != "" {
		t.Fatalf("list = %+v", list)
	}
	ca := byFile["ca.plg"]
	if ca.Name != "community.applications" || !ca.UpdateAvailable || ca.LatestVersion != "2025.01.10a" || ca.Author != "Andrew Zawadzki" || ca.Icon != "users" {
		t.Errorf("ca = %+v", ca)
	}
	if dt := byFile["dynamix.system.temp.plg"]; dt.UpdateAvailable || dt.LatestVersion != "" {
		t.Errorf("older tmp copy must not be an update: %+v", dt)
	}
	if ex := byFile["extra.plg"]; ex.Name != "extra" || ex.Version != "1.0" {
		t.Errorf("flash-only plugin: %+v", ex)
	}
	if list[0].Name != "community.applications" {
		t.Errorf("not sorted: %s first", list[0].Name)
	}
}

func TestListMissingDirs(t *testing.T) {
	setup(t)
	InstalledDir, BootDir = "/nonexistent/a", "/nonexistent/b"
	if _, err := List(); httperr.StatusOf(err) != http.StatusNotImplemented {
		t.Fatalf("err = %v", err)
	}
}

func TestRemoveRefusals(t *testing.T) {
	for _, c := range []struct {
		p       Plugin
		refused bool
	}{
		{Plugin{Name: "dynamix.system.temp", File: "dynamix.system.temp.plg"}, true},
		{Plugin{Name: "Dynamix.Cache.Dirs", File: "dynamix.cache.dirs.plg"}, true},
		{Plugin{Name: "something", File: "dynamix.x.plg"}, true},
		{Plugin{Name: "unRAIDServer", File: "unRAIDServer.plg"}, true},
		{Plugin{Name: "x", File: "unraidserver.plg"}, true},
		{Plugin{Name: "raidman", File: "raidman.plg"}, true},
		{Plugin{Name: "RaidMan", File: "other.plg"}, true},
		{Plugin{Name: "community.applications", File: "ca.plg"}, false},
		{Plugin{Name: "unassigned.devices", File: "unassigned.devices.plg"}, false},
		{Plugin{Name: "my-dynamix-fork", File: "my-dynamix-fork.plg"}, false},
	} {
		if got := RemoveRefusal(c.p) != ""; got != c.refused {
			t.Errorf("%+v refused=%v, want %v", c.p, got, c.refused)
		}
	}
}

func TestRemove(t *testing.T) {
	calls := setup(t)
	ctx := context.Background()
	for _, name := range []string{"dynamix.system.temp", "unRAIDServer", "raidman", "raidman.plg"} {
		if _, err := Remove(ctx, name); httperr.StatusOf(err) != http.StatusUnprocessableEntity {
			t.Errorf("remove %s: %v", name, err)
		}
	}
	for _, name := range []string{"nope", "../../etc/passwd", "-rf"} {
		if _, err := Remove(ctx, name); httperr.StatusOf(err) != http.StatusUnprocessableEntity {
			t.Errorf("remove %s: %v", name, err)
		}
	}
	if _, err := Remove(ctx, ""); httperr.StatusOf(err) != http.StatusBadRequest {
		t.Errorf("empty: %v", err)
	}
	if len(*calls) != 0 {
		t.Fatalf("refused removes ran commands: %v", *calls)
	}
	// By plugin name: argv gets the installed file name.
	res, err := Remove(ctx, "community.applications")
	if err != nil || !res.OK {
		t.Fatalf("remove: %+v %v", res, err)
	}
	if c := (*calls)[0]; c.name != PluginBinary || strings.Join(c.args, " ") != "remove ca.plg" {
		t.Errorf("call = %+v", c)
	}
	// Failure exit -> ok:false with output.
	Run = func(context.Context, string, ...string) (execx.Result, error) {
		return execx.Result{Stdout: []byte("plugin: remove failed"), ExitCode: 1}, nil
	}
	res, err = Remove(ctx, "ca")
	if err != nil || res.OK || res.Output != "plugin: remove failed" {
		t.Errorf("failed remove: %+v %v", res, err)
	}
}

func TestUpdate(t *testing.T) {
	calls := setup(t)
	ctx := context.Background()
	if _, err := Update(ctx, "unRAIDServer"); httperr.StatusOf(err) != http.StatusUnprocessableEntity {
		t.Errorf("OS update: %v", err)
	}
	// tmp copy present: update directly.
	os.WriteFile(filepath.Join(TmpDir, "ca.plg"), []byte("x"), 0o644)
	res, err := Update(ctx, "ca.plg")
	if err != nil || !res.OK {
		t.Fatalf("update: %+v %v", res, err)
	}
	if len(*calls) != 1 || strings.Join((*calls)[0].args, " ") != "update ca.plg" {
		t.Fatalf("calls = %+v", *calls)
	}
	// tmp copy missing: check first.
	*calls = nil
	if _, err := Update(ctx, "extra"); err != nil {
		t.Fatal(err)
	}
	if len(*calls) != 2 || strings.Join((*calls)[0].args, " ") != "check extra.plg" || strings.Join((*calls)[1].args, " ") != "update extra.plg" {
		t.Fatalf("calls = %+v", *calls)
	}
	// Self-update is detached.
	*calls = nil
	os.WriteFile(filepath.Join(TmpDir, "raidman.plg"), []byte("x"), 0o644)
	res, err = Update(ctx, "raidman")
	if err != nil || !res.OK || len(*calls) != 1 || (*calls)[0].name != "detached:"+PluginBinary || strings.Join((*calls)[0].args, " ") != "update raidman.plg" {
		t.Fatalf("self update: %+v %v %+v", res, err, *calls)
	}
	// Timeout -> ok:false.
	Run = func(context.Context, string, ...string) (execx.Result, error) {
		return execx.Result{ExitCode: -1}, context.DeadlineExceeded
	}
	res, err = Update(ctx, "ca")
	if err != nil || res.OK || !strings.Contains(res.Output, "timed out") {
		t.Errorf("timeout: %+v %v", res, err)
	}
}

func TestOpsSerialised(t *testing.T) {
	setup(t)
	opMu.Lock()
	defer opMu.Unlock()
	if _, err := Remove(context.Background(), "ca"); httperr.StatusOf(err) != http.StatusConflict {
		t.Errorf("busy remove: %v", err)
	}
	if _, err := CheckAll(context.Background()); httperr.StatusOf(err) != http.StatusConflict {
		t.Errorf("busy check: %v", err)
	}
}

func TestCheckAll(t *testing.T) {
	calls := setup(t)
	list, err := CheckAll(context.Background())
	if err != nil || len(list) != 5 || strings.Join((*calls)[0].args, " ") != "checkall" {
		t.Fatalf("%v %v %+v", list, err, *calls)
	}
	os.Remove(PluginBinary)
	if _, err := CheckAll(context.Background()); httperr.StatusOf(err) != http.StatusNotImplemented {
		t.Errorf("missing binary: %v", err)
	}
	os.WriteFile(PluginBinary, nil, 0o755)
	Run = func(context.Context, string, ...string) (execx.Result, error) {
		return execx.Result{}, errors.New("exec failed")
	}
	if _, err := CheckAll(context.Background()); err == nil {
		t.Error("exec failure must error")
	}
}
