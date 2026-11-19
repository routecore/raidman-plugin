package smart

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/routecore/raidman-plugin/src/internal/service/execx"
	"github.com/routecore/raidman-plugin/src/internal/service/httperr"
)

func fixture(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestDeviceRe(t *testing.T) {
	for _, d := range []string{"sda", "sdz", "sdab", "nvme0n1", "nvme12n3"} {
		if !DeviceRe.MatchString(d) {
			t.Errorf("%q rejected", d)
		}
	}
	for _, d := range []string{"", "sd", "sda1", "sdabc", "SDA", "nvme0", "nvme0n1p1", "md1", "../sda", "/dev/sda", "sda ", "-sda", "sda;reboot", "nvmeXn1", "sda\n", "loop0"} {
		if DeviceRe.MatchString(d) {
			t.Errorf("%q accepted", d)
		}
	}
}

func TestParseATA(t *testing.T) {
	r, err := Parse("sdb", fixture(t, "ata.json"), 0)
	if err != nil {
		t.Fatal(err)
	}
	if r.Standby || r.Passed == nil || !*r.Passed || r.Temperature == nil || *r.Temperature != 34 || r.PowerOnHours == nil || *r.PowerOnHours != 35123 {
		t.Fatalf("report = %+v", r)
	}
	if len(r.Attributes) != 6 {
		t.Fatalf("attributes = %+v", r.Attributes)
	}
	byID := map[int]Attribute{}
	for _, a := range r.Attributes {
		byID[a.ID] = a
	}
	if a := byID[5]; !a.Failing || a.Raw != "2048" || a.Thresh != 140 || a.Name != "Reallocated_Sector_Ct" {
		t.Errorf("attr 5 = %+v", a)
	}
	if a := byID[190]; a.Failing || a.Raw != "34 (Min/Max 22/50)" {
		t.Errorf("attr 190 (failed in the past only) = %+v", a)
	}
	if a := byID[199]; a.Failing || a.Raw != "3" {
		t.Errorf("attr 199 = %+v", a)
	}
}

func TestParseStandby(t *testing.T) {
	for _, f := range []string{"standby.json", "standby_quiet.json"} {
		r, err := Parse("sdc", fixture(t, f), 2)
		if err != nil {
			t.Fatalf("%s: %v", f, err)
		}
		if !r.Standby || r.Passed != nil || r.Temperature != nil || r.Attributes == nil || len(r.Attributes) != 0 {
			t.Errorf("%s: %+v", f, r)
		}
		b, _ := json.Marshal(r)
		if !strings.Contains(string(b), `"attributes":[]`) || !strings.Contains(string(b), `"passed":null`) {
			t.Errorf("%s: JSON %s", f, b)
		}
	}
}

func TestParseNVMe(t *testing.T) {
	r, err := Parse("nvme0n1", fixture(t, "nvme.json"), 0)
	if err != nil {
		t.Fatal(err)
	}
	if r.Passed == nil || !*r.Passed || *r.Temperature != 41 || *r.PowerOnHours != 8000 {
		t.Fatalf("report = %+v", r)
	}
	// 17 scalar counters in smartctl's order; temperature_sensors skipped.
	if len(r.Attributes) != 17 || r.Attributes[0].Name != "critical_warning" || r.Attributes[0].ID != 1 || r.Attributes[5].Name != "data_units_read" || r.Attributes[5].Raw != "123456789" {
		t.Fatalf("attributes = %+v", r.Attributes)
	}
	failing := map[string]bool{}
	for _, a := range r.Attributes {
		if a.Failing {
			failing[a.Name] = true
		}
	}
	if len(failing) != 1 || !failing["available_spare"] {
		t.Errorf("failing = %v", failing)
	}
}

func TestParseFailures(t *testing.T) {
	if _, err := Parse("sdz", fixture(t, "openfail.json"), 2); err == nil || !strings.Contains(err.Error(), "No such device") {
		t.Errorf("open failure: %v", err)
	}
	if _, err := Parse("sdz", []byte("garbage"), 1); err == nil {
		t.Error("garbage must fail")
	}
	if _, err := Parse("sda", []byte(`{"smartctl":{"exit_status":1}}`), 1); err == nil {
		t.Error("bit 0 must fail")
	}
	// Failing health is data, not an error (exit bit 3).
	r, err := Parse("sdd", fixture(t, "failed.json"), 8)
	if err != nil || r.Passed == nil || *r.Passed || r.Standby {
		t.Errorf("failed health: %+v %v", r, err)
	}
}

func TestGet(t *testing.T) {
	dir := t.TempDir()
	oldBin, oldDev, oldRun := SmartctlBinary, DevDir, Run
	t.Cleanup(func() { SmartctlBinary, DevDir, Run = oldBin, oldDev, oldRun })
	SmartctlBinary = filepath.Join(dir, "smartctl")
	DevDir = filepath.Join(dir, "dev")
	os.MkdirAll(DevDir, 0o755)
	os.WriteFile(SmartctlBinary, nil, 0o755)
	os.WriteFile(filepath.Join(DevDir, "sdb"), nil, 0o644)

	var argv []string
	Run = func(_ context.Context, name string, args ...string) (execx.Result, error) {
		argv = append([]string{name}, args...)
		return execx.Result{Stdout: fixture(t, "standby.json"), ExitCode: 2}, nil
	}
	r, err := Get(context.Background(), "sdb")
	if err != nil || !r.Standby {
		t.Fatalf("%+v %v", r, err)
	}
	want := []string{SmartctlBinary, "-n", "standby", "-j", "-H", "-A", filepath.Join(DevDir, "sdb")}
	if strings.Join(argv, " ") != strings.Join(want, " ") {
		t.Errorf("argv = %v", argv)
	}
	if _, err := Get(context.Background(), "sdc"); httperr.StatusOf(err) != http.StatusUnprocessableEntity {
		t.Errorf("missing device: %v", err)
	}
	if _, err := Get(context.Background(), "../sdb"); httperr.StatusOf(err) != http.StatusBadRequest {
		t.Errorf("bad device: %v", err)
	}
}
