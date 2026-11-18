package array

import (
	"context"
	"net/http"
	"net/url"
	"path/filepath"
	"testing"
)

func TestGetDiskStates(t *testing.T) {
	oldDisks, oldDevs := DisksIniPath, DevsIniPath
	t.Cleanup(func() { DisksIniPath, DevsIniPath = oldDisks, oldDevs })
	DisksIniPath, DevsIniPath = "testdata/disks_state.ini", "testdata/devs.ini"

	got, err := GetDiskStates()
	if err != nil {
		t.Fatal(err)
	}
	byName := map[string]DiskState{}
	var order []string
	for _, d := range got {
		byName[d.Name] = d
		order = append(order, d.Name)
	}
	// Ordered by slot index; empty parity2 slot dropped; empty Boot slot kept
	// (official API rule); unassigned devices appended.
	want := []string{"parity", "disk1", "disk2", "cache", "boot", "boot2", "flash", "sdx"}
	if len(order) != len(want) {
		t.Fatalf("order = %v, want %v", order, want)
	}
	for i := range want {
		if order[i] != want[i] {
			t.Fatalf("order = %v, want %v", order, want)
		}
	}

	p := byName["parity"]
	if !p.Spundown || p.Temp != nil || p.Type != "Parity" || p.Device != "sdh" || p.Rotational == nil || !*p.Rotational {
		t.Errorf("parity = %+v", p)
	}
	d1 := byName["disk1"]
	if d1.Spundown || d1.Temp == nil || *d1.Temp != 31 || d1.Status != "DISK_OK" {
		t.Errorf("disk1 = %+v", d1)
	}
	if d2 := byName["disk2"]; d2.Temp != nil || d2.Status != "DISK_DSBL" {
		t.Errorf("disk2 = %+v", d2)
	}
	if c := byName["cache"]; c.Rotational == nil || *c.Rotational {
		t.Errorf("cache = %+v", c)
	}
	if b := byName["boot"]; b.Type != "Boot" || b.Device != "nvme1n1" {
		t.Errorf("boot = %+v", b)
	}
	if b := byName["boot2"]; b.Type != "Boot" || b.Device != "" || b.Status != "DISK_NP" {
		t.Errorf("boot2 = %+v", b)
	}
	if f := byName["flash"]; f.Type != "Flash" || f.Spundown || f.Temp != nil || f.Rotational != nil {
		t.Errorf("flash = %+v", f)
	}
	if u := byName["sdx"]; u.Type != "Unassigned" || u.Status != "DISK_OK" {
		t.Errorf("unassigned = %+v", u)
	}
}

func TestGetDiskStatesMissingFile(t *testing.T) {
	old := DisksIniPath
	t.Cleanup(func() { DisksIniPath = old })
	DisksIniPath = filepath.Join(t.TempDir(), "nope.ini")
	if _, err := GetDiskStates(); err == nil {
		t.Fatal("missing disks.ini must be an error, not an empty list")
	}
}

func TestParseTemp(t *testing.T) {
	if v := ParseTemp("42"); v == nil || *v != 42 {
		t.Fatal(v)
	}
	for _, in := range []string{"*", "", "  ", "n/a"} {
		if v := ParseTemp(in); v != nil {
			t.Errorf("ParseTemp(%q) = %d", in, *v)
		}
	}
}

func TestSpinRequest(t *testing.T) {
	f := withFixtures(t, varIdle)
	ctx := context.Background()
	if err := Spin(ctx, "all", "down"); err != nil {
		t.Fatal(err)
	}
	if err := Spin(ctx, "disk1", "up"); err != nil {
		t.Fatal(err)
	}
	want := []url.Values{{"cmdSpindownAll": {"Apply"}}, {"cmdSpinup": {"disk1"}}}
	if len(f.calls) != 2 || f.calls[0].Encode() != want[0].Encode() || f.calls[1].Encode() != want[1].Encode() {
		t.Fatalf("calls = %v", f.calls)
	}
	for _, c := range []struct{ disk, action string }{{"", "up"}, {"disk1", "sideways"}, {"-rf", "up"}} {
		if err := Spin(ctx, c.disk, c.action); StatusOf(err) != http.StatusBadRequest {
			t.Errorf("Spin(%q,%q) = %v, want 400", c.disk, c.action, err)
		}
	}
	if err := Spin(ctx, "disk42", "up"); StatusOf(err) != http.StatusNotFound {
		t.Errorf("unknown disk: %v", err)
	}
	if len(f.calls) != 2 {
		t.Fatalf("invalid requests reached emhttpd: %v", f.calls)
	}
}
