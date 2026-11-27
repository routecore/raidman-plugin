package array

import (
	"testing"

	"github.com/routecore/raidman-plugin/src/internal/domain"
)

func cacheNames(caches []domain.ArrayDisk) []string {
	var out []string
	for _, c := range caches {
		out = append(out, c.Name)
	}
	return out
}

func sameNames(got, want []string) bool {
	if len(got) != len(want) {
		return false
	}
	for i := range want {
		if got[i] != want[i] {
			return false
		}
	}
	return true
}

// A dedicated internal boot pool (7.3+) is shown by the webGUI only as
// internal boot, so neither of its slots is a pool here; the boot devices
// that share its disks are still reported.
func TestDedicatedBootPool73(t *testing.T) {
	st, err := getArrayStatusWithPaths("testdata/var.ini", "testdata/disks73_bootpool_dedicated.ini", "testdata/devs.ini")
	if err != nil {
		t.Fatal(err)
	}
	if got := cacheNames(st.Caches); !sameNames(got, []string{"cache"}) {
		t.Fatalf("caches = %v, want [cache]", got)
	}
	if st.Boot == nil || st.Boot.Name != "boot" || st.Boot.Device != "nvme1n1" {
		t.Fatalf("boot = %+v", st.Boot)
	}
	if len(st.BootDevices) != 2 || st.BootDevices[1].Device != "nvme2n1" {
		t.Fatalf("bootDevices = %+v", st.BootDevices)
	}
	if len(st.Disks) != 1 || len(st.Parities) != 1 {
		t.Fatalf("unexpected layout: %+v", st)
	}
}

// A hybrid ("yes") boot pool keeps its data partition, so it stays a pool,
// as on the webGUI Dashboard; its boot partition is also a boot device.
func TestHybridBootPool73(t *testing.T) {
	st, err := getArrayStatusWithPaths("testdata/var.ini", "testdata/disks73_bootpool_hybrid.ini", "testdata/devs.ini")
	if err != nil {
		t.Fatal(err)
	}
	if got := cacheNames(st.Caches); !sameNames(got, []string{"cache", "fast"}) {
		t.Fatalf("caches = %v, want [cache fast]", got)
	}
	if st.Boot == nil || st.Boot.Name != "boot" || len(st.BootDevices) != 1 {
		t.Fatalf("boot = %+v, bootDevices = %+v", st.Boot, st.BootDevices)
	}
}

// /api/disks/state keeps reporting the raw disks.ini slot type.
func TestDiskStatesDedicatedBootPool(t *testing.T) {
	oldDisks, oldDevs := DisksIniPath, DevsIniPath
	t.Cleanup(func() { DisksIniPath, DevsIniPath = oldDisks, oldDevs })
	DisksIniPath, DevsIniPath = "testdata/disks73_bootpool_dedicated.ini", "testdata/devs.ini"

	got, err := GetDiskStates()
	if err != nil {
		t.Fatal(err)
	}
	types := map[string]string{}
	for _, d := range got {
		types[d.Name] = d.Type
	}
	for name, want := range map[string]string{"bootpool": "Cache", "bootpool2": "Cache", "boot": "Boot", "boot2": "Boot"} {
		if types[name] != want {
			t.Errorf("%s type = %q, want %q", name, types[name], want)
		}
	}
}

func TestBootPoolModes(t *testing.T) {
	slot := func(idx, name, typ, mode string) map[string]string {
		d := map[string]string{"idx": idx, "name": name, "type": typ, "device": "nvme" + idx}
		if mode != "" {
			d["bootPool"] = mode
		}
		return d
	}
	sections := map[string]map[string]string{
		// Key only on the first slot: every member follows it.
		"bp":  slot("31", "bp", "Cache", " Dedicated "),
		"bp2": slot("32", "bp2", "Cache", ""),
		// A subpool belongs to its root pool.
		"bp~special": slot("33", "bp~special", "Cache", ""),
		"hy":         slot("34", "hy", "Cache", "YES"),
		"odd":        slot("35", "odd", "Cache", "bogus"),
		"legacy":     slot("36", "legacy", "Cache", ""),
		// A later slot's key does not override the first slot's.
		"late":  slot("37", "late", "Cache", "no"),
		"late2": slot("38", "late2", "Cache", "dedicated"),
		"disk1": slot("1", "disk1", "Data", "dedicated"),
	}
	modes := bootPoolModes(sections)
	for name, want := range map[string]bool{
		"bp": true, "bp2": true, "bp~special": true,
		"hy": false, "odd": false, "legacy": false,
		"late": false, "late2": false, "disk1": false,
	} {
		if got := isDedicatedBootPoolSlot(modes, name); got != want {
			t.Errorf("%s dedicated = %v, want %v (modes %v)", name, got, want, modes)
		}
	}
	if modes["hy"] != bootPoolHybrid || modes["odd"] != bootPoolNo || modes["legacy"] != bootPoolNo {
		t.Errorf("modes = %v", modes)
	}
}

// Pre-7.3 fixtures have no bootPool key: every pool resolves to "no".
func TestBootPoolModesLegacy(t *testing.T) {
	for _, f := range []string{"testdata/disks70.ini", "testdata/disks73.ini", "testdata/disks_state.ini"} {
		sections, err := parseIniSections(f)
		if err != nil {
			t.Fatal(err)
		}
		for p, m := range bootPoolModes(sections) {
			if m != bootPoolNo {
				t.Errorf("%s: pool %s mode = %q", f, p, m)
			}
		}
	}
}
