package array

import "strings"

// Unraid 7.3+ internal boot pools: a pool's type="Cache" slots may carry
// bootPool="no"|"yes"|"dedicated" in disks.ini (the key is absent before 7.3).
// A "dedicated" pool holds only the boot partition, so the webGUI never lists
// it as a pool (Dashboard: DashStats.page:1180-1181, nchan/update_2:423-424;
// Main: nchan/device_list shows only an "Internal Boot(Dedicated)" row). A
// "yes" (hybrid) pool keeps a data partition and stays a pool.
const (
	bootPoolNo        = "no"
	bootPoolHybrid    = "yes"
	bootPoolDedicated = "dedicated"
)

// poolRoot maps a disks.ini slot name to its pool root like the webGUI:
// prefix() strips trailing digits (include/Wrappers.php:173) and a ZFS
// subpool ("cache~special") belongs to the pool before the tilde
// (nchan/device_list: $root = explode($_tilde_,$pool)[0]).
func poolRoot(name string) string {
	root := strings.TrimRight(name, "0123456789")
	if i := strings.Index(root, "~"); i >= 0 {
		root = root[:i]
	}
	return root
}

// normalizeBootPoolMode mirrors resolve_boot_pool_mode (nchan/device_list:325):
// lowercase, trimmed, and anything other than no/yes/dedicated means "no".
func normalizeBootPoolMode(v string) string {
	switch m := strings.ToLower(strings.TrimSpace(v)); m {
	case bootPoolNo, bootPoolHybrid, bootPoolDedicated:
		return m
	}
	return bootPoolNo
}

// bootPoolModes resolves the boot pool mode of every pool in disks.ini. Like
// the webGUI it reads the key from the pool's first slot only: the slot named
// after the pool ($disks[$pool], DashStats.page:1178), else the first slot in
// slot order whose prefix is the pool name (get_first_pool_disk_in_disks,
// nchan/device_list:297). Pools without the key (7.0-7.2) resolve to "no".
func bootPoolModes(sections map[string]map[string]string) map[string]string {
	first := map[string]map[string]string{}
	for _, s := range sortedSections(sections) {
		d := sections[s]
		name := poolSlotName(s, d)
		// get_first_pool_disk_in_disks compares the plain prefix with the
		// root, so subpool slots never stand in for the pool's first slot.
		p := strings.TrimRight(name, "0123456789")
		if p == "" {
			continue
		}
		if name == p || first[p] == nil {
			first[p] = d
		}
	}
	modes := map[string]string{}
	for p, d := range first {
		if d["type"] != "Cache" {
			continue
		}
		modes[p] = normalizeBootPoolMode(d["bootPool"])
	}
	return modes
}

// isDedicatedBootPoolSlot reports whether a type="Cache" slot belongs to a
// dedicated internal boot pool.
func isDedicatedBootPoolSlot(modes map[string]string, name string) bool {
	return modes[poolRoot(name)] == bootPoolDedicated
}

// poolSlotName is the disks.ini slot name the webGUI keys pools by.
func poolSlotName(section string, d map[string]string) string {
	if n := d["name"]; n != "" {
		return n
	}
	return section
}
