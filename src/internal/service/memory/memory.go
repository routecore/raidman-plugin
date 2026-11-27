// Package memory reports how host RAM is used: total / used / page cache
// from /proc/meminfo, the ZFS ARC (which Linux counts as "used", not
// cache), the resident memory of running VMs (qemu processes) and of Docker
// containers (the docker cgroup).
//
// Everything is read from procfs / cgroupfs; nothing is executed. Values a
// host cannot report (no ZFS module, no qemu, no docker cgroup) are nil.
package memory

import (
	"bufio"
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// Overridable in tests.
var (
	ProcDir      = "/proc"
	ArcstatsPath = "/proc/spl/kstat/zfs/arcstats"
	CgroupDir    = "/sys/fs/cgroup"
)

// maxProcFile bounds every procfs / cgroupfs read.
const maxProcFile = 1 << 20

// Breakdown is the GET /api/system/memory response (bytes).
type Breakdown struct {
	TotalBytes  uint64  `json:"totalBytes"`
	UsedBytes   uint64  `json:"usedBytes"`
	CachedBytes uint64  `json:"cachedBytes"`
	ZfsArcBytes *uint64 `json:"zfsArcBytes"`
	VMBytes     *uint64 `json:"vmBytes"`
	DockerBytes *uint64 `json:"dockerBytes"`
}

func readSmall(p string) ([]byte, error) {
	f, err := os.Open(p)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return io.ReadAll(io.LimitReader(f, maxProcFile))
}

// ParseMeminfo returns /proc/meminfo in bytes ("MemTotal: 16 kB" -> 16384).
func ParseMeminfo(data []byte) map[string]uint64 {
	out := map[string]uint64{}
	sc := bufio.NewScanner(bytes.NewReader(data))
	for sc.Scan() {
		key, rest, ok := strings.Cut(sc.Text(), ":")
		if !ok {
			continue
		}
		f := strings.Fields(rest)
		if len(f) == 0 {
			continue
		}
		v, err := strconv.ParseUint(f[0], 10, 64)
		if err != nil {
			continue
		}
		if len(f) > 1 && strings.EqualFold(f[1], "kB") {
			v *= 1024
		}
		out[strings.TrimSpace(key)] = v
	}
	return out
}

// FromMeminfo computes total / used / cached like free(1): used is what is
// not available (MemTotal - MemAvailable), cached is buffers + page cache +
// reclaimable slab.
func FromMeminfo(m map[string]uint64) (total, used, cached uint64, err error) {
	total, ok := m["MemTotal"]
	if !ok || total == 0 {
		return 0, 0, 0, errors.New("MemTotal missing from meminfo")
	}
	avail, ok := m["MemAvailable"]
	if !ok {
		// Kernels before 3.14.
		avail = m["MemFree"] + m["Buffers"] + m["Cached"]
	}
	if avail < total {
		used = total - avail
	}
	cached = m["Buffers"] + m["Cached"] + m["SReclaimable"]
	return total, used, cached, nil
}

// ParseArcstats returns the ARC size from /proc/spl/kstat/zfs/arcstats
// ("name type data" rows after a two-line header).
func ParseArcstats(data []byte) (uint64, bool) {
	sc := bufio.NewScanner(bytes.NewReader(data))
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) == 3 && f[0] == "size" {
			if v, err := strconv.ParseUint(f[2], 10, 64); err == nil {
				return v, true
			}
		}
	}
	return 0, false
}

// ParseStatus returns Name and VmRSS (bytes) from /proc/<pid>/status.
func ParseStatus(data []byte) (name string, rss uint64) {
	sc := bufio.NewScanner(bytes.NewReader(data))
	for sc.Scan() {
		key, rest, ok := strings.Cut(sc.Text(), ":")
		if !ok {
			continue
		}
		switch key {
		case "Name":
			name = strings.TrimSpace(rest)
		case "VmRSS":
			f := strings.Fields(rest)
			if len(f) > 0 {
				if v, err := strconv.ParseUint(f[0], 10, 64); err == nil {
					rss = v * 1024
				}
			}
		}
	}
	return name, rss
}

// vmResident sums the resident memory of every qemu process (one per
// running VM). nil when /proc cannot be listed.
func vmResident() *uint64 {
	des, err := os.ReadDir(ProcDir)
	if err != nil {
		return nil
	}
	var sum uint64
	for _, de := range des {
		if _, err := strconv.Atoi(de.Name()); err != nil {
			continue
		}
		data, err := readSmall(filepath.Join(ProcDir, de.Name(), "status"))
		if err != nil {
			continue // exited meanwhile
		}
		// The kernel truncates comm to 15 bytes ("qemu-system-x86").
		if name, rss := ParseStatus(data); strings.HasPrefix(name, "qemu-system") || name == "qemu-kvm" {
			sum += rss
		}
	}
	return &sum
}

// statValue returns key's value from a cgroup memory.stat file.
func statValue(data []byte, key string) uint64 {
	sc := bufio.NewScanner(bytes.NewReader(data))
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) == 2 && f[0] == key {
			v, _ := strconv.ParseUint(f[1], 10, 64)
			return v
		}
	}
	return 0
}

func readUint(p string) (uint64, bool) {
	data, err := readSmall(p)
	if err != nil {
		return 0, false
	}
	v, err := strconv.ParseUint(strings.TrimSpace(string(data)), 10, 64)
	return v, err == nil
}

// CgroupUsage returns the memory of cgroup group minus its inactive file
// cache (what "docker stats" shows), for cgroup v2 then v1. false when the
// group does not exist.
func CgroupUsage(group string) (uint64, bool) {
	try := func(usageFile, statFile, inactiveKey string) (uint64, bool) {
		usage, ok := readUint(usageFile)
		if !ok {
			return 0, false
		}
		if stat, err := readSmall(statFile); err == nil {
			if inactive := statValue(stat, inactiveKey); inactive < usage {
				usage -= inactive
			}
		}
		return usage, true
	}
	v2 := filepath.Join(CgroupDir, group)
	if v, ok := try(filepath.Join(v2, "memory.current"), filepath.Join(v2, "memory.stat"), "inactive_file"); ok {
		return v, true
	}
	v1 := filepath.Join(CgroupDir, "memory", group)
	return try(filepath.Join(v1, "memory.usage_in_bytes"), filepath.Join(v1, "memory.stat"), "total_inactive_file")
}

// Get reads the breakdown.
func Get() (Breakdown, error) {
	data, err := readSmall(filepath.Join(ProcDir, "meminfo"))
	if err != nil {
		return Breakdown{}, err
	}
	total, used, cached, err := FromMeminfo(ParseMeminfo(data))
	if err != nil {
		return Breakdown{}, err
	}
	b := Breakdown{TotalBytes: total, UsedBytes: used, CachedBytes: cached}
	if data, err := readSmall(ArcstatsPath); err == nil {
		if v, ok := ParseArcstats(data); ok {
			b.ZfsArcBytes = &v
		}
	}
	b.VMBytes = vmResident()
	if v, ok := CgroupUsage("docker"); ok {
		b.DockerBytes = &v
	}
	return b, nil
}
