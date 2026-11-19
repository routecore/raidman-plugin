package memory

import (
	"os"
	"path/filepath"
	"testing"
)

const meminfo = `MemTotal:       32768000 kB
MemFree:         1000000 kB
MemAvailable:   20000000 kB
Buffers:          100000 kB
Cached:          8000000 kB
SwapCached:            0 kB
SReclaimable:     400000 kB
HugePages_Total:       0
Hugepagesize:       2048 kB
`

const arcstats = `13 1 0x01 123 33456 1234567890 98765432101
name                            type data
hits                            4    123456789
misses                          4    1234
c_max                           4    16777216000
size                            4    8589934592
compressed_size                 4    4000000000
`

func TestParseMeminfo(t *testing.T) {
	m := ParseMeminfo([]byte(meminfo))
	if m["MemTotal"] != 32768000*1024 || m["HugePages_Total"] != 0 || m["Hugepagesize"] != 2048*1024 {
		t.Fatalf("%v", m)
	}
	total, used, cached, err := FromMeminfo(m)
	if err != nil || total != 32768000*1024 || used != (32768000-20000000)*1024 || cached != (100000+8000000+400000)*1024 {
		t.Fatalf("%d %d %d %v", total, used, cached, err)
	}
	// Old kernels: no MemAvailable.
	_, used, _, _ = FromMeminfo(map[string]uint64{"MemTotal": 100, "MemFree": 10, "Buffers": 5, "Cached": 15})
	if used != 70 {
		t.Fatalf("fallback used = %d", used)
	}
	if _, _, _, err := FromMeminfo(map[string]uint64{}); err == nil {
		t.Fatal("missing MemTotal must error")
	}
}

func TestParseArcstats(t *testing.T) {
	if v, ok := ParseArcstats([]byte(arcstats)); !ok || v != 8589934592 {
		t.Fatalf("%d %v", v, ok)
	}
	if _, ok := ParseArcstats([]byte("name type data\nhits 4 1\n")); ok {
		t.Fatal("no size row")
	}
	if _, ok := ParseArcstats([]byte("size 4 notanumber\n")); ok {
		t.Fatal("bad number")
	}
}

func TestParseStatus(t *testing.T) {
	name, rss := ParseStatus([]byte("Name:\tqemu-system-x86\nUmask:\t0022\nVmRSS:\t 8388608 kB\n"))
	if name != "qemu-system-x86" || rss != 8388608*1024 {
		t.Fatalf("%q %d", name, rss)
	}
}

func write(t *testing.T, p, data string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(data), 0o644); err != nil {
		t.Fatal(err)
	}
}

func setDirs(t *testing.T) string {
	root := t.TempDir()
	oldProc, oldArc, oldCg := ProcDir, ArcstatsPath, CgroupDir
	t.Cleanup(func() { ProcDir, ArcstatsPath, CgroupDir = oldProc, oldArc, oldCg })
	ProcDir = filepath.Join(root, "proc")
	ArcstatsPath = filepath.Join(root, "proc/spl/kstat/zfs/arcstats")
	CgroupDir = filepath.Join(root, "cgroup")
	return root
}

func TestGet(t *testing.T) {
	root := setDirs(t)
	write(t, filepath.Join(root, "proc/meminfo"), meminfo)
	write(t, filepath.Join(root, "proc/101/status"), "Name:\tqemu-system-x86\nVmRSS:\t1000 kB\n")
	write(t, filepath.Join(root, "proc/102/status"), "Name:\tqemu-system-aarch64\nVmRSS:\t500 kB\n")
	write(t, filepath.Join(root, "proc/103/status"), "Name:\tdockerd\nVmRSS:\t9999 kB\n")
	write(t, filepath.Join(root, "proc/self/status"), "Name:\tqemu-system-x86\nVmRSS:\t7777 kB\n") // not a pid dir

	b, err := Get()
	if err != nil {
		t.Fatal(err)
	}
	if b.TotalBytes != 32768000*1024 || b.ZfsArcBytes != nil || b.DockerBytes != nil || b.VMBytes == nil || *b.VMBytes != 1500*1024 {
		t.Fatalf("%+v", b)
	}

	// ZFS + cgroup v2 docker group.
	write(t, ArcstatsPath, arcstats)
	write(t, filepath.Join(CgroupDir, "docker/memory.current"), "1000000\n")
	write(t, filepath.Join(CgroupDir, "docker/memory.stat"), "anon 600000\nfile 400000\ninactive_file 300000\n")
	b, err = Get()
	if err != nil || b.ZfsArcBytes == nil || *b.ZfsArcBytes != 8589934592 || b.DockerBytes == nil || *b.DockerBytes != 700000 {
		t.Fatalf("%+v %v", b, err)
	}
}

func TestCgroupV1(t *testing.T) {
	setDirs(t)
	write(t, filepath.Join(CgroupDir, "memory/docker/memory.usage_in_bytes"), "5000\n")
	write(t, filepath.Join(CgroupDir, "memory/docker/memory.stat"), "cache 3000\ninactive_file 10\ntotal_inactive_file 2000\n")
	if v, ok := CgroupUsage("docker"); !ok || v != 3000 {
		t.Fatalf("%d %v", v, ok)
	}
	if _, ok := CgroupUsage("missing"); ok {
		t.Fatal("missing group")
	}
}

func TestGetNoProc(t *testing.T) {
	setDirs(t)
	if _, err := Get(); err == nil {
		t.Fatal("no meminfo must error")
	}
}
