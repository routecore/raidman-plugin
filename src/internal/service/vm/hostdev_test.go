package vm

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func readFixture(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestParseHostdevs(t *testing.T) {
	refs, err := parseHostdevs(readFixture(t, "domain_hostdevs.xml"))
	if err != nil {
		t.Fatal(err)
	}
	want := []hostdevRef{
		{Type: "pci", Address: "0000:01:00.0"},
		{Type: "pci", Address: "0000:01:00.1"},
		{Type: "pci", Address: "0000:0a:00.3"},
		{Type: "usb", Address: "046d:c52b", Vendor: "046d", Product: "c52b"},
		{Type: "usb", Address: "001.004"},
	}
	if !reflect.DeepEqual(refs, want) {
		t.Fatalf("refs =\n%+v\nwant\n%+v", refs, want)
	}

	// No <devices> / no hostdevs → empty, not nil.
	refs, err = parseHostdevs(`<domain><name>x</name></domain>`)
	if err != nil || refs == nil || len(refs) != 0 {
		t.Fatalf("empty domain: %v %v", refs, err)
	}
	if _, err := parseHostdevs(`<domain><devices>`); err == nil {
		t.Error("truncated XML parsed")
	}
}

func TestPCIAddressValidation(t *testing.T) {
	cases := []struct {
		a    hostdevXMLAddress
		want string
	}{
		{hostdevXMLAddress{Domain: "0x0000", Bus: "0x01", Slot: "0x00", Function: "0x0"}, "0000:01:00.0"},
		{hostdevXMLAddress{Domain: "0x10000", Bus: "0x01", Slot: "0x00", Function: "0x0"}, ""}, // domain > 16 bit
		{hostdevXMLAddress{Domain: "0", Bus: "255", Slot: "31", Function: "7"}, "0000:ff:1f.7"},
		{hostdevXMLAddress{Bus: "0x100", Slot: "0x00", Function: "0x0"}, ""}, // bus > 0xff
		{hostdevXMLAddress{Bus: "0x01", Slot: "0x20", Function: "0x0"}, ""},  // slot > 0x1f
		{hostdevXMLAddress{Bus: "0x01", Slot: "0x00", Function: "0x8"}, ""},  // function > 7
		{hostdevXMLAddress{Bus: "0x01", Slot: "0x00"}, ""},                   // function missing
		{hostdevXMLAddress{Bus: "0x01/..", Slot: "0x00", Function: "0"}, ""},
		{hostdevXMLAddress{Bus: "-1", Slot: "0x00", Function: "0"}, ""},
		{hostdevXMLAddress{Bus: " 0x02 ", Slot: "0x00", Function: "0"}, "0000:02:00.0"},
	}
	for _, c := range cases {
		a := c.a
		if got := pciAddress(&a); got != c.want {
			t.Errorf("pciAddress(%+v) = %q, want %q", c.a, got, c.want)
		}
	}
	if pciAddress(nil) != "" {
		t.Error("nil address")
	}
	for _, bad := range []string{"0000:01:00.8", "0000:1:00.0", "../../../etc", "0000:01:00.0/..", "0000:01:00.0\n", "0000:0G:00.0"} {
		if pciAddrRe.MatchString(bad) {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestClassKind(t *testing.T) {
	cases := map[uint32]string{
		0x030000: HostdevKindGPU,   // VGA compatible controller
		0x030200: HostdevKindGPU,   // 3D controller (e.g. Tesla / headless)
		0x038000: HostdevKindGPU,   // display controller, other
		0x040300: HostdevKindAudio, // HD audio (GPU HDMI function)
		0x040100: "",               // multimedia audio controller (legacy AC'97): not HDA
		0x0c0330: HostdevKindUSB,   // xHCI
		0x0c0320: HostdevKindUSB,   // EHCI
		0x010802: "",               // NVMe
		0x020000: "",               // Ethernet
		0x0c0500: "",               // SMBus
	}
	for class, want := range cases {
		if got := classKind(class); got != want {
			t.Errorf("classKind(%#06x) = %q, want %q", class, got, want)
		}
	}
}

// fakeSysfs writes /sys/bus/pci/devices/<addr>/{class,vendor,device}.
func fakeSysfs(t *testing.T, devs map[string][3]string) string {
	t.Helper()
	root := t.TempDir()
	for addr, v := range devs {
		dir := filepath.Join(root, addr)
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		for i, name := range []string{"class", "vendor", "device"} {
			if v[i] == "" {
				continue
			}
			if err := os.WriteFile(filepath.Join(dir, name), []byte(v[i]+"\n"), 0o644); err != nil {
				t.Fatal(err)
			}
		}
	}
	return root
}

func withHostData(t *testing.T, sysfs string, pciIDs, usbIDs []string) {
	t.Helper()
	oldSys, oldPCI, oldUSB := sysfsPCIDevices, pciIDsPaths, usbIDsPaths
	sysfsPCIDevices, pciIDsPaths, usbIDsPaths = sysfs, pciIDs, usbIDs
	t.Cleanup(func() { sysfsPCIDevices, pciIDsPaths, usbIDsPaths = oldSys, oldPCI, oldUSB })
}

func TestResolveHostdevs(t *testing.T) {
	sysfs := fakeSysfs(t, map[string][3]string{
		"0000:01:00.0": {"0x030000", "0x10de", "0x2204"},
		"0000:01:00.1": {"0x040300", "0x10de", "0x1aef"},
		"0000:0a:00.3": {"0x0c0330", "0x1912", "0x0014"},
	})
	abs, _ := filepath.Abs("testdata")
	withHostData(t, sysfs,
		[]string{filepath.Join(t.TempDir(), "missing.ids"), filepath.Join(abs, "pci.ids")},
		[]string{filepath.Join(abs, "usb.ids")})

	refs, err := parseHostdevs(readFixture(t, "domain_hostdevs.xml"))
	if err != nil {
		t.Fatal(err)
	}
	// Plus a PCI device that is not on this host (stale XML after a hardware change).
	refs = append(refs, hostdevRef{Type: "pci", Address: "0000:05:00.0"})
	got := resolveHostdevs(refs)

	b, _ := json.Marshal(got)
	want := `[` +
		`{"type":"pci","kind":"gpu","name":"GA102 [GeForce RTX 3090]","vendor":"NVIDIA Corporation","address":"0000:01:00.0"},` +
		`{"type":"pci","kind":"audio","name":"GA102 High Definition Audio Controller","vendor":"NVIDIA Corporation","address":"0000:01:00.1"},` +
		`{"type":"pci","kind":"usb","name":"uPD720201 USB 3.0 Host Controller","vendor":"Renesas Technology Corp.","address":"0000:0a:00.3"},` +
		`{"type":"usb","kind":"usb","name":"Unifying Receiver","vendor":"Logitech, Inc.","address":"046d:c52b"},` +
		`{"type":"usb","kind":"usb","name":null,"vendor":null,"address":"001.004"},` +
		`{"type":"pci","kind":null,"name":null,"vendor":null,"address":"0000:05:00.0"}` +
		`]`
	if string(b) != want {
		t.Errorf("hostdevs =\n%s\nwant\n%s", b, want)
	}

	// An address that slipped past parsing is never used as a path.
	if out := resolveHostdevs([]hostdevRef{{Type: "pci", Address: "../../../etc"}, {Type: "scsi", Address: "x"}}); len(out) != 0 {
		t.Errorf("invalid refs resolved: %+v", out)
	}
}

func TestResolveHostdevsWithoutIDsFile(t *testing.T) {
	sysfs := fakeSysfs(t, map[string][3]string{
		"0000:03:00.0": {"0x030000", "0x1002", "0x73bf"},
		"0000:04:00.0": {"0x030000", "0x1b36", "0x0100"}, // unknown vendor (QEMU)
	})
	withHostData(t, sysfs, []string{filepath.Join(t.TempDir(), "none.ids")}, nil)
	got := resolveHostdevs([]hostdevRef{{Type: "pci", Address: "0000:03:00.0"}, {Type: "pci", Address: "0000:04:00.0"}})
	if len(got) != 2 {
		t.Fatalf("got %+v", got)
	}
	if got[0].Vendor == nil || !strings.Contains(*got[0].Vendor, "AMD") || got[0].Name != nil || got[0].Kind == nil || *got[0].Kind != "gpu" {
		t.Errorf("AMD fallback = %+v", got[0])
	}
	if got[1].Vendor != nil || got[1].Name != nil {
		t.Errorf("unknown vendor = %+v", got[1])
	}
}

func TestScanIDs(t *testing.T) {
	ids := readFixture(t, "pci.ids")
	cases := []struct{ v, d, wantV, wantD string }{
		{"10de", "2204", "NVIDIA Corporation", "GA102 [GeForce RTX 3090]"},
		{"10de", "2206", "NVIDIA Corporation", "GA102 [GeForce RTX 3080]"}, // after a subsystem line
		{"10de", "ffff", "NVIDIA Corporation", ""},
		{"1002", "", "Advanced Micro Devices, Inc. [AMD/ATI]", ""},
		{"abcd", "0000", "", ""},
		{"1912", "0014", "Renesas Technology Corp.", "uPD720201 USB 3.0 Host Controller"},
		{"ffff", "00", "Illegal Vendor ID", ""},
	}
	for _, c := range cases {
		got := scanIDs(strings.NewReader(ids), c.v, c.d)
		if got.vendor != c.wantV || got.device != c.wantD {
			t.Errorf("scanIDs(%s,%s) = %+v", c.v, c.d, got)
		}
	}
	// The class section ("C 03  Display controller" / "\t00  VGA ...") is never read as vendor 0003/device 00.
	if got := scanIDs(strings.NewReader(ids), "c 03", ""); got.vendor != "" {
		t.Errorf("class section matched: %+v", got)
	}
	// Ids that are not 4 lowercase hex digits never trigger a file read.
	if v, d := lookupIDs([]string{"/nonexistent"}, "../x", ""); v != "" || d != "" {
		t.Error("invalid id looked up")
	}
}
