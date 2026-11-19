package vm

import (
	"bufio"
	"encoding/xml"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"

	"github.com/routecore/raidman-plugin/src/internal/domain"
)

// Host data sources for passthrough device names (overridable in tests).
// Nothing here runs a command: names come from sysfs files and the
// pci.ids / usb.ids databases that pciutils/usbutils ship.
var (
	sysfsPCIDevices = "/sys/bus/pci/devices"
	pciIDsPaths     = []string{"/usr/share/hwdata/pci.ids", "/usr/share/misc/pci.ids"}
	usbIDsPaths     = []string{"/usr/share/hwdata/usb.ids", "/usr/share/misc/usb.ids"}
)

// Hostdev kinds reported to the app.
const (
	HostdevKindGPU   = "gpu"
	HostdevKindAudio = "audio"
	HostdevKindUSB   = "usb"
)

// hostdevRef is a passthrough device as declared in the domain XML, before
// the host-side lookup. Address is already validated and canonical.
type hostdevRef struct {
	Type    string // "pci" | "usb"
	Address string // PCI "0000:01:00.0"; USB "046d:c52b" (vendor:product) or "001.004" (bus.device)
	Vendor  string // USB vendor id (4 lowercase hex), empty for PCI
	Product string // USB product id (4 lowercase hex), empty for PCI
}

// XML shapes for <devices><hostdev>. Attributes stay strings so a malformed
// value is skipped here instead of failing the whole domain parse.
type hostdevXMLAddress struct {
	Domain   string `xml:"domain,attr"`
	Bus      string `xml:"bus,attr"`
	Slot     string `xml:"slot,attr"`
	Function string `xml:"function,attr"`
	Device   string `xml:"device,attr"` // USB
}

type hostdevXMLID struct {
	ID string `xml:"id,attr"`
}

type hostdevXML struct {
	Mode   string `xml:"mode,attr"`
	Type   string `xml:"type,attr"`
	Source struct {
		// The host-side address. The hostdev's own <address> (sibling of
		// <source>) is the guest slot and is deliberately not read.
		Address *hostdevXMLAddress `xml:"address"`
		Vendor  *hostdevXMLID      `xml:"vendor"`
		Product *hostdevXMLID      `xml:"product"`
	} `xml:"source"`
}

type hostdevDomainXML struct {
	Hostdevs []hostdevXML `xml:"devices>hostdev"`
}

// pciAddrRe is the only PCI address form ever used to build a sysfs path.
var pciAddrRe = regexp.MustCompile(`^[0-9a-f]{4}:[0-9a-f]{2}:[0-9a-f]{2}\.[0-7]$`)

// hexIDRe matches a 4-digit lowercase hex vendor/device/product id.
var hexIDRe = regexp.MustCompile(`^[0-9a-f]{4}$`)

// parseXMLUint parses a libvirt numeric attribute ("0x01" or "1").
func parseXMLUint(s string, max uint64) (uint64, bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, false
	}
	v, err := strconv.ParseUint(s, 0, 32)
	if err != nil || v > max {
		return 0, false
	}
	return v, true
}

// pciAddress formats a PCI source address as DDDD:BB:SS.F, or "" when any
// component is missing or out of range.
func pciAddress(a *hostdevXMLAddress) string {
	if a == nil {
		return ""
	}
	dom, ok1 := parseXMLUint(a.Domain, 0xffff)
	if strings.TrimSpace(a.Domain) == "" {
		dom, ok1 = 0, true // libvirt defaults the domain to 0
	}
	bus, ok2 := parseXMLUint(a.Bus, 0xff)
	slot, ok3 := parseXMLUint(a.Slot, 0x1f)
	fn, ok4 := parseXMLUint(a.Function, 0x7)
	if !ok1 || !ok2 || !ok3 || !ok4 {
		return ""
	}
	addr := fmt.Sprintf("%04x:%02x:%02x.%x", dom, bus, slot, fn)
	if !pciAddrRe.MatchString(addr) {
		return ""
	}
	return addr
}

// usbID normalises a USB vendor/product id ("0x046d") to 4 lowercase hex.
func usbID(id *hostdevXMLID) string {
	if id == nil {
		return ""
	}
	v, ok := parseXMLUint(id.ID, 0xffff)
	if !ok {
		return ""
	}
	return fmt.Sprintf("%04x", v)
}

// parseHostdevs extracts PCI and USB passthrough devices (mode="subsystem")
// from a libvirt domain XML. Entries with missing or invalid addresses and
// other hostdev types (scsi, mdev, capabilities) are skipped.
func parseHostdevs(xmlStr string) ([]hostdevRef, error) {
	var d hostdevDomainXML
	if err := xml.Unmarshal([]byte(xmlStr), &d); err != nil {
		return nil, err
	}
	out := make([]hostdevRef, 0, len(d.Hostdevs))
	for _, h := range d.Hostdevs {
		if h.Mode != "" && h.Mode != "subsystem" {
			continue
		}
		switch h.Type {
		case "pci":
			if addr := pciAddress(h.Source.Address); addr != "" {
				out = append(out, hostdevRef{Type: "pci", Address: addr})
			}
		case "usb":
			vendor, product := usbID(h.Source.Vendor), usbID(h.Source.Product)
			if vendor != "" && product != "" {
				out = append(out, hostdevRef{Type: "usb", Address: vendor + ":" + product, Vendor: vendor, Product: product})
				continue
			}
			if a := h.Source.Address; a != nil {
				bus, ok1 := parseXMLUint(a.Bus, 999)
				dev, ok2 := parseXMLUint(a.Device, 999)
				if ok1 && ok2 {
					out = append(out, hostdevRef{Type: "usb", Address: fmt.Sprintf("%03d.%03d", bus, dev)})
				}
			}
		}
	}
	return out, nil
}

// classKind maps a PCI class code (24-bit, from sysfs "class") to a kind:
// 0x03xxxx display controller → gpu, 0x0403xx HD audio → audio,
// 0x0c03xx USB controller → usb.
func classKind(class uint32) string {
	switch {
	case class>>16 == 0x03:
		return HostdevKindGPU
	case class>>8 == 0x0403:
		return HostdevKindAudio
	case class>>8 == 0x0c03:
		return HostdevKindUSB
	}
	return ""
}

// readSysfsHex reads a small sysfs attribute such as "0x030000\n".
func readSysfsHex(path string, max uint64) (uint64, bool) {
	f, err := os.Open(path)
	if err != nil {
		return 0, false
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, 64))
	if err != nil {
		return 0, false
	}
	return parseXMLUint(string(b), max)
}

// Fallback vendor names for the common GPU/audio vendors when no pci.ids
// is installed.
var knownPCIVendors = map[string]string{
	"10de": "NVIDIA Corporation",
	"1002": "Advanced Micro Devices, Inc. [AMD/ATI]",
	"1022": "Advanced Micro Devices, Inc. [AMD]",
	"8086": "Intel Corporation",
}

func strPtr(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

// resolveHostdevs looks the devices up on the host: PCI class (kind),
// vendor and device names from sysfs + pci.ids, USB names from usb.ids.
// Missing data stays null; it never fails.
func resolveHostdevs(refs []hostdevRef) []domain.VmHostdev {
	out := make([]domain.VmHostdev, 0, len(refs))
	for _, r := range refs {
		h := domain.VmHostdev{Type: r.Type, Address: r.Address}
		switch r.Type {
		case "pci":
			if !pciAddrRe.MatchString(r.Address) {
				continue
			}
			dir := filepath.Join(sysfsPCIDevices, r.Address)
			if class, ok := readSysfsHex(filepath.Join(dir, "class"), 0xffffff); ok {
				h.Kind = strPtr(classKind(uint32(class)))
			}
			vid, vok := readSysfsHex(filepath.Join(dir, "vendor"), 0xffff)
			did, dok := readSysfsHex(filepath.Join(dir, "device"), 0xffff)
			if vok {
				v := fmt.Sprintf("%04x", vid)
				d := ""
				if dok {
					d = fmt.Sprintf("%04x", did)
				}
				vName, dName := lookupIDs(pciIDsPaths, v, d)
				if vName == "" {
					vName = knownPCIVendors[v]
				}
				h.Vendor, h.Name = strPtr(vName), strPtr(dName)
			}
		case "usb":
			h.Kind = strPtr(HostdevKindUSB)
			if r.Vendor != "" {
				vName, dName := lookupIDs(usbIDsPaths, r.Vendor, r.Product)
				h.Vendor, h.Name = strPtr(vName), strPtr(dName)
			}
		default:
			continue
		}
		out = append(out, h)
	}
	return out
}

// ---- pci.ids / usb.ids ----------------------------------------------------

type idsNames struct{ vendor, device string }

var (
	idsMu    sync.Mutex
	idsCache = map[string]idsNames{} // "<file>|<vendor>|<device>" → names (negative results too)
)

// lookupIDs returns the vendor and device names for 4-hex ids from the first
// readable ids file. Results (including misses) are cached per process; a
// lookup scans the file once, so only devices actually passed through cost
// a read.
func lookupIDs(paths []string, vendor, device string) (string, string) {
	if !hexIDRe.MatchString(vendor) || (device != "" && !hexIDRe.MatchString(device)) {
		return "", ""
	}
	for _, p := range paths {
		key := p + "|" + vendor + "|" + device
		idsMu.Lock()
		res, ok := idsCache[key]
		idsMu.Unlock()
		if ok {
			return res.vendor, res.device
		}
		f, err := os.Open(p)
		if err != nil {
			continue
		}
		res = scanIDs(f, vendor, device)
		f.Close()
		idsMu.Lock()
		idsCache[key] = res
		idsMu.Unlock()
		return res.vendor, res.device
	}
	return "", ""
}

// scanIDs parses the pci.ids/usb.ids format:
//
//	vvvv  Vendor name
//	<TAB>dddd  Device name
//	<TAB><TAB>ssss ssss  Subsystem name
//
// The vendor list ends at the first top-level line that is not a vendor
// (the "C xx" class section and, in usb.ids, further sections).
func scanIDs(r io.Reader, vendor, device string) idsNames {
	var res idsNames
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 4096), 64*1024)
	inVendor := false
	for sc.Scan() {
		line := sc.Text()
		if line == "" || line[0] == '#' {
			continue
		}
		if line[0] != '\t' {
			id, name, ok := idsEntry(line)
			if !ok {
				break // end of the vendor section
			}
			if inVendor {
				break // passed our vendor without finding the device
			}
			if id == vendor {
				inVendor = true
				res.vendor = name
				if device == "" {
					break
				}
			}
			continue
		}
		if !inVendor || strings.HasPrefix(line, "\t\t") {
			continue
		}
		if id, name, ok := idsEntry(line[1:]); ok && id == device {
			res.device = name
			break
		}
	}
	return res
}

// idsEntry splits "abcd  Name" into its lowercase id and name.
func idsEntry(s string) (string, string, bool) {
	if len(s) < 7 || s[4] != ' ' {
		return "", "", false
	}
	id := strings.ToLower(s[:4])
	if !hexIDRe.MatchString(id) {
		return "", "", false
	}
	name := strings.TrimSpace(s[5:])
	if name == "" {
		return "", "", false
	}
	return id, name, true
}
