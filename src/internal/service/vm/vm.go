package vm

import (
	"encoding/hex"
	"encoding/xml"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/routecore/raidman-plugin/src/internal/domain"

	libvirt "github.com/digitalocean/go-libvirt"
	"libvirt.org/go/libvirtxml"
)

// Helper to connect to libvirt
func connect() (*libvirt.Libvirt, error) {

	c, err := net.DialTimeout("unix", "/var/run/libvirt/libvirt-sock", 2*time.Second)
	if err != nil {
		return nil, err
	}

	l := libvirt.New(c)
	if err := l.Connect(); err != nil {
		c.Close()
		return nil, err
	}

	return l, nil
}

// ParseUUID parses a libvirt domain UUID in canonical (8-4-4-4-12) or plain
// 32-hex form.
func ParseUUID(s string) (libvirt.UUID, bool) {
	var u libvirt.UUID
	h := strings.ReplaceAll(s, "-", "")
	if len(h) != 32 || (len(s) != 32 && len(s) != 36) {
		return u, false
	}
	if len(s) == 36 && (s[8] != '-' || s[13] != '-' || s[18] != '-' || s[23] != '-') {
		return u, false
	}
	b, err := hex.DecodeString(h)
	if err != nil {
		return u, false
	}
	copy(u[:], b)
	return u, true
}

// FormatUUID renders a libvirt UUID in canonical form.
func FormatUUID(u libvirt.UUID) string {
	h := hex.EncodeToString(u[:])
	return h[0:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:32]
}

// lookupDomain resolves a VM reference: a UUID (what the official API calls
// the VM id) or the exact libvirt name, which may contain spaces/Unicode.
// Names are passed to libvirt over RPC, never through a shell.
func lookupDomain(l *libvirt.Libvirt, ref string) (libvirt.Domain, error) {
	if u, ok := ParseUUID(ref); ok {
		if dom, err := l.DomainLookupByUUID(u); err == nil {
			return dom, nil
		}
	}
	return l.DomainLookupByName(ref)
}

// ErrNotRunning is returned when a VM must be running for an operation.
var ErrNotRunning = errors.New("VM is not running")

// Domain identifies a resolved VM.
type Domain struct {
	Name string
	UUID string
}

// ResolveDomain resolves a VM reference to its exact libvirt name and UUID.
func ResolveDomain(ref string) (*Domain, error) {
	l, err := connect()
	if err != nil {
		return nil, fmt.Errorf("failed to connect to libvirt: %v", err)
	}
	defer l.Disconnect()
	dom, err := lookupDomain(l, ref)
	if err != nil {
		return nil, err
	}
	return &Domain{Name: dom.Name, UUID: FormatUUID(dom.UUID)}, nil
}

func GetVmIp(l *libvirt.Libvirt, dom libvirt.Domain) string {
	// Source: 2 = Agent
	ifaces, err := l.DomainInterfaceAddresses(dom, uint32(2), 0)
	if err == nil {
		for _, iface := range ifaces {
			for _, addr := range iface.Addrs {
				// Type 0 = IPv4
				if addr.Type == 0 {
					return addr.Addr
				}
			}
		}
	}
	return ""
}

func enrichVmInfo(l *libvirt.Libvirt, dom libvirt.Domain) (domain.VmInfo, error) {
	info := domain.VmInfo{Name: dom.Name}

	// ID / UUID
	if dom.ID != -1 {
		info.DomId = fmt.Sprintf("%d", dom.ID)
	}
	info.Uuid = fmt.Sprintf("%x", dom.UUID) // protocol-1 format (32 hex, no dashes)

	// Get State & Info
	state, maxMem, _, nrVirtCpu, cpuTime, err := l.DomainGetInfo(dom)
	if err == nil {
		info.Vcpus = int(nrVirtCpu)
		info.Memory = int64(maxMem) * 1024 // KB to Bytes
		info.CpuTime = fmt.Sprintf("%d", cpuTime)

		// Map State
		switch state {
		case 1: // RUNNING
			info.DetailedState = "running"
		case 3: // PAUSED
			info.DetailedState = "paused"
		case 5: // SHUTOFF
			info.DetailedState = "shutoff"
		case 6: // CRASHED
			info.DetailedState = "crashed"
		case 7: // PMSUSPENDED
			info.DetailedState = "pmsuspended"
		default:
			info.DetailedState = "unknown"
		}
	}

	// Autostart
	autostart, err := l.DomainGetAutostart(dom)
	if err == nil {
		info.Autostart = (autostart == 1)
	}

	// Persistent
	persistent, err := l.DomainIsPersistent(dom)
	if err == nil {
		info.Persistent = (persistent == 1)
	}

	// XML Description
	xmlStr, err := l.DomainGetXMLDesc(dom, 0)
	if err == nil {
		// 1. Unraid Custom Metadata Parse
		var customCfg domain.DomainXml
		if err := xml.Unmarshal([]byte(xmlStr), &customCfg); err == nil {
			if customCfg.Metadata.VmTemplate.Icon != "" {
				info.Icon = customCfg.Metadata.VmTemplate.Icon
			}
			if customCfg.Metadata.VmTemplate.Os != "" {
				info.TemplateOs = customCfg.Metadata.VmTemplate.Os
			}
		}

		// 2. Standard Libvirt Parse
		var domCfg libvirtxml.Domain
		if err := xml.Unmarshal([]byte(xmlStr), &domCfg); err == nil {
			// Description
			info.Description = domCfg.Description
			// OS Type
			if domCfg.OS != nil && domCfg.OS.Type != nil {
				info.OsType = domCfg.OS.Type.Arch
			}

			// Devices
			if domCfg.Devices != nil {
				// Disks
				for _, d := range domCfg.Devices.Disks {
					src := ""
					if d.Source != nil {
						if d.Source.File != nil {
							src = d.Source.File.File
						} else if d.Source.Block != nil {
							src = d.Source.Block.Dev
						}
					}
					target := ""
					if d.Target != nil {
						target = d.Target.Dev
					}
					bus := ""
					if d.Target != nil {
						bus = d.Target.Bus
					}
					bootOrder := 0
					if d.Boot != nil {
						bootOrder = int(d.Boot.Order)
					}

					info.Disks = append(info.Disks, domain.VmDisk{
						Source:    src,
						Target:    target,
						Bus:       bus,
						Type:      d.Device,
						Serial:    d.Serial,
						BootOrder: bootOrder,
					})
				}

				// Interfaces
				for _, i := range domCfg.Devices.Interfaces {
					net := ""
					if i.Source != nil {
						if i.Source.Bridge != nil {
							net = i.Source.Bridge.Bridge
						} else if i.Source.Network != nil {
							net = i.Source.Network.Network
						}
					}
					mac := ""
					if i.MAC != nil {
						mac = i.MAC.Address
					}

					ip := GetVmIp(l, dom)

					model := ""
					if i.Model != nil {
						model = i.Model.Type
					}

					info.Interfaces = append(info.Interfaces, domain.VmInterface{
						Mac:       mac,
						Model:     model,
						Network:   net,
						IpAddress: ip,
					})
				}

				// Graphics
				for _, g := range domCfg.Devices.Graphics {
					gType := "unknown"
					gPort := 0

					if g.VNC != nil {
						gType = "vnc"
						gPort = g.VNC.Port
					} else if g.Spice != nil {
						gType = "spice"
						gPort = g.Spice.Port
					} else if g.RDP != nil {
						gType = "rdp"
						gPort = g.RDP.Port
					}

					if gType != "unknown" {
						info.Graphics = append(info.Graphics, domain.VmGraphics{
							Type: gType,
							Port: gPort,
						})
					}
				}
			}
		}
	}
	return info, nil
}

func GetVms() ([]domain.VmInfo, error) {
	l, err := connect()
	if err != nil {
		return []domain.VmInfo{}, fmt.Errorf("failed to connect to libvirt: %v", err)
	}
	defer func() {
		if err := l.Disconnect(); err != nil {
			// ignore
		}
	}()

	// List Defined (Inactive) and Active Domains
	doms, err := l.Domains()
	if err != nil {
		return []domain.VmInfo{}, fmt.Errorf("failed to list domains: %v", err)
	}

	vms := make([]domain.VmInfo, 0)

	for _, dom := range doms {
		info, err := enrichVmInfo(l, dom)
		if err != nil {
			continue
		}
		vms = append(vms, info)
	}

	return vms, nil
}

func GetVmInfo(vmName string) (*domain.VmInfo, error) {
	l, err := connect()
	if err != nil {
		return nil, fmt.Errorf("failed to connect to libvirt: %v", err)
	}
	defer func() {
		if err := l.Disconnect(); err != nil {
			// ignore
		}
	}()

	dom, err := lookupDomain(l, vmName)
	if err != nil {
		return nil, err
	}

	info, err := enrichVmInfo(l, dom)
	return &info, err
}

func SetVmAutostart(vmName string, enabled bool) error {
	l, err := connect()
	if err != nil {
		return err
	}
	defer l.Disconnect()

	dom, err := lookupDomain(l, vmName)
	if err != nil {
		return err
	}

	if enabled {
		return l.DomainSetAutostart(dom, 1)
	}
	return l.DomainSetAutostart(dom, 0)
}

func ExecuteVmAction(vmName string, action string) error {
	l, err := connect()
	if err != nil {
		return err
	}
	defer l.Disconnect()

	dom, err := lookupDomain(l, vmName)
	if err != nil {
		return err
	}

	switch action {
	case "start":
		return l.DomainCreate(dom)
	case "stop":
		return l.DomainShutdown(dom)
	case "force-stop":
		return l.DomainDestroy(dom)
	case "pause":
		return l.DomainSuspend(dom)
	case "resume":
		return l.DomainResume(dom)
	case "restart":
		return l.DomainReboot(dom, 0) // 0 = Default
	case "hibernate":
		// DomainPmSuspendForDuration
		return l.DomainPmSuspendForDuration(dom, 1, 0, 0)
	default:
		return fmt.Errorf("invalid action: %s", action)
	}
}

func GetVncPort(vmName string) (string, error) {
	l, err := connect()
	if err != nil {
		return "", err
	}
	defer l.Disconnect()

	dom, err := lookupDomain(l, vmName)
	if err != nil {
		return "", err
	}

	xmlStr, err := l.DomainGetXMLDesc(dom, 0)
	if err != nil {
		return "", err
	}

	var domCfg libvirtxml.Domain
	if err := xml.Unmarshal([]byte(xmlStr), &domCfg); err != nil {
		return "", err
	}

	if domCfg.Devices != nil {
		for _, g := range domCfg.Devices.Graphics {
			if g.VNC != nil {
				if g.VNC.Port <= 0 {
					// autoport VM that is not running has port -1
					return "", ErrNotRunning
				}
				return fmt.Sprintf("%d", g.VNC.Port), nil
			}
		}
	}

	return "", fmt.Errorf("no vnc graphics found")
}
