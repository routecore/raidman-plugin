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

// stateName maps a libvirt domain state to the plugin's detailedState.
func stateName(state uint8) string {
	switch libvirt.DomainState(state) {
	case libvirt.DomainRunning:
		return "running"
	case libvirt.DomainBlocked:
		return "blocked"
	case libvirt.DomainPaused:
		return "paused"
	case libvirt.DomainShutdown:
		return "shutdown"
	case libvirt.DomainShutoff:
		return "shutoff"
	case libvirt.DomainCrashed:
		return "crashed"
	case libvirt.DomainPmsuspended:
		return "pmsuspended"
	}
	return "unknown"
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
	stateKnown := false
	if err == nil {
		info.Vcpus = int(nrVirtCpu)
		info.Memory = int64(maxMem) * 1024 // KB to Bytes
		info.CpuTime = fmt.Sprintf("%d", cpuTime)

		info.DetailedState = stateName(state)
		stateKnown = true
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

		// 2. Passthrough devices (own parser: string attributes, strict
		// address validation, host-side names from sysfs/pci.ids).
		if refs, err := parseHostdevs(xmlStr); err == nil {
			info.Hostdevs = resolveHostdevs(refs)
		}

		// 3. Standard Libvirt Parse
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

				// Interfaces: one address query per source for the whole
				// domain, matched to each NIC by MAC.
				var nicIPs map[string][]string
				if stateKnown && len(domCfg.Devices.Interfaces) > 0 {
					macs := make([]string, 0, len(domCfg.Devices.Interfaces))
					for _, i := range domCfg.Devices.Interfaces {
						if i.MAC != nil {
							macs = append(macs, i.MAC.Address)
						}
					}
					nicIPs = resolveNICIPs(macs, sourcesForState(state, agentConnected(domCfg.Devices)), func(src libvirt.DomainInterfaceAddressesSource) ([]libvirt.DomainInterface, error) {
						return l.DomainInterfaceAddresses(dom, uint32(src), 0)
					})
				}
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

					ips := nicIPs[normMAC(mac)]
					if ips == nil {
						ips = []string{}
					}
					ip := ""
					if len(ips) > 0 {
						ip = ips[0]
					}

					model := ""
					if i.Model != nil {
						model = i.Model.Type
					}

					info.Interfaces = append(info.Interfaces, domain.VmInterface{
						Mac:         mac,
						Model:       model,
						Network:     net,
						IpAddress:   ip,
						IpAddresses: ips,
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

// Actions accepted by ExecuteVmAction.
var vmActions = map[string]bool{
	"start": true, "stop": true, "force-stop": true, "pause": true,
	"resume": true, "restart": true, "hibernate": true, "reset": true,
}

// ValidAction reports whether ExecuteVmAction knows the action.
func ValidAction(action string) bool { return vmActions[action] }

func ExecuteVmAction(vmName string, action string) error {
	if !ValidAction(action) {
		return fmt.Errorf("invalid action: %s", action)
	}
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
	case "reset":
		return resetDomain(l, dom)
	default:
		return fmt.Errorf("invalid action: %s", action)
	}
}

// resetConn is the part of *libvirt.Libvirt that resetDomain uses (a fake
// in tests).
type resetConn interface {
	DomainGetState(dom libvirt.Domain, flags uint32) (int32, int32, error)
	DomainReset(dom libvirt.Domain, flags uint32) error
	DomainIsPersistent(dom libvirt.Domain) (int32, error)
	DomainDestroy(dom libvirt.Domain) error
	DomainCreate(dom libvirt.Domain) error
}

// isUnsupported reports libvirt's "not supported by this hypervisor/driver"
// errors, the only ones after which the destroy+create fallback is used.
func isUnsupported(err error) bool {
	// go-libvirt turns libvirtd's "unknown procedure" (an RPC this daemon
	// does not have) into the ErrUnsupported sentinel, not a libvirt.Error.
	if errors.Is(err, libvirt.ErrUnsupported) {
		return true
	}
	var le libvirt.Error
	if !errors.As(err, &le) {
		return false
	}
	switch libvirt.ErrorNumber(le.Code) {
	case libvirt.ErrNoSupport, libvirt.ErrArgumentUnsupported, libvirt.ErrOperationUnsupported:
		return true
	}
	return false
}

// resetDomain performs a hard reset (like pressing the reset button; the
// guest OS is not asked). The domain must be active (ErrNotRunning
// otherwise). If the hypervisor does not support virDomainReset and the VM
// was running, it falls back to destroy + create, but only for persistent
// domains: destroying a transient domain would delete it.
//
// A crashed domain (on_crash="preserve": the QEMU process is kept) is reset
// with destroy + create directly, again only when persistent. That is what
// the official API's resetVm does in every state, and the app offers reset
// for crashed VMs; virDomainReset would leave such a guest paused.
func resetDomain(c resetConn, dom libvirt.Domain) error {
	state, _, err := c.DomainGetState(dom, 0)
	if err != nil {
		return err
	}
	st := libvirt.DomainState(state)
	switch st {
	case libvirt.DomainRunning, libvirt.DomainBlocked, libvirt.DomainPaused:
	case libvirt.DomainCrashed:
		return destroyAndCreate(c, dom, errors.New("the VM crashed"))
	default:
		return ErrNotRunning
	}
	err = c.DomainReset(dom, 0)
	if err == nil || !isUnsupported(err) {
		return err
	}
	if st != libvirt.DomainRunning && st != libvirt.DomainBlocked {
		return err
	}
	return destroyAndCreate(c, dom, err)
}

// destroyAndCreate force-stops and starts a persistent domain; why says in
// the error why a plain virDomainReset was not used.
func destroyAndCreate(c resetConn, dom libvirt.Domain, why error) error {
	persistent, perr := c.DomainIsPersistent(dom)
	if perr != nil || persistent != 1 {
		return fmt.Errorf("cannot reset (%w) and the VM is not persistent, so it is not force-stopped and started again", why)
	}
	if err := c.DomainDestroy(dom); err != nil {
		return fmt.Errorf("reset fallback: force stop failed: %w", err)
	}
	if err := c.DomainCreate(dom); err != nil {
		return fmt.Errorf("reset fallback: the VM was stopped but could not be started again: %w", err)
	}
	return nil
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
