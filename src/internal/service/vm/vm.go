package vm

import (
	"encoding/hex"
	"encoding/xml"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync/atomic"
	"time"

	"github.com/routecore/raidman-plugin/src/internal/domain"

	libvirt "github.com/digitalocean/go-libvirt"
	"libvirt.org/go/libvirtxml"
)

// libvirt RPC budgets. go-libvirt puts no deadline on RPCs, so a wedged
// libvirtd would pin the calling goroutine (and its stream slot) forever.
// Each operation dials its own connection; the watchdog closes it when one
// RPC goes unanswered for longer than the budget, which fails every pending
// call, and the next operation simply dials again. A socket read deadline
// cannot be used: go-libvirt treats a timeout as a temporary error and keeps
// re-reading in a busy loop. Overridable in tests.
var (
	// queryTimeout bounds each read-only RPC (lookups, info, XML, agent
	// address queries, which libvirt itself times out after a few seconds).
	queryTimeout = 30 * time.Second
	// actionTimeout bounds each RPC of a state change: destroying or
	// starting a VM with passthrough devices can legitimately take well over
	// 30 seconds.
	actionTimeout = 3 * time.Minute
)

// ErrTimeout is returned (wrapped) when libvirtd did not answer an RPC
// within its budget.
var ErrTimeout = errors.New("libvirt did not respond in time")

// libvirtSocket is the libvirtd socket; dialLibvirt is overridable in tests.
const libvirtSocket = "/var/run/libvirt/libvirt-sock"

var dialLibvirt = func() (net.Conn, error) {
	return net.DialTimeout("unix", libvirtSocket, 2*time.Second)
}

// watchdogConn closes the connection when no request was written for
// timeout. Every RPC writes a request, so the timer re-arms per call; it is
// stopped when the connection is closed.
type watchdogConn struct {
	net.Conn
	timeout time.Duration
	timer   *time.Timer
	fired   atomic.Bool
}

func newWatchdogConn(c net.Conn, timeout time.Duration) *watchdogConn {
	w := &watchdogConn{Conn: c, timeout: timeout}
	w.timer = time.AfterFunc(timeout, func() {
		w.fired.Store(true)
		c.Close()
	})
	return w
}

func (w *watchdogConn) Write(b []byte) (int, error) {
	w.timer.Reset(w.timeout)
	return w.Conn.Write(b)
}

func (w *watchdogConn) Close() error {
	w.timer.Stop()
	return w.Conn.Close()
}

// conn is a libvirt connection guarded by a watchdog.
type conn struct {
	*libvirt.Libvirt
	wd *watchdogConn
}

// connect dials libvirtd; timeout bounds each RPC, including the handshake
// and the final Disconnect.
func connect(timeout time.Duration) (*conn, error) {
	c, err := dialLibvirt()
	if err != nil {
		return nil, err
	}
	wd := newWatchdogConn(c, timeout)
	l := libvirt.New(wd)
	if err := l.Connect(); err != nil {
		wd.Close()
		return nil, wrapTimeout(wd, err)
	}
	return &conn{Libvirt: l, wd: wd}, nil
}

func wrapTimeout(wd *watchdogConn, err error) error {
	if err != nil && wd.fired.Load() && !errors.Is(err, ErrTimeout) {
		return fmt.Errorf("%w: %v", ErrTimeout, err)
	}
	return err
}

// close disconnects (still under the watchdog: Disconnect sends an RPC) and,
// when the watchdog fired, marks *errp as a timeout.
func (c *conn) close(errp *error) {
	_ = c.Disconnect()
	c.wd.Close()
	if errp != nil {
		*errp = wrapTimeout(c.wd, *errp)
	}
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

// ErrWrongState marks an action the VM's current state does not allow (see
// refusal).
var ErrWrongState = errors.New("the VM's state does not allow this action")

// stateError is an ErrWrongState with its message and, when libvirt refused
// the call, libvirt's error.
type stateError struct {
	msg   string
	cause error
}

func (e *stateError) Error() string { return e.msg }
func (e *stateError) Unwrap() []error {
	if e.cause == nil {
		return []error{ErrWrongState}
	}
	return []error{ErrWrongState, e.cause}
}

// IsNotFound reports libvirt's "Domain not found" (an unknown name or UUID).
func IsNotFound(err error) bool { return libvirt.IsNotFound(err) }

// IsWrongState reports an action the VM's current state does not allow:
// ErrNotRunning or ErrWrongState, which are only returned after the
// domain's state was read. libvirt's VIR_ERR_OPERATION_INVALID alone is not
// enough: it also covers a passthrough device in use, an inactive network
// and the like.
func IsWrongState(err error) bool {
	return errors.Is(err, ErrNotRunning) || errors.Is(err, ErrWrongState)
}

// isOperationInvalid reports libvirt's "Requested operation is not valid".
func isOperationInvalid(err error) bool {
	var le libvirt.Error
	return errors.As(err, &le) && libvirt.ErrorNumber(le.Code) == libvirt.ErrOperationInvalid
}

// Domain identifies a resolved VM.
type Domain struct {
	Name string
	UUID string
}

// ResolveDomain resolves a VM reference to its exact libvirt name and UUID.
func ResolveDomain(ref string) (_ *Domain, err error) {
	l, err := connect(queryTimeout)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to libvirt: %w", err)
	}
	defer l.close(&err)
	dom, err := lookupDomain(l.Libvirt, ref)
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

func GetVms() (_ []domain.VmInfo, err error) {
	l, err := connect(queryTimeout)
	if err != nil {
		return []domain.VmInfo{}, fmt.Errorf("failed to connect to libvirt: %w", err)
	}
	defer l.close(&err)

	// List Defined (Inactive) and Active Domains
	doms, err := l.Domains()
	if err != nil {
		return []domain.VmInfo{}, fmt.Errorf("failed to list domains: %v", err)
	}

	vms := make([]domain.VmInfo, 0)

	for _, dom := range doms {
		info, err := enrichVmInfo(l.Libvirt, dom)
		if err != nil {
			continue
		}
		vms = append(vms, info)
	}
	if l.wd.fired.Load() {
		// The connection was cut mid-way: do not report a partial list.
		return []domain.VmInfo{}, ErrTimeout
	}

	return vms, nil
}

func GetVmInfo(vmName string) (_ *domain.VmInfo, err error) {
	l, err := connect(queryTimeout)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to libvirt: %w", err)
	}
	defer l.close(&err)

	dom, err := lookupDomain(l.Libvirt, vmName)
	if err != nil {
		return nil, err
	}

	info, err := enrichVmInfo(l.Libvirt, dom)
	if err == nil && l.wd.fired.Load() {
		return nil, ErrTimeout
	}
	return &info, err
}

func SetVmAutostart(vmName string, enabled bool) (err error) {
	l, err := connect(queryTimeout)
	if err != nil {
		return err
	}
	defer l.close(&err)

	dom, err := lookupDomain(l.Libvirt, vmName)
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

func ExecuteVmAction(vmName string, action string) (err error) {
	if !ValidAction(action) {
		return fmt.Errorf("invalid action: %s", action)
	}
	l, err := connect(actionTimeout)
	if err != nil {
		return err
	}
	defer l.close(&err)

	dom, err := lookupDomain(l.Libvirt, vmName)
	if err != nil {
		return err
	}
	return runAction(l.Libvirt, dom, action)
}

// actionConn is the part of *libvirt.Libvirt that runAction uses (a fake
// in tests).
type actionConn interface {
	resetConn
	DomainShutdown(dom libvirt.Domain) error
	DomainSuspend(dom libvirt.Domain) error
	DomainResume(dom libvirt.Domain) error
	DomainReboot(dom libvirt.Domain, flags libvirt.DomainRebootFlagValues) error
	DomainPmSuspendForDuration(dom libvirt.Domain, target uint32, duration uint64, flags uint32) error
}

// active reports a state in which the domain has a running QEMU process.
func active(st libvirt.DomainState) bool {
	switch st {
	case libvirt.DomainRunning, libvirt.DomainBlocked, libvirt.DomainPaused,
		libvirt.DomainShutdown, libvirt.DomainCrashed, libvirt.DomainPmsuspended:
		return true
	}
	return false
}

// refusal returns why the domain's state does not allow action, or "" when
// it may be tried. Only the clear cases are refused (start of an active VM,
// resume of one that is not paused, anything else on a shut-off VM, reset
// as resetDomain decides); the rest is left to libvirt.
func refusal(action string, st libvirt.DomainState) string {
	switch action {
	case "start":
		switch {
		case st == libvirt.DomainRunning || st == libvirt.DomainBlocked:
			return "VM is already running"
		case active(st):
			return "VM is already running (" + stateName(uint8(st)) + ")"
		}
	case "resume":
		switch st {
		case libvirt.DomainPaused, libvirt.DomainCrashed, libvirt.DomainNostate:
		default:
			return "VM is not paused"
		}
	case "stop", "force-stop", "pause", "restart", "hibernate":
		if st == libvirt.DomainShutoff {
			return ErrNotRunning.Error()
		}
	case "reset": // as resetDomain
		switch st {
		case libvirt.DomainRunning, libvirt.DomainBlocked, libvirt.DomainPaused, libvirt.DomainCrashed:
		default:
			return ErrNotRunning.Error()
		}
	}
	return ""
}

// runAction checks the domain's state, then runs the action. A state that
// does not allow it answers ErrWrongState (409); so does libvirt's
// "operation invalid" when the state, read again, is not the one the action
// is meant for (see stateChanged). Every other failure is returned as is
// (500 with libvirt's message).
func runAction(c actionConn, dom libvirt.Domain, action string) error {
	if action == "reset" {
		return resetDomain(c, dom) // checks the state itself
	}
	state, _, err := c.DomainGetState(dom, 0)
	if err != nil {
		return err
	}
	if msg := refusal(action, libvirt.DomainState(state)); msg != "" {
		return &stateError{msg: msg}
	}
	switch action {
	case "start":
		err = c.DomainCreate(dom)
	case "stop":
		err = c.DomainShutdown(dom)
	case "force-stop":
		err = c.DomainDestroy(dom)
	case "pause":
		err = c.DomainSuspend(dom)
	case "resume":
		err = c.DomainResume(dom)
	case "restart":
		err = c.DomainReboot(dom, 0) // 0 = Default
	case "hibernate":
		err = c.DomainPmSuspendForDuration(dom, 1, 0, 0)
	default:
		return fmt.Errorf("invalid action: %s", action)
	}
	return stateChanged(c, dom, action, err)
}

// usualState reports whether st is a state action is meant for: start a
// shut-off VM, stop/restart/pause/hibernate a running one, resume a paused
// one, force-stop an active one, reset a running or paused one.
func usualState(action string, st libvirt.DomainState) bool {
	running := st == libvirt.DomainRunning || st == libvirt.DomainBlocked
	switch action {
	case "start":
		return st == libvirt.DomainShutoff
	case "stop", "restart", "pause", "hibernate":
		return running
	case "resume":
		return st == libvirt.DomainPaused
	case "force-stop":
		return active(st)
	case "reset":
		return running || st == libvirt.DomainPaused
	}
	return true
}

// stateChanged turns libvirt's "operation invalid" into a stateError when
// the domain's state, read again, is not one the action is meant for (a VM
// that is paused, stopped meanwhile, ...). In its usual state the refusal
// has another cause (a passthrough device in use, an inactive network) and
// err is returned as is.
func stateChanged(c resetConn, dom libvirt.Domain, action string, err error) error {
	if err == nil || !isOperationInvalid(err) {
		return err
	}
	state, _, serr := c.DomainGetState(dom, 0)
	if serr == nil && !usualState(action, libvirt.DomainState(state)) {
		return &stateError{msg: err.Error(), cause: err}
	}
	return err
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
		return stateChanged(c, dom, "reset", err)
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

func GetVncPort(vmName string) (_ string, err error) {
	l, err := connect(queryTimeout)
	if err != nil {
		return "", err
	}
	defer l.close(&err)

	dom, err := lookupDomain(l.Libvirt, vmName)
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
