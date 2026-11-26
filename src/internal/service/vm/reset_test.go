package vm

import (
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"

	libvirt "github.com/digitalocean/go-libvirt"
)

type fakeResetConn struct {
	state      libvirt.DomainState
	stateAfter libvirt.DomainState // from the second DomainGetState on (0: state)
	stateErr   error
	resetErr   error
	persistent int32
	destroyErr error
	createErr  error
	actionErr  error // shutdown, suspend, resume, reboot, PM suspend
	calls      []string
	states     int
}

func (f *fakeResetConn) DomainGetState(libvirt.Domain, uint32) (int32, int32, error) {
	f.calls = append(f.calls, "state")
	f.states++
	if f.states > 1 && f.stateAfter != 0 {
		return int32(f.stateAfter), 0, f.stateErr
	}
	return int32(f.state), 0, f.stateErr
}
func (f *fakeResetConn) DomainShutdown(libvirt.Domain) error {
	f.calls = append(f.calls, "shutdown")
	return f.actionErr
}
func (f *fakeResetConn) DomainSuspend(libvirt.Domain) error {
	f.calls = append(f.calls, "suspend")
	return f.actionErr
}
func (f *fakeResetConn) DomainResume(libvirt.Domain) error {
	f.calls = append(f.calls, "resume")
	return f.actionErr
}
func (f *fakeResetConn) DomainReboot(libvirt.Domain, libvirt.DomainRebootFlagValues) error {
	f.calls = append(f.calls, "reboot")
	return f.actionErr
}
func (f *fakeResetConn) DomainPmSuspendForDuration(libvirt.Domain, uint32, uint64, uint32) error {
	f.calls = append(f.calls, "pmsuspend")
	return f.actionErr
}

// The real connection satisfies the interface runAction uses.
var _ actionConn = (*libvirt.Libvirt)(nil)

func (f *fakeResetConn) DomainReset(libvirt.Domain, uint32) error {
	f.calls = append(f.calls, "reset")
	return f.resetErr
}
func (f *fakeResetConn) DomainIsPersistent(libvirt.Domain) (int32, error) {
	f.calls = append(f.calls, "persistent")
	return f.persistent, nil
}
func (f *fakeResetConn) DomainDestroy(libvirt.Domain) error {
	f.calls = append(f.calls, "destroy")
	return f.destroyErr
}
func (f *fakeResetConn) DomainCreate(libvirt.Domain) error {
	f.calls = append(f.calls, "create")
	return f.createErr
}

var errUnsupported = libvirt.Error{Code: uint32(libvirt.ErrOperationUnsupported), Message: "Operation not supported: reset"}

func TestResetDomain(t *testing.T) {
	cases := []struct {
		name      string
		conn      fakeResetConn
		wantCalls []string
		wantErr   string // substring; "" = success
		notRun    bool
	}{
		{"running: DomainReset", fakeResetConn{state: libvirt.DomainRunning}, []string{"state", "reset"}, "", false},
		{"blocked (idle) counts as running", fakeResetConn{state: libvirt.DomainBlocked}, []string{"state", "reset"}, "", false},
		{"paused: DomainReset only", fakeResetConn{state: libvirt.DomainPaused}, []string{"state", "reset"}, "", false},
		{"shut off: refused", fakeResetConn{state: libvirt.DomainShutoff}, []string{"state"}, "not running", true},
		{"crashed + persistent: destroy+create (like upstream resetVm)", fakeResetConn{state: libvirt.DomainCrashed, persistent: 1},
			[]string{"state", "persistent", "destroy", "create"}, "", false},
		{"crashed + transient: refused, not destroyed", fakeResetConn{state: libvirt.DomainCrashed, persistent: 0},
			[]string{"state", "persistent"}, "not persistent", false},
		{"shutdown (shutting down): refused", fakeResetConn{state: libvirt.DomainShutdown}, []string{"state"}, "not running", true},
		{"pmsuspended: refused", fakeResetConn{state: libvirt.DomainPmsuspended}, []string{"state"}, "not running", true},
		{"unsupported RPC (ErrUnsupported sentinel) + running: destroy+create", fakeResetConn{state: libvirt.DomainRunning, resetErr: libvirt.ErrUnsupported, persistent: 1},
			[]string{"state", "reset", "persistent", "destroy", "create"}, "", false},
		{"state error", fakeResetConn{stateErr: errors.New("no domain")}, []string{"state"}, "no domain", false},
		{"other reset error: no fallback, state unchanged: 500", fakeResetConn{state: libvirt.DomainRunning, resetErr: libvirt.Error{Code: uint32(libvirt.ErrOperationInvalid), Message: "domain is not running"}},
			[]string{"state", "reset", "state"}, "domain is not running", false},
		{"unsupported + running + persistent: destroy+create", fakeResetConn{state: libvirt.DomainRunning, resetErr: errUnsupported, persistent: 1},
			[]string{"state", "reset", "persistent", "destroy", "create"}, "", false},
		{"unsupported (wrapped, ErrNoSupport)", fakeResetConn{state: libvirt.DomainBlocked, resetErr: errors.Join(errors.New("rpc"), libvirt.Error{Code: uint32(libvirt.ErrNoSupport), Message: "this function is not supported"}), persistent: 1},
			[]string{"state", "reset", "persistent", "destroy", "create"}, "", false},
		{"unsupported + paused: no fallback", fakeResetConn{state: libvirt.DomainPaused, resetErr: errUnsupported, persistent: 1},
			[]string{"state", "reset"}, "not supported", false},
		{"unsupported + transient: no fallback", fakeResetConn{state: libvirt.DomainRunning, resetErr: errUnsupported, persistent: 0},
			[]string{"state", "reset", "persistent"}, "not persistent", false},
		{"fallback destroy fails", fakeResetConn{state: libvirt.DomainRunning, resetErr: errUnsupported, persistent: 1, destroyErr: errors.New("busy")},
			[]string{"state", "reset", "persistent", "destroy"}, "force stop failed", false},
		{"fallback create fails: says the VM is off", fakeResetConn{state: libvirt.DomainRunning, resetErr: errUnsupported, persistent: 1, createErr: errors.New("hostdev busy")},
			[]string{"state", "reset", "persistent", "destroy", "create"}, "stopped but could not be started", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			conn := c.conn
			err := resetDomain(&conn, libvirt.Domain{Name: "vm"})
			if !reflect.DeepEqual(conn.calls, c.wantCalls) {
				t.Errorf("calls = %v, want %v", conn.calls, c.wantCalls)
			}
			switch {
			case c.wantErr == "" && err != nil:
				t.Errorf("err = %v", err)
			case c.wantErr != "" && (err == nil || !strings.Contains(err.Error(), c.wantErr)):
				t.Errorf("err = %v, want %q", err, c.wantErr)
			}
			if errors.Is(err, ErrNotRunning) != c.notRun {
				t.Errorf("ErrNotRunning = %v, want %v", errors.Is(err, ErrNotRunning), c.notRun)
			}
			// Only a refusal read from the state is a 409; a failed
			// fallback (the VM is off by then) is not.
			if IsWrongState(err) != c.notRun {
				t.Errorf("IsWrongState = %v, want %v", IsWrongState(err), c.notRun)
			}
		})
	}
}

func TestValidAction(t *testing.T) {
	for _, a := range []string{"start", "stop", "force-stop", "pause", "resume", "restart", "hibernate", "reset"} {
		if !ValidAction(a) {
			t.Errorf("%s rejected", a)
		}
	}
	for _, a := range []string{"", "Reset", "reboot", "destroy", "reset "} {
		if ValidAction(a) {
			t.Errorf("%q accepted", a)
		}
	}
	if err := ExecuteVmAction("vm", "explode"); err == nil || !strings.Contains(err.Error(), "invalid action") {
		t.Errorf("invalid action reached libvirt: %v", err)
	}
}

func TestStateName(t *testing.T) {
	want := map[libvirt.DomainState]string{
		libvirt.DomainNostate:     "unknown",
		libvirt.DomainRunning:     "running",
		libvirt.DomainBlocked:     "blocked",
		libvirt.DomainPaused:      "paused",
		libvirt.DomainShutdown:    "shutdown",
		libvirt.DomainShutoff:     "shutoff",
		libvirt.DomainCrashed:     "crashed",
		libvirt.DomainPmsuspended: "pmsuspended",
		42:                        "unknown",
	}
	for st, w := range want {
		if got := stateName(uint8(st)); got != w {
			t.Errorf("stateName(%d) = %q, want %q", st, got, w)
		}
	}
}

// IsNotFound / IsWrongState classify libvirt's answers for the API's 422
// and 409; anything else stays a plain failure.
func TestErrorClassification(t *testing.T) {
	noDomain := libvirt.Error{Code: uint32(libvirt.ErrNoDomain), Message: "Domain not found: no domain with matching name 'x'"}
	// "Operation invalid" alone is no longer a 409: libvirt also answers it
	// for a passthrough device in use or an inactive network.
	invalid := libvirt.Error{Code: uint32(libvirt.ErrOperationInvalid), Message: "Requested operation is not valid: network 'br9' is not active"}
	other := libvirt.Error{Code: uint32(libvirt.ErrInternalError), Message: "internal error"}
	for _, c := range []struct {
		err             error
		notFound, state bool
	}{
		{noDomain, true, false},
		{fmt.Errorf("lookup: %w", noDomain), true, false},
		{invalid, false, false},
		{fmt.Errorf("wrapped: %w", invalid), false, false},
		{ErrNotRunning, false, true},
		{&stateError{msg: "VM is not paused"}, false, true},
		{fmt.Errorf("x: %w", &stateError{msg: "m", cause: invalid}), false, true},
		{fmt.Errorf("reset fallback: the VM was stopped but could not be started again: %w", invalid), false, false},
		{other, false, false},
		{errors.New("Domain not found"), false, false}, // only libvirt's code counts
		{nil, false, false},
	} {
		if got := IsNotFound(c.err); got != c.notFound {
			t.Errorf("IsNotFound(%v) = %v", c.err, got)
		}
		if got := IsWrongState(c.err); got != c.state {
			t.Errorf("IsWrongState(%v) = %v", c.err, got)
		}
	}
}

// runAction refuses what the domain's state clearly does not allow (409),
// lets libvirt decide the rest, and turns libvirt's "operation invalid"
// into a 409 only when the state, read again, does not allow the action.
func TestRunAction(t *testing.T) {
	invalid := libvirt.Error{Code: uint32(libvirt.ErrOperationInvalid), Message: "Requested operation is not valid: domain is not running"}
	hostdev := libvirt.Error{Code: uint32(libvirt.ErrOperationInvalid), Message: "Requested operation is not valid: PCI device 0000:01:00.0 is in use by driver QEMU, domain other"}
	other := libvirt.Error{Code: uint32(libvirt.ErrInternalError), Message: "internal error"}
	const ok, conflict, fail = 200, 409, 500
	cases := []struct {
		action    string
		conn      fakeResetConn
		wantCalls []string
		want      int
		msg       string
	}{
		// Clear conflicts never reach libvirt.
		{"start", fakeResetConn{state: libvirt.DomainRunning}, []string{"state"}, conflict, "VM is already running"},
		{"start", fakeResetConn{state: libvirt.DomainBlocked}, []string{"state"}, conflict, "VM is already running"},
		{"start", fakeResetConn{state: libvirt.DomainPaused}, []string{"state"}, conflict, "VM is already running (paused)"},
		{"stop", fakeResetConn{state: libvirt.DomainShutoff}, []string{"state"}, conflict, "VM is not running"},
		{"force-stop", fakeResetConn{state: libvirt.DomainShutoff}, []string{"state"}, conflict, "VM is not running"},
		{"restart", fakeResetConn{state: libvirt.DomainShutoff}, []string{"state"}, conflict, "VM is not running"},
		{"pause", fakeResetConn{state: libvirt.DomainShutoff}, []string{"state"}, conflict, "VM is not running"},
		{"hibernate", fakeResetConn{state: libvirt.DomainShutoff}, []string{"state"}, conflict, "VM is not running"},
		{"resume", fakeResetConn{state: libvirt.DomainRunning}, []string{"state"}, conflict, "VM is not paused"},
		{"resume", fakeResetConn{state: libvirt.DomainShutoff}, []string{"state"}, conflict, "VM is not paused"},
		// Allowed states.
		{"start", fakeResetConn{state: libvirt.DomainShutoff}, []string{"state", "create"}, ok, ""},
		{"stop", fakeResetConn{state: libvirt.DomainRunning}, []string{"state", "shutdown"}, ok, ""},
		{"force-stop", fakeResetConn{state: libvirt.DomainCrashed}, []string{"state", "destroy"}, ok, ""},
		{"pause", fakeResetConn{state: libvirt.DomainBlocked}, []string{"state", "suspend"}, ok, ""},
		{"resume", fakeResetConn{state: libvirt.DomainPaused}, []string{"state", "resume"}, ok, ""},
		{"restart", fakeResetConn{state: libvirt.DomainRunning}, []string{"state", "reboot"}, ok, ""},
		{"hibernate", fakeResetConn{state: libvirt.DomainRunning}, []string{"state", "pmsuspend"}, ok, ""},
		// "Operation invalid" for something other than the state: 500 with
		// libvirt's message (the state still allows the action).
		{"start", fakeResetConn{state: libvirt.DomainShutoff, createErr: hostdev}, []string{"state", "create", "state"}, fail, "in use"},
		{"stop", fakeResetConn{state: libvirt.DomainPaused, actionErr: invalid}, []string{"state", "shutdown", "state"}, fail, "domain is not running"},
		// The state changed after the check: 409.
		{"stop", fakeResetConn{state: libvirt.DomainRunning, stateAfter: libvirt.DomainShutoff, actionErr: invalid}, []string{"state", "shutdown", "state"}, conflict, "domain is not running"},
		{"start", fakeResetConn{state: libvirt.DomainShutoff, stateAfter: libvirt.DomainRunning, createErr: invalid}, []string{"state", "create", "state"}, conflict, "not valid"},
		// Other failures: 500; a state that cannot be read is no conflict.
		{"stop", fakeResetConn{state: libvirt.DomainRunning, actionErr: other}, []string{"state", "shutdown"}, fail, "internal error"},
		{"stop", fakeResetConn{stateErr: other}, []string{"state"}, fail, "internal error"},
		// Reset: its own checks; a reset refused because the VM stopped
		// meanwhile is a 409, a failed fallback a 500.
		{"reset", fakeResetConn{state: libvirt.DomainShutdown}, []string{"state"}, conflict, "not running"},
		{"reset", fakeResetConn{state: libvirt.DomainRunning, stateAfter: libvirt.DomainShutoff, resetErr: invalid}, []string{"state", "reset", "state"}, conflict, "domain is not running"},
		{"reset", fakeResetConn{state: libvirt.DomainRunning, resetErr: errUnsupported, persistent: 1, createErr: invalid},
			[]string{"state", "reset", "persistent", "destroy", "create"}, fail, "stopped but could not be started"},
		{"reset", fakeResetConn{state: libvirt.DomainCrashed, persistent: 1, createErr: invalid},
			[]string{"state", "persistent", "destroy", "create"}, fail, "stopped but could not be started"},
	}
	for _, c := range cases {
		t.Run(fmt.Sprintf("%s/%v", c.action, c.wantCalls), func(t *testing.T) {
			conn := c.conn
			err := runAction(&conn, libvirt.Domain{Name: "vm"}, c.action)
			if !reflect.DeepEqual(conn.calls, c.wantCalls) {
				t.Errorf("calls = %v, want %v", conn.calls, c.wantCalls)
			}
			got := ok
			switch {
			case IsWrongState(err):
				got = conflict
			case err != nil:
				got = fail
			}
			if got != c.want || (err != nil && !strings.Contains(err.Error(), c.msg)) {
				t.Errorf("err = %v (%d), want %d %q", err, got, c.want, c.msg)
			}
			if IsNotFound(err) {
				t.Errorf("not found: %v", err)
			}
		})
	}
	// An unknown domain stays not found (422), even from the state read.
	noDomain := libvirt.Error{Code: uint32(libvirt.ErrNoDomain), Message: "Domain not found"}
	conn := fakeResetConn{stateErr: noDomain}
	if err := runAction(&conn, libvirt.Domain{}, "start"); !IsNotFound(err) || IsWrongState(err) {
		t.Errorf("vanished domain: %v", err)
	}
}
