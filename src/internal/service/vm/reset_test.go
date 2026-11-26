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
	stateErr   error
	resetErr   error
	persistent int32
	destroyErr error
	createErr  error
	calls      []string
}

func (f *fakeResetConn) DomainGetState(libvirt.Domain, uint32) (int32, int32, error) {
	f.calls = append(f.calls, "state")
	return int32(f.state), 0, f.stateErr
}
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
		{"other reset error: no fallback", fakeResetConn{state: libvirt.DomainRunning, resetErr: libvirt.Error{Code: uint32(libvirt.ErrOperationInvalid), Message: "domain is not running"}},
			[]string{"state", "reset"}, "domain is not running", false},
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
	invalid := libvirt.Error{Code: uint32(libvirt.ErrOperationInvalid), Message: "Requested operation is not valid: domain is not running"}
	other := libvirt.Error{Code: uint32(libvirt.ErrInternalError), Message: "internal error"}
	for _, c := range []struct {
		err             error
		notFound, state bool
	}{
		{noDomain, true, false},
		{fmt.Errorf("lookup: %w", noDomain), true, false},
		{invalid, false, true},
		{fmt.Errorf("wrapped: %w", invalid), false, true},
		{ErrNotRunning, false, true},
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
