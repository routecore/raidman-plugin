package api

import (
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/routecore/raidman-plugin/src/internal/service/vm"
)

// TestVmActionReset checks the reset action's authz (VMS:UPDATE_ANY, like
// every other power action), the 400 for unknown actions (rejected before
// libvirt) and the 409 for a VM that is not running.
func TestVmActionReset(t *testing.T) {
	a, _ := newTestApi(t)
	h, err := a.Handler()
	if err != nil {
		t.Fatal(err)
	}
	var calls []string
	var next error
	orig := executeVmAction
	executeVmAction = func(ref, action string) error {
		calls = append(calls, ref+"|"+action)
		return next
	}
	t.Cleanup(func() { executeVmAction = orig })

	body := `{"vm":"Windows 11","action":"reset"}`
	if code, _ := doReq(t, h, "POST", "/api/vm/action", body, keyViewer); code != http.StatusForbidden {
		t.Errorf("viewer reset: %d, want 403", code)
	}
	if code, _ := doReq(t, h, "POST", "/api/vm/action", body, keyGuest); code != http.StatusForbidden {
		t.Errorf("guest reset: %d, want 403", code)
	}
	if len(calls) != 0 {
		t.Fatalf("forbidden keys reached libvirt: %v", calls)
	}

	if code, b := doReq(t, h, "POST", "/api/vm/action", body, keyVMOps); code != http.StatusOK || !strings.Contains(string(b), `"success":true`) {
		t.Errorf("vmops reset: %d %s", code, b)
	}
	if len(calls) != 1 || calls[0] != "Windows 11|reset" {
		t.Errorf("calls = %v", calls)
	}

	next = vm.ErrNotRunning
	if code, _ := doReq(t, h, "POST", "/api/vm/action", body, keyAdmin); code != http.StatusConflict {
		t.Errorf("reset of stopped VM: %d, want 409", code)
	}
	next = errors.New("libvirt exploded")
	if code, _ := doReq(t, h, "POST", "/api/vm/action", body, keyAdmin); code != http.StatusInternalServerError {
		t.Errorf("libvirt failure: %d, want 500", code)
	}

	calls = nil
	if code, _ := doReq(t, h, "POST", "/api/vm/action", `{"vm":"Windows 11","action":"explode"}`, keyAdmin); code != http.StatusBadRequest {
		t.Errorf("unknown action: %d, want 400", code)
	}
	if len(calls) != 0 {
		t.Errorf("unknown action reached libvirt: %v", calls)
	}
}
