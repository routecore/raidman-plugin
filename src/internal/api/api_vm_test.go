package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"reflect"
	"strconv"
	"strings"
	"testing"

	libvirt "github.com/digitalocean/go-libvirt"

	"github.com/routecore/raidman-plugin/src/internal/domain"
	"github.com/routecore/raidman-plugin/src/internal/service/httperr"
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

// Unknown VMs answer 422 + JSON "code":"not_found" on action, autostart and
// info (like unknown containers); wrong-state actions answer a plain-text
// 409; autostart requires "enabled".
func TestVmErrorStatuses(t *testing.T) {
	a, _ := newTestApi(t)
	h, err := a.Handler()
	if err != nil {
		t.Fatal(err)
	}
	noDomain := libvirt.Error{Code: uint32(libvirt.ErrNoDomain), Message: "Domain not found: no domain with matching name 'ghost'"}
	invalid := libvirt.Error{Code: uint32(libvirt.ErrOperationInvalid), Message: "Requested operation is not valid: domain is already running"}
	var next error
	var autostart []bool
	oldExec, oldInfo, oldAuto := executeVmAction, getVmInfo, setVmAutostart
	t.Cleanup(func() { executeVmAction, getVmInfo, setVmAutostart = oldExec, oldInfo, oldAuto })
	executeVmAction = func(string, string) error { return next }
	getVmInfo = func(string) (*domain.VmInfo, error) { return nil, next }
	setVmAutostart = func(_ string, on bool) error {
		autostart = append(autostart, on)
		return next
	}

	next = noDomain
	for _, c := range []struct{ method, path, body string }{
		{"POST", "/api/vm/action", `{"vm":"ghost","action":"start"}`},
		{"POST", "/api/vm/autostart", `{"vm":"ghost","enabled":true}`},
		{"GET", "/api/vm/info?vm=ghost", ""},
	} {
		code, body := doReq(t, h, c.method, c.path, c.body, keyAdmin)
		var m map[string]string
		if code != http.StatusUnprocessableEntity || json.Unmarshal(body, &m) != nil || m["code"] != httperr.CodeNotFound || m["error"] == "" {
			t.Errorf("%s unknown VM: %d %q, want 422 not_found", c.path, code, body)
		}
	}

	next = invalid
	code, body := doReq(t, h, "POST", "/api/vm/action", `{"vm":"Windows 11","action":"start"}`, keyAdmin)
	if code != http.StatusConflict || json.Valid(body) || !strings.Contains(string(body), "already running") {
		t.Errorf("start of a running VM: %d %q, want plain-text 409", code, body)
	}
	next = errors.New("libvirt exploded")
	if code, _ := doReq(t, h, "POST", "/api/vm/action", `{"vm":"Windows 11","action":"start"}`, keyAdmin); code != http.StatusInternalServerError {
		t.Errorf("libvirt failure: %d, want 500", code)
	}

	next, autostart = nil, nil
	for _, body := range []string{`{"vm":"Windows 11"}`, `{"vm":"Windows 11","enabled":null}`} {
		if code, b := doReq(t, h, "POST", "/api/vm/autostart", body, keyAdmin); code != http.StatusBadRequest {
			t.Errorf("autostart %s: %d %q, want 400", body, code, b)
		}
	}
	if len(autostart) != 0 {
		t.Fatalf("autostart without enabled reached libvirt: %v", autostart)
	}
	for _, on := range []bool{false, true} {
		body := `{"vm":"Windows 11","enabled":` + strconv.FormatBool(on) + `}`
		if code, b := doReq(t, h, "POST", "/api/vm/autostart", body, keyAdmin); code != http.StatusOK {
			t.Errorf("autostart %v: %d %q", on, code, b)
		}
	}
	if !reflect.DeepEqual(autostart, []bool{false, true}) {
		t.Errorf("autostart calls = %v", autostart)
	}
}
