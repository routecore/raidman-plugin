package array

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strconv"

	"github.com/routecore/raidman-plugin/src/internal/service/emhttp"
)

// State file locations (overridable in tests).
var (
	VarIniPath   = "/var/local/emhttp/var.ini"
	DisksIniPath = "/var/local/emhttp/disks.ini"
	DevsIniPath  = "/var/local/emhttp/devs.ini"
)

// Emcmd is the emhttpd command runner (overridable in tests).
var Emcmd interface {
	Cmd(ctx context.Context, params url.Values) error
} = emhttp.Default

// ActionError carries an HTTP status for the API layer.
type ActionError struct {
	Status int
	Msg    string
}

func (e *ActionError) Error() string { return e.Msg }

func badRequest(format string, a ...any) error {
	return &ActionError{Status: http.StatusBadRequest, Msg: fmt.Sprintf(format, a...)}
}
func conflict(format string, a ...any) error {
	return &ActionError{Status: http.StatusConflict, Msg: fmt.Sprintf(format, a...)}
}
func notFound(format string, a ...any) error {
	return &ActionError{Status: http.StatusNotFound, Msg: fmt.Sprintf(format, a...)}
}

// StatusOf maps an error to an HTTP status (500 for unknown errors).
func StatusOf(err error) int {
	var ae *ActionError
	if errors.As(err, &ae) {
		return ae.Status
	}
	return http.StatusInternalServerError
}

// ParityState is the current parity operation state derived from var.ini.
type ParityState int

const (
	ParityIdle ParityState = iota
	ParityRunning
	ParityPaused
)

func (p ParityState) String() string {
	switch p {
	case ParityRunning:
		return "running"
	case ParityPaused:
		return "paused"
	}
	return "idle"
}

// ReadParityState reads mdState and the parity operation state from var.ini.
//
// Running vs paused follows the webGUI, which decides between its Pause and
// Resume buttons on mdResync (ArrayOperation.page: an operation exists while
// mdResyncPos > 0; mdResync != 0 shows "Pause", mdResync == 0 shows
// "Resume"). mdResyncDt (the sample interval the official API uses for its
// status) can be 0 for a moment while a check runs, so it is not used: a
// legacy "nocheck" must never cancel a running check it meant to pause.
// mdResync != 0 with mdResyncPos 0 is an operation that has just started.
func ReadParityState() (ParityState, string, error) {
	vars, err := emhttp.ReadIni(VarIniPath)
	if err != nil {
		return ParityIdle, "", fmt.Errorf("could not read array state: %w", err)
	}
	num := func(k string) int64 {
		n, _ := strconv.ParseInt(vars[k], 10, 64)
		return n
	}
	mdState := vars["mdState"]
	switch {
	case num("mdResync") != 0:
		return ParityRunning, mdState, nil
	case num("mdResyncPos") > 0:
		return ParityPaused, mdState, nil
	}
	return ParityIdle, mdState, nil
}

// ParityAction starts, pauses, resumes or cancels a parity check through
// emhttpd, using the exact form fields the Unraid webGUI submits
// (webgui ArrayOperation.page; unraid-api graph/resolvers/array/parity.service.ts):
//
//	start:  cmdCheck=Check [+ optionCorrect=correct]
//	pause:  cmdCheckPause
//	resume: cmdCheckResume   (continues from mdResyncPos; plain cmdCheck would restart from 0)
//	cancel: cmdCheckCancel
func ParityAction(ctx context.Context, action string, correct bool) error {
	state, mdState, err := ReadParityState()
	if err != nil {
		return err
	}
	if mdState != "" && mdState != "STARTED" {
		return conflict("array is not started (state %s)", mdState)
	}
	params := url.Values{"startState": {"STARTED"}}
	switch action {
	case "start":
		if state != ParityIdle {
			return conflict("a parity operation is already %s", state)
		}
		params.Set("cmdCheck", "Check")
		if correct {
			params.Set("optionCorrect", "correct")
		}
	case "pause":
		if state != ParityRunning {
			return conflict("no running parity operation to pause (state %s)", state)
		}
		params.Set("cmdCheckPause", "")
	case "resume":
		if state != ParityPaused {
			return conflict("no paused parity operation to resume (state %s)", state)
		}
		params.Set("cmdCheckResume", "")
	case "cancel":
		if state == ParityIdle {
			return conflict("no parity operation in progress")
		}
		params.Set("cmdCheckCancel", "")
	default:
		return badRequest("invalid parity action: %s", action)
	}
	if err := Emcmd.Cmd(ctx, params); err != nil {
		return fmt.Errorf("parity %s failed: %w", action, err)
	}
	return nil
}

// LegacyParityAction maps the protocol-1 verbs used by older RaidMan apps
// (which sent "check" for both START and RESUME and "nocheck" for both PAUSE
// and CANCEL) onto safe, deterministic operations:
//
//	check:   paused -> resume; idle -> start read-only (non-correcting) check; running -> 409
//	sync:    paused -> resume; idle -> start correcting check;              running -> 409
//	nocheck: running -> pause; paused -> cancel;                            idle -> 409
//	nosync:  running or paused -> cancel;                                   idle -> 409
//
// "nocheck" pauses first so an old app's PAUSE never discards progress; a
// second "nocheck" (old app's CANCEL on a paused check) cancels.
func LegacyParityAction(ctx context.Context, verb string) (string, error) {
	state, _, err := ReadParityState()
	if err != nil {
		return "", err
	}
	var action string
	correct := false
	switch verb {
	case "check", "sync":
		switch state {
		case ParityPaused:
			action = "resume"
		case ParityIdle:
			action = "start"
			correct = verb == "sync"
		default:
			return "", conflict("a parity operation is already running")
		}
	case "nocheck":
		switch state {
		case ParityRunning:
			action = "pause"
		case ParityPaused:
			action = "cancel"
		default:
			return "", conflict("no parity operation in progress")
		}
	case "nosync":
		if state == ParityIdle {
			return "", conflict("no parity operation in progress")
		}
		action = "cancel"
	default:
		return "", badRequest("invalid action: %s", verb)
	}
	return action, ParityAction(ctx, action, correct)
}

var diskNameRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.~-]{0,63}$`)

// ValidDiskName reports whether name is an acceptable emhttp device name.
func ValidDiskName(name string) bool { return diskNameRe.MatchString(name) }

func spinVerb(up bool) string {
	if up {
		return "up"
	}
	return "down"
}

// SpinAll spins all array and pool devices up or down, like the webGUI's
// "Spin Up"/"Spin Down" buttons (webgui include/ToggleState.php:
// emcmd "cmdSpin{up|down}All=Apply").
func SpinAll(ctx context.Context, up bool) error {
	field := "cmdSpin" + spinVerb(up) + "All"
	if err := Emcmd.Cmd(ctx, url.Values{field: {"Apply"}}); err != nil {
		return fmt.Errorf("spin %s all failed: %w", spinVerb(up), err)
	}
	return nil
}

// SpinDisk spins a single device (array, pool or unassigned) by its emhttp
// name, like the webGUI (ToggleState.php: emcmd "cmdSpin{up|down}=<name>").
// Unknown names return a 404 error rather than a silent success.
func SpinDisk(ctx context.Context, name string, up bool) error {
	if !ValidDiskName(name) {
		return badRequest("invalid disk name")
	}
	if !knownDevice(name) {
		return notFound("disk %q not found", name)
	}
	field := "cmdSpin" + spinVerb(up)
	if err := Emcmd.Cmd(ctx, url.Values{field: {name}}); err != nil {
		return fmt.Errorf("spin %s %s failed: %w", spinVerb(up), name, err)
	}
	return nil
}

func knownDevice(name string) bool {
	for _, p := range []string{DisksIniPath, DevsIniPath} {
		sections, err := parseIniSections(p)
		if err != nil {
			continue
		}
		for section, data := range sections {
			if section == name || data["name"] == name {
				return true
			}
		}
	}
	return false
}

// ExecuteAction implements the protocol-1 POST /api/array/action verbs.
func ExecuteAction(ctx context.Context, action string) error {
	switch action {
	case "check", "nocheck", "sync", "nosync":
		_, err := LegacyParityAction(ctx, action)
		return err
	case "spinup":
		return SpinAll(ctx, true)
	case "spindown":
		return SpinAll(ctx, false)
	}
	return badRequest("invalid action: %s", action)
}
