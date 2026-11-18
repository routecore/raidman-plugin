// Package mover reports and controls Unraid's mover.
//
// Reference (unraid/webgui master):
//   - sbin/mover (installed as /usr/local/sbin/mover): "mover start|stop|status",
//     PIDFILE=/var/run/mover.pid; a pid only counts while /proc/<pid>/cmdline
//     is a mover process (is_mover_pid). "mover start" runs in the foreground
//     for the whole move.
//   - ArrayOperation.page: the webGUI's Move button posts cmdStartMover to
//     emhttpd, which launches the mover in the background.
//   - var.ini shareMoverActive="yes" while the mover runs (official API
//     store/state-parsers/var.ts).
package mover

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/routecore/raidman-plugin/src/internal/service/emhttp"
)

// Overridable in tests.
var (
	VarIniPath  = "/var/local/emhttp/var.ini"
	PidFile     = "/var/run/mover.pid"
	ProcDir     = "/proc"
	MoverBinary = "/usr/local/sbin/mover"

	Emcmd interface {
		Cmd(ctx context.Context, params url.Values) error
	} = emhttp.Default

	// RunCommand runs a short command with argv only (never a shell).
	RunCommand = func(ctx context.Context, name string, args ...string) ([]byte, error) {
		return exec.CommandContext(ctx, name, args...).CombinedOutput()
	}

	StopTimeout = 30 * time.Second
)

// Error carries an HTTP status for the API layer.
type Error struct {
	Status int
	Msg    string
}

func (e *Error) Error() string { return e.Msg }

// StatusOf maps an error to an HTTP status (500 for unknown errors).
func StatusOf(err error) int {
	var me *Error
	if errors.As(err, &me) {
		return me.Status
	}
	return http.StatusInternalServerError
}

// Status is the GET /api/mover/status response.
type Status struct {
	Running bool `json:"running"`
}

var moverCmdline = regexp.MustCompile(`(^|\s)(\S*/)?mover(\s|$)`)

// pidRunning mirrors the mover script's is_mover_pid.
func pidRunning() bool {
	b, err := os.ReadFile(PidFile)
	if err != nil {
		return false
	}
	pid := strings.TrimSpace(string(b))
	if pid == "" || strings.Trim(pid, "0123456789") != "" || pid == "0" {
		return false
	}
	cmd, err := os.ReadFile(filepath.Join(ProcDir, pid, "cmdline"))
	if err != nil {
		return false
	}
	return moverCmdline.MatchString(strings.ReplaceAll(string(cmd), "\x00", " "))
}

// GetStatus reports whether the mover runs, from var.ini and the pid file.
func GetStatus() (Status, error) {
	vars, err := emhttp.ReadIni(VarIniPath)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return Status{}, fmt.Errorf("could not read array state: %w", err)
	}
	return Status{Running: vars["shareMoverActive"] == "yes" || pidRunning()}, nil
}

// Action performs POST /api/mover/action.
//
// start: refused (409) when the array is not started, user shares are
// disabled or the mover already runs; otherwise sent to emhttpd exactly as the
// webGUI's Move button does (cmdStartMover). A long-running "mover start" is
// never exec'd from a request.
//
// stop: runs "mover stop" (argv, bounded by StopTimeout) and confirms the
// mover is gone afterwards.
func Action(ctx context.Context, action string) (Status, error) {
	switch action {
	case "start":
		vars, err := emhttp.ReadIni(VarIniPath)
		if err != nil {
			return Status{}, fmt.Errorf("could not read array state: %w", err)
		}
		if st := vars["fsState"]; st != "" && st != "Started" {
			return Status{}, &Error{http.StatusConflict, "array is not started (state " + st + ")"}
		}
		if v, ok := vars["shareUser"]; ok && v != "e" {
			return Status{}, &Error{http.StatusConflict, "user shares are disabled"}
		}
		// The webGUI disables its Move button while a parity operation
		// runs (ArrayOperation.page, mymonitor state 1).
		if n, _ := strconv.ParseInt(vars["mdResync"], 10, 64); n != 0 {
			return Status{}, &Error{http.StatusConflict, "a parity operation is running"}
		}
		if s, _ := GetStatus(); s.Running {
			return s, &Error{http.StatusConflict, "mover is already running"}
		}
		if err := Emcmd.Cmd(ctx, url.Values{"cmdStartMover": {"Move"}}); err != nil {
			return Status{}, fmt.Errorf("start mover failed: %w", err)
		}
		s, _ := GetStatus()
		return s, nil

	case "stop":
		if s, _ := GetStatus(); !s.Running {
			return s, &Error{http.StatusConflict, "mover is not running"}
		}
		cctx, cancel := context.WithTimeout(ctx, StopTimeout)
		defer cancel()
		out, err := RunCommand(cctx, MoverBinary, "stop")
		if err != nil {
			msg := strings.TrimSpace(string(out))
			if msg == "" {
				msg = err.Error()
			}
			return Status{}, fmt.Errorf("stop mover failed: %s", msg)
		}
		if pidRunning() {
			return Status{Running: true}, fmt.Errorf("mover still running after stop")
		}
		// The pid is gone; var.ini's shareMoverActive may lag behind.
		return Status{Running: false}, nil
	}
	return Status{}, &Error{http.StatusBadRequest, fmt.Sprintf("invalid mover action %q (want start or stop)", action)}
}
