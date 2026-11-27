// Package system runs host power actions through Unraid's clean shutdown path.
//
// Reference (unraid/webgui master):
//   - emhttp/plugins/dynamix/include/Boot.php (the webGUI Reboot / Shutdown
//     buttons): "/sbin/reboot -n" / "/sbin/poweroff -n", after creating or
//     removing /boot/unraidsafemode.
//   - sbin/powerdown (deprecated, logs a warning): "/sbin/reboot" for -r,
//     else "/sbin/init 0".
//
// Without -f, sysvinit's reboot/poweroff (halt.c) hand over to shutdown(8),
// so init switches to runlevel 6/0 and Unraid's rc.6 stops services and the
// array cleanly before the power changes. -n only disables halt's own sync
// on the direct path and is omitted; -f (immediate, unclean) is never used.
package system

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"syscall"
)

// Overridable in tests (reboot/poweroff exist on developer machines too).
var (
	RebootBinary   = "/sbin/reboot"
	PoweroffBinary = "/sbin/poweroff"
	SafeModeFlag   = "/boot/unraidsafemode"

	StartDetached = func(name string, args ...string) error {
		cmd := exec.Command(name, args...)
		// Own session: the shutdown sequence stops this daemon and must not
		// take the command with it.
		cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
		if err := cmd.Start(); err != nil {
			return err
		}
		go func() { _ = cmd.Wait() }()
		return nil
	}
)

// Options for ExecuteAction.
type Options struct {
	// SafeMode, when set, creates (true) or removes (false) the safe-mode
	// flag like the webGUI's "Reboot in safe mode" checkbox. nil leaves it
	// untouched (protocol-1 behaviour).
	SafeMode *bool
}

// ExecuteAction starts a clean shutdown or reboot. It returns once the
// command has been started; the host goes down shortly after.
func ExecuteAction(action string, opts Options) error {
	var bin string
	switch action {
	case "shutdown":
		bin = PoweroffBinary
	case "reboot":
		bin = RebootBinary
	default:
		return fmt.Errorf("unknown action: %s", action)
	}
	if _, err := os.Stat(bin); err != nil {
		return fmt.Errorf("%s unavailable: %w", bin, err)
	}
	if opts.SafeMode != nil {
		if *opts.SafeMode {
			f, err := os.OpenFile(SafeModeFlag, os.O_CREATE|os.O_WRONLY, 0o644)
			if err != nil {
				return fmt.Errorf("could not set safe mode: %w", err)
			}
			f.Close()
		} else if err := os.Remove(SafeModeFlag); err != nil && !os.IsNotExist(err) {
			// Boot.php clears it with a silent @unlink and goes on: a flag that
			// cannot be removed must not block a normal reboot or shutdown.
			log.Printf("[system] could not clear safe mode flag %s: %v", SafeModeFlag, err)
		}
	}
	if err := StartDetached(bin); err != nil {
		return fmt.Errorf("failed to start %s: %w", action, err)
	}
	return nil
}
