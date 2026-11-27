package api

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"unicode/utf8"

	"github.com/creack/pty"
	"github.com/gorilla/websocket"

	"github.com/routecore/raidman-plugin/src/internal/service/auth"
	"github.com/routecore/raidman-plugin/src/internal/service/docker"
	"github.com/routecore/raidman-plugin/src/internal/service/vm"
)

// Overridable in tests.
var (
	qemuLogDir    = "/var/log/libvirt/qemu"
	resolveDomain = vm.ResolveDomain
)

// ptyStream returns the handler for a PTY-backed stream type.
func ptyStream(termType string) func(a *Api, ws *wsConn, r *http.Request, k *auth.Key) {
	return func(a *Api, ws *wsConn, r *http.Request, k *auth.Key) {
		a.handlePty(ws, termType, r, k)
	}
}

// buildPtyCommand validates the request and builds the command for a PTY
// stream. User-supplied values only ever appear as single argv entries after
// validation (and after "--" where the tool supports it); nothing goes
// through a shell. watch, when not nil (container consoles), is started
// once the command runs and ended once the session has ended (see
// execWatch).
func (a *Api) buildPtyCommand(termType string, r *http.Request) (cmd *exec.Cmd, errMsg string, watch *execWatch) {
	q := r.URL.Query()
	termEnv := append(os.Environ(), "TERM=xterm-256color")
	switch termType {
	case "host":
		if !a.hostTerminalEnabled() {
			log.Printf("[SECURITY] Host terminal disabled by settings")
			return nil, errHostTerminalDisabled, nil
		}
		cmd := exec.Command("/bin/bash", "--login")
		cmd.Env = termEnv
		if home := os.Getenv("HOME"); home != "" {
			cmd.Dir = home
		}
		return cmd, "", nil

	case "docker", "docker-log":
		id, err := normalizeContainerRef(q.Get("container"))
		if err != nil {
			return nil, "Error: " + err.Error(), nil
		}
		if termType == "docker" {
			// Optional shell= (contract §4): allowlisted, default sh.
			shell := "sh"
			if v := q.Get("shell"); v != "" {
				s, ok := docker.NormalizeShell(v)
				if !ok {
					return nil, "Error: unsupported shell (allowed: " + strings.Join(docker.ExecShells, ", ") + ")", nil
				}
				shell = s
			}
			// The tag marks the processes started in the container (see
			// execWatch); it is passed to the container only, never
			// set in the docker CLI's own environment.
			tag, err := newExecTag()
			if err != nil {
				return nil, "Error: " + err.Error(), nil
			}
			// The container's full id ties the cleanup to its processes.
			// Unknown here (a missing container: the CLI says so), it is
			// looked up again at the end.
			ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
			fullID, _ := containerFullID(ctx, id)
			cancel()
			cmd := exec.Command("docker", "exec", "-it", "-e", execTagEnv+"="+tag, "--", id, shell)
			cmd.Env = termEnv
			return cmd, "", newExecWatch(id, fullID, tag)
		}
		return exec.Command("docker", "logs", "-f", "--tail", "100", "--", id), "", nil

	case "vm": // serial console
		ref := q.Get("vm")
		if err := validateVMRef(ref); err != nil {
			return nil, "Error: " + err.Error(), nil
		}
		dom, err := resolveDomain(ref)
		if err != nil {
			return nil, "Error: VM not found: " + err.Error(), nil
		}
		// The UUID can never be mistaken for an option and needs no quoting.
		cmd := exec.Command("virsh", "console", dom.UUID)
		cmd.Env = termEnv
		return cmd, "", nil

	case "vm-log":
		ref := q.Get("vm")
		if err := validateVMRef(ref); err != nil {
			return nil, "Error: " + err.Error(), nil
		}
		// The log of a VM libvirt no longer knows (deleted, renamed) can
		// still be read by name; only when there is neither a domain nor a
		// log is the stream refused, without the host path, instead of
		// leaving tail -F waiting for a file that never appears.
		name := ref
		dom, derr := resolveDomain(ref)
		if derr == nil {
			name = dom.Name
		}
		logPath, ok := vmLogPath(name)
		if !ok {
			return nil, "Error: invalid vm name", nil
		}
		if derr != nil {
			if _, err := os.Stat(logPath); err != nil {
				return nil, "Error: VM not found", nil
			}
		}
		return exec.Command("tail", "-F", "-n", "100", "--", logPath), "", nil
	}
	return nil, "Error: unknown type", nil
}

// vmLogPath builds the libvirt QEMU log path for a domain name and verifies it
// stays inside the log directory.
func vmLogPath(name string) (string, bool) {
	if name == "" || filepath.Base(name) != name || name == "." || name == ".." {
		return "", false
	}
	p := filepath.Join(qemuLogDir, name+".log")
	if !strings.HasPrefix(filepath.Clean(p), qemuLogDir+"/") {
		return "", false
	}
	return p, true
}

// errHostTerminalDisabled is sent (and used as the close reason) when the
// host terminal is turned off in the plugin settings.
const errHostTerminalDisabled = "Error: Host terminal access is disabled by administrator"

// hangupGrace is how long a hung-up session's process group gets to exit
// before it is killed.
const hangupGrace = 3 * time.Second

func (a *Api) handlePty(ws *wsConn, termType string, r *http.Request, k *auth.Key) {
	cmd, errMsg, watch := a.buildPtyCommand(termType, r)
	if cmd == nil {
		_ = ws.WriteText(errMsg)
		// Nothing else reads this socket; drain it so the peer's close
		// echo ends the connection promptly.
		ws.drain()
		if errMsg == errHostTerminalDisabled {
			ws.closeWith(websocket.ClosePolicyViolation, "host terminal disabled")
		} else {
			ws.closeWith(websocket.CloseNormalClosure, errMsg)
		}
		return
	}
	log.Printf("[AUDIT] Starting PTY session %q by key %s from %q", termType, k.Label(), truncate(clientIP(r), 64))
	if watch != nil {
		// Counted from here so Shutdown waits for the cleanup (see
		// waitExecCleanups).
		a.execCleanups.Add(1)
	}

	// pty.Start runs the child with Setsid, so it leads its own process
	// group and the whole group can be signalled on close. The terminal
	// starts at 80x24 (not 0x0) until the client sends its size: docker
	// exec copies the size at start, and full-screen programs started
	// before the first resize would otherwise misrender.
	ptmx, err := pty.StartWithSize(cmd, &pty.Winsize{Cols: defaultCols, Rows: defaultRows})
	if err != nil {
		if watch != nil {
			a.execCleanups.Add(-1)
		}
		_ = ws.WriteText("Error starting pty: " + err.Error())
		ws.drain()
		ws.closeWith(websocket.CloseNormalClosure, "Error starting pty")
		return
	}
	master := pollableMaster(ptmx)
	if watch != nil {
		// Records the exec'd shell while the console is open.
		watch.start()
	}

	// The watcher below may signal the process group only while the leader
	// has not been reaped (a reaped pid/pgid can be recycled), so the
	// deferred cleanup stops it and waits for it before terminateGroup
	// reaps the leader.
	stop := make(chan struct{})
	var watcher sync.WaitGroup
	defer func() {
		close(stop)
		watcher.Wait()
		_ = master.Close()
		// Killing the docker CLI alone would leave the container's
		// processes running, so the watch ends them, on its own goroutine:
		// it reads /proc and may block on a stuck process, and must
		// never keep the CLI alive or the stream slot held.
		cliExited := make(chan struct{})
		if watch != nil {
			go func() {
				defer a.execCleanups.Add(-1)
				watch.end(cliExited)
			}()
		}
		terminateGroup(cmd)
		close(cliExited)
		log.Printf("[AUDIT] PTY session %q by key %s ended", termType, k.Label())
		// The process ended on its own (exit, logs of a stopped
		// container, ...): tell the client with a clean close instead of
		// dropping the TCP connection.
		if ws.ctx.Err() == nil {
			code := -1
			if cmd.ProcessState != nil {
				code = cmd.ProcessState.ExitCode()
			}
			ws.closeWith(websocket.CloseNormalClosure, fmt.Sprintf("process exited (%d)", code))
		}
	}()

	// Socket closed, key revoked or ping failure: close the master (which
	// wakes the blocked Read below) and hang up the session's process
	// group, killing it if it ignores SIGHUP. An idle shell or a quiet log
	// stream writes nothing, so waiting for output would leak the process,
	// the goroutines and the stream slot.
	watcher.Add(1)
	go func() {
		defer watcher.Done()
		select {
		case <-stop:
			return
		case <-ws.ctx.Done():
		}
		_ = master.Close()
		pid := cmd.Process.Pid
		_ = syscall.Kill(-pid, syscall.SIGHUP)
		select {
		case <-stop:
		case <-time.After(hangupGrace):
			_ = syscall.Kill(-pid, syscall.SIGKILL)
		}
	}()

	// Log streams are read-only (they only need DOCKER/VMS:READ_ANY):
	// client input is never written to their PTY.
	readOnly := termType == "docker-log" || termType == "vm-log"
	go func() {
		for {
			mt, message, err := ws.ReadMessage()
			if err != nil {
				return // ReadMessage cancelled ws.ctx; the watcher cleans up
			}
			if mt == websocket.TextMessage {
				if cols, rows, ok := parseResize(message); ok {
					// A failed resize must not end the session.
					_ = pty.Setsize(master, &pty.Winsize{Cols: cols, Rows: rows})
					continue
				}
			}
			if readOnly {
				continue
			}
			if _, err := master.Write(message); err != nil {
				return
			}
		}
	}()

	// Output frames never end inside a UTF-8 sequence: an incomplete tail
	// (at most utf8.UTFMax-1 bytes) is kept at the front of buf and sent
	// with the next read, so clients decoding frame by frame do not turn
	// split characters into U+FFFD.
	buf := make([]byte, 32*1024)
	pending := 0
	for {
		n, err := master.Read(buf[pending:])
		n += pending
		send := utf8SafeLen(buf[:n])
		if err != nil {
			send = n // flush everything at EOF/error
		}
		if send > 0 {
			if werr := ws.WriteMessage(websocket.BinaryMessage, buf[:send]); werr != nil {
				return
			}
		}
		pending = copy(buf, buf[send:n])
		if err != nil {
			return
		}
	}
}

// utf8SafeLen returns how many leading bytes of p can be sent without
// splitting a UTF-8 sequence: it holds back an incomplete multi-byte
// sequence at the very end. Invalid bytes are never held back (FullRune
// reports true for them), so non-UTF-8 output always flows.
func utf8SafeLen(p []byte) int {
	for i := len(p) - 1; i >= 0 && i >= len(p)-(utf8.UTFMax-1); i-- {
		if utf8.RuneStart(p[i]) {
			if utf8.FullRune(p[i:]) {
				return len(p)
			}
			return i
		}
	}
	return len(p)
}

// pollableMaster moves the PTY master onto the runtime poller.
//
// creack/pty calls Fd() on the master, which switches it to blocking mode;
// a Read blocked on such a file is not woken by Close, so a session whose
// child is idle would never notice the client leaving. A duplicate set to
// non-blocking and wrapped with os.NewFile is registered with the poller
// (and Fd() on it, e.g. from pty.Setsize, keeps it non-blocking), so Close
// interrupts the pending Read. If that fails the original is returned and
// the process-group hang-up still ends the session.
func pollableMaster(ptmx *os.File) *os.File {
	// ForkLock keeps a concurrent exec from inheriting the fd before it
	// is marked close-on-exec.
	syscall.ForkLock.RLock()
	nfd, err := syscall.Dup(int(ptmx.Fd()))
	if err == nil {
		syscall.CloseOnExec(nfd)
	}
	syscall.ForkLock.RUnlock()
	if err != nil {
		return ptmx
	}
	if err := syscall.SetNonblock(nfd, true); err != nil {
		_ = syscall.Close(nfd)
		return ptmx
	}
	_ = ptmx.Close()
	return os.NewFile(uintptr(nfd), ptmx.Name())
}

// Terminal size bounds for resize requests, and the size a terminal starts
// with.
const (
	maxTermDim  = 1000
	defaultCols = 80
	defaultRows = 24
)

// resizeEscRe is the xterm window-size report "CSI 8 ; rows ; cols t".
var resizeEscRe = regexp.MustCompile(`^\x1b\[8;(\d{1,5});(\d{1,5})t$`)

// parseResize recognises a resize control frame (protocol 2, contract §4):
// a text frame that is exactly "\x1b[8;<rows>;<cols>t", or exactly the JSON
// object {"type":"resize","cols":N,"rows":M}. Anything else is terminal
// input and goes to the PTY untouched. Values must be 1..1000.
func parseResize(msg []byte) (cols, rows uint16, ok bool) {
	if len(msg) == 0 || len(msg) > 128 {
		return 0, 0, false
	}
	var c, r int
	switch msg[0] {
	case 0x1b:
		m := resizeEscRe.FindSubmatch(msg)
		if m == nil {
			return 0, 0, false
		}
		r, _ = strconv.Atoi(string(m[1]))
		c, _ = strconv.Atoi(string(m[2]))
	case '{':
		var f struct {
			Type *string `json:"type"`
			Cols *int    `json:"cols"`
			Rows *int    `json:"rows"`
		}
		dec := json.NewDecoder(bytes.NewReader(msg))
		dec.DisallowUnknownFields()
		if dec.Decode(&f) != nil || dec.More() || f.Type == nil || *f.Type != "resize" || f.Cols == nil || f.Rows == nil {
			return 0, 0, false
		}
		c, r = *f.Cols, *f.Rows
	default:
		return 0, 0, false
	}
	if c < 1 || r < 1 || c > maxTermDim || r > maxTermDim {
		return 0, 0, false
	}
	return uint16(c), uint16(r), true
}

// terminateGroup hangs up the session's process group, waits briefly for the
// leader to exit, then kills the group if it ignored SIGHUP. Always reaps the
// leader so no zombie is left.
func terminateGroup(cmd *exec.Cmd) {
	if cmd.Process == nil {
		return
	}
	pid := cmd.Process.Pid
	_ = syscall.Kill(-pid, syscall.SIGHUP)
	done := make(chan struct{})
	go func() {
		_ = cmd.Wait()
		close(done)
	}()
	select {
	case <-done:
		return
	case <-time.After(3 * time.Second):
	}
	_ = syscall.Kill(-pid, syscall.SIGKILL)
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		log.Printf("PTY process %d did not exit after SIGKILL", pid)
	}
}
