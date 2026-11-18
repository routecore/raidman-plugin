package api

import (
	"bytes"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/creack/pty"
	"github.com/gorilla/websocket"

	"github.com/routecore/raidman-plugin/src/internal/service/auth"
	"github.com/routecore/raidman-plugin/src/internal/service/docker"
	"github.com/routecore/raidman-plugin/src/internal/service/vm"
)

const qemuLogDir = "/var/log/libvirt/qemu"

// ptyStream returns the handler for a PTY-backed stream type.
func ptyStream(termType string) func(a *Api, ws *wsConn, r *http.Request, k *auth.Key) {
	return func(a *Api, ws *wsConn, r *http.Request, k *auth.Key) {
		a.handlePty(ws, termType, r, k)
	}
}

// buildPtyCommand validates the request and builds the command for a PTY
// stream. User-supplied values only ever appear as single argv entries after
// validation (and after "--" where the tool supports it); nothing goes
// through a shell.
func (a *Api) buildPtyCommand(termType string, r *http.Request) (*exec.Cmd, string) {
	q := r.URL.Query()
	termEnv := append(os.Environ(), "TERM=xterm-256color")
	switch termType {
	case "host":
		if !a.hostTerminalEnabled() {
			log.Printf("[SECURITY] Host terminal disabled by settings")
			return nil, "Error: Host terminal access is disabled by administrator"
		}
		cmd := exec.Command("/bin/bash", "--login")
		cmd.Env = termEnv
		if home := os.Getenv("HOME"); home != "" {
			cmd.Dir = home
		}
		return cmd, ""

	case "docker", "docker-log":
		id, err := normalizeContainerRef(q.Get("container"))
		if err != nil {
			return nil, "Error: " + err.Error()
		}
		if termType == "docker" {
			// Optional shell= (contract §4): allowlisted, default sh.
			shell := "sh"
			if v := q.Get("shell"); v != "" {
				s, ok := docker.NormalizeShell(v)
				if !ok {
					return nil, "Error: unsupported shell (allowed: " + strings.Join(docker.ExecShells, ", ") + ")"
				}
				shell = s
			}
			cmd := exec.Command("docker", "exec", "-it", "--", id, shell)
			cmd.Env = termEnv
			return cmd, ""
		}
		return exec.Command("docker", "logs", "-f", "--tail", "100", "--", id), ""

	case "vm": // serial console
		ref := q.Get("vm")
		if err := validateVMRef(ref); err != nil {
			return nil, "Error: " + err.Error()
		}
		dom, err := vm.ResolveDomain(ref)
		if err != nil {
			return nil, "Error: VM not found: " + err.Error()
		}
		// The UUID can never be mistaken for an option and needs no quoting.
		cmd := exec.Command("virsh", "console", dom.UUID)
		cmd.Env = termEnv
		return cmd, ""

	case "vm-log":
		ref := q.Get("vm")
		if err := validateVMRef(ref); err != nil {
			return nil, "Error: " + err.Error()
		}
		name := ref
		if dom, err := vm.ResolveDomain(ref); err == nil {
			name = dom.Name
		}
		logPath, ok := vmLogPath(name)
		if !ok {
			return nil, "Error: invalid vm name"
		}
		return exec.Command("tail", "-F", "-n", "100", "--", logPath), ""
	}
	return nil, "Error: unknown type"
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

func (a *Api) handlePty(ws *wsConn, termType string, r *http.Request, k *auth.Key) {
	cmd, errMsg := a.buildPtyCommand(termType, r)
	if cmd == nil {
		_ = ws.WriteText(errMsg)
		return
	}
	log.Printf("[AUDIT] Starting PTY session %q by key %s from %s", termType, k.Label(), r.RemoteAddr)

	// pty.Start runs the child with Setsid, so it leads its own process
	// group and the whole group can be signalled on close.
	ptmx, err := pty.Start(cmd)
	if err != nil {
		_ = ws.WriteText("Error starting pty: " + err.Error())
		return
	}
	defer func() {
		_ = ptmx.Close()
		terminateGroup(cmd)
		log.Printf("[AUDIT] PTY session %q by key %s ended", termType, k.Label())
	}()

	// Socket closed, key revoked or ping failure: close the PTY so the read
	// loop below ends.
	go func() {
		<-ws.ctx.Done()
		_ = ptmx.Close()
	}()

	// Log streams are read-only (they only need DOCKER/VMS:READ_ANY):
	// client input is never written to their PTY.
	readOnly := termType == "docker-log" || termType == "vm-log"
	go func() {
		for {
			mt, message, err := ws.ReadMessage()
			if err != nil {
				_ = ptmx.Close()
				return
			}
			if mt == websocket.TextMessage {
				if cols, rows, ok := parseResize(message); ok {
					// A failed resize must not end the session.
					_ = pty.Setsize(ptmx, &pty.Winsize{Cols: cols, Rows: rows})
					continue
				}
			}
			if readOnly {
				continue
			}
			if _, err := ptmx.Write(message); err != nil {
				return
			}
		}
	}()

	buf := make([]byte, 32*1024)
	for {
		n, err := ptmx.Read(buf)
		if n > 0 {
			if werr := ws.WriteMessage(websocket.BinaryMessage, buf[:n]); werr != nil {
				return
			}
		}
		if err != nil {
			return
		}
	}
}

// Terminal size bounds for resize requests.
const maxTermDim = 1000

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
