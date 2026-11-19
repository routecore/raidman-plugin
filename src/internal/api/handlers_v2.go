package api

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/routecore/raidman-plugin/src/internal/service/array"
	"github.com/routecore/raidman-plugin/src/internal/service/auth"
	"github.com/routecore/raidman-plugin/src/internal/service/docker"
	"github.com/routecore/raidman-plugin/src/internal/service/emhttp"
	"github.com/routecore/raidman-plugin/src/internal/service/mover"
)

// ProtocolVersion is the plugin HTTP/WS protocol reported by /api/health.
const ProtocolVersion = 2

// Features is the protocol-2 feature list (contract §4; the app prefixes
// them with "plugin:").
var Features = []string{
	"docker.updates",
	"docker.meta",
	"disks.state",
	"disks.spin",
	"mover",
	"parity.v2",
	"power",
	"terminal.resize",
	// VM additions: POST /api/vm/action {"action":"reset"}; per-NIC
	// interfaces[].ipAddresses; hostdevs[] on /api/vm/info and /api/vms.
	"vm.reset",
	"vm.ips",
	"vm.hostdevs",
	// Feature wave: GET /api/plugins, POST /api/plugins/check; POST
	// /api/plugins/update and /remove; GET /api/disks/smart; GET
	// /api/files/list and /download; GET /api/system/memory; GET /api/ups/nut.
	"plugins.list",
	"plugins.ops",
	"disks.smart",
	"files",
	"mem.breakdown",
	"ups.nut",
}

// Paths read by /api/health (overridable in tests).
var (
	healthVarIni        = "/var/local/emhttp/var.ini"
	healthUnraidVersion = "/etc/unraid-version"
)

// Timeouts for read-only Docker calls and emhttpd commands. Spin-up can take
// a while per disk, so emhttpd gets the client's own 60 s limit.
const (
	dockerReadTimeout = 20 * time.Second
	emcmdTimeout      = 90 * time.Second
)

// decodeBody decodes a small JSON request body strictly enough to reject
// garbage but tolerant of unknown fields (additive clients).
func decodeBody(r *http.Request, v any) error {
	dec := json.NewDecoder(io.LimitReader(r.Body, 64*1024))
	if err := dec.Decode(v); err != nil {
		return errors.New("invalid JSON body")
	}
	return nil
}

// unraidVersion returns the OS version from var.ini, else /etc/unraid-version.
func unraidVersion() *string {
	if vars, err := emhttp.ReadIni(healthVarIni); err == nil && vars["version"] != "" {
		v := vars["version"]
		return &v
	}
	if vars, err := emhttp.ReadIni(healthUnraidVersion); err == nil && vars["version"] != "" {
		v := vars["version"]
		return &v
	}
	return nil
}

// ---- health ---------------------------------------------------------------

func (a *Api) handleHealth(w http.ResponseWriter, _ *http.Request, _ *auth.Key, _ authSource) {
	version := ""
	if a.ctx != nil {
		version = a.ctx.Config.Version
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"version":      version,
		"protocol":     ProtocolVersion,
		"features":     Features,
		"unraid":       unraidVersion(),
		"hostTerminal": a.hostTerminalEnabled(),
	})
}

// ---- docker -----------------------------------------------------------------

// Docker data sources (overridable in tests).
var (
	getDockerUpdates   = docker.GetUpdates
	getDockerMeta      = docker.GetMeta
	triggerUpdateCheck = docker.TriggerUpdateCheck
	updateCheckRunning = docker.UpdateCheckRunning
)

func (a *Api) handleDockerUpdates(w http.ResponseWriter, r *http.Request, _ *auth.Key, _ authSource) {
	ctx, cancel := context.WithTimeout(r.Context(), dockerReadTimeout)
	defer cancel()
	list, err := getDockerUpdates(ctx)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "docker: "+err.Error())
		return
	}
	if updateCheckRunning() {
		w.Header().Set("X-Raidman-Update-Check", "running")
	}
	writeJSON(w, http.StatusOK, list)
}

func (a *Api) handleDockerUpdateCheck(w http.ResponseWriter, _ *http.Request, k *auth.Key, _ authSource) {
	already, err := triggerUpdateCheck(a.baseCtx)
	if err != nil {
		status := http.StatusInternalServerError
		if errors.Is(err, docker.ErrCheckUnavailable) {
			status = http.StatusNotImplemented
		}
		log.Printf("[AUDIT] Docker update check FAILED by key %s: %v", k.Label(), err)
		writeJSONError(w, status, err.Error())
		return
	}
	log.Printf("[AUDIT] Docker update check started by key %s (already running: %v)", k.Label(), already)
	resp := map[string]any{"started": true}
	if already {
		resp["alreadyRunning"] = true
	}
	writeJSON(w, http.StatusOK, resp)
}

func (a *Api) handleDockerMeta(w http.ResponseWriter, r *http.Request, _ *auth.Key, _ authSource) {
	ctx, cancel := context.WithTimeout(r.Context(), dockerReadTimeout)
	defer cancel()
	list, err := getDockerMeta(ctx)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "docker: "+err.Error())
		return
	}
	writeJSON(w, http.StatusOK, list)
}

// ---- disks ------------------------------------------------------------------

func (a *Api) handleDisksState(w http.ResponseWriter, _ *http.Request, _ *auth.Key, _ authSource) {
	disks, err := array.GetDiskStates()
	if err != nil {
		status := http.StatusInternalServerError
		if errors.Is(err, os.ErrNotExist) {
			status = http.StatusServiceUnavailable
		}
		writeJSONError(w, status, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, disks)
}

func (a *Api) handleDisksSpin(w http.ResponseWriter, r *http.Request, k *auth.Key, _ authSource) {
	var req struct {
		Disk   string `json:"disk"`
		Action string `json:"action"`
	}
	if err := decodeBody(r, &req); err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), emcmdTimeout)
	defer cancel()
	if err := array.Spin(ctx, req.Disk, req.Action); err != nil {
		log.Printf("[AUDIT] Spin %s %q FAILED by key %s: %v", req.Action, req.Disk, k.Label(), err)
		writeJSONError(w, array.StatusOf(err), err.Error())
		return
	}
	log.Printf("[AUDIT] Spin %s %q by key %s", req.Action, req.Disk, k.Label())
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

// ---- mover ------------------------------------------------------------------

func (a *Api) handleMoverStatus(w http.ResponseWriter, _ *http.Request, _ *auth.Key, _ authSource) {
	st, err := mover.GetStatus()
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, st)
}

func (a *Api) handleMoverAction(w http.ResponseWriter, r *http.Request, k *auth.Key, _ authSource) {
	var req struct {
		Action string `json:"action"`
	}
	if err := decodeBody(r, &req); err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), emcmdTimeout)
	defer cancel()
	st, err := mover.Action(ctx, req.Action)
	if err != nil {
		log.Printf("[AUDIT] Mover %q FAILED by key %s: %v", req.Action, k.Label(), err)
		writeJSONError(w, mover.StatusOf(err), err.Error())
		return
	}
	log.Printf("[AUDIT] Mover %q by key %s", req.Action, k.Label())
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "running": st.Running})
}

// ---- parity -----------------------------------------------------------------

func (a *Api) handleParityAction(w http.ResponseWriter, r *http.Request, k *auth.Key, _ authSource) {
	var req struct {
		Action  string `json:"action"`
		Correct bool   `json:"correct"`
	}
	if err := decodeBody(r, &req); err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}
	req.Action = strings.ToLower(strings.TrimSpace(req.Action))
	ctx, cancel := context.WithTimeout(r.Context(), emcmdTimeout)
	defer cancel()
	if err := array.ParityAction(ctx, req.Action, req.Correct); err != nil {
		log.Printf("[AUDIT] Parity %q (correct=%v) FAILED by key %s: %v", req.Action, req.Correct, k.Label(), err)
		writeJSONError(w, array.StatusOf(err), err.Error())
		return
	}
	log.Printf("[AUDIT] Parity %q (correct=%v) by key %s", req.Action, req.Correct, k.Label())
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}
