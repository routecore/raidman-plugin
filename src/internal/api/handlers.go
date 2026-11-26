package api

import (
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/routecore/raidman-plugin/src/internal/service/array"
	"github.com/routecore/raidman-plugin/src/internal/service/auth"
	"github.com/routecore/raidman-plugin/src/internal/service/docker"
	"github.com/routecore/raidman-plugin/src/internal/service/httperr"
	"github.com/routecore/raidman-plugin/src/internal/service/system"
	"github.com/routecore/raidman-plugin/src/internal/service/vm"
)

// VM operations; variables for tests (never reach libvirt there).
var (
	executeVmAction = vm.ExecuteVmAction
	getVmInfo       = vm.GetVmInfo
	setVmAutostart  = vm.SetVmAutostart
)

// vmNotFound answers an unknown VM like an unknown container: 422 with
// "code":"not_found" as JSON (a 404 tells the app "plugin outdated"). It
// reports whether err was one.
func vmNotFound(w http.ResponseWriter, err error) bool {
	if !vm.IsNotFound(err) {
		return false
	}
	writeHTTPError(w, httperr.NotFound("%s", err.Error()))
	return true
}

// vmErrorStatus is the plain-text status of any other VM error: 409 when
// the VM's state does not allow the operation, else 500.
func vmErrorStatus(err error) int {
	if vm.IsWrongState(err) {
		return http.StatusConflict
	}
	return http.StatusInternalServerError
}

// vmIconDir is a variable for tests.
var vmIconDir = "/usr/local/emhttp/plugins/dynamix.vm.manager/templates/images"

// Docker container sources (overridable in tests).
var (
	getContainers          = docker.GetContainers
	executeContainerAction = docker.ExecuteContainerAction
)

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// writeJSONError writes the protocol-2 error shape { "error": "..." }.
// Protocol-1 routes keep their plain-text errors (http.Error).
func writeJSONError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

// writeJSONErrorCode writes { "error": "...", "code": "..." }: code is a
// stable machine-readable reason (httperr.CodeNotFound, ...).
func writeJSONErrorCode(w http.ResponseWriter, status int, code, msg string) {
	if code == "" {
		writeJSONError(w, status, msg)
		return
	}
	writeJSON(w, status, map[string]string{"error": msg, "code": code})
}

// writeHTTPError writes a service error as JSON with the status and code
// carried by an *httperr.Error (500 and no code otherwise).
func writeHTTPError(w http.ResponseWriter, err error) {
	writeJSONErrorCode(w, httperr.StatusOf(err), httperr.CodeOf(err), err.Error())
}

// arrayHTTPError converts an array service error to an *httperr.Error. The
// array package answers a missing disk with 404; like every missing resource
// it goes out as 422 + not_found (a 404 tells the app "plugin outdated").
func arrayHTTPError(err error) error {
	status := array.StatusOf(err)
	if status == http.StatusNotFound {
		return httperr.NotFound("%s", err.Error())
	}
	return &httperr.Error{Status: status, Msg: err.Error()}
}

func writeSuccess(w http.ResponseWriter) {
	writeJSON(w, http.StatusOK, map[string]bool{"success": true})
}

// ---- VMs ------------------------------------------------------------------

func (a *Api) handleVmInfo(w http.ResponseWriter, r *http.Request, _ *auth.Key, _ authSource) {
	ref := r.URL.Query().Get("vm")
	if ref == "" {
		http.Error(w, "Missing vm param", http.StatusBadRequest)
		return
	}
	if err := validateVMRef(ref); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	info, err := getVmInfo(ref)
	if err != nil {
		if !vmNotFound(w, err) {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
		return
	}
	writeJSON(w, http.StatusOK, info)
}

func (a *Api) handleGetVms(w http.ResponseWriter, _ *http.Request, _ *auth.Key, _ authSource) {
	vms, err := vm.GetVms()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, vms)
}

func (a *Api) handleVmAutostart(w http.ResponseWriter, r *http.Request, k *auth.Key, _ authSource) {
	var req struct {
		Vm string `json:"vm"`
		// A pointer: a request without "enabled" must not silently turn
		// autostart off.
		Enabled *bool `json:"enabled"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}
	if req.Vm == "" {
		http.Error(w, "Missing vm name", http.StatusBadRequest)
		return
	}
	if req.Enabled == nil {
		http.Error(w, "Missing enabled", http.StatusBadRequest)
		return
	}
	if err := validateVMRef(req.Vm); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if err := setVmAutostart(req.Vm, *req.Enabled); err != nil {
		log.Printf("[AUDIT] VM autostart=%v on %q FAILED by key %s: %v", *req.Enabled, req.Vm, k.Label(), err)
		if !vmNotFound(w, err) {
			http.Error(w, err.Error(), vmErrorStatus(err))
		}
		return
	}
	log.Printf("[AUDIT] VM autostart=%v on %q by key %s", *req.Enabled, req.Vm, k.Label())
	writeSuccess(w)
}

func (a *Api) handleVmAction(w http.ResponseWriter, r *http.Request, k *auth.Key, _ authSource) {
	var req struct {
		Vm     string `json:"vm"`
		Action string `json:"action"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}
	if req.Vm == "" || req.Action == "" {
		http.Error(w, "Missing params", http.StatusBadRequest)
		return
	}
	if err := validateVMRef(req.Vm); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if !vm.ValidAction(req.Action) {
		http.Error(w, "invalid action: "+req.Action, http.StatusBadRequest)
		return
	}
	if err := executeVmAction(req.Vm, req.Action); err != nil {
		log.Printf("[AUDIT] VM action %q on %q FAILED by key %s: %v", req.Action, req.Vm, k.Label(), err)
		if !vmNotFound(w, err) {
			http.Error(w, err.Error(), vmErrorStatus(err))
		}
		return
	}
	log.Printf("[AUDIT] VM action %q on %q by key %s", req.Action, req.Vm, k.Label())
	writeSuccess(w)
}

func (a *Api) handleVmIcon(w http.ResponseWriter, r *http.Request, _ *auth.Key, _ authSource) {
	iconName := r.URL.Query().Get("icon")
	if iconName == "" {
		http.Error(w, "Missing icon param", http.StatusBadRequest)
		return
	}
	if !validIconName(iconName) {
		http.Error(w, "Invalid icon name", http.StatusBadRequest)
		return
	}
	iconPath := filepath.Join(vmIconDir, iconName)
	// Regular files only (after following symlinks in this root-owned
	// directory): ServeFile would list a directory.
	if fi, err := os.Stat(iconPath); err != nil || !fi.Mode().IsRegular() {
		http.NotFound(w, r)
		return
	}
	http.ServeFile(w, r, iconPath)
}

// ---- Array ----------------------------------------------------------------

func (a *Api) handleArrayStatus(w http.ResponseWriter, _ *http.Request, _ *auth.Key, _ authSource) {
	status, err := array.GetArrayStatus()
	if err != nil {
		http.Error(w, "Error getting status: "+err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, status)
}

func (a *Api) handleGetParityHistory(w http.ResponseWriter, _ *http.Request, _ *auth.Key, _ authSource) {
	history, err := array.GetParityHistory()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, history)
}

// handleArrayAction keeps the protocol-1 verbs (check, nocheck, sync,
// nosync, spinup, spindown) with corrected semantics; see
// array.LegacyParityAction and array.SpinAll.
func (a *Api) handleArrayAction(w http.ResponseWriter, r *http.Request, k *auth.Key, _ authSource) {
	var req struct {
		Action string `json:"action"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}
	if req.Action == "" {
		http.Error(w, "Missing action", http.StatusBadRequest)
		return
	}
	if err := array.ExecuteAction(r.Context(), req.Action); err != nil {
		log.Printf("[AUDIT] Array action %q FAILED by key %s: %v", req.Action, k.Label(), err)
		http.Error(w, err.Error(), httperr.StatusOf(arrayHTTPError(err)))
		return
	}
	log.Printf("[AUDIT] Array action %q by key %s", req.Action, k.Label())
	writeSuccess(w)
}

// ---- Docker ---------------------------------------------------------------

// handleGetContainers answers the full inspect document per container by
// default. ?fields=summary (or ?summary=1; opt-in, for the app's list polls) answers only
// the fields the app's list reads; see containerSummary. Other "fields"
// values are ignored (full documents), so older plugins that do not know the
// parameter stay compatible with clients that always send it.
//
// Sizes are computed with ?size=1, and also for a request with none of
// fields, summary, size or env: protocol-1 apps (1.2.0) send a bare GET and
// read SizeRootFs, which protocol-1 plugins always included. Current apps
// always send fields=summary, so they never pay for it.
func (a *Api) handleGetContainers(w http.ResponseWriter, r *http.Request, k *auth.Key, _ authSource) {
	q := r.URL.Query()
	legacy := !q.Has("fields") && !q.Has("summary") && !q.Has("size") && !q.Has("env")
	containers, err := getContainers(r.Context(), docker.ContainerOptions{Size: q.Get("size") == "1" || legacy})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if q.Get("fields") == "summary" || q.Get("summary") == "1" {
		// Never carries Env (Config is projected), whatever ?env says.
		out := make([]map[string]any, 0, len(containers))
		for _, c := range containers {
			out = append(out, containerSummary(c))
		}
		writeJSON(w, http.StatusOK, out)
		return
	}
	// Container environment often holds secrets. Only an explicit request
	// (?env=1) from a key that may modify containers gets it.
	withEnv := q.Get("env") == "1" && k.Has(auth.ResourceDocker, auth.ActionUpdateAny)
	if !withEnv {
		for _, c := range containers {
			docker.StripEnv(c)
		}
	}
	writeJSON(w, http.StatusOK, containers)
}

func (a *Api) handleContainerAction(w http.ResponseWriter, r *http.Request, k *auth.Key, _ authSource) {
	var req struct {
		Container string `json:"container"`
		Action    string `json:"action"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}
	if req.Container == "" {
		http.Error(w, "Invalid params", http.StatusBadRequest)
		return
	}
	if req.Action == "" {
		http.Error(w, "Missing action", http.StatusBadRequest)
		return
	}
	id, err := normalizeContainerRef(req.Container)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if err := executeContainerAction(r.Context(), id, req.Action); err != nil {
		log.Printf("[AUDIT] Docker action %q on %q FAILED by key %s: %v", req.Action, id, k.Label(), err)
		if errors.Is(err, docker.ErrNotFound) {
			// 422 + JSON code, not 404: the app reads a plugin 404 as "route
			// missing, plugin outdated" (e.g. a stale list after a recreate).
			writeHTTPError(w, httperr.NotFound("%s", err.Error()))
			return
		}
		status := http.StatusInternalServerError
		switch {
		case errors.Is(err, docker.ErrInvalidAction):
			status = http.StatusBadRequest
		case errors.Is(err, docker.ErrWrongState):
			// A double tap (pause twice, kill a stopped container) is not
			// a server failure. Plain text like every protocol-1 error; the
			// message is short and carries no container id.
			status = http.StatusConflict
		}
		http.Error(w, err.Error(), status)
		return
	}
	log.Printf("[AUDIT] Docker action %q on %q by key %s", req.Action, id, k.Label())
	writeSuccess(w)
}

// containerSummary projects one inspect map to what the app's container list
// reads (utils/api/domains/docker.ts mapPluginContainer, pluginStatusText and
// components/docker/model.ts): identity, image, state, command, labels, ports,
// networks, network mode, restart policy, mounts, AutoStart and, with
// ?size=1, the sizes. It builds new maps (never aliases c) from an allowlist,
// so Env, GraphDriver, the rest of HostConfig and State.Health.Log stay out.
func containerSummary(c map[string]any) map[string]any {
	out := pickKeys(c, "Id", "Name", "Image", "Created", "AutoStart", "SizeRw", "SizeRootFs")
	if st, ok := c["State"].(map[string]any); ok {
		s := pickKeys(st, "Status", "Running", "Paused", "Restarting", "OOMKilled", "Dead",
			"ExitCode", "Error", "StartedAt", "FinishedAt")
		if h, ok := st["Health"].(map[string]any); ok {
			s["Health"] = pickKeys(h, "Status", "FailingStreak")
		}
		out["State"] = s
	}
	if cfg, ok := c["Config"].(map[string]any); ok {
		out["Config"] = pickKeys(cfg, "Image", "Cmd", "Labels")
	}
	if ns, ok := c["NetworkSettings"].(map[string]any); ok {
		n := pickKeys(ns, "Ports")
		if nets, ok := ns["Networks"].(map[string]any); ok {
			pn := make(map[string]any, len(nets))
			for name, v := range nets {
				if ep, ok := v.(map[string]any); ok {
					pn[name] = pickKeys(ep, "IPAddress", "IPPrefixLen", "Gateway", "MacAddress", "GlobalIPv6Address")
				} else {
					pn[name] = v
				}
			}
			n["Networks"] = pn
		}
		out["NetworkSettings"] = n
	}
	if hc, ok := c["HostConfig"].(map[string]any); ok {
		out["HostConfig"] = pickKeys(hc, "NetworkMode", "RestartPolicy")
	}
	if mounts, ok := c["Mounts"].([]any); ok {
		pm := make([]any, 0, len(mounts))
		for _, v := range mounts {
			if m, ok := v.(map[string]any); ok {
				pm = append(pm, pickKeys(m, "Type", "Name", "Source", "Destination", "Mode", "RW"))
			}
		}
		out["Mounts"] = pm
	}
	return out
}

// pickKeys copies the present keys of src into a new map.
func pickKeys(src map[string]any, keys ...string) map[string]any {
	out := make(map[string]any, len(keys))
	for _, k := range keys {
		if v, ok := src[k]; ok {
			out[k] = v
		}
	}
	return out
}

// ---- System ---------------------------------------------------------------

func (a *Api) handleSystemAction(w http.ResponseWriter, r *http.Request, k *auth.Key, _ authSource) {
	var req struct {
		Action string `json:"action"`
		// SafeMode (optional, reboot only): like the webGUI checkbox.
		SafeMode *bool `json:"safeMode"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}
	if req.Action != "shutdown" && req.Action != "reboot" {
		http.Error(w, "Invalid action", http.StatusBadRequest)
		return
	}
	// Both go through Unraid's clean path (init -> rc.6 stops the array);
	// see service/system.
	if err := system.ExecuteAction(req.Action, system.Options{SafeMode: req.SafeMode}); err != nil {
		log.Printf("[AUDIT] System action %q FAILED by key %s: %v", req.Action, k.Label(), err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	log.Printf("[AUDIT] System action %q executed by key %s", req.Action, k.Label())
	writeSuccess(w)
}

// ---- noVNC ----------------------------------------------------------------

func (a *Api) handleNoVNC(w http.ResponseWriter, r *http.Request, k *auth.Key, src authSource) {
	// Requests authenticated by key (header or the app's cookie) get an opaque
	// session cookie so the web view's sub-resource and WebSocket requests
	// work without the key itself ever being stored in a plugin cookie.
	if (src == authHeader || src == authKeyCookie) && !a.hasSessionFor(r, k) {
		if id, err := a.sessions.create(k.Hash()); err == nil {
			// Secure when nginx was reached over HTTPS, or a proxy/tunnel in
			// front of it was (X-Raidman-Client-Proto, set by raidman.conf).
			// Only ever adds the flag, so a spoofed value cannot weaken it.
			isSecure := r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https" ||
				strings.EqualFold(r.Header.Get("X-Raidman-Client-Proto"), "https")
			http.SetCookie(w, &http.Cookie{
				Name:     sessionCookieName,
				Value:    id,
				Path:     "/raidman/",
				MaxAge:   int(sessionTTL.Seconds()),
				HttpOnly: true,
				Secure:   isSecure,
				SameSite: http.SameSiteLaxMode,
			})
		}
	}
	a.novnc.ServeHTTP(w, r)
}

// hasSessionFor reports whether r already carries a live session cookie for k.
func (a *Api) hasSessionFor(r *http.Request, k *auth.Key) bool {
	c, err := r.Cookie(sessionCookieName)
	if err != nil || c.Value == "" {
		return false
	}
	h, ok := a.sessions.resolve(c.Value)
	return ok && h == k.Hash()
}
