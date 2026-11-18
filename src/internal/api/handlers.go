package api

import (
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"os"
	"path/filepath"

	"github.com/routecore/raidman-plugin/src/internal/service/array"
	"github.com/routecore/raidman-plugin/src/internal/service/auth"
	"github.com/routecore/raidman-plugin/src/internal/service/docker"
	"github.com/routecore/raidman-plugin/src/internal/service/system"
	"github.com/routecore/raidman-plugin/src/internal/service/vm"
)

// vmIconDir is a variable for tests.
var vmIconDir = "/usr/local/emhttp/plugins/dynamix.vm.manager/templates/images"

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
	info, err := vm.GetVmInfo(ref)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
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
		Vm      string `json:"vm"`
		Enabled bool   `json:"enabled"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}
	if req.Vm == "" {
		http.Error(w, "Missing vm name", http.StatusBadRequest)
		return
	}
	if err := validateVMRef(req.Vm); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if err := vm.SetVmAutostart(req.Vm, req.Enabled); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	log.Printf("[AUDIT] VM autostart=%v on %q by key %s", req.Enabled, req.Vm, k.Label())
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
	if err := vm.ExecuteVmAction(req.Vm, req.Action); err != nil {
		log.Printf("[AUDIT] VM action %q on %q FAILED by key %s: %v", req.Action, req.Vm, k.Label(), err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
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
		http.Error(w, err.Error(), array.StatusOf(err))
		return
	}
	log.Printf("[AUDIT] Array action %q by key %s", req.Action, k.Label())
	writeSuccess(w)
}

// ---- Docker ---------------------------------------------------------------

func (a *Api) handleGetContainers(w http.ResponseWriter, r *http.Request, k *auth.Key, _ authSource) {
	q := r.URL.Query()
	containers, err := docker.GetContainers(r.Context(), docker.ContainerOptions{Size: q.Get("size") == "1"})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
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
	if err := docker.ExecuteContainerAction(r.Context(), id, req.Action); err != nil {
		status := http.StatusInternalServerError
		switch {
		case errors.Is(err, docker.ErrNotFound):
			status = http.StatusNotFound
		case errors.Is(err, docker.ErrInvalidAction):
			status = http.StatusBadRequest
		}
		log.Printf("[AUDIT] Docker action %q on %q FAILED by key %s: %v", req.Action, id, k.Label(), err)
		http.Error(w, err.Error(), status)
		return
	}
	log.Printf("[AUDIT] Docker action %q on %q by key %s", req.Action, id, k.Label())
	writeSuccess(w)
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
			isSecure := r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https"
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
