package api

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"log"
	"net/http"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/routecore/raidman-plugin/src/internal/service/auth"
	"github.com/routecore/raidman-plugin/src/internal/service/files"
	"github.com/routecore/raidman-plugin/src/internal/service/memory"
	"github.com/routecore/raidman-plugin/src/internal/service/nut"
	"github.com/routecore/raidman-plugin/src/internal/service/plugins"
	"github.com/routecore/raidman-plugin/src/internal/service/smart"
)

// Feature wave endpoints (plugins.list, plugins.ops, disks.smart, files,
// mem.breakdown, ups.nut). Statuses avoid 404 (the app reads it as "route
// missing, old plugin") and 502-504 (read as "daemon down"): a missing
// entity is 422, a missing host tool 501.

// Data sources (overridable in tests).
var (
	listPlugins    = plugins.List
	checkPlugins   = plugins.CheckAll
	updatePlugin   = plugins.Update
	removePlugin   = plugins.Remove
	getSmart       = smart.Get
	getMemory      = memory.Get
	getNut         = nut.Get
	pluginUpdateTO = 10 * time.Minute
)

const nutTimeout = 30 * time.Second

// writeServiceError answers a service error as JSON, keeping its "code"
// (e.g. 501 smart_unsupported, 422 not_found).
func writeServiceError(w http.ResponseWriter, err error) {
	writeHTTPError(w, err)
}

// opResponse is { ok, output }; a failed operation also carries the output
// as "message" so clients that turn ok:false into an error keep it.
type opResponse struct {
	OK      bool   `json:"ok"`
	Output  string `json:"output"`
	Message string `json:"message,omitempty"`
}

func opBody(res plugins.OpResult) opResponse {
	out := opResponse{OK: res.OK, Output: res.Output}
	if !res.OK {
		out.Message = res.Output
		if strings.TrimSpace(out.Message) == "" {
			out.Message = "plugin command failed"
		}
	}
	return out
}

// ---- plugins ----------------------------------------------------------------

func (a *Api) handlePluginsList(w http.ResponseWriter, _ *http.Request, _ *auth.Key, _ authSource) {
	list, err := listPlugins()
	if err != nil {
		writeServiceError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"plugins": list})
}

func (a *Api) handlePluginsCheck(w http.ResponseWriter, _ *http.Request, k *auth.Key, _ authSource) {
	// Daemon-scoped: a client that goes away does not cut the check short.
	list, err := checkPlugins(a.baseCtx)
	if err != nil {
		log.Printf("[AUDIT] Plugin update check FAILED by key %s: %v", k.Label(), err)
		writeServiceError(w, err)
		return
	}
	log.Printf("[AUDIT] Plugin update check by key %s", k.Label())
	writeJSON(w, http.StatusOK, map[string]any{"plugins": list})
}

func decodeName(w http.ResponseWriter, r *http.Request) (string, bool) {
	var req struct {
		Name string `json:"name"`
	}
	if err := decodeBody(r, &req); err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return "", false
	}
	if strings.TrimSpace(req.Name) == "" {
		writeJSONError(w, http.StatusBadRequest, "name missing")
		return "", false
	}
	return req.Name, true
}

func (a *Api) handlePluginUpdate(w http.ResponseWriter, r *http.Request, k *auth.Key, _ authSource) {
	name, ok := decodeName(w, r)
	if !ok {
		return
	}
	// Daemon-scoped with the contract's 10-minute limit: an install must not
	// be killed halfway because the phone locked.
	ctx, cancel := context.WithTimeout(a.baseCtx, pluginUpdateTO)
	defer cancel()
	res, err := updatePlugin(ctx, name)
	if err != nil {
		log.Printf("[AUDIT] Plugin update %q REFUSED for key %s: %v", name, k.Label(), err)
		writeServiceError(w, err)
		return
	}
	log.Printf("[AUDIT] Plugin update %q by key %s (ok: %v)", name, k.Label(), res.OK)
	writeJSON(w, http.StatusOK, opBody(res))
}

func (a *Api) handlePluginRemove(w http.ResponseWriter, r *http.Request, k *auth.Key, _ authSource) {
	name, ok := decodeName(w, r)
	if !ok {
		return
	}
	res, err := removePlugin(a.baseCtx, name)
	if err != nil {
		log.Printf("[AUDIT] Plugin remove %q REFUSED for key %s: %v", name, k.Label(), err)
		writeServiceError(w, err)
		return
	}
	log.Printf("[AUDIT] Plugin remove %q by key %s (ok: %v)", name, k.Label(), res.OK)
	writeJSON(w, http.StatusOK, opBody(res))
}

// ---- SMART ------------------------------------------------------------------

func (a *Api) handleDiskSmart(w http.ResponseWriter, r *http.Request, _ *auth.Key, _ authSource) {
	rep, err := getSmart(r.Context(), r.URL.Query().Get("device"))
	if err != nil {
		writeServiceError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, rep)
}

// ---- files ------------------------------------------------------------------

// handleFilesList serves one page of a directory. offset (>= 0, default 0)
// and limit (1..files.MaxEntries, default files.MaxEntries) are optional;
// without them the response is the first page, as before paging existed.
func (a *Api) handleFilesList(w http.ResponseWriter, r *http.Request, _ *auth.Key, _ authSource) {
	q := r.URL.Query()
	var opt files.ListOptions
	if v := q.Get("offset"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 0 {
			writeJSONError(w, http.StatusBadRequest, "invalid offset")
			return
		}
		opt.Offset = n
	}
	if v := q.Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > files.MaxEntries {
			writeJSONError(w, http.StatusBadRequest, fmt.Sprintf("invalid limit (1-%d)", files.MaxEntries))
			return
		}
		opt.Limit = n
	}
	l, err := files.ListContext(r.Context(), q.Get("path"), opt)
	if err != nil {
		writeServiceError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, l)
}

func (a *Api) handleFilesDownload(w http.ResponseWriter, r *http.Request, k *auth.Key, _ authSource) {
	raw := r.URL.Query().Get("path")
	f, fi, err := files.Open(raw)
	if err != nil {
		writeServiceError(w, err)
		return
	}
	defer f.Close()
	name := filepath.Base(f.Name())
	// Every GET is audited, with its range: any range form ("bytes=0-", "bytes=-N",
	// "bytes=1-") can read (nearly) the whole file, so none may skip the log.
	if r.Method == http.MethodGet {
		rg := r.Header.Get("Range")
		log.Printf("[AUDIT] File download %q (%d bytes, range %q) by key %s", f.Name(), fi.Size(), rg, k.Label())
	}
	h := w.Header()
	h.Set("Content-Type", files.ContentType(name))
	h.Set("Content-Disposition", files.ContentDisposition(name))
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Cache-Control", "private, no-store")
	// Range requests (video preview, resumed downloads) and HEAD.
	http.ServeContent(w, r, name, fi.ModTime(), f)
}

// ---- memory -----------------------------------------------------------------

func (a *Api) handleSystemMemory(w http.ResponseWriter, _ *http.Request, _ *auth.Key, _ authSource) {
	b, err := getMemory()
	if err != nil {
		status := http.StatusInternalServerError
		if errors.Is(err, fs.ErrNotExist) {
			status = http.StatusNotImplemented
		}
		writeJSONError(w, status, "memory: "+err.Error())
		return
	}
	writeJSON(w, http.StatusOK, b)
}

// ---- UPS (NUT) --------------------------------------------------------------

func (a *Api) handleUpsNut(w http.ResponseWriter, r *http.Request, _ *auth.Key, _ authSource) {
	ctx, cancel := context.WithTimeout(r.Context(), nutTimeout)
	defer cancel()
	writeJSON(w, http.StatusOK, getNut(ctx))
}
