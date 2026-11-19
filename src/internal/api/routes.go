package api

import (
	"fmt"
	"log"
	"net/http"
	"strings"

	"github.com/routecore/raidman-plugin/src/internal/service/auth"
)

type keyHandler func(w http.ResponseWriter, r *http.Request, k *auth.Key, src authSource)

// route is one HTTP endpoint. Every route must declare a Requirement; the
// zero value is rejected at registration (deny by default).
type route struct {
	Path string
	// Methods allowed after authorization; nil keeps the protocol-1
	// behaviour of accepting any method. Checked after auth so an
	// unauthenticated caller always gets 401.
	Methods []string
	Req     Requirement
	Handler keyHandler
	// Prefix registers Path as a subtree ("/novnc/").
	Prefix bool
	// Preflight handles CORS OPTIONS before authentication.
	Preflight bool
	// V2 marks a protocol-2 route: every error, including 401/403/405, is
	// JSON { "error": "..." }. Protocol-1 routes keep plain-text errors.
	V2 bool
	// CookieAuth reports whether this request may authenticate with a
	// cookie (the app's x-api-key cookie or the raidman_session cookie).
	// nil means header only. Cookies exist solely for the VNC web view, so
	// only noVNC assets and the vm-vnc stream accept them; everything else
	// (host terminal, power, docker exec, ...) needs the x-api-key header,
	// which a cross-site page cannot set (CSRF).
	CookieAuth func(r *http.Request) bool
}

// maxBodyBytes bounds every request body (all requests are small JSON).
const maxBodyBytes = 1 << 20

func cookieAlways(*http.Request) bool { return true }

func cookieForVNCStream(r *http.Request) bool {
	t := r.URL.Query()["type"]
	return len(t) == 1 && t[0] == "vm-vnc"
}

func (rt route) errorWriter() errorWriter {
	if rt.V2 {
		return writeJSONError
	}
	return textError
}

// routes is the HTTP route table (contract §4). Paths are relative to the
// /raidman prefix that nginx strips.
func (a *Api) routes() []route {
	post := []string{http.MethodPost}
	get := []string{http.MethodGet, http.MethodHead}
	return []route{
		// VMs
		{Path: "/api/vm/info", Req: Perm(auth.ResourceVMs, auth.ActionReadAny), Handler: a.handleVmInfo},
		{Path: "/api/vms", Req: Perm(auth.ResourceVMs, auth.ActionReadAny), Handler: a.handleGetVms},
		{Path: "/api/vm/autostart", Methods: post, Req: Perm(auth.ResourceVMs, auth.ActionUpdateAny), Handler: a.handleVmAutostart},
		{Path: "/api/vm/action", Methods: post, Req: Perm(auth.ResourceVMs, auth.ActionUpdateAny), Handler: a.handleVmAction},
		{Path: "/api/vm/icon", Req: AnyKey(), Handler: a.handleVmIcon},

		// Array
		{Path: "/api/array/status", Req: Perm(auth.ResourceArray, auth.ActionReadAny), Handler: a.handleArrayStatus},
		{Path: "/api/array/history", Req: Perm(auth.ResourceArray, auth.ActionReadAny), Handler: a.handleGetParityHistory},
		{Path: "/api/array/action", Methods: post, Req: Perm(auth.ResourceArray, auth.ActionUpdateAny), Handler: a.handleArrayAction},

		// Docker
		{Path: "/api/docker/containers", Req: Perm(auth.ResourceDocker, auth.ActionReadAny), Handler: a.handleGetContainers},
		{Path: "/api/docker/action", Methods: post, Req: Perm(auth.ResourceDocker, auth.ActionUpdateAny), Handler: a.handleContainerAction},

		// System (protocol-1 shape; shutdown/reboot now take Unraid's clean path)
		{Path: "/api/system/action", Methods: post, Req: AdminOnly(), Handler: a.handleSystemAction},

		// ---- Protocol 2 (contract §4 "New routes"); JSON errors ----
		{Path: "/api/health", Methods: get, Req: AnyKey(), Handler: a.handleHealth, V2: true},
		{Path: "/api/docker/updates", Methods: get, Req: Perm(auth.ResourceDocker, auth.ActionReadAny), Handler: a.handleDockerUpdates, V2: true},
		{Path: "/api/docker/updates/check", Methods: post, Req: Perm(auth.ResourceDocker, auth.ActionUpdateAny), Handler: a.handleDockerUpdateCheck, V2: true},
		{Path: "/api/docker/meta", Methods: get, Req: Perm(auth.ResourceDocker, auth.ActionReadAny), Handler: a.handleDockerMeta, V2: true},
		{Path: "/api/disks/state", Methods: get, Req: Perm(auth.ResourceArray, auth.ActionReadAny), Handler: a.handleDisksState, V2: true},
		{Path: "/api/disks/spin", Methods: post, Req: Perm(auth.ResourceArray, auth.ActionUpdateAny), Handler: a.handleDisksSpin, V2: true},
		{Path: "/api/mover/status", Methods: get, Req: Perm(auth.ResourceArray, auth.ActionReadAny), Handler: a.handleMoverStatus, V2: true},
		{Path: "/api/mover/action", Methods: post, Req: Perm(auth.ResourceArray, auth.ActionUpdateAny), Handler: a.handleMoverAction, V2: true},
		{Path: "/api/parity/action", Methods: post, Req: Perm(auth.ResourceArray, auth.ActionUpdateAny), Handler: a.handleParityAction, V2: true},

		// Feature wave (plugins.list, plugins.ops, disks.smart, files, mem.breakdown, ups.nut)
		{Path: "/api/plugins", Methods: get, Req: Perm(auth.ResourceConfig, auth.ActionReadAny), Handler: a.handlePluginsList, V2: true},
		{Path: "/api/plugins/check", Methods: post, Req: Perm(auth.ResourceConfig, auth.ActionUpdateAny), Handler: a.handlePluginsCheck, V2: true},
		{Path: "/api/plugins/update", Methods: post, Req: Perm(auth.ResourceConfig, auth.ActionUpdateAny), Handler: a.handlePluginUpdate, V2: true},
		{Path: "/api/plugins/remove", Methods: post, Req: AdminOnly(), Handler: a.handlePluginRemove, V2: true},
		{Path: "/api/disks/smart", Methods: get, Req: Perm(auth.ResourceArray, auth.ActionReadAny), Handler: a.handleDiskSmart, V2: true},
		{Path: "/api/files/list", Methods: get, Req: AdminOnly(), Handler: a.handleFilesList, V2: true},
		{Path: "/api/files/download", Methods: get, Req: AdminOnly(), Handler: a.handleFilesDownload, V2: true},
		{Path: "/api/system/memory", Methods: get, Req: Perm(auth.ResourceInfo, auth.ActionReadAny), Handler: a.handleSystemMemory, V2: true},
		{Path: "/api/ups/nut", Methods: get, Req: Perm(auth.ResourceConfig, auth.ActionReadAny), Handler: a.handleUpsNut, V2: true},

		// WebSocket streams: authentication here, per-type authorization in
		// handleConnect against wsRoutes().
		{Path: "/connect", Req: AnyKey(), Handler: a.handleConnect, CookieAuth: cookieForVNCStream},

		// noVNC static assets
		{Path: "/novnc/", Prefix: true, Preflight: true, Req: AnyKey(), Handler: a.handleNoVNC, CookieAuth: cookieAlways},
	}
}

// wsRoutes is the /connect?type= table (contract §4).
func (a *Api) wsRoutes() map[string]wsRoute {
	return map[string]wsRoute{
		"array-status": {Req: Perm(auth.ResourceArray, auth.ActionReadAny), ReadLimit: readLimitDefault, Handle: (*Api).streamArrayStatus},
		"docker-stats": {Req: Perm(auth.ResourceDocker, auth.ActionReadAny), ReadLimit: readLimitDefault, Handle: (*Api).streamDockerStats},
		"docker-log":   {Req: Perm(auth.ResourceDocker, auth.ActionReadAny), ReadLimit: readLimitDefault, Handle: ptyStream("docker-log")},
		"docker":       {Req: Perm(auth.ResourceDocker, auth.ActionUpdateAny), ReadLimit: readLimitDefault, Handle: ptyStream("docker")},
		"vm-log":       {Req: Perm(auth.ResourceVMs, auth.ActionReadAny), ReadLimit: readLimitDefault, Handle: ptyStream("vm-log")},
		"vm":           {Req: Perm(auth.ResourceVMs, auth.ActionUpdateAny), ReadLimit: readLimitDefault, Handle: ptyStream("vm")},
		"vm-vnc":       {Req: Perm(auth.ResourceVMs, auth.ActionUpdateAny), ReadLimit: readLimitVNC, Handle: (*Api).streamVNC},
		"host":         {Req: AdminOnly(), ReadLimit: readLimitDefault, Handle: ptyStream("host")},
	}
}

// register adds every route to mux behind the authorization wrapper.
// It returns an error if any route lacks a requirement or a handler.
func (a *Api) register(mux *http.ServeMux, routes []route) error {
	for _, rt := range routes {
		if !rt.Req.Valid() {
			return fmt.Errorf("route %s has no valid requirement", rt.Path)
		}
		if rt.Handler == nil {
			return fmt.Errorf("route %s has no handler", rt.Path)
		}
		if rt.Prefix != strings.HasSuffix(rt.Path, "/") {
			return fmt.Errorf("route %s: prefix routes must end in '/' and exact routes must not", rt.Path)
		}
		mux.Handle(rt.Path, a.wrap(rt))
	}
	for typ, wr := range a.wsRoutes() {
		if !wr.Req.Valid() || wr.Handle == nil || wr.ReadLimit < readLimitDefault {
			return fmt.Errorf("websocket type %s is not fully declared", typ)
		}
	}
	// Anything else is 404 (no implicit routes).
	mux.HandleFunc("/", http.NotFound)
	return nil
}

func (a *Api) wrap(rt route) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if rt.Preflight {
			w.Header().Set("Access-Control-Allow-Origin", "*")
			w.Header().Set("Access-Control-Allow-Methods", "GET, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "*")
			if r.Method == http.MethodOptions {
				return
			}
		}
		if r.Body != nil {
			r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)
		}
		errf := rt.errorWriter()
		allowCookie := rt.CookieAuth != nil && rt.CookieAuth(r)
		k, src := a.authorize(w, r, rt.Req, allowCookie, errf)
		if k == nil {
			return
		}
		if rt.Methods != nil && !containsStr(rt.Methods, r.Method) {
			w.Header().Set("Allow", strings.Join(rt.Methods, ", "))
			errf(w, http.StatusMethodNotAllowed, "Method not allowed")
			return
		}
		rt.Handler(w, r, k, src)
	})
}

// handleConnect upgrades /connect?type=... after per-type authorization.
// Order is part of protocol 1 (old apps probe with it): invalid key -> 401
// (done by the wrapper), unknown type -> 400, insufficient permission -> 403.
func (a *Api) handleConnect(w http.ResponseWriter, r *http.Request, k *auth.Key, src authSource) {
	connType := r.URL.Query().Get("type")
	wr, ok := a.wsRoutes()[connType]
	if !ok {
		http.Error(w, "Unknown connection type", http.StatusBadRequest)
		return
	}
	if !wr.Req.Allows(k) {
		if securityLog.allow("denied-stream:" + k.ID + ":" + connType) {
			log.Printf("[SECURITY] Key %s denied stream %q (requires %s)", k.Label(), connType, wr.Req)
		}
		http.Error(w, fmt.Sprintf("Permission denied: requires %s", wr.Req), http.StatusForbidden)
		return
	}

	release, ok := a.streams.acquire(k.Hash())
	if !ok {
		if securityLog.allow("streams:" + k.ID) {
			log.Printf("[SECURITY] Key %s exceeded the open stream limit (%s)", k.Label(), connType)
		}
		http.Error(w, "Too many open connections", http.StatusTooManyRequests)
		return
	}
	defer release()

	c, err := upgraderFor(src).Upgrade(w, r, nil)
	if err != nil {
		log.Print("upgrade:", err)
		return
	}
	ws := newWSConn(a.baseCtx, c, wr.ReadLimit)
	defer ws.Close()

	hash := k.Hash()
	go ws.watchAuth(func() error {
		cur, err := a.keys.ByHash(hash)
		if err != nil {
			return err
		}
		if !wr.Req.Allows(cur) {
			return fmt.Errorf("key %s no longer has %s", cur.Label(), wr.Req)
		}
		if connType == "host" && !a.hostTerminalEnabled() {
			return fmt.Errorf("host terminal disabled by administrator")
		}
		return nil
	})

	wr.Handle(a, ws, r, k)
}

func containsStr(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}
