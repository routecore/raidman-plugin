package api

import (
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/routecore/raidman-plugin/src/internal/service/auth"
)

type reqKind int

const (
	reqInvalid reqKind = iota // zero value: a route without a declared requirement
	reqAnyKey
	reqPermission
	reqAdmin
)

// Requirement is what a route demands from the presented API key. The zero
// value is invalid, so a route that forgets to declare one cannot be
// registered (deny by default).
type Requirement struct {
	kind     reqKind
	Resource string
	Action   string
}

// AnyKey accepts any valid (and allowlisted) key.
func AnyKey() Requirement { return Requirement{kind: reqAnyKey} }

// Perm requires an upstream permission, e.g. Perm(auth.ResourceDocker, auth.ActionReadAny).
func Perm(resource, action string) Requirement {
	return Requirement{kind: reqPermission, Resource: resource, Action: action}
}

// AdminOnly requires the ADMIN role.
func AdminOnly() Requirement { return Requirement{kind: reqAdmin} }

// Valid reports whether the requirement was declared.
func (q Requirement) Valid() bool {
	switch q.kind {
	case reqAnyKey, reqAdmin:
		return true
	case reqPermission:
		return q.Resource != "" && q.Action != ""
	}
	return false
}

// Allows reports whether key k satisfies the requirement.
func (q Requirement) Allows(k *auth.Key) bool {
	if k == nil {
		return false
	}
	switch q.kind {
	case reqAnyKey:
		return true
	case reqPermission:
		return k.Has(q.Resource, q.Action)
	case reqAdmin:
		return k.IsAdmin()
	}
	return false
}

func (q Requirement) String() string {
	switch q.kind {
	case reqAnyKey:
		return "any valid key"
	case reqPermission:
		return q.Resource + ":" + q.Action
	case reqAdmin:
		return "ADMIN"
	}
	return "invalid"
}

// authSource tells how a request was authenticated.
type authSource int

const (
	authNone authSource = iota
	authHeader
	authKeyCookie
	authSession
)

var errNoCredentials = errors.New("missing API key")

// authenticate resolves the request's credentials to a key.
//
// Order: x-api-key header (CSRF-safe), then - only where allowCookie is set
// (noVNC assets and the vm-vnc stream) - the x-api-key cookie set by the
// app's VNC web view, then the plugin's opaque raidman_session cookie. Cookies
// are only honoured from a same-origin Origin/Referer (CSRF protection).
// Session ids map server-side to the key's hash and are re-resolved on every
// request, so a revoked or rotated key invalidates its sessions immediately.
func (a *Api) authenticate(r *http.Request, allowCookie bool) (*auth.Key, authSource, error) {
	if v := r.Header.Get("x-api-key"); v != "" {
		k, err := a.keys.Authenticate(v)
		return k, authHeader, err
	}
	if !allowCookie {
		return nil, authNone, errNoCredentials
	}
	keyCookie, _ := r.Cookie("x-api-key")
	sessCookie, _ := r.Cookie(sessionCookieName)
	if keyCookie == nil && sessCookie == nil {
		return nil, authNone, errNoCredentials
	}
	if !isSafeOrigin(r) {
		// Keyed by client address, never by the (attacker-chosen) Origin.
		if securityLog.allow("origin:" + clientIP(r)) {
			log.Printf("[SECURITY] Ignoring auth cookies from untrusted origin %q (%s)", truncate(r.Header.Get("Origin"), 128), clientIP(r))
		}
		return nil, authNone, errNoCredentials
	}
	if keyCookie != nil && keyCookie.Value != "" {
		k, err := a.keys.Authenticate(keyCookie.Value)
		return k, authKeyCookie, err
	}
	if sessCookie != nil && sessCookie.Value != "" {
		h, ok := a.sessions.resolve(sessCookie.Value)
		if !ok {
			return nil, authSession, auth.ErrUnknownKey
		}
		k, err := a.keys.ByHash(h)
		return k, authSession, err
	}
	return nil, authNone, errNoCredentials
}

// authorize authenticates r and checks req. On failure it writes 401 (no or
// invalid key) or 403 (valid key, insufficient permission) and returns nil.
//
// errf writes the error body: plain text for protocol-1 routes, the
// protocol-2 JSON shape { "error": "..." } for new routes.
func (a *Api) authorize(w http.ResponseWriter, r *http.Request, req Requirement, allowCookie bool, errf errorWriter) (*auth.Key, authSource) {
	if errf == nil {
		errf = textError
	}
	if !req.Valid() {
		// Should be impossible: register() refuses such routes.
		errf(w, http.StatusForbidden, "Forbidden")
		return nil, authNone
	}
	k, src, err := a.authenticate(r, allowCookie)
	if err != nil {
		if errors.Is(err, auth.ErrKeyNotAllowed) {
			if securityLog.allow("allowlist:" + k.Label()) {
				log.Printf("[SECURITY] Key %s rejected by RaidMan allowlist (%s %s)", k.Label(), r.Method, logPath(r))
			}
		} else if !errors.Is(err, errNoCredentials) {
			if securityLog.allow("invalid:" + clientIP(r)) {
				log.Printf("[SECURITY] Invalid API key from %q (%s %s)", truncate(clientIP(r), 64), r.Method, logPath(r))
			}
		}
		errf(w, http.StatusUnauthorized, "Unauthorized")
		return nil, authNone
	}
	if !req.Allows(k) {
		if securityLog.allow("denied:" + k.ID + ":" + r.URL.Path) {
			log.Printf("[SECURITY] Key %s denied %s %s (requires %s)", k.Label(), r.Method, logPath(r), req)
		}
		errf(w, http.StatusForbidden, fmt.Sprintf("Permission denied: requires %s", req))
		return nil, authNone
	}
	return k, src
}

// errorWriter writes an error response with the given status.
type errorWriter func(w http.ResponseWriter, status int, msg string)

// textError is the protocol-1 error body (plain text).
func textError(w http.ResponseWriter, status int, msg string) { http.Error(w, msg, status) }

// clientIP is the address nginx reports (X-Real-IP), else the socket peer.
func clientIP(r *http.Request) string {
	if ip := r.Header.Get("X-Real-IP"); ip != "" {
		return ip
	}
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		return host
	}
	return r.RemoteAddr
}

// logLimiter suppresses repeats of the same security log line so a client
// retrying with a bad key cannot fill /var/log (a small tmpfs on Unraid).
type logLimiter struct {
	mu     sync.Mutex
	last   map[string]time.Time
	window time.Duration
}

var securityLog = &logLimiter{last: map[string]time.Time{}, window: time.Minute}

// logLimiterMax bounds the limiter's memory. Keys include client addresses,
// key labels and request paths; when the map is full of live entries, new
// lines are dropped rather than growing the map (or the tmpfs log).
const logLimiterMax = 1024

func (l *logLimiter) allow(key string) bool {
	key = truncate(key, 256)
	now := time.Now()
	l.mu.Lock()
	defer l.mu.Unlock()
	if t, ok := l.last[key]; ok && now.Sub(t) < l.window {
		return false
	}
	if len(l.last) >= logLimiterMax {
		for k, t := range l.last {
			if now.Sub(t) >= l.window {
				delete(l.last, k)
			}
		}
		if len(l.last) >= logLimiterMax {
			return false
		}
	}
	l.last[key] = now
	return true
}

// logPathMax bounds how much of a request path is written to the log.
const logPathMax = 200

// logPath is the request path for a log line: quoted (so a decoded %0A in an
// attacker-chosen path under a prefix route cannot start a forged line) and
// truncated (so one request cannot write kilobytes).
func logPath(r *http.Request) string {
	return fmt.Sprintf("%q", truncate(r.URL.Path, logPathMax))
}

// truncate shortens s to at most n bytes (for logs and map keys).
func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
