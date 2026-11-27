package api

import (
	"context"
	"encoding/json"
	"log"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/gorilla/websocket"

	"github.com/routecore/raidman-plugin/src/internal/service/auth"
)

const (
	// Time allowed to read the next message (any frame, including pong).
	pongWait = 75 * time.Second
	// Time allowed to write a message to the peer.
	writeWait = 10 * time.Second
	// Send pings to peer with this period. Must be less than pongWait and
	// below nginx's proxy_read_timeout.
	pingPeriod = 30 * time.Second
	// How often open sockets re-check that their key is still valid.
	authRecheckPeriod = 5 * time.Second

	// Read limits. Interactive sockets must accept pastes / clipboard data.
	readLimitDefault = 64 * 1024
	readLimitVNC     = 4 * 1024 * 1024
)

// Open stream limits. Each stream holds a goroutine set and possibly a
// process (PTY) or a Docker/libvirt connection; a key cannot open unbounded
// numbers of them.
const (
	maxStreamsPerKey = 32
	maxStreamsTotal  = 256
)

// cookieUpgrader is used for cookie-authenticated upgrades (noVNC in a web
// view): the Origin must be this server (CSRF / cross-site WebSocket
// hijacking). authenticate() already refused cookies from other origins;
// this is the second line of defence.
var cookieUpgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool {
		if isSafeOrigin(r) {
			return true
		}
		log.Printf("[SECURITY] WS Blocked Origin %q from %q", truncate(r.Header.Get("Origin"), 128), truncate(clientIP(r), 64))
		return false
	},
}

// headerUpgrader is used when the key came in the x-api-key header or as the
// subprotocol. A cross-site page cannot set that header and does not know the
// key, so the request cannot be forged cross-site and the Origin (which native
// clients and reverse proxies set inconsistently) is not checked. No
// subprotocol is ever echoed back (Subprotocols is unset and Upgrade gets no
// response header), so the key never appears in a response.
var headerUpgrader = websocket.Upgrader{
	CheckOrigin: func(*http.Request) bool { return true },
}

func upgraderFor(src authSource) *websocket.Upgrader {
	if src == authHeader || src == authSubprotocol {
		return &headerUpgrader
	}
	return &cookieUpgrader
}

// streamLimiter caps open streams per key and in total.
type streamLimiter struct {
	mu     sync.Mutex
	perKey map[[32]byte]int
	total  int
}

func newStreamLimiter() *streamLimiter {
	return &streamLimiter{perKey: map[[32]byte]int{}}
}

// acquire reserves a stream slot for key h. release must be called once.
func (l *streamLimiter) acquire(h [32]byte) (release func(), ok bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.total >= maxStreamsTotal || l.perKey[h] >= maxStreamsPerKey {
		return nil, false
	}
	l.total++
	l.perKey[h]++
	var once sync.Once
	return func() {
		once.Do(func() {
			l.mu.Lock()
			defer l.mu.Unlock()
			l.total--
			if l.perKey[h]--; l.perKey[h] <= 0 {
				delete(l.perKey, h)
			}
		})
	}, true
}

// wsConn wraps a websocket with a per-connection context, serialised writes
// (each with a fresh deadline) and keepalive.
type wsConn struct {
	c      *websocket.Conn
	ctx    context.Context
	cancel context.CancelFunc
	wmu    sync.Mutex
	// remote is the client address for logs (X-Real-IP from nginx; the
	// socket peer is always nginx on loopback).
	remote string
}

func newWSConn(parent context.Context, c *websocket.Conn, readLimit int64, remote string) *wsConn {
	ctx, cancel := context.WithCancel(parent)
	w := &wsConn{c: c, ctx: ctx, cancel: cancel, remote: truncate(remote, 64)}
	c.SetReadLimit(readLimit)
	_ = c.SetReadDeadline(time.Now().Add(pongWait))
	c.SetPongHandler(func(string) error {
		return c.SetReadDeadline(time.Now().Add(pongWait))
	})
	c.SetPingHandler(func(message string) error {
		_ = c.SetReadDeadline(time.Now().Add(pongWait))
		err := c.WriteControl(websocket.PongMessage, []byte(message), time.Now().Add(writeWait))
		if err == websocket.ErrCloseSent {
			return nil
		}
		return err
	})
	// Closing the socket when the context ends unblocks any reader.
	go func() {
		<-ctx.Done()
		_ = c.Close()
	}()
	go w.pingLoop()
	return w
}

// Close ends the connection and its context.
func (w *wsConn) Close() {
	w.cancel()
}

// WriteMessage is safe for concurrent use; every write gets its own deadline.
func (w *wsConn) WriteMessage(mt int, data []byte) error {
	w.wmu.Lock()
	defer w.wmu.Unlock()
	_ = w.c.SetWriteDeadline(time.Now().Add(writeWait))
	err := w.c.WriteMessage(mt, data)
	if err != nil {
		w.cancel()
	}
	return err
}

func (w *wsConn) WriteJSON(v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	return w.WriteMessage(websocket.TextMessage, b)
}

func (w *wsConn) WriteText(s string) error {
	return w.WriteMessage(websocket.TextMessage, []byte(s))
}

// ReadMessage reads the next data message and refreshes the read deadline.
// Any error cancels the connection context.
func (w *wsConn) ReadMessage() (int, []byte, error) {
	mt, b, err := w.c.ReadMessage()
	if err != nil {
		w.cancel()
		return mt, b, err
	}
	_ = w.c.SetReadDeadline(time.Now().Add(pongWait))
	return mt, b, nil
}

// drain consumes (and discards) client messages on output-only streams so
// control frames are processed and a disconnect cancels the context.
func (w *wsConn) drain() {
	go func() {
		for {
			if _, _, err := w.c.NextReader(); err != nil {
				w.cancel()
				return
			}
			_ = w.c.SetReadDeadline(time.Now().Add(pongWait))
		}
	}()
}

// pingLoop only uses WriteControl, which gorilla allows concurrently with
// other writers, and never touches the shared write deadline.
func (w *wsConn) pingLoop() {
	t := time.NewTicker(pingPeriod)
	defer t.Stop()
	for {
		select {
		case <-w.ctx.Done():
			return
		case <-t.C:
			if err := w.c.WriteControl(websocket.PingMessage, nil, time.Now().Add(writeWait)); err != nil {
				log.Printf("Ping failed to %q: %v", w.remote, err)
				w.cancel()
				return
			}
		}
	}
}

// maxCloseReason is the largest close reason that fits a control frame
// (125-byte payload minus the 2-byte status code).
const maxCloseReason = 123

// closeGrace is how long closeWith waits for the peer to answer the close
// frame before dropping the connection.
const closeGrace = 2 * time.Second

// closeWith sends a close frame with a reason and ends the connection. The
// reason is truncated (on a UTF-8 boundary) to fit a control frame; a longer
// one would make gorilla refuse to send the close frame at all.
//
// It then waits (up to closeGrace) for the peer's closing frame, which the
// connection's reader turns into a cancelled context, so the TCP close does
// not race the close frame (closing with unread input pending can reset the
// connection and the peer may never see the frame). The caller must have a
// reader running on the connection (a stream's input loop or drain);
// without one the wait simply times out.
func (w *wsConn) closeWith(code int, reason string) {
	if len(reason) > maxCloseReason {
		cut := maxCloseReason
		for cut > 0 && !utf8.RuneStart(reason[cut]) {
			cut--
		}
		reason = reason[:cut]
	}
	err := w.c.WriteControl(websocket.CloseMessage, websocket.FormatCloseMessage(code, reason), time.Now().Add(writeWait))
	if err == nil {
		t := time.NewTimer(closeGrace)
		select {
		case <-w.ctx.Done():
		case <-t.C:
		}
		t.Stop()
	}
	w.cancel()
}

// watchAuth periodically re-validates the connection's key (deleted, rotated,
// de-permissioned or removed from the allowlist) and closes the socket when it
// no longer passes check.
func (w *wsConn) watchAuth(check func() error) {
	t := time.NewTicker(authRecheckPeriod)
	defer t.Stop()
	for {
		select {
		case <-w.ctx.Done():
			return
		case <-t.C:
			if err := check(); err != nil {
				log.Printf("[SECURITY] Closing session from %q: %v", w.remote, err)
				w.closeWith(websocket.ClosePolicyViolation, err.Error())
				return
			}
		}
	}
}

// wsRoute declares a /connect?type= stream.
type wsRoute struct {
	Req       Requirement
	ReadLimit int64
	Handle    func(a *Api, ws *wsConn, r *http.Request, k *auth.Key)
}

// isSafeOrigin reports whether a browser request comes from this server's own
// origin. Requests without Origin and Referer (native clients) pass.
//
// Scheme-less host comparison is not enough: cookies are not port-scoped, so
// a web UI on another port of the same host (e.g. a Docker container) would
// otherwise pass. The port is compared too. nginx forwards the Host the
// client used (with its port) as X-Forwarded-Host; without an explicit port
// the origin must use its scheme's default port. Loopback origins are only
// accepted when the server itself was reached on that loopback name.
func isSafeOrigin(r *http.Request) bool {
	origin := r.Header.Get("Origin")
	if origin == "" {
		origin = r.Header.Get("Referer")
	}
	if origin == "" {
		return true
	}

	u, err := url.Parse(origin)
	if err != nil || u.Host == "" {
		return false // includes Origin: null
	}
	scheme := strings.ToLower(u.Scheme)
	if scheme != "http" && scheme != "https" {
		return false
	}
	// A page loaded over plain HTTP must not drive a connection the client
	// made over HTTPS (an injected http:// page on the same host would
	// otherwise ride the Secure cookie). Only the client-proto signals that
	// can tighten this are used, so a spoofed header cannot loosen it.
	if scheme == "http" && clientUsedHTTPS(r) {
		return false
	}
	originPort := u.Port()
	if originPort == "" {
		originPort = defaultPort(scheme)
	}

	reqHost := r.Header.Get("X-Forwarded-Host")
	if i := strings.IndexByte(reqHost, ','); i >= 0 {
		reqHost = reqHost[:i]
	}
	reqHost = strings.TrimSpace(reqHost)
	if reqHost == "" {
		reqHost = r.Host
	}
	host, port := splitHostPortLoose(reqHost)
	if host == "" || !strings.EqualFold(u.Hostname(), host) {
		return false
	}
	if port == "" {
		return originPort == defaultPort(scheme)
	}
	return originPort == port
}

// clientUsedHTTPS reports whether the browser used HTTPS for the hop closest
// to it. raidman.conf passes the X-Forwarded-Proto a proxy or tunnel in front
// of nginx sent as X-Raidman-Client-Proto; when present it alone decides (an
// http:// proxy in front of an https:// Unraid is a plain-HTTP client). Only
// without it does nginx's own scheme (X-Forwarded-Proto, or TLS) count. A
// browser page cannot set these headers on a WebSocket upgrade or a
// sub-resource load, so a cross-site page cannot loosen the check.
func clientUsedHTTPS(r *http.Request) bool {
	if p := strings.TrimSpace(r.Header.Get("X-Raidman-Client-Proto")); p != "" {
		if i := strings.IndexByte(p, ','); i >= 0 {
			p = strings.TrimSpace(p[:i]) // first proxy in a chain
		}
		return strings.EqualFold(p, "https")
	}
	return r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https"
}

func defaultPort(scheme string) string {
	if scheme == "https" {
		return "443"
	}
	return "80"
}

// splitHostPortLoose splits "host", "host:port", "[v6]" or "[v6]:port".
func splitHostPortLoose(hp string) (host, port string) {
	if h, p, err := net.SplitHostPort(hp); err == nil {
		return h, p
	}
	return strings.TrimSuffix(strings.TrimPrefix(hp, "["), "]"), ""
}
