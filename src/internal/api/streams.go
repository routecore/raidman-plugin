package api

import (
	"context"
	"errors"
	"log"
	"net"
	"net/http"
	"time"

	"github.com/gorilla/websocket"

	"github.com/routecore/raidman-plugin/src/internal/domain"
	"github.com/routecore/raidman-plugin/src/internal/service/array"
	"github.com/routecore/raidman-plugin/src/internal/service/auth"
	"github.com/routecore/raidman-plugin/src/internal/service/docker"
	"github.com/routecore/raidman-plugin/src/internal/service/vm"
)

func (a *Api) streamArrayStatus(ws *wsConn, _ *http.Request, _ *auth.Key) {
	ws.drain()

	// Polled once per second (the broadcast is rate limited to that anyway).
	// No inotify watcher per connection: each one is an inotify instance,
	// and root's instance limit (128 by default) is shared with Unraid's
	// own daemons.
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	var prevStatus *domain.ArrayStatus
	var lastUpdate, lastBroadcast time.Time

	broadcast := func() bool {
		// Debounce: at most one broadcast per second.
		if time.Since(lastBroadcast) < 900*time.Millisecond {
			return true
		}
		status, err := array.GetArrayStatus()
		if err != nil {
			log.Printf("Error getting array status: %v", err)
			return true
		}
		now := time.Now()
		if prevStatus != nil {
			if delta := now.Sub(lastUpdate).Seconds(); delta > 0 {
				array.CalculateSpeeds(status, prevStatus, delta)
			}
		}
		prevStatus, lastUpdate, lastBroadcast = status, now, now

		return ws.WriteJSON(arrayStatusMessage(status)) == nil
	}

	if !broadcast() {
		return
	}
	for {
		select {
		case <-ws.ctx.Done():
			return
		case <-ticker.C:
			if !broadcast() {
				return
			}
		}
	}
}

// arrayStatusMessage is one array-status socket message: {"array": {...}}
// plus an optional top-level "health" (var.ini health: resync action,
// disabled/unmountable disks, mover, safe mode) that older plugins omit.
func arrayStatusMessage(status *domain.ArrayStatus) map[string]any {
	msg := map[string]any{
		"array": map[string]any{
			"state":             status.State,
			"parityCheckStatus": status.ParityCheckStatus,
			"parities":          status.Parities,
			"disks":             status.Disks,
			"caches":            status.Caches,
			"boot":              status.Boot,
			"bootDevices":       status.BootDevices,
			"unassigned":        status.Unassigned,
		},
	}
	if status.Health != nil {
		msg["health"] = status.Health
	}
	return msg
}

func (a *Api) streamDockerStats(ws *wsConn, r *http.Request, _ *auth.Key) {
	ws.drain()

	containerID := ""
	if raw := r.URL.Query().Get("container"); raw != "" {
		id, err := normalizeContainerRef(raw)
		if err != nil {
			_ = ws.WriteText("Error: " + err.Error())
			ws.closeWith(websocket.CloseNormalClosure, err.Error())
			return
		}
		containerID = id
	}

	// All sockets share one sampler (one stats stream per container, not
	// one per socket); this loop only reads its latest samples.
	sub, err := docker.SubscribeStats()
	if err != nil {
		_ = ws.WriteText("Error: " + err.Error())
		ws.closeWith(websocket.CloseInternalServerErr, "docker stats unavailable")
		return
	}
	defer sub.Close()

	const interval = 2 * time.Second
	timer := time.NewTimer(0)
	defer timer.Stop()
	failures := 0
	sent := false
	fastUntil := time.Now().Add(3 * time.Second)
	for {
		select {
		case <-ws.ctx.Done():
			return
		case <-timer.C:
		}
		var (
			payload any
			ready   bool
			err     error
		)
		if containerID != "" {
			payload, ready, err = sub.One(ws.ctx, containerID)
		} else {
			payload, ready, err = sub.All()
		}
		switch {
		case ws.ctx.Err() != nil:
			return
		case errors.Is(err, docker.ErrNotFound):
			_ = ws.WriteText("Error: container not found")
			ws.closeWith(websocket.CloseNormalClosure, "container not found")
			return
		case errors.Is(err, context.DeadlineExceeded):
			// Slow docker daemon; not a failure, try again next tick.
			log.Printf("docker-stats: %v", err)
		case err != nil:
			failures++
			log.Printf("docker-stats: %v", err)
			if failures >= 5 {
				_ = ws.WriteText("Error: " + err.Error())
				ws.closeWith(websocket.CloseInternalServerErr, "docker stats unavailable")
				return
			}
		default:
			failures = 0
			if ready {
				if ws.WriteJSON(payload) != nil {
					return
				}
				sent = true
			}
		}
		// Poll quickly (for a few seconds at most) until the first samples
		// are in, then every interval.
		if !sent && err == nil && time.Now().Before(fastUntil) {
			timer.Reset(250 * time.Millisecond)
		} else {
			timer.Reset(interval)
		}
	}
}

// getVncPort is a variable for tests (never reaches libvirt there).
var getVncPort = vm.GetVncPort

func (a *Api) streamVNC(ws *wsConn, r *http.Request, _ *auth.Key) {
	// fail sends the error text, then a close frame (without it the client
	// sees 1006, an abnormal drop). Nothing reads the socket yet, so a
	// drain picks up the peer's close echo; it must not run once the
	// client -> VNC reader below has started.
	fail := func(msg, reason string) {
		_ = ws.WriteText(msg)
		ws.drain()
		ws.closeWith(websocket.CloseNormalClosure, reason)
	}
	ref := r.URL.Query().Get("vm")
	if err := validateVMRef(ref); err != nil {
		fail("Error: "+err.Error(), err.Error())
		return
	}

	port, err := getVncPort(ref)
	if err != nil {
		fail("Error finding VNC port: "+err.Error(), "VNC port not found")
		return
	}

	vncConn, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", port), 5*time.Second)
	if err != nil {
		fail("Error connecting to VNC: "+err.Error(), "VNC connection failed")
		return
	}
	defer vncConn.Close()
	go func() {
		<-ws.ctx.Done()
		_ = vncConn.Close()
	}()

	done := make(chan struct{}, 2)
	// client -> VNC
	go func() {
		defer func() { done <- struct{}{} }()
		for {
			_, msg, err := ws.ReadMessage()
			if err != nil {
				return
			}
			if _, err := vncConn.Write(msg); err != nil {
				return
			}
		}
	}()
	// VNC -> client. This is the only data writer on the socket; each write
	// sets its own deadline (wsConn.WriteMessage).
	go func() {
		defer func() { done <- struct{}{} }()
		buf := make([]byte, 32*1024)
		for {
			n, err := vncConn.Read(buf)
			if n > 0 {
				if werr := ws.WriteMessage(websocket.BinaryMessage, buf[:n]); werr != nil {
					return
				}
			}
			if err != nil {
				return
			}
		}
	}()
	<-done
}
