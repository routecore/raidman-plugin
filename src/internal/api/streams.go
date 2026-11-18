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

		wrapper := map[string]any{
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
		return ws.WriteJSON(wrapper) == nil
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

func (a *Api) streamDockerStats(ws *wsConn, r *http.Request, _ *auth.Key) {
	ws.drain()

	containerID := ""
	if raw := r.URL.Query().Get("container"); raw != "" {
		id, err := normalizeContainerRef(raw)
		if err != nil {
			_ = ws.WriteText("Error: " + err.Error())
			return
		}
		containerID = id
	}

	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	failures := 0
	for {
		stats, err := docker.GetContainerStats(ws.ctx, containerID)
		switch {
		case ws.ctx.Err() != nil:
			return
		case errors.Is(err, docker.ErrNotFound):
			_ = ws.WriteText("Error: container not found")
			ws.closeWith(websocket.CloseNormalClosure, "container not found")
			return
		case errors.Is(err, context.DeadlineExceeded):
			// Slow sample (busy daemon); not a failure, try again next tick.
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
			var payload any = stats
			if containerID != "" {
				if len(stats) == 0 {
					break
				}
				payload = stats[0]
			}
			if ws.WriteJSON(payload) != nil {
				return
			}
		}
		select {
		case <-ws.ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func (a *Api) streamVNC(ws *wsConn, r *http.Request, _ *auth.Key) {
	ref := r.URL.Query().Get("vm")
	if err := validateVMRef(ref); err != nil {
		_ = ws.WriteText("Error: " + err.Error())
		return
	}

	port, err := vm.GetVncPort(ref)
	if err != nil {
		_ = ws.WriteText("Error finding VNC port: " + err.Error())
		return
	}

	vncConn, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", port), 5*time.Second)
	if err != nil {
		_ = ws.WriteText("Error connecting to VNC: " + err.Error())
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
