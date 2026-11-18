package api

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"syscall"
	"time"

	"github.com/routecore/raidman-plugin/src/internal/domain"
	"github.com/routecore/raidman-plugin/src/internal/service/auth"
	"github.com/routecore/raidman-plugin/src/internal/service/config"
)

const novncPath = "/usr/local/emhttp/plugins/raidman/web/novnc"

type Api struct {
	ctx      *domain.Context
	keys     *auth.Store
	sessions *sessionStore
	streams  *streamLimiter
	novnc    http.Handler

	// hostTerminalEnabled reads the settings toggle (injectable for tests).
	hostTerminalEnabled func() bool

	baseCtx    context.Context
	cancelBase context.CancelFunc
	server     *http.Server
}

// Create builds the API server around a key store.
func Create(ctx *domain.Context, keys *auth.Store) *Api {
	base, cancel := context.WithCancel(context.Background())
	if _, err := os.Stat(novncPath); err != nil {
		log.Printf("WARNING: noVNC directory not found at %s", novncPath)
	} else {
		log.Printf("Serving noVNC from: %s", novncPath)
	}
	return &Api{
		ctx:                 ctx,
		keys:                keys,
		sessions:            newSessionStore(),
		streams:             newStreamLimiter(),
		novnc:               http.StripPrefix("/novnc/", http.FileServer(http.Dir(novncPath))),
		hostTerminalEnabled: func() bool { return config.GetSettings().HostTerminalEnabled },
		baseCtx:             base,
		cancelBase:          cancel,
	}
}

// Handler returns the complete HTTP handler (route table behind the
// authorization wrapper, with the /raidman prefix stripped).
func (a *Api) Handler() (http.Handler, error) {
	mux := http.NewServeMux()
	if err := a.register(mux, a.routes()); err != nil {
		return nil, err
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/raidman") {
			r.URL.Path = strings.TrimPrefix(r.URL.Path, "/raidman")
			if r.URL.Path == "" {
				r.URL.Path = "/"
			}
		}
		mux.ServeHTTP(w, r)
	}), nil
}

// Run listens and serves until Shutdown. If the port is still held (e.g. the
// previous daemon is exiting during an upgrade) it retries for a while
// instead of failing immediately.
func (a *Api) Run() error {
	handler, err := a.Handler()
	if err != nil {
		return err
	}
	addr := net.JoinHostPort(a.ctx.Config.Host, a.ctx.Config.Port)

	var ln net.Listener
	for attempt := 1; ; attempt++ {
		ln, err = net.Listen("tcp", addr)
		if err == nil {
			break
		}
		if !errors.Is(err, syscall.EADDRINUSE) || attempt >= 30 {
			return fmt.Errorf("listen %s: %w", addr, err)
		}
		log.Printf("Address %s in use, retrying (%d/30)...", addr, attempt)
		select {
		case <-a.baseCtx.Done():
			return a.baseCtx.Err()
		case <-time.After(time.Second):
		}
	}
	log.Printf("Listening on %s", addr)

	a.server = &http.Server{
		Handler:           handler,
		ReadHeaderTimeout: 15 * time.Second,
		// No ReadTimeout: it would cancel the request context of long
		// emhttpd commands (spin-up waits for every disk). Bodies are
		// bounded by MaxBytesReader and nginx buffers them anyway.
		IdleTimeout: 2 * time.Minute,
		BaseContext: func(net.Listener) context.Context { return a.baseCtx },
	}
	err = a.server.Serve(ln)
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

// Shutdown stops accepting requests, closes open streams and waits briefly
// for in-flight requests.
func (a *Api) Shutdown(ctx context.Context) error {
	a.cancelBase()
	if a.server == nil {
		return nil
	}
	return a.server.Shutdown(ctx)
}
