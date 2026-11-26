package service

import (
	"context"
	"log"
	"mime"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/routecore/raidman-plugin/src/internal/api"
	"github.com/routecore/raidman-plugin/src/internal/domain"
	"github.com/routecore/raidman-plugin/src/internal/monitor"
	"github.com/routecore/raidman-plugin/src/internal/service/array"
	"github.com/routecore/raidman-plugin/src/internal/service/auth"
	"github.com/routecore/raidman-plugin/src/internal/service/config"
)

type Orchestrator struct {
	ctx *domain.Context
}

func CreateOrchestrator(ctx *domain.Context) *Orchestrator {
	return &Orchestrator{
		ctx: ctx,
	}
}

func (o *Orchestrator) Run() error {
	log.Printf("Starting Raidman Plugin (Version: %s)...", o.ctx.Config.Version)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Settings first: the key allowlist depends on them.
	config.LoadSettings()
	config.WatchSettings()

	// API keys from the upstream key store. The watcher also handles the
	// directory being created after startup (first key ever created).
	keys := auth.NewStore(auth.DefaultKeysPath, config.AllowPolicy)
	keys.Reload()
	go keys.Watch(ctx)

	mime.AddExtensionType(".css", "text/css")
	mime.AddExtensionType(".js", "application/javascript")
	mime.AddExtensionType(".mjs", "application/javascript")
	mime.AddExtensionType(".html", "text/html")
	mime.AddExtensionType(".svg", "image/svg+xml")
	mime.AddExtensionType(".json", "application/json")
	mime.AddExtensionType(".wasm", "application/wasm")

	// Parity history and pause stamps, which Unraid only keeps while a
	// browser has the webGUI open (see array/parity_log.go).
	go array.DefaultParityLogger.Run(ctx, 5*time.Second)

	server := api.Create(o.ctx, keys)
	serverErr := make(chan error, 1)
	go func() {
		serverErr <- server.Run()
	}()

	nginxMonitor, err := monitor.NewNginxMonitor()
	if err != nil {
		log.Printf("Failed to create Nginx Monitor: %v", err)
	} else {
		log.Println("Starting Nginx Configuration Monitor...")
		nginxMonitor.Start()
	}

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGTERM, syscall.SIGINT)
	select {
	case s := <-sig:
		log.Printf("Received %s signal. Shutting down...", s)
	case err := <-serverErr:
		if err != nil {
			return err
		}
	}

	shutdownCtx, done := context.WithTimeout(context.Background(), 5*time.Second)
	defer done()
	if err := server.Shutdown(shutdownCtx); err != nil {
		log.Printf("Shutdown: %v", err)
	}
	return nil
}
