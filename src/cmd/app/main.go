package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"strconv"

	"github.com/routecore/raidman-plugin/src/internal/domain"
	"github.com/routecore/raidman-plugin/src/internal/service"
)

// Version is overridden at build time: -ldflags "-X main.Version=<tag>".
var Version = "2026.11.18"

func main() {
	port := flag.String("port", "9876", "Port to listen on")
	host := flag.String("host", "127.0.0.1", "Host to bind to (nginx proxies /raidman/ to it)")
	pidFile := flag.String("pidfile", "", "Write the daemon PID to this file")
	showVersion := flag.Bool("version", false, "Print the version and exit")
	flag.Parse()

	if *showVersion {
		fmt.Println(Version)
		return
	}

	if *pidFile != "" {
		if err := os.WriteFile(*pidFile, []byte(strconv.Itoa(os.Getpid())+"\n"), 0o644); err != nil {
			log.Printf("Could not write pid file %s: %v", *pidFile, err)
		} else {
			defer os.Remove(*pidFile)
		}
	}

	ctx := &domain.Context{
		Config: domain.Config{
			Version: Version,
			Host:    *host,
			Port:    *port,
		},
	}

	orchestrator := service.CreateOrchestrator(ctx)
	if err := orchestrator.Run(); err != nil {
		if *pidFile != "" {
			os.Remove(*pidFile)
		}
		log.Fatalf("Error running orchestrator: %v", err)
	}
}
