module github.com/routecore/raidman-plugin

go 1.26.0

require (
	github.com/containerd/errdefs v1.0.0
	github.com/creack/pty v1.1.24
	github.com/digitalocean/go-libvirt v0.0.0-20261013170128-efbbdf578ac8
	github.com/docker/go-units v0.5.0
	github.com/fsnotify/fsnotify v1.10.1
	github.com/gorilla/websocket v1.5.4-0.20250319132907-e064f32e3674 // upstream main: fixes GO-2026-6278 (no tagged release yet)
	github.com/moby/moby/api v1.57.0
	github.com/moby/moby/client v0.6.3
	golang.org/x/sys v0.41.0
	libvirt.org/go/libvirtxml v1.12008.0
)

require (
	github.com/Microsoft/go-winio v0.6.2 // indirect
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/containerd/errdefs/pkg v0.3.0 // indirect
	github.com/distribution/reference v0.6.0 // indirect
	github.com/docker/go-connections v0.8.2 // indirect
	github.com/felixge/httpsnoop v1.0.4 // indirect
	github.com/go-logr/logr v1.4.4 // indirect
	github.com/go-logr/stdr v1.2.2 // indirect
	github.com/moby/docker-image-spec v1.3.1 // indirect
	github.com/opencontainers/go-digest v1.0.0 // indirect
	github.com/opencontainers/image-spec v1.1.1 // indirect
	go.opentelemetry.io/auto/sdk v1.2.1 // indirect
	go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp v0.64.0 // indirect
	go.opentelemetry.io/otel v1.47.0 // indirect; security floor: GO-2026-5506, GO-2026-6974 (moby/client needs only 1.39)
	go.opentelemetry.io/otel/metric v1.47.0 // indirect; kept in step with otel (GO-2026-5506, GO-2026-6974)
	go.opentelemetry.io/otel/trace v1.47.0 // indirect; kept in step with otel (GO-2026-5506, GO-2026-6974)
	golang.org/x/crypto v0.48.0 // indirect
	golang.org/x/net v0.49.0 // indirect
)

require go.opentelemetry.io/otel/log v1.47.0 // indirect
