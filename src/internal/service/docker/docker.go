package docker

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	cerrdefs "github.com/containerd/errdefs"
	"github.com/moby/moby/client"
)

type ContainerStats struct {
	ID       string `json:"ID"`
	CPUPerc  string `json:"CPUPerc"`
	MemPerc  string `json:"MemPerc"`
	MemUsage string `json:"MemUsage"`
	// NetIO is "rx / tx" summed over all networks (docker stats format);
	// omitted when the container has no network stats (host/none mode).
	NetIO string `json:"NetIO,omitempty"`
	// BlockIO is "read / write" bytes (docker stats format).
	BlockIO string `json:"BlockIO,omitempty"`
}

type StatsJSON struct {
	ID          string                  `json:"id"`
	Name        string                  `json:"name"`
	CPUStats    CPUStats                `json:"cpu_stats"`
	PreCPUStats CPUStats                `json:"precpu_stats"`
	MemoryStats MemoryStats             `json:"memory_stats"`
	Networks    map[string]NetworkStats `json:"networks"`
	BlkioStats  BlkioStats              `json:"blkio_stats"`
}

type NetworkStats struct {
	RxBytes uint64 `json:"rx_bytes"`
	TxBytes uint64 `json:"tx_bytes"`
}

type BlkioStats struct {
	IoServiceBytesRecursive []BlkioEntry `json:"io_service_bytes_recursive"`
}

type BlkioEntry struct {
	Op    string `json:"op"`
	Value uint64 `json:"value"`
}

type CPUStats struct {
	CPUUsage    CPUUsage `json:"cpu_usage"`
	SystemUsage uint64   `json:"system_cpu_usage"`
	OnlineCPUs  uint32   `json:"online_cpus"`
}

type CPUUsage struct {
	TotalUsage  uint64   `json:"total_usage"`
	PercpuUsage []uint64 `json:"percpu_usage"`
}

type MemoryStats struct {
	Usage uint64            `json:"usage"`
	Limit uint64            `json:"limit"`
	Stats map[string]uint64 `json:"stats"`
}

// ErrNotFound is returned when a container does not exist.
var ErrNotFound = errors.New("container not found")

// ErrInvalidAction is returned for an unknown container action (HTTP 400).
var ErrInvalidAction = errors.New("invalid action")

// ErrWrongState is returned (wrapped, see stateError) when the container's
// state does not allow the action: pausing a paused container, unpausing a
// running one, killing or pausing a stopped one (HTTP 409).
var ErrWrongState = errors.New("container state does not allow this action")

// stateError is a wrong-state error with a short, fixed message: the
// daemon's own text carries the full container id ("container 29f44a...
// is already paused"), which clients should not have to show.
type stateError struct {
	msg   string
	cause error
}

func (e *stateError) Error() string   { return e.msg }
func (e *stateError) Unwrap() []error { return []error{ErrWrongState, e.cause} }

// stateMessages maps daemon wording (lower-cased) to the short message.
var stateMessages = []struct{ daemon, msg string }{
	{"already paused", "container is already paused"},
	{"is not paused", "container is not paused"},
	{"is paused", "container is paused"},
	{"is not running", "container is not running"},
	{"is restarting", "container is restarting"},
	{"marked for removal", "container is being removed"},
}

// daemonStateRe is the daemon's own wrong-state sentence ("container
// <64-hex id> is already paused"), recognised even when the error is not
// classified as a conflict.
var daemonStateRe = regexp.MustCompile(`(?i)\bcontainer [0-9a-f]{12,64} is (already paused|not paused|paused|not running|restarting)\b`)

// wrapState turns the daemon's wrong-state answers into a stateError. The
// daemon sends them as 409 Conflict (errdefs.Conflict); daemonStateRe is
// only a fallback for one that classifies them differently, narrow enough
// that a genuine failure is never reported as a state conflict.
func wrapState(err error) error {
	if err == nil || (!cerrdefs.IsConflict(err) && !daemonStateRe.MatchString(err.Error())) {
		return err
	}
	lower := strings.ToLower(err.Error())
	for _, m := range stateMessages {
		if strings.Contains(lower, m.daemon) {
			return &stateError{msg: m.msg, cause: err}
		}
	}
	return &stateError{msg: ErrWrongState.Error(), cause: err}
}

var (
	cliMu  sync.Mutex
	shared *client.Client
)

// getDockerClient returns a process-wide Docker client. The client is
// goroutine-safe and connects lazily, so one instance is reused for every
// request instead of building a new one per call.
func getDockerClient() (*client.Client, error) {
	cliMu.Lock()
	defer cliMu.Unlock()
	if shared != nil {
		return shared, nil
	}
	c, err := client.New(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		return nil, err
	}
	shared = c
	return c, nil
}

// rawInspect returns GET /containers/{id}/json exactly as the daemon sends it.
// The moby API types decode some fields strictly (network.Port, netip.Addr):
// one odd value, such as an image's "6881-6889/tcp" ExposedPorts key, would
// fail the whole typed inspect and drop the container. The raw document also
// keeps every field the daemon sends, as the old string-typed client did.
// The path is unversioned, so the daemon answers with its own API version.
func rawInspect(ctx context.Context, cli *client.Client, id string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://docker/containers/"+url.PathEscape(id)+"/json", nil)
	if err != nil {
		return nil, err
	}
	resp, err := rawHTTPClient(cli).Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxInspectBytes))
	if err != nil {
		return nil, err
	}
	switch {
	case resp.StatusCode == http.StatusNotFound:
		return nil, fmt.Errorf("%w: %s", ErrNotFound, id)
	case resp.StatusCode != http.StatusOK:
		return nil, fmt.Errorf("inspect %s: daemon answered %d", id, resp.StatusCode)
	case !json.Valid(body):
		return nil, fmt.Errorf("inspect %s: invalid JSON from the daemon", id)
	}
	return body, nil
}

// maxInspectBytes bounds one inspect document (normally a few KiB).
const maxInspectBytes = 8 << 20

var (
	rawMu     sync.Mutex
	rawFor    *client.Client
	rawClient *http.Client
)

// rawHTTPClient speaks HTTP over the Docker client's own connection (socket,
// TLS and custom transports as configured), one instance per Docker client.
func rawHTTPClient(cli *client.Client) *http.Client {
	rawMu.Lock()
	defer rawMu.Unlock()
	if rawFor != cli {
		dial := cli.Dialer()
		rawClient = &http.Client{Transport: &http.Transport{
			DialContext:     func(ctx context.Context, _, _ string) (net.Conn, error) { return dial(ctx) },
			MaxIdleConns:    inspectConcurrency,
			IdleConnTimeout: 30 * time.Second,
		}}
		rawFor = cli
	}
	return rawClient
}

func wrapNotFound(err error) error {
	if err != nil && cerrdefs.IsNotFound(err) {
		return fmt.Errorf("%w: %v", ErrNotFound, err)
	}
	return err
}

// ExecuteContainerAction runs a lifecycle action. containerID must already be
// normalised and validated by the caller.
func ExecuteContainerAction(ctx context.Context, containerID string, action string) error {
	cli, err := getDockerClient()
	if err != nil {
		return err
	}
	switch action {
	case "start":
		_, err = cli.ContainerStart(ctx, containerID, client.ContainerStartOptions{})
	case "stop":
		_, err = cli.ContainerStop(ctx, containerID, client.ContainerStopOptions{})
	case "restart":
		_, err = cli.ContainerRestart(ctx, containerID, client.ContainerRestartOptions{})
	case "kill":
		_, err = cli.ContainerKill(ctx, containerID, client.ContainerKillOptions{Signal: "KILL"})
	case "pause":
		_, err = cli.ContainerPause(ctx, containerID, client.ContainerPauseOptions{})
	case "unpause":
		_, err = cli.ContainerUnpause(ctx, containerID, client.ContainerUnpauseOptions{})
	default:
		return fmt.Errorf("%w: %s", ErrInvalidAction, action)
	}
	invalidateAll()
	if err != nil && !cerrdefs.IsNotFound(err) {
		return wrapState(err)
	}
	return wrapNotFound(err)
}

// ---- container list -------------------------------------------------------

const (
	inspectConcurrency = 6
	inspectTTL         = 30 * time.Second
)

type inspectEntry struct {
	state   string
	fetched time.Time
	data    []byte // marshalled inspect JSON; decoded fresh for every caller
}

var (
	cacheMu      sync.Mutex
	inspectCache = map[string]inspectEntry{}
)

func invalidateAll() {
	cacheMu.Lock()
	inspectCache = map[string]inspectEntry{}
	cacheMu.Unlock()
}

// ContainerOptions controls GetContainers.
type ContainerOptions struct {
	// Size asks Docker to compute SizeRw/SizeRootFs. Expensive (walks every
	// container's layers and may wake array disks), so off by default.
	Size bool
}

// GetContainers returns the inspect JSON of every container (the protocol-1
// shape the app parses) with "AutoStart" injected, and "SizeRw"/"SizeRootFs"
// when opts.Size is set. Inspect results are cached per container for a short
// time and refreshed whenever the container's state changes; inspections run
// with bounded concurrency. Every call returns freshly decoded maps that the
// caller may modify (e.g. to strip Config.Env) without affecting the cache.
func GetContainers(ctx context.Context, opts ContainerOptions) ([]map[string]any, error) {
	cli, err := getDockerClient()
	if err != nil {
		return nil, err
	}
	listed, err := cli.ContainerList(ctx, client.ContainerListOptions{All: true, Size: opts.Size})
	if err != nil {
		return nil, err
	}
	containers := listed.Items
	if len(containers) == 0 {
		return []map[string]any{}, nil
	}

	autoStart := readAutostart("/var/lib/docker/unraid-autostart")

	raw := make([][]byte, len(containers))
	sem := make(chan struct{}, inspectConcurrency)
	var wg sync.WaitGroup
	now := time.Now()
	for i, c := range containers {
		cacheMu.Lock()
		e, ok := inspectCache[c.ID]
		cacheMu.Unlock()
		if ok && e.state == string(c.State) && now.Sub(e.fetched) < inspectTTL {
			raw[i] = e.data
			continue
		}
		wg.Add(1)
		go func(i int, id, state string) {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
			case <-ctx.Done():
				return
			}
			defer func() { <-sem }()
			b, err := rawInspect(ctx, cli, id)
			if err != nil {
				if !errors.Is(err, ErrNotFound) && ctx.Err() == nil {
					log.Printf("docker: inspect %s: %v", id, err)
				}
				return // removed between list and inspect, or the daemon failed
			}
			raw[i] = b
			cacheMu.Lock()
			inspectCache[id] = inspectEntry{state: state, fetched: time.Now(), data: b}
			cacheMu.Unlock()
		}(i, c.ID, string(c.State))
	}
	wg.Wait()
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	// Drop cache entries for containers that no longer exist.
	live := make(map[string]bool, len(containers))
	for _, c := range containers {
		live[c.ID] = true
	}
	cacheMu.Lock()
	for id := range inspectCache {
		if !live[id] {
			delete(inspectCache, id)
		}
	}
	cacheMu.Unlock()

	result := make([]map[string]any, 0, len(containers))
	for i, c := range containers {
		if raw[i] == nil {
			continue
		}
		var m map[string]any
		if err := json.Unmarshal(raw[i], &m); err != nil {
			continue
		}
		name := ""
		if n, ok := m["Name"].(string); ok {
			name = strings.TrimPrefix(n, "/")
		}
		m["AutoStart"] = autoStart[name]
		if opts.Size {
			m["SizeRw"] = c.SizeRw
			m["SizeRootFs"] = c.SizeRootFs
		}
		result = append(result, m)
	}
	return result, nil
}

func readAutostart(path string) map[string]bool {
	out := map[string]bool{}
	content, err := os.ReadFile(path)
	if err != nil {
		return out
	}
	for _, line := range strings.Split(string(content), "\n") {
		if f := strings.Fields(line); len(f) > 0 {
			out[f[0]] = true
		}
	}
	return out
}

// StripEnv removes Config.Env from an inspect map in place. The map must be
// one returned by GetContainers (never shared with the cache).
func StripEnv(m map[string]any) {
	if cfg, ok := m["Config"].(map[string]any); ok {
		delete(cfg, "Env")
	}
}
