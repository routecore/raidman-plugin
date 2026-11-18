package docker

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/client"
	"github.com/docker/go-units"
)

type ContainerStats struct {
	ID       string `json:"ID"`
	CPUPerc  string `json:"CPUPerc"`
	MemPerc  string `json:"MemPerc"`
	MemUsage string `json:"MemUsage"`
}

type StatsJSON struct {
	ID          string      `json:"id"`
	Name        string      `json:"name"`
	CPUStats    CPUStats    `json:"cpu_stats"`
	PreCPUStats CPUStats    `json:"precpu_stats"`
	MemoryStats MemoryStats `json:"memory_stats"`
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
	c, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		return nil, err
	}
	shared = c
	return c, nil
}

func wrapNotFound(err error) error {
	if err != nil && client.IsErrNotFound(err) {
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
		err = cli.ContainerStart(ctx, containerID, container.StartOptions{})
	case "stop":
		err = cli.ContainerStop(ctx, containerID, container.StopOptions{})
	case "restart":
		err = cli.ContainerRestart(ctx, containerID, container.StopOptions{})
	case "kill":
		err = cli.ContainerKill(ctx, containerID, "KILL")
	case "pause":
		err = cli.ContainerPause(ctx, containerID)
	case "unpause":
		err = cli.ContainerUnpause(ctx, containerID)
	default:
		return fmt.Errorf("%w: %s", ErrInvalidAction, action)
	}
	invalidateAll()
	return wrapNotFound(err)
}

// statsConcurrency only guards against pathological container counts; each
// stats call waits ~1s for its second sample, so a low bound would slow the
// all-containers stream down.
const statsConcurrency = 64

// GetContainerStats returns CPU/memory usage for one container (containerID
// non-empty) or for all running containers. For a single container, a missing
// container returns ErrNotFound so the caller can report it instead of
// silently polling forever.
func GetContainerStats(ctx context.Context, containerID string) ([]ContainerStats, error) {
	cli, err := getDockerClient()
	if err != nil {
		return nil, err
	}

	var ids []string
	if containerID != "" {
		// A stopped container never sends a second stats sample; report
		// zero usage instead of blocking until the timeout.
		insp, err := cli.ContainerInspect(ctx, containerID)
		if err != nil {
			return nil, wrapNotFound(err)
		}
		if insp.State == nil || !insp.State.Running {
			return []ContainerStats{{ID: insp.ID, CPUPerc: "0.00%", MemPerc: "0.00%", MemUsage: "0B / 0B"}}, nil
		}
		ids = []string{insp.ID}
	} else {
		list, err := cli.ContainerList(ctx, container.ListOptions{})
		if err != nil {
			return nil, err
		}
		for _, c := range list {
			ids = append(ids, c.ID)
		}
	}

	results := make([]ContainerStats, len(ids))
	errs := make([]error, len(ids))
	sem := make(chan struct{}, statsConcurrency)
	var wg sync.WaitGroup
	for i, id := range ids {
		wg.Add(1)
		go func(i int, id string) {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
			case <-ctx.Done():
				errs[i] = ctx.Err()
				return
			}
			defer func() { <-sem }()
			results[i], errs[i] = statsFor(ctx, cli, id)
		}(i, id)
	}
	wg.Wait()

	if containerID != "" {
		if errs[0] != nil {
			return nil, errs[0]
		}
		return results, nil
	}
	out := make([]ContainerStats, 0, len(results))
	for i, r := range results {
		if errs[i] == nil && r.ID != "" {
			out = append(out, r)
		}
	}
	return out, ctx.Err()
}

func statsFor(ctx context.Context, cli *client.Client, id string) (ContainerStats, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	// Streaming stats: the second frame carries both current and previous
	// CPU samples, which the CPU percentage needs. The context bounds it.
	stats, err := cli.ContainerStats(ctx, id, true)
	if err != nil {
		if ctx.Err() != nil {
			return ContainerStats{}, ctx.Err()
		}
		return ContainerStats{}, wrapNotFound(err)
	}
	defer stats.Body.Close()

	var s StatsJSON
	dec := json.NewDecoder(stats.Body)
	if err := dec.Decode(&s); err != nil {
		if ctx.Err() != nil {
			return ContainerStats{}, ctx.Err()
		}
		return ContainerStats{}, err
	}
	if s.PreCPUStats.CPUUsage.TotalUsage == 0 {
		var second StatsJSON
		if err := dec.Decode(&second); err == nil {
			s = second
		}
	}

	cpuPercent := 0.0
	cpuDelta := float64(s.CPUStats.CPUUsage.TotalUsage) - float64(s.PreCPUStats.CPUUsage.TotalUsage)
	systemDelta := float64(s.CPUStats.SystemUsage) - float64(s.PreCPUStats.SystemUsage)
	if systemDelta > 0.0 && cpuDelta > 0.0 {
		onlineCPUs := float64(s.CPUStats.OnlineCPUs)
		if onlineCPUs == 0.0 {
			onlineCPUs = float64(len(s.CPUStats.CPUUsage.PercpuUsage))
		}
		cpuPercent = (cpuDelta / systemDelta) * onlineCPUs * 100.0
	}

	memUsage := float64(s.MemoryStats.Usage)
	if cache, ok := s.MemoryStats.Stats["cache"]; ok {
		memUsage -= float64(cache)
	} else if inactive, ok := s.MemoryStats.Stats["inactive_file"]; ok {
		memUsage -= float64(inactive)
	}
	memLimit := float64(s.MemoryStats.Limit)
	memPercent := 0.0
	if memLimit > 0 {
		memPercent = (memUsage / memLimit) * 100.0
	}

	return ContainerStats{
		ID:       id,
		CPUPerc:  fmt.Sprintf("%.2f%%", cpuPercent),
		MemPerc:  fmt.Sprintf("%.2f%%", memPercent),
		MemUsage: fmt.Sprintf("%s / %s", units.HumanSize(memUsage), units.HumanSize(memLimit)),
	}, nil
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
	containers, err := cli.ContainerList(ctx, container.ListOptions{All: true, Size: opts.Size})
	if err != nil {
		return nil, err
	}
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
		if ok && e.state == c.State && now.Sub(e.fetched) < inspectTTL {
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
			insp, err := cli.ContainerInspect(ctx, id)
			if err != nil {
				return // removed between list and inspect
			}
			b, err := json.Marshal(insp)
			if err != nil {
				return
			}
			raw[i] = b
			cacheMu.Lock()
			inspectCache[id] = inspectEntry{state: state, fetched: time.Now(), data: b}
			cacheMu.Unlock()
		}(i, c.ID, c.State)
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
