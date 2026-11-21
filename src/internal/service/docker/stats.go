package docker

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/client"
	"github.com/docker/go-units"
)

// ---- shared stats sampler -------------------------------------------------
//
// Every docker-stats socket reads from one process-wide sampler instead of
// polling Docker itself. While at least one subscription is open, the sampler
// keeps one long-lived streaming stats request per running container (Docker
// sends a frame about every second), re-lists running containers every
// statsRelist, and keeps the latest computed sample per container. The last
// Close stops it and every stream.

const (
	statsRelist  = 10 * time.Second // container list refresh
	statsRetry   = 2 * time.Second  // list retry after a failure
	statsStale   = 10 * time.Second // samples older than this are not reported
	statsWarmup  = 3 * time.Second  // wait this long for first frames before reporting a partial list
	statsTimeout = 10 * time.Second // container list / inspect timeout
)

// statsSource is the part of the Docker API the sampler needs (faked in tests).
type statsSource interface {
	ListRunning(ctx context.Context) ([]string, error)
	// Inspect resolves a container reference to its full ID; a missing
	// container returns ErrNotFound.
	Inspect(ctx context.Context, ref string) (id string, running bool, err error)
	// Stream opens a streaming stats request (one JSON frame per second).
	Stream(ctx context.Context, id string) (io.ReadCloser, error)
}

type dockerStatsSource struct{ cli *client.Client }

func (d dockerStatsSource) ListRunning(ctx context.Context) ([]string, error) {
	list, err := d.cli.ContainerList(ctx, container.ListOptions{})
	if err != nil {
		return nil, err
	}
	ids := make([]string, 0, len(list))
	for _, c := range list {
		ids = append(ids, c.ID)
	}
	return ids, nil
}

func (d dockerStatsSource) Inspect(ctx context.Context, ref string) (string, bool, error) {
	insp, err := d.cli.ContainerInspect(ctx, ref)
	if err != nil {
		return "", false, wrapNotFound(err)
	}
	return insp.ID, insp.State != nil && insp.State.Running, nil
}

func (d dockerStatsSource) Stream(ctx context.Context, id string) (io.ReadCloser, error) {
	r, err := d.cli.ContainerStats(ctx, id, true)
	if err != nil {
		return nil, wrapNotFound(err)
	}
	return r.Body, nil
}

type statsHub struct {
	mu        sync.Mutex
	refs      int
	cur       *statsSampler
	newSource func() (statsSource, error)
	relist    time.Duration
}

var defaultStatsHub = &statsHub{
	newSource: func() (statsSource, error) {
		cli, err := getDockerClient()
		if err != nil {
			return nil, err
		}
		return dockerStatsSource{cli}, nil
	},
	relist: statsRelist,
}

// StatsSubscription is one consumer of the shared sampler. Close it when done.
type StatsSubscription struct {
	hub  *statsHub
	s    *statsSampler
	once sync.Once
}

// SubscribeStats registers a consumer of the shared stats sampler, starting
// it if this is the first one.
func SubscribeStats() (*StatsSubscription, error) {
	return defaultStatsHub.subscribe()
}

func (h *statsHub) subscribe() (*StatsSubscription, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.cur == nil {
		src, err := h.newSource()
		if err != nil {
			return nil, err
		}
		h.cur = startSampler(src, h.relist)
	}
	h.refs++
	return &StatsSubscription{hub: h, s: h.cur}, nil
}

// Close releases the subscription; the last one stops the sampler.
func (sub *StatsSubscription) Close() {
	sub.once.Do(func() {
		h := sub.hub
		h.mu.Lock()
		defer h.mu.Unlock()
		h.refs--
		if h.refs == 0 {
			h.cur.cancel()
			h.cur = nil
		}
	})
}

// All returns the latest sample of every running container, in container
// list order. ok is false until the first list (and, for up to statsWarmup,
// the first frames) are in, so "not sampled yet" never reads as "no
// containers". err is the last list error while listing fails.
func (sub *StatsSubscription) All() (stats []ContainerStats, ok bool, err error) {
	return sub.s.all(time.Now())
}

// One returns the latest sample of one container (ref is an ID or name).
// A stopped container reports zero usage and a missing one ErrNotFound. ok is
// false while the first frames of a container are pending.
func (sub *StatsSubscription) One(ctx context.Context, ref string) (ContainerStats, bool, error) {
	ctx, cancel := context.WithTimeout(ctx, statsTimeout)
	defer cancel()
	id, running, err := sub.s.src.Inspect(ctx, ref)
	if err != nil {
		return ContainerStats{}, false, err
	}
	if !running {
		// A stopped container sends no stats; report zero usage.
		return ContainerStats{ID: id, CPUPerc: "0.00%", MemPerc: "0.00%", MemUsage: "0B / 0B"}, true, nil
	}
	return sub.s.one(id, time.Now())
}

type statsSample struct {
	stats ContainerStats
	at    time.Time
}

type statsStream struct{ cancel context.CancelFunc }

type statsSampler struct {
	src    statsSource
	ctx    context.Context
	cancel context.CancelFunc
	relist time.Duration

	mu        sync.Mutex
	streams   map[string]*statsStream
	latest    map[string]statsSample
	streamErr map[string]error // last failed stream open per container, until read by one()
	order     []string         // running containers from the last list
	firstList time.Time        // zero until the first successful list
	listErr   error
}

func startSampler(src statsSource, relist time.Duration) *statsSampler {
	ctx, cancel := context.WithCancel(context.Background())
	s := &statsSampler{
		src:       src,
		ctx:       ctx,
		cancel:    cancel,
		relist:    relist,
		streams:   map[string]*statsStream{},
		latest:    map[string]statsSample{},
		streamErr: map[string]error{},
	}
	go s.run()
	return s
}

func (s *statsSampler) run() {
	for {
		ctx, cancel := context.WithTimeout(s.ctx, statsTimeout)
		ids, err := s.src.ListRunning(ctx)
		cancel()
		if s.ctx.Err() != nil {
			return
		}
		s.mu.Lock()
		if err != nil {
			s.listErr = err
		} else {
			s.listErr = nil
			s.order = ids
			if s.firstList.IsZero() {
				s.firstList = time.Now()
			}
			running := make(map[string]bool, len(ids))
			for _, id := range ids {
				running[id] = true
				s.watchLocked(id)
			}
			for id, st := range s.streams {
				if !running[id] {
					st.cancel()
					delete(s.streams, id)
					delete(s.latest, id)
				}
			}
			for id := range s.streamErr {
				if !running[id] {
					delete(s.streamErr, id)
				}
			}
		}
		s.mu.Unlock()

		wait := s.relist
		if err != nil {
			wait = statsRetry
		}
		t := time.NewTimer(wait)
		select {
		case <-s.ctx.Done():
			t.Stop()
			return
		case <-t.C:
		}
	}
}

// watchLocked starts a stats stream for id unless one is running. s.mu held.
func (s *statsSampler) watchLocked(id string) {
	if _, ok := s.streams[id]; ok || s.ctx.Err() != nil {
		return
	}
	ctx, cancel := context.WithCancel(s.ctx)
	st := &statsStream{cancel: cancel}
	s.streams[id] = st
	go s.runStream(ctx, id, st)
}

func (s *statsSampler) runStream(ctx context.Context, id string, st *statsStream) {
	defer func() {
		st.cancel()
		s.mu.Lock()
		if s.streams[id] == st {
			delete(s.streams, id)
			delete(s.latest, id)
		}
		s.mu.Unlock()
	}()
	body, err := s.src.Stream(ctx, id)
	if err != nil {
		s.mu.Lock()
		if s.streams[id] == st && ctx.Err() == nil {
			s.streamErr[id] = err
		}
		s.mu.Unlock()
		return
	}
	defer body.Close()
	dec := json.NewDecoder(body)
	first := true
	for {
		var f StatsJSON
		if err := dec.Decode(&f); err != nil {
			return
		}
		// The first frame has no previous CPU sample to diff against.
		if first && f.PreCPUStats.SystemUsage == 0 {
			first = false
			continue
		}
		first = false
		sample := statsSample{stats: computeStats(id, f), at: time.Now()}
		s.mu.Lock()
		if s.streams[id] != st {
			s.mu.Unlock()
			return
		}
		s.latest[id] = sample
		delete(s.streamErr, id)
		s.mu.Unlock()
	}
}

func (s *statsSampler) all(now time.Time) ([]ContainerStats, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.listErr != nil {
		return nil, false, s.listErr
	}
	if s.firstList.IsZero() {
		return nil, false, nil
	}
	out := make([]ContainerStats, 0, len(s.order))
	for _, id := range s.order {
		if smp, ok := s.latest[id]; ok && now.Sub(smp.at) <= statsStale {
			out = append(out, smp.stats)
		}
	}
	if len(out) < len(s.order) && now.Sub(s.firstList) < statsWarmup {
		return nil, false, nil
	}
	return out, true, nil
}

func (s *statsSampler) one(id string, now time.Time) (ContainerStats, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if smp, ok := s.latest[id]; ok && now.Sub(smp.at) <= statsStale {
		return smp.stats, true, nil
	}
	// Report a failed stream open once so the caller's failure count applies,
	// then retry.
	err := s.streamErr[id]
	delete(s.streamErr, id)
	s.watchLocked(id)
	return ContainerStats{}, false, err
}

// computeStats turns one Docker stats frame into the docker-stats payload
// (same formulas and formatting as the docker CLI).
func computeStats(id string, s StatsJSON) ContainerStats {
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

	out := ContainerStats{
		ID:       id,
		CPUPerc:  fmt.Sprintf("%.2f%%", cpuPercent),
		MemPerc:  fmt.Sprintf("%.2f%%", memPercent),
		MemUsage: fmt.Sprintf("%s / %s", units.HumanSize(memUsage), units.HumanSize(memLimit)),
	}

	// Host/none network mode has no "networks": leave NetIO unset rather
	// than claiming 0B / 0B.
	if s.Networks != nil {
		var rx, tx uint64
		for _, n := range s.Networks {
			rx += n.RxBytes
			tx += n.TxBytes
		}
		out.NetIO = ioPair(rx, tx)
	}

	// cgroup v1 reports "Read"/"Write" (plus "Sync", "Total", ...), cgroup v2
	// "read"/"write": match the first letter like the docker CLI.
	var read, write uint64
	for _, e := range s.BlkioStats.IoServiceBytesRecursive {
		if e.Op == "" {
			continue
		}
		switch e.Op[0] {
		case 'r', 'R':
			read += e.Value
		case 'w', 'W':
			write += e.Value
		}
	}
	out.BlockIO = ioPair(read, write)
	return out
}

func ioPair(a, b uint64) string {
	return units.HumanSizeWithPrecision(float64(a), 3) + " / " + units.HumanSizeWithPrecision(float64(b), 3)
}
