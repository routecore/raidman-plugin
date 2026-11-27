package docker

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"sync"
	"testing"
	"time"
)

func TestComputeStatsNetAndBlockIO(t *testing.T) {
	cases := []struct {
		name, frame          string
		wantNet, wantBlock   string
		wantCPU, wantMemPerc string
	}{
		{
			name: "cgroup v2, two networks",
			frame: `{"cpu_stats":{"cpu_usage":{"total_usage":300},"system_cpu_usage":2000,"online_cpus":4},
				"precpu_stats":{"cpu_usage":{"total_usage":200},"system_cpu_usage":1000,"online_cpus":4},
				"memory_stats":{"usage":3000,"limit":10000,"stats":{"inactive_file":1000}},
				"networks":{"eth0":{"rx_bytes":1500,"tx_bytes":500},"eth1":{"rx_bytes":500,"tx_bytes":1500}},
				"blkio_stats":{"io_service_bytes_recursive":[{"op":"read","value":1000000},{"op":"write","value":2000},{"op":"read","value":500000}]}}`,
			wantNet: "2kB / 2kB", wantBlock: "1.5MB / 2kB", wantCPU: "40.00%", wantMemPerc: "20.00%",
		},
		{
			name: "cgroup v1 ops, host network",
			frame: `{"cpu_stats":{"cpu_usage":{"total_usage":100,"percpu_usage":[1,2]},"system_cpu_usage":1000},
				"precpu_stats":{"cpu_usage":{"total_usage":50},"system_cpu_usage":500},
				"memory_stats":{"usage":100,"limit":1000},
				"blkio_stats":{"io_service_bytes_recursive":[{"op":"Read","value":4096},{"op":"Write","value":8192},{"op":"Sync","value":99},{"op":"Total","value":12288},{"op":"","value":7}]}}`,
			wantNet: "", wantBlock: "4.1kB / 8.19kB", wantCPU: "20.00%", wantMemPerc: "10.00%",
		},
		{
			name:    "no blkio entries",
			frame:   `{"networks":{"eth0":{"rx_bytes":0,"tx_bytes":0}}}`,
			wantNet: "0B / 0B", wantBlock: "0B / 0B", wantCPU: "0.00%", wantMemPerc: "0.00%",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var f StatsJSON
			if err := json.Unmarshal([]byte(c.frame), &f); err != nil {
				t.Fatal(err)
			}
			got := computeStats("abc", f)
			if got.ID != "abc" || got.NetIO != c.wantNet || got.BlockIO != c.wantBlock || got.CPUPerc != c.wantCPU || got.MemPerc != c.wantMemPerc {
				t.Fatalf("got %+v", got)
			}
			b, _ := json.Marshal(got)
			var m map[string]any
			_ = json.Unmarshal(b, &m)
			if _, ok := m["NetIO"]; ok != (c.wantNet != "") {
				t.Fatalf("NetIO presence in %s", b)
			}
		})
	}
}

// fakeStatsSource streams synthetic frames (50% CPU on one core) every 5ms.
type fakeStatsSource struct {
	mu      sync.Mutex
	running []string
	stopped map[string]bool // exists but not running
	listErr error
	openErr error
	opens   map[string]int
	active  int
}

func newFakeSource(running ...string) *fakeStatsSource {
	return &fakeStatsSource{running: running, stopped: map[string]bool{}, opens: map[string]int{}}
}

func (f *fakeStatsSource) ListRunning(context.Context) ([]string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.listErr != nil {
		return nil, f.listErr
	}
	return append([]string(nil), f.running...), nil
}

func (f *fakeStatsSource) Inspect(_ context.Context, ref string) (string, bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.stopped[ref] {
		return ref, false, nil
	}
	if ref == "missing" {
		return "", false, ErrNotFound
	}
	return ref, true, nil
}

func (f *fakeStatsSource) Stream(ctx context.Context, id string) (io.ReadCloser, error) {
	f.mu.Lock()
	f.opens[id]++
	if f.openErr != nil {
		f.mu.Unlock()
		return nil, f.openErr
	}
	f.active++
	f.mu.Unlock()
	pr, pw := io.Pipe()
	go func() {
		defer func() {
			f.mu.Lock()
			f.active--
			f.mu.Unlock()
			pw.Close()
		}()
		enc := json.NewEncoder(pw)
		var prev CPUStats
		for i := uint64(1); ; i++ {
			cur := CPUStats{CPUUsage: CPUUsage{TotalUsage: 50 * i}, SystemUsage: 100 * i, OnlineCPUs: 1}
			if err := enc.Encode(StatsJSON{CPUStats: cur, PreCPUStats: prev}); err != nil {
				return
			}
			prev = cur
			select {
			case <-ctx.Done():
				return
			case <-time.After(5 * time.Millisecond):
			}
		}
	}()
	go func() {
		<-ctx.Done()
		pr.CloseWithError(ctx.Err())
	}()
	return pr, nil
}

func (f *fakeStatsSource) snapshot() (map[string]int, int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	opens := map[string]int{}
	for k, v := range f.opens {
		opens[k] = v
	}
	return opens, f.active
}

func eventually(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func testHub(src *fakeStatsSource, relist time.Duration) *statsHub {
	return &statsHub{newSource: func() (statsSource, error) { return src, nil }, relist: relist}
}

func TestStatsSamplerSharedAndRefCounted(t *testing.T) {
	src := newFakeSource("a", "b")
	hub := testHub(src, 10*time.Millisecond)

	sub1, err := hub.subscribe()
	if err != nil {
		t.Fatal(err)
	}
	sub2, err := hub.subscribe()
	if err != nil {
		t.Fatal(err)
	}
	if sub1.s != sub2.s {
		t.Fatal("subscriptions must share one sampler")
	}

	eventually(t, "samples for both containers", func() bool {
		st, ok, err := sub1.All()
		return err == nil && ok && len(st) == 2
	})
	st, ok, _ := sub2.All()
	if !ok || len(st) != 2 || st[0].ID != "a" || st[1].ID != "b" || st[0].CPUPerc != "50.00%" {
		t.Fatalf("sub2 sees %+v ok=%v", st, ok)
	}

	time.Sleep(50 * time.Millisecond) // several relists
	opens, active := src.snapshot()
	if opens["a"] != 1 || opens["b"] != 1 || active != 2 {
		t.Fatalf("want one long-lived stream per container, opens=%v active=%d", opens, active)
	}

	sub1.Close()
	sub1.Close() // idempotent
	if _, active := src.snapshot(); active != 2 {
		t.Fatal("streams must keep running while a subscriber remains")
	}
	sub2.Close()
	eventually(t, "streams stopped after the last Close", func() bool {
		_, active := src.snapshot()
		return active == 0
	})
	hub.mu.Lock()
	if hub.cur != nil || hub.refs != 0 {
		t.Fatalf("hub not reset: refs=%d", hub.refs)
	}
	hub.mu.Unlock()

	// A new subscriber starts a fresh sampler.
	sub3, err := hub.subscribe()
	if err != nil {
		t.Fatal(err)
	}
	defer sub3.Close()
	eventually(t, "restarted streams", func() bool {
		opens, _ := src.snapshot()
		return opens["a"] == 2 && opens["b"] == 2
	})
}

func TestStatsSamplerFollowsContainerList(t *testing.T) {
	src := newFakeSource("a", "b")
	sub, _ := testHub(src, 10*time.Millisecond).subscribe()
	defer sub.Close()

	eventually(t, "two containers", func() bool {
		st, ok, _ := sub.All()
		return ok && len(st) == 2
	})

	src.mu.Lock()
	src.running = []string{"b", "c"}
	src.mu.Unlock()
	eventually(t, "a dropped, c added", func() bool {
		st, ok, _ := sub.All()
		return ok && len(st) == 2 && st[0].ID == "b" && st[1].ID == "c"
	})
	eventually(t, "stream of a stopped", func() bool {
		_, active := src.snapshot()
		return active == 2
	})

	// Nothing running: an empty (ready) list, not "pending".
	src.mu.Lock()
	src.running = nil
	src.mu.Unlock()
	eventually(t, "empty list", func() bool {
		st, ok, _ := sub.All()
		return ok && len(st) == 0
	})

	// List failures are reported.
	boom := errors.New("docker down")
	src.mu.Lock()
	src.listErr = boom
	src.mu.Unlock()
	eventually(t, "list error", func() bool {
		_, _, err := sub.All()
		return errors.Is(err, boom)
	})
}

func TestStatsSamplerNotReadyBeforeFirstList(t *testing.T) {
	s := &statsSampler{streams: map[string]*statsStream{}, latest: map[string]statsSample{}}
	if st, ok, err := s.all(time.Now()); ok || err != nil || st != nil {
		t.Fatalf("before first list: %v %v %v", st, ok, err)
	}
	now := time.Now()
	s.firstList = now
	s.order = []string{"a", "b"}
	s.latest["a"] = statsSample{stats: ContainerStats{ID: "a"}, at: now}
	if _, ok, _ := s.all(now.Add(time.Second)); ok {
		t.Fatal("partial samples must wait for the warmup")
	}
	if st, ok, _ := s.all(now.Add(statsWarmup)); !ok || len(st) != 1 {
		t.Fatalf("after warmup: %v %v", st, ok)
	}
	if st, ok, _ := s.all(now.Add(statsStale + time.Second)); !ok || len(st) != 0 {
		t.Fatalf("stale samples must be dropped: %v %v", st, ok)
	}
}

func TestStatsSubscriptionOne(t *testing.T) {
	src := newFakeSource()
	src.stopped["idle"] = true
	// One list at start (empty); no relist during the test.
	sub, _ := testHub(src, time.Hour).subscribe()
	defer sub.Close()
	ctx := context.Background()

	if _, _, err := sub.One(ctx, "missing"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing container: %v", err)
	}
	st, ok, err := sub.One(ctx, "idle")
	if err != nil || !ok || st.CPUPerc != "0.00%" || st.MemUsage != "0B / 0B" {
		t.Fatalf("stopped container: %+v %v %v", st, ok, err)
	}

	// A running container not (yet) in the list is watched on demand.
	eventually(t, "first list", func() bool {
		_, ok, _ := sub.All()
		return ok
	})
	eventually(t, "sample for x", func() bool {
		st, ok, err := sub.One(ctx, "x")
		return err == nil && ok && st.ID == "x" && st.CPUPerc == "50.00%"
	})
	if opens, _ := src.snapshot(); opens["x"] != 1 {
		t.Fatalf("one stream per container, opens=%v", opens)
	}
}

func TestStatsSubscriptionOneReportsStreamFailures(t *testing.T) {
	src := newFakeSource()
	boom := errors.New("stats endpoint failed")
	src.openErr = boom
	sub, _ := testHub(src, time.Hour).subscribe()
	defer sub.Close()
	eventually(t, "first list", func() bool {
		_, ok, _ := sub.All()
		return ok
	})
	ctx := context.Background()
	if _, ok, err := sub.One(ctx, "x"); ok || err != nil {
		t.Fatalf("first call only starts the stream: ok=%v err=%v", ok, err)
	}
	// The failed open is reported (so the socket's failure count applies)
	// and the stream is retried.
	eventually(t, "stream error", func() bool {
		_, _, err := sub.One(ctx, "x")
		return errors.Is(err, boom)
	})
	src.mu.Lock()
	src.openErr = nil
	src.mu.Unlock()
	eventually(t, "recovered sample", func() bool {
		st, ok, err := sub.One(ctx, "x")
		return err == nil && ok && st.ID == "x"
	})
}
