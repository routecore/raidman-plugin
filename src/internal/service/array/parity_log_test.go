package array

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestMain keeps every test in this package away from the real
// /var/tmp and /boot paths.
func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "parity-log")
	if err != nil {
		panic(err)
	}
	StampsPath = filepath.Join(dir, "stamps.ini")
	ResyncPath = filepath.Join(dir, "resync.ini")
	ParityLogPath = filepath.Join(dir, "parity-checks.log")
	code := m.Run()
	os.RemoveAll(dir)
	os.Exit(code)
}

func withClock(t *testing.T, unix int64) {
	t.Helper()
	old := nowFunc
	nowFunc = func() time.Time { return time.Unix(unix, 0) }
	t.Cleanup(func() { nowFunc = old })
}

func TestParityLogTimestamp(t *testing.T) {
	loc := time.FixedZone("X", 3*3600)
	cases := map[time.Time]string{
		time.Date(2026, 11, 5, 9, 3, 1, 0, loc):    "2026 Nov  5 09:03:01",
		time.Date(2026, 11, 26, 0, 56, 49, 0, loc): "2026 Nov 26 00:56:49",
		time.Date(2027, 1, 10, 23, 0, 0, 0, loc):   "2027 Jan 10 23:00:00",
	}
	for in, want := range cases {
		if got := parityLogTimestamp(in); got != want {
			t.Errorf("%v: got %q want %q", in, got, want)
		}
	}
}

// A check paused and resumed through the API is logged once, without the
// paused time, and its elapsed time does not restart at resume.
func TestParityPauseResumeHistory(t *testing.T) {
	withFixtures(t, "mdState=\"STARTED\"\nmdResync=\"1000\"\nmdResyncPos=\"500\"\nmdResyncDt=\"30\"\nsbSynced=\"1000\"\nsbSynced2=\"0\"\nmdResyncSize=\"1000000\"\nmdResyncAction=\"check P\"\n")
	withClock(t, 1100)
	if err := ParityAction(context.Background(), "pause", false); err != nil {
		t.Fatal(err)
	}
	// emhttpd: paused, then resumed (sbSynced moves to the resume time).
	os.WriteFile(VarIniPath, []byte("mdState=\"STARTED\"\nmdResync=\"0\"\nmdResyncPos=\"500\"\nmdResyncDt=\"0\"\nsbSynced=\"1000\"\nsbSynced2=\"0\"\nmdResyncSize=\"1000000\"\nmdResyncAction=\"check P\"\n"), 0o644)
	withClock(t, 1400)
	if err := ParityAction(context.Background(), "resume", false); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(StampsPath); string(b) != "1000,1100,1400" {
		t.Fatalf("stamps.ini = %q", b)
	}
	os.WriteFile(VarIniPath, []byte("mdState=\"STARTED\"\nmdResync=\"1000\"\nmdResyncPos=\"600\"\nmdResyncDt=\"30\"\nsbSynced=\"1400\"\nsbSynced2=\"0\"\nmdResyncSize=\"1000000\"\nmdResyncAction=\"check P\"\n"), 0o644)
	withClock(t, 1500)
	st, err := GetArrayStatus()
	if err != nil {
		t.Fatal(err)
	}
	if d := st.ParityCheckStatus.Duration; d != 500 {
		t.Errorf("elapsed = %d, want 500 (since the first start)", d)
	}
	var lg ParityLogger
	if err := lg.Tick(); err != nil { // running: remembers action and size
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(ResyncPath); string(b) != "check P,1000000" {
		t.Errorf("resync.ini = %q", b)
	}
	// Finished at 2000: duration 2000-1000-300 paused = 700 s.
	os.WriteFile(VarIniPath, []byte("mdState=\"STARTED\"\nmdResync=\"0\"\nmdResyncPos=\"0\"\nmdResyncDt=\"0\"\nsbSynced=\"1400\"\nsbSynced2=\"2000\"\nsbSyncExit=\"0\"\nsbSyncErrs=\"3\"\nmdResyncSize=\"1000000\"\nmdResyncAction=\"check P\"\n"), 0o644)
	for i := 0; i < 6; i++ {
		if err := lg.Tick(); err != nil {
			t.Fatal(err)
		}
	}
	b, _ := os.ReadFile(ParityLogPath)
	lines := strings.Split(strings.TrimSpace(string(b)), "\n")
	if len(lines) != 1 {
		t.Fatalf("log has %d lines: %q", len(lines), b)
	}
	want := parityLogTimestamp(time.Unix(2000, 0)) + "|700|1462857|0|3|check P|1000000"
	if lines[0] != want {
		t.Errorf("log line %q, want %q", lines[0], want)
	}
	if _, err := os.Stat(StampsPath); !os.IsNotExist(err) {
		t.Errorf("stamps.ini not removed after logging")
	}
	h, _ := GetParityHistory()
	if len(h) != 1 || h[0].Duration != 700 || h[0].Errors != 3 || h[0].Status != "COMPLETED" {
		t.Errorf("history = %+v", h)
	}
}

// A line the webGUI already wrote is not written again.
func TestParityLogSkipsWebGUILine(t *testing.T) {
	withFixtures(t, "mdState=\"STARTED\"\nmdResyncPos=\"0\"\nsbSynced=\"1000\"\nsbSynced2=\"2000\"\nsbSyncExit=\"-4\"\nsbSyncErrs=\"0\"\n")
	line := parityLogTimestamp(time.Unix(2000, 0)) + "|1000|0|-4|0|check P|1000000\n"
	os.WriteFile(ParityLogPath, []byte(line), 0o644)
	var lg ParityLogger
	for i := 0; i < 3; i++ {
		if err := lg.Tick(); err != nil {
			t.Fatal(err)
		}
	}
	if b, _ := os.ReadFile(ParityLogPath); string(b) != line {
		t.Errorf("log changed: %q", b)
	}
}

// A new check drops the previous check's stamps after logging it.
func TestParityStartLogsAndClearsStamps(t *testing.T) {
	withFixtures(t, "mdState=\"STARTED\"\nmdResync=\"0\"\nmdResyncPos=\"0\"\nmdResyncDt=\"0\"\nsbSynced=\"1000\"\nsbSynced2=\"2000\"\nsbSyncExit=\"-4\"\nsbSyncErrs=\"0\"\n")
	os.WriteFile(StampsPath, []byte("900,950,1000"), 0o644)
	if err := ParityAction(context.Background(), "start", false); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(StampsPath); !os.IsNotExist(err) {
		t.Errorf("stamps.ini kept")
	}
	b, _ := os.ReadFile(ParityLogPath)
	if !strings.Contains(string(b), "|1050|0|-4|0|") {
		t.Errorf("log = %q, want the cancelled check with 1050 s", b)
	}
}

// Cancelled while paused after two pauses: paused time is counted from the
// front (pause,resume pairs) plus the trailing pause up to the end.
func TestParityHistoryTwoPausesCancelledWhilePaused(t *testing.T) {
	withFixtures(t, "mdState=\"STARTED\"\nmdResync=\"0\"\nmdResyncPos=\"0\"\nsbSynced=\"1400\"\nsbSynced2=\"1700\"\nsbSyncExit=\"-4\"\nsbSyncErrs=\"0\"\nmdResyncAction=\"check P\"\nmdResyncSize=\"1000\"\n")
	os.WriteFile(StampsPath, []byte("1000,1100,1400,1600"), 0o644)
	var lg ParityLogger
	if err := lg.Tick(); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(ParityLogPath)
	// 1700-1000 = 700 total, paused 300 (1100-1400) + 100 (1600-1700) = 400 -> 300.
	if !strings.Contains(string(b), "|300|0|-4|0|check P|1000") {
		t.Errorf("log = %q", b)
	}
	if d, ok := LastLoggedDuration(1700); !ok || d != 300 {
		t.Errorf("LastLoggedDuration = %d %v", d, ok)
	}
	st, _ := GetArrayStatus()
	if st.ParityCheckStatus.Duration != 300 {
		t.Errorf("idle duration = %d, want 300 from the history line", st.ParityCheckStatus.Duration)
	}
}

// A stamps.ini from an earlier operation is not used for a running one and is removed.
func TestStaleStampsIgnored(t *testing.T) {
	withFixtures(t, "mdState=\"STARTED\"\nmdResync=\"1000\"\nmdResyncPos=\"500\"\nmdResyncDt=\"30\"\nsbSynced=\"5000\"\nsbSynced2=\"0\"\nmdResyncSize=\"1000\"\nmdResyncAction=\"check P\"\n")
	os.WriteFile(StampsPath, []byte("1000,1100,1400"), 0o644) // old check: resumed at 1400
	os.WriteFile(ResyncPath, []byte("recon P,999"), 0o644)
	withClock(t, 5100)
	st, _ := GetArrayStatus()
	if st.ParityCheckStatus.Duration != 100 {
		t.Errorf("duration = %d, want 100 (not from the stale start)", st.ParityCheckStatus.Duration)
	}
	var lg ParityLogger
	if err := lg.Tick(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(StampsPath); !os.IsNotExist(err) {
		t.Errorf("stale stamps.ini kept")
	}
	if b, _ := os.ReadFile(ResyncPath); string(b) != "check P,1000" {
		t.Errorf("resync.ini = %q", b)
	}
}

// A line the webGUI wrote in another time zone is the same check: no new line.
func TestParityLogOtherZoneNotDuplicated(t *testing.T) {
	withFixtures(t, "mdState=\"STARTED\"\nmdResyncPos=\"0\"\nsbSynced=\"1795640000\"\nsbSynced2=\"1795644148\"\nsbSyncExit=\"0\"\nsbSyncErrs=\"0\"\n")
	other := time.FixedZone("X", -5*3600-1800)
	line := parityLogTimestamp(time.Unix(1795644148, 0).In(other)) + "|4148|0|0|0|check P|1\n"
	// parityLogTimestamp converts to the local zone; build the foreign field by hand.
	f := time.Unix(1795644148, 0).In(other).Format("2006.Jan.02 15:04:05")
	f = strings.ReplaceAll(strings.ReplaceAll(f, ".0", "  "), ".", " ")
	line = f + "|4148|0|0|0|check P|1\n"
	os.WriteFile(ParityLogPath, []byte(line), 0o644)
	var lg ParityLogger
	for i := 0; i < 5; i++ {
		if err := lg.Tick(); err != nil {
			t.Fatal(err)
		}
	}
	if b, _ := os.ReadFile(ParityLogPath); string(b) != line {
		t.Errorf("log changed: %q", b)
	}
	if sameLoggedTime(f, 1795644148+60) {
		t.Errorf("a different instant matched")
	}
}
