package array

import (
	"context"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"testing"
)

type fakeEmcmd struct {
	calls []url.Values
	err   error
}

func (f *fakeEmcmd) Cmd(_ context.Context, p url.Values) error {
	f.calls = append(f.calls, p)
	return f.err
}

func withFixtures(t *testing.T, varIni string) *fakeEmcmd {
	t.Helper()
	dir := t.TempDir()
	write := func(name, content string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
		return p
	}
	disks, _ := os.ReadFile("testdata/disks73.ini")
	devs, _ := os.ReadFile("testdata/devs.ini")
	oldVar, oldDisks, oldDevs, oldEm := VarIniPath, DisksIniPath, DevsIniPath, Emcmd
	VarIniPath = write("var.ini", varIni)
	DisksIniPath = write("disks.ini", string(disks))
	DevsIniPath = write("devs.ini", string(devs))
	f := &fakeEmcmd{}
	Emcmd = f
	t.Cleanup(func() { VarIniPath, DisksIniPath, DevsIniPath, Emcmd = oldVar, oldDisks, oldDevs, oldEm })
	return f
}

const (
	varIdle    = "mdState=\"STARTED\"\nmdResync=\"0\"\nmdResyncPos=\"0\"\nmdResyncDt=\"0\"\n"
	varRunning = "mdState=\"STARTED\"\nmdResync=\"1000\"\nmdResyncPos=\"500\"\nmdResyncDt=\"30\"\n"
	// webGUI: paused = mdResyncPos > 0 with mdResync == 0.
	varPaused = "mdState=\"STARTED\"\nmdResync=\"0\"\nmdResyncPos=\"500\"\nmdResyncDt=\"0\"\n"
	// Running check sampled with mdResyncDt 0: still running (Pause button).
	varRunningNoDt = "mdState=\"STARTED\"\nmdResync=\"1000\"\nmdResyncPos=\"500\"\nmdResyncDt=\"0\"\n"
	varStopped     = "mdState=\"STOPPED\"\nmdResync=\"0\"\nmdResyncPos=\"0\"\nmdResyncDt=\"0\"\n"
)

func TestLegacyParityMapping(t *testing.T) {
	cases := []struct {
		verb, varIni, wantAction, wantField string
		wantCorrect                         bool
		wantStatus                          int
	}{
		{"check", varIdle, "start", "cmdCheck", false, 0},
		{"check", varPaused, "resume", "cmdCheckResume", false, 0},
		{"check", varRunning, "", "", false, http.StatusConflict},
		{"sync", varIdle, "start", "cmdCheck", true, 0},
		{"sync", varPaused, "resume", "cmdCheckResume", false, 0},
		{"nocheck", varRunning, "pause", "cmdCheckPause", false, 0},
		{"nocheck", varRunningNoDt, "pause", "cmdCheckPause", false, 0},
		{"check", varRunningNoDt, "", "", false, http.StatusConflict},
		{"nocheck", varPaused, "cancel", "cmdCheckCancel", false, 0},
		{"nocheck", varIdle, "", "", false, http.StatusConflict},
		{"nosync", varRunning, "cancel", "cmdCheckCancel", false, 0},
		{"nosync", varIdle, "", "", false, http.StatusConflict},
		{"check", varStopped, "start", "", false, http.StatusConflict},
		{"bogus", varIdle, "", "", false, http.StatusBadRequest},
	}
	for _, c := range cases {
		f := withFixtures(t, c.varIni)
		action, err := LegacyParityAction(context.Background(), c.verb)
		if c.wantStatus != 0 {
			if err == nil || StatusOf(err) != c.wantStatus {
				t.Errorf("%s/%q: err=%v status=%d want %d", c.verb, c.varIni, err, StatusOf(err), c.wantStatus)
			}
			if len(f.calls) != 0 {
				t.Errorf("%s: emcmd called on error path: %v", c.verb, f.calls)
			}
			continue
		}
		if err != nil || action != c.wantAction {
			t.Errorf("%s: action=%q err=%v want %q", c.verb, action, err, c.wantAction)
			continue
		}
		if len(f.calls) != 1 {
			t.Fatalf("%s: calls=%v", c.verb, f.calls)
		}
		p := f.calls[0]
		if _, ok := p[c.wantField]; !ok {
			t.Errorf("%s: missing field %s in %v", c.verb, c.wantField, p)
		}
		if p.Get("startState") != "STARTED" {
			t.Errorf("%s: startState=%q", c.verb, p.Get("startState"))
		}
		if got := p.Get("optionCorrect") == "correct"; got != c.wantCorrect {
			t.Errorf("%s: optionCorrect=%v want %v", c.verb, got, c.wantCorrect)
		}
	}
}

func TestParityActionEmcmdFailureIsReported(t *testing.T) {
	f := withFixtures(t, varIdle)
	f.err = os.ErrPermission
	if err := ParityAction(context.Background(), "start", false); err == nil {
		t.Fatal("emcmd failure must be returned")
	}
}

func TestSpin(t *testing.T) {
	f := withFixtures(t, varIdle)
	ctx := context.Background()

	if err := ExecuteAction(ctx, "spindown"); err != nil {
		t.Fatal(err)
	}
	if err := ExecuteAction(ctx, "spinup"); err != nil {
		t.Fatal(err)
	}
	if err := SpinDisk(ctx, "parity", false); err != nil {
		t.Fatal(err)
	}
	if err := SpinDisk(ctx, "sdx", true); err != nil { // unassigned device
		t.Fatal(err)
	}
	want := []url.Values{
		{"cmdSpindownAll": {"Apply"}},
		{"cmdSpinupAll": {"Apply"}},
		{"cmdSpindown": {"parity"}},
		{"cmdSpinup": {"sdx"}},
	}
	if len(f.calls) != len(want) {
		t.Fatalf("calls = %v", f.calls)
	}
	for i := range want {
		if f.calls[i].Encode() != want[i].Encode() {
			t.Errorf("call %d = %v, want %v", i, f.calls[i], want[i])
		}
	}

	if err := SpinDisk(ctx, "disk9", true); StatusOf(err) != http.StatusNotFound {
		t.Errorf("unknown disk: %v", err)
	}
	if err := SpinDisk(ctx, "-x", true); StatusOf(err) != http.StatusBadRequest {
		t.Errorf("invalid disk name: %v", err)
	}
	f.err = os.ErrDeadlineExceeded
	if err := SpinAll(ctx, true); err == nil {
		t.Error("spin failure must be reported")
	}
}

func TestBootSlot73(t *testing.T) {
	st, err := getArrayStatusWithPaths("testdata/var.ini", "testdata/disks73.ini", "testdata/devs.ini")
	if err != nil {
		t.Fatal(err)
	}
	if st.Boot == nil || st.Boot.Name != "boot" || st.Boot.Device != "nvme1n1" {
		t.Fatalf("boot = %+v", st.Boot)
	}
	if len(st.BootDevices) != 2 {
		t.Fatalf("bootDevices = %+v", st.BootDevices)
	}
	for _, c := range st.Caches {
		if c.Type == "Boot" || c.Type == "Flash" {
			t.Fatalf("boot/flash device leaked into caches: %+v", c)
		}
	}
	if len(st.Caches) != 1 || st.Caches[0].Name != "cache" {
		t.Fatalf("caches = %+v", st.Caches)
	}
	if len(st.Parities) != 1 || st.Parities[0].IsSpinning {
		t.Fatalf("parities = %+v", st.Parities)
	}
	if len(st.Unassigned) != 1 {
		t.Fatalf("unassigned = %+v", st.Unassigned)
	}
}

func TestBootSlotFlash(t *testing.T) {
	st, err := getArrayStatusWithPaths("testdata/var.ini", "testdata/disks70.ini", "testdata/devs.ini")
	if err != nil {
		t.Fatal(err)
	}
	if st.Boot == nil || st.Boot.Name != "flash" {
		t.Fatalf("boot = %+v", st.Boot)
	}
	if len(st.Disks) != 1 || len(st.Parities) != 1 || len(st.Caches) != 0 {
		t.Fatalf("unexpected layout: %+v", st)
	}
}
