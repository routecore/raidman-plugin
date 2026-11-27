package mover

import (
	"context"
	"errors"
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

type env struct {
	dir  string
	em   *fakeEmcmd
	runs [][]string
}

// setup points every path at a temp dir; nothing real is read or exec'd.
func setup(t *testing.T, varIni string, moverPid string, cmdline string) *env {
	t.Helper()
	e := &env{dir: t.TempDir(), em: &fakeEmcmd{}}
	oldVar, oldPid, oldProc, oldEm, oldRun := VarIniPath, PidFile, ProcDir, Emcmd, RunCommand
	t.Cleanup(func() { VarIniPath, PidFile, ProcDir, Emcmd, RunCommand = oldVar, oldPid, oldProc, oldEm, oldRun })
	VarIniPath = filepath.Join(e.dir, "var.ini")
	PidFile = filepath.Join(e.dir, "mover.pid")
	ProcDir = filepath.Join(e.dir, "proc")
	Emcmd = e.em
	RunCommand = func(_ context.Context, name string, args ...string) ([]byte, error) {
		e.runs = append(e.runs, append([]string{name}, args...))
		os.Remove(PidFile) // "mover stop" removes the pid file
		return []byte("mover: stopped\n"), nil
	}
	if err := os.WriteFile(VarIniPath, []byte(varIni), 0o644); err != nil {
		t.Fatal(err)
	}
	if moverPid != "" {
		os.WriteFile(PidFile, []byte(moverPid+"\n"), 0o644)
		os.MkdirAll(filepath.Join(ProcDir, moverPid), 0o755)
		os.WriteFile(filepath.Join(ProcDir, moverPid, "cmdline"), []byte(cmdline), 0o644)
	}
	return e
}

const varStarted = "fsState=\"Started\"\nshareUser=\"e\"\nshareMoverActive=\"no\"\n"

func TestStatus(t *testing.T) {
	setup(t, varStarted, "", "")
	if s, err := GetStatus(); err != nil || s.Running {
		t.Fatalf("idle: %+v %v", s, err)
	}
	setup(t, "shareMoverActive=\"yes\"\n", "", "")
	if s, _ := GetStatus(); !s.Running {
		t.Fatal("shareMoverActive=yes must report running")
	}
	setup(t, varStarted, "4242", "/bin/bash\x00/usr/local/sbin/mover\x00start\x00")
	if s, _ := GetStatus(); !s.Running {
		t.Fatal("live mover pid must report running")
	}
	// Stale pid file whose pid now belongs to another process.
	setup(t, varStarted, "4243", "/usr/sbin/sshd\x00-D\x00")
	if s, _ := GetStatus(); s.Running {
		t.Fatal("stale pid must not count")
	}
	// Pid file without a process.
	e := setup(t, varStarted, "", "")
	os.WriteFile(PidFile, []byte("99999\n"), 0o644)
	_ = e
	if s, _ := GetStatus(); s.Running {
		t.Fatal("dead pid must not count")
	}
}

func TestStart(t *testing.T) {
	e := setup(t, varStarted, "", "")
	if _, err := Action(context.Background(), "start"); err != nil {
		t.Fatal(err)
	}
	if len(e.em.calls) != 1 || e.em.calls[0].Get("cmdStartMover") != "Move" {
		t.Fatalf("emcmd calls = %v", e.em.calls)
	}
	if len(e.runs) != 0 {
		t.Fatalf("start must not exec the mover itself: %v", e.runs)
	}

	for _, c := range []struct {
		varIni, pid string
	}{
		{"fsState=\"Stopped\"\nshareUser=\"e\"\n", ""},
		{"fsState=\"Started\"\nshareUser=\"-\"\n", ""},
		{varStarted, "77"},
	} {
		e := setup(t, c.varIni, c.pid, "/usr/local/sbin/mover\x00start\x00")
		if _, err := Action(context.Background(), "start"); StatusOf(err) != http.StatusConflict || len(e.em.calls) != 0 {
			t.Errorf("var=%q pid=%q: err=%v calls=%v", c.varIni, c.pid, err, e.em.calls)
		}
	}

	e = setup(t, varStarted, "", "")
	e.em.err = errors.New("emhttpd: busy")
	if _, err := Action(context.Background(), "start"); err == nil || StatusOf(err) != http.StatusInternalServerError {
		t.Fatalf("emcmd failure must be reported: %v", err)
	}
}

func TestStop(t *testing.T) {
	e := setup(t, varStarted, "", "")
	if _, err := Action(context.Background(), "stop"); StatusOf(err) != http.StatusConflict || len(e.runs) != 0 {
		t.Fatalf("stop when idle: %v runs=%v", err, e.runs)
	}
	e = setup(t, varStarted, "4242", "/usr/local/sbin/mover\x00start\x00")
	s, err := Action(context.Background(), "stop")
	if err != nil || s.Running {
		t.Fatalf("stop: %+v %v", s, err)
	}
	if len(e.runs) != 1 || e.runs[0][0] != MoverBinary || e.runs[0][1] != "stop" || len(e.runs[0]) != 2 {
		t.Fatalf("runs = %v", e.runs)
	}
	// Mover survives "stop": reported as an error, never as success.
	e = setup(t, varStarted, "4242", "/usr/local/sbin/mover\x00start\x00")
	RunCommand = func(context.Context, string, ...string) ([]byte, error) { return nil, nil }
	if _, err := Action(context.Background(), "stop"); err == nil {
		t.Fatal("surviving mover must be an error")
	}
}

func TestInvalidAction(t *testing.T) {
	setup(t, varStarted, "", "")
	if _, err := Action(context.Background(), "pause"); StatusOf(err) != http.StatusBadRequest {
		t.Fatal(err)
	}
}

// The webGUI disables Move while a parity operation runs.
func TestStartRefusedDuringParity(t *testing.T) {
	e := setup(t, "fsState=\"Started\"\nshareUser=\"e\"\nmdResync=\"1000\"\nshareMoverActive=\"no\"\n", "", "")
	_, err := Action(context.Background(), "start")
	if StatusOf(err) != http.StatusConflict || len(e.em.calls) != 0 {
		t.Fatalf("err=%v calls=%v", err, e.em.calls)
	}
}
