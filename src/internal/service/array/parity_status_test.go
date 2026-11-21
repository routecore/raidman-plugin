package array

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func statusFromVar(t *testing.T, varIni string) *statusResult {
	t.Helper()
	p := filepath.Join(t.TempDir(), "var.ini")
	if err := os.WriteFile(p, []byte(varIni), 0o644); err != nil {
		t.Fatal(err)
	}
	st, err := getArrayStatusWithPaths(p, "testdata/disks70.ini", "testdata/devs.ini")
	if err != nil {
		t.Fatal(err)
	}
	return &statusResult{st.ParityCheckStatus.Duration, st.ParityCheckStatus.ErrorsThisCheck,
		st.ParityCheckStatus.Errors, st.ParityCheckStatus.Status, st.ParityCheckStatus.Action}
}

type statusResult struct {
	duration, errorsThisCheck, errors int64
	status, action                    string
}

func fixClock(t *testing.T, unix int64) {
	t.Helper()
	old := nowFunc
	nowFunc = func() time.Time { return time.Unix(unix, 0) }
	t.Cleanup(func() { nowFunc = old })
}

const (
	// A check started at 1000 that already found 7 errors before the daemon
	// first read var.ini (scheduled overnight check, daemon restart).
	varCheckInProgress = "mdState=\"STARTED\"\nmdResyncAction=\"check P\"\nmdResync=\"2000\"\nmdResyncSize=\"2000\"\nmdResyncPos=\"500\"\nmdResyncDt=\"30\"\nmdResyncDb=\"3000\"\nmdResyncCorr=\"0\"\nsbSynced=\"1000\"\nsbSynced2=\"0\"\nsbSyncErrs=\"7\"\n"
	varRebuildPaused   = "mdState=\"STARTED\"\nmdResyncAction=\"recon D1\"\nmdResync=\"0\"\nmdResyncSize=\"2000\"\nmdResyncPos=\"500\"\nmdResyncDt=\"0\"\nsbSynced=\"1000\"\nsbSynced2=\"0\"\nsbSyncErrs=\"0\"\n"
	// Last check ran from 1000 to 4600 and found 3 errors.
	varIdleAfterCheck = "mdState=\"STARTED\"\nmdResyncAction=\"check P\"\nmdResync=\"0\"\nmdResyncSize=\"2000\"\nmdResyncPos=\"0\"\nmdResyncDt=\"0\"\nsbSynced=\"1000\"\nsbSynced2=\"4600\"\nsbSyncErrs=\"3\"\n"
)

func TestParityDurationAndErrorsFromVarIni(t *testing.T) {
	fixClock(t, 1600)

	// First read of a check already in progress: the duration and errors
	// are those of the whole check, not of what this process observed.
	got := statusFromVar(t, varCheckInProgress)
	want := statusResult{duration: 600, errorsThisCheck: 7, errors: 7, status: "RUNNING_CHECK", action: "check P"}
	if *got != want {
		t.Fatalf("in progress = %+v, want %+v", *got, want)
	}

	// Re-reading later (no state carried between calls) keeps counting from sbSynced.
	fixClock(t, 1900)
	if got := statusFromVar(t, varCheckInProgress); got.duration != 900 || got.errorsThisCheck != 7 {
		t.Fatalf("later read = %+v", *got)
	}

	// Paused rebuild: elapsed since sbSynced, action says it is a rebuild.
	got = statusFromVar(t, varRebuildPaused)
	if got.status != "PAUSED_CHECK" || got.action != "recon D1" || got.duration != 900 {
		t.Fatalf("paused rebuild = %+v", *got)
	}

	// Idle: duration of the last check, no action.
	got = statusFromVar(t, varIdleAfterCheck)
	want = statusResult{duration: 3600, errorsThisCheck: 0, errors: 3, status: "IDLE"}
	if *got != want {
		t.Fatalf("idle = %+v, want %+v", *got, want)
	}

	// A check that starts after an unobserved one is measured on its own.
	fixClock(t, 10_000)
	got = statusFromVar(t, "mdState=\"STARTED\"\nmdResync=\"2000\"\nmdResyncSize=\"2000\"\nmdResyncPos=\"10\"\nmdResyncDt=\"30\"\nsbSynced=\"9990\"\nsbSynced2=\"0\"\nsbSyncErrs=\"1\"\n")
	if got.duration != 10 || got.errorsThisCheck != 1 {
		t.Fatalf("next check = %+v", *got)
	}

	// Never synced / clock behind sbSynced: no negative or bogus durations.
	if got := statusFromVar(t, varIdle); got.duration != 0 {
		t.Fatalf("never run duration = %d", got.duration)
	}
	fixClock(t, 500)
	if got := statusFromVar(t, varCheckInProgress); got.duration != 0 {
		t.Fatalf("clock behind sbSynced: duration = %d", got.duration)
	}
	if got := statusFromVar(t, "mdState=\"STARTED\"\nsbSynced=\"5000\"\nsbSynced2=\"4000\"\n"); got.duration != 0 {
		t.Fatalf("sbSynced2 < sbSynced: duration = %d", got.duration)
	}
}

func TestArrayHealthFromVarIni(t *testing.T) {
	varIni := "mdState=\"STARTED\"\nmdResyncAction=\"recon D1\"\nmdResyncPos=\"500\"\nmdResyncDb=\"3000\"\nmdResyncDt=\"30\"\n" +
		"mdNumDisabled=\"1\"\nmdNumInvalid=\"2\"\nmdNumMissing=\"0\"\nfsState=\"Started\"\nfsProgress=\"\"\nfsCopyPrcnt=\"42\"\n" +
		"fsNumUnmountable=\"1\"\nshareMoverActive=\"yes\"\nsafeMode=\"no\"\n"
	p := filepath.Join(t.TempDir(), "var.ini")
	if err := os.WriteFile(p, []byte(varIni), 0o644); err != nil {
		t.Fatal(err)
	}
	st, err := getArrayStatusWithPaths(p, "testdata/disks70.ini", "testdata/devs.ini")
	if err != nil {
		t.Fatal(err)
	}
	b, err := json.Marshal(st.Health)
	if err != nil {
		t.Fatal(err)
	}
	want := `{"resyncPos":500,"resyncDb":3000,"resyncDt":30,"resyncAction":"recon D1","numDisabled":1,"numInvalid":2,"numMissing":0,` +
		`"fsState":"Started","fsProgress":null,"fsCopyPercent":42,"numUnmountable":1,"moverActive":true,"safeMode":false}`
	if string(b) != want {
		t.Fatalf("health =\n%s\nwant\n%s", b, want)
	}

	if !iniBool("true") || !iniBool("YES") || iniBool("no") || iniBool("") {
		t.Fatal("iniBool")
	}
}
