package system

import (
	"os"
	"path/filepath"
	"testing"
)

func setup(t *testing.T) (*[][]string, string) {
	t.Helper()
	dir := t.TempDir()
	oldR, oldP, oldS, oldStart := RebootBinary, PoweroffBinary, SafeModeFlag, StartDetached
	t.Cleanup(func() { RebootBinary, PoweroffBinary, SafeModeFlag, StartDetached = oldR, oldP, oldS, oldStart })
	RebootBinary = filepath.Join(dir, "reboot")
	PoweroffBinary = filepath.Join(dir, "poweroff")
	SafeModeFlag = filepath.Join(dir, "unraidsafemode")
	for _, p := range []string{RebootBinary, PoweroffBinary} {
		os.WriteFile(p, []byte("#!/bin/sh\n"), 0o755)
	}
	var calls [][]string
	// Never exec anything in tests.
	StartDetached = func(name string, args ...string) error {
		calls = append(calls, append([]string{name}, args...))
		return nil
	}
	return &calls, dir
}

func TestExecuteAction(t *testing.T) {
	calls, _ := setup(t)
	if err := ExecuteAction("shutdown", Options{}); err != nil {
		t.Fatal(err)
	}
	if err := ExecuteAction("reboot", Options{}); err != nil {
		t.Fatal(err)
	}
	if len(*calls) != 2 || (*calls)[0][0] != PoweroffBinary || (*calls)[1][0] != RebootBinary {
		t.Fatalf("calls = %v", *calls)
	}
	for _, c := range *calls {
		for _, a := range c[1:] {
			if a == "-f" {
				t.Fatalf("immediate (-f) power action used: %v", c)
			}
		}
	}
	if err := ExecuteAction("halt", Options{}); err == nil {
		t.Fatal("unknown action accepted")
	}
	if len(*calls) != 2 {
		t.Fatal("unknown action executed something")
	}
}

func TestSafeModeFlag(t *testing.T) {
	setup(t)
	yes, no := true, false
	if err := ExecuteAction("reboot", Options{SafeMode: &yes}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(SafeModeFlag); err != nil {
		t.Fatal("safe mode flag not created")
	}
	if err := ExecuteAction("reboot", Options{}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(SafeModeFlag); err != nil {
		t.Fatal("nil SafeMode must leave the flag alone")
	}
	if err := ExecuteAction("reboot", Options{SafeMode: &no}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(SafeModeFlag); !os.IsNotExist(err) {
		t.Fatal("safe mode flag not removed")
	}
}

// A flag that cannot be removed (here: a non-empty directory in its place)
// must not stop the reboot, like Boot.php's @unlink.
func TestSafeModeClearFailureStillReboots(t *testing.T) {
	calls, _ := setup(t)
	if err := os.MkdirAll(filepath.Join(SafeModeFlag, "keep"), 0o755); err != nil {
		t.Fatal(err)
	}
	no := false
	if err := ExecuteAction("reboot", Options{SafeMode: &no}); err != nil {
		t.Fatalf("reboot refused: %v", err)
	}
	if len(*calls) != 1 {
		t.Fatalf("reboot not started: %v", *calls)
	}
}

func TestMissingBinary(t *testing.T) {
	calls, _ := setup(t)
	os.Remove(RebootBinary)
	if err := ExecuteAction("reboot", Options{}); err == nil || len(*calls) != 0 {
		t.Fatalf("missing binary: %v %v", err, *calls)
	}
}
