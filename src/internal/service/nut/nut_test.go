package nut

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/routecore/raidman-plugin/src/internal/service/execx"
)

const upscOut = `Init SSL without certificate database
battery.charge: 100
battery.runtime: 2280
battery.voltage: 27.0
device.mfr: CPS
device.model: CP1500PFCLCD
input.voltage: 230.0
ups.load: 17
ups.status: OL
ups.test.result: No test initiated
weird line without colon
: empty key
bad key: x
`

func TestParseVars(t *testing.T) {
	v := ParseVars([]byte(upscOut))
	if len(v) != 9 || v["ups.status"] != "OL" || v["battery.runtime"] != "2280" || v["ups.test.result"] != "No test initiated" {
		t.Fatalf("%v", v)
	}
	if v := ParseVars([]byte("ups.alarm:\n")); v["ups.alarm"] != "" || len(v) != 1 {
		t.Fatalf("empty value: %v", v)
	}
}

func TestParseList(t *testing.T) {
	got := ParseList([]byte("Init SSL without certificate database\nups\nCyberPower_1\n-oops\nbad name\n\n"))
	if strings.Join(got, ",") != "ups,CyberPower_1" {
		t.Fatalf("%v", got)
	}
}

func TestDeviceRe(t *testing.T) {
	for _, ok := range []string{"ups", "ups@localhost", "ups@192.168.1.10", "ups@nas.lan:3493", "My_UPS-2.a"} {
		if !DeviceRe.MatchString(ok) {
			t.Errorf("%q should match", ok)
		}
	}
	for _, bad := range []string{"", "-l", "--help", "ups name", "ups@", "ups@-h", "ups;rm", "ups@host:99999x", "ups\n"} {
		if DeviceRe.MatchString(bad) {
			t.Errorf("%q should not match", bad)
		}
	}
}

func TestParseMonitors(t *testing.T) {
	conf := "# MONITOR commented 1 a b master\nMONITOR ups@192.168.1.10 1 monuser secret slave\n  monitor local@localhost 1 u p primary\nMONITOR -x 1 u p slave\nMINSUPPLIES 1\n"
	if got := strings.Join(ParseMonitors([]byte(conf)), ","); got != "ups@192.168.1.10,local@localhost" {
		t.Fatalf("%v", got)
	}
}

type runCall struct{ args []string }

func fake(t *testing.T, answers map[string]execx.Result) *[]runCall {
	t.Helper()
	dir := t.TempDir()
	bin := filepath.Join(dir, "upsc")
	if err := os.WriteFile(bin, nil, 0o755); err != nil {
		t.Fatal(err)
	}
	oldC, oldM, oldRun := UpscCandidates, UpsmonConf, Run
	t.Cleanup(func() { UpscCandidates, UpsmonConf, Run = oldC, oldM, oldRun })
	UpscCandidates = []string{filepath.Join(dir, "missing"), bin}
	UpsmonConf = []string{filepath.Join(dir, "upsmon.conf")}
	var mu sync.Mutex
	calls := &[]runCall{}
	Run = func(_ context.Context, name string, args ...string) (execx.Result, error) {
		mu.Lock()
		*calls = append(*calls, runCall{args})
		mu.Unlock()
		if name != bin {
			return execx.Result{}, errors.New("wrong binary")
		}
		if r, ok := answers[strings.Join(args, " ")]; ok {
			return r, nil
		}
		return execx.Result{ExitCode: 1, Stderr: []byte("Error: Unknown UPS")}, nil
	}
	return calls
}

func TestGet(t *testing.T) {
	calls := fake(t, map[string]execx.Result{
		"-l":                   {Stdout: []byte("ups\nstale\n")},
		"ups":                  {Stdout: []byte(upscOut)},
		"stale":                {ExitCode: 1, Stdout: []byte("Error: Data stale\n")},
		"remote@10.0.0.2:3493": {Stdout: []byte("ups.status: OB LB\n")},
	})
	os.WriteFile(UpsmonConf[0], []byte("MONITOR ups@localhost 1 u p primary\nMONITOR remote@10.0.0.2:3493 1 u p secondary\n"), 0o600)
	st := Get(context.Background())
	if !st.Available || len(st.Devices) != 2 || st.Devices[0].Name != "ups" || st.Devices[1].Name != "remote@10.0.0.2:3493" || st.Devices[1].Vars["ups.status"] != "OB LB" {
		t.Fatalf("%+v", st)
	}
	// ups@localhost is the local "ups": queried once.
	n := 0
	for _, c := range *calls {
		if len(c.args) == 1 && c.args[0] == "ups" {
			n++
		}
	}
	if n != 1 || len(*calls) != 4 {
		t.Fatalf("calls: %+v", *calls)
	}
}

func TestGetUnavailable(t *testing.T) {
	// upsd down: "upsc -l" fails, no upsmon.conf.
	fake(t, map[string]execx.Result{})
	st := Get(context.Background())
	if st.Available || st.Devices == nil || len(st.Devices) != 0 {
		t.Fatalf("%+v", st)
	}
	// No upsc at all.
	UpscCandidates = []string{"/nonexistent/upsc"}
	if st := Get(context.Background()); st.Available || st.Devices == nil {
		t.Fatalf("%+v", st)
	}
}

func TestGetBounded(t *testing.T) {
	var list strings.Builder
	answers := map[string]execx.Result{}
	for i := 0; i < MaxDevices+5; i++ {
		name := "u" + strings.Repeat("x", i)
		list.WriteString(name + "\n")
		answers[name] = execx.Result{Stdout: []byte("ups.status: OL\n")}
	}
	answers["-l"] = execx.Result{Stdout: []byte(list.String())}
	fake(t, answers)
	if st := Get(context.Background()); len(st.Devices) != MaxDevices {
		t.Fatalf("%d devices", len(st.Devices))
	}
}
