// Package nut reads UPS variables from a Network UPS Tools server with the
// stock upsc client: "upsc -l" lists the local upsd's UPS names and
// "upsc <ups>" prints "key: value" lines. A host that only monitors a remote
// NUT server (upsmon netclient) has no local upsd, so the systems named on
// upsmon.conf MONITOR lines ("ups@host") are queried too.
//
// UPS names reach argv only after DeviceRe validated them (no leading "-",
// no spaces), and every call has its own timeout.
package nut

import (
	"bufio"
	"bytes"
	"context"
	"io"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/routecore/raidman-plugin/src/internal/service/execx"
)

// Overridable in tests.
var (
	// UpscCandidates are tried in order (the NUT plugins install to /usr/bin).
	UpscCandidates = []string{"/usr/bin/upsc", "/usr/local/bin/upsc", "/usr/sbin/upsc"}
	UpsmonConf     = []string{"/etc/nut/upsmon.conf", "/etc/ups/upsmon.conf"}
	CallTimeout    = 8 * time.Second

	Run execx.Runner = execx.Run
)

// MaxDevices bounds how many UPSes are queried per request.
const MaxDevices = 8

var (
	// DeviceRe accepts "ups" and "ups@host[:port]" (NUT upsname syntax).
	DeviceRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}(@[A-Za-z0-9][A-Za-z0-9._-]{0,252}(:[0-9]{1,5})?)?$`)
	varKeyRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)
)

// Device is one UPS and its variables.
type Device struct {
	Name string            `json:"name"`
	Vars map[string]string `json:"vars"`
}

// Status is the GET /api/ups/nut response.
type Status struct {
	Available bool     `json:"available"`
	Devices   []Device `json:"devices"`
}

// ParseList returns the valid UPS names of "upsc -l" output (anything else,
// such as SSL warnings, is skipped).
func ParseList(out []byte) []string {
	var names []string
	sc := bufio.NewScanner(bytes.NewReader(out))
	for sc.Scan() {
		if n := strings.TrimSpace(sc.Text()); DeviceRe.MatchString(n) {
			names = append(names, n)
		}
	}
	return names
}

// ParseVars returns the "key: value" lines of "upsc <ups>" output.
func ParseVars(out []byte) map[string]string {
	vars := map[string]string{}
	sc := bufio.NewScanner(bytes.NewReader(out))
	for sc.Scan() {
		key, val, ok := strings.Cut(sc.Text(), ": ")
		if !ok {
			key, val, ok = strings.Cut(sc.Text(), ":")
			if !ok {
				continue
			}
		}
		key = strings.TrimSpace(key)
		if !varKeyRe.MatchString(key) || !strings.Contains(key, ".") {
			continue
		}
		vars[key] = strings.TrimSpace(val)
	}
	return vars
}

// ParseMonitors returns the systems of upsmon.conf MONITOR lines
// ("MONITOR <system> <powervalue> <user> <password> <type>").
func ParseMonitors(conf []byte) []string {
	var out []string
	sc := bufio.NewScanner(bytes.NewReader(conf))
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) >= 2 && strings.EqualFold(f[0], "MONITOR") && DeviceRe.MatchString(f[1]) {
			out = append(out, f[1])
		}
	}
	return out
}

func upsc() string {
	for _, c := range UpscCandidates {
		if fi, err := os.Stat(c); err == nil && fi.Mode().IsRegular() {
			return c
		}
	}
	return ""
}

func call(ctx context.Context, bin string, args ...string) ([]byte, bool) {
	cctx, cancel := context.WithTimeout(ctx, CallTimeout)
	defer cancel()
	res, err := Run(cctx, bin, args...)
	if err != nil || res.ExitCode != 0 {
		return nil, false
	}
	return res.Stdout, true
}

// localName maps "ups@localhost" / "ups@127.0.0.1" to the local name "ups".
func localName(system string) string {
	name, host, ok := strings.Cut(system, "@")
	if !ok {
		return system
	}
	host, _, _ = strings.Cut(host, ":")
	if host == "localhost" || host == "127.0.0.1" {
		return name
	}
	return system
}

func monitors() []string {
	for _, p := range UpsmonConf {
		f, err := os.Open(p)
		if err != nil {
			continue
		}
		data, err := io.ReadAll(io.LimitReader(f, 256*1024))
		f.Close()
		if err == nil {
			return ParseMonitors(data)
		}
	}
	return nil
}

// Get queries every known UPS. Available is false (and Devices empty) when
// upsc is missing or no UPS answered.
func Get(ctx context.Context) Status {
	st := Status{Devices: []Device{}}
	bin := upsc()
	if bin == "" {
		return st
	}
	var systems []string
	seen := map[string]bool{}
	add := func(s string) {
		s = localName(s)
		if !seen[s] && len(systems) < MaxDevices {
			seen[s] = true
			systems = append(systems, s)
		}
	}
	if out, ok := call(ctx, bin, "-l"); ok {
		for _, n := range ParseList(out) {
			add(n)
		}
	}
	for _, m := range monitors() {
		add(m)
	}
	for _, s := range systems {
		if ctx.Err() != nil {
			break
		}
		out, ok := call(ctx, bin, s)
		if !ok {
			continue
		}
		if vars := ParseVars(out); len(vars) > 0 {
			st.Devices = append(st.Devices, Device{Name: s, Vars: vars})
		}
	}
	st.Available = len(st.Devices) > 0
	return st
}
