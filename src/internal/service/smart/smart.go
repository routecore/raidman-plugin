// Package smart reads SMART health and attributes with smartctl without ever
// waking a spun-down disk ("-n standby": smartctl skips a disk in STANDBY or
// SLEEP and exits with bit 1 set).
//
// smartctl's exit status is a bitmask (bit 0: command line error, bit 1:
// open failed or skipped for its power mode, bit 2: a SMART command failed,
// bit 3+: health / attribute findings), so the JSON on stdout is parsed for
// every exit code and the status only decides the error cases.
package smart

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/routecore/raidman-plugin/src/internal/service/execx"
	"github.com/routecore/raidman-plugin/src/internal/service/httperr"
)

// Overridable in tests.
var (
	SmartctlBinary = "/usr/sbin/smartctl"
	DevDir         = "/dev"
	Timeout        = 30 * time.Second

	Run execx.Runner = execx.Run
)

// DeviceRe is the accepted device name (sdX, sdXY, nvmeNnM).
var DeviceRe = regexp.MustCompile(`^(sd[a-z]{1,2}|nvme\d+n\d+)$`)

// Attribute is one SMART attribute row.
type Attribute struct {
	ID      int    `json:"id"`
	Name    string `json:"name"`
	Value   int    `json:"value"`
	Worst   int    `json:"worst"`
	Thresh  int    `json:"thresh"`
	Raw     string `json:"raw"`
	Failing bool   `json:"failing"`
}

// Report is the GET /api/disks/smart response.
type Report struct {
	Device       string      `json:"device"`
	Standby      bool        `json:"standby"`
	Passed       *bool       `json:"passed"`
	Temperature  *int64      `json:"temperature"`
	PowerOnHours *int64      `json:"powerOnHours"`
	Attributes   []Attribute `json:"attributes"`
}

type message struct {
	String   string `json:"string"`
	Severity string `json:"severity"`
}

type smartJSON struct {
	Smartctl struct {
		Messages   []message `json:"messages"`
		ExitStatus *int      `json:"exit_status"`
	} `json:"smartctl"`
	Device       *json.RawMessage `json:"device"`
	SmartSupport *struct {
		Available *bool `json:"available"`
		Enabled   *bool `json:"enabled"`
	} `json:"smart_support"`
	SmartStatus *struct {
		Passed *bool `json:"passed"`
	} `json:"smart_status"`
	Temperature *struct {
		Current *int64 `json:"current"`
	} `json:"temperature"`
	PowerOnTime *struct {
		Hours *int64 `json:"hours"`
	} `json:"power_on_time"`
	ATA *struct {
		Table []struct {
			ID         int    `json:"id"`
			Name       string `json:"name"`
			Value      int    `json:"value"`
			Worst      int    `json:"worst"`
			Thresh     int    `json:"thresh"`
			WhenFailed string `json:"when_failed"`
			Raw        struct {
				Value  json.Number `json:"value"`
				String string      `json:"string"`
			} `json:"raw"`
		} `json:"table"`
	} `json:"ata_smart_attributes"`
	NVMe json.RawMessage `json:"nvme_smart_health_information_log"`
}

// ValidateDevice checks the device name and that /dev/<device> exists.
func ValidateDevice(device string) error {
	if !DeviceRe.MatchString(device) {
		return httperr.New(http.StatusBadRequest, "invalid device %q", device)
	}
	if _, err := os.Stat(filepath.Join(DevDir, device)); err != nil {
		return httperr.New(http.StatusUnprocessableEntity, "device %s not found", device)
	}
	return nil
}

// Get runs smartctl for device (validated) and parses its report.
func Get(ctx context.Context, device string) (Report, error) {
	if err := ValidateDevice(device); err != nil {
		return Report{}, err
	}
	if _, err := os.Stat(SmartctlBinary); err != nil {
		return Report{}, &httperr.Error{Status: http.StatusNotImplemented, Msg: "smartctl not found"}
	}
	cctx, cancel := context.WithTimeout(ctx, Timeout)
	defer cancel()
	res, err := Run(cctx, SmartctlBinary, "-n", "standby", "-j", "-H", "-A", filepath.Join(DevDir, device))
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) {
			return Report{}, &httperr.Error{Status: http.StatusInternalServerError, Msg: "smartctl timed out"}
		}
		return Report{}, fmt.Errorf("smartctl failed: %w", err)
	}
	return Parse(device, res.Stdout, res.ExitCode)
}

func isPowerModeSkip(msgs []message) bool {
	for _, m := range msgs {
		s := strings.ToLower(m.String)
		if strings.Contains(s, "standby mode") || strings.Contains(s, "sleep mode") {
			return true
		}
	}
	return false
}

func firstError(msgs []message) string {
	for _, m := range msgs {
		if m.Severity == "error" && m.String != "" {
			return m.String
		}
	}
	return ""
}

// unsupportedRe matches smartctl messages meaning the device cannot report
// SMART at all (as opposed to a failure reading it).
var unsupportedRe = regexp.MustCompile(`(?i)unknown usb bridge|unable to detect device type|please specify device type|smart support is:\s*unavailable|does not support smart|smart (support )?is not (available|supported)`)

func unsupported(msg string) error {
	return &httperr.Error{Status: http.StatusNotImplemented, Code: httperr.CodeSmartUnsupported, Msg: "SMART is not available for this device (" + msg + ")"}
}

// Parse turns smartctl -j output into a Report.
func Parse(device string, stdout []byte, exitCode int) (Report, error) {
	var j smartJSON
	dec := json.NewDecoder(bytes.NewReader(stdout))
	dec.UseNumber()
	if err := dec.Decode(&j); err != nil {
		return Report{}, fmt.Errorf("smartctl returned no JSON (exit %d)", exitCode)
	}
	if j.Smartctl.ExitStatus != nil && exitCode < 0 {
		exitCode = *j.Smartctl.ExitStatus
	}
	rep := Report{Device: device, Attributes: []Attribute{}}

	hasData := j.SmartStatus != nil || j.ATA != nil || len(j.NVMe) > 0 || j.Temperature != nil
	if msg := firstError(j.Smartctl.Messages); msg != "" && unsupportedRe.MatchString(msg) {
		return Report{}, unsupported(msg)
	}
	if ss := j.SmartSupport; ss != nil && ss.Available != nil && !*ss.Available && !hasData {
		return Report{}, unsupported("SMART support unavailable")
	}
	if exitCode >= 0 && exitCode&1 != 0 {
		msg := firstError(j.Smartctl.Messages)
		if msg == "" {
			msg = "invalid smartctl arguments"
		}
		return Report{}, errors.New("smartctl: " + msg)
	}
	if isPowerModeSkip(j.Smartctl.Messages) ||
		(exitCode >= 0 && exitCode&2 != 0 && !hasData && j.Device != nil && firstError(j.Smartctl.Messages) == "") {
		rep.Standby = true
		return rep, nil
	}
	if exitCode >= 0 && exitCode&2 != 0 && !hasData {
		msg := firstError(j.Smartctl.Messages)
		if msg == "" {
			msg = "could not open device"
		}
		return Report{}, errors.New("smartctl: " + msg)
	}

	if j.SmartStatus != nil && j.SmartStatus.Passed != nil {
		p := *j.SmartStatus.Passed
		rep.Passed = &p
	}
	if j.Temperature != nil && j.Temperature.Current != nil {
		v := *j.Temperature.Current
		rep.Temperature = &v
	}
	if j.PowerOnTime != nil && j.PowerOnTime.Hours != nil {
		v := *j.PowerOnTime.Hours
		rep.PowerOnHours = &v
	}
	if j.ATA != nil {
		for _, a := range j.ATA.Table {
			raw := a.Raw.String
			if raw == "" {
				raw = a.Raw.Value.String()
			}
			rep.Attributes = append(rep.Attributes, Attribute{
				ID: a.ID, Name: a.Name, Value: a.Value, Worst: a.Worst, Thresh: a.Thresh, Raw: raw,
				Failing: a.WhenFailed == "now" || (a.Thresh > 0 && a.Value <= a.Thresh),
			})
		}
	}
	if len(j.NVMe) > 0 {
		attrs, err := nvmeAttributes(j.NVMe)
		if err != nil {
			return Report{}, fmt.Errorf("smartctl: %w", err)
		}
		rep.Attributes = append(rep.Attributes, attrs...)
	}
	return rep, nil
}

// nvmeAttributes turns the NVMe health log (an object of scalar counters)
// into rows in smartctl's order, ids numbered from 1. Non-scalar fields
// (temperature_sensors) are skipped.
func nvmeAttributes(raw json.RawMessage) ([]Attribute, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	if t, err := dec.Token(); err != nil || t != json.Delim('{') {
		return nil, errors.New("invalid NVMe health log")
	}
	type kv struct {
		key string
		val json.Number
	}
	var rows []kv
	vals := map[string]json.Number{}
	for dec.More() {
		t, err := dec.Token()
		if err != nil {
			return nil, err
		}
		key, _ := t.(string)
		var v any
		if err := dec.Decode(&v); err != nil {
			return nil, err
		}
		if n, ok := v.(json.Number); ok {
			rows = append(rows, kv{key, n})
			vals[key] = n
		}
	}
	num := func(k string) (int64, bool) {
		n, ok := vals[k]
		if !ok {
			return 0, false
		}
		i, err := n.Int64()
		return i, err == nil
	}
	out := make([]Attribute, 0, len(rows))
	for i, r := range rows {
		failing := false
		v, _ := r.val.Int64()
		switch r.key {
		case "critical_warning", "media_errors":
			failing = v != 0
		case "available_spare":
			if th, ok := num("available_spare_threshold"); ok {
				failing = v < th
			}
		case "percentage_used":
			failing = v >= 100
		}
		out = append(out, Attribute{ID: i + 1, Name: r.key, Raw: r.val.String(), Failing: failing})
	}
	return out, nil
}
