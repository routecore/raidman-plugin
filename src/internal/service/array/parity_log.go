package array

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"log"
	"math"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/routecore/raidman-plugin/src/internal/service/emhttp"
)

// Parity bookkeeping that Unraid leaves to its webGUI. emhttpd only keeps
// the current operation in var.ini; the webGUI adds:
//
//   - /var/tmp/stamps.ini (include/ParityControl.php): the operation's first
//     start time plus a time stamp per pause and resume, so elapsed time and
//     the logged duration survive a pause (emhttpd moves sbSynced on resume);
//   - /var/tmp/resync.ini (nchan/parity_list): action and size of the running
//     operation, kept after it ends;
//   - /boot/config/parity-checks.log (nchan/parity_list): one history line per
//     finished operation.
//
// parity_list only runs while a browser has the webGUI open, so a server
// managed from the app alone never got history. The daemon mirrors the same
// steps with the same files and formats, and skips a line the webGUI already
// wrote (both compare against the log's last time stamp).
var (
	StampsPath    = "/var/tmp/stamps.ini"
	ResyncPath    = "/var/tmp/resync.ini"
	ParityLogPath = "/boot/config/parity-checks.log"
)

var stampsMu sync.Mutex

// recordParityStamp does what ParityControl.php does for the webGUI's Pause
// and Resume buttons: on the first pause it stores the operation's start
// (sbSynced), then it appends the current time.
func recordParityStamp(pause bool, sbSynced string) error {
	stampsMu.Lock()
	defer stampsMu.Unlock()
	if pause {
		if _, err := os.Stat(StampsPath); errors.Is(err, fs.ErrNotExist) {
			if err := os.WriteFile(StampsPath, []byte(sbSynced), 0o644); err != nil {
				return err
			}
		}
	}
	f, err := os.OpenFile(StampsPath, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o644)
	if err != nil {
		return err
	}
	_, werr := fmt.Fprintf(f, ",%d", nowFunc().Unix())
	if cerr := f.Close(); werr == nil {
		werr = cerr
	}
	return werr
}

// readStamps returns stamps.ini's numbers (nil when there is none).
func readStamps() []int64 {
	b, err := os.ReadFile(StampsPath)
	if err != nil {
		return nil
	}
	var out []int64
	for _, s := range strings.Split(strings.TrimSpace(string(b)), ",") {
		n, err := strconv.ParseInt(strings.TrimSpace(s), 10, 64)
		if err != nil {
			return nil
		}
		out = append(out, n)
	}
	return out
}

// operationStart is when the current parity operation first started: the
// first stamp when it was paused at least once, else sbSynced (as the
// webGUI's parity_list computes its elapsed time).
func operationStart(sbSynced int64) int64 {
	if st := readStamps(); len(st) > 0 && st[0] > 0 {
		return st[0]
	}
	return sbSynced
}

// parityLogTimestamp formats like parity_list:
// str_replace(['.0','.'], ['  ',' '], date('Y.M.d H:i:s', $t)),
// e.g. "2026 Nov  5 09:03:01" (date() uses /etc/localtime, as Go does).
func parityLogTimestamp(t time.Time) string {
	s := t.Format("2006.Jan.02 15:04:05")
	s = strings.ReplaceAll(s, ".0", "  ")
	return strings.ReplaceAll(s, ".", " ")
}

// lastLoggedTimestamp is the date field of the log's last line ("" when the
// log is missing or empty).
func lastLoggedTimestamp() (string, error) {
	f, err := os.Open(ParityLogPath)
	if errors.Is(err, fs.ErrNotExist) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	defer f.Close()
	last := ""
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	for sc.Scan() {
		if line := sc.Text(); strings.TrimSpace(line) != "" {
			last = line
		}
	}
	if err := sc.Err(); err != nil {
		return "", err
	}
	date, _, _ := strings.Cut(last, "|")
	return date, nil
}

// parityLogLine builds the history line like Helpers.php last_parity_check().
func parityLogLine(vars map[string]string, timestamp string) string {
	num := func(k string) int64 {
		n, _ := strconv.ParseInt(strings.TrimSpace(vars[k]), 10, 64)
		return n
	}
	stamps := readStamps()
	start := num("sbSynced")
	if len(stamps) > 0 && stamps[0] > 0 {
		start = stamps[0]
	}
	// Pairs after the start are pause,resume; an odd trailing stamp
	// (paused when it ended) is ignored, as in last_parity_check().
	var idle int64
	if len(stamps) > 1 {
		rest := stamps[1:]
		for len(rest) > 1 {
			idle += rest[len(rest)-1] - rest[len(rest)-2]
			rest = rest[:len(rest)-2]
		}
	}
	action, size := vars["mdResyncAction"], vars["mdResyncSize"]
	if b, err := os.ReadFile(ResyncPath); err == nil {
		a, s, _ := strings.Cut(strings.TrimSpace(string(b)), ",")
		action, size = a, s
	}
	duration := num("sbSynced2") - start - idle
	status := strings.TrimSpace(vars["sbSyncExit"])
	var speed int64
	if code, err := strconv.ParseInt(status, 10, 64); err == nil && code == 0 && duration > 0 {
		sz, _ := strconv.ParseFloat(size, 64)
		speed = int64(math.Round(sz * 1024 / float64(duration)))
	}
	errs := strings.TrimSpace(vars["sbSyncErrs"])
	if errs == "" {
		errs = "0"
	}
	return fmt.Sprintf("%s|%d|%d|%s|%s|%s|%s\n", timestamp, duration, speed, status, errs, action, size)
}

// ParityLogger is the daemon's copy of parity_list's history step.
type ParityLogger struct {
	mu          sync.Mutex
	removeAfter int // parity_list's $remove_resync_files
	lastErr     string
}

// DefaultParityLogger is the daemon's logger; ParityAction also uses it to
// log a finished operation before a new one starts.
var DefaultParityLogger = &ParityLogger{}

// Tick runs one parity_list iteration against var.ini.
func (p *ParityLogger) Tick() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	vars, err := emhttp.ReadIni(VarIniPath)
	if err != nil {
		return err
	}
	num := func(k string) int64 {
		n, _ := strconv.ParseInt(strings.TrimSpace(vars[k]), 10, 64)
		return n
	}
	if num("mdResyncPos") > 0 {
		if _, err := os.Stat(ResyncPath); errors.Is(err, fs.ErrNotExist) {
			return os.WriteFile(ResyncPath, []byte(vars["mdResyncAction"]+","+vars["mdResyncSize"]), 0o644)
		}
		return nil
	}
	if num("sbSynced") == 0 || num("sbSynced2") == 0 {
		return nil
	}
	stamp := parityLogTimestamp(time.Unix(num("sbSynced2"), 0))
	last, err := lastLoggedTimestamp()
	if err != nil {
		return err
	}
	switch {
	case last != stamp:
		stampsMu.Lock()
		line := parityLogLine(vars, stamp)
		stampsMu.Unlock()
		f, err := os.OpenFile(ParityLogPath, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o644)
		if err != nil {
			return err
		}
		_, werr := f.WriteString(line)
		if cerr := f.Close(); werr == nil {
			werr = cerr
		}
		if werr != nil {
			return werr
		}
		p.removeAfter = 1
	case p.removeAfter >= 3:
		stampsMu.Lock()
		_ = os.Remove(StampsPath)
		_ = os.Remove(ResyncPath)
		stampsMu.Unlock()
		p.removeAfter = 0
	case p.removeAfter != 0:
		p.removeAfter++
	}
	return nil
}

// beforeStart logs a finished operation that is not in the history yet and
// drops its stamps, so a check started right after another one does not
// inherit its start time and pauses.
func (p *ParityLogger) beforeStart() error {
	err := p.Tick()
	p.mu.Lock()
	defer p.mu.Unlock()
	stampsMu.Lock()
	defer stampsMu.Unlock()
	for _, f := range []string{StampsPath, ResyncPath} {
		if rerr := os.Remove(f); rerr != nil && !errors.Is(rerr, fs.ErrNotExist) && err == nil {
			err = rerr
		}
	}
	p.removeAfter = 0
	return err
}

// Run ticks every interval until ctx ends. Errors are logged once per
// distinct message so a read-only flash does not flood the syslog.
func (p *ParityLogger) Run(ctx context.Context, interval time.Duration) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		if err := p.Tick(); err != nil {
			if msg := err.Error(); msg != p.lastErr {
				log.Printf("parity history: %v", err)
				p.lastErr = msg
			}
		} else {
			p.lastErr = ""
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}
