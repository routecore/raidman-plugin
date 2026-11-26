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
// (sbSynced), then it appends the current time. sbSynced is var.ini's value
// from before the command (emhttpd moves it on resume). A file that does not
// belong to this operation is replaced on pause and left alone on resume.
func recordParityStamp(pause bool, sbSynced string) error {
	stampsMu.Lock()
	defer stampsMu.Unlock()
	sb, _ := strconv.ParseInt(strings.TrimSpace(sbSynced), 10, 64)
	if pause {
		if currentStamps(sb, false) == nil {
			if err := os.WriteFile(StampsPath, []byte(strconv.FormatInt(sb, 10)), 0o644); err != nil {
				return err
			}
		}
	} else if currentStamps(sb, true) == nil {
		return nil
	}
	f, err := os.OpenFile(StampsPath, os.O_WRONLY|os.O_APPEND, 0o644)
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

// stampSlack is how far the stamp written at a resume may be from the
// sbSynced emhttpd sets for that resume (both are "now" at the button press).
const stampSlack = 30

// currentStamps returns stamps.ini when it belongs to the parity operation
// var.ini shows as running or paused, nil otherwise. A file left behind by an
// earlier operation (the webGUI wrote the history line and its countdown never
// ran, the daemon restarted, a check started by cron or the webGUI) must not
// lend the next operation its start time and pauses. After a resume emhttpd
// moves sbSynced to the resume time, so a file that fits ends with that
// resume while running, or with a pause no older than it while paused.
func currentStamps(sbSynced int64, paused bool) []int64 {
	st := readStamps()
	if len(st) < 2 || st[0] <= 0 || st[0] > sbSynced+stampSlack {
		return nil
	}
	last := st[len(st)-1]
	if (len(st)-1)%2 == 0 { // ends with a resume
		if paused || last < sbSynced-stampSlack || last > sbSynced+stampSlack {
			return nil
		}
	} else { // ends with a pause
		if !paused || last < sbSynced-stampSlack {
			return nil
		}
	}
	return st
}

// operationStart is when the current parity operation first started: the
// first stamp when it was paused at least once, else sbSynced (as the
// webGUI's parity_list computes its elapsed time).
func operationStart(sbSynced int64, paused bool) int64 {
	if st := currentStamps(sbSynced, paused); st != nil {
		return st[0]
	}
	return sbSynced
}

// pausedTime adds up the paused intervals of stamps (start, then pause,resume
// pairs). A trailing pause (the operation ended while paused) counts up to
// end. Unlike the webGUI's last_parity_check(), which pairs from the end and
// so subtracts a running interval when the count is odd, pairs are taken
// from the front.
func pausedTime(st []int64, end int64) int64 {
	var idle int64
	for i := 1; i < len(st); i += 2 {
		if i+1 < len(st) {
			idle += st[i+1] - st[i]
		} else if end > st[i] {
			idle += end - st[i]
		}
	}
	return idle
}

// parityLogTimestamp formats like parity_list:
// str_replace(['.0','.'], ['  ',' '], date('Y.M.d H:i:s', $t)),
// e.g. "2026 Nov  5 09:03:01" (date() uses /etc/localtime, as Go does).
func parityLogTimestamp(t time.Time) string {
	s := t.In(localZone()).Format("2006.Jan.02 15:04:05")
	s = strings.ReplaceAll(s, ".0", "  ")
	return strings.ReplaceAll(s, ".", " ")
}

// LocaltimePath is the zone file PHP's date() follows (Unraid's local_prepend
// sets the PHP zone from it). It is read again on every use, so a zone
// changed in Settings while the daemon runs is picked up like the webGUI does.
var LocaltimePath = "/etc/localtime"

func localZone() *time.Location {
	if b, err := os.ReadFile(LocaltimePath); err == nil {
		if loc, err := time.LoadLocationFromTZData("Local", b); err == nil {
			return loc
		}
	}
	return time.Local
}

// sameLoggedTime reports whether a history date field names the instant
// synced2 in any time zone: the wall-clock difference is a whole number of
// quarter hours of at most 14 hours. The webGUI and the daemon may format in
// different zones (a zone changed while one of them runs); comparing strings
// alone would make each append the other's line again on every tick.
func sameLoggedTime(field string, synced2 int64) bool {
	f := strings.Fields(field)
	if len(f) != 4 {
		return false
	}
	wall, err := time.Parse("2006 Jan 2 15:04:05", strings.Join(f, " "))
	if err != nil {
		return false
	}
	utc := time.Unix(synced2, 0).UTC()
	ref := time.Date(utc.Year(), utc.Month(), utc.Day(), utc.Hour(), utc.Minute(), utc.Second(), 0, time.UTC)
	d := int64(wall.Sub(ref).Seconds())
	if d < 0 {
		d = -d
	}
	return d <= 14*3600 && d%900 == 0
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
	end := num("sbSynced2")
	start := num("sbSynced")
	var idle int64
	// Ended while paused or running: either way the file must be this
	// operation's (its last stamp is no older than the last resume).
	st := currentStamps(start, false)
	if st == nil {
		st = currentStamps(start, true)
	}
	if st != nil {
		start = st[0]
		idle = pausedTime(st, end)
	}
	action, size := vars["mdResyncAction"], vars["mdResyncSize"]
	if b, err := os.ReadFile(ResyncPath); err == nil {
		a, s, _ := strings.Cut(strings.TrimSpace(string(b)), ",")
		action, size = a, s
	}
	duration := end - start - idle
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
	removeAfter int   // parity_list's $remove_resync_files
	logged      int64 // sbSynced2 of the last operation known to be in the log
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
		paused := num("mdResync") == 0
		stampsMu.Lock()
		defer stampsMu.Unlock()
		if _, err := os.Stat(StampsPath); err == nil && currentStamps(num("sbSynced"), paused) == nil {
			_ = os.Remove(StampsPath) // left by an earlier operation
		}
		want := vars["mdResyncAction"] + "," + vars["mdResyncSize"]
		if b, err := os.ReadFile(ResyncPath); err != nil || strings.TrimSpace(string(b)) != want {
			return os.WriteFile(ResyncPath, []byte(want), 0o644)
		}
		return nil
	}
	synced2 := num("sbSynced2")
	if num("sbSynced") == 0 || synced2 == 0 {
		return nil
	}
	last, err := lastLoggedTimestamp()
	if err != nil {
		return err
	}
	logged := p.logged == synced2 || sameLoggedTime(last, synced2)
	switch {
	case !logged:
		stamp := parityLogTimestamp(time.Unix(synced2, 0))
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
		p.logged = synced2
		p.removeAfter = 1
	case p.removeAfter >= 3:
		stampsMu.Lock()
		_ = os.Remove(StampsPath)
		_ = os.Remove(ResyncPath)
		stampsMu.Unlock()
		p.removeAfter = 0
	case p.removeAfter != 0:
		p.removeAfter++
	default:
		// Logged by the webGUI (or before a restart): its countdown may never
		// have run, so clear what that operation left behind here too.
		p.logged = synced2
		if leftovers() {
			p.removeAfter = 1
		}
	}
	return nil
}

func leftovers() bool {
	for _, f := range []string{StampsPath, ResyncPath} {
		if _, err := os.Stat(f); err == nil {
			return true
		}
	}
	return false
}

// lastLineCache keeps the log's last line by path, size and mtime: the array
// status asks on every poll and the log lives on the USB flash.
var lastLineCache struct {
	sync.Mutex
	path  string
	size  int64
	mtime time.Time
	line  string
}

func cachedLastLine() (string, bool) {
	fi, err := os.Stat(ParityLogPath)
	if err != nil {
		return "", false
	}
	c := &lastLineCache
	c.Lock()
	defer c.Unlock()
	if c.path == ParityLogPath && c.size == fi.Size() && c.mtime.Equal(fi.ModTime()) {
		return c.line, true
	}
	f, err := os.Open(ParityLogPath)
	if err != nil {
		return "", false
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
	if sc.Err() != nil {
		return "", false
	}
	c.path, c.size, c.mtime, c.line = ParityLogPath, fi.Size(), fi.ModTime(), last
	return last, true
}

// LastLoggedDuration is the duration of the history line for the operation
// that ended at synced2, when the log's last line is that operation (it
// leaves out paused time; sbSynced2 - sbSynced does not after a resume).
func LastLoggedDuration(synced2 int64) (int64, bool) {
	last, ok := cachedLastLine()
	if !ok {
		return 0, false
	}
	parts := strings.Split(last, "|")
	if len(parts) < 2 || !sameLoggedTime(parts[0], synced2) {
		return 0, false
	}
	d, err := strconv.ParseInt(strings.TrimSpace(parts[1]), 10, 64)
	return d, err == nil && d > 0
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
