package monitor

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/fsnotify/fsnotify"
)

const (
	NginxConfDir      = "/etc/nginx/conf.d"
	LocationsConfFile = "locations.conf"
	RaidmanConfFile   = "raidman.conf"
	RaidmanConfLine   = "include /etc/nginx/conf.d/raidman.conf;"
	NginxBinary       = "/usr/sbin/nginx"
	// Left by the plg install when it replaced raidman.conf but could not
	// reload nginx (nginx -t failed for another reason, or the reload failed).
	ReloadPendingFile = "/var/run/raidman-nginx-reload"

	// rc.nginx regenerates locations.conf in several writes; wait for it to
	// settle before inspecting it.
	debounceDelay = 2 * time.Second
	// After a failed injection, don't retry for this long.
	failureCooldown = 30 * time.Second
	// While the include is missing (for example nginx -t failed because of
	// another plugin's config and was then fixed without rewriting
	// locations.conf), check again this often. A check is only a file read
	// once the include is present.
	defaultRetryInterval = 60 * time.Second
	// Periodic retries after an injection that nginx rejected back off from
	// failureCooldown up to this, while locations.conf and raidman.conf stay
	// the same. A change to either file retries at once.
	maxRetryBackoff = time.Hour
)

type NginxMonitor struct {
	watcher     *fsnotify.Watcher
	lastFailure time.Time
	// Last logged pre-check error, so a periodic retry against a config that
	// stays broken logs it once instead of every interval.
	lastPrecheckErr string
	// Fingerprint of locations.conf + raidman.conf when nginx last rejected
	// the injected include, and how many times in a row it did.
	failedFor   [sha256.Size]byte
	failedCount int
	// raidman.conf was missing at the last check (logged once).
	snippetMissing bool

	// Overridable for tests.
	confDir       string
	reloadPending string // "" = no marker check
	validate      func() error
	reload        func() error
	retryInterval time.Duration // 0 = defaultRetryInterval
}

func NewNginxMonitor() (*NginxMonitor, error) {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, err
	}
	return &NginxMonitor{
		watcher:       watcher,
		confDir:       NginxConfDir,
		reloadPending: ReloadPendingFile,
		validate:      validateNginxConfig,
		reload:        reloadNginx,
	}, nil
}

func (m *NginxMonitor) Start() {
	if err := m.watcher.Add(m.confDir); err != nil {
		log.Printf("Monitor: Error watching %s: %v. Monitoring disabled.", m.confDir, err)
		m.watcher.Close()
		return
	}

	log.Printf("Monitor: Started watching %s for %s", m.confDir, LocationsConfFile)

	// Initial check on startup
	m.checkAndInject()

	go func() {
		defer m.watcher.Close()
		retry := time.NewTicker(m.interval())
		defer retry.Stop()
		var timer *time.Timer
		var timerC <-chan time.Time
		for {
			select {
			case event, ok := <-m.watcher.Events:
				if !ok {
					return
				}
				if base := filepath.Base(event.Name); base != LocationsConfFile && base != RaidmanConfFile {
					continue
				}
				if event.Op&(fsnotify.Write|fsnotify.Create|fsnotify.Rename|fsnotify.Chmod) == 0 {
					continue
				}
				if timer == nil {
					timer = time.NewTimer(debounceDelay)
				} else {
					timer.Reset(debounceDelay)
				}
				timerC = timer.C
			case <-timerC:
				timerC = nil
				m.checkAndInject()
			case <-retry.C:
				m.retryInject()
			case err, ok := <-m.watcher.Errors:
				if !ok {
					return
				}
				log.Println("Monitor: Watcher error:", err)
			}
		}
	}()
}

func (m *NginxMonitor) interval() time.Duration {
	if m.retryInterval > 0 {
		return m.retryInterval
	}
	return defaultRetryInterval
}

// retryInject is the periodic check. After nginx rejected the injected
// include, it waits failureCooldown, doubling per failure up to
// maxRetryBackoff, as long as neither config file changed.
func (m *NginxMonitor) retryInject() {
	if m.failedCount > 0 {
		backoff := failureCooldown << min(m.failedCount-1, 10)
		if backoff > maxRetryBackoff {
			backoff = maxRetryBackoff
		}
		if time.Since(m.lastFailure) < backoff && m.fingerprint() == m.failedFor {
			return
		}
	}
	m.checkAndInject()
}

// fingerprint identifies the current locations.conf and raidman.conf
// (a zero value when either cannot be read).
func (m *NginxMonitor) fingerprint() [sha256.Size]byte {
	var zero [sha256.Size]byte
	loc, err := os.ReadFile(filepath.Join(m.confDir, LocationsConfFile))
	if err != nil {
		return zero
	}
	snip, err := os.ReadFile(filepath.Join(m.confDir, RaidmanConfFile))
	if err != nil {
		return zero
	}
	return fingerprintOf(loc, snip)
}

func fingerprintOf(loc, snip []byte) [sha256.Size]byte {
	h := sha256.New()
	_ = binary.Write(h, binary.BigEndian, uint64(len(loc)))
	h.Write(loc)
	h.Write(snip)
	var out [sha256.Size]byte
	copy(out[:], h.Sum(nil))
	return out
}

func (m *NginxMonitor) checkAndInject() {
	// Cooldown: if we failed recently, don't try again immediately.
	if time.Since(m.lastFailure) < failureCooldown {
		return
	}

	path := filepath.Join(m.confDir, LocationsConfFile)
	original, err := os.ReadFile(path)
	if err != nil {
		if !os.IsNotExist(err) {
			log.Printf("Monitor: Error reading %s: %v", path, err)
		}
		return
	}
	if bytes.Contains(original, []byte(RaidmanConfLine)) {
		m.reloadIfPending()
		return
	}

	// Never add an include whose file is missing (for example after the plg
	// install rolled back): nginx -t would reject it every time.
	snippet, err := os.ReadFile(filepath.Join(m.confDir, RaidmanConfFile))
	if err != nil {
		if !m.snippetMissing {
			m.snippetMissing = true
			log.Printf("Monitor: %s is missing (%v). Not adding the include until it exists.", RaidmanConfFile, err)
		}
		return
	}
	m.snippetMissing = false

	// Only touch the config if nginx currently accepts it.
	if err := m.validate(); err != nil {
		if msg := err.Error(); msg != m.lastPrecheckErr {
			m.lastPrecheckErr = msg
			log.Printf("Monitor: Pre-check failed. Nginx config is currently invalid: %v. Skipping injection; retrying every %s.", err, m.interval())
		}
		return
	}
	if m.lastPrecheckErr != "" {
		log.Println("Monitor: Nginx config is valid again.")
		m.lastPrecheckErr = ""
	}

	log.Printf("Monitor: Raidman config missing in %s, attempting injection...", LocationsConfFile)
	content := string(original)
	if !strings.HasSuffix(content, "\n") && content != "" {
		content += "\n"
	}
	content += RaidmanConfLine + "\n"

	if err := replaceIfUnchanged(path, original, []byte(content)); err != nil {
		log.Printf("Monitor: Not injecting: %v", err)
		return
	}

	if err := m.validate(); err != nil {
		log.Printf("Monitor: Injection resulted in invalid config: %v. Reverting...", err)
		if err := replaceIfUnchanged(path, []byte(content), original); err != nil {
			log.Printf("Monitor: CRITICAL: failed to revert %s: %v", path, err)
		} else {
			log.Println("Monitor: Reverted config successfully.")
		}
		m.lastFailure = time.Now()
		fp := fingerprintOf(original, snippet)
		if fp == m.failedFor {
			m.failedCount++
		} else {
			m.failedFor, m.failedCount = fp, 1
		}
		return
	}
	m.failedCount = 0

	if err := m.reload(); err != nil {
		log.Printf("Monitor: Config valid but reload failed: %v", err)
	} else {
		m.clearReloadPending()
		log.Println("Monitor: Nginx reloaded successfully with Raidman config.")
	}
}

// reloadIfPending reloads nginx when the plg install replaced raidman.conf
// without reloading. On an update the include is already present, so the
// injection path never runs and nginx would otherwise keep serving the old
// snippet until something else reloads it.
func (m *NginxMonitor) reloadIfPending() {
	if m.reloadPending == "" {
		return
	}
	if _, err := os.Stat(m.reloadPending); err != nil {
		return
	}
	if err := m.validate(); err != nil {
		if msg := err.Error(); msg != m.lastPrecheckErr {
			m.lastPrecheckErr = msg
			log.Printf("Monitor: %s changed but nginx config is currently invalid: %v. Reload deferred; retrying every %s.", RaidmanConfFile, err, m.interval())
		}
		return
	}
	if m.lastPrecheckErr != "" {
		log.Println("Monitor: Nginx config is valid again.")
		m.lastPrecheckErr = ""
	}
	if err := m.reload(); err != nil {
		log.Printf("Monitor: Reload for the updated %s failed: %v", RaidmanConfFile, err)
		return
	}
	m.clearReloadPending()
	log.Printf("Monitor: Nginx reloaded with the updated %s.", RaidmanConfFile)
}

func (m *NginxMonitor) clearReloadPending() {
	if m.reloadPending == "" {
		return
	}
	if err := os.Remove(m.reloadPending); err != nil && !os.IsNotExist(err) {
		log.Printf("Monitor: Could not remove %s: %v", m.reloadPending, err)
	}
}

// replaceIfUnchanged atomically replaces path with next (temp file + rename)
// provided its current content still equals expected, so a concurrent
// regeneration by rc.nginx is never clobbered with stale content.
func replaceIfUnchanged(path string, expected, next []byte) error {
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".raidman-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName) // no-op after a successful rename
	if _, err := tmp.Write(next); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(info.Mode().Perm()); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	current, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if !bytes.Equal(current, expected) {
		return fmt.Errorf("%s changed while preparing the update", path)
	}
	return os.Rename(tmpName, path)
}

func validateNginxConfig() error {
	cmd := exec.Command(NginxBinary, "-t")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%v: %s", err, strings.TrimSpace(string(output)))
	}
	return nil
}

func reloadNginx() error {
	if _, err := os.Stat("/var/run/nginx.pid"); os.IsNotExist(err) {
		log.Println("Monitor: Nginx PID file not found. Skipping reload.")
		return nil
	}
	return exec.Command(NginxBinary, "-s", "reload").Run()
}
