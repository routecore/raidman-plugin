package monitor

import (
	"bytes"
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
	RaidmanConfLine   = "include /etc/nginx/conf.d/raidman.conf;"
	NginxBinary       = "/usr/sbin/nginx"

	// rc.nginx regenerates locations.conf in several writes; wait for it to
	// settle before inspecting it.
	debounceDelay = 2 * time.Second
	// After a failed injection, don't retry for this long.
	failureCooldown = 30 * time.Second
)

type NginxMonitor struct {
	watcher     *fsnotify.Watcher
	lastFailure time.Time

	// Overridable for tests.
	confDir  string
	validate func() error
	reload   func() error
}

func NewNginxMonitor() (*NginxMonitor, error) {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, err
	}
	return &NginxMonitor{
		watcher:  watcher,
		confDir:  NginxConfDir,
		validate: validateNginxConfig,
		reload:   reloadNginx,
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
		var timer *time.Timer
		var timerC <-chan time.Time
		for {
			select {
			case event, ok := <-m.watcher.Events:
				if !ok {
					return
				}
				if filepath.Base(event.Name) != LocationsConfFile {
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
			case err, ok := <-m.watcher.Errors:
				if !ok {
					return
				}
				log.Println("Monitor: Watcher error:", err)
			}
		}
	}()
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
		return
	}

	// Only touch the config if nginx currently accepts it.
	if err := m.validate(); err != nil {
		log.Printf("Monitor: Pre-check failed. Nginx config is currently invalid: %v. Skipping injection.", err)
		return
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
		return
	}

	if err := m.reload(); err != nil {
		log.Printf("Monitor: Config valid but reload failed: %v", err)
	} else {
		log.Println("Monitor: Nginx reloaded successfully with Raidman config.")
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
