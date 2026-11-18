package config

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"
)

// SettingsPath is a variable for tests.
var SettingsPath = "/boot/config/plugins/raidman/settings.json"

type Settings struct {
	HostTerminalEnabled bool `json:"host_terminal_enabled"`
	RestrictApiKeys     bool `json:"restrict_api_keys"`
	// AllowedApiKeys holds upstream API key ids. Settings written by plugin
	// versions before 2026.11 contain raw key secrets instead; those are still
	// matched (by hash) until the settings page is saved again.
	AllowedApiKeys []string `json:"allowed_api_keys"`
}

// AllowPolicy returns the current allowlist settings (for auth.Store).
func AllowPolicy() (bool, []string) {
	s := GetSettings()
	return s.RestrictApiKeys, s.AllowedApiKeys
}

var (
	currentSettings *Settings
	settingsMutex   sync.RWMutex
	// loadedOnce is set after the first successful load (or a confirmed
	// absence of the file).
	loadedOnce bool
)

// failClosed is used when settings.json exists but cannot be read or parsed
// before any good version was loaded: the administrator may have restricted
// keys or disabled the host terminal, so neither is assumed. Saving the
// settings page again (or fixing the file) restores normal operation.
func failClosed() *Settings {
	return &Settings{HostTerminalEnabled: false, RestrictApiKeys: true, AllowedApiKeys: []string{}}
}

func init() {
	// specific default settings
	currentSettings = &Settings{
		HostTerminalEnabled: true,
		RestrictApiKeys:     false,
		AllowedApiKeys:      []string{},
	}
}

// parseSettings decodes settings.json leniently: booleans may also be the
// strings "true"/"false" or 0/1, and allowed_api_keys may be a list or an
// object of strings (a non-sequential PHP array). Only invalid JSON, or a
// restrict_api_keys value that cannot be read, is an error (fail closed).
// Missing fields keep the Go zero value, as in every earlier version.
func parseSettings(content []byte) (*Settings, error) {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(content, &raw); err != nil {
		return nil, err
	}
	s := &Settings{AllowedApiKeys: []string{}}
	var err error
	if v, ok := raw["host_terminal_enabled"]; ok {
		if s.HostTerminalEnabled, err = lenientBool(v); err != nil {
			// Unreadable: keep the terminal off rather than guess.
			s.HostTerminalEnabled = false
		}
	}
	if v, ok := raw["restrict_api_keys"]; ok {
		if s.RestrictApiKeys, err = lenientBool(v); err != nil {
			return nil, fmt.Errorf("restrict_api_keys: %w", err)
		}
	}
	if v, ok := raw["allowed_api_keys"]; ok && string(v) != "null" {
		var list []json.RawMessage
		if json.Unmarshal(v, &list) != nil {
			var obj map[string]json.RawMessage
			if json.Unmarshal(v, &obj) != nil {
				return nil, fmt.Errorf("allowed_api_keys is neither a list nor an object")
			}
			for _, e := range obj {
				list = append(list, e)
			}
		}
		for _, e := range list {
			var id string
			if json.Unmarshal(e, &id) == nil && id != "" {
				s.AllowedApiKeys = append(s.AllowedApiKeys, id)
			}
		}
	}
	return s, nil
}

func lenientBool(v json.RawMessage) (bool, error) {
	var b bool
	if json.Unmarshal(v, &b) == nil {
		return b, nil
	}
	var str string
	if json.Unmarshal(v, &str) == nil {
		switch strings.ToLower(strings.TrimSpace(str)) {
		case "true", "1", "yes", "on":
			return true, nil
		case "false", "0", "no", "off", "":
			return false, nil
		}
	}
	var n float64
	if json.Unmarshal(v, &n) == nil {
		return n != 0, nil
	}
	return false, fmt.Errorf("not a boolean: %s", string(v))
}

func GetSettings() *Settings {
	settingsMutex.RLock()
	defer settingsMutex.RUnlock()
	return currentSettings
}

func LoadSettings() {
	settingsMutex.Lock()
	defer settingsMutex.Unlock()

	defer func() {
		log.Printf("[CONFIG] Loaded Settings: HostTerminal=%v, RestrictKeys=%v, AllowedKeys=%d",
			currentSettings.HostTerminalEnabled,
			currentSettings.RestrictApiKeys,
			len(currentSettings.AllowedApiKeys))
	}()

	content, err := os.ReadFile(SettingsPath)
	if os.IsNotExist(err) {
		log.Printf("[CONFIG] No settings file found at %s, using defaults", SettingsPath)
		loadedOnce = true
		return
	}
	if err == nil {
		var newSettings *Settings
		if newSettings, err = parseSettings(content); err == nil {
			currentSettings = newSettings
			loadedOnce = true
			return
		}
	}
	if loadedOnce {
		// Most likely a partial write by the settings page; keep the last
		// good settings until the next change event.
		log.Printf("[CONFIG] Error loading settings file (%v); keeping previous settings", err)
		return
	}
	log.Printf("[CONFIG] [SECURITY] Error loading settings file %s (%v); failing closed (all keys denied, host terminal disabled) until it is fixed or saved again", SettingsPath, err)
	currentSettings = failClosed()
}

func WatchSettings() {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		log.Printf("[CONFIG] Error creating watcher: %v", err)
		return
	}

	// Watch the directory because editors might atomic save (rename)
	dir := filepath.Dir(SettingsPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		log.Printf("[CONFIG] Error creating settings directory %s: %v", dir, err)
		return
	}
	if err := watcher.Add(dir); err != nil {
		log.Printf("[CONFIG] Error watching directory %s: %v", dir, err)
		return
	}

	go func() {
		defer watcher.Close()
		for {
			select {
			case event, ok := <-watcher.Events:
				if !ok {
					return
				}
				if event.Name == SettingsPath {
					if event.Op&fsnotify.Write == fsnotify.Write || event.Op&fsnotify.Create == fsnotify.Create || event.Op&fsnotify.Rename == fsnotify.Rename {
						log.Println("[CONFIG] Settings file changed, reloading...")
						// Small delay to ensure write complete
						time.Sleep(100 * time.Millisecond)
						LoadSettings()
					}
				}
			case err, ok := <-watcher.Errors:
				if !ok {
					return
				}
				log.Println("[CONFIG] Watcher error:", err)
			}
		}
	}()
}
