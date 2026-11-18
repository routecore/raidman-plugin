package auth

import (
	"context"
	"crypto/subtle"
	"errors"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"
)

// DefaultKeysPath is the upstream Unraid API key store.
const DefaultKeysPath = "/boot/config/plugins/dynamix.my.servers/keys"

var (
	// ErrUnknownKey means the presented secret matches no key on disk.
	ErrUnknownKey = errors.New("invalid API key")
	// ErrKeyNotAllowed means the key exists but is excluded by the plugin's allowlist.
	ErrKeyNotAllowed = errors.New("API key is not allowed to use RaidMan")
)

// AllowPolicy returns the plugin allowlist settings.
// allowed contains upstream key ids (current format) or, for settings written
// by older plugin versions, raw key secrets.
type AllowPolicy func() (restrict bool, allowed []string)

type fileEntry struct {
	key   *Key
	mtime time.Time
	size  int64
	since time.Time // failed entries: when the file first failed to parse
}

// parseGrace is how long a key whose file became unparseable keeps working
// (it is most likely being rewritten). After that it is revoked, matching the
// Unraid API, which rejects keys it cannot validate.
const parseGrace = 2 * time.Minute

// Store holds the parsed API keys and keeps them in sync with the key directory.
type Store struct {
	dir    string
	policy AllowPolicy

	mu      sync.RWMutex
	files   map[string]fileEntry // file name -> entry
	failed  map[string]fileEntry // unparseable files (key nil) already reported
	byHash  map[[32]byte]*Key
	missing bool // last Reload found no readable directory
}

// NewStore creates a key store reading from dir. policy may be nil (no allowlist).
func NewStore(dir string, policy AllowPolicy) *Store {
	return &Store{
		dir:    dir,
		policy: policy,
		files:  map[string]fileEntry{},
		failed: map[string]fileEntry{},
		byHash: map[[32]byte]*Key{},
	}
}

// Dir returns the directory the store reads from.
func (s *Store) Dir() string { return s.dir }

// Reload re-reads the key directory. Files that disappeared are revoked
// immediately. A file that still exists but fails to parse keeps its previous
// entry for parseGrace (it is most likely being rewritten); every failure is
// logged once.
func (s *Store) Reload() {
	entries, err := os.ReadDir(s.dir)
	if err != nil {
		s.mu.Lock()
		hadKeys := len(s.files) > 0
		wasMissing := s.missing
		s.files = map[string]fileEntry{}
		s.byHash = map[[32]byte]*Key{}
		s.missing = true
		s.mu.Unlock()
		if wasMissing && !hadKeys {
			return // already reported
		}
		if os.IsNotExist(err) {
			if hadKeys {
				log.Printf("[AUTH] Keys directory %s disappeared; all keys revoked", s.dir)
			} else {
				log.Printf("[AUTH] Keys directory %s does not exist yet (no API keys created); watching for it", s.dir)
			}
		} else {
			log.Printf("[AUTH] Could not read keys directory %s: %v; all keys revoked", s.dir, err)
		}
		return
	}

	s.mu.RLock()
	prev := s.files
	prevFailed := s.failed
	s.mu.RUnlock()
	failed := map[string]fileEntry{}

	next := make(map[string]fileEntry, len(entries))
	changed := false
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".json") {
			continue
		}
		path := filepath.Join(s.dir, name)
		info, err := os.Stat(path)
		if err != nil {
			continue // vanished between ReadDir and Stat
		}
		if old, ok := prev[name]; ok && old.mtime.Equal(info.ModTime()) && old.size == info.Size() {
			next[name] = old
			continue
		}
		if f, ok := prevFailed[name]; ok && f.mtime.Equal(info.ModTime()) && f.size == info.Size() {
			// Same broken file as last time: already logged.
			failed[name] = f
			if old, ok := prev[name]; ok {
				if time.Since(f.since) < parseGrace {
					next[name] = old
				} else {
					log.Printf("[AUTH] Key file %s still invalid after %s; key revoked", name, parseGrace)
					changed = true
				}
			}
			continue
		}
		changed = true
		data, err := os.ReadFile(path)
		if err != nil {
			log.Printf("[AUTH] Could not read key file %s: %v", name, err)
			if old, ok := prev[name]; ok {
				next[name] = old
			}
			continue
		}
		k, warnings, err := ParseKey(data)
		if err != nil {
			since := time.Now()
			if f, ok := prevFailed[name]; ok {
				since = f.since
			}
			failed[name] = fileEntry{mtime: info.ModTime(), size: info.Size(), since: since}
			if old, ok := prev[name]; ok && time.Since(since) < parseGrace {
				log.Printf("[AUTH] Could not parse key file %s (%v); keeping previous version until it is valid", name, err)
				next[name] = old
			} else {
				log.Printf("[AUTH] Could not parse key file %s: %v; key ignored", name, err)
			}
			continue
		}
		for _, w := range warnings {
			log.Printf("[AUTH] Key file %s: %s", name, w)
		}
		if k.ID == "" {
			// Upstream names key files "<id>.json"; the settings page uses
			// the same fallback for the allowlist.
			k.ID = strings.TrimSuffix(name, ".json")
		}
		log.Printf("[AUTH] Key %s from %s: %s", k.Label(), name, describeGrants(k))
		next[name] = fileEntry{key: k, mtime: info.ModTime(), size: info.Size()}
	}

	if len(next) != len(prev) {
		changed = true
	}
	byHash := make(map[[32]byte]*Key, len(next))
	for _, fe := range next {
		byHash[fe.key.hash] = fe.key
	}

	s.mu.Lock()
	wasMissing := s.missing
	s.files = next
	s.failed = failed
	s.byHash = byHash
	s.missing = false
	s.mu.Unlock()
	if changed || wasMissing {
		log.Printf("[AUTH] Loaded %d API key(s) from %s", len(byHash), s.dir)
	}
}

// Count returns the number of loaded keys.
func (s *Store) Count() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.byHash)
}

// Authenticate resolves a raw secret to a key, applying the allowlist.
func (s *Store) Authenticate(secret string) (*Key, error) {
	if secret == "" {
		return nil, ErrUnknownKey
	}
	return s.ByHash(HashSecret(secret))
}

// ByHash resolves a key by the SHA-256 of its secret, applying the allowlist.
// On ErrKeyNotAllowed the (rejected) key is returned for logging only.
// Used to re-validate sessions and open WebSockets after key changes.
func (s *Store) ByHash(h [32]byte) (*Key, error) {
	s.mu.RLock()
	k, ok := s.byHash[h]
	s.mu.RUnlock()
	if !ok {
		return nil, ErrUnknownKey
	}
	if !s.allowed(k) {
		// The key is returned (for logging) together with the error; callers
		// must treat any non-nil error as a failed authentication.
		return k, ErrKeyNotAllowed
	}
	return k, nil
}

func (s *Store) allowed(k *Key) bool {
	if s.policy == nil {
		return true
	}
	restrict, list := s.policy()
	if !restrict {
		return true
	}
	return AllowlistMatches(k, list)
}

// AllowlistMatches reports whether a key is in the allowlist. Entries are
// upstream key ids; entries written by older plugin versions are raw secrets,
// which are matched by hash so restricted installs keep working after upgrade.
func AllowlistMatches(k *Key, list []string) bool {
	for _, entry := range list {
		if entry == "" {
			continue
		}
		if k.ID != "" && entry == k.ID {
			return true
		}
		h := HashSecret(entry)
		if subtle.ConstantTimeCompare(h[:], k.hash[:]) == 1 {
			return true
		}
	}
	return false
}

// Watch keeps the store in sync with the key directory until ctx is cancelled.
// It watches the parent directory as well, so a key directory created after
// startup (first key ever created) is picked up, reloads are debounced, and a
// slow periodic rescan covers missed events.
func (s *Store) Watch(ctx context.Context) {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		log.Printf("[AUTH] Could not create key watcher (%v); falling back to polling", err)
		s.poll(ctx, nil)
		return
	}
	go func() {
		<-ctx.Done()
		watcher.Close()
	}()
	s.poll(ctx, watcher)
}

func (s *Store) ensureWatches(w *fsnotify.Watcher, watchingDir *bool) {
	if w == nil {
		return
	}
	parent := filepath.Dir(s.dir)
	// Walk up to the closest existing ancestor so creation of any missing
	// level is observed.
	for p := parent; ; p = filepath.Dir(p) {
		if _, err := os.Stat(p); err == nil {
			_ = w.Add(p) // idempotent
			break
		}
		if p == filepath.Dir(p) {
			break
		}
	}
	if !*watchingDir {
		if _, err := os.Stat(s.dir); err == nil {
			if err := w.Add(s.dir); err == nil {
				*watchingDir = true
				log.Printf("[AUTH] Watching %s for API key changes", s.dir)
			}
		}
	}
}

func (s *Store) poll(ctx context.Context, w *fsnotify.Watcher) {
	watchingDir := false
	s.ensureWatches(w, &watchingDir)

	var events <-chan fsnotify.Event
	var errs <-chan error
	if w != nil {
		events = w.Events
		errs = w.Errors
	}
	rescan := time.NewTicker(60 * time.Second)
	defer rescan.Stop()
	var debounce *time.Timer
	var debounceC <-chan time.Time

	for {
		select {
		case <-ctx.Done():
			if debounce != nil {
				debounce.Stop()
			}
			return
		case ev, ok := <-events:
			if !ok {
				events = nil
				continue
			}
			if ev.Name == s.dir && ev.Op&(fsnotify.Remove|fsnotify.Rename) != 0 {
				watchingDir = false
			}
			if ev.Name == s.dir || filepath.Dir(ev.Name) == s.dir {
				if debounce == nil {
					debounce = time.NewTimer(300 * time.Millisecond)
				} else {
					debounce.Reset(300 * time.Millisecond)
				}
				debounceC = debounce.C
			}
		case err, ok := <-errs:
			if !ok {
				errs = nil
				continue
			}
			log.Printf("[AUTH] Key watcher error: %v", err)
		case <-debounceC:
			debounceC = nil
			s.ensureWatches(w, &watchingDir)
			s.Reload()
		case <-rescan.C:
			s.ensureWatches(w, &watchingDir)
			s.Reload()
		}
	}
}
