package api

import (
	"crypto/rand"
	"encoding/base64"
	"sync"
	"time"
)

const (
	sessionCookieName = "raidman_session"
	sessionTTL        = time.Hour
	maxSessions       = 4096
	// maxSessionsPerKey stops one key from churning sessions until it
	// evicts everybody else's (every cookie-less /novnc/ request mints one).
	maxSessionsPerKey = 16
)

type sessionEntry struct {
	keyHash [32]byte
	expires time.Time
}

// sessionStore maps opaque random session ids (the raidman_session cookie) to
// the hash of the API key that created them. The raw key never leaves the
// request headers, and every lookup is re-validated against the key store.
type sessionStore struct {
	mu  sync.Mutex
	m   map[string]sessionEntry
	now func() time.Time
}

func newSessionStore() *sessionStore {
	return &sessionStore{m: map[string]sessionEntry{}, now: time.Now}
}

func (s *sessionStore) create(keyHash [32]byte) (string, error) {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	id := base64.RawURLEncoding.EncodeToString(b[:])
	now := s.now()
	s.mu.Lock()
	defer s.mu.Unlock()
	// Per-key cap: drop expired entries of this key, then its oldest.
	var mine []string
	for k, e := range s.m {
		if e.keyHash != keyHash {
			continue
		}
		if now.After(e.expires) {
			delete(s.m, k)
			continue
		}
		mine = append(mine, k)
	}
	for len(mine) >= maxSessionsPerKey {
		oldest := 0
		for i := range mine {
			if s.m[mine[i]].expires.Before(s.m[mine[oldest]].expires) {
				oldest = i
			}
		}
		delete(s.m, mine[oldest])
		mine = append(mine[:oldest], mine[oldest+1:]...)
	}
	if len(s.m) >= maxSessions {
		for k, e := range s.m {
			if now.After(e.expires) {
				delete(s.m, k)
			}
		}
		// Still full: evict the entries closest to expiry.
		for len(s.m) >= maxSessions {
			var oldest string
			var oldestExp time.Time
			for k, e := range s.m {
				if oldest == "" || e.expires.Before(oldestExp) {
					oldest, oldestExp = k, e.expires
				}
			}
			delete(s.m, oldest)
		}
	}
	s.m[id] = sessionEntry{keyHash: keyHash, expires: now.Add(sessionTTL)}
	return id, nil
}

// resolve returns the key hash bound to a session id, if it exists and has
// not expired.
func (s *sessionStore) resolve(id string) ([32]byte, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.m[id]
	if !ok {
		return [32]byte{}, false
	}
	if s.now().After(e.expires) {
		delete(s.m, id)
		return [32]byte{}, false
	}
	return e.keyHash, true
}
