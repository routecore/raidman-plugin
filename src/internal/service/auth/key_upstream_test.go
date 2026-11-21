package auth

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// ca is a valid createdAt member for inline fixtures.
const ca = `"createdAt":"2026-01-02T03:04:05.000Z"`

// Key files the Unraid API rejects in loadApiKeyFile (class-validator on the
// ApiKey model) must yield no key here either - above all never an ADMIN one.
func TestParseRejectsWhatUpstreamRejects(t *testing.T) {
	const ok = `"key":"s","id":"i","name":"n",` + ca
	cases := map[string]string{
		"unknown role next to ADMIN":     `{` + ok + `,"roles":["ADMIN","OWNER"],"permissions":[]}`,
		"padded role (upstream no trim)": `{` + ok + `,"roles":["admin "],"permissions":[]}`,
		"non-string role":                `{` + ok + `,"roles":["ADMIN",1],"permissions":[]}`,
		"legacy string scope":            `{` + ok + `,"roles":[],"permissions":["role:admin"]}`,
		"legacy wildcard scope":          `{` + ok + `,"roles":[],"permissions":["docker:*"]}`,
		"non-object permission":          `{` + ok + `,"roles":["ADMIN"],"permissions":[42]}`,
		"null permission":                `{` + ok + `,"roles":["ADMIN"],"permissions":[null]}`,
		"permission without resource":    `{` + ok + `,"roles":["ADMIN"],"permissions":[{"actions":["READ_ANY"]}]}`,
		"permission without actions":     `{` + ok + `,"roles":["ADMIN"],"permissions":[{"resource":"DOCKER"}]}`,
		"permission with empty actions":  `{` + ok + `,"roles":["ADMIN"],"permissions":[{"resource":"DOCKER","actions":[]}]}`,
		"only unknown actions":           `{` + ok + `,"roles":["ADMIN"],"permissions":[{"resource":"DOCKER","actions":["*"]}]}`,
		"non-string action":              `{` + ok + `,"roles":["ADMIN"],"permissions":[{"resource":"DOCKER","actions":[1]}]}`,
		"wildcard resource":              `{` + ok + `,"roles":["ADMIN"],"permissions":[{"resource":"*","actions":["READ_ANY"]}]}`,
		"roles missing":                  `{` + ok + `,"permissions":[{"resource":"DOCKER","actions":["READ_ANY"]}]}`,
		"roles null":                     `{` + ok + `,"roles":null,"permissions":[]}`,
		"permissions missing":            `{` + ok + `,"roles":["ADMIN"]}`,
		"name missing":                   `{"key":"s","id":"i",` + ca + `,"roles":["ADMIN"],"permissions":[]}`,
		"name empty":                     `{"key":"s","id":"i","name":"",` + ca + `,"roles":["ADMIN"],"permissions":[]}`,
		"id missing":                     `{"key":"s","name":"n",` + ca + `,"roles":["ADMIN"],"permissions":[]}`,
		"id empty":                       `{"key":"s","id":"","name":"n",` + ca + `,"roles":["ADMIN"],"permissions":[]}`,
		"id with path separator":         `{"key":"s","id":"../x","name":"n",` + ca + `,"roles":["ADMIN"],"permissions":[]}`,
		"createdAt missing":              `{"key":"s","id":"i","name":"n","roles":["ADMIN"],"permissions":[]}`,
		"createdAt empty":                `{"key":"s","id":"i","name":"n","createdAt":"","roles":["ADMIN"],"permissions":[]}`,
		"createdAt not a string":         `{"key":"s","id":"i","name":"n","createdAt":1,"roles":["ADMIN"],"permissions":[]}`,
	}
	for name, js := range cases {
		if k, _, err := ParseKey([]byte(js)); err == nil {
			t.Errorf("%s: accepted (admin=%v grants=%v), want rejection", name, k.IsAdmin(), k.GrantList())
		}
	}
}

// The forms upstream accepts keep working: lower-case roles, legacy action
// verbs, mixed-case resources, and an empty roles list with permissions.
func TestParseAcceptsUpstreamShapes(t *testing.T) {
	for _, js := range []string{
		fixtureAdmin, fixtureViewer, fixtureGuest, fixtureConnect, fixturePermOnly, fixtureLegacyActions,
		`{"id":"a","key":"s","name":"n","roles":["admin"],"permissions":[],` + ca + `}`,
	} {
		if _, _, err := ParseKey([]byte(js)); err != nil {
			t.Errorf("rejected %s: %v", js, err)
		}
	}
}

// A rejected file in the store yields no key at all.
func TestStoreIgnoresUpstreamInvalidKey(t *testing.T) {
	dir := t.TempDir()
	writeKey(t, dir, "x.json", `{"id":"x","key":"stale-admin","name":"old","roles":["ADMIN","OWNER"],"permissions":[],`+ca+`}`)
	s := NewStore(dir, nil)
	s.Reload()
	if _, err := s.Authenticate("stale-admin"); err != ErrUnknownKey {
		t.Fatalf("upstream-invalid key authenticated: %v", err)
	}
}

// A same-size rewrite with the original mtime restored (vfat's 2-second
// mtime granularity) must still be picked up.
func TestStoreReloadDetectsSameSizeSameMtimeRewrite(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "k.json")
	admin := `{"id":"k","key":"rewritten","name":"n","roles":["ADMIN"],"permissions":[],` + ca + `}`
	guest := `{"id":"k","key":"rewritten","name":"n","roles":["GUEST"],"permissions":[],` + ca + `}`
	if len(admin) != len(guest) {
		t.Fatal("fixtures must have the same length")
	}
	writeKey(t, dir, "k.json", admin)
	mt := time.Now().Add(-time.Hour).Truncate(2 * time.Second)
	if err := os.Chtimes(path, mt, mt); err != nil {
		t.Fatal(err)
	}
	s := NewStore(dir, nil)
	s.Reload()
	if k, err := s.Authenticate("rewritten"); err != nil || !k.IsAdmin() {
		t.Fatalf("initial load: %v", err)
	}

	writeKey(t, dir, "k.json", guest)
	if err := os.Chtimes(path, mt, mt); err != nil {
		t.Fatal(err)
	}
	s.Reload()
	k, err := s.Authenticate("rewritten")
	if err != nil {
		t.Fatal(err)
	}
	if k.IsAdmin() || !k.Has(ResourceMe, ActionReadAny) {
		t.Fatalf("stale grants after same-size rewrite: %v", k.GrantList())
	}
}

// An unchanged file keeps its parsed entry (no re-parse, same *Key).
func TestStoreReloadReusesUnchangedEntry(t *testing.T) {
	dir := t.TempDir()
	writeKey(t, dir, "a.json", fixtureAdmin)
	s := NewStore(dir, nil)
	s.Reload()
	k1, _ := s.Authenticate("adminsecret0123456789")
	bumpMtime(t, filepath.Join(dir, "a.json")) // touch only
	s.Reload()
	k2, _ := s.Authenticate("adminsecret0123456789")
	if k1 == nil || k1 != k2 {
		t.Fatal("unchanged content was re-parsed")
	}
}

// An oversized file is refused as invalid.
func TestStoreRefusesOversizedKeyFile(t *testing.T) {
	dir := t.TempDir()
	pad := make([]byte, maxKeyFileSize)
	for i := range pad {
		pad[i] = ' '
	}
	writeKey(t, dir, "big.json", `{"id":"b","key":"big","name":"n","roles":["ADMIN"],"permissions":[],`+ca+`}`+string(pad))
	s := NewStore(dir, nil)
	s.Reload()
	if _, err := s.Authenticate("big"); err != ErrUnknownKey {
		t.Fatalf("oversized key file accepted: %v", err)
	}
}
