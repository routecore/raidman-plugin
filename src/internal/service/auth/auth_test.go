package auth

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// Fixtures in the exact on-disk shape written by unraid-api v4.x
// (ApiKey model: id, key, name, description, roles[], permissions[{resource, actions[]}], createdAt).
const (
	fixtureAdmin   = `{"id":"7c1d4f1e-2b5a-4c39-9d0e-0f6a1b2c3d4e","key":"adminsecret0123456789","name":"RaidMan","description":"created by app","roles":["ADMIN"],"permissions":[],"createdAt":"2026-01-02T03:04:05.000Z"}`
	fixtureViewer  = `{"id":"v-1","key":"viewersecret","name":"viewer","roles":["VIEWER"],"permissions":[],"createdAt":"2026-01-02T03:04:05.000Z"}`
	fixtureGuest   = `{"id":"g-1","key":"guestsecret","name":"guest","roles":["GUEST"],"permissions":[],"createdAt":"2026-01-02T03:04:05.000Z"}`
	fixtureConnect = `{"id":"c-1","key":"connectsecret","name":"connect","roles":["CONNECT"],"permissions":[],"createdAt":"2026-01-02T03:04:05.000Z"}`
	// Permission-only key (unraid-api #2152: roles may be empty).
	fixturePermOnly = `{"id":"p-1","key":"permsecret","name":"docker-ops","roles":[],"permissions":[{"resource":"DOCKER","actions":["READ_ANY","UPDATE_ANY"]},{"resource":"ARRAY","actions":["READ_ANY"]}],"createdAt":"2026-01-02T03:04:05.000Z"}`
	// Legacy file: lower-case role, legacy verbs, mixed-case resource.
	fixtureLegacyActions = `{"id":"l-1","key":"legacysecret","name":"legacy","roles":["viewer"],"permissions":[{"resource":"vms","actions":["update","read:any","DELETE"]},{"resource":"Docker","actions":["update:own"]}],"createdAt":"2024-01-02T03:04:05.000Z"}`
	// Legacy string scopes (pre-object permission format): rejected by the
	// Unraid API (permissions must be objects), so rejected here too.
	fixtureLegacyScopes = `{"id":"s-1","key":"scopesecret","name":"scopes","roles":[],"permissions":["docker:*","vms:read","role:guest"],"createdAt":"2024-01-02T03:04:05.000Z"}`
)

func mustParse(t *testing.T, js string) *Key {
	t.Helper()
	k, _, err := ParseKey([]byte(js))
	if err != nil {
		t.Fatalf("ParseKey: %v", err)
	}
	return k
}

type check struct {
	res, act string
	want     bool
}

func runChecks(t *testing.T, name string, k *Key, checks []check) {
	t.Helper()
	for _, c := range checks {
		if got := k.Has(c.res, c.act); got != c.want {
			t.Errorf("%s: Has(%s, %s) = %v, want %v (grants %v)", name, c.res, c.act, got, c.want, k.GrantList())
		}
	}
}

func TestParseAdmin(t *testing.T) {
	k := mustParse(t, fixtureAdmin)
	if !k.IsAdmin() {
		t.Fatal("ADMIN key not admin")
	}
	if k.ID != "7c1d4f1e-2b5a-4c39-9d0e-0f6a1b2c3d4e" || k.Name != "RaidMan" {
		t.Fatalf("id/name not decoded: %q %q", k.ID, k.Name)
	}
	runChecks(t, "admin", k, []check{
		{ResourceDocker, ActionUpdateAny, true},
		{ResourceVMs, ActionDeleteOwn, true},
		{ResourceAPIKey, ActionReadAny, true},
	})
}

func TestParseViewer(t *testing.T) {
	k := mustParse(t, fixtureViewer)
	if k.IsAdmin() {
		t.Fatal("VIEWER must not be admin")
	}
	runChecks(t, "viewer", k, []check{
		{ResourceDocker, ActionReadAny, true},
		{ResourceVMs, ActionReadAny, true},
		{ResourceArray, ActionReadAny, true},
		{ResourceMe, ActionReadAny, true},
		{ResourceDocker, ActionUpdateAny, false},
		{ResourceArray, ActionUpdateAny, false},
		{ResourceAPIKey, ActionReadAny, false}, // VIEWER excludes API_KEY
		{ResourceDocker, ActionReadOwn, false},
	})
}

func TestParseGuest(t *testing.T) {
	k := mustParse(t, fixtureGuest)
	runChecks(t, "guest", k, []check{
		{ResourceMe, ActionReadAny, true},
		{ResourceDocker, ActionReadAny, false},
		{ResourceVMs, ActionReadAny, false},
		{ResourceArray, ActionReadAny, false},
	})
}

func TestParseConnect(t *testing.T) {
	k := mustParse(t, fixtureConnect)
	runChecks(t, "connect", k, []check{
		{ResourceDocker, ActionReadAny, true}, // inherits VIEWER
		{ResourceConnectRemoteAccess, ActionUpdateAny, true},
		{ResourceDocker, ActionUpdateAny, false},
		{ResourceAPIKey, ActionReadAny, false},
	})
}

func TestParsePermissionOnly(t *testing.T) {
	k := mustParse(t, fixturePermOnly)
	if len(k.Roles) != 0 {
		t.Fatalf("roles = %v", k.Roles)
	}
	runChecks(t, "perm-only", k, []check{
		{ResourceDocker, ActionReadAny, true},
		{ResourceDocker, ActionUpdateAny, true},
		{ResourceArray, ActionReadAny, true},
		{ResourceArray, ActionUpdateAny, false},
		{ResourceVMs, ActionReadAny, false},
		{ResourceMe, ActionReadAny, false},
	})
	if k.IsAdmin() {
		t.Fatal("permissions must never make a key ADMIN")
	}
}

func TestParseLegacyActions(t *testing.T) {
	k, warnings, err := ParseKey([]byte(fixtureLegacyActions))
	if err != nil {
		t.Fatal(err)
	}
	if len(warnings) != 0 {
		t.Fatalf("unexpected warnings: %v", warnings)
	}
	if len(k.Roles) != 1 || k.Roles[0] != RoleViewer {
		t.Fatalf("roles = %v", k.Roles)
	}
	runChecks(t, "legacy", k, []check{
		{ResourceVMs, ActionUpdateAny, true}, // "update" -> UPDATE_ANY
		{ResourceVMs, ActionReadAny, true},   // "read:any"
		{ResourceVMs, ActionDeleteAny, true}, // "DELETE" -> DELETE_ANY
		{ResourceDocker, ActionUpdateOwn, true},
		{ResourceDocker, ActionUpdateAny, false}, // OWN never satisfies ANY
		{ResourceDocker, ActionReadAny, true},    // from VIEWER
	})
}

func TestParseLegacyScopesRejected(t *testing.T) {
	if k, _, err := ParseKey([]byte(fixtureLegacyScopes)); err == nil {
		t.Fatalf("legacy string scopes must reject the key, got grants %v", k.GrantList())
	}
}

func TestParseWildcardAndUnknownGrantNothing(t *testing.T) {
	// An unknown but enum-shaped resource (added by a newer Unraid API) is
	// skipped; unknown actions next to a known one are dropped.
	js := `{"id":"w","key":"wild","name":"w","roles":[],"permissions":[{"resource":"NOPE","actions":["READ_ANY"]},{"resource":"DOCKER","actions":["*","write","read"]}],"createdAt":"2026-01-02T03:04:05.000Z"}`
	k, warnings, err := ParseKey([]byte(js))
	if err != nil {
		t.Fatal(err)
	}
	if len(warnings) == 0 {
		t.Fatal("expected warnings for unknown resource/actions")
	}
	if k.IsAdmin() || k.Has(ResourceDocker, ActionUpdateAny) || !k.Has(ResourceDocker, ActionReadAny) {
		t.Fatalf("grants = %v", k.GrantList())
	}
	if got := k.GrantList(); len(got) != 1 {
		t.Fatalf("grants = %v, want only DOCKER:READ_ANY", got)
	}
}

func TestParseErrors(t *testing.T) {
	if _, _, err := ParseKey([]byte(`{"id":"x","roles":["ADMIN"]}`)); err != ErrNoSecret {
		t.Fatalf("missing secret: err = %v", err)
	}
	if _, _, err := ParseKey([]byte(`{not json`)); err == nil {
		t.Fatal("expected error for invalid JSON")
	}
	if _, _, err := ParseKey([]byte(`{"key":"k","roles":"ADMIN"}`)); err == nil {
		t.Fatal("expected error for roles of wrong type")
	}
}

func TestNormalizeLegacyAction(t *testing.T) {
	// Mirrors packages/unraid-shared/src/util/__tests__/permissions.test.ts.
	cases := map[string]string{
		"create":     ActionCreateAny,
		"read":       ActionReadAny,
		"update":     ActionUpdateAny,
		"delete":     ActionDeleteAny,
		"CREATE_ANY": ActionCreateAny,
		"READ_OWN":   ActionReadOwn,
		"create:any": ActionCreateAny,
		"read:own":   ActionReadOwn,
		"Update:Any": ActionUpdateAny,
		"DELETE:OWN": ActionDeleteOwn,
		"Read":       ActionReadAny,
		"invalid":    "",
		"write":      "",
		"*":          "",
		"read:all":   "",
		"":           "",
	}
	for in, want := range cases {
		got, ok := NormalizeLegacyAction(in)
		if want == "" {
			if ok {
				t.Errorf("NormalizeLegacyAction(%q) = %q, want rejection", in, got)
			}
			continue
		}
		if !ok || got != want {
			t.Errorf("NormalizeLegacyAction(%q) = %q,%v want %q", in, got, ok, want)
		}
	}
}

func writeKey(t *testing.T, dir, name, js string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(js), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestStoreReloadAndRevocation(t *testing.T) {
	dir := t.TempDir()
	writeKey(t, dir, "a.json", fixtureAdmin)
	writeKey(t, dir, "v.json", fixtureViewer)
	writeKey(t, dir, "notes.txt", "ignored")
	s := NewStore(dir, nil)
	s.Reload()
	if s.Count() != 2 {
		t.Fatalf("count = %d", s.Count())
	}
	k, err := s.Authenticate("adminsecret0123456789")
	if err != nil || !k.IsAdmin() {
		t.Fatalf("admin auth: %v", err)
	}
	if _, err := s.Authenticate("nope"); err != ErrUnknownKey {
		t.Fatalf("unknown key err = %v", err)
	}
	if _, err := s.Authenticate(""); err != ErrUnknownKey {
		t.Fatalf("empty key err = %v", err)
	}

	// A half-written file keeps the previous version.
	writeKey(t, dir, "v.json", `{"id":"v-1","key":"viewer`)
	bumpMtime(t, filepath.Join(dir, "v.json"))
	s.Reload()
	if _, err := s.Authenticate("viewersecret"); err != nil {
		t.Fatalf("corrupt rewrite should keep previous key: %v", err)
	}

	// Deleting a file revokes it immediately.
	os.Remove(filepath.Join(dir, "v.json"))
	s.Reload()
	if _, err := s.Authenticate("viewersecret"); err != ErrUnknownKey {
		t.Fatalf("deleted key still valid: %v", err)
	}

	// A new corrupt file is ignored (and logged), not fatal.
	writeKey(t, dir, "bad.json", `{oops`)
	s.Reload()
	if s.Count() != 1 {
		t.Fatalf("count after bad file = %d", s.Count())
	}
}

func bumpMtime(t *testing.T, path string) {
	t.Helper()
	future := time.Now().Add(2 * time.Second)
	if err := os.Chtimes(path, future, future); err != nil {
		t.Fatal(err)
	}
}

func TestStoreMissingDirThenCreated(t *testing.T) {
	parent := t.TempDir()
	dir := filepath.Join(parent, "keys")
	s := NewStore(dir, nil)
	s.Reload()
	if s.Count() != 0 {
		t.Fatal("expected no keys")
	}
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	writeKey(t, dir, "a.json", fixtureAdmin)
	s.Reload()
	if _, err := s.Authenticate("adminsecret0123456789"); err != nil {
		t.Fatalf("key in late-created dir not loaded: %v", err)
	}
}

func TestStoreAllowlist(t *testing.T) {
	dir := t.TempDir()
	writeKey(t, dir, "a.json", fixtureAdmin)
	writeKey(t, dir, "v.json", fixtureViewer)
	writeKey(t, dir, "g.json", fixtureGuest)
	restrict := true
	allowed := []string{"7c1d4f1e-2b5a-4c39-9d0e-0f6a1b2c3d4e", "guestsecret"} // id + legacy raw secret
	s := NewStore(dir, func() (bool, []string) { return restrict, allowed })
	s.Reload()

	if _, err := s.Authenticate("adminsecret0123456789"); err != nil {
		t.Fatalf("allowlisted by id: %v", err)
	}
	if _, err := s.Authenticate("guestsecret"); err != nil {
		t.Fatalf("allowlisted by legacy secret: %v", err)
	}
	if k, err := s.Authenticate("viewersecret"); err != ErrKeyNotAllowed || k == nil {
		t.Fatalf("not allowlisted: k=%v err=%v", k, err)
	}
	restrict = false
	if _, err := s.Authenticate("viewersecret"); err != nil {
		t.Fatalf("restriction off: %v", err)
	}
}

func TestStoreWatchPicksUpLateKeysDir(t *testing.T) {
	parent := t.TempDir()
	dir := filepath.Join(parent, "keys")
	s := NewStore(dir, nil)
	s.Reload()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go s.Watch(ctx)
	time.Sleep(200 * time.Millisecond) // let the watcher register the parent

	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	time.Sleep(time.Second) // debounce + watch on the new directory
	writeKey(t, dir, "a.json", fixtureAdmin)

	waitFor := func(cond func() bool, what string) {
		t.Helper()
		deadline := time.Now().Add(5 * time.Second)
		for !cond() {
			if time.Now().After(deadline) {
				t.Fatalf("timed out waiting for %s", what)
			}
			time.Sleep(50 * time.Millisecond)
		}
	}
	waitFor(func() bool { _, err := s.Authenticate("adminsecret0123456789"); return err == nil }, "key in late-created dir")

	os.Remove(filepath.Join(dir, "a.json"))
	waitFor(func() bool { _, err := s.Authenticate("adminsecret0123456789"); return err == ErrUnknownKey }, "revocation on delete")
}

func TestStoreBrokenKeyGracePeriod(t *testing.T) {
	dir := t.TempDir()
	writeKey(t, dir, "v.json", fixtureViewer)
	s := NewStore(dir, nil)
	s.Reload()
	writeKey(t, dir, "v.json", `{broken`)
	bumpMtime(t, filepath.Join(dir, "v.json"))
	s.Reload()
	if _, err := s.Authenticate("viewersecret"); err != nil {
		t.Fatal("key should survive within the grace period")
	}
	// Age the failure past the grace period.
	s.mu.Lock()
	f := s.failed["v.json"]
	f.since = time.Now().Add(-parseGrace - time.Second)
	s.failed["v.json"] = f
	s.mu.Unlock()
	s.Reload()
	if _, err := s.Authenticate("viewersecret"); err != ErrUnknownKey {
		t.Fatalf("key still valid after grace period: %v", err)
	}
}
