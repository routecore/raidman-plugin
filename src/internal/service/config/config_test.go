package config

import (
	"os"
	"path/filepath"
	"testing"
)

func withSettingsFile(t *testing.T, content *string) {
	t.Helper()
	p := filepath.Join(t.TempDir(), "settings.json")
	if content != nil {
		if err := os.WriteFile(p, []byte(*content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	oldPath, oldSettings, oldLoaded := SettingsPath, currentSettings, loadedOnce
	SettingsPath, loadedOnce = p, false
	currentSettings = &Settings{HostTerminalEnabled: true, AllowedApiKeys: []string{}}
	t.Cleanup(func() { SettingsPath, currentSettings, loadedOnce = oldPath, oldSettings, oldLoaded })
}

func TestMissingSettingsUseDefaults(t *testing.T) {
	withSettingsFile(t, nil)
	LoadSettings()
	if s := GetSettings(); !s.HostTerminalEnabled || s.RestrictApiKeys {
		t.Fatalf("defaults changed: %+v", s)
	}
}

// A corrupt settings file at startup must not silently lift a key
// restriction or re-enable a disabled host terminal.
func TestCorruptSettingsFailClosedAtStartup(t *testing.T) {
	bad := `{"restrict_api_keys": true, "allowed_api_keys": ["id-1"` // truncated
	withSettingsFile(t, &bad)
	LoadSettings()
	s := GetSettings()
	if s.HostTerminalEnabled || !s.RestrictApiKeys || len(s.AllowedApiKeys) != 0 {
		t.Fatalf("not fail-closed: %+v", s)
	}
	restrict, allowed := AllowPolicy()
	if !restrict || len(allowed) != 0 {
		t.Fatal("allow policy must deny everything")
	}

	// Fixing the file restores normal operation.
	if err := os.WriteFile(SettingsPath, []byte(`{"host_terminal_enabled":true,"restrict_api_keys":false}`), 0o644); err != nil {
		t.Fatal(err)
	}
	LoadSettings()
	if s := GetSettings(); !s.HostTerminalEnabled || s.RestrictApiKeys || s.AllowedApiKeys == nil {
		t.Fatalf("valid settings not applied: %+v", s)
	}
}

func TestPartialWriteKeepsPreviousSettings(t *testing.T) {
	good := `{"host_terminal_enabled":false,"restrict_api_keys":true,"allowed_api_keys":["id-1"]}`
	withSettingsFile(t, &good)
	LoadSettings()
	if err := os.WriteFile(SettingsPath, []byte(`{"host_ter`), 0o644); err != nil {
		t.Fatal(err)
	}
	LoadSettings()
	s := GetSettings()
	if s.HostTerminalEnabled || !s.RestrictApiKeys || len(s.AllowedApiKeys) != 1 {
		t.Fatalf("previous settings lost: %+v", s)
	}
}

// Files written by every page version (old: booleans + list; legacy raw
// secrets in the list) and odd-but-valid shapes must parse, not fail closed.
func TestParseSettingsShapes(t *testing.T) {
	cases := map[string]Settings{
		`{"host_terminal_enabled": true, "restrict_api_keys": false, "allowed_api_keys": []}`:                                                Settings{HostTerminalEnabled: true},
		"{\n    \"host_terminal_enabled\": false,\n    \"restrict_api_keys\": true,\n    \"allowed_api_keys\": [\n        \"abc\"\n    ]\n}": Settings{RestrictApiKeys: true, AllowedApiKeys: []string{"abc"}},
		`{"host_terminal_enabled": "true", "restrict_api_keys": "1", "allowed_api_keys": {"3": "x"}}`:                                        Settings{HostTerminalEnabled: true, RestrictApiKeys: true, AllowedApiKeys: []string{"x"}},
		`{"restrict_api_keys": true, "allowed_api_keys": null, "extra": 1}`:                                                                  Settings{RestrictApiKeys: true},
		`{}`: Settings{},
	}
	for in, want := range cases {
		got, err := parseSettings([]byte(in))
		if err != nil {
			t.Errorf("%s: %v", in, err)
			continue
		}
		if got.HostTerminalEnabled != want.HostTerminalEnabled || got.RestrictApiKeys != want.RestrictApiKeys || len(got.AllowedApiKeys) != len(want.AllowedApiKeys) || got.AllowedApiKeys == nil {
			t.Errorf("%s: got %+v want %+v", in, got, want)
		}
		for i := range want.AllowedApiKeys {
			if got.AllowedApiKeys[i] != want.AllowedApiKeys[i] {
				t.Errorf("%s: keys %v", in, got.AllowedApiKeys)
			}
		}
	}
	for _, bad := range []string{`{"restrict_api_keys": {}}`, `{"allowed_api_keys": 5}`, `[1,2]`, `{"x":`} {
		if _, err := parseSettings([]byte(bad)); err == nil {
			t.Errorf("%s: want error", bad)
		}
	}
}
