package array

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// slot is one disks.ini section: type, fsType, luksState.
type slot struct{ name, typ, fs, luks string }

func writeEncryptionFixture(t *testing.T, defaultFs string, keyfile bool, slots []slot) string {
	t.Helper()
	dir := t.TempDir()
	var disks strings.Builder
	for _, s := range slots {
		disks.WriteString("[\"" + s.name + "\"]\nname=\"" + s.name + "\"\ntype=\"" + s.typ + "\"\nluksState=\"" + s.luks + "\"\nfsType=\"" + s.fs + "\"\n")
	}
	keyPath := filepath.Join(dir, "keyfile")
	if keyfile {
		if err := os.WriteFile(keyPath, []byte("k"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	vars := "mdState=\"STOPPED\"\nfsState=\"Stopped\"\ndefaultFsType=\"" + defaultFs + "\"\nluksKeyfile=\"" + keyPath + "\"\n"
	DisksIniPath = filepath.Join(dir, "disks.ini")
	VarIniPath = filepath.Join(dir, "var.ini")
	if err := os.WriteFile(DisksIniPath, []byte(disks.String()), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(VarIniPath, []byte(vars), 0o600); err != nil {
		t.Fatal(err)
	}
	return keyPath
}

func TestGetEncryption(t *testing.T) {
	oldDisks, oldVar := DisksIniPath, VarIniPath
	t.Cleanup(func() { DisksIniPath, VarIniPath = oldDisks, oldVar })

	cases := []struct {
		name      string
		defaultFs string
		keyfile   bool
		slots     []slot
		want      Encryption
	}{
		{"plain array", "xfs", false,
			[]slot{{"parity", "Parity", "", "0"}, {"disk1", "Data", "xfs", "0"}, {"disk2", "Data", "auto", "0"}, {"cache", "Cache", "btrfs", "0"}},
			Encryption{Status: EncryptionNone}},
		{"no disks", "xfs", false, nil, Encryption{Status: EncryptionNone}},
		{"key loaded", "xfs", false,
			[]slot{{"disk1", "Data", "luks:xfs", "1"}, {"disk2", "Data", "xfs", "0"}},
			Encryption{Status: EncryptionPresent}},
		{"missing key", "xfs", false,
			[]slot{{"disk1", "Data", "luks:xfs", "2"}, {"disk2", "Data", "luks:xfs", "2"}},
			Encryption{Status: EncryptionMissing}},
		{"wrong key with a saved keyfile", "xfs", true,
			[]slot{{"disk1", "Data", "luks:xfs", "3"}},
			Encryption{Status: EncryptionWrong, Keyfile: true}},
		{"missing beats wrong", "xfs", false,
			[]slot{{"disk1", "Data", "luks:xfs", "3"}, {"cache", "Cache", "luks:btrfs", "2"}},
			Encryption{Status: EncryptionMissing}},
		{"encrypted disk not yet unlocked asks for a new key", "xfs", false,
			[]slot{{"disk1", "Data", "luks:xfs", "0"}},
			Encryption{Status: EncryptionNew}},
		// Empty slots are listed with fsType "auto": the webGUI counts them as
		// "to be encrypted" when the default file system is an encrypted one.
		{"encrypted default file system asks for a new key", "luks:xfs", false,
			[]slot{{"disk1", "Data", "xfs", "0"}, {"disk2", "Data", "auto", "0"}},
			Encryption{Status: EncryptionNew}},
		{"new key loses to a known key state", "luks:xfs", false,
			[]slot{{"disk1", "Data", "luks:xfs", "2"}, {"disk2", "Data", "auto", "0"}},
			Encryption{Status: EncryptionMissing}},
		{"parity and boot slots are ignored", "xfs", false,
			[]slot{{"parity", "Parity", "luks:xfs", "2"}, {"flash", "Flash", "luks:xfs", "2"}, {"disk1", "Data", "xfs", "2"}},
			Encryption{Status: EncryptionNone}},
		{"key state of an unencrypted disk is ignored", "xfs", false,
			[]slot{{"disk1", "Data", "btrfs", "3"}},
			Encryption{Status: EncryptionNone}},
		{"keyfile reported without encrypted disks", "xfs", true,
			[]slot{{"disk1", "Data", "xfs", "0"}},
			Encryption{Status: EncryptionNone, Keyfile: true}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			writeEncryptionFixture(t, c.defaultFs, c.keyfile, c.slots)
			got, err := GetEncryption()
			if err != nil {
				t.Fatal(err)
			}
			if got != c.want {
				t.Errorf("got %+v, want %+v", got, c.want)
			}
		})
	}
}

func TestGetEncryptionMissingStateFiles(t *testing.T) {
	oldDisks, oldVar := DisksIniPath, VarIniPath
	t.Cleanup(func() { DisksIniPath, VarIniPath = oldDisks, oldVar })

	DisksIniPath, VarIniPath = filepath.Join(t.TempDir(), "nope.ini"), "testdata/var.ini"
	if _, err := GetEncryption(); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("missing disks.ini: err = %v, want not-exist", err)
	}
	DisksIniPath, VarIniPath = "testdata/disks_state.ini", filepath.Join(t.TempDir(), "nope.ini")
	if _, err := GetEncryption(); err == nil {
		t.Error("missing var.ini must be an error")
	}
}

func TestDeleteKeyfile(t *testing.T) {
	oldDisks, oldVar := DisksIniPath, VarIniPath
	t.Cleanup(func() { DisksIniPath, VarIniPath = oldDisks, oldVar })
	wrong := []slot{{"disk1", "Data", "luks:xfs", "3"}}

	key := writeEncryptionFixture(t, "xfs", true, wrong)
	got, err := DeleteKeyfile()
	if err != nil {
		t.Fatal(err)
	}
	if got != (Encryption{Status: EncryptionWrong}) {
		t.Errorf("got %+v", got)
	}
	if _, err := os.Stat(key); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("keyfile still there: %v", err)
	}

	// Refused (409, keyfile kept) unless the saved keyfile is the wrong key on a stopped array.
	for _, c := range []struct {
		name    string
		keyfile bool
		slots   []slot
		started bool
	}{
		{"missing key", true, []slot{{"disk1", "Data", "luks:xfs", "2"}}, false},
		{"key loaded", true, []slot{{"disk1", "Data", "luks:xfs", "1"}}, false},
		{"no keyfile", false, wrong, false},
		{"array started", true, wrong, true},
	} {
		key := writeEncryptionFixture(t, "xfs", c.keyfile, c.slots)
		if c.started {
			if err := os.WriteFile(VarIniPath, []byte("mdState=\"STARTED\"\nfsState=\"Started\"\nluksKeyfile=\""+key+"\"\n"), 0o600); err != nil {
				t.Fatal(err)
			}
		}
		_, err := DeleteKeyfile()
		if StatusOf(err) != 409 {
			t.Errorf("%s: err = %v, want 409", c.name, err)
		}
		if _, statErr := os.Stat(key); c.keyfile && statErr != nil {
			t.Errorf("%s: keyfile removed", c.name)
		}
	}
}
