package array

import (
	"fmt"
	"os"
	"strings"

	"github.com/routecore/raidman-plugin/src/internal/service/emhttp"
)

// Encryption statuses, in the webGUI's words (Main → Array Operation).
const (
	EncryptionNone    = "none"    // no encrypted disk: plain Start
	EncryptionNew     = "new"     // "Enter new key": passphrase typed twice, or a keyfile
	EncryptionMissing = "missing" // "Missing key": passphrase or keyfile
	EncryptionWrong   = "wrong"   // "Wrong key": passphrase or keyfile (keyfile only while one is saved)
	EncryptionPresent = "present" // the key is loaded: plain Start
)

// Encryption is GET /api/array/encryption: what the webGUI's Start row asks
// for before it lets an encrypted array start.
type Encryption struct {
	Status string `json:"status"`
	// Keyfile is true while var.ini's luksKeyfile exists on the server.
	Keyfile bool `json:"keyfile"`
}

// GetEncryption mirrors the encryption check of the webGUI's
// ArrayOperation.page: it looks at the Data and Cache slots of disks.ini
// (empty slots too, which emhttp lists with fsType "auto") and var.ini's
// defaultFsType and luksKeyfile. Only state files are read; no disk is touched.
func GetEncryption() (Encryption, error) {
	enc, _, err := readEncryption()
	return enc, err
}

// DeleteKeyfile is the webGUI's "Delete (will delete the encryption keyfile)"
// on a stopped array whose saved keyfile is the wrong key: it removes var.ini's
// luksKeyfile so a passphrase can be entered instead. Anything else is refused,
// like the webGUI, which only offers it in that state. Returns the new status.
func DeleteKeyfile() (Encryption, error) {
	enc, vars, err := readEncryption()
	if err != nil {
		return Encryption{}, err
	}
	if vars["mdState"] == "STARTED" || (vars["fsState"] != "" && vars["fsState"] != "Stopped") {
		return Encryption{}, conflict("the array is not stopped")
	}
	if enc.Status != EncryptionWrong || !enc.Keyfile {
		return Encryption{}, conflict("no wrong keyfile to delete (status %s)", enc.Status)
	}
	if err := os.Remove(vars["luksKeyfile"]); err != nil && !os.IsNotExist(err) {
		return Encryption{}, fmt.Errorf("could not delete the keyfile: %w", err)
	}
	enc.Keyfile = false
	return enc, nil
}

func readEncryption() (Encryption, map[string]string, error) {
	disks, err := parseIniSections(DisksIniPath)
	if err != nil {
		return Encryption{}, nil, fmt.Errorf("could not read disk state: %w", err)
	}
	vars, err := emhttp.ReadIni(VarIniPath)
	if err != nil {
		return Encryption{}, nil, fmt.Errorf("could not read array state: %w", err)
	}
	defaultLuks := strings.HasPrefix(vars["defaultFsType"], "luks:")

	var forced, present, missing, wrong bool
	for _, d := range disks {
		if d["type"] != "Data" && d["type"] != "Cache" {
			continue
		}
		fsType := d["fsType"]
		luks := strings.HasPrefix(fsType, "luks:")
		auto := fsType == "auto"
		if luks || (auto && defaultLuks) {
			forced = true
		}
		if luks || auto {
			switch strings.TrimSpace(d["luksState"]) {
			case "1":
				present = true
			case "2":
				missing = true
			case "3":
				wrong = true
			}
		}
	}

	out := Encryption{Status: EncryptionNone}
	if path := vars["luksKeyfile"]; path != "" {
		if info, err := os.Stat(path); err == nil && !info.IsDir() {
			out.Keyfile = true
		}
	}
	// Same precedence as the webGUI: a known key state wins over "new key",
	// then missing, then wrong; present needs no input.
	switch {
	case present || missing || wrong:
		switch {
		case missing:
			out.Status = EncryptionMissing
		case wrong:
			out.Status = EncryptionWrong
		default:
			out.Status = EncryptionPresent
		}
	case forced:
		out.Status = EncryptionNew
	}
	return out, vars, nil
}
