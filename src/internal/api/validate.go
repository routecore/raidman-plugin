package api

import (
	"errors"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"
)

// Docker container names/ids: first char alphanumeric, then [A-Za-z0-9_.-]
// (same rule the Docker daemon enforces). This also rules out a leading '-'
// that a CLI could read as an option.
var containerRefRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,254}$`)

// iconNameRe restricts VM icon file names (served from the VM manager's
// image directory).
var iconNameRe = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}$`)

var (
	errMissingContainer = errors.New("container param missing")
	errInvalidContainer = errors.New("invalid container id")
	errMissingVM        = errors.New("vm param missing")
	errInvalidVM        = errors.New("invalid vm name")
)

// normalizeContainerRef accepts a raw Docker id, a container name, or an
// upstream Unraid API PrefixedID ("<serverId>:<id>"), strips everything up to
// and including the last ':' and validates the remainder.
func normalizeContainerRef(ref string) (string, error) {
	ref = strings.TrimSpace(ref)
	if ref == "" {
		return "", errMissingContainer
	}
	if i := strings.LastIndex(ref, ":"); i >= 0 {
		ref = ref[i+1:]
	}
	ref = strings.TrimPrefix(ref, "/") // inspect-style "/name"
	if !containerRefRe.MatchString(ref) {
		return "", errInvalidContainer
	}
	return ref, nil
}

// validateVMRef accepts any libvirt domain name (spaces, parentheses,
// Unicode, ...) or UUID. Names never reach a shell: they go to libvirt over
// RPC or to argv after resolution. Rejected: empty, invalid UTF-8, control
// characters, '/', a leading '-' (could be read as an option) and overlong
// values.
func validateVMRef(ref string) error {
	if ref == "" {
		return errMissingVM
	}
	if len(ref) > 512 || !utf8.ValidString(ref) || strings.HasPrefix(ref, "-") || strings.ContainsRune(ref, '/') {
		return errInvalidVM
	}
	for _, r := range ref {
		if unicode.IsControl(r) {
			return errInvalidVM
		}
	}
	return nil
}

func validIconName(name string) bool {
	return iconNameRe.MatchString(name) && !strings.Contains(name, "..")
}
