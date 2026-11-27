package auth

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// Permission is the upstream permission shape: { resource, actions[] }.
type Permission struct {
	Resource string   `json:"resource"`
	Actions  []string `json:"actions"`
}

// Key is a parsed API key from the upstream key store
// (/boot/config/plugins/dynamix.my.servers/keys/<id>.json).
// The secret itself is never exposed; only its SHA-256 is kept.
type Key struct {
	ID          string
	Name        string
	Roles       []string
	Permissions []Permission

	hash   [32]byte
	admin  bool
	grants map[string]map[string]bool
}

// HashSecret returns the lookup hash for a raw key secret.
func HashSecret(secret string) [32]byte {
	return sha256.Sum256([]byte(secret))
}

// Hash returns the SHA-256 of the key secret.
func (k *Key) Hash() [32]byte { return k.hash }

// IsAdmin reports whether the key holds the ADMIN role. Only the role counts:
// no combination of explicit permissions makes a key ADMIN.
func (k *Key) IsAdmin() bool { return k != nil && k.admin }

// Has reports whether the key may perform action on resource, using upstream
// casbin semantics: exact (resource, action) match after role expansion, with
// ADMIN matching everything. *_OWN never satisfies *_ANY.
func (k *Key) Has(resource, action string) bool {
	if k == nil {
		return false
	}
	if k.admin {
		return true
	}
	acts, ok := k.grants[resource]
	return ok && acts[action]
}

// Label identifies the key in logs without revealing any part of the secret.
func (k *Key) Label() string {
	if k == nil {
		return "<none>"
	}
	switch {
	case k.Name != "" && k.ID != "":
		return fmt.Sprintf("%q (%s)", k.Name, k.ID)
	case k.ID != "":
		return k.ID
	case k.Name != "":
		return fmt.Sprintf("%q", k.Name)
	}
	return fmt.Sprintf("sha256:%x", k.hash[:6])
}

// GrantList returns the effective explicit grants as sorted "RESOURCE:ACTION"
// strings (role expansion included, ADMIN reported as "*:*"). Used in tests and
// diagnostics.
func (k *Key) GrantList() []string {
	if k.admin {
		return []string{"*:*"}
	}
	var out []string
	for r, acts := range k.grants {
		for a := range acts {
			out = append(out, r+":"+a)
		}
	}
	sort.Strings(out)
	return out
}

type rawKey struct {
	ID          *string           `json:"id"`
	Name        *string           `json:"name"`
	Key         string            `json:"key"`
	CreatedAt   *string           `json:"createdAt"`
	Roles       []json.RawMessage `json:"roles"`
	Permissions []json.RawMessage `json:"permissions"`
}

// RequireCreatedAt makes a key file without a non-empty createdAt string
// invalid, like upstream. Overridable in tests whose fixtures predate it.
var RequireCreatedAt = true

// ErrNoSecret is returned when a key file has no "key" field.
var ErrNoSecret = errors.New("key file has no secret")

// enumShaped matches names shaped like an upstream Resource enum value. An
// unknown resource of this shape is most likely one a newer Unraid API added,
// so it is skipped instead of invalidating the key.
var enumShaped = regexp.MustCompile(`^[A-Z][A-Z0-9_]*$`)

// ParseKey decodes an upstream API key file and accepts only files the
// Unraid API itself accepts (loadApiKeyFile: roles upper-cased, actions run
// through normalizeLegacyActions, then class-validator on the ApiKey model),
// so a key Unraid ignores - and therefore does not show in its API Keys page -
// never works against RaidMan. The whole key is rejected (error) when:
//   - id, name or createdAt is missing or empty, or id is not a plain file
//     name
//   - roles or permissions is missing or not an array
//   - a role is not a string or, upper-cased, not an upstream Role
//   - a permission is not a {resource, actions[]} object (legacy string
//     scopes included), or none of its actions is a known AuthAction
//
// Normalisation kept from upstream: role case, legacy actions ("read",
// "read:any", "READ"). Resource case is also folded. A resource that is not
// in the mirrored enum but is shaped like one (a resource added by a newer
// Unraid API) is skipped with a warning and grants nothing; any other
// unknown resource rejects the key. Unknown actions next to known ones are
// dropped, like upstream.
func ParseKey(data []byte) (*Key, []string, error) {
	var raw rawKey
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, nil, fmt.Errorf("invalid JSON: %w", err)
	}
	if raw.Key == "" {
		return nil, nil, ErrNoSecret
	}
	if raw.ID == nil || *raw.ID == "" {
		return nil, nil, errors.New("key file has no id")
	}
	if id := *raw.ID; id == "." || id == ".." || strings.ContainsAny(id, "/\\:\x00") {
		return nil, nil, fmt.Errorf("invalid key id %q", id)
	}
	if raw.Name == nil || *raw.Name == "" {
		return nil, nil, errors.New("key file has no name")
	}
	if RequireCreatedAt && (raw.CreatedAt == nil || *raw.CreatedAt == "") {
		return nil, nil, errors.New("key file has no createdAt")
	}
	if raw.Roles == nil {
		return nil, nil, errors.New("key file has no roles array")
	}
	if raw.Permissions == nil {
		return nil, nil, errors.New("key file has no permissions array")
	}

	k := &Key{
		ID:     *raw.ID,
		Name:   *raw.Name,
		hash:   HashSecret(raw.Key),
		grants: map[string]map[string]bool{},
	}
	var warnings []string

	add := func(resource, action string) {
		m, ok := k.grants[resource]
		if !ok {
			m = map[string]bool{}
			k.grants[resource] = m
		}
		m[action] = true
	}
	addPerm := func(resource string, actions []string) {
		for i := range k.Permissions {
			if k.Permissions[i].Resource == resource {
				for _, a := range actions {
					if !contains(k.Permissions[i].Actions, a) {
						k.Permissions[i].Actions = append(k.Permissions[i].Actions, a)
					}
				}
				return
			}
		}
		k.Permissions = append(k.Permissions, Permission{Resource: resource, Actions: append([]string(nil), actions...)})
	}

	for _, rr := range raw.Roles {
		var s string
		if err := json.Unmarshal(rr, &s); err != nil {
			return nil, nil, fmt.Errorf("non-string role %s", string(rr))
		}
		// Upstream upper-cases roles (no trimming) before the enum check.
		role := strings.ToUpper(s)
		if !roleSet[role] {
			return nil, nil, fmt.Errorf("unknown role %q", s)
		}
		if !contains(k.Roles, role) {
			k.Roles = append(k.Roles, role)
		}
	}

	for _, rp := range raw.Permissions {
		var obj struct {
			Resource *string  `json:"resource"`
			Actions  []string `json:"actions"`
		}
		if len(rp) == 0 || rp[0] != '{' {
			return nil, nil, fmt.Errorf("permission is not an object: %s", string(rp))
		}
		if err := json.Unmarshal(rp, &obj); err != nil || obj.Resource == nil {
			return nil, nil, fmt.Errorf("malformed permission %s", string(rp))
		}
		var acts []string
		for _, a := range obj.Actions {
			na, ok := NormalizeLegacyAction(a)
			if !ok {
				warnings = append(warnings, fmt.Sprintf("ignoring unknown action %q on %s", a, *obj.Resource))
				continue
			}
			if !contains(acts, na) {
				acts = append(acts, na)
			}
		}
		if len(acts) == 0 {
			// Upstream: ArrayMinSize(1) after normalizeLegacyActions.
			return nil, nil, fmt.Errorf("permission on %q has no valid actions", *obj.Resource)
		}
		res, ok := NormalizeResource(*obj.Resource)
		if !ok {
			if !enumShaped.MatchString(res) {
				return nil, nil, fmt.Errorf("invalid resource %q", *obj.Resource)
			}
			warnings = append(warnings, fmt.Sprintf("ignoring permission for unknown resource %q", *obj.Resource))
			continue
		}
		addPerm(res, acts)
	}

	for _, role := range k.Roles {
		if role == RoleAdmin {
			k.admin = true
		}
		roleGrants(role, add)
	}
	for _, p := range k.Permissions {
		for _, a := range p.Actions {
			add(p.Resource, a)
		}
	}
	if len(k.Roles) == 0 && len(k.Permissions) == 0 {
		warnings = append(warnings, "key has no usable roles or permissions")
	}
	return k, warnings, nil
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

// describeGrants is a compact human description for logs.
func describeGrants(k *Key) string {
	if k.admin {
		return "ADMIN"
	}
	parts := []string{}
	if len(k.Roles) > 0 {
		parts = append(parts, "roles="+strings.Join(k.Roles, ","))
	}
	if len(k.Permissions) > 0 {
		var ps []string
		for _, p := range k.Permissions {
			ps = append(ps, p.Resource+"["+strings.Join(p.Actions, ",")+"]")
		}
		parts = append(parts, "perms="+strings.Join(ps, " "))
	}
	return strings.Join(parts, " ")
}
