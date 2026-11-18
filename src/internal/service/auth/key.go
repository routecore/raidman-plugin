package auth

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
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
	ID          string            `json:"id"`
	Name        string            `json:"name"`
	Key         string            `json:"key"`
	Roles       []json.RawMessage `json:"roles"`
	Permissions []json.RawMessage `json:"permissions"`
}

// ErrNoSecret is returned when a key file has no "key" field.
var ErrNoSecret = errors.New("key file has no secret")

// ParseKey decodes an upstream API key file. It accepts:
//   - the current upstream shape: roles: ["ADMIN"], permissions: [{resource, actions[]}]
//   - lower/mixed-case roles, resources and actions
//   - legacy actions ("read", "read:any", "READ") normalised like upstream's
//     normalizeLegacyActions
//   - legacy string scopes in permissions ("docker:read", "docker:*", "role:viewer")
//
// Unknown roles, resources or actions are skipped (they grant nothing) and
// reported in warnings. A structurally invalid file returns an error.
func ParseKey(data []byte) (*Key, []string, error) {
	var raw rawKey
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, nil, fmt.Errorf("invalid JSON: %w", err)
	}
	if raw.Key == "" {
		return nil, nil, ErrNoSecret
	}

	k := &Key{
		ID:     raw.ID,
		Name:   raw.Name,
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
	addRole := func(role string) {
		for _, r := range k.Roles {
			if r == role {
				return
			}
		}
		k.Roles = append(k.Roles, role)
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
			warnings = append(warnings, fmt.Sprintf("ignoring non-string role %s", string(rr)))
			continue
		}
		role, ok := NormalizeRole(s)
		if !ok {
			warnings = append(warnings, fmt.Sprintf("ignoring unknown role %q", s))
			continue
		}
		addRole(role)
	}

	for _, rp := range raw.Permissions {
		// Legacy string scope.
		var scope string
		if err := json.Unmarshal(rp, &scope); err == nil {
			role, res, acts, ok := parseScope(scope)
			if !ok {
				warnings = append(warnings, fmt.Sprintf("ignoring unknown permission scope %q", scope))
				continue
			}
			if role != "" {
				addRole(role)
			} else {
				addPerm(res, acts)
			}
			continue
		}
		// Upstream object form.
		var obj struct {
			Resource string   `json:"resource"`
			Actions  []string `json:"actions"`
		}
		if err := json.Unmarshal(rp, &obj); err != nil {
			warnings = append(warnings, fmt.Sprintf("ignoring malformed permission %s", string(rp)))
			continue
		}
		res, ok := NormalizeResource(obj.Resource)
		if !ok {
			warnings = append(warnings, fmt.Sprintf("ignoring permission for unknown resource %q", obj.Resource))
			continue
		}
		var acts []string
		for _, a := range obj.Actions {
			na, ok := NormalizeLegacyAction(a)
			if !ok {
				warnings = append(warnings, fmt.Sprintf("ignoring unknown action %q on %s", a, res))
				continue
			}
			if !contains(acts, na) {
				acts = append(acts, na)
			}
		}
		if len(acts) == 0 {
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
