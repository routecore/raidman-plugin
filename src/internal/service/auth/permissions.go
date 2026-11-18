package auth

import "strings"

// Upstream enums, mirrored from @unraid/shared (packages/unraid-shared/src/graphql-enums.ts).

// Actions (AuthAction).
const (
	ActionCreateAny = "CREATE_ANY"
	ActionCreateOwn = "CREATE_OWN"
	ActionReadAny   = "READ_ANY"
	ActionReadOwn   = "READ_OWN"
	ActionUpdateAny = "UPDATE_ANY"
	ActionUpdateOwn = "UPDATE_OWN"
	ActionDeleteAny = "DELETE_ANY"
	ActionDeleteOwn = "DELETE_OWN"
)

// Resources used by the plugin's route table (subset of upstream Resource).
const (
	ResourceAPIKey              = "API_KEY"
	ResourceArray               = "ARRAY"
	ResourceConnectRemoteAccess = "CONNECT__REMOTE_ACCESS"
	ResourceDocker              = "DOCKER"
	ResourceMe                  = "ME"
	ResourceVMs                 = "VMS"
)

// Roles (Role).
const (
	RoleAdmin   = "ADMIN"
	RoleConnect = "CONNECT"
	RoleGuest   = "GUEST"
	RoleViewer  = "VIEWER"
)

var allActions = []string{
	ActionCreateAny, ActionCreateOwn,
	ActionReadAny, ActionReadOwn,
	ActionUpdateAny, ActionUpdateOwn,
	ActionDeleteAny, ActionDeleteOwn,
}

// allResources mirrors the upstream Resource enum (v4.37.12).
var allResources = []string{
	"ACTIVATION_CODE", "API_KEY", "ARRAY", "CLOUD", "CONFIG", "CONNECT",
	"CONNECT__REMOTE_ACCESS", "CUSTOMIZATIONS", "DASHBOARD", "DISK", "DISPLAY",
	"DOCKER", "FLASH", "INFO", "LOGS", "ME", "NETWORK", "NOTIFICATIONS", "ONLINE",
	"OS", "OWNER", "PERMISSION", "REGISTRATION", "SERVERS", "SERVICES", "SHARE",
	"VARS", "VMS", "WELCOME",
}

var (
	actionSet   = toSet(allActions)
	resourceSet = toSet(allResources)
	roleSet     = toSet([]string{RoleAdmin, RoleConnect, RoleGuest, RoleViewer})
)

func toSet(in []string) map[string]bool {
	m := make(map[string]bool, len(in))
	for _, s := range in {
		m[s] = true
	}
	return m
}

// parseActionToAuthAction mirrors upstream parseActionToAuthAction
// (packages/unraid-shared/src/util/permissions.ts).
func parseActionToAuthAction(action string) (string, bool) {
	if action == "" {
		return "", false
	}
	if actionSet[action] {
		return action, true
	}
	normalized := strings.ToUpper(strings.TrimSpace(action))
	if strings.Contains(normalized, ":") {
		parts := strings.Split(normalized, ":")
		if len(parts) != 2 {
			return "", false
		}
		if parts[1] != "ANY" && parts[1] != "OWN" {
			return "", false
		}
		normalized = parts[0] + "_" + parts[1]
	}
	if actionSet[normalized] {
		return normalized, true
	}
	parts := strings.Split(normalized, "_")
	if len(parts) == 1 {
		switch parts[0] {
		case "CREATE", "READ", "UPDATE", "DELETE":
			return parts[0] + "_ANY", true
		}
	}
	return "", false
}

// NormalizeLegacyAction mirrors upstream normalizeLegacyAction: it accepts
// "read", "READ", "read:any", "READ_ANY", "update:own", ... and returns the
// AuthAction enum value. Unknown values (including "*") are rejected, exactly
// like upstream, so they never grant anything.
func NormalizeLegacyAction(action string) (string, bool) {
	lower := strings.ToLower(action)
	var s string
	switch {
	case strings.Contains(lower, ":"):
		s = lower
	case strings.Contains(action, "_"):
		s = strings.Replace(lower, "_", ":", 1)
	case lower == "create" || lower == "read" || lower == "update" || lower == "delete":
		s = lower + ":any"
	default:
		s = lower
	}
	return parseActionToAuthAction(s)
}

// NormalizeResource upper-cases a resource name and checks it against the
// upstream enum.
func NormalizeResource(resource string) (string, bool) {
	r := strings.ToUpper(strings.TrimSpace(resource))
	return r, resourceSet[r]
}

// NormalizeRole upper-cases a role and checks it against the upstream enum.
func NormalizeRole(role string) (string, bool) {
	r := strings.ToUpper(strings.TrimSpace(role))
	return r, roleSet[r]
}

// roleGrants expands a role the way upstream's casbin BASE_POLICY does
// (api/src/unraid-api/auth/casbin/policy.ts):
//
//	p, ADMIN, *, *
//	p, CONNECT, CONNECT__REMOTE_ACCESS, UPDATE_ANY
//	p, GUEST, ME, READ_ANY
//	p, VIEWER, <every resource except API_KEY>, READ_ANY
//	g, ADMIN, GUEST ; g, CONNECT, VIEWER ; g, VIEWER, GUEST
//
// ADMIN is handled separately (wildcard) and is not expanded here.
func roleGrants(role string, add func(resource, action string)) {
	switch role {
	case RoleGuest:
		add(ResourceMe, ActionReadAny)
	case RoleViewer:
		roleGrants(RoleGuest, add)
		for _, r := range allResources {
			if r != ResourceAPIKey {
				add(r, ActionReadAny)
			}
		}
	case RoleConnect:
		roleGrants(RoleViewer, add)
		add(ResourceConnectRemoteAccess, ActionUpdateAny)
	}
}

// parseScope mirrors upstream convertScopesToPermissions for a single legacy
// string scope such as "docker:read", "docker:*" or "role:viewer".
// It returns either a role, or a resource with its actions.
func parseScope(scope string) (role string, resource string, actions []string, ok bool) {
	if strings.HasPrefix(scope, "role:") {
		r, ok := NormalizeRole(scope[len("role:"):])
		return r, "", nil, ok
	}
	idx := strings.Index(scope, ":")
	if idx <= 0 {
		return "", "", nil, false
	}
	res, ok := NormalizeResource(scope[:idx])
	if !ok {
		return "", "", nil, false
	}
	act := strings.TrimSpace(scope[idx+1:])
	if act == "*" {
		return "", res, []string{ActionCreateAny, ActionReadAny, ActionUpdateAny, ActionDeleteAny}, true
	}
	a, ok := parseActionToAuthAction(act)
	if !ok {
		return "", "", nil, false
	}
	return "", res, []string{a}, true
}
