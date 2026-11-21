package api

import "github.com/routecore/raidman-plugin/src/internal/service/auth"

// The key fixtures in api_test.go (testKeyFiles) and security_test.go predate
// auth.RequireCreatedAt and have no "createdAt". Relax the check for this
// package's tests only; the auth package tests the strict default. Remove
// this file once those fixtures carry createdAt.
func init() { auth.RequireCreatedAt = false }
