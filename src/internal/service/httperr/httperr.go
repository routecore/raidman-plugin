// Package httperr carries an HTTP status from a service to the API layer.
package httperr

import (
	"errors"
	"fmt"
	"net/http"
)

// CodeNotFound is the machine-readable code for a missing resource
// (container, disk, path, plugin...). Missing resources are answered with
// 422, never 404: the app reads any plugin 404 as "route missing, plugin
// outdated". The code lets it tell "this thing is gone" apart from other 422s.
const CodeNotFound = "not_found"

// Error is a service error with the HTTP status the API should answer and an
// optional machine-readable Code (sent as "code" next to "error").
type Error struct {
	Status int
	Msg    string
	Code   string
}

func (e *Error) Error() string { return e.Msg }

// New returns an *Error with a formatted message.
func New(status int, format string, a ...any) error {
	return &Error{Status: status, Msg: fmt.Sprintf(format, a...)}
}

// NotFound returns a missing-resource error: 422 with CodeNotFound.
func NotFound(format string, a ...any) error {
	return &Error{Status: http.StatusUnprocessableEntity, Code: CodeNotFound, Msg: fmt.Sprintf(format, a...)}
}

// StatusOf maps an error to an HTTP status (500 for unknown errors).
func StatusOf(err error) int {
	var e *Error
	if errors.As(err, &e) {
		return e.Status
	}
	return http.StatusInternalServerError
}

// CodeOf returns the error's machine-readable code ("" if none).
func CodeOf(err error) string {
	var e *Error
	if errors.As(err, &e) {
		return e.Code
	}
	return ""
}
