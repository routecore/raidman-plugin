// Package httperr carries an HTTP status from a service to the API layer.
package httperr

import (
	"errors"
	"fmt"
	"net/http"
)

// Error is a service error with the HTTP status the API should answer.
type Error struct {
	Status int
	Msg    string
}

func (e *Error) Error() string { return e.Msg }

// New returns an *Error with a formatted message.
func New(status int, format string, a ...any) error {
	return &Error{Status: status, Msg: fmt.Sprintf(format, a...)}
}

// StatusOf maps an error to an HTTP status (500 for unknown errors).
func StatusOf(err error) int {
	var e *Error
	if errors.As(err, &e) {
		return e.Status
	}
	return http.StatusInternalServerError
}
