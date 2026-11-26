//go:build !linux

package api

import (
	"errors"
	"syscall"
)

// No pidfds outside Linux (development builds): signals go by pid.
func pidfdOpen(int) (int, error)            { return -1, errors.ErrUnsupported }
func pidfdSignal(int, syscall.Signal) error { return errors.ErrUnsupported }
func pidfdClose(int)                        {}
