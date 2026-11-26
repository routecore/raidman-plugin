//go:build linux

package api

import (
	"syscall"

	"golang.org/x/sys/unix"
)

// pidfdOpen opens a pidfd for pid (Linux 5.3+; ENOSYS before).
func pidfdOpen(pid int) (int, error) { return unix.PidfdOpen(pid, 0) }

// pidfdSignal sends sig to the process a pidfd refers to: never to a later
// process that reused its pid.
func pidfdSignal(fd int, sig syscall.Signal) error { return unix.PidfdSendSignal(fd, sig, nil, 0) }

func pidfdClose(fd int) { _ = unix.Close(fd) }
