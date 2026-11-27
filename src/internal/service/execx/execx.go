// Package execx runs host commands with argv only (never a shell), a
// context deadline and bounded output.
package execx

import (
	"bytes"
	"context"
	"errors"
	"os/exec"
	"time"
)

// MaxOutput bounds each captured stream; the head is kept and the rest is
// dropped (commands here print a few KB at most).
const MaxOutput = 1 << 20

// Result of a finished command. ExitCode is -1 when the command could not be
// started or was killed.
type Result struct {
	Stdout   []byte
	Stderr   []byte
	ExitCode int
}

// Runner runs name with args until it exits or ctx ends.
type Runner func(ctx context.Context, name string, args ...string) (Result, error)

// Run is the real Runner. A non-zero exit is not an error (callers decide):
// err is only set when the command could not run or ctx ended.
func Run(ctx context.Context, name string, args ...string) (Result, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	var out, errb capped
	cmd.Stdout = &out
	cmd.Stderr = &errb
	// Grandchildren that keep the pipes open must not hang the caller
	// after the command itself exited or was killed.
	cmd.WaitDelay = 5 * time.Second
	err := cmd.Run()
	res := Result{Stdout: out.Bytes(), Stderr: errb.Bytes(), ExitCode: -1}
	if cmd.ProcessState != nil {
		res.ExitCode = cmd.ProcessState.ExitCode()
	}
	if ctx.Err() != nil {
		return res, ctx.Err()
	}
	var ee *exec.ExitError
	if err != nil && errors.As(err, &ee) {
		return res, nil
	}
	if errors.Is(err, exec.ErrWaitDelay) {
		return res, nil
	}
	return res, err
}

// capped is a bytes.Buffer that silently stops growing at MaxOutput.
type capped struct{ bytes.Buffer }

func (c *capped) Write(p []byte) (int, error) {
	if room := MaxOutput - c.Len(); room > 0 {
		if len(p) > room {
			c.Buffer.Write(p[:room])
		} else {
			c.Buffer.Write(p)
		}
	}
	return len(p), nil
}
