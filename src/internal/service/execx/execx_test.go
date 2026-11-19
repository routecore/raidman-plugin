package execx

import (
	"context"
	"testing"
	"time"
)

func TestRunExitCodeAndArgv(t *testing.T) {
	// argv is passed verbatim: no shell expands "$HOME" or ";".
	res, err := Run(context.Background(), "/bin/echo", "$HOME;", "x")
	if err != nil || res.ExitCode != 0 || string(res.Stdout) != "$HOME; x\n" {
		t.Fatalf("echo: %+v %v", res, err)
	}
	res, err = Run(context.Background(), "/bin/sh", "-c", "exit 3")
	if err != nil || res.ExitCode != 3 {
		t.Fatalf("exit 3: %+v %v", res, err)
	}
	if _, err := Run(context.Background(), "/nonexistent/binary"); err == nil {
		t.Fatal("missing binary must error")
	}
}

func TestRunTimeout(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	start := time.Now()
	if _, err := Run(ctx, "/bin/sleep", "5"); err == nil {
		t.Fatal("timeout must error")
	}
	if time.Since(start) > 3*time.Second {
		t.Fatal("timeout not enforced")
	}
}

func TestCapped(t *testing.T) {
	var c capped
	big := make([]byte, MaxOutput+10)
	if n, _ := c.Write(big); n != len(big) || c.Len() != MaxOutput {
		t.Fatalf("n=%d len=%d", n, c.Len())
	}
}
