package vm

import (
	"errors"
	"io"
	"net"
	"runtime"
	"testing"
	"time"

	"github.com/digitalocean/go-libvirt/libvirttest"
)

// hungLibvirtd makes dialLibvirt return a connection to a peer that reads
// every request and never answers (a wedged libvirtd).
func hungLibvirtd(t *testing.T) {
	t.Helper()
	old := dialLibvirt
	t.Cleanup(func() { dialLibvirt = old })
	dialLibvirt = func() (net.Conn, error) {
		client, server := net.Pipe()
		go func() {
			_, _ = io.Copy(io.Discard, server)
			server.Close()
		}()
		return client, nil
	}
}

func TestConnectTimesOutOnHungLibvirtd(t *testing.T) {
	hungLibvirtd(t)
	start := time.Now()
	done := make(chan error, 1)
	go func() {
		c, err := connect(100 * time.Millisecond)
		if err == nil {
			c.close(nil)
		}
		done <- err
	}()
	select {
	case err := <-done:
		if !errors.Is(err, ErrTimeout) {
			t.Fatalf("err = %v, want ErrTimeout", err)
		}
		if d := time.Since(start); d > 5*time.Second {
			t.Fatalf("took %s", d)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("connect to a hung libvirtd did not return")
	}
}

// Timed-out attempts release their goroutines, and the next attempt dials a
// fresh connection (reconnect).
func TestTimedOutConnectionsAreReleased(t *testing.T) {
	hungLibvirtd(t)
	dials := 0
	inner := dialLibvirt
	dialLibvirt = func() (net.Conn, error) { dials++; return inner() }

	before := runtime.NumGoroutine()
	for i := 0; i < 3; i++ {
		if _, err := connect(50 * time.Millisecond); !errors.Is(err, ErrTimeout) {
			t.Fatalf("attempt %d: err = %v, want ErrTimeout", i, err)
		}
	}
	if dials != 3 {
		t.Fatalf("dials = %d, want a fresh connection per attempt", dials)
	}
	deadline := time.Now().Add(5 * time.Second)
	for runtime.NumGoroutine() > before+1 {
		if time.Now().After(deadline) {
			t.Fatalf("goroutines leaked: %d -> %d", before, runtime.NumGoroutine())
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// The watchdog re-arms on every request, so a long sequence of quick RPCs is
// not cut off by the per-RPC budget.
func TestWatchdogRearmsOnWrite(t *testing.T) {
	client, server := net.Pipe()
	defer server.Close()
	go func() { _, _ = io.Copy(io.Discard, server) }()
	wd := newWatchdogConn(client, 150*time.Millisecond)
	defer wd.Close()
	for i := 0; i < 6; i++ {
		time.Sleep(50 * time.Millisecond)
		if _, err := wd.Write([]byte("x")); err != nil {
			t.Fatalf("write %d after %dms: %v", i, (i+1)*50, err)
		}
	}
	if wd.fired.Load() {
		t.Fatal("watchdog fired although requests kept flowing")
	}
	time.Sleep(300 * time.Millisecond)
	if !wd.fired.Load() {
		t.Fatal("watchdog did not fire on an idle, unanswered connection")
	}
	if _, err := wd.Write([]byte("x")); err == nil {
		t.Fatal("connection still usable after the watchdog fired")
	}
}

// libvirtd answers the handshake and the lookup, then wedges on the next
// RPC: the exported operation returns ErrTimeout promptly, including its
// Disconnect on the cut connection.
func TestOperationTimesOutWhenLibvirtdWedgesAfterConnect(t *testing.T) {
	oldDial, oldQuery := dialLibvirt, queryTimeout
	t.Cleanup(func() { dialLibvirt, queryTimeout = oldDial, oldQuery })
	mock := libvirttest.New()
	dialLibvirt = mock.Dial // answers ConnectOpen and DomainLookupByName only
	queryTimeout = 200 * time.Millisecond

	start := time.Now()
	done := make(chan error, 1)
	go func() {
		_, err := GetVncPort("test") // DomainGetXMLDesc is never answered
		done <- err
	}()
	select {
	case err := <-done:
		if !errors.Is(err, ErrTimeout) {
			t.Fatalf("err = %v, want ErrTimeout", err)
		}
		if d := time.Since(start); d > 3*time.Second {
			t.Fatalf("took %s", d)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("operation on a wedged libvirtd did not return")
	}
}
