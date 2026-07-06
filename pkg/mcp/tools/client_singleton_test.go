/*
Copyright (c) 2026 Security Research
*/
package mcptools

import (
	"context"
	"errors"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/inovacc/unravel-oss/internal/ipc"
)

// fakeConn satisfies net.Conn well enough for ipc.NewClient (the read
// loop will block on Read forever — that's fine for these tests since
// we never make verb calls).
type fakeConn struct{}

func (fakeConn) Read(b []byte) (int, error)         { time.Sleep(time.Hour); return 0, nil }
func (fakeConn) Write(b []byte) (int, error)        { return len(b), nil }
func (fakeConn) Close() error                       { return nil }
func (fakeConn) LocalAddr() net.Addr                { return nil }
func (fakeConn) RemoteAddr() net.Addr               { return nil }
func (fakeConn) SetDeadline(t time.Time) error      { return nil }
func (fakeConn) SetReadDeadline(t time.Time) error  { return nil }
func (fakeConn) SetWriteDeadline(t time.Time) error { return nil }

func resetSingletonForTest(t *testing.T) {
	t.Helper()
	clientSingletonMu.Lock()
	defer clientSingletonMu.Unlock()
	clientSingleton = nil
	clientSingletonErr = nil
	clientSingletonOnce = false
}

// withAuthBypass overrides newAuthClientFn so tests that use fakeConn
// (which cannot handshake) bypass the real sys.hello round-trip.
func withAuthBypass(t *testing.T) {
	t.Helper()
	origNewAuth := newAuthClientFn
	newAuthClientFn = func(_ context.Context, conn net.Conn, _ string) (*ipc.Client, error) {
		return ipc.NewClient(conn), nil // bypass handshake in unit test
	}
	t.Cleanup(func() { newAuthClientFn = origNewAuth })
}

func withSingletonHooks(t *testing.T, dial dialFunc, spawn autospawnFunc) {
	t.Helper()
	origDial, origSpawn := dialFn, autospawnFn
	dialFn, autospawnFn = dial, spawn
	t.Cleanup(func() {
		dialFn, autospawnFn = origDial, origSpawn
		resetSingletonForTest(t)
	})
	resetSingletonForTest(t)
}

// withFastDialTiming shrinks the poll-dial budget + backoff so tests that
// exercise the autospawn-wait path run in milliseconds instead of the 15s
// production budget.
func withFastDialTiming(t *testing.T) {
	t.Helper()
	origBudget, origBackoff := spawnWaitTimeout, dialBackoff
	spawnWaitTimeout = 200 * time.Millisecond
	dialBackoff = 5 * time.Millisecond
	t.Cleanup(func() { spawnWaitTimeout, dialBackoff = origBudget, origBackoff })
}

func TestClientSingleton_SuccessDial(t *testing.T) {
	withAuthBypass(t)
	dialCalls := 0
	spawnCalls := 0
	withSingletonHooks(t,
		func(ctx context.Context, _ string) (net.Conn, error) {
			dialCalls++
			return fakeConn{}, nil
		},
		func(_, _ string, _ func() bool) error { spawnCalls++; return nil },
	)

	kb, err := getKBClient(context.Background())
	if err != nil {
		t.Fatalf("getKBClient: %v", err)
	}
	if kb == nil {
		t.Fatal("nil KBClient")
	}
	if dialCalls != 1 {
		t.Errorf("dial calls: got %d, want 1", dialCalls)
	}
	if spawnCalls != 0 {
		t.Errorf("spawn calls: got %d, want 0", spawnCalls)
	}
}

func TestClientSingleton_DialFailsAutospawnSucceeds(t *testing.T) {
	withAuthBypass(t)
	var dialCalls atomic.Int32
	spawnCalls := 0
	withSingletonHooks(t,
		func(ctx context.Context, _ string) (net.Conn, error) {
			n := dialCalls.Add(1)
			if n == 1 {
				return nil, errors.New("connection refused")
			}
			return fakeConn{}, nil
		},
		func(_, _ string, _ func() bool) error { spawnCalls++; return nil },
	)

	kb, err := getKBClient(context.Background())
	if err != nil {
		t.Fatalf("getKBClient: %v", err)
	}
	if kb == nil {
		t.Fatal("nil KBClient")
	}
	if got := dialCalls.Load(); got != 2 {
		t.Errorf("dial calls: got %d, want 2", got)
	}
	if spawnCalls != 1 {
		t.Errorf("spawn calls: got %d, want 1", spawnCalls)
	}
}

func TestClientSingleton_PersistentFailureReturnsErrUnavailable(t *testing.T) {
	withFastDialTiming(t) // keep the poll-dial wait short when it can never succeed
	var dialCalls atomic.Int32
	var spawnCalls atomic.Int32
	withSingletonHooks(t,
		func(ctx context.Context, _ string) (net.Conn, error) {
			dialCalls.Add(1)
			return nil, errors.New("connection refused")
		},
		func(_, _ string, _ func() bool) error { spawnCalls.Add(1); return nil },
	)

	_, err := getKBClient(context.Background())
	if !errors.Is(err, ErrSupervisorUnavailable) {
		t.Fatalf("first call: got %v, want ErrSupervisorUnavailable", err)
	}

	dialsAfterFirst := dialCalls.Load()
	spawnsAfterFirst := spawnCalls.Load()

	// Second call should hit the cached error: no further dial / spawn.
	_, err = getEnrichClient(context.Background())
	if !errors.Is(err, ErrSupervisorUnavailable) {
		t.Fatalf("second call: got %v, want ErrSupervisorUnavailable", err)
	}
	if dialCalls.Load() != dialsAfterFirst {
		t.Errorf("cached failure path made extra dial calls: %d -> %d",
			dialsAfterFirst, dialCalls.Load())
	}
	if spawnCalls.Load() != spawnsAfterFirst {
		t.Errorf("cached failure path made extra autospawn calls: %d -> %d",
			spawnsAfterFirst, spawnCalls.Load())
	}
}

func TestClientSingleton_AllFourGettersShareSameClient(t *testing.T) {
	withAuthBypass(t)
	withSingletonHooks(t,
		func(ctx context.Context, _ string) (net.Conn, error) { return fakeConn{}, nil },
		func(_, _ string, _ func() bool) error { return nil },
	)

	kb, err := getKBClient(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	en, err := getEnrichClient(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	dr, err := getDriftClient(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	ca, err := getCaptureClient(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	// All four must come from the same cached singleton.
	clientSingletonMu.Lock()
	defer clientSingletonMu.Unlock()
	if clientSingleton == nil {
		t.Fatal("singleton not cached")
	}
	if kb != clientSingleton.kb {
		t.Error("KBClient does not match cached singleton")
	}
	if en != clientSingleton.enrich {
		t.Error("EnrichClient does not match cached singleton")
	}
	if dr != clientSingleton.drift {
		t.Error("DriftClient does not match cached singleton")
	}
	if ca != clientSingleton.capture {
		t.Error("CaptureClient does not match cached singleton")
	}
	if clientSingleton.ipcClient == nil {
		t.Error("ipcClient not cached")
	}
}

// TestClientSingleton_AutospawnWaitsForColdDaemon pins the cold-start fix:
// after autospawn the dial loop must keep polling past the old 3-attempt cap
// until a slow daemon finally binds its socket, instead of caching a premature
// ErrSupervisorUnavailable that sticks for the whole MCP-process life.
func TestClientSingleton_AutospawnWaitsForColdDaemon(t *testing.T) {
	withAuthBypass(t)
	withFastDialTiming(t)
	var dialCalls atomic.Int32
	spawnCalls := 0
	withSingletonHooks(t,
		func(_ context.Context, _ string) (net.Conn, error) {
			// Cold daemon: socket isn't bound until the 5th dial (past old cap).
			if dialCalls.Add(1) < 5 {
				return nil, errors.New(`open \\.\pipe\unravel: The system cannot find the file specified`)
			}
			return fakeConn{}, nil
		},
		func(_, _ string, _ func() bool) error { spawnCalls++; return nil },
	)

	kb, err := getKBClient(context.Background())
	if err != nil {
		t.Fatalf("getKBClient gave up before the cold daemon was ready: %v", err)
	}
	if kb == nil {
		t.Fatal("nil KBClient")
	}
	if got := dialCalls.Load(); got < 5 {
		t.Errorf("dial calls: got %d, want >=5 (must poll past the old 3-attempt cap)", got)
	}
	if spawnCalls != 1 {
		t.Errorf("spawn calls: got %d, want 1 (autospawn exactly once)", spawnCalls)
	}
}
