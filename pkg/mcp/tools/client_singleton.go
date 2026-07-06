/*
Copyright (c) 2026 Security Research
*/
package mcptools

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"time"

	"github.com/inovacc/unravel-oss/internal/ipc"
	"github.com/inovacc/unravel-oss/internal/supervisor"
	"github.com/inovacc/unravel-oss/internal/supervisor/clients"
)

// ErrSupervisorUnavailable is returned when the supervisor cannot be
// reached after exhausting autospawn retries. MCP tools should map this
// to a friendly error message ("the unravel daemon could not be started
// — run `unravel daemon serve` manually or check logs").
var ErrSupervisorUnavailable = errors.New("supervisor unavailable")

// singletonClient holds the dialed supervisor connection plus the four
// per-domain typed clients. One instance per process; first-use lazy
// init with sync.Once-style semantics (cached success or failure).
type singletonClient struct {
	ipcClient *ipc.Client
	kb        *clients.KBClient
	enrich    *clients.EnrichClient
	drift     *clients.DriftClient
	capture   *clients.CaptureClient
	daemon    *clients.DaemonClient
}

// Package-level singleton state. The mutex guards both the singleton
// pointer + the cached error + the once-flag. The init path is wrapped
// in its own mutex to serialize concurrent first-callers, but after
// the first successful (or failed-and-cached) init the read path is
// a single mutex-protected pointer read.
var (
	clientSingletonMu   sync.Mutex
	clientSingleton     *singletonClient
	clientSingletonErr  error
	clientSingletonOnce bool
)

// dialFunc / autospawnFunc are seams for testing. Production wires them
// to ipc.Dial and supervisor.Autospawn; tests override before calling
// any of the get*Client helpers.
type (
	dialFunc      = func(ctx context.Context, socketPath string) (net.Conn, error)
	autospawnFunc = func(execPath, socketDir string, confirmLive func() bool) error
)

var (
	dialFn      dialFunc      = ipc.Dial
	autospawnFn autospawnFunc = supervisor.Autospawn
)

// newAuthClientFn constructs the authenticated IPC client (reads the
// supervisor's token file and performs the sys.hello handshake).
// Overridable in tests, which use a fakeConn that cannot handshake.
var newAuthClientFn = func(ctx context.Context, conn net.Conn, socketDir string) (*ipc.Client, error) {
	tok, err := os.ReadFile(filepath.Join(socketDir, "token"))
	if err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("read supervisor token (is the daemon running?): %w", err)
	}
	hctx, cancel := context.WithTimeout(ctx, dialTimeout)
	defer cancel()
	hello := ipc.HelloRequest{ClientVersion: "1", OS: runtime.GOOS, PID: os.Getpid()}
	return ipc.NewAuthClient(hctx, conn, string(tok), hello)
}

// dialTimeout bounds a single dial. dialBackoff is the pause between
// poll-dials while waiting for an autospawned daemon to bind the socket.
// spawnWaitTimeout is the TOTAL budget for that wait.
//
// Why the generous budget: a named-pipe / UDS dial FAILS INSTANTLY when the
// socket is absent, so a few fast retries elapse in ~milliseconds. But a
// COLD autospawned daemon connects to a (possibly remote) Postgres and runs
// migrations before it begins listening — routinely several seconds. The old
// 3-attempt / ~300ms window gave up long before a cold daemon was ready and
// cached ErrSupervisorUnavailable, which is sticky for the whole MCP-process
// life — so the first call poisoned the entire session. Waiting out the cold
// start here is what prevents that foot-gun.
//
// dialBackoff and spawnWaitTimeout are vars so tests can shrink them.
const dialTimeout = 2 * time.Second

var (
	dialBackoff      = 100 * time.Millisecond
	spawnWaitTimeout = 15 * time.Second
)

// ensureSingleton runs the lazy init (or returns the cached result).
// Cached errors are sticky for the lifetime of the process; the
// --no-autospawn flag (Phase C2) will gate whether we re-attempt.
func ensureSingleton(ctx context.Context) (*singletonClient, error) {
	clientSingletonMu.Lock()
	defer clientSingletonMu.Unlock()
	if clientSingletonOnce {
		return clientSingleton, clientSingletonErr
	}
	clientSingletonOnce = true

	sc, err := dialAndWrap(ctx)
	if err != nil {
		clientSingletonErr = err
		return nil, err
	}
	clientSingleton = sc
	return sc, nil
}

// dialAndWrap performs the dial → autospawn → retry loop and on success
// builds the four typed clients over a shared ipc.Client bus. The caller
// owns the singleton mutex.
func dialAndWrap(ctx context.Context) (*singletonClient, error) {
	socketDir := supervisor.DefaultSocketDir()
	addr := supervisor.SocketPath(socketDir)

	// 1. Bare dial — the supervisor may already be running (warm path).
	conn, dialErr := dialOnce(ctx, addr)
	if dialErr != nil {
		// 2. Not reachable: autospawn once, then wait generously for the
		//    daemon to bind the socket. A cold start (remote DB connect +
		//    migrations) takes seconds; the old ~300ms window cached a
		//    premature failure that stuck for the whole MCP-process life.
		execPath, execErr := os.Executable()
		if execErr != nil {
			return nil, fmt.Errorf("%w: resolve executable: %w",
				ErrSupervisorUnavailable, execErr)
		}
		// confirmLive is a bounded liveness probe handed to Autospawn so the
		// crash-loop guard records a failure when the child forks but dies on
		// startup (DB connect / migration / bind death) instead of a bogus
		// success. It is a bare dial — independent of the singleton's own IPC
		// dial below — so a child that never binds counts toward the guard.
		confirmLive := func() bool {
			c, derr := dialOnce(ctx, addr)
			if derr != nil {
				return false
			}
			_ = c.Close()
			return true
		}
		if spawnErr := autospawnFn(execPath, socketDir, confirmLive); spawnErr != nil {
			if errors.Is(spawnErr, supervisor.ErrSpawnLoopDetected) {
				return nil, fmt.Errorf("%w: %w", ErrSupervisorUnavailable, spawnErr)
			}
			if errors.Is(spawnErr, supervisor.ErrAutospawnTestBinary) {
				// We are a `go test` binary: Autospawn refused to fork (forking
				// would re-run the whole suite detached). No daemon will ever
				// bind the socket, so skip the multi-second pollDial wait and
				// fail fast — otherwise the first kb_* call inside a test blocks
				// for the entire spawnWaitTimeout budget before giving up.
				return nil, fmt.Errorf("%w: %w", ErrSupervisorUnavailable, spawnErr)
			}
			// Non-fatal: a peer process may already be spawning the daemon,
			// or the child forked but never came up (recorded as a guard
			// failure inside Autospawn). Fall through and wait for the socket.
		}
		conn, dialErr = pollDial(ctx, addr, spawnWaitTimeout)
		if dialErr != nil {
			return nil, fmt.Errorf("%w: dial %s after autospawn (waited %s): %w",
				ErrSupervisorUnavailable, addr, spawnWaitTimeout, dialErr)
		}
	}

	cli, err := newAuthClientFn(ctx, conn, socketDir)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrSupervisorUnavailable, err)
	}
	return &singletonClient{
		ipcClient: cli,
		kb:        clients.NewKBClient(cli),
		enrich:    clients.NewEnrichClient(cli),
		drift:     clients.NewDriftClient(cli),
		capture:   clients.NewCaptureClient(cli),
		daemon:    clients.NewDaemonClient(cli),
	}, nil
}

// dialOnce performs a single dial bounded by dialTimeout.
func dialOnce(ctx context.Context, addr string) (net.Conn, error) {
	dctx, cancel := context.WithTimeout(ctx, dialTimeout)
	defer cancel()
	return dialFn(dctx, addr)
}

// pollDial retries dialOnce every dialBackoff until it connects, the budget
// expires, or ctx is cancelled. Used to wait out a cold autospawned daemon
// that has not yet bound its socket.
func pollDial(ctx context.Context, addr string, budget time.Duration) (net.Conn, error) {
	deadline := time.Now().Add(budget)
	lastErr := errors.New("no dial attempted")
	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(dialBackoff):
		}
		conn, err := dialOnce(ctx, addr)
		if err == nil {
			return conn, nil
		}
		lastErr = err
		if !time.Now().Before(deadline) {
			return nil, lastErr
		}
	}
}

// getKBClient returns the cached KB client, dialing + autospawning on
// first call. Returns ErrSupervisorUnavailable (wrapped with context)
// if the supervisor cannot be reached.
func getKBClient(ctx context.Context) (*clients.KBClient, error) {
	sc, err := ensureSingleton(ctx)
	if err != nil {
		return nil, err
	}
	return sc.kb, nil
}

// getEnrichClient — see getKBClient.
func getEnrichClient(ctx context.Context) (*clients.EnrichClient, error) {
	sc, err := ensureSingleton(ctx)
	if err != nil {
		return nil, err
	}
	return sc.enrich, nil
}

// getDriftClient — see getKBClient.
func getDriftClient(ctx context.Context) (*clients.DriftClient, error) {
	sc, err := ensureSingleton(ctx)
	if err != nil {
		return nil, err
	}
	return sc.drift, nil
}

// getCaptureClient — see getKBClient. Note: capture.Visual is a
// long-running verb (10–60s); callers should pass deadline-bearing ctx.
func getCaptureClient(ctx context.Context) (*clients.CaptureClient, error) {
	sc, err := ensureSingleton(ctx)
	if err != nil {
		return nil, err
	}
	return sc.capture, nil
}

// getDaemonClient — see getKBClient. Used by plugin_doctor (B7-P3).
func getDaemonClient(ctx context.Context) (*clients.DaemonClient, error) {
	sc, err := ensureSingleton(ctx)
	if err != nil {
		return nil, err
	}
	return sc.daemon, nil
}
