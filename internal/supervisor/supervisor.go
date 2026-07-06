/*
Copyright (c) 2026 Security Research
*/
// Package supervisor implements unravel's host-singleton daemon.
// One process per user account per machine; long-lived; owns DB pool,
// session state, workspace bindings, and in-flight enrich/drift state.
// MCP processes spawn per Claude Code session and dial this supervisor
// over IPC. See spec
// docs/superpowers/specs/2026-05-27-supervisor-singleton-pattern-design.md
package supervisor

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/inovacc/unravel-oss/internal/ipc"
	kbdb "github.com/inovacc/unravel-oss/pkg/knowledge/kb/db"
)

// Config controls Supervisor instantiation.
type Config struct {
	SocketDir   string        // dir holding daemon.sock + server.json + spawn-history.json
	IdleTimeout time.Duration // default 30 min
	Logger      *slog.Logger
	// DSN is the postgres:// URL for the knowledge catalog. When empty
	// kb.* verbs return CodeUnavailable (errKBNoDB). When non-empty the
	// supervisor opens a *sql.DB at New() time and closes it at Stop().
	// Per PG-V17-5 DSN consolidation: the supervisor owns the pool; MCP
	// tool processes dial in over IPC and never open their own DB.
	DSN string

	// ExitWhenIdle, when true, makes the idle watcher trigger a graceful
	// shutdown once the daemon has had zero agents and no IPC activity for
	// IdleTimeout. The production daemon binary sets this; it defaults off so
	// tests and lifecycle-only callers are never killed mid-run. Clients
	// transparently re-autospawn the supervisor on their next connect.
	ExitWhenIdle bool
}

// AgentRecord, SessionRecord, WorkspaceRecord are populated by PG-V17-4.
// Stub types here so the supervisor compiles with the maps in place.
type AgentRecord struct {
	AgentID     string
	ClientKind  string
	CWD         string
	ConnectedAt time.Time
}

type SessionRecord struct {
	SessionID     string
	AgentID       string
	WorkspaceID   string
	CWD           string
	LastHeartbeat time.Time
}

type WorkspaceRecord struct {
	WorkspaceID string
	App         string
	AgentSet    map[string]struct{}
	ActivatedAt time.Time
}

// Supervisor is the long-lived daemon process body.
type Supervisor struct {
	cfg Config

	// Wire layer.
	server *ipc.Server
	ln     net.Listener

	// db is the optional Postgres pool wired from Config.DSN. nil when
	// the supervisor runs without DB access (lifecycle-only tests).
	db *sql.DB

	// In-memory state (populated by PG-V17-4 verbs).
	agents       map[string]*AgentRecord
	agentsMu     sync.RWMutex
	sessions     map[string]*SessionRecord
	sessionsMu   sync.RWMutex
	workspaces   map[string]*WorkspaceRecord
	workspacesMu sync.RWMutex

	// Lifecycle.
	now        func() time.Time
	stopCh     chan struct{}
	stopOnce   sync.Once // guards close(stopCh) + the shutdown sequence
	wg         sync.WaitGroup
	tokenPath  string    // <SocketDir>/token; removed on Stop
	lock       *fileLock // host-singleton exclusive lock; released on Stop
	startedAt  time.Time // set in Start; idle baseline before any activity
	onIdleExit func()    // injected idle-exit hook; default calls Stop()
}

// ErrSingletonHeld is returned by Start when another supervisor process
// already holds the host-singleton lock for this SocketDir. The caller
// should NOT remove the socket — a live peer owns the endpoint — and may
// re-probe and exit cleanly.
var ErrSingletonHeld = errors.New("supervisor: another daemon holds the host-singleton lock")

// New constructs a Supervisor with hello + ping verbs registered. Does
// not start listening (call Start).
func New(cfg Config) (*Supervisor, error) {
	if cfg.SocketDir == "" {
		return nil, fmt.Errorf("supervisor: SocketDir required")
	}
	if cfg.IdleTimeout == 0 {
		cfg.IdleTimeout = 30 * time.Minute
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	sv := &Supervisor{
		cfg:        cfg,
		server:     ipc.NewServer(),
		agents:     make(map[string]*AgentRecord),
		sessions:   make(map[string]*SessionRecord),
		workspaces: make(map[string]*WorkspaceRecord),
		now:        time.Now,
		stopCh:     make(chan struct{}),
	}
	if cfg.DSN != "" {
		db, err := kbdb.Open(context.Background(), cfg.DSN)
		if err != nil {
			return nil, fmt.Errorf("supervisor: open DB: %w", err)
		}
		sv.db = db
	}
	sv.registerLifecycleVerbs()
	sv.registerStateVerbs()
	sv.registerKBVerbs()
	sv.registerEnrichVerbs()
	sv.registerDriftVerbs()
	sv.registerCaptureVerbs()
	sv.registerDaemonVerbs()
	return sv, nil
}

// SocketPath returns the IPC address the supervisor listens on.
// On POSIX: absolute UDS path ($SocketDir/daemon.sock).
// On Windows: a named-pipe path derived from SocketDir (see socketPath_windows.go).
// Useful for tests and clients.
func (sv *Supervisor) SocketPath() string {
	return socketPath(sv.cfg.SocketDir)
}

// Start binds the listener and runs the accept loop in a background
// goroutine. Returns once the listener is bound.
func (sv *Supervisor) Start(ctx context.Context) error {
	// Host-singleton serialization: acquire the exclusive lock BEFORE binding
	// the socket. This is the single serialization point regardless of how
	// many MCP processes autospawn concurrently. On contention a live peer
	// owns the endpoint — return ErrSingletonHeld and do NOT remove/rebind the
	// socket (which would hijack the peer's live listener).
	lock, err := acquireFileLock(filepath.Join(sv.cfg.SocketDir, "daemon.lock"))
	if err != nil {
		if errors.Is(err, errLockHeld) {
			return ErrSingletonHeld
		}
		return fmt.Errorf("supervisor: acquire singleton lock: %w", err)
	}
	sv.lock = lock

	token, err := ipc.GenerateToken()
	if err != nil {
		_ = sv.lock.release()
		sv.lock = nil
		return fmt.Errorf("supervisor: generate token: %w", err)
	}
	sv.tokenPath = filepath.Join(sv.cfg.SocketDir, "token")
	if err := ipc.WriteTokenFile(sv.tokenPath, token); err != nil {
		_ = sv.lock.release()
		sv.lock = nil
		return fmt.Errorf("supervisor: write token: %w", err)
	}
	sv.server.SetAuth(token, ipc.LocalPeerVerifier)

	ln, err := ipc.Listen(sv.SocketPath())
	if err != nil {
		_ = sv.lock.release()
		sv.lock = nil
		return fmt.Errorf("supervisor: bind listener: %w", err)
	}
	sv.ln = ln
	sv.startedAt = sv.now()
	if sv.onIdleExit == nil {
		sv.onIdleExit = func() { _ = sv.Stop() }
	}
	sv.wg.Add(3)
	go sv.acceptLoop(ctx)
	go sv.idleWatcher(ctx)
	go sv.heartbeatReaper(ctx)
	sv.cfg.Logger.Info("supervisor: listening", "socket", sv.SocketPath())
	return nil
}

// drainTimeout bounds how long Stop waits for in-flight verb handlers to
// finish before tearing down the DB pool. A wedged handler must not block
// shutdown forever. Var so tests can shrink it.
var drainTimeout = 10 * time.Second

// Stop closes the listener, drains in-flight verb handlers, then tears down
// the DB pool and releases the singleton lock. It is idempotent and safe to
// call concurrently (guarded by sync.Once) — a second Stop, a racing SIGTERM,
// or an idle-exit are all harmless.
func (sv *Supervisor) Stop() error {
	sv.stopOnce.Do(func() {
		close(sv.stopCh)

		// Stop accepting new connections first.
		if sv.ln != nil {
			_ = sv.ln.Close()
		}
		if sv.tokenPath != "" {
			_ = os.Remove(sv.tokenPath)
		}

		// Drain in-flight dispatch goroutines BEFORE closing the DB pool, so a
		// handler never touches a closed *sql.DB (use-after-close) and the
		// sv.db field is never torn down underneath a running query. Bounded so
		// a wedged handler can't hang shutdown.
		drainCtx, cancel := context.WithTimeout(context.Background(), drainTimeout)
		defer cancel()
		if err := sv.server.Shutdown(drainCtx); err != nil {
			sv.cfg.Logger.Warn("supervisor: handler drain timed out; closing pool anyway", "err", err)
		}

		// Wait for the lifecycle goroutines (accept/idle/heartbeat) to exit.
		sv.wg.Wait()

		// Now safe to close the pool: no handler can be in flight. Deliberately
		// do NOT nil sv.db — leaving it non-nil means any late handler that
		// somehow slipped through sees a clean "sql: database is closed" error
		// instead of racing an unsynchronised pointer write.
		if sv.db != nil {
			_ = sv.db.Close()
		}
		if sv.lock != nil {
			_ = sv.lock.release()
			sv.lock = nil
		}
	})
	return nil
}

func (sv *Supervisor) acceptLoop(ctx context.Context) {
	defer sv.wg.Done()
	if err := sv.server.Serve(ctx, sv.ln); err != nil {
		// Serve returns when ln.Close() is called — expected at shutdown.
		select {
		case <-sv.stopCh:
			return
		default:
			sv.cfg.Logger.Warn("supervisor: accept loop exited unexpectedly", "err", err)
		}
	}
}

// idleTickInterval returns the idle-check cadence (IdleTimeout/6), floored at
// 1ms so time.NewTicker never panics on a sub-6ns or non-positive timeout.
func idleTickInterval(timeout time.Duration) time.Duration {
	if d := timeout / 6; d > 0 {
		return d
	}
	return time.Millisecond
}

// idleWatcher periodically checks for quiescence (zero agents and no IPC
// activity for IdleTimeout) and, when ExitWhenIdle is set, triggers a
// single-shot graceful shutdown. Runs until stopCh or ctx is done.
func (sv *Supervisor) idleWatcher(ctx context.Context) {
	defer sv.wg.Done()
	ticker := time.NewTicker(idleTickInterval(sv.cfg.IdleTimeout)) // check ~6x per timeout
	defer ticker.Stop()
	var fired bool
	for {
		select {
		case <-sv.stopCh:
			return
		case <-ctx.Done():
			return
		case <-ticker.C:
			sv.agentsMu.RLock()
			n := len(sv.agents)
			sv.agentsMu.RUnlock()
			if n != 0 {
				continue
			}
			// Truly-idle check: zero agents AND no IPC activity for IdleTimeout.
			// lastActive is the most recent inbound verb, or the start time if
			// nothing has ever arrived.
			lastActive := sv.server.LastActivity()
			if lastActive.IsZero() {
				lastActive = sv.startedAt
			}
			if sv.now().Sub(lastActive) < sv.cfg.IdleTimeout {
				continue
			}
			sv.cfg.Logger.Info("supervisor: idle timeout — agent count = 0",
				"timeout", sv.cfg.IdleTimeout, "exit_when_idle", sv.cfg.ExitWhenIdle)
			if sv.cfg.ExitWhenIdle && !fired {
				fired = true
				// Run the exit hook in its own goroutine: the default hook calls
				// Stop(), which wg.Wait()s on this very goroutine — calling it
				// inline would deadlock.
				go sv.onIdleExit()
				return
			}
		}
	}
}
