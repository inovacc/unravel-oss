/*
Copyright (c) 2026 Security Research
*/
// Monitor — the per-run audit + heartbeat + sweeper helper for EnrichCore.
// All DB writes that go beyond per-success writeEnrichment live here so
// enrich.go stays focused on the worker pool semantics.
//
// Lifecycle:
//
//	m, err := StartMonitor(ctx, db, opts, totalTarget)  // INSERT enrich_runs row
//	defer m.Finalise("completed" | "failed")             // UPDATE status, ended_at
//	... worker calls m.RecordAttempt(...)                 // INSERT enrich_attempts row
//	... worker calls m.IncCompleted() / IncFailed()       // bumps in-memory counters
//	... heartbeat goroutine flushes counters to enrich_runs every HeartbeatInterval
//	... sweeper goroutine flips peer rows older than StaleAfter to 'interrupted'
//
// All methods are safe to call on a nil receiver — that's the path callers
// take when Opts.MonitorDisabled is true. Finalise is idempotent.
package kbenrich

import (
	"context"
	"database/sql"
	"fmt"
	"log/slog"
	"os"
	"sync"
	"sync/atomic"
	"time"
)

const (
	defaultHeartbeatInterval = 30 * time.Second
	defaultStaleAfter        = 10 * time.Minute
	maxHostLen               = 255
)

// Monitor owns the per-run audit row + background goroutines.
type Monitor struct {
	db                *sql.DB
	runID             string
	resumed           bool
	heartbeatInterval time.Duration
	staleAfter        time.Duration

	completed atomic.Int64
	failed    atomic.Int64

	ctx       context.Context
	cancel    context.CancelFunc
	doneHB    chan struct{}
	doneSweep chan struct{}

	finaliseOnce sync.Once
}

// StartMonitor inserts (or resumes) the enrich_runs row, then launches the
// heartbeat + sweeper goroutines. Returns a *Monitor whose RunID() identifies
// the run.
func StartMonitor(parent context.Context, db *sql.DB, opts Opts, totalTarget int) (*Monitor, error) {
	hbInt := opts.HeartbeatInterval
	if hbInt <= 0 {
		hbInt = defaultHeartbeatInterval
	}
	staleAfter := opts.StaleAfter
	if staleAfter <= 0 {
		staleAfter = defaultStaleAfter
	}
	model := opts.Model
	if model == "" {
		model = "sonnet"
	}

	host, _ := os.Hostname()
	if len(host) > maxHostLen {
		host = host[:maxHostLen]
	}
	pid := os.Getpid()

	runID, resumed, err := resolveRunID(parent, db, opts, model, host, pid, totalTarget, staleAfter)
	if err != nil {
		return nil, err
	}

	ctx, cancel := context.WithCancel(parent)
	m := &Monitor{
		db:                db,
		runID:             runID,
		resumed:           resumed,
		heartbeatInterval: hbInt,
		staleAfter:        staleAfter,
		ctx:               ctx,
		cancel:            cancel,
		doneHB:            make(chan struct{}),
		doneSweep:         make(chan struct{}),
	}

	go m.runHeartbeat()
	go m.runSweeper()

	return m, nil
}

// resolveRunID either reuses an in-progress row whose last_heartbeat_at is
// fresh, or inserts a brand-new row. Resume logic is keyed on (app, host),
// per spec §5.3 step 1.
func resolveRunID(ctx context.Context, db *sql.DB, opts Opts, model, host string, pid, totalTarget int, staleAfter time.Duration) (string, bool, error) {
	// Explicit resume by id.
	if opts.ResumeRunID != "" {
		var foundID string
		err := db.QueryRowContext(ctx,
			`SELECT run_id::text FROM enrich_runs WHERE run_id = $1::uuid AND status = 'in_progress'`,
			opts.ResumeRunID).Scan(&foundID)
		if err == nil {
			return foundID, true, nil
		}
		if err != sql.ErrNoRows {
			return "", false, fmt.Errorf("resume by id: %w", err)
		}
		// Fall through to fresh insert.
	} else if !opts.ForceNewRun && !opts.MonitorDisabled {
		var foundID string
		err := db.QueryRowContext(ctx, `
			SELECT run_id::text FROM enrich_runs
			 WHERE status = 'in_progress'
			   AND app = $1
			   AND host = $2
			   AND (now() - last_heartbeat_at) < ($3 || ' milliseconds')::interval
			 ORDER BY started_at DESC LIMIT 1`,
			opts.App, host, fmt.Sprintf("%d", staleAfter.Milliseconds())).Scan(&foundID)
		if err == nil {
			return foundID, true, nil
		}
		if err != sql.ErrNoRows {
			return "", false, fmt.Errorf("resume autodetect: %w", err)
		}
	}

	// Fresh insert.
	var parent sql.NullString
	if opts.ParentRunID != "" {
		parent = sql.NullString{String: opts.ParentRunID, Valid: true}
	}
	var newID string
	err := db.QueryRowContext(ctx, `
		INSERT INTO enrich_runs
		  (app, model, concurrency, prompt_batch, status, total_target, host, pid, parent_run_id)
		VALUES ($1, $2, $3, $4, 'in_progress', $5, $6, $7, $8::uuid)
		RETURNING run_id::text`,
		opts.App, model, opts.Concurrent, opts.PromptBatch, totalTarget, host, pid, parent,
	).Scan(&newID)
	if err != nil {
		return "", false, fmt.Errorf("insert enrich_runs: %w", err)
	}
	return newID, false, nil
}

// RunID returns the run UUID, or "" when m is nil.
func (m *Monitor) RunID() string {
	if m == nil {
		return ""
	}
	return m.runID
}

// Resumed reports whether StartMonitor reused an existing in-progress row.
func (m *Monitor) Resumed() bool {
	if m == nil {
		return false
	}
	return m.resumed
}

// IncCompleted bumps the in-memory completed counter (flushed by heartbeat).
func (m *Monitor) IncCompleted() {
	if m == nil {
		return
	}
	m.completed.Add(1)
}

// IncFailed bumps the in-memory failed counter (flushed by heartbeat).
func (m *Monitor) IncFailed() {
	if m == nil {
		return
	}
	m.failed.Add(1)
}

// RecordAttempt INSERTs one enrich_attempts row with the redacted message.
// errMessage is passed through Redact before storage.
func (m *Monitor) RecordAttempt(moduleID int64, status, errClass, errMessage, modelUsed string, attemptNo int) {
	if m == nil {
		return
	}
	var (
		ec sql.NullString
		em sql.NullString
	)
	if errClass != "" {
		ec = sql.NullString{String: errClass, Valid: true}
	}
	if errMessage != "" {
		em = sql.NullString{String: Redact(errMessage), Valid: true}
	}
	// TODO(phase-g): wire token usage when sampling response refactor lands
	if _, err := m.db.Exec(`
		INSERT INTO enrich_attempts
		  (run_id, module_id, ended_at, status, error_class, error_message_redacted, model_used, attempt_no, cost_micro_usd)
		VALUES ($1::uuid, $2, now(), $3, $4, $5, $6, $7, $8)`,
		m.runID, moduleID, status, ec, em, modelUsed, attemptNo, int64(0),
	); err != nil {
		slog.Warn("kbenrich: insert enrich_attempts failed", "err", err, "run_id", m.runID, "module_id", moduleID)
	}
}

// Abort halts the heartbeat + sweeper goroutines but does NOT update the
// enrich_runs status row. Used when EnrichCore unwinds because a worker
// panicked (or the host process is otherwise about to die) and the run
// should be left in_progress so the cross-session SweepInterrupted path
// can flip it to 'interrupted' after StaleAfter elapses.
//
// Idempotent — guarded by the same once as Finalise so the second call
// (either Abort or Finalise) is a no-op.
func (m *Monitor) Abort() {
	if m == nil {
		return
	}
	m.finaliseOnce.Do(func() {
		m.cancel()
		<-m.doneHB
		<-m.doneSweep
	})
}

// Finalise stops the background goroutines and writes the terminal status.
// Idempotent — safe to defer + call explicitly.
func (m *Monitor) Finalise(finalStatus string) {
	if m == nil {
		return
	}
	m.finaliseOnce.Do(func() {
		m.cancel()
		<-m.doneHB
		<-m.doneSweep
		// One last counter flush + status update.
		if _, err := m.db.Exec(`
			UPDATE enrich_runs
			   SET status = $1,
			       completed = $2,
			       failed = $3,
			       last_heartbeat_at = now(),
			       ended_at = now()
			 WHERE run_id = $4::uuid`,
			finalStatus, m.completed.Load(), m.failed.Load(), m.runID,
		); err != nil {
			slog.Warn("kbenrich: finalise update failed", "err", err, "run_id", m.runID)
		}
	})
}

func (m *Monitor) runHeartbeat() {
	defer close(m.doneHB)
	t := time.NewTicker(m.heartbeatInterval)
	defer t.Stop()
	for {
		select {
		case <-m.ctx.Done():
			return
		case <-t.C:
			if _, err := m.db.Exec(`
				UPDATE enrich_runs
				   SET last_heartbeat_at = now(), completed = $1, failed = $2
				 WHERE run_id = $3::uuid`,
				m.completed.Load(), m.failed.Load(), m.runID,
			); err != nil {
				slog.Warn("kbenrich: heartbeat update failed", "err", err, "run_id", m.runID)
			}
		}
	}
}

func (m *Monitor) runSweeper() {
	defer close(m.doneSweep)
	tick := max(m.staleAfter/3, time.Second)
	t := time.NewTicker(tick)
	defer t.Stop()
	for {
		select {
		case <-m.ctx.Done():
			return
		case <-t.C:
			if _, err := sweepInterruptedExcept(m.db, m.staleAfter, m.runID); err != nil {
				slog.Warn("kbenrich: sweeper failed", "err", err)
			}
		}
	}
}

// SweepInterrupted flips any in_progress run whose last_heartbeat_at is older
// than staleAfter to status='interrupted', ended_at=now(). Used both by the
// background sweeper goroutine (excluding self) and by the _status MCP tool
// (no self to exclude). Returns rows affected.
func SweepInterrupted(db *sql.DB, staleAfter time.Duration) (int64, error) {
	return sweepInterruptedExcept(db, staleAfter, "")
}

func sweepInterruptedExcept(db *sql.DB, staleAfter time.Duration, exceptRunID string) (int64, error) {
	if staleAfter <= 0 {
		staleAfter = defaultStaleAfter
	}
	q := `UPDATE enrich_runs
	         SET status = 'interrupted', ended_at = now()
	       WHERE status = 'in_progress'
	         AND (now() - last_heartbeat_at) > ($1 || ' milliseconds')::interval`
	args := []any{fmt.Sprintf("%d", staleAfter.Milliseconds())}
	if exceptRunID != "" {
		q += " AND run_id <> $2::uuid"
		args = append(args, exceptRunID)
	}
	res, err := db.Exec(q, args...)
	if err != nil {
		return 0, fmt.Errorf("sweep interrupted: %w", err)
	}
	n, _ := res.RowsAffected()
	return n, nil
}
