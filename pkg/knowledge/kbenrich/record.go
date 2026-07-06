/*
Copyright (c) 2026 Security Research
*/

// Package kbenrich / record.go: stateless free-function entry points for
// the enrich_runs / enrich_attempts audit tables. Used by the upcoming
// enrich.* supervisor dispatcher (Phase A8 / v2.17 thin-client refactor)
// so per-attempt recording does not require constructing a stateful
// Monitor.
//
// The stateful Monitor (monitor.go) remains the authority for the
// in-process EnrichCore path — heartbeats, sweepers, and the
// once-Finalise lifecycle live there. The free-functions in this file
// duplicate just the I/O fragments needed by the cross-session plugin
// orchestrator (Claude Code session opens a run, fans out subagents,
// records each attempt via the supervisor verb, finalises the run).
//
// NOTE 2026-05-27: extraction also FIXES the column names the legacy
// pkg/mcp/tools/kb_enrich_run_record.go used. Migration 000013 created
// enrich_runs with run_id / total_target / concurrency / host / pid; the
// legacy code wrote id / target_limit / concurrent / expected_total /
// host_pid and would have errored against the real schema. The
// extracted SQL below tracks the migration shape. The legacy MCP tool's
// startEnrichRun / recordEnrichAttempt are now thin delegates pointing
// here, so any downstream caller using the public MCP tool name
// (unravel_kb_enrich_record) gains the schema fix for free.
package kbenrich

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"

	"github.com/google/uuid"
)

// ErrRecordRunNotFound is returned by RecordAttempt when the (run_id,
// module_id) pair references a run row that doesn't exist. Wrappers map
// to CodeNotFound / ErrEnrichRunNotFound at the supervisor + client
// boundary.
var ErrRecordRunNotFound = errors.New("kbenrich: enrich run not found")

// StartRunOptions controls StartRun().
type StartRunOptions struct {
	App         string
	TotalTarget int
	Model       string // default "claude-code-subagent"
}

// StartRunPayload is the response body for StartRun().
type StartRunPayload struct {
	RunID string `json:"run_id"`
	App   string `json:"app"`
	Model string `json:"model"`
	Host  string `json:"host"`
}

// StartRun inserts a new enrich_runs row in status='in_progress' and
// returns the freshly-minted run_id. Mirrors the legacy MCP-tool
// startEnrichRun helper but uses the correct column names from migration
// 000013_enrich_session_monitor.
func StartRun(ctx context.Context, db *sql.DB, opts StartRunOptions) (*StartRunPayload, error) {
	if db == nil {
		return nil, fmt.Errorf("StartRun: nil db")
	}
	runID := uuid.NewString()
	model := opts.Model
	if model == "" {
		model = "claude-code-subagent"
	}
	host, _ := os.Hostname()
	pid := os.Getpid()
	_, err := db.ExecContext(ctx, `INSERT INTO enrich_runs
		(run_id, started_at, last_heartbeat_at, app, model, concurrency, prompt_batch,
		 status, total_target, completed, failed, host, pid)
		VALUES ($1::uuid, NOW(), NOW(), $2, $3, 1, 1, 'in_progress', $4, 0, 0, $5, $6)`,
		runID, opts.App, model, opts.TotalTarget, host, pid)
	if err != nil {
		return nil, fmt.Errorf("insert enrich_runs: %w", err)
	}
	return &StartRunPayload{RunID: runID, App: opts.App, Model: model, Host: host}, nil
}

// RecordAttemptOptions controls RecordAttempt().
type RecordAttemptOptions struct {
	RunID        string
	ModuleID     int64
	AttemptNo    int    // default 1
	Status       string // 'success' | 'failure' | 'timeout' | 'interrupted'
	ErrorClass   string
	ErrorMsg     string // redacted by RecordAttempt before storage
	ModelUsed    string // default "claude-code-subagent"
	CostMicroUSD int64
}

// RecordAttemptPayload is the response body for RecordAttempt().
type RecordAttemptPayload struct {
	RunID     string `json:"run_id"`
	ModuleID  int64  `json:"module_id"`
	AttemptNo int    `json:"attempt_no"`
	Status    string `json:"status"`
	Recorded  bool   `json:"recorded"`
}

// RecordAttempt inserts one enrich_attempts row + bumps the parent
// run's completed/failed counter and last_heartbeat_at. ErrorMsg is
// passed through Redact before storage so the audit table never holds
// raw model output.
//
// Returns ErrRecordRunNotFound (wrapped) when the parent run row does
// not exist (FK violation surfaces as a Postgres 23503 error code).
func RecordAttempt(ctx context.Context, db *sql.DB, opts RecordAttemptOptions) (*RecordAttemptPayload, error) {
	if db == nil {
		return nil, fmt.Errorf("RecordAttempt: nil db")
	}
	if opts.RunID == "" || opts.ModuleID == 0 || opts.Status == "" {
		return nil, fmt.Errorf("RecordAttempt: run_id, module_id, status required")
	}
	attemptNo := max(opts.AttemptNo, 1)
	model := opts.ModelUsed
	if model == "" {
		model = "claude-code-subagent"
	}

	var ec sql.NullString
	var em sql.NullString
	if opts.ErrorClass != "" {
		ec = sql.NullString{String: opts.ErrorClass, Valid: true}
	}
	if opts.ErrorMsg != "" {
		em = sql.NullString{String: Redact(opts.ErrorMsg), Valid: true}
	}

	// Wrap the attempt INSERT and the parent-run counter UPDATE in one
	// transaction so they commit atomically (hardening finding #11). A crash
	// or transient failure between the two statements previously left
	// enrich_runs.completed/failed permanently disagreeing with the count of
	// enrich_attempts rows; the counter error was also swallowed. Mirrors the
	// BeginTx/Commit shape in RecordCost (recordcost.go).
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("RecordAttempt: begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }() // no-op after Commit

	if _, err := tx.ExecContext(ctx, `INSERT INTO enrich_attempts
		(run_id, module_id, attempt_no, started_at, ended_at, status,
		 error_class, error_message_redacted, model_used)
		VALUES ($1::uuid, $2, $3, NOW(), NOW(), $4, $5, $6, $7)`,
		opts.RunID, opts.ModuleID, attemptNo, opts.Status, ec, em, model); err != nil {
		// Postgres FK violation on run_id maps to "run not found".
		if isForeignKeyViolation(err) {
			return nil, fmt.Errorf("%w: %s", ErrRecordRunNotFound, opts.RunID)
		}
		return nil, fmt.Errorf("insert enrich_attempts: %w", err)
	}

	// Bump completed/failed + heartbeat on the parent run row. Now in the
	// same tx and the error is propagated (rolls the INSERT back) rather than
	// swallowed, so the counter can never silently drift from the attempts.
	col := "failed"
	if opts.Status == "success" {
		col = "completed"
	}
	if _, err := tx.ExecContext(ctx,
		fmt.Sprintf(`UPDATE enrich_runs SET %s = %s + 1, last_heartbeat_at = NOW() WHERE run_id = $1::uuid`, col, col),
		opts.RunID); err != nil {
		return nil, fmt.Errorf("bump enrich_runs counter: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("RecordAttempt: commit: %w", err)
	}

	return &RecordAttemptPayload{
		RunID:     opts.RunID,
		ModuleID:  opts.ModuleID,
		AttemptNo: attemptNo,
		Status:    opts.Status,
		Recorded:  true,
	}, nil
}

// isForeignKeyViolation returns true when err carries the Postgres
// 23503 sqlstate. Implemented via string-match rather than pulling in
// jackc/pgconn so this package stays driver-agnostic — the lib/pq
// driver bundled by kbdb wraps errors with the sqlstate in the message.
func isForeignKeyViolation(err error) bool {
	if err == nil {
		return false
	}
	// pq.Error.Code → "23503" appears in Error() output of both lib/pq and
	// pgx (when wrapped). This is a best-effort signal.
	msg := err.Error()
	return contains(msg, "23503") || contains(msg, "foreign key constraint")
}

func contains(haystack, needle string) bool {
	if len(needle) == 0 {
		return true
	}
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return true
		}
	}
	return false
}
