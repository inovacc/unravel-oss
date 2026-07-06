/*
Copyright (c) 2026 Security Research
*/

// Package kbenrich / status.go: free-function Status() that consolidates the
// three SELECTs + heartbeat sweep formerly inlined in
// pkg/mcp/tools/knowledge_enrich_status.go. Lives here so the supervisor
// dispatcher and the MCP tool can both call the exact same code path.
package kbenrich

import (
	"context"
	"database/sql"
	"fmt"
	"time"
)

// StatusStaleAfter is the heartbeat staleness threshold used by Status when
// it sweeps in_progress enrich_runs to 'interrupted'. Public so callers can
// override (e.g. tests that want a tighter horizon).
const StatusStaleAfter = 10 * time.Minute

// StatusOptions controls Status() output. All fields optional.
//
//   - App      : filter runs and coverage to a single app (empty = all apps)
//   - RunID    : when non-empty, include a failed-module detail block for the run
//   - Limit    : max number of runs to return (default 20, hard cap 200)
type StatusOptions struct {
	App   string
	RunID string
	Limit int
}

// StatusRun is one row in the runs[] block.
type StatusRun struct {
	RunID               string `json:"run_id"`
	App                 string `json:"app"`
	Model               string `json:"model"`
	Status              string `json:"status"`
	StartedAgoSec       int64  `json:"started_ago_sec"`
	LastHeartbeatAgoSec int64  `json:"last_heartbeat_ago_sec"`
	Completed           int    `json:"completed"`
	Failed              int    `json:"failed"`
	TotalTarget         int    `json:"total_target"`
	InFlight            int    `json:"in_flight"`
}

// StatusCoverageRow is one entry in coverage.by_app.
type StatusCoverageRow struct {
	App        string  `json:"app"`
	Modules    int     `json:"modules"`
	Summarised int     `json:"summarised"`
	Pct        float64 `json:"pct"`
}

// StatusCoverage wraps coverage.by_app — matches the legacy MCP tool's
// nested map[string]any{"by_app": [...]} shape.
type StatusCoverage struct {
	ByApp []StatusCoverageRow `json:"by_app"`
}

// StatusDetailRow is one failure recorded in enrich_attempts for the run.
type StatusDetailRow struct {
	ModuleID     int64  `json:"module_id"`
	ErrorClass   string `json:"error_class"`
	ErrorMessage string `json:"error_message_redacted"`
	AttemptNo    int    `json:"attempt_no"`
}

// StatusDetail wraps the per-run failed-attempt block.
type StatusDetail struct {
	RunID    string            `json:"run_id"`
	Failures []StatusDetailRow `json:"failures"`
}

// StatusPayload is the wire body returned by Status(). Field names match
// the legacy JSON shape so the MCP tool's external contract is unchanged.
type StatusPayload struct {
	Runs     []StatusRun    `json:"runs"`
	Coverage StatusCoverage `json:"coverage"`
	Detail   *StatusDetail  `json:"detail,omitempty"`
}

// Status returns recent enrich_runs, sweeps stale in_progress rows to
// 'interrupted', and (when opts.RunID is set) the failed-module detail
// block for that run.
//
// The sweep side-effect is intentional — see KBC-ENRICH-SESSION-MONITOR;
// it's the cross-session liveness check.
func Status(ctx context.Context, db *sql.DB, opts StatusOptions) (*StatusPayload, error) {
	if db == nil {
		return nil, fmt.Errorf("Status: nil db")
	}
	if opts.Limit < 1 {
		opts.Limit = 20
	}
	if opts.Limit > 200 {
		opts.Limit = 200
	}

	// Side-effect: sweep stale in_progress rows.
	if _, err := SweepInterrupted(db, StatusStaleAfter); err != nil {
		return nil, fmt.Errorf("sweep: %w", err)
	}

	runs, err := statusQueryRuns(ctx, db, opts.App, opts.Limit)
	if err != nil {
		return nil, fmt.Errorf("list runs: %w", err)
	}
	coverage, err := statusQueryCoverage(ctx, db, opts.App)
	if err != nil {
		return nil, fmt.Errorf("coverage: %w", err)
	}

	out := &StatusPayload{Runs: runs, Coverage: coverage}

	if opts.RunID != "" {
		detail, err := statusQueryDetail(ctx, db, opts.RunID)
		if err != nil {
			return nil, fmt.Errorf("detail: %w", err)
		}
		out.Detail = detail
	}
	return out, nil
}

func statusQueryRuns(ctx context.Context, db *sql.DB, app string, limit int) ([]StatusRun, error) {
	q := `
		SELECT run_id::text, app, model, status,
		       EXTRACT(EPOCH FROM (now() - started_at))::bigint,
		       EXTRACT(EPOCH FROM (now() - last_heartbeat_at))::bigint,
		       completed, failed, total_target
		  FROM enrich_runs`
	args := []any{}
	if app != "" {
		args = append(args, app)
		q += " WHERE app = $1"
	}
	q += " ORDER BY started_at DESC LIMIT "
	args = append(args, limit)
	q += fmt.Sprintf("$%d", len(args))

	rows, err := db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	out := []StatusRun{}
	for rows.Next() {
		var r StatusRun
		if err := rows.Scan(
			&r.RunID, &r.App, &r.Model, &r.Status,
			&r.StartedAgoSec, &r.LastHeartbeatAgoSec,
			&r.Completed, &r.Failed, &r.TotalTarget,
		); err != nil {
			return nil, err
		}
		r.InFlight = max(r.TotalTarget-r.Completed-r.Failed, 0)
		out = append(out, r)
	}
	return out, rows.Err()
}

func statusQueryCoverage(ctx context.Context, db *sql.DB, app string) (StatusCoverage, error) {
	q := `
		SELECT app,
		       COUNT(*) FILTER (WHERE NOT is_vendored) AS total,
		       COUNT(*) FILTER (WHERE summary IS NOT NULL AND summary <> '' AND NOT is_vendored) AS summarised
		  FROM modules`
	args := []any{}
	if app != "" {
		args = append(args, app)
		q += " WHERE app = $1"
	}
	q += " GROUP BY app ORDER BY app"

	rows, err := db.QueryContext(ctx, q, args...)
	if err != nil {
		return StatusCoverage{}, err
	}
	defer func() { _ = rows.Close() }()

	out := StatusCoverage{ByApp: []StatusCoverageRow{}}
	for rows.Next() {
		var row StatusCoverageRow
		var appName sql.NullString
		if err := rows.Scan(&appName, &row.Modules, &row.Summarised); err != nil {
			return StatusCoverage{}, err
		}
		row.App = appName.String
		if row.Modules > 0 {
			row.Pct = float64(row.Summarised) / float64(row.Modules) * 100.0
		}
		out.ByApp = append(out.ByApp, row)
	}
	return out, rows.Err()
}

func statusQueryDetail(ctx context.Context, db *sql.DB, runID string) (*StatusDetail, error) {
	rows, err := db.QueryContext(ctx, `
		SELECT module_id, COALESCE(error_class,''),
		       COALESCE(error_message_redacted,''), attempt_no
		  FROM enrich_attempts
		 WHERE run_id = $1::uuid
		   AND status IN ('failure','timeout')
		 ORDER BY module_id, attempt_no DESC`, runID)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	out := &StatusDetail{RunID: runID, Failures: []StatusDetailRow{}}
	for rows.Next() {
		var r StatusDetailRow
		if err := rows.Scan(&r.ModuleID, &r.ErrorClass, &r.ErrorMessage, &r.AttemptNo); err != nil {
			return nil, err
		}
		out.Failures = append(out.Failures, r)
	}
	return out, rows.Err()
}
