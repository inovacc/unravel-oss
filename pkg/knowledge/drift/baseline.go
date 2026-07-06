/*
Copyright (c) 2026 Security Research
*/
package drift

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
)

// ErrNoBaseline indicates no baseline is set for the requested app.
var ErrNoBaseline = errors.New("no baseline set for app")

// ErrRunTooSmall indicates the run candidate has fewer modules processed
// than the min-run-size threshold (pass force=true to override).
var ErrRunTooSmall = errors.New("run too small to baseline (use force to override)")

// ShowBaseline returns the run_id currently tagged as baseline for app.
// Returns ErrNoBaseline if none is set.
func ShowBaseline(ctx context.Context, db *sql.DB, app string) (string, error) {
	var id string
	err := db.QueryRowContext(ctx,
		`SELECT run_id::text FROM enrich_runs WHERE app = $1 AND baseline_for IS NOT NULL`,
		app).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return "", ErrNoBaseline
	}
	if err != nil {
		return "", fmt.Errorf("show baseline: %w", err)
	}
	return id, nil
}

// SetBaseline promotes runID to be the baseline for app, replacing any
// existing baseline atomically. Refuses runs with completed <
// minRunSize unless force is true. The unique partial index on
// enrich_runs(app) WHERE baseline_for IS NOT NULL is honoured by the
// clear-then-set sequence inside a single transaction.
func SetBaseline(ctx context.Context, db *sql.DB, app string, runID string, force bool, minRunSize int) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	var runApp string
	var modsProcessed int
	err = tx.QueryRowContext(ctx,
		`SELECT app, completed FROM enrich_runs WHERE run_id = $1::uuid`,
		runID).Scan(&runApp, &modsProcessed)
	if errors.Is(err, sql.ErrNoRows) {
		return fmt.Errorf("run_id=%s not found", runID)
	}
	if err != nil {
		return fmt.Errorf("verify run: %w", err)
	}
	if runApp != app {
		return fmt.Errorf("run_id=%s belongs to app=%q, not %q", runID, runApp, app)
	}
	if !force && modsProcessed < minRunSize {
		return fmt.Errorf("%w: modules_processed=%d, min=%d",
			ErrRunTooSmall, modsProcessed, minRunSize)
	}

	if _, err := tx.ExecContext(ctx,
		`UPDATE enrich_runs SET baseline_for = NULL WHERE app = $1 AND baseline_for IS NOT NULL`,
		app); err != nil {
		return fmt.Errorf("clear existing baseline: %w", err)
	}
	if _, err := tx.ExecContext(ctx,
		`UPDATE enrich_runs SET baseline_for = $1 WHERE run_id = $2::uuid`,
		app, runID); err != nil {
		return fmt.Errorf("set baseline: %w", err)
	}
	return tx.Commit()
}

// ClearBaseline removes the baseline tag for app (no-op if none set).
func ClearBaseline(ctx context.Context, db *sql.DB, app string) error {
	if _, err := db.ExecContext(ctx,
		`UPDATE enrich_runs SET baseline_for = NULL WHERE app = $1 AND baseline_for IS NOT NULL`,
		app); err != nil {
		return fmt.Errorf("clear baseline: %w", err)
	}
	return nil
}

// LoadBaseline returns the RunMetrics of the current baseline for app, or
// ErrNoBaseline if none is set. Internally: ShowBaseline + ComputeMetrics.
func LoadBaseline(ctx context.Context, db *sql.DB, app string) (RunMetrics, error) {
	runID, err := ShowBaseline(ctx, db, app)
	if err != nil {
		return RunMetrics{}, err
	}
	return ComputeMetrics(ctx, db, runID)
}
