/*
Copyright (c) 2026 Security Research
*/
package drift

import (
	"context"
	"database/sql"
	"fmt"
	"log/slog"
)

// WriteAlerts inserts one row into drift_alerts for every drifted metric
// in verdict.Deltas, and emits a slog.Warn per alert. Non-drifted metrics
// are NOT persisted (sparse-alert design — drift_alerts only contains
// signal rows). Returns the count of rows written.
//
// No-ops (no rows written, no warns) when:
//   - verdict.Drifted is false
//   - verdict.Skipped is true (e.g., no baseline / run too small)
func WriteAlerts(ctx context.Context, db *sql.DB, app string, verdict DriftVerdict) (int, error) {
	if !verdict.Drifted || verdict.Skipped {
		return 0, nil
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return 0, fmt.Errorf("begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	n := 0
	for _, d := range verdict.Deltas {
		if !d.Drifted {
			continue
		}
		_, err := tx.ExecContext(ctx,
			`INSERT INTO drift_alerts
			   (app, run_id, baseline_run_id, metric, baseline_value,
			    recent_value, relative_delta, threshold_relative)
			 VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
			app, verdict.RecentRunID, verdict.BaselineRunID, d.Metric,
			d.BaselineValue, d.RecentValue, d.RelativeDelta, verdict.ThresholdRelative)
		if err != nil {
			return n, fmt.Errorf("insert drift_alert: %w", err)
		}
		slog.Warn("kb drift alert",
			"app", app,
			"run_id", verdict.RecentRunID,
			"baseline_run_id", verdict.BaselineRunID,
			"metric", d.Metric,
			"baseline_value", d.BaselineValue,
			"recent_value", d.RecentValue,
			"relative_delta", d.RelativeDelta,
			"threshold", verdict.ThresholdRelative)
		n++
	}
	if err := tx.Commit(); err != nil {
		return n, fmt.Errorf("commit alerts: %w", err)
	}
	return n, nil
}
