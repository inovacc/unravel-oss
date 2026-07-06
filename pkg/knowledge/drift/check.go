/*
Copyright (c) 2026 Security Research
*/
package drift

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
)

// Check is the top-level orchestrator: ComputeMetrics(recent) →
// LoadBaseline → Compare → WriteAlerts. Returns the verdict.
//
// Callers should treat drift detection as non-fatal: a returned error
// indicates a diagnostic problem (e.g., DB read failed), not a verdict-
// generating event. The recommended pattern in kbenrich.Run() is:
//
//	if !o.NoDrift {
//	    if _, err := drift.Check(ctx, db, runID, drift.DefaultOpts()); err != nil {
//	        slog.Warn("drift check failed (non-fatal)", "err", err, "run_id", runID)
//	    }
//	}
//
// Skip semantics:
//   - run has fewer than Opts.MinRunSize modules → Skipped=true,
//     SkipReason="run_too_small"
//   - no baseline set for this app → Skipped=true, SkipReason="no_baseline"
func Check(ctx context.Context, db *sql.DB, runID string, o Opts) (DriftVerdict, error) {
	if o.ThresholdRelative <= 0 {
		o = DefaultOpts()
	}
	recent, err := ComputeMetrics(ctx, db, runID)
	if err != nil {
		return DriftVerdict{}, fmt.Errorf("compute recent: %w", err)
	}
	if recent.ModulesProcessed < o.MinRunSize {
		slog.Info("drift check skipped: run too small",
			"app", recent.App, "run_id", runID,
			"modules_processed", recent.ModulesProcessed, "min", o.MinRunSize)
		return DriftVerdict{
			Skipped: true, SkipReason: "run_too_small",
			RecentRunID: runID, ThresholdRelative: o.ThresholdRelative,
		}, nil
	}
	baseline, err := LoadBaseline(ctx, db, recent.App)
	if errors.Is(err, ErrNoBaseline) {
		slog.Info("drift check skipped: no baseline set",
			"app", recent.App, "run_id", runID)
		return DriftVerdict{
			Skipped: true, SkipReason: "no_baseline",
			RecentRunID: runID, ThresholdRelative: o.ThresholdRelative,
		}, nil
	}
	if err != nil {
		return DriftVerdict{}, fmt.Errorf("load baseline: %w", err)
	}

	v := Compare(baseline, recent, o)
	if v.Drifted {
		if _, err := WriteAlerts(ctx, db, recent.App, v); err != nil {
			// Persisting failed; row-level slog.Warn already emitted from
			// inside WriteAlerts for the rows that did insert. Surface the
			// error to the caller for telemetry but the verdict is intact.
			slog.Warn("drift WriteAlerts failed (verdict still returned)",
				"err", err, "app", recent.App, "run_id", runID)
		}
	}
	return v, nil
}
