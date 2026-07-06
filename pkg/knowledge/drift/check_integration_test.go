//go:build integration

/*
Copyright (c) 2026 Security Research
*/
package drift_test

import (
	"context"
	"testing"

	"github.com/inovacc/unravel-oss/pkg/knowledge/drift"
	"github.com/inovacc/unravel-oss/pkg/knowledge/kb/dbtest"
)

func TestCheck_NoBaseline_Skips(t *testing.T) {
	ctx := context.Background()
	db, _ := dbtest.StartPostgresOrSkip(t)
	defer func() { _ = db.Close() }()
	runID := seedFixture(t, ctx, db, "canary-nob", 30, 27, 2, 1, 4000)

	v, err := drift.Check(ctx, db, runID, drift.DefaultOpts())
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if !v.Skipped || v.SkipReason != "no_baseline" {
		t.Fatalf("Check no-baseline: got Skipped=%v reason=%q, want true/no_baseline",
			v.Skipped, v.SkipReason)
	}
	if v.RecentRunID != runID {
		t.Errorf("RecentRunID = %q, want %q", v.RecentRunID, runID)
	}
}

func TestCheck_TooSmall_Skips(t *testing.T) {
	ctx := context.Background()
	db, _ := dbtest.StartPostgresOrSkip(t)
	defer func() { _ = db.Close() }()

	baselineID := seedFixture(t, ctx, db, "canary-small", 30, 27, 2, 1, 4000)
	if err := drift.SetBaseline(ctx, db, "canary-small", baselineID, false, 25); err != nil {
		t.Fatalf("SetBaseline: %v", err)
	}
	smallID := seedFixture(t, ctx, db, "canary-small", 10, 9, 1, 0, 4000)

	v, err := drift.Check(ctx, db, smallID, drift.DefaultOpts())
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if !v.Skipped || v.SkipReason != "run_too_small" {
		t.Fatalf("Check too-small: got Skipped=%v reason=%q, want true/run_too_small",
			v.Skipped, v.SkipReason)
	}
}

func TestCheck_DriftFiresAndWritesAlerts(t *testing.T) {
	ctx := context.Background()
	db, _ := dbtest.StartPostgresOrSkip(t)
	defer func() { _ = db.Close() }()

	// Baseline: 30 modules, 27 clean success, 2 opus, 1 human-review
	baselineID := seedFixture(t, ctx, db, "canary-drift", 30, 27, 2, 1, 4000)
	if err := drift.SetBaseline(ctx, db, "canary-drift", baselineID, false, 25); err != nil {
		t.Fatalf("SetBaseline: %v", err)
	}

	// Degraded: same 30 modules total, but only 20 clean + 8 opus + 2 HR.
	// success_rate: baseline 29/30=0.967 → recent 28/30=0.933, |Δ|/0.967 ≈ 0.035 → no drift
	// escalation_rate: baseline 2/30=0.067 → recent 8/30=0.267, Δ/0.067 ≈ 3.0 → DRIFT
	// human_review_rate: baseline 1/30=0.033 → recent 2/30=0.067, |Δ|/0.033 ≈ 1.0 → DRIFT
	degradedID := seedFixture(t, ctx, db, "canary-drift", 30, 20, 8, 2, 4000)

	v, err := drift.Check(ctx, db, degradedID, drift.DefaultOpts())
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if v.Skipped {
		t.Fatalf("Check skipped unexpectedly: reason=%q", v.SkipReason)
	}
	if !v.Drifted {
		t.Fatalf("Drifted=false; expected drift on degraded run\n verdict=%+v", v)
	}

	var n int
	if err := db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM drift_alerts WHERE run_id = $1`, degradedID).Scan(&n); err != nil {
		t.Fatalf("count alerts: %v", err)
	}
	if n < 1 {
		t.Fatalf("expected at least one drift_alerts row, got %d", n)
	}
}
