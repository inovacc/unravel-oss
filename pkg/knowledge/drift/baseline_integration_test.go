//go:build integration

/*
Copyright (c) 2026 Security Research
*/
package drift_test

import (
	"context"
	"errors"
	"testing"

	"github.com/inovacc/unravel-oss/pkg/knowledge/drift"
	"github.com/inovacc/unravel-oss/pkg/knowledge/kb/dbtest"
)

func TestBaseline_SetShowClear(t *testing.T) {
	ctx := context.Background()
	db, _ := dbtest.StartPostgresOrSkip(t)
	defer func() { _ = db.Close() }()

	// Seed two runs for the same app, both above MinRunSize (25 default).
	runID1 := seedFixture(t, ctx, db, "canary", 30, 25, 3, 2, 5000)
	runID2 := seedFixture(t, ctx, db, "canary", 30, 24, 4, 2, 5500)

	if _, err := drift.ShowBaseline(ctx, db, "canary"); !errors.Is(err, drift.ErrNoBaseline) {
		t.Fatalf("ShowBaseline empty: got err=%v, want ErrNoBaseline", err)
	}

	if err := drift.SetBaseline(ctx, db, "canary", runID1, false, 25); err != nil {
		t.Fatalf("SetBaseline: %v", err)
	}

	got, err := drift.ShowBaseline(ctx, db, "canary")
	if err != nil {
		t.Fatalf("ShowBaseline: %v", err)
	}
	if got != runID1 {
		t.Fatalf("ShowBaseline = %q, want %q", got, runID1)
	}

	// Re-set: unique partial index honoured (the inner tx clears first)
	if err := drift.SetBaseline(ctx, db, "canary", runID2, false, 25); err != nil {
		t.Fatalf("SetBaseline re-set: %v", err)
	}
	got, _ = drift.ShowBaseline(ctx, db, "canary")
	if got != runID2 {
		t.Fatalf("after re-set ShowBaseline = %q, want %q", got, runID2)
	}

	if err := drift.ClearBaseline(ctx, db, "canary"); err != nil {
		t.Fatalf("ClearBaseline: %v", err)
	}
	if _, err := drift.ShowBaseline(ctx, db, "canary"); !errors.Is(err, drift.ErrNoBaseline) {
		t.Fatalf("ShowBaseline after clear: got err=%v, want ErrNoBaseline", err)
	}

	// Clear is idempotent
	if err := drift.ClearBaseline(ctx, db, "canary"); err != nil {
		t.Fatalf("ClearBaseline idempotent: %v", err)
	}
}

func TestBaseline_SetRefusesTooSmallWithoutForce(t *testing.T) {
	ctx := context.Background()
	db, _ := dbtest.StartPostgresOrSkip(t)
	defer func() { _ = db.Close() }()

	// 10 modules; threshold 25 → must refuse without force.
	tinyRun := seedFixture(t, ctx, db, "canary", 10, 10, 0, 0, 1000)

	err := drift.SetBaseline(ctx, db, "canary", tinyRun, false, 25)
	if !errors.Is(err, drift.ErrRunTooSmall) {
		t.Fatalf("SetBaseline tiny: got err=%v, want ErrRunTooSmall", err)
	}

	// With force=true, should succeed
	if err := drift.SetBaseline(ctx, db, "canary", tinyRun, true, 25); err != nil {
		t.Fatalf("SetBaseline tiny w/ force: %v", err)
	}

	got, _ := drift.ShowBaseline(ctx, db, "canary")
	if got != tinyRun {
		t.Fatalf("after force-set ShowBaseline = %q, want %q", got, tinyRun)
	}
}

func TestBaseline_SetWrongAppFails(t *testing.T) {
	ctx := context.Background()
	db, _ := dbtest.StartPostgresOrSkip(t)
	defer func() { _ = db.Close() }()

	runID := seedFixture(t, ctx, db, "appA", 30, 25, 3, 2, 5000)

	err := drift.SetBaseline(ctx, db, "appB", runID, false, 25)
	if err == nil {
		t.Fatalf("SetBaseline cross-app: got nil err, want app-mismatch error")
	}
}

func TestBaseline_SetMissingRun(t *testing.T) {
	ctx := context.Background()
	db, _ := dbtest.StartPostgresOrSkip(t)
	defer func() { _ = db.Close() }()

	err := drift.SetBaseline(ctx, db, "canary", "00000000-0000-0000-0000-000000000000", false, 25)
	if err == nil {
		t.Fatalf("SetBaseline missing run: got nil err, want not-found error")
	}
}

func TestLoadBaseline_ReturnsMetrics(t *testing.T) {
	ctx := context.Background()
	db, _ := dbtest.StartPostgresOrSkip(t)
	defer func() { _ = db.Close() }()

	runID := seedFixture(t, ctx, db, "canary", 30, 27, 2, 1, 4000)
	if err := drift.SetBaseline(ctx, db, "canary", runID, false, 25); err != nil {
		t.Fatalf("SetBaseline: %v", err)
	}

	m, err := drift.LoadBaseline(ctx, db, "canary")
	if err != nil {
		t.Fatalf("LoadBaseline: %v", err)
	}
	if m.RunID != runID {
		t.Errorf("RunID = %q, want %q", m.RunID, runID)
	}
	if m.ModulesProcessed != 30 {
		t.Errorf("ModulesProcessed = %d, want 30", m.ModulesProcessed)
	}
}

func TestLoadBaseline_NoBaseline(t *testing.T) {
	ctx := context.Background()
	db, _ := dbtest.StartPostgresOrSkip(t)
	defer func() { _ = db.Close() }()

	_, err := drift.LoadBaseline(ctx, db, "never-set")
	if !errors.Is(err, drift.ErrNoBaseline) {
		t.Fatalf("LoadBaseline never-set: got err=%v, want ErrNoBaseline", err)
	}
}
