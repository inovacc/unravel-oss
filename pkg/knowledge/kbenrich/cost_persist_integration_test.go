//go:build integration

/*
Copyright (c) 2026 Security Research
*/
package kbenrich_test

import (
	"context"
	"testing"

	"github.com/inovacc/unravel-oss/pkg/knowledge/kb/dbtest"
)

// TestEnrichAttempt_PersistsCost smoke-checks that cost_micro_usd can be
// written and read on enrich_attempts (column added by migration 000017).
// Not a behavioural test of the write path — that's covered by the unit
// table in cost_test.go (added by this task).
func TestEnrichAttempt_PersistsCost(t *testing.T) {
	ctx := context.Background()
	db, _ := dbtest.StartPostgresOrSkip(t)

	var runID string
	if err := db.QueryRowContext(ctx,
		`INSERT INTO enrich_runs (app, status, started_at, model, concurrency, prompt_batch, total_target, host, pid)
	         VALUES ('canary', 'in_progress', now(), 'haiku', 1, 1, 100, 'test-host', 1234)
	         RETURNING run_id`).Scan(&runID); err != nil {
		t.Fatalf("seed enrich_runs: %v", err)
	}

	if _, err := db.ExecContext(ctx,
		`INSERT INTO modules (app, name, body_sha256, body_size)
		 VALUES ('canary', 'test-mod', 'sha', 100)`); err != nil {
		t.Fatalf("seed module: %v", err)
	}
	var modID int64
	if err := db.QueryRowContext(ctx, `SELECT id FROM modules WHERE name = 'test-mod'`).Scan(&modID); err != nil {
		t.Fatalf("get module id: %v", err)
	}

	if _, err := db.ExecContext(ctx,
		`INSERT INTO enrich_attempts (run_id, module_id, attempt_no, status, cost_micro_usd, model_used)
		 VALUES ($1, $2, 1, 'success', 12345, 'haiku')`, runID, modID); err != nil {
		t.Fatalf("insert with cost: %v", err)
	}

	var got int64
	if err := db.QueryRowContext(ctx,
		`SELECT cost_micro_usd FROM enrich_attempts WHERE run_id = $1`, runID).Scan(&got); err != nil {
		t.Fatalf("read back: %v", err)
	}
	if got != 12345 {
		t.Fatalf("cost_micro_usd = %d, want 12345", got)
	}
}
