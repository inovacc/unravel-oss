//go:build integration

/*
Copyright (c) 2026 Security Research

Integration coverage for RecordAttempt's transactional counter bump
(hardening finding #11). The attempt INSERT and the enrich_runs counter
UPDATE must commit atomically so completed/failed never drift from the
actual count of enrich_attempts rows.

Requires Postgres (testcontainers via Docker, or UNRAVEL_TEST_DSN). Skips
under -short / when Docker is unavailable via dbtest.StartPostgresOrSkip.
*/

package kbenrich_test

import (
	"context"
	"errors"
	"testing"

	"github.com/inovacc/unravel-oss/pkg/knowledge/kb/dbtest"
	"github.com/inovacc/unravel-oss/pkg/knowledge/kbenrich"
)

func TestRecordAttempt_CounterMatchesAttempts(t *testing.T) {
	conn, _ := dbtest.StartPostgresOrSkip(t)
	ctx := context.Background()

	app := "whatsapp"
	run, err := kbenrich.StartRun(ctx, conn, kbenrich.StartRunOptions{
		App: app, TotalTarget: 5, Model: "haiku",
	})
	if err != nil {
		t.Fatalf("StartRun: %v", err)
	}

	const nSuccess, nFail = 3, 2
	for i := 0; i < nSuccess; i++ {
		m := seedModule(t, conn, app)
		if _, err := kbenrich.RecordAttempt(ctx, conn, kbenrich.RecordAttemptOptions{
			RunID: run.RunID, ModuleID: m, Status: "success", ModelUsed: "haiku",
		}); err != nil {
			t.Fatalf("RecordAttempt success: %v", err)
		}
	}
	for i := 0; i < nFail; i++ {
		m := seedModule(t, conn, app)
		if _, err := kbenrich.RecordAttempt(ctx, conn, kbenrich.RecordAttemptOptions{
			RunID: run.RunID, ModuleID: m, Status: "failure",
			ErrorClass: "timeout", ErrorMsg: "boom", ModelUsed: "haiku",
		}); err != nil {
			t.Fatalf("RecordAttempt failure: %v", err)
		}
	}

	// Counters must exactly match the attempt rows — the whole point of the
	// transaction is that they cannot drift.
	var completed, failed int
	if err := conn.QueryRowContext(ctx,
		`SELECT completed, failed FROM enrich_runs WHERE run_id = $1::uuid`,
		run.RunID).Scan(&completed, &failed); err != nil {
		t.Fatalf("read counters: %v", err)
	}
	if completed != nSuccess {
		t.Errorf("completed = %d, want %d", completed, nSuccess)
	}
	if failed != nFail {
		t.Errorf("failed = %d, want %d", failed, nFail)
	}

	var attemptRows int
	if err := conn.QueryRowContext(ctx,
		`SELECT count(*) FROM enrich_attempts WHERE run_id = $1::uuid`,
		run.RunID).Scan(&attemptRows); err != nil {
		t.Fatalf("count attempts: %v", err)
	}
	if attemptRows != nSuccess+nFail {
		t.Errorf("attempt rows = %d, want %d", attemptRows, nSuccess+nFail)
	}
	if completed+failed != attemptRows {
		t.Errorf("counter drift: completed+failed=%d != attempts=%d", completed+failed, attemptRows)
	}
}

// TestRecordAttempt_MissingRunRollsBack proves that when the parent run
// does not exist, the FK violation aborts the whole operation (no attempt
// row, no counter change) and surfaces ErrRecordRunNotFound — the
// transaction never half-commits.
func TestRecordAttempt_MissingRunRollsBack(t *testing.T) {
	conn, _ := dbtest.StartPostgresOrSkip(t)
	ctx := context.Background()

	m := seedModule(t, conn, "whatsapp")
	const ghost = "00000000-0000-0000-0000-000000000000"

	_, err := kbenrich.RecordAttempt(ctx, conn, kbenrich.RecordAttemptOptions{
		RunID: ghost, ModuleID: m, Status: "success", ModelUsed: "haiku",
	})
	if err == nil {
		t.Fatalf("RecordAttempt against missing run: want error, got nil")
	}
	if !errors.Is(err, kbenrich.ErrRecordRunNotFound) {
		t.Fatalf("want ErrRecordRunNotFound, got %v", err)
	}

	var n int
	if err := conn.QueryRowContext(ctx,
		`SELECT count(*) FROM enrich_attempts WHERE run_id = $1::uuid`,
		ghost).Scan(&n); err != nil {
		t.Fatalf("count attempts: %v", err)
	}
	if n != 0 {
		t.Errorf("attempt rows for missing run = %d, want 0 (no half-commit)", n)
	}
}
