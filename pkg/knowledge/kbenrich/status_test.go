//go:build integration

/*
Copyright (c) 2026 Security Research
*/
package kbenrich

import (
	"context"
	"testing"

	"github.com/inovacc/unravel-oss/pkg/knowledge/kb/dbtest"
)

// TestStatus_SweepsAndLists is the kbenrich-side mirror of the
// MCP tool's TestEnrichStatus_SweepsAndLists test. Seeds a stale
// in_progress run + a completed run and asserts that Status:
//
//  1. Sweeps the stale row to 'interrupted'.
//  2. Returns the runs list.
//  3. Returns coverage.by_app.
//  4. When opts.RunID is set, includes the failed-module detail block.
func TestStatus_SweepsAndLists(t *testing.T) {
	db, _ := dbtest.StartPostgresOrSkip(t)

	var staleID string
	if err := db.QueryRow(`
		INSERT INTO enrich_runs (app, model, concurrency, prompt_batch, status, total_target,
		   started_at, last_heartbeat_at, host, pid)
		VALUES ('teams','sonnet',8,10,'in_progress',500,
		        now() - interval '30 min', now() - interval '15 min', 'fake', 1)
		RETURNING run_id::text`).Scan(&staleID); err != nil {
		t.Fatalf("seed stale: %v", err)
	}

	var completedID string
	if err := db.QueryRow(`
		INSERT INTO enrich_runs (app, model, concurrency, prompt_batch, status, total_target, completed, failed,
		   started_at, ended_at, last_heartbeat_at, host, pid)
		VALUES ('teams','sonnet',8,10,'completed',100,99,1,
		        now() - interval '5 min', now() - interval '4 min', now() - interval '4 min', 'fake', 2)
		RETURNING run_id::text`).Scan(&completedID); err != nil {
		t.Fatalf("seed completed: %v", err)
	}

	var modID int64
	if err := db.QueryRow(`
		INSERT INTO modules (app, name, body_excerpt, body_sha256)
		VALUES ('teams','failedMod','x','sha-status-kbenrich')
		RETURNING id`).Scan(&modID); err != nil {
		t.Fatalf("seed module: %v", err)
	}
	if _, err := db.Exec(`
		INSERT INTO enrich_attempts (run_id, module_id, ended_at, status, error_class,
		   error_message_redacted, model_used, attempt_no)
		VALUES ($1::uuid, $2, now(), 'failure', 'json_parse', 'parse: bad token', 'sonnet', 1)`,
		completedID, modID); err != nil {
		t.Fatalf("seed attempt: %v", err)
	}

	out, err := Status(context.Background(), db, StatusOptions{App: "teams", Limit: 50, RunID: completedID})
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if len(out.Runs) < 1 {
		t.Errorf("want >=1 run, got %d", len(out.Runs))
	}
	if out.Coverage.ByApp == nil {
		t.Errorf("coverage.by_app missing")
	}
	if out.Detail == nil || len(out.Detail.Failures) != 1 {
		t.Errorf("detail failures: got %+v", out.Detail)
	}

	// Sweep side-effect: the stale row should now be 'interrupted'.
	var sweptStatus string
	if err := db.QueryRow(`SELECT status FROM enrich_runs WHERE run_id=$1::uuid`, staleID).Scan(&sweptStatus); err != nil {
		t.Fatalf("re-fetch stale: %v", err)
	}
	if sweptStatus != "interrupted" {
		t.Errorf("stale run status: got %q, want interrupted", sweptStatus)
	}
}

func TestStatus_NilDB(t *testing.T) {
	_, err := Status(context.Background(), nil, StatusOptions{})
	if err == nil {
		t.Fatalf("Status(nil db): want error, got nil")
	}
}
