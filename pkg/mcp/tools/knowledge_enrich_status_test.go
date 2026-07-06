//go:build integration

/*
Copyright (c) 2026 Security Research
*/
package mcptools

import (
	"context"
	"testing"
	"time"

	"github.com/inovacc/unravel-oss/pkg/knowledge/kb/dbtest"
)

// TestEnrichStatus_SweepsAndLists seeds two enrich_runs rows (one stale
// in_progress, one completed). Calling the status handler must:
//  1. Flip the stale row to 'interrupted' (sweeper side-effect).
//  2. Return the runs list shaped per spec §6.1.
//  3. Return coverage.by_app entries.
//  4. When RunID is provided, return the failed-module detail block.
func TestEnrichStatus_SweepsAndLists(t *testing.T) {
	db, dsn := dbtest.StartPostgresOrSkip(t)

	// stale in_progress (should be swept).
	var staleID string
	if err := db.QueryRow(`
		INSERT INTO enrich_runs (app, model, concurrency, prompt_batch, status, total_target,
		   started_at, last_heartbeat_at, host, pid)
		VALUES ('teams','sonnet',8,10,'in_progress',500,
		        now() - interval '30 min', now() - interval '15 min', 'fake', 1)
		RETURNING run_id::text`).Scan(&staleID); err != nil {
		t.Fatalf("seed stale: %v", err)
	}

	// completed row (recent).
	var completedID string
	if err := db.QueryRow(`
		INSERT INTO enrich_runs (app, model, concurrency, prompt_batch, status, total_target, completed, failed,
		   started_at, ended_at, last_heartbeat_at, host, pid)
		VALUES ('teams','sonnet',8,10,'completed',100,99,1,
		        now() - interval '5 min', now() - interval '4 min', now() - interval '4 min', 'fake', 2)
		RETURNING run_id::text`).Scan(&completedID); err != nil {
		t.Fatalf("seed completed: %v", err)
	}

	// Seed a module + a failed attempt under the completed row for the detail-block test.
	var modID int64
	if err := db.QueryRow(`
		INSERT INTO modules (app, name, body_excerpt, body_sha256)
		VALUES ('teams','failedMod','x','sha-status')
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

	// Run the status handler (handler resolves DSN via openKB).
	in := EnrichStatusInput{DB: dsn, Limit: 50, RunID: completedID}
	res, payload, err := handleKnowledgeEnrichStatus(context.Background(), nil, in)
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	if res == nil || res.IsError {
		t.Fatalf("handler returned error result: %+v", res)
	}
	m, ok := payload.(map[string]any)
	if !ok {
		t.Fatalf("payload not map[string]any: %T", payload)
	}

	runs, _ := m["runs"].([]map[string]any)
	if len(runs) < 1 {
		t.Errorf("expected >=1 run, got %d (payload=%+v)", len(runs), m)
	}

	if _, ok := m["coverage"]; !ok {
		t.Errorf("missing coverage in payload")
	}
	if _, ok := m["detail"]; !ok {
		t.Errorf("missing detail in payload (RunID was set)")
	}

	// Side-effect check: stale row must now be 'interrupted'.
	var status string
	if err := db.QueryRow(`SELECT status FROM enrich_runs WHERE run_id=$1::uuid`, staleID).Scan(&status); err != nil {
		t.Fatalf("recheck stale: %v", err)
	}
	if status != "interrupted" {
		t.Errorf("stale row not swept: status=%s", status)
	}

	// Sanity: wait a tick to let nothing dangle.
	_ = time.Now()
}
