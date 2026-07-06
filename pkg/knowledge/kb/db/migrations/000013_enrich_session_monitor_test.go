//go:build integration

package migrations_test

import (
	"database/sql"
	"testing"

	"github.com/inovacc/unravel-oss/pkg/knowledge/kb/dbtest"
)

// TestMigration_013_EnrichSessionMonitorSchema asserts migration 000013
// created the enrich_runs and enrich_attempts tables with the required
// columns and the partial index on status='in_progress'.
func TestMigration_013_EnrichSessionMonitorSchema(t *testing.T) {
	conn, _ := dbtest.StartPostgresOrSkip(t)

	for _, table := range []string{"enrich_runs", "enrich_attempts"} {
		var rel sql.NullString
		if err := conn.QueryRow(`SELECT to_regclass('public.' || $1)::text`, table).Scan(&rel); err != nil {
			t.Fatalf("to_regclass %s: %v", table, err)
		}
		if !rel.Valid || rel.String != table {
			t.Fatalf("%s table not registered: %+v", table, rel)
		}
	}

	wantRunCols := []string{
		"run_id", "app", "model", "concurrency", "prompt_batch",
		"started_at", "ended_at", "status", "total_target",
		"completed", "failed", "last_heartbeat_at", "host", "pid", "parent_run_id",
	}
	for _, col := range wantRunCols {
		var n int
		if err := conn.QueryRow(`
			SELECT COUNT(*) FROM information_schema.columns
			 WHERE table_schema='public' AND table_name='enrich_runs' AND column_name=$1`, col).Scan(&n); err != nil {
			t.Fatalf("scan enrich_runs.%s: %v", col, err)
		}
		if n != 1 {
			t.Errorf("enrich_runs.%s: expected 1 column, got %d", col, n)
		}
	}

	wantAttemptCols := []string{
		"attempt_id", "run_id", "module_id",
		"started_at", "ended_at", "status",
		"error_class", "error_message_redacted",
		"model_used", "prompt_tokens_est", "attempt_no",
	}
	for _, col := range wantAttemptCols {
		var n int
		if err := conn.QueryRow(`
			SELECT COUNT(*) FROM information_schema.columns
			 WHERE table_schema='public' AND table_name='enrich_attempts' AND column_name=$1`, col).Scan(&n); err != nil {
			t.Fatalf("scan enrich_attempts.%s: %v", col, err)
		}
		if n != 1 {
			t.Errorf("enrich_attempts.%s: expected 1 column, got %d", col, n)
		}
	}

	// Partial index on status='in_progress' for the sweeper.
	var n int
	if err := conn.QueryRow(`
		SELECT COUNT(*) FROM pg_indexes
		 WHERE schemaname='public'
		   AND tablename='enrich_runs'
		   AND indexdef ILIKE '%status%in_progress%'`).Scan(&n); err != nil {
		t.Fatalf("scan partial idx: %v", err)
	}
	if n < 1 {
		t.Errorf("expected partial index on enrich_runs(status='in_progress'), got count=%d", n)
	}
}
