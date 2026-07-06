//go:build integration

package migrations_test

import (
	"database/sql"
	"testing"

	"github.com/inovacc/unravel-oss/pkg/knowledge/kb/dbtest"
)

// TestMigration_010_KbScorecardsExists asserts migration 000010 created
// the kb_scorecards table with the expected columns and the UNIQUE
// constraint on source_id.
func TestMigration_010_KbScorecardsExists(t *testing.T) {
	conn, _ := dbtest.StartPostgres(t)

	var rel sql.NullString
	if err := conn.QueryRow(`SELECT to_regclass('public.kb_scorecards')::text`).Scan(&rel); err != nil {
		t.Fatalf("to_regclass: %v", err)
	}
	if !rel.Valid || rel.String != "kb_scorecards" {
		t.Fatalf("kb_scorecards table not registered: %+v", rel)
	}

	wantCols := []string{
		"id", "kb_id", "source_id",
		"mean_score", "dims_at_80", "dims_at_50", "dims_at_20",
		"loop_exit", "citations_ok",
		"iterations", "iterations_jsonl", "scorecard_json", "generated_at",
	}
	for _, col := range wantCols {
		var n int
		row := conn.QueryRow(`
			SELECT COUNT(*)
			  FROM information_schema.columns
			 WHERE table_schema = 'public'
			   AND table_name = 'kb_scorecards'
			   AND column_name = $1`, col)
		if err := row.Scan(&n); err != nil {
			t.Fatalf("scan %s: %v", col, err)
		}
		if n != 1 {
			t.Errorf("kb_scorecards.%s: expected 1 column, got %d", col, n)
		}
	}

	// UNIQUE(source_id) — there must be a unique constraint covering
	// exactly the source_id column on kb_scorecards.
	var uniqCount int
	if err := conn.QueryRow(`
		SELECT COUNT(*)
		  FROM information_schema.table_constraints tc
		  JOIN information_schema.constraint_column_usage ccu
		    ON tc.constraint_name = ccu.constraint_name
		 WHERE tc.table_schema = 'public'
		   AND tc.table_name = 'kb_scorecards'
		   AND tc.constraint_type = 'UNIQUE'
		   AND ccu.column_name = 'source_id'`).Scan(&uniqCount); err != nil {
		t.Fatalf("scan unique: %v", err)
	}
	if uniqCount < 1 {
		t.Errorf("UNIQUE(source_id) constraint missing on kb_scorecards")
	}

	// Three named indexes must be present.
	for _, idx := range []string{
		"idx_kb_scorecards_kb_id_generated_at",
		"idx_kb_scorecards_mean",
		"idx_kb_scorecards_loop_exit_partial",
	} {
		var n int
		if err := conn.QueryRow(`
			SELECT COUNT(*) FROM pg_indexes
			 WHERE schemaname = 'public' AND indexname = $1`, idx).Scan(&n); err != nil {
			t.Fatalf("scan idx %s: %v", idx, err)
		}
		if n != 1 {
			t.Errorf("expected index %s, got count=%d", idx, n)
		}
	}
}
