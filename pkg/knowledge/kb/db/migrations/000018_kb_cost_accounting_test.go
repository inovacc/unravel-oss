//go:build integration

/*
Copyright (c) 2026 Security Research
*/

package migrations_test

import (
	"database/sql"
	"testing"

	"github.com/inovacc/unravel-oss/pkg/knowledge/kb/dbtest"
)

// TestMigration_018_KBCostAccountingSchema asserts migration 000018 added the
// token columns to enrich_attempts / enrich_runs and created kb_cost_rollup
// with a composite (scope,key) primary key.
func TestMigration_018_KBCostAccountingSchema(t *testing.T) {
	conn, _ := dbtest.StartPostgresOrSkip(t)

	// kb_cost_rollup table exists.
	var rel sql.NullString
	if err := conn.QueryRow(
		`SELECT to_regclass('public.kb_cost_rollup')::text`).Scan(&rel); err != nil {
		t.Fatalf("to_regclass kb_cost_rollup: %v", err)
	}
	if !rel.Valid || rel.String != "kb_cost_rollup" {
		t.Fatalf("kb_cost_rollup not registered: %+v", rel)
	}

	wantCols := map[string][]string{
		"enrich_attempts": {"input_tokens", "output_tokens"},
		"enrich_runs":     {"total_tokens", "total_cost_micro_usd"},
		"kb_cost_rollup": {
			"scope", "key", "total_tokens",
			"total_cost_micro_usd", "attempts", "updated_at",
		},
	}
	for table, cols := range wantCols {
		for _, col := range cols {
			var n int
			if err := conn.QueryRow(`
				SELECT COUNT(*) FROM information_schema.columns
				 WHERE table_schema='public' AND table_name=$1 AND column_name=$2`,
				table, col).Scan(&n); err != nil {
				t.Fatalf("scan %s.%s: %v", table, col, err)
			}
			if n != 1 {
				t.Errorf("%s.%s: expected 1 column, got %d", table, col, n)
			}
		}
	}

	// Composite primary key (scope,key).
	var pkCols int
	if err := conn.QueryRow(`
		SELECT COUNT(*) FROM information_schema.table_constraints tc
		  JOIN information_schema.key_column_usage kcu
		    ON tc.constraint_name = kcu.constraint_name
		 WHERE tc.table_name='kb_cost_rollup'
		   AND tc.constraint_type='PRIMARY KEY'`).Scan(&pkCols); err != nil {
		t.Fatalf("scan pk: %v", err)
	}
	if pkCols != 2 {
		t.Errorf("kb_cost_rollup PK column count = %d, want 2", pkCols)
	}
}
