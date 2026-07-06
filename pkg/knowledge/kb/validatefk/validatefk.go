/*
Copyright (c) 2026 Security Research

Package validatefk promotes the Phase-29 NOT VALID FK on
knowledge_sources.kb_id to a fully-validated constraint. Per
D-34-FK-VALIDATE, the VALIDATE step lives in its own service / CLI
command and is never folded into the backfill transaction.

The constraint name is fixed by migration 000004 (kb_identity):
knowledge_sources_kb_id_fkey. Postgres' ALTER TABLE ... VALIDATE
CONSTRAINT acquires a SHARE UPDATE EXCLUSIVE lock — concurrent reads
proceed, but writers are briefly blocked. Operators are expected to
run this after `unravel kb backfill` has populated all legacy rows.
*/
package validatefk

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
)

// constraintName is the FK installed by migration 000004_kb_identity.
const constraintName = "knowledge_sources_kb_id_fkey"

// ValidateFK runs `ALTER TABLE knowledge_sources VALIDATE CONSTRAINT
// knowledge_sources_kb_id_fkey`. Idempotent: re-running against a
// constraint already promoted to VALID is a Postgres-level no-op.
//
// On failure, the wrapper attempts a diagnostic count of orphan rows
// (knowledge_sources.kb_id values absent from kb_apps) and returns the
// D-34-VALIDATE-FAIL-MODE error shape so analysts know to run
// `unravel kb backfill` first or inspect with the embedded SELECT.
func ValidateFK(ctx context.Context, db *sql.DB) error {
	if db == nil {
		return errors.New("nil db")
	}

	_, err := db.ExecContext(ctx,
		`ALTER TABLE knowledge_sources VALIDATE CONSTRAINT `+constraintName,
	)
	if err == nil {
		return nil
	}

	// Diagnostic: count orphans so the analyst sees actionable detail.
	var orphans int
	diagErr := db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM knowledge_sources
		 WHERE kb_id IS NOT NULL
		   AND kb_id NOT IN (SELECT kb_id FROM kb_apps)`,
	).Scan(&orphans)
	if diagErr != nil {
		// Diagnostic itself failed — surface the original VALIDATE error.
		return fmt.Errorf("validate constraint: %w", err)
	}

	return fmt.Errorf(
		"validate failed: %d rows have kb_id not present in kb_apps; "+
			"run \"unravel kb backfill\" first or inspect with: "+
			"SELECT id, app, kb_id FROM knowledge_sources "+
			"WHERE kb_id NOT IN (SELECT kb_id FROM kb_apps): %w",
		orphans, err,
	)
}
