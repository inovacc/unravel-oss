/*
Copyright (c) 2026 Security Research
*/

package identity

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

// MergeIDs collapses two kb_id rows by recording loser→winner in kb_aliases,
// rewriting any knowledge_sources rows still pointing at the loser (offsetting
// their epochs past the winner's max so the two lineages don't collide on
// UNIQUE(kb_id, epoch)), repointing kb_scorecards, and deleting the loser
// kb_apps row. Runs in a single tx with READ COMMITTED isolation per
// D-29-MERGE-SQL. Refuses to merge when winner is itself an alias
// (D-29-MERGE-RESOLVER, no chains). Returns the count of knowledge_sources
// rows updated.
func MergeIDs(ctx context.Context, db *sql.DB, loser, winner, mergedBy, reason string) (int64, error) {
	switch {
	case db == nil:
		return 0, errors.New("db is required")
	case loser == "":
		return 0, errors.New("loser kb_id required")
	case winner == "":
		return 0, errors.New("winner kb_id required")
	case loser == winner:
		return 0, errors.New("loser and winner must differ")
	}

	tx, err := db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		return 0, fmt.Errorf("begin tx: %w", err)
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback()
		}
	}()

	// Refuse merge chains: winner must itself not already be an alias.
	var winnerCanonical string
	err = tx.QueryRowContext(ctx,
		`SELECT canonical_kb_id FROM kb_aliases WHERE alias_kb_id = $1`, winner).
		Scan(&winnerCanonical)
	switch {
	case err == nil:
		return 0, fmt.Errorf("winner is a stale alias: %s", winner)
	case !errors.Is(err, sql.ErrNoRows):
		return 0, fmt.Errorf("check winner alias: %w", err)
	}

	// Existence checks — both kb_apps rows must exist.
	if err := mustExistKBApp(ctx, tx, loser); err != nil {
		return 0, fmt.Errorf("loser kb_id not found: %s", loser)
	}
	if err := mustExistKBApp(ctx, tx, winner); err != nil {
		return 0, fmt.Errorf("winner kb_id not found: %s", winner)
	}

	// 1) Insert alias mapping.
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO kb_aliases (alias_kb_id, canonical_kb_id, merged_at, merged_by, reason)
		 VALUES ($1, $2, $3, $4, $5)`,
		loser, winner, time.Now().Unix(), nullable(mergedBy), nullable(reason),
	); err != nil {
		return 0, fmt.Errorf("insert kb_aliases: %w", err)
	}

	// 2) Rewrite knowledge_sources.kb_id from loser to winner, offsetting the
	// loser's epochs past the winner's max so the two lineages don't collide
	// on knowledge_sources_kb_epoch_uq (UNIQUE(kb_id, epoch), migration
	// 000004). An identity fork (app updated → new content fingerprint → new
	// kb_id) means both lineages naturally start at epoch 1; a blind kb_id
	// rewrite would duplicate (winner, 1). We acquire the same per-app
	// advisory lock identity.AllocateEpoch uses so a concurrent ingest can't
	// allocate a winner epoch between our MAX() read and the rewrite
	// (D-29-EPOCH-ALLOC). The offset preserves each lineage's internal
	// ordering and appends the loser's history after the winner's; true
	// chronology is still recoverable from captured_at.
	//
	// Post-offset uniqueness invariant: the loser's epochs are already
	// unique within the loser kb_id (enforced by knowledge_sources_kb_epoch_uq
	// before this merge), and a constant monotonic add preserves that
	// uniqueness; adding MAX(winner.epoch) shifts the whole loser set strictly
	// above every winner epoch, so the unioned (winner, epoch) set stays
	// collision-free.
	if _, err := tx.ExecContext(ctx,
		`SELECT pg_advisory_xact_lock(hashtext('kb_epoch:' || $1))`, winner); err != nil {
		return 0, fmt.Errorf("advisory lock winner: %w", err)
	}
	var epochOffset int64
	if err := tx.QueryRowContext(ctx,
		`SELECT COALESCE(MAX(epoch), 0) FROM knowledge_sources WHERE kb_id = $1`,
		winner).Scan(&epochOffset); err != nil {
		return 0, fmt.Errorf("compute winner epoch offset: %w", err)
	}
	res, err := tx.ExecContext(ctx,
		`UPDATE knowledge_sources SET kb_id = $1, epoch = epoch + $2 WHERE kb_id = $3`,
		winner, epochOffset, loser)
	if err != nil {
		return 0, fmt.Errorf("update knowledge_sources: %w", err)
	}
	rowsUpdated, err := res.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("rows affected: %w", err)
	}

	// 3) Repoint kb_scorecards from loser to winner. kb_scorecards.kb_id is
	// NOT NULL REFERENCES kb_apps(kb_id) with no ON DELETE CASCADE (migration
	// 000010), so any loser scorecard would FK-block the loser kb_apps delete
	// below. source_id stays stable across the rewrite.
	if _, err := tx.ExecContext(ctx,
		`UPDATE kb_scorecards SET kb_id = $1 WHERE kb_id = $2`, winner, loser); err != nil {
		return 0, fmt.Errorf("update kb_scorecards: %w", err)
	}

	// 4) Delete loser kb_apps row. Aliases pointing to it via canonical_kb_id
	// won't exist (we just inserted loser→winner; the FK is on canonical_kb_id
	// which is winner, not loser).
	if _, err := tx.ExecContext(ctx,
		`DELETE FROM kb_apps WHERE kb_id = $1`, loser); err != nil {
		return 0, fmt.Errorf("delete kb_apps: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("commit: %w", err)
	}
	committed = true
	return rowsUpdated, nil
}

// ResolveAlias returns the canonical kb_id for input. When input has no
// kb_aliases row, returns input unchanged with nil error (D-29-MERGE-RESOLVER).
func ResolveAlias(ctx context.Context, db *sql.DB, input string) (string, error) {
	if db == nil {
		return "", errors.New("db is required")
	}
	if input == "" {
		return "", errors.New("input kb_id required")
	}
	var canonical string
	err := db.QueryRowContext(ctx,
		`SELECT canonical_kb_id FROM kb_aliases WHERE alias_kb_id = $1`, input).
		Scan(&canonical)
	if errors.Is(err, sql.ErrNoRows) {
		return input, nil
	}
	if err != nil {
		return "", fmt.Errorf("resolve alias: %w", err)
	}
	return canonical, nil
}

// AllocateEpoch acquires the per-app advisory tx lock and returns the next
// epoch number for kbID (COALESCE(MAX(epoch),0)+1). Caller owns tx
// lifecycle. The advisory lock is auto-released on tx commit/rollback,
// serializing concurrent ingest writers per D-29-EPOCH-ALLOC.
func AllocateEpoch(ctx context.Context, tx *sql.Tx, kbID string) (int64, error) {
	if tx == nil {
		return 0, errors.New("tx is required")
	}
	if kbID == "" {
		return 0, errors.New("kb_id required")
	}
	if _, err := tx.ExecContext(ctx,
		`SELECT pg_advisory_xact_lock(hashtext('kb_epoch:' || $1))`, kbID); err != nil {
		return 0, fmt.Errorf("advisory lock: %w", err)
	}
	var epoch int64
	if err := tx.QueryRowContext(ctx,
		`SELECT COALESCE(MAX(epoch), 0) + 1 FROM knowledge_sources WHERE kb_id = $1`,
		kbID).Scan(&epoch); err != nil {
		return 0, fmt.Errorf("compute next epoch: %w", err)
	}
	return epoch, nil
}

func mustExistKBApp(ctx context.Context, tx *sql.Tx, kbID string) error {
	var found int
	err := tx.QueryRowContext(ctx,
		`SELECT 1 FROM kb_apps WHERE kb_id = $1`, kbID).Scan(&found)
	if errors.Is(err, sql.ErrNoRows) {
		return sql.ErrNoRows
	}
	if err != nil {
		return fmt.Errorf("kb_apps existence: %w", err)
	}
	return nil
}

// nullable converts an empty string to a nil interface so the Postgres
// driver writes NULL rather than the empty string.
func nullable(s string) any {
	if s == "" {
		return nil
	}
	return s
}
