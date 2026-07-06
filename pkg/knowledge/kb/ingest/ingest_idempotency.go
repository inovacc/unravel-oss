/*
Copyright (c) 2026 Security Research

Pre-transaction idempotency check for the v2.5 ingest writer.

Per D-30-IDEMPOTENCY: before the ingest transaction begins, check
whether knowledge_sources already has a row with the same
(kb_id, binary_sha256). If so, return a SkipResult and skip the
ingest with exit-0 semantics. The UNIQUE(kb_id, epoch) constraint
remains the actual security boundary; this check is for analyst
ergonomics + idempotent re-runs of `unravel kb capture`.

License: BSD-3-Clause.
*/

package ingest

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

// SkipResult signals that ingest should be skipped because an
// identical snapshot (same kb_id + binary_sha256) already exists.
//
// Epoch is int64 to match knowledge_sources.epoch BIGINT and
// identity.AllocateEpoch's return type — no truncation between layers.
type SkipResult struct {
	Epoch      int64     `json:"epoch"`
	KSID       string    `json:"ks_id"`
	CapturedAt time.Time `json:"captured_at"`
	Reason     string    `json:"reason"`
}

// CheckIdempotency runs a SELECT against knowledge_sources keyed by
// (kb_id, binary_sha256) per D-30-IDEMPOTENCY.
//
// Returns:
//   - (nil, nil) when no prior snapshot exists — caller proceeds with
//     ingest.
//   - (*SkipResult, nil) when a prior snapshot exists — caller exits 0
//     with the human-readable reason.
//   - (nil, err) on actual SQL errors.
//
// The query runs OUTSIDE the ingest transaction (best-effort pre-check).
func CheckIdempotency(ctx context.Context, db *sql.DB, kbID, binarySHA256 string) (*SkipResult, error) {
	if db == nil {
		return nil, errors.New("db is required")
	}
	if kbID == "" {
		return nil, errors.New("kb_id required")
	}
	if binarySHA256 == "" {
		return nil, errors.New("binary_sha256 required")
	}

	const q = `
		SELECT epoch, ks_id, captured_at
		FROM knowledge_sources
		WHERE kb_id = $1 AND binary_sha256 = $2
		LIMIT 1
	`

	var (
		epoch      int64
		ksID       string
		capturedAt int64
	)
	err := db.QueryRowContext(ctx, q, kbID, binarySHA256).Scan(&epoch, &ksID, &capturedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("idempotency lookup: %w", err)
	}

	at := time.UnixMilli(capturedAt)
	reason := fmt.Sprintf(
		"snapshot already ingested at epoch %d (captured_at=%s)",
		epoch, at.Format(time.RFC3339),
	)
	return &SkipResult{
		Epoch:      epoch,
		KSID:       ksID,
		CapturedAt: at,
		Reason:     reason,
	}, nil
}
