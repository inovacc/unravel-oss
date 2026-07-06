/*
Copyright (c) 2026 Security Research
*/

// Package store — P59 kb_scorecards ingest writer (EMIT-02).
//
// InsertScorecard runs inside the caller's *sql.Tx (single-tx safe per v2.5
// D-30; analog: pkg/knowledge/kb/ingest/ingest.go writeBodies/writeFacts).
// Uses database/sql with $N placeholders (A5 — NOT pgx). Idempotent via
// ON CONFLICT (source_id) DO UPDATE so the same source_id always reflects
// the latest scorecard write.
package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"

	"github.com/inovacc/unravel-oss/pkg/knowledge/scorecard"
)

// InsertScorecard upserts one row into kb_scorecards. mean_score column
// receives mean10 (sum*10/12) computed from sc.Dimensions.
func InsertScorecard(
	ctx context.Context,
	tx *sql.Tx,
	kbID string,
	sourceID int64,
	sc *scorecard.Scorecard,
	log *scorecard.IterationLog,
) error {
	if tx == nil {
		return fmt.Errorf("scorecard writer: nil tx")
	}
	if sc == nil {
		return fmt.Errorf("scorecard writer: nil scorecard")
	}

	mean10, at80, at50, at20 := computeAggregates(sc)
	loopExit := deriveLoopExit(sc, log, at80)
	iterCount := 0
	if log != nil {
		iterCount = len(log.Records)
	}

	scJSON, err := json.Marshal(sc)
	if err != nil {
		return fmt.Errorf("marshal scorecard: %w", err)
	}
	var iterJSON any
	if log != nil {
		raw, err := json.Marshal(log)
		if err != nil {
			return fmt.Errorf("marshal iteration log: %w", err)
		}
		iterJSON = raw
	}

	const q = `
		INSERT INTO kb_scorecards (
			kb_id, source_id, mean_score,
			dims_at_80, dims_at_50, dims_at_20,
			loop_exit, citations_ok,
			iterations, iterations_jsonl, scorecard_json
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
		ON CONFLICT (source_id) DO UPDATE SET
			kb_id            = EXCLUDED.kb_id,
			mean_score       = EXCLUDED.mean_score,
			dims_at_80       = EXCLUDED.dims_at_80,
			dims_at_50       = EXCLUDED.dims_at_50,
			dims_at_20       = EXCLUDED.dims_at_20,
			loop_exit        = EXCLUDED.loop_exit,
			citations_ok     = EXCLUDED.citations_ok,
			iterations       = EXCLUDED.iterations,
			iterations_jsonl = EXCLUDED.iterations_jsonl,
			scorecard_json   = EXCLUDED.scorecard_json,
			generated_at     = now()
	`
	if _, err := tx.ExecContext(ctx, q,
		kbID, sourceID, mean10,
		at80, at50, at20,
		loopExit, sc.CitationsOK,
		iterCount, iterJSON, scJSON,
	); err != nil {
		return fmt.Errorf("insert kb_scorecard: %w", err)
	}
	return nil
}

func computeAggregates(sc *scorecard.Scorecard) (mean10, at80, at50, at20 int) {
	sum := 0
	for _, d := range sc.Dimensions {
		sum += d.Score
		if d.Score >= 80 {
			at80++
		}
		if d.Score >= 50 {
			at50++
		}
		if d.Score >= 20 {
			at20++
		}
	}
	if len(sc.Dimensions) > 0 {
		mean10 = sum * 10 / 12
	}
	return
}

func deriveLoopExit(sc *scorecard.Scorecard, log *scorecard.IterationLog, at80 int) bool {
	if log != nil && len(log.Records) > 0 {
		last := log.Records[len(log.Records)-1]
		return last.CitationsOK && last.PostCoverage >= 10 && last.PostMean >= 80
	}
	return sc.CitationsOK && at80 >= 10
}
