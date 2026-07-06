/*
Copyright (c) 2026 Security Research
*/

// Package store — P59-04b kb_scorecards ingest helper.
//
// IngestScorecardFromDir is the public entry point for KB ingest pipelines
// (e.g. `unravel kb extract`, sweep, or future bulk-load) to attach a
// scorecard to a knowledge_sources row inside the caller's transaction.
//
// Reads <kbOutputDir>/SCORECARD.md presence as a sanity probe (no parse —
// the canonical payload is the in-memory *Scorecard) and serializes the
// scorecard via InsertScorecard.
//
// Deferred wiring: at P59 ship time the existing knowledge-ingest path in
// cmd/knowledge_ingest.go does not produce a kbID/sourceID alongside the
// SCORECARD.md output, so no in-tree caller invokes this helper yet. The
// public surface is in place so a future bulk-ingest pass (P60 corpus
// rescan) can call it without further package changes.
package store

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"

	"github.com/inovacc/unravel-oss/pkg/knowledge/scorecard"
)

// IngestScorecardFromDir attaches an in-memory Scorecard to a
// knowledge_sources row identified by sourceID. kbOutputDir is the directory
// where SCORECARD.md was written by EmitScorecardMD; it is used here only
// for a presence check (the actual JSONB persisted in kb_scorecards comes
// from the in-memory *Scorecard parameter).
func IngestScorecardFromDir(
	ctx context.Context,
	tx *sql.Tx,
	kbOutputDir, kbID string,
	sourceID int64,
	sc *scorecard.Scorecard,
	log *scorecard.IterationLog,
) error {
	mdPath := filepath.Join(kbOutputDir, "SCORECARD.md")
	if _, err := os.Stat(mdPath); err != nil {
		// Not fatal: caller may have ingest paths where SCORECARD.md was
		// not emitted. Continue and persist whatever in-memory state was
		// passed.
		_ = err
	}
	if err := InsertScorecard(ctx, tx, kbID, sourceID, sc, log); err != nil {
		return fmt.Errorf("ingest kb_scorecard: %w", err)
	}
	return nil
}
