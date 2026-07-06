/*
Copyright (c) 2026 Security Research
*/
// Timeline — chronological epoch deltas for a KB app.
//
// Extracted out of pkg/mcp/tools/kb.go (kbTimelineHandler) and
// cmd/kb_timeline.go so the supervisor dispatcher
// (internal/supervisor/kb_dispatch.go) and the MCP tool/CLI share one
// source of truth for the DB-reading portion of kb_timeline. See
// docs/superpowers/plans/2026-05-27-v2.17-thinclient-refactor.md
// (Phase A4).
//
// The wire shape (TimelinePayload) is byte-for-byte compatible with the
// JSON the MCP tool emitted prior to the A4 extraction:
//
//	{
//	  "kb_id":  "<canonical>",
//	  "epochs": [TimelineEpoch{...}, ...]
//	}
//
// Alias resolution remains in the caller (pkg/knowledge/kb/identity);
// Timeline operates on the already-canonical kb_id so the store layer
// stays free of identity-system dependencies.
package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
)

// TimelineOptions controls Timeline's behavior.
//
// KbID is required and must already be the canonical id (alias
// resolution is the caller's responsibility — see
// pkg/knowledge/kb/identity.ResolveAlias).
//
// Reverse mirrors the legacy `--reverse` CLI flag: when true the result
// is ordered newest-first; otherwise oldest-first.
type TimelineOptions struct {
	KbID    string `json:"kb_id"`
	Reverse bool   `json:"reverse,omitempty"`
}

// TimelineEpoch is one row in the timeline. Wire-shape mirrors the
// kbEpochInfo struct the MCP tool emitted prior to the A4 extraction.
type TimelineEpoch struct {
	Epoch          int            `json:"epoch"`
	CapturedAt     int64          `json:"captured_at"`
	AppVersion     *string        `json:"app_version"`
	RiskLevel      *string        `json:"risk_level"`
	DepthScore     *int           `json:"depth_score"`
	ModulesIndexed int            `json:"modules_indexed"`
	ModulesDelta   int            `json:"modules_delta"`
	DiffCounts     map[string]int `json:"diff_counts"`
}

// TimelinePayload is the response body shared by the MCP tool, the
// CLI, and the supervisor dispatcher.
type TimelinePayload struct {
	KBID   string          `json:"kb_id"`
	Epochs []TimelineEpoch `json:"epochs"`
}

// Timeline returns the chronological epoch deltas for opts.KbID.
//
// Two queries run sequentially:
//
//  1. knowledge_sources rows for the kb_id ordered by epoch ascending,
//     with a windowed LAG to compute modules_delta vs. the previous
//     epoch (NULL on the first row, normalized to 0).
//  2. per-epoch, per-category diff counts from kb_diffs joined on
//     to_source_id → knowledge_sources, grouped by (epoch, category).
//
// Results are merged in-memory and reversed when opts.Reverse is true.
// An empty kb_id returns a non-nil payload with an empty Epochs slice
// (not an error) so callers can distinguish "no data" from "bad input"
// — empty/missing kb_id surfaces as a wrapped error.
func Timeline(ctx context.Context, db *sql.DB, opts TimelineOptions) (*TimelinePayload, error) {
	if db == nil {
		return nil, errors.New("kb_timeline: nil db")
	}
	if opts.KbID == "" {
		return nil, errors.New("kb_timeline: kb_id required")
	}

	rows, err := db.QueryContext(ctx, `
		SELECT epoch, captured_at, app_version, risk_level, depth_score, modules_indexed,
		       modules_indexed - LAG(modules_indexed) OVER (ORDER BY epoch) as modules_delta
		FROM knowledge_sources
		WHERE kb_id = $1
		ORDER BY epoch ASC
	`, opts.KbID)
	if err != nil {
		return nil, fmt.Errorf("query evolution: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var epochs []TimelineEpoch
	for rows.Next() {
		var ei TimelineEpoch
		var av, rl *string
		var ds *int
		var md *int // LAG can be NULL for first row
		if err := rows.Scan(&ei.Epoch, &ei.CapturedAt, &av, &rl, &ds, &ei.ModulesIndexed, &md); err != nil {
			return nil, fmt.Errorf("scan evolution: %w", err)
		}
		ei.AppVersion = av
		ei.RiskLevel = rl
		ei.DepthScore = ds
		if md != nil {
			ei.ModulesDelta = *md
		}
		ei.DiffCounts = make(map[string]int)
		epochs = append(epochs, ei)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate evolution: %w", err)
	}

	dRows, err := db.QueryContext(ctx, `
		SELECT ks.epoch, d.category, COUNT(*)
		FROM kb_diffs d
		JOIN knowledge_sources ks ON ks.id = d.to_source_id
		WHERE ks.kb_id = $1
		GROUP BY ks.epoch, d.category
	`, opts.KbID)
	if err != nil {
		return nil, fmt.Errorf("query diff counts: %w", err)
	}
	defer func() { _ = dRows.Close() }()

	idx := make(map[int]*TimelineEpoch, len(epochs))
	for i := range epochs {
		idx[epochs[i].Epoch] = &epochs[i]
	}
	for dRows.Next() {
		var te int
		var cat string
		var count int
		if err := dRows.Scan(&te, &cat, &count); err != nil {
			return nil, fmt.Errorf("scan diff count: %w", err)
		}
		if ei, ok := idx[te]; ok {
			ei.DiffCounts[cat] = count
		}
	}
	if err := dRows.Err(); err != nil {
		return nil, fmt.Errorf("iterate diff counts: %w", err)
	}

	if opts.Reverse {
		for i, j := 0, len(epochs)-1; i < j; i, j = i+1, j-1 {
			epochs[i], epochs[j] = epochs[j], epochs[i]
		}
	}

	if epochs == nil {
		epochs = []TimelineEpoch{}
	}
	return &TimelinePayload{KBID: opts.KbID, Epochs: epochs}, nil
}
