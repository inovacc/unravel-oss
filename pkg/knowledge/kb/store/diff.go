/*
Copyright (c) 2026 Security Research
*/
package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"

	"github.com/inovacc/unravel-oss/pkg/knowledge/kb/diff"
	"github.com/inovacc/unravel-oss/pkg/knowledge/kb/identity"

	"github.com/lib/pq"
)

// DiffOptions controls Diff: KBID may be either a canonical or alias id
// (Diff resolves it server-side). FromEpoch < ToEpoch; if gap==1 the
// fast consecutive path is used, otherwise the long-range bucket-merge
// path. Categories restricts the result to that filter set (empty = all).
type DiffOptions struct {
	KBID       string
	FromEpoch  int64
	ToEpoch    int64
	Categories []string
}

// DiffChangeItem is one (added/removed/modified) entry within a category.
type DiffChangeItem struct {
	Identifier string `json:"identifier"`
	Data       any    `json:"data"`
}

// DiffCategoryBucket aggregates per-category added/removed/modified.
type DiffCategoryBucket struct {
	Added    []any `json:"added,omitempty"`
	Removed  []any `json:"removed,omitempty"`
	Modified []any `json:"modified,omitempty"`
}

// DiffPayload is the wire shape Diff returns. The supervisor verb
// kb.diff aliases this; the MCP handler reshapes it into the legacy
// kbDiffResult wire envelope (Mode field, KbID, FromEpoch, ToEpoch).
type DiffPayload struct {
	KBID       string                         `json:"kb_id"`
	FromEpoch  int64                          `json:"from_epoch"`
	ToEpoch    int64                          `json:"to_epoch"`
	Mode       string                         `json:"mode"` // "consecutive" | "longrange"
	Categories map[string]*DiffCategoryBucket `json:"categories"`
}

// Diff is the v2.17.1 kbstore wrapper that lets the supervisor kb.diff
// verb back the unravel_kb_diff MCP tool without direct DB access.
// Branches on gap (consecutive vs long-range) and resolves aliases
// server-side so the MCP tool can drop both kbDB.QueryContext sites it
// previously had.
func Diff(ctx context.Context, db *sql.DB, opts DiffOptions) (*DiffPayload, error) {
	if db == nil {
		return nil, fmt.Errorf("Diff: nil db")
	}
	if opts.KBID == "" {
		return nil, fmt.Errorf("Diff: kb_id required")
	}
	if opts.FromEpoch >= opts.ToEpoch {
		return nil, fmt.Errorf("Diff: from (%d) must be < to (%d)", opts.FromEpoch, opts.ToEpoch)
	}

	canonical, err := identity.ResolveAlias(ctx, db, opts.KBID)
	if err != nil {
		return nil, fmt.Errorf("Diff: resolve alias: %w", err)
	}

	gap := opts.ToEpoch - opts.FromEpoch
	if gap == 1 {
		return diffConsecutive(ctx, db, canonical, opts.FromEpoch, opts.ToEpoch, opts.Categories)
	}
	return diffLongRange(ctx, db, canonical, opts.FromEpoch, opts.ToEpoch, opts.Categories)
}

func diffConsecutive(ctx context.Context, db *sql.DB, kbID string, from, to int64, categories []string) (*DiffPayload, error) {
	query := `
SELECT d.category, d.change_type, d.identifier, d.payload
FROM kb_diffs d
JOIN knowledge_sources s1 ON d.from_source_id = s1.id
JOIN knowledge_sources s2 ON d.to_source_id = s2.id
WHERE s1.kb_id = $1 AND s1.epoch = $2 AND s2.epoch = $3 AND s2.kb_id = $1`
	args := []any{kbID, from, to}
	if len(categories) > 0 {
		query += " AND d.category = ANY($4)"
		args = append(args, pq.Array(categories))
	}
	rows, err := db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("query kb_diffs: %w", err)
	}
	defer func() { _ = rows.Close() }()

	out := &DiffPayload{
		KBID:       kbID,
		FromEpoch:  from,
		ToEpoch:    to,
		Mode:       "consecutive",
		Categories: make(map[string]*DiffCategoryBucket),
	}
	for rows.Next() {
		var cat, changeType, identifier string
		var payloadJSON []byte
		if err := rows.Scan(&cat, &changeType, &identifier, &payloadJSON); err != nil {
			return nil, fmt.Errorf("scan kb_diff: %w", err)
		}
		var payload any
		if err := json.Unmarshal(payloadJSON, &payload); err != nil {
			payload = string(payloadJSON)
		}
		if out.Categories[cat] == nil {
			out.Categories[cat] = &DiffCategoryBucket{}
		}
		item := DiffChangeItem{Identifier: identifier, Data: payload}
		switch changeType {
		case "added":
			out.Categories[cat].Added = append(out.Categories[cat].Added, item)
		case "removed":
			out.Categories[cat].Removed = append(out.Categories[cat].Removed, item)
		case "modified":
			out.Categories[cat].Modified = append(out.Categories[cat].Modified, item)
		}
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("rows: %w", err)
	}
	return out, nil
}

func diffLongRange(ctx context.Context, db *sql.DB, kbID string, from, to int64, categories []string) (*DiffPayload, error) {
	payload, err := diff.LongRangeDiff(ctx, db, kbID, from, to)
	if err != nil {
		return nil, err
	}
	filter := make(map[string]bool, len(categories))
	for _, c := range categories {
		filter[c] = true
	}
	out := &DiffPayload{
		KBID:       kbID,
		FromEpoch:  from,
		ToEpoch:    to,
		Mode:       "longrange",
		Categories: make(map[string]*DiffCategoryBucket),
	}
	merge := func(src map[string][]diff.FactDiffEntry, sink func(*DiffCategoryBucket, any)) {
		for cat, items := range src {
			if len(filter) > 0 && !filter[cat] {
				continue
			}
			if out.Categories[cat] == nil {
				out.Categories[cat] = &DiffCategoryBucket{}
			}
			for _, item := range items {
				sink(out.Categories[cat], item)
			}
		}
	}
	merge(payload.Added, func(c *DiffCategoryBucket, v any) { c.Added = append(c.Added, v) })
	merge(payload.Removed, func(c *DiffCategoryBucket, v any) { c.Removed = append(c.Removed, v) })
	merge(payload.Modified, func(c *DiffCategoryBucket, v any) { c.Modified = append(c.Modified, v) })
	return out, nil
}
