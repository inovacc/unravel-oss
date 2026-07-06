/*
Copyright (c) 2026 Security Research
*/

package diff

import (
	"context"
	"database/sql"
	"fmt"
)

// FactSetDiff groups long-range fact-set differences by category.
type FactSetDiff struct {
	Added    map[string][]FactDiffEntry `json:"added"`
	Removed  map[string][]FactDiffEntry `json:"removed"`
	Modified map[string][]FactDiffEntry `json:"modified"`
}

// FactDiffEntry is a single fact change inside a FactSetDiff bucket.
type FactDiffEntry struct {
	Key      string `json:"key"`
	Value    string `json:"value,omitempty"`
	OldValue string `json:"old_value,omitempty"`
	NewValue string `json:"new_value,omitempty"`
}

// LongRangeDiff composes facts-only set-difference between two non-adjacent
// epochs. NEVER joins kb_diffs rows — it queries app_facts directly per
// D-30-LONGRANGE-IMPL, mitigating PITFALLS-CRIT-3 (long-range row explosion).
//
// Epoch params are int64 to match identity.AllocateEpoch and
// knowledge_sources.epoch column type.
//
// Returns an error when (toEpoch - fromEpoch) > 20 per D-30-LONGRANGE-CAP.
// The error message starts EXACTLY with "long-range diff capped at 20 epochs"
// — callers may strings.HasPrefix on that literal.
//
// Joins app_facts via the legacy knowledge_sources.app TEXT key
// (D-30-FACT-APP-LINK) — backfill of kb_id-keyed app_facts is deferred to
// Phase 34.
func LongRangeDiff(ctx context.Context, db *sql.DB, kbID string, fromEpoch, toEpoch int64) (*FactSetDiff, error) {
	if toEpoch-fromEpoch > 20 {
		return nil, fmt.Errorf("long-range diff capped at 20 epochs (requested %d); narrow range or use knowledge_source_evolution view", toEpoch-fromEpoch)
	}
	if toEpoch <= fromEpoch {
		return nil, fmt.Errorf("long-range diff requires toEpoch > fromEpoch, got from=%d to=%d", fromEpoch, toEpoch)
	}

	// Single-round-trip FULL OUTER JOIN over app_facts at both endpoints.
	// All inputs bound via $1/$2/$3 placeholders (T-30-02-01).
	const q = `
WITH prev AS (
    SELECT category, key, value
      FROM app_facts af
      JOIN knowledge_sources ks ON af.app = ks.app
     WHERE ks.kb_id = $1 AND ks.epoch = $2
),
next AS (
    SELECT category, key, value
      FROM app_facts af
      JOIN knowledge_sources ks ON af.app = ks.app
     WHERE ks.kb_id = $1 AND ks.epoch = $3
)
SELECT
    COALESCE(p.category, n.category) AS category,
    COALESCE(p.key, n.key)           AS key,
    p.value                          AS old_value,
    n.value                          AS new_value,
    (p.category IS NULL)             AS missing_prev,
    (n.category IS NULL)             AS missing_next
FROM prev p FULL OUTER JOIN next n
  ON p.category = n.category AND p.key = n.key
WHERE p.value IS DISTINCT FROM n.value
`
	rows, err := db.QueryContext(ctx, q, kbID, fromEpoch, toEpoch)
	if err != nil {
		return nil, fmt.Errorf("long-range query: %w", err)
	}
	defer func() { _ = rows.Close() }()

	out := &FactSetDiff{
		Added:    make(map[string][]FactDiffEntry),
		Removed:  make(map[string][]FactDiffEntry),
		Modified: make(map[string][]FactDiffEntry),
	}
	for rows.Next() {
		var cat, key string
		var oldVal, newVal sql.NullString
		var missingPrev, missingNext bool
		if err := rows.Scan(&cat, &key, &oldVal, &newVal, &missingPrev, &missingNext); err != nil {
			return nil, fmt.Errorf("scan long-range row: %w", err)
		}
		switch {
		case missingPrev:
			out.Added[cat] = append(out.Added[cat], FactDiffEntry{Key: key, Value: newVal.String})
		case missingNext:
			out.Removed[cat] = append(out.Removed[cat], FactDiffEntry{Key: key, Value: oldVal.String})
		default:
			out.Modified[cat] = append(out.Modified[cat], FactDiffEntry{Key: key, OldValue: oldVal.String, NewValue: newVal.String})
		}
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("long-range rows: %w", err)
	}
	return out, nil
}
