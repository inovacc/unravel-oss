/*
Copyright (c) 2026 Security Research
*/

package diff

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"
)

// ComputeConsecutive computes typed diffs between two consecutive epochs of
// the same kb_id. It SELECTs facts for each epoch joined via the legacy
// knowledge_sources.app TEXT bridge (D-30-FACT-APP-LINK), performs in-memory
// set-difference per category, and returns Diff rows ready for INSERT into
// kb_diffs.
//
// The tx must already hold the advisory lock from identity.AllocateEpoch.
// Phase 30 ingest invokes this at step 8 of the ingest transaction
// (D-30-INGEST-TX-SCOPE).
//
// Epoch params are int64 to match identity.AllocateEpoch return type
// (pkg/knowledge/kb/identity/merge.go:125 returns (int64, error)). NO int
// conversions anywhere — guards against narrowing on 32-bit builds
// (T-30-02-06).
//
// thisEpoch MUST equal prevEpoch+1 — D-30-DIFF-WRITES-ONLY-CONSECUTIVE; this
// primitive NEVER composes long-range diffs (use LongRangeDiff for that).
// Returns an error otherwise.
//
// Component category is NEVER emitted by Phase 30 ingest
// (D-30-COMPONENT-DEFERRED). Phase 31 classifier owns those writes.
func ComputeConsecutive(ctx context.Context, tx *sql.Tx, kbID string, prevEpoch, thisEpoch int64) ([]Diff, error) {
	if thisEpoch != prevEpoch+1 {
		return nil, fmt.Errorf("consecutive diff requires thisEpoch==prevEpoch+1, got prev=%d this=%d", prevEpoch, thisEpoch)
	}

	fromID, fromApp, err := resolveSource(ctx, tx, kbID, prevEpoch)
	if err != nil {
		return nil, fmt.Errorf("resolve from source: %w", err)
	}
	toID, toApp, err := resolveSource(ctx, tx, kbID, thisEpoch)
	if err != nil {
		return nil, fmt.Errorf("resolve to source: %w", err)
	}

	prevFacts, err := loadFacts(ctx, tx, fromApp)
	if err != nil {
		return nil, fmt.Errorf("load prev facts: %w", err)
	}
	nextFacts, err := loadFacts(ctx, tx, toApp)
	if err != nil {
		return nil, fmt.Errorf("load next facts: %w", err)
	}

	now := time.Now().UnixMilli()
	out := make([]Diff, 0, 16)

	// Each fact key is "<category>/<key>" so identical facts collide on the
	// composite key but cross-category collisions don't happen. The category
	// column drives downstream typing.
	allKeys := make(map[string]struct{}, len(prevFacts)+len(nextFacts))
	for k := range prevFacts {
		allKeys[k] = struct{}{}
	}
	for k := range nextFacts {
		allKeys[k] = struct{}{}
	}

	for k := range allKeys {
		oldVal, hasOld := prevFacts[k]
		newVal, hasNew := nextFacts[k]
		var change string
		switch {
		case !hasOld && hasNew:
			change = ChangeAdded
		case hasOld && !hasNew:
			change = ChangeRemoved
		case oldVal != newVal:
			change = ChangeModified
		default:
			continue
		}
		payload := FactDiff{Key: k, OldValue: oldVal, NewValue: newVal}
		raw, err := json.Marshal(payload)
		if err != nil {
			return nil, fmt.Errorf("marshal fact payload: %w", err)
		}
		ident, err := Identifier(CategoryFact, payload)
		if err != nil {
			return nil, fmt.Errorf("fact identifier: %w", err)
		}
		out = append(out, Diff{
			FromSourceID: fromID,
			ToSourceID:   toID,
			Category:     CategoryFact,
			ChangeType:   change,
			Identifier:   ident,
			Payload:      raw,
			ComputedAt:   now,
		})
	}

	return out, nil
}

// ResolveSource is the exported variant of resolveSource. Returns the
// (source_id, app) for (kb_id, epoch) in knowledge_sources. Used by the
// ingest pipeline to look up the prev-epoch source_id before snapshotting
// facts and computing diffs in memory.
func ResolveSource(ctx context.Context, tx *sql.Tx, kbID string, epoch int64) (int64, string, error) {
	return resolveSource(ctx, tx, kbID, epoch)
}

// resolveSource looks up the knowledge_sources row for (kb_id, epoch) and
// returns the bigint id PK and legacy app TEXT key. Parameterized SQL — no
// concatenation (T-30-02-01).
func resolveSource(ctx context.Context, tx *sql.Tx, kbID string, epoch int64) (int64, string, error) {
	var id int64
	var app string
	err := tx.QueryRowContext(ctx,
		`SELECT id, app FROM knowledge_sources WHERE kb_id = $1 AND epoch = $2`,
		kbID, epoch,
	).Scan(&id, &app)
	if err != nil {
		return 0, "", fmt.Errorf("kb_id=%s epoch=%d: %w", kbID, epoch, err)
	}
	return id, app, nil
}

// LoadFactsForApp is the exported variant of loadFacts. Returns app_facts
// keyed by "<category>/<key>" for the given app. Used by the ingest
// pipeline to snapshot prev-epoch facts BEFORE the current-epoch UPSERT
// overwrites them — otherwise ComputeConsecutive would see identical
// prev/next state and emit zero diffs.
func LoadFactsForApp(ctx context.Context, tx *sql.Tx, app string) (map[string]string, error) {
	return loadFacts(ctx, tx, app)
}

// ComputeFromSnapshots diffs two pre-loaded fact maps and returns the
// Diff rows ready to be written to kb_diffs. Identical semantics to
// ComputeConsecutive but without re-reading app_facts — required when
// the new-epoch UPSERT has already mutated the table.
func ComputeFromSnapshots(prev, next map[string]string, fromID, toID int64) ([]Diff, error) {
	now := time.Now().UnixMilli()
	out := make([]Diff, 0, 16)

	allKeys := make(map[string]struct{}, len(prev)+len(next))
	for k := range prev {
		allKeys[k] = struct{}{}
	}
	for k := range next {
		allKeys[k] = struct{}{}
	}

	for k := range allKeys {
		oldVal, hasOld := prev[k]
		newVal, hasNew := next[k]
		var change string
		switch {
		case !hasOld && hasNew:
			change = ChangeAdded
		case hasOld && !hasNew:
			change = ChangeRemoved
		case oldVal != newVal:
			change = ChangeModified
		default:
			continue
		}
		payload := FactDiff{Key: k, OldValue: oldVal, NewValue: newVal}
		raw, err := json.Marshal(payload)
		if err != nil {
			return nil, fmt.Errorf("marshal fact payload: %w", err)
		}
		ident, err := Identifier(CategoryFact, payload)
		if err != nil {
			return nil, fmt.Errorf("fact identifier: %w", err)
		}
		out = append(out, Diff{
			FromSourceID: fromID,
			ToSourceID:   toID,
			Category:     CategoryFact,
			ChangeType:   change,
			Identifier:   ident,
			Payload:      raw,
			ComputedAt:   now,
		})
	}
	return out, nil
}

// loadFacts returns app_facts keyed by "<category>/<key>" for the given
// legacy app TEXT bridge value (D-30-FACT-APP-LINK).
func loadFacts(ctx context.Context, tx *sql.Tx, app string) (map[string]string, error) {
	rows, err := tx.QueryContext(ctx,
		`SELECT category, key, value FROM app_facts WHERE app = $1`,
		app,
	)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	out := make(map[string]string, 32)
	for rows.Next() {
		var cat, k string
		var v sql.NullString
		if err := rows.Scan(&cat, &k, &v); err != nil {
			return nil, err
		}
		out[cat+"/"+k] = v.String
	}
	return out, rows.Err()
}
