//go:build integration

/*
Copyright (c) 2026 Security Research

Integration tests for kbstore.Timeline. Boots a transient Postgres via
dbtest.StartPostgres, seeds a kb_apps row with multiple knowledge_sources
epochs and matching kb_diffs rows, then exercises Timeline end-to-end.

Covers:
  - TestTimeline_Basic       — ordered ASC by epoch, modules_delta is
                               populated from LAG (NULL on first row
                               normalized to 0), per-epoch diff counts
                               propagate from kb_diffs.
  - TestTimeline_Reverse     — Reverse=true flips the order newest-first.
  - TestTimeline_EmptyKbID   — kb_id with no rows returns empty Epochs,
                               not an error.
  - TestTimeline_Validation  — nil db / empty kb_id surface lowercase
                               wrapped errors.
*/

package store_test

import (
	"context"
	"database/sql"
	"testing"

	"github.com/inovacc/unravel-oss/pkg/knowledge/kb/dbtest"
	"github.com/inovacc/unravel-oss/pkg/knowledge/kb/store"
)

func seedKSEpoch(t *testing.T, db *sql.DB, kbID string, epoch int, capturedAt int64, modulesIndexed int, appVer, risk string, depth int) int64 {
	t.Helper()
	var id int64
	err := db.QueryRow(
		`INSERT INTO knowledge_sources (
		    app, epoch, source_path, source_kind, captured_at,
		    modules_indexed, bodies_indexed,
		    app_version, risk_level, depth_score,
		    kb_id, ks_id)
		 VALUES ($1, $2, '/tmp/seed', 'electron', $3, $4, 0, $5, $6, $7, $8, $9)
		 RETURNING id`,
		kbID, epoch, capturedAt, modulesIndexed, appVer, risk, depth, kbID, kbID+"-e",
	).Scan(&id)
	if err != nil {
		t.Fatalf("seed knowledge_sources epoch=%d: %v", epoch, err)
	}
	return id
}

func seedKBDiff(t *testing.T, db *sql.DB, fromID, toID int64, category, changeType, identifier string) {
	t.Helper()
	_, err := db.Exec(
		`INSERT INTO kb_diffs (from_source_id, to_source_id, category, change_type, identifier, payload)
		 VALUES ($1, $2, $3, $4, $5, '{}'::jsonb)`,
		fromID, toID, category, changeType, identifier,
	)
	if err != nil {
		t.Fatalf("seed kb_diff %s/%s: %v", category, identifier, err)
	}
}

func TestTimeline_Basic(t *testing.T) {
	db, _ := dbtest.StartPostgres(t)
	ctx := context.Background()

	const kbID = "kbtl000000000001"
	seedKBAppMinimal(t, db, kbID)

	id1 := seedKSEpoch(t, db, kbID, 1, 1000, 10, "1.0.0", "low", 50)
	id2 := seedKSEpoch(t, db, kbID, 2, 2000, 15, "1.1.0", "medium", 60)
	id3 := seedKSEpoch(t, db, kbID, 3, 3000, 14, "1.2.0", "medium", 65)

	// epoch 2 sees 2 new files vs epoch 1, epoch 3 sees 1 dep removed vs epoch 2.
	seedKBDiff(t, db, id1, id2, "file", "added", "/a.js")
	seedKBDiff(t, db, id1, id2, "file", "added", "/b.js")
	seedKBDiff(t, db, id2, id3, "dep", "removed", "lodash")
	_ = id3

	out, err := store.Timeline(ctx, db, store.TimelineOptions{KbID: kbID})
	if err != nil {
		t.Fatalf("Timeline: %v", err)
	}
	if out.KBID != kbID {
		t.Errorf("KBID = %q, want %q", out.KBID, kbID)
	}
	if len(out.Epochs) != 3 {
		t.Fatalf("epochs len = %d, want 3", len(out.Epochs))
	}

	// Chronological order.
	for i, want := range []int{1, 2, 3} {
		if out.Epochs[i].Epoch != want {
			t.Errorf("epoch[%d] = %d, want %d", i, out.Epochs[i].Epoch, want)
		}
	}

	// modules_delta: first=0 (NULL LAG), 2nd=+5, 3rd=-1.
	if got := out.Epochs[0].ModulesDelta; got != 0 {
		t.Errorf("epoch1 modules_delta = %d, want 0", got)
	}
	if got := out.Epochs[1].ModulesDelta; got != 5 {
		t.Errorf("epoch2 modules_delta = %d, want 5", got)
	}
	if got := out.Epochs[2].ModulesDelta; got != -1 {
		t.Errorf("epoch3 modules_delta = %d, want -1", got)
	}

	// diff_counts.
	if got := out.Epochs[1].DiffCounts["file"]; got != 2 {
		t.Errorf("epoch2 diff_counts[file] = %d, want 2", got)
	}
	if got := out.Epochs[2].DiffCounts["dep"]; got != 1 {
		t.Errorf("epoch3 diff_counts[dep] = %d, want 1", got)
	}
	if got := out.Epochs[0].DiffCounts; len(got) != 0 {
		t.Errorf("epoch1 diff_counts = %v, want empty", got)
	}

	// Pointer-typed nullable fields populated.
	if out.Epochs[0].AppVersion == nil || *out.Epochs[0].AppVersion != "1.0.0" {
		t.Errorf("epoch1 app_version = %v, want 1.0.0", out.Epochs[0].AppVersion)
	}
	if out.Epochs[1].RiskLevel == nil || *out.Epochs[1].RiskLevel != "medium" {
		t.Errorf("epoch2 risk_level = %v, want medium", out.Epochs[1].RiskLevel)
	}
	if out.Epochs[2].DepthScore == nil || *out.Epochs[2].DepthScore != 65 {
		t.Errorf("epoch3 depth_score = %v, want 65", out.Epochs[2].DepthScore)
	}
}

func TestTimeline_Reverse(t *testing.T) {
	db, _ := dbtest.StartPostgres(t)
	ctx := context.Background()

	const kbID = "kbtl000000000002"
	seedKBAppMinimal(t, db, kbID)
	_ = seedKSEpoch(t, db, kbID, 1, 1000, 5, "1.0", "low", 10)
	_ = seedKSEpoch(t, db, kbID, 2, 2000, 7, "1.1", "low", 12)

	out, err := store.Timeline(ctx, db, store.TimelineOptions{KbID: kbID, Reverse: true})
	if err != nil {
		t.Fatalf("Timeline reverse: %v", err)
	}
	if len(out.Epochs) != 2 {
		t.Fatalf("epochs len = %d, want 2", len(out.Epochs))
	}
	if out.Epochs[0].Epoch != 2 || out.Epochs[1].Epoch != 1 {
		t.Errorf("reverse order = [%d,%d], want [2,1]", out.Epochs[0].Epoch, out.Epochs[1].Epoch)
	}
}

func TestTimeline_EmptyKbID(t *testing.T) {
	db, _ := dbtest.StartPostgres(t)
	ctx := context.Background()

	out, err := store.Timeline(ctx, db, store.TimelineOptions{KbID: "kbtl999999999999"})
	if err != nil {
		t.Fatalf("Timeline unknown kb_id: %v", err)
	}
	if out == nil {
		t.Fatal("payload nil, want non-nil")
	}
	if len(out.Epochs) != 0 {
		t.Errorf("epochs len = %d, want 0 (empty range)", len(out.Epochs))
	}
}

func TestTimeline_Validation(t *testing.T) {
	ctx := context.Background()

	if _, err := store.Timeline(ctx, nil, store.TimelineOptions{KbID: "x"}); err == nil {
		t.Error("expected error for nil db")
	}

	db, _ := dbtest.StartPostgres(t)
	if _, err := store.Timeline(ctx, db, store.TimelineOptions{}); err == nil {
		t.Error("expected error for empty kb_id")
	}
}
