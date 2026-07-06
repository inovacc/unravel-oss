//go:build integration

package store_test

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/inovacc/unravel-oss/pkg/knowledge/kb/dbtest"
	"github.com/inovacc/unravel-oss/pkg/knowledge/kb/store"
	"github.com/inovacc/unravel-oss/pkg/knowledge/scorecard"
)

func TestInsertScorecard_RoundTrip(t *testing.T) {
	conn, _ := dbtest.StartPostgres(t)
	ctx := context.Background()

	// Seed prerequisites: a kb_apps row + a knowledge_sources row.
	const kbID = "270943e5bc622a72"
	now := time.Now().UnixMilli()
	if _, err := conn.ExecContext(ctx, `
		INSERT INTO kb_apps (kb_id, canonical_name, display_name, platform,
		                     first_seen_at, last_seen_at)
		VALUES ($1, 'whatsapp', 'WhatsApp', 'electron', $2, $2)
	`, kbID, now); err != nil {
		t.Fatalf("seed kb_apps: %v", err)
	}
	var sourceID int64
	if err := conn.QueryRowContext(ctx, `
		INSERT INTO knowledge_sources (app, epoch, source_path, source_kind, captured_at)
		VALUES ('whatsapp', 1, '/tmp/whatsapp.msix', 'msix', $1)
		RETURNING id
	`, now).Scan(&sourceID); err != nil {
		t.Fatalf("seed knowledge_sources: %v", err)
	}

	sc := &scorecard.Scorecard{
		KbID: kbID,
		Dimensions: []scorecard.DimScore{
			{ID: "identity", Name: "Identity", Score: 90},
			{ID: "filesystem", Name: "Filesystem map", Score: 95},
			{ID: "binary_surface", Name: "Binary surface", Score: 90},
			{ID: "source_layer", Name: "Source layer", Score: 90},
			{ID: "ipc", Name: "IPC", Score: 75},
			{ID: "api", Name: "API surface", Score: 85},
			{ID: "wire", Name: "Wire formats", Score: 85},
			{ID: "storage", Name: "Storage schemas", Score: 90},
			{ID: "auth", Name: "Auth surface", Score: 80},
			{ID: "crypto", Name: "Crypto", Score: 85},
			{ID: "state_machines", Name: "State machines", Score: 80},
			{ID: "behavior", Name: "Behavior", Score: 85},
		},
		Coverage:    11,
		CitationsOK: true,
	}
	log := &scorecard.IterationLog{
		Records: []scorecard.IterationRecord{
			{ID: "iter-1", Iter: 1, TS: "2026-05-06T18:56:51Z", Mean: 78, Coverage: 7, PostMean: 85, PostCoverage: 11, CitationsOK: true},
		},
	}

	tx, err := conn.BeginTx(ctx, nil)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	if err := store.InsertScorecard(ctx, tx, kbID, sourceID, sc, log); err != nil {
		_ = tx.Rollback()
		t.Fatalf("InsertScorecard: %v", err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatalf("commit: %v", err)
	}

	var (
		gotKbID                        string
		meanScore, dimsAt80            int
		dimsAt50, dimsAt20, iterations int
		loopExit, citationsOK          bool
		scJSONRaw, iterJSONRaw         []byte
	)
	if err := conn.QueryRowContext(ctx, `
		SELECT kb_id, mean_score, dims_at_80, dims_at_50, dims_at_20,
		       loop_exit, citations_ok, iterations, scorecard_json, iterations_jsonl
		  FROM kb_scorecards WHERE source_id = $1
	`, sourceID).Scan(
		&gotKbID, &meanScore, &dimsAt80, &dimsAt50, &dimsAt20,
		&loopExit, &citationsOK, &iterations, &scJSONRaw, &iterJSONRaw,
	); err != nil {
		t.Fatalf("select: %v", err)
	}
	if gotKbID != kbID {
		t.Errorf("kb_id = %q, want %q", gotKbID, kbID)
	}
	if meanScore != 858 {
		t.Errorf("mean_score = %d, want 858", meanScore)
	}
	if dimsAt80 != 11 || dimsAt50 != 12 || dimsAt20 != 12 {
		t.Errorf("aggregates = (%d,%d,%d) want (11,12,12)", dimsAt80, dimsAt50, dimsAt20)
	}
	if !loopExit {
		t.Errorf("loop_exit = false, want true")
	}
	if !citationsOK {
		t.Errorf("citations_ok = false, want true")
	}
	if iterations != 1 {
		t.Errorf("iterations = %d, want 1", iterations)
	}
	var rt scorecard.Scorecard
	if err := json.Unmarshal(scJSONRaw, &rt); err != nil {
		t.Errorf("unmarshal scorecard_json: %v", err)
	}
	if rt.KbID != kbID || len(rt.Dimensions) != 12 {
		t.Errorf("scorecard_json round-trip mismatch: %+v", rt)
	}
	var rtLog scorecard.IterationLog
	if err := json.Unmarshal(iterJSONRaw, &rtLog); err != nil {
		t.Errorf("unmarshal iterations_jsonl: %v", err)
	}
	if len(rtLog.Records) != 1 || rtLog.Records[0].ID != "iter-1" {
		t.Errorf("iterations_jsonl round-trip mismatch: %+v", rtLog)
	}

	// Idempotency: second insert with same source_id replaces the first row.
	sc.CitationsOK = false
	tx2, _ := conn.BeginTx(ctx, nil)
	if err := store.InsertScorecard(ctx, tx2, kbID, sourceID, sc, log); err != nil {
		_ = tx2.Rollback()
		t.Fatalf("second InsertScorecard: %v", err)
	}
	if err := tx2.Commit(); err != nil {
		t.Fatalf("commit2: %v", err)
	}
	var rowCount int
	if err := conn.QueryRowContext(ctx, `SELECT COUNT(*) FROM kb_scorecards WHERE source_id = $1`, sourceID).Scan(&rowCount); err != nil {
		t.Fatalf("count: %v", err)
	}
	if rowCount != 1 {
		t.Errorf("idempotent re-insert produced %d rows, want 1", rowCount)
	}
	var citAfter bool
	if err := conn.QueryRowContext(ctx, `SELECT citations_ok FROM kb_scorecards WHERE source_id = $1`, sourceID).Scan(&citAfter); err != nil {
		t.Fatalf("scan citations: %v", err)
	}
	if citAfter {
		t.Errorf("citations_ok = true after upsert with false")
	}
}
