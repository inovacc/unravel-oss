//go:build integration

/*
Copyright (c) 2026 Security Research

Integration tests for kbstore.PullGap / kbstore.PushAnswer. Boots a
transient Postgres via dbtest.StartPostgres, seeds app_facts rows, then
exercises the gap-resolution loop end-to-end.

Covers:
  - TestPullGap_EmptyWhenNoGaps   — value-not-null only ⇒ empty payload
                                    (GapID=0, Message set), no error.
  - TestPullGap_ReturnsOpenGap    — open row surfaced with category+key
                                    and prompt rendered.
  - TestPushAnswer_MarksAnswered  — UPDATE lands; subsequent PullGap
                                    skips the row.
  - TestPushAnswer_Validation     — GapID=0 ⇒ wrapped error; nil db ⇒
                                    wrapped error.
*/

package store_test

import (
	"context"
	"database/sql"
	"strings"
	"testing"

	"github.com/inovacc/unravel-oss/pkg/knowledge/kb/dbtest"
	"github.com/inovacc/unravel-oss/pkg/knowledge/kb/store"
)

func TestPullGap_EmptyWhenNoGaps(t *testing.T) {
	db, _ := dbtest.StartPostgres(t)
	ctx := context.Background()

	// One filled row (value not null) ⇒ no open gaps.
	_ = seedAppFactGap(t, db, "appA", "net", "endpoint",
		sql.NullString{String: "https://x", Valid: true},
		sql.NullString{})

	out, err := store.PullGap(ctx, db, store.PullGapOptions{App: "appA"})
	if err != nil {
		t.Fatalf("PullGap: %v", err)
	}
	if out == nil {
		t.Fatal("payload nil, want non-nil empty payload")
	}
	if out.GapID != 0 {
		t.Errorf("GapID = %d, want 0", out.GapID)
	}
	if out.Message == "" {
		t.Error("Message empty, want short-circuit message")
	}
}

func TestPullGap_ReturnsOpenGap(t *testing.T) {
	db, _ := dbtest.StartPostgres(t)
	ctx := context.Background()

	id := seedAppFactGap(t, db, "appB", "auth", "login_url",
		sql.NullString{},
		sql.NullString{String: "what is the login url?", Valid: true})

	out, err := store.PullGap(ctx, db, store.PullGapOptions{App: "appB"})
	if err != nil {
		t.Fatalf("PullGap: %v", err)
	}
	if out.GapID != id {
		t.Errorf("GapID = %d, want %d", out.GapID, id)
	}
	if out.App != "appB" || out.Category != "auth" || out.Key != "login_url" {
		t.Errorf("identity mismatch: got app=%q category=%q key=%q", out.App, out.Category, out.Key)
	}
	if out.Prompt == "" {
		t.Error("Prompt empty, want template-rendered text")
	}
}

func TestPushAnswer_MarksAnswered(t *testing.T) {
	db, _ := dbtest.StartPostgres(t)
	ctx := context.Background()

	id := seedAppFactGap(t, db, "appC", "telemetry", "endpoint",
		sql.NullString{},
		sql.NullString{String: "telemetry endpoint?", Valid: true})

	res, err := store.PushAnswer(ctx, db, store.PushAnswerOptions{
		GapID: id, Value: "https://t.example/ingest",
	})
	if err != nil {
		t.Fatalf("PushAnswer: %v", err)
	}
	if !res.OK || res.GapID != id || res.App != "appC" {
		t.Errorf("PushAnswer result mismatch: %+v", res)
	}

	// Row should now be filled — PullGap returns the empty-payload shape.
	out, err := store.PullGap(ctx, db, store.PullGapOptions{App: "appC"})
	if err != nil {
		t.Fatalf("PullGap after push: %v", err)
	}
	if out.GapID != 0 {
		t.Errorf("after push GapID = %d, want 0 (row marked answered)", out.GapID)
	}

	// fact_history should have one row.
	var n int
	if err := db.QueryRow(`SELECT COUNT(*) FROM fact_history WHERE fact_id = $1`, id).Scan(&n); err != nil {
		t.Fatalf("count fact_history: %v", err)
	}
	if n != 1 {
		t.Errorf("fact_history rows = %d, want 1", n)
	}
}

func TestPushAnswer_Validation(t *testing.T) {
	ctx := context.Background()

	if _, err := store.PushAnswer(ctx, nil, store.PushAnswerOptions{GapID: 1, Value: "x"}); err == nil {
		t.Error("expected error for nil db")
	}

	db, _ := dbtest.StartPostgres(t)
	_, err := store.PushAnswer(ctx, db, store.PushAnswerOptions{GapID: 0, Value: "x"})
	if err == nil {
		t.Fatal("expected error for gap_id=0")
	}
	if !strings.Contains(err.Error(), "gap_id required") {
		t.Errorf("unexpected error message: %v", err)
	}

	// Non-existent gap id ⇒ error.
	_, err = store.PushAnswer(ctx, db, store.PushAnswerOptions{GapID: 999999, Value: "x"})
	if err == nil {
		t.Error("expected error for non-existent gap id")
	}
}

func TestPullGap_Validation(t *testing.T) {
	ctx := context.Background()
	if _, err := store.PullGap(ctx, nil, store.PullGapOptions{App: "x"}); err == nil {
		t.Error("expected error for nil db")
	}
	db, _ := dbtest.StartPostgres(t)
	if _, err := store.PullGap(ctx, db, store.PullGapOptions{}); err == nil {
		t.Error("expected error for empty app")
	}
}
