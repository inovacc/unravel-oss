/*
Copyright (c) 2026 Security Research

Docker-free test for hardening finding #2: writeEnrichment (via the exported
WriteEnrichmentJSONContext) must thread the caller's context into the write
transaction so a cancelled run / deadline aborts the blocked connection
acquire or the write mid-statement instead of running on context.Background().

Uses an in-memory modernc SQLite *sql.DB purely to obtain a real, non-nil
database handle — no Postgres/Docker. An already-cancelled context must make
db.BeginTx return context.Canceled BEFORE any SQL runs, which is only
possible if the context is actually plumbed through (the pre-fix code used
db.Begin() with context.Background() and would have hit a missing-table SQL
error instead).
*/
package kbenrich

import (
	"context"
	"database/sql"
	"errors"
	"testing"

	_ "modernc.org/sqlite"
)

func validEnrichmentJSON() []byte {
	return []byte(`{"summary":"does X","role":"util","long_summary":"longer",` +
		`"inputs":[],"outputs":[],"side_effects":[],"deps":[],"tags":["a"]}`)
}

func TestWriteEnrichmentJSONContext_HonorsCancellation(t *testing.T) {
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel before the call so BeginTx must fail fast

	err = WriteEnrichmentJSONContext(ctx, db, 1, "app", "deadbeef", "raw", "haiku", validEnrichmentJSON())
	if err == nil {
		t.Fatalf("WriteEnrichmentJSONContext with cancelled ctx: want error, got nil")
	}
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("want context.Canceled (ctx threaded into BeginTx), got %v", err)
	}
}

// TestWriteEnrichmentJSON_NilDB keeps the exported deprecated shim's nil-db
// guard covered.
func TestWriteEnrichmentJSON_NilDB(t *testing.T) {
	if err := WriteEnrichmentJSON(nil, 1, "app", "sha", "raw", "haiku", validEnrichmentJSON()); err == nil {
		t.Fatalf("WriteEnrichmentJSON(nil db): want error, got nil")
	}
}
