//go:build integration

/*
Copyright (c) 2026 Security Research
*/

package diff

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"testing"

	"github.com/inovacc/unravel-oss/pkg/knowledge/kb/dbtest"
)

// TestLongRange_CapPrefix verifies D-30-LONGRANGE-CAP. The error MUST start
// EXACTLY with the literal "long-range diff capped at 20 epochs" so callers
// can strings.HasPrefix on it (PITFALLS-CRIT-3 mitigation).
func TestLongRange_CapPrefix(t *testing.T) {
	db, _ := dbtest.StartPostgres(t)
	seedLongRange(t, db, "kb-cap", 25)

	_, err := LongRangeDiff(context.Background(), db, "kb-cap", 1, 25)
	if err == nil {
		t.Fatal("expected cap error for span=24, got nil")
	}
	const wantPrefix = "long-range diff capped at 20 epochs"
	if !strings.HasPrefix(err.Error(), wantPrefix) {
		t.Fatalf("error %q does not start with prefix %q", err.Error(), wantPrefix)
	}
}

// TestLongRange_BoundaryAccept exercises the 20-epoch span boundary: 21-1=20
// is the largest accepted span.
func TestLongRange_BoundaryAccept(t *testing.T) {
	db, _ := dbtest.StartPostgres(t)
	seedLongRange(t, db, "kb-edge", 21)

	got, err := LongRangeDiff(context.Background(), db, "kb-edge", 1, 21)
	if err != nil {
		t.Fatalf("expected boundary 20-span to succeed, got %v", err)
	}
	if got == nil {
		t.Fatal("expected non-nil FactSetDiff")
	}
}

// TestLongRange_FactSetSemantics verifies the per-category bucketing.
func TestLongRange_FactSetSemantics(t *testing.T) {
	db, _ := dbtest.StartPostgres(t)

	// Hand-seed kb_apps + 5 knowledge_sources rows + tailored app_facts that
	// exercise added/removed/modified across two categories.
	mustExec(t, db, `INSERT INTO kb_apps (kb_id, canonical_name, display_name, package_id, platform, publisher, first_seen_at, last_seen_at)
		VALUES ('kb-set','kb-set','kb-set','com.x','win','x',0,0)`)
	for i := 1; i <= 5; i++ {
		mustExec(t, db,
			`INSERT INTO knowledge_sources (app, epoch, source_path, source_kind, source_sha256, captured_at, modules_indexed, bodies_indexed, kb_id, ks_id)
			 VALUES ($1, $2, '/p', 'cache', $3, $4, 0, 0, 'kb-set', $5)`,
			fmt.Sprintf("app-set-e%d", i), i, fmt.Sprintf("sha-set-%d", i), int64(i*1000), fmt.Sprintf("ks-set-%d", i),
		)
	}
	// Epoch 1 facts.
	mustExec(t, db, `INSERT INTO app_facts (app, category, key, value, source_step) VALUES
		('app-set-e1','crypto','db_cipher','AES-CBC','x'),
		('app-set-e1','crypto','kdf','PBKDF2','x'),
		('app-set-e1','auth','scope','read','x')`)
	// Epoch 5 facts: db_cipher modified, kdf removed, oauth_token added,
	// auth/scope unchanged (must NOT appear in the diff).
	mustExec(t, db, `INSERT INTO app_facts (app, category, key, value, source_step) VALUES
		('app-set-e5','crypto','db_cipher','AES-GCM','x'),
		('app-set-e5','crypto','oauth_token','XYZ','x'),
		('app-set-e5','auth','scope','read','x')`)

	got, err := LongRangeDiff(context.Background(), db, "kb-set", 1, 5)
	if err != nil {
		t.Fatalf("LongRangeDiff: %v", err)
	}

	if len(got.Modified["crypto"]) != 1 || got.Modified["crypto"][0].Key != "db_cipher" ||
		got.Modified["crypto"][0].OldValue != "AES-CBC" || got.Modified["crypto"][0].NewValue != "AES-GCM" {
		t.Fatalf("expected crypto.db_cipher modified AES-CBC→AES-GCM, got %+v", got.Modified["crypto"])
	}
	if len(got.Removed["crypto"]) != 1 || got.Removed["crypto"][0].Key != "kdf" {
		t.Fatalf("expected crypto.kdf removed, got %+v", got.Removed["crypto"])
	}
	if len(got.Added["crypto"]) != 1 || got.Added["crypto"][0].Key != "oauth_token" {
		t.Fatalf("expected crypto.oauth_token added, got %+v", got.Added["crypto"])
	}
	if len(got.Added["auth"])+len(got.Removed["auth"])+len(got.Modified["auth"]) != 0 {
		t.Fatalf("expected unchanged auth/scope to be absent, got auth=%+v", got)
	}
}

// TestLongRange_EqualEpochs rejects the degenerate range.
func TestLongRange_EqualEpochs(t *testing.T) {
	db, _ := dbtest.StartPostgres(t)
	seedLongRange(t, db, "kb-eq", 5)

	_, err := LongRangeDiff(context.Background(), db, "kb-eq", 5, 5)
	if err == nil {
		t.Fatal("expected error for fromEpoch == toEpoch")
	}
	if !strings.Contains(err.Error(), "requires toEpoch > fromEpoch") {
		t.Fatalf("unexpected error: %v", err)
	}
}

// seedLongRange seeds kb_apps + N knowledge_sources rows with monotonic epochs.
// Each epoch gets a single distinguishing app_facts row so the diff has shape.
func seedLongRange(t *testing.T, db *sql.DB, kbID string, n int) {
	t.Helper()
	mustExec(t, db,
		`INSERT INTO kb_apps (kb_id, canonical_name, display_name, package_id, platform, publisher, first_seen_at, last_seen_at)
		 VALUES ($1, $1, $1, 'com.x', 'win', 'x', 0, 0)`, kbID)
	for i := 1; i <= n; i++ {
		app := fmt.Sprintf("%s-app-e%d", kbID, i)
		mustExec(t, db,
			`INSERT INTO knowledge_sources (app, epoch, source_path, source_kind, source_sha256, captured_at, modules_indexed, bodies_indexed, kb_id, ks_id)
			 VALUES ($1, $2, '/p', 'cache', $3, $4, 0, 0, $5, $6)`,
			app, i, fmt.Sprintf("%s-sha-%d", kbID, i), int64(i*1000), kbID, fmt.Sprintf("%s-ks-%d", kbID, i),
		)
		mustExec(t, db,
			`INSERT INTO app_facts (app, category, key, value, source_step)
			 VALUES ($1, 'crypto', 'k', $2, 'x')`, app, fmt.Sprintf("v%d", i),
		)
	}
}

func mustExec(t *testing.T, db *sql.DB, q string, args ...any) {
	t.Helper()
	if _, err := db.ExecContext(context.Background(), q, args...); err != nil {
		t.Fatalf("exec %q: %v", q, err)
	}
}
