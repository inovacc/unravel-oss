//go:build integration

/*
Copyright (c) 2026 Security Research

Integration tests for the Phase-34 legacy backfill. Boot a transient
Postgres via dbtest.StartPostgres, seed knowledge_sources rows with
kb_id=NULL across multiple legacy app names, exercise backfill.Run.

Three behaviors covered (per Plan 34-01 task 34-01-01):

  * TestBackfill_PopulatesLegacyRows — derived kb_id matches the
    SHA-256[:16] of lower(app)||'|unknown' for every legacy row.
  * TestBackfill_Idempotent          — second run is a strict no-op.
  * TestBackfill_UpsertsKBApps       — one kb_apps row per legacy app,
    platform='unknown', metadata.derivation='legacy_app_text_only',
    first_seen_at == MIN(captured_at), last_seen_at == MAX(captured_at).
*/

package backfill_test

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"strings"
	"testing"
	"time"

	"github.com/inovacc/unravel-oss/pkg/knowledge/kb/backfill"
	"github.com/inovacc/unravel-oss/pkg/knowledge/kb/dbtest"
)

// derive computes the legacy kb_id the way Postgres' pgcrypto does:
// substring(encode(digest(lower(app)||'|unknown','sha256'),'hex'),1,16).
func derive(app string) string {
	h := sha256.Sum256([]byte(strings.ToLower(app) + "|unknown"))
	return hex.EncodeToString(h[:])[:16]
}

// seedLegacy inserts n knowledge_sources rows, cycling across the apps
// slice, with kb_id=NULL. Each row gets a deterministic captured_at and
// a unique source_path / source_sha256 to avoid the (app, epoch) and
// legacy (app, source_sha256) collisions even though migration 000006
// dropped the latter.
func seedLegacy(t *testing.T, db *sql.DB, n int, apps []string) {
	t.Helper()
	if len(apps) == 0 {
		t.Fatal("seedLegacy: empty apps slice")
	}
	now := time.Now().UnixMilli()
	// Track per-app epoch counter to avoid UNIQUE(app, epoch) collisions.
	epochCount := make(map[string]int, len(apps))
	for i := 0; i < n; i++ {
		app := apps[i%len(apps)]
		epochCount[app]++
		ep := epochCount[app]
		captured := now - int64(i)*1000
		// Pad sha256 to 64 hex chars.
		sha := []byte("0000000000000000000000000000000000000000000000000000000000000000")
		hexCh := []byte("0123456789abcdef")
		// Encode i into the last 8 nybbles for uniqueness.
		for k := 0; k < 8; k++ {
			sha[63-k] = hexCh[(i>>(4*k))&0xF]
		}
		_, err := db.Exec(
			`INSERT INTO knowledge_sources
              (app, epoch, source_path, source_kind, source_sha256, captured_at)
              VALUES ($1, $2, $3, 'other', $4, $5)`,
			app, ep, "/tmp/legacy/"+app+"/"+string(sha[56:]), string(sha), captured,
		)
		if err != nil {
			t.Fatalf("seed insert (i=%d, app=%q): %v", i, app, err)
		}
	}
}

func TestBackfill_PopulatesLegacyRows(t *testing.T) {
	db, _ := dbtest.StartPostgres(t)
	apps := []string{"WhatsApp", "Cluely", "PerSSua-Client"}
	seedLegacy(t, db, 50, apps)

	ctx := context.Background()
	rep, err := backfill.Run(ctx, db, backfill.Options{})
	if err != nil {
		t.Fatalf("backfill.Run: %v", err)
	}
	if rep.RowsBackfilled != 50 {
		t.Errorf("RowsBackfilled = %d, want 50", rep.RowsBackfilled)
	}
	if rep.AppsCreated != len(apps) {
		t.Errorf("AppsCreated = %d, want %d", rep.AppsCreated, len(apps))
	}
	if rep.SchemaVersion != 1 {
		t.Errorf("SchemaVersion = %d, want 1", rep.SchemaVersion)
	}

	// Every legacy row now has the derived kb_id.
	for _, app := range apps {
		want := derive(app)
		var got sql.NullString
		var nullCount int
		row := db.QueryRow(`SELECT MIN(kb_id), count(*) FILTER (WHERE kb_id IS NULL)
                            FROM knowledge_sources WHERE app = $1`, app)
		var minKB sql.NullString
		if err := row.Scan(&minKB, &nullCount); err != nil {
			t.Fatalf("scan kb_id for %q: %v", app, err)
		}
		got = minKB
		if nullCount != 0 {
			t.Errorf("app=%q still has %d NULL kb_id rows", app, nullCount)
		}
		if !got.Valid || got.String != want {
			t.Errorf("app=%q kb_id = %v, want %s", app, got, want)
		}
	}

	// Spot-check: count of rows in knowledge_sources with kb_id IS NULL == 0.
	var leftNull int
	if err := db.QueryRow(`SELECT count(*) FROM knowledge_sources WHERE kb_id IS NULL`).Scan(&leftNull); err != nil {
		t.Fatalf("count null: %v", err)
	}
	if leftNull != 0 {
		t.Errorf("rows with NULL kb_id after backfill = %d, want 0", leftNull)
	}
}

func TestBackfill_Idempotent(t *testing.T) {
	db, _ := dbtest.StartPostgres(t)
	apps := []string{"alpha", "Beta", "gamma_test"}
	seedLegacy(t, db, 30, apps)

	ctx := context.Background()
	rep1, err := backfill.Run(ctx, db, backfill.Options{})
	if err != nil {
		t.Fatalf("first run: %v", err)
	}
	if rep1.RowsBackfilled == 0 {
		t.Errorf("first run RowsBackfilled = 0, want >0")
	}

	// Snapshot counts.
	ksCountBefore := scalarInt(t, db, `SELECT count(*) FROM knowledge_sources`)
	appsCountBefore := scalarInt(t, db, `SELECT count(*) FROM kb_apps`)

	rep2, err := backfill.Run(ctx, db, backfill.Options{})
	if err != nil {
		t.Fatalf("second run: %v", err)
	}
	if rep2.RowsBackfilled != 0 {
		t.Errorf("second run RowsBackfilled = %d, want 0", rep2.RowsBackfilled)
	}
	if rep2.AppsCreated != 0 {
		t.Errorf("second run AppsCreated = %d, want 0", rep2.AppsCreated)
	}
	if rep2.SchemaVersion != 1 {
		t.Errorf("second run SchemaVersion = %d, want 1", rep2.SchemaVersion)
	}

	ksCountAfter := scalarInt(t, db, `SELECT count(*) FROM knowledge_sources`)
	appsCountAfter := scalarInt(t, db, `SELECT count(*) FROM kb_apps`)
	if ksCountBefore != ksCountAfter {
		t.Errorf("knowledge_sources count drift: %d -> %d", ksCountBefore, ksCountAfter)
	}
	if appsCountBefore != appsCountAfter {
		t.Errorf("kb_apps count drift: %d -> %d", appsCountBefore, appsCountAfter)
	}
}

func TestBackfill_UpsertsKBApps(t *testing.T) {
	db, _ := dbtest.StartPostgres(t)
	apps := []string{"Foo App", "bar_app", "Baz"}
	seedLegacy(t, db, 18, apps)

	ctx := context.Background()
	if _, err := backfill.Run(ctx, db, backfill.Options{}); err != nil {
		t.Fatalf("backfill.Run: %v", err)
	}

	for _, app := range apps {
		kbID := derive(app)
		var (
			platform   string
			derivation sql.NullString
			firstSeen  int64
			lastSeen   int64
			displayN   string
			canonical  string
		)
		err := db.QueryRow(
			`SELECT platform, metadata->>'derivation', first_seen_at, last_seen_at, display_name, canonical_name
             FROM kb_apps WHERE kb_id = $1`, kbID,
		).Scan(&platform, &derivation, &firstSeen, &lastSeen, &displayN, &canonical)
		if err != nil {
			t.Fatalf("kb_apps row missing for app=%q kb_id=%s: %v", app, kbID, err)
		}
		if platform != "unknown" {
			t.Errorf("app=%q platform = %q, want unknown", app, platform)
		}
		if !derivation.Valid || derivation.String != "legacy_app_text_only" {
			t.Errorf("app=%q metadata.derivation = %v, want legacy_app_text_only", app, derivation)
		}
		if displayN != app {
			t.Errorf("app=%q display_name = %q, want %q", app, displayN, app)
		}
		if canonical == "" {
			t.Errorf("app=%q canonical_name empty", app)
		}

		// first_seen_at == MIN(captured_at), last_seen_at == MAX(captured_at)
		var minCap, maxCap int64
		if err := db.QueryRow(
			`SELECT MIN(captured_at), MAX(captured_at) FROM knowledge_sources WHERE app = $1`, app,
		).Scan(&minCap, &maxCap); err != nil {
			t.Fatalf("compute min/max captured_at for %q: %v", app, err)
		}
		if firstSeen != minCap {
			t.Errorf("app=%q first_seen_at = %d, want %d (MIN)", app, firstSeen, minCap)
		}
		if lastSeen != maxCap {
			t.Errorf("app=%q last_seen_at = %d, want %d (MAX)", app, lastSeen, maxCap)
		}
	}

	// Exactly one kb_apps row per distinct legacy app (no duplicates).
	got := scalarInt(t, db, `SELECT count(*) FROM kb_apps WHERE metadata->>'derivation' = 'legacy_app_text_only'`)
	if got != len(apps) {
		t.Errorf("kb_apps legacy row count = %d, want %d", got, len(apps))
	}
}

func scalarInt(t *testing.T, db *sql.DB, q string, args ...any) int {
	t.Helper()
	var n int
	if err := db.QueryRow(q, args...).Scan(&n); err != nil {
		t.Fatalf("scalar %q: %v", q, err)
	}
	return n
}
