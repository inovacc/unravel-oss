//go:build integration

/*
Copyright (c) 2026 Security Research

Integration tests for the read-query helpers in store.go (Search, Dump,
Pending, Facts, Gaps, Stats) against a real Postgres catalog via
dbtest.StartPostgres + dbtest.SeedFixtures.

store_test.go (package store, internal) used to claim this same surface via
kbdb.Open(ctx, ":memory:") against an in-process SQLite catalog, but it
predated the SQLite -> Postgres cutover: Open's dsnOverride is no longer a
filesystem path, so that test failed at runtime under -tags=integration
("parse dsn: invalid connection string"). dbtest.SeedFixtures's doc comment
("mirrors what the pre-deletion newDB helper inserted") confirms this file
is the intended replacement, exercised against Postgres instead of SQLite.
store_test.go has since been deleted — `go build`/`go test` compile and run
every test file in a package regardless of name (a bare `go test` has no
implicit per-file selection; `-run` is opt-in filtering the caller must
supply), so a stale file left in place would have kept failing every
`-tags=integration` run, not just ones that happened to name its tests.
*/

package store_test

import (
	"testing"

	"github.com/inovacc/unravel-oss/pkg/knowledge/kb/dbtest"
	"github.com/inovacc/unravel-oss/pkg/knowledge/kb/store"
)

func TestSearch_FiltersByAppAndCountsSightings(t *testing.T) {
	db, _ := dbtest.StartPostgres(t)
	dbtest.SeedFixtures(t, db)

	hits, err := store.Search(db, "whatsapp", "messages", 10)
	if err != nil {
		t.Fatalf("Search: %v", err)
	}
	if len(hits) != 1 {
		t.Fatalf("expected 1 hit, got %d: %+v", len(hits), hits)
	}
	if hits[0].App != "whatsapp" || hits[0].ID != 1 {
		t.Errorf("unexpected hit: %+v", hits[0])
	}
	if hits[0].Sightings != 2 {
		t.Errorf("sightings = %d, want 2", hits[0].Sightings)
	}
}

// TestSearch_AllAppsWhenAppEmpty proves an empty app filter drops the
// "AND m.app = $N" clause rather than restricting to one app. "TeamsChat"
// only appears in the teams module's synthetic_name (part of
// search_text); calling Search with app="" must still find it.
func TestSearch_AllAppsWhenAppEmpty(t *testing.T) {
	db, _ := dbtest.StartPostgres(t)
	dbtest.SeedFixtures(t, db)

	hits, err := store.Search(db, "", "TeamsChat", 10)
	if err != nil {
		t.Fatalf("Search: %v", err)
	}
	if len(hits) != 1 {
		t.Fatalf("expected exactly 1 hit across apps, got %d: %+v", len(hits), hits)
	}
	if hits[0].App != "teams" || hits[0].ID != 2 {
		t.Errorf("unexpected hit: %+v", hits[0])
	}
}

// TestSearch_ExcludesBodyOnlyContent guards the two-tier search design
// fixed by migration 000014 (search_text_excludes_body): search_text
// (the ranked ILIKE+trigram path Search runs on) is a GENERATED column
// over name/synthetic_name/symbols_json/summary/tags only — body_excerpt
// is deliberately excluded so the ranked path can't shadow the separate
// FTS-fallback path over body content (see migration 000014's comment:
// "the ranked path always matched anything FTS fallback could find, so
// the fallback path was dead code"). A module whose ONLY match is in its
// body_excerpt must NOT appear in Search results; a module matching by
// name must.
func TestSearch_ExcludesBodyOnlyContent(t *testing.T) {
	db, _ := dbtest.StartPostgres(t)
	dbtest.SeedFixtures(t, db)

	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := db.Exec(q, args...); err != nil {
			t.Fatalf("exec %q: %v", q, err)
		}
	}
	exec(`INSERT INTO module_bodies (body_sha256, body, body_size, stored_at)
	      VALUES ('ccc', '\x63', 1, 0), ('ddd', '\x64', 1, 0)`)

	// Module 3: matches via name.
	exec(`INSERT INTO modules
	      (id, app, name, synthetic_name, body_size, body_excerpt, body_sha256, symbols_json, summary, tags)
	      OVERRIDING SYSTEM VALUE
	      VALUES (3, 'whatsapp', 'NeedleTarget', NULL, 100, 'irrelevant body', 'ccc', NULL, NULL, NULL)`)
	// Module 4: the token ONLY appears in body_excerpt — must be invisible
	// to Search since body_excerpt is not part of search_text.
	exec(`INSERT INTO modules
	      (id, app, name, synthetic_name, body_size, body_excerpt, body_sha256, symbols_json, summary, tags)
	      OVERRIDING SYSTEM VALUE
	      VALUES (4, 'whatsapp', 'a1b2c3d4', NULL, 2000,
	              'NeedleTarget NeedleTarget NeedleTarget', 'ddd', NULL, NULL, NULL)`)

	hits, err := store.Search(db, "whatsapp", "NeedleTarget", 10)
	if err != nil {
		t.Fatalf("Search: %v", err)
	}
	if len(hits) != 1 {
		t.Fatalf("expected exactly 1 hit (name match only), got %d: %+v", len(hits), hits)
	}
	if hits[0].ID != 3 {
		t.Errorf("got id=%d, want id=3 (name match); body-only module 4 leaked into results: %+v", hits[0].ID, hits)
	}
}

func TestDump_ReturnsModuleWithBodyAndSightings(t *testing.T) {
	db, _ := dbtest.StartPostgres(t)
	dbtest.SeedFixtures(t, db)

	row, err := store.Dump(db, 1, 5)
	if err != nil {
		t.Fatalf("Dump: %v", err)
	}
	if row.App != "whatsapp" || row.Name != "WAWebMsgCollection" {
		t.Errorf("unexpected row: %+v", row)
	}
	if row.Sha256 != "aaa" {
		t.Errorf("sha256 = %q, want aaa", row.Sha256)
	}
	if len(row.Body) == 0 {
		t.Error("expected body bytes fetched from module_bodies, got none")
	}
	if len(row.Sightings) != 2 {
		t.Errorf("sightings = %d, want 2", len(row.Sightings))
	}
}

func TestDump_MissingIDReturnsError(t *testing.T) {
	db, _ := dbtest.StartPostgres(t)
	dbtest.SeedFixtures(t, db)

	if _, err := store.Dump(db, 9999, 5); err == nil {
		t.Fatal("expected error for missing id")
	}
}

func TestPending_FiltersByApp(t *testing.T) {
	db, _ := dbtest.StartPostgres(t)
	dbtest.SeedFixtures(t, db)

	rows, err := store.Pending(db, "", 10)
	if err != nil {
		t.Fatalf("Pending: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("expected 1 pending, got %d: %+v", len(rows), rows)
	}
	if rows[0].ID != 2 || rows[0].App != "teams" {
		t.Errorf("unexpected pending row: %+v", rows[0])
	}

	rows, err = store.Pending(db, "whatsapp", 10)
	if err != nil {
		t.Fatalf("Pending(whatsapp): %v", err)
	}
	if len(rows) != 0 {
		t.Errorf("expected 0 pending for whatsapp (already summarized), got %d", len(rows))
	}
}

func TestFacts_FilledOnly(t *testing.T) {
	db, _ := dbtest.StartPostgres(t)
	dbtest.SeedFixtures(t, db)

	facts, err := store.Facts(db, "whatsapp", "", false)
	if err != nil {
		t.Fatalf("Facts: %v", err)
	}
	if len(facts) != 1 {
		t.Fatalf("expected 1 filled fact, got %d: %+v", len(facts), facts)
	}
	if facts[0].Key != "db_cipher" || !facts[0].Value.Valid || facts[0].Value.String != "AES-CBC" {
		t.Errorf("unexpected fact: %+v", facts[0])
	}
}

func TestGaps_AcrossApps(t *testing.T) {
	db, _ := dbtest.StartPostgres(t)
	dbtest.SeedFixtures(t, db)

	gaps, err := store.Gaps(db, "", "")
	if err != nil {
		t.Fatalf("Gaps: %v", err)
	}
	if len(gaps) != 2 {
		t.Fatalf("expected 2 gaps, got %d: %+v", len(gaps), gaps)
	}
	for _, g := range gaps {
		if g.Value.Valid {
			t.Errorf("gap row should have NULL value: %+v", g)
		}
	}
}

func TestGaps_FilteredByCategory(t *testing.T) {
	db, _ := dbtest.StartPostgres(t)
	dbtest.SeedFixtures(t, db)

	gaps, err := store.Gaps(db, "whatsapp", "crypto")
	if err != nil {
		t.Fatalf("Gaps: %v", err)
	}
	if len(gaps) != 1 || gaps[0].Key != "kdf" {
		t.Errorf("unexpected gaps: %+v", gaps)
	}
}

func TestStats_AggregatesPerApp(t *testing.T) {
	db, _ := dbtest.StartPostgres(t)
	dbtest.SeedFixtures(t, db)

	rows, err := store.Stats(db)
	if err != nil {
		t.Fatalf("Stats: %v", err)
	}
	if len(rows) != 2 {
		t.Fatalf("expected 2 app rows, got %d: %+v", len(rows), rows)
	}
	byApp := map[string]store.StatsRow{}
	for _, r := range rows {
		byApp[r.App] = r
	}
	if r := byApp["whatsapp"]; r.Total != 1 || r.Summarized != 1 {
		t.Errorf("whatsapp stats: %+v", r)
	}
	if r := byApp["teams"]; r.Total != 1 || r.Summarized != 0 {
		t.Errorf("teams stats: %+v", r)
	}
}
