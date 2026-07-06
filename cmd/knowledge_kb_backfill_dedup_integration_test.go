//go:build integration

/*
Copyright (c) 2026 Security Research

Integration coverage for `unravel knowledge backfill-dedup` (T1.4 / KB-OVERSEG
P1): drives the full command against an ephemeral Postgres (kbOpenDB honours
the --database DSN) and proves it drains pending rows stuck behind an already-enriched
identical-body sibling, is idempotent, and never touches un-hashed rows.
*/
package cmd

import (
	"testing"

	"github.com/inovacc/unravel-oss/pkg/knowledge/kb/dbtest"
)

func TestBackfillDedup_DrainsStuckSiblings(t *testing.T) {
	db, dsn := dbtest.StartPostgres(t)
	const sha = "bf-sha"

	// Enriched representative (appA): summary set + a module_enrichment row.
	var repID int
	if err := db.QueryRow(`INSERT INTO modules (app, name, body_excerpt, body_sha256, summary, tags)
		VALUES ('bfA', 'rep', 'function x(){}', $1, 'rep summary', 'vendor') RETURNING id`, sha).Scan(&repID); err != nil {
		t.Fatalf("seed rep: %v", err)
	}
	if _, err := db.Exec(`INSERT INTO module_enrichment
		(module_id, long_summary, role, inputs_json, outputs_json, side_effects, deps_json, raw_response, model, body_sha256, created_at)
		VALUES ($1, 'rep long', 'util', '[]', '[]', '[]', '[]', 'raw', 'test', $2, 1)`, repID, sha); err != nil {
		t.Fatalf("seed rep enrichment: %v", err)
	}
	// Pending siblings (distinct apps, same body) — stuck behind the rep.
	for _, app := range []string{"bfB", "bfC"} {
		if _, err := db.Exec(`INSERT INTO modules (app, name, body_excerpt, body_sha256)
			VALUES ($1, 'pend', 'function x(){}', $2)`, app, sha); err != nil {
			t.Fatalf("seed sibling %s: %v", app, err)
		}
	}
	// An un-hashed pending row that must be left alone.
	if _, err := db.Exec(`INSERT INTO modules (app, name, body_excerpt, body_sha256)
		VALUES ('bfD', 'unhashed', 'function y(){}', '')`); err != nil {
		t.Fatalf("seed unhashed: %v", err)
	}

	// Drive the command against the ephemeral DB.
	backfillDedupDB, backfillDedupApp, backfillDedupDryRun = dsn, "", false
	defer func() { backfillDedupDB, backfillDedupApp, backfillDedupDryRun = "", "", false }()
	if err := runKBBackfillDedup(nil, nil); err != nil {
		t.Fatalf("runKBBackfillDedup: %v", err)
	}

	// Both siblings cleared from pending.
	var stuck int
	if err := db.QueryRow(`SELECT COUNT(*) FROM modules WHERE body_sha256=$1 AND summary IS NULL`, sha).Scan(&stuck); err != nil {
		t.Fatalf("count stuck: %v", err)
	}
	if stuck != 0 {
		t.Errorf("siblings must be drained, %d still pending", stuck)
	}
	// Each sibling got a module_enrichment row carrying the rep's content.
	var sibEnriched int
	if err := db.QueryRow(`SELECT COUNT(*) FROM module_enrichment e JOIN modules m ON m.id=e.module_id
		WHERE m.body_sha256=$1 AND m.id <> $2 AND e.long_summary='rep long' AND e.role='util'`, sha, repID).Scan(&sibEnriched); err != nil {
		t.Fatalf("count sibling enrichment: %v", err)
	}
	if sibEnriched != 2 {
		t.Errorf("both siblings must inherit rep enrichment, got %d/2", sibEnriched)
	}
	// Un-hashed row untouched.
	var unhashedPending int
	if err := db.QueryRow(`SELECT COUNT(*) FROM modules WHERE app='bfD' AND body_sha256='' AND summary IS NULL`).Scan(&unhashedPending); err != nil {
		t.Fatalf("count unhashed: %v", err)
	}
	if unhashedPending != 1 {
		t.Errorf("un-hashed row must NOT be backfilled, got %d pending", unhashedPending)
	}

	// Idempotent: a second run is a no-op and must not error.
	if err := runKBBackfillDedup(nil, nil); err != nil {
		t.Fatalf("second runKBBackfillDedup (idempotency): %v", err)
	}
}
