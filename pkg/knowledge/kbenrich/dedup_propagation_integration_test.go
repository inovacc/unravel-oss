//go:build integration

/*
Copyright (c) 2026 Security Research

T1.4 (KB-OVERSEG P1) cross-app dedup fan-out: PendingModules collapses
identical bodies to one representative, and writeEnrichment propagates the
enrichment to every still-pending sibling sharing that non-empty body hash.
Un-hashed (empty body_sha256) rows must never be collapsed or cross-propagated.
*/
package kbenrich_test

import (
	"context"
	"testing"

	"github.com/inovacc/unravel-oss/pkg/knowledge/kb/dbtest"
	"github.com/inovacc/unravel-oss/pkg/knowledge/kbenrich"
)

const t14Payload = `{"summary":"shared summary","long_summary":"shared long","role":"util",` +
	`"inputs":[],"outputs":[],"side_effects":[],"deps":[],"tags":["vendor"]}`

// TestPendingModules_DedupsIdenticalBody — read side: N identical-body rows
// (across distinct apps, since UNIQUE(app,body_sha256) forbids same-app dupes)
// collapse to ONE representative; a unique-body row is unaffected.
func TestPendingModules_DedupsIdenticalBody(t *testing.T) {
	db, _ := dbtest.StartPostgresOrSkip(t)
	const sha = "t14-dedup-sha"
	for _, app := range []string{"t14a", "t14b", "t14c"} {
		if _, err := db.Exec(`INSERT INTO modules (app, name, body_excerpt, body_sha256)
			VALUES ($1, $2, 'function x(){}', $3)`, app, "mod_"+app, sha); err != nil {
			t.Fatalf("seed %s: %v", app, err)
		}
	}
	if _, err := db.Exec(`INSERT INTO modules (app, name, body_excerpt, body_sha256)
		VALUES ('t14a', 'solo', 'function y(){}', 't14-solo-sha')`); err != nil {
		t.Fatalf("seed solo: %v", err)
	}

	got, err := kbenrich.PendingModules(context.Background(), db, "", 50, false, false)
	if err != nil {
		t.Fatalf("PendingModules: %v", err)
	}
	shared, solo := 0, 0
	for _, m := range got {
		switch m.SHA256 {
		case sha:
			shared++
		case "t14-solo-sha":
			solo++
		}
	}
	if shared != 1 {
		t.Errorf("identical-body rows must collapse to 1 representative, got %d", shared)
	}
	if solo != 1 {
		t.Errorf("unique-body row must still appear once, got %d", solo)
	}
}

// TestWriteEnrichment_PropagatesToSiblings — write side: enriching one of N
// identical-body siblings clears all N from pending and gives each a
// module_enrichment row.
func TestWriteEnrichment_PropagatesToSiblings(t *testing.T) {
	db, _ := dbtest.StartPostgresOrSkip(t)
	const sha = "t14-prop-sha"
	var firstID int
	for i, app := range []string{"t14p1", "t14p2", "t14p3"} {
		var id int
		if err := db.QueryRow(`INSERT INTO modules (app, name, body_excerpt, body_sha256)
			VALUES ($1, $2, 'function x(){}', $3) RETURNING id`, app, "mod_"+app, sha).Scan(&id); err != nil {
			t.Fatalf("seed %s: %v", app, err)
		}
		if i == 0 {
			firstID = id
		}
	}

	if err := kbenrich.WriteEnrichmentJSON(db, firstID, "t14p1", sha, `{"raw":"r"}`, "test", []byte(t14Payload)); err != nil {
		t.Fatalf("WriteEnrichmentJSON: %v", err)
	}

	var stillPending int
	if err := db.QueryRow(`SELECT COUNT(*) FROM modules WHERE body_sha256=$1 AND summary IS NULL`, sha).Scan(&stillPending); err != nil {
		t.Fatalf("count pending: %v", err)
	}
	if stillPending != 0 {
		t.Errorf("all %d identical-body siblings must clear from pending, %d still pending", 3, stillPending)
	}

	var enriched int
	if err := db.QueryRow(`SELECT COUNT(*) FROM module_enrichment e
		JOIN modules m ON m.id = e.module_id WHERE m.body_sha256=$1`, sha).Scan(&enriched); err != nil {
		t.Fatalf("count enrichment: %v", err)
	}
	if enriched != 3 {
		t.Errorf("every sibling must get a module_enrichment row, got %d/3", enriched)
	}

	// A sibling (not the writer) must carry the propagated long_summary + role.
	var ls, role string
	if err := db.QueryRow(`SELECT e.long_summary, e.role FROM module_enrichment e
		JOIN modules m ON m.id = e.module_id
		WHERE m.body_sha256=$1 AND m.id <> $2 LIMIT 1`, sha, firstID).Scan(&ls, &role); err != nil {
		t.Fatalf("read sibling enrichment: %v", err)
	}
	if ls != "shared long" || role != "util" {
		t.Errorf("sibling enrichment not propagated: long_summary=%q role=%q", ls, role)
	}

	// PendingModules over all apps must now return zero rows for this body.
	got, err := kbenrich.PendingModules(context.Background(), db, "", 50, false, false)
	if err != nil {
		t.Fatalf("PendingModules post-write: %v", err)
	}
	for _, m := range got {
		if m.SHA256 == sha {
			t.Errorf("body %s should be fully enriched, still pending: id=%d app=%s", sha, m.ID, m.App)
		}
	}
}

// TestWriteEnrichment_EmptyShaNotCollapsedNorPropagated — the data-loss trap:
// rows with an empty body_sha256 are distinct modules, never deduped on read
// and never cross-propagated on write.
func TestWriteEnrichment_EmptyShaNotCollapsedNorPropagated(t *testing.T) {
	db, _ := dbtest.StartPostgresOrSkip(t)
	var firstID int
	apps := []string{"t14e1", "t14e2", "t14e3"}
	for i, app := range apps {
		var id int
		// Empty body_sha256 ('' permitted once per app by UNIQUE(app,body_sha256)).
		if err := db.QueryRow(`INSERT INTO modules (app, name, body_excerpt, body_sha256)
			VALUES ($1, $2, 'function x(){}', '') RETURNING id`, app, "emod_"+app).Scan(&id); err != nil {
			t.Fatalf("seed %s: %v", app, err)
		}
		if i == 0 {
			firstID = id
		}
	}

	// Read side: all three empty-sha rows must be returned (NOT collapsed).
	got, err := kbenrich.PendingModules(context.Background(), db, "", 50, false, false)
	if err != nil {
		t.Fatalf("PendingModules: %v", err)
	}
	emptyCount := 0
	for _, m := range got {
		for _, app := range apps {
			if m.App == app && m.SHA256 == "" {
				emptyCount++
			}
		}
	}
	if emptyCount != 3 {
		t.Errorf("empty-sha rows must NOT be collapsed; want 3 returned, got %d", emptyCount)
	}

	// Write side: enriching one empty-sha row must not touch the others.
	if err := kbenrich.WriteEnrichmentJSON(db, firstID, apps[0], "", `{"raw":"r"}`, "test", []byte(t14Payload)); err != nil {
		t.Fatalf("WriteEnrichmentJSON empty-sha: %v", err)
	}
	var othersPending int
	if err := db.QueryRow(`SELECT COUNT(*) FROM modules
		WHERE body_sha256='' AND summary IS NULL AND app IN ($1, $2)`, apps[1], apps[2]).Scan(&othersPending); err != nil {
		t.Fatalf("count other empty-sha pending: %v", err)
	}
	if othersPending != 2 {
		t.Errorf("empty-sha siblings must NOT be cross-propagated; want 2 still pending, got %d", othersPending)
	}
}
