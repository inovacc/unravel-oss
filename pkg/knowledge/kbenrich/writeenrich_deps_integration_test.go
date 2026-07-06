//go:build integration

/*
Copyright (c) 2026 Security Research
*/
package kbenrich_test

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/inovacc/unravel-oss/pkg/knowledge/kb/dbtest"
	"github.com/inovacc/unravel-oss/pkg/knowledge/kbenrich"
)

// TestWriteEnrichment_DepBatch_ZeroOneMany asserts the batched dep insert in
// writeEnrichment correctly handles 0, 1, and 50 deps with mixed
// resolvable / unresolvable names. Locks KBC-WRITE-ENRICH-DEP-BATCH: the
// per-dep SELECT+INSERT loop was collapsed into a single ANY-array resolve +
// single multi-VALUES insert.
func TestWriteEnrichment_DepBatch_ZeroOneMany(t *testing.T) {
	db, _ := dbtest.StartPostgresOrSkip(t)

	app := "batchdepsapp"

	// Seed 25 resolvable target modules; another 25 dep names won't exist
	// (must be persisted with NULL to_id).
	resolvable := make([]string, 25)
	for i := range resolvable {
		name := fmt.Sprintf("resolvable_%02d", i)
		resolvable[i] = name
		if _, err := db.Exec(`
			INSERT INTO modules (app, name, body_excerpt, body_sha256)
			VALUES ($1, $2, '', $3)`,
			app, name, fmt.Sprintf("sha-resolvable-%02d", i),
		); err != nil {
			t.Fatalf("seed resolvable %d: %v", i, err)
		}
	}

	// Source module whose deps we'll write.
	var srcID int
	if err := db.QueryRow(`
		INSERT INTO modules (app, name, body_excerpt, body_sha256)
		VALUES ($1, 'src', '', 'sha-src')
		RETURNING id`, app).Scan(&srcID); err != nil {
		t.Fatalf("seed src: %v", err)
	}

	build := func(deps []string) []byte {
		depsJSON, _ := json.Marshal(deps)
		payload := fmt.Sprintf(`{
			"summary":"s","long_summary":"ls","role":"util",
			"inputs":[],"outputs":[],"side_effects":[],
			"deps":%s,"tags":[]
		}`, depsJSON)
		return []byte(payload)
	}

	cases := []struct {
		name      string
		deps      []string
		wantCount int
	}{
		{"zero", []string{}, 0},
		{"one resolvable", []string{"resolvable_00"}, 1},
		{"one unresolvable", []string{"ghost"}, 1},
		{"empty entries skipped", []string{"", "resolvable_01", ""}, 1},
		{"duplicate dedup", []string{"resolvable_02", "resolvable_02", "resolvable_02"}, 1},
		// 50 = 25 resolvable + 25 ghosts.
		{"fifty mixed", buildFifty(resolvable), 50},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			start := time.Now()
			if err := kbenrich.WriteEnrichmentJSON(
				db, srcID, app, "sha-src", `{"raw":"r"}`, "test", build(tc.deps),
			); err != nil {
				t.Fatalf("WriteEnrichmentJSON: %v", err)
			}
			if tc.name == "fifty mixed" {
				// Observational only (KBC-WRITE-ENRICH-DEP-BATCH re-verification,
				// 2026-07-01) — in-repo data point for the batched-write wall
				// clock on a 50-dep module. NOT a pass/fail threshold: dockerized
				// Postgres timing is not a stable perf signal, so this is a
				// t.Logf, never an assertion.
				t.Logf("WriteEnrichmentJSON(50 deps, batched 2-round-trip dep write) took %s", time.Since(start))
			}

			var got int
			if err := db.QueryRow(
				`SELECT COUNT(*) FROM module_deps WHERE from_id = $1`, srcID,
			).Scan(&got); err != nil {
				t.Fatalf("count deps: %v", err)
			}
			if got != tc.wantCount {
				t.Fatalf("deps count: got %d want %d", got, tc.wantCount)
			}

			// Resolvable names must have non-NULL to_id; unresolvable must be NULL.
			if tc.name == "fifty mixed" {
				var resolvedCount, unresolvedCount int
				if err := db.QueryRow(
					`SELECT
						COUNT(*) FILTER (WHERE to_id IS NOT NULL),
						COUNT(*) FILTER (WHERE to_id IS NULL)
					FROM module_deps WHERE from_id = $1`, srcID,
				).Scan(&resolvedCount, &unresolvedCount); err != nil {
					t.Fatalf("count by resolution: %v", err)
				}
				if resolvedCount != 25 || unresolvedCount != 25 {
					t.Fatalf("resolution split: got resolved=%d unresolved=%d want 25/25",
						resolvedCount, unresolvedCount)
				}
			}
		})
	}
}

func buildFifty(resolvable []string) []string {
	deps := make([]string, 0, 50)
	deps = append(deps, resolvable...)
	for i := 0; i < 25; i++ {
		deps = append(deps, fmt.Sprintf("ghost_%02d", i))
	}
	return deps
}

// TestWriteEnrichment_DepBatch_ReplacesPriorDeps asserts that a second
// WriteEnrichmentJSON call replaces (not appends) the prior dep set — the
// DELETE precedes the batched INSERT.
func TestWriteEnrichment_DepBatch_ReplacesPriorDeps(t *testing.T) {
	db, _ := dbtest.StartPostgresOrSkip(t)
	app := "replaceapp"

	for _, name := range []string{"alpha", "beta", "gamma"} {
		if _, err := db.Exec(`
			INSERT INTO modules (app, name, body_excerpt, body_sha256)
			VALUES ($1, $2, '', $3)`,
			app, name, "sha-"+name,
		); err != nil {
			t.Fatalf("seed %s: %v", name, err)
		}
	}
	var srcID int
	if err := db.QueryRow(`
		INSERT INTO modules (app, name, body_excerpt, body_sha256)
		VALUES ($1, 'src', '', 'sha-src')
		RETURNING id`, app).Scan(&srcID); err != nil {
		t.Fatalf("seed src: %v", err)
	}
	build := func(deps []string) []byte {
		depsJSON, _ := json.Marshal(deps)
		return []byte(fmt.Sprintf(
			`{"summary":"s","long_summary":"ls","role":"util","inputs":[],"outputs":[],"side_effects":[],"deps":%s,"tags":[]}`,
			depsJSON))
	}

	if err := kbenrich.WriteEnrichmentJSON(db, srcID, app, "sha-src", "", "test", build([]string{"alpha", "beta"})); err != nil {
		t.Fatalf("first write: %v", err)
	}
	if err := kbenrich.WriteEnrichmentJSON(db, srcID, app, "sha-src", "", "test", build([]string{"gamma"})); err != nil {
		t.Fatalf("second write: %v", err)
	}

	rows, err := db.Query(`SELECT to_name FROM module_deps WHERE from_id = $1 ORDER BY to_name`, srcID)
	if err != nil {
		t.Fatalf("select deps: %v", err)
	}
	defer func() { _ = rows.Close() }()
	var names []string
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			t.Fatalf("scan: %v", err)
		}
		names = append(names, n)
	}
	got := strings.Join(names, ",")
	if got != "gamma" {
		t.Fatalf("post-replace deps: got %q want %q", got, "gamma")
	}
}

// TestWriteEnrichment_DepBatch_IdempotentSameDeps asserts that re-enriching a
// module with the IDENTICAL dep set does not create duplicate module_deps
// rows: the DELETE-then-batched-INSERT ordering combined with
// ON CONFLICT (from_id, to_name) DO NOTHING makes repeated writes of the same
// deps a no-op on row count, resolution, and linkage.
func TestWriteEnrichment_DepBatch_IdempotentSameDeps(t *testing.T) {
	db, _ := dbtest.StartPostgresOrSkip(t)
	app := "idempotentapp"

	for _, name := range []string{"left", "right"} {
		if _, err := db.Exec(`
			INSERT INTO modules (app, name, body_excerpt, body_sha256)
			VALUES ($1, $2, '', $3)`,
			app, name, "sha-"+name,
		); err != nil {
			t.Fatalf("seed %s: %v", name, err)
		}
	}
	var srcID int
	if err := db.QueryRow(`
		INSERT INTO modules (app, name, body_excerpt, body_sha256)
		VALUES ($1, 'src', '', 'sha-src')
		RETURNING id`, app).Scan(&srcID); err != nil {
		t.Fatalf("seed src: %v", err)
	}
	build := func(deps []string) []byte {
		depsJSON, _ := json.Marshal(deps)
		return []byte(fmt.Sprintf(
			`{"summary":"s","long_summary":"ls","role":"util","inputs":[],"outputs":[],"side_effects":[],"deps":%s,"tags":[]}`,
			depsJSON))
	}
	// One resolvable ("left"), one unresolvable ("ghost") dep, written 3 times.
	deps := []string{"left", "ghost"}
	for i := 0; i < 3; i++ {
		if err := kbenrich.WriteEnrichmentJSON(db, srcID, app, "sha-src", "", "test", build(deps)); err != nil {
			t.Fatalf("write %d: %v", i, err)
		}
	}

	var count, resolvedCount, unresolvedCount int
	if err := db.QueryRow(`
		SELECT COUNT(*),
		       COUNT(*) FILTER (WHERE to_id IS NOT NULL),
		       COUNT(*) FILTER (WHERE to_id IS NULL)
		FROM module_deps WHERE from_id = $1`, srcID,
	).Scan(&count, &resolvedCount, &unresolvedCount); err != nil {
		t.Fatalf("count deps: %v", err)
	}
	if count != 2 {
		t.Fatalf("repeated identical-dep writes must not duplicate rows: got %d rows want 2", count)
	}
	if resolvedCount != 1 || unresolvedCount != 1 {
		t.Fatalf("resolution split after repeated writes: got resolved=%d unresolved=%d want 1/1",
			resolvedCount, unresolvedCount)
	}
}
