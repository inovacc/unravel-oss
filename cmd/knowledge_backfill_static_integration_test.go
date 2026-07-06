//go:build integration

package cmd

import (
	"crypto/sha256"
	"database/sql"
	"fmt"
	"os"
	"testing"

	"github.com/inovacc/unravel-oss/pkg/knowledge/kb/backfill"
	"github.com/inovacc/unravel-oss/pkg/knowledge/kb/dbtest"

	// registers all lang extractors
	_ "github.com/inovacc/unravel-oss/pkg/knowledge/kb/langs"
)

// TestBackfillStaticIntegration seeds modules with noisy/empty symbols and
// missing module_deps, runs the backfill logic, and asserts:
//   - module_deps rows > 0 (for modules that have parseable imports)
//   - IsNoisy(symbols_json) == false for all seeded rows after backfill
func TestBackfillStaticIntegration(t *testing.T) {
	if _, skip := os.LookupEnv("SKIP_INTEGRATION"); skip {
		t.Skip("SKIP_INTEGRATION set")
	}
	db, _ := dbtest.StartPostgres(t)

	// ── seed ─────────────────────────────────────────────────────────

	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := db.Exec(q, args...); err != nil {
			t.Fatalf("seed exec: %v\nquery: %s", err, q)
		}
	}

	// JS body with a real import and real function.
	jsBody := []byte(`import React from "react";
import { useState } from "react";
export function MyComponent(props) {
	const [count, setCount] = useState(0);
	return count;
}
`)
	// Noisy symbols_json — the old extractor's garbage.
	noisySymbols := `{"methods":["return","switch","if"]}`

	// Compute sha256 for the body.
	sha := bodySHA256(jsBody)

	exec(`INSERT INTO module_bodies (body_sha256, body, body_size, stored_at)
	      VALUES ($1, $2, $3, 0)`, sha, jsBody, len(jsBody))

	// Module 1: noisy symbols, no deps.
	exec(`INSERT INTO modules (app, name, body_sha256, symbols_json, lang)
	      VALUES ('testapp', 'MyComponent.js', $1, $2, 'js')
	      ON CONFLICT DO NOTHING`, sha, noisySymbols)

	// Module 2: null symbols, no body in module_bodies (will be skipped).
	// We need a body for it too.
	sha2 := bodySHA256([]byte("const X = 1;"))
	exec(`INSERT INTO module_bodies (body_sha256, body, body_size, stored_at)
	      VALUES ($1, $2, $3, 0)`, sha2, []byte("const X = 1;"), 12)
	exec(`INSERT INTO modules (app, name, body_sha256, symbols_json, lang)
	      VALUES ('testapp', 'config.js', $1, NULL, 'js')
	      ON CONFLICT DO NOTHING`, sha2)

	// ── verify baseline: module_deps should be empty ──────────────────

	var depsBefore int64
	if err := db.QueryRow(`SELECT COUNT(*) FROM module_deps`).Scan(&depsBefore); err != nil {
		t.Fatalf("count deps before: %v", err)
	}
	if depsBefore != 0 {
		t.Fatalf("expected 0 deps before backfill, got %d", depsBefore)
	}

	// ── run backfill ──────────────────────────────────────────────────

	// Override globals for this test.
	old := backfillStaticDryRun
	backfillStaticDryRun = false
	backfillStaticApps = "testapp"
	backfillStaticWorkers = 2
	backfillStaticLimit = 0
	defer func() {
		backfillStaticDryRun = old
		backfillStaticApps = ""
	}()

	if err := runBackfillWorkers(db); err != nil {
		t.Fatalf("runBackfillWorkers: %v", err)
	}

	// ── assert: module_deps > 0 ───────────────────────────────────────

	var depsAfter int64
	if err := db.QueryRow(`SELECT COUNT(*) FROM module_deps`).Scan(&depsAfter); err != nil {
		t.Fatalf("count deps after: %v", err)
	}
	if depsAfter == 0 {
		t.Errorf("expected module_deps > 0 after backfill, got 0")
	}
	t.Logf("module_deps after backfill: %d", depsAfter)

	// ── assert: no noisy symbols_json remaining ───────────────────────

	rows, err := db.Query(`SELECT symbols_json FROM modules WHERE app = 'testapp' AND symbols_json IS NOT NULL`)
	if err != nil {
		t.Fatalf("query symbols: %v", err)
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var s sql.NullString
		if err := rows.Scan(&s); err != nil {
			t.Fatalf("scan: %v", err)
		}
		if s.Valid && s.String != "" && backfill.IsNoisy(s.String) {
			t.Errorf("symbols_json is still noisy after backfill: %s", s.String)
		}
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("rows err: %v", err)
	}
	t.Log("backfill integration test PASS")
}

// bodySHA256 computes the hex-encoded SHA-256 of b, matching the digest
// format used by the ingest walker (stored in module_bodies.body_sha256).
func bodySHA256(b []byte) string {
	sum := sha256.Sum256(b)
	return fmt.Sprintf("%x", sum[:])
}
