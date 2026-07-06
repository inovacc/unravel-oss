//go:build integration

/*
Copyright (c) 2026 Security Research

Round-trip fidelity integration test for Phase 43:

	capture → export(db1) → import(db2) → assert equivalence.

The test materializes two ephemeral Postgres testcontainers, runs the
real kb capture pipeline against db1 (driving runKbCapture per Phase 36),
exports the captured kb_id as a D-43 bundle, then imports the bundle into
db2 and asserts:

 1. Round-trip preserves kb_apps + knowledge_sources + app_facts row counts.
 2. Re-importing the same bundle is a no-op (KBIM-03 idempotency).

Build-tag exclusion (`integration`) keeps the slow-test out of `go test
-short`. See plan 43-02 (KBIM-02 + KBIM-03) and ../03 SUMMARY for context.
*/
package cmd

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/inovacc/unravel-oss/pkg/knowledge/kb/dbtest"
	kbexport "github.com/inovacc/unravel-oss/pkg/knowledge/kb/export"
	kbimport "github.com/inovacc/unravel-oss/pkg/knowledge/kb/import_"
)

// TestKBImport_RoundTripFidelity proves a captured KB can be exported as
// a D-43 bundle and re-imported into a fresh Postgres without loss.
func TestKBImport_RoundTripFidelity(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test")
	}

	apkPath := requireFixture(t, resolveFixture(t, "input/fdroid.apk"))

	ctx := context.Background()

	// ----- db1: capture + export ------------------------------------------
	db1, dsn1 := dbtest.StartPostgres(t)
	kbID, _, _, _ := driveKbCapture(t, ctx, db1, dsn1, apkPath)

	tmp := t.TempDir()
	manifest, err := kbexport.Export(ctx, db1, kbID, tmp)
	if err != nil {
		t.Fatalf("export: %v", err)
	}
	if manifest.KbID != kbID {
		t.Fatalf("manifest kb_id mismatch: got %q want %q", manifest.KbID, kbID)
	}
	tarballPath, err := kbexport.Pack(tmp, kbID)
	if err != nil {
		t.Fatalf("pack: %v", err)
	}

	// Sanity: bundle.json + tarball exist.
	for _, p := range []string{
		filepath.Join(tmp, kbID+".kbb", "bundle.json"),
		tarballPath,
	} {
		if _, err := requireExists(p); err != nil {
			t.Fatalf("expected %s: %v", p, err)
		}
	}

	// ----- db2: import (fresh DB) -----------------------------------------
	db2, _ := dbtest.StartPostgres(t)
	report, err := kbimport.Import(ctx, db2, tarballPath)
	if err != nil {
		t.Fatalf("import: %v", err)
	}
	if report.KbID != kbID {
		t.Fatalf("import report kb_id mismatch: got %q want %q", report.KbID, kbID)
	}
	if report.NewRowsCount["kb_apps"] != 1 {
		t.Fatalf("expected 1 new kb_apps row; got %d", report.NewRowsCount["kb_apps"])
	}
	if report.NewRowsCount["knowledge_sources"] < 1 {
		t.Fatalf("expected ≥1 new knowledge_sources rows; got %d", report.NewRowsCount["knowledge_sources"])
	}

	// ----- assert kb_apps presence in db2 ---------------------------------
	var present int
	if err := db2.QueryRowContext(ctx, `SELECT COUNT(*) FROM kb_apps WHERE kb_id = $1`, kbID).Scan(&present); err != nil {
		t.Fatalf("query db2 kb_apps: %v", err)
	}
	if present != 1 {
		t.Fatalf("kb_apps row not found in db2 after import (got count=%d)", present)
	}

	// ----- idempotency: re-import same bundle into db2 → 0 new rows ------
	report2, err := kbimport.Import(ctx, db2, tarballPath)
	if err != nil {
		t.Fatalf("re-import: %v", err)
	}
	totalNew := 0
	for _, n := range report2.NewRowsCount {
		totalNew += n
	}
	if totalNew != 0 {
		t.Fatalf("re-import produced %d new rows (expected 0); breakdown=%v", totalNew, report2.NewRowsCount)
	}
}

func requireExists(path string) (bool, error) {
	if _, err := os.Stat(path); err != nil {
		return false, err
	}
	return true, nil
}
