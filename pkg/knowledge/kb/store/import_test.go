//go:build integration

/*
Copyright (c) 2026 Security Research

Integration tests for kbstore.Import. Boots a transient Postgres via
dbtest.StartPostgres, writes a synthetic D-43 bundle directory tree to
disk, and exercises Import end-to-end.

Covers:
  - TestImport_Basic         — first import inserts kb_apps + knowledge_sources
                               + app_facts rows; KBID is preserved; NewRows
                               and Counts populated; ImportedCount > 0.
  - TestImport_Idempotent    — re-importing the same bundle produces zero
                               new rows and bumps ConflictsSkipped.
  - TestImport_Validation    — nil db, empty bundle_path, bogus path all
                               surface lowercase wrapped errors.
*/

package store_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/inovacc/unravel-oss/pkg/knowledge/kb/dbtest"
	kbexport "github.com/inovacc/unravel-oss/pkg/knowledge/kb/export"
	"github.com/inovacc/unravel-oss/pkg/knowledge/kb/store"
)

// writeImportBundle materializes a minimal D-43 bundle directory tree on
// disk under root and returns the bundle root path. Mirrors the synthetic
// bundle shape used by pkg/knowledge/kb/import_/import_test.go.
func writeImportBundle(t *testing.T, root, kbID, platform string) string {
	t.Helper()
	bundleRoot := filepath.Join(root, kbID+".kbb")
	for _, sub := range []string{"knowledge_sources", "app_facts", "kb_diffs"} {
		if err := os.MkdirAll(filepath.Join(bundleRoot, sub), 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", sub, err)
		}
	}

	knowledgeBytes := []byte(`{"epoch":1,"name":"v1"}`)
	if err := os.WriteFile(filepath.Join(bundleRoot, "knowledge.json"), knowledgeBytes, 0o644); err != nil {
		t.Fatalf("write knowledge.json: %v", err)
	}

	sourceJSON := []byte(`{"epoch":1,"name":"v1"}`)
	if err := os.WriteFile(
		filepath.Join(bundleRoot, "knowledge_sources", "1-aaaaaaaaaaaa.json"),
		sourceJSON, 0o644,
	); err != nil {
		t.Fatalf("write source: %v", err)
	}

	factLine := []byte(`{"epoch":1,"category":"comm","key":"transport","value":"https"}` + "\n")
	if err := os.WriteFile(
		filepath.Join(bundleRoot, "app_facts", "1.jsonl"),
		factLine, 0o644,
	); err != nil {
		t.Fatalf("write fact: %v", err)
	}

	sum := sha256.Sum256(knowledgeBytes)
	checksum := hex.EncodeToString(sum[:])
	manifest := &kbexport.BundleManifest{
		BundleSchemaVersion: kbexport.BundleSchemaVersion,
		KbID:                kbID,
		Platform:            platform,
		ExportedAt:          time.Date(2026, 5, 27, 12, 0, 0, 0, time.UTC),
		ExportedBy:          "github.com/inovacc/unravel-oss/test",
		Counts:              kbexport.Counts{KnowledgeSources: 1, AppFacts: 1, KbDiffs: 0},
		Checksum:            checksum,
	}
	mb, err := kbexport.MarshalManifest(manifest)
	if err != nil {
		t.Fatalf("marshal manifest: %v", err)
	}
	if err := os.WriteFile(filepath.Join(bundleRoot, "bundle.json"), mb, 0o644); err != nil {
		t.Fatalf("write bundle.json: %v", err)
	}
	return bundleRoot
}

func TestImport_Basic(t *testing.T) {
	db, _ := dbtest.StartPostgres(t)
	ctx := context.Background()

	const kbID = "kbimp000000000001"
	bundleRoot := writeImportBundle(t, t.TempDir(), kbID, "android")

	out, err := store.Import(ctx, db, store.ImportOptions{BundlePath: bundleRoot})
	if err != nil {
		t.Fatalf("Import: %v", err)
	}
	if out.KBID != kbID {
		t.Errorf("kb_id = %q, want %q", out.KBID, kbID)
	}
	if out.NewRows["kb_apps"] != 1 {
		t.Errorf("new_rows[kb_apps] = %d, want 1", out.NewRows["kb_apps"])
	}
	if out.NewRows["knowledge_sources"] != 1 {
		t.Errorf("new_rows[knowledge_sources] = %d, want 1", out.NewRows["knowledge_sources"])
	}
	if out.NewRows["app_facts"] != 1 {
		t.Errorf("new_rows[app_facts] = %d, want 1", out.NewRows["app_facts"])
	}
	if out.ImportedCount < 3 {
		t.Errorf("imported_count = %d, want >= 3", out.ImportedCount)
	}
	if out.Counts.KnowledgeSources != 1 || out.Counts.AppFacts != 1 {
		t.Errorf("counts = %+v, want KnowledgeSources=1 AppFacts=1", out.Counts)
	}

	// Confirm kb_apps row landed.
	var present int
	if err := db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM kb_apps WHERE kb_id = $1`, kbID).Scan(&present); err != nil {
		t.Fatalf("query kb_apps: %v", err)
	}
	if present != 1 {
		t.Fatalf("kb_apps row not present after import (count=%d)", present)
	}
}

func TestImport_Idempotent(t *testing.T) {
	db, _ := dbtest.StartPostgres(t)
	ctx := context.Background()

	const kbID = "kbimp000000000002"
	bundleRoot := writeImportBundle(t, t.TempDir(), kbID, "android")

	if _, err := store.Import(ctx, db, store.ImportOptions{BundlePath: bundleRoot}); err != nil {
		t.Fatalf("first Import: %v", err)
	}
	out, err := store.Import(ctx, db, store.ImportOptions{BundlePath: bundleRoot})
	if err != nil {
		t.Fatalf("second Import: %v", err)
	}
	if out.ImportedCount != 0 {
		t.Errorf("imported_count = %d, want 0 on re-import; new_rows=%v", out.ImportedCount, out.NewRows)
	}
	if out.ConflictsSkipped["kb_apps"] != 1 {
		t.Errorf("conflicts_skipped[kb_apps] = %d, want 1", out.ConflictsSkipped["kb_apps"])
	}
}

func TestImport_Validation(t *testing.T) {
	ctx := context.Background()

	if _, err := store.Import(ctx, nil, store.ImportOptions{BundlePath: "/tmp/x"}); err == nil {
		t.Error("expected error for nil db")
	}

	db, _ := dbtest.StartPostgres(t)
	if _, err := store.Import(ctx, db, store.ImportOptions{}); err == nil {
		t.Error("expected error for empty bundle_path")
	}
	if _, err := store.Import(ctx, db, store.ImportOptions{BundlePath: "/nonexistent/bundle/path"}); err == nil {
		t.Error("expected error for missing bundle path")
	}
}
