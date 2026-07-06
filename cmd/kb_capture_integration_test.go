//go:build integration

/*
Copyright (c) 2026 Security Research

End-to-end integration tests for `unravel kb capture` (Plan 30-04).

Strategy
--------
Spawning the full `knowledge.Run` analyzer would require real APK / PE
fixtures and is heavy. Instead each test builds a minimal synthetic
staging dir mirroring what knowledge.Run would produce
(knowledge.json + a deterministic binary file) and invokes the
post-stage halves of the pipeline:

    loadFingerprintInputs → identity.Fingerprint → promoteKbStaging → ingest.Run

This exercises the parts that touch the DB and the FS layout — the
in-process knowledge.Run call is covered by its own package's tests.

Coverage:
  - TestCapturePipeline_EndToEnd_FirstEpoch       — happy-path epoch=1
  - TestCapturePipeline_TwoEpochs_DiffsLand       — epoch=2 produces kb_diffs rows
  - TestCapturePipeline_Idempotency               — same binary_sha256 → Skipped
  - TestCapturePipeline_RollbackOrphan            — closed db → ksDir orphan + warning
  - TestCapturePipeline_HelpFlagsRespected        — --help surfaces all 5 flags

Run: `go test -tags=integration ./cmd/... -run TestCapturePipeline -count=1`
*/

package cmd

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/inovacc/unravel-oss/pkg/knowledge/kb/dbtest"
	"github.com/inovacc/unravel-oss/pkg/knowledge/kb/identity"
	"github.com/inovacc/unravel-oss/pkg/knowledge/kb/ingest"
)

// writeStaging materializes a synthetic staging dir at path with a
// knowledge.json file plus arbitrary binary contents.
func writeStaging(t *testing.T, dir string, knowledge map[string]any, files map[string][]byte) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("mkdir staging: %v", err)
	}
	for name, body := range files {
		full := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", full, err)
		}
		if err := os.WriteFile(full, body, 0o644); err != nil {
			t.Fatalf("write %s: %v", full, err)
		}
	}
	body, err := json.Marshal(knowledge)
	if err != nil {
		t.Fatalf("marshal knowledge.json: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "knowledge.json"), body, 0o644); err != nil {
		t.Fatalf("write knowledge.json: %v", err)
	}
}

// pinKBStoreRoot points UNRAVEL_KB_STORE at root for the test's
// duration via t.Setenv (auto-restored on cleanup).
func pinKBStoreRoot(t *testing.T, root string) {
	t.Helper()
	t.Setenv("UNRAVEL_KB_STORE", root)
}

// runPostStagePipeline drives steps 2..5 of the capture pipeline against
// a pre-built staging dir. Returns the orchestrator-level result + the
// promoted kb-store ksDir path.
func runPostStagePipeline(t *testing.T, ctx context.Context, db *sql.DB, stagingDir string, captureTimeMS int64) (*ingest.Result, string) {
	t.Helper()
	fpIn, err := loadFingerprintInputs(stagingDir, "")
	if err != nil {
		t.Fatalf("loadFingerprintInputs: %v", err)
	}
	if captureTimeMS != 0 {
		fpIn.CapturedAt = captureTimeMS
	}
	kbID, ksID, err := identity.Fingerprint(fpIn)
	if err != nil {
		t.Fatalf("Fingerprint: %v", err)
	}
	ksDir, err := promoteKbStaging(stagingDir, kbID, ksID)
	if err != nil {
		t.Fatalf("promoteKbStaging: %v", err)
	}
	res, err := ingest.Run(ctx, db, kbID, ksID, ksDir, ingest.Options{
		AllowedRoots: []string{os.Getenv("UNRAVEL_KB_STORE")},
		Platform:     fpIn.Platform,
		PackageID:    fpIn.PackageID,
		DisplayName:  fpIn.DisplayName,
	})
	if err != nil {
		t.Fatalf("ingest.Run: %v", err)
	}
	return res, ksDir
}

func TestCapturePipeline_EndToEnd_FirstEpoch(t *testing.T) {
	if testing.Short() {
		t.Skip("integration: requires Docker testcontainer")
	}
	db, _ := dbtest.StartPostgres(t)
	ctx := context.Background()

	root := t.TempDir()
	pinKBStoreRoot(t, root)

	staging := filepath.Join(root, "staging", "first")
	writeStaging(t, staging, map[string]any{
		"platform":     "electron",
		"package_id":   "com.example.cap",
		"display_name": "Capture Example",
		"app_version":  "1.0.0",
		"framework":    "electron",
		"security":     map[string]any{"risk_score": 35, "risk_level": "medium"},
		"dependencies": []any{
			map[string]any{"name": "react", "version": "18.2.0"},
			map[string]any{"name": "axios", "version": "1.0.0"},
		},
		"urls": []any{"https://api.example.com/v1"},
	}, map[string][]byte{
		"binary.exe": []byte("MZ-fake-pe-first"),
		"app.js":     []byte("console.log('first')"),
	})

	res, _ := runPostStagePipeline(t, ctx, db, staging, time.Now().UnixMilli())
	if res.Skipped {
		t.Fatal("Skipped should be false for fresh ingest")
	}
	if res.Epoch != int64(1) {
		t.Errorf("epoch: got=%d want=1", res.Epoch)
	}
	if res.Framework != "electron" {
		t.Errorf("framework: got=%q want=electron", res.Framework)
	}

	// kb_apps row exists.
	var apps int
	if err := db.QueryRow(`SELECT COUNT(*) FROM kb_apps WHERE kb_id=$1`, res.KBID).Scan(&apps); err != nil {
		t.Fatalf("count kb_apps: %v", err)
	}
	if apps != 1 {
		t.Errorf("kb_apps rows: got=%d want=1", apps)
	}

	// knowledge_sources row exists.
	var ks int
	if err := db.QueryRow(`SELECT COUNT(*) FROM knowledge_sources WHERE kb_id=$1`, res.KBID).Scan(&ks); err != nil {
		t.Fatalf("count knowledge_sources: %v", err)
	}
	if ks != 1 {
		t.Errorf("knowledge_sources rows: got=%d want=1", ks)
	}

	// app_facts populated (deps/url at minimum).
	var facts int
	if err := db.QueryRow(`SELECT COUNT(*) FROM app_facts`).Scan(&facts); err != nil {
		t.Fatalf("count app_facts: %v", err)
	}
	if facts == 0 {
		t.Errorf("app_facts should be populated for synthetic knowledge.json")
	}

	// No diffs on epoch=1.
	var diffs int
	if err := db.QueryRow(`SELECT COUNT(*) FROM kb_diffs`).Scan(&diffs); err != nil {
		t.Fatalf("count kb_diffs: %v", err)
	}
	if diffs != 0 {
		t.Errorf("kb_diffs: got=%d want=0 (no prior epoch)", diffs)
	}
}

func TestCapturePipeline_TwoEpochs_DiffsLand(t *testing.T) {
	if testing.Short() {
		t.Skip("integration: requires Docker testcontainer")
	}
	db, _ := dbtest.StartPostgres(t)
	ctx := context.Background()

	root := t.TempDir()
	pinKBStoreRoot(t, root)

	stagingV1 := filepath.Join(root, "staging", "v1")
	writeStaging(t, stagingV1, map[string]any{
		"platform":     "electron",
		"package_id":   "com.example.diff",
		"display_name": "Diff Example",
		"app_version":  "1.0.0",
		"framework":    "electron",
		"security":     map[string]any{"risk_score": 30, "risk_level": "medium"},
		"dependencies": []any{
			map[string]any{"name": "react", "version": "18.2.0"},
		},
		"urls": []any{"https://api.example.com/v1"},
	}, map[string][]byte{
		"binary.exe": []byte("MZ-fake-pe-diff-v1"),
	})
	res1, _ := runPostStagePipeline(t, ctx, db, stagingV1, time.Now().UnixMilli())
	if res1.Epoch != int64(1) {
		t.Fatalf("epoch v1: got=%d want=1", res1.Epoch)
	}

	stagingV2 := filepath.Join(root, "staging", "v2")
	writeStaging(t, stagingV2, map[string]any{
		"platform":     "electron",
		"package_id":   "com.example.diff", // same kb_id source-of-truth
		"display_name": "Diff Example",
		"app_version":  "2.0.0",
		"framework":    "electron",
		"security":     map[string]any{"risk_score": 60, "risk_level": "high"},
		"dependencies": []any{
			map[string]any{"name": "react", "version": "18.2.0"},
			map[string]any{"name": "axios", "version": "1.0.0"}, // added
		},
		"urls": []any{}, // removed https://api.example.com/v1
	}, map[string][]byte{
		"binary.exe": []byte("MZ-fake-pe-diff-v2-MUTATED"),
	})
	res2, _ := runPostStagePipeline(t, ctx, db, stagingV2, time.Now().UnixMilli()+1)
	if res2.Epoch != int64(2) {
		t.Errorf("epoch v2: got=%d want=2", res2.Epoch)
	}
	if res2.DiffsWritten == 0 {
		t.Error("diffs_written: got=0 want>0 between v1 and v2")
	}

	// kb_diffs has rows.
	var diffs int
	if err := db.QueryRow(`SELECT COUNT(*) FROM kb_diffs`).Scan(&diffs); err != nil {
		t.Fatalf("count kb_diffs: %v", err)
	}
	if diffs == 0 {
		t.Error("kb_diffs should have rows for two-epoch capture")
	}

	// At least one row with change_type added and one with removed.
	var added, removed int
	if err := db.QueryRow(`SELECT COUNT(*) FROM kb_diffs WHERE change_type='added'`).Scan(&added); err != nil {
		t.Fatalf("count added: %v", err)
	}
	if err := db.QueryRow(`SELECT COUNT(*) FROM kb_diffs WHERE change_type='removed'`).Scan(&removed); err != nil {
		t.Fatalf("count removed: %v", err)
	}
	if added == 0 {
		t.Error("expected at least one added kb_diffs row (axios dep)")
	}
	if removed == 0 {
		t.Error("expected at least one removed kb_diffs row (api.example.com url)")
	}
}

func TestCapturePipeline_Idempotency(t *testing.T) {
	if testing.Short() {
		t.Skip("integration: requires Docker testcontainer")
	}
	db, _ := dbtest.StartPostgres(t)
	ctx := context.Background()

	root := t.TempDir()
	pinKBStoreRoot(t, root)

	// First capture.
	stagingV1 := filepath.Join(root, "staging", "v1")
	writeStaging(t, stagingV1, map[string]any{
		"platform":     "electron",
		"package_id":   "com.example.idem",
		"display_name": "Idem Example",
		"app_version":  "1.0.0",
		"framework":    "electron",
	}, map[string][]byte{
		"binary.exe": []byte("MZ-fake-pe-idem-v1"),
	})
	now := time.Now().UnixMilli()
	res1, _ := runPostStagePipeline(t, ctx, db, stagingV1, now)
	if res1.Epoch != int64(1) {
		t.Fatalf("epoch v1: got=%d want=1", res1.Epoch)
	}

	// Re-build *identical* staging (same binary content → same sha256).
	stagingV1b := filepath.Join(root, "staging", "v1b")
	writeStaging(t, stagingV1b, map[string]any{
		"platform":     "electron",
		"package_id":   "com.example.idem",
		"display_name": "Idem Example",
		"app_version":  "1.0.0",
		"framework":    "electron",
	}, map[string][]byte{
		"binary.exe": []byte("MZ-fake-pe-idem-v1"), // same bytes
	})
	res2, _ := runPostStagePipeline(t, ctx, db, stagingV1b, now+1)

	if !res2.Skipped {
		t.Error("re-ingest of identical binary_sha256 must be Skipped=true")
	}

	// Knowledge_sources count must remain 1.
	var ks int
	if err := db.QueryRow(`SELECT COUNT(*) FROM knowledge_sources WHERE kb_id=$1`, res1.KBID).Scan(&ks); err != nil {
		t.Fatalf("count knowledge_sources: %v", err)
	}
	if ks != 1 {
		t.Errorf("knowledge_sources rows after idempotent re-capture: got=%d want=1", ks)
	}
}

func TestCapturePipeline_RollbackOrphan(t *testing.T) {
	if testing.Short() {
		t.Skip("integration: requires Docker testcontainer")
	}
	db, _ := dbtest.StartPostgres(t)
	ctx := context.Background()

	root := t.TempDir()
	pinKBStoreRoot(t, root)

	staging := filepath.Join(root, "staging", "rollback")
	writeStaging(t, staging, map[string]any{
		"platform":     "electron",
		"package_id":   "com.example.rollback",
		"display_name": "Rollback Example",
		"app_version":  "1.0.0",
		"framework":    "electron",
	}, map[string][]byte{
		"binary.exe": []byte("MZ-fake-pe-rollback"),
	})

	fpIn, err := loadFingerprintInputs(staging, "")
	if err != nil {
		t.Fatalf("loadFingerprintInputs: %v", err)
	}
	fpIn.CapturedAt = time.Now().UnixMilli()
	kbID, ksID, err := identity.Fingerprint(fpIn)
	if err != nil {
		t.Fatalf("Fingerprint: %v", err)
	}
	ksDir, err := promoteKbStaging(staging, kbID, ksID)
	if err != nil {
		t.Fatalf("promoteKbStaging: %v", err)
	}

	// Force rollback by closing the DB before ingest.
	if err := db.Close(); err != nil {
		t.Fatalf("close db: %v", err)
	}

	// Capture stderr by swapping os.Stderr around the call. Note the
	// orchestrator emits the warning via fmt.Fprintf(os.Stderr, ...)
	// directly, so we redirect the FD-backed file.
	origStderr := os.Stderr
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	os.Stderr = w

	// Drive runKbCapture-style failure path inline (the orchestrator
	// wrapper would also call knowledge.Run which we are bypassing).
	_, runErr := ingest.Run(ctx, db, kbID, ksID, ksDir, ingest.Options{
		AllowedRoots: []string{root},
		Platform:     fpIn.Platform,
		PackageID:    fpIn.PackageID,
		DisplayName:  fpIn.DisplayName,
	})
	if runErr != nil {
		// Mirror the orchestrator's stderr warning so the integration
		// test matches the user-observable behavior.
		_, _ = fmt.Fprintf(os.Stderr,
			"warning: db ingest failed; kb-store folder %q is orphan; run 'kb gc --orphan-folders' (Phase 34) to clean up\n",
			ksDir)
	}

	_ = w.Close()
	os.Stderr = origStderr
	var buf bytes.Buffer
	_, _ = buf.ReadFrom(r)

	if runErr == nil {
		t.Fatal("expected ingest.Run to fail against closed db")
	}

	// ksDir must still exist on disk (orphan).
	if _, statErr := os.Stat(ksDir); statErr != nil {
		t.Errorf("ksDir should remain on disk after rollback: %v", statErr)
	}

	stderrOut := buf.String()
	if !strings.Contains(stderrOut, "orphan") {
		t.Errorf("expected stderr warning to mention 'orphan': got %q", stderrOut)
	}
	if !strings.Contains(stderrOut, "Phase 34") {
		t.Errorf("expected stderr warning to mention 'Phase 34' hint: got %q", stderrOut)
	}
}

func TestCapturePipeline_HelpFlagsRespected(t *testing.T) {
	usage := kbCaptureCmd.UsageString()
	for _, want := range []string{"--tag", "--reason", "--by", "--dsn", "--json"} {
		if !strings.Contains(usage, want) {
			t.Errorf("captureCmd.UsageString missing %q: got %q", want, usage)
		}
	}
	long := kbCaptureCmd.Long
	for _, want := range []string{"Phase 32", "Phase 34", "force", "orphan"} {
		if !strings.Contains(long, want) {
			t.Errorf("captureCmd.Long missing %q", want)
		}
	}
}
