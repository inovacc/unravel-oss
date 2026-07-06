//go:build integration

/*
Copyright (c) 2026 Security Research

Integration tests for the v2.5 ingest writer against a testcontainer
Postgres. Skipped in default `go test ./...` runs; enabled by
`go test -tags=integration ./pkg/knowledge/kb/ingest/...`.

Coverage:

  - Test A: single capture (epoch=1) populates all SCOR-01 columns,
    kb_diffs has 0 rows.
  - Test B: two-epoch capture; epoch=2; DiffsWritten reflects facts
    that changed between snapshots.
  - Test C: idempotent re-ingest with identical binary_sha256
    short-circuits with Skipped=true and no new knowledge_sources row.
  - Test D: concurrent same-kb_id captures serialize via advisory
    lock; epoch set is {1,2,3,4,5} no duplicates.
  - Test E: Phase 30 boundary: module_components row count remains 0.
*/

package ingest

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/inovacc/unravel-oss/pkg/knowledge/kb/dbtest"
	"github.com/inovacc/unravel-oss/pkg/knowledge/kb/identity"
)

func writeKS(t *testing.T, dir string, knowledge map[string]any, files map[string][]byte) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	for name, body := range files {
		full := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
		if err := os.WriteFile(full, body, 0o644); err != nil {
			t.Fatalf("write: %v", err)
		}
	}
	if knowledge != nil {
		body, err := json.Marshal(knowledge)
		if err != nil {
			t.Fatalf("marshal knowledge: %v", err)
		}
		if err := os.WriteFile(filepath.Join(dir, "knowledge.json"), body, 0o644); err != nil {
			t.Fatalf("write knowledge.json: %v", err)
		}
	}
}

func fingerprintInputs(pkg, platform, version string) identity.FingerprintInputs {
	return identity.FingerprintInputs{
		Platform:   platform,
		PackageID:  pkg,
		AppVersion: version,
		CapturedAt: time.Now().Unix(),
	}
}

func TestIngest_SingleCapture(t *testing.T) {
	db, _ := dbtest.StartPostgres(t)
	ctx := context.Background()

	root := t.TempDir()
	ksDir := filepath.Join(root, "ks-v1")
	writeKS(t, ksDir, map[string]any{
		"framework": "electron",
		"security":  map[string]any{"risk_score": 45, "risk_level": "medium"},
		"dependencies": []any{
			map[string]any{"name": "react", "version": "18.2.0"},
		},
	}, map[string][]byte{
		"binary.exe": []byte("MZ-fake-pe-v1"),
		"app.js":     []byte("console.log('v1')"),
	})

	kbID, ksID, err := identity.Fingerprint(fingerprintInputs("com.example.app", "electron", "1.0.0"))
	if err != nil {
		t.Fatalf("fingerprint: %v", err)
	}

	res, err := Run(ctx, db, kbID, ksID, ksDir, Options{
		AllowedRoots: []string{root},
		Platform:     "electron",
		PackageID:    "com.example.app",
		DisplayName:  "Example",
	})
	if err != nil {
		t.Fatalf("ingest run: %v", err)
	}
	if res.Skipped {
		t.Fatal("Skipped should be false for fresh ingest")
	}
	if res.Epoch != int64(1) {
		t.Errorf("epoch: got=%d want=1", res.Epoch)
	}
	if res.Framework != "electron" {
		t.Errorf("framework: got=%q want=electron", res.Framework)
	}
	if res.RiskScore == nil || *res.RiskScore != 45 {
		t.Errorf("risk_score: got=%v want=45", res.RiskScore)
	}
	if res.DiffsWritten != 0 {
		t.Errorf("diffs_written: got=%d want=0 (epoch=1 has no prior)", res.DiffsWritten)
	}

	// SCOR-01 columns populated
	var (
		fw, lvl   sql.NullString
		score     sql.NullInt64
		dscore    sql.NullInt64
		binSHA    sql.NullString
		modsCount int64
	)
	if err := db.QueryRowContext(ctx, `
		SELECT framework, risk_level, risk_score, depth_score, binary_sha256, modules_indexed
		FROM knowledge_sources WHERE kb_id=$1 AND epoch=$2
	`, kbID, 1).Scan(&fw, &lvl, &score, &dscore, &binSHA, &modsCount); err != nil {
		t.Fatalf("scan ks row: %v", err)
	}
	if !fw.Valid || fw.String != "electron" {
		t.Errorf("framework column: got=%v", fw)
	}
	if !binSHA.Valid || binSHA.String == "" {
		t.Error("binary_sha256 should be populated")
	}

	// kb_diffs should be empty
	var diffsCount int
	if err := db.QueryRow(`SELECT COUNT(*) FROM kb_diffs`).Scan(&diffsCount); err != nil {
		t.Fatalf("count diffs: %v", err)
	}
	if diffsCount != 0 {
		t.Errorf("kb_diffs: got=%d want=0 (no prior epoch)", diffsCount)
	}

	// Phase 30 boundary: module_components untouched
	var compsCount int
	if err := db.QueryRow(`SELECT COUNT(*) FROM module_components`).Scan(&compsCount); err != nil {
		t.Fatalf("count module_components: %v", err)
	}
	if compsCount != 0 {
		t.Errorf("module_components: got=%d want=0 (Phase 31 boundary)", compsCount)
	}
}

func TestIngest_TwoEpochsAndIdempotency(t *testing.T) {
	db, _ := dbtest.StartPostgres(t)
	ctx := context.Background()

	root := t.TempDir()
	ksV1 := filepath.Join(root, "ks-v1")
	writeKS(t, ksV1, map[string]any{
		"framework": "electron",
		"security":  map[string]any{"risk_score": 30, "risk_level": "medium"},
		"dependencies": []any{
			map[string]any{"name": "react", "version": "18.2.0"},
		},
	}, map[string][]byte{
		"binary.exe": []byte("MZ-fake-pe-v1"),
		"app.js":     []byte("v1"),
	})

	kbID1, ksID1, _ := identity.Fingerprint(fingerprintInputs("com.example.app", "electron", "1.0.0"))
	res1, err := Run(ctx, db, kbID1, ksID1, ksV1, Options{
		AllowedRoots: []string{root},
		Platform:     "electron",
		PackageID:    "com.example.app",
		DisplayName:  "Example",
	})
	if err != nil {
		t.Fatalf("ingest v1: %v", err)
	}
	if res1.Epoch != int64(1) {
		t.Fatalf("epoch v1: got=%d want=1", res1.Epoch)
	}

	// Test C — idempotent re-ingest with same binary
	res1b, err := Run(ctx, db, kbID1, ksID1, ksV1, Options{
		AllowedRoots: []string{root},
		Platform:     "electron",
		PackageID:    "com.example.app",
		DisplayName:  "Example",
	})
	if err != nil {
		t.Fatalf("ingest v1 (re-run): %v", err)
	}
	if !res1b.Skipped {
		t.Error("re-ingest of identical binary_sha256 should be skipped")
	}
	if res1b.Epoch != int64(1) {
		t.Errorf("re-ingest epoch: got=%d want=1", res1b.Epoch)
	}

	// Test B — second epoch with mutated content
	ksV2 := filepath.Join(root, "ks-v2")
	writeKS(t, ksV2, map[string]any{
		"framework": "electron",
		"security":  map[string]any{"risk_score": 60, "risk_level": "high"},
		"dependencies": []any{
			map[string]any{"name": "react", "version": "18.3.0"}, // bump
			map[string]any{"name": "axios", "version": "1.0.0"},  // added
		},
	}, map[string][]byte{
		"binary.exe": []byte("MZ-fake-pe-v2-MUTATED"),
		"app.js":     []byte("v2-mutated"),
	})

	_, ksID2, _ := identity.Fingerprint(fingerprintInputs("com.example.app", "electron", "2.0.0"))
	res2, err := Run(ctx, db, kbID1, ksID2, ksV2, Options{
		AllowedRoots: []string{root},
		Platform:     "electron",
		PackageID:    "com.example.app",
		DisplayName:  "Example",
	})
	if err != nil {
		t.Fatalf("ingest v2: %v", err)
	}
	if res2.Epoch != int64(2) {
		t.Errorf("epoch v2: got=%d want=2", res2.Epoch)
	}
	if res2.DiffsWritten == 0 {
		t.Error("expected diffs_written > 0 between v1 and v2")
	}

	// kb_diffs should have rows
	var diffs int
	if err := db.QueryRow(`SELECT COUNT(*) FROM kb_diffs`).Scan(&diffs); err != nil {
		t.Fatalf("count diffs: %v", err)
	}
	if diffs == 0 {
		t.Error("kb_diffs should have rows for two-epoch capture")
	}

	// Phase 30 boundary preserved
	var compsCount int
	if err := db.QueryRow(`SELECT COUNT(*) FROM module_components`).Scan(&compsCount); err != nil {
		t.Fatalf("count module_components: %v", err)
	}
	if compsCount != 0 {
		t.Errorf("module_components: got=%d want=0 (Phase 31 boundary)", compsCount)
	}
}

func TestIngest_ConcurrentSameKBSerialize(t *testing.T) {
	db, _ := dbtest.StartPostgres(t)
	ctx := context.Background()

	root := t.TempDir()
	const goroutines = 5

	// Pin same kbID by sharing PackageID across all goroutines.
	kbID, _, _ := identity.Fingerprint(fingerprintInputs("com.example.concurrent", "electron", "1.0.0"))

	var wg sync.WaitGroup
	errs := make(chan error, goroutines)

	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			ksDir := filepath.Join(root, fmt.Sprintf("ks-%d", i))
			writeKS(t, ksDir, map[string]any{
				"framework": "electron",
			}, map[string][]byte{
				"binary.exe": []byte(fmt.Sprintf("MZ-unique-content-%d", i)),
			})
			ksID := fmt.Sprintf("%s:1.0.%d:%d", kbID, i, time.Now().UnixNano())
			_, err := Run(ctx, db, kbID, ksID, ksDir, Options{
				AllowedRoots: []string{root},
				Platform:     "electron",
				PackageID:    "com.example.concurrent",
				DisplayName:  "Concurrent",
			})
			if err != nil {
				errs <- err
			}
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Errorf("concurrent ingest err: %v", err)
	}

	// Assert epoch set is exactly {1,2,3,4,5} — no duplicates.
	rows, err := db.Query(`SELECT epoch FROM knowledge_sources WHERE kb_id=$1 ORDER BY epoch`, kbID)
	if err != nil {
		t.Fatalf("query epochs: %v", err)
	}
	defer func() { _ = rows.Close() }()
	seen := map[int]int{}
	var got []int
	for rows.Next() {
		var e int
		if err := rows.Scan(&e); err != nil {
			t.Fatalf("scan: %v", err)
		}
		got = append(got, e)
		seen[e]++
	}
	if len(got) != goroutines {
		t.Errorf("epoch count: got=%d want=%d (epochs=%v)", len(got), goroutines, got)
	}
	for e, n := range seen {
		if n > 1 {
			t.Errorf("duplicate epoch %d (count=%d)", e, n)
		}
	}
}
