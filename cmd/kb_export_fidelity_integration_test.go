//go:build integration

// Integration: serial — mutates kbExportFlags + config DSN.

package cmd

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/spf13/cobra"

	"github.com/inovacc/unravel-oss/pkg/knowledge/kb/dbtest"
	"github.com/inovacc/unravel-oss/pkg/knowledge/kb/exportbundle"
)

// seedFidelityModules seeds the minimal 4-way chain for TestKbExportFidelityBundle:
//
//	kb_apps  (K, "teams")
//	knowledge_sources (K, "teams", epoch=1) → sourceID
//	modules A (full body + enrichment), B (excerpt only), C (absent)
//	module_app_refs for A, B, C
//	module_bodies for A only
//	module_enrichment for A only
//
// Returns (sourceID, shaA, moduleAID, moduleBID, moduleCID).
func seedFidelityModules(t *testing.T, db *sql.DB) (sourceID int64, shaA string, moduleAID, moduleBID, moduleCID int64) {
	t.Helper()
	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := db.Exec(q, args...); err != nil {
			t.Fatalf("seed exec: %v\nquery: %s", err, q)
		}
	}

	// ── 1. kb_apps ────────────────────────────────────────────────────────
	exec(`INSERT INTO kb_apps
		(kb_id, canonical_name, display_name, platform, first_seen_at, last_seen_at)
		VALUES ('K', 'teams', 'Teams', 'uwp', 0, 0)`)

	// ── 2. knowledge_sources ──────────────────────────────────────────────
	err := db.QueryRow(`INSERT INTO knowledge_sources
		(app, epoch, source_path, source_kind, captured_at, kb_id)
		VALUES ('teams', 1, '/tmp/fidelity-test', 'other', 0, 'K')
		RETURNING id`).Scan(&sourceID)
	if err != nil {
		t.Fatalf("insert knowledge_sources: %v", err)
	}

	// ── 3. Module A: full body + enrichment ───────────────────────────────
	bodyA := []byte("FULL-BODY-A")
	h := sha256.Sum256(bodyA)
	shaA = hex.EncodeToString(h[:])

	exec(`INSERT INTO module_bodies (body_sha256, body, body_size, stored_at)
		VALUES ($1, $2, $3, 0)`, shaA, bodyA, len(bodyA))

	exec(`INSERT INTO modules
		(app, name, body_size, body_excerpt, body_sha256, summary, tags, synthetic_name)
		VALUES ('teams', 'AlphaMod', $1, 'ignored', $2, 'A sum', 't1', 'AlphaSynthetic')`,
		len(bodyA), shaA)

	if err := db.QueryRow(`SELECT id FROM modules WHERE body_sha256 = $1`, shaA).Scan(&moduleAID); err != nil {
		t.Fatalf("select moduleAID: %v", err)
	}

	exec(`INSERT INTO module_app_refs (body_sha256, app, source_id, observed_at)
		VALUES ($1, 'teams', $2, 0)`, shaA, sourceID)

	exec(`INSERT INTO module_enrichment
		(module_id, role, long_summary, inputs_json, outputs_json, side_effects, deps_json, created_at)
		VALUES ($1, 'auth', 'LS', '[]', '[]', 'se', '[]', 0)`, moduleAID)

	// ── 4. Module B: no body, excerpt only ────────────────────────────────
	shaB := "sha_fidelity_beta_mod_excerpt_only_x"
	exec(`INSERT INTO modules
		(app, name, body_size, body_excerpt, body_sha256)
		VALUES ('teams', 'BetaMod', 0, 'EXCERPT-B', $1)`, shaB)

	if err := db.QueryRow(`SELECT id FROM modules WHERE body_sha256 = $1`, shaB).Scan(&moduleBID); err != nil {
		t.Fatalf("select moduleBID: %v", err)
	}

	exec(`INSERT INTO module_app_refs (body_sha256, app, source_id, observed_at)
		VALUES ($1, 'teams', $2, 0)`, shaB, sourceID)

	// ── 5. Module C: no body, no excerpt ─────────────────────────────────
	shaC := "sha_fidelity_gamma_mod_absent_xxxxxx"
	exec(`INSERT INTO modules
		(app, name, body_size, body_excerpt, body_sha256)
		VALUES ('teams', 'GammaMod', 0, '', $1)`, shaC)

	if err := db.QueryRow(`SELECT id FROM modules WHERE body_sha256 = $1`, shaC).Scan(&moduleCID); err != nil {
		t.Fatalf("select moduleCID: %v", err)
	}

	exec(`INSERT INTO module_app_refs (body_sha256, app, source_id, observed_at)
		VALUES ($1, 'teams', $2, 0)`, shaC, sourceID)

	return sourceID, shaA, moduleAID, moduleBID, moduleCID
}

// parseManifest reads and decodes manifest.json from dir.
func parseManifest(t *testing.T, dir string) exportbundle.Manifest {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(dir, "manifest.json"))
	if err != nil {
		t.Fatalf("read manifest.json: %v", err)
	}
	var m exportbundle.Manifest
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatalf("unmarshal manifest.json: %v", err)
	}
	return m
}

// invokeKbExportFidelity builds a cobra.Command with buffer, sets all flags,
// and calls runKbExport (which dispatches to runKbExportFidelity when bodies=true).
func invokeKbExportFidelity(t *testing.T) error {
	t.Helper()
	var buf bytes.Buffer
	cmd := &cobra.Command{}
	cmd.SetOut(&buf)
	cmd.SetContext(context.Background())
	return runKbExport(cmd, nil)
}

// TestKbExportFidelityBundle is the integration test for the kb export --bodies
// fidelity path. It is serial (no t.Parallel()) because it mutates package-level
// kbExportFlags and config DSN.
func TestKbExportFidelityBundle(t *testing.T) {
	// ── 1. Boot Postgres container + apply migrations ──────────────────────
	db, dsn := dbtest.StartPostgres(t)
	pinDSNViaConfig(t, dsn)

	// ── 2. Seed the 4-way chain ────────────────────────────────────────────
	_, shaA, _, _, _ := seedFidelityModules(t, db)

	// ── 3. Save + restore all mutated kbExportFlags fields ────────────────
	savedBodies := kbExportFlags.bodies
	// output backs the root persistent --output/-o flag (§7 of
	// COMMAND-TAXONOMY.md); the fidelity path reads it directly instead of a
	// local --out redeclaration.
	savedOut := output
	savedLimit := kbExportFlags.limit
	savedMaxBytes := kbExportFlags.maxBytes
	savedKbID := kbExportFlags.kbID
	savedDSN := kbExportFlags.dsn
	t.Cleanup(func() {
		kbExportFlags.bodies = savedBodies
		output = savedOut
		kbExportFlags.limit = savedLimit
		kbExportFlags.maxBytes = savedMaxBytes
		kbExportFlags.kbID = savedKbID
		kbExportFlags.dsn = savedDSN
	})

	// Shared defaults (per-subtest may override).
	kbExportFlags.dsn = "" // uses config.yaml pinned by pinDSNViaConfig
	kbExportFlags.kbID = "K"
	kbExportFlags.limit = 0
	kbExportFlags.maxBytes = 0

	// ── 4. Run 1: full fidelity export ────────────────────────────────────
	dir1 := t.TempDir()
	kbExportFlags.bodies = true
	output = dir1

	if err := invokeKbExportFidelity(t); err != nil {
		t.Fatalf("run1 fidelity export: %v", err)
	}

	// ── 5. Assert manifest ────────────────────────────────────────────────
	m := parseManifest(t, dir1)

	if m.SchemaVersion != exportbundle.SchemaVersion {
		t.Errorf("schema_version: got %d, want %d", m.SchemaVersion, exportbundle.SchemaVersion)
	}
	if m.ModuleCount != 3 {
		t.Errorf("module_count: got %d, want 3", m.ModuleCount)
	}
	if len(m.Records) != 3 {
		t.Errorf("records len: got %d, want 3", len(m.Records))
	}

	// Find records by name for deterministic assertions.
	recByName := make(map[string]exportbundle.ManifestRecord, 3)
	for _, r := range m.Records {
		recByName[r.Name] = r
	}

	// Module A: full body.
	if ra, ok := recByName["AlphaMod"]; !ok {
		t.Error("AlphaMod record missing")
	} else {
		if ra.BodyStatus != "full" {
			t.Errorf("AlphaMod body_status: got %q, want full", ra.BodyStatus)
		}
		absA := filepath.Join(dir1, exportbundle.BodyPath(shaA))
		got, err := os.ReadFile(absA)
		if err != nil {
			t.Fatalf("read AlphaMod body file: %v", err)
		}
		if !bytes.Equal(got, []byte("FULL-BODY-A")) {
			t.Errorf("AlphaMod body content: got %q, want FULL-BODY-A", got)
		}
		if ra.Role != "auth" {
			t.Errorf("AlphaMod role: got %q, want auth", ra.Role)
		}
		if ra.LongSummary != "LS" {
			t.Errorf("AlphaMod long_summary: got %q, want LS", ra.LongSummary)
		}
		if ra.Summary != "A sum" {
			t.Errorf("AlphaMod summary: got %q, want 'A sum'", ra.Summary)
		}
		if ra.Tags != "t1" {
			t.Errorf("AlphaMod tags: got %q, want t1", ra.Tags)
		}
		if ra.SyntheticName != "AlphaSynthetic" {
			t.Errorf("AlphaMod synthetic_name: got %q, want AlphaSynthetic", ra.SyntheticName)
		}
	}

	// Module B: excerpt.
	if rb, ok := recByName["BetaMod"]; !ok {
		t.Error("BetaMod record missing")
	} else {
		if rb.BodyStatus != "excerpt" {
			t.Errorf("BetaMod body_status: got %q, want excerpt", rb.BodyStatus)
		}
		if rb.BodyPath == "" {
			t.Error("BetaMod body_path: expected non-empty for excerpt")
		} else {
			got, err := os.ReadFile(filepath.Join(dir1, rb.BodyPath))
			if err != nil {
				t.Fatalf("read BetaMod body file: %v", err)
			}
			if !bytes.Equal(got, []byte("EXCERPT-B")) {
				t.Errorf("BetaMod body content: got %q, want EXCERPT-B", got)
			}
		}
	}

	// Module C: absent.
	if rc, ok := recByName["GammaMod"]; !ok {
		t.Error("GammaMod record missing")
	} else {
		if rc.BodyStatus != "absent" {
			t.Errorf("GammaMod body_status: got %q, want absent", rc.BodyStatus)
		}
		if rc.BodyPath != "" {
			t.Errorf("GammaMod body_path: got %q, want empty", rc.BodyPath)
		}
		if rc.BodyPath == "" {
			// Confirm no file exists at what would be the path.
			absC := filepath.Join(dir1, exportbundle.BodyPath(rc.BodySHA256))
			if _, err := os.Stat(absC); err == nil {
				t.Error("GammaMod: body file should not exist for absent status")
			}
		}
	}

	// ── 6. Idempotent re-run ──────────────────────────────────────────────
	// Capture content of A's body file before second run.
	absA := filepath.Join(dir1, exportbundle.BodyPath(shaA))
	beforeBytes, err := os.ReadFile(absA)
	if err != nil {
		t.Fatalf("read AlphaMod body before idempotent run: %v", err)
	}

	if err := invokeKbExportFidelity(t); err != nil {
		t.Fatalf("idempotent re-run: %v", err)
	}

	m2 := parseManifest(t, dir1)
	if m2.ModuleCount != 3 || len(m2.Records) != 3 {
		t.Errorf("idempotent re-run: module_count=%d records=%d, want 3/3", m2.ModuleCount, len(m2.Records))
	}

	afterBytes, err := os.ReadFile(absA)
	if err != nil {
		t.Fatalf("read AlphaMod body after idempotent run: %v", err)
	}
	if !bytes.Equal(beforeBytes, afterBytes) {
		t.Error("idempotent re-run: AlphaMod body content changed")
	}

	// ── 7. Truncated: maxBytes < len("FULL-BODY-A") ───────────────────────
	dir2 := t.TempDir()
	output = dir2
	kbExportFlags.maxBytes = 3 // "FULL-BODY-A" is 11 bytes → triggers truncation

	if err := invokeKbExportFidelity(t); err != nil {
		t.Fatalf("truncated run: %v", err)
	}

	mt := parseManifest(t, dir2)
	if !mt.Truncated {
		t.Error("truncated run: expected manifest.truncated=true")
	}
	if len(mt.Records) >= 3 {
		t.Errorf("truncated run: expected fewer than 3 records, got %d", len(mt.Records))
	}

	// Reset maxBytes for subsequent steps.
	kbExportFlags.maxBytes = 0

	// ── 8. Default parity: bodies=false → legacy path, no manifest.json ──
	dir3 := t.TempDir()
	kbExportFlags.bodies = false
	output = dir3

	// Legacy path requires --output flag and positional arg; without them it
	// returns an error about missing args. That is the legacy guard: the fidelity
	// manifest must NOT be created in dir3.
	var buf bytes.Buffer
	legacyCmd := &cobra.Command{}
	legacyCmd.SetOut(&buf)
	legacyCmd.SetContext(context.Background())
	_ = runKbExport(legacyCmd, nil) // error expected (legacy missing --output); we don't care

	if _, err := os.Stat(filepath.Join(dir3, "manifest.json")); err == nil {
		t.Error("default parity: manifest.json must NOT be created when --bodies=false")
	}
}
