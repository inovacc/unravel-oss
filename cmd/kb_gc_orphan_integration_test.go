//go:build integration

/*
Copyright (c) 2026 Security Research

Integration tests for `unravel kb gc` orphan modes (Phase 34 Plan 03).

Coverage:
  - TestGC_OrphanBodies  — DELETE module_bodies rows with no module_app_refs.
  - TestGC_OrphanFiles   — DELETE files rows with no file_app_refs.
  - TestGC_OrphanFolders — RemoveAll on <kb-store>/apps/<kb_id>/versions/<leaf>
                           where (kb_id, captured_at) has no knowledge_sources row.

Run: `go test -tags=integration -run 'TestGC_Orphan(Bodies|Files|Folders)' -v ./cmd/...`
*/

package cmd

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/inovacc/unravel-oss/pkg/knowledge/kb/dbtest"
)

// withDSN sets gcDSN for the duration of the test; existing flags
// reset is handled by resetGCFlags() in kb_gc_orphan_test.go.
func withDSN(t *testing.T, dsn string) {
	t.Helper()
	gcDSN = dsn
}

// seedKbApp inserts a kb_apps row so FK constraints don't reject
// downstream knowledge_sources / module_app_refs rows.
func seedKbApp(t *testing.T, db *sql.DB, kbID, name string) {
	t.Helper()
	now := time.Now().UnixMilli()
	_, err := db.Exec(
		`INSERT INTO kb_apps (kb_id, canonical_name, display_name, platform,
		                       first_seen_at, last_seen_at)
		 VALUES ($1, $2, $2, 'windows', $3, $3)`,
		kbID, name, now,
	)
	if err != nil {
		t.Fatalf("seedKbApp(%s): %v", kbID, err)
	}
}

func TestGC_OrphanBodies(t *testing.T) {
	defer resetGCFlags()()
	db, dsn := dbtest.StartPostgres(t)
	withDSN(t, dsn)

	seedKbApp(t, db, "aaaaaaaaaaaaaaaa", "AppA")

	// Insert two bodies; only one referenced by module_app_refs.
	mustExec(t, db,
		`INSERT INTO module_bodies (body_sha256, body, body_size, stored_at)
		 VALUES ('aa11', '\x6161', 2, 0), ('bb22', '\x6262', 2, 0)`)
	mustExec(t, db,
		`INSERT INTO knowledge_sources
		   (app, epoch, source_path, source_kind, source_sha256, kb_id, captured_at)
		 VALUES ('AppA', 1, '/tmp/a', 'other',
		         '0000000000000000000000000000000000000000000000000000000000000001',
		         'aaaaaaaaaaaaaaaa', 1700000000)`)
	var srcID int64
	if err := db.QueryRow(`SELECT id FROM knowledge_sources WHERE app='AppA' AND epoch=1`).Scan(&srcID); err != nil {
		t.Fatalf("fetch source id: %v", err)
	}
	mustExec(t, db,
		`INSERT INTO module_app_refs (body_sha256, app, source_id, observed_at)
		 VALUES ('aa11', 'AppA', $1, 0)`, srcID)

	gcOrphanBodies = true
	gcYes = true

	if err := runKbGC(gcCmd, nil); err != nil {
		t.Fatalf("runKbGC(orphan-bodies): %v", err)
	}

	// aa11 preserved, bb22 deleted.
	if !rowExists(t, db, `SELECT 1 FROM module_bodies WHERE body_sha256='aa11'`) {
		t.Error("expected aa11 to be preserved")
	}
	if rowExists(t, db, `SELECT 1 FROM module_bodies WHERE body_sha256='bb22'`) {
		t.Error("expected bb22 to be deleted")
	}
}

func TestGC_OrphanFiles(t *testing.T) {
	defer resetGCFlags()()
	db, dsn := dbtest.StartPostgres(t)
	withDSN(t, dsn)

	seedKbApp(t, db, "aaaaaaaaaaaaaaaa", "AppA")

	now := time.Now().UnixMilli()
	mustExec(t, db,
		`INSERT INTO files (file_sha256, file_size, first_seen_at)
		 VALUES ('cc33', 100, $1), ('dd44', 200, $1)`, now)
	mustExec(t, db,
		`INSERT INTO knowledge_sources
		   (app, epoch, source_path, source_kind, source_sha256, kb_id, captured_at)
		 VALUES ('AppA', 1, '/tmp/a', 'other',
		         '0000000000000000000000000000000000000000000000000000000000000002',
		         'aaaaaaaaaaaaaaaa', 1700000000)`)
	var srcID int64
	if err := db.QueryRow(`SELECT id FROM knowledge_sources WHERE app='AppA' AND epoch=1`).Scan(&srcID); err != nil {
		t.Fatalf("fetch source id: %v", err)
	}
	mustExec(t, db,
		`INSERT INTO file_app_refs (file_sha256, source_id, rel_path, observed_at)
		 VALUES ('cc33', $1, 'foo/bar', $2)`, srcID, now)

	gcOrphanFiles = true
	gcYes = true

	if err := runKbGC(gcCmd, nil); err != nil {
		t.Fatalf("runKbGC(orphan-files): %v", err)
	}

	if !rowExists(t, db, `SELECT 1 FROM files WHERE file_sha256='cc33'`) {
		t.Error("expected cc33 to be preserved")
	}
	if rowExists(t, db, `SELECT 1 FROM files WHERE file_sha256='dd44'`) {
		t.Error("expected dd44 to be deleted")
	}
}

func TestGC_OrphanFolders(t *testing.T) {
	defer resetGCFlags()()
	db, dsn := dbtest.StartPostgres(t)
	withDSN(t, dsn)

	tmp := t.TempDir()
	t.Setenv("UNRAVEL_KB_STORE", tmp)

	const realKB = "aaaaaaaaaaaaaaaa"
	const orphanKB = "bbbbbbbbbbbbbbbb"
	const malformedKB = "cccccccccccccccc"

	seedKbApp(t, db, realKB, "RealApp")
	seedKbApp(t, db, orphanKB, "OrphanApp")
	seedKbApp(t, db, malformedKB, "MalformedApp")

	mustExec(t, db,
		`INSERT INTO knowledge_sources
		   (app, epoch, source_path, source_kind, source_sha256, kb_id, captured_at)
		 VALUES ('RealApp', 1, '/tmp/real', 'other',
		         '0000000000000000000000000000000000000000000000000000000000000003',
		         $1, 1700000000)`,
		realKB)

	realDir := filepath.Join(tmp, "apps", realKB, "versions", realKB+"_v1.0.0_1700000000")
	orphanDir := filepath.Join(tmp, "apps", orphanKB, "versions", orphanKB+"_v1.0.0_1700000001")
	malformedDir := filepath.Join(tmp, "apps", malformedKB, "versions", "malformed")
	for _, d := range []string{realDir, orphanDir, malformedDir} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", d, err)
		}
	}

	gcOrphanFolders = true
	gcYes = true

	if err := runKbGC(gcCmd, nil); err != nil {
		t.Fatalf("runKbGC(orphan-folders): %v", err)
	}

	if !pathExists(realDir) {
		t.Errorf("real dir %s should be preserved", realDir)
	}
	if pathExists(orphanDir) {
		t.Errorf("orphan dir %s should be removed", orphanDir)
	}
	if !pathExists(malformedDir) {
		t.Errorf("malformed dir %s should be preserved (skipped silently)", malformedDir)
	}
}

// ─── helpers ────────────────────────────────────────────────────────────

func mustExec(t *testing.T, db *sql.DB, q string, args ...any) {
	t.Helper()
	if _, err := db.ExecContext(context.Background(), q, args...); err != nil {
		t.Fatalf("exec %q: %v", q, err)
	}
}

func rowExists(t *testing.T, db *sql.DB, q string, args ...any) bool {
	t.Helper()
	var dummy int
	err := db.QueryRow(q, args...).Scan(&dummy)
	if err == nil {
		return true
	}
	if errors.Is(err, sql.ErrNoRows) {
		return false
	}
	t.Fatalf("rowExists query %q: %v", q, err)
	return false
}

func pathExists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}
