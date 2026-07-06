//go:build integration

package db_test

import (
	"testing"

	kbdb "github.com/inovacc/unravel-oss/pkg/knowledge/kb/db"
	"github.com/inovacc/unravel-oss/pkg/knowledge/kb/dbtest"
)

// TestForceVersionClearsDirty proves the migrate-force recovery contract:
// ForceVersion sets schema_migrations to an arbitrary version and clears the
// dirty flag WITHOUT running migration SQL, and the real recovery flow
// (force to the last-good/head version, then re-open which runs Migrate)
// leaves a clean catalog with a subsequent Migrate as a genuine no-op.
//
// Note: forcing BACKWARD to a version below the physical schema (e.g. 17 while
// the DB is at head) and then running Migrate is NOT a no-op — Up correctly
// re-runs the newer migrations and fails on already-existing objects. That is
// user error, not a recovery bug; the CLI doc instructs forcing to the
// last-KNOWN-GOOD version, which this test models.
func TestForceVersionClearsDirty(t *testing.T) {
	conn, _ := dbtest.StartPostgres(t)

	if err := kbdb.Migrate(conn); err != nil {
		t.Fatalf("initial Migrate: %v", err)
	}

	// Capture the real head version the migrations reached, so the recovery
	// assertion stays correct as new migrations are added.
	var head int
	if err := conn.QueryRow(`SELECT version FROM schema_migrations`).Scan(&head); err != nil {
		t.Fatalf("read head version: %v", err)
	}

	// Simulate an interrupted migration: the catalog is flagged dirty.
	if _, err := conn.Exec(`UPDATE schema_migrations SET dirty = true`); err != nil {
		t.Fatalf("dirty seed: %v", err)
	}

	// ForceVersion sets an arbitrary version and clears dirty.
	if err := kbdb.ForceVersion(conn, 17); err != nil {
		t.Fatalf("ForceVersion: %v", err)
	}
	var version int
	var dirty bool
	if err := conn.QueryRow(`SELECT version, dirty FROM schema_migrations`).Scan(&version, &dirty); err != nil {
		t.Fatalf("read schema_migrations: %v", err)
	}
	if version != 17 || dirty {
		t.Fatalf("want version=17 dirty=false, got version=%d dirty=%v", version, dirty)
	}

	// ForceVersion runs NO migration SQL: the physical schema stays at head, so
	// a column added by a migration newer than 17 (knowledge_sources.commit_hash,
	// migration 000018) must still be present despite the forced version=17.
	var colExists bool
	if err := conn.QueryRow(`SELECT EXISTS (
		SELECT 1 FROM information_schema.columns
		WHERE table_name = 'knowledge_sources' AND column_name = 'commit_hash')`).Scan(&colExists); err != nil {
		t.Fatalf("check post-17 column: %v", err)
	}
	if !colExists {
		t.Fatalf("ForceVersion must not run migration SQL, but post-17 column knowledge_sources.commit_hash is gone")
	}

	// Real dirty-recovery flow: force to the last-good/head version, then the
	// re-open's Migrate is a genuine no-op (nothing left to apply).
	if err := kbdb.ForceVersion(conn, head); err != nil {
		t.Fatalf("ForceVersion to head %d: %v", head, err)
	}
	if err := kbdb.Migrate(conn); err != nil {
		t.Fatalf("Migrate after force-to-head should be a no-op: %v", err)
	}
	if err := conn.QueryRow(`SELECT version, dirty FROM schema_migrations`).Scan(&version, &dirty); err != nil {
		t.Fatalf("read schema_migrations after recovery: %v", err)
	}
	if version != head || dirty {
		t.Fatalf("after recovery want version=%d dirty=false, got version=%d dirty=%v", head, version, dirty)
	}
}
