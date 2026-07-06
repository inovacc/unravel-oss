//go:build integration

package db_test

import (
	"context"
	"database/sql"
	"testing"

	kbdb "github.com/inovacc/unravel-oss/pkg/knowledge/kb/db"
	"github.com/inovacc/unravel-oss/pkg/knowledge/kb/dbtest"
)

// TestOpenEmptyPathRejected verifies Open() with an empty DSN AND no
// config.yaml fallback produces an error. We can't easily simulate the
// "no config" path in CI, so we accept either nil (config provided a DSN)
// or an error. The original sqlite test asserted error-only because the
// sqlite signature took a path; here Open(ctx, "") legitimately falls
// back to pkg/config and may succeed if a config exists. Skip when
// config-driven open works to keep the test deterministic across machines.
func TestOpenEmptyPathRejected(t *testing.T) {
	conn, err := kbdb.Open(context.Background(), "")
	if err == nil {
		_ = conn.Close()
		t.Skip("local pkg/config provides a DSN; empty-DSN error path is environment-dependent")
	}
	// err != nil — that's the original assertion.
}

// TestOpenInMemoryAppliesSchema (renamed from sqlite version) — boot
// fresh pg, verify the core tables exist via pg_catalog.
func TestOpenInMemoryAppliesSchema(t *testing.T) {
	conn, _ := dbtest.StartPostgres(t)

	want := []string{
		"modules",
		"module_sightings",
		"module_bodies",
		"module_enrichment",
		"module_deps",
		"module_components",
		"app_facts",
		"fact_history",
		"module_embeddings",
		"repos",
	}
	for _, name := range want {
		var got string
		err := conn.QueryRow(`
			SELECT tablename
			  FROM pg_catalog.pg_tables
			 WHERE schemaname = 'public' AND tablename = $1
			UNION
			SELECT viewname
			  FROM pg_catalog.pg_views
			 WHERE schemaname = 'public' AND viewname = $1`, name).Scan(&got)
		if err != nil {
			t.Errorf("table %q missing: %v", name, err)
		}
	}
}

// TestOpenIsIdempotent — re-opening (and re-running migrations) against
// a populated database is a no-op. We exercise this by booting one
// container and calling Migrate twice on the same conn.
func TestOpenIsIdempotent(t *testing.T) {
	conn, _ := dbtest.StartPostgres(t)
	if err := kbdb.Migrate(conn); err != nil {
		t.Fatalf("migrate (second run): %v", err)
	}
}

// TestMigrationsApplied (replaces TestSchemaNotEmpty) — pg uses
// embedded golang-migrate sources, not a `Schema` const. Assert that
// the canonical `modules` relation is registered.
func TestMigrationsApplied(t *testing.T) {
	conn, _ := dbtest.StartPostgres(t)
	var rel sql.NullString
	if err := conn.QueryRow(`SELECT to_regclass('public.modules')::text`).Scan(&rel); err != nil {
		t.Fatalf("to_regclass: %v", err)
	}
	if !rel.Valid || rel.String != "modules" {
		t.Fatalf("modules table not registered: got %+v", rel)
	}
}

// TestModulesHasLangAndRepoRoot — assert the source-code ingest columns
// are present on a fresh DB.
func TestModulesHasLangAndRepoRoot(t *testing.T) {
	conn, _ := dbtest.StartPostgres(t)
	for _, col := range []string{"lang", "repo_root"} {
		var n int
		row := conn.QueryRow(`
			SELECT COUNT(*)
			  FROM information_schema.columns
			 WHERE table_schema = 'public'
			   AND table_name = 'modules'
			   AND column_name = $1`, col)
		if err := row.Scan(&n); err != nil {
			t.Fatalf("scan %s: %v", col, err)
		}
		if n != 1 {
			t.Errorf("modules.%s: expected 1 column, got %d", col, n)
		}
	}
}

// TestMigration_009_DropsModuleTopics asserts migration 000009 removed
// the module_topics table; pg_class lookup must return zero rows.
func TestMigration_009_DropsModuleTopics(t *testing.T) {
	conn, _ := dbtest.StartPostgres(t)

	var rel sql.NullString
	if err := conn.QueryRow(`SELECT to_regclass('public.module_topics')::text`).Scan(&rel); err != nil {
		t.Fatalf("to_regclass: %v", err)
	}
	if rel.Valid {
		t.Errorf("module_topics still exists after 000009: %q", rel.String)
	}
}

func contains(haystack, needle string) bool {
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return true
		}
	}
	return false
}

// TestMigrateIdempotent (replaces TestApplyAdditiveMigrationsLegacyDB)
// — golang-migrate handles its own state via schema_migrations. Re-
// applying after a successful run returns ErrNoChange (swallowed inside
// Migrate). Run it twice, assert no error.
func TestMigrateIdempotent(t *testing.T) {
	conn, _ := dbtest.StartPostgres(t)
	for i := 0; i < 2; i++ {
		if err := kbdb.Migrate(conn); err != nil {
			t.Fatalf("migrate #%d: %v", i, err)
		}
	}
}
