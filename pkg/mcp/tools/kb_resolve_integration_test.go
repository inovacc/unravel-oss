//go:build integration

/*
Copyright (c) 2026 Security Research
*/
package mcptools

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/inovacc/unravel-oss/pkg/knowledge/kb/dbtest"
)

// TestKBResolve_EmptyCatalogIsLoud verifies that kbResolve against a fresh
// (empty) Postgres container:
//   - derives identity (database + user) from the live connection,
//   - reports the migration version applied by dbtest (> 0),
//   - counts zero apps and zero knowledge_sources,
//   - and that emptyResultDiagnostic produces a loud text containing
//     "knowledge_sources=0" plus a non-nil structured "catalog" key.
func TestKBResolve_EmptyCatalogIsLoud(t *testing.T) {
	if testing.Short() {
		t.Skip("requires Postgres testcontainer")
	}

	_, dsn := dbtest.StartPostgres(t) // db handle owned by dbtest (auto-cleanup); kbResolve opens & owns its own pool

	db, info, err := kbResolve(context.Background(), dsn)
	defer func() {
		if db != nil {
			_ = db.Close()
		}
	}()
	if err != nil {
		t.Fatalf("kbResolve: %v", err)
	}

	// Empty catalog: no apps, no knowledge_sources.
	if info.Catalog.Apps != 0 || info.Catalog.Sources != 0 {
		t.Fatalf("fresh catalog should be empty, got %+v", info.Catalog)
	}

	// Identity derived from the live connection.
	if info.Database == "" || info.User == "" {
		t.Fatalf("identity not derived from connection: database=%q user=%q", info.Database, info.User)
	}

	// Migration version must be > 0 (dbtest applies all embedded migrations).
	if info.Catalog.MigrationVersion == 0 {
		t.Fatalf("migration version not reported (expected >0 after dbtest migrations); got %d", info.Catalog.MigrationVersion)
	}

	// emptyResultDiagnostic must be loud about the empty catalog.
	text, structured := emptyResultDiagnostic(info, "modules") // "modules" = representative result-kind label for the diagnostic
	if !strings.Contains(text, "knowledge_sources=0") {
		t.Fatalf("empty diagnostic not loud: %s", text)
	}
	if structured["catalog"] == nil {
		t.Fatalf("structured diagnostic missing catalog key: %#v", structured)
	}
}

// TestKBResolve_SeededCatalogHappyPath verifies that kbResolve against a
// Postgres container with at least one kb_apps + knowledge_sources row:
//   - reports Apps >= 1 and Sources >= 1 in the catalog summary,
//   - and that emptyResultDiagnostic does NOT emit the "zero knowledge_sources"
//     hint (i.e. a non-empty catalog is treated as healthy, not empty).
func TestKBResolve_SeededCatalogHappyPath(t *testing.T) {
	if testing.Short() {
		t.Skip("requires Postgres testcontainer")
	}

	db, dsn := dbtest.StartPostgres(t)
	t.Cleanup(func() { _ = db.Close() })

	kbID := "dddd6666dddd6666"
	ksID := kbID + ":v1:1"

	// Seed one kb_apps row.
	if _, err := db.Exec(
		`INSERT INTO kb_apps (kb_id, canonical_name, display_name, platform,
		                      first_seen_at, last_seen_at)
		 VALUES ($1, $2, $3, $4, $5, $6)`,
		kbID, "seeded-app", "Seeded App", "windows-msix",
		time.Now().Unix(), time.Now().Unix(),
	); err != nil {
		t.Fatalf("seed kb_apps: %v", err)
	}

	// Seed one knowledge_sources row.
	if _, err := db.Exec(
		`INSERT INTO knowledge_sources
		   (app, source_path, source_kind, captured_at, app_version, epoch, kb_id, ks_id)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
		"app-"+kbID, "/tmp/seed/"+ksID, "other",
		time.Now().UnixMilli(), "v1", int64(1), kbID, ksID,
	); err != nil {
		t.Fatalf("seed knowledge_sources: %v", err)
	}

	// kbResolve opens its own pool from the DSN.
	resolvedDB, info, err := kbResolve(context.Background(), dsn)
	t.Cleanup(func() {
		if resolvedDB != nil {
			_ = resolvedDB.Close()
		}
	})
	if err != nil {
		t.Fatalf("kbResolve: %v", err)
	}

	// Catalog must reflect the seeded rows.
	if info.Catalog.Apps < 1 {
		t.Fatalf("catalog.Apps = %d want >= 1", info.Catalog.Apps)
	}
	if info.Catalog.Sources < 1 {
		t.Fatalf("catalog.Sources = %d want >= 1", info.Catalog.Sources)
	}

	// emptyResultDiagnostic must NOT emit the zero-sources hint when catalog is non-empty.
	text, _ := emptyResultDiagnostic(info, "modules")
	if strings.Contains(text, "catalog has zero knowledge_sources") {
		t.Fatalf("non-empty catalog still produced zero-sources hint: %s", text)
	}
}
