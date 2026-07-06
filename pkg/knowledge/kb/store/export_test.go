//go:build integration

/*
Copyright (c) 2026 Security Research

Integration tests for kbstore.Export. Boots a transient Postgres via
dbtest.StartPostgres, seeds a minimal kb_apps + knowledge_sources +
module_app_refs + app_facts graph for one app, exercises Export.

Covers:
  - TestExport_Basic         — counts per kind (kb_app, snapshots, modules,
                               module_app_refs, app_facts) match what was
                               seeded; ExportedUnderAlias=false; SnapshotIDs
                               populated; Canonical equals the seeded kb_id.
  - TestExport_LatestOnly    — LatestOnly=true returns the newest snapshot
                               only.
  - TestExport_AliasResolves — kbID that is an alias resolves to the canonical
                               id and sets ExportedUnderAlias=true.
  - TestExport_Validation    — empty kb_id rejected; unknown kb_id surfaces
                               the underlying "query kb_app" error.
*/

package store_test

import (
	"context"
	"database/sql"
	"testing"

	"github.com/inovacc/unravel-oss/pkg/knowledge/kb/dbtest"
	"github.com/inovacc/unravel-oss/pkg/knowledge/kb/store"
)

// seedSnapshot inserts a knowledge_sources row and returns its id.
func seedSnapshot(t *testing.T, db *sql.DB, kbID, ksID, app string, epoch int64) int64 {
	t.Helper()
	var id int64
	err := db.QueryRow(
		`INSERT INTO knowledge_sources (
		    app, epoch, source_path, source_kind, captured_at,
		    modules_indexed, bodies_indexed, kb_id, ks_id)
		 VALUES ($1, $2, '/tmp/seed', 'electron', 0, 0, 0, $3, $4)
		 RETURNING id`,
		app, epoch, kbID, ksID,
	).Scan(&id)
	if err != nil {
		t.Fatalf("seed snapshot ks_id=%s: %v", ksID, err)
	}
	return id
}

// seedModuleWithRef inserts a modules row and a module_app_refs row
// pointing at sourceID.
func seedModuleWithRef(t *testing.T, db *sql.DB, modID int64, app, name string, sourceID int64) {
	t.Helper()
	body := padSHA(modID)
	if _, err := db.Exec(
		`INSERT INTO modules (id, app, name, body_size, body_sha256, summary)
		 VALUES ($1, $2, $3, 0, $4, 'enriched')`,
		modID, app, name, body,
	); err != nil {
		t.Fatalf("seed module id=%d: %v", modID, err)
	}
	if _, err := db.Exec(
		`INSERT INTO module_app_refs (module_id, body_sha256, app, source_id, observed_at)
		 VALUES ($1, $2, $3, $4, 0)`,
		modID, body, app, sourceID,
	); err != nil {
		t.Fatalf("seed module_app_ref module_id=%d: %v", modID, err)
	}
}

// seedAlias inserts a kb_aliases row.
func seedAlias(t *testing.T, db *sql.DB, alias, canonical string) {
	t.Helper()
	_, err := db.Exec(
		`INSERT INTO kb_aliases (alias_kb_id, canonical_kb_id, merged_at, merged_by, reason)
		 VALUES ($1, $2, 0, 'test', 'test merge')`,
		alias, canonical,
	)
	if err != nil {
		t.Fatalf("seed alias %s->%s: %v", alias, canonical, err)
	}
}

func TestExport_Basic(t *testing.T) {
	db, _ := dbtest.StartPostgres(t)
	ctx := context.Background()

	const kbID = "kbexp000000000001"
	const app = "appExp"
	seedKBApp(t, db, kbID, app, "App Export", "electron")
	s1 := seedSnapshot(t, db, kbID, "ks0001", app, 1)
	s2 := seedSnapshot(t, db, kbID, "ks0002", app, 2)
	seedModuleWithRef(t, db, 101, app, "alpha", s1)
	seedModuleWithRef(t, db, 102, app, "beta", s2)
	seedAppFact(t, db, app, "permissions", "screen-capture", "yes")

	out, err := store.Export(ctx, db, kbID, store.ExportOptions{})
	if err != nil {
		t.Fatalf("Export: %v", err)
	}
	if out.SchemaVersion != store.ExportSchemaVersion {
		t.Errorf("schema_version = %d, want %d", out.SchemaVersion, store.ExportSchemaVersion)
	}
	if out.ExportedUnderAlias {
		t.Error("exported_under_alias = true, want false")
	}
	if out.Canonical != kbID {
		t.Errorf("canonical = %q, want %q", out.Canonical, kbID)
	}
	if out.KBApp == nil || out.KBApp.KBID != kbID {
		t.Fatalf("kb_app = %+v, want kb_id=%s", out.KBApp, kbID)
	}
	if got := len(out.Snapshots); got != 2 {
		t.Errorf("snapshots = %d, want 2", got)
	}
	if got := len(out.SnapshotIDs); got != 2 {
		t.Errorf("snapshot_ids = %d, want 2", got)
	}
	if got := len(out.Modules); got != 2 {
		t.Errorf("modules = %d, want 2", got)
	}
	if got := len(out.ModuleAppRefs); got != 2 {
		t.Errorf("module_app_refs = %d, want 2", got)
	}
	if got := len(out.AppFacts); got != 1 {
		t.Errorf("app_facts = %d, want 1", got)
	}
}

func TestExport_LatestOnly(t *testing.T) {
	db, _ := dbtest.StartPostgres(t)
	ctx := context.Background()

	const kbID = "kbexplatest00001"
	const app = "appLatest"
	seedKBApp(t, db, kbID, app, "App Latest", "electron")
	_ = seedSnapshot(t, db, kbID, "ks0001", app, 1)
	s2 := seedSnapshot(t, db, kbID, "ks0002", app, 2)

	out, err := store.Export(ctx, db, kbID, store.ExportOptions{LatestOnly: true})
	if err != nil {
		t.Fatalf("Export: %v", err)
	}
	if got := len(out.Snapshots); got != 1 {
		t.Fatalf("snapshots = %d, want 1 (latest only)", got)
	}
	if out.Snapshots[0].ID != s2 {
		t.Errorf("latest snapshot id = %d, want %d", out.Snapshots[0].ID, s2)
	}
	if out.Snapshots[0].Epoch != 2 {
		t.Errorf("latest epoch = %d, want 2", out.Snapshots[0].Epoch)
	}
}

func TestExport_AliasResolves(t *testing.T) {
	db, _ := dbtest.StartPostgres(t)
	ctx := context.Background()

	const canonical = "kbexpcanon000001"
	const alias = "kbexpalias000001"
	const app = "appAliased"
	seedKBApp(t, db, canonical, app, "App Aliased", "electron")
	seedAlias(t, db, alias, canonical)
	_ = seedSnapshot(t, db, canonical, "ks0001", app, 1)

	out, err := store.Export(ctx, db, alias, store.ExportOptions{})
	if err != nil {
		t.Fatalf("Export: %v", err)
	}
	if !out.ExportedUnderAlias {
		t.Error("exported_under_alias = false, want true")
	}
	if out.Canonical != canonical {
		t.Errorf("canonical = %q, want %q", out.Canonical, canonical)
	}
	if out.KBApp == nil || out.KBApp.KBID != canonical {
		t.Errorf("kb_app.kb_id = %v, want %s", out.KBApp, canonical)
	}
	// kb_aliases row dumped under canonical's aliases.
	if len(out.Aliases) != 1 || out.Aliases[0].AliasKBID != alias {
		t.Errorf("aliases = %+v, want one row aliasing %s", out.Aliases, alias)
	}
}

func TestExport_Validation(t *testing.T) {
	db, _ := dbtest.StartPostgres(t)
	ctx := context.Background()

	if _, err := store.Export(ctx, db, "", store.ExportOptions{}); err == nil {
		t.Error("empty kb_id: want error, got nil")
	}
	// Unknown kb_id must fail at the kb_app query step.
	if _, err := store.Export(ctx, db, "kbexpmissing0001", store.ExportOptions{}); err == nil {
		t.Error("unknown kb_id: want error, got nil")
	}
}
