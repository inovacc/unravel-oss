//go:build integration

/*
Copyright (c) 2026 Security Research

Integration tests for kbstore.Apps. Boots a transient Postgres via
dbtest.StartPostgres, seeds a kb_apps row + knowledge_sources epoch,
then exercises Apps end-to-end.
*/

package store_test

import (
	"context"
	"database/sql"
	"testing"

	"github.com/inovacc/unravel-oss/pkg/knowledge/kb/dbtest"
	"github.com/inovacc/unravel-oss/pkg/knowledge/kb/store"
)

func seedKBAppRow(t *testing.T, db *sql.DB, kbID, platform, framework string, tags []string, lastSeen int64) {
	t.Helper()
	_, err := db.Exec(
		`INSERT INTO kb_apps (kb_id, canonical_name, display_name, platform, framework,
		                       app_count, source_count, aliases, metadata, tags, last_seen_at)
		 VALUES ($1, $1, $1, $2, $3, 0, 0, ARRAY[]::text[], '{}'::jsonb, $4, $5)
		 ON CONFLICT DO NOTHING`,
		kbID, platform, framework, tags, lastSeen,
	)
	if err != nil {
		t.Fatalf("seed kb_app %q: %v", kbID, err)
	}
}

func TestApps_Basic(t *testing.T) {
	db, _ := dbtest.StartPostgres(t)
	ctx := context.Background()

	seedKBAppRow(t, db, "kbapps0000000001", "windows", "electron", []string{"stealth"}, 1000)
	seedKBAppRow(t, db, "kbapps0000000002", "android", "react-native", []string{"telemetry"}, 2000)

	out, err := store.Apps(ctx, db, store.AppsOptions{})
	if err != nil {
		t.Fatalf("Apps: %v", err)
	}
	if out.Returned != 2 {
		t.Errorf("returned = %d, want 2", out.Returned)
	}
	if len(out.Items) != 2 {
		t.Fatalf("items len = %d, want 2", len(out.Items))
	}
	// Ordered DESC by last_seen_at — kbID#2 (2000) precedes kbID#1 (1000).
	if out.Items[0].KBID != "kbapps0000000002" {
		t.Errorf("first kb_id = %q, want kbapps0000000002", out.Items[0].KBID)
	}
}

func TestApps_PlatformFilter(t *testing.T) {
	db, _ := dbtest.StartPostgres(t)
	ctx := context.Background()

	seedKBAppRow(t, db, "kbapps0000000003", "windows", "electron", nil, 1000)
	seedKBAppRow(t, db, "kbapps0000000004", "android", "tauri", nil, 2000)

	out, err := store.Apps(ctx, db, store.AppsOptions{Platform: "android"})
	if err != nil {
		t.Fatalf("Apps: %v", err)
	}
	if out.Returned != 1 {
		t.Fatalf("returned = %d, want 1", out.Returned)
	}
	if out.Items[0].Platform != "android" {
		t.Errorf("platform = %q, want android", out.Items[0].Platform)
	}
}

func TestApps_Validation(t *testing.T) {
	ctx := context.Background()
	if _, err := store.Apps(ctx, nil, store.AppsOptions{}); err == nil {
		t.Error("expected error for nil db")
	}
}

func TestApps_Empty(t *testing.T) {
	db, _ := dbtest.StartPostgres(t)
	ctx := context.Background()

	out, err := store.Apps(ctx, db, store.AppsOptions{})
	if err != nil {
		t.Fatalf("Apps: %v", err)
	}
	if out == nil {
		t.Fatal("payload nil, want non-nil")
	}
	if out.Returned != 0 {
		t.Errorf("returned = %d, want 0", out.Returned)
	}
}
