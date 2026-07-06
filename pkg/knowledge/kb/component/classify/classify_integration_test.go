//go:build integration

/*
Copyright (c) 2026 Security Research

Integration tests for classify.Run against a real Postgres testcontainer.
Proves UPSERT semantics, manual-override preservation, latest-epoch
resolution, and explicit-epoch filtering against the live schema.
*/

package classify_test

import (
	"context"
	"database/sql"
	"testing"

	"github.com/inovacc/unravel-oss/pkg/knowledge/kb/component/classify"
	_ "github.com/inovacc/unravel-oss/pkg/knowledge/kb/component/runtime" // populate rule registry
	"github.com/inovacc/unravel-oss/pkg/knowledge/kb/dbtest"
)

const ksRowSQL = `INSERT INTO knowledge_sources
  (app, kb_id, epoch, source_path, source_kind, captured_at)
  VALUES ($1, $2, $3, $4, 'other', 1) RETURNING id`

const moduleRowSQL = `INSERT INTO modules
  (app, name, body_size, body_excerpt, body_sha256, symbols_json, first_source_id)
  VALUES ($1, $2, 1, $3, $4, $5, $6) RETURNING id`

const bodySQL = `INSERT INTO module_bodies (body_sha256, body, body_size, stored_at)
  VALUES ($1, '\x00', 1, 0) ON CONFLICT (body_sha256) DO NOTHING`

const kbAppSQL = `INSERT INTO kb_apps
  (kb_id, canonical_name, display_name, platform, first_seen_at, last_seen_at)
  VALUES ($1, 'name', 'Name', 'windows-msix', 1, 1)`

func seedKBApp(t *testing.T, db *sql.DB, kbID string) {
	t.Helper()
	if _, err := db.Exec(kbAppSQL, kbID); err != nil {
		t.Fatalf("seed kb_apps: %v", err)
	}
}

func seedSource(t *testing.T, db *sql.DB, app, kbID string, epoch int) int64 {
	t.Helper()
	var id int64
	if err := db.QueryRow(ksRowSQL, app, kbID, epoch, "/x").Scan(&id); err != nil {
		t.Fatalf("seed knowledge_sources: %v", err)
	}
	return id
}

func seedModule(t *testing.T, db *sql.DB, app, name, sha, symbols string, sourceID int64) int64 {
	t.Helper()
	if _, err := db.Exec(bodySQL, sha); err != nil {
		t.Fatalf("seed module_bodies: %v", err)
	}
	var id int64
	if err := db.QueryRow(moduleRowSQL, app, name, "", sha, symbols, sourceID).Scan(&id); err != nil {
		t.Fatalf("seed modules: %v", err)
	}
	return id
}

// TestRun_HappyPath_LatestEpoch seeds three modules across one source and
// asserts each lands in the right bucket via the rule registry. Names use
// strings that the auth/crypto rule packages match on.
func TestRun_HappyPath_LatestEpoch(t *testing.T) {
	db, _ := dbtest.StartPostgres(t)
	ctx := context.Background()
	const kb = "k1"
	seedKBApp(t, db, kb)
	src := seedSource(t, db, "app", kb, 1)
	authID := seedModule(t, db, "app", "AuthService", "h-auth",
		`{"oauth":1,"jwt":1,"refresh_token":1}`, src)
	cryptoID := seedModule(t, db, "app", "AesGcmCipher", "h-crypto",
		`{"AesGcm":1,"sha256":1}`, src)
	otherID := seedModule(t, db, "app", "Foo", "h-other", `{"bar":1}`, src)

	rep, err := classify.Run(ctx, db, kb, 0)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if rep.Epoch != 1 || rep.ModulesClassified != 3 {
		t.Fatalf("rep=%+v want epoch=1 classified=3", rep)
	}

	rows, err := db.Query(`SELECT module_id, component, classifier FROM module_components`)
	if err != nil {
		t.Fatalf("read module_components: %v", err)
	}
	defer rows.Close()
	got := map[int64]string{}
	for rows.Next() {
		var id int64
		var comp, classifier string
		if err := rows.Scan(&id, &comp, &classifier); err != nil {
			t.Fatalf("scan: %v", err)
		}
		if classifier != "rule" {
			t.Fatalf("module %d classifier=%s want rule", id, classifier)
		}
		got[id] = comp
	}
	if len(got) != 3 {
		t.Fatalf("want 3 module_components rows, got %d (%v)", len(got), got)
	}
	if got[authID] != "auth" {
		t.Errorf("auth module bucket=%s want auth", got[authID])
	}
	if got[cryptoID] != "crypto" {
		t.Errorf("crypto module bucket=%s want crypto", got[cryptoID])
	}
	if got[otherID] != "other" {
		t.Errorf("other module bucket=%s want other", got[otherID])
	}
}

// TestRun_PreservesManualOverride seeds modules, runs classify once, then
// flips one row to classifier='manual' and re-runs. The manual row's
// component must NOT be overwritten.
func TestRun_PreservesManualOverride(t *testing.T) {
	db, _ := dbtest.StartPostgres(t)
	ctx := context.Background()
	const kb = "kmanual"
	seedKBApp(t, db, kb)
	src := seedSource(t, db, "app", kb, 1)
	authID := seedModule(t, db, "app", "AuthService", "h-auth",
		`{"oauth":1,"jwt":1}`, src)
	cryptoID := seedModule(t, db, "app", "AesGcmCipher", "h-crypto",
		`{"AesGcm":1}`, src)

	if _, err := classify.Run(ctx, db, kb, 0); err != nil {
		t.Fatalf("first Run: %v", err)
	}
	if _, err := db.Exec(
		`UPDATE module_components SET classifier='manual', component='security'
		 WHERE module_id = $1`, authID); err != nil {
		t.Fatalf("flip to manual: %v", err)
	}

	if _, err := classify.Run(ctx, db, kb, 0); err != nil {
		t.Fatalf("second Run: %v", err)
	}

	var comp, classifier string
	if err := db.QueryRow(
		`SELECT component, classifier FROM module_components WHERE module_id = $1`,
		authID).Scan(&comp, &classifier); err != nil {
		t.Fatalf("read auth row: %v", err)
	}
	if classifier != "manual" || comp != "security" {
		t.Fatalf("manual override NOT preserved: comp=%s classifier=%s", comp, classifier)
	}

	if err := db.QueryRow(
		`SELECT component, classifier FROM module_components WHERE module_id = $1`,
		cryptoID).Scan(&comp, &classifier); err != nil {
		t.Fatalf("read crypto row: %v", err)
	}
	if classifier != "rule" || comp != "crypto" {
		t.Fatalf("rule row not refreshed: comp=%s classifier=%s", comp, classifier)
	}
}

// TestRun_EmptyKB_NoEpoch asserts that classifying a kb_id with zero
// knowledge_sources rows returns Report{ModulesClassified:0} and nil err.
func TestRun_EmptyKB_NoEpoch(t *testing.T) {
	db, _ := dbtest.StartPostgres(t)
	ctx := context.Background()
	seedKBApp(t, db, "k_empty")

	rep, err := classify.Run(ctx, db, "k_empty", 0)
	if err != nil {
		t.Fatalf("Run on empty kb: %v", err)
	}
	if rep == nil || rep.ModulesClassified != 0 {
		t.Fatalf("want empty Report, got %+v", rep)
	}
}

// TestRun_ExplicitEpoch seeds two epochs with disjoint module sets and
// asserts that explicit epoch=1 only classifies epoch-1 modules.
func TestRun_ExplicitEpoch(t *testing.T) {
	db, _ := dbtest.StartPostgres(t)
	ctx := context.Background()
	const kb = "kep"
	seedKBApp(t, db, kb)
	src1 := seedSource(t, db, "app", kb, 1)
	src2 := seedSource(t, db, "app", kb, 2)
	id1 := seedModule(t, db, "app", "AuthService", "h-e1",
		`{"oauth":1,"jwt":1}`, src1)
	_ = seedModule(t, db, "app", "AesGcmCipher", "h-e2",
		`{"AesGcm":1}`, src2)

	rep, err := classify.Run(ctx, db, kb, 1)
	if err != nil {
		t.Fatalf("Run epoch=1: %v", err)
	}
	if rep.ModulesClassified != 1 || rep.Epoch != 1 {
		t.Fatalf("rep=%+v want classified=1 epoch=1", rep)
	}

	var n int
	if err := db.QueryRow(`SELECT COUNT(*) FROM module_components WHERE module_id = $1`, id1).Scan(&n); err != nil {
		t.Fatalf("count: %v", err)
	}
	if n != 1 {
		t.Fatalf("epoch-1 module not classified, got n=%d", n)
	}
	if err := db.QueryRow(`SELECT COUNT(*) FROM module_components`).Scan(&n); err != nil {
		t.Fatalf("count all: %v", err)
	}
	if n != 1 {
		t.Fatalf("epoch-2 module leaked into module_components, got n=%d", n)
	}
}
