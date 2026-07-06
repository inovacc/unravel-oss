//go:build integration

/*
Copyright (c) 2026 Security Research

Integration tests for kbstore.DiffApps. Boots a transient Postgres via
dbtest.StartPostgres, seeds enriched modules across two apps with
overlapping and disjoint names, exercises DiffApps.

Covers:
  - TestDiffApps_OverlapAndUnique — only_in_a / only_in_b / common counts.
  - TestDiffApps_CategoryFilter   — tags ILIKE narrows each side.
  - TestDiffApps_Validation       — empty / equal app names rejected.
*/

package store_test

import (
	"context"
	"database/sql"
	"testing"

	"github.com/inovacc/unravel-oss/pkg/knowledge/kb/dbtest"
	"github.com/inovacc/unravel-oss/pkg/knowledge/kb/store"
)

// seedModule inserts an enriched (summary IS NOT NULL) module row.
func seedModule(t *testing.T, db *sql.DB, id int64, app, name, tags string) {
	t.Helper()
	_, err := db.Exec(
		`INSERT INTO modules (id, app, name, body_size, body_sha256, summary, tags)
		 VALUES ($1, $2, $3, 0, $4, 'enriched', NULLIF($5,''))`,
		id, app, name, padSHA(id), tags,
	)
	if err != nil {
		t.Fatalf("seed module id=%d: %v", id, err)
	}
}

// seedUnenriched inserts a module with NULL summary (should be ignored
// by DiffApps).
func seedUnenriched(t *testing.T, db *sql.DB, id int64, app, name string) {
	t.Helper()
	_, err := db.Exec(
		`INSERT INTO modules (id, app, name, body_size, body_sha256)
		 VALUES ($1, $2, $3, 0, $4)`,
		id, app, name, padSHA(id),
	)
	if err != nil {
		t.Fatalf("seed unenriched id=%d: %v", id, err)
	}
}

// padSHA returns a deterministic 64-char hex string derived from id.
func padSHA(id int64) string {
	out := []byte("0000000000000000000000000000000000000000000000000000000000000000")
	hexCh := []byte("0123456789abcdef")
	for k := 0; k < 16; k++ {
		out[63-k] = hexCh[(id>>(4*k))&0xF]
	}
	return string(out)
}

func TestDiffApps_OverlapAndUnique(t *testing.T) {
	db, _ := dbtest.StartPostgres(t)
	ctx := context.Background()

	// App A: alpha, beta, gamma (gamma shared, others unique)
	seedModule(t, db, 1, "appA", "alpha", "crypto")
	seedModule(t, db, 2, "appA", "beta", "network")
	seedModule(t, db, 3, "appA", "gamma", "crypto")
	// App B: gamma, delta, epsilon (gamma shared)
	seedModule(t, db, 4, "appB", "gamma", "crypto")
	seedModule(t, db, 5, "appB", "delta", "network")
	seedModule(t, db, 6, "appB", "epsilon", "")
	// Noise: unenriched module — must NOT participate.
	seedUnenriched(t, db, 7, "appA", "ghost")

	res, err := store.DiffApps(ctx, db, "appA", "appB", store.DiffAppsOptions{})
	if err != nil {
		t.Fatalf("DiffApps: %v", err)
	}
	if res.AOnlyCount != 2 {
		t.Errorf("a_only_count = %d, want 2", res.AOnlyCount)
	}
	if res.BOnlyCount != 2 {
		t.Errorf("b_only_count = %d, want 2", res.BOnlyCount)
	}
	if res.CommonCount != 1 {
		t.Errorf("common_count = %d, want 1", res.CommonCount)
	}
	// Verify names — appA unique should be alpha + beta.
	gotA := map[string]bool{}
	for _, m := range res.AOnly {
		gotA[m.Name] = true
	}
	if !gotA["alpha"] || !gotA["beta"] || gotA["gamma"] || gotA["ghost"] {
		t.Errorf("a_only names = %v, want {alpha, beta}", gotA)
	}
	if res.AppA != "appA" || res.AppB != "appB" {
		t.Errorf("app_a/app_b = %q/%q, want appA/appB", res.AppA, res.AppB)
	}
}

func TestDiffApps_CategoryFilter(t *testing.T) {
	db, _ := dbtest.StartPostgres(t)
	ctx := context.Background()

	seedModule(t, db, 10, "x", "x_crypto_only", "crypto")
	seedModule(t, db, 11, "x", "x_net_only", "network")
	seedModule(t, db, 12, "y", "y_crypto_only", "crypto")
	seedModule(t, db, 13, "y", "y_net_only", "network")

	res, err := store.DiffApps(ctx, db, "x", "y", store.DiffAppsOptions{Category: "crypto"})
	if err != nil {
		t.Fatalf("DiffApps: %v", err)
	}
	if res.AOnlyCount != 1 || res.AOnly[0].Name != "x_crypto_only" {
		t.Errorf("a_only = %+v, want [x_crypto_only]", res.AOnly)
	}
	if res.BOnlyCount != 1 || res.BOnly[0].Name != "y_crypto_only" {
		t.Errorf("b_only = %+v, want [y_crypto_only]", res.BOnly)
	}
	if res.CommonCount != 0 {
		t.Errorf("common_count = %d, want 0", res.CommonCount)
	}
	if res.Category != "crypto" {
		t.Errorf("category = %q, want crypto", res.Category)
	}
}

func TestDiffApps_Validation(t *testing.T) {
	db, _ := dbtest.StartPostgres(t)
	ctx := context.Background()

	if _, err := store.DiffApps(ctx, db, "", "b", store.DiffAppsOptions{}); err == nil {
		t.Error("empty app_a: want error, got nil")
	}
	if _, err := store.DiffApps(ctx, db, "a", "", store.DiffAppsOptions{}); err == nil {
		t.Error("empty app_b: want error, got nil")
	}
	if _, err := store.DiffApps(ctx, db, "same", "same", store.DiffAppsOptions{}); err == nil {
		t.Error("equal app names: want error, got nil")
	}
}
