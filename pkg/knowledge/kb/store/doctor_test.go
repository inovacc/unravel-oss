//go:build integration

/*
Copyright (c) 2026 Security Research

Integration tests for kbstore.Doctor. Boots a transient Postgres via
dbtest.StartPostgres, then exercises the connectivity + catalog
probes.
*/

package store_test

import (
	"context"
	"testing"

	"github.com/inovacc/unravel-oss/pkg/knowledge/kb/dbtest"
	"github.com/inovacc/unravel-oss/pkg/knowledge/kb/store"
)

func TestDoctor_EmptyCatalog(t *testing.T) {
	db, _ := dbtest.StartPostgres(t)
	ctx := context.Background()

	rep, err := store.Doctor(ctx, db, store.DoctorOptions{})
	if err != nil {
		t.Fatalf("Doctor: %v", err)
	}
	if rep == nil {
		t.Fatal("report nil, want non-nil")
	}
	if !rep.DBOpen {
		t.Errorf("db_open = false, want true; ping_error=%q", rep.PingError)
	}
	if rep.Catalog.SummaryErr != "" {
		t.Errorf("summary_error = %q, want empty", rep.Catalog.SummaryErr)
	}
	if !rep.OK {
		t.Errorf("ok = false, want true (empty catalog still healthy)")
	}
}

func TestDoctor_WithApps(t *testing.T) {
	db, _ := dbtest.StartPostgres(t)
	ctx := context.Background()

	seedKBAppRow(t, db, "kbdoc00000000001", "windows", "electron", nil, 1000)
	seedKBAppRow(t, db, "kbdoc00000000002", "android", "tauri", nil, 2000)

	rep, err := store.Doctor(ctx, db, store.DoctorOptions{App: "kbdoc00000000001"})
	if err != nil {
		t.Fatalf("Doctor: %v", err)
	}
	if rep.Catalog.Apps < 2 {
		t.Errorf("catalog.apps = %d, want >= 2", rep.Catalog.Apps)
	}
	if rep.App != "kbdoc00000000001" {
		t.Errorf("app = %q, want kbdoc00000000001", rep.App)
	}
}

func TestDoctor_NilApp_NoError(t *testing.T) {
	db, _ := dbtest.StartPostgres(t)
	ctx := context.Background()

	if _, err := store.Doctor(ctx, db, store.DoctorOptions{}); err != nil {
		t.Errorf("Doctor with empty App: unexpected err: %v", err)
	}
}

func TestDoctor_Validation(t *testing.T) {
	ctx := context.Background()
	if _, err := store.Doctor(ctx, nil, store.DoctorOptions{}); err == nil {
		t.Error("expected error for nil db")
	}
}
