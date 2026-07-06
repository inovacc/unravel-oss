/*
Copyright (c) 2026 Security Research
*/
package store

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestReconcile_MigratesFlatAndGCsOrphans(t *testing.T) {
	s := testStore(t)

	// Fabricate a legacy flat, Version-1 cache: one indexed flat entry +
	// one flat orphan, with an index that lists only the indexed one.
	indexedID := newUUIDv7()
	indexedDir := filepath.Join(s.baseDir, indexedID)
	if err := os.MkdirAll(indexedDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(indexedDir, "result.json"), []byte("payload-123"), 0o644); err != nil {
		t.Fatal(err)
	}

	orphanID := newUUIDv7()
	orphanDir := filepath.Join(s.baseDir, orphanID)
	if err := os.MkdirAll(orphanDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(orphanDir, "result.json"), []byte("orphan"), 0o644); err != nil {
		t.Fatal(err)
	}

	idx := &Index{Version: 1, Entries: []Entry{{
		ID:        indexedID,
		Type:      "dissect",
		CreatedAt: time.Now().UTC(),
		CacheDir:  indexedDir, // flat
		Size:      0,          // pre-Size field
	}}}
	if err := s.writeIndex(idx); err != nil {
		t.Fatal(err)
	}

	// grace=0 so the just-created flat orphan is eligible for GC in the test.
	rep, err := s.reconcileWithGrace(0, false)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Migrated != 1 {
		t.Errorf("Migrated = %d, want 1", rep.Migrated)
	}
	if rep.SizeBackfilled != 1 {
		t.Errorf("SizeBackfilled = %d, want 1", rep.SizeBackfilled)
	}
	if rep.OrphansGC != 1 {
		t.Errorf("OrphansGC = %d, want 1", rep.OrphansGC)
	}

	got, _ := s.readIndex()
	if got.Version != IndexVersionSharded {
		t.Errorf("version = %d, want %d", got.Version, IndexVersionSharded)
	}
	e := got.Entries[0]
	wantDir := filepath.Join(s.baseDir, shardFor(indexedID), indexedID)
	if e.CacheDir != wantDir {
		t.Errorf("CacheDir = %q, want %q", e.CacheDir, wantDir)
	}
	if e.Size != int64(len("payload-123")) {
		t.Errorf("Size = %d, want %d", e.Size, len("payload-123"))
	}
	if _, err := os.Stat(filepath.Join(wantDir, "result.json")); err != nil {
		t.Error("payload not present at sharded path")
	}
	if _, err := os.Stat(indexedDir); !os.IsNotExist(err) {
		t.Error("old flat dir still present after migration")
	}
	if _, err := os.Stat(orphanDir); !os.IsNotExist(err) {
		t.Error("orphan not GC'd")
	}

	// Idempotent: a second run changes nothing.
	rep2, err := s.reconcileWithGrace(0, false)
	if err != nil {
		t.Fatal(err)
	}
	if rep2.Migrated != 0 || rep2.OrphansGC != 0 {
		t.Errorf("second run not a no-op: %+v", rep2)
	}
}
