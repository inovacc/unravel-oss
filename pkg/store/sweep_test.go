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

func TestUUIDv7Helpers(t *testing.T) {
	id := newUUIDv7()
	if !isUUIDv7(id) {
		t.Fatalf("newUUIDv7 output %q not recognized as uuidv7", id)
	}

	ts, ok := uuidv7Time(id)
	if !ok {
		t.Fatal("uuidv7Time !ok for a valid id")
	}
	if d := time.Since(ts); d < 0 || d > time.Minute {
		t.Errorf("embedded time off from now by %v", d)
	}

	bad := []string{
		"a3",         // shard bucket
		"cache.json", // index file name
		"not-a-uuid",
		"",
		"019e3ce1-9a23-1c1c-b16a-79c4b0180000", // version nibble 1, not 7
		"019E3CE1-9A23-7C1C-B16A-79C4B0180000", // uppercase (we only emit lowercase)
	}
	for _, b := range bad {
		if isUUIDv7(b) {
			t.Errorf("isUUIDv7(%q) = true, want false", b)
		}
		if _, ok := uuidv7Time(b); ok {
			t.Errorf("uuidv7Time(%q) ok = true, want false", b)
		}
	}
}

// seedOrphan creates a uuidv7-named entry dir (sharded if shard != "", else
// legacy flat) with one payload file, and returns its path. Used by the
// gcOrphans tests in Task 5.
func seedOrphan(t *testing.T, base, shard string) string {
	t.Helper()
	id := newUUIDv7()
	var dir string
	if shard != "" {
		dir = filepath.Join(base, shard, id)
	} else {
		dir = filepath.Join(base, id)
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "result.json"), []byte("orphan"), 0o644); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestGCOrphans_RemovesUntrackedKeepsTracked(t *testing.T) {
	s := testStore(t)

	// One tracked entry via Put (sharded, indexed).
	src := writeSourceFile(t, "x")
	kept, err := s.Put(src, "dissect", nil, map[string][]byte{"r": []byte("data")})
	if err != nil {
		t.Fatal(err)
	}

	// Two orphans (flat + sharded) and one non-uuid dir that must be untouched.
	flatOrphan := seedOrphan(t, s.baseDir, "")
	shardOrphan := seedOrphan(t, s.baseDir, "zz")
	nonUUID := filepath.Join(s.baseDir, "ab", "not-a-uuid")
	if err := os.MkdirAll(nonUUID, 0o755); err != nil {
		t.Fatal(err)
	}

	// grace=0 → uuid orphans (embedded time slightly before now) are eligible.
	removed, _, err := s.gcOrphans(0, false)
	if err != nil {
		t.Fatal(err)
	}
	if removed != 2 {
		t.Errorf("removed = %d, want 2", removed)
	}
	if _, err := os.Stat(flatOrphan); !os.IsNotExist(err) {
		t.Error("flat orphan not removed")
	}
	if _, err := os.Stat(shardOrphan); !os.IsNotExist(err) {
		t.Error("shard orphan not removed")
	}
	if _, err := os.Stat(kept.CacheDir); err != nil {
		t.Error("indexed entry was wrongly removed")
	}
	if _, err := os.Stat(nonUUID); err != nil {
		t.Error("non-uuid dir was wrongly removed")
	}
}

func TestGCOrphans_GraceProtectsYoung(t *testing.T) {
	s := testStore(t)
	dir := seedOrphan(t, s.baseDir, "zz")

	removed, _, _ := s.gcOrphans(time.Hour, false) // young (≈now) within 1h grace
	if removed != 0 {
		t.Errorf("removed = %d young orphans, want 0", removed)
	}
	if _, err := os.Stat(dir); err != nil {
		t.Error("young orphan wrongly removed")
	}
}

func TestGCOrphans_RefusesOnCorruptIndex(t *testing.T) {
	s := testStore(t)

	// A real indexed entry so the cache dir + index both exist.
	src := writeSourceFile(t, "x")
	kept, err := s.Put(src, "dissect", nil, map[string][]byte{"r": []byte("data")})
	if err != nil {
		t.Fatal(err)
	}

	// Corrupt the index on disk.
	if err := os.WriteFile(s.indexPath, []byte("{invalid json"), 0o644); err != nil {
		t.Fatal(err)
	}

	// gcOrphans must REFUSE (error) and delete nothing — treating a corrupt
	// index as empty would classify the real entry as an orphan and wipe it.
	removed, _, gcErr := s.gcOrphans(0, false)
	if gcErr == nil {
		t.Fatal("gcOrphans on a corrupt index returned nil error; want refusal")
	}
	if removed != 0 {
		t.Errorf("gcOrphans removed %d dirs on a corrupt index; want 0", removed)
	}
	if _, err := os.Stat(kept.CacheDir); err != nil {
		t.Error("indexed entry deleted despite corrupt-index refusal")
	}
}

func TestGCOrphans_DryRun(t *testing.T) {
	s := testStore(t)
	dir := seedOrphan(t, s.baseDir, "zz")

	removed, _, _ := s.gcOrphans(0, true)
	if removed != 1 {
		t.Errorf("dry-run count = %d, want 1", removed)
	}
	if _, err := os.Stat(dir); err != nil {
		t.Error("dry-run deleted a dir")
	}
}
