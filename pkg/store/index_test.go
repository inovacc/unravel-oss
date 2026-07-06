/*
Copyright (c) 2026 Security Research
*/
package store

import (
	"os"
	"testing"
)

func TestWriteIndex_AtomicNoTempLeftover(t *testing.T) {
	s := testStore(t)

	idx := &Index{Version: IndexVersionSharded, Entries: []Entry{{ID: "x"}}}
	if err := s.writeIndex(idx); err != nil {
		t.Fatal(err)
	}

	// No temp file left behind.
	if _, err := os.Stat(s.indexPath + ".tmp"); !os.IsNotExist(err) {
		t.Error("temp index file left behind after writeIndex")
	}

	// Readable + correct.
	got, err := s.readIndex()
	if err != nil {
		t.Fatal(err)
	}
	if got.Version != IndexVersionSharded || len(got.Entries) != 1 || got.Entries[0].ID != "x" {
		t.Fatalf("round-trip mismatch: %+v", got)
	}

	// Overwriting an existing index (rename-replace) must succeed.
	idx.Entries = append(idx.Entries, Entry{ID: "y"})
	if err := s.writeIndex(idx); err != nil {
		t.Fatalf("overwrite: %v", err)
	}
	got, _ = s.readIndex()
	if len(got.Entries) != 2 {
		t.Errorf("after overwrite entries = %d, want 2", len(got.Entries))
	}
}
