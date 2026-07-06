/*
Copyright (c) 2026 Security Research
*/
package mcp

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestPruneOldest_Basic(t *testing.T) {
	dir := t.TempDir()
	// Create 5 .txt files with staggered mtimes; oldest first.
	now := time.Now()
	for i := range 5 {
		path := filepath.Join(dir, fmt.Sprintf("interaction_%02d.txt", i))
		if err := os.WriteFile(path, []byte("x"), 0o644); err != nil {
			t.Fatalf("write %d: %v", i, err)
		}
		// Older files have earlier mtimes.
		mt := now.Add(time.Duration(i) * time.Second)
		if err := os.Chtimes(path, mt, mt); err != nil {
			t.Fatalf("chtimes %d: %v", i, err)
		}
	}

	pruneOldest(dir, 3)

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("readdir: %v", err)
	}
	if len(entries) != 3 {
		t.Fatalf("after prune: got %d entries, want 3", len(entries))
	}
	// The 3 kept files should be the newest (indexes 2, 3, 4).
	names := map[string]bool{}
	for _, e := range entries {
		names[e.Name()] = true
	}
	for _, kept := range []string{"interaction_02.txt", "interaction_03.txt", "interaction_04.txt"} {
		if !names[kept] {
			t.Errorf("expected %q to be kept, missing", kept)
		}
	}
	for _, evicted := range []string{"interaction_00.txt", "interaction_01.txt"} {
		if names[evicted] {
			t.Errorf("expected %q to be evicted, still present", evicted)
		}
	}
}

func TestPruneOldest_BelowThreshold(t *testing.T) {
	dir := t.TempDir()
	for i := range 2 {
		if err := os.WriteFile(filepath.Join(dir, fmt.Sprintf("x_%d.txt", i)), []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	pruneOldest(dir, 10)
	entries, _ := os.ReadDir(dir)
	if len(entries) != 2 {
		t.Errorf("below threshold: got %d, want 2", len(entries))
	}
}

func TestPruneOldest_NonTxtIgnored(t *testing.T) {
	dir := t.TempDir()
	// 3 .txt + 2 .json — only .txt should be considered.
	for i := range 3 {
		_ = os.WriteFile(filepath.Join(dir, fmt.Sprintf("a_%d.txt", i)), []byte("x"), 0o644)
	}
	_ = os.WriteFile(filepath.Join(dir, "config.json"), []byte("{}"), 0o644)
	_ = os.WriteFile(filepath.Join(dir, "manifest.json"), []byte("{}"), 0o644)

	pruneOldest(dir, 1)

	entries, _ := os.ReadDir(dir)
	// Expect 1 .txt + 2 .json untouched = 3 total.
	if len(entries) != 3 {
		t.Errorf("non-txt ignored: got %d, want 3", len(entries))
	}
	var txtCount int
	for _, e := range entries {
		if filepath.Ext(e.Name()) == ".txt" {
			txtCount++
		}
	}
	if txtCount != 1 {
		t.Errorf(".txt count after prune to 1: got %d, want 1", txtCount)
	}
}

func TestPruneOldest_MissingDir(t *testing.T) {
	// Must not panic on a missing dir.
	pruneOldest(filepath.Join(t.TempDir(), "does-not-exist"), 5)
}
