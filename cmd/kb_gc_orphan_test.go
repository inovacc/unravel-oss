/*
Copyright (c) 2026 Security Research

Tests for `unravel kb gc` orphan-cleanup modes (Phase 34 Plan 03).

  * TestGC_OrphanFlagMutex — unit test (no DB) asserting the three orphan
    modes are mutually exclusive and cannot be combined with the
    snapshot-purge filters.
  * TestGC_OrphanBodies / TestGC_OrphanFiles / TestGC_OrphanFolders —
    integration-tagged; live behind `//go:build integration` in
    kb_gc_orphan_integration_test.go.
*/

package cmd

import (
	"strings"
	"testing"
)

// resetGCFlags returns a function that restores all gc* package-level
// flag vars to zero values. Call as `defer resetGCFlags()()` so test
// state never bleeds across cases.
func resetGCFlags() func() {
	prevOlderThan := gcOlderThan
	prevKeepLatest := gcKeepLatest
	prevAll := gcAll
	prevDryRun := gcDryRun
	prevYes := gcYes
	prevJSON := gcJSON
	prevDSN := gcDSN
	prevOrphanFolders := gcOrphanFolders
	prevOrphanBodies := gcOrphanBodies
	prevOrphanFiles := gcOrphanFiles
	return func() {
		gcOlderThan = prevOlderThan
		gcKeepLatest = prevKeepLatest
		gcAll = prevAll
		gcDryRun = prevDryRun
		gcYes = prevYes
		gcJSON = prevJSON
		gcDSN = prevDSN
		gcOrphanFolders = prevOrphanFolders
		gcOrphanBodies = prevOrphanBodies
		gcOrphanFiles = prevOrphanFiles
	}
}

func TestGC_OrphanFlagMutex(t *testing.T) {
	t.Run("two orphan modes rejected", func(t *testing.T) {
		defer resetGCFlags()()
		gcOrphanFolders = true
		gcOrphanBodies = true

		err := runKbGC(gcCmd, nil)
		if err == nil {
			t.Fatal("expected error for two orphan modes set, got nil")
		}
		if !strings.Contains(err.Error(), "mutually exclusive") {
			t.Errorf("expected 'mutually exclusive' in err, got: %v", err)
		}
	})

	t.Run("orphan + older-than rejected", func(t *testing.T) {
		defer resetGCFlags()()
		gcOrphanFolders = true
		gcOlderThan = "30d"

		err := runKbGC(gcCmd, nil)
		if err == nil {
			t.Fatal("expected error for orphan + older-than, got nil")
		}
		if !strings.Contains(err.Error(), "cannot be combined") {
			t.Errorf("expected 'cannot be combined' in err, got: %v", err)
		}
	})

	t.Run("orphan + keep-latest rejected", func(t *testing.T) {
		defer resetGCFlags()()
		gcOrphanBodies = true
		gcKeepLatest = 5

		err := runKbGC(gcCmd, nil)
		if err == nil {
			t.Fatal("expected error for orphan + keep-latest, got nil")
		}
		if !strings.Contains(err.Error(), "cannot be combined") {
			t.Errorf("expected 'cannot be combined' in err, got: %v", err)
		}
	})

	t.Run("three orphan modes rejected", func(t *testing.T) {
		defer resetGCFlags()()
		gcOrphanFolders = true
		gcOrphanBodies = true
		gcOrphanFiles = true

		err := runKbGC(gcCmd, nil)
		if err == nil {
			t.Fatal("expected error for three orphan modes, got nil")
		}
		if !strings.Contains(err.Error(), "mutually exclusive") {
			t.Errorf("expected 'mutually exclusive' in err, got: %v", err)
		}
	})
}
