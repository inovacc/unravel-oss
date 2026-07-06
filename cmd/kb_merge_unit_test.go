/*
Copyright (c) 2026 Security Research
*/

package cmd

import (
	"bytes"
	"path/filepath"
	"strings"
	"testing"
)

// TestKbMerge_MissingConfig exercises the missing-config guard. With config-only
// DSN resolution, the error must surface ErrConfigNotFound's user-facing
// remediation hint pointing at `unravel db setup`.
func TestKbMerge_MissingConfig(t *testing.T) {
	// Point UNRAVEL_CONFIG at a non-existent path so config.Load returns
	// ErrConfigNotFound deterministically without touching the user's real
	// config.yaml.
	t.Setenv("UNRAVEL_CONFIG", filepath.Join(t.TempDir(), "missing.yaml"))

	// Reset package globals — other tests in this package share them.
	kbMergeBy = ""
	kbMergeReason = ""

	var stdout, stderr bytes.Buffer
	rootCmd.SetOut(&stdout)
	rootCmd.SetErr(&stderr)
	rootCmd.SetArgs([]string{"kb", "ops", "merge", "loser-id", "winner-id"})

	err := rootCmd.Execute()
	if err == nil {
		t.Fatalf("expected error, got nil; stdout=%q stderr=%q", stdout.String(), stderr.String())
	}
	if !strings.Contains(err.Error(), "unravel db setup") {
		t.Fatalf("unexpected error: %v", err)
	}
}
