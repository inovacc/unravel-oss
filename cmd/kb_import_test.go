/*
Copyright (c) 2026 Security Research

Unit tests for `unravel kb import` cobra subcommand — Phase 43-02 flag
wiring + error paths. Live DB integration is covered in
cmd/kb_import_roundtrip_integration_test.go.
*/
package cmd

import (
	"bytes"
	"strings"
	"testing"
)

// TestKBImport_FlagsRegistered — sanity that the flags exist on the command.
func TestKBImport_FlagsRegistered(t *testing.T) {
	for _, name := range []string{"bundle", "json", "verify-key", "allow-unsigned"} {
		if kbImportCmd.Flags().Lookup(name) == nil {
			t.Fatalf("missing flag --%s on kb import command", name)
		}
	}
}

// TestKBImport_RequiresBundleFlag — empty --bundle is rejected before any DB
// work happens (good fail-fast behavior).
func TestKBImport_RequiresBundleFlag(t *testing.T) {
	prev := kbImportFlags
	t.Cleanup(func() { kbImportFlags = prev })

	kbImportFlags = prev
	kbImportFlags.bundle = ""

	cmd := kbImportCmd
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	err := runKbImport(cmd, nil)
	if err == nil {
		t.Fatal("expected error for empty --bundle")
	}
	if !strings.Contains(err.Error(), "bundle") {
		t.Fatalf("error must mention bundle; got %v", err)
	}
}

// TestKBImport_BundlePathMustExist — a non-existent --bundle path errors out
// before opening the DB.
func TestKBImport_BundlePathMustExist(t *testing.T) {
	prev := kbImportFlags
	t.Cleanup(func() { kbImportFlags = prev })

	kbImportFlags = prev
	kbImportFlags.bundle = "/path/that/definitely/does/not/exist/bundle.kbb.tar.gz"

	cmd := kbImportCmd
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	err := runKbImport(cmd, nil)
	if err == nil {
		t.Fatal("expected error for non-existent bundle path")
	}
}
