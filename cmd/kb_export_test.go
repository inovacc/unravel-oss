/*
Copyright (c) 2026 Security Research

Unit tests for `unravel kb export` cobra subcommand — Phase 43 bundle mode
flag wiring + error paths. Live DB integration is covered separately.
*/
package cmd

import (
	"bytes"
	"context"
	"strings"
	"testing"
)

// TestKBExport_BundleRequiresKbID — bundle mode rejects missing --kb-id.
func TestKBExport_BundleRequiresKbID(t *testing.T) {
	prev := kbExportFlags
	t.Cleanup(func() { kbExportFlags = prev })

	kbExportFlags = struct {
		latestOnly bool
		jsonOut    bool
		dsn        string
		bundle     bool
		kbID       string
		outDir     string
		noPack     bool
		signKey    string
		bodies     bool
		limit      int
		maxBytes   int64
	}{bundle: true, kbID: ""}

	cmd := kbExportCmd
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	err := runKbExportBundle(context.Background(), cmd)
	if err == nil {
		t.Fatal("expected error for missing --kb-id")
	}
	if !strings.Contains(err.Error(), "kb-id") {
		t.Fatalf("error must mention --kb-id; got %v", err)
	}
}

// TestKBExport_LegacyRequiresOutput — legacy (non-bundle) mode requires both
// positional kb_id and -o output flag.
func TestKBExport_LegacyRequiresOutput(t *testing.T) {
	prev := kbExportFlags
	prevOutput := output
	t.Cleanup(func() {
		kbExportFlags = prev
		output = prevOutput
	})

	kbExportFlags = struct {
		latestOnly bool
		jsonOut    bool
		dsn        string
		bundle     bool
		kbID       string
		outDir     string
		noPack     bool
		signKey    string
		bodies     bool
		limit      int
		maxBytes   int64
	}{}
	// output backs the root persistent --output/-o flag (§7); the legacy
	// export path reads it directly instead of a local redeclaration.
	output = ""

	cmd := kbExportCmd
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	err := runKbExport(cmd, []string{"some-kb"})
	if err == nil {
		t.Fatal("expected error for missing --output")
	}
	if !strings.Contains(err.Error(), "output") {
		t.Fatalf("error must mention --output; got %v", err)
	}
}

// TestKBExport_FlagsRegistered — sanity that bundle-mode flags exist on the
// command (--kb-id, --out-dir, --no-pack, --bundle).
func TestKBExport_FlagsRegistered(t *testing.T) {
	for _, name := range []string{"bundle", "kb-id", "out-dir", "no-pack"} {
		if kbExportCmd.Flags().Lookup(name) == nil {
			t.Fatalf("missing flag --%s on kb export command", name)
		}
	}
}
