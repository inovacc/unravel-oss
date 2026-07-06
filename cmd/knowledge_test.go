/*
Copyright (c) 2026 Security Research

Plan 07-04 Task 2: CLI wiring tests for `unravel knowledge migrate` +
`--with-ai` flag.
*/
package cmd

import (
	"bytes"
	"strings"
	"testing"
)

// TestKnowledgeMigrateSubcommandRegistered verifies the migrate subcommand
// is wired under `kb transfer` with a required `--to` flag.
func TestKnowledgeMigrateSubcommandRegistered(t *testing.T) {
	var found bool
	for _, sub := range kbTransferCmd.Commands() {
		if sub.Use == "migrate <kb-dir>" {
			found = true
			fl := sub.Flag("to")
			if fl == nil {
				t.Fatal("migrate: --to flag missing")
			}
			break
		}
	}
	if !found {
		t.Fatal("migrate subcommand not registered under kbTransferCmd")
	}
}

// TestKnowledgeWithAIFlagRegistered verifies the `kb enrich generate` command
// accepts a --with-ai flag (D-14).
func TestKnowledgeWithAIFlagRegistered(t *testing.T) {
	fl := kbGenerateCmd.Flag("with-ai")
	if fl == nil {
		t.Fatal("kb enrich generate: --with-ai flag missing")
	}
	if fl.Value.Type() != "bool" {
		t.Fatalf("generate --with-ai: expected bool, got %s", fl.Value.Type())
	}
}

// TestKnowledgeP59FlagsRegistered verifies the six P59-04a flags are
// registered on the `kb enrich generate` command with the documented defaults.
func TestKnowledgeP59FlagsRegistered(t *testing.T) {
	cases := []struct {
		name string
		typ  string
		def  string
	}{
		{"iterate", "bool", "false"},
		{"cdp-port", "int", "0"},
		{"max-iter", "int", "5"},
		{"threshold", "int", "80"},
		{"scorecard-md", "bool", "true"},
		{"strict-citations", "bool", "true"},
	}
	for _, c := range cases {
		fl := kbGenerateCmd.Flag(c.name)
		if fl == nil {
			t.Errorf("generate: --%s flag missing", c.name)
			continue
		}
		if fl.Value.Type() != c.typ {
			t.Errorf("--%s: type %q, want %q", c.name, fl.Value.Type(), c.typ)
		}
		if fl.DefValue != c.def {
			t.Errorf("--%s: default %q, want %q", c.name, fl.DefValue, c.def)
		}
	}
}

// TestKnowledgeMigrateRejectsBadFramework verifies runKnowledgeMigrate
// surfaces a clear error when --to is not in the whitelist.
func TestKnowledgeMigrateRejectsBadFramework(t *testing.T) {
	prev := kbMigrateTo
	t.Cleanup(func() { kbMigrateTo = prev })
	kbMigrateTo = "ruby-on-rails"

	// Use a fresh buffer for stderr capture; cobra invocation fails before
	// any FS work happens because IsValid rejects the framework.
	cmd := kbMigrateCmd
	cmd.SetOut(new(bytes.Buffer))
	cmd.SetErr(new(bytes.Buffer))

	err := runKnowledgeMigrate(cmd, []string{t.TempDir()})
	if err == nil {
		t.Fatal("expected error for unknown framework, got nil")
	}
	if !strings.Contains(err.Error(), "ruby-on-rails") {
		t.Errorf("error should name the rejected framework: %v", err)
	}
}
