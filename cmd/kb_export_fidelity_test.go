/*
Copyright (c) 2026 Security Research

Unit test for kb export --bodies fidelity flag wiring (Task 2, Phase kbc-v-export-fidelity).
*/
package cmd

import "testing"

func TestKbExportFidelityFlags(t *testing.T) {
	for _, f := range []string{"bodies", "limit", "max-bytes"} {
		if kbExportCmd.Flags().Lookup(f) == nil {
			t.Fatalf("--%s not registered on kb export", f)
		}
	}
	// The fidelity output directory comes from the root persistent
	// --output/-o flag (§7 of COMMAND-TAXONOMY.md), not a local --out
	// redeclaration. Flag() climbs the command tree to find it.
	if kbExportCmd.Flag("output") == nil {
		t.Fatal("--output not reachable on kb export (root persistent flag)")
	}
	if kbExportCmd.Flags().Lookup("out") != nil {
		t.Fatal("--out must not be locally registered on kb export (unified onto root --output)")
	}
}
