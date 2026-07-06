package cmd

import "testing"

func TestSynthNamesFlagsRegistered(t *testing.T) {
	for _, f := range []string{"app", "limit", "force", "dry-run", "verify", "database"} {
		if kbSynthNamesCmd.Flags().Lookup(f) == nil {
			t.Fatalf("--%s not registered on synth-names", f)
		}
	}
}
