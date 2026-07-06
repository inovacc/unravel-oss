/*
Copyright (c) 2026 Security Research
*/
package cmd

import "testing"

func TestTopicsFlagsRegistered(t *testing.T) {
	for _, f := range []string{"app", "limit", "force", "dry-run", "verify", "database"} {
		if kbTopicsCmd.Flags().Lookup(f) == nil {
			t.Fatalf("--%s not registered on knowledge topics", f)
		}
	}
}
