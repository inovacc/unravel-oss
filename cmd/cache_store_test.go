/*
Copyright (c) 2026 Security Research
*/
package cmd

import "testing"

func TestStoreReconcileCommandRegistered(t *testing.T) {
	found := false
	for _, c := range storeCmd.Commands() {
		if c.Name() == "reconcile" {
			found = true
			break
		}
	}
	if !found {
		t.Error("`store reconcile` subcommand is not registered")
	}
}
