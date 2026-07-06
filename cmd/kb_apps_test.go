/*
Copyright (c) 2026 Security Research
*/

package cmd

import (
	"strings"
	"testing"
)

// TestKbAppsMeanMinFlagPresent asserts the --mean-min flag is registered
// on `unravel kb apps` (P59-03b). Cobra-level smoke; no DB required.
func TestKbAppsMeanMinFlagPresent(t *testing.T) {
	f := appsCmd.Flags().Lookup("mean-min")
	if f == nil {
		t.Fatalf("--mean-min flag missing on appsCmd")
	}
	if f.DefValue != "0" {
		t.Errorf("--mean-min default = %q, want %q", f.DefValue, "0")
	}
	if !strings.Contains(strings.ToLower(f.Usage), "mean") {
		t.Errorf("--mean-min usage text missing 'mean': %q", f.Usage)
	}
}
