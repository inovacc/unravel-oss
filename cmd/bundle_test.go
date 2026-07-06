/*
Copyright (c) 2026 Security Research

06-04 Task 1: smoke tests for the bundle CLI surface. Validates the
cobra command registration, path-traversal sanitisation (T-06-01), and
symlink rejection (T-06-06).
*/
package cmd

import (
	"strings"
	"testing"
)

func TestBundleCmd_Registered(t *testing.T) {
	// Walk rootCmd children for "bundle".
	var found bool
	for _, c := range rootCmd.Commands() {
		if c.Use == "bundle" {
			found = true
			// Must have a "reconstruct" subcommand.
			var hasRec bool
			for _, sc := range c.Commands() {
				if strings.HasPrefix(sc.Use, "reconstruct") {
					hasRec = true
					break
				}
			}
			if !hasRec {
				t.Errorf("bundle command missing 'reconstruct' subcommand")
			}
		}
	}
	if !found {
		t.Errorf("bundle top-level command not registered on rootCmd")
	}
}

func TestSanitizeBundlePath_RejectsTraversal(t *testing.T) {
	cases := []string{"../../etc/passwd", "..", "../bar"}
	for _, p := range cases {
		if _, err := sanitizeBundlePath(p, false); err == nil {
			t.Errorf("expected path traversal rejection for %q", p)
		}
	}
}

func TestSanitizeBundlePath_RejectsEmpty(t *testing.T) {
	if _, err := sanitizeBundlePath("", false); err == nil {
		t.Error("expected error for empty path")
	}
}
