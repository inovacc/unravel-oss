/*
Copyright (c) 2026 Security Research

06-04 Task 1: smoke tests for the jsdeob beautify --ai flag.
Validates cobra registration and path-traversal sanitisation.
*/
package cmd

import "testing"

func TestJsdeobBeautify_AIFlagRegistered(t *testing.T) {
	for _, c := range rootCmd.Commands() {
		if c.Use != "jsdeob" {
			continue
		}
		for _, sc := range c.Commands() {
			if sc.Name() == "beautify" {
				if f := sc.Flags().Lookup("ai"); f == nil {
					t.Errorf("jsdeob beautify missing --ai flag")
				}
				return
			}
		}
		t.Error("jsdeob beautify subcommand not found")
		return
	}
	t.Error("jsdeob top-level command not registered")
}

func TestSanitizeJsdeobPath_RejectsTraversal(t *testing.T) {
	cases := []string{"../../etc/passwd", ".."}
	for _, p := range cases {
		if _, err := sanitizeJsdeobPath(p, false); err == nil {
			t.Errorf("expected path traversal rejection for %q", p)
		}
	}
}
