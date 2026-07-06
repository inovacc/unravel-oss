/*
Copyright (c) 2026 Security Research

06-04 Task 1: smoke tests for the java beautify subcommand and the
--beautify flag on java decompile. Validates cobra registration and
path-traversal sanitisation (T-06-01).
*/
package cmd

import "testing"

func TestJavaBeautify_SubcommandRegistered(t *testing.T) {
	var hasJava bool
	for _, c := range rootCmd.Commands() {
		if c.Use == "java" {
			hasJava = true
			var hasBeautify, hasDecompile bool
			for _, sc := range c.Commands() {
				if sc.Name() == "beautify" {
					hasBeautify = true
				}
				if sc.Name() == "decompile" {
					hasDecompile = true
					if f := sc.Flags().Lookup("beautify"); f == nil {
						t.Errorf("java decompile missing --beautify flag")
					}
				}
			}
			if !hasBeautify {
				t.Errorf("java beautify subcommand not registered")
			}
			if !hasDecompile {
				t.Errorf("java decompile subcommand missing")
			}
		}
	}
	if !hasJava {
		t.Error("java top-level command not registered")
	}
}

func TestSanitizeJavaCmdPath_RejectsTraversal(t *testing.T) {
	cases := []string{"../../etc/passwd", ".."}
	for _, p := range cases {
		if _, err := sanitizeJavaCmdPath(p, false); err == nil {
			t.Errorf("expected path traversal rejection for %q", p)
		}
	}
}
