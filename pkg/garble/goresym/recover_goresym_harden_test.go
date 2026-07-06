//go:build goresym

/*
Copyright (c) 2026 Security Research
*/
package goresym_test

import (
	"path/filepath"
	"slices"
	"testing"

	"github.com/inovacc/unravel-oss/pkg/garble/goresym"
)

// TestBuildGoresymArgs_ArgumentInjectionGuards verifies the argv builder
// neutralises both attacker-influenced inputs: a malicious GoVersion read from
// the binary's .go.buildinfo, and a leading-dash path. Finding #23.
func TestBuildGoresymArgs_ArgumentInjectionGuards(t *testing.T) {
	t.Run("malicious GoVersion is dropped", func(t *testing.T) {
		for _, bad := range []string{"-d", "-manualload=evil", "go1.2.3 -d", "1.26"} {
			args := goresym.BuildGoresymArgsForTest(goresym.Options{GoVersion: bad}, "bin")
			if slices.Contains(args, bad) {
				t.Fatalf("malicious GoVersion %q leaked into argv: %v", bad, args)
			}
			if slices.Contains(args, "-v") {
				t.Fatalf("expected -v dropped for malicious GoVersion %q, got %v", bad, args)
			}
		}
	})

	t.Run("legitimate GoVersion is passed", func(t *testing.T) {
		args := goresym.BuildGoresymArgsForTest(goresym.Options{GoVersion: "go1.26.4"}, "bin")
		i := slices.Index(args, "-v")
		if i < 0 || i+1 >= len(args) || args[i+1] != "go1.26.4" {
			t.Fatalf("expected -v go1.26.4 in argv, got %v", args)
		}
	})

	t.Run("path follows -- end-of-options and is absolute", func(t *testing.T) {
		args := goresym.BuildGoresymArgsForTest(goresym.Options{}, "-rf")
		i := slices.Index(args, "--")
		if i < 0 {
			t.Fatalf("expected -- end-of-options marker, got %v", args)
		}
		if i != len(args)-2 {
			t.Fatalf("expected path to be the last arg right after --, got %v", args)
		}
		got := args[len(args)-1]
		if !filepath.IsAbs(got) {
			t.Fatalf("expected absolutised path, got %q (argv %v)", got, args)
		}
	})
}
