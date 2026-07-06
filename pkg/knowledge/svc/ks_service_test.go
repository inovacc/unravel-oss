/*
Copyright (c) 2026 Security Research

Argument-injection hardening tests (finding #10). git checkout <ref> and
git grep <pattern> must never let a leading-dash value be parsed as a flag:
checkout uses `--end-of-options` before the ref (a trailing "--" alone does
NOT stop a dash-leading ref from parsing as a flag), grep uses "-e <pattern>".
*/
package svc

import (
	"slices"
	"testing"
)

func TestCheckoutArgs_EndOfOptions(t *testing.T) {
	tests := []struct {
		name string
		ref  string
		want []string
	}{
		{
			name: "ordinary sha",
			ref:  "a1b2c3d",
			want: []string{"checkout", "--end-of-options", "a1b2c3d", "--"},
		},
		{
			name: "epoch ref",
			ref:  "refs/unravel/epoch-3",
			want: []string{"checkout", "--end-of-options", "refs/unravel/epoch-3", "--"},
		},
		{
			name: "leading-dash payload neutralized",
			ref:  "--orphan",
			want: []string{"checkout", "--end-of-options", "--orphan", "--"},
		},
		{
			name: "detach payload neutralized",
			ref:  "--detach",
			want: []string{"checkout", "--end-of-options", "--detach", "--"},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := checkoutArgs(tc.ref)
			if !slices.Equal(got, tc.want) {
				t.Fatalf("checkoutArgs(%q) = %v, want %v", tc.ref, got, tc.want)
			}
			// --end-of-options MUST appear before the ref: a trailing "--"
			// alone leaves a dash-leading ref parseable as a flag (verified:
			// `git checkout --detach --` detaches HEAD).
			eoo := slices.Index(got, "--end-of-options")
			refIdx := slices.Index(got, tc.ref)
			if eoo < 0 || refIdx < eoo {
				t.Fatalf("checkoutArgs(%q) = %v: --end-of-options must precede the ref", tc.ref, got)
			}
		})
	}
}

func TestGrepArgs_EndOfOptions(t *testing.T) {
	tests := []struct {
		name    string
		pattern string
		want    []string
	}{
		{
			name:    "ordinary pattern",
			pattern: "setContentProtection",
			want:    []string{"grep", "-n", "-I", "--color=always", "-e", "setContentProtection", "--"},
		},
		{
			name:    "leading-dash RCE payload neutralized",
			pattern: "--open-files-in-pager=echo PWNED;false",
			want:    []string{"grep", "-n", "-I", "--color=always", "-e", "--open-files-in-pager=echo PWNED;false", "--"},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := grepArgs(tc.pattern)
			if !slices.Equal(got, tc.want) {
				t.Fatalf("grepArgs(%q) = %v, want %v", tc.pattern, got, tc.want)
			}
			// "-e <pattern>" guarantees the pattern occupies the value slot
			// of -e, never a flag position; trailing "--" ends options.
			if got[len(got)-1] != "--" {
				t.Fatalf("grepArgs(%q): missing trailing -- separator", tc.pattern)
			}
			eIdx := slices.Index(got, "-e")
			if eIdx < 0 || got[eIdx+1] != tc.pattern {
				t.Fatalf("grepArgs(%q): pattern not in -e value slot: %v", tc.pattern, got)
			}
		})
	}
}
