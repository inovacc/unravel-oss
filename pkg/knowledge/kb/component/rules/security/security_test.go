/*
Copyright (c) 2026 Security Research
*/

package security

import (
	"testing"

	"github.com/inovacc/unravel-oss/pkg/knowledge/kb/component"
)

func TestRules_Security(t *testing.T) {
	cases := []struct {
		name string
		mod  component.Module
		want string
	}{
		{
			name: "path+name+symbol",
			mod: component.Module{
				Name: "SandboxPolicy", Path: "src/security/sandbox.go",
				SymbolsJSON: `["sandbox","permission","csp"]`,
			},
			want: "security",
		},
		{
			name: "name+symbol",
			mod: component.Module{
				Name: "Sanitizer", Path: "src/util/x.go",
				SymbolsJSON: `["sanitize","policy"]`,
			},
			want: "security",
		},
		{
			name: "path+symbol",
			mod: component.Module{
				Name: "Util", Path: "src/sandbox/runner.go",
				SymbolsJSON: `["csp","sandbox"]`,
			},
			want: "security",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			result := component.Apply(tc.mod)
			if result.Component != tc.want {
				t.Fatalf("Component = %q, want %q (evidence=%q)", result.Component, tc.want, result.Evidence)
			}
			if result.Classifier != "rule" {
				t.Fatalf("Classifier = %q, want rule", result.Classifier)
			}
		})
	}
}
