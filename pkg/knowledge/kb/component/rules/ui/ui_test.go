/*
Copyright (c) 2026 Security Research
*/

package ui

import (
	"testing"

	"github.com/inovacc/unravel-oss/pkg/knowledge/kb/component"
)

func TestRules_UI(t *testing.T) {
	cases := []struct {
		name string
		mod  component.Module
		want string
	}{
		{
			name: "path+name+symbol",
			mod: component.Module{
				Name: "HomeView", Path: "src/ui/home.tsx",
				SymbolsJSON: `["React","useState"]`,
			},
			want: "ui",
		},
		{
			name: "name+symbol",
			mod: component.Module{
				Name: "ProfilePage", Path: "src/util/x.tsx",
				SymbolsJSON: `["useState"]`,
			},
			want: "ui",
		},
		{
			name: "path+symbol",
			mod: component.Module{
				Name: "Util", Path: "src/widget/x.tsx",
				SymbolsJSON: `["Svelte"]`,
			},
			want: "ui",
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
