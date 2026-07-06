/*
Copyright (c) 2026 Security Research
*/

package stealth

import (
	"testing"

	"github.com/inovacc/unravel-oss/pkg/knowledge/kb/component"
)

func TestRules_Stealth(t *testing.T) {
	cases := []struct {
		name string
		mod  component.Module
		want string
	}{
		{
			name: "path+name+symbol",
			mod: component.Module{
				Name: "OverlayHide", Path: "src/stealth/overlay.js",
				SymbolsJSON: `["setContentProtection"]`,
			},
			want: "stealth",
		},
		{
			name: "name+symbol",
			mod: component.Module{
				Name: "InvisibleWindow", Path: "src/util/x.js",
				SymbolsJSON: `["hideFromCapture"]`,
			},
			want: "stealth",
		},
		{
			name: "strict symbol",
			mod: component.Module{
				Name: "Util", Path: "src/x.js",
				SymbolsJSON: `["allow-set-content-protected"]`,
			},
			want: "stealth",
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
