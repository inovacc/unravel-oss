/*
Copyright (c) 2026 Security Research
*/

package negatives

import (
	"testing"

	"github.com/inovacc/unravel-oss/pkg/knowledge/kb/component"
	// Pull in the auth and crypto positive rules so suppression has something
	// to suppress (otherwise the absence of positive matches is meaningless).
	_ "github.com/inovacc/unravel-oss/pkg/knowledge/kb/component/rules/auth"
	_ "github.com/inovacc/unravel-oss/pkg/knowledge/kb/component/rules/crypto"
)

func TestNegatives_Suppress(t *testing.T) {
	cases := []struct {
		name    string
		mod     component.Module
		notWant string // bucket that must NOT win
	}{
		{
			name: "test file with Token symbol does not classify as auth",
			mod: component.Module{
				Name: "session_test", Path: "src/session/session_test.go",
				SymbolsJSON: `["token","jwt"]`,
			},
			notWant: "auth",
		},
		{
			name: "docs path with oauth keyword does not classify as auth",
			mod: component.Module{
				Name: "OAuthGuide", Path: "docs/oauth.md",
				SymbolsJSON: `["oauth"]`,
			},
			notWant: "auth",
		},
		{
			name: "graphics module with crypto symbol does not classify as crypto",
			mod: component.Module{
				Name: "AnimationRunner", Path: "src/render/anim.go",
				SymbolsJSON: `["crypto","sha256"]`,
			},
			notWant: "crypto",
		},
		{
			name: "cmd path with Login does not classify as auth",
			mod: component.Module{
				Name: "LoginCmd", Path: "cmd/login.go",
				SymbolsJSON: `["Login"]`,
			},
			notWant: "auth",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			result := component.Apply(tc.mod)
			if result.Component == tc.notWant {
				t.Fatalf("Component = %q (suppression failed); evidence=%q", result.Component, result.Evidence)
			}
			if result.Classifier != "rule" {
				t.Fatalf("Classifier = %q, want rule", result.Classifier)
			}
		})
	}
}
