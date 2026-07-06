/*
Copyright (c) 2026 Security Research
*/

package auth

import (
	"testing"

	"github.com/inovacc/unravel-oss/pkg/knowledge/kb/component"
)

func TestRules_Auth(t *testing.T) {
	cases := []struct {
		name    string
		mod     component.Module
		want    string
		wantCls string
	}{
		{
			name: "path+name+symbol -> auth 0.95",
			mod: component.Module{
				Name: "OAuthSession", Path: "src/auth/session.go",
				SymbolsJSON: `["jwt","login","password"]`,
			},
			want: "auth", wantCls: "rule",
		},
		{
			name: "name+symbol -> auth",
			mod: component.Module{
				Name: "TokenStore", Path: "src/util/store.go",
				SymbolsJSON: `["jwt","credential"]`,
			},
			want: "auth", wantCls: "rule",
		},
		{
			name: "login-only weak match -> auth",
			mod: component.Module{
				Name: "SignInButton", Path: "src/ui/button.go",
				SymbolsJSON: `["onClick"]`,
			},
			want: "auth", wantCls: "rule",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			result := component.Apply(tc.mod)
			if result.Component != tc.want {
				t.Fatalf("Component = %q, want %q (evidence=%q)", result.Component, tc.want, result.Evidence)
			}
			if result.Classifier != tc.wantCls {
				t.Fatalf("Classifier = %q, want %q", result.Classifier, tc.wantCls)
			}
		})
	}
}
