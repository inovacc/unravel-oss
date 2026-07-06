/*
Copyright (c) 2026 Security Research
*/

package crypto

import (
	"testing"

	"github.com/inovacc/unravel-oss/pkg/knowledge/kb/component"
)

func TestRules_Crypto(t *testing.T) {
	cases := []struct {
		name string
		mod  component.Module
		want string
	}{
		{
			name: "path+name+symbol",
			mod: component.Module{
				Name: "AesCipher", Path: "src/crypto/aes.go",
				SymbolsJSON: `["AesGcm","sha256"]`,
			},
			want: "crypto",
		},
		{
			name: "name+symbol",
			mod: component.Module{
				Name: "HashUtil", Path: "src/util/hash.go",
				SymbolsJSON: `["sha256","hmac"]`,
			},
			want: "crypto",
		},
		{
			name: "strict symbol-only",
			mod: component.Module{
				Name: "Util", Path: "src/util/x.go",
				SymbolsJSON: `["Curve25519"]`,
			},
			want: "crypto",
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
