/*
Copyright (c) 2026 Security Research
*/

package communication

import (
	"testing"

	"github.com/inovacc/unravel-oss/pkg/knowledge/kb/component"
)

func TestRules_Communication(t *testing.T) {
	cases := []struct {
		name string
		mod  component.Module
		want string
	}{
		{
			name: "path+name+symbol",
			mod: component.Module{
				Name: "HttpClient", Path: "src/http/client.go",
				SymbolsJSON: `["http.Client","fetch"]`,
			},
			want: "communication",
		},
		{
			name: "name+symbol",
			mod: component.Module{
				Name: "ApiFetcher", Path: "src/util/x.go",
				SymbolsJSON: `["axios"]`,
			},
			want: "communication",
		},
		{
			name: "path+symbol",
			mod: component.Module{
				Name: "Dialer", Path: "src/net/dial.go",
				SymbolsJSON: `["grpc.Dial"]`,
			},
			want: "communication",
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
