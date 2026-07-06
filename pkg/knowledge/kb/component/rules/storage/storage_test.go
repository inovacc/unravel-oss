/*
Copyright (c) 2026 Security Research
*/

package storage

import (
	"testing"

	"github.com/inovacc/unravel-oss/pkg/knowledge/kb/component"
)

func TestRules_Storage(t *testing.T) {
	cases := []struct {
		name string
		mod  component.Module
		want string
	}{
		{
			name: "path+name+symbol",
			mod: component.Module{
				Name: "LevelDBCache", Path: "src/storage/leveldb.go",
				SymbolsJSON: `["leveldb","kvstore"]`,
			},
			want: "storage",
		},
		{
			name: "name+symbol",
			mod: component.Module{
				Name: "SqliteRepository", Path: "src/util/x.go",
				SymbolsJSON: `["sqlite"]`,
			},
			want: "storage",
		},
		{
			name: "path+symbol",
			mod: component.Module{
				Name: "Util", Path: "src/cache/x.go",
				SymbolsJSON: `["indexeddb"]`,
			},
			want: "storage",
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
