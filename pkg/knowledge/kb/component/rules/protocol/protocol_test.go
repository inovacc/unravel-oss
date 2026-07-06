/*
Copyright (c) 2026 Security Research
*/

package protocol

import (
	"testing"

	"github.com/inovacc/unravel-oss/pkg/knowledge/kb/component"
)

func TestRules_Protocol(t *testing.T) {
	cases := []struct {
		name string
		mod  component.Module
		want string
	}{
		{
			name: "path+name+symbol",
			mod: component.Module{
				Name: "PbCodec", Path: "src/proto/codec.go",
				SymbolsJSON: `["proto.Marshal","protobuf"]`,
			},
			want: "protocol",
		},
		{
			name: "name+symbol",
			mod: component.Module{
				Name: "Encoder", Path: "src/util/x.go",
				SymbolsJSON: `["msgpack"]`,
			},
			want: "protocol",
		},
		{
			name: "path+symbol",
			mod: component.Module{
				Name: "Util", Path: "src/codec/x.go",
				SymbolsJSON: `["cbor"]`,
			},
			want: "protocol",
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
