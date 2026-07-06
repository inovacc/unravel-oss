/*
Copyright (c) 2026 Security Research
*/

package ipc

import (
	"testing"

	"github.com/inovacc/unravel-oss/pkg/knowledge/kb/component"
)

func TestRules_IPC(t *testing.T) {
	cases := []struct {
		name string
		mod  component.Module
		want string
	}{
		{
			name: "path+name+symbol",
			mod: component.Module{
				Name: "IpcBridge", Path: "src/ipc/bridge.js",
				SymbolsJSON: `["ipcRenderer","contextBridge"]`,
			},
			want: "ipc",
		},
		{
			name: "name+symbol",
			mod: component.Module{
				Name: "PreloadChannel", Path: "src/util/x.js",
				SymbolsJSON: `["postMessage"]`,
			},
			want: "ipc",
		},
		{
			name: "path+symbol",
			mod: component.Module{
				Name: "Util", Path: "src/preload/x.js",
				SymbolsJSON: `["MessageChannel"]`,
			},
			want: "ipc",
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
