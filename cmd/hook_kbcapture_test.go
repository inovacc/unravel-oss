/*
Copyright (c) 2026 Security Research
*/

package cmd

import (
	"strings"
	"testing"
)

func TestExtractDissectPath(t *testing.T) {
	cases := []struct {
		name string
		json string
		want string
	}{
		{"path key", `{"tool_name":"unravel_app_dissect","tool_input":{"path":"/a/b.dll"}}`, "/a/b.dll"},
		{"file key", `{"tool_input":{"file":"/x/y.jar"}}`, "/x/y.jar"},
		{"target key", `{"tool_input":{"target":"/t/z.wasm"}}`, "/t/z.wasm"},
		{"missing", `{"tool_input":{}}`, ""},
		{"garbage", `not json`, ""},
		{"empty", ``, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := extractDissectPath(strings.NewReader(c.json))
			if got != c.want {
				t.Errorf("extractDissectPath(%s) = %q, want %q", c.json, got, c.want)
			}
		})
	}
}
