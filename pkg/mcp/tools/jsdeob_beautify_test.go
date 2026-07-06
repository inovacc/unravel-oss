/*
Copyright (c) 2026 Security Research

06-04 Task 2: smoke tests for the unravel_js_beautify MCP tool.
*/
package mcptools

import (
	"os"
	"strings"
	"testing"
)

func TestSanitizeJsMCPPath_RejectsTraversal(t *testing.T) {
	cases := []string{"../../etc/passwd", "..", "../bar"}
	for _, p := range cases {
		if _, err := sanitizeJsMCPPath(p, false); err == nil {
			t.Errorf("expected path traversal rejection for %q", p)
		}
	}
}

func TestJsBeautify_Registered(t *testing.T) {
	body, err := os.ReadFile("jsdeob.go")
	if err != nil {
		t.Fatalf("read jsdeob.go: %v", err)
	}
	if !strings.Contains(string(body), `"unravel_js_beautify"`) {
		t.Error("unravel_js_beautify not registered in jsdeob.go")
	}
	if !strings.Contains(string(body), "JsBeautifyInput") {
		t.Error("JsBeautifyInput type missing")
	}
	if !strings.Contains(string(body), `jsonschema:`) {
		t.Error("JsBeautifyInput missing jsonschema tags")
	}
}
