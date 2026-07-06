/*
Copyright (c) 2026 Security Research

06-04 Task 2: smoke tests for the unravel_java_beautify MCP tool.
*/
package mcptools

import (
	"os"
	"strings"
	"testing"
)

func TestSanitizeJavaMCPPath_RejectsTraversal(t *testing.T) {
	cases := []string{"../../etc/passwd", "..", "../bar"}
	for _, p := range cases {
		if _, err := sanitizeJavaMCPPath(p, false); err == nil {
			t.Errorf("expected path traversal rejection for %q", p)
		}
	}
}

func TestJavaBeautify_Registered(t *testing.T) {
	body, err := os.ReadFile("java.go")
	if err != nil {
		t.Fatalf("read java.go: %v", err)
	}
	if !strings.Contains(string(body), `"unravel_java_beautify"`) {
		t.Error("unravel_java_beautify not registered in java.go")
	}
	// Confirm typed input has jsonschema tags (D-16).
	if !strings.Contains(string(body), "JavaBeautifyInput") {
		t.Error("JavaBeautifyInput type missing")
	}
	if !strings.Contains(string(body), `jsonschema:`) {
		t.Error("JavaBeautifyInput missing jsonschema tags")
	}
}
