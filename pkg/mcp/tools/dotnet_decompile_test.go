/*
Copyright (c) 2026 Security Research
*/
package mcptools

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestMCPTool_DotnetDecompile_Registered verifies that the new
// unravel_dotnet_decompile tool name appears in pkg/mcptools/dotnet.go and
// that its typed input struct exposes Input/Output/IncludeFramework/Beautify
// with jsonschema tags (D-16 enforcement).
func TestMCPTool_DotnetDecompile_Registered(t *testing.T) {
	body, err := os.ReadFile("dotnet.go")
	if err != nil {
		t.Fatalf("read dotnet.go: %v", err)
	}
	src := string(body)

	if !strings.Contains(src, `"unravel_dotnet_decompile"`) {
		t.Error("expected unravel_dotnet_decompile tool name in dotnet.go")
	}
	if !strings.Contains(src, "type DotNetDecompileInput struct") {
		t.Error("expected DotNetDecompileInput struct definition")
	}
	for _, want := range []string{"Input ", "Output ", "IncludeFramework ", "Beautify "} {
		if !strings.Contains(src, want) {
			t.Errorf("DotNetDecompileInput missing field beginning with %q", want)
		}
	}
	for _, want := range []string{`json:"input"`, `json:"output"`, `jsonschema:`} {
		if !strings.Contains(src, want) {
			t.Errorf("DotNetDecompileInput missing tag fragment %q", want)
		}
	}
	if !strings.Contains(src, "handleDotnetDecompile") {
		t.Error("expected handleDotnetDecompile handler in dotnet.go")
	}
}

// TestMCPTool_DotnetDecompile_RejectsTraversal verifies the MCP-boundary
// path sanitizer rejects path traversal attempts before any subprocess work
// (T-05-01 mitigation).
func TestMCPTool_DotnetDecompile_RejectsTraversal(t *testing.T) {
	cases := []struct {
		name string
		in   string
	}{
		{"dotdot-relative", "../etc/passwd"},
		{"dotdot-mid", "foo/../../bar"},
		{"empty", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := sanitizeDotnetMCPPath(tc.in, false)
			if err == nil {
				t.Errorf("expected error for input %q, got nil", tc.in)
			} else if !strings.Contains(strings.ToLower(err.Error()), "path") &&
				!strings.Contains(strings.ToLower(err.Error()), "empty") {
				t.Errorf("error message should mention path or empty, got: %v", err)
			}
		})
	}
}

// TestMCPTool_DotnetDecompile_AcceptsValid verifies sanitizeMCPPath accepts a
// well-formed existing path and returns its absolute form.
func TestMCPTool_DotnetDecompile_AcceptsValid(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "a.dll")
	if err := os.WriteFile(f, []byte("MZ"), 0o644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}

	got, err := sanitizeDotnetMCPPath(f, true)
	if err != nil {
		t.Fatalf("sanitize valid path: %v", err)
	}
	if !filepath.IsAbs(got) {
		t.Errorf("expected absolute path, got %q", got)
	}
}
