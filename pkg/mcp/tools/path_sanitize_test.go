/*
Copyright (c) 2026 Security Research

path_sanitize_test.go — direct unit tests for the pure helper functions
shared across several MCP tool handlers (winui.go, npm.go): sanitizeMCPPath
(the path-traversal boundary guard, T-04-01), jsonResultCapped (the 1 MiB
response-size cap, T-04-15), and splitPkgSpec (npm "name@version" parsing).
These are exercised only indirectly today via handler-level error-path
tests; this file pins down the helpers' own edge cases directly, with no
filesystem I/O beyond t.TempDir() and no external process/network/DB.
*/
package mcptools

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// --- sanitizeMCPPath -------------------------------------------------------

func TestSanitizeMCPPath_Empty(t *testing.T) {
	got, err := sanitizeMCPPath("")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "" {
		t.Errorf("sanitizeMCPPath(\"\") = %q, want empty", got)
	}
}

func TestSanitizeMCPPath_RejectsLeadingTraversal(t *testing.T) {
	_, err := sanitizeMCPPath("../secret")
	if err == nil {
		t.Fatal("expected error for leading '..' segment")
	}
	if !strings.Contains(err.Error(), "'..' segment") {
		t.Errorf("error %q missing '..' segment message", err.Error())
	}
}

func TestSanitizeMCPPath_RejectsTraversalThatSurvivesClean(t *testing.T) {
	// filepath.Clean("a/../../b") == "../b" (one ".." can't be cancelled
	// because it walks above the relative root) — the guard must still
	// catch it even though the raw input has no leading "..".
	// Built manually (not via filepath.Join, which would call Clean itself)
	// so the surviving ".." reaches sanitizeMCPPath's own Clean call.
	in := "a" + string(filepath.Separator) + ".." + string(filepath.Separator) + ".." + string(filepath.Separator) + "b"
	_, err := sanitizeMCPPath(in)
	if err == nil {
		t.Fatalf("expected error for traversal surviving Clean, input=%q", in)
	}
}

func TestSanitizeMCPPath_TraversalThatCancelsOutIsAccepted(t *testing.T) {
	// filepath.Clean("a/../b") == "b" — the ".." is fully absorbed before
	// the segment scan runs, so this must NOT be rejected.
	in := "a" + string(filepath.Separator) + ".." + string(filepath.Separator) + "b"
	got, err := sanitizeMCPPath(in)
	if err != nil {
		t.Fatalf("unexpected error for self-cancelling traversal: %v", err)
	}
	if !filepath.IsAbs(got) {
		t.Errorf("expected absolute path, got %q", got)
	}
	if !strings.HasSuffix(got, "b") {
		t.Errorf("expected path ending in 'b', got %q", got)
	}
}

func TestSanitizeMCPPath_ValidRelativePathResolvesAbsolute(t *testing.T) {
	got, err := sanitizeMCPPath(filepath.Join("some", "dir"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !filepath.IsAbs(got) {
		t.Errorf("expected absolute path, got %q", got)
	}
}

func TestSanitizeMCPPath_ValidAbsolutePathPassesThrough(t *testing.T) {
	dir := t.TempDir()
	got, err := sanitizeMCPPath(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := filepath.Clean(dir)
	if got != want {
		t.Errorf("sanitizeMCPPath(%q) = %q, want %q", dir, got, want)
	}
}

// --- jsonResultCapped --------------------------------------------------

func TestJsonResultCapped_SmallPayloadUnchanged(t *testing.T) {
	v := map[string]string{"key": "value"}
	capped := jsonResultCapped(v)
	plain := jsonResult(v)

	if capped.IsError {
		t.Fatal("unexpected error result for small payload")
	}
	if len(capped.Content) != 1 || len(plain.Content) != 1 {
		t.Fatalf("expected 1 content block each, got capped=%d plain=%d", len(capped.Content), len(plain.Content))
	}

	cappedText := capped.Content[0].(*mcp.TextContent).Text
	plainText := plain.Content[0].(*mcp.TextContent).Text
	if cappedText != plainText {
		t.Errorf("jsonResultCapped altered a small payload:\ngot:  %s\nwant: %s", cappedText, plainText)
	}
}

func TestJsonResultCapped_LargePayloadTruncated(t *testing.T) {
	// Build a payload whose marshaled JSON exceeds the 1 MiB cap.
	big := strings.Repeat("x", 2<<20) // 2 MiB of filler
	v := map[string]string{"blob": big}

	uncapped := jsonResult(v)
	uncappedText := uncapped.Content[0].(*mcp.TextContent).Text
	const maxBytes = 1 << 20
	if len(uncappedText) <= maxBytes {
		t.Fatalf("test payload not large enough: uncapped length %d <= %d", len(uncappedText), maxBytes)
	}

	capped := jsonResultCapped(v)
	if capped.IsError {
		t.Fatal("unexpected error result for large payload")
	}
	cappedText := capped.Content[0].(*mcp.TextContent).Text
	if len(cappedText) > maxBytes {
		t.Errorf("capped text length %d exceeds cap %d", len(cappedText), maxBytes)
	}
	if !strings.Contains(cappedText, `"truncated":true`) {
		t.Errorf("capped text missing truncated marker: %s", cappedText[max(0, len(cappedText)-64):])
	}
}

// --- splitPkgSpec --------------------------------------------------------

func TestSplitPkgSpec(t *testing.T) {
	tests := []struct {
		name        string
		in          string
		wantName    string
		wantVersion string
	}{
		{"unscoped no version", "lodash", "lodash", ""},
		{"unscoped with version", "lodash@4.17.21", "lodash", "4.17.21"},
		{"scoped no version", "@scope/pkg", "@scope/pkg", ""},
		{"scoped with version", "@scope/pkg@1.2.3", "@scope/pkg", "1.2.3"},
		{"scoped with tag", "@scope/pkg@latest", "@scope/pkg", "latest"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotName, gotVersion := splitPkgSpec(tt.in)
			if gotName != tt.wantName || gotVersion != tt.wantVersion {
				t.Errorf("splitPkgSpec(%q) = (%q, %q), want (%q, %q)",
					tt.in, gotName, gotVersion, tt.wantName, tt.wantVersion)
			}
		})
	}
}
