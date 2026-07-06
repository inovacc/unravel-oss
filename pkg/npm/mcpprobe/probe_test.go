/*
Copyright (c) 2026 Security Research
*/
package mcpprobe

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/inovacc/unravel-oss/pkg/npm"
)

func TestFindEntryPoint_BinField(t *testing.T) {
	dir := t.TempDir()

	// Write a package.json with bin field.
	pkg := map[string]any{
		"name":    "test-mcp-server",
		"version": "1.0.0",
		"bin": map[string]any{
			"test-mcp-server": "./dist/index.js",
		},
	}

	data, _ := json.Marshal(pkg)
	if err := os.WriteFile(filepath.Join(dir, "package.json"), data, 0o644); err != nil {
		t.Fatal(err)
	}

	parsed, err := npm.ParsePackageJSON(filepath.Join(dir, "package.json"))
	if err != nil {
		t.Fatal(err)
	}

	entry, err := findEntryPoint(dir, parsed)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if entry != "./dist/index.js" {
		t.Errorf("expected ./dist/index.js, got %s", entry)
	}
}

func TestFindEntryPoint_BinStringFormat(t *testing.T) {
	dir := t.TempDir()

	pkg := map[string]any{
		"name":    "my-server",
		"version": "2.0.0",
		"bin":     "./cli.js",
	}

	data, _ := json.Marshal(pkg)
	if err := os.WriteFile(filepath.Join(dir, "package.json"), data, 0o644); err != nil {
		t.Fatal(err)
	}

	parsed, err := npm.ParsePackageJSON(filepath.Join(dir, "package.json"))
	if err != nil {
		t.Fatal(err)
	}

	entry, err := findEntryPoint(dir, parsed)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if entry != "./cli.js" {
		t.Errorf("expected ./cli.js, got %s", entry)
	}
}

func TestFindEntryPoint_PrefersMCPBin(t *testing.T) {
	dir := t.TempDir()

	pkg := map[string]any{
		"name":    "multi-bin",
		"version": "1.0.0",
		"bin": map[string]any{
			"helper":     "./helper.js",
			"mcp-server": "./server.js",
		},
	}

	data, _ := json.Marshal(pkg)
	if err := os.WriteFile(filepath.Join(dir, "package.json"), data, 0o644); err != nil {
		t.Fatal(err)
	}

	parsed, err := npm.ParsePackageJSON(filepath.Join(dir, "package.json"))
	if err != nil {
		t.Fatal(err)
	}

	entry, err := findEntryPoint(dir, parsed)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if entry != "./server.js" {
		t.Errorf("expected ./server.js (mcp-server bin), got %s", entry)
	}
}

func TestFindEntryPoint_MainField(t *testing.T) {
	dir := t.TempDir()

	// Create the main file so stat succeeds.
	if err := os.WriteFile(filepath.Join(dir, "index.mjs"), []byte("// server"), 0o644); err != nil {
		t.Fatal(err)
	}

	pkg := map[string]any{
		"name":    "main-pkg",
		"version": "1.0.0",
		"main":    "index.mjs",
	}

	data, _ := json.Marshal(pkg)
	if err := os.WriteFile(filepath.Join(dir, "package.json"), data, 0o644); err != nil {
		t.Fatal(err)
	}

	parsed, err := npm.ParsePackageJSON(filepath.Join(dir, "package.json"))
	if err != nil {
		t.Fatal(err)
	}

	entry, err := findEntryPoint(dir, parsed)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if entry != "index.mjs" {
		t.Errorf("expected index.mjs, got %s", entry)
	}
}

func TestFindEntryPoint_FallbackCandidates(t *testing.T) {
	dir := t.TempDir()

	// Create a server.js as a fallback candidate.
	if err := os.WriteFile(filepath.Join(dir, "server.js"), []byte("// mcp server"), 0o644); err != nil {
		t.Fatal(err)
	}

	pkg := map[string]any{
		"name":    "no-bin-pkg",
		"version": "1.0.0",
	}

	data, _ := json.Marshal(pkg)
	if err := os.WriteFile(filepath.Join(dir, "package.json"), data, 0o644); err != nil {
		t.Fatal(err)
	}

	parsed, err := npm.ParsePackageJSON(filepath.Join(dir, "package.json"))
	if err != nil {
		t.Fatal(err)
	}

	entry, err := findEntryPoint(dir, parsed)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// index.js comes before server.js in the candidate list
	if entry != "server.js" {
		t.Errorf("expected server.js, got %s", entry)
	}
}

func TestFindEntryPoint_ScriptStart(t *testing.T) {
	dir := t.TempDir()

	pkg := map[string]any{
		"name":    "script-pkg",
		"version": "1.0.0",
		"scripts": map[string]any{
			"start": "node src/main.js --stdio",
		},
	}

	data, _ := json.Marshal(pkg)
	if err := os.WriteFile(filepath.Join(dir, "package.json"), data, 0o644); err != nil {
		t.Fatal(err)
	}

	parsed, err := npm.ParsePackageJSON(filepath.Join(dir, "package.json"))
	if err != nil {
		t.Fatal(err)
	}

	entry, err := findEntryPoint(dir, parsed)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if entry != "src/main.js" {
		t.Errorf("expected src/main.js, got %s", entry)
	}
}

func TestFindEntryPoint_NoEntryPoint(t *testing.T) {
	dir := t.TempDir()

	pkg := map[string]any{
		"name":    "empty-pkg",
		"version": "1.0.0",
	}

	data, _ := json.Marshal(pkg)
	if err := os.WriteFile(filepath.Join(dir, "package.json"), data, 0o644); err != nil {
		t.Fatal(err)
	}

	parsed, err := npm.ParsePackageJSON(filepath.Join(dir, "package.json"))
	if err != nil {
		t.Fatal(err)
	}

	_, err = findEntryPoint(dir, parsed)
	if err == nil {
		t.Fatal("expected error when no entry point found")
	}
}

func TestExtractFileFromScript(t *testing.T) {
	tests := []struct {
		name   string
		script string
		want   string
	}{
		{"node script", "node server.js", "server.js"},
		{"node with args", "node src/index.js --stdio", "src/index.js"},
		{"tsx script", "tsx src/main.ts", "src/main.ts"},
		{"mjs script", "node dist/index.mjs", "dist/index.mjs"},
		{"cjs script", "node dist/index.cjs", "dist/index.cjs"},
		{"no file", "echo hello", ""},
		{"empty", "", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractFileFromScript(tt.script)
			if got != tt.want {
				t.Errorf("extractFileFromScript(%q) = %q, want %q", tt.script, got, tt.want)
			}
		})
	}
}

func TestBuildCommand(t *testing.T) {
	dir := "/tmp/test-pkg"

	tests := []struct {
		name       string
		entry      string
		wantArgs   int
		wantHasAbs bool
	}{
		{"js file", "index.js", 1, true},
		{"mjs file", "dist/server.mjs", 1, true},
		{"ts file", "src/main.ts", 2, true}, // npx tsx <abs>
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd, args := buildCommand(dir, tt.entry)
			if cmd == "" {
				t.Error("command should not be empty")
			}

			if len(args) != tt.wantArgs {
				t.Errorf("expected %d args, got %d: %v", tt.wantArgs, len(args), args)
			}
		})
	}
}

func TestFormatToolList_Empty(t *testing.T) {
	result := &ProbeResult{
		PackageName:    "test-pkg",
		PackageVersion: "1.0.0",
		ServerName:     "test",
	}

	output := FormatToolList(result)
	if output != "No tools discovered." {
		t.Errorf("expected 'No tools discovered.', got %q", output)
	}
}

func TestFormatToolList_WithTools(t *testing.T) {
	result := &ProbeResult{
		PackageName:    "mcp-server-time",
		PackageVersion: "1.0.0",
		ServerName:     "time-server",
		ServerVersion:  "1.0.0",
		ProtocolVer:    "2024-11-05",
		Transport:      "stdio",
		EntryPoint:     "dist/index.js",
		TotalTools:     2,
		Duration:       500 * time.Millisecond,
		Tools: []ToolDetail{
			{Name: "get_time", Description: "Get current time"},
			{Name: "set_timezone", Description: "Set timezone"},
		},
	}

	output := FormatToolList(result)

	// Verify key content is present.
	for _, want := range []string{
		"time-server",
		"v1.0.0",
		"mcp-server-time@1.0.0",
		"dist/index.js",
		"stdio",
		"Total Tools:   2",
		"get_time",
		"set_timezone",
	} {
		if !contains(output, want) {
			t.Errorf("output missing %q", want)
		}
	}
}

func TestFormatToolList_Nil(t *testing.T) {
	output := FormatToolList(nil)
	if output != "No tools discovered." {
		t.Errorf("expected 'No tools discovered.', got %q", output)
	}
}

func TestProbeResult_JSON(t *testing.T) {
	result := &ProbeResult{
		PackageName:    "test-server",
		PackageVersion: "1.0.0",
		ServerName:     "test",
		Transport:      "stdio",
		EntryPoint:     "index.js",
		TotalTools:     1,
		Tools: []ToolDetail{
			{
				Name:        "hello",
				Description: "Say hello",
				InputSchema: json.RawMessage(`{"type":"object","properties":{"name":{"type":"string"}}}`),
			},
		},
	}

	data, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("unexpected marshal error: %v", err)
	}

	var parsed ProbeResult
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("unexpected unmarshal error: %v", err)
	}

	if parsed.PackageName != "test-server" {
		t.Errorf("expected package_name test-server, got %s", parsed.PackageName)
	}

	if len(parsed.Tools) != 1 {
		t.Fatalf("expected 1 tool, got %d", len(parsed.Tools))
	}

	if parsed.Tools[0].Name != "hello" {
		t.Errorf("expected tool name hello, got %s", parsed.Tools[0].Name)
	}

	if parsed.Tools[0].InputSchema == nil {
		t.Error("expected input schema to be preserved")
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && searchSubstring(s, substr)
}

func searchSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}

	return false
}
