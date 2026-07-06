/*
Copyright (c) 2026 Security Research
*/
package claude

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// TestWriteAssetsRoundtrip writes the rendered plugin to a tempdir and
// verifies the required files all landed.
func TestWriteAssetsRoundtrip(t *testing.T) {
	dir := t.TempDir()
	n, err := WriteAssets(dir)
	if err != nil {
		t.Fatalf("WriteAssets: %v", err)
	}
	if n < 9 {
		t.Fatalf("expected >=9 files written, got %d", n)
	}
	required := []string{
		".claude-plugin/plugin.json",
		".mcp.json",
		"commands/enrich.md",
		"commands/doctor.md",
		"commands/help.md",
		"skills/enrich/SKILL.md",
		"skills/kb/SKILL.md",
		"agents/unravel-enricher.md",
	}
	for _, r := range required {
		if _, err := os.Stat(filepath.Join(dir, r)); err != nil {
			t.Errorf("required file missing: %s (%v)", r, err)
		}
	}
}

// TestPatchSettingsPreservesUnrelatedKeys verifies the settings.json
// patcher only touches enabledPlugins[<our key>].
func TestPatchSettingsPreservesUnrelatedKeys(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("USERPROFILE", tmp)
	t.Setenv("HOME", tmp)

	settingsPath := filepath.Join(tmp, ".claude", "settings.json")
	if err := os.MkdirAll(filepath.Dir(settingsPath), 0o755); err != nil {
		t.Fatal(err)
	}
	pre := map[string]any{
		"theme":       "dark",
		"effortLevel": "medium",
		"enabledPlugins": map[string]any{
			"some-other@marketplace": true,
		},
		"customKey": "must-survive",
	}
	preBytes, _ := json.Marshal(pre)
	if err := os.WriteFile(settingsPath, preBytes, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := PatchSettings(); err != nil {
		t.Fatalf("PatchSettings: %v", err)
	}
	raw, _ := os.ReadFile(settingsPath)
	var post map[string]any
	if err := json.Unmarshal(raw, &post); err != nil {
		t.Fatalf("post parse: %v", err)
	}
	if post["theme"] != "dark" || post["customKey"] != "must-survive" || post["effortLevel"] != "medium" {
		t.Errorf("unrelated keys mutated: %v", post)
	}
	enabled := post["enabledPlugins"].(map[string]any)
	if enabled["some-other@marketplace"] != true {
		t.Errorf("unrelated enabledPlugins entry lost: %v", enabled)
	}
	if enabled[pluginEnabledKey] != true {
		t.Errorf("expected enabledPlugins[%q]=true, got %v", pluginEnabledKey, enabled[pluginEnabledKey])
	}
}

// TestPatchMarketplaceCreatesAndUpdates verifies own-marketplace
// creation + idempotent re-run.
func TestPatchMarketplaceCreatesAndUpdates(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("USERPROFILE", tmp)
	t.Setenv("HOME", tmp)

	if err := PatchMarketplace(); err != nil {
		t.Fatalf("create: %v", err)
	}
	if !MarketplaceHasEntry() {
		t.Fatal("entry not present after create")
	}
	if err := PatchMarketplace(); err != nil {
		t.Fatalf("idempotent: %v", err)
	}
	path, _ := marketplaceJSONPath()
	raw, _ := os.ReadFile(path)
	var doc map[string]any
	_ = json.Unmarshal(raw, &doc)
	if doc["name"] != "unravel" {
		t.Errorf("marketplace name: got %v want unravel", doc["name"])
	}
	plugins, _ := doc["plugins"].([]any)
	if len(plugins) != 1 {
		t.Errorf("expected exactly 1 plugin, got %d", len(plugins))
	}
}

// TestManifestParses verifies the synthesised plugin manifest is valid.
func TestManifestParses(t *testing.T) {
	m, err := Manifest()
	if err != nil {
		t.Fatal(err)
	}
	if m.Name != "unravel" || m.Version == "" {
		t.Errorf("manifest: %+v", m)
	}
}

// TestWalkYieldsAssets confirms the asset registry has the expected count.
func TestWalkYieldsAssets(t *testing.T) {
	n := 0
	err := Walk(func(_ string, _ []byte) error { n++; return nil })
	if err != nil {
		t.Fatal(err)
	}
	if n < 9 {
		t.Errorf("expected >=9 assets, got %d", n)
	}
}

// TestPluginMcpJson_HasNoUnravelServer asserts the plugin .mcp.json
// does not register the unravel MCP server (CLI-first doctrine).
func TestPluginMcpJson_HasNoUnravelServer(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "..", "assets", "plugin", ".mcp.json"))
	if err != nil {
		t.Fatalf("read plugin .mcp.json: %v", err)
	}
	var doc map[string]any
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatalf("parse: %v", err)
	}
	servers, _ := doc["mcpServers"].(map[string]any)
	if _, ok := servers["unravel"]; ok {
		t.Fatal("plugin .mcp.json must NOT register the unravel MCP server (CLI-first doctrine)")
	}
}
