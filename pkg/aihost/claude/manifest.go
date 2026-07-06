/*
Copyright (c) 2026 Security Research
*/

package claude

import (
	"encoding/json"
	"fmt"
)

// Single source of truth for plugin manifest metadata. Changing these
// values changes both the generated .claude-plugin/plugin.json and the
// PluginManifest returned by Manifest().
const (
	Name        = "unravel"
	Version     = "0.1.0"
	Description = "JS module reverse-engineering enrichment via Claude Code subagent fanout (Task tool) with Postgres-backed knowledge base."
	Author      = "Security Research"
	Repository  = "https://github.com/dyammarcano/unravel"
	License     = "BSD-3-Clause"

	// MCP server registration (.mcp.json). Command is the binary on PATH;
	// args are passed verbatim. Keep in sync with cmd/mcp.go subcommand.
	McpServerName = "unravel"
	McpCommand    = "unravel"
)

var (
	McpArgs  = []string{"mcp"}
	Keywords = []string{"reverse-engineering", "enrichment", "javascript", "minified", "deobfuscation", "knowledge-base"}
)

// PluginAuthor matches the object shape Claude Code's plugin loader
// requires: {"name": "..."} (string form fails manifest validation).
type PluginAuthor struct {
	Name string `json:"name"`
}

// PluginManifest mirrors .claude-plugin/plugin.json shape.
type PluginManifest struct {
	Name        string       `json:"name"`
	Version     string       `json:"version"`
	Description string       `json:"description"`
	Author      PluginAuthor `json:"author"`
	Repository  string       `json:"repository,omitempty"`
	License     string       `json:"license,omitempty"`
	Keywords    []string     `json:"keywords,omitempty"`
}

// Manifest returns plugin manifest synthesised from package consts.
func Manifest() (PluginManifest, error) {
	m := PluginManifest{
		Name:        Name,
		Version:     Version,
		Description: Description,
		Author:      PluginAuthor{Name: Author},
		Repository:  Repository,
		License:     License,
		Keywords:    Keywords,
	}
	if m.Name == "" || m.Version == "" {
		return PluginManifest{}, fmt.Errorf("plugin: const Name/Version empty")
	}
	return m, nil
}

// PluginJSON returns the bytes that should be written to
// .claude-plugin/plugin.json (pretty-printed, trailing newline).
func PluginJSON() ([]byte, error) {
	m, err := Manifest()
	if err != nil {
		return nil, err
	}
	b, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("marshal plugin.json: %w", err)
	}
	return append(b, '\n'), nil
}

// McpJSON returns the bytes that should be written to plugin's .mcp.json.
// Spec form: top-level "mcpServers" map.
func McpJSON() ([]byte, error) {
	doc := map[string]any{
		"mcpServers": map[string]any{
			McpServerName: map[string]any{
				"command": McpCommand,
				"args":    McpArgs,
			},
		},
	}
	b, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("marshal .mcp.json: %w", err)
	}
	return append(b, '\n'), nil
}

// GeneratedFiles returns map of path -> contents for files synthesised
// from Go consts (not embedded). writePluginAssets writes these alongside
// embedded markdown.
func GeneratedFiles() (map[string][]byte, error) {
	pj, err := PluginJSON()
	if err != nil {
		return nil, err
	}
	mj, err := McpJSON()
	if err != nil {
		return nil, err
	}
	hj, err := HooksJSON()
	if err != nil {
		return nil, err
	}
	return map[string][]byte{
		".claude-plugin/plugin.json": pj,
		".mcp.json":                  mj,
		// hooks/ is excluded from the install stale-sweep (install.go:71),
		// so shipping hooks.json here both writes it and preserves it across
		// reinstalls — same treatment as .mcp.json.
		"hooks/hooks.json": hj,
	}, nil
}

// CommandNames is defined in embed.go (derived from generatedAssets).
