/*
Copyright (c) 2026 Security Research
*/

// Package codex implements the unravel plugin for OpenAI Codex CLI.
// Layout mirrors Claude Code closely: `.codex-plugin/plugin.json` +
// `.mcp.json` (spec form) + `skills/<name>/SKILL.md`. Personal install
// path is `~/.codex/plugins/<name>/`; marketplace registration lives
// at `~/.agents/plugins/marketplace.json`.
//
// Source: https://developers.openai.com/codex/plugins/build
package codex

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/inovacc/unravel-oss/pkg/aihost"
	claude "github.com/inovacc/unravel-oss/pkg/aihost/claude"
)

func init() { aihost.Register(func() aihost.Host { return Host{} }) }

// Identity / runtime consts mirror claude package — Codex consumes the
// same MCP server binary and the same enrich skill.
const (
	Name        = "unravel"
	Version     = claude.Version
	Description = claude.Description
	McpCommand  = claude.McpCommand
)

// Host satisfies aihost.Host for Codex CLI.
type Host struct{}

func (Host) Name() string { return "codex" }

func (Host) InstallTarget() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("resolve home: %w", err)
	}
	return filepath.Join(home, ".codex", "plugins", Name), nil
}

// Walk yields the bundled enrich skill plus the synthesized command/agent
// library skills — codex has no native commands/agents surface analogue, so
// the libraries keep those discoverable as skills.
func (Host) Walk(fn func(path string, data []byte) error) error {
	td := aihost.TemplateData{Name: Name, Version: Version, Description: Description, McpCommand: McpCommand}
	skill, ok := aihost.AssetByPath(aihost.KindSkill, "skills/enrich/SKILL.md")
	if !ok {
		return fmt.Errorf("codex: missing source skill enrich/SKILL.md in shared registry")
	}
	body, err := skill.Render(td)
	if err != nil {
		return fmt.Errorf("render skill: %w", err)
	}
	if err := fn("skills/enrich/SKILL.md", body); err != nil {
		return err
	}
	// Portable command/agent libraries keep commands+agents discoverable on a
	// skills-only host (codex has no native command/agent surface).
	for _, lib := range aihost.PortableLibrarySkills() {
		lb, err := lib.Render(td)
		if err != nil {
			return fmt.Errorf("render %s: %w", lib.Path, err)
		}
		if err := fn(lib.Path, lb); err != nil {
			return err
		}
	}
	return nil
}

// ManifestFiles returns .codex-plugin/plugin.json + .mcp.json bytes.
func (Host) ManifestFiles() (map[string][]byte, error) {
	pj, err := pluginJSON()
	if err != nil {
		return nil, err
	}
	mj, err := mcpJSON()
	if err != nil {
		return nil, err
	}
	return map[string][]byte{
		".codex-plugin/plugin.json": pj,
		".mcp.json":                 mj,
	}, nil
}

func pluginJSON() ([]byte, error) {
	doc := map[string]any{
		"name":        Name,
		"version":     Version,
		"description": Description,
		"author":      map[string]any{"name": "Security Research"},
		"license":     "BSD-3-Clause",
		"skills":      "skills",
		"mcpServers":  ".mcp.json",
	}
	return marshalIndent(doc)
}

func mcpJSON() ([]byte, error) {
	doc := map[string]any{
		"mcpServers": map[string]any{
			Name: map[string]any{
				"command": McpCommand,
				"args":    []string{"mcp"},
			},
		},
	}
	return marshalIndent(doc)
}

// Install writes rendered assets + manifest files to target. Atomic
// tmp+rename per file. Returns count written. Marketplace registration
// (~/.agents/plugins/marketplace.json) is left to the user for now —
// auto-registration ships when codex CLI exposes a stable add command.
func (h Host) Install(target string) (int, error) {
	if target == "" {
		return 0, fmt.Errorf("codex install: target must not be empty")
	}
	if err := os.MkdirAll(target, 0o755); err != nil {
		return 0, fmt.Errorf("codex mkdir target: %w", err)
	}
	count := 0
	writeOne := func(rel string, data []byte) error {
		dst := filepath.Join(target, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
			return err
		}
		tmp := dst + ".tmp"
		if err := os.WriteFile(tmp, data, 0o644); err != nil {
			return err
		}
		if err := os.Rename(tmp, dst); err != nil {
			return err
		}
		count++
		return nil
	}
	if err := h.Walk(writeOne); err != nil {
		return count, err
	}
	mf, err := h.ManifestFiles()
	if err != nil {
		return count, err
	}
	for rel, data := range mf {
		if err := writeOne(rel, data); err != nil {
			return count, err
		}
	}
	if err := h.PatchMarketplace(target); err != nil {
		fmt.Fprintf(os.Stderr, "[codex] marketplace.json patch failed: %v\n", err)
		fmt.Fprintf(os.Stderr, "[codex] manual fix: add %q entry to ~/.agents/plugins/marketplace.json\n", Name)
	}
	return count, nil
}

// PatchMarketplace patches ~/.agents/plugins/marketplace.json with a
// "local" source pointing at the installed target. Best-effort: emits
// a manual hint if the file cannot be written. Safe to call repeatedly
// (idempotent: replaces existing entry with same name).
func (h Host) PatchMarketplace(target string) error {
	home, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("codex resolve home: %w", err)
	}
	mpPath := filepath.Join(home, ".agents", "plugins", "marketplace.json")
	if err := os.MkdirAll(filepath.Dir(mpPath), 0o755); err != nil {
		return fmt.Errorf("codex mkdir marketplace: %w", err)
	}

	var doc map[string]any
	if raw, err := os.ReadFile(mpPath); err == nil {
		_ = json.Unmarshal(raw, &doc)
	}
	if doc == nil {
		doc = map[string]any{"name": "local-codex", "plugins": []any{}}
	}
	plugins, _ := doc["plugins"].([]any)
	kept := plugins[:0]
	for _, p := range plugins {
		if entry, ok := p.(map[string]any); ok && entry["name"] == Name {
			continue
		}
		kept = append(kept, p)
	}
	kept = append(kept, map[string]any{
		"name": Name,
		"source": map[string]any{
			"source": "local",
			"path":   target,
		},
		"policy": map[string]any{
			"installation":   "AVAILABLE",
			"authentication": "ON_INSTALL",
		},
		"category": "developer-tools",
	})
	doc["plugins"] = kept

	out, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return err
	}
	out = append(out, '\n')
	tmp := mpPath + ".tmp"
	if err := os.WriteFile(tmp, out, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, mpPath)
}

// Uninstall removes the install target directory wholesale.
func (Host) Uninstall(target string) error {
	if target == "" {
		return fmt.Errorf("codex uninstall: target must not be empty")
	}
	if err := os.RemoveAll(target); err != nil {
		return fmt.Errorf("codex rm %s: %w", target, err)
	}
	return nil
}

// PrintStatus writes a one-block status report.
func (h Host) PrintStatus(w *os.File) error {
	target, err := h.InstallTarget()
	if err != nil {
		return err
	}
	exists := false
	if info, err := os.Stat(target); err == nil && info.IsDir() {
		exists = true
	}
	fmt.Fprintf(w, "host          : %s\n", h.Name())
	fmt.Fprintf(w, "install target: %s\n", target)
	fmt.Fprintf(w, "target exists : %v\n", exists)
	fmt.Fprintf(w, "manifest      : .codex-plugin/plugin.json + .mcp.json\n")
	fmt.Fprintf(w, "marketplace   : manual — add to ~/.agents/plugins/marketplace.json\n")
	return nil
}

func marshalIndent(v any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
