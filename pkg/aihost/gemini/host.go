/*
Copyright (c) 2026 Security Research
*/

// Package gemini implements the unravel plugin for Google's Gemini CLI.
// Layout: `gemini-extension.json` at extension root (NOT under a
// `.gemini-extension/` subdir) with `mcpServers` embedded; skills live
// at `skills/<name>/SKILL.md`. Install path is
// `~/.gemini/extensions/<name>/`. Custom commands are TOML (different
// format from Claude markdown) — omitted for now; only the skill +
// MCP server are exposed.
//
// Source: https://github.com/google-gemini/gemini-cli/tree/main/docs/extensions
package gemini

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/inovacc/unravel-oss/pkg/aihost"
	claude "github.com/inovacc/unravel-oss/pkg/aihost/claude"
)

func init() { aihost.Register(func() aihost.Host { return Host{} }) }

const (
	Name        = "unravel"
	Version     = claude.Version
	Description = claude.Description
	McpCommand  = claude.McpCommand
)

// Host satisfies aihost.Host for Gemini CLI.
type Host struct{}

func (Host) Name() string { return "gemini" }

func (Host) InstallTarget() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("resolve home: %w", err)
	}
	return filepath.Join(home, ".gemini", "extensions", Name), nil
}

// Walk yields the bundled enrich skill plus the synthesized command/agent
// library skills — Gemini's native commands are TOML (not MD) and it has no
// native agent surface, so the libraries keep those discoverable as skills.
func (Host) Walk(fn func(path string, data []byte) error) error {
	td := aihost.TemplateData{Name: Name, Version: Version, Description: Description, McpCommand: McpCommand}
	skill, ok := aihost.AssetByPath(aihost.KindSkill, "skills/enrich/SKILL.md")
	if !ok {
		return fmt.Errorf("gemini: missing source skill enrich/SKILL.md in shared registry")
	}
	body, err := skill.Render(td)
	if err != nil {
		return fmt.Errorf("render skill: %w", err)
	}
	if err := fn("skills/enrich/SKILL.md", body); err != nil {
		return err
	}
	// Portable command/agent libraries keep commands+agents discoverable on a
	// skills-only host (Gemini has no native command/agent surface).
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

// ManifestFiles returns gemini-extension.json (mcpServers embedded
// inline — no separate .mcp.json on this host).
func (Host) ManifestFiles() (map[string][]byte, error) {
	mj, err := extensionJSON()
	if err != nil {
		return nil, err
	}
	return map[string][]byte{
		"gemini-extension.json": mj,
		"GEMINI.md":             []byte(geminiContext()),
	}, nil
}

// Install writes rendered assets + manifest files to target. Atomic
// tmp+rename per file. Returns count written. Auto-register via
// `gemini extensions install <target>` is left to the user for now;
// the CLI invocation will land alongside marketplace registration in
// a follow-up commit.
func (h Host) Install(target string) (int, error) {
	if target == "" {
		return 0, fmt.Errorf("gemini install: target must not be empty")
	}
	if err := os.MkdirAll(target, 0o755); err != nil {
		return 0, fmt.Errorf("gemini mkdir target: %w", err)
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
	registerViaCLI(target)
	return count, nil
}

// registerViaCLI shells out `gemini extensions install <target>` so the
// CLI indexes our extension. Best-effort: prints a manual hint if the
// gemini binary is not on PATH or the registration sub-call fails.
func registerViaCLI(target string) {
	bin, err := exec.LookPath("gemini")
	if err != nil {
		fmt.Fprintf(os.Stderr, "[gemini] gemini CLI not on PATH — run manually:\n  gemini extensions install %q\n", target)
		return
	}
	out, err := exec.Command(bin, "extensions", "install", target).CombinedOutput()
	if err != nil {
		fmt.Fprintf(os.Stderr, "[gemini] extensions install said: %s (err: %v)\n", string(out), err)
		return
	}
	fmt.Fprintln(os.Stderr, "[gemini] registered via gemini extensions install")
}

// Uninstall removes the install target directory wholesale.
func (Host) Uninstall(target string) error {
	if target == "" {
		return fmt.Errorf("gemini uninstall: target must not be empty")
	}
	if err := os.RemoveAll(target); err != nil {
		return fmt.Errorf("gemini rm %s: %w", target, err)
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
	fmt.Fprintf(w, "manifest      : gemini-extension.json (mcpServers inline) + GEMINI.md\n")
	fmt.Fprintf(w, "register      : manual — `gemini extensions install <target>` or symlink\n")
	return nil
}

func extensionJSON() ([]byte, error) {
	doc := map[string]any{
		"name":            Name,
		"version":         Version,
		"description":     Description,
		"contextFileName": "GEMINI.md",
		"mcpServers": map[string]any{
			Name: map[string]any{
				"command": McpCommand,
				"args":    []string{"mcp"},
			},
		},
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetIndent("", "  ")
	if err := enc.Encode(doc); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// geminiContext returns the GEMINI.md context file loaded at session
// start. It fetches the unified conversion & analysis context from
// the shared registry.
func geminiContext() string {
	asset, ok := aihost.AssetByPath(aihost.KindSkill, "skills/transpile/GEMINI.md")
	if !ok {
		return "# unravel\n\nMissing context asset skills/transpile/GEMINI.md"
	}
	return asset.Body
}
