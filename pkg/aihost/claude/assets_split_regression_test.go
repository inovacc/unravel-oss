/*
Copyright (c) 2026 Security Research
*/
package claude

import (
	"bytes"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/inovacc/unravel-oss/pkg/aihost"
	_ "github.com/inovacc/unravel-oss/pkg/aihost/assets/all"
)

// TestAssetsByPath_AllPresent fails if any expected Path goes missing
// during the split.
func TestAssetsByPath_AllPresent(t *testing.T) {
	wantPaths := []string{
		"agents/unravel-enricher.md",
		"agents/unravel-enricher-poly.md",
		"agents/unravel-dissector.md",
		"agents/unravel-self-healer.md",
		"agents/unravel-code-extractor.md",
		"agents/unravel-style-extractor.md",
		"agents/unravel-reassembler.md",
		"agents/unravel-mapper.md",
		"agents/unravel-cleanroom-porter.md",
		"agents/unravel-kb-builder.md",
		"agents/unravel-security-auditor.md",
		"agents/unravel-triage.md",
		"agents/unravel-resume.md",
		"agents/unravel-corpus-grower.md",
		"agents/unravel-cross-ref.md",
		"agents/unravel-kb-query.md",
		"agents/unravel-parity-tester.md",
		"agents/unravel-cve-scanner.md",
		"agents/unravel-transpiler.md",
		"agents/unravel-codebase-analyst.md",
		"agents/unravel-insights-analyst.md",
		"skills/enrich/SKILL.md",
		"skills/kb/SKILL.md",
		"commands/doctor.md",
		"commands/enrich.md",
		"commands/help.md",
		"commands/pending.md",
		"commands/retry.md",
		"commands/vendored.md",
		"commands/verify.md",
		"commands/build.md",
		"commands/dissect.md",
		"commands/heal.md",
		"commands/extract.md",
		"commands/style.md",
		"commands/reassemble.md",
		"commands/map.md",
		"commands/port.md",
		"commands/audit.md",
		"commands/triage.md",
		"commands/resume.md",
		"commands/grow.md",
		"commands/xref.md",
		"commands/query.md",
		"commands/parity.md",
		"commands/cve.md",
		"commands/transpile.md",
		"commands/analyze-code.md",
		"commands/insights.md",
		"commands/kb.md",
	}
	assets := aihost.AllAssets()
	have := make(map[string]bool, len(assets))
	for _, a := range assets {
		have[a.Path] = true
	}
	for _, p := range wantPaths {
		if !have[p] {
			t.Errorf("missing asset %q in registry", p)
		}
	}
}

// TestAssets_FrontmatterEndsWithNewline guards against a class of ship
// defect: Asset.Render() writes the closing "---\n" delimiter (and, for
// skills, may inject "created: ...\n") directly after executing
// a.Frontmatter verbatim, with no separating newline inserted. If a raw
// Frontmatter string literal does not itself end with "\n", the closing
// delimiter (or injected created line) merges onto the last frontmatter
// line, producing malformed YAML frontmatter in the shipped asset.
func TestAssets_FrontmatterEndsWithNewline(t *testing.T) {
	for _, a := range aihost.AllAssets() {
		if a.Frontmatter == "" {
			continue
		}
		if !strings.HasSuffix(a.Frontmatter, "\n") {
			t.Errorf("asset %q: Frontmatter does not end with a newline; Render() will merge the closing --- (or injected created: line) onto the last frontmatter line", a.Path)
		}
	}
}

// TestDissectAsset_NoMcpUnravelRefs ensures the dissect asset has been
// migrated to CLI-based commands and contains no MCP tool references.
func TestDissectAsset_NoMcpUnravelRefs(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "assets", "dissect", "dissect.go"))
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if bytes.Contains(data, []byte("mcp__unravel__")) || bytes.Contains(data, []byte("unravel_app_detect")) {
		t.Fatal("dissect asset must reference the CLI, not mcp__unravel__ tools")
	}
}

// TestCliSkill_Registered ensures the CLI-reference skill asset registers
// the unravel-cli skill so agents/commands know the `unravel <group> <verb>`
// command surface now that the plugin no longer registers MCP tools.
func TestCliSkill_Registered(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "assets", "cli", "cli.go"))
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if !bytes.Contains(data, []byte("skills/unravel-cli/SKILL.md")) {
		t.Fatal("cli asset must register the unravel-cli skill")
	}
}

// TestAssets_NoMcpUnravelRefsAnywhere is the repo-wide guard: no plugin
// asset file may reference mcp__unravel__ tools now that the plugin is
// CLI-first.
func TestAssets_NoMcpUnravelRefsAnywhere(t *testing.T) {
	root := filepath.Join("..", "assets")
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(p, ".go") {
			return err
		}
		data, rerr := os.ReadFile(p)
		if rerr != nil {
			return rerr
		}
		if bytes.Contains(data, []byte("mcp__unravel__")) {
			t.Errorf("%s still references mcp__unravel__ tools", p)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
