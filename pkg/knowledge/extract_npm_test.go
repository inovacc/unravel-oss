package knowledge

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/inovacc/unravel-oss/pkg/dissect"
	"github.com/inovacc/unravel-oss/pkg/npm"
)

func TestExtractNPMKnowledge(t *testing.T) {
	dir := t.TempDir()
	writeNPMFixture(t, filepath.Join(dir, "package.json"), `{
		"name": "@scope/tool",
		"version": "1.0.0",
		"description": "fixture cli",
		"homepage": "https://example.com/tool",
		"repository": {"type": "git", "url": "git+https://github.com/example/tool.git"},
		"license": "MIT",
		"bin": {"tool": "bin/tool.js"},
		"scripts": {"postinstall": "node scripts/postinstall.js"},
		"dependencies": {"axios": "^1.0.0"},
		"devDependencies": {"typescript": "^5.0.0"}
	}`)
	writeNPMFixture(t, filepath.Join(dir, "bin", "tool.js"), `#!/usr/bin/env node
fetch("https://api.example.com/v1")
`)
	writeNPMFixture(t, filepath.Join(dir, "scripts", "postinstall.js"), `require("child_process").exec("node -v")`)

	analysis, err := npm.Analyze(dir)
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	kr := Extract(&dissect.DissectResult{
		Path:        dir,
		FileName:    "tool",
		NPMAnalysis: analysis,
	})

	if kr.Framework != "npm" {
		t.Fatalf("Framework = %q, want npm", kr.Framework)
	}
	if kr.NPM == nil {
		t.Fatal("NPM knowledge missing")
	}
	if kr.NPM.Repository != "https://github.com/example/tool" {
		t.Fatalf("Repository = %q", kr.NPM.Repository)
	}
	if kr.NPM.SourceMode != "github-repository" {
		t.Fatalf("SourceMode = %q", kr.NPM.SourceMode)
	}
	if kr.NPM.RiskScore == 0 {
		t.Fatal("RiskScore = 0, want npm analysis risk propagated")
	}
	if len(kr.NPM.NetworkCalls) == 0 {
		t.Fatal("NetworkCalls empty")
	}
	if kr.Communication == nil || len(kr.Communication.Endpoints) == 0 {
		t.Fatal("Communication endpoints empty")
	}
	if kr.Communication.Endpoints[0].URL != "https://api.example.com/v1" {
		t.Fatalf("endpoint URL = %q", kr.Communication.Endpoints[0].URL)
	}
	if len(kr.SourceFiles) < 3 {
		t.Fatalf("SourceFiles = %d, want package, bin, and postinstall sources", len(kr.SourceFiles))
	}
	for _, sf := range kr.SourceFiles {
		if sf.Content == nil {
			t.Fatalf("SourceFile %s has nil Content", sf.Path)
		}
	}
}

func writeNPMFixture(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
}
