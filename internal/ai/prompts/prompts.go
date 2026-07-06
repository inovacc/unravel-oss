/*
Copyright (c) 2026 Security Research
*/

// Package prompts is the embedded registry of AI prompts used by the
// unravel reconstruction pipeline. Each prompt is a single .md file
// committed beside this source file and loaded at runtime via embed.FS.
//
// Mirrors the pkg/knowledge/kb/prompts/ pattern verbatim so the home of
// every AI prompt in the codebase is consistent.
package prompts

import (
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
)

//go:embed *.md
var promptFS embed.FS

// Read returns the raw bytes of <name>.md from the embedded FS as a string.
func Read(name string) (string, error) {
	b, err := promptFS.ReadFile(name + ".md")
	if err != nil {
		return "", fmt.Errorf("read prompt %q: %w", name, err)
	}
	return string(b), nil
}

// CSharpPrompt returns the C# beautification prompt body. Panics if the
// embedded asset is missing — that is a programming error caught at
// package-init in tests.
func CSharpPrompt() string {
	s, err := Read("csharp")
	if err != nil {
		panic(fmt.Sprintf("prompts: missing csharp.md: %v", err))
	}
	return s
}

// JavaPrompt returns the Java beautification prompt body. Panics if the
// embedded asset is missing — that is a programming error caught at
// package-init in tests.
func JavaPrompt() string {
	s, err := Read("java")
	if err != nil {
		panic(fmt.Sprintf("prompts: missing java.md: %v", err))
	}
	return s
}

// JavaScriptPrompt returns the JavaScript beautification prompt body
// (Phase 6 / 06-02). Panics if the embedded asset is missing — that is a
// programming error caught at package-init in tests.
func JavaScriptPrompt() string {
	s, err := Read("javascript")
	if err != nil {
		panic(fmt.Sprintf("prompts: missing javascript.md: %v", err))
	}
	return s
}

// FridaPrompt returns the Frida script enrichment prompt body
// (Phase 9 / FRIDA-01 D-16). Panics if the embedded asset is missing —
// that is a programming error caught at package-init in tests.
func FridaPrompt() string {
	s, err := Read("frida")
	if err != nil {
		panic(fmt.Sprintf("prompts: missing frida.md: %v", err))
	}
	return s
}

// ExecutiveSummaryPrompt returns the forensic executive-summary prompt body
// (Phase 10 / RPT-04). Panics if the embedded asset is missing — that is a
// programming error caught at package-init in tests.
func ExecutiveSummaryPrompt() string {
	s, err := Read("executive-summary")
	if err != nil {
		panic(fmt.Sprintf("prompts: missing executive-summary.md: %v", err))
	}
	return s
}

// BundlePrompt returns the bundle module-boundary detection prompt body
// (Phase 6 / 06-03). Panics if the embedded asset is missing — that is
// a programming error caught at package-init in tests.
func BundlePrompt() string {
	s, err := Read("bundle")
	if err != nil {
		panic(fmt.Sprintf("prompts: missing bundle.md: %v", err))
	}
	return s
}

// PromptHash returns the lowercase hex sha256 of the rendered prompt body
// for <name>.md. Used to record provenance in manifest.json so re-runs
// after a prompt edit are detectable.
func PromptHash(name string) string {
	s, err := Read(name)
	if err != nil {
		// Hash of empty string is stable; surface error path via test.
		s = ""
	}
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// Names returns the slugs (filename-without-extension) of every embedded
// prompt, sorted. Diagnostic / discovery only.
func Names() []string {
	entries, err := promptFS.ReadDir(".")
	if err != nil {
		return nil
	}
	out := make([]string, 0, len(entries))
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".md") {
			continue
		}
		out = append(out, strings.TrimSuffix(e.Name(), ".md"))
	}
	sort.Strings(out)
	return out
}
