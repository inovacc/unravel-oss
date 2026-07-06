/*
Copyright (c) 2026 Security Research

Per CONTEXT D-28, the sentinel literals are re-declared locally rather than
imported from pkg/knowledge/migrate (avoids a cross-package coupling for two
short string constants that exist independently in each call site).
*/
package enrich

import (
	"bytes"
	"text/template"

	"github.com/inovacc/unravel-oss/internal/ai/prompts"
)

// Sentinel boundaries (Phase 9 D-18 / T-09-01) — re-declared locally per
// CONTEXT D-28. Any user-supplied content fed to MCP MUST be wrapped between
// these tokens.
const (
	UserSourceBegin = "<<<USER_SOURCE_BEGIN>>>"
	UserSourceEnd   = "<<<USER_SOURCE_END>>>"
)

// promptData backs the frida.md template variables.
type promptData struct {
	Script           string
	DecompiledSource string
}

// renderPrompt renders the embedded frida.md template against scriptBody and
// the optional decompiled-source bundle. The sentinels in frida.md ensure
// every user-supplied chunk is bracketed.
func renderPrompt(scriptBody, decompiled string) string {
	tmpl, err := template.New("frida-enrich").Parse(prompts.FridaPrompt())
	if err != nil {
		// Programming error — caught by tests at package-init.
		return ""
	}
	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, promptData{
		Script:           scriptBody,
		DecompiledSource: decompiled,
	}); err != nil {
		return ""
	}
	return buf.String()
}
