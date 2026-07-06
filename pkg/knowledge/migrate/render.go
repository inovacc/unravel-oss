/*
Copyright (c) 2026 Security Research
*/
package migrate

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"text/template"
)

// MigrationHint is the structured per-component migration record (D-05).
//
// Field names mirror the on-disk JSON schema verbatim — JSON tags are NOT
// renamed. SchemaVersion is always 1 in this phase.
type MigrationHint struct {
	SchemaVersion int               `json:"schema_version"`
	Component     string            `json:"component"`
	Framework     string            `json:"framework"`
	Role          string            `json:"role"`
	Inputs        []string          `json:"inputs"`
	Outputs       []string          `json:"outputs"`
	SideEffects   []string          `json:"side_effects"`
	Equivalents   map[string]string `json:"equivalents"`
}

// templateFile is a single file passed into the prompt template's `range`.
type templateFile struct {
	Path    string
	Content string
}

// templateData backs the migration.md template variables.
type templateData struct {
	Framework string
	Component string
	Files     []templateFile
}

// renderPrompt renders the embedded migration.md template with the supplied
// data. Sentinels `<<<USER_SOURCE_BEGIN>>>` / `<<<USER_SOURCE_END>>>` are
// preserved verbatim from the template (T-07-03).
func renderPrompt(d templateData) (string, error) {
	t, err := template.New("migration").Parse(promptTemplate)
	if err != nil {
		return "", fmt.Errorf("parse migration template: %w", err)
	}
	var buf bytes.Buffer
	if err := t.Execute(&buf, d); err != nil {
		return "", fmt.Errorf("execute migration template: %w", err)
	}
	return buf.String(), nil
}

// errPathTraversal is returned when a write target resolves outside the
// expected KB tree (T-07-01). Mirrors pkg/knowledge.errPathTraversal but
// kept package-local to avoid an import cycle with pkg/knowledge.
var errPathTraversal = errors.New("migrate: path traversal rejected")

// writeFileAtomic writes data to path via temp+rename. Refuses any path with
// a `..` segment after slash-normalisation. Refuses to follow an existing
// symlink at the destination.
func writeFileAtomic(path string, data []byte, perm os.FileMode) error {
	for _, seg := range strings.Split(filepath.ToSlash(path), "/") {
		if seg == ".." {
			return errPathTraversal
		}
	}
	abs, err := filepath.Abs(filepath.Clean(path))
	if err != nil {
		return fmt.Errorf("resolve abs: %w", err)
	}
	if info, err := os.Lstat(abs); err == nil {
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("migrate: refusing to overwrite symlink %s", abs)
		}
	}
	if err := os.MkdirAll(filepath.Dir(abs), 0o755); err != nil {
		return fmt.Errorf("mkdir parent: %w", err)
	}
	tmp := abs + ".tmp"
	if err := os.WriteFile(tmp, data, perm); err != nil {
		return fmt.Errorf("write tmp: %w", err)
	}
	if err := os.Rename(tmp, abs); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("rename: %w", err)
	}
	return nil
}

// writeJSONAtomic marshals v with indented JSON and writes via writeFileAtomic.
func writeJSONAtomic(path string, v any) error {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal json: %w", err)
	}
	return writeFileAtomic(path, data, 0o644)
}

// writeHint emits both migration.json and summary.md for a single
// (component, framework) under dir. dir is created with 0o755 if missing.
func writeHint(hint MigrationHint, dir string) error {
	if err := writeJSONAtomic(filepath.Join(dir, "migration.json"), hint); err != nil {
		return fmt.Errorf("write migration.json: %w", err)
	}
	summary := buildSummary(hint)
	if err := writeFileAtomic(filepath.Join(dir, "summary.md"), []byte(summary), 0o644); err != nil {
		return fmt.Errorf("write summary.md: %w", err)
	}
	return nil
}

// buildSummary produces a short Markdown summary (≤ 5 sentences) from the
// structured hint. The 5-sentence cap is enforced by deliberate construction
// — never more than five `. ` boundaries are inserted by this function.
func buildSummary(h MigrationHint) string {
	var b strings.Builder
	b.WriteString("# Migration: ")
	b.WriteString(h.Component)
	b.WriteString(" -> ")
	b.WriteString(h.Framework)
	b.WriteString("\n\n")

	role := strings.TrimSpace(h.Role)
	if role == "" {
		role = "Component role not extracted."
	}
	if !strings.HasSuffix(role, ".") {
		role += "."
	}
	b.WriteString(role)
	b.WriteString(" ")

	if len(h.Inputs) > 0 {
		b.WriteString("Primary input: ")
		b.WriteString(h.Inputs[0])
		b.WriteString(". ")
	}
	if len(h.Outputs) > 0 {
		b.WriteString("Primary output: ")
		b.WriteString(h.Outputs[0])
		b.WriteString(". ")
	}
	if len(h.SideEffects) > 0 {
		b.WriteString("Observable side effect: ")
		b.WriteString(h.SideEffects[0])
		b.WriteString(". ")
	}
	if eq, ok := h.Equivalents[h.Framework]; ok && eq != "" {
		b.WriteString("Equivalent in ")
		b.WriteString(h.Framework)
		b.WriteString(": ")
		b.WriteString(eq)
		if !strings.HasSuffix(eq, ".") {
			b.WriteString(".")
		}
	}
	b.WriteString("\n")
	return b.String()
}
