/*
Copyright (c) 2026 Security Research
*/
package frida

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// errSymlinkReject mirrors the policy in pkg/knowledge/atomic.go (T-09-03).
var errSymlinkReject = errors.New("frida: symlink target rejected")

// WriteMarkdown renders a ValidationReport as a Markdown report and writes it
// atomically to outPath. Severity badges are text-only per D-23.
func WriteMarkdown(report *ValidationReport, outPath string) error {
	if report == nil {
		return fmt.Errorf("nil report")
	}
	abs, err := sanitizePath(outPath)
	if err != nil {
		return fmt.Errorf("sanitize out path: %w", err)
	}
	md := RenderMarkdown(report)
	if werr := writeFileAtomicLocal(abs, []byte(md), 0o644); werr != nil {
		return fmt.Errorf("write markdown: %w", werr)
	}
	return nil
}

// writeFileAtomicLocal mirrors knowledge.WriteFileAtomic semantics without
// creating an import cycle (pkg/knowledge -> pkg/dissect -> pkg/frida).
// T-09-03: temp+rename + symlink reject; path-traversal handled by caller.
func writeFileAtomicLocal(path string, data []byte, perm os.FileMode) error {
	if info, err := os.Lstat(path); err == nil {
		if info.Mode()&os.ModeSymlink != 0 {
			return errSymlinkReject
		}
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("mkdir parent: %w", err)
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, perm); err != nil {
		return fmt.Errorf("write tmp: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("rename: %w", err)
	}
	return nil
}

// RenderMarkdown returns the Markdown representation of a ValidationReport.
// Exposed separately so tests can scan the rendered text without writing to disk.
func RenderMarkdown(report *ValidationReport) string {
	var b strings.Builder

	pkg := report.PackageName
	if pkg == "" {
		pkg = "unknown"
	}

	fmt.Fprintf(&b, "# Frida Validation Report — %s\n\n", pkg)
	fmt.Fprintf(&b, "Capture: `%s`  ·  Criteria: `%s`\n\n", report.CapturePath, report.CriteriaPath)

	b.WriteString("## Summary\n\n")
	fmt.Fprintf(&b, "- Total criteria: %d\n", report.Summary.Total)
	fmt.Fprintf(&b, "- **[BLOCK]**: %d  ·  **[FLAG]**: %d  ·  **[PASS]**: %d\n\n",
		report.Summary.Block, report.Summary.Flag, report.Summary.Pass)

	b.WriteString("## Findings\n\n")
	if len(report.Findings) == 0 {
		b.WriteString("_No findings._\n")
		return b.String()
	}

	b.WriteString("| Severity | Hook | Operator | Expected | Observed | Message |\n")
	b.WriteString("|----------|------|----------|----------|----------|---------|\n")
	for _, f := range report.Findings {
		fmt.Fprintf(&b, "| **[%s]** | `%s` | `%s` | %s | %s | %s |\n",
			f.Severity,
			escapeMD(f.HookID),
			escapeMD(f.Operator),
			escapeMD(stringifyValue(f.Expected)),
			escapeMD(stringifyValue(f.Observed)),
			escapeMD(f.Message),
		)
	}
	b.WriteString("\n")

	// Per-finding sections for BLOCK/FLAG callouts.
	for _, f := range report.Findings {
		if f.Severity == SeverityPass {
			continue
		}
		fmt.Fprintf(&b, "### **[%s]** %s\n", f.Severity, f.HookID)
		fmt.Fprintf(&b, "- Operator: `%s`\n", f.Operator)
		if f.Expected != nil {
			fmt.Fprintf(&b, "- Expected: %s\n", stringifyValue(f.Expected))
		}
		if f.Observed != nil {
			fmt.Fprintf(&b, "- Observed: %s\n", stringifyValue(f.Observed))
		}
		if f.Message != "" {
			fmt.Fprintf(&b, "- Note: %s\n", f.Message)
		}
		b.WriteString("\n")
	}

	return b.String()
}

// escapeMD performs minimal escaping for table cells: replace pipe and newline.
func escapeMD(s string) string {
	if s == "" {
		return "—"
	}
	s = strings.ReplaceAll(s, "|", `\|`)
	s = strings.ReplaceAll(s, "\n", " ")
	return s
}
