/*
Copyright (c) 2026 Security Research

diff_markdown.go — Markdown report renderer + atomic dual-emit (D-11).

Severity badges are TEXT-ONLY ([BLOCK] / [FLAG] / [PASS]) per CLAUDE.md
"no emojis" rule.
*/
package knowledge

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	visualdiff "github.com/inovacc/unravel-oss/pkg/capture/diff"
	"github.com/inovacc/unravel-oss/pkg/knowledge/regressions"
)

// RenderMarkdownReport returns a human-readable Markdown rendering of d.
func RenderMarkdownReport(d *DiffResult) string {
	var b strings.Builder
	b.WriteString("# KB Diff Report\n\n")
	fmt.Fprintf(&b, "- Old: `%s`\n", d.OldPath)
	fmt.Fprintf(&b, "- New: `%s`\n", d.NewPath)
	fmt.Fprintf(&b, "- Schema: %d\n\n", d.SchemaVersion)

	// Summary counts.
	var blocks, flags, passes int
	for _, r := range d.Regressions {
		switch r.Severity {
		case regressions.SeverityBlock:
			blocks++
		case regressions.SeverityFlag:
			flags++
		case regressions.SeverityPass:
			passes++
		}
	}
	b.WriteString("## Summary\n\n")
	fmt.Fprintf(&b, "**[BLOCK]** %d &nbsp;&nbsp; **[FLAG]** %d &nbsp;&nbsp; **[PASS]** %d\n\n",
		blocks, flags, passes)

	// Regression table.
	b.WriteString("## Regressions\n\n")
	if len(d.Regressions) == 0 {
		b.WriteString("_No regressions classified._\n\n")
	} else {
		b.WriteString("| ID | Dimension | Severity | Source | Message |\n")
		b.WriteString("|----|-----------|----------|--------|---------|\n")
		regs := append([]regressions.Regression(nil), d.Regressions...)
		sort.SliceStable(regs, func(i, j int) bool {
			return severityWeight(regs[i].Severity) < severityWeight(regs[j].Severity)
		})
		for _, r := range regs {
			fmt.Fprintf(&b, "| `%s` | %s | %s | %s | %s |\n",
				r.RuleID, r.Dimension, badge(r.Severity), r.Source, escapePipes(r.Message))
		}
		b.WriteString("\n")
	}

	// Per-dimension sections.
	if d.Permissions != nil {
		b.WriteString("## Permissions\n\n")
		writePermissions(&b, d.Permissions)
	}
	if d.SecurityConfig != nil {
		b.WriteString("## Security Config\n\n")
		writeSecurityConfig(&b, d.SecurityConfig)
	}
	if d.Structural != nil {
		b.WriteString("## Structural\n\n")
		writeStructural(&b, d.Structural)
	}
	if d.TextEquivalence != nil {
		b.WriteString("## Text Equivalence\n\n")
		writeTextEquivalence(&b, d.TextEquivalence)
	}

	// Phase 8 additive section. Only emitted when visual data is present.
	if d.Visual != nil {
		writeVisualRegressions(&b, d.Visual)
	}

	return b.String()
}

// visualBadge maps capture/diff Severity → markdown text-only badge (D-21).
func visualBadge(s visualdiff.Severity) string {
	switch s {
	case visualdiff.SeverityBLOCK:
		return "**[BLOCK]**"
	case visualdiff.SeverityFLAG:
		return "**[FLAG]**"
	case visualdiff.SeverityPASS:
		return "**[PASS]**"
	}
	return string(s)
}

func writeVisualRegressions(b *strings.Builder, vr *visualdiff.VisualResult) {
	b.WriteString("## Visual Regressions\n\n")
	if vr.Summary != "" {
		fmt.Fprintf(b, "%s\n\n", vr.Summary)
	}

	if len(vr.Added) > 0 {
		b.WriteString("### States Added\n\n")
		for _, s := range vr.Added {
			fmt.Fprintf(b, "- **[FLAG]** `%s`\n", s)
		}
		b.WriteString("\n")
	}
	if len(vr.Removed) > 0 {
		b.WriteString("### States Removed\n\n")
		for _, s := range vr.Removed {
			fmt.Fprintf(b, "- **[FLAG]** `%s`\n", s)
		}
		b.WriteString("\n")
	}
	if len(vr.States) > 0 {
		b.WriteString("### States Modified\n\n")
		keys := make([]string, 0, len(vr.States))
		for k := range vr.States {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			sd := vr.States[k]
			if sd == nil {
				continue
			}
			sev := sd.WorstSeverity()
			fmt.Fprintf(b, "- %s `%s`", visualBadge(sev), k)
			if sd.Image != nil {
				fmt.Fprintf(b, " image:sha256_match=%t,dist=%d", sd.Image.SHA256Match, sd.Image.HashDistance)
			}
			if sd.Tree != nil {
				fmt.Fprintf(b, " tree:+%d/-%d/~%d",
					len(sd.Tree.Added), len(sd.Tree.Removed), len(sd.Tree.Moved))
			}
			if sd.Layout != nil {
				fmt.Fprintf(b, " layout:%d-moved/%d-resized",
					len(sd.Layout.Movements), len(sd.Layout.SizeChanges))
			}
			b.WriteString("\n")
		}
		b.WriteString("\n")
	}
}

func badge(sev string) string {
	switch sev {
	case regressions.SeverityBlock:
		return "**[BLOCK]**"
	case regressions.SeverityFlag:
		return "**[FLAG]**"
	case regressions.SeverityPass:
		return "**[PASS]**"
	}
	return sev
}

func severityWeight(s string) int {
	switch s {
	case regressions.SeverityBlock:
		return 0
	case regressions.SeverityFlag:
		return 1
	case regressions.SeverityPass:
		return 2
	}
	return 3
}

func escapePipes(s string) string {
	return strings.ReplaceAll(s, "|", "\\|")
}

func writePermissions(b *strings.Builder, p *regressions.Permissions) {
	if len(p.AndroidAdded) > 0 {
		b.WriteString("**Android added:**\n\n")
		for _, perm := range p.AndroidAdded {
			marker := ""
			if perm.Dangerous {
				marker = " (dangerous)"
			}
			fmt.Fprintf(b, "- `%s`%s\n", perm.Name, marker)
		}
		b.WriteString("\n")
	}
	if len(p.AndroidRemoved) > 0 {
		b.WriteString("**Android removed:**\n\n")
		for _, perm := range p.AndroidRemoved {
			fmt.Fprintf(b, "- `%s`\n", perm.Name)
		}
		b.WriteString("\n")
	}
}

func writeSecurityConfig(b *strings.Builder, sc *regressions.SecurityConfig) {
	if len(sc.CSPAdditions) > 0 {
		b.WriteString("**CSP additions:**\n\n")
		for _, t := range sc.CSPAdditions {
			fmt.Fprintf(b, "- `%s`\n", t)
		}
		b.WriteString("\n")
	}
	if len(sc.CSPRemovals) > 0 {
		b.WriteString("**CSP removals:**\n\n")
		for _, t := range sc.CSPRemovals {
			fmt.Fprintf(b, "- `%s`\n", t)
		}
		b.WriteString("\n")
	}
	if len(sc.WebPrefsChanged) > 0 {
		b.WriteString("**webPreferences changed:**\n\n")
		keys := make([]string, 0, len(sc.WebPrefsChanged))
		for k := range sc.WebPrefsChanged {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			vc := sc.WebPrefsChanged[k]
			fmt.Fprintf(b, "- `%s`: `%v` -> `%v`\n", k, vc.Old, vc.New)
		}
		b.WriteString("\n")
	}
	if sc.CertPinningRemoved {
		b.WriteString("**Certificate pinning removed.**\n\n")
	}
}

func writeStructural(b *strings.Builder, s *regressions.Structural) {
	if s.TelemetryCountOld != s.TelemetryCountNew {
		fmt.Fprintf(b, "- Telemetry SDKs: %d -> %d\n", s.TelemetryCountOld, s.TelemetryCountNew)
	}
	if s.EndpointsCountOld != s.EndpointsCountNew {
		fmt.Fprintf(b, "- API endpoints: %d -> %d\n", s.EndpointsCountOld, s.EndpointsCountNew)
	}
	if len(s.TelemetryAdded) > 0 {
		fmt.Fprintf(b, "- Telemetry added: %s\n", strings.Join(s.TelemetryAdded, ", "))
	}
	if len(s.EndpointsAdded) > 0 {
		fmt.Fprintf(b, "- Endpoints added: %s\n", strings.Join(s.EndpointsAdded, ", "))
	}
	b.WriteString("\n")
}

func writeTextEquivalence(b *strings.Builder, te *regressions.TextEquivalence) {
	if len(te.ModulesEquivalent) > 0 {
		fmt.Fprintf(b, "- Equivalent modules: %d\n", len(te.ModulesEquivalent))
	}
	if len(te.ModulesChanged) > 0 {
		fmt.Fprintf(b, "- Changed modules: %d\n", len(te.ModulesChanged))
	}
	if len(te.Bypassed) > 0 {
		fmt.Fprintf(b, "- Bypassed (large input): %d\n", len(te.Bypassed))
	}
	b.WriteString("\n")
}

// WriteDiff writes <dir>/diff.json AND <dir>/DIFF.md atomically. Either both
// succeed or neither (D-11).
func WriteDiff(d *DiffResult, dir string) error {
	jsonPath := filepath.Join(dir, "diff.json")
	mdPath := filepath.Join(dir, "DIFF.md")

	if err := writeJSONAtomic(jsonPath, d); err != nil {
		return fmt.Errorf("write diff.json: %w", err)
	}
	md := RenderMarkdownReport(d)
	if err := writeFileAtomic(mdPath, []byte(md), 0o644); err != nil {
		// Roll back the JSON we just wrote so the pair invariant holds.
		_ = removeBestEffort(jsonPath)
		return fmt.Errorf("write DIFF.md: %w", err)
	}
	return nil
}

func removeBestEffort(p string) error {
	abs, err := filepath.Abs(filepath.Clean(p))
	if err != nil {
		return err
	}
	return os.Remove(abs)
}
