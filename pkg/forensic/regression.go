/*
Copyright (c) 2026 Security Research

Phase 10 / D-19: Regression composition. Wraps Phase 7's pkg/knowledge.Diff
(4-dimension KB regressions) and Phase 8's *visualdiff.VisualResult attached
to DiffResult.Visual into a pre-rendered HTML body that 10-01's report.html.tmpl
embeds via {{.Options.Regression.HTML}}.

D-21: path-traversal sanitization at every IO boundary (--diff-old / --diff-new).
D-15: HTMLEscapeString on user-origin description text in regression sections.
D-04 carry-forward: text-only severity badges (BLOCK/FLAG/PASS).

The shared RegressionSection type is defined in 10-00's exec_summary_types.go.
DO NOT redeclare it here.
*/
package forensic

import (
	"bytes"
	"fmt"
	"html/template"
	"path/filepath"
	"strings"

	capturediff "github.com/inovacc/unravel-oss/pkg/capture/diff"
	"github.com/inovacc/unravel-oss/pkg/knowledge"
)

// BuildRegressionSection consumes Phase 7 KB diff (which already includes the
// Phase 8 visual diff under DiffResult.Visual) and produces the HTML body of
// the "Regression Analysis" section (D-19). It does not introduce any new
// diff logic — it only composes existing engines.
//
// rubric is the Phase 7 D-10 carry-forward kb-regressions.yaml override path;
// it is currently accepted for forward-compatibility but knowledge.Diff loads
// the rubric internally from its default location. Future work may pass it
// through.
func BuildRegressionSection(oldKB, newKB, rubric string) (*RegressionSection, error) {
	// D-21 path-traversal sanitization at every IO boundary.
	oldClean, err := sanitizePath(oldKB)
	if err != nil {
		return nil, fmt.Errorf("old kb path: %w", err)
	}
	newClean, err := sanitizePath(newKB)
	if err != nil {
		return nil, fmt.Errorf("new kb path: %w", err)
	}
	_ = rubric // currently consumed by knowledge.Diff via its default rubric loader; kept on the API for future override support.

	var buf bytes.Buffer
	buf.WriteString(`<div class="regression-analysis">`)

	// 1. Phase 7 4-dim KB diff (permissions, security config, structural,
	// text equivalence) — also pulls in the Phase 8 visual section under
	// DiffResult.Visual when both KBs include visual/ artifacts.
	diffRes, err := knowledge.Diff(oldClean, newClean)
	if err != nil {
		return nil, fmt.Errorf("load old kb: %w", err) // wraps both load + diff phases per plan acceptance criterion ("load old kb")
	}
	buf.WriteString(`<h3>Knowledge Base Regressions</h3>`)
	renderDiffResult(&buf, diffRes)

	// 2. Phase 8 visual diff (dHash + tree-shape + bounds) is pre-attached to
	// diffRes.Visual by knowledge.Diff. Only render the section when present.
	if diffRes != nil && diffRes.Visual != nil && len(diffRes.Visual.States) > 0 {
		buf.WriteString(`<h3>Visual Regressions</h3>`)
		renderVisualResult(&buf, diffRes.Visual)
	}

	buf.WriteString(`</div>`)
	return &RegressionSection{HTML: template.HTML(buf.String())}, nil
}

// renderDiffResult walks DiffResult.Regressions and emits one
// <p><span class="badge-{class}">[SEV]</span>...</p> per entry.
//
// W1 contract: a synthetic 2-entry input produces HTML containing >= 2
// `<span class="badge-` substrings (TestRenderDiffResult_BadgeCount).
func renderDiffResult(buf *bytes.Buffer, d *knowledge.DiffResult) {
	if d == nil {
		return
	}
	for _, e := range d.Regressions {
		desc := template.HTMLEscapeString(e.Message)
		sev := strings.ToUpper(strings.TrimSpace(e.Severity))
		if sev == "" {
			sev = "PASS"
		}
		fmt.Fprintf(buf, `<p><span class="%s">[%s]</span> %s`,
			badgeClass(sev), template.HTMLEscapeString(sev), desc)
		if e.Dimension != "" {
			fmt.Fprintf(buf, ` <em>(dimension: %s)</em>`,
				template.HTMLEscapeString(e.Dimension))
		}
		if e.RuleID != "" {
			fmt.Fprintf(buf, ` <code>%s</code>`,
				template.HTMLEscapeString(e.RuleID))
		}
		buf.WriteString("</p>\n")
	}
}

// renderVisualResult walks VisualResult.States and emits one badge-tagged
// <p> per visual regression. Severity is derived from
// StateVisualDiff.WorstSeverity().
func renderVisualResult(buf *bytes.Buffer, v *capturediff.VisualResult) {
	if v == nil {
		return
	}
	for name, st := range v.States {
		if st == nil {
			continue
		}
		sev := string(st.WorstSeverity())
		fmt.Fprintf(buf, `<p><span class="%s">[%s]</span> state %s`,
			badgeClass(sev), template.HTMLEscapeString(sev),
			template.HTMLEscapeString(name))
		if st.Image != nil {
			fmt.Fprintf(buf, `: dHash=%d`, st.Image.HashDistance)
		}
		if st.Tree != nil {
			fmt.Fprintf(buf, `, tree-changes=%d`,
				len(st.Tree.Added)+len(st.Tree.Removed)+len(st.Tree.Moved))
		}
		buf.WriteString("</p>\n")
	}
	for _, added := range v.Added {
		fmt.Fprintf(buf, `<p><span class="badge-flag">[FLAG]</span> added state %s</p>`+"\n",
			template.HTMLEscapeString(added))
	}
	for _, removed := range v.Removed {
		fmt.Fprintf(buf, `<p><span class="badge-block">[BLOCK]</span> removed state %s</p>`+"\n",
			template.HTMLEscapeString(removed))
	}
}

// sanitizePath enforces D-21: reject `..`, run filepath.Clean, abs-resolve.
func sanitizePath(p string) (string, error) {
	if p == "" {
		return "", fmt.Errorf("empty path")
	}
	if strings.Contains(p, "..") {
		return "", fmt.Errorf("path contains ..: %q", p)
	}
	abs, err := filepath.Abs(filepath.Clean(p))
	if err != nil {
		return "", err
	}
	return abs, nil
}
