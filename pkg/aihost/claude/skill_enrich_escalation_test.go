/*
Copyright (c) 2026 Security Research
*/
// Pins the KBC-ENRICH-MODEL-ESCALATION (Phase D2) markdown graft inside
// the skills/enrich/SKILL.md plugin asset. If this test ever fails, the
// model-escalation protocol section has been deleted, renamed, or
// reordered relative to the Workflow header — see
// docs/superpowers/specs/2026-05-24-enrich-opus-escalation-protocol.md
// for the canonical text.
package claude

import (
	"strings"
	"testing"

	"github.com/inovacc/unravel-oss/pkg/aihost"
	_ "github.com/inovacc/unravel-oss/pkg/aihost/assets/all"
)

func findEnrichSkill(t *testing.T) string {
	t.Helper()
	for _, a := range aihost.AllAssets() {
		if a.Path == "skills/enrich/SKILL.md" {
			return a.Body
		}
	}
	t.Fatalf("skills/enrich/SKILL.md asset not found in generatedAssets")
	return ""
}

func TestEnrichSkill_EscalationSectionPresent(t *testing.T) {
	body := findEnrichSkill(t)

	const header = "## Model-escalation protocol (KBC-ENRICH-MODEL-ESCALATION)"
	if !strings.Contains(body, header) {
		t.Fatalf("enrich SKILL.md missing escalation header %q", header)
	}

	steps := []string{
		"1. **First 3 attempts** use the default model",
		"2. **After 3 sonnet failures on the same module**",
		"3. **On opus success**",
		"4. **On opus failure**",
		"5. The operator clears the flag via",
	}
	prev := strings.Index(body, header)
	for _, s := range steps {
		idx := strings.Index(body[prev:], s)
		if idx < 0 {
			t.Errorf("enrich SKILL.md missing escalation step %q after offset %d", s, prev)
			continue
		}
		prev += idx + len(s)
	}

	for _, sub := range []string{"## Quota cost", "## Why the orchestrator (skill), not Go"} {
		if !strings.Contains(body, sub) {
			t.Errorf("enrich SKILL.md missing %q subsection", sub)
		}
	}
}

func TestEnrichSkill_EscalationInsertedBeforeFetchStep(t *testing.T) {
	body := findEnrichSkill(t)
	const header = "## Model-escalation protocol (KBC-ENRICH-MODEL-ESCALATION)"
	const fetchHeader = "### 1. Fetch pending modules"
	const workflowHeader = "## Workflow"

	wfIdx := strings.Index(body, workflowHeader)
	if wfIdx < 0 {
		t.Fatalf("enrich SKILL.md missing %q", workflowHeader)
	}
	escIdx := strings.Index(body, header)
	if escIdx < 0 {
		t.Fatalf("enrich SKILL.md missing %q", header)
	}
	fetchIdx := strings.Index(body, fetchHeader)
	if fetchIdx < 0 {
		t.Fatalf("enrich SKILL.md missing %q", fetchHeader)
	}

	if !(wfIdx < escIdx && escIdx < fetchIdx) {
		t.Fatalf("escalation section misordered: workflow=%d escalation=%d fetch=%d (want workflow<escalation<fetch)",
			wfIdx, escIdx, fetchIdx)
	}
}
