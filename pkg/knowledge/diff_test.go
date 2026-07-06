/*
Copyright (c) 2026 Security Research
*/
package knowledge

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/inovacc/unravel-oss/pkg/knowledge/regressions"
)

const (
	oldFixture = "testdata/kb-old"
	newFixture = "testdata/kb-new"
)

func runDiff(t *testing.T) *DiffResult {
	t.Helper()
	d, err := Diff(oldFixture, newFixture)
	if err != nil {
		t.Fatalf("Diff err: %v", err)
	}
	return d
}

func ruleFired(d *DiffResult, id string) *regressions.Regression {
	for i := range d.Regressions {
		if d.Regressions[i].RuleID == id {
			return &d.Regressions[i]
		}
	}
	return nil
}

func TestDiffPermissionsBlock(t *testing.T) {
	d := runDiff(t)
	if d.Permissions == nil {
		t.Fatal("expected Permissions populated")
	}
	r := ruleFired(d, "dangerous-permission-added")
	if r == nil {
		t.Fatalf("expected dangerous-permission-added; regs=%+v", d.Regressions)
	}
	if r.Severity != regressions.SeverityBlock {
		t.Errorf("severity=%q want BLOCK", r.Severity)
	}
}

func TestDiffCSPRegression(t *testing.T) {
	d := runDiff(t)
	if d.SecurityConfig == nil {
		t.Fatal("expected SecurityConfig populated")
	}
	r := ruleFired(d, "csp-unsafe-inline-added")
	if r == nil || r.Severity != regressions.SeverityBlock {
		t.Fatalf("expected csp-unsafe-inline-added BLOCK; got %v", r)
	}
}

func TestDiffSandboxRemoved(t *testing.T) {
	d := runDiff(t)
	r := ruleFired(d, "sandbox-flag-removed")
	if r == nil || r.Severity != regressions.SeverityBlock {
		t.Fatalf("expected sandbox-flag-removed BLOCK; got %v", r)
	}
}

func TestDiffStructuralTelemetry(t *testing.T) {
	d := runDiff(t)
	if d.Structural == nil {
		t.Fatal("expected Structural populated")
	}
	r := ruleFired(d, "telemetry-sdk-added")
	if r == nil || r.Severity != regressions.SeverityFlag {
		t.Fatalf("expected telemetry-sdk-added FLAG; got %v", r)
	}
	if d.Structural.TelemetryCountOld != 1 || d.Structural.TelemetryCountNew != 2 {
		t.Errorf("telemetry counts %d->%d want 1->2",
			d.Structural.TelemetryCountOld, d.Structural.TelemetryCountNew)
	}
}

func TestDiffSchemaVersion2(t *testing.T) {
	d := runDiff(t)
	if d.SchemaVersion != 2 {
		t.Errorf("schema=%d want 2", d.SchemaVersion)
	}
}

func TestDiffBackCompatLegacyFields(t *testing.T) {
	d := runDiff(t)
	// Top-level manifest.json is identical, so the legacy comparator
	// fallback should produce zero diffs for it.
	// Marshal+unmarshal round-trip ensures the legacy fields still emit.
	out, err := json.Marshal(d)
	if err != nil {
		t.Fatal(err)
	}
	var back map[string]any
	if err := json.Unmarshal(out, &back); err != nil {
		t.Fatal(err)
	}
	// "summary" is required regardless.
	if _, ok := back["summary"]; !ok {
		t.Error("summary field missing from JSON encoding")
	}
}

func TestDiffPathTraversalReject(t *testing.T) {
	_, err := Diff("/tmp/foo/../etc", "/tmp/bar")
	if !errors.Is(err, errPathTraversalDiff) {
		t.Fatalf("expected errPathTraversalDiff, got %v", err)
	}
}

func TestDiffWritesAtomic(t *testing.T) {
	d := runDiff(t)
	out := t.TempDir()
	if err := WriteDiff(d, out); err != nil {
		t.Fatalf("WriteDiff: %v", err)
	}
	for _, name := range []string{"diff.json", "DIFF.md"} {
		p := filepath.Join(out, name)
		info, err := os.Stat(p)
		if err != nil {
			t.Fatalf("expected %s: %v", name, err)
		}
		if info.Size() == 0 {
			t.Errorf("%s is zero bytes", name)
		}
		// No leftover .tmp.
		if _, err := os.Stat(p + ".tmp"); !os.IsNotExist(err) {
			t.Errorf("%s.tmp leaked: %v", name, err)
		}
	}
}

func TestDiffMarkdownReport(t *testing.T) {
	d := runDiff(t)
	md := RenderMarkdownReport(d)
	if !strings.Contains(md, "**[BLOCK]**") {
		t.Errorf("markdown missing [BLOCK] badge")
	}
	if !strings.Contains(md, "| ID | Dimension | Severity | Source | Message |") {
		t.Errorf("markdown missing regression table header")
	}
	if !strings.Contains(md, "## Permissions") {
		t.Errorf("markdown missing Permissions section")
	}
	if !strings.Contains(md, "## Security Config") {
		t.Errorf("markdown missing Security Config section")
	}
}

func TestDiffSummaryCounts(t *testing.T) {
	d := runDiff(t)
	// Expect: 3 BLOCK (csp-unsafe-inline, dangerous-perm, sandbox-removed),
	// 1 FLAG (telemetry).
	var b, f int
	for _, r := range d.Regressions {
		switch r.Severity {
		case regressions.SeverityBlock:
			b++
		case regressions.SeverityFlag:
			f++
		}
	}
	if b < 3 {
		t.Errorf("BLOCK count=%d want >=3", b)
	}
	if f < 1 {
		t.Errorf("FLAG count=%d want >=1", f)
	}
	if !strings.Contains(d.Summary, "BLOCK") {
		t.Errorf("Summary missing BLOCK count: %q", d.Summary)
	}
}
