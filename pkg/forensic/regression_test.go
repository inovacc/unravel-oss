/*
Copyright (c) 2026 Security Research
*/
package forensic

import (
	"bytes"
	"path/filepath"
	"strings"
	"testing"

	"github.com/inovacc/unravel-oss/pkg/knowledge"
	"github.com/inovacc/unravel-oss/pkg/knowledge/regressions"
)

func TestSanitizePath_Rejects(t *testing.T) {
	if _, err := sanitizePath("../etc/passwd"); err == nil {
		t.Fatal("expected error for path containing ..")
	}
	if _, err := sanitizePath("foo/../bar"); err == nil {
		t.Fatal("expected error for embedded ..")
	}
	if _, err := sanitizePath(""); err == nil {
		t.Fatal("expected error for empty path")
	}

	abs, err := sanitizePath("foo/bar")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !filepath.IsAbs(abs) {
		t.Fatalf("expected absolute path, got %q", abs)
	}
}

func TestRenderDiffResult_BadgeCount(t *testing.T) {
	d := &knowledge.DiffResult{
		Regressions: []regressions.Regression{
			{RuleID: "RULE-1", Dimension: "permissions", Severity: "BLOCK", Message: "Dangerous permission added: CAMERA"},
			{RuleID: "RULE-2", Dimension: "security_config", Severity: "FLAG", Message: "CSP relaxed: unsafe-inline"},
		},
	}
	var buf bytes.Buffer
	renderDiffResult(&buf, d)

	count := bytes.Count(buf.Bytes(), []byte(`<span class="badge-`))
	if count < 2 {
		t.Fatalf("expected >= 2 badge spans, got %d. Output: %s", count, buf.String())
	}

	// XSS / D-15: HTML-escape user content.
	xss := &knowledge.DiffResult{
		Regressions: []regressions.Regression{
			{Severity: "BLOCK", Message: "<script>alert(1)</script>"},
		},
	}
	buf.Reset()
	renderDiffResult(&buf, xss)
	if strings.Contains(buf.String(), "<script>") {
		t.Fatalf("expected escaped output, got raw <script>: %s", buf.String())
	}
	if !strings.Contains(buf.String(), "&lt;script&gt;") {
		t.Fatalf("expected HTML-escaped content, got: %s", buf.String())
	}
}

func TestRenderDiffResult_NilSafe(t *testing.T) {
	var buf bytes.Buffer
	renderDiffResult(&buf, nil)
	if buf.Len() != 0 {
		t.Fatalf("expected no output for nil input, got %q", buf.String())
	}
}

func TestBuildRegressionSection_LoadFailure(t *testing.T) {
	_, err := BuildRegressionSection("/nonexistent-old-kb-12345", "/nonexistent-new-kb-12345", "")
	if err == nil {
		t.Fatal("expected error for nonexistent KB dir")
	}
	if !strings.Contains(err.Error(), "load old kb") && !strings.Contains(err.Error(), "old kb path") {
		t.Fatalf("expected error wrapping 'load old kb' or 'old kb path', got: %v", err)
	}
}

func TestBuildRegressionSection_RejectsTraversal(t *testing.T) {
	_, err := BuildRegressionSection("../etc", "../tmp", "")
	if err == nil {
		t.Fatal("expected sanitizePath rejection for ..")
	}
	if !strings.Contains(err.Error(), "old kb path") {
		t.Fatalf("expected old kb path error, got: %v", err)
	}
}
