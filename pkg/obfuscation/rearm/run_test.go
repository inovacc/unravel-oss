package rearm

import (
	"context"
	"errors"
	"testing"

	"github.com/inovacc/unravel-oss/pkg/dissect"
)

func TestRun_RearmsAndWritesReport(t *testing.T) {
	r := &dissect.DissectResult{
		JSAnalysis:   &dissect.JSAnalysisResult{ObfuscationScore: 90, File: "app.js"},
		BeautifiedJS: "function a(){return 1}",
	}
	fb := &fakeBeautifier{resp: "MECHANISM: terser|88\n```js\nfunction app(){return 1;}\n```"}
	Run(context.Background(), r, fb, DefaultOptions())
	if r.ObfuscationReport == nil || len(r.ObfuscationReport.Modules) != 1 {
		t.Fatalf("report not assembled: %+v", r.ObfuscationReport)
	}
	m := r.ObfuscationReport.Modules[0]
	if m.Status != "rearmed" || m.Mechanism != "terser" || m.Provenance != "ai-mcp-sampling" {
		t.Fatalf("module not tagged: %+v", m)
	}
	if r.BeautifiedJS != "function app(){return 1;}" {
		t.Fatalf("reconstructed code not materialized into BeautifiedJS: %q", r.BeautifiedJS)
	}
}

func TestRun_AIUnavailable_HonestA(t *testing.T) {
	r := &dissect.DissectResult{
		JSAnalysis:   &dissect.JSAnalysisResult{ObfuscationScore: 90, File: "app.js"},
		BeautifiedJS: "ORIGINAL",
	}
	fb := &fakeBeautifier{err: errors.New("ai unavailable")}
	Run(context.Background(), r, fb, DefaultOptions())
	if r.ObfuscationReport == nil || len(r.ObfuscationReport.Modules) != 1 {
		t.Fatalf("candidate must still be recorded (decision A)")
	}
	m := r.ObfuscationReport.Modules[0]
	if m.Status != "not_rearmed_ai_unavailable" || m.Mechanism != "minified/obfuscated-js" {
		t.Fatalf("honest-A not satisfied: %+v", m)
	}
	if r.BeautifiedJS != "ORIGINAL" {
		t.Fatalf("must NOT overwrite source when AI unavailable")
	}
	if len(r.Errors) == 0 {
		t.Fatalf("error must be recorded non-fatally")
	}
}

func TestRun_NoCandidates_NilReport(t *testing.T) {
	r := &dissect.DissectResult{}
	Run(context.Background(), r, &fakeBeautifier{}, DefaultOptions())
	if r.ObfuscationReport != nil {
		t.Fatalf("zero candidates => nil report (honest-empty)")
	}
}
