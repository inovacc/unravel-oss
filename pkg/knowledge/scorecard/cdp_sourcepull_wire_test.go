/*
Copyright (c) 2026 Security Research
*/

package scorecard

import (
	"testing"

	"github.com/inovacc/unravel-oss/pkg/dissect"
)

func TestApplyPulledToResult_PopulatesJSAndCSS(t *testing.T) {
	r := &dissect.DissectResult{}
	ps := &PulledSources{
		JS:  []ScriptSrc{{URL: "https://x/a.js", ScriptID: "1", Source: "function a(){return 1}"}},
		CSS: []StyleSrc{{URL: "https://x/s.css", StyleSheetID: "c1", Source: ".x{display:flex}"}},
	}
	applyPulledToResult(r, ps)
	if r.JSAnalysis == nil || r.JSAnalysis.Size == 0 {
		t.Fatalf("JSAnalysis not set: %+v", r.JSAnalysis)
	}
	if r.RecoveredCSS == nil || r.RecoveredCSS.Files != 1 {
		t.Fatalf("RecoveredCSS not set: %+v", r.RecoveredCSS)
	}
}

func TestApplyPulledToResult_HonestEmpty(t *testing.T) {
	r := &dissect.DissectResult{}
	applyPulledToResult(r, &PulledSources{})
	applyPulledToResult(r, nil)
	if r.JSAnalysis != nil || r.RecoveredCSS != nil {
		t.Fatal("synthesized from empty")
	}
}
