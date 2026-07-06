package dissect

import "testing"

func TestObfuscationReportShape(t *testing.T) {
	r := &DissectResult{}
	r.ObfuscationReport = &ObfuscationReport{
		Mechanisms: []MechanismFinding{{Lang: "js", Name: "terser", Confidence: 85, ModuleRef: "app.js"}},
		Modules: []RearmedModule{{
			Lang: "js", ModuleRef: "app.js", Mechanism: "terser", Confidence: 85,
			Status: "rearmed", Provenance: "ai-mcp-sampling", Model: "claude",
		}},
	}
	if r.ObfuscationReport.Modules[0].Status != "rearmed" {
		t.Fatalf("status not set")
	}
}
