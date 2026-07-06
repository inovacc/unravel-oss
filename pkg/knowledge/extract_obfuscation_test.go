package knowledge

import (
	"testing"

	"github.com/inovacc/unravel-oss/pkg/dissect"
)

func TestExtractObfuscationReport(t *testing.T) {
	dr := &dissect.DissectResult{ObfuscationReport: &dissect.ObfuscationReport{
		Modules: []dissect.RearmedModule{{Lang: "js", ModuleRef: "app.js", Mechanism: "terser", Status: "rearmed", Provenance: "ai-mcp-sampling"}},
	}}
	kr := &KnowledgeResult{}
	applyObfuscationReport(kr, dr)
	if kr.ObfuscationReport == nil || len(kr.ObfuscationReport.Modules) != 1 {
		t.Fatalf("not mapped: %+v", kr.ObfuscationReport)
	}
}
