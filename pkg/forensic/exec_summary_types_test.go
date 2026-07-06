/*
Copyright (c) 2026 Security Research
*/
package forensic

import (
	"context"
	"testing"
)

func TestNilMCPClient_AlwaysErrors(t *testing.T) {
	_, err := NilMCPClient().Summarize(context.Background(), "noop")
	if err == nil {
		t.Fatal("expected nilMCPClient.Summarize to return an error")
	}
}

func TestExecSummary_FieldShape(t *testing.T) {
	s := ExecSummary{TLDR: "x", TopRisks: []TopRisk{{Title: "t", Severity: "BLOCK", CWE: 798}}, RemediationPriorities: []string{"y"}}
	if s.TopRisks[0].CWE != 798 {
		t.Fatal("TopRisk.CWE round-trip broke")
	}
}
