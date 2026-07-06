/*
Copyright (c) 2026 Security Research
*/
package forensic

import "testing"

func TestRiskFor(t *testing.T) {
	tests := []struct {
		name        string
		findingType string
		severity    string
		wantL       Likelihood
		wantI       Impact
		wantOK      bool
	}{
		// Severity overrides (D-10)
		{"BLOCK override", "anything", "BLOCK", HighL, HighI, true},
		{"FLAG override", "anything", "FLAG", MedL, MedI, true},
		{"PASS excluded", "anything", "PASS", 0, 0, false},
		// 8 seeded entries
		{"csp_relaxation", "csp_relaxation", "", MedL, HighI, true},
		{"eval_or_unsafe_inline", "eval_or_unsafe_inline", "", HighL, HighI, true},
		{"dangerous_permission", "dangerous_permission", "", MedL, HighI, true},
		{"sandbox_removed", "sandbox_removed", "", HighL, HighI, true},
		{"hardcoded_credential", "hardcoded_credential", "", HighL, HighI, true},
		{"telemetry_sdk_added", "telemetry_sdk_added", "", LowL, MedI, true},
		{"content_protection", "content_protection", "", HighL, MedI, true},
		{"module_count_delta_50", "module_count_delta_50", "", MedL, LowI, true},
		// Unknown
		{"unknown", "no_such_type", "", 0, 0, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotL, gotI, gotOK := RiskFor(tt.findingType, tt.severity)
			if gotL != tt.wantL || gotI != tt.wantI || gotOK != tt.wantOK {
				t.Fatalf("RiskFor(%q,%q) = (%d,%d,%v); want (%d,%d,%v)",
					tt.findingType, tt.severity, gotL, gotI, gotOK,
					tt.wantL, tt.wantI, tt.wantOK)
			}
		})
	}
}

func TestMatrixCell(t *testing.T) {
	if got := MatrixCell(HighL, HighI); got != "L3I3" {
		t.Errorf("MatrixCell(HighL,HighI) = %q; want L3I3", got)
	}
	if got := MatrixCell(LowL, LowI); got != "L1I1" {
		t.Errorf("MatrixCell(LowL,LowI) = %q; want L1I1", got)
	}
	if got := MatrixCell(MedL, MedI); got != "L2I2" {
		t.Errorf("MatrixCell(MedL,MedI) = %q; want L2I2", got)
	}
}
