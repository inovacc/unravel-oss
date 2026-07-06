/*
Copyright (c) 2026 Security Research
*/
package drift

import "testing"

func TestCompare_NoDrift(t *testing.T) {
	baseline := RunMetrics{
		RunID: "00000000-0000-0000-0000-000000000001", App: "x", ModulesProcessed: 30,
		SuccessRate: 0.85, EscalationRate: 0.10, HumanReviewRate: 0.05, MeanCostMicroUSD: 5000,
	}
	recent := RunMetrics{
		RunID: "00000000-0000-0000-0000-000000000002", App: "x", ModulesProcessed: 30,
		SuccessRate: 0.83, EscalationRate: 0.11, HumanReviewRate: 0.05, MeanCostMicroUSD: 5100,
	}
	v := Compare(baseline, recent, DefaultOpts())
	if v.Drifted {
		t.Errorf("Drifted=true, want false; deltas=%+v", v.Deltas)
	}
	if v.ThresholdRelative != 0.20 {
		t.Errorf("ThresholdRelative = %v, want 0.20", v.ThresholdRelative)
	}
	if len(v.Deltas) != 4 {
		t.Errorf("len(Deltas) = %d, want 4", len(v.Deltas))
	}
	if v.BaselineRunID != "00000000-0000-0000-0000-000000000001" {
		t.Errorf("BaselineRunID = %q, want uuid-1", v.BaselineRunID)
	}
	if v.RecentRunID != "00000000-0000-0000-0000-000000000002" {
		t.Errorf("RecentRunID = %q, want uuid-2", v.RecentRunID)
	}
}

func TestCompare_EscalationDoubled(t *testing.T) {
	baseline := RunMetrics{
		RunID: "00000000-0000-0000-0000-000000000001", App: "x", ModulesProcessed: 30,
		SuccessRate: 0.85, EscalationRate: 0.10, HumanReviewRate: 0.05, MeanCostMicroUSD: 5000,
	}
	recent := RunMetrics{
		RunID: "00000000-0000-0000-0000-000000000002", App: "x", ModulesProcessed: 30,
		SuccessRate: 0.85, EscalationRate: 0.25, HumanReviewRate: 0.05, MeanCostMicroUSD: 5000,
	}
	v := Compare(baseline, recent, DefaultOpts())
	if !v.Drifted {
		t.Fatalf("Drifted=false, want true; deltas=%+v", v.Deltas)
	}
	// Escalation went 0.10 → 0.25; relative_delta = (0.25 - 0.10) / 0.10 = 1.5
	found := false
	for _, d := range v.Deltas {
		if d.Metric == "escalation_rate" {
			found = true
			if !d.Drifted {
				t.Errorf("escalation_rate.Drifted=false, want true")
			}
			if d.RelativeDelta < 1.49 || d.RelativeDelta > 1.51 {
				t.Errorf("escalation_rate.RelativeDelta = %v, want ~1.5", d.RelativeDelta)
			}
		}
	}
	if !found {
		t.Fatalf("escalation_rate delta not found in %+v", v.Deltas)
	}
}

func TestCompare_NearZeroBaseline(t *testing.T) {
	// Baseline escalation = 0; recent escalation = 0.05. Relative delta uses
	// the 0.01 floor in the denominator: 0.05 / 0.01 = 5.0 → drifted.
	baseline := RunMetrics{
		RunID: "00000000-0000-0000-0000-000000000001", App: "x", ModulesProcessed: 30,
		SuccessRate: 1.0, EscalationRate: 0.0, HumanReviewRate: 0.0, MeanCostMicroUSD: 0,
	}
	recent := RunMetrics{
		RunID: "00000000-0000-0000-0000-000000000002", App: "x", ModulesProcessed: 30,
		SuccessRate: 1.0, EscalationRate: 0.05, HumanReviewRate: 0.0, MeanCostMicroUSD: 0,
	}
	v := Compare(baseline, recent, DefaultOpts())
	if !v.Drifted {
		t.Fatalf("near-zero baseline should drift on +0.05 absolute; deltas=%+v", v.Deltas)
	}
	for _, d := range v.Deltas {
		if d.Metric == "escalation_rate" {
			if d.RelativeDelta < 4.9 || d.RelativeDelta > 5.1 {
				t.Errorf("escalation_rate.RelativeDelta = %v, want ~5.0 (0.05/0.01)", d.RelativeDelta)
			}
		}
	}
}

func TestCompare_NegativeDelta(t *testing.T) {
	// Success_rate drops from 0.90 to 0.50 — large negative relative delta.
	baseline := RunMetrics{
		RunID: "00000000-0000-0000-0000-000000000001", App: "x", ModulesProcessed: 30,
		SuccessRate: 0.90, EscalationRate: 0.05, HumanReviewRate: 0.05, MeanCostMicroUSD: 5000,
	}
	recent := RunMetrics{
		RunID: "00000000-0000-0000-0000-000000000002", App: "x", ModulesProcessed: 30,
		SuccessRate: 0.50, EscalationRate: 0.05, HumanReviewRate: 0.05, MeanCostMicroUSD: 5000,
	}
	v := Compare(baseline, recent, DefaultOpts())
	if !v.Drifted {
		t.Fatalf("success_rate drop should drift; deltas=%+v", v.Deltas)
	}
	for _, d := range v.Deltas {
		if d.Metric == "success_rate" {
			if d.RelativeDelta >= 0 {
				t.Errorf("success_rate.RelativeDelta = %v, want negative", d.RelativeDelta)
			}
		}
	}
}

func TestCompare_ThresholdOverride(t *testing.T) {
	// With default 0.20 threshold, 0.15 relative delta does NOT drift.
	// With override 0.10, the same delta DOES drift.
	baseline := RunMetrics{
		RunID: "00000000-0000-0000-0000-000000000001", App: "x", ModulesProcessed: 30,
		SuccessRate: 1.0, EscalationRate: 0.20, HumanReviewRate: 0.0, MeanCostMicroUSD: 5000,
	}
	recent := RunMetrics{
		RunID: "00000000-0000-0000-0000-000000000002", App: "x", ModulesProcessed: 30,
		SuccessRate: 1.0, EscalationRate: 0.23, HumanReviewRate: 0.0, MeanCostMicroUSD: 5000,
	}
	// (0.23 - 0.20) / 0.20 = 0.15

	defaultV := Compare(baseline, recent, DefaultOpts())
	if defaultV.Drifted {
		t.Errorf("with 0.20 threshold, 0.15 delta should NOT drift")
	}

	stricter := DefaultOpts()
	stricter.ThresholdRelative = 0.10
	strictV := Compare(baseline, recent, stricter)
	if !strictV.Drifted {
		t.Errorf("with 0.10 threshold, 0.15 delta SHOULD drift")
	}
}
