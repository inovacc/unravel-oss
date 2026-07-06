/*
Copyright (c) 2026 Security Research
*/
package drift

import "math"

// minDenom is the floor applied to the baseline value before computing
// relative_delta. Prevents division blow-ups when the baseline is 0 (e.g.,
// baseline escalation_rate=0 → recent=0.05 produces RelativeDelta=5.0).
const minDenom = 0.01

// Compare returns a DriftVerdict comparing recent against baseline using
// relative-delta thresholding. Always emits four MetricDelta rows (one per
// tracked metric); Drifted is true iff any of them are.
func Compare(baseline, recent RunMetrics, o Opts) DriftVerdict {
	if o.ThresholdRelative <= 0 {
		o.ThresholdRelative = 0.20
	}

	mk := func(name string, b, r float64) MetricDelta {
		denom := math.Max(b, minDenom)
		rel := (r - b) / denom
		return MetricDelta{
			Metric:        name,
			BaselineValue: b,
			RecentValue:   r,
			RelativeDelta: rel,
			Drifted:       math.Abs(rel) >= o.ThresholdRelative,
		}
	}

	deltas := []MetricDelta{
		mk("success_rate", baseline.SuccessRate, recent.SuccessRate),
		mk("escalation_rate", baseline.EscalationRate, recent.EscalationRate),
		mk("human_review_rate", baseline.HumanReviewRate, recent.HumanReviewRate),
		mk("mean_cost_micro_usd", baseline.MeanCostMicroUSD, recent.MeanCostMicroUSD),
	}

	v := DriftVerdict{
		Deltas:            deltas,
		BaselineRunID:     baseline.RunID,
		RecentRunID:       recent.RunID,
		ThresholdRelative: o.ThresholdRelative,
	}
	for _, d := range deltas {
		if d.Drifted {
			v.Drifted = true
			break
		}
	}
	return v
}
