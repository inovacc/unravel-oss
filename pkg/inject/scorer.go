/*
Copyright (c) 2026 Security Research
*/
package inject

// RankConfidence picks the strongest confidence among multiple evidence items.
// high beats medium beats low. Empty input returns ConfidenceLow. Used by
// per-framework scanners when a single seam has multiple evidence items of
// differing strength (16-CONTEXT D-03).
func RankConfidence(items ...Confidence) Confidence {
	best := ConfidenceLow
	for _, c := range items {
		switch c {
		case ConfidenceHigh:
			return ConfidenceHigh
		case ConfidenceMedium:
			best = ConfidenceMedium
		}
	}
	return best
}
