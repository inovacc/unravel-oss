/*
Copyright (c) 2026 Security Research
*/
package rearm

import "sort"

// RankAndBound sorts by Signal desc, Size desc, ModuleRef asc (stable,
// deterministic), drops modules over MaxModuleBytes, truncates at MaxModules,
// and stops once the estimated token budget (len(Source)/4) is exceeded.
func RankAndBound(cands []Candidate, b Bounds) []Candidate {
	f := make([]Candidate, 0, len(cands))
	for _, c := range cands {
		if b.MaxModuleBytes > 0 && c.Size > b.MaxModuleBytes {
			continue
		}
		f = append(f, c)
	}
	sort.SliceStable(f, func(i, j int) bool {
		if f[i].Signal != f[j].Signal {
			return f[i].Signal > f[j].Signal
		}
		if f[i].Size != f[j].Size {
			return f[i].Size > f[j].Size
		}
		return f[i].ModuleRef < f[j].ModuleRef
	})
	var out []Candidate
	tokens := 0
	for _, c := range f {
		if b.MaxModules > 0 && len(out) >= b.MaxModules {
			break
		}
		est := len(c.Source) / 4
		if b.MaxTotalTokens > 0 && tokens+est > b.MaxTotalTokens {
			break
		}
		tokens += est
		out = append(out, c)
	}
	return out
}
