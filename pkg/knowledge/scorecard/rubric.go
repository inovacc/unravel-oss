/*
Copyright (c) 2026 Security Research
*/
package scorecard

import (
	"fmt"

	"github.com/inovacc/unravel-oss/pkg/analysis"
	"github.com/inovacc/unravel-oss/pkg/dissect"
)

// Rubric orchestrates per-dim scorers in canonical CanonicalDims order.
type Rubric struct {
	ordered []Scorer
}

// New constructs a Rubric with registered scorers sorted into canonical dim
// order. Scorers whose ID is not in CanonicalDims are dropped. Missing
// canonical IDs produce a zero-score placeholder DimScore at Score time so
// output always has 12 entries.
func New() *Rubric {
	byID := make(map[string]Scorer, len(scorers))
	for _, s := range scorers {
		byID[s.ID()] = s
	}
	ordered := make([]Scorer, 0, len(CanonicalDims))
	for _, id := range CanonicalDims {
		if s, ok := byID[id]; ok {
			ordered = append(ordered, s)
		}
	}
	return &Rubric{ordered: ordered}
}

// Score iterates the ordered scorer slice and assembles a Scorecard.
// Scorers that panic are recovered and produce a zero-score DimScore with a
// missing-evidence note so one bad scorer cannot take the rest down.
func (rb *Rubric) Score(r *dissect.DissectResult, rs *analysis.ResultSet) Scorecard {
	out := Scorecard{Dimensions: make([]DimScore, 0, len(CanonicalDims))}
	if r != nil {
		out.KbID = r.CacheID
	}
	have := make(map[string]bool, len(rb.ordered))
	for _, s := range rb.ordered {
		have[s.ID()] = true
		out.Dimensions = append(out.Dimensions, scoreOne(s, r, rs))
	}
	for _, id := range CanonicalDims {
		if have[id] {
			continue
		}
		out.Dimensions = append(out.Dimensions, DimScore{
			ID:    id,
			Name:  id,
			Score: 0,
			Evidence: []Evidence{{
				Kind:   "missing",
				Source: "registry",
				Detail: "no scorer registered for dim",
			}},
		})
	}
	out.Dimensions = sortByCanonical(out.Dimensions)
	out.Coverage = computeCoverage(out.Dimensions)
	return out
}

func scoreOne(s Scorer, r *dissect.DissectResult, rs *analysis.ResultSet) (ds DimScore) {
	defer func() {
		if rec := recover(); rec != nil {
			ds = DimScore{
				ID:    s.ID(),
				Name:  s.Name(),
				Score: 0,
				Evidence: []Evidence{{
					Kind:   "missing",
					Source: "scorer",
					Detail: fmt.Sprintf("scorer panic: %v", rec),
				}},
			}
		}
	}()
	return s.Score(r, rs)
}

func sortByCanonical(in []DimScore) []DimScore {
	idx := make(map[string]int, len(CanonicalDims))
	for i, id := range CanonicalDims {
		idx[id] = i
	}
	out := make([]DimScore, len(CanonicalDims))
	seen := make([]bool, len(CanonicalDims))
	for _, d := range in {
		if i, ok := idx[d.ID]; ok && !seen[i] {
			out[i] = d
			seen[i] = true
		}
	}
	for i, ok := range seen {
		if !ok {
			out[i] = DimScore{ID: CanonicalDims[i], Name: CanonicalDims[i]}
		}
	}
	return out
}

// computeCoverage returns the count of dims with Score >= 80.
func computeCoverage(dims []DimScore) int {
	n := 0
	for _, d := range dims {
		if d.Score >= 80 {
			n++
		}
	}
	return n
}
