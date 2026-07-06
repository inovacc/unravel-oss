/*
Copyright (c) 2026 Security Research
*/

package bundle

import (
	"fmt"
	"sort"

	recon "github.com/inovacc/unravel-oss/internal/ai/reconstruct/chunk"
)

// ReasonBalanceValidationFailed marks proposals dropped by Pass 3.
const ReasonBalanceValidationFailed = "balance_validation_failed"

// ValidateProposals enforces Pass 3 of the D-11 strategy:
//   - sort proposals ascending by Start;
//   - drop any whose [Start, End) extends beyond src bounds;
//   - drop overlapping later proposals (first-wins);
//   - drop proposals whose slice fails brace-balance via the shared
//     chunker (LangJavaScript), recording reason
//     "balance_validation_failed".
//
// Returns survivors plus a parallel slice of human-readable drop reasons.
func ValidateProposals(src []byte, proposals []ModuleProposal) (survivors []ModuleProposal, dropped []string) {
	defer func() {
		if r := recover(); r != nil {
			survivors = nil
			dropped = append(dropped, fmt.Sprintf("validate_panic: %v", r))
		}
	}()

	if len(proposals) == 0 {
		return nil, nil
	}

	// 1. Sort by Start.
	sorted := make([]ModuleProposal, len(proposals))
	copy(sorted, proposals)
	sort.SliceStable(sorted, func(i, j int) bool { return sorted[i].Start < sorted[j].Start })

	// 2. Bounds check + 3. overlap check (first-wins).
	survivors = make([]ModuleProposal, 0, len(sorted))
	prevEnd := -1
	for _, p := range sorted {
		if p.Start < 0 || p.End <= p.Start || p.End > len(src) {
			dropped = append(dropped, fmt.Sprintf("out_of_bounds: [%d,%d)", p.Start, p.End))
			continue
		}
		if p.Start < prevEnd {
			dropped = append(dropped, fmt.Sprintf("overlap: [%d,%d) vs prev_end=%d", p.Start, p.End, prevEnd))
			continue
		}
		// 4. Brace balance via shared chunker.
		if !braceBalanced(src[p.Start:p.End]) {
			dropped = append(dropped, ReasonBalanceValidationFailed)
			continue
		}
		survivors = append(survivors, p)
		if p.End > prevEnd {
			prevEnd = p.End
		}
	}
	return survivors, dropped
}

// braceBalanced runs the shared chunker over the slice and reports
// whether it parsed without ParseErr or imbalance.
func braceBalanced(slice []byte) (ok bool) {
	defer func() {
		if r := recover(); r != nil {
			ok = false
		}
	}()
	if len(slice) == 0 {
		return false
	}
	chunks, err := recon.Chunk(slice, recon.LangJavaScript, recon.Options{MaxBytes: 0})
	if err != nil {
		return false
	}
	for _, c := range chunks {
		if c.ParseErr != "" {
			return false
		}
	}
	// Independent depth check — shared chunker may not flag
	// pathologically-nested-but-balanced slices.
	return depthBalanced(slice)
}

// depthBalanced is a small string/comment-aware brace counter. Returns
// true when the slice ends at depth 0 with no string-mode leak. Capped
// at depth 1024 (matches chunk pkg) to bound DoS surface.
func depthBalanced(src []byte) bool {
	const maxDepth = 1024
	depth := 0
	mode := 0 // 0=code 1=dq 2=sq 3=tpl 4=line 5=block 6=regex
	n := len(src)
	for i := 0; i < n; i++ {
		c := src[i]
		switch mode {
		case 0:
			switch c {
			case '{':
				depth++
				if depth > maxDepth {
					return false
				}
			case '}':
				depth--
				if depth < 0 {
					return false
				}
			case '"':
				mode = 1
			case '\'':
				mode = 2
			case '`':
				mode = 3
			case '/':
				if i+1 < n {
					if src[i+1] == '/' {
						mode = 4
						i++
					} else if src[i+1] == '*' {
						mode = 5
						i++
					}
				}
			}
		case 1:
			if c == '\\' && i+1 < n {
				i++
			} else if c == '"' {
				mode = 0
			}
		case 2:
			if c == '\\' && i+1 < n {
				i++
			} else if c == '\'' {
				mode = 0
			}
		case 3:
			if c == '\\' && i+1 < n {
				i++
			} else if c == '`' {
				mode = 0
			}
		case 4:
			if c == '\n' {
				mode = 0
			}
		case 5:
			if c == '*' && i+1 < n && src[i+1] == '/' {
				mode = 0
				i++
			}
		}
	}
	return depth == 0 && mode == 0
}
