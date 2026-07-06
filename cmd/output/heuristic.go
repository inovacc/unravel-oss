/*
Copyright (c) 2026 Security Research
*/
package output

import (
	"fmt"
	"strings"

	"github.com/inovacc/unravel-oss/pkg/heuristic"
)

// PrintHeuristicResult displays heuristic scan results.
func PrintHeuristicResult(r *heuristic.Result, verbose bool) {
	w := 74
	border := strings.Repeat("═", w)

	fmt.Printf("╔%s╗\n", border)
	fmt.Printf("║%-*s║\n", w, "  HEURISTIC MALICIOUS CODE ANALYSIS")
	fmt.Printf("╠%s╣\n", border)
	fmt.Printf("║ Files Scanned:  %-*d║\n", w-18, r.FilesScanned)
	fmt.Printf("║ Total Findings: %-*d║\n", w-18, r.TotalFindings)
	fmt.Printf("║ Threat Score:   %-*d║\n", w-18, r.ThreatScore)
	fmt.Printf("║ Threat Level:   %-*s║\n", w-18, colorLevel(r.ThreatLevel))
	fmt.Printf("╠%s╣\n", border)

	// Category breakdown
	if len(r.Categories) > 0 {
		fmt.Printf("║%-*s║\n", w, "  CATEGORY BREAKDOWN")
		fmt.Printf("╠%s╣\n", border)

		for _, cat := range sortedCategories(r) {
			cs := r.Categories[cat]
			label := categoryLabel(cat)
			fmt.Printf("║ %-20s %3d findings  score=%-4d  max=%s%s║\n",
				label, cs.Count, cs.Score,
				string(cs.MaxSev),
				strings.Repeat(" ", w-52-len(string(cs.MaxSev))-len(label)+20),
			)
		}
		fmt.Printf("╠%s╣\n", border)
	}

	// Top findings
	if len(r.TopFindings) > 0 {
		fmt.Printf("║%-*s║\n", w, "  TOP FINDINGS")
		fmt.Printf("╠%s╣\n", border)

		limit := len(r.TopFindings)
		if !verbose && limit > 10 {
			limit = 10
		}

		for i, f := range r.TopFindings[:limit] {
			fmt.Printf("║ %2d. [%s] %s%s║\n", i+1,
				padSeverity(string(f.Severity)),
				Truncate(f.Name, w-22),
				strings.Repeat(" ", max(0, w-22-len(Truncate(f.Name, w-22)))),
			)
			fmt.Printf("║     %s%s║\n",
				Truncate(f.Description, w-6),
				strings.Repeat(" ", max(0, w-6-len(Truncate(f.Description, w-6)))),
			)
			shortFile := Truncate(f.File, 40)
			fmt.Printf("║     %s:%d%s║\n",
				shortFile, f.Line,
				strings.Repeat(" ", max(0, w-6-len(shortFile)-1-digitCount(f.Line))),
			)
			if verbose && f.Evidence != "" {
				evi := Truncate(f.Evidence, w-8)
				fmt.Printf("║       %s%s║\n", evi,
					strings.Repeat(" ", max(0, w-8-len(evi))))
			}
		}

		if !verbose && len(r.TopFindings) > limit {
			msg := fmt.Sprintf("  ... and %d more (use -v for all)", len(r.TopFindings)-limit)
			fmt.Printf("║%-*s║\n", w, msg)
		}
	}

	fmt.Printf("╚%s╝\n", border)
}

func colorLevel(level string) string {
	switch level {
	case "CRITICAL":
		return "\033[91m" + level + "\033[0m"
	case "HIGH":
		return "\033[93m" + level + "\033[0m"
	case "MEDIUM":
		return "\033[33m" + level + "\033[0m"
	case "LOW":
		return "\033[36m" + level + "\033[0m"
	default:
		return "\033[92m" + level + "\033[0m"
	}
}

func padSeverity(s string) string {
	for len(s) < 8 {
		s += " "
	}
	return s
}

func categoryLabel(c heuristic.Category) string {
	labels := map[heuristic.Category]string{
		heuristic.CategoryNetwork:     "Network/Exfil",
		heuristic.CategoryObfuscation: "Obfuscation",
		heuristic.CategoryExecution:   "Execution",
		heuristic.CategoryDataAccess:  "Data Access",
		heuristic.CategoryPersistence: "Persistence",
		heuristic.CategoryEvasion:     "Evasion",
		heuristic.CategoryCrypto:      "Crypto",
		heuristic.CategorySupplyChain: "Supply Chain",
	}
	if l, ok := labels[c]; ok {
		return l
	}
	return string(c)
}

func sortedCategories(r *heuristic.Result) []heuristic.Category {
	order := []heuristic.Category{
		heuristic.CategoryNetwork,
		heuristic.CategoryObfuscation,
		heuristic.CategoryExecution,
		heuristic.CategoryDataAccess,
		heuristic.CategoryPersistence,
		heuristic.CategoryEvasion,
		heuristic.CategoryCrypto,
		heuristic.CategorySupplyChain,
	}
	var present []heuristic.Category
	for _, c := range order {
		if _, ok := r.Categories[c]; ok {
			present = append(present, c)
		}
	}
	return present
}

func digitCount(n int) int {
	if n == 0 {
		return 1
	}
	count := 0
	for n > 0 {
		n /= 10
		count++
	}
	return count
}
