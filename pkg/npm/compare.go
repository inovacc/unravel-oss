/*
Copyright (c) 2026 Security Research
*/
package npm

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

// CompareReport generates a side-by-side risk comparison matrix in markdown
// for multiple AnalysisResult values. Results are sorted by risk score descending.
func CompareReport(results []*AnalysisResult) string {
	if len(results) == 0 {
		return "# npm Batch Comparison Report\n\nNo packages analyzed.\n"
	}

	// Sort by risk score descending, then by package name for stability.
	sorted := make([]*AnalysisResult, len(results))
	copy(sorted, results)
	sort.Slice(sorted, func(i, j int) bool {
		if sorted[i].RiskScore != sorted[j].RiskScore {
			return sorted[i].RiskScore > sorted[j].RiskScore
		}
		return sorted[i].PackageName < sorted[j].PackageName
	})

	var b strings.Builder

	b.WriteString("# npm Batch Comparison Report\n\n")
	b.WriteString(fmt.Sprintf("**Generated:** %s\n", time.Now().UTC().Format(time.RFC3339)))
	b.WriteString(fmt.Sprintf("**Packages:** %d\n\n", len(sorted)))

	// Risk comparison matrix table.
	b.WriteString("## Risk Comparison Matrix\n\n")
	b.WriteString("| Package | Version | Risk Score | Network Calls | FS Access | Exec Calls | Secrets | Obfuscation Score | Supply Chain Risk |\n")
	b.WriteString("|---------|---------|------------|---------------|-----------|------------|---------|-------------------|-------------------|\n")

	for _, r := range sorted {
		obfScore := obfuscationScore(r)
		b.WriteString(fmt.Sprintf("| %s | %s | %s | %d | %d | %d | %d | %d | %d |\n",
			r.PackageName,
			r.Version,
			riskBadge(r.RiskScore),
			len(r.NetworkCalls),
			len(r.FSAccess),
			len(r.ExecCalls),
			len(r.Secrets),
			obfScore,
			len(r.SupplyChainRisks),
		))
	}

	b.WriteString("\n")

	// Summary section.
	b.WriteString("## Summary\n\n")

	totalRisk := 0
	totalNetwork := 0
	totalFS := 0
	totalExec := 0
	totalSecrets := 0
	totalObf := 0
	totalSupply := 0
	highRisk := 0
	criticalRisk := 0

	for _, r := range sorted {
		totalRisk += r.RiskScore
		totalNetwork += len(r.NetworkCalls)
		totalFS += len(r.FSAccess)
		totalExec += len(r.ExecCalls)
		totalSecrets += len(r.Secrets)
		totalObf += obfuscationScore(r)
		totalSupply += len(r.SupplyChainRisks)

		if r.RiskScore > 50 {
			highRisk++
		}
		if r.RiskScore > 75 {
			criticalRisk++
		}
	}

	avgRisk := totalRisk / len(sorted)

	b.WriteString("### Totals\n\n")
	b.WriteString(fmt.Sprintf("| Metric | Total |\n"))
	b.WriteString(fmt.Sprintf("|--------|-------|\n"))
	b.WriteString(fmt.Sprintf("| Packages Analyzed | %d |\n", len(sorted)))
	b.WriteString(fmt.Sprintf("| Average Risk Score | %d/100 |\n", avgRisk))
	b.WriteString(fmt.Sprintf("| High Risk (>50) | %d |\n", highRisk))
	b.WriteString(fmt.Sprintf("| Critical (>75) | %d |\n", criticalRisk))
	b.WriteString(fmt.Sprintf("| Total Network Calls | %d |\n", totalNetwork))
	b.WriteString(fmt.Sprintf("| Total FS Access | %d |\n", totalFS))
	b.WriteString(fmt.Sprintf("| Total Exec Calls | %d |\n", totalExec))
	b.WriteString(fmt.Sprintf("| Total Secrets | %d |\n", totalSecrets))
	b.WriteString(fmt.Sprintf("| Total Obfuscation Score | %d |\n", totalObf))
	b.WriteString(fmt.Sprintf("| Total Supply Chain Risks | %d |\n", totalSupply))
	b.WriteString("\n")

	// Category breakdown per package.
	b.WriteString("### Category Breakdown\n\n")

	for _, r := range sorted {
		b.WriteString(fmt.Sprintf("#### %s@%s (Risk: %d/100)\n\n", r.PackageName, r.Version, r.RiskScore))

		if len(r.RiskFactors) > 0 {
			for _, rf := range r.RiskFactors {
				b.WriteString(fmt.Sprintf("- %s\n", rf))
			}
		} else {
			b.WriteString("- No risk factors detected\n")
		}

		b.WriteString("\n")
	}

	return b.String()
}

// obfuscationScore returns a numeric obfuscation risk score for the comparison matrix.
// Each indicator adds 15 points, capped at 30 (matching calculateRisk logic).
func obfuscationScore(r *AnalysisResult) int {
	count := len(r.ObfuscationIndicators)
	if count == 0 {
		return 0
	}
	score := min(count*15, 30)
	return score
}

// riskBadge returns a risk score with a severity label.
func riskBadge(score int) string {
	switch {
	case score > 75:
		return fmt.Sprintf("**%d/100** CRITICAL", score)
	case score > 50:
		return fmt.Sprintf("**%d/100** HIGH", score)
	case score > 25:
		return fmt.Sprintf("%d/100 MEDIUM", score)
	default:
		return fmt.Sprintf("%d/100 LOW", score)
	}
}
