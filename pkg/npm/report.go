/*
Copyright (c) 2026 Security Research
*/
package npm

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// GenerateMarkdown creates a markdown security report for an npm analysis.
func GenerateMarkdown(result *AnalysisResult) string {
	var b strings.Builder

	b.WriteString(fmt.Sprintf("# npm Security Report: %s@%s\n\n", result.PackageName, result.Version))
	b.WriteString(fmt.Sprintf("**Generated:** %s\n", time.Now().UTC().Format(time.RFC3339)))
	b.WriteString(fmt.Sprintf("**Risk Score:** %d/100\n\n", result.RiskScore))

	// Summary
	b.WriteString("## Summary\n\n")
	b.WriteString(fmt.Sprintf("- Dependencies: %d\n", result.Dependencies))
	b.WriteString(fmt.Sprintf("- PostInstall hooks: %s\n", boolYesNo(result.HasPostInstall)))
	b.WriteString(fmt.Sprintf("- Network calls: %d\n", len(result.NetworkCalls)))
	b.WriteString(fmt.Sprintf("- Exec calls: %d\n", len(result.ExecCalls)))
	b.WriteString(fmt.Sprintf("- Secrets detected: %d\n", len(result.Secrets)))
	b.WriteString(fmt.Sprintf("- MCP tools: %d\n", len(result.MCPTools)))
	b.WriteString(fmt.Sprintf("- Obfuscation indicators: %d\n", len(result.ObfuscationIndicators)))
	b.WriteString(fmt.Sprintf("- Supply chain risks: %d\n", len(result.SupplyChainRisks)))

	if result.DeobfuscatedFiles > 0 {
		b.WriteString(fmt.Sprintf("- Deobfuscation candidates: %d\n", result.DeobfuscatedFiles))
	}

	b.WriteString("\n")

	// Risk Factors
	if len(result.RiskFactors) > 0 {
		b.WriteString("## Risk Factors\n\n")
		for _, rf := range result.RiskFactors {
			b.WriteString(fmt.Sprintf("- %s\n", rf))
		}
		b.WriteString("\n")
	}

	// Network Calls
	if len(result.NetworkCalls) > 0 {
		b.WriteString("## Network Calls\n\n")
		for _, nc := range result.NetworkCalls {
			b.WriteString(fmt.Sprintf("- %s\n", nc))
		}
		b.WriteString("\n")
	}

	// Exec Calls
	if len(result.ExecCalls) > 0 {
		b.WriteString("## Exec Calls\n\n")
		for _, ec := range result.ExecCalls {
			b.WriteString(fmt.Sprintf("- %s\n", ec))
		}
		b.WriteString("\n")
	}

	// Install Scripts
	if len(result.InstallScripts) > 0 {
		b.WriteString("## Install Scripts\n\n")
		b.WriteString("| Hook | Script |\n")
		b.WriteString("|------|--------|\n")
		for hook, script := range result.InstallScripts {
			b.WriteString(fmt.Sprintf("| %s | `%s` |\n", hook, script))
		}
		b.WriteString("\n")
	}

	// MCP Tools
	if len(result.MCPTools) > 0 {
		b.WriteString("## MCP Tools\n\n")
		for _, t := range result.MCPTools {
			b.WriteString(fmt.Sprintf("- %s\n", t))
		}
		b.WriteString("\n")
	}

	// Obfuscation Indicators
	if len(result.ObfuscationIndicators) > 0 {
		b.WriteString("## Obfuscation Indicators\n\n")
		for _, ind := range result.ObfuscationIndicators {
			b.WriteString(fmt.Sprintf("- %s\n", ind))
		}
		b.WriteString("\n")
	}

	// Supply Chain Risks
	if len(result.SupplyChainRisks) > 0 {
		b.WriteString("## Supply Chain Risks\n\n")
		for _, risk := range result.SupplyChainRisks {
			b.WriteString(fmt.Sprintf("- %s\n", risk))
		}
		b.WriteString("\n")
	}

	return b.String()
}

// GenerateJSON creates a structured JSON report string.
func GenerateJSON(result *AnalysisResult) (string, error) {
	type jsonReport struct {
		*AnalysisResult
		Generated string `json:"generated"`
	}

	report := &jsonReport{
		AnalysisResult: result,
		Generated:      time.Now().UTC().Format(time.RFC3339),
	}

	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return "", fmt.Errorf("marshaling report: %w", err)
	}

	return string(data), nil
}

func boolYesNo(v bool) string {
	if v {
		return "yes"
	}

	return "no"
}
