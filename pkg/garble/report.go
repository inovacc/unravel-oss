/*
Copyright © 2026 Security Research
*/
package garble

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// GenerateDetectReport writes a markdown report for a single detection result.
func GenerateDetectReport(result *DetectionResult, outPath string) error {
	dir := filepath.Dir(outPath)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("create report dir: %w", err)
	}

	report := buildDetectReport(result)

	return os.WriteFile(outPath, []byte(report), 0o644)
}

// GenerateScanReport writes a markdown report for a directory scan.
func GenerateScanReport(result *ScanResult, outPath string) error {
	dir := filepath.Dir(outPath)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("create report dir: %w", err)
	}

	report := buildScanReport(result)

	return os.WriteFile(outPath, []byte(report), 0o644)
}

func buildDetectReport(result *DetectionResult) string {
	var b strings.Builder

	b.WriteString(fmt.Sprintf("# Garble Detection Report: %s\n\n", result.FileName))
	b.WriteString(fmt.Sprintf("- **File:** `%s`\n", result.FilePath))
	b.WriteString(fmt.Sprintf("- **Size:** %d bytes\n", result.FileSize))
	b.WriteString(fmt.Sprintf("- **Format:** %s\n", result.Format))
	b.WriteString(fmt.Sprintf("- **Date:** %s\n\n", time.Now().Format("2006-01-02 15:04:05")))

	b.WriteString("## Detection Result\n\n")
	b.WriteString(fmt.Sprintf("- **Garbled:** %v\n", result.IsGarbled))
	b.WriteString(fmt.Sprintf("- **Confidence:** %.1f%% (%s)\n\n", result.Confidence*100, result.ConfidenceLabel))

	b.WriteString("## Heuristics\n\n")
	b.WriteString("| # | Heuristic | Weight | Detected | Details |\n")
	b.WriteString("|---|-----------|--------|----------|---------|\n")

	for i, h := range result.Heuristics {
		detected := "No"
		if h.Detected {
			detected = "**Yes**"
		}

		details := h.Details
		if len(details) > 60 {
			details = details[:57] + "..."
		}

		b.WriteString(fmt.Sprintf("| %d | %s | %.2f | %s | %s |\n",
			i+1, h.Description, h.Weight, detected, details))
	}

	b.WriteString("\n")

	return b.String()
}

func buildScanReport(result *ScanResult) string {
	var b strings.Builder

	b.WriteString("# Garble Scan Report\n\n")
	b.WriteString(fmt.Sprintf("- **Directory:** `%s`\n", result.Directory))
	b.WriteString(fmt.Sprintf("- **Date:** %s\n", time.Now().Format("2006-01-02 15:04:05")))
	b.WriteString(fmt.Sprintf("- **Files Scanned:** %d\n", result.TotalFiles))
	b.WriteString(fmt.Sprintf("- **Go Binaries Found:** %d\n", result.GoBinaryCount))
	b.WriteString(fmt.Sprintf("- **Garbled Binaries:** %d\n\n", result.GarbledCount))

	if len(result.Results) == 0 {
		b.WriteString("No Go binaries found.\n")
		return b.String()
	}

	b.WriteString("## Results\n\n")
	b.WriteString("| Binary | Format | Garbled | Confidence | Label |\n")
	b.WriteString("|--------|--------|---------|------------|-------|\n")

	for _, r := range result.Results {
		garbled := "No"
		if r.IsGarbled {
			garbled = "**Yes**"
		}

		b.WriteString(fmt.Sprintf("| %s | %s | %s | %.1f%% | %s |\n",
			r.FileName, r.Format, garbled, r.Confidence*100, r.ConfidenceLabel))
	}

	b.WriteString("\n")

	// Detailed sections for garbled binaries
	for _, r := range result.Results {
		if !r.IsGarbled {
			continue
		}

		b.WriteString(fmt.Sprintf("### %s\n\n", r.FileName))
		b.WriteString(fmt.Sprintf("- **Path:** `%s`\n", r.FilePath))
		b.WriteString(fmt.Sprintf("- **Confidence:** %.1f%% (%s)\n\n", r.Confidence*100, r.ConfidenceLabel))

		b.WriteString("| Heuristic | Detected | Details |\n")
		b.WriteString("|-----------|----------|---------|\n")

		for _, h := range r.Heuristics {
			detected := "No"
			if h.Detected {
				detected = "Yes"
			}

			details := h.Details
			if len(details) > 50 {
				details = details[:47] + "..."
			}

			b.WriteString(fmt.Sprintf("| %s | %s | %s |\n", h.Description, detected, details))
		}

		b.WriteString("\n")
	}

	return b.String()
}
