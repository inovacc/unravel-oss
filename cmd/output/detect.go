/*
Copyright (c) 2026 Security Research
*/
package output

import (
	"fmt"
	"strings"

	"github.com/inovacc/unravel-oss/pkg/detect"
)

// PrintFileDetect prints file type detection results.
func PrintFileDetect(r *detect.DetectResult, verbose bool) {
	w := 70
	border := strings.Repeat("═", w)

	fmt.Printf("╔%s╗\n", border)
	fmt.Printf("║%-*s║\n", w, "  FILE TYPE DETECTION")
	fmt.Printf("╠%s╣\n", border)
	fmt.Printf("║ Name: %-*s║\n", w-7, Truncate(r.Name, w-8))
	fmt.Printf("║ Path: %-*s║\n", w-7, Truncate(r.Path, w-8))
	fmt.Printf("║ Size: %-*s║\n", w-7, FormatSize(r.Size))
	fmt.Printf("╠%s╣\n", border)
	fmt.Printf("║ Type:       %-*s║\n", w-13, string(r.FileType))
	fmt.Printf("║ Category:   %-*s║\n", w-13, string(r.Category))
	fmt.Printf("║ Confidence: %-*s║\n", w-13, string(r.Confidence))

	if r.Details != "" {
		fmt.Printf("║ Details:    %-*s║\n", w-13, Truncate(r.Details, w-14))
	}

	if verbose && r.MagicBytes != "" {
		fmt.Printf("║ Magic:      %-*s║\n", w-13, Truncate(r.MagicBytes, w-14))
	}

	if len(r.ApplicableCommands) > 0 {
		fmt.Printf("╠%s╣\n", border)
		fmt.Printf("║ %-*s║\n", w-1, "APPLICABLE COMMANDS")

		for i, cmd := range r.ApplicableCommands {
			line := fmt.Sprintf("%d. unravel %s", i+1, cmd.Command)
			desc := fmt.Sprintf("   %s", cmd.Description)

			fmt.Printf("║  %-*s║\n", w-2, Truncate(line, w-3))
			fmt.Printf("║  %-*s║\n", w-2, Truncate(desc, w-3))
		}
	}

	fmt.Printf("╚%s╝\n", border)
}

// PrintScanResult prints directory scan results.
func PrintScanResult(r *detect.ScanResult, verbose bool) {
	w := 70
	border := strings.Repeat("═", w)

	fmt.Printf("╔%s╗\n", border)
	fmt.Printf("║%-*s║\n", w, "  DIRECTORY SCAN RESULTS")
	fmt.Printf("╠%s╣\n", border)
	fmt.Printf("║ Path: %-*s║\n", w-7, Truncate(r.Path, w-8))
	fmt.Printf("║ Total files scanned: %-*d║\n", w-22, r.TotalFiles)
	fmt.Printf("║ Detected items: %-*d║\n", w-18, len(r.Detected))
	fmt.Printf("╠%s╣\n", border)

	// Summary by type
	if len(r.Summary) > 0 {
		fmt.Printf("║ %-*s║\n", w-1, "SUMMARY BY TYPE")

		for typeName, count := range r.Summary {
			line := fmt.Sprintf("%-25s %d", typeName, count)
			fmt.Printf("║   %-*s║\n", w-3, line)
		}

		fmt.Printf("╠%s╣\n", border)
	}

	// Detected files
	if len(r.Detected) > 0 {
		fmt.Printf("║ %-*s║\n", w-1, "DETECTED FILES")
		fmt.Printf("╠%s╣\n", border)

		for _, d := range r.Detected {
			typeStr := fmt.Sprintf("[%s]", d.FileType)

			name := d.Name
			if d.IsDir {
				name += "/"
			}

			line := fmt.Sprintf("%-18s %s", typeStr, name)
			fmt.Printf("║ %-*s║\n", w-1, Truncate(line, w-2))

			if len(d.ApplicableCommands) > 0 {
				cmds := make([]string, 0, len(d.ApplicableCommands))
				for _, c := range d.ApplicableCommands {
					cmds = append(cmds, c.Command)
				}

				cmdLine := fmt.Sprintf("  -> %s", strings.Join(cmds, ", "))
				fmt.Printf("║ %-*s║\n", w-1, Truncate(cmdLine, w-2))
			}

			if verbose && d.Details != "" {
				detailLine := fmt.Sprintf("  %s", d.Details)
				fmt.Printf("║ %-*s║\n", w-1, Truncate(detailLine, w-2))
			}
		}
	}

	// Errors
	if len(r.Errors) > 0 {
		fmt.Printf("╠%s╣\n", border)
		fmt.Printf("║ %-*s║\n", w-1, fmt.Sprintf("ERRORS (%d)", len(r.Errors)))

		for _, e := range r.Errors {
			fmt.Printf("║  %-*s║\n", w-2, Truncate(e, w-3))
		}
	}

	fmt.Printf("╚%s╝\n", border)
}
