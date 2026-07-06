/*
Copyright (c) 2026 Security Research
*/
package output

import (
	"fmt"
	"strings"

	"github.com/inovacc/unravel-oss/pkg/msi"
)

// PrintMsiInfo prints MSI package metadata analysis.
func PrintMsiInfo(info *msi.InfoResult) {
	w := 66
	border := strings.Repeat("═", w)

	fmt.Printf("╔%s╗\n", border)
	fmt.Printf("║%-*s║\n", w, "  MSI PACKAGE ANALYSIS")
	fmt.Printf("╠%s╣\n", border)
	fmt.Printf("║ File:    %-*s║\n", w-10, Truncate(info.FileName, w-11))
	fmt.Printf("║ Size:    %-*s║\n", w-10, msi.FormatBytes(info.Size))
	fmt.Printf("╠%s╣\n", border)

	// Product info
	fmt.Printf("║ %-*s║\n", w-1, "PRODUCT INFORMATION")

	if info.ProductName != "" {
		fmt.Printf("║   Product:      %-*s║\n", w-18, Truncate(info.ProductName, w-19))
	}

	if info.ProductVersion != "" {
		fmt.Printf("║   Version:      %-*s║\n", w-18, info.ProductVersion)
	}

	if info.Manufacturer != "" {
		fmt.Printf("║   Manufacturer: %-*s║\n", w-18, Truncate(info.Manufacturer, w-19))
	}

	if info.ProductCode != "" {
		fmt.Printf("║   Product Code: %-*s║\n", w-18, info.ProductCode)
	}

	if info.UpgradeCode != "" {
		fmt.Printf("║   Upgrade Code: %-*s║\n", w-18, info.UpgradeCode)
	}

	// Structure
	fmt.Printf("╠%s╣\n", border)
	fmt.Printf("║ %-*s║\n", w-1, "STRUCTURE")
	fmt.Printf("║   Tables: %-*d║\n", w-12, len(info.Tables))
	fmt.Printf("║   Files:  %-*d║\n", w-12, info.FileCount)

	if len(info.CustomActions) > 0 {
		fmt.Printf("║   Custom Actions: %-*d║\n", w-20, len(info.CustomActions))
	}

	if len(info.RegistryEntries) > 0 {
		fmt.Printf("║   Registry:       %-*d║\n", w-20, len(info.RegistryEntries))
	}

	// Tables
	if len(info.Tables) > 0 {
		fmt.Printf("╠%s╣\n", border)
		fmt.Printf("║ %-*s║\n", w-1, "TABLES")

		line := strings.Join(info.Tables, ", ")
		// Wrap long table lists
		for len(line) > w-4 {
			cut := strings.LastIndex(line[:w-4], ",")
			if cut <= 0 {
				cut = w - 4
			}

			fmt.Printf("║  %-*s║\n", w-2, line[:cut+1])
			line = strings.TrimSpace(line[cut+1:])
		}

		if line != "" {
			fmt.Printf("║  %-*s║\n", w-2, line)
		}
	}

	// Custom Actions (security-relevant)
	if len(info.CustomActions) > 0 {
		fmt.Printf("╠%s╣\n", border)
		fmt.Printf("║ %-*s║\n", w-1, "CUSTOM ACTIONS")

		for _, ca := range info.CustomActions {
			line := fmt.Sprintf("%-25s type=%d", Truncate(ca.Action, 25), ca.Type)
			fmt.Printf("║  %-*s║\n", w-2, Truncate(line, w-3))
		}
	}

	// Signature
	fmt.Printf("╠%s╣\n", border)
	fmt.Printf("║ %-*s║\n", w-1, "SIGNATURES")

	if info.HasSignature {
		fmt.Printf("║   Signed: %-*s║\n", w-11, "Yes (Authenticode)")
	} else {
		fmt.Printf("║   Signed: %-*s║\n", w-11, "No")
	}

	// File listing
	if len(info.Files) > 0 {
		fmt.Printf("╠%s╣\n", border)
		fmt.Printf("║ %-*s║\n", w-1, fmt.Sprintf("FILES (%d)", len(info.Files)))

		for _, f := range info.Files {
			line := fmt.Sprintf("%-40s %s", Truncate(f.Name, 40), msi.FormatBytes(f.FileSize))
			fmt.Printf("║  %-*s║\n", w-2, Truncate(line, w-3))
		}
	}

	fmt.Printf("╚%s╝\n", border)
}

// PrintMsiExtract prints the MSI extraction completion report.
func PrintMsiExtract(report *msi.ExtractReport) {
	fmt.Println("\nExtraction Complete")
	fmt.Println(strings.Repeat("=", 50))
	fmt.Printf("Source:  %s\n", report.Source)
	fmt.Printf("Output:  %s\n", report.Output)
	fmt.Printf("Streams: %d\n", report.Streams)
	fmt.Printf("Files:   %d\n", report.Files)
	fmt.Printf("Size:    %s\n", msi.FormatBytes(report.TotalSize))

	if len(report.Errors) > 0 {
		fmt.Printf("\nErrors (%d):\n", len(report.Errors))

		for _, e := range report.Errors {
			fmt.Printf("  - %s\n", e)
		}
	}

	fmt.Println(strings.Repeat("=", 50))
}

// PrintMsiVerify prints MSI signature verification results.
func PrintMsiVerify(result *msi.VerifyResult) {
	w := 66
	border := strings.Repeat("═", w)

	fmt.Printf("╔%s╗\n", border)
	fmt.Printf("║%-*s║\n", w, "  MSI SIGNATURE VERIFICATION")
	fmt.Printf("╠%s╣\n", border)
	fmt.Printf("║ File: %-*s║\n", w-7, Truncate(result.FileName, w-8))
	fmt.Printf("╠%s╣\n", border)

	if result.HasSignature {
		fmt.Printf("║ Signed: %-*s║\n", w-9, "Yes (Authenticode)")
	} else {
		fmt.Printf("║ Signed: %-*s║\n", w-9, "No")
	}

	fmt.Printf("╚%s╝\n", border)
}
