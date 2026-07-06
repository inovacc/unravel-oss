/*
Copyright (c) 2026 Security Research
*/
package output

import (
	"fmt"
	"strings"

	"github.com/inovacc/unravel-oss/pkg/msix"
)

// PrintMsixInfo prints MSIX package metadata analysis.
func PrintMsixInfo(info *msix.InfoResult) {
	w := 66
	border := strings.Repeat("═", w)

	fmt.Printf("╔%s╗\n", border)
	fmt.Printf("║%-*s║\n", w, "  MSIX PACKAGE ANALYSIS")
	fmt.Printf("╠%s╣\n", border)
	fmt.Printf("║ File:    %-*s║\n", w-10, Truncate(info.FileName, w-11))
	fmt.Printf("║ Size:    %-*s║\n", w-10, msix.FormatBytes(info.Size))
	fmt.Printf("╠%s╣\n", border)

	// Package identity
	fmt.Printf("║ %-*s║\n", w-1, "PACKAGE IDENTITY")

	if info.PackageName != "" {
		fmt.Printf("║   Name:         %-*s║\n", w-18, Truncate(info.PackageName, w-19))
	}

	if info.PackageVersion != "" {
		fmt.Printf("║   Version:      %-*s║\n", w-18, info.PackageVersion)
	}

	if info.Publisher != "" {
		fmt.Printf("║   Publisher:    %-*s║\n", w-18, Truncate(info.Publisher, w-19))
	}

	if info.DisplayName != "" {
		fmt.Printf("║   Display Name: %-*s║\n", w-18, Truncate(info.DisplayName, w-19))
	}

	if info.ProcessorArchitecture != "" {
		fmt.Printf("║   Architecture: %-*s║\n", w-18, info.ProcessorArchitecture)
	}

	// Structure
	fmt.Printf("╠%s╣\n", border)
	fmt.Printf("║ %-*s║\n", w-1, "STRUCTURE")
	fmt.Printf("║   Files:      %-*d║\n", w-16, info.FileCount)
	fmt.Printf("║   Total Size: %-*s║\n", w-16, msix.FormatBytes(info.TotalSize))
	fmt.Printf("║   BlockMap:   %-*v║\n", w-16, info.HasBlockMap)
	fmt.Printf("║   Signed:     %-*v║\n", w-16, info.HasSignature)

	// Dependencies
	if len(info.Dependencies) > 0 {
		fmt.Printf("╠%s╣\n", border)
		fmt.Printf("║ %-*s║\n", w-1, "DEPENDENCIES")

		for _, dep := range info.Dependencies {
			line := fmt.Sprintf("%s (min: %s)", dep.Name, dep.MinVersion)
			fmt.Printf("║  %-*s║\n", w-2, Truncate(line, w-3))
		}
	}

	// Capabilities
	if len(info.Capabilities) > 0 {
		fmt.Printf("╠%s╣\n", border)
		fmt.Printf("║ %-*s║\n", w-1, "CAPABILITIES")

		for _, cap := range info.Capabilities {
			fmt.Printf("║  %-*s║\n", w-2, Truncate(cap, w-3))
		}
	}

	// Applications
	if len(info.Applications) > 0 {
		fmt.Printf("╠%s╣\n", border)
		fmt.Printf("║ %-*s║\n", w-1, "APPLICATIONS")

		for _, app := range info.Applications {
			line := fmt.Sprintf("%-20s → %s", Truncate(app.ID, 20), app.Executable)
			fmt.Printf("║  %-*s║\n", w-2, Truncate(line, w-3))
		}
	}

	// Signature
	fmt.Printf("╠%s╣\n", border)
	fmt.Printf("║ %-*s║\n", w-1, "SIGNATURES")

	if info.HasSignature {
		fmt.Printf("║   Signed: %-*s║\n", w-11, "Yes (AppxSignature.p7x)")
	} else {
		fmt.Printf("║   Signed: %-*s║\n", w-11, "No")
	}

	// File listing
	if len(info.Files) > 0 {
		fmt.Printf("╠%s╣\n", border)
		fmt.Printf("║ %-*s║\n", w-1, fmt.Sprintf("FILES (%d)", len(info.Files)))

		for _, f := range info.Files {
			line := fmt.Sprintf("%-40s %s", Truncate(f.Name, 40), msix.FormatBytes(f.Size))
			fmt.Printf("║  %-*s║\n", w-2, Truncate(line, w-3))
		}
	}

	fmt.Printf("╚%s╝\n", border)
}

// PrintMsixExtract prints the MSIX extraction completion report.
func PrintMsixExtract(report *msix.ExtractReport) {
	fmt.Println("\nExtraction Complete")
	fmt.Println(strings.Repeat("=", 50))
	fmt.Printf("Source:      %s\n", report.Source)
	fmt.Printf("Output:      %s\n", report.Output)
	fmt.Printf("Files:       %d\n", report.Files)
	fmt.Printf("Directories: %d\n", report.Directories)
	fmt.Printf("Size:        %s\n", msix.FormatBytes(report.TotalSize))

	if len(report.Errors) > 0 {
		fmt.Printf("\nErrors (%d):\n", len(report.Errors))

		for _, e := range report.Errors {
			fmt.Printf("  - %s\n", e)
		}
	}

	fmt.Println(strings.Repeat("=", 50))
}

// PrintMsixVerify prints MSIX signature verification results.
func PrintMsixVerify(result *msix.VerifyResult) {
	w := 66
	border := strings.Repeat("═", w)

	fmt.Printf("╔%s╗\n", border)
	fmt.Printf("║%-*s║\n", w, "  MSIX SIGNATURE VERIFICATION")
	fmt.Printf("╠%s╣\n", border)
	fmt.Printf("║ File: %-*s║\n", w-7, Truncate(result.FileName, w-8))
	fmt.Printf("╠%s╣\n", border)

	if result.HasSignature {
		fmt.Printf("║ Signed:   %-*s║\n", w-11, "Yes (AppxSignature.p7x)")
	} else {
		fmt.Printf("║ Signed:   %-*s║\n", w-11, "No")
	}

	if result.HasBlockMap {
		fmt.Printf("║ BlockMap: %-*s║\n", w-11, "Yes")
	} else {
		fmt.Printf("║ BlockMap: %-*s║\n", w-11, "No")
	}

	fmt.Printf("╚%s╝\n", border)
}
