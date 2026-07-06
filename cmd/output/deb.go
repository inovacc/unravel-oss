/*
Copyright (c) 2026 Security Research
*/
package output

import (
	"fmt"
	"strings"

	"github.com/inovacc/unravel-oss/pkg/deb"
)

// PrintDebInfo prints DEB package metadata analysis.
func PrintDebInfo(info *deb.InfoResult) {
	w := 66
	border := strings.Repeat("═", w)

	fmt.Printf("╔%s╗\n", border)
	fmt.Printf("║%-*s║\n", w, "  DEB PACKAGE ANALYSIS")
	fmt.Printf("╠%s╣\n", border)
	fmt.Printf("║ File:    %-*s║\n", w-10, Truncate(info.FileName, w-11))
	fmt.Printf("║ Size:    %-*s║\n", w-10, deb.FormatBytes(info.Size))
	fmt.Printf("║ Format:  %-*s║\n", w-10, info.FormatVersion)
	fmt.Printf("╠%s╣\n", border)

	if info.Control != nil {
		ctrl := info.Control

		fmt.Printf("║ %-*s║\n", w-1, "PACKAGE METADATA")
		fmt.Printf("║   Package:      %-*s║\n", w-18, ctrl.Package)
		fmt.Printf("║   Version:      %-*s║\n", w-18, ctrl.Version)
		fmt.Printf("║   Architecture: %-*s║\n", w-18, ctrl.Architecture)
		fmt.Printf("║   Maintainer:   %-*s║\n", w-18, Truncate(ctrl.Maintainer, w-19))

		if ctrl.Section != "" {
			fmt.Printf("║   Section:      %-*s║\n", w-18, ctrl.Section)
		}

		if ctrl.Priority != "" {
			fmt.Printf("║   Priority:     %-*s║\n", w-18, ctrl.Priority)
		}

		if ctrl.Homepage != "" {
			fmt.Printf("║   Homepage:     %-*s║\n", w-18, Truncate(ctrl.Homepage, w-19))
		}

		if ctrl.InstalledSize != "" {
			fmt.Printf("║   Inst. Size:   %-*s║\n", w-18, ctrl.InstalledSize+" KiB")
		}

		if ctrl.Description != "" {
			desc := ctrl.Description
			if idx := strings.Index(desc, "\n"); idx > 0 {
				desc = desc[:idx]
			}

			fmt.Printf("║   Description:  %-*s║\n", w-18, Truncate(strings.TrimSpace(desc), w-19))
		}

		if ctrl.Depends != "" {
			fmt.Printf("╠%s╣\n", border)
			fmt.Printf("║ %-*s║\n", w-1, "DEPENDENCIES")

			for dep := range strings.SplitSeq(ctrl.Depends, ",") {
				fmt.Printf("║   %-*s║\n", w-3, Truncate(strings.TrimSpace(dep), w-4))
			}
		}
	}

	// Archives and scripts
	fmt.Printf("╠%s╣\n", border)
	fmt.Printf("║ %-*s║\n", w-1, "STRUCTURE")
	fmt.Printf("║   Control: %-*s║\n", w-12, info.ControlArchive)
	fmt.Printf("║   Data:    %-*s║\n", w-12, info.DataArchive)
	fmt.Printf("║   Files:   %-*d║\n", w-12, info.FileCount)
	fmt.Printf("║   Dirs:    %-*d║\n", w-12, info.DirCount)
	fmt.Printf("║   Size:    %-*s║\n", w-12, deb.FormatBytes(info.TotalSize))

	if len(info.Scripts) > 0 {
		fmt.Printf("║   Scripts: %-*s║\n", w-12, strings.Join(info.Scripts, ", "))
	}

	// Signature
	fmt.Printf("╠%s╣\n", border)
	fmt.Printf("║ %-*s║\n", w-1, "SIGNATURES")

	if info.HasSignature {
		fmt.Printf("║   Signed: %-*s║\n", w-11, "Yes")

		for _, sf := range info.SignatureFiles {
			fmt.Printf("║   %-*s║\n", w-3, sf)
		}
	} else {
		fmt.Printf("║   Signed: %-*s║\n", w-11, "No")
	}

	// File listing (verbose)
	if len(info.Files) > 0 {
		fmt.Printf("╠%s╣\n", border)
		fmt.Printf("║ %-*s║\n", w-1, fmt.Sprintf("FILES (%d)", len(info.Files)))

		for _, f := range info.Files {
			if f.IsDir {
				fmt.Printf("║   %-*s║\n", w-3, Truncate(f.Name+"/", w-4))
			} else if f.IsLink {
				line := fmt.Sprintf("%s -> %s", f.Name, f.LinkTarget)
				fmt.Printf("║   %-*s║\n", w-3, Truncate(line, w-4))
			} else {
				line := fmt.Sprintf("%-45s %s", Truncate(f.Name, 45), deb.FormatBytes(f.Size))
				fmt.Printf("║   %-*s║\n", w-3, Truncate(line, w-4))
			}
		}
	}

	fmt.Printf("╚%s╝\n", border)
}

// PrintDebExtract prints the DEB extraction completion report.
func PrintDebExtract(report *deb.ExtractReport) {
	fmt.Println("\nExtraction Complete")
	fmt.Println(strings.Repeat("=", 50))
	fmt.Printf("Source:      %s\n", report.Source)
	fmt.Printf("Output:      %s\n", report.Output)
	fmt.Printf("Files:       %d\n", report.Files)
	fmt.Printf("Directories: %d\n", report.Directories)
	fmt.Printf("Total Size:  %s\n", deb.FormatBytes(report.TotalSize))

	if len(report.Errors) > 0 {
		fmt.Printf("\nErrors (%d):\n", len(report.Errors))

		for _, e := range report.Errors {
			fmt.Printf("  - %s\n", e)
		}
	}

	fmt.Println(strings.Repeat("=", 50))
}

// PrintDebVerify prints DEB signature verification results.
func PrintDebVerify(result *deb.VerifyResult) {
	w := 66
	border := strings.Repeat("═", w)

	fmt.Printf("╔%s╗\n", border)
	fmt.Printf("║%-*s║\n", w, "  DEB SIGNATURE VERIFICATION")
	fmt.Printf("╠%s╣\n", border)
	fmt.Printf("║ File: %-*s║\n", w-7, Truncate(result.FileName, w-8))
	fmt.Printf("╠%s╣\n", border)

	if result.HasSignature {
		fmt.Printf("║ Signed: %-*s║\n", w-9, "Yes")
		fmt.Printf("║ Type:   %-*s║\n", w-9, result.SignatureType)

		for _, sf := range result.SignatureFiles {
			fmt.Printf("║   %-*s║\n", w-3, sf)
		}
	} else {
		fmt.Printf("║ Signed: %-*s║\n", w-9, "No")
		fmt.Printf("║ Note:   %-*s║\n", w-9, "Most .deb files rely on repository signatures")
	}

	fmt.Printf("╚%s╝\n", border)
}
