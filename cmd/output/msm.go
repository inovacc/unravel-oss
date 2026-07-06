/*
Copyright (c) 2026 Security Research
*/
package output

import (
	"fmt"
	"strings"

	"github.com/inovacc/unravel-oss/pkg/msm"
)

// PrintMsmInfo prints Merge Module (.msm) metadata analysis.
func PrintMsmInfo(info *msm.InfoResult) {
	w := 66
	border := strings.Repeat("═", w)

	fmt.Printf("╔%s╗\n", border)
	fmt.Printf("║%-*s║\n", w, "  MERGE MODULE (MSM) ANALYSIS")
	fmt.Printf("╠%s╣\n", border)
	fmt.Printf("║ File:    %-*s║\n", w-10, Truncate(info.FileName, w-11))
	fmt.Printf("║ Size:    %-*s║\n", w-10, msm.FormatBytes(info.Size))
	fmt.Printf("╠%s╣\n", border)

	fmt.Printf("║ %-*s║\n", w-1, "MODULE")
	yesNo := "No"
	if info.IsMergeModule {
		yesNo = "Yes"
	}
	fmt.Printf("║   Merge Module: %-*s║\n", w-18, yesNo)
	if info.ModuleID != "" {
		fmt.Printf("║   Module ID:    %-*s║\n", w-18, Truncate(info.ModuleID, w-19))
	}
	if info.Version != "" {
		fmt.Printf("║   Version:      %-*s║\n", w-18, info.Version)
	}
	if info.Language != 0 {
		fmt.Printf("║   Language:     %-*d║\n", w-18, info.Language)
	}

	fmt.Printf("╠%s╣\n", border)
	fmt.Printf("║ %-*s║\n", w-1, "STRUCTURE")
	fmt.Printf("║   Tables:       %-*d║\n", w-18, len(info.Tables))
	fmt.Printf("║   Components:   %-*d║\n", w-18, len(info.Components))
	fmt.Printf("║   Files:        %-*d║\n", w-18, len(info.Files))
	fmt.Printf("║   Driver Files: %-*d║\n", w-18, len(info.DriverFiles))

	signed := "No"
	if info.HasSignature {
		signed = "Yes (Authenticode)"
	}
	fmt.Printf("║   Signed:       %-*s║\n", w-18, signed)

	if len(info.EmbeddedCabinets) > 0 {
		fmt.Printf("╠%s╣\n", border)
		fmt.Printf("║ %-*s║\n", w-1, "EMBEDDED CABINETS")
		for _, c := range info.EmbeddedCabinets {
			fmt.Printf("║   %-*s║\n", w-3, Truncate(c, w-4))
		}
	}

	if len(info.DriverFiles) > 0 {
		fmt.Printf("╠%s╣\n", border)
		fmt.Printf("║ %-*s║\n", w-1, fmt.Sprintf("DRIVER FILES (%d)", len(info.DriverFiles)))
		for _, f := range info.DriverFiles {
			line := fmt.Sprintf("%-40s %s", Truncate(f.Name, 40), msm.FormatBytes(f.FileSize))
			fmt.Printf("║   %-*s║\n", w-3, Truncate(line, w-4))
		}
	}

	if len(info.Files) > 0 {
		fmt.Printf("╠%s╣\n", border)
		fmt.Printf("║ %-*s║\n", w-1, fmt.Sprintf("FILES (%d)", len(info.Files)))
		for _, f := range info.Files {
			tag := ""
			if f.IsDriver {
				tag = " [driver]"
			}
			line := fmt.Sprintf("%-40s%s", Truncate(f.Name, 40), tag)
			fmt.Printf("║   %-*s║\n", w-3, Truncate(line, w-4))
		}
	}

	if len(info.Warnings) > 0 {
		fmt.Printf("╠%s╣\n", border)
		fmt.Printf("║ %-*s║\n", w-1, "WARNINGS")
		for _, warn := range info.Warnings {
			fmt.Printf("║   %-*s║\n", w-3, Truncate(warn, w-4))
		}
	}

	fmt.Printf("╚%s╝\n", border)
}
