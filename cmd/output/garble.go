/*
Copyright (c) 2026 Security Research
*/
package output

import (
	"fmt"
	"strings"

	"github.com/inovacc/unravel-oss/pkg/garble"
)

// PrintGarbleDetect prints a box-drawing display for garble detection results.
func PrintGarbleDetect(result *garble.DetectionResult) {
	w := 66
	border := strings.Repeat("═", w)

	fmt.Printf("╔%s╗\n", border)
	fmt.Printf("║%-*s║\n", w, "  GARBLE OBFUSCATION DETECTION")
	fmt.Printf("╠%s╣\n", border)
	fmt.Printf("║ File: %-*s║\n", w-7, Truncate(result.FileName, w-8))
	fmt.Printf("║ Path: %-*s║\n", w-7, Truncate(result.FilePath, w-8))
	fmt.Printf("║ Size: %-*s║\n", w-7, FormatSize(result.FileSize))
	fmt.Printf("║ Format: %-*s║\n", w-9, result.Format)
	fmt.Printf("╠%s╣\n", border)

	// Verdict
	verdict := "NOT GARBLED"
	if result.IsGarbled {
		verdict = fmt.Sprintf("GARBLED (%s confidence)", result.ConfidenceLabel)
	}

	fmt.Printf("║ Verdict: %-*s║\n", w-10, verdict)
	fmt.Printf("║ Confidence: %-*s║\n", w-13, fmt.Sprintf("%.1f%%", result.Confidence*100))
	fmt.Printf("╠%s╣\n", border)

	// Heuristics
	fmt.Printf("║ %-*s║\n", w-1, "HEURISTICS")

	for i, h := range result.Heuristics {
		indicator := "[ ]"
		if h.Detected {
			indicator = "[X]"
		}

		desc := fmt.Sprintf("%s %s (%.2f)", indicator, h.Description, h.Weight)
		fmt.Printf("║  %d. %-*s║\n", i+1, w-5, Truncate(desc, w-6))

		if h.Details != "" {
			fmt.Printf("║     %-*s║\n", w-5, Truncate(h.Details, w-6))
		}
	}

	fmt.Printf("╚%s╝\n", border)
}

// PrintGarbleInfo prints a box-drawing display for Go binary metadata.
func PrintGarbleInfo(info *garble.BinaryInfo, verbose bool) {
	w := 66
	border := strings.Repeat("═", w)

	fmt.Printf("╔%s╗\n", border)
	fmt.Printf("║%-*s║\n", w, "  GO BINARY INFO")
	fmt.Printf("╠%s╣\n", border)
	fmt.Printf("║ File: %-*s║\n", w-7, Truncate(info.FileName, w-8))
	fmt.Printf("║ Path: %-*s║\n", w-7, Truncate(info.FilePath, w-8))
	fmt.Printf("║ Size: %-*s║\n", w-7, FormatSize(info.FileSize))
	fmt.Printf("║ Format: %-*s║\n", w-9, info.Format)
	fmt.Printf("╠%s╣\n", border)

	fmt.Printf("║ %-*s║\n", w-1, "BUILD")

	goVer := info.GoVersion
	if goVer == "" {
		goVer = "(unknown)"
	}

	fmt.Printf("║   Go Version: %-*s║\n", w-15, goVer)

	modulePath := info.ModulePath
	if modulePath == "" {
		modulePath = "(unknown)"
	}

	fmt.Printf("║   Module:     %-*s║\n", w-15, Truncate(modulePath, w-16))

	fmt.Printf("║   OS/Arch:    %-*s║\n", w-15, fmt.Sprintf("%s/%s", info.OS, info.Arch))

	if info.BuildID != "" {
		fmt.Printf("║   Build ID:   %-*s║\n", w-15, Truncate(info.BuildID, w-16))
	}

	fmt.Printf("╠%s╣\n", border)
	fmt.Printf("║ %-*s║\n", w-1, "FEATURES")

	fmt.Printf("║   Static linked:  %-*s║\n", w-19, BoolYesNo(info.IsStaticLinked))
	fmt.Printf("║   Symbol table:   %-*s║\n", w-19, BoolYesNo(info.HasSymbolTable))

	if info.HasSymbolTable {
		fmt.Printf("║   Symbol count:   %-*s║\n", w-19, fmt.Sprintf("%d", info.SymbolCount))
	}

	fmt.Printf("║   DWARF debug:    %-*s║\n", w-19, BoolYesNo(info.HasDWARF))
	fmt.Printf("║   Build info:     %-*s║\n", w-19, BoolYesNo(info.HasBuildInfo))

	// Build settings
	if len(info.BuildSettings) > 0 {
		fmt.Printf("╠%s╣\n", border)
		fmt.Printf("║ %-*s║\n", w-1, "BUILD SETTINGS")

		for k, v := range info.BuildSettings {
			line := fmt.Sprintf("%s = %s", k, v)
			fmt.Printf("║   %-*s║\n", w-3, Truncate(line, w-4))
		}
	}

	// Sections (verbose)
	if verbose && len(info.Sections) > 0 {
		fmt.Printf("╠%s╣\n", border)
		fmt.Printf("║ %-*s║\n", w-1, fmt.Sprintf("SECTIONS (%d)", len(info.Sections)))

		for _, sect := range info.Sections {
			fmt.Printf("║   %-*s║\n", w-3, Truncate(sect, w-4))
		}
	}

	fmt.Printf("╚%s╝\n", border)
}

// PrintGarbleStrings prints a table of extracted strings with entropy analysis.
func PrintGarbleStrings(result *garble.StringsResult, verbose bool) {
	fmt.Printf("File: %s\n", result.FileName)
	fmt.Printf("Total strings: %d\n", result.TotalStrings)
	fmt.Printf("Average entropy: %.2f bits\n", result.AvgEntropy)
	fmt.Printf("High-entropy strings (>4.5): %d\n\n", result.HighEntropyCount)

	// Category summary
	fmt.Printf("%-15s %s\n", "CATEGORY", "COUNT")
	fmt.Println(strings.Repeat("-", 25))

	for cat, count := range result.ByCategory {
		fmt.Printf("%-15s %d\n", cat, count)
	}

	fmt.Println()

	// Top strings per category
	for cat, strs := range result.TopByCategory {
		if cat == garble.CatGeneral {
			continue
		}

		fmt.Printf("[%s]\n", cat)

		for _, s := range strs {
			display := s
			if len(display) > 80 {
				display = display[:77] + "..."
			}

			fmt.Printf("  %s\n", display)
		}

		fmt.Println()
	}

	// If verbose, show all strings
	if verbose {
		fmt.Printf("%-8s %-10s %-15s %-6s %s\n", "OFFSET", "LENGTH", "CATEGORY", "ENT", "VALUE")
		fmt.Println(strings.Repeat("-", 90))

		for _, s := range result.Strings {
			val := s.Value
			if len(val) > 50 {
				val = val[:47] + "..."
			}

			fmt.Printf("%-8d %-10d %-15s %-6.2f %s\n",
				s.Offset, s.Length, s.Category, s.Entropy, val)
		}
	}
}

// PrintGarbleSymbols prints a table of binary symbols with obfuscation analysis.
func PrintGarbleSymbols(result *garble.SymbolsResult, verbose bool) {
	fmt.Printf("File: %s\n", result.FileName)
	fmt.Printf("Format: %s\n", result.Format)
	fmt.Printf("Total symbols: %d\n", result.TotalSymbols)
	fmt.Printf("Functions: %d\n", result.FunctionCount)
	fmt.Printf("Objects: %d\n", result.ObjectCount)
	fmt.Printf("Runtime symbols: %d\n", result.RuntimeCount)
	fmt.Printf("Obfuscated symbols: %d\n", result.ObfuscatedCount)
	fmt.Printf("Obfuscation ratio: %.1f%%\n\n", result.ObfuscationRatio*100)

	// Packages
	if len(result.Packages) > 0 {
		fmt.Printf("Packages (%d):\n", len(result.Packages))

		for _, pkg := range result.Packages {
			fmt.Printf("  %s\n", pkg)
		}

		fmt.Println()
	}

	// Top obfuscated
	if len(result.TopObfuscated) > 0 {
		fmt.Printf("Obfuscated symbols (top %d):\n", len(result.TopObfuscated))

		for _, name := range result.TopObfuscated {
			display := name
			if len(display) > 80 {
				display = display[:77] + "..."
			}

			fmt.Printf("  %s\n", display)
		}

		fmt.Println()
	}

	// Verbose: full symbol table
	if verbose {
		fmt.Printf("%-50s %-8s %-6s %-6s %-6s\n", "NAME", "TYPE", "OBFSC", "RTLIB", "PKG")
		fmt.Println(strings.Repeat("-", 80))

		for _, s := range result.Symbols {
			name := s.Name
			if len(name) > 50 {
				name = name[:47] + "..."
			}

			obfsc := " "
			if s.IsObfuscated {
				obfsc = "X"
			}

			rtlib := " "
			if s.IsRuntime {
				rtlib = "R"
			}

			pkg := s.Package
			if len(pkg) > 10 {
				pkg = pkg[:7] + "..."
			}

			fmt.Printf("%-50s %-8s %-6s %-6s %-6s\n", name, s.Type, obfsc, rtlib, pkg)
		}
	}
}
