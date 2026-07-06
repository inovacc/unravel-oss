/*
Copyright (c) 2026 Security Research
*/
package output

import (
	"fmt"

	"github.com/inovacc/unravel-oss/pkg/nodeaddon"
)

// PrintNodeAddonInfo prints the full analysis result for a Node.js native addon.
func PrintNodeAddonInfo(r *nodeaddon.Result) {
	fmt.Printf("Node Addon: %s\n", r.FileName)
	fmt.Printf("  Path:         %s\n", r.FilePath)
	fmt.Printf("  Size:         %s\n", FormatSize(r.FileSize))
	fmt.Printf("  Format:       %s\n", r.Format)
	fmt.Printf("  Architecture: %s (%d-bit)\n", r.Architecture, r.Bits)
	fmt.Printf("  N-API:        %v\n", r.IsNAPI)

	if r.NAPIVersion > 0 {
		fmt.Printf("  N-API Version: %d\n", r.NAPIVersion)
	}

	fmt.Printf("  Exports:      %d\n", len(r.Exports))
	fmt.Printf("  Imports:      %d libraries\n", len(r.Imports))
	fmt.Printf("  Risk Score:   %d/100\n", r.RiskScore)

	if len(r.NAPIExports) > 0 {
		fmt.Println("\nN-API Exports:")
		for _, name := range r.NAPIExports {
			fmt.Printf("  %s\n", name)
		}
	}

	if len(r.Exports) > 0 {
		fmt.Println("\nExported Functions:")
		shown := 0
		for _, exp := range r.Exports {
			if exp.IsNAPI {
				continue // already shown above
			}
			tag := ""
			if exp.Address > 0 {
				tag = fmt.Sprintf("  @ 0x%x", exp.Address)
			}
			fmt.Printf("  %s%s\n", exp.Name, tag)
			shown++
			if shown >= 50 {
				remaining := len(r.Exports) - len(r.NAPIExports) - shown
				if remaining > 0 {
					fmt.Printf("  ... and %d more\n", remaining)
				}
				break
			}
		}
	}

	if len(r.Imports) > 0 {
		fmt.Println("\nImported Libraries:")
		for _, imp := range r.Imports {
			fmt.Printf("  %-30s  [%s]\n", imp.Library, imp.Category)
		}
	}

	if len(r.RiskFactors) > 0 {
		fmt.Println("\nRisk Factors:")
		for _, rf := range r.RiskFactors {
			fmt.Printf("  [%-8s] %-30s %s\n", rf.Severity, rf.Name, rf.Description)
		}
	}

	if r.Binding != nil {
		fmt.Println("\nBinding Info:")
		if r.Binding.PackageName != "" {
			fmt.Printf("  Package:      %s\n", r.Binding.PackageName)
		}
		if r.Binding.BuildSystem != "" {
			fmt.Printf("  Build System: %s\n", r.Binding.BuildSystem)
		}
		if r.Binding.TargetName != "" {
			fmt.Printf("  Target:       %s\n", r.Binding.TargetName)
		}
		fmt.Printf("  binding.gyp:  %v\n", r.Binding.BindingGyp)
	}

	if r.CertInfo != nil {
		fmt.Println("\nCertificate:")
		fmt.Printf("  Signed: true\n")
	}
}

// PrintNodeAddonSymbols prints the symbol table analysis.
func PrintNodeAddonSymbols(r *nodeaddon.SymbolsResult) {
	fmt.Printf("Node Addon Symbols: %s\n", r.FileName)
	fmt.Printf("  Total Symbols: %d\n", r.TotalSymbols)
	fmt.Printf("  Has N-API:     %v\n", r.HasNAPI)
	fmt.Println()

	if len(r.NAPISymbols) > 0 {
		fmt.Println("N-API Symbols:")
		for _, sym := range r.NAPISymbols {
			addr := ""
			if sym.Address > 0 {
				addr = fmt.Sprintf("  @ 0x%x", sym.Address)
			}
			fmt.Printf("  %s%s\n", sym.Name, addr)
		}
		fmt.Println()
	}

	fmt.Println("All Exports:")
	for _, sym := range r.Exports {
		tag := ""
		if sym.IsNAPI {
			tag = " [N-API]"
		}
		addr := ""
		if sym.Address > 0 {
			addr = fmt.Sprintf("  @ 0x%x", sym.Address)
		}
		fmt.Printf("  %s%s%s\n", sym.Name, tag, addr)
	}
}

// PrintNodeAddonStrings prints the strings extraction result.
func PrintNodeAddonStrings(r *nodeaddon.StringsResult) {
	fmt.Printf("Node Addon Strings: %s\n", r.FileName)
	fmt.Printf("  Total Strings:     %d\n", r.TotalStrings)
	fmt.Printf("  Avg Entropy:       %.2f\n", r.AvgEntropy)
	fmt.Printf("  High Entropy (>4.5): %d\n", r.HighEntropyCount)
	fmt.Println()

	if len(r.ByCategory) > 0 {
		fmt.Println("By Category:")
		for cat, count := range r.ByCategory {
			fmt.Printf("  %-15s %d\n", cat, count)
		}
		fmt.Println()
	}

	// Print top strings by category
	for cat, strs := range r.TopByCategory {
		if len(strs) == 0 || cat == "GENERAL" {
			continue
		}
		fmt.Printf("%s:\n", cat)
		for _, s := range strs {
			display := Truncate(s, 100)
			fmt.Printf("  %s\n", display)
		}
		fmt.Println()
	}
}
