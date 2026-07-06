/*
Copyright (c) 2026 Security Research
*/
package output

import (
	"fmt"

	"github.com/inovacc/unravel-oss/pkg/css"
)

// PrintCSSResult displays CSS extraction results in human-readable format.
func PrintCSSResult(result *css.Result, verbose bool) {
	if result == nil {
		fmt.Println("No CSS extraction results.")
		return
	}

	fmt.Println("CSS Extraction Summary")
	fmt.Println("======================")
	fmt.Printf("  CSS files:        %d\n", result.Stats.CSSFiles)
	fmt.Printf("  HTML files:       %d\n", result.Stats.HTMLFiles)
	fmt.Printf("  CSS-in-JS found:  %d\n", result.Stats.CSSInJSFound)
	fmt.Printf("  Imports resolved: %d\n", result.Stats.ImportsResolved)
	fmt.Printf("  Rules deduped:    %d\n", result.Stats.RulesRemovedDedup)
	fmt.Printf("  Unused removed:   %d\n", result.Stats.UnusedRemoved)
	fmt.Printf("  Components:       %d\n", result.Stats.ComponentCount)

	if result.OutputDir != "" {
		fmt.Printf("  Output:           %s\n", result.OutputDir)
	}

	if len(result.Components) > 0 {
		fmt.Println("\nComponents:")
		for _, c := range result.Components {
			fmt.Printf("  %-30s %d stylesheets\n", c.Name, len(c.Stylesheets))
		}
	}

	if verbose && len(result.Stylesheets) > 0 {
		fmt.Println("\nStylesheets:")
		for _, s := range result.Stylesheets {
			sizeInfo := ""
			if s.OriginalSize > 0 {
				sizeInfo = fmt.Sprintf(" (%s -> %s)",
					FormatSize(s.OriginalSize),
					FormatSize(s.CleanedSize))
			}
			fmt.Printf("  [%s] %-50s %d rules%s\n",
				s.Source, Truncate(s.Path, 50), s.RuleCount, sizeInfo)
		}
	}

	if len(result.Errors) > 0 {
		fmt.Printf("\nWarnings: %d\n", len(result.Errors))
		for _, e := range result.Errors {
			fmt.Printf("  - %s\n", Truncate(e, 120))
		}
	}
}

// PrintCSSBatchResult displays batch CSS extraction results.
func PrintCSSBatchResult(results []*css.Result) {
	fmt.Printf("Batch CSS Extraction: %d paths processed\n\n", len(results))

	totalCSS := 0
	totalErrors := 0

	for i, r := range results {
		if r == nil {
			fmt.Printf("[%d] (nil result)\n", i+1)
			continue
		}

		status := "OK"
		if len(r.Errors) > 0 {
			status = fmt.Sprintf("%d warnings", len(r.Errors))
		}

		fmt.Printf("[%d] %d CSS files, %d components  [%s]\n",
			i+1, r.Stats.CSSFiles, r.Stats.ComponentCount, status)

		totalCSS += r.Stats.CSSFiles
		totalErrors += len(r.Errors)
	}

	fmt.Printf("\nTotal: %d CSS files, %d warnings\n", totalCSS, totalErrors)
}
