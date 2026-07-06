/*
Copyright (c) 2026 Security Research
*/
package output

import (
	"fmt"

	"github.com/inovacc/unravel-oss/pkg/winui"
)

// DisplayWinUIDetectResult prints signals + frameworks (fast detect view).
func DisplayWinUIDetectResult(res *winui.Result) {
	if res == nil {
		fmt.Println("(no result)")
		return
	}

	fmt.Printf("IsWinUI:     %s\n", BoolYesNo(res.IsWinUI))
	if len(res.Frameworks) > 0 {
		fmt.Printf("\nFrameworks (%d):\n", len(res.Frameworks))
		for _, fi := range res.Frameworks {
			ver := fi.Version
			if ver == "" {
				ver = "-"
			}
			fmt.Printf("  %-20s ver=%-12s conf=%-9s src=%s\n",
				Truncate(fi.Name, 20), Truncate(ver, 12), fi.Confidence, fi.Source)
		}
	} else {
		fmt.Println("\nFrameworks: (none)")
	}

	if len(res.Signals) > 0 {
		fmt.Printf("\nSignals (%d):\n", len(res.Signals))
		for _, s := range res.Signals {
			fmt.Printf("  %-16s conf=%-9s %s\n", s.Kind, s.Confidence, Truncate(s.Detail, 80))
		}
	}

	if len(res.Errors) > 0 {
		fmt.Printf("\nErrors (%d):\n", len(res.Errors))
		for _, e := range res.Errors {
			fmt.Printf("  - %s\n", Truncate(e, 100))
		}
	}
}

// DisplayWinUIAnalyzeResult prints detection summary + XAMLIndex.
func DisplayWinUIAnalyzeResult(res *winui.Result) {
	if res == nil {
		fmt.Println("(no result)")
		return
	}

	DisplayWinUIDetectResult(res)
	DisplayWinUIXAMLIndex(res.XAMLIndex)
}

// DisplayWinUIXAMLIndex prints a compact XAML index summary.
func DisplayWinUIXAMLIndex(idx *winui.XAMLIndex) {
	if idx == nil || len(idx.Entries) == 0 {
		fmt.Println("\nXAML Index: (empty)")
		return
	}

	fmt.Printf("\nXAML Index (%d entries):\n", len(idx.Entries))
	for _, e := range idx.Entries {
		fmt.Printf("  [%-16s] keys=%-3d controls=%-3d bindings=%-3d  %s\n",
			e.Kind, len(e.ResourceKeys), len(e.ControlTypes), len(e.Bindings),
			Truncate(e.Path, 80))
	}
	if len(idx.Errors) > 0 {
		fmt.Printf("XAML Errors (%d):\n", len(idx.Errors))
		for _, e := range idx.Errors {
			fmt.Printf("  - %s\n", Truncate(e, 100))
		}
	}
}
