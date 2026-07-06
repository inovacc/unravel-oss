/*
Copyright (c) 2026 Security Research
*/
package output

import (
	"fmt"

	"github.com/inovacc/unravel-oss/pkg/webview2"
)

// DisplayDetectResult prints signals + runtime summary (fast detect view).
func DisplayDetectResult(res *webview2.Result) {
	if res == nil {
		fmt.Println("(no result)")
		return
	}

	fmt.Printf("IsWebView2:   %s\n", BoolYesNo(res.IsWebView2))
	fmt.Printf("Runtime Mode: %s\n", orDash(res.Runtime.Mode))
	if res.Runtime.Version != "" {
		fmt.Printf("Runtime Ver:  %s\n", res.Runtime.Version)
	}
	if res.Runtime.InstallDir != "" {
		fmt.Printf("Runtime Dir:  %s\n", res.Runtime.InstallDir)
	}

	if len(res.Signals) > 0 {
		fmt.Printf("\nSignals (%d):\n", len(res.Signals))
		for _, s := range res.Signals {
			fmt.Printf("  %-16s conf=%.2f  %s\n", s.Kind, s.Confidence, Truncate(s.Detail, 80))
		}
	} else {
		fmt.Println("\nSignals: (none)")
	}

	if len(res.Errors) > 0 {
		fmt.Printf("\nErrors (%d):\n", len(res.Errors))
		for _, e := range res.Errors {
			fmt.Printf("  - %s\n", Truncate(e, 100))
		}
	}
}

// DisplayAnalyzeResult prints signals, runtime, UDFs, profiles, and data summary.
func DisplayAnalyzeResult(res *webview2.Result) {
	if res == nil {
		fmt.Println("(no result)")
		return
	}

	DisplayDetectResult(res)

	fmt.Printf("\nUser Data Folders (%d):\n", len(res.UDFs))
	for _, u := range res.UDFs {
		fmt.Printf("  [%-18s] exists=%s  %s\n", u.Source, BoolYesNo(u.Exists), u.Path)
	}

	fmt.Printf("\nProfiles (%d):\n", len(res.Profiles))
	for _, p := range res.Profiles {
		fmt.Printf("  %-24s  %s\n", p.Name, p.Path)
	}

	fmt.Printf("\nProfile Data Blocks: %d\n", len(res.ProfileData))
}

// DisplayUDFs prints a compact UDF-only listing.
func DisplayUDFs(res *webview2.Result) {
	if res == nil || len(res.UDFs) == 0 {
		fmt.Println("(no UDF candidates found)")
		return
	}

	fmt.Printf("User Data Folders (%d):\n", len(res.UDFs))
	for _, u := range res.UDFs {
		fmt.Printf("  [%-18s] exists=%s  %s\n", u.Source, BoolYesNo(u.Exists), u.Path)
	}

	if len(res.Profiles) > 0 {
		fmt.Printf("\nProfiles (%d):\n", len(res.Profiles))
		for _, p := range res.Profiles {
			fmt.Printf("  %-24s  %s\n", p.Name, p.Path)
		}
	}
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}
