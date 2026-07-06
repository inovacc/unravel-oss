/*
Copyright (c) 2026 Security Research
*/
package output

import (
	"fmt"
	"strings"

	"github.com/inovacc/unravel-oss/pkg/extension"
)

// PrintExtensionDetail prints detailed extension analysis with box drawing.
func PrintExtensionDetail(info *extension.ExtensionInfo) {
	fmt.Println("╔══════════════════════════════════════════════════════════════╗")
	fmt.Println("║                 EXTENSION ANALYSIS                           ║")
	fmt.Println("╠══════════════════════════════════════════════════════════════╣")
	fmt.Printf("║ Name: %-54s ║\n", Truncate(info.Name, 54))
	fmt.Printf("║ ID: %-56s ║\n", info.ID)
	fmt.Printf("║ Version: %-51s ║\n", info.Version)
	fmt.Printf("║ Manifest: V%-49d ║\n", info.ManifestVer)
	fmt.Printf("║ Browser: %-51s ║\n", info.Browser)
	fmt.Printf("║ Profile: %-51s ║\n", info.Profile)
	fmt.Println("╠══════════════════════════════════════════════════════════════╣")
	fmt.Printf("║ Risk Level: %-48s ║\n", info.RiskLevel)
	fmt.Printf("║ Risk Score: %-48d ║\n", info.RiskScore)
	fmt.Println("╚══════════════════════════════════════════════════════════════╝")

	// Permissions
	if len(info.Permissions.All) > 0 {
		fmt.Printf("\nPermissions (%d total)\n", len(info.Permissions.All))
		fmt.Println(strings.Repeat("-", 60))

		for _, level := range []string{"CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"} {
			perms := info.Permissions.ByRisk[level]
			if len(perms) == 0 {
				continue
			}

			fmt.Printf("  [%s]\n", level)

			for _, p := range perms {
				fmt.Printf("    - %s\n", p)
			}
		}
	}

	if len(info.Permissions.Hosts) > 0 {
		fmt.Printf("\nHost Permissions (%d)\n", len(info.Permissions.Hosts))
		fmt.Println(strings.Repeat("-", 60))

		for _, h := range info.Permissions.Hosts {
			fmt.Printf("    %s\n", h)
		}
	}

	// Content Scripts
	if len(info.ContentScripts) > 0 {
		fmt.Printf("\nContent Scripts (%d)\n", len(info.ContentScripts))
		fmt.Println(strings.Repeat("-", 60))

		for _, cs := range info.ContentScripts {
			fmt.Printf("  Matches: %s\n", strings.Join(cs.Matches, ", "))

			if cs.RunAt != "" {
				fmt.Printf("  Run At: %s\n", cs.RunAt)
			}

			for _, js := range cs.JS {
				fmt.Printf("    JS: %s\n", js)
			}
		}
	}

	// Code Findings
	if len(info.CodeFindings) > 0 {
		fmt.Printf("\nSuspicious Code Patterns (%d)\n", len(info.CodeFindings))
		fmt.Println(strings.Repeat("-", 60))

		for _, f := range info.CodeFindings {
			fmt.Printf("  [%s] %s\n", f.Risk, f.Pattern)
			fmt.Printf("    File: %s", f.File)

			if f.Line > 0 {
				fmt.Printf(":%d", f.Line)
			}

			fmt.Println()

			if f.Context != "" {
				fmt.Printf("    Context: ...%s...\n", f.Context)
			}
		}
	}

	// Stealth Findings
	if len(info.StealthFlags) > 0 {
		fmt.Printf("\nStealth Indicators (%d)\n", len(info.StealthFlags))
		fmt.Println(strings.Repeat("-", 60))

		for _, f := range info.StealthFlags {
			fmt.Printf("  [%s] %s\n", f.Risk, f.Name)
			fmt.Printf("    %s\n", f.Description)

			if f.File != "" {
				fmt.Printf("    File: %s\n", f.File)
			}

			fmt.Printf("    Evidence: %s\n", f.Evidence)
		}
	}

	// Cheating Flags
	if len(info.CheatingFlags) > 0 {
		fmt.Printf("\nCheating Indicators (%d)\n", len(info.CheatingFlags))
		fmt.Println(strings.Repeat("-", 60))

		for _, f := range info.CheatingFlags {
			fmt.Printf("  - %s\n", f)
		}
	}
}
