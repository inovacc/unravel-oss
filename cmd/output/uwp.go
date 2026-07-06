/*
Copyright (c) 2026 Security Research
*/
package output

import (
	"fmt"

	"github.com/inovacc/unravel-oss/pkg/uwp"
)

// DisplayUWPDetectResult prints UWP detection signals + frameworks.
func DisplayUWPDetectResult(res *uwp.Result) {
	if res == nil {
		fmt.Println("(no result)")
		return
	}

	fmt.Printf("IsUWP:       %s\n", BoolYesNo(res.IsUWP))
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

	if res.Manifest != nil {
		fmt.Printf("\nPackage Family Name: %s\n", orDashU(res.Manifest.PFN))
		fmt.Printf("Identity:    %s %s (%s)\n",
			res.Manifest.Identity.Name, res.Manifest.Identity.Version,
			res.Manifest.Identity.ProcessorArch)
		fmt.Printf("Publisher:   %s\n", res.Manifest.Identity.Publisher)
		if len(res.Manifest.TargetFamilies) > 0 {
			fmt.Printf("Targets:     %v\n", res.Manifest.TargetFamilies)
		}
	}

	if len(res.Errors) > 0 {
		fmt.Printf("\nErrors (%d):\n", len(res.Errors))
		for _, e := range res.Errors {
			fmt.Printf("  - %s\n", Truncate(e, 100))
		}
	}
}

// DisplayUWPAnalyzeResult prints full UWP analysis: detection + capabilities + score + DPAPI provenance.
func DisplayUWPAnalyzeResult(res *uwp.Result) {
	if res == nil {
		fmt.Println("(no result)")
		return
	}

	DisplayUWPDetectResult(res)
	DisplayUWPCapabilities(res)
	DisplayUWPScore(res.Score)
	DisplayUWPDPAPIBlobs(res.DPAPIBlobs)
	if res.XAMLIndex != nil {
		fmt.Printf("\nXAML Index (%d entries)\n", len(res.XAMLIndex.Entries))
	}
}

// DisplayUWPCapabilities prints the manifest capability list in declaration order.
func DisplayUWPCapabilities(res *uwp.Result) {
	if res == nil || res.Manifest == nil || len(res.Manifest.Capabilities) == 0 {
		fmt.Println("\nCapabilities: (none)")
		return
	}
	fmt.Printf("\nCapabilities (%d):\n", len(res.Manifest.Capabilities))
	for _, c := range res.Manifest.Capabilities {
		ns := c.Namespace
		if ns == "" {
			ns = "foundation"
		}
		fmt.Printf("  [%-12s] %s\n", ns, c.Name)
	}
}

// DisplayUWPScore prints the categorical-plus-numeric capability score.
func DisplayUWPScore(s *uwp.Score) {
	if s == nil {
		fmt.Println("\nScore: (not computed)")
		return
	}
	fmt.Printf("\nScore:       %d/100  (%s)\n", s.Value, s.Level)
	fmt.Printf("Base:        %d   Multiplier: %.2fx\n", s.Base, s.Multiplier)
	if len(s.Evidence) > 0 {
		fmt.Printf("Evidence (%d):\n", len(s.Evidence))
		for _, e := range s.Evidence {
			fmt.Printf("  - %s\n", Truncate(e, 100))
		}
	}
}

// DisplayUWPDPAPIBlobs prints provenance for DPAPI-protected blobs (D-18: never decrypted).
func DisplayUWPDPAPIBlobs(blobs []uwp.DPAPIBlob) {
	if len(blobs) == 0 {
		return
	}
	fmt.Printf("\nDPAPI Blobs (%d) — provenance only, NOT decrypted:\n", len(blobs))
	for _, b := range blobs {
		fmt.Printf("  - %s  hdr=% x  %s\n", Truncate(b.Path, 60), b.Bytes, b.Note)
	}
}

func orDashU(s string) string {
	if s == "" {
		return "-"
	}
	return s
}
