/*
Copyright (c) 2026 Security Research
*/
package output

import (
	"fmt"
	"strings"
	"time"

	"github.com/inovacc/unravel-oss/pkg/rpm"
)

// PrintRpmInfo prints RPM package metadata analysis.
func PrintRpmInfo(info *rpm.InfoResult) {
	w := 66
	border := strings.Repeat("═", w)

	fmt.Printf("╔%s╗\n", border)
	fmt.Printf("║%-*s║\n", w, "  RPM PACKAGE ANALYSIS")
	fmt.Printf("╠%s╣\n", border)
	fmt.Printf("║ File:    %-*s║\n", w-10, Truncate(info.FileName, w-11))
	fmt.Printf("║ Size:    %-*s║\n", w-10, rpm.FormatBytes(info.Size))
	fmt.Printf("║ RPM:     %-*s║\n", w-10, info.RPMVersion)
	fmt.Printf("║ Type:    %-*s║\n", w-10, info.Type)
	fmt.Printf("╠%s╣\n", border)

	fmt.Printf("║ %-*s║\n", w-1, "PACKAGE METADATA")
	fmt.Printf("║   Name:         %-*s║\n", w-18, info.Name)

	nevra := info.Version
	if info.Release != "" {
		nevra += "-" + info.Release
	}

	if info.Epoch != "" {
		nevra = info.Epoch + ":" + nevra
	}

	fmt.Printf("║   Version:      %-*s║\n", w-18, nevra)
	fmt.Printf("║   Arch:         %-*s║\n", w-18, info.Arch)
	fmt.Printf("║   OS:           %-*s║\n", w-18, info.OS)
	fmt.Printf("║   License:      %-*s║\n", w-18, Truncate(info.License, w-19))

	if info.Vendor != "" {
		fmt.Printf("║   Vendor:       %-*s║\n", w-18, Truncate(info.Vendor, w-19))
	}

	if info.Packager != "" {
		fmt.Printf("║   Packager:     %-*s║\n", w-18, Truncate(info.Packager, w-19))
	}

	if info.Group != "" {
		fmt.Printf("║   Group:        %-*s║\n", w-18, Truncate(info.Group, w-19))
	}

	if info.URL != "" {
		fmt.Printf("║   URL:          %-*s║\n", w-18, Truncate(info.URL, w-19))
	}

	if info.Distribution != "" {
		fmt.Printf("║   Distribution: %-*s║\n", w-18, Truncate(info.Distribution, w-19))
	}

	if info.SourceRPM != "" {
		fmt.Printf("║   Source RPM:   %-*s║\n", w-18, Truncate(info.SourceRPM, w-19))
	}

	if info.Summary != "" {
		fmt.Printf("╠%s╣\n", border)
		fmt.Printf("║ %-*s║\n", w-1, "SUMMARY")

		for _, line := range WrapText(info.Summary, w-3) {
			fmt.Printf("║   %-*s║\n", w-3, line)
		}
	}

	fmt.Printf("╠%s╣\n", border)
	fmt.Printf("║ %-*s║\n", w-1, "BUILD INFO")

	if info.BuildTime > 0 {
		t := time.Unix(info.BuildTime, 0).UTC()
		fmt.Printf("║   Build Time:   %-*s║\n", w-18, t.Format("2006-01-02 15:04:05 UTC"))
	}

	if info.BuildHost != "" {
		fmt.Printf("║   Build Host:   %-*s║\n", w-18, Truncate(info.BuildHost, w-19))
	}

	fmt.Printf("║   Inst. Size:   %-*s║\n", w-18, rpm.FormatBytes(info.InstalledSize))
	fmt.Printf("║   Payload:      %-*s║\n", w-18, fmt.Sprintf("%s (%s)", info.PayloadFormat, info.PayloadCompressor))
	fmt.Printf("║   Header Tags:  %-*d║\n", w-18, info.HeaderTagCount)
	fmt.Printf("║   Sig Tags:     %-*d║\n", w-18, info.SigTagCount)

	// Signatures
	fmt.Printf("╠%s╣\n", border)
	fmt.Printf("║ %-*s║\n", w-1, "SIGNATURES")

	if info.HasSignature {
		fmt.Printf("║   Signed: %-*s║\n", w-11, "Yes")

		for k, v := range info.SignatureInfo {
			line := fmt.Sprintf("%-12s %s", k+":", v)
			fmt.Printf("║   %-*s║\n", w-3, Truncate(line, w-4))
		}
	} else {
		fmt.Printf("║   Signed: %-*s║\n", w-11, "No")
	}

	fmt.Printf("╚%s╝\n", border)
}

// PrintRpmExtract prints the RPM extraction completion report.
func PrintRpmExtract(report *rpm.ExtractReport) {
	fmt.Println("\nExtraction Complete")
	fmt.Println(strings.Repeat("=", 50))
	fmt.Printf("Source:      %s\n", report.Source)
	fmt.Printf("Output:      %s\n", report.Output)
	fmt.Printf("Compressor:  %s\n", report.Compressor)
	fmt.Printf("Files:       %d\n", report.Files)
	fmt.Printf("Directories: %d\n", report.Directories)
	fmt.Printf("Total Size:  %s\n", rpm.FormatBytes(report.TotalSize))

	if len(report.Errors) > 0 {
		fmt.Printf("\nErrors (%d):\n", len(report.Errors))

		for _, e := range report.Errors {
			fmt.Printf("  - %s\n", e)
		}
	}

	fmt.Println(strings.Repeat("=", 50))
}

// PrintRpmVerify prints RPM signature and hash verification.
func PrintRpmVerify(result *rpm.VerifyResult) {
	w := 66
	border := strings.Repeat("═", w)

	fmt.Printf("╔%s╗\n", border)
	fmt.Printf("║%-*s║\n", w, "  RPM SIGNATURE VERIFICATION")
	fmt.Printf("╠%s╣\n", border)
	fmt.Printf("║ File: %-*s║\n", w-7, Truncate(result.FileName, w-8))
	fmt.Printf("╠%s╣\n", border)

	if len(result.Hashes) > 0 {
		fmt.Printf("║ %-*s║\n", w-1, "HASHES")

		for algo, hash := range result.Hashes {
			fmt.Printf("║   %-6s %-*s║\n", algo+":", w-10, Truncate(hash, w-11))
		}
	}

	fmt.Printf("╠%s╣\n", border)

	if result.HasSignature {
		fmt.Printf("║ Signed: %-*s║\n", w-9, "Yes")

		for _, sig := range result.Signatures {
			fmt.Printf("║   %-*s║\n", w-3, sig)
		}
	} else {
		fmt.Printf("║ Signed: %-*s║\n", w-9, "No (no cryptographic signatures)")
	}

	fmt.Printf("╚%s╝\n", border)
}
