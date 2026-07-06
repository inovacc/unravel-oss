/*
Copyright (c) 2026 Security Research
*/
package output

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/inovacc/unravel-oss/pkg/android/apk"
	"github.com/inovacc/unravel-oss/pkg/android/dex"
	"github.com/inovacc/unravel-oss/pkg/android/framework"
	"github.com/inovacc/unravel-oss/pkg/android/kotlin"
	"github.com/inovacc/unravel-oss/pkg/android/manifest"
	"github.com/inovacc/unravel-oss/pkg/android/native"
	"github.com/inovacc/unravel-oss/pkg/android/network"
	"github.com/inovacc/unravel-oss/pkg/android/obfuscation"
	"github.com/inovacc/unravel-oss/pkg/android/protobuf"
	"github.com/inovacc/unravel-oss/pkg/android/resources"
	"github.com/inovacc/unravel-oss/pkg/android/secret"
	"github.com/inovacc/unravel-oss/pkg/android/telemetry"
	"github.com/inovacc/unravel-oss/pkg/android/tools"
)

// PrintAndroidInfo prints APK metadata analysis box.
func PrintAndroidInfo(info *apk.InfoResult) {
	w := 66
	border := strings.Repeat("═", w)

	fmt.Printf("╔%s╗\n", border)
	fmt.Printf("║%-*s║\n", w, "  APK ANALYSIS")
	fmt.Printf("╠%s╣\n", border)
	fmt.Printf("║ File:   %-*s║\n", w-9, Truncate(info.FileName, w-10))
	fmt.Printf("║ Format: %-*s║\n", w-9, string(info.Format))
	fmt.Printf("║ Size:   %-*s║\n", w-9, apk.FormatBytes(info.Size))
	fmt.Printf("╠%s╣\n", border)

	fmt.Printf("║ %-*s║\n", w-1, "CONTENTS")
	fmt.Printf("║   Files:        %-*d║\n", w-18, info.TotalFiles)
	fmt.Printf("║   Directories:  %-*d║\n", w-18, info.TotalDirs)
	fmt.Printf("║   Uncompressed: %-*s║\n", w-18, apk.FormatBytes(info.UncompressedSize))
	fmt.Printf("║   Manifest:     %-*s║\n", w-18, BoolYesNo(info.HasManifest))
	fmt.Printf("║   DEX files:    %-*d║\n", w-18, info.DEXCount)

	for _, dexFile := range info.DEXFiles {
		fmt.Printf("║     %-*s║\n", w-5, Truncate(dexFile, w-6))
	}

	fmt.Printf("║   Resources:    %-*s║\n", w-18, BoolYesNo(info.HasResources))
	fmt.Printf("║   Assets:       %-*s║\n", w-18, BoolYesNo(info.HasAssets))
	fmt.Printf("║   Kotlin:       %-*s║\n", w-18, BoolYesNo(info.HasKotlin))

	// Native libs
	if len(info.NativeLibs) > 0 {
		fmt.Printf("╠%s╣\n", border)
		fmt.Printf("║ %-*s║\n", w-1, "NATIVE LIBRARIES")

		abis := make([]string, 0, len(info.NativeLibs))
		for abi := range info.NativeLibs {
			abis = append(abis, abi)
		}

		sort.Strings(abis)

		for _, abi := range abis {
			fmt.Printf("║   %-14s %-*d║\n", abi+":", w-18, info.NativeLibs[abi])
		}
	}

	// Signatures
	fmt.Printf("╠%s╣\n", border)
	fmt.Printf("║ %-*s║\n", w-1, "SIGNATURES")
	fmt.Printf("║   Signed:       %-*s║\n", w-18, BoolYesNo(info.HasSignature))

	if len(info.SignatureSchemes) > 0 {
		fmt.Printf("║   Schemes:      %-*s║\n", w-18, strings.Join(info.SignatureSchemes, ", "))
	}

	// Bundle info (APKM/XAPK)
	if info.BundleInfo != nil {
		bi := info.BundleInfo

		fmt.Printf("╠%s╣\n", border)
		fmt.Printf("║ %-*s║\n", w-1, "BUNDLE INFO")

		if bi.PackageName != "" {
			fmt.Printf("║   Package:     %-*s║\n", w-17, Truncate(bi.PackageName, w-18))
		}

		if bi.VersionName != "" {
			fmt.Printf("║   Version:     %-*s║\n", w-17, bi.VersionName)
		}

		if bi.VersionCode > 0 {
			fmt.Printf("║   Version Code: %-*d║\n", w-18, bi.VersionCode)
		}

		if bi.MinSDK > 0 {
			fmt.Printf("║   Min SDK:     %-*d║\n", w-17, bi.MinSDK)
		}

		if bi.TargetSDK > 0 {
			fmt.Printf("║   Target SDK:  %-*d║\n", w-17, bi.TargetSDK)
		}

		if bi.ABIs != "" {
			fmt.Printf("║   ABIs:        %-*s║\n", w-17, bi.ABIs)
		}

		if bi.IconFile != "" {
			fmt.Printf("║   Icon:        %-*s║\n", w-17, bi.IconFile)
		}
	}

	// Split APKs (APKM/XAPK)
	if len(info.SplitAPKs) > 0 {
		fmt.Printf("╠%s╣\n", border)
		fmt.Printf("║ %-*s║\n", w-1, fmt.Sprintf("SPLIT APKs (%d)", len(info.SplitAPKs)))

		for _, sa := range info.SplitAPKs {
			fmt.Printf("║   %-*s║\n", w-3, Truncate(sa, w-4))
		}
	}

	// Entries (verbose)
	if len(info.Entries) > 0 {
		fmt.Printf("╠%s╣\n", border)
		fmt.Printf("║ %-*s║\n", w-1, fmt.Sprintf("ENTRIES (%d)", len(info.Entries)))

		for _, e := range info.Entries {
			if e.IsDir {
				fmt.Printf("║   %-*s║\n", w-3, Truncate(e.Name+"/", w-4))
			} else {
				line := fmt.Sprintf("%-45s %8s  %s", Truncate(e.Name, 45), apk.FormatBytes(e.Size), e.Category)
				fmt.Printf("║   %-*s║\n", w-3, Truncate(line, w-4))
			}
		}
	}

	fmt.Printf("╚%s╝\n", border)
}

// PrintAndroidExtract prints the extraction completion report.
func PrintAndroidExtract(report *apk.ExtractReport) {
	fmt.Println("\nExtraction Complete")
	fmt.Println(strings.Repeat("=", 50))
	fmt.Printf("Source:      %s\n", report.Source)
	fmt.Printf("Output:      %s\n", report.Output)
	fmt.Printf("Format:      %s\n", report.Format)
	fmt.Printf("Files:       %d\n", report.Files)
	fmt.Printf("Directories: %d\n", report.Directories)
	fmt.Printf("Total Size:  %s\n", apk.FormatBytes(report.TotalSize))

	if len(report.Errors) > 0 {
		fmt.Printf("\nErrors (%d):\n", len(report.Errors))

		for _, e := range report.Errors {
			fmt.Printf("  - %s\n", e)
		}
	}

	fmt.Println(strings.Repeat("=", 50))
}

// PrintAndroidVerify prints APK signature verification results.
func PrintAndroidVerify(result *apk.VerifyResult) {
	w := 66
	border := strings.Repeat("═", w)

	fmt.Printf("╔%s╗\n", border)
	fmt.Printf("║%-*s║\n", w, "  APK SIGNATURE VERIFICATION")
	fmt.Printf("╠%s╣\n", border)
	fmt.Printf("║ File: %-*s║\n", w-7, Truncate(result.FileName, w-8))
	fmt.Printf("╠%s╣\n", border)

	for _, sig := range result.Signatures {
		status := "NOT PRESENT"

		if sig.Present {
			if sig.Valid {
				status = "PASS"
			} else {
				status = "FAIL"
			}
		}

		label := fmt.Sprintf("%-4s  %s", string(sig.Scheme)+":", status)
		if sig.Present {
			label += fmt.Sprintf("  (signers: %d)", sig.SignerCount)
		}

		fmt.Printf("║   %-*s║\n", w-3, label)

		if sig.Error != "" {
			fmt.Printf("║     Error: %-*s║\n", w-11, Truncate(sig.Error, w-12))
		}
	}

	fmt.Printf("╠%s╣\n", border)

	overall := "INVALID"
	if result.OverallValid {
		overall = "VALID"
	}

	fmt.Printf("║ Overall: %-*s║\n", w-10, overall)

	if len(result.Schemes) > 0 {
		fmt.Printf("║ Schemes: %-*s║\n", w-10, strings.Join(result.Schemes, ", "))
	}

	fmt.Printf("╚%s╝\n", border)
}

// PrintAndroidCert prints certificate details.
func PrintAndroidCert(result *apk.CertResult) {
	w := 66
	border := strings.Repeat("═", w)

	fmt.Printf("╔%s╗\n", border)
	fmt.Printf("║%-*s║\n", w, "  APK CERTIFICATES")
	fmt.Printf("╠%s╣\n", border)
	fmt.Printf("║ File:   %-*s║\n", w-9, Truncate(result.FileName, w-10))
	fmt.Printf("║ Source: %-*s║\n", w-9, result.Source)
	fmt.Printf("╠%s╣\n", border)

	if len(result.Certificates) == 0 {
		fmt.Printf("║ %-*s║\n", w-1, "No certificates found")
		fmt.Printf("╚%s╝\n", border)

		return
	}

	for i, cert := range result.Certificates {
		if i > 0 {
			fmt.Printf("╠%s╣\n", border)
		}

		fmt.Printf("║ %-*s║\n", w-1, fmt.Sprintf("CERTIFICATE #%d", i+1))
		fmt.Printf("║   Subject:   %-*s║\n", w-15, Truncate(cert.Subject, w-16))
		fmt.Printf("║   Issuer:    %-*s║\n", w-15, Truncate(cert.Issuer, w-16))
		fmt.Printf("║   Serial:    %-*s║\n", w-15, Truncate(cert.SerialNumber, w-16))
		fmt.Printf("║   Valid:     %-*s║\n", w-15,
			fmt.Sprintf("%s to %s", cert.NotBefore.Format("2006-01-02"), cert.NotAfter.Format("2006-01-02")))
		fmt.Printf("║   Algorithm: %-*s║\n", w-15, cert.SignatureAlgorithm)
		fmt.Printf("║   PubKey:    %-*s║\n", w-15, cert.PublicKeyAlgorithm)
		fmt.Printf("║   Version:   %-*d║\n", w-15, cert.Version)

		status := "VALID"
		if cert.IsExpired {
			status = "EXPIRED"
		}

		if cert.IsSelfSigned {
			status += " (self-signed)"
		}

		fmt.Printf("║   Status:    %-*s║\n", w-15, status)

		fmt.Printf("║   %-*s║\n", w-3, "Fingerprints:")
		fmt.Printf("║     MD5:    %-*s║\n", w-13, Truncate(cert.Fingerprint.MD5, w-14))
		fmt.Printf("║     SHA1:   %-*s║\n", w-13, Truncate(cert.Fingerprint.SHA1, w-14))
		fmt.Printf("║     SHA256: %-*s║\n", w-13, Truncate(cert.Fingerprint.SHA256, w-14))
	}

	fmt.Printf("╚%s╝\n", border)
}

// PrintAndroidTools prints reverse engineering tools status.
func PrintAndroidTools(status *tools.ToolsStatus, verbose bool) {
	w := 66
	border := strings.Repeat("═", w)

	fmt.Printf("╔%s╗\n", border)
	fmt.Printf("║%-*s║\n", w, "  ANDROID REVERSE ENGINEERING TOOLS")
	fmt.Printf("╠%s╣\n", border)
	fmt.Printf("║ Available: %-*s║\n", w-12, fmt.Sprintf("%d / %d", status.Available, status.Total))
	fmt.Printf("║ Java:      %-*s║\n", w-12, BoolYesNo(status.JavaOK))
	fmt.Printf("║ .NET:      %-*s║\n", w-12, BoolYesNo(status.DotnetOK))
	fmt.Printf("║ ADB:       %-*s║\n", w-12, BoolYesNo(status.AdbOK))
	fmt.Printf("╠%s╣\n", border)

	// Sort tools by name for consistent output
	sorted := make([]*tools.Tool, len(status.Tools))
	copy(sorted, status.Tools)
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].Name < sorted[j].Name
	})

	for _, t := range sorted {
		icon := "[-]"
		if t.Available {
			icon = "[+]"
		}

		info := fmt.Sprintf("%s %-12s %-6s", icon, t.Name, string(t.Type))
		if t.Available {
			ver := t.Version
			if ver == "" {
				ver = "installed"
			}

			info += " " + Truncate(ver, w-len(info)-3)
		} else {
			info += " " + t.Error
		}

		fmt.Printf("║ %-*s║\n", w-1, Truncate(info, w-2))

		if t.Available && t.Path != "" && verbose {
			fmt.Printf("║   Path: %-*s║\n", w-9, Truncate(t.Path, w-10))
		}
	}

	fmt.Printf("╚%s╝\n", border)
}

// PrintAndroidDecompile prints decompilation pipeline status.
func PrintAndroidDecompile(result *tools.DecompileResult) {
	w := 66
	border := strings.Repeat("═", w)

	fmt.Printf("╔%s╗\n", border)
	fmt.Printf("║%-*s║\n", w, "  DECOMPILATION PIPELINE")
	fmt.Printf("╠%s╣\n", border)
	fmt.Printf("║ Input:   %-*s║\n", w-10, Truncate(result.InputPath, w-11))
	fmt.Printf("║ Format:  %-*s║\n", w-10, string(result.InputFormat))
	fmt.Printf("║ Output:  %-*s║\n", w-10, Truncate(result.OutputDir, w-11))
	fmt.Printf("║ Duration: %-*s║\n", w-11, result.TotalDuration.Round(time.Millisecond).String())
	fmt.Printf("╠%s╣\n", border)

	fmt.Printf("║ %-*s║\n", w-1, "PIPELINE STEPS")

	for _, step := range result.Steps {
		icon := "[-]"
		if step.Success {
			icon = "[+]"
		}

		line := fmt.Sprintf("%s %-10s %s (%s)", icon, step.Tool, step.Action, step.Duration.Round(time.Millisecond))
		fmt.Printf("║ %-*s║\n", w-1, Truncate(line, w-2))

		if step.Error != "" && !step.Success {
			fmt.Printf("║   Error: %-*s║\n", w-9, Truncate(step.Error, w-10))
		}
	}

	if len(result.ToolsUsed) > 0 {
		fmt.Printf("╠%s╣\n", border)
		fmt.Printf("║ Tools used:    %-*s║\n", w-16, strings.Join(result.ToolsUsed, ", "))
	}

	if len(result.ToolsSkipped) > 0 {
		fmt.Printf("║ Tools skipped: %-*s║\n", w-16, strings.Join(result.ToolsSkipped, ", "))
	}

	if len(result.ToolsMissing) > 0 {
		fmt.Printf("║ Tools missing: %-*s║\n", w-16, strings.Join(result.ToolsMissing, ", "))
	}

	if len(result.Errors) > 0 {
		fmt.Printf("╠%s╣\n", border)
		fmt.Printf("║ %-*s║\n", w-1, fmt.Sprintf("ERRORS (%d)", len(result.Errors)))

		for _, e := range result.Errors {
			fmt.Printf("║   %-*s║\n", w-3, Truncate(e, w-4))
		}
	}

	fmt.Printf("╚%s╝\n", border)
}

// PrintAndroidRun prints tool execution results.
func PrintAndroidRun(result *tools.RunResult, verbose bool) {
	w := 66
	border := strings.Repeat("═", w)

	fmt.Printf("╔%s╗\n", border)
	fmt.Printf("║%-*s║\n", w, fmt.Sprintf("  %s", strings.ToUpper(result.Tool)))
	fmt.Printf("╠%s╣\n", border)
	fmt.Printf("║ Command:  %-*s║\n", w-11, Truncate(result.Command, w-12))
	fmt.Printf("║ Duration: %-*s║\n", w-11, result.Duration.Round(time.Millisecond).String())
	fmt.Printf("║ Exit:     %-*d║\n", w-11, result.ExitCode)

	if result.OutputDir != "" {
		fmt.Printf("║ Output:   %-*s║\n", w-11, Truncate(result.OutputDir, w-12))
	}

	if result.Error != "" {
		fmt.Printf("╠%s╣\n", border)
		fmt.Printf("║ Error: %-*s║\n", w-8, Truncate(result.Error, w-9))
	}

	if result.Stdout != "" && verbose {
		fmt.Printf("╠%s╣\n", border)
		fmt.Printf("║ %-*s║\n", w-1, "STDOUT")

		for line := range strings.SplitSeq(strings.TrimSpace(result.Stdout), "\n") {
			fmt.Printf("║   %-*s║\n", w-3, Truncate(line, w-4))
		}
	}

	if result.Stderr != "" && verbose {
		fmt.Printf("╠%s╣\n", border)
		fmt.Printf("║ %-*s║\n", w-1, "STDERR")

		for line := range strings.SplitSeq(strings.TrimSpace(result.Stderr), "\n") {
			fmt.Printf("║   %-*s║\n", w-3, Truncate(line, w-4))
		}
	}

	if result.ExitCode == 0 {
		fmt.Printf("╠%s╣\n", border)
		fmt.Printf("║ %-*s║\n", w-1, "SUCCESS")
	}

	fmt.Printf("╚%s╝\n", border)
}

// PrintAndroidManifest prints AndroidManifest.xml structured display.
func PrintAndroidManifest(m *manifest.Manifest) {
	w := 66
	border := strings.Repeat("═", w)

	fmt.Printf("╔%s╗\n", border)
	fmt.Printf("║%-*s║\n", w, "  ANDROID MANIFEST")
	fmt.Printf("╠%s╣\n", border)
	fmt.Printf("║ Package:     %-*s║\n", w-14, Truncate(m.Package, w-15))
	fmt.Printf("║ Version:     %-*s║\n", w-14, fmt.Sprintf("%s (code %d)", m.VersionName, m.VersionCode))
	fmt.Printf("║ Min SDK:     %-*d║\n", w-14, m.MinSDK)
	fmt.Printf("║ Target SDK:  %-*d║\n", w-14, m.TargetSDK)

	// Security flags
	fmt.Printf("╠%s╣\n", border)
	fmt.Printf("║ %-*s║\n", w-1, "SECURITY FLAGS")
	fmt.Printf("║   Debuggable:            %-*s║\n", w-26, BoolYesNo(m.Security.Debuggable))
	fmt.Printf("║   Allow Backup:          %-*s║\n", w-26, BoolYesNo(m.Security.AllowBackup))
	fmt.Printf("║   Cleartext Traffic:     %-*s║\n", w-26, BoolYesNo(m.Security.UsesCleartextTraffic))
	fmt.Printf("║   Network Security Cfg:  %-*s║\n", w-26, BoolYesNo(m.Security.NetworkSecurityConfig))

	// Permissions
	if len(m.Permissions) > 0 {
		fmt.Printf("╠%s╣\n", border)
		fmt.Printf("║ %-*s║\n", w-1, fmt.Sprintf("PERMISSIONS (%d)", len(m.Permissions)))

		dangerous := 0

		for _, p := range m.Permissions {
			if p.RiskLevel == "dangerous" {
				dangerous++
			}
		}

		if dangerous > 0 {
			fmt.Printf("║   %-*s║\n", w-3, fmt.Sprintf("⚠ %d dangerous permissions", dangerous))
		}

		for _, p := range m.Permissions {
			risk := ""

			switch p.RiskLevel {
			case "dangerous":
				risk = " [DANGEROUS]"
			case "signature":
				risk = " [SIGNATURE]"
			}

			fmt.Printf("║   %-*s║\n", w-3, Truncate(p.Name+risk, w-4))
		}
	}

	// Components
	if len(m.Components) > 0 {
		fmt.Printf("╠%s╣\n", border)
		fmt.Printf("║ %-*s║\n", w-1, fmt.Sprintf("COMPONENTS (%d)", len(m.Components)))

		for _, c := range m.Components {
			exported := ""
			if c.Exported != nil && *c.Exported {
				exported = " [EXPORTED]"
			}

			line := fmt.Sprintf("[%s] %s%s", c.Type, c.Name, exported)
			fmt.Printf("║   %-*s║\n", w-3, Truncate(line, w-4))
		}
	}

	// Features
	if len(m.Features) > 0 {
		fmt.Printf("╠%s╣\n", border)
		fmt.Printf("║ %-*s║\n", w-1, fmt.Sprintf("FEATURES (%d)", len(m.Features)))

		for _, f := range m.Features {
			fmt.Printf("║   %-*s║\n", w-3, Truncate(f, w-4))
		}
	}

	fmt.Printf("╚%s╝\n", border)
}

// PrintAndroidSecrets prints secret scan findings.
func PrintAndroidSecrets(result *secret.ScanResult) {
	w := 66
	border := strings.Repeat("═", w)

	fmt.Printf("╔%s╗\n", border)
	fmt.Printf("║%-*s║\n", w, "  SECRET SCAN RESULTS")
	fmt.Printf("╠%s╣\n", border)
	fmt.Printf("║ Files Scanned:   %-*d║\n", w-19, result.FilesScanned)
	fmt.Printf("║ Total Findings:  %-*d║\n", w-19, result.TotalFindings)
	fmt.Printf("║ High Confidence: %-*d║\n", w-19, result.HighConfidence)
	fmt.Printf("║ Med Confidence:  %-*d║\n", w-19, result.MedConfidence)

	if len(result.Findings) > 0 {
		fmt.Printf("╠%s╣\n", border)
		fmt.Printf("║ %-*s║\n", w-1, "FINDINGS")

		for _, f := range result.Findings {
			conf := "[HIGH]"
			if f.Confidence == "medium" {
				conf = "[MED] "
			}

			line := fmt.Sprintf("%s %-22s %s", conf, f.Type, f.Value)
			fmt.Printf("║   %-*s║\n", w-3, Truncate(line, w-4))
			fmt.Printf("║     File: %-*s║\n", w-11, Truncate(f.File, w-12))
		}
	} else {
		fmt.Printf("╠%s╣\n", border)
		fmt.Printf("║ %-*s║\n", w-1, "No secrets found")
	}

	fmt.Printf("╚%s╝\n", border)
}

// PrintAndroidDex prints DEX analysis results.
func PrintAndroidDex(result *dex.ParseResult) {
	w := 66
	border := strings.Repeat("═", w)

	fmt.Printf("╔%s╗\n", border)
	fmt.Printf("║%-*s║\n", w, "  DEX ANALYSIS")
	fmt.Printf("╠%s╣\n", border)
	fmt.Printf("║ DEX Files:   %-*d║\n", w-14, len(result.DexFiles))
	fmt.Printf("║ Multi-DEX:   %-*s║\n", w-14, BoolYesNo(result.MultiDex))
	fmt.Printf("║ Classes:     %-*d║\n", w-14, result.TotalClasses)
	fmt.Printf("║ Methods:     %-*d║\n", w-14, result.TotalMethods)
	fmt.Printf("║ Fields:      %-*d║\n", w-14, result.TotalFields)
	fmt.Printf("║ Strings:     %-*d║\n", w-14, result.TotalStrings)

	for _, df := range result.DexFiles {
		fmt.Printf("╠%s╣\n", border)
		fmt.Printf("║ %-*s║\n", w-1, df.Name)
		fmt.Printf("║   Version: %-*s║\n", w-12, df.Version)
		fmt.Printf("║   Classes: %-*d║\n", w-12, len(df.Classes))
		fmt.Printf("║   Methods: %-*d║\n", w-12, len(df.Methods))
	}

	if len(result.RiskFindings) > 0 {
		fmt.Printf("╠%s╣\n", border)
		fmt.Printf("║ %-*s║\n", w-1, fmt.Sprintf("RISK FINDINGS (%d)", len(result.RiskFindings)))

		for _, f := range result.RiskFindings {
			line := fmt.Sprintf("[%s] %s: %s", f.Severity, f.Category, f.Description)
			fmt.Printf("║   %-*s║\n", w-3, Truncate(line, w-4))
		}
	}

	if len(result.HighEntropyStrings) > 0 {
		fmt.Printf("╠%s╣\n", border)
		fmt.Printf("║ %-*s║\n", w-1, fmt.Sprintf("HIGH-ENTROPY STRINGS (%d)", len(result.HighEntropyStrings)))

		limit := min(len(result.HighEntropyStrings), 10)

		for _, s := range result.HighEntropyStrings[:limit] {
			val := s.Value
			if len(val) > 40 {
				val = val[:40] + "..."
			}

			line := fmt.Sprintf("%.2f  %s", s.Entropy, val)
			fmt.Printf("║   %-*s║\n", w-3, Truncate(line, w-4))
		}
	}

	fmt.Printf("╚%s╝\n", border)
}

// PrintAndroidNative prints native library analysis.
func PrintAndroidNative(result *native.ScanResult) {
	w := 66
	border := strings.Repeat("═", w)

	fmt.Printf("╔%s╗\n", border)
	fmt.Printf("║%-*s║\n", w, "  NATIVE LIBRARY ANALYSIS")
	fmt.Printf("╠%s╣\n", border)
	fmt.Printf("║ Libraries: %-*d║\n", w-12, result.TotalLibs)

	if result.PackerDetected != "" {
		fmt.Printf("║ Packer:    %-*s║\n", w-12, result.PackerDetected)
	}

	if len(result.ABIs) > 0 {
		fmt.Printf("╠%s╣\n", border)
		fmt.Printf("║ %-*s║\n", w-1, "ABI SUMMARY")

		for _, a := range result.ABIs {
			fmt.Printf("║   %-14s %-*d║\n", a.ABI+":", w-18, a.Count)
		}
	}

	if len(result.JNIExports) > 0 {
		fmt.Printf("╠%s╣\n", border)
		fmt.Printf("║ %-*s║\n", w-1, fmt.Sprintf("JNI EXPORTS (%d)", len(result.JNIExports)))

		limit := min(len(result.JNIExports), 20)

		for _, e := range result.JNIExports[:limit] {
			line := fmt.Sprintf("%s: %s", e.Library, e.JavaName)
			fmt.Printf("║   %-*s║\n", w-3, Truncate(line, w-4))
		}
	}

	if len(result.Findings) > 0 {
		fmt.Printf("╠%s╣\n", border)
		fmt.Printf("║ %-*s║\n", w-1, fmt.Sprintf("SECURITY FINDINGS (%d)", len(result.Findings)))

		for _, f := range result.Findings {
			line := fmt.Sprintf("[%s] %s: %s (%s)", f.Severity, f.Category, f.Description, f.Library)
			fmt.Printf("║   %-*s║\n", w-3, Truncate(line, w-4))
		}
	}

	fmt.Printf("╚%s╝\n", border)
}

// PrintAndroidObfuscation prints obfuscation detection results.
func PrintAndroidObfuscation(result *obfuscation.Result) {
	w := 66
	border := strings.Repeat("═", w)

	fmt.Printf("╔%s╗\n", border)
	fmt.Printf("║%-*s║\n", w, "  OBFUSCATION DETECTION")
	fmt.Printf("╠%s╣\n", border)
	fmt.Printf("║ Type:        %-*s║\n", w-15, string(result.Type))
	fmt.Printf("║ Confidence:  %-*s║\n", w-15, fmt.Sprintf("%.1f%% (%s)", result.Confidence, result.Label))
	fmt.Printf("║ Mapping:     %-*s║\n", w-15, BoolYesNo(result.HasMapping))
	fmt.Printf("║ Short Class: %-*s║\n", w-15, fmt.Sprintf("%.1f%%", result.ShortClassPct))
	fmt.Printf("║ Short Method:%-*s║\n", w-15, fmt.Sprintf("%.1f%%", result.ShortMethodPct))
	fmt.Printf("║ Avg Name Len:%-*s║\n", w-15, fmt.Sprintf("%.1f", result.AvgClassNameLen))
	fmt.Printf("║ Avg Pkg Dep: %-*s║\n", w-15, fmt.Sprintf("%.1f", result.AvgPkgDepth))

	if result.Packer != nil {
		fmt.Printf("╠%s╣\n", border)
		fmt.Printf("║ %-*s║\n", w-1, "PACKER DETECTED")
		fmt.Printf("║   Name:       %-*s║\n", w-15, result.Packer.Name)
		fmt.Printf("║   Confidence: %-*s║\n", w-15, fmt.Sprintf("%.0f%%", result.Packer.Confidence))
		fmt.Printf("║   Evidence:   %-*s║\n", w-15, Truncate(result.Packer.Evidence, w-16))
	}

	if len(result.Indicators) > 0 {
		fmt.Printf("╠%s╣\n", border)
		fmt.Printf("║ %-*s║\n", w-1, "INDICATORS")

		for _, ind := range result.Indicators {
			icon := "[-]"
			if ind.Detected {
				icon = "[+]"
			}

			line := fmt.Sprintf("%s %s (%.0f)", icon, ind.Name, ind.Weight)
			fmt.Printf("║   %-*s║\n", w-3, Truncate(line, w-4))

			if ind.Details != "" {
				fmt.Printf("║       %-*s║\n", w-7, Truncate(ind.Details, w-8))
			}
		}
	}

	fmt.Printf("╚%s╝\n", border)
}

// PrintAndroidTelemetry prints telemetry & stealth SDK detection.
func PrintAndroidTelemetry(result *telemetry.ScanResult) {
	w := 66
	border := strings.Repeat("═", w)

	fmt.Printf("╔%s╗\n", border)
	fmt.Printf("║%-*s║\n", w, "  TELEMETRY & STEALTH DETECTION")
	fmt.Printf("╠%s╣\n", border)
	fmt.Printf("║ Total SDKs:  %-*d║\n", w-14, result.TotalSDKs)
	fmt.Printf("║ Analytics:   %-*s║\n", w-14, BoolYesNo(result.HasAnalytics))
	fmt.Printf("║ Ads:         %-*s║\n", w-14, BoolYesNo(result.HasAds))
	fmt.Printf("║ Stealth:     %-*s║\n", w-14, BoolYesNo(result.HasStealth))

	if len(result.SDKs) > 0 {
		fmt.Printf("╠%s╣\n", border)
		fmt.Printf("║ %-*s║\n", w-1, fmt.Sprintf("DETECTED SDKs (%d)", len(result.SDKs)))

		limit := min(len(result.SDKs), 20)

		for _, sdk := range result.SDKs[:limit] {
			line := fmt.Sprintf("%s [%s] %.0f%%", sdk.Name, sdk.Category, sdk.Confidence)
			fmt.Printf("║   %-*s║\n", w-3, Truncate(line, w-4))
		}

		if len(result.SDKs) > 20 {
			fmt.Printf("║   %-*s║\n", w-3, fmt.Sprintf("... and %d more", len(result.SDKs)-20))
		}
	}

	if len(result.StealthFeatures) > 0 {
		fmt.Printf("╠%s╣\n", border)
		fmt.Printf("║ %-*s║\n", w-1, fmt.Sprintf("STEALTH FEATURES (%d)", len(result.StealthFeatures)))

		for _, f := range result.StealthFeatures {
			icon := "[!]"
			if f.Risk == "high" {
				icon = "[!!]"
			}

			line := fmt.Sprintf("%s %s", icon, f.Type)
			fmt.Printf("║   %-*s║\n", w-3, Truncate(line, w-4))
			fmt.Printf("║       %-*s║\n", w-7, Truncate(f.Description, w-8))

			if f.Component != "" {
				comp := fmt.Sprintf("Component: %s", f.Component)
				fmt.Printf("║       %-*s║\n", w-7, Truncate(comp, w-8))
			}
		}
	}

	fmt.Printf("╚%s╝\n", border)
}

// PrintAndroidNetwork prints network & API analysis.
func PrintAndroidNetwork(result *network.ScanResult) {
	w := 66
	border := strings.Repeat("═", w)

	fmt.Printf("╔%s╗\n", border)
	fmt.Printf("║%-*s║\n", w, "  NETWORK & API ANALYSIS")
	fmt.Printf("╠%s╣\n", border)
	fmt.Printf("║ URLs:      %-*d║\n", w-12, result.TotalURLs)
	fmt.Printf("║ Domains:   %-*d║\n", w-12, result.TotalDomains)
	fmt.Printf("║ Cleartext: %-*s║\n", w-12, BoolYesNo(result.CleartextAllowed))

	if result.CertPinning != nil {
		fmt.Printf("║ Pinning:   %-*s║\n", w-12, BoolYesNo(result.CertPinning.HasPinning))

		if len(result.CertPinning.Sources) > 0 {
			fmt.Printf("║   Sources: %-*s║\n", w-12, strings.Join(result.CertPinning.Sources, ", "))
		}
	}

	if result.NetworkSecConfig != nil && result.NetworkSecConfig.Present {
		fmt.Printf("║ NetSecCfg: %-*s║\n", w-12,
			fmt.Sprintf("present (%d domain configs)", len(result.NetworkSecConfig.DomainConfigs)))
	}

	if len(result.Domains) > 0 {
		fmt.Printf("╠%s╣\n", border)
		fmt.Printf("║ %-*s║\n", w-1, fmt.Sprintf("DOMAINS (%d)", len(result.Domains)))

		limit := min(len(result.Domains), 30)

		for _, d := range result.Domains[:limit] {
			line := fmt.Sprintf("[%s] %s (%d)", d.Category, d.Domain, d.Count)
			fmt.Printf("║   %-*s║\n", w-3, Truncate(line, w-4))
		}

		if len(result.Domains) > 30 {
			fmt.Printf("║   %-*s║\n", w-3, fmt.Sprintf("... and %d more", len(result.Domains)-30))
		}
	}

	fmt.Printf("╚%s╝\n", border)
}

// PrintAndroidResources prints resources & assets analysis.
func PrintAndroidResources(result *resources.ScanResult) {
	w := 66
	border := strings.Repeat("═", w)

	fmt.Printf("╔%s╗\n", border)
	fmt.Printf("║%-*s║\n", w, "  RESOURCES & ASSETS")
	fmt.Printf("╠%s╣\n", border)
	fmt.Printf("║ Assets:    %-*d║\n", w-12, result.TotalAssets)
	fmt.Printf("║ Size:      %-*s║\n", w-12, apk.FormatBytes(result.TotalSize))
	fmt.Printf("║ WebView:   %-*s║\n", w-12, BoolYesNo(result.HasWebView))
	fmt.Printf("║ Databases: %-*s║\n", w-12, BoolYesNo(result.HasDatabases))

	if result.PackageName != "" {
		fmt.Printf("║ Package:   %-*s║\n", w-12, Truncate(result.PackageName, w-13))
	}

	if result.StringPool != nil {
		fmt.Printf("║ Strings:   %-*d║\n", w-12, result.StringPool.TotalStrings)
	}

	if len(result.Categories) > 0 {
		fmt.Printf("╠%s╣\n", border)
		fmt.Printf("║ %-*s║\n", w-1, "CATEGORIES")

		for cat, count := range result.Categories {
			fmt.Printf("║   %-14s %-*d║\n", string(cat)+":", w-18, count)
		}
	}

	if len(result.TypeNames) > 0 {
		fmt.Printf("╠%s╣\n", border)
		fmt.Printf("║ %-*s║\n", w-1, fmt.Sprintf("RESOURCE TYPES (%d)", len(result.TypeNames)))

		for _, t := range result.TypeNames {
			fmt.Printf("║   %-*s║\n", w-3, Truncate(t, w-4))
		}
	}

	fmt.Printf("╚%s╝\n", border)
}

// PrintAndroidProtobuf prints protobuf/gRPC detection results.
func PrintAndroidProtobuf(result *protobuf.ScanResult) {
	w := 66
	border := strings.Repeat("═", w)

	fmt.Printf("╔%s╗\n", border)
	fmt.Printf("║%-*s║\n", w, "  PROTOBUF & gRPC ANALYSIS")
	fmt.Printf("╠%s╣\n", border)
	fmt.Printf("║ Has Protobuf:  %-*s║\n", w-16, BoolYesNo(result.HasProtobuf))
	fmt.Printf("║ Has gRPC:      %-*s║\n", w-16, BoolYesNo(result.HasGRPC))

	if result.GRPCFramework != "" {
		fmt.Printf("║ Framework:     %-*s║\n", w-16, result.GRPCFramework)
	}

	fmt.Printf("║ Proto Refs:    %-*d║\n", w-16, result.TotalProtoRefs)

	if len(result.ProtoFiles) > 0 {
		fmt.Printf("╠%s╣\n", border)
		fmt.Printf("║ %-*s║\n", w-1, fmt.Sprintf("PROTO FILES (%d)", len(result.ProtoFiles)))

		for _, pf := range result.ProtoFiles {
			line := fmt.Sprintf("[%s] %s", pf.Source, pf.Name)
			fmt.Printf("║   %-*s║\n", w-3, Truncate(line, w-4))
		}
	}

	if len(result.GRPCServices) > 0 {
		fmt.Printf("╠%s╣\n", border)
		fmt.Printf("║ %-*s║\n", w-1, fmt.Sprintf("gRPC SERVICES (%d)", len(result.GRPCServices)))

		for _, svc := range result.GRPCServices {
			line := fmt.Sprintf("%s (%s)", svc.ServiceName, svc.ClassName)
			fmt.Printf("║   %-*s║\n", w-3, Truncate(line, w-4))
		}
	}

	if len(result.MessageTypes) > 0 {
		fmt.Printf("╠%s╣\n", border)

		limit := min(len(result.MessageTypes), 30)

		fmt.Printf("║ %-*s║\n", w-1, fmt.Sprintf("MESSAGE TYPES (%d)", len(result.MessageTypes)))

		for _, mt := range result.MessageTypes[:limit] {
			fmt.Printf("║   %-*s║\n", w-3, Truncate(mt, w-4))
		}

		if len(result.MessageTypes) > 30 {
			fmt.Printf("║   %-*s║\n", w-3, fmt.Sprintf("... and %d more", len(result.MessageTypes)-30))
		}
	}

	fmt.Printf("╚%s╝\n", border)
}

// PrintAndroidKotlin prints Kotlin feature detection.
func PrintAndroidKotlin(result *kotlin.ScanResult) {
	w := 66
	border := strings.Repeat("═", w)

	fmt.Printf("╔%s╗\n", border)
	fmt.Printf("║%-*s║\n", w, "  KOTLIN ANALYSIS")
	fmt.Printf("╠%s╣\n", border)
	fmt.Printf("║ Has Kotlin:      %-*s║\n", w-18, BoolYesNo(result.HasKotlin))

	if result.KotlinVersion != "" {
		fmt.Printf("║ Version:         %-*s║\n", w-18, result.KotlinVersion)
	}

	fmt.Printf("║ Kotlin Classes:  %-*s║\n", w-18,
		fmt.Sprintf("%d / %d (%.1f%%)", result.Stats.KotlinClasses, result.Stats.TotalClasses, result.Stats.KotlinPercent))
	fmt.Printf("║ Companion Objs:  %-*d║\n", w-18, result.Stats.CompanionObjects)
	fmt.Printf("║ Inline Classes:  %-*d║\n", w-18, result.Stats.InlineClasses)

	if len(result.Features) > 0 {
		fmt.Printf("╠%s╣\n", border)
		fmt.Printf("║ %-*s║\n", w-1, "FEATURES")

		for _, f := range result.Features {
			status := "No"
			if f.Detected {
				status = "Yes"
			}

			fmt.Printf("║   %-30s %-*s║\n", f.Name, w-34, status)
		}
	}

	if result.Coroutines != nil && result.Coroutines.HasCoroutines {
		fmt.Printf("╠%s╣\n", border)
		fmt.Printf("║ %-*s║\n", w-1, "COROUTINES")
		fmt.Printf("║   Flow:            %-*s║\n", w-20, BoolYesNo(result.Coroutines.HasFlow))
		fmt.Printf("║   Channel:         %-*s║\n", w-20, BoolYesNo(result.Coroutines.HasChannel))
		fmt.Printf("║   Suspend Funcs:   %-*d║\n", w-20, result.Coroutines.SuspendFuncs)

		if len(result.Coroutines.Dispatchers) > 0 {
			fmt.Printf("║   Dispatchers:     %-*s║\n", w-20,
				Truncate(strings.Join(result.Coroutines.Dispatchers, ", "), w-21))
		}
	}

	if len(result.DataClasses) > 0 {
		fmt.Printf("╠%s╣\n", border)
		fmt.Printf("║ %-*s║\n", w-1, fmt.Sprintf("DATA CLASSES (%d)", len(result.DataClasses)))

		limit := min(len(result.DataClasses), 10)

		for _, dc := range result.DataClasses[:limit] {
			line := fmt.Sprintf("%s (%d props)", dc.ClassName, len(dc.Properties))
			fmt.Printf("║   %-*s║\n", w-3, Truncate(line, w-4))
		}

		if len(result.DataClasses) > 10 {
			fmt.Printf("║   %-*s║\n", w-3, fmt.Sprintf("... and %d more", len(result.DataClasses)-10))
		}
	}

	if result.Compose != nil && result.Compose.HasCompose {
		fmt.Printf("╠%s╣\n", border)
		fmt.Printf("║ %-*s║\n", w-1, "JETPACK COMPOSE")
		fmt.Printf("║   Composables:     %-*d║\n", w-20, result.Compose.Composables)
	}

	if result.Serialization != nil && result.Serialization.HasSerialization {
		fmt.Printf("╠%s╣\n", border)
		fmt.Printf("║ %-*s║\n", w-1, "KOTLINX SERIALIZATION")

		if result.Serialization.Format != "" {
			fmt.Printf("║   Format:          %-*s║\n", w-20, result.Serialization.Format)
		}
	}

	fmt.Printf("╚%s╝\n", border)
}

// PrintFrameworkAnalysis prints framework detection results.
func PrintFrameworkAnalysis(result *framework.ScanResult) {
	w := 66
	border := strings.Repeat("═", w)

	fmt.Printf("╔%s╗\n", border)
	fmt.Printf("║%-*s║\n", w, "  FRAMEWORK ANALYSIS")
	fmt.Printf("╠%s╣\n", border)

	if result.Framework == "" {
		fmt.Printf("║ Framework: %-*s║\n", w-12, "None detected (native Java/Kotlin)")
		fmt.Printf("╚%s╝\n", border)
		return
	}

	fmt.Printf("║ Framework: %-*s║\n", w-12, result.Framework)

	if result.Flutter != nil {
		f := result.Flutter
		fmt.Printf("╠%s╣\n", border)
		fmt.Printf("║ %-*s║\n", w-1, "FLUTTER")
		if f.EngineVersion != "" {
			fmt.Printf("║   Engine:         %-*s║\n", w-20, f.EngineVersion)
		}
		if f.DartVersion != "" {
			fmt.Printf("║   Dart:           %-*s║\n", w-20, f.DartVersion)
		}
		fmt.Printf("║   Obfuscated:     %-*s║\n", w-20, BoolYesNo(f.IsObfuscated))
		fmt.Printf("║   Asset Manifest: %-*s║\n", w-20, BoolYesNo(f.HasAssetManifest))
		if len(f.ABIs) > 0 {
			fmt.Printf("║   ABIs:           %-*s║\n", w-20, strings.Join(f.ABIs, ", "))
		}
		if len(f.SnapshotFiles) > 0 {
			fmt.Printf("║   Snapshots:      %-*d║\n", w-20, len(f.SnapshotFiles))
		}
		if len(f.Plugins) > 0 {
			fmt.Printf("║   Plugins:        %-*s║\n", w-20,
				Truncate(strings.Join(f.Plugins, ", "), w-21))
		}
	}

	if result.ReactNative != nil {
		rn := result.ReactNative
		fmt.Printf("╠%s╣\n", border)
		fmt.Printf("║ %-*s║\n", w-1, "REACT NATIVE")
		fmt.Printf("║   JS Engine:      %-*s║\n", w-20, rn.JSEngine)
		if rn.HermesVersion != "" {
			fmt.Printf("║   Hermes BC:      %-*s║\n", w-20, rn.HermesVersion)
		}
		fmt.Printf("║   JS Bundle:      %-*s║\n", w-20, BoolYesNo(rn.HasJSBundle))
		if rn.JSBundleSize > 0 {
			fmt.Printf("║   Bundle Size:    %-*s║\n", w-20, FormatSize(rn.JSBundleSize))
		}
		if rn.SourceMap != nil && rn.SourceMap.SourceCount > 0 {
			detail := fmt.Sprintf("Yes (%d sources", rn.SourceMap.SourceCount)
			if rn.SourceMap.HasSources {
				detail += ", inline content present"
			}
			detail += ")"
			fmt.Printf("║   Source Map:      %-*s║\n", w-20, Truncate(detail, w-21))
			for _, f := range rn.SourceMap.Files {
				fmt.Printf("║     %-*s║\n", w-5, Truncate(f, w-6))
			}
			if len(rn.SourceMap.TopSources) > 0 {
				fmt.Printf("║   %-*s║\n", w-3, fmt.Sprintf("Sources (top %d):", len(rn.SourceMap.TopSources)))
				for _, s := range rn.SourceMap.TopSources {
					fmt.Printf("║     %-*s║\n", w-5, Truncate(s, w-6))
				}
			}
		} else {
			fmt.Printf("║   Source Map:      %-*s║\n", w-20, BoolYesNo(rn.HasSourceMap))
		}
		if len(rn.ABIs) > 0 {
			fmt.Printf("║   ABIs:           %-*s║\n", w-20, strings.Join(rn.ABIs, ", "))
		}
		if len(rn.NativeModules) > 0 {
			fmt.Printf("║   Native Modules: %-*d║\n", w-20, len(rn.NativeModules))
			limit := min(len(rn.NativeModules), 10)
			for _, m := range rn.NativeModules[:limit] {
				fmt.Printf("║     %-*s║\n", w-5, Truncate(m, w-6))
			}
		}
	}

	if result.Xamarin != nil {
		x := result.Xamarin
		fmt.Printf("╠%s╣\n", border)
		fmt.Printf("║ %-*s║\n", w-1, "XAMARIN / .NET")
		fmt.Printf("║   Xamarin.Forms:   %-*s║\n", w-20, BoolYesNo(x.IsXamarinForms))
		fmt.Printf("║   .NET MAUI:      %-*s║\n", w-20, BoolYesNo(x.IsMAUI))
		fmt.Printf("║   AOT Compiled:   %-*s║\n", w-20, BoolYesNo(x.HasAOT))
		fmt.Printf("║   Assemblies:     %-*d║\n", w-20, x.AssemblyCount)
		if len(x.ABIs) > 0 {
			fmt.Printf("║   ABIs:           %-*s║\n", w-20, strings.Join(x.ABIs, ", "))
		}
		if len(x.Assemblies) > 0 {
			limit := min(len(x.Assemblies), 10)
			for _, a := range x.Assemblies[:limit] {
				fmt.Printf("║     %-*s║\n", w-5, Truncate(a, w-6))
			}
			if len(x.Assemblies) > 10 {
				fmt.Printf("║     %-*s║\n", w-5, fmt.Sprintf("... and %d more", len(x.Assemblies)-10))
			}
		}
	}

	fmt.Printf("╚%s╝\n", border)
}
