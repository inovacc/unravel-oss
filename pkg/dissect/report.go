/*
Copyright (c) 2026 Security Research
*/
package dissect

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/inovacc/unravel-oss/internal/ai"
	androidmanifest "github.com/inovacc/unravel-oss/pkg/android/manifest"
	"github.com/inovacc/unravel-oss/pkg/android/secret"
)

// GenerateMarkdownReport writes a Markdown report summarizing the dissect result.
func GenerateMarkdownReport(result *DissectResult, path string) error {
	var sb strings.Builder

	// DSC-06 / 13-06: title and Path: must always reflect the CURRENT
	// invocation's input, not whatever was cached. SourcePath is stamped
	// fresh on every call (fresh-run and cache-hit alike) by Run() and
	// renderReport(); we use it as the single source of truth.
	// Title prefers the CURRENT invocation's SourcePath basename when stamped
	// (set by Run / renderReport). Falls back to FileName so legacy callers
	// that hand-construct DissectResult without SourcePath keep working.
	titleName := result.FileName
	if result.SourcePath != "" {
		titleName = filepath.Base(result.SourcePath)
	}
	sb.WriteString(fmt.Sprintf("# Dissect Report: %s\n\n", titleName))

	src := result.SourcePath
	if src == "" {
		src = result.Path
	}
	sb.WriteString(fmt.Sprintf("**Source:** `%s`\n", src))
	if result.OutputDirLabel != "" {
		sb.WriteString(fmt.Sprintf("**Output label:** `%s`\n", result.OutputDirLabel))
	}
	// DSC-06: legacy Path: line uses current SourcePath when stamped so a
	// cached result.Path can never bleed into a fresh report. Fallback to
	// result.Path keeps legacy callers working.
	pathLine := result.Path
	if result.SourcePath != "" {
		pathLine = result.SourcePath
	}
	sb.WriteString(fmt.Sprintf("**Path:** `%s`\n", pathLine))
	sb.WriteString(fmt.Sprintf("**Size:** %s\n", formatReportSize(result.Size)))
	sb.WriteString(fmt.Sprintf("**Type:** %s (%s)\n", result.Detection.FileType, result.Detection.Category))
	sb.WriteString(fmt.Sprintf("**Confidence:** %s\n", result.Detection.Confidence))
	sb.WriteString(fmt.Sprintf("**Timestamp:** %s\n", result.StartedAt.Format(time.RFC3339)))
	sb.WriteString(fmt.Sprintf("**Duration:** %s\n\n", result.Duration))

	if result.Detection.Details != "" {
		sb.WriteString(fmt.Sprintf("**Details:** %s\n\n", result.Detection.Details))
	}

	sb.WriteString("---\n\n")

	// Analyses summary
	sb.WriteString("## Analyses Performed\n\n")
	sb.WriteString("| Analysis | Status | Duration |\n")
	sb.WriteString("|----------|--------|----------|\n")

	for _, a := range result.Analyses {
		icon := "OK"

		switch a.Status {
		case "error":
			icon = "ERROR"
		case "skipped":
			icon = "SKIP"
		}

		sb.WriteString(fmt.Sprintf("| %s | %s | %s |\n", a.Name, icon, a.Duration))
	}

	sb.WriteString("\n")

	// Garble detection
	if result.GarbleDetect != nil {
		sb.WriteString("## Garble Obfuscation Detection\n\n")
		sb.WriteString(fmt.Sprintf("- **Garbled:** %v\n", result.GarbleDetect.IsGarbled))
		sb.WriteString(fmt.Sprintf("- **Confidence:** %.1f%% (%s)\n", result.GarbleDetect.Confidence, result.GarbleDetect.ConfidenceLabel))

		if len(result.GarbleDetect.Heuristics) > 0 {
			sb.WriteString("\n| Heuristic | Detected | Weight |\n|-----------|----------|--------|\n")

			for _, h := range result.GarbleDetect.Heuristics {
				sb.WriteString(fmt.Sprintf("| %s | %v | %.1f |\n", h.Name, h.Detected, h.Weight))
			}
		}

		sb.WriteString("\n")
	}

	// Garble info
	if result.GarbleInfo != nil {
		sb.WriteString("## Go Binary Info\n\n")
		sb.WriteString(fmt.Sprintf("- **Go Version:** %s\n", result.GarbleInfo.GoVersion))

		if result.GarbleInfo.ModulePath != "" {
			sb.WriteString(fmt.Sprintf("- **Module:** %s\n", result.GarbleInfo.ModulePath))
		}

		sb.WriteString(fmt.Sprintf("- **Arch:** %s\n", result.GarbleInfo.Arch))
		sb.WriteString(fmt.Sprintf("- **OS:** %s\n", result.GarbleInfo.OS))
		sb.WriteString(fmt.Sprintf("- **Format:** %s\n", result.GarbleInfo.Format))
		sb.WriteString(fmt.Sprintf("- **Static Linked:** %v\n", result.GarbleInfo.IsStaticLinked))
		sb.WriteString(fmt.Sprintf("- **Symbols:** %d\n", result.GarbleInfo.SymbolCount))
		sb.WriteString(fmt.Sprintf("- **DWARF:** %v\n\n", result.GarbleInfo.HasDWARF))
	}

	// UPX packing info
	if result.UPXInfo != nil {
		sb.WriteString("## UPX Packing Info\n\n")
		sb.WriteString(fmt.Sprintf("- **Format:** %s\n", result.UPXInfo.Format))
		sb.WriteString(fmt.Sprintf("- **Ratio:** %.1f%%\n", result.UPXInfo.Ratio))
		sb.WriteString(fmt.Sprintf("- **Original Size:** %s\n", formatReportSize(result.UPXInfo.OriginalSize)))
		sb.WriteString(fmt.Sprintf("- **Packed Size:** %s\n", formatReportSize(result.UPXInfo.PackedSize)))

		if result.UPXInfo.Version != "" {
			sb.WriteString(fmt.Sprintf("- **UPX Version:** %s\n", result.UPXInfo.Version))
		}

		if result.UPXInfo.Method != "" {
			sb.WriteString(fmt.Sprintf("- **Method:** %s\n", result.UPXInfo.Method))
		}

		sb.WriteString("\n")
	}

	// NSIS installer info
	if result.NSISInfo != nil {
		sb.WriteString("## NSIS Installer Info\n\n")

		if result.NSISInfo.NSISVersion != "" {
			sb.WriteString(fmt.Sprintf("- **Version:** %s\n", result.NSISInfo.NSISVersion))
		}

		if result.NSISInfo.Compression != "" {
			sb.WriteString(fmt.Sprintf("- **Compression:** %s\n", result.NSISInfo.Compression))
		}

		sb.WriteString(fmt.Sprintf("- **Solid:** %v\n", result.NSISInfo.IsSolid))
		sb.WriteString(fmt.Sprintf("- **Has Uninstall:** %v\n", result.NSISInfo.HasUninstall))

		if result.NSISInfo.HeaderSize > 0 {
			sb.WriteString(fmt.Sprintf("- **Header Size:** %s\n", formatReportSize(result.NSISInfo.HeaderSize)))
		}

		if result.NSISInfo.DataSize > 0 {
			sb.WriteString(fmt.Sprintf("- **Data Size:** %s\n", formatReportSize(result.NSISInfo.DataSize)))
		}

		if result.NSISInfo.FileCount > 0 {
			sb.WriteString(fmt.Sprintf("- **File Count:** %d\n", result.NSISInfo.FileCount))
		}

		if len(result.NSISInfo.Strings) > 0 {
			sb.WriteString("\n### Notable Strings\n\n")

			limit := min(len(result.NSISInfo.Strings), 20)

			for _, s := range result.NSISInfo.Strings[:limit] {
				sb.WriteString(fmt.Sprintf("- `%s`\n", s))
			}

			if len(result.NSISInfo.Strings) > 20 {
				sb.WriteString(fmt.Sprintf("\n*... and %d more*\n", len(result.NSISInfo.Strings)-20))
			}
		}

		sb.WriteString("\n")
	}

	// Certificate info
	if result.CertInfo != nil {
		sb.WriteString("## Certificate Info\n\n")
		sb.WriteString(fmt.Sprintf("- **Has Signature:** %v\n", result.CertInfo.HasSignature))

		if result.CertInfo.Signer != nil {
			sb.WriteString(fmt.Sprintf("- **Signer:** %s\n", result.CertInfo.Signer.Subject))
			sb.WriteString(fmt.Sprintf("- **Issuer:** %s\n", result.CertInfo.Signer.Issuer))
			sb.WriteString(fmt.Sprintf("- **Expired:** %v\n", result.CertInfo.Signer.IsExpired))
		}

		sb.WriteString(fmt.Sprintf("- **Verified:** %v\n\n", result.CertInfo.Verified))
	}

	// Binary info
	if result.BinaryInfo != nil {
		bi := result.BinaryInfo
		sb.WriteString("## Binary Info\n\n")
		sb.WriteString(fmt.Sprintf("- **Type:** %s\n", bi.Type))
		sb.WriteString(fmt.Sprintf("- **Architecture:** %s\n", bi.Arch))
		sb.WriteString(fmt.Sprintf("- **Size:** %.1f MB\n", bi.SizeMB))
		sb.WriteString(fmt.Sprintf("- **Strings:** %d\n", bi.StringsTotal))
		sb.WriteString(fmt.Sprintf("- **URLs:** %d\n", bi.URLCount))

		if len(bi.Libraries) > 0 {
			sb.WriteString(fmt.Sprintf("- **Libraries:** %d\n", len(bi.Libraries)))
		}

		if len(bi.Imports) > 0 {
			sb.WriteString(fmt.Sprintf("- **Imports:** %d\n", len(bi.Imports)))
		}

		if len(bi.SampleURLs) > 0 {
			sb.WriteString("\n### Sample URLs\n\n")

			limit := min(len(bi.SampleURLs), 15)

			for _, u := range bi.SampleURLs[:limit] {
				sb.WriteString(fmt.Sprintf("- `%s`\n", u))
			}

			if len(bi.SampleURLs) > 15 {
				sb.WriteString(fmt.Sprintf("\n*... and %d more*\n", len(bi.SampleURLs)-15))
			}
		}

		sb.WriteString("\n")
	}

	// String extraction (garble strings)
	if result.GarbleStrings != nil {
		gs := result.GarbleStrings
		sb.WriteString("## String Extraction\n\n")
		sb.WriteString(fmt.Sprintf("- **Total Strings:** %d\n", gs.TotalStrings))
		sb.WriteString(fmt.Sprintf("- **Average Entropy:** %.2f\n", gs.AvgEntropy))
		sb.WriteString(fmt.Sprintf("- **High Entropy Count:** %d\n", gs.HighEntropyCount))

		if len(gs.ByCategory) > 0 {
			sb.WriteString("\n### Categories\n\n")
			sb.WriteString("| Category | Count |\n")
			sb.WriteString("|----------|-------|\n")

			for cat, count := range gs.ByCategory {
				sb.WriteString(fmt.Sprintf("| %s | %d |\n", cat, count))
			}
		}

		if urls, ok := gs.TopByCategory["url"]; ok && len(urls) > 0 {
			sb.WriteString("\n### Top URLs\n\n")

			limit := min(len(urls), 10)

			for _, u := range urls[:limit] {
				sb.WriteString(fmt.Sprintf("- `%s`\n", u))
			}
		}

		if apis, ok := gs.TopByCategory["api_endpoint"]; ok && len(apis) > 0 {
			sb.WriteString("\n### Top API Endpoints\n\n")

			limit := min(len(apis), 10)

			for _, a := range apis[:limit] {
				sb.WriteString(fmt.Sprintf("- `%s`\n", a))
			}
		}

		sb.WriteString("\n")
	}

	// Symbol analysis (garble symbols)
	if result.GarbleSymbols != nil {
		gs := result.GarbleSymbols
		sb.WriteString("## Symbol Analysis\n\n")
		sb.WriteString(fmt.Sprintf("- **Format:** %s\n", gs.Format))
		sb.WriteString(fmt.Sprintf("- **Total Symbols:** %d\n", gs.TotalSymbols))
		sb.WriteString(fmt.Sprintf("- **Functions:** %d\n", gs.FunctionCount))
		sb.WriteString(fmt.Sprintf("- **Obfuscated:** %d (%.1f%%)\n", gs.ObfuscatedCount, gs.ObfuscationRatio*100))

		if len(gs.Packages) > 0 {
			sb.WriteString(fmt.Sprintf("- **Packages:** %d\n", len(gs.Packages)))
		}

		if len(gs.TopObfuscated) > 0 {
			sb.WriteString("\n### Sample Obfuscated Symbols\n\n")

			limit := min(len(gs.TopObfuscated), 10)

			for _, s := range gs.TopObfuscated[:limit] {
				sb.WriteString(fmt.Sprintf("- `%s`\n", s))
			}

			if len(gs.TopObfuscated) > 10 {
				sb.WriteString(fmt.Sprintf("\n*... and %d more*\n", len(gs.TopObfuscated)-10))
			}
		}

		sb.WriteString("\n")
	}

	// APK info
	if result.APKInfo != nil {
		sb.WriteString("## APK Info\n\n")
		sb.WriteString(fmt.Sprintf("- **Format:** %s\n", result.APKInfo.Format))
		sb.WriteString(fmt.Sprintf("- **Total Files:** %d\n", result.APKInfo.TotalFiles))
		sb.WriteString(fmt.Sprintf("- **DEX Files:** %d\n", result.APKInfo.DEXCount))
		sb.WriteString(fmt.Sprintf("- **Has Manifest:** %v\n", result.APKInfo.HasManifest))
		sb.WriteString(fmt.Sprintf("- **Has Kotlin:** %v\n", result.APKInfo.HasKotlin))
		sb.WriteString(fmt.Sprintf("- **Has Signature:** %v\n", result.APKInfo.HasSignature))

		if len(result.APKInfo.SignatureSchemes) > 0 {
			sb.WriteString(fmt.Sprintf("- **Signature Schemes:** %s\n", strings.Join(result.APKInfo.SignatureSchemes, ", ")))
		}

		sb.WriteString("\n")
	}

	// APK verification
	if result.APKVerify != nil {
		sb.WriteString("## APK Signature Verification\n\n")
		sb.WriteString(fmt.Sprintf("- **Overall Valid:** %v\n", result.APKVerify.OverallValid))

		if len(result.APKVerify.Schemes) > 0 {
			sb.WriteString(fmt.Sprintf("- **Schemes Found:** %s\n", strings.Join(result.APKVerify.Schemes, ", ")))
		}

		sb.WriteString("\n")
	}

	// APK certificate
	if result.APKCert != nil && len(result.APKCert.Certificates) > 0 {
		sb.WriteString("## APK Certificates\n\n")

		for i, c := range result.APKCert.Certificates {
			sb.WriteString(fmt.Sprintf("### Certificate %d\n\n", i+1))
			sb.WriteString(fmt.Sprintf("- **Subject:** %s\n", c.Subject))
			sb.WriteString(fmt.Sprintf("- **Issuer:** %s\n", c.Issuer))
			sb.WriteString(fmt.Sprintf("- **Algorithm:** %s\n", c.SignatureAlgorithm))
			sb.WriteString(fmt.Sprintf("- **SHA-256:** %s\n\n", c.Fingerprint.SHA256))
		}
	}

	// Manifest analysis
	if result.ManifestInfo != nil {
		m := result.ManifestInfo
		sb.WriteString("## Manifest Analysis\n\n")
		sb.WriteString(fmt.Sprintf("- **Package:** %s\n", m.Package))
		sb.WriteString(fmt.Sprintf("- **Version:** %s (code %d)\n", m.VersionName, m.VersionCode))
		sb.WriteString(fmt.Sprintf("- **Min SDK:** %d\n", m.MinSDK))
		sb.WriteString(fmt.Sprintf("- **Target SDK:** %d\n", m.TargetSDK))

		// Security score and risk level from analysis
		if a := result.ManifestAnalysis; a != nil {
			sb.WriteString(fmt.Sprintf("- **Security Score:** %d/100 (%s)\n", a.SecurityScore, a.RiskLevel))
		}

		sb.WriteString("\n### Security Flags\n\n")
		sb.WriteString(fmt.Sprintf("- **Debuggable:** %v\n", m.Security.Debuggable))
		sb.WriteString(fmt.Sprintf("- **Allow Backup:** %v\n", m.Security.AllowBackup))
		sb.WriteString(fmt.Sprintf("- **Cleartext Traffic:** %v\n", m.Security.UsesCleartextTraffic))
		sb.WriteString(fmt.Sprintf("- **Network Security Config:** %v\n", m.Security.NetworkSecurityConfig))

		if len(m.Permissions) > 0 {
			sb.WriteString("\n### Permissions")

			// Permission summary from analysis
			if a := result.ManifestAnalysis; a != nil {
				ps := a.PermissionSummary
				sb.WriteString(fmt.Sprintf(" (%d dangerous, %d normal, %d signature, %d unknown)",
					ps.Dangerous, ps.Normal, ps.Signature, ps.Unknown))
			}

			sb.WriteString("\n\n")
			sb.WriteString("| Permission | Risk Level |\n")
			sb.WriteString("|------------|------------|\n")

			for _, p := range m.Permissions {
				sb.WriteString(fmt.Sprintf("| %s | %s |\n", p.Name, p.RiskLevel))
			}

			// Permission groups
			if a := result.ManifestAnalysis; a != nil && len(a.PermissionSummary.Groups) > 0 {
				sb.WriteString("\n**Permission Groups:** ")
				first := true
				for group, perms := range a.PermissionSummary.Groups {
					if !first {
						sb.WriteString(", ")
					}
					sb.WriteString(fmt.Sprintf("%s (%d)", group, len(perms)))
					first = false
				}
				sb.WriteString("\n")
			}
		}

		// Component risks from analysis (replaces simple exported components list)
		if a := result.ManifestAnalysis; a != nil && len(a.ComponentRisks) > 0 {
			sb.WriteString("\n### Exported Components (Risk Analysis)\n\n")
			sb.WriteString("| Name | Type | Risk | Reason |\n")
			sb.WriteString("|------|------|------|--------|\n")

			for _, cr := range a.ComponentRisks {
				sb.WriteString(fmt.Sprintf("| %s | %s | %s | %s |\n", cr.Name, cr.Type, cr.Risk, cr.Reason))
			}
		} else {
			// Fallback to simple exported list if no analysis
			var exported []androidmanifest.Component
			for _, c := range m.Components {
				if c.Exported != nil && *c.Exported {
					exported = append(exported, c)
				}
			}

			if len(exported) > 0 {
				sb.WriteString("\n### Exported Components\n\n")
				sb.WriteString("| Name | Type | Permission |\n")
				sb.WriteString("|------|------|------------|\n")

				for _, c := range exported {
					perm := c.Permission
					if perm == "" {
						perm = "-"
					}

					sb.WriteString(fmt.Sprintf("| %s | %s | %s |\n", c.Name, c.Type, perm))
				}
			}
		}

		// Deep links from analysis (includes guarded status)
		if a := result.ManifestAnalysis; a != nil && len(a.DeepLinks) > 0 {
			sb.WriteString("\n### Deep Links\n\n")
			sb.WriteString("| URI | Component | Guarded |\n")
			sb.WriteString("|-----|-----------|--------|\n")

			for _, dl := range a.DeepLinks {
				guarded := "No"
				if dl.Guarded {
					guarded = "Yes"
				}
				sb.WriteString(fmt.Sprintf("| `%s` | %s | %s |\n", dl.URI, dl.Component, guarded))
			}
		} else {
			// Fallback
			var deepLinks []string
			for _, c := range m.Components {
				for _, f := range c.IntentFilters {
					for _, d := range f.Data {
						if d.Scheme != "" {
							link := d.Scheme + "://"
							if d.Host != "" {
								link += d.Host
							}
							if d.Path != "" {
								link += d.Path
							}
							deepLinks = append(deepLinks, link)
						}
					}
				}
			}

			if len(deepLinks) > 0 {
				sb.WriteString("\n### Deep Links\n\n")
				for _, dl := range deepLinks {
					sb.WriteString(fmt.Sprintf("- `%s`\n", dl))
				}
			}
		}

		// Security issues from analysis
		if a := result.ManifestAnalysis; a != nil && len(a.SecurityIssues) > 0 {
			sb.WriteString("\n### Security Issues\n\n")
			sb.WriteString("| Severity | Issue | Description |\n")
			sb.WriteString("|----------|-------|-------------|\n")

			for _, issue := range a.SecurityIssues {
				sb.WriteString(fmt.Sprintf("| %s | %s | %s |\n", issue.Severity, issue.Title, issue.Description))
			}
		}

		sb.WriteString("\n")
	}

	// Secrets & credentials
	if result.Secrets != nil && result.Secrets.TotalFindings > 0 {
		sb.WriteString("## Secrets & Credentials\n\n")
		sb.WriteString(fmt.Sprintf("- **Total Findings:** %d (High: %d, Medium: %d)\n", result.Secrets.TotalFindings, result.Secrets.HighConfidence, result.Secrets.MedConfidence))
		sb.WriteString(fmt.Sprintf("- **Files Scanned:** %d\n\n", result.Secrets.FilesScanned))

		// Non-URL findings table
		var secretFindings []secret.Finding
		var urls []string

		for _, f := range result.Secrets.Findings {
			if f.Type == "URL" {
				urls = append(urls, f.Value)
			} else {
				secretFindings = append(secretFindings, f)
			}
		}

		if len(secretFindings) > 0 {
			sb.WriteString("| Type | File | Confidence | Value |\n")
			sb.WriteString("|------|------|------------|-------|\n")

			for _, f := range secretFindings {
				sb.WriteString(fmt.Sprintf("| %s | %s | %s | `%s` |\n", f.Type, f.File, f.Confidence, f.Value))
			}

			sb.WriteString("\n")
		}

		if len(urls) > 0 {
			sb.WriteString("### URLs Discovered\n\n")

			seen := make(map[string]bool)

			for _, u := range urls {
				if seen[u] {
					continue
				}

				seen[u] = true
				sb.WriteString(fmt.Sprintf("- `%s`\n", u))
			}

			sb.WriteString("\n")
		}
	}

	// DEX analysis
	if result.DEXAnalysis != nil {
		d := result.DEXAnalysis
		sb.WriteString("## DEX Analysis\n\n")
		sb.WriteString(fmt.Sprintf("- **DEX Files:** %d\n", len(d.DexFiles)))
		sb.WriteString(fmt.Sprintf("- **Multi-DEX:** %v\n", d.MultiDex))
		sb.WriteString(fmt.Sprintf("- **Total Classes:** %d\n", d.TotalClasses))
		sb.WriteString(fmt.Sprintf("- **Total Methods:** %d\n", d.TotalMethods))
		sb.WriteString(fmt.Sprintf("- **Total Fields:** %d\n", d.TotalFields))
		sb.WriteString(fmt.Sprintf("- **Total Strings:** %d\n", d.TotalStrings))

		if len(d.HighEntropyStrings) > 0 {
			sb.WriteString(fmt.Sprintf("\n### High-Entropy Strings (%d)\n\n", len(d.HighEntropyStrings)))
			sb.WriteString("| Value | Entropy | Source |\n|-------|---------|--------|\n")

			limit := min(len(d.HighEntropyStrings), 20)

			for _, s := range d.HighEntropyStrings[:limit] {
				val := s.Value
				if len(val) > 40 {
					val = val[:40] + "..."
				}

				sb.WriteString(fmt.Sprintf("| `%s` | %.2f | %s |\n", val, s.Entropy, s.Source))
			}

			if len(d.HighEntropyStrings) > 20 {
				sb.WriteString(fmt.Sprintf("\n*... and %d more*\n", len(d.HighEntropyStrings)-20))
			}
		}

		if len(d.RiskFindings) > 0 {
			sb.WriteString(fmt.Sprintf("\n### Risk Findings (%d)\n\n", len(d.RiskFindings)))
			sb.WriteString("| Category | Severity | API | Description |\n|----------|----------|-----|-------------|\n")

			for _, f := range d.RiskFindings {
				api := f.API
				if f.ClassName != "" {
					api = f.ClassName
					if f.MethodName != "" {
						api += "." + f.MethodName
					}
				}

				sb.WriteString(fmt.Sprintf("| %s | %s | %s | %s |\n", f.Category, f.Severity, api, f.Description))
			}
		}

		sb.WriteString("\n")
	}

	// Kotlin analysis
	if result.KotlinAnalysis != nil && result.KotlinAnalysis.HasKotlin {
		k := result.KotlinAnalysis
		sb.WriteString("## Kotlin Analysis\n\n")
		sb.WriteString(fmt.Sprintf("- **Has Kotlin:** %v\n", k.HasKotlin))

		if k.KotlinVersion != "" {
			sb.WriteString(fmt.Sprintf("- **Version:** %s\n", k.KotlinVersion))
		}

		sb.WriteString(fmt.Sprintf("- **Kotlin Classes:** %d / %d (%.1f%%)\n",
			k.Stats.KotlinClasses, k.Stats.TotalClasses, k.Stats.KotlinPercent))

		if len(k.Features) > 0 {
			sb.WriteString("\n### Features\n\n")
			sb.WriteString("| Feature | Detected | Evidence |\n|---------|----------|----------|\n")

			for _, f := range k.Features {
				detected := "No"
				if f.Detected {
					detected = "Yes"
				}

				evidence := f.Evidence
				if len(evidence) > 50 {
					evidence = evidence[:50] + "..."
				}

				sb.WriteString(fmt.Sprintf("| %s | %s | %s |\n", f.Name, detected, evidence))
			}
		}

		if k.Coroutines != nil && k.Coroutines.HasCoroutines {
			sb.WriteString("\n### Coroutines\n\n")
			sb.WriteString(fmt.Sprintf("- **Has Coroutines:** %v\n", k.Coroutines.HasCoroutines))
			sb.WriteString(fmt.Sprintf("- **Has Flow:** %v\n", k.Coroutines.HasFlow))
			sb.WriteString(fmt.Sprintf("- **Has Channel:** %v\n", k.Coroutines.HasChannel))
			sb.WriteString(fmt.Sprintf("- **Suspend Functions:** %d\n", k.Coroutines.SuspendFuncs))

			if len(k.Coroutines.Dispatchers) > 0 {
				sb.WriteString(fmt.Sprintf("- **Dispatchers:** %s\n", strings.Join(k.Coroutines.Dispatchers, ", ")))
			}
		}

		if len(k.DataClasses) > 0 {
			sb.WriteString(fmt.Sprintf("\n### Data Classes (%d)\n\n", len(k.DataClasses)))

			limit := min(len(k.DataClasses), 10)

			for _, dc := range k.DataClasses[:limit] {
				sb.WriteString(fmt.Sprintf("- `%s` (%d properties)\n", dc.ClassName, len(dc.Properties)))
			}

			if len(k.DataClasses) > 10 {
				sb.WriteString(fmt.Sprintf("\n*... and %d more*\n", len(k.DataClasses)-10))
			}
		}

		if k.Compose != nil && k.Compose.HasCompose {
			sb.WriteString("\n### Jetpack Compose\n\n")
			sb.WriteString(fmt.Sprintf("- **Composables:** %d\n", k.Compose.Composables))
		}

		sb.WriteString("\n")
	}

	// Native library analysis
	if result.NativeAnalysis != nil && result.NativeAnalysis.TotalLibs > 0 {
		n := result.NativeAnalysis
		sb.WriteString("## Native Library Analysis\n\n")
		sb.WriteString(fmt.Sprintf("- **Total Libraries:** %d\n", n.TotalLibs))

		if n.PackerDetected != "" {
			sb.WriteString(fmt.Sprintf("- **Packer Detected:** %s\n", n.PackerDetected))
		}

		if len(n.ABIs) > 0 {
			sb.WriteString("\n### ABI Summary\n\n")
			sb.WriteString("| ABI | Libraries | Total Size |\n|-----|-----------|------------|\n")

			for _, a := range n.ABIs {
				sb.WriteString(fmt.Sprintf("| %s | %d | %s |\n", a.ABI, a.Count, formatReportSize(a.TotalSize)))
			}
		}

		if len(n.JNIExports) > 0 {
			sb.WriteString(fmt.Sprintf("\n### JNI Exports (%d)\n\n", len(n.JNIExports)))
			sb.WriteString("| Library | Symbol | Java Name |\n|---------|--------|-----------|\n")

			limit := min(len(n.JNIExports), 30)

			for _, e := range n.JNIExports[:limit] {
				sb.WriteString(fmt.Sprintf("| %s | %s | %s |\n", e.Library, e.Symbol, e.JavaName))
			}

			if len(n.JNIExports) > 30 {
				sb.WriteString(fmt.Sprintf("\n*... and %d more*\n", len(n.JNIExports)-30))
			}
		}

		if len(n.Findings) > 0 {
			sb.WriteString(fmt.Sprintf("\n### Security Findings (%d)\n\n", len(n.Findings)))
			sb.WriteString("| Library | Category | Severity | Pattern | Description |\n|---------|----------|----------|---------|-------------|\n")

			for _, f := range n.Findings {
				sb.WriteString(fmt.Sprintf("| %s | %s | %s | %s | %s |\n", f.Library, f.Category, f.Severity, f.Pattern, f.Description))
			}
		}

		sb.WriteString("\n")
	}

	// Obfuscation detection
	if result.ObfuscationAnalysis != nil {
		o := result.ObfuscationAnalysis
		sb.WriteString("## Obfuscation Detection\n\n")
		sb.WriteString(fmt.Sprintf("- **Type:** %s\n", o.Type))
		sb.WriteString(fmt.Sprintf("- **Confidence:** %.1f%% (%s)\n", o.Confidence, o.Label))
		sb.WriteString(fmt.Sprintf("- **Has Mapping File:** %v\n", o.HasMapping))
		sb.WriteString(fmt.Sprintf("- **Short Class Names:** %.1f%%\n", o.ShortClassPct))
		sb.WriteString(fmt.Sprintf("- **Short Method Names:** %.1f%%\n", o.ShortMethodPct))
		sb.WriteString(fmt.Sprintf("- **Avg Class Name Length:** %.1f\n", o.AvgClassNameLen))
		sb.WriteString(fmt.Sprintf("- **Avg Package Depth:** %.1f\n", o.AvgPkgDepth))

		if o.Packer != nil {
			sb.WriteString(fmt.Sprintf("- **Packer:** %s (confidence: %.0f%%, evidence: %s)\n", o.Packer.Name, o.Packer.Confidence, o.Packer.Evidence))
		}

		if len(o.Indicators) > 0 {
			sb.WriteString("\n### Indicators\n\n")
			sb.WriteString("| Indicator | Detected | Weight | Details |\n|-----------|----------|--------|---------|\n")

			for _, ind := range o.Indicators {
				detected := "No"
				if ind.Detected {
					detected = "Yes"
				}

				sb.WriteString(fmt.Sprintf("| %s | %s | %.0f | %s |\n", ind.Name, detected, ind.Weight, ind.Details))
			}
		}

		sb.WriteString("\n")
	}

	// Telemetry & stealth detection
	if result.TelemetryAnalysis != nil {
		t := result.TelemetryAnalysis
		sb.WriteString("## Telemetry & Stealth Detection\n\n")
		sb.WriteString(fmt.Sprintf("- **Total SDKs:** %d\n", t.TotalSDKs))
		sb.WriteString(fmt.Sprintf("- **Has Analytics:** %v\n", t.HasAnalytics))
		sb.WriteString(fmt.Sprintf("- **Has Ads:** %v\n", t.HasAds))
		sb.WriteString(fmt.Sprintf("- **Has Stealth:** %v\n", t.HasStealth))

		if len(t.SDKs) > 0 {
			sb.WriteString("\n### Detected SDKs\n\n")
			sb.WriteString("| Name | Category | Confidence | Package |\n")
			sb.WriteString("|------|----------|------------|----------|\n")

			for _, sdk := range t.SDKs {
				sb.WriteString(fmt.Sprintf("| %s | %s | %.0f%% | %s |\n",
					sdk.Name, sdk.Category, sdk.Confidence, sdk.Package))
			}
		}

		if len(t.StealthFeatures) > 0 {
			sb.WriteString("\n### Stealth Features\n\n")
			sb.WriteString("| Type | Component | Risk | Description |\n")
			sb.WriteString("|------|-----------|------|-------------|\n")

			for _, f := range t.StealthFeatures {
				sb.WriteString(fmt.Sprintf("| %s | %s | %s | %s |\n",
					f.Type, f.Component, f.Risk, f.Description))
			}
		}

		sb.WriteString("\n")
	}

	// Protobuf & gRPC detection
	if result.ProtobufAnalysis != nil && (result.ProtobufAnalysis.HasProtobuf || result.ProtobufAnalysis.HasGRPC) {
		p := result.ProtobufAnalysis
		sb.WriteString("## Protobuf & gRPC Detection\n\n")
		sb.WriteString(fmt.Sprintf("- **Has Protobuf:** %v\n", p.HasProtobuf))
		sb.WriteString(fmt.Sprintf("- **Has gRPC:** %v\n", p.HasGRPC))

		if p.GRPCFramework != "" {
			sb.WriteString(fmt.Sprintf("- **Framework:** %s\n", p.GRPCFramework))
		}

		sb.WriteString(fmt.Sprintf("- **Total Proto Refs:** %d\n", p.TotalProtoRefs))

		if len(p.ProtoFiles) > 0 {
			sb.WriteString(fmt.Sprintf("\n### Proto Files (%d)\n\n", len(p.ProtoFiles)))
			sb.WriteString("| Name | Source |\n|------|--------|\n")

			for _, pf := range p.ProtoFiles {
				sb.WriteString(fmt.Sprintf("| %s | %s |\n", pf.Name, pf.Source))
			}
		}

		if len(p.GRPCServices) > 0 {
			sb.WriteString(fmt.Sprintf("\n### gRPC Services (%d)\n\n", len(p.GRPCServices)))
			sb.WriteString("| Service | Class | Framework |\n|---------|-------|-----------|\n")

			for _, svc := range p.GRPCServices {
				sb.WriteString(fmt.Sprintf("| %s | %s | %s |\n", svc.ServiceName, svc.ClassName, svc.Framework))
			}
		}

		if len(p.MessageTypes) > 0 {
			limit := min(len(p.MessageTypes), 30)

			sb.WriteString(fmt.Sprintf("\n### Message Types (%d)\n\n", len(p.MessageTypes)))

			for _, mt := range p.MessageTypes[:limit] {
				sb.WriteString(fmt.Sprintf("- %s\n", mt))
			}

			if len(p.MessageTypes) > 30 {
				sb.WriteString(fmt.Sprintf("\n*... and %d more*\n", len(p.MessageTypes)-30))
			}
		}

		sb.WriteString("\n")
	}

	// Network & API analysis
	if result.NetworkAnalysis != nil {
		n := result.NetworkAnalysis
		sb.WriteString("## Network & API Analysis\n\n")
		sb.WriteString(fmt.Sprintf("- **Total URLs:** %d\n", n.TotalURLs))
		sb.WriteString(fmt.Sprintf("- **Total Domains:** %d\n", n.TotalDomains))
		sb.WriteString(fmt.Sprintf("- **Cleartext Allowed:** %v\n", n.CleartextAllowed))

		if n.CertPinning != nil {
			sb.WriteString(fmt.Sprintf("- **Cert Pinning:** %v", n.CertPinning.HasPinning))
			if len(n.CertPinning.Sources) > 0 {
				sb.WriteString(fmt.Sprintf(" (sources: %s)", strings.Join(n.CertPinning.Sources, ", ")))
			}
			sb.WriteString("\n")
		}

		if n.NetworkSecConfig != nil && n.NetworkSecConfig.Present {
			sb.WriteString(fmt.Sprintf("- **Network Security Config:** present (%d domain configs)\n", len(n.NetworkSecConfig.DomainConfigs)))
		}

		if len(n.Domains) > 0 {
			sb.WriteString("\n### Domain Inventory\n\n")
			sb.WriteString("| Domain | Category | Count | Schemes |\n")
			sb.WriteString("|--------|----------|-------|----------|\n")

			limit := min(len(n.Domains), 50)

			for _, d := range n.Domains[:limit] {
				sb.WriteString(fmt.Sprintf("| %s | %s | %d | %s |\n",
					d.Domain, d.Category, d.Count, strings.Join(d.Schemes, ", ")))
			}

			if len(n.Domains) > 50 {
				sb.WriteString(fmt.Sprintf("\n*... and %d more domains*\n", len(n.Domains)-50))
			}
		}

		if n.CertPinning != nil && len(n.CertPinning.PinnedDomains) > 0 {
			sb.WriteString("\n### Pinned Domains\n\n")
			sb.WriteString("| Domain | Source | Pins |\n")
			sb.WriteString("|--------|--------|------|\n")

			for _, pd := range n.CertPinning.PinnedDomains {
				sb.WriteString(fmt.Sprintf("| %s | %s | %d |\n", pd.Domain, pd.Source, len(pd.Pins)))
			}
		}

		sb.WriteString("\n")
	}

	// Resources & assets analysis
	if result.ResourceAnalysis != nil {
		r := result.ResourceAnalysis
		sb.WriteString("## Resources & Assets\n\n")
		sb.WriteString(fmt.Sprintf("- **Total Assets:** %d\n", r.TotalAssets))
		sb.WriteString(fmt.Sprintf("- **Total Size:** %s\n", formatReportSize(r.TotalSize)))
		sb.WriteString(fmt.Sprintf("- **WebView UI:** %v\n", r.HasWebView))
		sb.WriteString(fmt.Sprintf("- **Databases:** %v\n", r.HasDatabases))

		if r.PackageName != "" {
			sb.WriteString(fmt.Sprintf("- **Package:** %s\n", r.PackageName))
		}

		if r.StringPool != nil {
			sb.WriteString(fmt.Sprintf("- **String Pool:** %d strings (UTF-8: %v)\n", r.StringPool.TotalStrings, r.StringPool.UTF8))
		}

		if len(r.Categories) > 0 {
			sb.WriteString("\n### Asset Categories\n\n")
			sb.WriteString("| Category | Count |\n")
			sb.WriteString("|----------|-------|\n")

			for cat, count := range r.Categories {
				sb.WriteString(fmt.Sprintf("| %s | %d |\n", cat, count))
			}
		}

		if len(r.TypeNames) > 0 {
			sb.WriteString(fmt.Sprintf("\n### Resource Types (%d)\n\n", len(r.TypeNames)))

			for _, t := range r.TypeNames {
				sb.WriteString(fmt.Sprintf("- %s\n", t))
			}
		}

		sb.WriteString("\n")
	}

	// APK extraction
	if result.APKExtract != nil {
		sb.WriteString("## APK Extraction\n\n")
		sb.WriteString(fmt.Sprintf("- **Source:** `%s`\n", result.APKExtract.Source))
		sb.WriteString(fmt.Sprintf("- **Output:** `%s`\n", result.APKExtract.Output))
		sb.WriteString(fmt.Sprintf("- **Format:** %s\n", result.APKExtract.Format))
		sb.WriteString(fmt.Sprintf("- **Files Extracted:** %d\n", result.APKExtract.Files))
		sb.WriteString(fmt.Sprintf("- **Directories:** %d\n", result.APKExtract.Directories))
		sb.WriteString(fmt.Sprintf("- **Total Size:** %s\n", formatReportSize(result.APKExtract.TotalSize)))

		if len(result.APKExtract.Errors) > 0 {
			sb.WriteString(fmt.Sprintf("- **Extraction Errors:** %d\n", len(result.APKExtract.Errors)))
		}

		sb.WriteString("\n")
	}

	// Decompilation pipeline
	if result.Decompile != nil {
		sb.WriteString("## Decompilation Pipeline\n\n")
		sb.WriteString(fmt.Sprintf("- **Input Format:** %s\n", result.Decompile.InputFormat))
		sb.WriteString(fmt.Sprintf("- **Output:** `%s`\n", result.Decompile.OutputDir))
		sb.WriteString(fmt.Sprintf("- **Total Duration:** %s\n", result.Decompile.TotalDuration))

		if len(result.Decompile.ToolsUsed) > 0 {
			sb.WriteString(fmt.Sprintf("- **Tools Used:** %s\n", strings.Join(result.Decompile.ToolsUsed, ", ")))
		}

		if len(result.Decompile.ToolsMissing) > 0 {
			sb.WriteString(fmt.Sprintf("- **Tools Missing:** %s\n", strings.Join(result.Decompile.ToolsMissing, ", ")))
		}

		if len(result.Decompile.ToolsSkipped) > 0 {
			sb.WriteString(fmt.Sprintf("- **Tools Skipped:** %s\n", strings.Join(result.Decompile.ToolsSkipped, ", ")))
		}

		sb.WriteString("\n")

		if len(result.Decompile.Steps) > 0 {
			sb.WriteString("### Pipeline Steps\n\n")
			sb.WriteString("| Tool | Action | Success | Duration |\n")
			sb.WriteString("|------|--------|---------|----------|\n")

			for _, s := range result.Decompile.Steps {
				success := "Yes"
				if !s.Success {
					success = "No"
				}

				sb.WriteString(fmt.Sprintf("| %s | %s | %s | %s |\n", s.Tool, s.Action, success, s.Duration))
			}

			sb.WriteString("\n")
		}

		if len(result.Decompile.Errors) > 0 {
			sb.WriteString("### Decompilation Errors\n\n")

			for _, e := range result.Decompile.Errors {
				sb.WriteString(fmt.Sprintf("- %s\n", e))
			}

			sb.WriteString("\n")
		}
	}

	// Tools status
	if result.ToolsStatus != nil {
		sb.WriteString("## RE Tools Status\n\n")
		sb.WriteString(fmt.Sprintf("- **Available:** %d / %d\n", result.ToolsStatus.Available, result.ToolsStatus.Total))
		sb.WriteString(fmt.Sprintf("- **Java Runtime:** %v\n", result.ToolsStatus.JavaOK))
		sb.WriteString(fmt.Sprintf("- **Dotnet Runtime:** %v\n", result.ToolsStatus.DotnetOK))
		sb.WriteString(fmt.Sprintf("- **ADB:** %v\n\n", result.ToolsStatus.AdbOK))

		sb.WriteString("| Tool | Available | Version |\n")
		sb.WriteString("|------|-----------|----------|\n")

		for _, t := range result.ToolsStatus.Tools {
			avail := "No"
			if t.Available {
				avail = "Yes"
			}

			ver := t.Version
			if ver == "" {
				ver = "-"
			}

			sb.WriteString(fmt.Sprintf("| %s | %s | %s |\n", t.Name, avail, ver))
		}

		sb.WriteString("\n")
	}

	// DEB info
	if result.DEBInfo != nil {
		sb.WriteString("## DEB Package Info\n\n")

		if result.DEBInfo.Control != nil {
			sb.WriteString(fmt.Sprintf("- **Package:** %s\n", result.DEBInfo.Control.Package))
			sb.WriteString(fmt.Sprintf("- **Version:** %s\n", result.DEBInfo.Control.Version))
			sb.WriteString(fmt.Sprintf("- **Architecture:** %s\n", result.DEBInfo.Control.Architecture))
		}

		sb.WriteString(fmt.Sprintf("- **Files:** %d\n", result.DEBInfo.FileCount))
		sb.WriteString(fmt.Sprintf("- **Total Size:** %s\n\n", formatReportSize(result.DEBInfo.TotalSize)))
	}

	// DEB verification
	if result.DEBVerify != nil {
		sb.WriteString("## DEB Signature Verification\n\n")
		sb.WriteString(fmt.Sprintf("- **Has Signature:** %v\n\n", result.DEBVerify.HasSignature))
	}

	// RPM info
	if result.RPMInfo != nil {
		sb.WriteString("## RPM Package Info\n\n")
		sb.WriteString(fmt.Sprintf("- **Name:** %s\n", result.RPMInfo.Name))
		sb.WriteString(fmt.Sprintf("- **Version:** %s-%s\n", result.RPMInfo.Version, result.RPMInfo.Release))
		sb.WriteString(fmt.Sprintf("- **Architecture:** %s\n", result.RPMInfo.Arch))

		if result.RPMInfo.Summary != "" {
			sb.WriteString(fmt.Sprintf("- **Summary:** %s\n", result.RPMInfo.Summary))
		}

		sb.WriteString(fmt.Sprintf("- **Has Signature:** %v\n\n", result.RPMInfo.HasSignature))
	}

	// RPM verification
	if result.RPMVerify != nil {
		sb.WriteString("## RPM Signature Verification\n\n")
		sb.WriteString(fmt.Sprintf("- **Has Signature:** %v\n\n", result.RPMVerify.HasSignature))
	}

	// ASAR stats
	if result.ASARStats != nil {
		sb.WriteString("## ASAR Archive\n\n")
		sb.WriteString(fmt.Sprintf("- **Header Size:** %d bytes\n", result.ASARStats.HeaderSize))
		sb.WriteString(fmt.Sprintf("- **Files:** %d\n", result.ASARStats.FileCount))
		sb.WriteString(fmt.Sprintf("- **Directories:** %d\n", result.ASARStats.DirCount))
		sb.WriteString(fmt.Sprintf("- **Total Size:** %s\n\n", formatReportSize(result.ASARStats.TotalSize)))
	}

	// LevelDB
	if result.LevelDB != nil {
		sb.WriteString("## LevelDB\n\n")
		sb.WriteString(fmt.Sprintf("- **Entries:** %d\n", result.LevelDB.Stats.TotalEntries))
		sb.WriteString(fmt.Sprintf("- **Valid:** %d\n", result.LevelDB.Stats.ValidEntries))
		sb.WriteString(fmt.Sprintf("- **Deleted:** %d\n\n", result.LevelDB.Stats.DeletedEntries))
	}

	// Cache
	if result.Cache != nil {
		sb.WriteString("## Chromium Cache\n\n")
		sb.WriteString(fmt.Sprintf("- **Format:** %s\n", result.Cache.CacheFormat))
		sb.WriteString(fmt.Sprintf("- **Entries:** %d\n", result.Cache.Stats.TotalEntries))
		sb.WriteString(fmt.Sprintf("- **Domains:** %d\n\n", len(result.Cache.ByDomain)))
	}

	// JS analysis
	if result.JSAnalysis != nil {
		sb.WriteString("## JavaScript Analysis\n\n")
		sb.WriteString(fmt.Sprintf("- **Obfuscation Score:** %d\n", result.JSAnalysis.ObfuscationScore))
		sb.WriteString(fmt.Sprintf("- **Strings:** %d\n", result.JSAnalysis.StringsCount))
		sb.WriteString(fmt.Sprintf("- **Functions:** %d\n", result.JSAnalysis.FunctionsCount))

		if len(result.JSAnalysis.DangerousCalls) > 0 {
			sb.WriteString(fmt.Sprintf("- **Dangerous Calls:** %s\n", strings.Join(result.JSAnalysis.DangerousCalls, "; ")))
		}

		if len(result.JSAnalysis.URLs) > 0 {
			sb.WriteString(fmt.Sprintf("- **URLs Found:** %d\n", len(result.JSAnalysis.URLs)))
		}

		sb.WriteString("\n")
	}

	// App analysis
	if result.AppAnalysis != nil {
		sb.WriteString("## Application Security Analysis\n\n")
		sb.WriteString(fmt.Sprintf("- **App:** %s (%s)\n", result.AppAnalysis.AppInfo.Name, result.AppAnalysis.AppInfo.DisplayName))
		sb.WriteString(fmt.Sprintf("- **Risk Level:** %s (Score: %d)\n", result.AppAnalysis.Analysis.RiskLevel, result.AppAnalysis.Analysis.RiskScore))

		stealth := "No"
		if result.AppAnalysis.AppInfo.HasStealth {
			stealth = "Yes"
		}

		sb.WriteString(fmt.Sprintf("- **Stealth Features:** %s\n", stealth))
		sb.WriteString(fmt.Sprintf("- **Security Settings:** %d\n", len(result.AppAnalysis.Analysis.SecuritySettings)))
		sb.WriteString(fmt.Sprintf("- **IPC Commands:** %d\n", len(result.AppAnalysis.Analysis.IPCCommands)))
		sb.WriteString(fmt.Sprintf("- **Telemetry Services:** %d\n\n", len(result.AppAnalysis.AppInfo.Telemetry)))
	}

	// Extension package analysis
	if result.ExtAnalysis != nil {
		sb.WriteString("## Extension Package Analysis\n\n")
		sb.WriteString(fmt.Sprintf("- **Name:** %s\n", result.ExtAnalysis.Name))
		sb.WriteString(fmt.Sprintf("- **Version:** %s\n", result.ExtAnalysis.Version))
		sb.WriteString(fmt.Sprintf("- **Manifest Version:** V%d\n", result.ExtAnalysis.ManifestVer))
		sb.WriteString(fmt.Sprintf("- **Source Type:** %s\n", result.ExtAnalysis.SourceType))
		sb.WriteString(fmt.Sprintf("- **Risk Level:** %s (Score: %d)\n", result.ExtAnalysis.RiskLevel, result.ExtAnalysis.RiskScore))
		sb.WriteString(fmt.Sprintf("- **Permissions:** %d\n", len(result.ExtAnalysis.Permissions.All)))
		sb.WriteString(fmt.Sprintf("- **Host Permissions:** %d\n", len(result.ExtAnalysis.Permissions.Hosts)))
		sb.WriteString(fmt.Sprintf("- **Native Hosts:** %d\n", len(result.ExtAnalysis.NativeMessagingHosts)))
		sb.WriteString(fmt.Sprintf("- **WebSocket Endpoints:** %d\n\n", len(result.ExtAnalysis.WebSocketEndpoints)))
	}

	// Disassembly
	if result.Disassembly != nil {
		sb.WriteString("## Disassembly\n\n")
		sb.WriteString(fmt.Sprintf("- **Architecture:** %s (%d-bit)\n", result.Disassembly.Architecture, result.Disassembly.Bits))
		sb.WriteString(fmt.Sprintf("- **Format:** %s\n", result.Disassembly.Format))
		sb.WriteString(fmt.Sprintf("- **Tool:** %s\n", result.Disassembly.Tool))
		sb.WriteString(fmt.Sprintf("- **Entry Point:** 0x%x\n", result.Disassembly.EntryPoint))

		if len(result.Disassembly.Imports) > 0 {
			sb.WriteString(fmt.Sprintf("- **Imports:** %d\n", len(result.Disassembly.Imports)))
		}

		if len(result.Disassembly.Exports) > 0 {
			sb.WriteString(fmt.Sprintf("- **Exports:** %d\n", len(result.Disassembly.Exports)))
		}

		for _, sec := range result.Disassembly.Sections {
			sb.WriteString(fmt.Sprintf("\n### Section: %s (0x%x, %d bytes, %d instructions)\n\n",
				sec.Name, sec.Address, sec.Size, len(sec.Instructions)))

			// Show first 20 instructions
			limit := min(len(sec.Instructions), 20)

			sb.WriteString("```asm\n")

			for _, insn := range sec.Instructions[:limit] {
				if insn.Operands != "" {
					sb.WriteString(fmt.Sprintf("0x%x: %s %s\n", insn.Address, insn.Mnemonic, insn.Operands))
				} else {
					sb.WriteString(fmt.Sprintf("0x%x: %s\n", insn.Address, insn.Mnemonic))
				}
			}

			if len(sec.Instructions) > limit {
				sb.WriteString(fmt.Sprintf("... (%d more instructions)\n", len(sec.Instructions)-limit))
			}

			sb.WriteString("```\n")
		}

		sb.WriteString("\n")
	}

	// Beautified JavaScript
	if result.BeautifiedJS != "" {
		sb.WriteString("## Beautified JavaScript\n\n")

		preview := result.BeautifiedJS
		if len(preview) > 2000 {
			preview = preview[:2000] + "\n... (truncated)"
		}

		sb.WriteString("```javascript\n")
		sb.WriteString(preview)
		sb.WriteString("\n```\n\n")
	}

	// Errors
	if len(result.Errors) > 0 {
		sb.WriteString("## Errors\n\n")

		for _, e := range result.Errors {
			sb.WriteString(fmt.Sprintf("- %s\n", e))
		}

		sb.WriteString("\n")
	}

	// AI prompt
	if result.AIPrompt != "" {
		sb.WriteString("## AI Dissection Prompt\n\n")
		sb.WriteString("An AI system prompt for deep analysis was generated and saved to `AI_PROMPT.md`.\n")
		sb.WriteString("Feed it to an AI assistant alongside the extracted artifacts for exhaustive analysis.\n\n")
	}

	// AI insights
	if result.AIInsights != nil {
		sb.WriteString("## AI-Powered Deep Analysis\n\n")
		sb.WriteString(fmt.Sprintf("- **Duration:** %s\n", result.AIInsights.Duration))

		if result.AIInsights.Usage != nil {
			sb.WriteString(fmt.Sprintf("- **Tokens:** %d input / %d output\n",
				result.AIInsights.Usage.InputTokens, result.AIInsights.Usage.OutputTokens))
		}

		sb.WriteString("\nFull AI analysis saved to `AI_ANALYSIS.md`.\n\n")
	}

	sb.WriteString("---\n\n")
	sb.WriteString(fmt.Sprintf("*Generated by unravel dissect at %s*\n", time.Now().Format(time.RFC3339)))

	return os.WriteFile(path, []byte(sb.String()), 0644)
}

// WriteAIAnalysisReport writes the AI deep analysis as a standalone Markdown file.
func WriteAIAnalysisReport(insights *ai.AnalysisResult, path string) error {
	var sb strings.Builder

	sb.WriteString("# AI-Powered Deep Analysis\n\n")
	sb.WriteString(fmt.Sprintf("**Duration:** %s\n", insights.Duration))

	if insights.Usage != nil {
		sb.WriteString(fmt.Sprintf("**Tokens:** %d input / %d output\n",
			insights.Usage.InputTokens, insights.Usage.OutputTokens))
	}

	sb.WriteString("\n---\n\n")

	writeSection := func(title, content string) {
		if content == "" {
			return
		}

		sb.WriteString(fmt.Sprintf("## %s\n\n", title))
		sb.WriteString(content)
		sb.WriteString("\n\n")
	}

	writeSection("Manifest Analysis", insights.Manifest)
	writeSection("Code Architecture", insights.CodeArchitecture)
	writeSection("Security Findings", insights.SecurityFindings)
	writeSection("Network & API Surface", insights.NetworkSurface)
	writeSection("Secrets & Credentials", insights.SecretsExposed)
	writeSection("Obfuscation & Protection", insights.Obfuscation)
	writeSection("Risk Assessment", insights.RiskAssessment)

	sb.WriteString("---\n\n")
	sb.WriteString(fmt.Sprintf("*Generated by unravel dissect --ai at %s*\n", time.Now().Format(time.RFC3339)))

	return os.WriteFile(path, []byte(sb.String()), 0644)
}

func formatReportSize(bytes int64) string {
	const (
		kb = 1024
		mb = 1024 * kb
		gb = 1024 * mb
	)
	switch {
	case bytes >= gb:
		return fmt.Sprintf("%.1f GB", float64(bytes)/float64(gb))
	case bytes >= mb:
		return fmt.Sprintf("%.1f MB", float64(bytes)/float64(mb))
	case bytes >= kb:
		return fmt.Sprintf("%.1f KB", float64(bytes)/float64(kb))
	default:
		return fmt.Sprintf("%d bytes", bytes)
	}
}
