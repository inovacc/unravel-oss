/*
Copyright (c) 2026 Security Research
*/
package output

import (
	"fmt"
	"slices"
	"strings"

	"github.com/inovacc/unravel-oss/pkg/dissect"
)

// PrintDissect prints the dissect pipeline results box.
func PrintDissect(r *dissect.DissectResult) {
	w := 70
	border := strings.Repeat("═", w)

	fmt.Printf("╔%s╗\n", border)
	fmt.Printf("║%-*s║\n", w, "  DISSECT RESULTS")
	fmt.Printf("╠%s╣\n", border)

	// File info (wrap long names/paths instead of truncating)
	printWrappedField("Name", r.FileName, w)
	printWrappedField("Path", r.Path, w)
	fmt.Printf("║ Size: %-*s║\n", w-7, FormatSize(r.Size))

	// Detection
	fmt.Printf("╠%s╣\n", border)
	fmt.Printf("║ Type:       %-*s║\n", w-13, string(r.Detection.FileType))
	fmt.Printf("║ Category:   %-*s║\n", w-13, string(r.Detection.Category))
	fmt.Printf("║ Confidence: %-*s║\n", w-13, string(r.Detection.Confidence))

	if r.Detection.Details != "" {
		fmt.Printf("║ Details:    %-*s║\n", w-13, Truncate(r.Detection.Details, w-14))
	}

	// Analyses table
	if len(r.Analyses) > 0 {
		fmt.Printf("╠%s╣\n", border)
		fmt.Printf("║ %-*s║\n", w-1, "ANALYSES")

		for _, a := range r.Analyses {
			icon := "✓"

			switch a.Status {
			case "error":
				icon = "✗"
			case "skipped":
				icon = "○"
			}

			line := fmt.Sprintf("%s %-30s %s", icon, a.Name, a.Duration)
			fmt.Printf("║  %-*s║\n", w-2, Truncate(line, w-3))
		}
	}

	// Key findings
	findings := CollectDissectFindings(r)
	if len(findings) > 0 {
		fmt.Printf("╠%s╣\n", border)
		fmt.Printf("║ %-*s║\n", w-1, "KEY FINDINGS")

		for _, f := range findings {
			fmt.Printf("║  %-*s║\n", w-2, Truncate(f, w-3))
		}
	}

	// Errors
	if len(r.Errors) > 0 {
		fmt.Printf("╠%s╣\n", border)
		fmt.Printf("║ %-*s║\n", w-1, fmt.Sprintf("ERRORS (%d)", len(r.Errors)))

		for _, e := range r.Errors {
			fmt.Printf("║  %-*s║\n", w-2, Truncate(e, w-3))
		}
	}

	// Duration footer
	fmt.Printf("╠%s╣\n", border)
	fmt.Printf("║ Duration: %-*s║\n", w-11, r.Duration.String())
	fmt.Printf("╚%s╝\n", border)
}

// printWrappedField prints a labeled field that wraps long values across
// multiple lines within the box, instead of truncating them.
func printWrappedField(label, value string, w int) {
	prefix := fmt.Sprintf(" %s: ", label)
	contentWidth := w - len(prefix) - 1 // -1 for trailing ║ padding

	if len(value) <= contentWidth {
		fmt.Printf("║%s%-*s║\n", prefix, contentWidth, value)
		return
	}

	lines := WrapText(value, contentWidth)
	// First line with label
	fmt.Printf("║%s%-*s║\n", prefix, contentWidth, lines[0])
	// Continuation lines aligned with value start
	indent := strings.Repeat(" ", len(prefix))
	for _, line := range lines[1:] {
		fmt.Printf("║%s%-*s║\n", indent, contentWidth, line)
	}
}

// CollectDissectFindings extracts key findings from a dissect result.
func CollectDissectFindings(r *dissect.DissectResult) []string {
	var findings []string

	// Go binary findings
	if r.GarbleDetect != nil {
		verdict := "not garbled"
		if r.GarbleDetect.IsGarbled {
			verdict = fmt.Sprintf("GARBLED (%.0f%% confidence)", r.GarbleDetect.Confidence)
		}

		findings = append(findings, fmt.Sprintf("Garble: %s", verdict))
	}

	if r.GarbleInfo != nil {
		if r.GarbleInfo.GoVersion != "" {
			findings = append(findings, fmt.Sprintf("Go version: %s", r.GarbleInfo.GoVersion))
		}

		if r.GarbleInfo.ModulePath != "" {
			findings = append(findings, fmt.Sprintf("Module: %s", r.GarbleInfo.ModulePath))
		}
	}

	// Certificate findings
	if r.CertInfo != nil {
		if r.CertInfo.HasSignature {
			signer := "unknown"
			if r.CertInfo.Signer != nil {
				signer = r.CertInfo.Signer.CommonName
				if signer == "" {
					signer = r.CertInfo.Signer.Organization
				}
			}

			findings = append(findings, fmt.Sprintf("Signed by: %s", signer))
		} else {
			findings = append(findings, "No digital signature")
		}
	}

	// APK findings
	if r.APKInfo != nil {
		findings = append(findings, fmt.Sprintf("APK format: %s, %d files", r.APKInfo.Format, r.APKInfo.TotalFiles))
		if len(r.APKInfo.SignatureSchemes) > 0 {
			findings = append(findings, fmt.Sprintf("Signature schemes: %s", strings.Join(r.APKInfo.SignatureSchemes, ", ")))
		}
	}

	// APK extraction findings
	if r.APKExtract != nil {
		findings = append(findings, fmt.Sprintf("Extracted: %d files (%s)",
			r.APKExtract.Files, FormatSize(r.APKExtract.TotalSize)))
	}

	// Decompile findings
	if r.Decompile != nil {
		if len(r.Decompile.ToolsUsed) > 0 {
			findings = append(findings, fmt.Sprintf("Decompile: %d tools used (%s)",
				len(r.Decompile.ToolsUsed), strings.Join(r.Decompile.ToolsUsed, ", ")))
		}

		if len(r.Decompile.ToolsMissing) > 0 {
			findings = append(findings, fmt.Sprintf("Tools missing: %s",
				strings.Join(r.Decompile.ToolsMissing, ", ")))
		}
	}

	// Tools status findings
	if r.ToolsStatus != nil {
		findings = append(findings, fmt.Sprintf("RE tools: %d/%d available",
			r.ToolsStatus.Available, r.ToolsStatus.Total))
	}

	// AI prompt
	if r.AIPrompt != "" {
		findings = append(findings, "AI dissection prompt: generated")
	}

	// AI insights
	if r.AIInsights != nil {
		findings = append(findings, fmt.Sprintf("AI analysis: completed (%s)", r.AIInsights.Duration))
		if r.AIInsights.Usage != nil {
			findings = append(findings, fmt.Sprintf("Tokens: %d in / %d out",
				r.AIInsights.Usage.InputTokens, r.AIInsights.Usage.OutputTokens))
		}
	}

	// Disassembly findings
	if r.Disassembly != nil {
		total := 0
		for _, s := range r.Disassembly.Sections {
			total += len(s.Instructions)
		}

		findings = append(findings, fmt.Sprintf("Disassembly: %s %s, %d instructions (%s)",
			r.Disassembly.Architecture, r.Disassembly.Format, total, r.Disassembly.Tool))
	}

	// Beautified JS
	if r.BeautifiedJS != "" {
		findings = append(findings, fmt.Sprintf("JS beautified: %d bytes", len(r.BeautifiedJS)))
	}

	// DEB findings
	if r.DEBInfo != nil && r.DEBInfo.Control != nil {
		findings = append(findings, fmt.Sprintf("Package: %s %s (%s)",
			r.DEBInfo.Control.Package, r.DEBInfo.Control.Version, r.DEBInfo.Control.Architecture))
	}

	// MSI findings
	if r.MSIInfo != nil {
		name := r.MSIInfo.ProductName
		if name == "" {
			name = r.MSIInfo.FileName
		}

		findings = append(findings, fmt.Sprintf("MSI: %s %s (%s)",
			name, r.MSIInfo.ProductVersion, r.MSIInfo.Manufacturer))

		if len(r.MSIInfo.CustomActions) > 0 {
			findings = append(findings, fmt.Sprintf("Custom actions: %d", len(r.MSIInfo.CustomActions)))
		}
	}

	// RPM findings
	if r.RPMInfo != nil {
		findings = append(findings, fmt.Sprintf("Package: %s %s-%s (%s)",
			r.RPMInfo.Name, r.RPMInfo.Version, r.RPMInfo.Release, r.RPMInfo.Arch))
	}

	// ASAR findings
	if r.ASARStats != nil {
		findings = append(findings, fmt.Sprintf("ASAR: %d files, %s total",
			r.ASARStats.FileCount, FormatSize(r.ASARStats.TotalSize)))
	}

	// LevelDB findings
	if r.LevelDB != nil {
		findings = append(findings, fmt.Sprintf("LevelDB: %d entries (%d valid)",
			r.LevelDB.Stats.TotalEntries, r.LevelDB.Stats.ValidEntries))
	}

	// Cache findings
	if r.Cache != nil {
		findings = append(findings, fmt.Sprintf("Cache: %s format, %d entries, %d domains",
			r.Cache.CacheFormat, r.Cache.Stats.TotalEntries, len(r.Cache.ByDomain)))
	}

	// JS findings
	if r.JSAnalysis != nil {
		level := "LOW"
		if r.JSAnalysis.ObfuscationScore >= 50 {
			level = "HIGH"
		} else if r.JSAnalysis.ObfuscationScore >= 20 {
			level = "MEDIUM"
		}

		findings = append(findings, fmt.Sprintf("Obfuscation: %d (%s)", r.JSAnalysis.ObfuscationScore, level))
		if len(r.JSAnalysis.DangerousCalls) > 0 {
			findings = append(findings, fmt.Sprintf("Dangerous calls: %d", len(r.JSAnalysis.DangerousCalls)))
		}
	}

	// App analysis findings
	if r.AppAnalysis != nil {
		findings = append(findings, fmt.Sprintf("Risk: %s (score %d)",
			r.AppAnalysis.Analysis.RiskLevel, r.AppAnalysis.Analysis.RiskScore))
		if r.AppAnalysis.AppInfo.HasStealth {
			findings = append(findings, "Stealth features: DETECTED")
		}
	}

	// Framework detection findings
	if r.FrameworkAnalysis != nil && r.FrameworkAnalysis.Framework != "" {
		findings = append(findings, fmt.Sprintf("Framework: %s", r.FrameworkAnalysis.Framework))
		if r.FrameworkAnalysis.Flutter != nil {
			if r.FrameworkAnalysis.Flutter.EngineVersion != "" {
				findings = append(findings, fmt.Sprintf("Flutter engine: %s", r.FrameworkAnalysis.Flutter.EngineVersion))
			}
			if r.FrameworkAnalysis.Flutter.DartVersion != "" {
				findings = append(findings, fmt.Sprintf("Dart version: %s", r.FrameworkAnalysis.Flutter.DartVersion))
			}
			if r.FrameworkAnalysis.Flutter.IsObfuscated {
				findings = append(findings, "Flutter: obfuscated (no snapshots)")
			}
			if len(r.FrameworkAnalysis.Flutter.Plugins) > 0 {
				findings = append(findings, fmt.Sprintf("Flutter plugins: %d", len(r.FrameworkAnalysis.Flutter.Plugins)))
			}
		}
		if r.FrameworkAnalysis.ReactNative != nil {
			engine := r.FrameworkAnalysis.ReactNative.JSEngine
			if r.FrameworkAnalysis.ReactNative.HermesVersion != "" {
				engine += fmt.Sprintf(" (bytecode v%s)", r.FrameworkAnalysis.ReactNative.HermesVersion)
			}
			findings = append(findings, fmt.Sprintf("JS engine: %s", engine))
			if sm := r.FrameworkAnalysis.ReactNative.SourceMap; sm != nil && sm.SourceCount > 0 {
				detail := fmt.Sprintf("Source maps: %d sources exposed", sm.SourceCount)
				if sm.HasSources {
					detail += " (inline content present)"
				}
				findings = append(findings, detail)
			}
		}
		if r.FrameworkAnalysis.Xamarin != nil {
			variant := "Xamarin.Android"
			if r.FrameworkAnalysis.Xamarin.IsMAUI {
				variant = "MAUI"
			} else if r.FrameworkAnalysis.Xamarin.IsXamarinForms {
				variant = "Xamarin.Forms"
			}
			findings = append(findings, fmt.Sprintf("Xamarin variant: %s", variant))
		}
	}

	// Frida scripts
	if r.FridaScripts != nil && len(r.FridaScripts.Scripts) > 0 {
		findings = append(findings, fmt.Sprintf("Frida scripts: %d generated", len(r.FridaScripts.Scripts)))
		findings = append(findings, "Runtime instrumentation: available (unravel frida run)")
	}

	// Capture templates
	if r.FridaScripts != nil && r.FridaScripts.CaptureTemplates != nil && len(r.FridaScripts.CaptureTemplates.Templates) > 0 {
		findings = append(findings, fmt.Sprintf("Capture templates: %d generated", len(r.FridaScripts.CaptureTemplates.Templates)))
	}

	// Extension package findings
	if r.ExtAnalysis != nil {
		findings = append(findings, fmt.Sprintf("Extension risk: %s (score %d)",
			r.ExtAnalysis.RiskLevel, r.ExtAnalysis.RiskScore))
		if len(r.ExtAnalysis.NativeMessagingHosts) > 0 {
			findings = append(findings, fmt.Sprintf("Native hosts: %d", len(r.ExtAnalysis.NativeMessagingHosts)))
		}

		if len(r.ExtAnalysis.WebSocketEndpoints) > 0 {
			findings = append(findings, fmt.Sprintf("WebSocket endpoints: %d", len(r.ExtAnalysis.WebSocketEndpoints)))
		}
	}

	// Framework detection findings (detailed)
	if r.FrameworkAnalysis != nil && r.FrameworkAnalysis.Framework != "" {
		if r.FrameworkAnalysis.Flutter != nil {
			if r.FrameworkAnalysis.Flutter.IsObfuscated {
				findings = append(findings, "Flutter: obfuscated (no snapshot data)")
			}
			if len(r.FrameworkAnalysis.Flutter.ABIs) > 0 {
				findings = append(findings, fmt.Sprintf("Flutter ABIs: %s", strings.Join(r.FrameworkAnalysis.Flutter.ABIs, ", ")))
			}
		}
		if r.FrameworkAnalysis.ReactNative != nil {
			findings = append(findings, fmt.Sprintf("JS Engine: %s", r.FrameworkAnalysis.ReactNative.JSEngine))
			if r.FrameworkAnalysis.ReactNative.HermesVersion != "" {
				findings = append(findings, fmt.Sprintf("Hermes bytecode: v%s", r.FrameworkAnalysis.ReactNative.HermesVersion))
			}
		}
		if r.FrameworkAnalysis.Xamarin != nil {
			findings = append(findings, fmt.Sprintf("Assemblies: %d", r.FrameworkAnalysis.Xamarin.AssemblyCount))
			if r.FrameworkAnalysis.Xamarin.IsMAUI {
				findings = append(findings, "Platform: .NET MAUI")
			} else if r.FrameworkAnalysis.Xamarin.IsXamarinForms {
				findings = append(findings, "Platform: Xamarin.Forms")
			}
			if r.Decompile != nil {
				if slices.Contains(r.Decompile.ToolsUsed, "ilspycmd") {
					findings = append(findings, "Xamarin .NET decompilation: auto-triggered via framework detection")
				}
			}
		}
	}

	return findings
}
