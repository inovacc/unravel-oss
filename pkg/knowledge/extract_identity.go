package knowledge

import (
	"log/slog"
	"path/filepath"
	"strings"

	"github.com/inovacc/unravel-oss/pkg/dissect"
)

// extractIdentity returns (platform, packageID, displayName, publisher) per
// D-35-EXTRACT-DISPATCH. Order: MSIX → APK → iOS → .NET → Electron/Tauri → empty.
// MSIX wins over Electron-inside-MSIX (D-35-MSIX-WINS-FOR-ELECTRON).
// Never derives from filename or path (D-35-NO-FALLBACK-INFERENCE) — empty
// string is the explicit "could-not-determine" signal.
//
// DRIFT RECONCILIATION: 35-CONTEXT.md mentioned DotNetInfo.AssemblyName which
// does not exist on dissect.DissectResult. The correct source for the .NET
// identity is BinaryInfo.ProductName (PE VS_VERSION_INFO), guarded by
// DotnetDeps != nil || DotnetRuntime != nil (verified in 35-RESEARCH §Pitfalls #4).
func extractIdentity(r *dissect.DissectResult) (platform, packageID, displayName, publisher string) {
	if r == nil {
		return
	}

	// 1) MSIX/UWP first — wins over Electron-inside-MSIX (D-35-MSIX-WINS-FOR-ELECTRON).
	if r.MSIXInfo != nil && r.MSIXInfo.PackageName != "" {
		platform = "windows-msix"
		packageID = r.MSIXInfo.PackageName
		displayName = r.MSIXInfo.PublisherDisplayName
		if displayName == "" {
			displayName = r.MSIXInfo.PackageName
		}
		publisher = r.MSIXInfo.Publisher
		return
	}

	// Installed UWP directories: TypeUWPApp dispatch fires analyzeUWP
	// (pkg/dissect/analyze_uwp.go) which populates UWPInfo via the full
	// uwp.Analyze pipeline rather than MSIXInfo. Fall back to that
	// branch so identity propagates for installed apps too. Closes 999.12.
	if r.UWPInfo != nil && r.UWPInfo.Manifest != nil && r.UWPInfo.Manifest.Identity.Name != "" {
		platform = "windows-msix"
		packageID = r.UWPInfo.Manifest.Identity.Name
		displayName = r.UWPInfo.Manifest.Identity.Name
		publisher = r.UWPInfo.Manifest.Identity.Publisher
		return
	}

	// 2) APK
	if r.ManifestInfo != nil && r.ManifestInfo.Package != "" {
		platform = "android"
		packageID = r.ManifestInfo.Package
		displayName = r.ManifestInfo.Package
		return
	}

	// 3) iOS
	if r.IPAInfo != nil && r.IPAInfo.BundleID != "" {
		platform = "ios"
		packageID = r.IPAInfo.BundleID
		displayName = r.IPAInfo.BundleName
		if displayName == "" {
			displayName = r.IPAInfo.BundleID
		}
		if r.IPAInfo.SigningInfo != nil {
			publisher = r.IPAInfo.SigningInfo.TeamID
		}
		return
	}

	// 4) .NET — DRIFT RECONCILIATION: CONTEXT.md mentioned DotNetInfo.AssemblyName,
	// which does not exist on DissectResult. Use BinaryInfo.ProductName instead
	// (35-RESEARCH §Pitfalls #4; field-path verified at PE VS_VERSION_INFO source).
	if (r.DotnetDeps != nil || r.DotnetRuntime != nil) && r.BinaryInfo != nil && r.BinaryInfo.ProductName != "" {
		platform = "windows-pe"
		packageID = r.BinaryInfo.ProductName
		displayName = r.BinaryInfo.ProductName
		return
	}

	// 5) Electron / Tauri without MSIX wrapper — derive platform from binary type.
	// Directory-mode dispatch (TypeElectronApp / TypeTauriApp) does not populate
	// r.BinaryInfo; the per-binary results live on r.AppAnalysis.Binaries instead.
	// Use the first known binary type from either source — evidence-based, no
	// path/extension inference (preserves D-35-NO-FALLBACK-INFERENCE).
	if r.AppAnalysis != nil && (r.AppAnalysis.AppInfo.Type == "electron" || r.AppAnalysis.AppInfo.Type == "tauri") && r.AppAnalysis.AppInfo.Name != "" {
		binType := ""
		if r.BinaryInfo != nil {
			binType = r.BinaryInfo.Type
		}
		if binType == "" {
			for _, b := range r.AppAnalysis.Binaries {
				if b.Type != "" {
					binType = b.Type
					break
				}
			}
		}
		// binary.Analyze emits "PE"/"ELF"/"Mach-O" (capitalized); historical APK
		// path used lowercase — accept both so the Electron branch fires
		// regardless of which producer populated the Type field.
		switch strings.ToLower(strings.ReplaceAll(binType, "-", "")) {
		case "pe":
			platform = "windows-pe"
		case "elf":
			platform = "linux-elf"
		case "macho":
			platform = "macos"
		}
		packageID = r.AppAnalysis.AppInfo.Name
		displayName = r.AppAnalysis.AppInfo.DisplayName
		if displayName == "" {
			displayName = r.AppAnalysis.AppInfo.Name
		}
		return
	}

	// 6) NPM
	if r.NPMAnalysis != nil && r.NPMAnalysis.PackageName != "" {
		platform = "npm"
		packageID = r.NPMAnalysis.PackageName
		displayName = r.NPMAnalysis.PackageName
		return
	}

	// 7) Go binary — standalone Go tools/agents carry no package manifest. Prefer
	// the build-info module path (evidence from the binary itself, not the
	// filename); when it is stripped (-trimpath/-ldflags), fall back to the
	// binary's own base name so the app still gets a stable KB identity. This is
	// the one deliberate, narrowly-scoped exception to D-35-NO-FALLBACK-INFERENCE:
	// it fires ONLY for confirmed Go binaries that yield no manifest identity, so
	// Go apps stop dropping out of the KB entirely.
	if r.GarbleInfo != nil && (r.GarbleInfo.HasBuildInfo || r.GarbleInfo.GoVersion != "") {
		platform = goPlatform(r.GarbleInfo.OS)
		if mp := r.GarbleInfo.ModulePath; mp != "" && mp != "command-line-arguments" {
			packageID = mp
		} else {
			packageID = goBinaryName(r.Path)
		}
		displayName = packageID
		return
	}

	slog.Warn("knowledge: no identity derivable", "source", r.Path)
	return
}

// goPlatform maps a Go GOOS to the unravel platform tag, defaulting to "go" when
// the OS is unknown.
func goPlatform(goos string) string {
	switch strings.ToLower(goos) {
	case "windows":
		return "windows-pe"
	case "linux":
		return "linux-elf"
	case "darwin":
		return "macos"
	default:
		return "go"
	}
}

// goBinaryName is the binary's base name without a Windows .exe suffix — the
// fallback identity for a stripped Go binary.
func goBinaryName(p string) string {
	return strings.TrimSuffix(filepath.Base(p), ".exe")
}
