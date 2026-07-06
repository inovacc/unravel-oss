/*
Copyright (c) 2026 Security Research
*/

// audit_uwp.go: UWP / WinUI extractor coverage audit (D-38-DIMENSIONS-PER-STACK).
package depth

import "github.com/inovacc/unravel-oss/pkg/dissect"

// AuditUWP returns one Dimension per audited UWP / WinUI sub-extractor.
// Returns nil when dr is nil OR view is nil.
//
// Dimensions (canonical order, stable for downstream JSON consumers):
//
//	uwp.appxmanifest, uwp.capabilities, uwp.xaml_resources, uwp.pri_resources,
//	uwp.dependencies, uwp.signing_chain, uwp.localization,
//	winui.xaml, winui.xbf, winui.pri, winui.pe_embedded
//
// WinUI is folded into AuditUWP per D-38: WinUI is always part of a
// UWP-or-WinAppSDK package, so a single audit covers both surfaces.
func AuditUWP(dr *dissect.DissectResult, view UWPCoverageView) []Dimension {
	if dr == nil || view == nil {
		return nil
	}
	return []Dimension{
		NewDimension("uwp.appxmanifest", view.AppxManifestCovered(), totalUWPAppxManifest(dr)),
		NewDimension("uwp.capabilities", view.CapabilitiesCovered(), totalUWPCapabilities(dr)),
		NewDimension("uwp.xaml_resources", view.XAMLResourcesCovered(), totalUWPXAML(dr)),
		NewDimension("uwp.pri_resources", view.PRIResourcesCovered(), totalUWPPRI(dr)),
		NewDimension("uwp.dependencies", view.DependenciesCovered(), totalUWPDependencies(dr)),
		NewDimension("uwp.signing_chain", view.SigningChainCovered(), totalUWPSigning(dr)),
		NewDimension("uwp.localization", view.LocalizationCovered(), totalUWPLocalization(dr)),
		NewDimension("uwp.extensions", view.ExtensionsCovered(), totalUWPExtensions(dr)),
		NewDimension("uwp.endpoints", view.EndpointsCovered(), totalUWPEndpoints(dr)),
		NewDimension("uwp.source_files", view.SourceFilesCovered(), totalUWPSourceFiles(dr)),
		NewDimension("uwp.signed_modules", view.SignedModulesCovered(), totalUWPSignedModules(dr)),
		NewDimension("winui.xaml", view.WinUIXAMLCovered(), totalWinUIXAML(dr)),
		NewDimension("winui.xbf", view.WinUIXBFCovered(), totalWinUIXBF(dr)),
		NewDimension("winui.pri", view.WinUIPRICovered(), totalWinUIPRI(dr)),
		NewDimension("winui.pe_embedded", view.WinUIPEEmbeddedCovered(), totalWinUIPEEmbedded(dr)),
	}
}

// ---- total_uwp_* helpers ------------------------------------------------

func totalUWPAppxManifest(dr *dissect.DissectResult) int {
	// Manifest presence: count 1 when either MSIXInfo (cheap MSIX peek) or
	// UWPInfo.Manifest (full summarizer) returned a populated manifest.
	if dr.UWPInfo != nil && dr.UWPInfo.Manifest != nil && dr.UWPInfo.Manifest.PFN != "" {
		return 1
	}
	if dr.MSIXInfo != nil && dr.MSIXInfo.PackageName != "" {
		return 1
	}
	return 0
}

func totalUWPCapabilities(dr *dissect.DissectResult) int {
	if dr.UWPInfo != nil && dr.UWPInfo.Manifest != nil {
		return len(dr.UWPInfo.Manifest.Capabilities)
	}
	if dr.MSIXInfo != nil {
		return len(dr.MSIXInfo.Capabilities)
	}
	return 0
}

func totalUWPXAML(dr *dissect.DissectResult) int {
	if dr.UWPInfo == nil || dr.UWPInfo.XAMLIndex == nil {
		return 0
	}
	n := 0
	for _, e := range dr.UWPInfo.XAMLIndex.Entries {
		if e.Kind == "raw" {
			n++
		}
	}
	return n
}

func totalUWPPRI(dr *dissect.DissectResult) int {
	if dr.UWPInfo == nil || dr.UWPInfo.XAMLIndex == nil {
		return 0
	}
	n := 0
	for _, e := range dr.UWPInfo.XAMLIndex.Entries {
		if e.Kind == "pri" {
			n++
		}
	}
	return n
}

func totalUWPDependencies(dr *dissect.DissectResult) int {
	if dr.MSIXInfo != nil {
		return len(dr.MSIXInfo.Dependencies)
	}
	return 0
}

func totalUWPSigning(dr *dissect.DissectResult) int {
	if dr.MSIXInfo != nil && dr.MSIXInfo.HasSignature {
		return 1
	}
	// Installed UWP dirs lack the .msix archive signature blob; the signing
	// surface comes from PE Authenticode of an entry-point exe instead.
	if dr.CertInfo != nil && dr.CertInfo.HasSignature {
		return 1
	}
	return 0
}

func totalUWPLocalization(dr *dissect.DissectResult) int {
	if dr.UWPInfo == nil || dr.UWPInfo.Manifest == nil {
		return 0
	}
	return len(dr.UWPInfo.Manifest.TargetFamilies)
}

func totalUWPExtensions(dr *dissect.DissectResult) int {
	if dr.MSIXInfo == nil {
		return 0
	}
	return len(dr.MSIXInfo.Extensions)
}

func totalUWPEndpoints(dr *dissect.DissectResult) int {
	if dr.MSIXInfo == nil {
		return 0
	}
	return len(dr.MSIXInfo.URLs)
}

func totalUWPSourceFiles(dr *dissect.DissectResult) int {
	if dr.MSIXInfo == nil {
		return 0
	}
	return len(dr.MSIXInfo.Files)
}

// totalUWPSignedModules counts how many PE files were Authenticode-scanned
// (Signed != nil). Coverage = how many were scanned + signed.
func totalUWPSignedModules(dr *dissect.DissectResult) int {
	if dr.MSIXInfo == nil {
		return 0
	}
	n := 0
	for _, f := range dr.MSIXInfo.Files {
		if f.Signed != nil {
			n++
		}
	}
	return n
}

// ---- total_winui_* helpers ----------------------------------------------

func totalWinUIXAML(dr *dissect.DissectResult) int {
	if dr.WinUIInfo == nil || dr.WinUIInfo.XAMLIndex == nil {
		return 0
	}
	n := 0
	for _, e := range dr.WinUIInfo.XAMLIndex.Entries {
		if e.Kind == "raw" {
			n++
		}
	}
	return n
}

func totalWinUIXBF(dr *dissect.DissectResult) int {
	if dr.WinUIInfo == nil || dr.WinUIInfo.XAMLIndex == nil {
		return 0
	}
	n := 0
	for _, e := range dr.WinUIInfo.XAMLIndex.Entries {
		if e.Kind == "xbf" {
			n++
		}
	}
	return n
}

func totalWinUIPRI(dr *dissect.DissectResult) int {
	if dr.WinUIInfo == nil || dr.WinUIInfo.XAMLIndex == nil {
		return 0
	}
	n := 0
	for _, e := range dr.WinUIInfo.XAMLIndex.Entries {
		if e.Kind == "pri" {
			n++
		}
	}
	return n
}

func totalWinUIPEEmbedded(dr *dissect.DissectResult) int {
	if dr.WinUIInfo == nil || dr.WinUIInfo.XAMLIndex == nil {
		return 0
	}
	n := 0
	for _, e := range dr.WinUIInfo.XAMLIndex.Entries {
		if e.Kind == "pe-embedded" || e.Kind == "pe-embedded-xbf" {
			n++
		}
	}
	return n
}
