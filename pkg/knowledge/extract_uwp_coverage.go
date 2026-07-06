/*
Copyright (c) 2026 Security Research
*/

// extract_uwp_coverage.go: P38 Plan 38-02 — wire pkg/uwp + pkg/winui +
// pkg/webview2 extractor outputs into KnowledgeResult.Packaging.UWP +
// KnowledgeResult.WebView2.
//
// Empty extractor output stays empty (D-35-NO-FALLBACK-INFERENCE). Risk score
// is delegated to pkg/uwp/risk per D-38-CAPABILITY-REUSE-PKG-UWP-RISK — this
// file does NOT duplicate scoring logic.
//
// Filename uses _coverage.go suffix (NOT _windows.go) to avoid GOOS-suffix
// silent drop on non-Windows hosts (P37-02 deviation precedent).
package knowledge

import (
	"log/slog"
	"strings"

	"github.com/inovacc/unravel-oss/pkg/dissect"
	"github.com/inovacc/unravel-oss/pkg/knowledge/kb/depth"
	"github.com/inovacc/unravel-oss/pkg/uwp"
	"github.com/inovacc/unravel-oss/pkg/uwp/risk"
)

// Compile-time interface assertions: KnowledgeResult must satisfy the
// coverage views the depth audit functions consume. Per D-37-DEPTH-COVERED-RATIO
// these are the contract between pkg/knowledge and pkg/knowledge/kb/depth.
var (
	_ depth.UWPCoverageView      = (*KnowledgeResult)(nil)
	_ depth.WebView2CoverageView = (*KnowledgeResult)(nil)
)

// extractUWPCoverage wires UWP / WinUI / WebView2 extractor outputs into
// KnowledgeResult. Runs AFTER extractAndroidCoverage in Extract. No-op when
// kr.Platform != "windows" or no MSIX/UWP/WebView2 signal is present.
func extractUWPCoverage(dr *dissect.DissectResult, kr *KnowledgeResult) {
	if dr == nil || kr == nil {
		return
	}
	if !strings.HasPrefix(kr.Platform, "windows") {
		return
	}
	if dr.MSIXInfo == nil && dr.UWPInfo == nil && dr.WinUIInfo == nil && dr.WebView2Info == nil {
		slog.Warn("knowledge: windows platform but no UWP/WinUI/WebView2 signal in DissectResult",
			"source", dr.Path)
		return
	}

	// Populate UWP path when any UWP/WinUI signal exists.
	if dr.MSIXInfo != nil || dr.UWPInfo != nil || dr.WinUIInfo != nil {
		if kr.Packaging == nil {
			// Defensive: extractPackaging may not have populated Packaging yet
			// if MSIXInfo is absent. Keep allocation here so UWP-only signal
			// (UWPInfo without MSIXInfo) still surfaces.
			kr.Packaging = &PackagingKnowledge{Format: "uwp"}
		}
		if kr.Packaging.UWP == nil {
			kr.Packaging.UWP = &UWPKnowledge{}
		}
		extractUWPManifest(dr, kr)
		extractUWPCapabilities(dr, kr)
		extractUWPXAMLResources(dr, kr)
		extractUWPPRIResources(dr, kr)
		extractUWPDependencies(dr, kr)
		extractUWPSigningChain(dr, kr)
		extractUWPLocalization(dr, kr)
		extractUWPExtensions(dr, kr)
		extractUWPEndpoints(dr, kr)
		extractWinUIXAML(dr, kr)
		extractWinUIXBF(dr, kr)
		extractWinUIPRI(dr, kr)
		extractWinUIPEEmbedded(dr, kr)
	}

	if dr.WebView2Info != nil {
		extractWebView2(dr, kr)
	}
}

func extractUWPManifest(dr *dissect.DissectResult, kr *KnowledgeResult) {
	// Prefer UWPInfo.Manifest (full summarizer); fall back to MSIXInfo
	// (cheap peek) when UWPInfo absent.
	if dr.UWPInfo != nil && dr.UWPInfo.Manifest != nil {
		m := dr.UWPInfo.Manifest
		summary := &UWPManifestSummary{
			PFN:            m.PFN,
			Name:           m.Identity.Name,
			Publisher:      m.Identity.Publisher,
			Version:        m.Identity.Version,
			ProcessorArch:  m.Identity.ProcessorArch,
			TargetFamilies: append([]string(nil), m.TargetFamilies...),
		}
		for _, ep := range m.EntryPoints {
			label := ep.Id
			if ep.Executable != "" {
				label = ep.Id + "@" + ep.Executable
			}
			summary.EntryPoints = append(summary.EntryPoints, label)
		}
		kr.Packaging.UWP.AppxManifest = summary
		return
	}
	if dr.MSIXInfo != nil && dr.MSIXInfo.PackageName != "" {
		kr.Packaging.UWP.AppxManifest = &UWPManifestSummary{
			Name:          dr.MSIXInfo.PackageName,
			Publisher:     dr.MSIXInfo.Publisher,
			Version:       dr.MSIXInfo.PackageVersion,
			ProcessorArch: dr.MSIXInfo.ProcessorArchitecture,
		}
	}
}

func extractUWPCapabilities(dr *dissect.DissectResult, kr *KnowledgeResult) {
	if dr.UWPInfo != nil && dr.UWPInfo.Manifest != nil && len(dr.UWPInfo.Manifest.Capabilities) > 0 {
		caps := dr.UWPInfo.Manifest.Capabilities
		for _, c := range caps {
			kr.Packaging.UWP.Capabilities = append(kr.Packaging.UWP.Capabilities, UWPCapability{
				Name:      c.Name,
				Namespace: c.Namespace,
			})
		}
		// D-38-CAPABILITY-REUSE: delegate to pkg/uwp/risk. Use the score the
		// analyzer already computed when present; otherwise compute against
		// the default rubric (no signature info available here).
		if dr.UWPInfo.Score != nil {
			kr.Packaging.UWP.RiskScore = dr.UWPInfo.Score.Value
			kr.Packaging.UWP.RiskLevel = dr.UWPInfo.Score.Level
		} else {
			score := risk.Score(caps, uwp.SignatureInfo{}, nil)
			kr.Packaging.UWP.RiskScore = score.Value
			kr.Packaging.UWP.RiskLevel = score.Level
		}
		return
	}
	// Fallback: MSIXInfo carries a flat []string of capability names; we
	// surface them but cannot compute a numeric risk because the parser did
	// not retain namespace info. Risk score stays 0 — depth audit reports
	// the population coverage faithfully.
	if dr.MSIXInfo != nil {
		for _, name := range dr.MSIXInfo.Capabilities {
			kr.Packaging.UWP.Capabilities = append(kr.Packaging.UWP.Capabilities, UWPCapability{
				Name: name,
			})
		}
	}
}

func extractUWPXAMLResources(dr *dissect.DissectResult, kr *KnowledgeResult) {
	if dr.UWPInfo == nil || dr.UWPInfo.XAMLIndex == nil {
		return
	}
	for _, e := range dr.UWPInfo.XAMLIndex.Entries {
		if e.Kind != "raw" {
			continue
		}
		kr.Packaging.UWP.XAMLResources = append(kr.Packaging.UWP.XAMLResources, ResourceRef{
			Path:     e.Path,
			Category: "xaml",
		})
	}
}

func extractUWPPRIResources(dr *dissect.DissectResult, kr *KnowledgeResult) {
	if dr.UWPInfo == nil || dr.UWPInfo.XAMLIndex == nil {
		return
	}
	for _, e := range dr.UWPInfo.XAMLIndex.Entries {
		if e.Kind != "pri" {
			continue
		}
		kr.Packaging.UWP.PRIResources = append(kr.Packaging.UWP.PRIResources, ResourceRef{
			Path:     e.Path,
			Category: "pri",
		})
	}
}

func extractUWPDependencies(dr *dissect.DissectResult, kr *KnowledgeResult) {
	if dr.MSIXInfo == nil {
		return
	}
	for _, dep := range dr.MSIXInfo.Dependencies {
		kr.Packaging.UWP.Dependencies = append(kr.Packaging.UWP.Dependencies, dep.Name)
	}
}

func extractUWPSigningChain(dr *dissect.DissectResult, kr *KnowledgeResult) {
	if dr.MSIXInfo != nil && dr.MSIXInfo.HasSignature {
		entry := "msix-signed"
		if dr.MSIXInfo.PublisherDisplayName != "" {
			entry = dr.MSIXInfo.PublisherDisplayName
		}
		kr.Packaging.UWP.SigningChain = append(kr.Packaging.UWP.SigningChain, entry)
	}
	if dr.CertInfo != nil && dr.CertInfo.HasSignature && dr.CertInfo.Signer != nil {
		kr.Packaging.UWP.SigningChain = append(kr.Packaging.UWP.SigningChain, dr.CertInfo.Signer.Subject)
	}
}

func extractUWPLocalization(dr *dissect.DissectResult, kr *KnowledgeResult) {
	if dr.UWPInfo == nil || dr.UWPInfo.Manifest == nil {
		return
	}
	kr.Packaging.UWP.Localization = append(kr.Packaging.UWP.Localization, dr.UWPInfo.Manifest.TargetFamilies...)
}

func extractWinUIXAML(dr *dissect.DissectResult, kr *KnowledgeResult) {
	if dr.WinUIInfo == nil || dr.WinUIInfo.XAMLIndex == nil {
		return
	}
	for _, e := range dr.WinUIInfo.XAMLIndex.Entries {
		if e.Kind != "raw" {
			continue
		}
		kr.Packaging.UWP.WinUIXAML = append(kr.Packaging.UWP.WinUIXAML, ResourceRef{
			Path:     e.Path,
			Category: "winui-xaml",
		})
	}
}

func extractWinUIXBF(dr *dissect.DissectResult, kr *KnowledgeResult) {
	if dr.WinUIInfo == nil || dr.WinUIInfo.XAMLIndex == nil {
		return
	}
	for _, e := range dr.WinUIInfo.XAMLIndex.Entries {
		if e.Kind != "xbf" {
			continue
		}
		kr.Packaging.UWP.WinUIXBF = append(kr.Packaging.UWP.WinUIXBF, ResourceRef{
			Path:     e.Path,
			Category: "winui-xbf",
		})
	}
}

func extractWinUIPRI(dr *dissect.DissectResult, kr *KnowledgeResult) {
	if dr.WinUIInfo == nil || dr.WinUIInfo.XAMLIndex == nil {
		return
	}
	for _, e := range dr.WinUIInfo.XAMLIndex.Entries {
		if e.Kind != "pri" {
			continue
		}
		kr.Packaging.UWP.WinUIPRI = append(kr.Packaging.UWP.WinUIPRI, ResourceRef{
			Path:     e.Path,
			Category: "winui-pri",
		})
	}
}

func extractWinUIPEEmbedded(dr *dissect.DissectResult, kr *KnowledgeResult) {
	if dr.WinUIInfo == nil || dr.WinUIInfo.XAMLIndex == nil {
		return
	}
	for _, e := range dr.WinUIInfo.XAMLIndex.Entries {
		if e.Kind != "pe-embedded" && e.Kind != "pe-embedded-xbf" {
			continue
		}
		kr.Packaging.UWP.WinUIPEEmbedded = append(kr.Packaging.UWP.WinUIPEEmbedded, e.Path)
	}
}

func extractUWPExtensions(dr *dissect.DissectResult, kr *KnowledgeResult) {
	if dr.MSIXInfo == nil || len(dr.MSIXInfo.Extensions) == 0 {
		return
	}
	if kr.IPC == nil {
		kr.IPC = &IPCKnowledge{}
	}
	if kr.Communication == nil {
		kr.Communication = &CommunicationKnowledge{}
	}
	protocolSeen := map[string]bool{}
	for _, p := range kr.Communication.Protocols {
		protocolSeen[p] = true
	}
	for _, ext := range dr.MSIXInfo.Extensions {
		switch ext.Category {
		case "windows.appService":
			kr.IPC.Channels = append(kr.IPC.Channels, IPCChannel{
				Name:      "appservice:" + ext.Name,
				Direction: "bidirectional",
				RiskLevel: "medium",
			})
		case "windows.protocol":
			kr.IPC.Channels = append(kr.IPC.Channels, IPCChannel{
				Name:      "protocol:" + ext.Name,
				Direction: "inbound",
				RiskLevel: "medium",
			})
			if !protocolSeen[ext.Name] {
				kr.Communication.Protocols = append(kr.Communication.Protocols, ext.Name)
				protocolSeen[ext.Name] = true
			}
		case "windows.fileTypeAssociation":
			fts := strings.Join(ext.FileTypes, ",")
			kr.IPC.Channels = append(kr.IPC.Channels, IPCChannel{
				Name:      "fta:" + ext.Name + " (" + fts + ")",
				Direction: "inbound",
				RiskLevel: "low",
			})
		case "windows.backgroundTasks":
			for _, t := range ext.TaskTypes {
				kr.IPC.Channels = append(kr.IPC.Channels, IPCChannel{
					Name:      "bgtask:" + t,
					Direction: "inbound",
					RiskLevel: "medium",
				})
			}
		case "windows.comServer":
			for _, cls := range ext.ComClasses {
				kr.IPC.Channels = append(kr.IPC.Channels, IPCChannel{
					Name:       "com:" + cls,
					Direction:  "bidirectional",
					RiskLevel:  "high",
					Privileged: true,
				})
			}
		default:
			kr.IPC.Channels = append(kr.IPC.Channels, IPCChannel{
				Name:      "ext:" + ext.Category,
				Direction: "unknown",
			})
		}
	}
	if len(kr.IPC.Channels) > 0 {
		kr.IPC.Protocols = appendIfNew(kr.IPC.Protocols, "uwp-extension")
	}
}

// extractUWPEndpoints copies discovered HTTP/HTTPS URLs from MSIXInfo.URLs
// into kr.Communication.Endpoints. Each URL is categorized via the existing
// categorizePurpose helper so consumers see the same shape Android and
// Electron paths produce.
func extractUWPEndpoints(dr *dissect.DissectResult, kr *KnowledgeResult) {
	if dr.MSIXInfo == nil || len(dr.MSIXInfo.URLs) == 0 {
		return
	}
	if kr.Communication == nil {
		kr.Communication = &CommunicationKnowledge{}
	}
	seen := map[string]bool{}
	for _, ep := range kr.Communication.Endpoints {
		seen[ep.URL] = true
	}
	protocolSeen := map[string]bool{}
	for _, p := range kr.Communication.Protocols {
		protocolSeen[p] = true
	}
	for _, u := range dr.MSIXInfo.URLs {
		if seen[u] {
			continue
		}
		seen[u] = true
		kr.Communication.Endpoints = append(kr.Communication.Endpoints, Endpoint{
			URL:     u,
			Purpose: categorizePurpose(u),
		})
		switch {
		case strings.HasPrefix(u, "https://") && !protocolSeen["https"]:
			kr.Communication.Protocols = append(kr.Communication.Protocols, "https")
			protocolSeen["https"] = true
		case strings.HasPrefix(u, "http://") && !protocolSeen["http"]:
			kr.Communication.Protocols = append(kr.Communication.Protocols, "http")
			protocolSeen["http"] = true
		}
	}
}

func extractWebView2(dr *dissect.DissectResult, kr *KnowledgeResult) {
	if dr.WebView2Info == nil {
		return
	}
	if kr.WebView2 == nil {
		kr.WebView2 = &WebView2Knowledge{}
	}
	kr.WebView2.RuntimeMode = dr.WebView2Info.Runtime.Mode
	for _, u := range dr.WebView2Info.UDFs {
		kr.WebView2.UDFs = append(kr.WebView2.UDFs, u.Path)
		if kr.WebView2.UDFPath == "" && u.Exists {
			kr.WebView2.UDFPath = u.Path
		}
	}
	for _, p := range dr.WebView2Info.Profiles {
		kr.WebView2.Profiles = append(kr.WebView2.Profiles, p.Name)
	}
	for i := range dr.WebView2Info.ProfileData {
		kr.WebView2.CacheEntries = append(kr.WebView2.CacheEntries, ResourceRef{
			Path:     dr.WebView2Info.Profiles[minInt(i, len(dr.WebView2Info.Profiles)-1)].Name,
			Category: "webview2-cache",
		})
		kr.WebView2.PreferencesFlags = append(kr.WebView2.PreferencesFlags, "profile-data-block")
	}
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	if b < 0 {
		return 0
	}
	return b
}

// ---- depth.UWPCoverageView impl on *KnowledgeResult ---------------------

// AppxManifestCovered returns 1 when the AppxManifest summary propagated.
func (k *KnowledgeResult) AppxManifestCovered() int {
	if k == nil || k.Packaging == nil || k.Packaging.UWP == nil || k.Packaging.UWP.AppxManifest == nil {
		return 0
	}
	if k.Packaging.UWP.AppxManifest.Name == "" && k.Packaging.UWP.AppxManifest.PFN == "" {
		return 0
	}
	return 1
}

// CapabilitiesCovered returns the number of capabilities published.
func (k *KnowledgeResult) CapabilitiesCovered() int {
	if k == nil || k.Packaging == nil || k.Packaging.UWP == nil {
		return 0
	}
	return len(k.Packaging.UWP.Capabilities)
}

func (k *KnowledgeResult) XAMLResourcesCovered() int {
	if k == nil || k.Packaging == nil || k.Packaging.UWP == nil {
		return 0
	}
	return len(k.Packaging.UWP.XAMLResources)
}

func (k *KnowledgeResult) PRIResourcesCovered() int {
	if k == nil || k.Packaging == nil || k.Packaging.UWP == nil {
		return 0
	}
	return len(k.Packaging.UWP.PRIResources)
}

func (k *KnowledgeResult) DependenciesCovered() int {
	if k == nil || k.Packaging == nil || k.Packaging.UWP == nil {
		return 0
	}
	return len(k.Packaging.UWP.Dependencies)
}

func (k *KnowledgeResult) SigningChainCovered() int {
	if k == nil || k.Packaging == nil || k.Packaging.UWP == nil {
		return 0
	}
	return len(k.Packaging.UWP.SigningChain)
}

func (k *KnowledgeResult) LocalizationCovered() int {
	if k == nil || k.Packaging == nil || k.Packaging.UWP == nil {
		return 0
	}
	return len(k.Packaging.UWP.Localization)
}

func (k *KnowledgeResult) WinUIXAMLCovered() int {
	if k == nil || k.Packaging == nil || k.Packaging.UWP == nil {
		return 0
	}
	return len(k.Packaging.UWP.WinUIXAML)
}

func (k *KnowledgeResult) WinUIXBFCovered() int {
	if k == nil || k.Packaging == nil || k.Packaging.UWP == nil {
		return 0
	}
	return len(k.Packaging.UWP.WinUIXBF)
}

func (k *KnowledgeResult) WinUIPRICovered() int {
	if k == nil || k.Packaging == nil || k.Packaging.UWP == nil {
		return 0
	}
	return len(k.Packaging.UWP.WinUIPRI)
}

func (k *KnowledgeResult) WinUIPEEmbeddedCovered() int {
	if k == nil || k.Packaging == nil || k.Packaging.UWP == nil {
		return 0
	}
	return len(k.Packaging.UWP.WinUIPEEmbedded)
}

// Plan B6 dim views.

func (k *KnowledgeResult) ExtensionsCovered() int {
	if k == nil || k.IPC == nil {
		return 0
	}
	return len(k.IPC.Channels)
}

func (k *KnowledgeResult) EndpointsCovered() int {
	if k == nil || k.Communication == nil {
		return 0
	}
	return len(k.Communication.Endpoints)
}

func (k *KnowledgeResult) SourceFilesCovered() int {
	if k == nil {
		return 0
	}
	return len(k.SourceFiles)
}

// SignedModulesCovered counts PE source-file entries that have a non-nil
// Signed value AND that value is true. The total (in audit_uwp.totalUWPSignedModules)
// is the number of PE entries scanned regardless of result; this lets the
// dimension ratio express "fraction of scanned binaries that are signed."
func (k *KnowledgeResult) SignedModulesCovered() int {
	if k == nil {
		return 0
	}
	n := 0
	for _, f := range k.SourceFiles {
		if f.Signed != nil && *f.Signed {
			n++
		}
	}
	return n
}

// ---- depth.WebView2CoverageView impl on *KnowledgeResult ----------------

func (k *KnowledgeResult) UDFCovered() int {
	if k == nil || k.WebView2 == nil {
		return 0
	}
	return len(k.WebView2.UDFs)
}

func (k *KnowledgeResult) ProfilesCovered() int {
	if k == nil || k.WebView2 == nil {
		return 0
	}
	return len(k.WebView2.Profiles)
}

func (k *KnowledgeResult) CacheCovered() int {
	if k == nil || k.WebView2 == nil {
		return 0
	}
	return len(k.WebView2.CacheEntries)
}

func (k *KnowledgeResult) PreferencesCovered() int {
	if k == nil || k.WebView2 == nil {
		return 0
	}
	return len(k.WebView2.PreferencesFlags)
}
