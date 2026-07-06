/*
Copyright (c) 2026 Security Research
*/

// views.go: read-only coverage views over KnowledgeResult sub-structures.
// Audits depend on these interfaces (not on KnowledgeResult directly) to break
// the import cycle that would otherwise form once KnowledgeResult embeds
// []Dimension. Pattern established by P37-02 with AndroidCoverageView.
package depth

// UWPCoverageView exposes the UWP coverage data published into KnowledgeResult.
// Implementations live in pkg/knowledge.
type UWPCoverageView interface {
	AppxManifestCovered() int
	CapabilitiesCovered() int
	XAMLResourcesCovered() int
	PRIResourcesCovered() int
	DependenciesCovered() int
	SigningChainCovered() int
	LocalizationCovered() int
	WinUIXAMLCovered() int
	WinUIXBFCovered() int
	WinUIPRICovered() int
	WinUIPEEmbeddedCovered() int
	ExtensionsCovered() int
	EndpointsCovered() int
	SourceFilesCovered() int
	SignedModulesCovered() int
}

// ElectronCoverageView exposes the Electron coverage data published into KnowledgeResult.
type ElectronCoverageView interface {
	ASARFilesCovered() int
	JavaScriptImportsCovered() int
	ElectronMainCovered() int
	RendererProcessesCovered() int
	IPCChannelsCovered() int
	BundledNodeModulesCovered() int
	SourceMapsCovered() int
}

// WebView2CoverageView exposes WebView2 coverage data published into KnowledgeResult.
type WebView2CoverageView interface {
	UDFCovered() int
	ProfilesCovered() int
	CacheCovered() int
	PreferencesCovered() int
}
