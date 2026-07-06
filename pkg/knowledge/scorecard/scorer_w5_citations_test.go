/*
Copyright (c) 2026 Security Research
*/
package scorecard

// W5 — explicit per-scorer Citation.File != r.SourcePath assertion tests for
// all 10 cited scorers (P64-06 P58C-01). Each test feeds a UWP-style fixture
// where the typed-field binding can engage (MSIXInfo / JSAnalysis populated)
// and asserts NO Evidence.Citation.File equals r.SourcePath.
//
// Note: scorer_behavior.go also has a TestBehavior_CitationFile_NotSourcePath
// in scorer_behavior_test.go (added in 64-04). The same pattern is repeated
// here for the other 9 scorers so all 10 are covered by W5.

import (
	"testing"

	"github.com/inovacc/unravel-oss/pkg/cert"
	"github.com/inovacc/unravel-oss/pkg/dissect"
	"github.com/inovacc/unravel-oss/pkg/msix"
	"github.com/inovacc/unravel-oss/pkg/webview2"
)

const w5SourcePath = "C:/install/whatsapp"
const w5ManifestPath = "C:/install/whatsapp/AppxManifest.xml"
const w5JSFile = "C:/install/whatsapp/main.js"
const w5ProfilePath = "C:/install/whatsapp/EBWebView/Default"

func w5UWPFixture() *dissect.DissectResult {
	signed := true
	return &dissect.DissectResult{
		SourcePath: w5SourcePath,
		MSIXInfo: &msix.InfoResult{
			ManifestPath: w5ManifestPath,
			Capabilities: []string{"internetClient"},
			URLs:         []string{"https://api.example.com"},
			Files: []msix.FileEntry{
				{Name: "App.exe", Signed: &signed},
				{Name: "lib/sqlite3.dll", Signed: &signed},
				{Name: "ui/main.html"},
				{Name: "ui/app.js"},
				{Name: "EBWebView/Default/IndexedDB/db", Size: 1024},
			},
		},
		JSAnalysis: &dissect.JSAnalysisResult{
			File: w5JSFile,
			URLs: []string{"wss://gateway.example.com", "https://oauth.example.com/token"},
		},
		WebView2Info: &webview2.Result{
			IsWebView2: true,
			Profiles:   []webview2.ProfileInfo{{Name: "Default", Path: w5ProfilePath}},
		},
		CertInfo: &cert.CertInfo{},
	}
}

func assertNoSourcePathCitation(t *testing.T, scorerID string, ds DimScore) {
	t.Helper()
	for _, e := range ds.Evidence {
		if e.Citation == nil {
			continue
		}
		if e.Citation.File == w5SourcePath {
			t.Errorf("W5 violation [%s]: Citation.File == r.SourcePath (%q) on Evidence{Kind:%q,Path:%q}",
				scorerID, w5SourcePath, e.Kind, e.Path)
		}
	}
}

func TestBinarySurface_CitationFile_NotSourcePath(t *testing.T) {
	r := w5UWPFixture()
	assertNoSourcePathCitation(t, "binary_surface", binarySurfaceScorer{}.Score(r, nil))
}

func TestSourceLayer_CitationFile_NotSourcePath(t *testing.T) {
	r := w5UWPFixture()
	assertNoSourcePathCitation(t, "source_layer", sourceLayerScorer{}.Score(r, nil))
}

func TestStorage_CitationFile_NotSourcePath(t *testing.T) {
	r := w5UWPFixture()
	assertNoSourcePathCitation(t, "storage", storageScorer{}.Score(r, nil))
}

func TestCrypto_CitationFile_NotSourcePath(t *testing.T) {
	r := w5UWPFixture()
	assertNoSourcePathCitation(t, "crypto", cryptoScorer{}.Score(r, nil))
}

func TestWire_CitationFile_NotSourcePath(t *testing.T) {
	r := w5UWPFixture()
	assertNoSourcePathCitation(t, "wire", wireScorer{}.Score(r, nil))
}

func TestIdentity_CitationFile_NotSourcePath(t *testing.T) {
	r := w5UWPFixture()
	assertNoSourcePathCitation(t, "identity", identityScorer{}.Score(r, nil))
}

func TestFilesystem_CitationFile_NotSourcePath(t *testing.T) {
	r := w5UWPFixture()
	assertNoSourcePathCitation(t, "filesystem", filesystemScorer{}.Score(r, nil))
}

func TestIPC_CitationFile_NotSourcePath(t *testing.T) {
	r := w5UWPFixture()
	assertNoSourcePathCitation(t, "ipc", ipcScorer{}.Score(r, nil))
}

func TestAPI_CitationFile_NotSourcePath(t *testing.T) {
	r := w5UWPFixture()
	assertNoSourcePathCitation(t, "api", apiScorer{}.Score(r, nil))
}

func TestAuth_CitationFile_NotSourcePath(t *testing.T) {
	r := w5UWPFixture()
	assertNoSourcePathCitation(t, "auth", authScorer{}.Score(r, nil))
}
