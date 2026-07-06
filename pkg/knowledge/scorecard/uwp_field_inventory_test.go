/*
Copyright (c) 2026 Security Research
*/

// Package scorecard — TestUWPFieldInventory enforces the Wave-0 contract for
// SCRG-01..05 inputs. See .planning/phases/64-p58-deep-citations/64-00-field-inventory.md
// for the rationale and the verified field-binding table.
//
// If this test fails, the SCRG-01..05 implementations are coded against
// assumptions about DissectResult that no longer hold. Update the fixture
// (testdata/uwp_install_dir_fields.json) and the corresponding scorer field
// bindings before proceeding.
package scorecard

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// uwpFieldInventoryFixture mirrors the JSON fixture shape used to assert
// SCRG-01..05 input contracts. Only fields the SCRG scorers actually read are
// modeled; this is intentionally NOT a full DissectResult mirror.
type uwpFieldInventoryFixture struct {
	Comment    string `json:"_comment"`
	GroundedIn string `json:"_grounded_in"`
	Phase      string `json:"_phase"`
	Task       string `json:"_task"`

	MSIXInfo struct {
		ManifestPath string `json:"manifest_path"`
		Files        []struct {
			Name   string `json:"name"`
			Size   int64  `json:"size"`
			Signed *bool  `json:"signed"`
			Signer string `json:"signer"`
		} `json:"files"`
		Capabilities []string `json:"capabilities"`
		URLs         []string `json:"urls"`
	} `json:"msix_info"`

	JSAnalysis struct {
		File           string   `json:"file"`
		URLs           []string `json:"urls"`
		DangerousCalls []string `json:"dangerous_calls"`
		NetworkCalls   []string `json:"network_calls"`
	} `json:"js_analysis"`

	WebView2Info struct {
		IsWebView2 bool `json:"is_web_view2"`
		Profiles   []struct {
			Name string `json:"name"`
			Path string `json:"path"`
		} `json:"profiles"`
	} `json:"webview2_info"`

	PresenceFlags struct {
		MSIXFilesPopulated             bool `json:"msix_files_populated"`
		MSIXPEEntriesPresent           bool `json:"msix_pe_entries_present"`
		MSIXSourceEntriesPresent       bool `json:"msix_source_entries_present"`
		MSIXManifestPathPopulated      bool `json:"msix_manifest_path_populated"`
		JSAnalysisPopulated            bool `json:"js_analysis_populated"`
		WebView2ProfilesPopulated      bool `json:"webview2_profiles_populated"`
		SCRG04PEImportsSourceAvailable bool `json:"scrg_04_pe_imports_source_available"`
	} `json:"presence_flags"`
}

func loadUWPFieldInventoryFixture(t *testing.T) *uwpFieldInventoryFixture {
	t.Helper()
	path := filepath.Join("testdata", "uwp_install_dir_fields.json")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read fixture %s: %v", path, err)
	}
	var fx uwpFieldInventoryFixture
	if err := json.Unmarshal(data, &fx); err != nil {
		t.Fatalf("unmarshal fixture: %v", err)
	}
	return &fx
}

func hasSuffixAny(name string, exts ...string) bool {
	lower := strings.ToLower(name)
	for _, e := range exts {
		if strings.HasSuffix(lower, e) {
			return true
		}
	}
	return false
}

// TestUWPFieldInventory is the Wave-0 sand-foundation guard for SCRG-01..05.
// It MUST run on every `go test ./...` (no build tag).
func TestUWPFieldInventory(t *testing.T) {
	fx := loadUWPFieldInventoryFixture(t)

	// A1 — sand-foundation guard: msix_info.files must not be empty.
	if len(fx.MSIXInfo.Files) == 0 {
		t.Fatal("SCRG sand-foundation: msix_info.files is empty; all 5 SCRGs would emit empty Evidence")
	}

	// SCRG-01 — at least one PE entry (.exe or .dll).
	hasPE := false
	for _, f := range fx.MSIXInfo.Files {
		if hasSuffixAny(f.Name, ".exe", ".dll") {
			hasPE = true
			break
		}
	}
	if !hasPE {
		t.Error("SCRG-01: no .exe/.dll entries in msix_info.files; binary_surface scorer would emit empty Evidence")
	}

	// SCRG-02 — at least one source entry (.js OR .html OR .css).
	hasSource := false
	for _, f := range fx.MSIXInfo.Files {
		if hasSuffixAny(f.Name, ".js", ".html", ".css") {
			hasSource = true
			break
		}
	}
	if !hasSource {
		t.Error("SCRG-02: no .js/.html/.css entries in msix_info.files; source_layer scorer would emit empty Evidence")
	}

	// SCRG-02 alt — js_analysis.file populated OR ≥1 .js entry.
	hasJSSignal := fx.JSAnalysis.File != ""
	if !hasJSSignal {
		for _, f := range fx.MSIXInfo.Files {
			if hasSuffixAny(f.Name, ".js") {
				hasJSSignal = true
				break
			}
		}
	}
	if !hasJSSignal {
		t.Error("SCRG-02: js_analysis.file empty AND no .js in msix_info.files; JS source signal absent")
	}

	// SCRG-03 — webview2_info.profiles non-empty (UWP install-dir typical case).
	if len(fx.WebView2Info.Profiles) == 0 {
		t.Error("SCRG-03: webview2_info.profiles empty; storage scorer would emit empty Evidence (no fallback)")
	}

	// SCRG-04 — PE-imports source available (presence flag).
	if !fx.PresenceFlags.SCRG04PEImportsSourceAvailable {
		t.Error("SCRG-04: presence flag scrg_04_pe_imports_source_available=false; crypto scorer cannot walk PE imports")
	}

	// SCRG-05 — manifest_path must be populated (added in 64-00b).
	// SCRG-05's behavior scorer uses r.MSIXInfo.ManifestPath as the typed-field
	// Citation source for capability- and URL-derived Evidence. Empty here
	// would mean SCRG-05 falls back to r.SourcePath, defeating P58C-01.
	if fx.MSIXInfo.ManifestPath == "" {
		t.Error("SCRG-05: msix_info.manifest_path empty; behavior scorer Citation.File would degrade to r.SourcePath")
	}
	if !fx.PresenceFlags.MSIXManifestPathPopulated {
		t.Error("contract drift: presence_flags.msix_manifest_path_populated=false (64-00b must flip it to true)")
	}

	// Sanity — fixture metadata must be present so future readers can trace it.
	if fx.Phase == "" || fx.Task == "" {
		t.Error("fixture missing _phase / _task metadata; rebind to 64-00-field-inventory.md")
	}
	if fx.GroundedIn == "" {
		t.Error("fixture missing _grounded_in path; rebind to a real install-dir source_path")
	}
}
