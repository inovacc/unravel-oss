/* Copyright (c) 2026 Security Research */
package detect

import (
	"testing"
)

// TestTryUpgradeToWebView2App_Precedence verifies that framework classifications
// (Electron, Tauri, Go, Bun, etc.) win over WebView2 — pitfall 9 precedence.
func TestTryUpgradeToWebView2App_Precedence(t *testing.T) {
	cases := []FileType{
		TypeElectronApp,
		TypeTauriApp,
		TypeGoBinary,
		TypeBunStandalone,
		TypeUPXPacked,
		TypeNSIS,
		TypePyInstaller,
		TypePyZipApp,
		TypeAdvancedInstaller,
	}
	for _, ft := range cases {
		t.Run(string(ft), func(t *testing.T) {
			r := &DetectResult{FileType: ft, Category: CategoryBinary, Path: "/does/not/exist.exe"}
			tryUpgradeToWebView2App(r)
			if r.FileType != ft {
				t.Errorf("FileType changed from %q to %q — precedence violated", ft, r.FileType)
			}
		})
	}
}

// TestTryUpgradeToWebView2App_EmptyPath ensures the upgrade is a no-op when
// no path is set (e.g., in-memory detection paths).
func TestTryUpgradeToWebView2App_EmptyPath(t *testing.T) {
	r := &DetectResult{FileType: TypePE, Category: CategoryBinary, Path: ""}
	tryUpgradeToWebView2App(r)
	if r.FileType != TypePE {
		t.Errorf("FileType = %q, want TypePE (empty path should be a no-op)", r.FileType)
	}
}

// TestTryUpgradeToWebView2App_NonexistentFile ensures graceful handling of an
// unreadable PE path: the result stays as TypePE with no panic.
func TestTryUpgradeToWebView2App_NonexistentFile(t *testing.T) {
	r := &DetectResult{FileType: TypePE, Category: CategoryBinary, Path: "/definitely/not/here.exe"}
	tryUpgradeToWebView2App(r)
	if r.FileType != TypePE {
		t.Errorf("FileType = %q, want TypePE (pe.Open failure should be a no-op)", r.FileType)
	}
}

// TestTypeWebView2AppConstant verifies the FileType constant is registered
// (FRM-01 surface).
func TestTypeWebView2AppConstant(t *testing.T) {
	if TypeWebView2App != "WebView2 App" {
		t.Errorf("TypeWebView2App = %q, want %q", TypeWebView2App, "WebView2 App")
	}
}

// TestReadPEImportsQuiet_NonexistentFile ensures the quiet PE reader returns
// nil for missing/invalid files without panicking (T-03-02 DoS mitigation).
func TestReadPEImportsQuiet_NonexistentFile(t *testing.T) {
	imports := readPEImportsQuiet("/nonexistent/path.exe")
	if imports != nil {
		t.Errorf("want nil, got %v", imports)
	}
}
