/*
Copyright (c) 2026 Security Research
*/
package webview2

import "testing"

// TestDetect_UWPInstalledDir (P61 CLSR-03): verifies the package-level
// Detect convenience wrapper returns true for a UWP install-dir fixture
// containing AppxManifest.xml (with Microsoft.Web.WebView2.Runtime
// dependency) AND WebView2Loader.dll.
func TestDetect_UWPInstalledDir(t *testing.T) {
	if !Detect("testdata/uwp-installed-dir") {
		t.Fatalf("Detect=false; want true (UWP installed-dir AppxManifest + WebView2Loader.dll)")
	}
}

// TestDetect_EmptyAppDir ensures Detect("") returns false (non-regressing
// empty-string contract used by extractFramework's pre-call guard).
func TestDetect_EmptyAppDir(t *testing.T) {
	if Detect("") {
		t.Fatalf("Detect(\"\")=true; want false")
	}
}
